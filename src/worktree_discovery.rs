//! Find Cargo targets in the Git worktrees of repositories kache knows.
//!
//! This runs during quiet daemon maintenance, at most hourly, never in a
//! compiler wrapper or a command. Every tracked target's workspace
//! leads to its repository, and from there to the other repositories in the
//! same folders. Git lists each repository's worktrees and, in each, the
//! directories it ignores; every ignored `target/` Cargo has tagged is
//! recorded. Explicit repository roots also supply worktrees for external
//! inventory without tracking their targets. Ignored target symlinks under
//! configured external roots are recorded separately as untrusted observations.
//! Discovery does not claim completeness of source roots or aliases, or authorize cleanup.

use crate::config::Config;
use crate::maintenance::{Trigger, is_quiet, unix_now_secs};
use crate::store::Store;
use anyhow::Result;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const GIT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_INVENTORY_BYTES: u64 = 1 << 20;
#[cfg(unix)]
const MAX_GIT_METADATA_BYTES: u64 = 1 << 16;
/// How long Git may take to list one worktree's ignored directories.
const LISTING_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_LISTING_BYTES: u64 = 4 << 20;
/// External workspace candidates one discovery pass may inspect.
const MAX_EXTERNAL_RECORDS: usize = 8;
/// Source roots one discovery pass may probe for external inventory.
const MAX_EXTERNAL_SOURCES: usize = 16;
/// Configured repository roots and directory entries inspected per pass.
const MAX_REPOSITORY_ROOTS: usize = 16;
const MAX_REPOSITORY_ENTRIES_PER_ROOT: usize = 32;
/// Repositories one discovery pass may ask Git about.
const DISCOVERY_STEPS: usize = 2_000;
/// How long one discovery pass may spend.
const DISCOVERY_TIME: Duration = Duration::from_secs(20);
/// How long what a pass found counts as current.
const FRESH_FOR: Duration = Duration::from_secs(3600);
/// Holds the Unix time discovery last ran, so a restarted daemon keeps the
/// hourly pace. A new install or an upgrade has none, and discovers at its
/// first quiet check.
const LAST_RUN_FILE: &str = "target-discovery.last";

/// When this process last ran discovery, for a volume too full to keep
/// [`LAST_RUN_FILE`]: `0` before the first run.
static LAST_RUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static REPOSITORY_TURN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Copy)]
struct ExternalRoots<'a> {
    targets: &'a [PathBuf],
    repositories: &'a [PathBuf],
}

/// Whether a run last at `last` (Unix seconds, `0` for never) is stale at
/// `now`. A clock set back behind it does not stop discovery.
fn stale(last: u64, now: u64) -> bool {
    last == 0 || now < last || now - last >= FRESH_FOR.as_secs()
}

/// Whether to discover now: a periodic check (never the shutdown pass) on a
/// quiet machine, when both the recorded and the remembered last run are
/// stale.
fn due(periodic: bool, quiet: bool, recorded: u64, remembered: u64, now: u64) -> bool {
    periodic && quiet && stale(recorded, now) && stale(remembered, now)
}

/// The maintenance step: on a quiet machine, discover when the last run is
/// an hour old or there is none, and record when. `true` when it ran, so the
/// pass leaves its other walks for the next check.
pub(crate) fn run(config: &Config, trigger: Trigger<'_>) -> bool {
    let now = unix_now_secs();
    let record = config.cache_dir.join(LAST_RUN_FILE);
    let recorded = std::fs::read_to_string(&record)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0);
    let remembered = LAST_RUN.load(std::sync::atomic::Ordering::Relaxed);
    let periodic = matches!(trigger, Trigger::Periodic(_));
    let quiet = is_quiet(
        crate::scheduler::permits_in_use(&config.cache_dir),
        trigger.idle_for(),
    );
    if !due(periodic, quiet, recorded, remembered, now) {
        return false;
    }
    // Recorded before the pass, so a pass that fails waits an hour too.
    LAST_RUN.store(now, std::sync::atomic::Ordering::Relaxed);
    if let Err(error) = crate::atomic::atomic_replace(&record, now.to_string().as_bytes()) {
        tracing::warn!("cannot record the target discovery time: {error:#}");
    }
    let roots = ExternalRoots {
        targets: &config.external_target_roots,
        repositories: &config.external_repository_roots,
    };
    match Store::open(config).and_then(|store| discover(&store, roots, DISCOVERY_TIME, now)) {
        Ok(0) => {}
        Ok(found) => tracing::info!("found {found} target directories in Git worktrees"),
        Err(error) => tracing::warn!("target discovery failed: {error:#}"),
    }
    true
}

#[derive(Debug, PartialEq, Eq)]
struct Worktree {
    path: PathBuf,
    bare: bool,
    locked: bool,
    prunable: bool,
}

/// Parse Git's NUL-delimited porcelain records. An unknown attribute does not
/// change the meaning of the attributes used for cleanup decisions.
fn parse_worktrees(bytes: &[u8]) -> Vec<Worktree> {
    let mut trees = Vec::new();
    let mut current: Option<Worktree> = None;
    for field in bytes.split(|byte| *byte == 0) {
        if field.is_empty() {
            if let Some(tree) = current.take() {
                trees.push(tree);
            }
            continue;
        }
        if let Some(path) = field.strip_prefix(b"worktree ") {
            if let Some(tree) = current.take() {
                trees.push(tree);
            }
            #[cfg(unix)]
            let path = {
                use std::os::unix::ffi::OsStringExt;
                Some(PathBuf::from(std::ffi::OsString::from_vec(path.to_vec())))
            };
            #[cfg(not(unix))]
            let path = String::from_utf8(path.to_vec()).ok().map(PathBuf::from);
            current = path.map(|path| Worktree {
                path,
                bare: false,
                locked: false,
                prunable: false,
            });
        } else if let Some(tree) = current.as_mut() {
            tree.bare |= field == b"bare";
            tree.locked |= field == b"locked" || field.starts_with(b"locked ");
            tree.prunable |= field == b"prunable" || field.starts_with(b"prunable ");
        }
    }
    if let Some(tree) = current {
        trees.push(tree);
    }
    trees
}

/// `git -C dir <args>`'s output, or `None` if Git fails, outruns `timeout`
/// or `deadline`, or writes `max_bytes` or more. The repository's own
/// filesystem monitor is switched off: discovery reads repositories no build
/// ran in, and a configured `core.fsmonitor` is a program Git would run.
fn git_output(
    dir: &Path,
    args: &[&str],
    timeout: Duration,
    deadline: Instant,
    max_bytes: u64,
) -> Option<Vec<u8>> {
    let timeout = timeout.min(deadline.checked_duration_since(Instant::now())?);
    let mut child = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(dir)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = match std::thread::Builder::new()
        .name("kache-git-discovery".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(max_bytes).read_to_end(&mut bytes).ok()?;
            Some(bytes)
        }) {
        Ok(reader) => reader,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if deadline.checked_duration_since(Instant::now()).is_none() {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break None,
        }
    };
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let bytes = reader.join().ok().flatten()?;
    if !status?.success() || bytes.len() as u64 == max_bytes {
        return None;
    }
    Some(bytes)
}

fn inventory(workspace: &Path, deadline: Instant) -> Option<Vec<Worktree>> {
    let bytes = git_output(
        workspace,
        &["worktree", "list", "--porcelain", "-z"],
        GIT_TIMEOUT,
        deadline,
        MAX_INVENTORY_BYTES,
    )?;
    Some(
        parse_worktrees(&bytes)
            .into_iter()
            .filter_map(|mut tree| {
                tree.path = tree.path.canonicalize().ok()?;
                Some(tree)
            })
            .collect(),
    )
}

/// Where `seed` sits in its own worktree, relative to that worktree's root:
/// the nearest of its ancestors among `roots`.
fn seed_suffix(seed: &Path, roots: &HashSet<&Path>) -> Option<PathBuf> {
    let root = seed.ancestors().find(|dir| roots.contains(dir))?;
    seed.strip_prefix(root).ok().map(Path::to_path_buf)
}

/// The roots of `trees`, for [`seed_suffix`].
fn roots_of(trees: &[Worktree]) -> HashSet<&Path> {
    trees.iter().map(|tree| tree.path.as_path()).collect()
}

/// The workspaces at `suffix` in each of `trees` that has one.
fn workspaces_at<'a>(
    suffix: &'a Path,
    trees: &'a [&'a Worktree],
) -> impl Iterator<Item = PathBuf> + 'a {
    trees
        .iter()
        // `join("")` would add a trailing separator to the worktree's root.
        .map(move |tree| {
            if suffix.as_os_str().is_empty() {
                tree.path.clone()
            } else {
                tree.path.join(suffix)
            }
        })
        .filter(|workspace| {
            std::fs::symlink_metadata(workspace).is_ok_and(|meta| meta.file_type().is_dir())
                && workspace.join("Cargo.toml").is_file()
        })
}

/// Whether discovery may read `tree`: available to Git, and not shielded.
fn readable(tree: &Worktree, homes: &[PathBuf]) -> bool {
    !tree.bare && !tree.locked && !tree.prunable && !shielded(&tree.path, homes)
}

/// Map the source workspace's path relative to its Git worktree into each
/// sibling. A repository may contain more than one Cargo workspace.
#[cfg(test)]
fn sibling_workspaces(seed: &Path, trees: &[Worktree]) -> Vec<PathBuf> {
    let available: Vec<_> = trees.iter().filter(|tree| readable(tree, &[])).collect();
    seed_suffix(seed, &roots_of(trees))
        .map(|suffix| workspaces_at(&suffix, &available).collect())
        .unwrap_or_default()
}

/// The `target/` directories among a worktree's ignored ones, as Git lists
/// them with `ls-files --others --ignored --directory`: paths relative to
/// the worktree, NUL-separated, a directory with a trailing slash. Git does
/// not descend into an ignored directory, so a target inside another one
/// (`node_modules/…/target`, `target/package/…/target`) is not listed.
fn ignored_target_dirs(worktree: &Path, listing: &[u8]) -> Vec<PathBuf> {
    listing
        .split(|byte| *byte == 0)
        .filter_map(|entry| entry.strip_suffix(b"/"))
        .filter(|dir| *dir == b"target" || dir.ends_with(b"/target"))
        .filter_map(|dir| std::str::from_utf8(dir).ok())
        .map(|dir| worktree.join(dir))
        .collect()
}

#[derive(Default)]
struct TargetListing {
    targets: Vec<(PathBuf, PathBuf)>,
    links: Vec<PathBuf>,
    sources: Vec<PathBuf>,
}

/// Cargo-tagged ignored directories and, when requested, ignored target links.
fn targets_in_worktree(worktree: &Path, deadline: Instant, include_links: bool) -> TargetListing {
    let Some(listing) = git_output(
        worktree,
        &[
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
        ],
        LISTING_TIMEOUT,
        deadline,
        MAX_LISTING_BYTES,
    ) else {
        return TargetListing::default();
    };
    let dirs = ignored_target_dirs(worktree, &listing);
    let sources = if include_links {
        dirs.iter()
            .filter_map(|target| target.parent().map(Path::to_path_buf))
            .collect()
    } else {
        Vec::new()
    };
    let targets = dirs
        .into_iter()
        .filter(|target| crate::machine::cargo_tagged(target))
        .filter_map(|target| Some((target.clone(), target.parent()?.to_path_buf())))
        .collect();
    let links = if include_links {
        listing
            .split(|byte| *byte == 0)
            .filter(|entry| *entry == b"target" || entry.ends_with(b"/target"))
            .take_while(|_| Instant::now() < deadline)
            .filter_map(|entry| std::str::from_utf8(entry).ok())
            .map(|entry| worktree.join(entry))
            .filter(|target| {
                std::fs::symlink_metadata(target).is_ok_and(|meta| meta.file_type().is_symlink())
            })
            .filter_map(|target| target.parent().map(Path::to_path_buf))
            .collect()
    } else {
        Vec::new()
    };
    TargetListing {
        targets,
        links,
        sources,
    }
}

/// Places discovery never reads: the filesystem root, the home folder
/// itself (a dotfiles repository there would be listed whole), and folders
/// macOS asks the user about before an app reads them. Discovery neither
/// lists them, nor asks Git about them, nor crawls them. `homes` is the home
/// folder as spelled and as resolved, so a symlinked home is still matched.
fn shielded(dir: &Path, homes: &[PathBuf]) -> bool {
    const PROTECTED: [&str; 9] = [
        "Desktop",
        "Documents",
        "Downloads",
        "Library",
        "Pictures",
        "Music",
        "Movies",
        "Applications",
        "Public",
    ];
    dir.parent().is_none()
        || homes.iter().any(|home| {
            dir == home
                || PROTECTED
                    .iter()
                    .any(|name| dir.starts_with(home.join(name)))
        })
}

/// Git repositories directly in `dir`: children holding a `.git` directory
/// or worktree file, read one entry at a time until `deadline`.
fn repositories_in(dir: PathBuf, deadline: Instant) -> impl Iterator<Item = PathBuf> {
    std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .take_while(move |_| deadline.checked_duration_since(Instant::now()).is_some())
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .filter(|child| std::fs::symlink_metadata(child.join(".git")).is_ok())
}

fn configured_repositories(
    roots: &[PathBuf],
    deadline: Instant,
    homes: &[PathBuf],
    turn: u64,
    is_local: &dyn Fn(&Path) -> bool,
) -> Vec<PathBuf> {
    if roots.is_empty() {
        return Vec::new();
    }
    let offset = (turn % roots.len() as u64) as usize;
    let mut repositories = Vec::new();
    for root in roots[offset..]
        .iter()
        .chain(&roots[..offset])
        .take(MAX_REPOSITORY_ROOTS)
    {
        if Instant::now() >= deadline {
            break;
        }
        if shielded(root, homes) {
            continue;
        }
        let Ok(root) = root.canonicalize() else {
            continue;
        };
        if shielded(&root, homes) || !root.is_dir() || !is_local(&root) {
            continue;
        }
        let mut add_repository = |path: PathBuf| {
            if !shielded(&path, homes)
                && is_local(&path)
                && std::fs::symlink_metadata(path.join(".git"))
                    .is_ok_and(|meta| meta.is_dir() || meta.is_file())
            {
                repositories.push(path);
            }
        };
        add_repository(root.clone());
        for entry in std::fs::read_dir(&root)
            .into_iter()
            .flatten()
            .take(MAX_REPOSITORY_ENTRIES_PER_ROOT)
        {
            if Instant::now() >= deadline {
                break;
            }
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let Ok(child) = entry.path().canonicalize() else {
                continue;
            };
            add_repository(child);
        }
    }
    repositories
}

#[cfg(unix)]
fn read_git_metadata(path: &Path) -> std::io::Result<Option<String>> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut text = String::new();
    file.take(MAX_GIT_METADATA_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_GIT_METADATA_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(Some(text))
}

#[cfg(not(unix))]
fn read_git_metadata(_path: &Path) -> std::io::Result<Option<String>> {
    // Portable file opening cannot exclude blocking special files.
    Err(std::io::ErrorKind::Unsupported.into())
}

/// The Git directory every worktree of the repository holding `path`
/// shares, read from the filesystem without running Git: the nearest
/// `.git` directory, or the one a worktree's `.git` file points to through
/// its `commondir`. Two paths in one repository give the same answer.
fn repository_of(
    path: &Path,
    homes: &[PathBuf],
    local_only: Option<&dyn Fn(&Path) -> bool>,
) -> Option<PathBuf> {
    let safe =
        |path: &Path| !shielded(path, homes) && local_only.is_none_or(|is_local| is_local(path));
    let mut dot_git = None;
    for dir in path.ancestors() {
        let candidate = dir.join(".git");
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {
                dot_git = Some(candidate);
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) => {}
            Err(_) => return None,
        }
    }
    let dot_git = dot_git?;
    if dot_git.is_dir() {
        let common = dot_git.canonicalize().ok()?;
        return safe(&common).then_some(common);
    }
    let text = read_git_metadata(&dot_git).ok()??;
    let git_dir = Path::new(text.strip_prefix("gitdir:")?.trim());
    let git_dir = dot_git.parent()?.join(git_dir).canonicalize().ok()?;
    if !safe(&git_dir) {
        return None;
    }
    let common = match read_git_metadata(&git_dir.join("commondir")).ok()? {
        Some(common) => git_dir.join(common.trim()),
        None => git_dir,
    }
    .canonicalize()
    .ok()?;
    safe(&common).then_some(common)
}

/// `items` turned by `turn` places: each pass starts at a different one, so
/// a pass that runs out of time does not leave the same ones out every time.
fn rotated<T>(mut items: Vec<T>, turn: u64) -> Vec<T> {
    if !items.is_empty() {
        let by = (turn % items.len() as u64) as usize;
        items.rotate_left(by);
    }
    items
}

/// A coprime step reaches every candidate even when a pass stops early.
fn external_candidate_turn(turn: u64, count: usize) -> u64 {
    let step = (1..=MAX_EXTERNAL_RECORDS)
        .rev()
        .find(|step| {
            let (mut a, mut b) = (count, *step);
            while b != 0 {
                (a, b) = (b, a % b);
            }
            a == 1
        })
        .unwrap_or(1);
    turn.wrapping_mul(step as u64)
}

/// The turn for [`rotated`] at `now` (Unix seconds): the hour, as discovery
/// runs at most hourly.
fn turn_at(now: u64) -> u64 {
    now / FRESH_FOR.as_secs()
}

/// The home folder from its variable, as spelled and as resolved; none when
/// it is unset or empty.
fn homes_from(home: Option<std::ffi::OsString>) -> Vec<PathBuf> {
    let Some(home) = home.filter(|home| !home.is_empty()).map(PathBuf::from) else {
        return Vec::new();
    };
    let resolved = home.canonicalize().ok();
    let mut homes = vec![home];
    homes.extend(resolved.filter(|resolved| *resolved != homes[0]));
    homes
}

/// What Git says about one repository: its worktrees, and the targets in
/// them, as (target, workspace).
struct Survey {
    trees: Vec<Worktree>,
    targets: Vec<(PathBuf, PathBuf)>,
    links: Vec<PathBuf>,
    sources: Vec<PathBuf>,
}

/// Run `task` on each item, several at once (each mostly waits on Git and
/// the filesystem), and return the results in the items' order.
fn in_parallel<T: Sync, R: Send>(items: &[T], task: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let workers = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .clamp(1, 8);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done = std::sync::Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|scope| {
        for _ in 0..workers.min(items.len()) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(item) = items.get(index) else {
                        break;
                    };
                    let result = task(item);
                    if let Ok(mut done) = done.lock() {
                        done.push((index, result));
                    }
                }
            });
        }
    });
    let mut done = done
        .into_inner()
        .unwrap_or_else(|poison| poison.into_inner());
    done.sort_by_key(|(index, _)| *index);
    done.into_iter().map(|(_, result)| result).collect()
}

/// Survey each repository, given as a start inside it and the seed
/// workspaces in it: list its worktrees, then, across every readable
/// worktree at once, the tagged targets Git ignores. Each seed's place in
/// its worktree is also looked at in every sibling, once per place, which
/// finds a target there that Git does not ignore. Starts no Git after
/// `deadline`.
fn survey_all(
    repositories: &[(PathBuf, Vec<PathBuf>)],
    deadline: Instant,
    homes: &[PathBuf],
    turn: u64,
    include_links: bool,
    local_only: Option<&dyn Fn(&Path) -> bool>,
) -> Vec<Survey> {
    let can_read = |tree: &&Worktree| {
        readable(tree, homes) && local_only.is_none_or(|is_local| is_local(&tree.path))
    };
    // Asked in a turned order, so a pass that runs out of time leaves out
    // different repositories each time; answers go back in the given order.
    let order = rotated((0..repositories.len()).collect(), turn);
    let mut inventories: Vec<Option<Vec<Worktree>>> = std::iter::repeat_with(|| None)
        .take(repositories.len())
        .collect();
    let asked = in_parallel(&order, |index| inventory(&repositories[*index].0, deadline));
    for (index, trees) in order.into_iter().zip(asked) {
        inventories[index] = trees;
    }
    let worktrees: Vec<PathBuf> = inventories
        .iter()
        .flatten()
        .flatten()
        .filter(can_read)
        .map(|tree| tree.path.clone())
        .collect();
    let worktrees = rotated(worktrees, turn);
    let listed = in_parallel(&worktrees, |worktree| {
        targets_in_worktree(worktree, deadline, include_links)
    });
    let mut listed: HashMap<_, _> = worktrees.into_iter().zip(listed).collect();
    // In the order given, so builds' workspaces are recorded first.
    repositories
        .iter()
        .zip(inventories)
        .filter_map(|((_, seeds), trees)| {
            let trees = trees?;
            let available: Vec<_> = trees.iter().filter(can_read).collect();
            let roots = roots_of(&trees);
            let suffixes: BTreeSet<_> = seeds
                .iter()
                .filter_map(|seed| seed_suffix(seed, &roots))
                .collect();
            let mut targets: Vec<_> = suffixes
                .iter()
                .flat_map(|suffix| workspaces_at(suffix, &available))
                .map(|workspace| (workspace.join("target"), workspace))
                .collect();
            let mut links = Vec::new();
            let mut sources = Vec::new();
            for tree in &trees {
                let listing = listed.remove(&tree.path).unwrap_or_default();
                targets.extend(listing.targets);
                links.extend(listing.links);
                sources.extend(listing.sources);
            }
            Some(Survey {
                trees,
                targets,
                links,
                sources,
            })
        })
        .collect()
}

/// Group `starts` by the repository each is in, keeping the first start of
/// each and every seed, leaving out repositories in `seen` and starts that
/// are shielded. Stops taking new repositories at `limit` or `deadline`.
fn by_repository(
    starts: impl IntoIterator<Item = (PathBuf, Option<PathBuf>)>,
    seen: &mut HashSet<PathBuf>,
    limit: usize,
    deadline: Instant,
    homes: &[PathBuf],
    local_only: Option<&dyn Fn(&Path) -> bool>,
) -> Vec<(PathBuf, Vec<PathBuf>)> {
    let mut order = Vec::new();
    let mut grouped: HashMap<PathBuf, (PathBuf, Vec<PathBuf>)> = HashMap::new();
    for (start, seed) in starts {
        if Instant::now() >= deadline {
            break;
        }
        if shielded(&start, homes) {
            continue;
        }
        let Some(repository) = repository_of(&start, homes, local_only) else {
            continue;
        };
        if seen.contains(&repository) {
            continue;
        }
        if !grouped.contains_key(&repository) {
            if order.len() >= limit {
                break;
            }
            order.push(repository.clone());
            grouped.insert(repository.clone(), (start, Vec::new()));
        }
        if let Some(entry) = grouped.get_mut(&repository) {
            entry.1.extend(seed);
        }
    }
    order
        .into_iter()
        .filter_map(|repository| {
            seen.insert(repository.clone());
            grouped.remove(&repository)
        })
        .collect()
}

/// Discover targets in the Git worktrees of every repository a tracked
/// target belongs to, then of the other repositories in the folders those
/// worktrees sit in: the same workspace in each sibling worktree, and every
/// tagged `target/` Git ignores in each worktree, within `time`. A custom
/// target path outside its worktree is known only when a wrapper recorded it.
fn discover(store: &Store, roots: ExternalRoots<'_>, time: Duration, now: u64) -> Result<usize> {
    let homes = homes_from(std::env::var_os(if cfg!(windows) {
        "USERPROFILE"
    } else {
        "HOME"
    }));
    discover_within(store, roots, Instant::now() + time, &homes, turn_at(now))
}

fn discover_within(
    store: &Store,
    roots: ExternalRoots<'_>,
    deadline: Instant,
    homes: &[PathBuf],
    turn: u64,
) -> Result<usize> {
    discover_within_using(
        store,
        roots,
        deadline,
        homes,
        turn,
        |path| crate::cache_fs::probe(path).is_local == Some(true),
        observe_external_before_deadline,
    )
}

fn observe_external_before_deadline(
    store: &Store,
    workspace: &Path,
    root: &Path,
    sources: &[PathBuf],
    snapshot: &kache_store::filesystem::TargetSymlinkSnapshot,
    deadline: Instant,
) -> Result<bool> {
    if Instant::now() >= deadline {
        return Ok(false);
    }
    store.observe_external_target(workspace, root, sources, snapshot)
}

fn discover_within_using(
    store: &Store,
    roots: ExternalRoots<'_>,
    deadline: Instant,
    homes: &[PathBuf],
    turn: u64,
    is_local: impl Fn(&Path) -> bool,
    observe_external: impl Fn(
        &Store,
        &Path,
        &Path,
        &[PathBuf],
        &kache_store::filesystem::TargetSymlinkSnapshot,
        Instant,
    ) -> Result<bool>,
) -> Result<usize> {
    let configured = !roots.repositories.is_empty() && !roots.targets.is_empty();
    let start = Instant::now();
    let time = deadline.saturating_duration_since(start);
    let ordinary_deadline = if configured {
        start + time / 2
    } else {
        deadline
    };
    let configured_deadline = if configured {
        start + time / 2 + time / 4
    } else {
        deadline
    };
    let ordinary_limit = if configured {
        DISCOVERY_STEPS / 2
    } else {
        DISCOVERY_STEPS
    };
    let tracked = store.tracked_target_roots(0)?;
    let mut known: HashSet<_> = tracked.iter().map(|root| root.identity).collect();
    // Every tracked target leads to its repository, a target found through
    // Git too, so a repository stays reachable after its builds' rows go.
    // Turned, so a limit leaves out different ones each pass. A seed is
    // checked against the shield before it is resolved: resolving reads it.
    let seeds = rotated(tracked.iter().collect(), turn)
        .into_iter()
        .filter(|root| !shielded(&root.workspace_root, homes))
        .filter_map(|root| root.workspace_root.canonicalize().ok())
        .map(|seed| (seed.clone(), Some(seed)));
    let mut seen = HashSet::new();
    let known_repositories = by_repository(
        seeds,
        &mut seen,
        ordinary_limit,
        ordinary_deadline,
        homes,
        None,
    );
    let mut surveys = survey_all(
        &known_repositories,
        ordinary_deadline,
        homes,
        turn,
        !roots.targets.is_empty(),
        None,
    );
    // One hop out: the repositories beside the worktrees of the known ones.
    // The listing is lazy, so a spent limit stops it at once.
    let neighbourhood: BTreeSet<_> = surveys
        .iter()
        .flat_map(|survey| &survey.trees)
        .filter_map(|tree| tree.path.parent().map(Path::to_path_buf))
        .filter(|dir| !shielded(dir, homes))
        .collect();
    let beside = rotated(neighbourhood.into_iter().collect(), turn)
        .into_iter()
        .flat_map(|dir| repositories_in(dir, ordinary_deadline))
        .map(|repository| (repository, None));
    let limit = ordinary_limit.saturating_sub(seen.len());
    let neighbours = by_repository(beside, &mut seen, limit, ordinary_deadline, homes, None);
    surveys.extend(survey_all(
        &neighbours,
        ordinary_deadline,
        homes,
        turn,
        !roots.targets.is_empty(),
        None,
    ));

    let mut covered = HashSet::new();
    let mut found = 0;
    // What the surveys found is recorded whatever the time: a few inserts.
    for (target, workspace) in surveys.iter().flat_map(|survey| &survey.targets) {
        if !covered.insert(workspace.clone()) {
            continue;
        }
        if let Some(id) = crate::machine::directory_identity(target)
            && !known.insert(id)
        {
            continue;
        }
        found += usize::from(store.remember_discovered_target_root(target, workspace)?);
    }

    if configured {
        let repository_turn = REPOSITORY_TURN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let starts = configured_repositories(
            roots.repositories,
            configured_deadline,
            homes,
            repository_turn,
            &is_local,
        )
        .into_iter()
        .map(|repository| (repository, None));
        let limit = DISCOVERY_STEPS.saturating_sub(seen.len());
        let repositories = by_repository(
            starts,
            &mut seen,
            limit,
            configured_deadline,
            homes,
            Some(&is_local),
        );
        surveys.extend(survey_all(
            &repositories,
            configured_deadline,
            homes,
            turn,
            true,
            Some(&is_local),
        ));
    }

    if !roots.targets.is_empty() {
        let sources =
            tracked
                .iter()
                .map(|root| &root.workspace_root)
                .chain(surveys.iter().flat_map(|survey| {
                    survey
                        .trees
                        .iter()
                        .filter(|tree| readable(tree, homes))
                        .map(|tree| &tree.path)
                        .chain(survey.targets.iter().map(|(_, workspace)| workspace))
                        .chain(&survey.links)
                        .chain(&survey.sources)
                }));
        let links = surveys.iter().flat_map(|survey| &survey.links);
        inventory_external(
            store,
            roots.targets,
            deadline,
            homes,
            sources,
            links,
            is_local,
            observe_external,
            Instant::now,
        );
    }
    Ok(found)
}

fn inventory_external<'a>(
    store: &Store,
    external_roots: &[PathBuf],
    deadline: Instant,
    homes: &[PathBuf],
    source_paths: impl IntoIterator<Item = &'a PathBuf>,
    links: impl IntoIterator<Item = &'a PathBuf>,
    is_local: impl Fn(&Path) -> bool,
    observe_external: impl Fn(
        &Store,
        &Path,
        &Path,
        &[PathBuf],
        &kache_store::filesystem::TargetSymlinkSnapshot,
        Instant,
    ) -> Result<bool>,
    now: impl Fn() -> Instant,
) {
    let links: Vec<_> = links
        .into_iter()
        .filter(|workspace| !shielded(workspace, homes))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if links.is_empty() || now() >= deadline {
        return;
    }
    let turn = match store.next_external_inventory_turn() {
        Ok(turn) => turn,
        Err(error) => {
            tracing::warn!("cannot read external target inventory pass cursor: {error:#}");
            return;
        }
    };
    // Leave half the remaining time for candidates, subject to slow filesystem calls.
    let start = now();
    let source_deadline = start + deadline.saturating_duration_since(start) / 2;
    let source_paths = source_paths
        .into_iter()
        .take_while(|_| now() < source_deadline)
        .filter(|path| !shielded(path, homes))
        .collect::<BTreeSet<_>>();
    let source_turn = external_candidate_turn(turn, source_paths.len());
    let mut sources = Vec::new();
    for path in rotated(source_paths.into_iter().collect(), source_turn)
        .into_iter()
        .take(MAX_EXTERNAL_SOURCES)
    {
        if now() >= source_deadline {
            break;
        }
        let Ok(resolved) = path.canonicalize() else {
            continue;
        };
        if now() >= source_deadline {
            break;
        }
        if shielded(&resolved, homes) || !resolved.is_dir() {
            continue;
        }
        if now() >= source_deadline {
            break;
        }
        if is_local(&resolved) {
            // Preserve the spelling for snapshot revalidation.
            sources.push(path.clone());
        }
    }
    if now() >= deadline {
        return;
    }
    let turn = match store.reserve_external_inventory_turn(deadline) {
        Ok(Some(turn)) => turn,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!("cannot reserve external target inventory pass: {error:#}");
            return;
        }
    };
    let turn = external_candidate_turn(turn, links.len());
    let mut candidates = 0;
    'external: for workspace in rotated(links, turn) {
        if now() >= deadline || candidates == MAX_EXTERNAL_RECORDS {
            break;
        }
        let Ok(resolved) = workspace.canonicalize() else {
            continue;
        };
        if shielded(&resolved, homes)
            || !is_local(&resolved)
            || !is_local(&workspace.join("target"))
        {
            continue;
        }
        candidates += 1;
        for root in external_roots {
            if now() >= deadline {
                break;
            }
            if !is_local(root) {
                continue;
            }
            if now() >= deadline {
                break;
            }
            let Some(snapshot) =
                kache_store::filesystem::snapshot_workspace_target(workspace, root, &sources)
            else {
                continue;
            };
            if !is_local(&snapshot.backing_path) {
                continue;
            }
            if let Err(error) =
                observe_external(store, workspace, root, &sources, &snapshot, deadline)
            {
                tracing::warn!(
                    "cannot inventory external target {} under {}: {error:#}",
                    workspace.display(),
                    root.display()
                );
                break 'external;
            }
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets_only(targets: &[PathBuf]) -> ExternalRoots<'_> {
        ExternalRoots {
            targets,
            repositories: &[],
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn private_inventory_cache(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn cargo_target(workspace: &Path) -> PathBuf {
        std::fs::create_dir_all(workspace).unwrap();
        std::fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
        let target = workspace.join("target");
        std::fs::create_dir_all(target.join("debug")).unwrap();
        std::fs::write(
            target.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n",
        )
        .unwrap();
        target
    }

    #[test]
    fn only_target_directories_count_among_ignored_ones() {
        let root = Path::new("/w");
        let listing = b"target/\0extensions/kgw/target/\0node_modules/\0.env\0crates/removed/target/\0dist/targets/\0build/my-target/\0";
        assert_eq!(
            ignored_target_dirs(root, listing),
            vec![
                root.join("target"),
                root.join("extensions/kgw/target"),
                root.join("crates/removed/target"),
            ]
        );
    }

    #[test]
    fn discovery_never_reads_home_or_protected_folders() {
        let home = PathBuf::from("/Users/dev");
        let homes = std::slice::from_ref(&home);
        assert!(shielded(Path::new("/"), homes));
        assert!(shielded(&home, homes));
        assert!(shielded(&home.join("Documents"), homes));
        assert!(shielded(&home.join("Desktop/projects"), homes));
        assert!(!shielded(&home.join("code"), homes));
        assert!(!shielded(Path::new("/private/tmp"), homes));
        assert!(!shielded(&home.join("code"), &[]));
        // A home reached through a symlink is matched as spelled and as
        // resolved.
        let both = [home.clone(), PathBuf::from("/Volumes/Homes/dev")];
        assert!(shielded(Path::new("/Volumes/Homes/dev/Documents/x"), &both));
        assert!(shielded(Path::new("/Volumes/Homes/dev"), &both));
        assert!(!shielded(
            Path::new("/Volumes/Homes/dev/Documents/x"),
            homes
        ));
    }

    #[cfg(unix)]
    #[test]
    fn configured_roots_never_enumerate_shielded_paths_or_aliases() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let home = base.join("home");
        let documents = home.join("Documents");
        let parent = base.join("parent");
        for path in [&home, &documents, &parent] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::create_dir(home.join(".git")).unwrap();
        std::fs::create_dir(documents.join(".git")).unwrap();
        let home_alias = base.join("home-alias");
        let documents_alias = base.join("documents-alias");
        let root_alias = base.join("root-alias");
        symlink(&home, &home_alias).unwrap();
        symlink(&documents, &documents_alias).unwrap();
        symlink("/", &root_alias).unwrap();
        symlink(&documents, parent.join("protected-child")).unwrap();
        let linked_worktree = base.join("linked-worktree");
        std::fs::create_dir(&linked_worktree).unwrap();
        std::fs::write(
            linked_worktree.join(".git"),
            format!("gitdir: {}\n", documents.display()),
        )
        .unwrap();
        let homes = [home.clone()];
        let roots = [
            PathBuf::from("/"),
            home,
            documents,
            home_alias,
            documents_alias,
            root_alias,
        ];
        let deadline = Instant::now() + DISCOVERY_TIME;
        assert!(
            configured_repositories(&roots, deadline, &homes, 0, &|_| {
                panic!("shielded roots must not be probed")
            })
            .is_empty()
        );
        assert!(
            configured_repositories(
                std::slice::from_ref(&parent),
                deadline,
                &homes,
                0,
                &|path| {
                    assert_eq!(path, parent);
                    true
                }
            )
            .is_empty()
        );
        assert!(
            by_repository(
                [(linked_worktree, None)],
                &mut HashSet::new(),
                1,
                deadline,
                &homes,
                Some(&|_| panic!("protected Git directory must not be probed")),
            )
            .is_empty()
        );
    }

    #[test]
    fn configured_root_and_entry_limits_rotate_roots() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let roots: Vec<_> = (0..MAX_REPOSITORY_ROOTS + 5)
            .map(|index| {
                let root = base.join(format!("root-{index}"));
                std::fs::create_dir_all(root.join(".git")).unwrap();
                root
            })
            .collect();
        let mut visited = HashSet::new();
        for turn in 0..roots.len() {
            let found = configured_repositories(
                &roots,
                Instant::now() + DISCOVERY_TIME,
                &[],
                turn as u64,
                &|_| true,
            );
            assert_eq!(found.len(), MAX_REPOSITORY_ROOTS);
            visited.extend(found);
        }
        assert_eq!(visited, roots.into_iter().collect());

        let crowded = base.join("crowded");
        for index in 0..MAX_REPOSITORY_ENTRIES_PER_ROOT * 2 {
            std::fs::create_dir_all(crowded.join(format!("repo-{index}")).join(".git")).unwrap();
        }
        let found = configured_repositories(
            std::slice::from_ref(&crowded),
            Instant::now() + DISCOVERY_TIME,
            &[],
            0,
            &|_| true,
        );
        assert_eq!(found.len(), MAX_REPOSITORY_ENTRIES_PER_ROOT);
        assert!(
            configured_repositories(&[crowded], Instant::now(), &[], 0, &|_| {
                panic!("expired pass must not probe roots")
            })
            .is_empty()
        );
    }

    #[test]
    fn porcelain_parser_keeps_state_with_each_worktree() {
        let trees = parse_worktrees(
            b"worktree /repo\0HEAD abc\0\0worktree /other\0locked offline\0\0worktree /old\0prunable missing\0\0worktree /bare\0bare\0\0",
        );
        assert_eq!(trees.len(), 4);
        assert_eq!(trees[0].path, Path::new("/repo"));
        assert!(!trees[0].locked);
        assert!(trees[1].locked);
        assert!(trees[2].prunable);
        assert!(trees[3].bare);
    }

    #[test]
    fn a_workspace_at_a_worktree_root_maps_without_a_trailing_separator() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        for path in [&first, &second] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("Cargo.toml"), "").unwrap();
        }
        let tree = |path: &Path| Worktree {
            path: path.to_path_buf(),
            bare: false,
            locked: false,
            prunable: false,
        };
        let mapped = sibling_workspaces(&first, &[tree(&first), tree(&second)]);
        assert_eq!(mapped, vec![first.clone(), second.clone()]);
        assert!(
            mapped
                .iter()
                .all(|path| !path.to_string_lossy().ends_with(std::path::MAIN_SEPARATOR))
        );
    }

    #[test]
    fn maps_a_nested_workspace_only_into_available_worktrees() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        let locked = dir.path().join("locked");
        let no_manifest = dir.path().join("no-manifest");
        for path in [&first, &second, &locked] {
            std::fs::create_dir_all(path.join("rust")).unwrap();
            std::fs::write(path.join("rust/Cargo.toml"), "").unwrap();
        }
        std::fs::create_dir_all(no_manifest.join("rust")).unwrap();
        let trees = vec![
            Worktree {
                path: first.clone(),
                bare: false,
                locked: false,
                prunable: false,
            },
            Worktree {
                path: second.clone(),
                bare: false,
                locked: false,
                prunable: false,
            },
            Worktree {
                path: locked,
                bare: false,
                locked: true,
                prunable: false,
            },
            Worktree {
                path: no_manifest,
                bare: false,
                locked: false,
                prunable: false,
            },
        ];
        assert_eq!(
            sibling_workspaces(&first.join("rust"), &trees),
            vec![first.join("rust"), second.join("rust")]
        );
    }

    fn commit_and_add_worktree(repo: &Path, worktree: &Path) {
        git(repo, &["init", "-q"]);
        std::fs::write(repo.join(".gitignore"), "target/\n").unwrap();
        git(repo, &["add", ".gitignore"]);
        git(
            repo,
            &[
                "-c",
                "user.name=Kache Test",
                "-c",
                "user.email=kache@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "base",
            ],
        );
        git(
            repo,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                worktree.to_str().unwrap(),
            ],
        );
    }

    #[cfg(unix)]
    fn assert_repository_rejects_fifo(common: bool) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let git_dir = dir.path().join("git-dir");
        let common_dir = dir.path().join("common-dir");
        for path in [&repo, &git_dir, &common_dir] {
            std::fs::create_dir(path).unwrap();
        }
        let (fifo, contents) = if common {
            std::fs::write(
                repo.join(".git"),
                format!("gitdir: {}\n", git_dir.display()),
            )
            .unwrap();
            (
                git_dir.join("commondir"),
                format!("{}\n", common_dir.display()),
            )
        } else {
            (
                repo.join(".git"),
                format!("gitdir: {}\n", git_dir.display()),
            )
        };
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let _reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        writer.write_all(contents.as_bytes()).unwrap();
        drop(writer);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "worktree_discovery::tests::repository_fifo_child",
                "--ignored",
                "--nocapture",
            ])
            .env("KACHE_TEST_FIFO_REPOSITORY", &repo)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let timed_out = loop {
            if child.try_wait().unwrap().is_some() {
                break false;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                break true;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !timed_out && output.status.success() && stdout.contains("1 passed"),
            "FIFO at {} timed out: {timed_out}; stdout: {stdout}; stderr: {}",
            fifo.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn repository_rejects_dot_git_fifo_without_blocking() {
        assert_repository_rejects_fifo(false);
    }

    #[cfg(unix)]
    #[test]
    fn repository_rejects_commondir_fifo_without_blocking() {
        assert_repository_rejects_fifo(true);
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess fixture for FIFO metadata"]
    fn repository_fifo_child() {
        let repo = PathBuf::from(std::env::var_os("KACHE_TEST_FIFO_REPOSITORY").unwrap());
        assert_eq!(repository_of(&repo, &[], None), None);
    }

    #[cfg(unix)]
    fn git_metadata_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let repo = base.join("repo");
        let git_dir = base.join("git-dir");
        let common = base.join("common");
        for path in [&repo, &git_dir, &common] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(
            repo.join(".git"),
            format!("gitdir: {}\n", git_dir.display()),
        )
        .unwrap();
        (dir, repo, git_dir, common)
    }

    #[cfg(unix)]
    #[test]
    fn repository_accepts_bounded_git_metadata_and_rejects_oversized_files() {
        let (_dir, repo, git_dir, common) = git_metadata_fixture();
        let padded = |text: String| {
            let mut text = text;
            text.push_str(&" ".repeat((1 << 16) - text.len()));
            text
        };
        let mut dot_git = padded(format!("gitdir: {}", git_dir.display()));
        std::fs::write(repo.join(".git"), &dot_git).unwrap();
        assert_eq!(repository_of(&repo, &[], None), Some(git_dir.clone()));
        dot_git.push(' ');
        std::fs::write(repo.join(".git"), &dot_git).unwrap();
        assert_eq!(repository_of(&repo, &[], None), None);

        std::fs::write(repo.join(".git"), format!("gitdir: {}", git_dir.display())).unwrap();
        let mut commondir = padded(common.display().to_string());
        std::fs::write(git_dir.join("commondir"), &commondir).unwrap();
        assert_eq!(repository_of(&repo, &[], None), Some(common));
        commondir.push(' ');
        std::fs::write(git_dir.join("commondir"), &commondir).unwrap();
        assert_eq!(repository_of(&repo, &[], None), None);
    }

    #[cfg(unix)]
    #[test]
    fn repository_rejects_invalid_or_symlinked_dot_git_files() {
        use std::os::unix::fs::symlink;

        let (dir, repo, git_dir, _) = git_metadata_fixture();
        let dot_git = repo.join(".git");
        std::fs::write(&dot_git, b"gitdir: \xff").unwrap();
        assert_eq!(repository_of(&repo, &[], None), None);
        let target = dir.path().join("git-file");
        std::fs::write(&target, format!("gitdir: {}", git_dir.display())).unwrap();
        std::fs::remove_file(&dot_git).unwrap();
        symlink(target, &dot_git).unwrap();
        assert_eq!(repository_of(&repo, &[], None), None);
    }

    #[cfg(unix)]
    #[test]
    fn repository_rejects_invalid_or_special_commondir_instead_of_falling_back() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let (dir, repo, git_dir, common) = git_metadata_fixture();
        let commondir = git_dir.join("commondir");
        assert_eq!(repository_of(&repo, &[], None), Some(git_dir));
        std::fs::write(&commondir, b"\xff").unwrap();
        assert_eq!(repository_of(&repo, &[], None), None);
        std::fs::remove_file(&commondir).unwrap();
        let target = dir.path().join("common-file");
        std::fs::write(&target, common.display().to_string()).unwrap();
        symlink(&target, &commondir).unwrap();
        assert_eq!(repository_of(&repo, &[], None), None);
        std::fs::remove_file(&commondir).unwrap();
        symlink(dir.path().join("missing"), &commondir).unwrap();
        assert_eq!(repository_of(&repo, &[], None), None);
        std::fs::remove_file(&commondir).unwrap();
        std::fs::create_dir(&commondir).unwrap();
        assert_eq!(repository_of(&repo, &[], None), None);
        std::fs::remove_dir(&commondir).unwrap();
        let _socket = UnixListener::bind(&commondir).unwrap();
        assert_eq!(repository_of(&repo, &[], None), None);
    }

    #[cfg(unix)]
    #[test]
    fn repository_checks_git_and_common_directories_before_resolving_them() {
        use std::cell::RefCell;

        let (_dir, repo, git_dir, common) = git_metadata_fixture();
        std::fs::write(git_dir.join("commondir"), common.display().to_string()).unwrap();
        let visited = RefCell::new(Vec::new());
        let local = |path: &Path| {
            visited.borrow_mut().push(path.to_path_buf());
            path != common
        };
        assert_eq!(repository_of(&repo, &[], Some(&local)), None);
        assert_eq!(*visited.borrow(), [git_dir.clone(), common.clone()]);
        visited.borrow_mut().clear();
        assert_eq!(
            repository_of(&repo, std::slice::from_ref(&git_dir), Some(&local)),
            None
        );
        assert!(visited.borrow().is_empty());
        assert_eq!(
            repository_of(&repo, std::slice::from_ref(&common), Some(&local)),
            None
        );
        assert_eq!(visited.borrow().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn repository_does_not_skip_metadata_errors() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let blocked = repo.join("blocked");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir(&blocked).unwrap();
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let error = std::fs::symlink_metadata(blocked.join(".git")).unwrap_err();
        let repository = repository_of(&blocked, &[], None);
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            assert_eq!(repository, None);
        }
        let file = repo.join("file");
        std::fs::write(&file, "").unwrap();
        assert_eq!(
            repository_of(&file, &[], None),
            Some(repo.join(".git").canonicalize().unwrap())
        );
    }

    #[cfg(unix)]
    #[test]
    fn repository_accepts_a_separate_git_directory_without_commondir() {
        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let git_dir = dir.path().join("git-dir");
        let output = Command::new("git")
            .args(["init", "-q", "--separate-git-dir"])
            .arg(&git_dir)
            .arg(&repo)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!git_dir.join("commondir").exists());
        assert_eq!(
            repository_of(&repo, &[], None),
            Some(git_dir.canonicalize().unwrap())
        );
    }

    #[test]
    fn a_repository_and_its_worktrees_share_one_key() {
        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let worktree = dir.path().join("worktree");
        std::fs::create_dir_all(repo.join("deep/inside")).unwrap();
        commit_and_add_worktree(&repo, &worktree);
        let key = repository_of(&repo, &[], None).unwrap();
        assert_eq!(key, repo.join(".git").canonicalize().unwrap());
        assert_eq!(
            repository_of(&repo.join("deep/inside"), &[], None),
            Some(key.clone())
        );
        #[cfg(unix)]
        assert_eq!(repository_of(&worktree, &[], None), Some(key));
        #[cfg(not(unix))]
        assert_eq!(repository_of(&worktree, &[], None), None);
        assert_eq!(repository_of(Path::new("/"), &[], None), None);
    }

    #[test]
    fn discovery_runs_hourly_on_a_quiet_machine_and_at_first_after_start() {
        let hour = FRESH_FOR.as_secs();
        let now = 10 * hour;
        assert!(
            due(true, true, 0, 0, now),
            "never ran: an install or upgrade"
        );
        assert!(due(true, true, now - hour, 0, now));
        assert!(
            !due(true, true, now - hour + 1, 0, now),
            "ran within the hour"
        );
        assert!(
            !due(true, true, 0, now - 60, now),
            "this process ran it, unrecorded"
        );
        assert!(!due(true, false, 0, 0, now), "a build is running");
        assert!(!due(false, true, 0, 0, now), "the shutdown pass");
        assert!(stale(now + 60, now), "a clock set back does not stop it");
        assert!(!stale(now, now), "it just ran");
    }

    #[test]
    fn the_daemon_step_runs_when_due_and_records_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::test_support::test_config(dir.path().join("cache"));
        std::fs::create_dir_all(&config.cache_dir).unwrap();
        let record = config.cache_dir.join(LAST_RUN_FILE);
        let idle = crate::maintenance::RequestClock::idle();
        let busy = crate::maintenance::RequestClock::new();

        assert!(!run(&config, Trigger::Shutdown), "never at shutdown");
        assert!(
            !run(&config, Trigger::Periodic(&busy)),
            "not during a build"
        );
        assert!(!record.exists());
        LAST_RUN.store(0, std::sync::atomic::Ordering::Relaxed);
        assert!(run(&config, Trigger::Periodic(&idle)));
        let when: u64 = std::fs::read_to_string(&record)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(!stale(when, unix_now_secs()));
        assert!(
            !run(&config, Trigger::Periodic(&idle)),
            "ran within the hour"
        );
    }

    #[test]
    fn turns_follow_the_hour_and_home_is_read_both_ways() {
        let hour = FRESH_FOR.as_secs();
        assert_eq!(turn_at(0), 0);
        assert_eq!(turn_at(hour - 1), 0);
        assert_eq!(turn_at(5 * hour + 7), 5);
        assert!(homes_from(None).is_empty());
        assert!(homes_from(Some("".into())).is_empty());
        let dir = tempfile::tempdir().unwrap();
        let homes = homes_from(Some(dir.path().as_os_str().to_owned()));
        assert_eq!(homes[0], dir.path());
        let resolved = dir.path().canonicalize().unwrap();
        assert!(homes.contains(&resolved));
        assert_eq!(homes.len(), if resolved == dir.path() { 1 } else { 2 });
    }

    #[test]
    fn git_output_refuses_a_failure_and_output_at_its_cap() {
        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let later = Instant::now() + GIT_TIMEOUT;
        // Not a repository: Git fails, whatever it printed.
        assert_eq!(
            git_output(dir.path(), &["ls-files"], GIT_TIMEOUT, later, 1 << 20),
            None
        );
        let version = git_output(dir.path(), &["--version"], GIT_TIMEOUT, later, 1 << 20).unwrap();
        assert!(version.starts_with(b"git version"));
        let cap = version.len() as u64;
        assert_eq!(
            git_output(dir.path(), &["--version"], GIT_TIMEOUT, later, cap),
            None
        );
        assert_eq!(
            git_output(
                dir.path(),
                &["--version"],
                GIT_TIMEOUT,
                Instant::now(),
                1 << 20
            ),
            None
        );
    }

    #[test]
    fn each_pass_starts_at_a_different_place() {
        assert_eq!(rotated(vec![0, 1, 2], 0), vec![0, 1, 2]);
        assert_eq!(rotated(vec![0, 1, 2], 1), vec![1, 2, 0]);
        assert_eq!(rotated(vec![0, 1, 2], 5), vec![2, 0, 1]);
        assert!(rotated(Vec::<u8>::new(), 7).is_empty());
    }

    #[test]
    fn external_candidate_turn_reaches_every_position() {
        for count in [2, 8, 16, 17, 24] {
            let starts: HashSet<_> = (0..count)
                .map(|turn| external_candidate_turn(turn as u64, count) % count as u64)
                .collect();
            assert_eq!(starts.len(), count);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn external_candidates_reach_all_repositories_as_outer_order_changes() {
        use std::cell::RefCell;
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let storage = base.join("storage");
        let backing = storage.join("backing");
        std::fs::create_dir_all(&backing).unwrap();
        let surveys: Vec<_> = (0..9)
            .map(|index| {
                let repo = base.join(format!("repo-{index}"));
                let workspace = repo.join("app");
                std::fs::create_dir_all(&workspace).unwrap();
                std::fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
                symlink(&backing, workspace.join("target")).unwrap();
                Survey {
                    trees: vec![Worktree {
                        path: repo,
                        bare: false,
                        locked: false,
                        prunable: false,
                    }],
                    targets: Vec::new(),
                    links: vec![workspace],
                    sources: Vec::new(),
                }
            })
            .collect();
        let mut original_passes = Vec::new();
        for duplicate in [false, true] {
            let config = crate::test_support::test_config(base.join(format!("cache-{duplicate}")));
            private_inventory_cache(&config.cache_dir);
            let store = Store::open(&config).unwrap();
            let visited = RefCell::new(HashSet::new());
            let mut passes = Vec::new();
            for turn in 0..2 {
                let ordered = rotated(surveys.iter().collect(), turn);
                let mut links: Vec<_> = ordered.iter().flat_map(|survey| &survey.links).collect();
                if duplicate {
                    links.extend([links[0]; 2]);
                }
                let pass = RefCell::new(Vec::new());
                inventory_external(
                    &store,
                    std::slice::from_ref(&storage),
                    Instant::now() + DISCOVERY_TIME,
                    &[],
                    links.iter().copied(),
                    links.iter().copied(),
                    |_| true,
                    |_, workspace, _, _, _, _| {
                        pass.borrow_mut().push(workspace.to_path_buf());
                        visited.borrow_mut().insert(workspace.to_path_buf());
                        Ok(true)
                    },
                    Instant::now,
                );
                let pass = pass.into_inner();
                assert_eq!(pass.len(), 8);
                passes.push(pass);
            }
            assert_eq!(visited.borrow().len(), 9);
            if duplicate {
                assert_eq!(passes, original_passes);
            } else {
                original_passes = passes;
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn external_pass_reserves_only_after_candidates_and_source_preparation() {
        use std::cell::Cell;
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let storage = base.join("storage");
        let backing = storage.join("backing");
        let workspace = base.join("workspace");
        std::fs::create_dir_all(&backing).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        symlink(&backing, workspace.join("target")).unwrap();
        let config = crate::test_support::test_config(base.join("cache"));
        private_inventory_cache(&config.cache_dir);
        let store = Store::open(&config).unwrap();
        let start = Instant::now();
        let deadline = start + Duration::from_secs(10);
        let clock = Cell::new(start);
        let empty: Vec<PathBuf> = Vec::new();
        inventory_external(
            &store,
            std::slice::from_ref(&storage),
            deadline,
            &[],
            &empty,
            &empty,
            |_| panic!("no candidates"),
            |_, _, _, _, _, _| panic!("no candidates"),
            || clock.get(),
        );
        assert!(
            !config
                .cache_dir
                .join("external-target-inventory.db")
                .exists()
        );
        inventory_external(
            &store,
            std::slice::from_ref(&storage),
            deadline,
            &[],
            std::slice::from_ref(&workspace),
            std::slice::from_ref(&workspace),
            |_| {
                clock.set(deadline);
                true
            },
            |_, _, _, _, _, _| panic!("deadline expired in source preparation"),
            || clock.get(),
        );
        assert!(
            !config
                .cache_dir
                .join("external-target-inventory.db")
                .exists()
        );
        assert_eq!(store.next_external_inventory_turn().unwrap(), 0);

        clock.set(start);
        inventory_external(
            &store,
            std::slice::from_ref(&storage),
            deadline,
            &[],
            &empty,
            std::slice::from_ref(&workspace),
            |path| {
                if path == workspace.join("target") {
                    assert_eq!(store.next_external_inventory_turn().unwrap(), 1);
                }
                true
            },
            observe_external_before_deadline,
            || clock.get(),
        );
        assert_eq!(store.external_target_observations().unwrap().len(), 1);
        assert_eq!(store.next_external_inventory_turn().unwrap(), 1);
        inventory_external(
            &store,
            std::slice::from_ref(&storage),
            deadline,
            &[],
            &empty,
            &empty,
            |_| panic!("no candidates"),
            |_, _, _, _, _, _| panic!("no candidates"),
            || clock.get(),
        );
        clock.set(deadline);
        inventory_external(
            &store,
            std::slice::from_ref(&storage),
            deadline,
            &[],
            &empty,
            std::slice::from_ref(&workspace),
            |_| panic!("expired"),
            |_, _, _, _, _, _| panic!("expired"),
            || clock.get(),
        );
        assert_eq!(store.next_external_inventory_turn().unwrap(), 1);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn external_source_preparation_is_deduplicated_bounded_and_rotated() {
        use std::cell::{Cell, RefCell};
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let storage = base.join("storage");
        let backing = storage.join("backing");
        let workspace = base.join("workspace");
        let source_parent = base.join("sources");
        std::fs::create_dir_all(&backing).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        symlink(&backing, workspace.join("target")).unwrap();
        let sources: Vec<_> = (0..40)
            .map(|index| {
                let source = source_parent.join(format!("source-{index:02}"));
                std::fs::create_dir_all(&source).unwrap();
                source
            })
            .collect();
        let nonlocal = sources[3].clone();
        let missing = source_parent.join("missing");
        let mut paths = vec![sources[0].clone(); 40];
        paths.extend(sources.iter().cloned());
        paths.push(missing.clone());
        let config = crate::test_support::test_config(base.join("cache"));
        private_inventory_cache(&config.cache_dir);
        let store = Store::open(&config).unwrap();
        for timed in [true, false] {
            let mut first_probes = Vec::new();
            let mut all_probes = HashSet::new();
            for turn in 0..41 {
                let start = Instant::now();
                let clock = Cell::new(start);
                let probes = RefCell::new(Vec::new());
                let observed = RefCell::new(Vec::new());
                inventory_external(
                    &store,
                    std::slice::from_ref(&storage),
                    start + Duration::from_secs(12),
                    &[],
                    &paths,
                    std::slice::from_ref(&workspace),
                    |path| {
                        if path.starts_with(&source_parent) {
                            probes.borrow_mut().push(path.to_path_buf());
                            if timed {
                                clock.set(clock.get() + Duration::from_secs(1));
                            }
                        }
                        path != nonlocal
                    },
                    |_, candidate, _, prepared, _, _| {
                        observed.borrow_mut().push(candidate.to_path_buf());
                        assert!(prepared.len() <= 16);
                        assert!(!prepared.contains(&nonlocal));
                        assert!(!prepared.contains(&missing));
                        Ok(true)
                    },
                    || clock.get(),
                );
                let probes = probes.into_inner();
                assert_eq!(observed.into_inner(), vec![workspace.clone()]);
                assert!(!probes.is_empty());
                assert!(
                    probes.len() <= 16,
                    "too many source probes: {}",
                    probes.len()
                );
                assert_eq!(probes.iter().collect::<HashSet<_>>().len(), probes.len());
                all_probes.extend(probes.iter().cloned());
                if turn == 0 {
                    first_probes = probes;
                } else if turn == 1 {
                    assert_ne!(first_probes[0], probes[0]);
                }
            }
            assert_eq!(all_probes, sources.iter().cloned().collect());
        }
    }

    #[cfg(unix)]
    #[test]
    fn listing_a_worktree_never_runs_its_filesystem_monitor() {
        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        commit_and_add_worktree(&repo, &dir.path().join("worktree"));
        let target = cargo_target(&repo.join("app"));
        std::fs::write(repo.join(".git/info/exclude"), "target\n").unwrap();
        std::fs::create_dir(repo.join("link")).unwrap();
        std::os::unix::fs::symlink(&target, repo.join("link/target")).unwrap();
        let ran = dir.path().join("monitor-ran");
        let hook = dir.path().join("monitor");
        std::fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", ran.display())).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        git(&repo, &["config", "core.fsmonitor", hook.to_str().unwrap()]);
        // Git would run it for a listing like discovery's.
        let _ = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args([
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "--directory",
            ])
            .output();
        if !ran.exists() {
            return;
        }
        std::fs::remove_file(&ran).unwrap();

        let found = targets_in_worktree(
            &repo.canonicalize().unwrap(),
            Instant::now() + LISTING_TIMEOUT,
            true,
        );
        assert_eq!(found.targets.len(), 1, "{:?}", found.targets);
        assert_eq!(found.targets[0].0, target.canonicalize().unwrap());
        assert_eq!(found.links, vec![repo.canonicalize().unwrap().join("link")]);
        assert!(!ran.exists(), "discovery ran the repository's monitor");
    }

    #[test]
    fn discovery_leaves_home_and_protected_folders_alone() {
        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        // Git gets the home as spelled; the shield gets it both ways, as
        // `discover` passes it (`/var` is `/private/var` on macOS, and Windows
        // resolves to a `\\?\` path Git cannot create a worktree under).
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let homes = [home.clone(), home.canonicalize().unwrap()];
        // A dotfiles repository at home, with a worktree in Documents.
        commit_and_add_worktree(&home, &home.join("Documents/notes"));
        let built = cargo_target(&home.join("tools/rust"));
        cargo_target(&home.join("tools/other"));
        cargo_target(&home.join("Documents/notes/app"));
        let config = crate::test_support::test_config(dir.path().join("cache"));
        let store = Store::open(&config).unwrap();
        store
            .remember_target_root(&built, &home.join("tools/rust"))
            .unwrap();

        let pass =
            |deadline| discover_within(&store, targets_only(&[]), deadline, &homes, 0).unwrap();
        assert_eq!(pass(Instant::now() + DISCOVERY_TIME), 0);
        assert_eq!(store.tracked_target_roots(0).unwrap().len(), 1);
    }

    #[test]
    fn a_spent_pass_starts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let mut seen = HashSet::new();
        let starts = || vec![(repo.clone(), None)];
        assert!(
            by_repository(
                starts(),
                &mut seen,
                0,
                Instant::now() + LISTING_TIMEOUT,
                &[],
                None
            )
            .is_empty()
        );
        assert!(by_repository(starts(), &mut seen, 5, Instant::now(), &[], None).is_empty());
        assert!(seen.is_empty());
        assert_eq!(
            by_repository(
                starts(),
                &mut seen,
                5,
                Instant::now() + LISTING_TIMEOUT,
                &[],
                None
            )
            .len(),
            1
        );
    }

    #[test]
    fn discovery_crawls_every_worktree_of_a_known_repository() {
        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let sibling = dir.path().join("sibling");
        std::fs::create_dir_all(&repo).unwrap();
        commit_and_add_worktree(&repo, &sibling);
        let built = cargo_target(&repo.join("rust"));
        // Workspaces no build through kache used, at other paths than the
        // one it built: in the same worktree and in a sibling.
        let tool = cargo_target(&repo.join("tools/gen"));
        let extension = cargo_target(&sibling.join("extensions/kgw"));
        // A repository beside a known worktree is crawled too, one hop out.
        let neighbour = dir.path().join("neighbour");
        std::fs::create_dir_all(&neighbour).unwrap();
        commit_and_add_worktree(&neighbour, &dir.path().join("elsewhere/neighbour-wt"));
        let beside = cargo_target(&neighbour.join("app"));
        // One further away is not.
        let unrelated = dir.path().join("elsewhere/deeper/unrelated");
        std::fs::create_dir_all(&unrelated).unwrap();
        commit_and_add_worktree(
            &unrelated,
            &dir.path().join("elsewhere/deeper/unrelated-wt"),
        );
        cargo_target(&unrelated.join("rust"));

        let config = crate::test_support::test_config(dir.path().join("cache"));
        let store = Store::open(&config).unwrap();
        store
            .remember_target_root(&built, &repo.join("rust"))
            .unwrap();
        let pass = || {
            discover_within(
                &store,
                targets_only(&[]),
                Instant::now() + DISCOVERY_TIME,
                &[],
                0,
            )
        };
        assert_eq!(pass().unwrap(), 3);
        assert_eq!(pass().unwrap(), 0, "already known");
        let mut discovered: Vec<_> = store
            .tracked_target_roots(0)
            .unwrap()
            .into_iter()
            .filter(|root| root.discovered)
            .map(|root| root.path)
            .collect();
        discovered.sort();
        let mut expected = vec![
            tool.canonicalize().unwrap(),
            extension.canonicalize().unwrap(),
            beside.canonicalize().unwrap(),
        ];
        expected.sort();
        assert_eq!(discovered, expected);
    }

    #[cfg(unix)]
    #[test]
    fn unusable_configured_roots_do_not_stop_ordinary_discovery() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let repo = base.join("ordinary/repo");
        let sibling = base.join("ordinary/sibling");
        std::fs::create_dir_all(&repo).unwrap();
        commit_and_add_worktree(&repo, &sibling);
        let built = cargo_target(&repo.join("built"));
        let ordinary = cargo_target(&sibling.join("other"));
        let nonlocal = base.join("nonlocal");
        std::fs::create_dir_all(nonlocal.join("child/.git")).unwrap();
        let file = base.join("not-a-directory");
        std::fs::write(&file, "not a directory").unwrap();
        let dangling = base.join("dangling");
        symlink(base.join("missing"), &dangling).unwrap();
        let repository_roots = [base.join("missing"), file, dangling, nonlocal.clone()];
        let target_roots = [base.join("storage")];
        let config = crate::test_support::test_config(base.join("cache"));
        std::fs::create_dir_all(&config.cache_dir).unwrap();
        std::fs::set_permissions(&config.cache_dir, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let store = Store::open(&config).unwrap();
        store
            .remember_target_root(&built, &repo.join("built"))
            .unwrap();
        let roots = ExternalRoots {
            targets: &target_roots,
            repositories: &repository_roots,
        };
        assert_eq!(
            discover_within_using(
                &store,
                roots,
                Instant::now() + DISCOVERY_TIME,
                &[],
                0,
                |path| {
                    assert!(path == nonlocal || !path.starts_with(&nonlocal));
                    path != nonlocal
                },
                |_, _, _, _, _, _| panic!("no external links"),
            )
            .unwrap(),
            1
        );
        assert!(
            store
                .tracked_target_roots(0)
                .unwrap()
                .iter()
                .any(|row| row.path == ordinary && row.discovered)
        );
        assert!(store.external_target_observations().unwrap().is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn configured_roots_find_unseeded_external_links_as_inventory_only() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "worktree_discovery::tests::configured_roots_unseeded_child",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_str(&stdout[stdout.find('{').unwrap()..=stdout.rfind('}').unwrap()])
                .unwrap();
        assert_eq!(json["targets"], serde_json::json!([]));
        let external = json["external_targets"].as_array().unwrap();
        assert_eq!(external.len(), 2);
        assert!(external.iter().all(|row| row["status"] == "inventory_only"));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[ignore = "isolated discovery and targets command fixture"]
    fn configured_roots_unseeded_child() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let repo = base.join("source/repo");
        let sibling = base.join("source/sibling");
        let storage = base.join("storage");
        let backing = storage.join("shared");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&backing).unwrap();
        commit_and_add_worktree(&repo, &sibling);
        for worktree in [&repo, &sibling] {
            std::fs::write(worktree.join(".gitignore"), "target\n").unwrap();
        }
        for workspace in [repo.join("app"), sibling.join("tool")] {
            std::fs::create_dir(&workspace).unwrap();
            std::fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
            symlink(&backing, workspace.join("target")).unwrap();
        }
        for (worktree, workspace) in [(&repo, repo.join("app")), (&sibling, sibling.join("tool"))] {
            assert!(
                targets_in_worktree(worktree, Instant::now() + DISCOVERY_TIME, true)
                    .links
                    .contains(&workspace)
            );
        }
        let tagged = cargo_target(&sibling.join("unused"));
        let nested = base.join("source/nested/deep");
        std::fs::create_dir_all(&nested).unwrap();
        git(&nested, &["init", "-q"]);
        std::fs::write(nested.join(".gitignore"), "target\n").unwrap();
        symlink(&backing, nested.join("target")).unwrap();
        assert!(!backing.join("CACHEDIR.TAG").exists());
        assert_eq!(crate::cache_fs::probe(&base).is_local, Some(true));

        let idle = crate::maintenance::RequestClock::idle();
        for (name, repository_roots, target_roots, expected) in [
            ("off", vec![], vec![storage.clone()], false),
            ("no-storage", vec![repo.clone()], vec![], false),
            (
                "repository",
                vec![repo.clone()],
                vec![storage.clone()],
                true,
            ),
            (
                "parent",
                vec![base.join("source")],
                vec![storage.clone()],
                true,
            ),
        ] {
            let mut config = crate::test_support::test_config(base.join(format!("cache-{name}")));
            config.external_repository_roots = repository_roots;
            config.external_target_roots = target_roots;
            private_inventory_cache(&config.cache_dir);
            let store = Store::open(&config).unwrap();
            assert!(store.tracked_target_roots(0).unwrap().is_empty());
            LAST_RUN.store(0, std::sync::atomic::Ordering::Relaxed);
            assert!(run(&config, Trigger::Periodic(&idle)));
            assert!(store.tracked_target_roots(0).unwrap().is_empty());
            let observations = store.external_target_observations().unwrap();
            let workspaces: HashSet<_> = observations
                .iter()
                .map(|row| row.workspace_path.clone())
                .collect();
            assert_eq!(
                workspaces,
                if expected {
                    HashSet::from([repo.join("app"), sibling.join("tool")])
                } else {
                    HashSet::new()
                },
                "{name}"
            );
            assert!(tagged.exists());
            if name == "parent" {
                crate::cli::targets(&config, true).unwrap();
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn discovery_inventories_ignored_external_symlinks_without_tracking_targets() {
        use std::os::unix::fs::symlink;

        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        if crate::cache_fs::probe(dir.path()).is_local != Some(true) {
            return;
        }
        let storage = dir.path().join("storage");
        let repo = storage.join("source/repo");
        let sibling = storage.join("source/sibling");
        std::fs::create_dir_all(&repo).unwrap();
        commit_and_add_worktree(&repo, &sibling);
        std::fs::write(repo.join(".gitignore"), "target\n").unwrap();
        std::fs::write(sibling.join(".gitignore"), "target\n!rust/target\n").unwrap();
        let built = cargo_target(&repo.join("rust"));
        let shared = storage.join("build/shared");
        std::fs::create_dir_all(&shared).unwrap();
        assert!(!shared.join("CACHEDIR.TAG").exists());
        symlink(&shared, repo.join("target")).unwrap();
        let tagged = cargo_target(&storage.join("build/tagged-workspace"));
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let untagged_source = sibling.join("untagged");
        std::fs::create_dir_all(untagged_source.join("target")).unwrap();
        std::fs::write(untagged_source.join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::create_dir(sibling.join("regular")).unwrap();
        std::fs::write(sibling.join("regular/target"), "not a link").unwrap();
        for (workspace, backing) in [
            (sibling.join("app"), shared.clone()),
            (sibling.join("alternate"), shared.clone()),
            (sibling.join("tagged"), tagged.clone()),
            (sibling.join("outside"), outside.clone()),
            (sibling.join("missing"), dir.path().join("missing")),
            (sibling.join("source-link"), repo.clone()),
            (sibling.join("untagged-source-link"), untagged_source),
            (sibling.join("root-link"), storage.clone()),
            (sibling.join("rust"), tagged),
        ] {
            std::fs::create_dir_all(&workspace).unwrap();
            std::fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
            symlink(backing, workspace.join("target")).unwrap();
        }
        let listing = git_output(
            &sibling,
            &[
                "ls-files",
                "-z",
                "--others",
                "--ignored",
                "--exclude-standard",
                "--directory",
            ],
            LISTING_TIMEOUT,
            Instant::now() + LISTING_TIMEOUT,
            MAX_LISTING_BYTES,
        )
        .unwrap();
        assert!(
            listing
                .split(|byte| *byte == 0)
                .any(|entry| entry == b"app/target")
        );
        assert!(
            !listing
                .split(|byte| *byte == 0)
                .any(|entry| entry == b"rust/target")
        );

        let mut config = crate::test_support::test_config(dir.path().join("cache"));
        config.external_target_roots = vec![dir.path().join("absent-root"), storage.clone()];
        private_inventory_cache(&config.cache_dir);
        let store = Store::open(&config).unwrap();
        store
            .remember_target_root(&built, &repo.join("rust"))
            .unwrap();
        let tracked = store.tracked_target_roots(0).unwrap();
        assert_eq!(tracked.len(), 1);

        assert_eq!(
            discover(&store, targets_only(&[]), DISCOVERY_TIME, 0).unwrap(),
            0
        );
        assert!(
            !config
                .cache_dir
                .join("external-target-inventory.db")
                .exists()
        );
        assert_eq!(store.tracked_target_roots(0).unwrap(), tracked);
        assert!(store.external_target_observations().unwrap().is_empty());
        assert_eq!(
            discover_within(
                &store,
                targets_only(&config.external_target_roots),
                Instant::now(),
                &[],
                0
            )
            .unwrap(),
            0
        );
        assert!(store.external_target_observations().unwrap().is_empty());

        let isolated_config = crate::test_support::test_config(dir.path().join("cache-locality"));
        private_inventory_cache(&isolated_config.cache_dir);
        let isolated = Store::open(&isolated_config).unwrap();
        isolated
            .remember_target_root(&built, &repo.join("rust"))
            .unwrap();
        let local = |path: &Path| crate::cache_fs::probe(path).is_local == Some(true);
        discover_within_using(
            &isolated,
            targets_only(&config.external_target_roots),
            Instant::now() + DISCOVERY_TIME,
            &[],
            0,
            |path| path != storage && local(path),
            observe_external_before_deadline,
        )
        .unwrap();
        assert!(isolated.external_target_observations().unwrap().is_empty());
        discover_within_using(
            &isolated,
            targets_only(&config.external_target_roots),
            Instant::now() + DISCOVERY_TIME,
            &[],
            0,
            |path| path != shared && path != sibling.join("tagged") && local(path),
            observe_external_before_deadline,
        )
        .unwrap();
        assert!(isolated.external_target_observations().unwrap().is_empty());

        let found = discover(
            &store,
            targets_only(&config.external_target_roots),
            DISCOVERY_TIME,
            0,
        )
        .unwrap();
        let observations = store.external_target_observations().unwrap();
        let workspaces: Vec<_> = observations
            .iter()
            .map(|row| row.workspace_path.clone())
            .collect();
        let mut expected = vec![
            repo.clone(),
            sibling.join("alternate"),
            sibling.join("app"),
            sibling.join("tagged"),
        ];
        expected.sort();
        assert_eq!(workspaces, expected);
        let app = observations
            .iter()
            .find(|row| row.workspace_path == sibling.join("app"))
            .unwrap();
        let alternate = observations
            .iter()
            .find(|row| row.workspace_path == sibling.join("alternate"))
            .unwrap();
        assert_eq!(
            app.snapshot.backing_identity,
            alternate.snapshot.backing_identity
        );
        assert_eq!(app.snapshot.backing_path, shared.canonicalize().unwrap());
        assert_ne!(
            app.snapshot.symlink_identity,
            alternate.snapshot.symlink_identity
        );
        assert!(
            observations
                .iter()
                .all(|row| row.allowed_storage_root == storage)
        );
        assert_eq!(found, 0);
        assert_eq!(store.tracked_target_roots(0).unwrap(), tracked);

        let old_app = app.clone();
        let app_link = sibling.join("app/target");
        std::fs::remove_file(&app_link).unwrap();
        symlink(&outside, &app_link).unwrap();
        assert_eq!(
            discover(
                &store,
                targets_only(&config.external_target_roots),
                DISCOVERY_TIME,
                FRESH_FOR.as_secs()
            )
            .unwrap(),
            0
        );
        let observations = store.external_target_observations().unwrap();
        let app = observations
            .iter()
            .find(|row| row.workspace_path == sibling.join("app"))
            .unwrap();
        assert_eq!(app, &old_app);
        assert_eq!(store.tracked_target_roots(0).unwrap(), tracked);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn external_inventory_error_keeps_ordinary_discovery() {
        use std::cell::RefCell;
        use std::os::unix::fs::symlink;
        use std::sync::{Arc, Mutex};

        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let repo = base.join("source/repo");
        let sibling = base.join("source/sibling");
        let storage = base.join("storage");
        let backing = storage.join("backing");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&backing).unwrap();
        commit_and_add_worktree(&repo, &sibling);
        std::fs::write(sibling.join(".gitignore"), "target\n").unwrap();
        let built = cargo_target(&repo.join("built"));
        let normal = cargo_target(&sibling.join("normal"));
        let workspace = sibling.join("external");
        let later = sibling.join("later");
        for source in [&workspace, &later] {
            std::fs::create_dir(source).unwrap();
            std::fs::write(source.join("Cargo.toml"), "[workspace]\n").unwrap();
            symlink(&backing, source.join("target")).unwrap();
        }

        let mut first_observations = HashSet::new();
        for turn in [0, 1] {
            let config = crate::test_support::test_config(base.join(format!("cache-{turn}")));
            private_inventory_cache(&config.cache_dir);
            let store = Store::open(&config).unwrap();
            store
                .remember_target_root(&built, &repo.join("built"))
                .unwrap();
            if turn == 1 {
                assert_eq!(
                    store
                        .reserve_external_inventory_turn(Instant::now() + DISCOVERY_TIME)
                        .unwrap(),
                    Some(0)
                );
            }
            let before_snapshot = RefCell::new(Vec::new());
            let calls = RefCell::new(Vec::new());
            let output = Arc::new(Mutex::new(Vec::new()));
            let writer = Arc::clone(&output);
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_writer(move || Capture(Arc::clone(&writer)))
                .finish();
            let result = tracing::subscriber::with_default(subscriber, || {
                discover_within_using(
                    &store,
                    targets_only(std::slice::from_ref(&storage)),
                    Instant::now() + DISCOVERY_TIME,
                    &[],
                    turn,
                    |path| {
                        if path == workspace.join("target") || path == later.join("target") {
                            let registered = store
                                .tracked_target_roots(0)
                                .unwrap()
                                .iter()
                                .any(|row| row.path == normal && row.discovered);
                            before_snapshot
                                .borrow_mut()
                                .push((path.to_path_buf(), registered));
                        }
                        true
                    },
                    |_, observed_workspace, observed_root, _, _, _| {
                        assert_eq!(observed_root, storage);
                        calls.borrow_mut().push(observed_workspace.to_path_buf());
                        Err(anyhow::anyhow!("injected inventory failure"))
                    },
                )
            });
            let calls = calls.into_inner();
            assert_eq!(calls.len(), 1, "the external slice must stop on failure");
            let observed_workspace = &calls[0];
            assert!(observed_workspace == &workspace || observed_workspace == &later);
            first_observations.insert(observed_workspace.clone());
            assert_eq!(
                before_snapshot.into_inner(),
                vec![(observed_workspace.join("target"), true)],
                "ordinary target must be registered before external inventory: {result:?}"
            );
            assert_eq!(result.unwrap(), 1);
            let rows = store.tracked_target_roots(0).unwrap();
            assert_eq!(rows.len(), 2);
            assert!(rows.iter().any(|row| row.path == normal && row.discovered));
            assert!(store.external_target_observations().unwrap().is_empty());
            let log = String::from_utf8(output.lock().unwrap().clone()).unwrap();
            for expected in [
                "WARN",
                "injected inventory failure",
                observed_workspace.to_str().unwrap(),
                storage.to_str().unwrap(),
            ] {
                assert!(log.contains(expected), "{expected} missing from {log}");
            }

            assert_eq!(
                discover_within_using(
                    &store,
                    targets_only(std::slice::from_ref(&storage)),
                    Instant::now() + DISCOVERY_TIME,
                    &[],
                    0,
                    |_| true,
                    observe_external_before_deadline,
                )
                .unwrap(),
                0
            );
            let observations = store.external_target_observations().unwrap();
            assert_eq!(observations.len(), 2);
            assert!(
                observations
                    .iter()
                    .any(|row| row.workspace_path == workspace)
            );
            assert!(observations.iter().any(|row| row.workspace_path == later));
            assert_eq!(
                discover_within_using(
                    &store,
                    targets_only(&[]),
                    Instant::now() + DISCOVERY_TIME,
                    &[],
                    0,
                    |_| panic!("locality must not be checked without external roots"),
                    |_, _, _, _, _, _| panic!("external observation must not run without roots"),
                )
                .unwrap(),
                0
            );
        }
        assert_eq!(first_observations, HashSet::from([workspace, later]));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn busy_inventory_keeps_ordinary_discovery_and_does_not_consume_a_turn() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "worktree_discovery::tests::busy_inventory_child",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[ignore = "subprocess fixture for inventory contention"]
    fn busy_inventory_child() {
        use std::cell::Cell;
        use std::os::unix::fs::symlink;
        use std::sync::{Arc, Mutex};

        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let repo = base.join("source/repo");
        let sibling = base.join("source/sibling");
        let storage = base.join("storage");
        let backing = storage.join("backing");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&backing).unwrap();
        commit_and_add_worktree(&repo, &sibling);
        std::fs::write(sibling.join(".gitignore"), "target\n").unwrap();
        let built = cargo_target(&repo.join("built"));
        let normal = cargo_target(&sibling.join("normal"));
        let workspace = sibling.join("external");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
        symlink(&backing, workspace.join("target")).unwrap();
        let config = crate::test_support::test_config(base.join("cache"));
        private_inventory_cache(&config.cache_dir);
        let store = Store::open(&config).unwrap();
        store
            .remember_target_root(&built, &repo.join("built"))
            .unwrap();
        assert_eq!(
            store
                .reserve_external_inventory_turn(Instant::now() + DISCOVERY_TIME)
                .unwrap(),
            Some(0)
        );
        let lock =
            std::fs::File::open(config.cache_dir.join("external-target-inventory.lock")).unwrap();
        lock.lock().unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&output);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || Capture(Arc::clone(&writer)))
            .finish();
        let observed = Cell::new(false);
        let result = tracing::subscriber::with_default(subscriber, || {
            discover_within_using(
                &store,
                targets_only(std::slice::from_ref(&storage)),
                Instant::now() + DISCOVERY_TIME,
                &[],
                0,
                |_| true,
                |_, _, _, _, _, _| {
                    observed.set(true);
                    Ok(true)
                },
            )
        });
        lock.unlock().unwrap();
        assert_eq!(result.unwrap(), 1);
        assert!(!observed.get());
        assert!(
            store
                .tracked_target_roots(0)
                .unwrap()
                .iter()
                .any(|row| row.path == normal && row.discovered)
        );
        assert_eq!(store.next_external_inventory_turn().unwrap(), 1);
        let log = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("cannot read external target inventory pass cursor"),
            "{log}"
        );
        assert!(log.contains("busy"), "{log}");

        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&output);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || Capture(Arc::clone(&writer)))
            .finish();
        let locked = Cell::new(false);
        let result = tracing::subscriber::with_default(subscriber, || {
            discover_within_using(
                &store,
                targets_only(std::slice::from_ref(&storage)),
                Instant::now() + DISCOVERY_TIME,
                &[],
                0,
                |_| {
                    if !locked.replace(true) {
                        lock.lock().unwrap();
                    }
                    true
                },
                |_, _, _, _, _, _| {
                    observed.set(true);
                    Ok(true)
                },
            )
        });
        if locked.get() {
            lock.unlock().unwrap();
        }
        assert!(locked.get());
        assert_eq!(result.unwrap(), 0);
        assert!(!observed.get());
        assert_eq!(store.next_external_inventory_turn().unwrap(), 1);
        let log = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("cannot reserve external target inventory pass"),
            "{log}"
        );
        assert!(log.contains("busy"), "{log}");
        assert_eq!(
            store
                .reserve_external_inventory_turn(Instant::now() + DISCOVERY_TIME)
                .unwrap(),
            Some(1)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn paused_inventory_cursor_transaction_does_not_block_cargo_leases() {
        use std::sync::mpsc;

        let dir = tempfile::tempdir().unwrap();
        let config = crate::test_support::test_config(dir.path().join("cache"));
        private_inventory_cache(&config.cache_dir);
        let store = Store::open(&config).unwrap();
        assert_eq!(
            store
                .reserve_external_inventory_turn(Instant::now() + DISCOVERY_TIME)
                .unwrap(),
            Some(0)
        );
        let writer = Store::open(&config).unwrap();
        let _first =
            crate::target_use::shared(&config.cache_dir, "cargo build", &mut Vec::new()).unwrap();
        let path = config.cache_dir.join("external-target-inventory.db");
        let reader = rusqlite::Connection::open(&path).unwrap();
        let probe = rusqlite::Connection::open(&path).unwrap();
        probe.busy_timeout(Duration::ZERO).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let current: i64 = reader
            .query_row(
                "SELECT next_turn FROM external_target_inventory_cursor WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current, 1);
        probe.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let (lease_tx, lease_rx) = mpsc::channel();
        let cache = config.cache_dir.clone();
        let (transaction_active, acquired, still_paused, result) = std::thread::scope(|scope| {
            let reserve = scope.spawn(move || {
                started_tx.send(()).unwrap();
                let result =
                    writer.reserve_external_inventory_turn(Instant::now() + DISCOVERY_TIME);
                done_tx.send(()).unwrap();
                result
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let limit = Instant::now() + Duration::from_secs(2);
            let active = loop {
                match probe.execute_batch("BEGIN IMMEDIATE") {
                    Ok(()) => probe.execute_batch("ROLLBACK").unwrap(),
                    Err(error)
                        if matches!(
                            error.sqlite_error_code(),
                            Some(
                                rusqlite::ErrorCode::DatabaseBusy
                                    | rusqlite::ErrorCode::DatabaseLocked
                            )
                        ) =>
                    {
                        break true;
                    }
                    Err(error) => panic!("cursor lock probe failed: {error}"),
                }
                if Instant::now() >= limit || done_rx.try_recv().is_ok() {
                    break false;
                }
                std::thread::yield_now();
            };
            let second = scope.spawn(move || {
                let mut notice = Vec::new();
                let lease = crate::target_use::shared(&cache, "cargo test", &mut notice).unwrap();
                lease_tx.send((lease, notice)).unwrap();
            });
            let acquired = lease_rx.recv_timeout(Duration::from_millis(150));
            let still_paused = matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
            reader.execute_batch("COMMIT").unwrap();
            second.join().unwrap();
            (active, acquired, still_paused, reserve.join().unwrap())
        });
        assert!(
            transaction_active,
            "cursor transaction never acquired its SQLite write lock"
        );
        let (_second, notice) =
            acquired.expect("second Cargo lease waited for the cursor transaction");
        assert!(notice.is_empty());
        assert!(
            still_paused,
            "cursor transaction completed before the second lease"
        );
        assert_eq!(result.unwrap(), Some(1));
        assert_eq!(store.next_external_inventory_turn().unwrap(), 2);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn daily_external_passes_reach_all_candidates_after_store_reopens() {
        use std::os::unix::fs::symlink;

        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let repo = base.join("source/repo");
        let sibling = base.join("source/sibling");
        let storage = base.join("storage");
        let backing = storage.join("backing");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&backing).unwrap();
        commit_and_add_worktree(&repo, &sibling);
        std::fs::write(sibling.join(".gitignore"), "target\n").unwrap();
        let built = cargo_target(&repo.join("built"));
        let workspaces: HashSet<_> = (0..12)
            .map(|index| {
                let workspace = sibling.join(format!("app-{index:02}"));
                std::fs::create_dir(&workspace).unwrap();
                std::fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
                symlink(&backing, workspace.join("target")).unwrap();
                workspace
            })
            .collect();
        let config = crate::test_support::test_config(base.join("cache"));
        private_inventory_cache(&config.cache_dir);
        let store = Store::open(&config).unwrap();
        store
            .remember_target_root(&built, &repo.join("built"))
            .unwrap();
        drop(store);
        for day in 0..2 {
            let store = Store::open(&config).unwrap();
            assert_eq!(
                discover(
                    &store,
                    targets_only(std::slice::from_ref(&storage)),
                    DISCOVERY_TIME,
                    day * 24 * 3600
                )
                .unwrap(),
                0
            );
            assert_eq!(
                store.external_target_observations().unwrap().len(),
                if day == 0 { 8 } else { 12 }
            );
        }
        let store = Store::open(&config).unwrap();
        let visited: HashSet<_> = store
            .external_target_observations()
            .unwrap()
            .into_iter()
            .map(|row| row.workspace_path)
            .collect();
        assert_eq!(visited, workspaces);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_inventory_caps_records_and_rotates_candidates() {
        use std::os::unix::fs::{OpenOptionsExt, symlink};

        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        if crate::cache_fs::probe(dir.path()).is_local != Some(true) {
            return;
        }
        let repo = dir.path().join("source/repo");
        let sibling = dir.path().join("source/sibling");
        let storage = dir.path().join("storage");
        let backing = storage.join("backing");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&backing).unwrap();
        commit_and_add_worktree(&repo, &sibling);
        std::fs::write(sibling.join(".gitignore"), "target\n").unwrap();
        let built = cargo_target(&repo.join("built"));
        for index in 0..(2 * MAX_EXTERNAL_RECORDS + 1) {
            let workspace = sibling.join(format!("app-{index:02}"));
            std::fs::create_dir(&workspace).unwrap();
            std::fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
            symlink(&backing, workspace.join("target")).unwrap();
        }
        let mut config = crate::test_support::test_config(dir.path().join("cache"));
        config.external_target_roots = vec![storage];
        private_inventory_cache(&config.cache_dir);
        let store = Store::open(&config).unwrap();
        store
            .remember_target_root(&built, &repo.join("built"))
            .unwrap();
        let tracked = store.tracked_target_roots(0).unwrap();
        assert_eq!(tracked.len(), 1);
        let workspace = sibling.join("app-00");
        let sources: Vec<_> = [repo.clone(), sibling.clone()]
            .into_iter()
            .chain(
                (0..2 * MAX_EXTERNAL_RECORDS + 1)
                    .map(|index| sibling.join(format!("app-{index:02}"))),
            )
            .collect();
        let root = &config.external_target_roots[0];
        let snapshot =
            kache_store::filesystem::snapshot_workspace_target(&workspace, root, &sources).unwrap();
        assert!(
            !observe_external_before_deadline(
                &store,
                &workspace,
                root,
                &sources,
                &snapshot,
                Instant::now(),
            )
            .unwrap()
        );
        assert!(store.external_target_observations().unwrap().is_empty());
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(config.cache_dir.join("external-target-inventory.db"))
            .unwrap();

        assert_eq!(
            discover(
                &store,
                targets_only(&config.external_target_roots),
                DISCOVERY_TIME,
                0
            )
            .unwrap(),
            0
        );
        assert_eq!(
            store.external_target_observations().unwrap().len(),
            MAX_EXTERNAL_RECORDS
        );
        assert_eq!(store.tracked_target_roots(0).unwrap(), tracked);
        assert_eq!(
            discover(
                &store,
                targets_only(&config.external_target_roots),
                DISCOVERY_TIME,
                FRESH_FOR.as_secs()
            )
            .unwrap(),
            0
        );
        assert_eq!(
            store.external_target_observations().unwrap().len(),
            2 * MAX_EXTERNAL_RECORDS
        );
        assert_eq!(store.tracked_target_roots(0).unwrap(), tracked);
        assert_eq!(
            discover(
                &store,
                targets_only(&config.external_target_roots),
                DISCOVERY_TIME,
                2 * FRESH_FOR.as_secs()
            )
            .unwrap(),
            0
        );
        assert_eq!(
            store.external_target_observations().unwrap().len(),
            2 * MAX_EXTERNAL_RECORDS + 1
        );
        assert_eq!(store.tracked_target_roots(0).unwrap(), tracked);
    }

    #[test]
    fn daemon_finds_a_sibling_target_without_claiming_a_build_used_it() {
        if Command::new("git")
            .arg("--version")
            .output()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let sibling = dir.path().join("sibling");
        let cache = dir.path().join("cache");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=Kache Test",
                "-c",
                "user.email=kache@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "base",
            ],
        );
        git(
            &repo,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                sibling.to_str().unwrap(),
            ],
        );
        let original = cargo_target(&repo.join("rust"));
        let found = cargo_target(&sibling.join("rust"));
        let config = crate::test_support::test_config(cache);
        let store = Store::open(&config).unwrap();
        store
            .remember_target_root(&original, &repo.join("rust"))
            .unwrap();

        assert_eq!(
            discover(&store, targets_only(&[]), DISCOVERY_TIME, 0).unwrap(),
            1
        );
        assert_eq!(
            discover(&store, targets_only(&[]), DISCOVERY_TIME, 0).unwrap(),
            0
        );
        let roots = store.tracked_target_roots(0).unwrap();
        assert_eq!(roots.len(), 2);
        let sibling_row = roots
            .iter()
            .find(|root| root.path == found.canonicalize().unwrap())
            .unwrap();
        assert!(sibling_row.discovered);
        assert_eq!(
            sibling_row.workspace_root,
            sibling.join("rust").canonicalize().unwrap()
        );
        assert_eq!(sibling_row.rustc, None);

        let old_identity = sibling_row.identity;
        std::fs::rename(&found, sibling.join("old-target")).unwrap();
        cargo_target(&sibling.join("rust"));
        assert_eq!(
            discover(&store, targets_only(&[]), DISCOVERY_TIME, 0).unwrap(),
            1
        );
        let replaced = store
            .tracked_target_roots(0)
            .unwrap()
            .into_iter()
            .find(|root| root.path == found.canonicalize().unwrap())
            .unwrap();
        assert!(replaced.discovered);
        assert_ne!(replaced.identity, old_identity);

        store
            .remember_target_root(&found, &sibling.join("rust"))
            .unwrap();
        let row = store
            .tracked_target_roots(0)
            .unwrap()
            .into_iter()
            .find(|root| root.path == found)
            .unwrap();
        assert_eq!(store.tracked_target_roots(0).unwrap().len(), 2);
        assert!(
            !row.discovered,
            "a real build replaces discovery provenance"
        );

        store.forget_target_root(&found).unwrap();
        std::fs::remove_dir_all(&found).unwrap();
        std::fs::create_dir_all(found.join("debug")).unwrap();
        assert_eq!(
            discover(&store, targets_only(&[]), DISCOVERY_TIME, 0).unwrap(),
            0
        );
        assert_eq!(store.tracked_target_roots(0).unwrap().len(), 1);
    }
}
