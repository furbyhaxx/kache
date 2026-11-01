//! Build units a live target directory no longer uses.
//!
//! Cargo keeps every unit it ever built under a profile: a lockfile update, a
//! feature change or a new toolchain moves the build on to new units and
//! leaves the old ones behind. Cargo reads the fingerprint of every unit a
//! build uses, even when nothing needs compiling.
//!
//! A read shows up only if the filesystem records it. Linux's `relatime` and
//! macOS both refresh an access time on a read when it is older than the
//! file's modification time, and otherwise at most daily (Linux) or never
//! (macOS). So the fingerprints are armed: each file's access time is set
//! just below its modification time, and the moment is recorded. Any build
//! that uses the unit afterwards reads the fingerprint and moves the access
//! time past that moment. Cargo judges freshness by modification times only,
//! so arming changes nothing it looks at.
//!
//! [`prune`] arms a target directory the first time it sees it. Once the
//! configured window has passed, it removes every unit whose fingerprint was
//! neither read nor written since, and arms the rest again. It does nothing
//! on a filesystem where reads never move an access time (`noatime`), or on
//! one that is not local, where Cargo does not lock its build directories.
//! When the probe for reads cannot run, as on a full volume, the target
//! keeps its arming and waits for the next pass.
//!
//! Both of Cargo's layouts are handled (see [`crate::cargo_layout`]):
//!
//! - From Cargo 1.100, a unit is `<profile>/build/<pkg>/<hash>/`, with its
//!   fingerprint in `fingerprint/`.
//! - Before, a unit's fingerprint is `<profile>/.fingerprint/<pkg>-<hash>/`,
//!   a build script's directory `<profile>/build/<pkg>-<hash>/`, and its
//!   outputs are named `<crate>-<hash>…` in `deps/` and `examples/`. A file
//!   there goes only when both its hash and its crate name match the unit.
//!
//! Every lock Cargo takes in a profile directory is held while its units are
//! removed, so a build waits rather than lose a unit it just found fresh. The
//! fingerprint goes first, so a removal cut short leaves outputs Cargo
//! rebuilds rather than a fingerprint it trusts. A unit that is needed after
//! all is restored from the cache or compiled again.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The locks Cargo takes in a profile directory: `.cargo-lock` in every
/// version, and the build and artifact locks from 1.100.
const LOCKS: [&str; 3] = [".cargo-lock", ".cargo-build-lock", ".cargo-artifact-lock"];

/// Name of the file [`probe_reads`] reads.
const PROBE: &str = ".kache-atime-probe";

/// Directory under the cache dir holding when each target was armed.
const ARMED_DIR: &str = "unit-prune";

/// What [`prune`] removed from one target directory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Pruned {
    pub(crate) units: usize,
    pub(crate) bytes: u64,
    /// Units kept because a build read or wrote them since the last arming.
    #[serde(skip)]
    pub(crate) used: usize,
}

/// Whether reading a file in `dir` whose access time is older than its
/// modification time moves the access time, which is what arming relies on.
/// An error means the probe could not run: a full volume refuses its file,
/// which says nothing about reads.
fn probe_reads(dir: &Path) -> std::io::Result<bool> {
    let probe = dir.join(format!("{PROBE}-{}", std::process::id()));
    let moved = (|| -> std::io::Result<bool> {
        std::fs::write(&probe, b"probe")?;
        let armed = arm_file(&probe)?;
        std::fs::read(&probe)?;
        let accessed = filetime::FileTime::from_last_access_time(&std::fs::metadata(&probe)?);
        Ok(moved_past(accessed, armed))
    })();
    let _ = std::fs::remove_file(&probe);
    moved
}

/// [`probe_reads`], counting a probe that could not run as no.
#[cfg(test)]
pub(crate) fn reads_visible(dir: &Path) -> bool {
    probe_reads(dir).unwrap_or(false)
}

/// Whether `accessed` is later than the `armed` access time: a read moved it.
fn moved_past(accessed: filetime::FileTime, armed: filetime::FileTime) -> bool {
    accessed > armed
}

/// Set `file`'s access time a second below its modification time, and
/// return it.
fn arm_file(file: &Path) -> std::io::Result<filetime::FileTime> {
    let modified = filetime::FileTime::from_last_modification_time(&std::fs::metadata(file)?);
    let armed = filetime::FileTime::from_unix_time(modified.unix_seconds() - 1, 0);
    filetime::set_file_atime(file, armed)?;
    Ok(armed)
}

/// Arm every file of `fingerprint`.
fn arm(fingerprint: &Path) {
    for file in entries(fingerprint) {
        let _ = arm_file(&file);
    }
}

/// Whether any file of `fingerprint` was read or written after `armed`. An
/// unreadable file counts as used.
pub(crate) fn used_since(fingerprint: &Path, armed: SystemTime) -> bool {
    let files = entries(fingerprint);
    if files.is_empty() {
        return std::fs::metadata(fingerprint)
            .and_then(|metadata| metadata.modified())
            .map_or(true, |modified| modified > armed);
    }
    files.iter().any(|file| {
        std::fs::metadata(file).map_or(true, |metadata| {
            [metadata.accessed(), metadata.modified()]
                .into_iter()
                .any(|time| time.map_or(true, |time| time > armed))
        })
    })
}

/// One unit of a profile directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unit {
    /// `build/<pkg>/<hash>/`, fingerprint in `fingerprint/`.
    PerUnit { dir: PathBuf },
    /// `.fingerprint/<pkg>-<hash>/` and the files named by its hash.
    Shared {
        profile: PathBuf,
        package: String,
        hash: String,
    },
}

impl Unit {
    pub(crate) fn fingerprint(&self) -> PathBuf {
        match self {
            Unit::PerUnit { dir } => dir.join("fingerprint"),
            Unit::Shared {
                profile,
                package,
                hash,
            } => profile
                .join(".fingerprint")
                .join(format!("{package}-{hash}")),
        }
    }

    /// Everything the unit owns, fingerprint first. `outputs` indexes a
    /// shared layout's `deps/` and `examples/` by hash.
    pub(crate) fn parts(&self, outputs: &Outputs) -> Vec<PathBuf> {
        match self {
            Unit::PerUnit { dir } => vec![dir.join("fingerprint"), dir.clone()],
            Unit::Shared {
                profile,
                package,
                hash,
            } => {
                let named = format!("{package}-{hash}");
                let mut parts = vec![
                    profile.join(".fingerprint").join(&named),
                    profile.join("build").join(&named),
                ];
                let crate_name = package.replace('-', "_");
                for (stem, path) in outputs.get(hash).into_iter().flatten() {
                    if stem.strip_prefix("lib").unwrap_or(stem) == crate_name || *stem == crate_name
                    {
                        parts.push(path.clone());
                    }
                }
                parts
            }
        }
    }
}

/// A shared layout's `deps/` and `examples/` entries by the hash in their
/// name, each with the name before the hash.
pub(crate) type Outputs = HashMap<String, Vec<(String, PathBuf)>>;

/// Split `name` at its `-<16 hex>` unit hash, the hash followed by the end
/// or a `.`: `libserde-0123456789abcdef.rlib` is `("libserde", hash)`.
pub(crate) fn hashed_name(name: &str) -> Option<(&str, &str)> {
    name.match_indices('-').find_map(|(at, _)| {
        let (stem, rest) = name.split_at(at);
        let (hash, after) = rest.get(1..)?.split_at_checked(16)?;
        let ends = after.is_empty() || after.starts_with('.');
        (crate::cargo_layout::is_unit_hash(hash) && ends).then_some((stem, hash))
    })
}

pub(crate) fn outputs(profile: &Path) -> Outputs {
    let mut outputs = Outputs::new();
    for dir in ["deps", "examples"] {
        for entry in entries(&profile.join(dir)) {
            let name = file_name(&entry);
            if let Some((stem, hash)) = hashed_name(&name) {
                outputs
                    .entry(hash.to_owned())
                    .or_default()
                    .push((stem.to_owned(), entry.clone()));
            }
        }
    }
    outputs
}

/// The units of one profile directory, in either layout.
pub(crate) fn units(profile: &Path) -> Vec<Unit> {
    let mut units = Vec::new();
    for fingerprint in subdirectories(&profile.join(".fingerprint")) {
        let name = file_name(&fingerprint);
        if let Some(package) = crate::cargo_layout::legacy_unit_package(&name) {
            units.push(Unit::Shared {
                profile: profile.to_path_buf(),
                package: package.to_owned(),
                hash: name[package.len() + 1..].to_owned(),
            });
        }
    }
    for package in subdirectories(&profile.join("build")) {
        for dir in subdirectories(&package) {
            let per_unit = crate::cargo_layout::is_unit_hash(&file_name(&dir))
                && dir.join("fingerprint").is_dir();
            if per_unit {
                units.push(Unit::PerUnit { dir });
            }
        }
    }
    units
}

/// The profile directories of a target directory: `<target>/<profile>` and
/// `<target>/<triple>/<profile>`, those holding any unit.
pub(crate) fn profiles(target_dir: &Path) -> Vec<PathBuf> {
    let mut profiles = Vec::new();
    for dir in subdirectories(target_dir) {
        if !units(&dir).is_empty() {
            profiles.push(dir);
            continue;
        }
        for nested in subdirectories(&dir) {
            if !units(&nested).is_empty() {
                profiles.push(nested);
            }
        }
    }
    profiles
}

/// Since when no build has used `target_dir`, as kache has watched it: the
/// moment [`watch`] or [`prune`] last armed it, when no unit's fingerprint has
/// been read or written since. Cargo reads the fingerprint of every unit a
/// build uses, even one that compiles nothing. `None` when it was never
/// armed, holds no unit, or a unit was used since. Reads only.
pub(crate) fn unused_since(cache_dir: &Path, target_dir: &Path) -> Option<SystemTime> {
    let armed = read_armed(&armed_record(cache_dir, target_dir))?;
    let units: Vec<Unit> = profiles(target_dir)
        .iter()
        .flat_map(|profile| units(profile))
        .collect();
    let unused = !units.is_empty()
        && !units
            .iter()
            .any(|unit| used_since(&unit.fingerprint(), armed));
    unused.then_some(armed)
}

/// Watch `target_dir` so a later [`unused_since`] shows whether a build used
/// it: arm it at `now`, but no earlier than `not_before`, unless it has gone
/// unused since an arming at or after `not_before`. Every profile is armed
/// under Cargo's locks, and the arming is recorded only when none was held.
/// The earlier record goes first ([`forget_armed`]); where it cannot, nothing
/// is armed. Like [`prune`], it needs a local filesystem that shows reads;
/// elsewhere it forgets any earlier watch, so the target never counts as
/// unused.
pub(crate) fn watch(cache_dir: &Path, target_dir: &Path, now: SystemTime, not_before: SystemTime) {
    watch_with(
        cache_dir,
        target_dir,
        now,
        not_before,
        shows_reads,
        write_armed,
    );
}

/// [`watch`], asking `shows_reads` whether arming works in `target_dir` and
/// recording the arming with `write`.
fn watch_with(
    cache_dir: &Path,
    target_dir: &Path,
    now: SystemTime,
    not_before: SystemTime,
    shows_reads: impl FnOnce(&Path) -> std::io::Result<bool>,
    write: impl FnOnce(&Path, SystemTime) -> anyhow::Result<()>,
) {
    let Ok(Some(_reservation)) = crate::target_use::try_exclusive(cache_dir) else {
        return;
    };
    let record = armed_record(cache_dir, target_dir);
    if !can_arm(&record, target_dir, shows_reads) {
        return;
    }
    if unused_since(cache_dir, target_dir).is_some_and(|since| since >= not_before) {
        return;
    }
    let mut held = Vec::new();
    for profile in profiles(target_dir) {
        let Some(locks) = hold(&profile) else {
            return;
        };
        held.push((profile, locks));
    }
    if !forget_armed(&record) {
        return;
    }
    for (profile, _locks) in &held {
        for unit in units(profile) {
            arm(&unit.fingerprint());
        }
    }
    if let Err(error) = write(&record, now.max(not_before)) {
        tracing::debug!(
            "could not record when {} was armed: {error:#}",
            target_dir.display()
        );
    }
}

/// An idle observation that keeps the kache reservation and existing Cargo
/// profile locks held until the caller finishes its final deletion checks.
#[allow(dead_code)]
pub(crate) struct VerifiedIdle {
    since: SystemTime,
    _reservation: crate::target_use::Reservation,
    _profiles: Vec<Held>,
}

#[allow(dead_code)]
impl VerifiedIdle {
    pub(crate) fn since(&self) -> SystemTime {
        self.since
    }
}

/// Revalidate a boot-bound watch, returning a lock guard only after `window`.
/// The caller must keep a nonempty epoch stable throughout a watch, replacing it
/// on daemon restart or any mount-change event, and synchronize changes with
/// the returned guard. A probe cannot detect unobserved temporary remounts, so
/// mount read-observation options must remain unchanged throughout the window.
/// The guard cannot prevent Cargo from creating a new, previously absent profile.
#[allow(dead_code)]
pub(crate) fn verified_watch(
    cache_dir: &Path,
    target_dir: &Path,
    now: SystemTime,
    not_before: SystemTime,
    window: Duration,
    epoch: &[u8],
) -> Option<VerifiedIdle> {
    #[cfg(target_os = "linux")]
    {
        let ops = VerifiedOps {
            epoch,
            boot: &linux_boot_id,
            uptime: &linux_boot_time,
            probe: &verified_shows_reads,
            arm: &verified_arm_file,
            read: &verified_read_file,
            write: &write_verified,
        };
        verified_watch_with(cache_dir, target_dir, now, not_before, window, &ops)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cache_dir, target_dir, now, not_before, window, epoch);
        None
    }
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize)]
struct VerifiedRecord {
    version: u8,
    boot: String,
    epoch: String,
    since: SystemTime,
    uptime: Duration,
    target: VerifiedIdentity,
    mount: String,
    fingerprints: String,
}

#[cfg(target_os = "linux")]
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct VerifiedIdentity {
    dev: u64,
    ino: u64,
    ctime: i64,
    ctime_nsec: i64,
    canonical: PathBuf,
}

#[cfg(target_os = "linux")]
struct VerifiedOps<'a> {
    epoch: &'a [u8],
    boot: &'a dyn Fn() -> Option<String>,
    uptime: &'a dyn Fn() -> Option<Duration>,
    probe: &'a dyn Fn(&Path) -> std::io::Result<bool>,
    arm: &'a dyn Fn(&Path, &std::fs::Metadata) -> std::io::Result<filetime::FileTime>,
    read: &'a dyn Fn(&Path, &std::fs::Metadata) -> std::io::Result<()>,
    write: &'a dyn Fn(&Path, &VerifiedRecord) -> anyhow::Result<()>,
}

#[cfg(target_os = "linux")]
fn verified_open_file(path: &Path, expected: &std::fs::Metadata) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.dev() != expected.dev() || metadata.ino() != expected.ino() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn verified_arm_file(
    path: &Path,
    expected: &std::fs::Metadata,
) -> std::io::Result<filetime::FileTime> {
    let file = verified_open_file(path, expected)?;
    let modified = filetime::FileTime::from_last_modification_time(&file.metadata()?);
    let seconds = modified
        .unix_seconds()
        .checked_sub(1)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    let armed = filetime::FileTime::from_unix_time(seconds, 0);
    filetime::set_file_handle_times(&file, Some(armed), None)?;
    Ok(armed)
}

#[cfg(target_os = "linux")]
fn verified_read_file(path: &Path, expected: &std::fs::Metadata) -> std::io::Result<()> {
    use std::io::Read;
    let read = verified_open_file(path, expected)?.read(&mut [0])?;
    if (read == 0) != (expected.len() == 0) {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verified_shows_reads(target: &Path) -> std::io::Result<bool> {
    if !matches!(
        crate::cache_fs::classify(&crate::cache_fs::probe(target)),
        crate::cache_fs::CacheFsVerdict::Local
    ) {
        return Ok(false);
    }
    let probe = tempfile::Builder::new().prefix(PROBE).tempfile_in(target)?;
    let result = (|| {
        std::fs::write(probe.path(), b"probe")?;
        let armed = arm_file(probe.path())?;
        std::fs::read(probe.path())?;
        let accessed = filetime::FileTime::from_last_access_time(&std::fs::metadata(probe.path())?);
        Ok(moved_past(accessed, armed))
    })();
    probe.close()?;
    result
}

#[cfg(target_os = "linux")]
fn linux_boot_id() -> Option<String> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let id = text.trim();
    let valid = id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    valid.then(|| id.to_owned())
}

#[cfg(target_os = "linux")]
fn linux_boot_time() -> Option<Duration> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time is a valid writable timespec and CLOCK_BOOTTIME is supported on Linux.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return None;
    }
    let seconds = u64::try_from(time.tv_sec).ok()?;
    let nanos = u32::try_from(time.tv_nsec).ok()?;
    (nanos < 1_000_000_000).then(|| Duration::new(seconds, nanos))
}

#[cfg(target_os = "linux")]
fn verified_record(cache_dir: &Path, target_dir: &Path) -> PathBuf {
    let digest = blake3::hash(target_dir.as_os_str().as_encoded_bytes()).to_hex();
    cache_dir.join("unit-watch-verified").join(&digest[..16])
}

#[cfg(target_os = "linux")]
fn write_verified(path: &Path, record: &VerifiedRecord) -> anyhow::Result<()> {
    crate::atomic::atomic_replace(path, &serde_json::to_vec(record)?)?;
    crate::atomic::fsync_dir(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("missing record directory"))?,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn verified_identity(target: &Path) -> Option<VerifiedIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(target).ok()?;
    if !metadata.is_dir() {
        return None;
    }
    Some(VerifiedIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
        canonical: std::fs::canonicalize(target).ok()?,
    })
}

#[cfg(target_os = "linux")]
fn verified_mount_id(path: &Path) -> Option<u64> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path).ok()?;
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).ok()?;
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:")?.trim().parse().ok())
}

#[cfg(target_os = "linux")]
fn verified_mount(target: &Path) -> Option<(u64, String)> {
    let id = verified_mount_id(target)?;
    let info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let line = info.lines().find(|line| {
        line.split_whitespace()
            .next()
            .and_then(|part| part.parse::<u64>().ok())
            == Some(id)
    })?;
    Some((id, blake3::hash(line.as_bytes()).to_hex().to_string()))
}

#[cfg(target_os = "linux")]
#[derive(PartialEq, Eq)]
struct VerifiedProfile {
    path: PathBuf,
    fingerprints: Vec<PathBuf>,
}

#[cfg(target_os = "linux")]
fn verified_entries(dir: &Path) -> Option<Vec<PathBuf>> {
    let mut result = std::fs::read_dir(dir)
        .ok()?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .ok()?;
    result.sort();
    Some(result)
}

#[cfg(target_os = "linux")]
fn verified_directory(path: &Path) -> Option<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Some(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn verified_profile(profile: &Path) -> Option<Option<VerifiedProfile>> {
    let shared = profile.join(".fingerprint");
    let build = profile.join("build");
    let deps = profile.join("deps");
    let examples = profile.join("examples");
    let has_shared = verified_directory(&shared)?;
    let has_build = verified_directory(&build)?;
    let has_deps = verified_directory(&deps)?;
    let has_examples = verified_directory(&examples)?;
    let has_incremental = verified_directory(&profile.join("incremental"))?;
    let mut has_lock = false;
    for name in LOCKS {
        match std::fs::symlink_metadata(profile.join(name)) {
            Ok(metadata) if metadata.is_file() => has_lock = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return None,
        }
    }
    if !has_shared && !has_build && !has_deps && !has_examples && !has_incremental && !has_lock {
        return Some(None);
    }
    let mut fingerprints = Vec::new();
    let mut shared_units = Vec::new();
    if has_shared {
        for dir in verified_entries(&shared)? {
            if !std::fs::symlink_metadata(&dir).ok()?.is_dir() {
                return None;
            }
            let name = dir.file_name()?.to_str()?;
            let package = crate::cargo_layout::legacy_unit_package(name)?;
            shared_units.push((
                package.replace('-', "_"),
                name[package.len() + 1..].to_owned(),
            ));
            fingerprints.push(dir);
        }
    }
    if has_build {
        for package in verified_entries(&build)? {
            if !std::fs::symlink_metadata(&package).ok()?.is_dir() {
                return None;
            }
            let name = package.file_name()?.to_str()?;
            if crate::cargo_layout::legacy_unit_package(name).is_some() {
                if !fingerprints.contains(&shared.join(name)) {
                    return None;
                }
                continue;
            }
            let units = verified_entries(&package)?;
            if units.is_empty() {
                return None;
            }
            for unit in units {
                let metadata = std::fs::symlink_metadata(&unit).ok()?;
                if !metadata.is_dir()
                    || !crate::cargo_layout::is_unit_hash(unit.file_name()?.to_str()?)
                {
                    return None;
                }
                let fingerprint = unit.join("fingerprint");
                if !verified_directory(&fingerprint)? {
                    return None;
                }
                fingerprints.push(fingerprint);
            }
        }
    }
    for (present, dir) in [(has_deps, deps), (has_examples, examples)] {
        if present {
            for output in verified_entries(&dir)? {
                let metadata = std::fs::symlink_metadata(&output).ok()?;
                if metadata.is_symlink() {
                    return None;
                }
                let name = output.file_name()?.to_str()?;
                if let Some((stem, hash)) = hashed_name(name)
                    && !shared_units.iter().any(|(package, known)| {
                        (package == stem || package == stem.strip_prefix("lib").unwrap_or(stem))
                            && known == hash
                    })
                {
                    return None;
                }
            }
        }
    }
    if fingerprints.is_empty() {
        return None;
    }
    fingerprints.sort();
    Some(Some(VerifiedProfile {
        path: profile.to_path_buf(),
        fingerprints,
    }))
}

#[cfg(target_os = "linux")]
fn verified_profiles(target: &Path) -> Option<Vec<VerifiedProfile>> {
    let mut profiles = Vec::new();
    for dir in verified_entries(target)? {
        let metadata = std::fs::symlink_metadata(&dir).ok()?;
        if metadata.is_symlink() {
            return None;
        }
        if !metadata.is_dir() {
            continue;
        }
        if let Some(profile) = verified_profile(&dir)? {
            profiles.push(profile);
            continue;
        }
        for nested in verified_entries(&dir)? {
            let metadata = std::fs::symlink_metadata(&nested).ok()?;
            if metadata.is_symlink() {
                return None;
            }
            if metadata.is_dir()
                && let Some(profile) = verified_profile(&nested)?
            {
                profiles.push(profile);
            }
        }
    }
    (!profiles.is_empty()).then_some(profiles)
}

#[cfg(target_os = "linux")]
fn verified_fingerprints(
    profiles: &[VerifiedProfile],
    mount: u64,
) -> Option<(Vec<PathBuf>, String)> {
    use std::os::unix::fs::MetadataExt;
    let mut files = Vec::new();
    let mut digest = blake3::Hasher::new();
    for profile in profiles {
        for fingerprint in &profile.fingerprints {
            for path in std::iter::once(fingerprint.clone()).chain(verified_entries(fingerprint)?) {
                let metadata = std::fs::symlink_metadata(&path).ok()?;
                if verified_mount_id(&path)? != mount {
                    return None;
                }
                if path == *fingerprint {
                    if !metadata.is_dir() {
                        return None;
                    }
                } else if metadata.is_file() {
                    files.push(path.clone());
                } else {
                    return None;
                }
                let name = path.as_os_str().as_encoded_bytes();
                digest.update(&(name.len() as u64).to_le_bytes());
                digest.update(name);
                for field in [
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime() as u64,
                    metadata.ctime_nsec() as u64,
                    metadata.mtime() as u64,
                    metadata.mtime_nsec() as u64,
                ] {
                    digest.update(&field.to_le_bytes());
                }
                if metadata.is_file() {
                    digest.update(&metadata.atime().to_le_bytes());
                    digest.update(&metadata.atime_nsec().to_le_bytes());
                }
            }
            if !files
                .iter()
                .any(|file| file.parent() == Some(fingerprint.as_path()))
            {
                return None;
            }
        }
    }
    Some((files, digest.finalize().to_hex().to_string()))
}

#[cfg(target_os = "linux")]
fn verified_watch_with(
    cache_dir: &Path,
    target_dir: &Path,
    now: SystemTime,
    not_before: SystemTime,
    window: Duration,
    ops: &VerifiedOps<'_>,
) -> Option<VerifiedIdle> {
    let reservation = crate::target_use::try_exclusive(cache_dir).ok()??;
    let path = verified_record(cache_dir, target_dir);
    let parent = path.parent()?;
    std::fs::create_dir_all(parent).ok()?;
    let old = std::fs::read(&path);
    if !forget_armed(&path) || crate::atomic::fsync_dir(parent).is_err() {
        return None;
    }
    let old = match old {
        Ok(bytes) => serde_json::from_slice::<VerifiedRecord>(&bytes).ok(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return None,
    };
    if window.is_zero() || ops.epoch.is_empty() {
        return None;
    }
    let epoch = blake3::hash(ops.epoch).to_hex().to_string();
    let boot = (ops.boot)()?;
    let uptime = (ops.uptime)()?;
    if now < not_before {
        return None;
    }
    let target_before = verified_identity(target_dir)?;
    let (mount_id, mount) = verified_mount(target_dir)?;
    let profiles = verified_profiles(target_dir)?;
    let mut locks = Vec::new();
    for profile in &profiles {
        locks.push(hold(&profile.path)?);
    }
    if verified_profiles(target_dir)? != profiles {
        return None;
    }
    let (files, fingerprints) = verified_fingerprints(&profiles, mount_id)?;
    if !(ops.probe)(target_dir).ok()? {
        return None;
    }
    let after_probe = verified_identity(target_dir)?;
    if target_before.dev != after_probe.dev
        || target_before.ino != after_probe.ino
        || target_before.canonical != after_probe.canonical
        || verified_mount(target_dir)? != (mount_id, mount.clone())
        || (ops.boot)().as_ref() != Some(&boot)
    {
        return None;
    }
    let valid = old.filter(|record| {
        record.version == 2
            && record.boot == boot
            && record.epoch == epoch
            && record.target == target_before
            && record.mount == mount
            && record.fingerprints == fingerprints
            && record.since >= not_before
            && record.since <= now
            && record.uptime <= uptime
    });
    let (since, started, final_fingerprints) = if let Some(record) = valid {
        (record.since, record.uptime, fingerprints)
    } else {
        let legacy = armed_record(cache_dir, target_dir);
        if !forget_armed(&legacy) {
            return None;
        }
        if let Some(parent) = legacy.parent().filter(|parent| parent.exists()) {
            crate::atomic::fsync_dir(parent).ok()?;
        }
        use std::os::unix::fs::MetadataExt;
        let mut armed_files = Vec::new();
        for file in &files {
            let metadata = std::fs::symlink_metadata(file).ok()?;
            if metadata.modified().ok()? > now.checked_sub(Duration::from_secs(2))? {
                return None;
            }
            if metadata.nlink() != 1 {
                return None;
            }
            let armed = (ops.arm)(file, &metadata).ok()?;
            (ops.read)(file, &metadata).ok()?;
            let read = std::fs::symlink_metadata(file).ok()?;
            if !read.is_file()
                || metadata.dev() != read.dev()
                || metadata.ino() != read.ino()
                || metadata.modified().ok()? != read.modified().ok()?
                || !moved_past(filetime::FileTime::from_last_access_time(&read), armed)
            {
                return None;
            }
            let armed = (ops.arm)(file, &metadata).ok()?;
            let after = std::fs::symlink_metadata(file).ok()?;
            if metadata.dev() != after.dev()
                || metadata.ino() != after.ino()
                || metadata.modified().ok()? != after.modified().ok()?
                || filetime::FileTime::from_last_access_time(&after) != armed
                || filetime::FileTime::from_last_modification_time(&after) <= armed
            {
                return None;
            }
            armed_files.push((file, armed));
        }
        if verified_profiles(target_dir)? != profiles {
            return None;
        }
        let (after_files, fingerprint_hash) = verified_fingerprints(&profiles, mount_id)?;
        if after_files != files {
            return None;
        }
        for (file, armed) in armed_files {
            let metadata = std::fs::symlink_metadata(file).ok()?;
            if filetime::FileTime::from_last_access_time(&metadata) != armed {
                return None;
            }
        }
        (now, (ops.uptime)()?, fingerprint_hash)
    };
    if (ops.boot)().as_ref() != Some(&boot)
        || verified_identity(target_dir)? != after_probe
        || verified_mount(target_dir)? != (mount_id, mount.clone())
        || verified_profiles(target_dir)? != profiles
        || verified_fingerprints(&profiles, mount_id)?.1 != final_fingerprints
    {
        return None;
    }
    let elapsed = (ops.uptime)()?.checked_sub(started)?;
    let record = VerifiedRecord {
        version: 2,
        boot,
        epoch,
        since,
        uptime: started,
        target: after_probe,
        mount,
        fingerprints: final_fingerprints,
    };
    (ops.write)(&path, &record).ok()?;
    (elapsed >= window).then_some(VerifiedIdle {
        since,
        _reservation: reservation,
        _profiles: locks,
    })
}

/// Where the moment `target_dir` was armed is recorded.
fn armed_record(cache_dir: &Path, target_dir: &Path) -> PathBuf {
    let digest = blake3::hash(target_dir.as_os_str().as_encoded_bytes()).to_hex();
    cache_dir.join(ARMED_DIR).join(&digest[..16])
}

fn read_armed(record: &Path) -> Option<SystemTime> {
    let seconds = std::fs::read_to_string(record)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
}

fn write_armed(record: &Path, at: SystemTime) -> anyhow::Result<()> {
    let seconds = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    std::fs::create_dir_all(record.parent().unwrap_or(record))?;
    crate::atomic::atomic_replace(record, seconds.to_string().as_bytes())
}

/// Remove `record` before the units it vouches for are armed again. Arming
/// erases the reads that show a unit was used since the recorded moment, so
/// a record that outlived it would count those units as unused. Writing the
/// new record can fail where removing the old one works: a full APFS volume
/// refuses to rename onto an existing file. `false` when it stays, and then
/// nothing may be armed.
fn forget_armed(record: &Path) -> bool {
    match std::fs::remove_file(record) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            tracing::debug!("cannot replace {}: {error}", record.display());
            false
        }
    }
}

/// What to do with a target armed at `armed`, at `now`, for `window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Never armed, or armed in the future by a clock set back: arm now.
    Arm,
    /// Armed less than `window` ago: nothing to judge yet.
    Wait,
    /// Remove what was not used since the moment given, then arm again.
    Judge(SystemTime),
}

pub(crate) fn step(armed: Option<SystemTime>, now: SystemTime, window: Duration) -> Step {
    let Some(armed) = armed else {
        return Step::Arm;
    };
    match now.duration_since(armed) {
        Ok(elapsed) if elapsed >= window => Step::Judge(armed),
        Ok(_) => Step::Wait,
        Err(_) => Step::Arm,
    }
}

/// Remove the units of `target_dir` not used within `window`, arming it first
/// if needed; see the module documentation. `cache_dir` keeps when it was
/// armed.
pub(crate) fn prune(
    cache_dir: &Path,
    target_dir: &Path,
    window: Duration,
    now: SystemTime,
) -> Pruned {
    prune_with(cache_dir, target_dir, window, now, shows_reads)
}

/// [`prune`], asking `shows_reads` whether arming works in `target_dir`.
fn prune_with(
    cache_dir: &Path,
    target_dir: &Path,
    window: Duration,
    now: SystemTime,
    shows_reads: impl FnOnce(&Path) -> std::io::Result<bool>,
) -> Pruned {
    let Ok(Some(_reservation)) = crate::target_use::try_exclusive(cache_dir) else {
        return Pruned::default();
    };
    if !can_arm(
        &armed_record(cache_dir, target_dir),
        target_dir,
        shows_reads,
    ) {
        return Pruned::default();
    }
    judge(cache_dir, target_dir, window, now)
}

/// Whether this pass may arm `target_dir`, by `shows_reads`. Where reads do
/// not show, an arming would no longer vouch for anything, so its `record`
/// is forgotten. A probe that could not run, as on a full volume, says
/// nothing about reads: the target waits for the next pass with its record.
fn can_arm(
    record: &Path,
    target_dir: &Path,
    shows_reads: impl FnOnce(&Path) -> std::io::Result<bool>,
) -> bool {
    match shows_reads(target_dir) {
        Ok(true) => true,
        Ok(false) => {
            let _ = std::fs::remove_file(record);
            false
        }
        Err(error) => {
            tracing::debug!(
                "skipping {} this pass: cannot tell whether reads show there: {error}",
                target_dir.display()
            );
            false
        }
    }
}

/// [`can_prune`] for `target_dir`: the filesystem's locality, then the probe.
/// An error means the probe could not run.
fn shows_reads(target_dir: &Path) -> std::io::Result<bool> {
    let local = matches!(
        crate::cache_fs::classify(&crate::cache_fs::probe(target_dir)),
        crate::cache_fs::CacheFsVerdict::Local
    );
    can_prune(local, || probe_reads(target_dir))
}

/// Pruning needs a local filesystem, where Cargo locks its build
/// directories, that also shows reads. `reads` is only asked when local.
fn can_prune(local: bool, reads: impl FnOnce() -> std::io::Result<bool>) -> std::io::Result<bool> {
    Ok(local && reads()?)
}

/// Arm `target_dir`, wait out `window`, then remove what was not used; the
/// part of [`prune`] after the filesystem was found to show reads.
fn judge(cache_dir: &Path, target_dir: &Path, window: Duration, now: SystemTime) -> Pruned {
    judge_with(cache_dir, target_dir, window, now, write_armed)
}

/// [`judge`], recording the arming with `write`.
fn judge_with(
    cache_dir: &Path,
    target_dir: &Path,
    window: Duration,
    now: SystemTime,
    write: impl FnOnce(&Path, SystemTime) -> anyhow::Result<()>,
) -> Pruned {
    let record = armed_record(cache_dir, target_dir);
    let armed = match step(read_armed(&record), now, window) {
        Step::Wait => return Pruned::default(),
        Step::Arm => None,
        Step::Judge(armed) => Some(armed),
    };
    // The old record goes before anything is armed again. A profile a build
    // held was neither judged nor armed, and with an old record that would
    // not go, nothing was armed: recording now would vouch for units never
    // armed, so the next check tries again.
    let (pruned, complete) = sweep(target_dir, armed, || forget_armed(&record));
    if !complete {
        return pruned;
    }
    // On failure no record is left, and the next check arms from scratch.
    if let Err(error) = write(&record, now) {
        tracing::debug!(
            "could not record when {} was armed: {error:#}",
            target_dir.display()
        );
    }
    pruned
}

/// What [`prune`] would remove from `target_dir` at `now` for `window`. Reads
/// only: nothing is removed or armed, and no lock is taken.
pub(crate) fn preview(
    cache_dir: &Path,
    target_dir: &Path,
    window: Duration,
    now: SystemTime,
) -> Pruned {
    let Step::Judge(armed) = step(
        read_armed(&armed_record(cache_dir, target_dir)),
        now,
        window,
    ) else {
        return Pruned::default();
    };
    let mut unused = Pruned::default();
    for profile in profiles(target_dir) {
        let outputs = outputs(&profile);
        for unit in units(&profile) {
            if let Some((_, bytes)) = stale(&unit, &outputs, armed) {
                unused.units += 1;
                unused.bytes += bytes;
            } else {
                unused.used += 1;
            }
        }
    }
    unused
}

/// The parts of `unit` and their bytes, when no build used it since `armed`.
fn stale(unit: &Unit, outputs: &Outputs, armed: SystemTime) -> Option<(Vec<PathBuf>, u64)> {
    if used_since(&unit.fingerprint(), armed) {
        return None;
    }
    let parts = unit.parts(outputs);
    let bytes = parts.iter().map(|part| size(part)).sum();
    Some((parts, bytes))
}

/// Hold every profile before removing or re-arming units. A partial pass must
/// not reset a used unit's access time while keeping the old arming record.
/// `false` when any profile is busy, with every unit left untouched. The
/// unused units go next; then `before_arming` decides whether the rest are
/// armed again, and `false` from it leaves them as they are.
fn sweep(
    target_dir: &Path,
    armed: Option<SystemTime>,
    before_arming: impl FnOnce() -> bool,
) -> (Pruned, bool) {
    let mut pruned = Pruned::default();
    let mut held = Vec::new();
    for profile in profiles(target_dir) {
        let Some(locks) = hold(&profile) else {
            return (pruned, false);
        };
        held.push((profile, locks));
    }
    let mut kept = Vec::new();
    for (profile, _locks) in &held {
        let outputs = outputs(profile);
        for unit in units(profile) {
            if let Some((parts, bytes)) = armed.and_then(|armed| stale(&unit, &outputs, armed)) {
                if remove(&parts).is_ok() {
                    pruned.units += 1;
                    pruned.bytes += bytes;
                }
                continue;
            }
            if armed.is_some() {
                pruned.used += 1;
            }
            kept.push(unit.fingerprint());
        }
    }
    if !before_arming() {
        return (pruned, false);
    }
    for fingerprint in kept {
        arm(&fingerprint);
    }
    (pruned, true)
}

/// Cargo locks this process holds, released when dropped.
pub(crate) struct Held(Vec<std::fs::File>);

impl Drop for Held {
    fn drop(&mut self) {
        // Closing our descriptor is insufficient if a concurrent fork still
        // holds a duplicate. Release ownership before that child reaches exec.
        for file in &self.0 {
            let _ = file.unlock();
        }
    }
}

/// Take every Cargo lock of `profile` without waiting, creating any that is
/// missing. `None` while a build holds one.
pub(crate) fn hold(profile: &Path) -> Option<Held> {
    let mut held = Held(Vec::new());
    for name in LOCKS {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(profile.join(name))
            .ok()?;
        file.try_lock().ok()?;
        held.0.push(file);
    }
    Some(held)
}

/// Remove `parts` in order, stopping at the first failure.
fn remove(parts: &[PathBuf]) -> std::io::Result<()> {
    for part in parts {
        let removed = match std::fs::symlink_metadata(part) {
            Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(part),
            Ok(_) => std::fs::remove_file(part),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        removed?;
    }
    Ok(())
}

/// Bytes under `path`, symbolic links not followed.
fn size(path: &Path) -> u64 {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => entries(path).iter().map(|entry| size(entry)).sum(),
        Ok(metadata) => metadata.len(),
        Err(_) => 0,
    }
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    paths.sort();
    paths
}

fn subdirectories(dir: &Path) -> Vec<PathBuf> {
    entries(dir)
        .into_iter()
        .filter(|path| std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()))
        .collect()
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "0123456789abcdef";
    const NEW: &str = "fedcba9876543210";
    const DAY: u64 = 86_400;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn ago(days: u64) -> SystemTime {
        SystemTime::now() - Duration::from_secs(days * DAY)
    }

    /// Set every file under `dir` to have been read and written at `at`.
    fn set_times(dir: &Path, at: SystemTime) {
        let time = filetime::FileTime::from_system_time(at);
        for entry in entries(dir) {
            if entry.is_dir() {
                set_times(&entry, at);
            } else {
                filetime::set_file_times(&entry, time, time).unwrap();
            }
        }
    }

    /// A shared-layout profile with units `OLD` and `NEW` of `serde`, and an
    /// output of another crate that happens to carry `OLD`.
    fn shared_profile(profile: &Path) {
        for hash in [OLD, NEW] {
            let name = format!("serde-{hash}");
            write(
                &profile.join(".fingerprint").join(&name).join("lib-serde"),
                "fp",
            );
            write(&profile.join("build").join(&name).join("output"), "");
            write(
                &profile.join("deps").join(format!("libserde-{hash}.rlib")),
                "rlib",
            );
            write(&profile.join("deps").join(format!("serde-{hash}.d")), "d");
        }
        write(&profile.join(format!("deps/libother-{OLD}.rlib")), "keep");
        write(&profile.join("deps/libplain.rlib"), "keep");
    }

    fn per_unit_profile(profile: &Path) {
        for hash in [OLD, NEW] {
            let unit = profile.join("build/serde").join(hash);
            write(&unit.join("fingerprint/lib-serde"), "fp");
            write(&unit.join("out/libserde.rlib"), "rlib-bytes");
        }
    }

    #[cfg(target_os = "linux")]
    fn simulated_read(path: &Path) -> std::io::Result<()> {
        filetime::set_file_atime(path, filetime::FileTime::now())
    }

    #[cfg(target_os = "linux")]
    fn verified_test_watch(
        cache: &Path,
        target: &Path,
        now: SystemTime,
        boot: Option<&str>,
    ) -> Option<VerifiedIdle> {
        let ops = VerifiedOps {
            epoch: b"epoch-a",
            boot: &|| boot.map(str::to_owned),
            uptime: &|| now.duration_since(SystemTime::UNIX_EPOCH).ok(),
            probe: &|_| Ok(true),
            arm: &verified_arm_file,
            read: &|file, _| simulated_read(file),
            write: &write_verified,
        };
        verified_watch_with(
            cache,
            target,
            now,
            SystemTime::UNIX_EPOCH,
            Duration::from_secs(12 * 3600),
            &ops,
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_restarts_the_twelve_hour_window_after_a_read() {
        for layout in [shared_profile as fn(&Path), per_unit_profile] {
            let dir = tempfile::tempdir().unwrap();
            let cache = dir.path().join("cache");
            let target = dir.path().join("target");
            layout(&target.join("debug"));
            let unrelated = target.join(format!("debug/deps/libother-{OLD}.rlib"));
            if unrelated.exists() {
                std::fs::remove_file(unrelated).unwrap();
            }
            set_times(&target, ago(40));
            let start = SystemTime::now() - Duration::from_secs(20 * 3600);
            let hours = |n: u64| Duration::from_secs(n * 3600);
            assert!(verified_test_watch(&cache, &target, start, Some("boot-a")).is_none());
            assert!(
                verified_test_watch(&cache, &target, start + hours(11), Some("boot-a")).is_none()
            );
            let guard =
                verified_test_watch(&cache, &target, start + hours(12), Some("boot-a")).unwrap();
            assert_eq!(guard.since(), start);
            assert!(crate::target_use::try_exclusive(&cache).unwrap().is_none());
            assert!(hold(&target.join("debug")).is_none());
            drop(guard);
            let fingerprint = unit_named(&target.join("debug"), NEW).fingerprint();
            simulated_read(entries(&fingerprint).first().unwrap()).unwrap();
            assert!(
                verified_test_watch(&cache, &target, start + hours(13), Some("boot-a")).is_none()
            );
            assert!(
                verified_test_watch(&cache, &target, start + hours(24), Some("boot-a")).is_none()
            );
            let guard =
                verified_test_watch(&cache, &target, start + hours(25), Some("boot-a")).unwrap();
            assert_eq!(guard.since(), start + hours(13));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_uses_boot_time_for_the_idle_window() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        per_unit_profile(&target.join("debug"));
        set_times(&target, ago(40));
        let now = SystemTime::now() - Duration::from_secs(2 * DAY);
        let window = Duration::from_secs(12 * 3600);
        let uptime = std::cell::Cell::new(Duration::from_secs(DAY));
        let ops = VerifiedOps {
            epoch: b"epoch-a",
            boot: &|| Some("boot-a".to_owned()),
            uptime: &|| Some(uptime.get()),
            probe: &|_| Ok(true),
            arm: &verified_arm_file,
            read: &|file, _| simulated_read(file),
            write: &write_verified,
        };
        assert!(
            verified_watch_with(&cache, &target, now, SystemTime::UNIX_EPOCH, window, &ops)
                .is_none()
        );
        uptime.set(uptime.get() + Duration::from_secs(3600));
        assert!(
            verified_watch_with(
                &cache,
                &target,
                now + window,
                SystemTime::UNIX_EPOCH,
                window,
                &ops
            )
            .is_none()
        );
        uptime.set(Duration::from_secs(DAY) + window);
        assert!(
            verified_watch_with(
                &cache,
                &target,
                now + window,
                SystemTime::UNIX_EPOCH,
                window,
                &ops
            )
            .is_some()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_restarts_after_an_observation_epoch_change() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        per_unit_profile(&target.join("debug"));
        set_times(&target, ago(40));
        let start = SystemTime::now() - Duration::from_secs(2 * DAY);
        let window = Duration::from_secs(12 * 3600);
        let watch = |epoch: &[u8], now: SystemTime| {
            let ops = VerifiedOps {
                epoch,
                boot: &|| Some("boot-a".to_owned()),
                uptime: &|| now.duration_since(SystemTime::UNIX_EPOCH).ok(),
                probe: &|_| Ok(true),
                arm: &verified_arm_file,
                read: &|file, _| simulated_read(file),
                write: &write_verified,
            };
            verified_watch_with(&cache, &target, now, SystemTime::UNIX_EPOCH, window, &ops)
        };
        assert!(watch(b"epoch-a", start).is_none());
        assert!(watch(b"epoch-a", start + window).is_some());
        assert!(watch(b"epoch-b", start + window).is_none());
        assert!(watch(b"epoch-b", start + 2 * window).is_some());
        assert!(watch(b"", start + 2 * window).is_none());
        assert!(watch(b"epoch-b", start + 2 * window).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_never_carries_evidence_across_boots() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        per_unit_profile(&target.join("debug"));
        set_times(&target, ago(40));
        let start = SystemTime::now() - Duration::from_secs(2 * DAY);
        let later = start + Duration::from_secs(12 * 3600);
        assert!(verified_test_watch(&cache, &target, start, Some("boot-a")).is_none());
        assert!(verified_test_watch(&cache, &target, later, Some("boot-b")).is_none());
        let after_window = later + Duration::from_secs(12 * 3600);
        assert!(verified_test_watch(&cache, &target, after_window, Some("boot-b")).is_some());
        assert!(verified_test_watch(&cache, &target, after_window, None).is_none());
        assert!(verified_test_watch(&cache, &target, after_window, Some("boot-b")).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_fails_closed_on_probe_arming_and_record_errors() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        per_unit_profile(&target.join("debug"));
        set_times(&target, ago(40));
        let start = SystemTime::now() - Duration::from_secs(2 * DAY);
        let window = Duration::from_secs(12 * 3600);
        let now = start + window;
        let boot = || Some("boot-a".to_owned());
        let uptime = || now.duration_since(SystemTime::UNIX_EPOCH).ok();
        let good_probe = |_: &Path| Ok(true);
        let bad_probe = |_: &Path| Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
        let no_reads = |_: &Path| Ok(false);
        let bad_arm = |_: &Path, _: &std::fs::Metadata| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        };
        let bad_read = |_: &Path, _: &std::fs::Metadata| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        };
        let hidden_read = |_: &Path, _: &std::fs::Metadata| Ok(());
        let fake_read = |file: &Path, _: &std::fs::Metadata| simulated_read(file);
        let bad_write = |_: &Path, _: &VerifiedRecord| Err(anyhow::anyhow!("write failed"));
        for (probe, arm, read, write) in [
            (
                &bad_probe as &dyn Fn(&Path) -> _,
                &verified_arm_file as &dyn Fn(&Path, &std::fs::Metadata) -> _,
                &fake_read as &dyn Fn(&Path, &std::fs::Metadata) -> _,
                &write_verified as &dyn Fn(&Path, &VerifiedRecord) -> _,
            ),
            (&no_reads, &verified_arm_file, &fake_read, &write_verified),
            (&good_probe, &bad_arm, &fake_read, &write_verified),
            (&good_probe, &verified_arm_file, &bad_read, &write_verified),
            (
                &good_probe,
                &verified_arm_file,
                &hidden_read,
                &write_verified,
            ),
            (&good_probe, &verified_arm_file, &fake_read, &bad_write),
        ] {
            assert!(verified_test_watch(&cache, &target, start, Some("boot-a")).is_none());
            read_now(&unit_named(&target.join("debug"), NEW));
            let ops = VerifiedOps {
                epoch: b"epoch-a",
                boot: &boot,
                uptime: &uptime,
                probe,
                arm,
                read,
                write,
            };
            assert!(
                verified_watch_with(&cache, &target, now, SystemTime::UNIX_EPOCH, window, &ops)
                    .is_none()
            );
            assert!(verified_test_watch(&cache, &target, now, Some("boot-a")).is_none());
            std::fs::remove_file(verified_record(&cache, &target)).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_detects_rearming_set_changes_and_target_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        per_unit_profile(&target.join("debug"));
        set_times(&target, ago(40));
        let mut now = SystemTime::now() - Duration::from_secs(4 * DAY);
        let window = Duration::from_secs(12 * 3600);
        assert!(verified_test_watch(&cache, &target, now, Some("boot-a")).is_none());
        for change in 0..3 {
            now += window;
            match change {
                0 => {
                    read_now(&unit_named(&target.join("debug"), NEW));
                    sweep(&target, None, || true);
                }
                1 => {
                    let fingerprint = unit_named(&target.join("debug"), NEW).fingerprint();
                    write(&fingerprint.join("new"), "new");
                    set_times(&fingerprint, ago(40));
                }
                _ => {
                    std::fs::rename(&target, dir.path().join("old-target")).unwrap();
                    per_unit_profile(&target.join("debug"));
                    set_times(&target, ago(40));
                }
            }
            assert!(
                verified_test_watch(&cache, &target, now, Some("boot-a")).is_none(),
                "change {change}"
            );
            assert_eq!(
                verified_test_watch(&cache, &target, now + window, Some("boot-a"))
                    .unwrap()
                    .since(),
                now
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_rejects_missing_empty_and_unknown_fingerprints() {
        for per_unit in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cache = dir.path().join("cache");
            let target = dir.path().join("target");
            let profile = target.join("debug");
            if per_unit {
                per_unit_profile(&profile);
            } else {
                shared_profile(&profile);
                std::fs::remove_file(profile.join(format!("deps/libother-{OLD}.rlib"))).unwrap();
            }
            set_times(&target, ago(40));
            let now = SystemTime::now() - Duration::from_secs(2 * DAY);
            let window = Duration::from_secs(12 * 3600);
            assert!(verified_test_watch(&cache, &target, now, Some("boot-a")).is_none());
            let fingerprint = unit_named(&profile, NEW).fingerprint();
            let file = fingerprint.join("lib-serde");
            std::fs::remove_file(&file).unwrap();
            assert!(verified_test_watch(&cache, &target, now + window, Some("boot-a")).is_none());
            assert!(!verified_record(&cache, &target).exists());
            std::fs::remove_dir(&fingerprint).unwrap();
            assert!(verified_test_watch(&cache, &target, now + window, Some("boot-a")).is_none());
            assert!(!verified_record(&cache, &target).exists());
            write(&file, "restored");
            set_times(&fingerprint, ago(40));
            assert!(verified_test_watch(&cache, &target, now + window, Some("boot-a")).is_none());
            let unknown = profile.join("build/unknown");
            write(&unknown.join("not-a-hash/fingerprint/file"), "unknown");
            assert!(
                verified_test_watch(&cache, &target, now + 2 * window, Some("boot-a")).is_none()
            );
            std::fs::remove_dir_all(unknown).unwrap();
            assert!(
                verified_test_watch(&cache, &target, now + 2 * window, Some("boot-a")).is_none()
            );
            assert!(
                verified_test_watch(&cache, &target, now + 3 * window, Some("boot-a")).is_some()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_arming_forgets_legacy_evidence_and_busy_locks_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        let profile = target.join("debug");
        per_unit_profile(&profile);
        set_times(&target, ago(40));
        let now = SystemTime::now() - Duration::from_secs(2 * DAY);
        let window = Duration::from_secs(12 * 3600);
        write_armed(&armed_record(&cache, &target), now - window).unwrap();
        read_now(&unit_named(&profile, NEW));
        assert!(verified_test_watch(&cache, &target, now, Some("boot-a")).is_none());
        assert_eq!(unused_since(&cache, &target), None);
        let locks = hold(&profile).unwrap();
        assert!(verified_test_watch(&cache, &target, now + window, Some("boot-a")).is_none());
        drop(locks);
        assert!(verified_test_watch(&cache, &target, now + window, Some("boot-a")).is_none());
        assert!(verified_test_watch(&cache, &target, now + 2 * window, Some("boot-a")).is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_observes_actual_fingerprint_reads_when_supported() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        let profile = target.join("debug");
        per_unit_profile(&profile);
        set_times(&target, ago(40));
        if !verified_shows_reads(&target).unwrap() {
            return;
        }
        let start = SystemTime::now() - Duration::from_secs(2 * DAY);
        let window = Duration::from_secs(12 * 3600);
        assert!(
            verified_watch(
                &cache,
                &target,
                SystemTime::now(),
                SystemTime::UNIX_EPOCH,
                window,
                b"epoch-a"
            )
            .is_none()
        );
        assert!(verified_record(&cache, &target).exists());
        let uptime = std::cell::Cell::new(Duration::from_secs(DAY));
        let ops = VerifiedOps {
            epoch: b"epoch-a",
            boot: &linux_boot_id,
            uptime: &|| Some(uptime.get()),
            probe: &verified_shows_reads,
            arm: &verified_arm_file,
            read: &verified_read_file,
            write: &write_verified,
        };
        assert!(
            verified_watch_with(&cache, &target, start, SystemTime::UNIX_EPOCH, window, &ops)
                .is_none()
        );
        uptime.set(uptime.get() + window);
        assert!(
            verified_watch_with(
                &cache,
                &target,
                start + window,
                SystemTime::UNIX_EPOCH,
                window,
                &ops
            )
            .is_some()
        );
        let fingerprint = unit_named(&profile, NEW).fingerprint();
        std::fs::read(fingerprint.join("lib-serde")).unwrap();
        assert!(
            verified_watch_with(
                &cache,
                &target,
                start + window,
                SystemTime::UNIX_EPOCH,
                window,
                &ops
            )
            .is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_never_arms_when_the_real_probe_cannot_observe_reads() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        per_unit_profile(&target.join("debug"));
        set_times(&target, ago(40));
        if !verified_shows_reads(&target).unwrap() {
            assert!(
                verified_watch(
                    &cache,
                    &target,
                    SystemTime::now(),
                    SystemTime::UNIX_EPOCH,
                    Duration::from_secs(12 * 3600),
                    b"epoch-a"
                )
                .is_none()
            );
            assert!(!verified_record(&cache, &target).exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_file_operations_refuse_replaced_files_and_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("fingerprint");
        let outside = dir.path().join("outside");
        write(&file, "original");
        write(&outside, "outside");
        let expected = std::fs::metadata(&file).unwrap();
        std::fs::rename(&file, dir.path().join("original")).unwrap();
        write(&file, "replacement");
        assert!(verified_arm_file(&file, &expected).is_err());
        assert!(verified_read_file(&file, &expected).is_err());
        std::fs::remove_file(&file).unwrap();
        symlink(&outside, &file).unwrap();
        assert!(verified_arm_file(&file, &expected).is_err());
        assert!(verified_read_file(&file, &expected).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_watch_rechecks_fingerprints_after_the_probe() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        let profile = target.join("debug");
        per_unit_profile(&profile);
        set_times(&target, ago(40));
        let now = SystemTime::now() - Duration::from_secs(2 * DAY);
        let window = Duration::from_secs(12 * 3600);
        assert!(verified_test_watch(&cache, &target, now, Some("boot-a")).is_none());
        let file = unit_named(&profile, NEW).fingerprint().join("lib-serde");
        let ops = VerifiedOps {
            epoch: b"epoch-a",
            boot: &|| Some("boot-a".to_owned()),
            uptime: &|| (now + window).duration_since(SystemTime::UNIX_EPOCH).ok(),
            probe: &|_| {
                simulated_read(&file)?;
                Ok(true)
            },
            arm: &verified_arm_file,
            read: &|file, _| simulated_read(file),
            write: &write_verified,
        };
        assert!(
            verified_watch_with(
                &cache,
                &target,
                now + window,
                SystemTime::UNIX_EPOCH,
                window,
                &ops
            )
            .is_none()
        );
        assert!(!verified_record(&cache, &target).exists());
        assert!(verified_test_watch(&cache, &target, now + window, Some("boot-a")).is_none());
    }

    #[test]
    fn a_watched_target_is_unused_until_a_build_reads_or_writes_a_unit() {
        for layout in [shared_profile as fn(&Path), per_unit_profile] {
            let cache = tempfile::tempdir().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target");
            layout(&target.join("debug"));
            assert_eq!(unused_since(cache.path(), &target), None, "never armed");

            set_times(&target, ago(40));
            let armed = SystemTime::now() - Duration::from_secs(3);
            sweep(&target, None, || true);
            write_armed(&armed_record(cache.path(), &target), armed).unwrap();
            let since = unused_since(cache.path(), &target).unwrap();
            assert!(
                since <= armed && armed.duration_since(since).unwrap() < Duration::from_secs(2)
            );

            // A build that compiles nothing still reads every fingerprint.
            let fingerprint = unit_named(&target.join("debug"), NEW).fingerprint();
            for file in entries(&fingerprint) {
                let now = filetime::FileTime::now();
                filetime::set_file_atime(&file, now).unwrap();
            }
            assert_eq!(
                unused_since(cache.path(), &target),
                None,
                "read since armed"
            );
        }
    }

    #[test]
    fn a_target_without_units_is_never_unused() {
        let cache = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        write(&target.join("debug/deps/libplain.rlib"), "keep");
        write_armed(&armed_record(cache.path(), &target), ago(40)).unwrap();
        assert_eq!(unused_since(cache.path(), &target), None);
    }

    fn unit_named(profile: &Path, hash: &str) -> Unit {
        units(profile)
            .into_iter()
            .find(|unit| unit.fingerprint().to_string_lossy().contains(hash))
            .unwrap()
    }

    /// Whether reads should move atime on `dir`: on Linux, unless `noatime`.
    #[cfg(target_os = "linux")]
    fn reads_should_show(dir: &Path) -> Option<bool> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
        // SAFETY: statvfs is plain old data; all-zero bytes are a valid value.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is NUL-terminated and `stat` is a valid out pointer.
        assert_eq!(unsafe { libc::statvfs(path.as_ptr(), &mut stat) }, 0);
        Some(stat.f_flag & libc::ST_NOATIME == 0)
    }

    /// Unknown elsewhere: NTFS and some macOS volumes skip it by setting.
    #[cfg(not(target_os = "linux"))]
    fn reads_should_show(_dir: &Path) -> Option<bool> {
        None
    }

    #[test]
    fn probes_whether_reads_move_an_armed_access_time() {
        let dir = tempfile::tempdir().unwrap();
        let visible = reads_visible(dir.path());
        if let Some(expected) = reads_should_show(dir.path()) {
            assert_eq!(visible, expected);
        }
        assert!(entries(dir.path()).is_empty(), "the probe is removed");
        assert!(!reads_visible(&dir.path().join("missing")));
        assert_eq!(
            probe_reads(&dir.path().join("missing")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound,
            "a probe that cannot run is not a probe that saw no read"
        );
        let armed = filetime::FileTime::from_unix_time(1_000, 0);
        assert!(moved_past(
            filetime::FileTime::from_unix_time(1_001, 0),
            armed
        ));
        assert!(!moved_past(armed, armed));
    }

    #[test]
    fn arms_waits_then_judges() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100 * DAY);
        let window = Duration::from_secs(30 * DAY);
        assert_eq!(step(None, now, window), Step::Arm);
        let armed = now - Duration::from_secs(30 * DAY);
        assert_eq!(step(Some(armed), now, window), Step::Judge(armed));
        let recent = armed + Duration::from_secs(1);
        assert_eq!(step(Some(recent), now, window), Step::Wait);
        let future = now + Duration::from_secs(1);
        assert_eq!(step(Some(future), now, window), Step::Arm);
    }

    #[test]
    fn finds_the_hash_in_an_output_name() {
        assert_eq!(
            hashed_name(&format!("libserde-{OLD}.rlib")),
            Some(("libserde", OLD))
        );
        assert_eq!(hashed_name(&format!("app-{OLD}")), Some(("app", OLD)));
        assert_eq!(
            hashed_name(&format!("proc-macro2-{OLD}.d")),
            Some(("proc-macro2", OLD))
        );
        assert_eq!(
            hashed_name(&format!("app-{OLD}.app.0-cgu.0.rcgu.o")),
            Some(("app", OLD))
        );
        for plain in ["libplain.rlib", "a-b", &format!("x-{OLD}x"), "x-0123"] {
            assert_eq!(hashed_name(plain), None, "{plain}");
        }
    }

    #[test]
    fn a_shared_unit_owns_only_outputs_of_its_crate() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("debug");
        shared_profile(&profile);
        let unit = unit_named(&profile, OLD);
        let name = format!("serde-{OLD}");
        assert_eq!(
            unit.parts(&outputs(&profile)),
            vec![
                profile.join(".fingerprint").join(&name),
                profile.join("build").join(&name),
                profile.join("deps").join(format!("libserde-{OLD}.rlib")),
                profile.join("deps").join(format!("serde-{OLD}.d")),
            ]
        );
        let hyphenated = Unit::Shared {
            profile: profile.clone(),
            package: "proc-macro2".into(),
            hash: NEW.into(),
        };
        write(
            &profile.join(format!("deps/libproc_macro2-{NEW}.rlib")),
            "x",
        );
        assert!(
            hyphenated
                .parts(&outputs(&profile))
                .contains(&profile.join(format!("deps/libproc_macro2-{NEW}.rlib")))
        );
    }

    #[test]
    fn finds_units_in_both_layouts_and_every_profile() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        shared_profile(&target.join("debug"));
        per_unit_profile(&target.join("aarch64-apple-darwin/release"));
        std::fs::create_dir_all(target.join("tmp")).unwrap();
        assert_eq!(
            profiles(target),
            vec![
                target.join("aarch64-apple-darwin/release"),
                target.join("debug")
            ]
        );
        assert!(
            units(&target.join("debug"))
                .iter()
                .all(|unit| matches!(unit, Unit::Shared { .. }))
        );
        assert_eq!(units(&target.join("aarch64-apple-darwin/release")).len(), 2);
        write(&target.join("debug/build/serde/nothex/fingerprint/x"), "");
        write(&target.join("debug/build/serde/aaaaaaaaaaaaaaaa/out/x"), "");
        write(&target.join("debug/.fingerprint/nohash/x"), "");
        assert_eq!(units(&target.join("debug")).len(), 2);
    }

    #[test]
    fn a_read_or_write_after_arming_is_use() {
        let dir = tempfile::tempdir().unwrap();
        let fingerprint = dir.path().join("fp");
        write(&fingerprint.join("a"), "a");
        write(&fingerprint.join("b"), "b");
        set_times(&fingerprint, ago(10));
        let armed = ago(5);
        assert!(!used_since(&fingerprint, armed));
        let read = filetime::FileTime::from_system_time(ago(1));
        filetime::set_file_atime(fingerprint.join("b"), read).unwrap();
        assert!(used_since(&fingerprint, armed));
        set_times(&fingerprint, ago(10));
        filetime::set_file_mtime(fingerprint.join("a"), read).unwrap();
        assert!(used_since(&fingerprint, armed));
        // An empty fingerprint is judged by the directory.
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        let old = filetime::FileTime::from_system_time(ago(10));
        filetime::set_file_mtime(&empty, old).unwrap();
        assert!(!used_since(&empty, armed));
        assert!(used_since(&empty, ago(20)));
        assert!(used_since(&dir.path().join("missing"), armed));
    }

    #[test]
    fn arming_puts_the_access_time_below_the_modification_time() {
        let dir = tempfile::tempdir().unwrap();
        let fingerprint = dir.path().join("fp");
        write(&fingerprint.join("a"), "a");
        set_times(&fingerprint, ago(10));
        arm(&fingerprint);
        let metadata = std::fs::metadata(fingerprint.join("a")).unwrap();
        let modified = filetime::FileTime::from_last_modification_time(&metadata);
        let accessed = filetime::FileTime::from_last_access_time(&metadata);
        assert_eq!(accessed.unix_seconds(), modified.unix_seconds() - 1);
        assert!(!used_since(&fingerprint, ago(5)));
        // Where reads show, a read now moves it past any moment after arming.
        std::fs::read(fingerprint.join("a")).unwrap();
        if reads_visible(dir.path()) {
            assert!(used_since(&fingerprint, ago(1)));
        }
    }

    #[test]
    fn a_time_equal_to_the_arming_is_not_use() {
        let dir = tempfile::tempdir().unwrap();
        let armed = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let at = filetime::FileTime::from_system_time(armed);
        let fingerprint = dir.path().join("fp");
        write(&fingerprint.join("a"), "a");
        filetime::set_file_times(fingerprint.join("a"), at, at).unwrap();
        assert!(!used_since(&fingerprint, armed));
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        filetime::set_file_mtime(&empty, at).unwrap();
        assert!(!used_since(&empty, armed));
    }

    /// Record a build's read of `unit`'s fingerprint now, the way a
    /// filesystem that shows reads would.
    fn read_now(unit: &Unit) {
        let now = filetime::FileTime::now();
        for file in entries(&unit.fingerprint()) {
            filetime::set_file_atime(&file, now).unwrap();
        }
    }

    #[test]
    fn removes_units_nobody_used_since_arming_in_both_layouts() {
        for per_unit in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cache = dir.path().join("cache");
            let target = dir.path().join("target");
            let profile = target.join("debug");
            if per_unit {
                per_unit_profile(&profile);
            } else {
                shared_profile(&profile);
            }
            set_times(&profile, ago(60));
            let window = Duration::from_secs(30 * DAY);
            // First sight: armed, nothing removed.
            assert_eq!(judge(&cache, &target, window, ago(40)), Pruned::default());
            assert_eq!(units(&profile).len(), 2);
            // Within the window: nothing to judge.
            assert_eq!(judge(&cache, &target, window, ago(20)), Pruned::default());
            // A build used `NEW` after arming.
            read_now(&unit_named(&profile, NEW));
            let old = unit_named(&profile, OLD);
            let parts = old.parts(&outputs(&profile));
            let bytes: u64 = parts.iter().map(|part| size(part)).sum();
            let pruned = judge(&cache, &target, window, SystemTime::now());
            assert_eq!(
                (pruned.units, pruned.bytes),
                (1, bytes),
                "per_unit={per_unit}"
            );
            for part in &parts {
                assert!(!part.exists(), "{}", part.display());
            }
            let left = units(&profile);
            assert_eq!(left, vec![unit_named(&profile, NEW)]);
            if !per_unit {
                assert!(profile.join(format!("deps/libother-{OLD}.rlib")).exists());
                assert!(profile.join("deps/libplain.rlib").exists());
            }
            for lock in LOCKS {
                assert!(profile.join(lock).exists(), "{lock}");
            }
            // Re-armed: judged again only after another window.
            assert_eq!(
                judge(&cache, &target, window, SystemTime::now()),
                Pruned::default()
            );
            let record = armed_record(&cache, &target);
            assert!(read_armed(&record).is_some());
        }
    }

    #[test]
    fn a_preview_reports_what_a_prune_removes_and_changes_nothing() {
        for per_unit in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cache = dir.path().join("cache");
            let target = dir.path().join("target");
            let profile = target.join("debug");
            if per_unit {
                per_unit_profile(&profile);
            } else {
                shared_profile(&profile);
            }
            set_times(&profile, ago(60));
            let window = Duration::from_secs(30 * DAY);
            let now = SystemTime::now();
            assert_eq!(preview(&cache, &target, window, now), Pruned::default());
            judge(&cache, &target, window, ago(40));
            assert_eq!(preview(&cache, &target, window, ago(20)), Pruned::default());
            let used = unit_named(&profile, NEW);
            read_now(&used);
            let accessed = |unit: &Unit| {
                entries(&unit.fingerprint())
                    .iter()
                    .map(|file| std::fs::metadata(file).unwrap().accessed().unwrap())
                    .collect::<Vec<_>>()
            };
            let before = accessed(&used);
            let record = armed_record(&cache, &target);
            let armed = read_armed(&record);
            let expected = preview(&cache, &target, window, now);
            assert_eq!(expected.units, 1, "per_unit={per_unit}");
            assert!(expected.bytes > 0);
            assert_eq!(units(&profile).len(), 2, "nothing removed");
            assert_eq!(accessed(&used), before, "nothing armed");
            assert_eq!(read_armed(&record), armed, "the record kept");
            assert_eq!(judge(&cache, &target, window, now), expected);
        }
    }

    #[test]
    fn needs_a_local_filesystem_that_shows_reads() {
        assert!(can_prune(true, || Ok(true)).unwrap());
        assert!(!can_prune(true, || Ok(false)).unwrap());
        assert!(!can_prune(false, || Ok(true)).unwrap());
        assert!(!can_prune(false, || panic!("not asked off a local filesystem")).unwrap());
        let full = || Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
        assert_eq!(
            can_prune(true, full).unwrap_err().kind(),
            std::io::ErrorKind::StorageFull
        );
    }

    #[test]
    fn prunes_only_where_the_filesystem_shows_reads() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let window = Duration::from_secs(30 * DAY);
        let missing = dir.path().join("missing");
        assert_eq!(
            prune(&cache, &missing, window, SystemTime::now()),
            Pruned::default()
        );
        assert_eq!(
            read_armed(&armed_record(&cache, &missing)),
            None,
            "a missing target is never armed"
        );
        let target = dir.path().join("target");
        per_unit_profile(&target.join("debug"));
        set_times(&target, ago(60));
        prune(&cache, &target, window, ago(40));
        let armed = read_armed(&armed_record(&cache, &target));
        // Arming happens only where reads show, and only then is it recorded.
        assert_eq!(armed.is_some(), reads_visible(&target));
    }

    #[test]
    fn a_probe_that_cannot_run_keeps_the_arming() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        let profile = target.join("debug");
        per_unit_profile(&profile);
        set_times(&target, ago(60));
        let record = armed_record(&cache, &target);
        write_armed(&record, ago(40)).unwrap();
        let armed = read_armed(&record);
        let window = Duration::from_secs(30 * DAY);
        let now = SystemTime::now();
        // A full volume refuses the probe's file.
        let full = |_: &Path| -> std::io::Result<bool> {
            Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
        };
        // Judged now, both units would go, and a watch would arm again.
        assert_eq!(
            prune_with(&cache, &target, window, now, full),
            Pruned::default()
        );
        assert_eq!(read_armed(&record), armed, "prune kept the arming");
        assert_eq!(units(&profile).len(), 2, "prune skipped the target");
        watch_with(&cache, &target, now, ago(30), full, write_armed);
        assert_eq!(read_armed(&record), armed, "watch kept the arming");

        // Reads that do not show still forget it.
        let hidden = |_: &Path| -> std::io::Result<bool> { Ok(false) };
        watch_with(&cache, &target, now, ago(30), hidden, write_armed);
        assert_eq!(read_armed(&record), None);
        write_armed(&record, ago(40)).unwrap();
        assert_eq!(
            prune_with(&cache, &target, window, now, hidden),
            Pruned::default()
        );
        assert_eq!(read_armed(&record), None);
        assert_eq!(units(&profile).len(), 2);
    }

    /// Write `record` the way a full APFS volume does: a new file goes in,
    /// but nothing is renamed onto one that exists.
    fn write_where_free(record: &Path, at: SystemTime) -> anyhow::Result<()> {
        if record.exists() {
            return Err(std::io::Error::from(std::io::ErrorKind::StorageFull).into());
        }
        write_armed(record, at)
    }

    fn write_nothing(_: &Path, _: SystemTime) -> anyhow::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::StorageFull).into())
    }

    #[test]
    fn an_arming_never_keeps_an_older_record() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        let profile = target.join("debug");
        per_unit_profile(&profile);
        set_times(&target, ago(60));
        let window = Duration::from_secs(30 * DAY);
        let hour = Duration::from_secs(3600);
        judge(&cache, &target, window, ago(40));
        let used = unit_named(&profile, NEW);
        read_now(&used);

        let now = SystemTime::now();
        let pruned = judge_with(&cache, &target, window, now, write_where_free);
        assert_eq!((pruned.units, pruned.used), (1, 1));
        // `used` was armed again under the new record. Judged an hour on
        // against the old one, it would look unused and go.
        assert_eq!(
            judge(&cache, &target, window, now + hour),
            Pruned::default()
        );
        assert_eq!(units(&profile), vec![used.clone()]);

        // With no record written at all, none is left: the next check arms
        // from scratch.
        read_now(&used);
        let later = now + window;
        let pruned = judge_with(&cache, &target, window, later, write_nothing);
        assert_eq!((pruned.units, pruned.used), (0, 1));
        assert_eq!(read_armed(&armed_record(&cache, &target)), None);
        assert_eq!(
            judge(&cache, &target, window, later + hour),
            Pruned::default()
        );
        assert_eq!(units(&profile), vec![used]);
    }

    #[test]
    fn a_watch_never_keeps_an_older_record() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        let profile = target.join("debug");
        per_unit_profile(&profile);
        set_times(&target, ago(60));
        let shows = |_: &Path| -> std::io::Result<bool> { Ok(true) };
        watch_with(&cache, &target, ago(10), ago(20), shows, write_armed);
        let first = unused_since(&cache, &target).unwrap();
        let used = unit_named(&profile, NEW);
        read_now(&used);

        let now = SystemTime::now();
        watch_with(&cache, &target, now, ago(20), shows, write_where_free);
        let since = unused_since(&cache, &target).unwrap();
        assert!(since > first, "idle from the new arming, not the old");

        read_now(&used);
        watch_with(&cache, &target, now, ago(20), shows, write_nothing);
        assert_eq!(unused_since(&cache, &target), None, "no record is left");
    }

    #[test]
    fn units_that_stay_are_not_armed_while_the_old_record_stays() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let profile = target.join("debug");
        per_unit_profile(&profile);
        set_times(&target, ago(60));
        sweep(&target, None, || true);
        let used = unit_named(&profile, NEW);
        read_now(&used);
        let armed = ago(40);
        let (pruned, complete) = sweep(&target, Some(armed), || false);
        assert_eq!((pruned.units, pruned.used, complete), (1, 1, false));
        assert!(
            used_since(&used.fingerprint(), armed),
            "the read still shows"
        );
        assert_eq!(units(&profile), vec![used]);
    }

    /// The record directory turned read-only after an arming was recorded:
    /// the old record can be neither replaced nor removed.
    #[cfg(unix)]
    #[test]
    fn a_record_that_cannot_be_removed_keeps_the_reads_it_judges_by() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: plain libc call with no arguments.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        let target = dir.path().join("target");
        let profile = target.join("debug");
        per_unit_profile(&profile);
        set_times(&target, ago(60));
        let window = Duration::from_secs(30 * DAY);
        judge(&cache, &target, window, ago(40));
        let record = armed_record(&cache, &target);
        let armed = read_armed(&record);
        let used = unit_named(&profile, NEW);
        read_now(&used);
        let records = record.parent().unwrap();
        let mode = |mode| std::fs::set_permissions(records, std::fs::Permissions::from_mode(mode));
        mode(0o555).unwrap();
        let now = SystemTime::now();
        let pruned = judge(&cache, &target, window, now);
        let shows = |_: &Path| -> std::io::Result<bool> { Ok(true) };
        watch_with(&cache, &target, now, ago(50), shows, write_armed);
        mode(0o755).unwrap();
        assert_eq!((pruned.units, pruned.used), (1, 1));
        assert_eq!(read_armed(&record), armed);
        assert_eq!(unused_since(&cache, &target), None, "watch armed nothing");

        let pruned = judge(&cache, &target, window, now + Duration::from_secs(3600));
        assert_eq!((pruned.units, pruned.used), (0, 1));
        assert_eq!(units(&profile), vec![used]);
    }

    #[test]
    fn a_profile_a_build_holds_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("debug");
        per_unit_profile(&profile);
        set_times(&profile, ago(10));
        for name in LOCKS {
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(profile.join(name))
                .unwrap();
            lock.lock().unwrap();
            let (pruned, complete) = sweep(dir.path(), Some(ago(5)), || true);
            assert_eq!(pruned, Pruned::default(), "{name}");
            assert!(!complete, "a held profile is reported: {name}");
            assert_eq!(units(&profile).len(), 2);
            // A fork elsewhere in the suite can hold a duplicate past the drop.
            lock.unlock().unwrap();
        }
        let (pruned, complete) = sweep(dir.path(), Some(ago(5)), || true);
        assert_eq!((pruned.units, complete), (2, true));
    }

    #[test]
    fn a_busy_profile_preserves_recent_use_in_every_profile() {
        for per_unit in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cache = dir.path().join("cache");
            let target = dir.path().join("target");
            for name in ["debug", "release"] {
                let profile = target.join(name);
                if per_unit {
                    per_unit_profile(&profile);
                } else {
                    shared_profile(&profile);
                }
            }
            set_times(&target, ago(60));
            let window = Duration::from_secs(30 * DAY);
            judge(&cache, &target, window, ago(40));
            let record = armed_record(&cache, &target);
            let armed = read_armed(&record).unwrap();
            // Whichever profile is visited first must retain its evidence
            // when a later profile is held by Cargo.
            let ordered = profiles(&target);
            let used = unit_named(&ordered[0], NEW);
            read_now(&used);
            let before: Vec<_> = entries(&used.fingerprint())
                .iter()
                .map(|file| std::fs::metadata(file).unwrap().accessed().unwrap())
                .collect();
            let locks = hold(&ordered[1]).unwrap();
            assert_eq!(
                judge(&cache, &target, window, SystemTime::now()),
                Pruned::default()
            );
            assert_eq!(read_armed(&record), Some(armed));
            assert_eq!(
                entries(&used.fingerprint())
                    .iter()
                    .map(|file| std::fs::metadata(file).unwrap().accessed().unwrap())
                    .collect::<Vec<_>>(),
                before,
                "a skipped pass must retain recent use"
            );
            assert_eq!(units(&ordered[0]).len(), 2);
            drop(locks);
            let pruned = judge(&cache, &target, window, SystemTime::now());
            assert_eq!((pruned.units, pruned.used), (3, 1));
            assert_eq!(units(&ordered[0]), vec![used]);
            assert!(units(&ordered[1]).is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn released_locks_are_free_while_a_duplicate_is_open() {
        let dir = tempfile::tempdir().unwrap();
        let held = hold(dir.path()).unwrap();
        // A fork shares the open file description the same way a duplicate does.
        let duplicates: Vec<_> = held.0.iter().map(|f| f.try_clone().unwrap()).collect();
        assert_eq!(duplicates.len(), LOCKS.len());
        assert!(hold(dir.path()).is_none(), "the locks are held");
        drop(held);
        assert!(hold(dir.path()).is_some(), "a duplicate kept a lock held");
        drop(duplicates);
    }

    #[test]
    fn records_when_a_target_was_armed() {
        let dir = tempfile::tempdir().unwrap();
        let record = armed_record(dir.path(), Path::new("/some/target"));
        assert_ne!(record, armed_record(dir.path(), Path::new("/other/target")));
        assert_eq!(read_armed(&record), None);
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        write_armed(&record, at).unwrap();
        assert_eq!(read_armed(&record), Some(at));
        std::fs::write(&record, "garbage").unwrap();
        assert_eq!(read_armed(&record), None);
    }

    #[test]
    fn removal_stops_at_the_first_failure() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        write(&a.join("x"), "x");
        let b = dir.path().join("b");
        write(&b, "bb");
        assert_eq!(size(&a) + size(&b), 3);
        remove(&[a.clone(), dir.path().join("missing"), b.clone()]).unwrap();
        assert!(!a.exists() && !b.exists());
        assert_eq!(size(&dir.path().join("missing")), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // SAFETY: plain libc call with no arguments.
            let root = unsafe { libc::geteuid() } == 0;
            let locked = dir.path().join("locked");
            write(&locked.join("file"), "x");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
            let after = dir.path().join("after");
            write(&after, "x");
            if !root {
                assert!(remove(&[locked.join("file"), after.clone()]).is_err());
                assert!(after.exists(), "nothing after a failure is removed");
            }
            // A part that cannot even be looked up is a failure, not absent.
            let sealed = dir.path().join("sealed");
            write(&sealed.join("file"), "x");
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
            if !root {
                assert!(remove(&[sealed.join("file"), after.clone()]).is_err());
                assert!(after.exists());
            }
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}
