//! Probe hardlinks and bidirectional reflinks between a build tree and staging.
//!
//! This is observability only; it does not change how artifacts are shared.

use std::io::Write;
use std::path::Path;

/// Outcome of one reflink probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReflinkProbe {
    /// The reflink succeeded.
    Supported,
    /// The filesystem or platform rejected this reflink as unsupported.
    Unsupported,
    /// The probe could not determine support, with an explanation.
    Unknown(String),
}

/// Outcome of [`probe_link_layout`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLayoutReport {
    /// Whether `link(source_tmp, staging_tmp)` succeeded.
    pub hardlink_supported: bool,
    /// `io::ErrorKind` name on failure (`CrossesDevices`, …), else `None`.
    pub error_kind: Option<String>,
    /// Full io error on failure, else `None`.
    pub error_message: Option<String>,
    /// Mount point containing the build-tree temp, if determinable (Linux).
    pub source_mount: Option<String>,
    /// Mount point containing `<store>/staging`, if determinable (Linux).
    pub dest_mount: Option<String>,
    /// Content of `/proc/sys/fs/protected_hardlinks` (`0`/`1`), if readable.
    pub protected_hardlinks: Option<String>,
    /// Current uid, if determinable (unix).
    pub uid: Option<u32>,
    /// Owner uid of the build-tree temp, if determinable (unix).
    pub source_owner: Option<u32>,
    /// Owner uid of the staging dir, if determinable (unix).
    pub dest_owner: Option<u32>,
    /// Outcome of a staging-local reflink.
    pub ficlone_supported: ReflinkProbe,
    /// Outcome of a reflink from the build tree into staging.
    pub reflink_build_to_staging: ReflinkProbe,
    /// Outcome of a reflink from staging into the build tree.
    pub reflink_staging_to_build: ReflinkProbe,
}

impl LinkLayoutReport {
    pub(crate) fn sharing_supported(&self) -> bool {
        self.hardlink_supported
            || (self.reflink_build_to_staging == ReflinkProbe::Supported
                && self.reflink_staging_to_build == ReflinkProbe::Supported)
    }

    pub(crate) fn cross_reflinks_determined(&self) -> bool {
        !matches!(self.reflink_build_to_staging, ReflinkProbe::Unknown(_))
            && !matches!(self.reflink_staging_to_build, ReflinkProbe::Unknown(_))
    }
}

/// Probe hardlinks and reflinks between `build_dir` and `staging_dir`.
///
/// Probe files are created exclusively in temporary paths and removed on
/// return. Inconclusive reflink probes retain their failure details.
pub fn probe_link_layout(build_dir: &Path, staging_dir: &Path) -> LinkLayoutReport {
    probe_link_layout_with(build_dir, staging_dir, reflink_supported_between)
}

fn probe_link_layout_with(
    build_dir: &Path,
    staging_dir: &Path,
    mut reflink_probe: impl FnMut(&Path, &Path) -> ReflinkProbe,
) -> LinkLayoutReport {
    let mut report = LinkLayoutReport {
        hardlink_supported: false,
        error_kind: None,
        error_message: None,
        source_mount: find_mount_for_path(build_dir),
        dest_mount: find_mount_for_path(staging_dir),
        protected_hardlinks: read_protected_hardlinks(),
        uid: current_uid(),
        source_owner: None,
        dest_owner: None,
        ficlone_supported: ReflinkProbe::Unknown("not attempted".into()),
        reflink_build_to_staging: ReflinkProbe::Unknown("not attempted".into()),
        reflink_staging_to_build: ReflinkProbe::Unknown("not attempted".into()),
    };

    if let Err(e) = std::fs::create_dir_all(staging_dir) {
        report.error_kind = Some("CreateDirFailed".to_string());
        report.error_message = Some(format!(
            "creating staging dir {}: {e}",
            staging_dir.display()
        ));
        return report;
    }
    report.ficlone_supported = reflink_probe(staging_dir, staging_dir);
    report.reflink_build_to_staging = reflink_probe(build_dir, staging_dir);
    report.reflink_staging_to_build = reflink_probe(staging_dir, build_dir);

    let mut source_tmp = match tempfile::Builder::new()
        .prefix(".kache-link-probe-")
        .tempfile_in(build_dir)
    {
        Ok(file) => file,
        Err(e) => {
            report.error_kind = Some(io_kind_name(&e));
            report.error_message = Some(format!(
                "creating probe file in {}: {e}",
                build_dir.display()
            ));
            return report;
        }
    };
    if let Err(e) = source_tmp.write_all(b"kache-link-probe") {
        report.error_kind = Some(io_kind_name(&e));
        report.error_message = Some(format!(
            "writing probe file in {}: {e}",
            build_dir.display()
        ));
        return report;
    }
    report.source_owner = file_owner(source_tmp.path());
    report.dest_owner = file_owner(staging_dir);

    let dest_tmp = match tempfile::Builder::new()
        .prefix(".kache-link-probe-")
        .tempdir_in(staging_dir)
    {
        Ok(dir) => dir,
        Err(e) => {
            report.error_kind = Some(io_kind_name(&e));
            report.error_message = Some(format!(
                "creating probe directory in {}: {e}",
                staging_dir.display()
            ));
            return report;
        }
    };
    let dest_path = dest_tmp.path().join("link");
    match std::fs::hard_link(source_tmp.path(), &dest_path) {
        Ok(()) => report.hardlink_supported = true,
        Err(e) => {
            report.error_kind = Some(io_kind_name(&e));
            report.error_message = Some(format!(
                "linking {} into {}: {e}",
                source_tmp.path().display(),
                dest_path.display()
            ));
        }
    }
    report
}

/// `path` as doctor shows it. On Unix it is resolved, so one directory
/// reached through a symlink such as macOS's `/var` is named one way;
/// unresolvable paths are shown as given. Windows shows it as given:
/// resolving would replace a `subst` drive or short name with another
/// spelling and add the `\\?\` prefix.
pub(crate) fn shown_path(path: &Path) -> String {
    if cfg!(unix)
        && let Ok(real) = std::fs::canonicalize(path)
    {
        return real.display().to_string();
    }
    path.display().to_string()
}

fn io_kind_name(e: &std::io::Error) -> String {
    format!("{:?}", e.kind())
}

/// Human detail for an EXDEV probe failure, with both mount roots.
pub(crate) fn format_exdev_detail(source_mount: Option<&str>, dest_mount: Option<&str>) -> String {
    format!(
        "{}. Put the cache and build tree on the SAME mount for zero-copy sharing",
        format_exdev_cause(source_mount, dest_mount)
    )
}

fn format_exdev_cause(source_mount: Option<&str>, dest_mount: Option<&str>) -> String {
    match (source_mount, dest_mount) {
        (Some(src), Some(dst)) if exdev_mounts_differ(src, dst) => format!(
            "EXDEV: build tree is on mount `{src}` but `<store>/staging` is on mount `{dst}` — \
             Linux refuses link() across mounts, including two bind mounts of one filesystem"
        ),
        (Some(mnt), Some(_)) => format!(
            "EXDEV even though both paths resolve under mount `{mnt}` — the two directories \
             are on different vfsmounts (e.g. separate bind mounts of one filesystem)"
        ),
        _ => "EXDEV: hardlink across mounts refused (mount roots could not be determined)"
            .to_string(),
    }
}

fn exdev_mounts_differ(src: &str, dst: &str) -> bool {
    src != dst
}

/// Human detail for an EPERM probe failure, with hardening + ownership.
pub(crate) fn format_eperm_detail(
    protected_hardlinks: Option<&str>,
    uid: Option<u32>,
    source_owner: Option<u32>,
    dest_owner: Option<u32>,
) -> String {
    let hardening = protected_hardlinks.unwrap_or("unknown");
    format!(
        "EPERM: hardlink refused (fs.protected_hardlinks={hardening}, uid={} owner, source owner={}, staging owner={}) — \
         under protected_hardlinks the caller must own the source. Ensure one uid owns the cache",
        uid.map_or("?".to_string(), |u| u.to_string()),
        source_owner.map_or("?".to_string(), |u| u.to_string()),
        dest_owner.map_or("?".to_string(), |u| u.to_string()),
    )
}

/// Human summary for the doctor check, dispatching on the probe outcome.
/// Pure so each arm is unit-testable without bind mounts.
pub(crate) fn format_probe_detail(report: &LinkLayoutReport) -> String {
    let cross_reflinks = format!(
        "cross-path reflinks: build → staging {}, staging → build {}",
        reflink_probe_status(&report.reflink_build_to_staging),
        reflink_probe_status(&report.reflink_staging_to_build),
    );
    let ficlone = match &report.ficlone_supported {
        ReflinkProbe::Supported => "staging reflinks supported".to_string(),
        ReflinkProbe::Unsupported => "staging reflinks unsupported".to_string(),
        ReflinkProbe::Unknown(reason) => format!("staging reflink support unknown ({reason})"),
    };
    if report.hardlink_supported {
        return format!(
            "hardlink build-tree → <store>/staging works ({ficlone}; {cross_reflinks})"
        );
    }
    let kind = report.error_kind.as_deref().unwrap_or("Unknown");
    if report.sharing_supported() {
        return format!(
            "{ficlone}; {cross_reflinks}; hardlink fallback unavailable (build-tree → <store>/staging failed: {kind})"
        );
    }
    let hardlink_detail = if kind == "CrossesDevices" {
        if report.cross_reflinks_determined() {
            format_exdev_detail(report.source_mount.as_deref(), report.dest_mount.as_deref())
        } else {
            format_exdev_cause(report.source_mount.as_deref(), report.dest_mount.as_deref())
        }
    } else if kind == "PermissionDenied" {
        format_eperm_detail(
            report.protected_hardlinks.as_deref(),
            report.uid,
            report.source_owner,
            report.dest_owner,
        )
    } else {
        format!(
            "hardlink build-tree → <store>/staging failed ({kind}): {}",
            report.error_message.as_deref().unwrap_or("unknown error")
        )
    };
    format!("{hardlink_detail}; {ficlone}; {cross_reflinks}")
}

fn reflink_probe_status(result: &ReflinkProbe) -> String {
    match result {
        ReflinkProbe::Supported => "works".to_string(),
        ReflinkProbe::Unsupported => "unsupported".to_string(),
        ReflinkProbe::Unknown(reason) => format!("unknown ({reason})"),
    }
}

/// Mount point containing `path`, if determinable. Linux parses
/// `/proc/self/mountinfo`; elsewhere returns `None`.
fn find_mount_for_path(path: &Path) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        let abs = absolute_path(path)?;
        find_mount_root(&abs, &content)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

/// Longest mount point in `mountinfo` that contains `abs_path`.
/// `abs_path` must be absolute; `mountinfo` is `/proc/self/mountinfo` content.
/// Pure so bind-mount EXDEV reporting is unit-testable without mounts.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn find_mount_root(abs_path: &Path, mountinfo: &str) -> Option<String> {
    let path_str = abs_path.to_string_lossy();
    if !path_str.starts_with('/') {
        return None;
    }
    let mut best: Option<String> = None;
    for line in mountinfo.lines() {
        let Some(mount_point) = parse_mountinfo_mount_point(line) else {
            continue;
        };
        if !path_is_under_mount(&path_str, &mount_point) {
            continue;
        }
        let longer = best
            .as_ref()
            .is_none_or(|current: &String| mount_point_is_longer(&mount_point, current));
        if longer {
            best = Some(mount_point);
        }
    }
    best
}

/// Whether `path` lives on `mount_point`. `/` is a prefix of every absolute
/// path; concatenating `"/" + "/"` would look for `//` and miss `/tmp`.
#[cfg(any(test, target_os = "linux"))]
fn path_is_under_mount(path: &str, mount_point: &str) -> bool {
    path == mount_point
        || (mount_point == "/" && path.starts_with('/'))
        || path.starts_with(&format!("{mount_point}/"))
}

#[cfg(any(test, target_os = "linux"))]
fn mount_point_is_longer(candidate: &str, current: &str) -> bool {
    candidate.len() > current.len()
}

/// Mount point field (5th) of one `/proc/self/mountinfo` line, unescaping
/// octal spaces. Returns `None` for malformed lines.
#[cfg(any(test, target_os = "linux"))]
fn parse_mountinfo_mount_point(line: &str) -> Option<String> {
    let mut parts = line.split(' ');
    // mountinfo: id parent major:minor root mount-point options …
    let _id = parts.next()?;
    let _parent = parts.next()?;
    let _dev = parts.next()?;
    let _root = parts.next()?;
    let mount_point = parts.next()?;
    if mount_point.is_empty() {
        return None;
    }
    Some(mount_point.replace("\\040", " ").replace("\\012", "\n"))
}

#[cfg(target_os = "linux")]
fn absolute_path(path: &Path) -> Option<std::path::PathBuf> {
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    std::env::current_dir().ok().map(|cwd| cwd.join(path))
}

/// Content of `/proc/sys/fs/protected_hardlinks` (`0`/`1`), trimmed.
fn read_protected_hardlinks() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/fs/protected_hardlinks")
            .ok()
            .and_then(|s| parse_protected_hardlinks(&s))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Parse `/proc/sys/fs/protected_hardlinks` content.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn parse_protected_hardlinks(content: &str) -> Option<String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

fn current_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: getuid is async-signal-safe and has no failure mode.
        Some(unsafe { libc::getuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn file_owner(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn reflink_supported_between(source_dir: &Path, dest_dir: &Path) -> ReflinkProbe {
    reflink_supported_between_with(source_dir, dest_dir, kache_fs::try_reflink)
}

pub(crate) fn reflink_supported_between_with(
    source_dir: &Path,
    dest_dir: &Path,
    try_reflink: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> ReflinkProbe {
    let probe = || -> Result<ReflinkProbe, String> {
        let mut source = tempfile::Builder::new()
            .prefix(".kache-reflink-probe-")
            .tempfile_in(source_dir)
            .map_err(|e| {
                format!(
                    "creating a temporary source in {}: {e}",
                    source_dir.display()
                )
            })?;
        // ReFS block cloning requires at least one complete filesystem cluster.
        source.write_all(&vec![b'k'; 128 * 1024]).map_err(|e| {
            format!(
                "writing a temporary source in {}: {e}",
                source_dir.display()
            )
        })?;
        let dest = tempfile::Builder::new()
            .prefix(".kache-reflink-probe-")
            .tempdir_in(dest_dir)
            .map_err(|e| {
                format!(
                    "creating a temporary destination in {}: {e}",
                    dest_dir.display()
                )
            })?;
        Ok(
            match try_reflink(source.path(), &dest.path().join("clone")) {
                Ok(()) => ReflinkProbe::Supported,
                Err(e) if clone_error_is_unsupported(&e) => ReflinkProbe::Unsupported,
                Err(e) => ReflinkProbe::Unknown(format!(
                    "cloning from {} to {}: {e}",
                    source_dir.display(),
                    dest_dir.display()
                )),
            },
        )
    };
    probe().unwrap_or_else(ReflinkProbe::Unknown)
}

fn clone_error_is_unsupported(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    if let Some(errno) = error.raw_os_error() {
        // ENOTSUP and EOPNOTSUPP have distinct values on macOS.
        return errno == libc::EXDEV
            || errno == libc::EOPNOTSUPP
            || errno == libc::ENOTSUP
            || cfg!(target_os = "linux") && errno == libc::ENOTTY;
    }
    #[cfg(windows)]
    if let Some(code) = error.raw_os_error() {
        use windows_sys::Win32::Foundation::{ERROR_NOT_SAME_DEVICE, ERROR_NOT_SUPPORTED};
        return code == ERROR_NOT_SAME_DEVICE as i32 || code == ERROR_NOT_SUPPORTED as i32;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        error.kind() == std::io::ErrorKind::Unsupported
    }
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ReflinkProbe::{Supported, Unknown, Unsupported};

    fn unknown() -> ReflinkProbe {
        Unknown("not attempted".into())
    }

    fn empty_report() -> LinkLayoutReport {
        LinkLayoutReport {
            hardlink_supported: false,
            error_kind: None,
            error_message: None,
            source_mount: None,
            dest_mount: None,
            protected_hardlinks: None,
            uid: None,
            source_owner: None,
            dest_owner: None,
            ficlone_supported: unknown(),
            reflink_build_to_staging: unknown(),
            reflink_staging_to_build: unknown(),
        }
    }

    #[test]
    fn io_kind_name_names_the_errno() {
        let cross = std::io::Error::new(std::io::ErrorKind::CrossesDevices, "x");
        let missing = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        assert_eq!(io_kind_name(&cross), "CrossesDevices");
        assert_eq!(io_kind_name(&missing), "NotFound");
    }

    /// uid/owner observations come from real syscalls: a file this process
    /// just created is owned by this process's uid.
    #[test]
    #[cfg(unix)]
    fn file_owner_matches_current_uid_for_own_files() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("owned");
        std::fs::write(&file, b"x").unwrap();
        let owner = file_owner(&file);
        let expected = std::fs::metadata(&file).unwrap().uid();
        assert_eq!(owner, Some(expected));
        assert_eq!(owner, current_uid());
        assert_eq!(current_uid(), Some(unsafe { libc::getuid() }));
        assert_eq!(
            file_owner(&dir.path().join("missing")),
            None,
            "a missing path has no owner"
        );
    }

    /// `/proc/sys/fs/protected_hardlinks` holds `0`, `1`, or `2` on every
    /// Linux kernel: assert the read parses to one of those, never a guess.
    #[test]
    #[cfg(target_os = "linux")]
    fn read_protected_hardlinks_reports_the_kernel_value() {
        let value = read_protected_hardlinks();
        assert!(
            matches!(value.as_deref(), Some("0") | Some("1") | Some("2")),
            "unexpected protected_hardlinks content: {value:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn absolute_path_passes_absolute_paths_through() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(absolute_path(dir.path()), Some(dir.path().to_path_buf()));
        let relative = Path::new("rel-link-probe");
        let got = absolute_path(relative).expect("cwd is resolvable");
        assert!(got.is_absolute(), "relative paths must be joined onto cwd");
        assert!(got.ends_with("rel-link-probe"));
        assert!(!got.as_os_str().is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn find_mount_for_path_resolves_a_real_mount() {
        let dir = tempfile::tempdir().unwrap();
        let root =
            find_mount_for_path(dir.path()).expect("mountinfo always resolves a tempdir on Linux");
        assert!(
            !root.is_empty() && dir.path().starts_with(&root),
            "mount root {root:?} must prefix {}",
            dir.path().display()
        );
    }

    #[test]
    fn find_mount_root_prefers_the_longest_prefix() {
        let mountinfo = "1 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                         2 1 8:1 / /foo rw - ext4 /dev/sda1 rw\n\
                         3 1 8:2 / /foo/bar rw - ext4 /dev/sda2 rw\n";
        assert_eq!(
            find_mount_root(Path::new("/foo/bar/x"), mountinfo).as_deref(),
            Some("/foo/bar"),
            "nested mounts resolve to the longest match"
        );
        assert_eq!(
            find_mount_root(Path::new("/foo/other"), mountinfo).as_deref(),
            Some("/foo")
        );
    }

    #[test]
    fn find_mount_root_matches_exact_mount_point() {
        let mountinfo = "23 28 0:20 / /sys/fs/cgroup ro shared:4 - cgroup2 cgroup2 rw\n\
                         30 1 8:1 / /mnt/data rw - ext4 /dev/sda1 rw\n";
        let got = find_mount_root(Path::new("/mnt/data"), mountinfo).unwrap();
        assert_eq!(got, "/mnt/data");
    }

    #[test]
    fn find_mount_root_prefers_longest_prefix() {
        let mountinfo = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
                         2 1 8:1 /sub /mnt/data rw - ext4 /dev/sda1 rw\n";
        let got = find_mount_root(Path::new("/mnt/data/sub/file"), mountinfo).unwrap();
        assert_eq!(got, "/mnt/data");
    }

    #[test]
    fn find_mount_root_returns_none_without_match() {
        let mountinfo = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        // Relative path can never match an absolute mount point.
        assert!(find_mount_root(Path::new("relative/path"), mountinfo).is_none());
    }

    #[test]
    fn find_mount_root_uses_slash_for_paths_with_no_nested_mount() {
        let mountinfo = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        assert_eq!(
            find_mount_root(Path::new("/tmp/foo"), mountinfo).as_deref(),
            Some("/"),
            "the root mount must prefix every absolute path"
        );
    }

    #[test]
    fn find_mount_root_skips_malformed_lines() {
        let mountinfo = "garbage\n1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        assert_eq!(
            find_mount_root(Path::new("/tmp/foo"), mountinfo).as_deref(),
            Some("/")
        );
    }

    #[test]
    fn path_is_under_mount_treats_slash_as_prefix_of_every_absolute_path() {
        assert!(path_is_under_mount("/tmp/foo", "/"));
        assert!(path_is_under_mount("/", "/"));
        assert!(path_is_under_mount("/mnt/data/x", "/mnt/data"));
        assert!(!path_is_under_mount("/mnt/data", "/mnt/data/x"));
        assert!(!path_is_under_mount("/mnt/other", "/mnt/data"));
    }

    #[test]
    fn find_mount_root_unescapes_octal_space() {
        let mountinfo = "1 0 8:1 / /mnt/my\\040data rw - ext4 /dev/sda1 rw\n";
        let got = find_mount_root(Path::new("/mnt/my data/file"), mountinfo).unwrap();
        assert_eq!(got, "/mnt/my data");
    }

    #[test]
    fn parse_mountinfo_mount_point_rejects_malformed_line() {
        assert!(parse_mountinfo_mount_point("").is_none());
        assert!(parse_mountinfo_mount_point("1 2 3").is_none());
    }

    #[test]
    fn parse_mountinfo_mount_point_accepts_well_formed_line() {
        let line = "23 28 0:20 / /sys/fs/cgroup ro shared:4 - cgroup2 cgroup2 rw";
        assert_eq!(
            parse_mountinfo_mount_point(line).as_deref(),
            Some("/sys/fs/cgroup")
        );
    }

    #[test]
    fn parse_protected_hardlinks_trims_and_rejects_empty() {
        assert_eq!(parse_protected_hardlinks("1\n").as_deref(), Some("1"));
        assert_eq!(parse_protected_hardlinks("0\n").as_deref(), Some("0"));
        assert!(parse_protected_hardlinks("  \n").is_none());
        assert!(parse_protected_hardlinks("").is_none());
    }

    #[test]
    fn format_exdev_detail_reports_both_mounts_when_different() {
        let got = format_exdev_detail(Some("/mnt/workspace"), Some("/mnt/cache"));
        assert!(got.contains("/mnt/workspace"));
        assert!(got.contains("/mnt/cache"));
        assert!(got.contains("build tree is on mount"));
        assert!(!got.contains("vfsmounts"));
    }

    #[test]
    fn format_exdev_detail_reports_bind_mount_when_same() {
        let got = format_exdev_detail(Some("/mnt/data"), Some("/mnt/data"));
        assert!(got.contains("vfsmounts"));
        assert!(!got.contains("build tree is on mount"));
    }

    #[test]
    fn exdev_mounts_differ_is_string_inequality() {
        assert!(exdev_mounts_differ("/a", "/b"));
        assert!(!exdev_mounts_differ("/a", "/a"));
    }

    #[test]
    #[cfg(any(test, target_os = "linux"))]
    fn mount_point_is_longer_compares_lengths() {
        assert!(mount_point_is_longer("/foo/bar", "/foo"));
        assert!(!mount_point_is_longer("/foo", "/foo"));
        assert!(!mount_point_is_longer("/a", "/bbb"));
    }

    #[test]
    fn format_exdev_detail_reports_unknown_mounts() {
        let got = format_exdev_detail(None, None);
        assert!(got.contains("could not be determined"));
    }

    #[test]
    fn format_eperm_detail_reports_hardening_and_owners() {
        let got = format_eperm_detail(Some("1"), Some(1000), Some(0), Some(0));
        assert!(got.contains("protected_hardlinks=1"));
        assert!(got.contains("1000"));
    }

    #[test]
    fn format_probe_detail_reports_success_with_ficlone() {
        let mut report = empty_report();
        report.hardlink_supported = true;
        report.ficlone_supported = Supported;
        let got = format_probe_detail(&report);
        assert!(got.contains("works"));
        assert!(got.contains("reflinks supported"), "{got}");
        assert!(!got.contains("FICLONE"), "{got}");
    }

    #[test]
    fn format_probe_detail_reports_success_without_ficlone() {
        let mut report = empty_report();
        report.hardlink_supported = true;
        report.ficlone_supported = Unsupported;
        let got = format_probe_detail(&report);
        assert!(got.contains("staging reflinks unsupported"), "{got}");
        assert!(!got.contains("ext4"), "{got}");
    }

    #[test]
    fn format_probe_detail_reports_success_with_unknown_ficlone() {
        let mut report = empty_report();
        report.hardlink_supported = true;
        report.ficlone_supported = Unknown("permission denied".into());
        let got = format_probe_detail(&report);
        assert!(got.contains("permission denied"), "{got}");
        assert!(got.contains("reflink support unknown"), "{got}");
    }

    #[test]
    fn format_probe_detail_reports_exdev_with_mounts() {
        let mut report = empty_report();
        report.error_kind = Some("CrossesDevices".to_string());
        report.source_mount = Some("/mnt/a".to_string());
        report.dest_mount = Some("/mnt/b".to_string());
        let got = format_probe_detail(&report);
        assert!(got.contains("EXDEV"));
        assert!(got.contains("/mnt/a"));
    }

    #[test]
    fn format_probe_detail_reports_eperm_with_hardening() {
        let mut report = empty_report();
        report.error_kind = Some("PermissionDenied".to_string());
        report.protected_hardlinks = Some("1".to_string());
        report.uid = Some(1000);
        let got = format_probe_detail(&report);
        assert!(got.contains("EPERM"));
    }

    #[test]
    fn format_probe_detail_reports_other_failure() {
        let mut report = empty_report();
        report.error_kind = Some("NotFound".to_string());
        report.error_message = Some("no such file".to_string());
        let got = format_probe_detail(&report);
        assert!(got.contains("NotFound"));
        assert!(got.contains("no such file"));
    }

    #[test]
    fn sharing_requires_a_hardlink_or_both_cross_path_reflinks() {
        for hardlink in [false, true] {
            for forward in [unknown(), Unsupported, Supported] {
                for reverse in [unknown(), Unsupported, Supported] {
                    let mut report = empty_report();
                    report.hardlink_supported = hardlink;
                    report.ficlone_supported = Supported;
                    report.reflink_build_to_staging = forward.clone();
                    report.reflink_staging_to_build = reverse.clone();
                    assert_eq!(
                        report.sharing_supported(),
                        hardlink || (forward == Supported && reverse == Supported),
                        "hardlink={hardlink}, forward={forward:?}, reverse={reverse:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn reflinks_in_both_directions_report_unavailable_hardlink_fallback() {
        let mut report = empty_report();
        report.error_kind = Some("CrossesDevices".to_string());
        report.ficlone_supported = Unknown("staging full".into());
        report.reflink_build_to_staging = Supported;
        report.reflink_staging_to_build = Supported;
        let detail = format_probe_detail(&report);
        assert!(detail.contains("staging reflink support unknown (staging full)"));
        assert!(report.sharing_supported());
        assert!(detail.contains("build → staging works"), "{detail}");
        assert!(detail.contains("staging → build works"), "{detail}");
        assert!(detail.contains("hardlink fallback unavailable"), "{detail}");
        assert!(detail.contains("CrossesDevices"), "{detail}");
        assert!(!detail.contains("SAME mount"), "{detail}");
    }

    #[test]
    fn unknown_cross_path_reflinks_do_not_claim_success_or_suggest_moving_mounts() {
        for (forward, reverse) in [
            (unknown(), unknown()),
            (unknown(), Supported),
            (Supported, unknown()),
            (Unsupported, unknown()),
            (unknown(), Unsupported),
        ] {
            let mut report = empty_report();
            report.error_kind = Some("CrossesDevices".to_string());
            report.ficlone_supported = Supported;
            report.reflink_build_to_staging = forward;
            report.reflink_staging_to_build = reverse;
            let detail = format_probe_detail(&report);
            assert!(!report.sharing_supported(), "{detail}");
            assert!(detail.contains("EXDEV"), "{detail}");
            assert!(detail.contains("unknown"), "{detail}");
            assert!(!detail.contains("SAME mount"), "{detail}");
        }
    }

    #[test]
    fn failed_cross_path_reflink_keeps_exdev_diagnostic() {
        for (forward, reverse) in [
            (Supported, Unsupported),
            (Unsupported, Supported),
            (Unsupported, Unsupported),
        ] {
            let mut report = empty_report();
            report.error_kind = Some("CrossesDevices".to_string());
            report.reflink_build_to_staging = forward;
            report.reflink_staging_to_build = reverse;
            let detail = format_probe_detail(&report);
            assert!(!report.sharing_supported());
            assert!(detail.contains("EXDEV"), "{detail}");
            assert!(detail.contains("SAME mount"), "{detail}");
            assert!(detail.contains("unsupported"), "{detail}");
        }
    }

    #[test]
    fn probe_records_each_cross_path_direction_separately() {
        let dir = tempfile::tempdir().unwrap();
        let build = dir.path().join("build");
        let staging = dir.path().join("staging");
        std::fs::create_dir(&build).unwrap();
        for (forward, reverse) in [(Supported, Unsupported), (unknown(), Supported)] {
            let mut calls = Vec::new();
            let report = probe_link_layout_with(&build, &staging, |src, dst| {
                calls.push((src.to_path_buf(), dst.to_path_buf()));
                if src == staging && dst == staging {
                    Supported
                } else if src == build && dst == staging {
                    forward.clone()
                } else if src == staging && dst == build {
                    reverse.clone()
                } else {
                    panic!("unexpected reflink paths: {src:?} → {dst:?}");
                }
            });
            assert_eq!(report.ficlone_supported, Supported);
            assert_eq!(report.reflink_build_to_staging, forward);
            assert_eq!(report.reflink_staging_to_build, reverse);
            assert_eq!(
                calls,
                vec![
                    (staging.clone(), staging.clone()),
                    (build.clone(), staging.clone()),
                    (staging.clone(), build.clone()),
                ]
            );
        }
    }

    #[test]
    fn probes_preserve_existing_files_and_clean_up_on_success_and_failure() {
        let dir = tempfile::tempdir().unwrap();
        let build = dir.path().join("build");
        let staging = dir.path().join("staging");
        std::fs::create_dir(&build).unwrap();
        std::fs::create_dir(&staging).unwrap();
        let existing_build = build.join(".kache-link-probe-existing");
        let existing_staging = staging.join(".kache-reflink-probe-existing");
        std::fs::write(&existing_build, b"build sentinel").unwrap();
        std::fs::write(&existing_staging, b"staging sentinel").unwrap();

        let report = probe_link_layout(&build, &staging);
        assert!(report.hardlink_supported, "{report:?}");
        let missing = dir.path().join("missing");
        let result = reflink_supported_between(&build, &missing);
        assert!(matches!(result, Unknown(reason) if reason.contains("temporary destination")));
        let failed = probe_link_layout(&existing_build, &staging);
        assert!(!failed.hardlink_supported);
        assert!(matches!(failed.reflink_build_to_staging, Unknown(_)));
        assert!(matches!(failed.reflink_staging_to_build, Unknown(_)));

        assert_eq!(std::fs::read(&existing_build).unwrap(), b"build sentinel");
        assert_eq!(
            std::fs::read(&existing_staging).unwrap(),
            b"staging sentinel"
        );
        assert_eq!(std::fs::read_dir(&build).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 1);
    }

    #[test]
    fn probe_succeeds_on_same_device_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let build_dir = dir.path().join("build");
        let staging_dir = dir.path().join("store").join("staging");
        std::fs::create_dir_all(&build_dir).unwrap();
        std::fs::create_dir_all(&staging_dir).unwrap();
        let report = probe_link_layout(&build_dir, &staging_dir);
        assert!(
            report.hardlink_supported,
            "same-device tempdir must hardlink: {report:?}"
        );
        assert!(report.error_kind.is_none());
    }

    #[test]
    fn probe_reports_other_for_missing_build_dir_file() {
        // A regular file as `build_dir` cannot hold the probe temp: write
        // fails with `NotADirectory`/`Other`, exercising the failure arm
        // without bind mounts.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let staging_dir = dir.path().join("staging");
        std::fs::create_dir_all(&staging_dir).unwrap();
        let report = probe_link_layout(&file, &staging_dir);
        assert!(!report.hardlink_supported);
        assert!(report.error_kind.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn reflink_clone_environmental_failures_are_unknown() {
        let dir = tempfile::tempdir().unwrap();
        for errno in [
            libc::ENOSPC,
            libc::EACCES,
            libc::EPERM,
            libc::EIO,
            libc::EINVAL,
        ] {
            let error = std::io::Error::from_raw_os_error(errno);
            let result = reflink_supported_between_with(dir.path(), dir.path(), |_, dest| {
                std::fs::write(dest, b"partial clone").unwrap();
                Err(std::io::Error::from_raw_os_error(errno))
            });
            assert!(
                matches!(result, Unknown(ref reason) if reason.contains(&error.to_string())),
                "errno {errno}: {result:?}"
            );
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn reflink_clone_cross_device_and_unsupported_are_determinate() {
        let dir = tempfile::tempdir().unwrap();
        for errno in [libc::EXDEV, libc::EOPNOTSUPP, libc::ENOTSUP] {
            let result = reflink_supported_between_with(dir.path(), dir.path(), |_, _| {
                Err(std::io::Error::from_raw_os_error(errno))
            });
            assert_eq!(result, Unsupported, "errno {errno}");
        }
        #[cfg(target_os = "linux")]
        assert_eq!(
            reflink_supported_between_with(dir.path(), dir.path(), |_, _| {
                Err(std::io::Error::from_raw_os_error(libc::ENOTTY))
            }),
            Unsupported
        );
    }

    #[cfg(windows)]
    #[test]
    fn reflink_clone_windows_errors_are_classified_conservatively() {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_DISK_FULL, ERROR_INVALID_FUNCTION, ERROR_NOT_SAME_DEVICE,
            ERROR_NOT_SUPPORTED,
        };

        let dir = tempfile::tempdir().unwrap();
        for code in [ERROR_NOT_SAME_DEVICE, ERROR_NOT_SUPPORTED] {
            let result = reflink_supported_between_with(dir.path(), dir.path(), |_, _| {
                Err(std::io::Error::from_raw_os_error(code as i32))
            });
            assert_eq!(result, Unsupported, "Windows error {code}");
        }
        for code in [ERROR_DISK_FULL, ERROR_ACCESS_DENIED, ERROR_INVALID_FUNCTION] {
            let result = reflink_supported_between_with(dir.path(), dir.path(), |_, _| {
                Err(std::io::Error::from_raw_os_error(code as i32))
            });
            assert!(matches!(result, Unknown(_)), "Windows error {code}");
        }
        let result = reflink_supported_between_with(dir.path(), dir.path(), |_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "file smaller than one cluster",
            ))
        });
        assert!(matches!(result, Unknown(_)));
    }

    #[test]
    fn reflink_probe_reports_success_from_a_successful_clone() {
        let dir = tempfile::tempdir().unwrap();
        let result = reflink_supported_between_with(dir.path(), dir.path(), |src, dest| {
            std::fs::copy(src, dest)?;
            Ok(())
        });
        assert_eq!(result, Supported);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn probe_reports_reflinks_for_a_staging_dir_it_creates() {
        let dir = tempfile::tempdir().unwrap();
        let staging_dir = dir.path().join("store").join("staging");
        let report = probe_link_layout_with(dir.path(), &staging_dir, |src, dst| {
            assert!(src.is_dir() && dst.is_dir());
            Supported
        });
        assert_eq!(report.ficlone_supported, Supported);
    }

    #[cfg(unix)]
    #[test]
    fn shown_paths_name_one_directory_one_way() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert_eq!(shown_path(&alias), shown_path(&real));
        assert_eq!(
            shown_path(&real),
            std::fs::canonicalize(&real).unwrap().display().to_string()
        );
        let missing = dir.path().join("missing");
        assert_eq!(shown_path(&missing), missing.display().to_string());
    }

    #[test]
    fn ficlone_probe_reports_missing_source_dir() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-dir");
        let result = reflink_supported_between(&missing, &missing);
        assert!(matches!(result, Unknown(reason) if reason.contains("temporary source")));
    }
}
