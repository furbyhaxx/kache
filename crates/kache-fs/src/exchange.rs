use std::ffi::OsStr;
use std::fs::File;
use std::io;

/// Atomically exchange two existing directory entries in an open parent directory.
///
/// On Linux, `first` and `second` must each be a single nonempty name other than
/// `.` or `..`, without `/` or NUL. The entries may have different types;
/// symbolic links themselves are exchanged rather than followed. An open handle
/// continues to refer to the object it originally opened.
///
/// This swaps entries only. It does not establish their types, ownership or
/// liveness, and does not prevent symlink or identity races. Callers must pin
/// and revalidate identities and coordinate all consumers before relying on the
/// result. The operation does not delete entries or provide durability.
///
/// # Example
///
/// This call assumes the caller has pinned and revalidated both entries and
/// coordinated consumers. It must also revalidate identities after the exchange.
///
/// ```no_run
/// use kache_fs::exchange_entries;
/// use std::{ffi::OsStr, fs::File, io};
///
/// fn exchange_pinned_entries(parent: &File) -> io::Result<()> {
///     exchange_entries(parent, OsStr::new("first"), OsStr::new("second"))
/// }
/// ```
///
/// # Errors
///
/// On Linux, invalid names return [`io::ErrorKind::InvalidInput`], and syscall
/// errors are propagated. On other platforms this returns
/// [`io::ErrorKind::Unsupported`]. There is no non-atomic fallback.
pub fn exchange_entries(parent: &File, first: &OsStr, second: &OsStr) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let first = component(first)?;
        let second = component(second)?;
        // SAFETY: both C strings and the borrowed file descriptor remain valid throughout the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                first.as_ptr(),
                parent.as_raw_fd(),
                second.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, first, second);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic entry exchange is only supported on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
fn component(name: &OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entry name must be a single component",
        ));
    }
    std::ffi::CString::new(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::exchange_entries;
    use crate::testutil::TempDir;
    use crate::{InodeId, file_identity, handle_identity};
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    fn siblings() -> (TempDir, File, InodeId, InodeId) {
        let dir = TempDir::new("exchange-siblings");
        let left = dir.path().join("left");
        let right = dir.path().join("right");
        fs::create_dir(&left).unwrap();
        fs::create_dir(&right).unwrap();
        fs::write(left.join("marker"), b"left").unwrap();
        fs::write(right.join("marker"), b"right").unwrap();
        let left_id = file_identity(&left).unwrap();
        let right_id = file_identity(&right).unwrap();
        let parent = File::open(dir.path()).unwrap();
        (dir, parent, left_id, right_id)
    }

    fn assert_siblings_unchanged(parent: &Path, left_id: InodeId, right_id: InodeId) {
        let left = parent.join("left");
        let right = parent.join("right");
        assert_eq!(file_identity(&left).unwrap(), left_id);
        assert_eq!(file_identity(&right).unwrap(), right_id);
        assert_eq!(fs::read(left.join("marker")).unwrap(), b"left");
        assert_eq!(fs::read(right.join("marker")).unwrap(), b"right");
    }

    #[test]
    fn exchange_keeps_a_workspace_symlink_valid_and_old_handle_pinned() {
        let dir = TempDir::new("exchange-directories");
        let parent_path = dir.path().join("parent");
        let workspace = dir.path().join("workspace");
        fs::create_dir(&parent_path).unwrap();
        fs::create_dir(&workspace).unwrap();
        let live = parent_path.join("live");
        let empty = parent_path.join("empty");
        fs::create_dir(&live).unwrap();
        fs::create_dir(&empty).unwrap();
        fs::write(live.join("marker"), b"old contents").unwrap();
        let link = workspace.join("target");
        symlink("../parent/live", &link).unwrap();
        let old_handle = File::open(&live).unwrap();
        let old_id = handle_identity(&old_handle).unwrap();
        let empty_id = file_identity(&empty).unwrap();
        assert_ne!(old_id, empty_id);
        assert_eq!(file_identity(&link).unwrap(), old_id);
        let parent = File::open(&parent_path).unwrap();

        exchange_entries(&parent, OsStr::new("live"), OsStr::new("empty")).unwrap();

        assert_eq!(fs::read_link(&link).unwrap(), Path::new("../parent/live"));
        assert!(link.is_dir());
        assert_eq!(file_identity(&link).unwrap(), empty_id);
        assert_eq!(file_identity(&live).unwrap(), empty_id);
        assert_eq!(file_identity(&empty).unwrap(), old_id);
        assert_eq!(handle_identity(&old_handle).unwrap(), old_id);
        assert_eq!(fs::read(empty.join("marker")).unwrap(), b"old contents");
        assert_eq!(fs::read_dir(&link).unwrap().count(), 0);
    }

    #[test]
    fn exchange_moves_a_symlink_entry_without_following_it() {
        let dir = TempDir::new("exchange-symlink-entry");
        fs::write(dir.path().join("referent"), b"referent").unwrap();
        fs::write(dir.path().join("regular"), b"regular").unwrap();
        symlink("referent", dir.path().join("link")).unwrap();
        let parent = File::open(dir.path()).unwrap();

        exchange_entries(&parent, OsStr::new("link"), OsStr::new("regular")).unwrap();

        assert_eq!(fs::read(dir.path().join("link")).unwrap(), b"regular");
        assert_eq!(
            fs::read_link(dir.path().join("regular")).unwrap(),
            Path::new("referent")
        );
        assert_eq!(fs::read(dir.path().join("regular")).unwrap(), b"referent");
        assert_eq!(fs::read(dir.path().join("referent")).unwrap(), b"referent");
    }

    #[test]
    fn exchange_accepts_non_utf8_names_relative_to_the_open_parent() {
        let dir = TempDir::new("exchange-open-parent");
        let parent_path = dir.path().join("parent");
        let moved_path = dir.path().join("moved");
        fs::create_dir(&parent_path).unwrap();
        let unusual = OsStr::from_bytes(b"\\\xff");
        fs::write(parent_path.join(unusual), b"unusual").unwrap();
        fs::write(parent_path.join("other"), b"other").unwrap();
        let parent = File::open(&parent_path).unwrap();
        fs::rename(&parent_path, &moved_path).unwrap();

        exchange_entries(&parent, unusual, OsStr::new("other")).unwrap();

        assert_eq!(fs::read(moved_path.join(unusual)).unwrap(), b"other");
        assert_eq!(fs::read(moved_path.join("other")).unwrap(), b"unusual");
        assert!(!parent_path.exists());
    }

    #[test]
    fn exchange_missing_entry_returns_the_os_error_and_changes_nothing() {
        let (dir, parent, left_id, right_id) = siblings();
        for (left, right) in [("left", "missing"), ("missing", "right")] {
            let error = exchange_entries(&parent, OsStr::new(left), OsStr::new(right)).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
            assert_siblings_unchanged(dir.path(), left_id, right_id);
            assert!(!dir.path().join("missing").exists());
        }
    }

    #[test]
    fn exchange_invalid_component_in_either_position_changes_nothing() {
        let (dir, parent, left_id, right_id) = siblings();
        let invalid: &[&[u8]] = &[
            b"",
            b".",
            b"..",
            b"/",
            b"/left",
            b"left/marker",
            b"left/",
            b"left\0suffix",
        ];
        for bytes in invalid {
            let name = OsStr::from_bytes(bytes);
            for (left, right) in [(name, OsStr::new("right")), (OsStr::new("left"), name)] {
                let error = exchange_entries(&parent, left, right).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{bytes:?}");
                assert_siblings_unchanged(dir.path(), left_id, right_id);
            }
        }
    }

    #[test]
    fn exchange_propagates_non_directory_parent_error() {
        let dir = TempDir::new("exchange-bad-parent");
        let parent = File::create(dir.path().join("file")).unwrap();
        let error = exchange_entries(&parent, OsStr::new("left"), OsStr::new("right")).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR));
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::exchange_entries;
    use crate::testutil::TempDir;
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io;

    #[test]
    fn exchange_is_unsupported_and_leaves_entries_unchanged() {
        let dir = TempDir::new("exchange-unsupported");
        let parent = File::create(dir.path().join("handle")).unwrap();
        fs::write(dir.path().join("left"), b"left").unwrap();
        fs::write(dir.path().join("right"), b"right").unwrap();

        for (left, right) in [("left", "right"), ("", "right"), ("left", "..")] {
            let error = exchange_entries(&parent, OsStr::new(left), OsStr::new(right)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(fs::read(dir.path().join("left")).unwrap(), b"left");
            assert_eq!(fs::read(dir.path().join("right")).unwrap(), b"right");
        }
    }
}
