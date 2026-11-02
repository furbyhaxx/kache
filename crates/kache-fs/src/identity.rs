use crate::InodeId;
use std::{fs, io, path::Path};

// Linux UAPI value absent from the locked libc 0.2.189.
#[cfg(target_os = "linux")]
const STATX_MNT_ID_UNIQUE: libc::c_uint = 0x0000_4000;

// The Linux UAPI fixes the result at 256 bytes; unused fields stay opaque.
#[cfg(target_os = "linux")]
#[repr(C, align(8))]
struct StatxBuffer {
    stx_mask: u32,
    _before_mount_id: [u8; 0x8c],
    stx_mnt_id: u64,
    _trailing: [u8; 0x68],
}

#[cfg(target_os = "linux")]
const _: () = {
    assert!(std::mem::size_of::<StatxBuffer>() == 0x100);
    assert!(std::mem::align_of::<StatxBuffer>() >= 8);
    assert!(std::mem::offset_of!(StatxBuffer, stx_mask) == 0);
    assert!(std::mem::offset_of!(StatxBuffer, stx_mnt_id) == 0x90);
};

#[cfg(target_os = "linux")]
impl StatxBuffer {
    fn new() -> Self {
        Self {
            stx_mask: 0,
            _before_mount_id: [0; 0x8c],
            stx_mnt_id: 0,
            _trailing: [0; 0x68],
        }
    }
}

/// A filesystem-specific opaque export handle.
///
/// Handles can be reused or replayed and do not establish a trusted volume
/// incarnation. A handle alone must not authorize adoption, reads, or deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueFileHandle {
    /// The filesystem-defined handle type returned by the kernel.
    pub handle_type: i32,
    /// The filesystem-defined opaque handle bytes.
    pub bytes: Vec<u8>,
}

/// An opaque handle and the mount identifier observed when exporting it.
///
/// Compare `handle` independently of `mount_id`: bind aliases can have
/// different mount IDs. Mount IDs are not persistent and can be reused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedFileHandle {
    /// The filesystem-specific handle, which is not an authorization.
    pub handle: OpaqueFileHandle,
    /// The nonpersistent mount identifier returned by the kernel.
    pub mount_id: i32,
}

/// Export a handle for the object pinned by an already-open file descriptor.
///
/// On Linux this uses `name_to_handle_at` with `AT_EMPTY_PATH`; it does not
/// reopen a pathname. The returned handle alone must not authorize adoption,
/// reads, or deletion. See [`OpaqueFileHandle`] for its identity limitations.
///
/// # Errors
///
/// On Linux, propagates syscall errors, including unsupported filesystems, and
/// rejects a returned length exceeding the buffer. On other platforms, returns
/// [`io::ErrorKind::Unsupported`].
pub fn export_file_handle(file: &fs::File) -> io::Result<ExportedFileHandle> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let mut buffer = ExportHandleBuffer::new();
        let mut mount_id: libc::c_int = 0;
        // SAFETY: file stays open, c"" is NUL-terminated, and buffer is aligned
        // with MAX_HANDLE_SZ writable bytes immediately following its C header.
        // mount_id points to a writable int and no 64-bit mount-ID flag is used.
        let result = unsafe {
            libc::name_to_handle_at(
                file.as_raw_fd(),
                c"".as_ptr(),
                (&raw mut buffer).cast(),
                &raw mut mount_id,
                libc::AT_EMPTY_PATH,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        buffer.exported(mount_id)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file handle export is only supported on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct ExportHandleBuffer {
    header: libc::file_handle,
    bytes: [u8; libc::MAX_HANDLE_SZ as usize],
}

#[cfg(target_os = "linux")]
const _: () = assert!(
    std::mem::offset_of!(ExportHandleBuffer, bytes)
        == std::mem::offset_of!(libc::file_handle, f_handle)
);

#[cfg(target_os = "linux")]
impl ExportHandleBuffer {
    fn new() -> Self {
        Self {
            header: libc::file_handle {
                handle_bytes: libc::MAX_HANDLE_SZ as libc::c_uint,
                handle_type: 0,
                f_handle: [],
            },
            bytes: [0; libc::MAX_HANDLE_SZ as usize],
        }
    }

    fn exported(&self, mount_id: i32) -> io::Result<ExportedFileHandle> {
        let Some(bytes) = self.bytes.get(..self.header.handle_bytes as usize) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "export handle length exceeds buffer capacity",
            ));
        };
        Ok(ExportedFileHandle {
            handle: OpaqueFileHandle {
                handle_type: self.header.handle_type,
                bytes: bytes.to_vec(),
            },
            mount_id,
        })
    }
}

/// Return the unique mount ID of the object pinned by an open file.
///
/// IDs are guaranteed unique only until reboot, and bind aliases can have
/// different IDs. An ID does not prove volume or snapshot incarnation,
/// establish consent, or authorize adoption, reads, or deletion.
///
/// # Errors
///
/// Returns [`io::ErrorKind::Unsupported`] when unique mount IDs are unavailable
/// or on non-Linux platforms. Other syscall errors are preserved.
pub fn unique_mount_id(file: &fs::File) -> io::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let mut stat = StatxBuffer::new();
        // SAFETY: file owns a live FD, AT_EMPTY_PATH uses the NUL-terminated
        // empty path, and stat is an aligned writable 256-byte UAPI buffer.
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx as libc::c_long,
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                STATX_MNT_ID_UNIQUE,
                &raw mut stat,
            )
        };
        let result = if result == 0 {
            Ok((stat.stx_mask, stat.stx_mnt_id))
        } else {
            Err(io::Error::last_os_error())
        };
        checked_unique_mount_id(result)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unique mount IDs are only supported on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
fn checked_unique_mount_id(result: io::Result<(u32, u64)>) -> io::Result<u64> {
    match result {
        Ok((mask, id)) if mask & STATX_MNT_ID_UNIQUE != 0 => Ok(id),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kernel did not return a unique mount ID",
        )),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)) => {
            Err(io::Error::new(io::ErrorKind::Unsupported, error))
        }
        Err(error) => Err(error),
    }
}

/// Identity of the object at `path`, following symlinks. Valid for comparing
/// live objects on this host; an inode can be reused after deletion.
pub fn file_identity(path: &Path) -> io::Result<InodeId> {
    let metadata = fs::metadata(path)?;
    metadata_identity(path, &metadata, true).map(|(id, _)| id)
}

/// Identity of the file an open handle refers to, whatever its path names
/// now. Compared with [`file_identity`] it tells whether the path was unlinked
/// or replaced after the handle was opened.
pub fn handle_identity(file: &fs::File) -> io::Result<InodeId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(InodeId {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        windows_handle_identity(file).map(|(id, _)| id)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file identity is unavailable",
        ))
    }
}

/// Identity of a directory. A symlink at the final component is rejected.
pub fn directory_identity(path: &Path) -> io::Result<InodeId> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a directory",
        ));
    }
    metadata_identity(path, &metadata, false).map(|(id, _)| id)
}

pub(crate) fn metadata_identity(
    path: &Path,
    metadata: &fs::Metadata,
    follow: bool,
) -> io::Result<(InodeId, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = (path, follow);
        Ok((
            InodeId {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            metadata.nlink(),
        ))
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        windows_metadata_identity(path, follow)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, metadata, follow);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file identity is unavailable",
        ))
    }
}

#[cfg(windows)]
fn windows_metadata_identity(path: &Path, follow: bool) -> io::Result<(InodeId, u64)> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let flags = FILE_FLAG_BACKUP_SEMANTICS
        | if follow {
            0
        } else {
            FILE_FLAG_OPEN_REPARSE_POINT
        };
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?;
    windows_handle_identity(&file)
}

#[cfg(windows)]
fn windows_handle_identity(file: &fs::File) -> io::Result<(InodeId, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle and output buffer are valid for this call.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        windows_identity(
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ),
        u64::from(info.nNumberOfLinks),
    ))
}

#[cfg(any(windows, test))]
fn windows_identity(volume: u32, high: u32, low: u32) -> InodeId {
    InodeId {
        dev: u64::from(volume),
        ino: (u64::from(high) << 32) | u64::from(low),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn windows_file_index_preserves_both_halves() {
        assert_eq!(
            windows_identity(0x1020_3040, 0x1122_3344, 0x5566_7788),
            InodeId {
                dev: 0x1020_3040,
                ino: 0x1122_3344_5566_7788
            }
        );
    }

    #[test]
    fn hardlinks_share_identity_but_copies_do_not() {
        let dir = TempDir::new("identity");
        let source = dir.write("source", 4096);
        let link = dir.path().join("link");
        let copy = dir.path().join("copy");
        fs::hard_link(&source, &link).unwrap();
        fs::copy(&source, &copy).unwrap();
        assert_eq!(
            file_identity(&source).unwrap(),
            file_identity(&link).unwrap()
        );
        assert_ne!(
            file_identity(&source).unwrap(),
            file_identity(&copy).unwrap()
        );
        assert!(directory_identity(&source).is_err());
        assert!(directory_identity(dir.path()).is_ok());
        assert!(file_identity(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn handle_identity_follows_the_file_not_the_path() {
        let dir = TempDir::new("handle-identity");
        let path = dir.write("lock", 16);
        let other = dir.write("other", 16);
        let handle = fs::File::open(&path).unwrap();
        assert_eq!(
            handle_identity(&handle).unwrap(),
            file_identity(&path).unwrap()
        );
        assert_ne!(
            handle_identity(&handle).unwrap(),
            file_identity(&other).unwrap()
        );

        // Replace what the path names while the handle stays open: the
        // handle keeps the old file's identity.
        let moved = dir.path().join("moved");
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"new").unwrap();
        assert_eq!(
            handle_identity(&handle).unwrap(),
            file_identity(&moved).unwrap()
        );
        assert_ne!(
            handle_identity(&handle).unwrap(),
            file_identity(&path).unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    struct ExportTestDir(std::path::PathBuf);

    #[cfg(target_os = "linux")]
    impl ExportTestDir {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;

            for attempt in 0..1000 {
                let path = std::env::temp_dir().join(format!(
                    "kache-fs-export-handle-{}-{attempt}",
                    std::process::id()
                ));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("failed to create private test directory: {error}"),
                }
            }
            panic!("could not allocate a private test directory");
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ExportTestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn export_handle_follows_the_pinned_directory_through_replacement() {
        use std::os::unix::fs::symlink;

        let dir = ExportTestDir::new();
        let path = dir.0.join("target");
        let moved = dir.0.join("moved");
        let workspace = dir.0.join("workspace");
        fs::create_dir(&path).unwrap();
        fs::create_dir(&workspace).unwrap();
        let link = workspace.join("target");
        symlink("../target", &link).unwrap();
        let pinned = fs::File::open(&link).unwrap();
        let original = match export_file_handle(&pinned) {
            Ok(handle) => handle,
            Err(error) if error.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                eprintln!("filesystem does not support export handles: {error}");
                return;
            }
            Err(error) => panic!("failed to export the pinned directory: {error}"),
        };

        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();

        let pinned_after = export_file_handle(&pinned).unwrap();
        let renamed = export_file_handle(&fs::File::open(&moved).unwrap()).unwrap();
        let replacement = export_file_handle(&fs::File::open(&link).unwrap()).unwrap();
        assert_eq!(original.handle, pinned_after.handle);
        assert_eq!(original.handle, renamed.handle);
        assert_ne!(original.handle, replacement.handle);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unique_mount_id_follows_the_pinned_directory_through_replacement() {
        use std::os::fd::AsRawFd;

        let dir = ExportTestDir::new();
        let path = dir.0.join("target");
        let moved = dir.0.join("moved");
        fs::create_dir(&path).unwrap();
        let pinned = fs::File::open(&path).unwrap();

        let mut stat = StatxBuffer::new();
        // SAFETY: pinned owns a live FD, AT_EMPTY_PATH uses the NUL-terminated
        // empty path, and stat is an aligned writable 256-byte UAPI buffer.
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx as libc::c_long,
                pinned.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                0x0000_4000_u32,
                &raw mut stat,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            assert!(matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EOPNOTSUPP)
            ));
            assert_eq!(
                unique_mount_id(&pinned).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            eprintln!("unique mount ID is unsupported: {error}");
            return;
        }
        if stat.stx_mask & 0x0000_4000 == 0 {
            assert_eq!(
                unique_mount_id(&pinned).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            eprintln!("kernel did not return the unique mount ID bit");
            return;
        }
        let original = unique_mount_id(&pinned).unwrap();
        assert_eq!(original, stat.stx_mnt_id);
        eprintln!("kernel returned the unique mount ID bit");

        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        let renamed = fs::File::open(&moved).unwrap();
        let replacement = fs::File::open(&path).unwrap();
        assert_eq!(
            handle_identity(&pinned).unwrap(),
            handle_identity(&renamed).unwrap()
        );
        assert_ne!(
            handle_identity(&pinned).unwrap(),
            handle_identity(&replacement).unwrap()
        );
        assert_eq!(unique_mount_id(&pinned).unwrap(), original);
        assert_eq!(unique_mount_id(&renamed).unwrap(), original);
        assert_eq!(unique_mount_id(&replacement).unwrap(), original);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unique_mount_id_rejects_legacy_masks_and_preserves_other_errors() {
        const STATX_MNT_ID: u32 = 0x0000_1000;
        const STATX_BASIC_STATS: u32 = 0x0000_07ff;
        for mask in [0, STATX_MNT_ID, STATX_BASIC_STATS | STATX_MNT_ID] {
            assert_eq!(
                checked_unique_mount_id(Ok((mask, 123))).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
        assert_eq!(
            checked_unique_mount_id(Ok((0x0000_4000, 123))).unwrap(),
            123
        );
        assert_eq!(
            checked_unique_mount_id(Ok((0x0000_4000 | STATX_MNT_ID, 0))).unwrap(),
            0
        );
        for code in [libc::ENOSYS, libc::EOPNOTSUPP] {
            assert_eq!(
                checked_unique_mount_id(Err(io::Error::from_raw_os_error(code)))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
        }
        for code in [libc::EBADF, libc::EACCES, libc::EINVAL, libc::EIO] {
            assert_eq!(
                checked_unique_mount_id(Err(io::Error::from_raw_os_error(code)))
                    .unwrap_err()
                    .raw_os_error(),
                Some(code)
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unique_mount_id_is_unsupported_off_linux() {
        let dir = TempDir::new("unique-mount-id-unsupported");
        let file = fs::File::open(dir.write("file", 1)).unwrap();
        assert_eq!(
            unique_mount_id(&file).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn export_handle_rejects_an_unexportable_socket() {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        let (socket, _peer) = UnixStream::pair().unwrap();
        let fd: OwnedFd = socket.into();
        let socket = fs::File::from(fd);
        let error = export_file_handle(&socket).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn export_handle_preserves_type_and_rejects_invalid_lengths() {
        let mut buffer = ExportHandleBuffer::new();
        buffer.header.handle_type = 129;
        buffer.header.handle_bytes = 3;
        buffer.bytes[..3].copy_from_slice(&[1, 2, 3]);
        let exported = buffer.exported(42).unwrap();
        assert_eq!(exported.handle.handle_type, 129);
        assert_eq!(exported.handle.bytes, [1, 2, 3]);
        assert_eq!(exported.mount_id, 42);

        for length in [0, libc::MAX_HANDLE_SZ as u32] {
            buffer.header.handle_bytes = length;
            assert_eq!(
                buffer.exported(42).unwrap().handle.bytes.len(),
                length as usize
            );
        }
        buffer.header.handle_bytes = libc::MAX_HANDLE_SZ as u32 + 1;
        assert_eq!(
            buffer.exported(42).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn export_handle_is_unsupported_off_linux() {
        let dir = TempDir::new("export-handle-unsupported");
        let file = fs::File::open(dir.write("file", 1)).unwrap();
        assert_eq!(
            export_file_handle(&file).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_identity_rejects_a_symlink() {
        let dir = TempDir::new("directory-symlink");
        let link = dir.path().join("alias");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(directory_identity(&link).is_err());
        assert_eq!(
            file_identity(&link).unwrap(),
            file_identity(dir.path()).unwrap()
        );
    }
}
