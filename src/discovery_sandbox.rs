use std::process::ExitCode;

pub(crate) const MARKER: &str = "__kache_discovery_sandbox_v1";

#[derive(Debug)]
enum SandboxError {
    UnexpectedArguments,
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
    #[cfg(target_os = "linux")]
    RequestTooLarge,
    #[cfg(target_os = "linux")]
    InvalidPath,
    #[cfg(target_os = "linux")]
    InvalidArgument,
    #[cfg(target_os = "linux")]
    InvalidDescriptor,
    #[cfg(target_os = "linux")]
    InvalidControl,
    #[cfg(target_os = "linux")]
    TooManyDescriptors,
    #[cfg(target_os = "linux")]
    Unenforced,
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::UnexpectedArguments => "unexpected internal arguments",
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => "discovery sandbox requires Linux Landlock",
            #[cfg(target_os = "linux")]
            Self::RequestTooLarge => "request too large",
            #[cfg(target_os = "linux")]
            Self::InvalidPath => "invalid absolute path",
            #[cfg(target_os = "linux")]
            Self::InvalidArgument => "invalid argument",
            #[cfg(target_os = "linux")]
            Self::InvalidDescriptor => "invalid O_PATH rule descriptor",
            #[cfg(target_os = "linux")]
            Self::InvalidControl => "invalid or truncated descriptor control message",
            #[cfg(target_os = "linux")]
            Self::TooManyDescriptors => "too many rule descriptors",
            #[cfg(target_os = "linux")]
            Self::Unenforced => "Landlock or no_new_privs not fully enforced",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SandboxError {}

// The caller must validate approval, origin, mount, ancestry, and identity, bound program I/O,
// scrub the helper's environment before launch, and control all stdio streams.
// This confines neither metadata visibility nor networking.
pub(crate) fn dispatch() -> Option<ExitCode> {
    let mut args = std::env::args_os();
    if args.nth(1)? != MARKER {
        return None;
    }
    let result = if args.next().is_some() {
        Err(SandboxError::UnexpectedArguments.into())
    } else {
        run()
    };
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            use std::io::Write;
            let _ = writeln!(std::io::stderr(), "discovery sandbox: {error:#}");
            ExitCode::FAILURE
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn run() -> anyhow::Result<()> {
    Err(SandboxError::UnsupportedPlatform.into())
}

#[cfg(target_os = "linux")]
const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[cfg(target_os = "linux")]
const MAX_RULE_FDS: usize = 64;

#[cfg(target_os = "linux")]
// Stdin is a Unix stream: send at most 64 KiB of JSON and 64 caller-pinned O_PATH
// descriptors using SCM_RIGHTS, then shut down the write side. Each rights message carries
// JSON bytes; after a short send, send remaining bytes without resending descriptors. Slots
// follow descriptor arrival order starting at 3 (0..=2 are reserved), not raw helper fds.
// The caller retains ownership.
// Renames and bind aliases of approved objects are allowed. The program needs execute access.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) read_fds: Vec<i32>,
    pub(crate) exec_fds: Vec<i32>,
    pub(crate) program: String,
    pub(crate) argv: Vec<String>,
}

#[cfg(target_os = "linux")]
struct PinnedRoot {
    index: usize,
    is_directory: bool,
    executable: bool,
}

#[cfg(target_os = "linux")]
fn validate_path(path: &str) -> anyhow::Result<()> {
    use std::path::{Component, Path};

    let parsed = Path::new(path);
    anyhow::ensure!(
        parsed.is_absolute()
            && !path.contains('\0')
            && !parsed.components().any(|part| part == Component::ParentDir),
        SandboxError::InvalidPath
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_request(socket: std::os::fd::RawFd) -> anyhow::Result<(Request, Vec<std::fs::File>)> {
    use std::os::fd::FromRawFd;

    const CONTROL_BYTES: usize = unsafe {
        libc::CMSG_SPACE((MAX_RULE_FDS * std::mem::size_of::<libc::c_int>()) as u32) as usize
    };
    const CONTROL_WORDS: usize = CONTROL_BYTES.div_ceil(std::mem::size_of::<usize>());
    let mut input = Vec::new();
    let mut fds = Vec::new();
    loop {
        let mut bytes = [0_u8; 8192];
        let mut control = [0_usize; CONTROL_WORDS];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: zeroed msghdr is valid, and both buffers remain live for recvmsg.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = CONTROL_BYTES;
        // SAFETY: the socket is caller-controlled and message points to writable buffers.
        let count = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
        if count == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }

        let mut invalid_control = false;
        // SAFETY: the kernel populated the aligned control buffer and installed its fds.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let length = (*header).cmsg_len;
                let header_length = libc::CMSG_LEN(0) as usize;
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                    && length >= header_length
                {
                    let data_length = length - header_length;
                    invalid_control |=
                        !data_length.is_multiple_of(std::mem::size_of::<libc::c_int>());
                    let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
                    for index in 0..data_length / std::mem::size_of::<libc::c_int>() {
                        fds.push(std::fs::File::from_raw_fd(data.add(index).read_unaligned()));
                    }
                } else {
                    invalid_control = true;
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        anyhow::ensure!(
            !invalid_control && message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0,
            SandboxError::InvalidControl
        );
        anyhow::ensure!(fds.len() <= MAX_RULE_FDS, SandboxError::TooManyDescriptors);
        if count == 0 {
            break;
        }
        input.extend_from_slice(&bytes[..count as usize]);
        anyhow::ensure!(
            input.len() <= MAX_REQUEST_BYTES,
            SandboxError::RequestTooLarge
        );
    }
    let request: Request = serde_json::from_slice(&input)?;
    validate_path(&request.program)?;
    anyhow::ensure!(
        request.argv.iter().all(|arg| !arg.contains('\0')),
        SandboxError::InvalidArgument
    );
    Ok((request, fds))
}

#[cfg(target_os = "linux")]
fn pin_roots(request: &Request, received: &[std::fs::File]) -> anyhow::Result<Vec<PinnedRoot>> {
    use std::os::fd::AsRawFd;

    for fd in received {
        let raw = fd.as_raw_fd();
        anyhow::ensure!(raw >= 3, SandboxError::InvalidDescriptor);
        // SAFETY: F_GETFL only inspects an owned descriptor.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        anyhow::ensure!(
            flags != -1 && flags & libc::O_PATH == libc::O_PATH,
            SandboxError::InvalidDescriptor
        );
    }

    let mut roots = Vec::new();
    for (slots, executable) in [(&request.read_fds, false), (&request.exec_fds, true)] {
        for &slot in slots {
            let index = usize::try_from(slot)
                .ok()
                .and_then(|slot| slot.checked_sub(3));
            let index = index.ok_or(SandboxError::InvalidDescriptor)?;
            let fd = received.get(index).ok_or(SandboxError::InvalidDescriptor)?;
            let is_directory = fd.metadata()?.is_dir();
            roots.push(PinnedRoot {
                index,
                is_directory,
                executable,
            });
        }
    }
    Ok(roots)
}

#[cfg(target_os = "linux")]
fn ensure_enforced(status: landlock::RulesetStatus, no_new_privs: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        status == landlock::RulesetStatus::FullyEnforced && no_new_privs,
        SandboxError::Unenforced
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn restrict_and_exec(
    request: Request,
    roots: Vec<PinnedRoot>,
    received: Vec<std::fs::File>,
) -> anyhow::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };
    use std::os::unix::process::CommandExt;

    let null_input = std::fs::File::open("/dev/null")?;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V3))?
        .create()?;
    for root in &roots {
        let fd = &received[root.index];
        if root.executable {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, AccessFs::Execute))?;
        } else if root.is_directory {
            ruleset =
                ruleset.add_rule(PathBeneath::new(fd, AccessFs::ReadFile | AccessFs::ReadDir))?;
        } else {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, AccessFs::ReadFile))?;
        }
    }
    let status = ruleset.restrict_self()?;
    drop(received);
    ensure_enforced(status.ruleset, status.no_new_privs)?;

    // On glibc, ENOEXEC may invoke /bin/sh; the helper never constructs a shell command string.
    let mut command = std::process::Command::new(&request.program);
    command
        .args(&request.argv)
        .stdin(std::process::Stdio::from(null_input))
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("HOME", "/nonexistent");
    // CLOEXEC leaves any owned descriptors valid if exec fails, avoiding fd reuse on drop.
    // SAFETY: this fresh-exec helper remains single-threaded and the hook only makes a syscall.
    unsafe {
        command.pre_exec(|| {
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Err(command.exec().into())
}

#[cfg(target_os = "linux")]
fn run() -> anyhow::Result<()> {
    let (request, received) = read_request(libc::STDIN_FILENO)?;
    let roots = pin_roots(&request, &received)?;
    restrict_and_exec(request, roots, received)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn enforcement_requires_full_status_and_no_new_privs() {
        use landlock::RulesetStatus::{FullyEnforced, NotEnforced, PartiallyEnforced};
        assert!(super::ensure_enforced(FullyEnforced, true).is_ok());
        assert!(super::ensure_enforced(FullyEnforced, false).is_err());
        assert!(super::ensure_enforced(PartiallyEnforced, true).is_err());
        assert!(super::ensure_enforced(NotEnforced, true).is_err());
    }

    #[test]
    fn failed_requests_close_all_received_descriptors() {
        use std::net::Shutdown;
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        for (payload, count) in [
            (&b"{"[..], 1),
            (
                &br#"{"read_fds":[],"exec_fds":[],"program":"/bin/sh","argv":[]}"#[..],
                65,
            ),
            (
                &br#"{"read_fds":[3],"exec_fds":[],"program":"/bin/sh","argv":[]}"#[..],
                1,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file");
            std::fs::write(&path, "data").unwrap();
            let source = std::fs::File::open(&path).unwrap();
            let waiter = std::fs::File::open(&path).unwrap();
            // SAFETY: both files are live; LOCK_NB prevents blocking the test.
            unsafe {
                assert_eq!(
                    libc::flock(source.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB),
                    0
                );
                assert_eq!(
                    libc::flock(waiter.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB),
                    -1
                );
            }
            let (sender, receiver) = UnixStream::pair().unwrap();
            let mut iov = libc::iovec {
                iov_base: payload.as_ptr().cast_mut().cast(),
                iov_len: payload.len(),
            };
            let bytes = count * std::mem::size_of::<libc::c_int>();
            // SAFETY: CMSG_SPACE computes the required aligned control buffer size.
            let control_bytes = unsafe { libc::CMSG_SPACE(bytes as u32) } as usize;
            let mut control = vec![0_usize; control_bytes.div_ceil(std::mem::size_of::<usize>())];
            // SAFETY: zeroed msghdr is valid, and its buffers remain live for sendmsg.
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = control_bytes;
            // SAFETY: control is aligned and sized for count copies of the open source fd.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(bytes as u32) as usize;
                let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
                for index in 0..count {
                    data.add(index).write(source.as_raw_fd());
                }
                assert_eq!(
                    libc::sendmsg(sender.as_raw_fd(), &message, 0),
                    payload.len() as isize
                );
            }
            sender.shutdown(Shutdown::Write).unwrap();
            drop(source);
            // SAFETY: waiter remains live; the queued SCM_RIGHTS retains the first lock.
            assert_eq!(
                unsafe { libc::flock(waiter.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                -1
            );
            let result = super::read_request(receiver.as_raw_fd()).and_then(|(request, fds)| {
                for fd in &fds {
                    // SAFETY: recvmsg returned this live owned descriptor.
                    assert_ne!(
                        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                        0
                    );
                }
                super::pin_roots(&request, &fds).map(|_| ())
            });
            assert!(result.is_err());
            // SAFETY: this succeeds only if every queued and received copy was closed.
            assert_eq!(
                unsafe { libc::flock(waiter.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0
            );
        }
    }
}
