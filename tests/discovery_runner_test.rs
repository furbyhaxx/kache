#![cfg(target_os = "linux")]

#[path = "../src/discovery_protocol.rs"]
mod discovery_protocol;

mod discovery_runner {
    include!("../src/discovery_runner/mod.rs");

    #[test]
    fn interrupted_ownership_check_retries_before_signalling() {
        let mut active = true;
        let mut waits = 0;
        let mut signals = 0;
        let result = signal_if_owned(
            &mut active,
            || {
                waits += 1;
                if waits == 1 {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Ok(())
                }
            },
            || {
                signals += 1;
                Ok(())
            },
        );
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(waits, 2);
        assert_eq!(signals, 1);
        assert!(!active);
    }

    #[test]
    fn lost_ownership_disarms_without_signalling() {
        let mut active = true;
        let mut signals = 0;
        let error = signal_if_owned(
            &mut active,
            || Err(io::Error::from_raw_os_error(libc::ECHILD)),
            || {
                signals += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        assert!(!active);
        signal_if_owned(
            &mut active,
            || panic!("ownership was already lost"),
            || panic!("must not signal after losing ownership"),
        )
        .unwrap();
        assert_eq!(signals, 0);
    }

    #[test]
    fn transient_wait_failure_remains_retryable() {
        let mut active = true;
        let mut waits = 0;
        let mut signals = 0;
        let error = signal_if_owned(
            &mut active,
            || {
                waits += 1;
                Err(io::Error::from_raw_os_error(libc::EIO))
            },
            || {
                signals += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(active);
        assert_eq!(signals, 0);
        signal_if_owned(
            &mut active,
            || {
                waits += 1;
                Ok(())
            },
            || {
                signals += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(waits, 2);
        assert_eq!(signals, 1);
        assert!(!active);
    }

    #[test]
    fn ownership_lost_after_wait_error_is_never_signalled() {
        let mut active = true;
        let mut signals = 0;
        let result = signal_if_owned(
            &mut active,
            || Err(io::Error::from_raw_os_error(libc::EIO)),
            || {
                signals += 1;
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
        assert!(active);
        let result = signal_if_owned(
            &mut active,
            || Err(io::Error::from_raw_os_error(libc::ECHILD)),
            || {
                signals += 1;
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ECHILD));
        assert!(!active);
        assert_eq!(signals, 0);
    }

    #[test]
    fn failed_signal_is_retried_only_after_rechecking_ownership() {
        let mut active = true;
        let mut waits = 0;
        let error = signal_if_owned(
            &mut active,
            || {
                waits += 1;
                Ok(())
            },
            || Err(io::Error::from_raw_os_error(libc::EIO)),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(active);
        signal_if_owned(
            &mut active,
            || {
                waits += 1;
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(waits, 2);
        assert!(!active);
    }

    #[tokio::test]
    async fn closed_control_socket_reports_an_error() {
        let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        drop(receiver);
        let sender = tokio::net::UnixStream::from_std(sender).unwrap();
        assert!(send_request(sender, b"{}", &[]).await.is_err());
    }

    #[tokio::test]
    async fn partial_control_writes_transfer_rights_once() {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::MetadataExt;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("root");
        std::fs::write(&file, b"fixture").unwrap();
        let root = super::path_fd(&file);
        let expected_inode = root.metadata().unwrap().ino();
        let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        let size: libc::c_int = 4096;
        // SAFETY: sender and the integer socket-option buffer remain valid for this call.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    sender.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&raw const size).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        sender.set_nonblocking(true).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sender = tokio::net::UnixStream::from_std(sender).unwrap();
        let input = vec![b'x'; 60_000];
        let expected = input.clone();
        let send = async { send_request(sender, &input, &[root.as_raw_fd()]).await };
        let receive = async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            tokio::task::spawn_blocking(move || {
                let mut output = Vec::new();
                let mut inodes = Vec::new();
                loop {
                    let mut bytes = [0_u8; 1024];
                    let mut control = [0_usize; 8];
                    let mut iov = libc::iovec {
                        iov_base: bytes.as_mut_ptr().cast(),
                        iov_len: bytes.len(),
                    };
                    // SAFETY: zero is a valid initial msghdr and the buffers outlive recvmsg.
                    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                    msg.msg_iov = &mut iov;
                    msg.msg_iovlen = 1;
                    msg.msg_control = control.as_mut_ptr().cast();
                    msg.msg_controllen = std::mem::size_of_val(&control);
                    // SAFETY: receiver and the writable message buffers are valid.
                    let n = unsafe {
                        libc::recvmsg(receiver.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC)
                    };
                    assert!(n >= 0, "{}", std::io::Error::last_os_error());
                    if n == 0 {
                        break;
                    }
                    output.extend_from_slice(&bytes[..n as usize]);
                    // SAFETY: recvmsg initialized the ancillary header and installed the received descriptor.
                    unsafe {
                        let header = libc::CMSG_FIRSTHDR(&msg);
                        if !header.is_null() {
                            assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
                            assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
                            assert_eq!(
                                (*header).cmsg_len,
                                libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize
                            );
                            let fd = libc::CMSG_DATA(header)
                                .cast::<libc::c_int>()
                                .read_unaligned();
                            let file = std::fs::File::from_raw_fd(fd);
                            inodes.push(file.metadata().unwrap().ino());
                            assert!(libc::CMSG_NXTHDR(&msg, header).is_null());
                        }
                    }
                }
                (output, inodes)
            })
            .await
            .unwrap()
        };
        let (sent, (actual, inodes)) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(send, receive)
        })
        .await
        .unwrap();
        sent.unwrap();
        assert_eq!(actual, expected);
        assert_eq!(inodes, [expected_inode]);
    }
}

use discovery_runner::{LaunchError, launch};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn path_fd(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
        .unwrap()
}

fn script_helper(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("helper");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

async fn real_helper(
    script: &str,
    args: &[&Path],
    approved: &[&Path],
    cap: usize,
    deadline: Duration,
) -> Result<Vec<u8>, LaunchError> {
    let system = ["/bin/sh", "/lib", "/lib64", "/usr/lib", "/usr/lib64"];
    let executables: Vec<_> = system
        .iter()
        .map(Path::new)
        .filter(|p| p.exists())
        .map(path_fd)
        .collect();
    let fixtures: Vec<_> = approved.iter().map(|p| path_fd(p)).collect();
    let read: Vec<_> = executables.iter().chain(&fixtures).collect();
    let exec: Vec<_> = executables.iter().collect();
    let mut argv = vec!["-c".to_owned(), script.to_owned(), "runner-test".to_owned()];
    argv.extend(args.iter().map(|path| path.to_str().unwrap().to_owned()));
    launch(
        Path::new(env!("CARGO_BIN_EXE_kache")),
        &read,
        &exec,
        "/bin/sh".to_owned(),
        argv,
        cap,
        deadline,
    )
    .await
}

#[tokio::test]
async fn approved_fixture_is_readable_but_unapproved_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let allowed_dir = dir.path().join("allowed");
    let denied_dir = dir.path().join("denied");
    std::fs::create_dir(&allowed_dir).unwrap();
    std::fs::create_dir(&denied_dir).unwrap();
    let allowed = allowed_dir.join("data");
    let denied = denied_dir.join("secret");
    std::fs::write(&allowed, b"visible\n").unwrap();
    std::fs::write(&denied, b"hidden\n").unwrap();
    let output = real_helper(
        "IFS= read -r value < \"$1\" || exit 10; printf '%s\\n' \"$value\"; if IFS= read -r value < \"$2\" 2>/dev/null; then exit 11; fi; printf 'denied\\n'",
        &[&allowed, &denied], &[&allowed_dir], 1024, Duration::from_secs(5),
    ).await.unwrap();
    assert_eq!(output, b"visible\ndenied\n");
    assert_eq!(std::fs::read(&denied).unwrap(), b"hidden\n");
}

#[tokio::test]
async fn empty_output_succeeds_and_nonzero_status_fails() {
    assert_eq!(
        real_helper("exit 0", &[], &[], 0, Duration::from_secs(5))
            .await
            .unwrap(),
        b""
    );
    assert!(matches!(
        real_helper(
            "printf partial; exit 7",
            &[],
            &[],
            1024,
            Duration::from_secs(5)
        )
        .await,
        Err(LaunchError::Failed(_))
    ));
}

#[tokio::test]
async fn exact_output_limit_succeeds_and_excess_fails() {
    let exact = real_helper("printf 1234", &[], &[], 4, Duration::from_secs(5)).await;
    assert_eq!(exact.unwrap(), b"1234");
    let excess = real_helper("printf 12345", &[], &[], 4, Duration::from_secs(5)).await;
    assert!(matches!(excess, Err(LaunchError::OutputLimit)));
}

#[tokio::test]
async fn startup_failure_and_crash_never_run_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("executed");
    let target = format!("printf target > '{}'", marker.display());
    let args = vec!["-c".to_owned(), target];
    let missing = dir.path().join("missing");
    assert!(
        launch(
            &missing,
            &[],
            &[],
            "/bin/sh".to_owned(),
            args.clone(),
            100,
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    let crash = script_helper(dir.path(), "kill -KILL $$");
    assert!(
        launch(
            &crash,
            &[],
            &[],
            "/bin/sh".to_owned(),
            args,
            100,
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    assert!(!marker.exists());
}

#[tokio::test]
async fn helper_environment_is_cleared() {
    const VARIABLE: &str = "KACHE_RUNNER_TEST_ENV_SENTINEL";
    if std::env::var_os(VARIABLE).is_some() {
        let dir = tempfile::tempdir().unwrap();
        let helper = script_helper(
            dir.path(),
            "/bin/cat >/dev/null; printf %s \"${KACHE_RUNNER_TEST_ENV_SENTINEL-unset}\"",
        );
        let output = launch(
            &helper,
            &[],
            &[],
            "/bin/sh".to_owned(),
            vec![],
            20,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(output, b"unset");
        return;
    }
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "helper_environment_is_cleared"])
        .env(VARIABLE, "inherited")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn unavailable_landlock_never_runs_the_target() {
    const VARIABLE: &str = "KACHE_RUNNER_TEST_BLOCK_LANDLOCK";
    if std::env::var_os(VARIABLE).is_some() {
        // SAFETY: the version query passes no pointer for the unused ruleset argument.
        let status = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0,
                1,
            )
        };
        assert_eq!(status, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOSYS)
        );
        let result = real_helper("printf LAUNCHED", &[], &[], 100, Duration::from_secs(5)).await;
        assert!(result.is_err(), "{result:?}");
        return;
    }
    use std::os::unix::process::CommandExt;
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "unavailable_landlock_never_runs_the_target"])
        .env(VARIABLE, "1")
        .kill_on_drop(true);
    // SAFETY: the filter is installed only in the new child and contains only syscalls.
    unsafe {
        command.as_std_mut().pre_exec(|| {
            let mut filter = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_landlock_create_ruleset as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn request_and_descriptor_limits_are_rejected_before_spawn() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("spawned");
    let helper = script_helper(
        dir.path(),
        &format!("printf launched > '{}'", marker.display()),
    );
    let large = vec!["x".repeat(65_536)];
    assert!(matches!(
        launch(
            &helper,
            &[],
            &[],
            "/bin/sh".to_owned(),
            large,
            100,
            Duration::from_secs(1)
        )
        .await,
        Err(LaunchError::RequestLimit)
    ));
    let fd = path_fd(dir.path());
    let too_many = vec![&fd; 65];
    assert!(matches!(
        launch(
            &helper,
            &too_many,
            &[],
            "/bin/sh".to_owned(),
            vec![],
            100,
            Duration::from_secs(1)
        )
        .await,
        Err(LaunchError::DescriptorLimit)
    ));
    assert!(matches!(
        launch(
            &helper,
            &[],
            &[],
            "/bin/sh".to_owned(),
            vec![],
            100,
            Duration::ZERO
        )
        .await,
        Err(LaunchError::TimedOut)
    ));
    assert!(!marker.exists());

    let valid_dir = tempfile::tempdir().unwrap();
    let valid = script_helper(valid_dir.path(), "/bin/cat >/dev/null; printf ok");
    let at_limit = vec![&fd; 64];
    let output = launch(
        &valid,
        &at_limit,
        &[],
        "/bin/sh".to_owned(),
        vec![],
        2,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(output, b"ok");
}

#[tokio::test]
async fn deadline_and_output_limit_survive_descendant_holding_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("descendant-survived");
    let helper = script_helper(
        dir.path(),
        &format!(
            "/bin/cat >/dev/null\n( /bin/sleep 1; printf survived > '{}' ) &\nprintf 12345\nexit 0",
            marker.display()
        ),
    );
    let start = Instant::now();
    let result = launch(
        &helper,
        &[],
        &[],
        "/bin/sh".to_owned(),
        vec![],
        100,
        Duration::from_millis(150),
    )
    .await;
    assert!(matches!(result, Err(LaunchError::TimedOut)), "{result:?}");
    assert!(start.elapsed() < Duration::from_secs(3));
    let result = launch(
        &helper,
        &[],
        &[],
        "/bin/sh".to_owned(),
        vec![],
        4,
        Duration::from_secs(3),
    )
    .await;
    assert!(
        matches!(result, Err(LaunchError::OutputLimit)),
        "{result:?}"
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!marker.exists());
}

#[tokio::test]
async fn cancellation_stops_the_owned_process_group() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let marker = dir.path().join("descendant-survived");
    let helper = script_helper(
        dir.path(),
        &format!(
            "/bin/cat >/dev/null\n( /bin/sleep 1; printf survived > '{}' ) &\nprintf ready > '{}'\nwait",
            marker.display(),
            ready.display()
        ),
    );
    let mut task = tokio::spawn(async move {
        launch(
            &helper,
            &[],
            &[],
            "/bin/sh".to_owned(),
            vec![],
            100,
            Duration::from_secs(10),
        )
        .await
    });
    tokio::select! {
        result = &mut task => panic!("launcher finished before readiness: {result:?}"),
        ready_result = tokio::time::timeout(Duration::from_secs(3), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }) => ready_result.expect("helper did not signal readiness"),
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!marker.exists());
}
