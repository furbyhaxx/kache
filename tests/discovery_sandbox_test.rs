#![cfg(target_os = "linux")]

use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const MARKER: &str = "__kache_discovery_sandbox_v1";

struct Policy {
    request: Value,
    roots: Vec<landlock::PathFd>,
}

impl Policy {
    fn add_root(&mut self, field: &str, path: &Path) {
        let fd = landlock::PathFd::new(path).unwrap();
        self.request[field]
            .as_array_mut()
            .unwrap()
            .push(json!(self.roots.len() + 3));
        self.roots.push(fd);
    }

    fn fds(&self) -> Vec<RawFd> {
        self.roots.iter().map(|fd| fd.as_fd().as_raw_fd()).collect()
    }
}

fn request(read_roots: &[&Path], script: &str, args: &[&Path]) -> Policy {
    let mut argv = vec![
        "-c".to_owned(),
        script.to_owned(),
        "sandbox-test".to_owned(),
    ];
    argv.extend(args.iter().map(|path| path.to_str().unwrap().to_owned()));
    let mut policy = Policy {
        request: json!({"read_fds": [], "exec_fds": [], "program": "/bin/sh", "argv": argv}),
        roots: Vec::new(),
    };
    for path in [
        "/bin/sh",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/etc/ld.so.cache",
    ]
    .into_iter()
    .map(Path::new)
    .filter(|path| path.exists())
    .chain(read_roots.iter().copied())
    {
        policy.add_root("read_fds", path);
    }
    for path in ["/bin/sh", "/lib", "/lib64", "/usr/lib", "/usr/lib64"]
        .into_iter()
        .map(Path::new)
        .filter(|path| path.exists())
    {
        policy.add_root("exec_fds", path);
    }
    policy
}

fn inherit_fds(command: &mut Command, fds: Vec<libc::c_int>) {
    // SAFETY: these descriptors stay open until spawn, and only the child changes flags.
    unsafe {
        command.pre_exec(move || {
            for &fd in &fds {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn helper() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kache"));
    command
        .arg(MARKER)
        .env_clear()
        .env("KACHE_FAMILY_PROBE_ACTIVE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn send_fds(socket: &UnixStream, input: &[u8], fds: &[RawFd]) -> io::Result<usize> {
    if input.is_empty() {
        return Ok(0);
    }
    let mut iov = libc::iovec {
        iov_base: input.as_ptr().cast_mut().cast(),
        iov_len: input.len(),
    };
    // SAFETY: zeroed msghdr is valid, and iov and control remain live for sendmsg.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    let control_bytes = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let mut control = vec![0_usize; control_bytes.div_ceil(std::mem::size_of::<usize>())];
    if !fds.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_bytes;
        // SAFETY: control is aligned and has CMSG_SPACE for the supplied descriptor array.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                fds.len(),
            );
        }
    }
    // SAFETY: message references live buffers and socket is open.
    let count = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    if count == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(count as usize)
    }
}

fn run_bytes(mut command: Command, input: &[u8], fds: &[RawFd]) -> Output {
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    command.stdin(Stdio::from(OwnedFd::from(receiver)));
    let child = command.spawn().unwrap();
    let sent = send_fds(&sender, input, fds).unwrap();
    sender.write_all(&input[sent..]).unwrap();
    let _ = sender.shutdown(Shutdown::Write);
    child.wait_with_output().unwrap()
}

fn run(policy: &Policy) -> Output {
    run_bytes(
        helper(),
        &serde_json::to_vec(&policy.request).unwrap(),
        &policy.fds(),
    )
}

#[test]
fn approved_reads_work_and_unapproved_reads_and_writes_fail() {
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("allowed");
    let denied = dir.path().join("denied");
    std::fs::create_dir(&allowed).unwrap();
    std::fs::create_dir(&denied).unwrap();
    let allowed_file = allowed.join("data");
    let denied_file = denied.join("secret");
    std::fs::write(&allowed_file, "visible\n").unwrap();
    std::fs::write(&denied_file, "hidden\n").unwrap();
    let policy = request(
        &[&allowed],
        "IFS= read -r value < \"$1\" || exit 10; printf '%s\\n' \"$value\"; if IFS= read -r value < \"$2\" 2>/dev/null; then exit 11; fi; if printf overwritten > \"$1\" 2>/dev/null; then exit 12; fi; printf 'denied\\n'",
        &[&allowed_file, &denied_file],
    );
    let output = run(&policy);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"visible\ndenied\n");
    assert_eq!(std::fs::read(&allowed_file).unwrap(), b"visible\n");
}

#[test]
fn directory_listing_and_read_execute_grants_are_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("allowed");
    let denied = dir.path().join("denied");
    std::fs::create_dir(&allowed).unwrap();
    std::fs::create_dir(&denied).unwrap();
    std::fs::write(allowed.join("visible"), "data").unwrap();
    std::fs::write(denied.join("hidden"), "data").unwrap();

    let mut list = request(&[&allowed, Path::new("/bin/ls")], "", &[]);
    list.request["program"] = json!("/bin/ls");
    list.add_root("exec_fds", Path::new("/bin/ls"));
    list.request["argv"] = json!([allowed]);
    let output = run(&list);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"visible\n");
    list.request["argv"] = json!([denied]);
    let output = run(&list);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let executable = allowed.join("sh");
    std::fs::copy("/bin/sh", &executable).unwrap();
    let mut read_only = request(&[&allowed], "printf LAUNCHED", &[]);
    read_only.request["program"] = json!(executable);
    let output = run(&read_only);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let mut exec_only = request(&[], "printf LAUNCHED", &[]);
    exec_only.request["program"] = json!(executable);
    exec_only.add_root("exec_fds", &executable);
    let output = run(&exec_only);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let fd = exec_only.request["exec_fds"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    exec_only.request["read_fds"]
        .as_array_mut()
        .unwrap()
        .push(fd);
    let output = run(&exec_only);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"LAUNCHED");
}

#[test]
fn direct_truncate_is_denied_even_in_a_readable_root() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::write(&data, "original").unwrap();
    let executable = Path::new("/usr/bin/truncate");
    let baseline = Command::new(executable)
        .env_clear()
        .args(["-s", "0"])
        .arg(&data)
        .output()
        .unwrap();
    assert!(baseline.status.success());
    assert_eq!(std::fs::read(&data).unwrap(), b"");
    std::fs::write(&data, "original").unwrap();

    let mut policy = request(&[dir.path(), executable], "", &[]);
    policy.request["program"] = json!(executable);
    policy.request["argv"] = json!(["-s", "0", data]);
    policy.add_root("exec_fds", executable);
    let output = run(&policy);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Permission denied"));
    assert_eq!(std::fs::read(&data).unwrap(), b"original");
}

#[test]
fn approved_non_directory_file_can_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, "data\n").unwrap();
    let policy = request(
        &[&file],
        "IFS= read -r value < \"$1\" || exit 1; printf '%s' \"$value\"",
        &[&file],
    );
    let output = run(&policy);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"data");
}

#[test]
fn arguments_are_passed_literally() {
    let mut policy = request(&[Path::new("/bin/echo")], "", &[]);
    policy.request["program"] = json!("/bin/echo");
    policy.add_root("exec_fds", Path::new("/bin/echo"));
    policy.request["argv"] = json!(["literal; printf INJECTED"]);
    let output = run(&policy);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"literal; printf INJECTED\n");
}

#[test]
fn environment_is_fixed_and_entry_precedes_normal_startup() {
    let policy = request(
        &[],
        "printf '%s:%s:%s' \"$LANG\" \"$PATH\" \"${KACHE_FAMILY_PROBE_ACTIVE-unset}\"",
        &[],
    );
    let output = run(&policy);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"C:/usr/bin:/bin:unset");
}

#[test]
fn invalid_requests_never_launch() {
    let base = request(&[], "printf LAUNCHED", &[]);
    let output = run(&base);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"LAUNCHED");

    let mut cases = Vec::new();
    for (field, value) in [
        ("program", json!("relative")),
        ("program", json!("/tmp/../bin/bash")),
        ("program", json!("/bin/\u{0}bash")),
        ("program", json!("/does-not-exist")),
        ("read_roots", json!(["/tmp"])),
        ("argv", json!(["-c", "printf LAUNCHED\u{0}"])),
        ("unexpected", json!(true)),
    ] {
        let mut invalid = base.request.clone();
        invalid[field] = value;
        cases.push((
            field.to_owned(),
            serde_json::to_vec(&invalid).unwrap(),
            false,
        ));
    }
    for field in ["read_fds", "exec_fds"] {
        for (value, is_descriptor) in [
            (json!(-1), true),
            (json!(0), true),
            (json!(1), true),
            (json!(2), true),
            (json!(base.roots.len() + 3), true),
            (json!(i32::MAX), true),
            (json!("/tmp"), false),
            (json!(1.5), false),
            (json!(null), false),
            (json!({"fd": 3}), false),
            (json!(2147483648_u64), false),
        ] {
            let mut invalid = base.request.clone();
            invalid[field].as_array_mut().unwrap().push(value.clone());
            cases.push((
                format!("{field}: {value}"),
                serde_json::to_vec(&invalid).unwrap(),
                is_descriptor,
            ));
        }
    }
    cases.extend([
        ("incomplete JSON".into(), b"{".to_vec(), false),
        ("invalid UTF-8".into(), vec![0xff], false),
        (
            "oversized".into(),
            vec![b' '; ((64 * 1024) + 1) as usize],
            false,
        ),
    ]);
    for (name, input, is_descriptor) in cases {
        let output = run_bytes(helper(), &input, &base.fds());
        assert!(!output.status.success(), "{name}");
        assert!(output.stdout.is_empty(), "{name}: {:?}", output.stdout);
        if is_descriptor {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("invalid O_PATH rule descriptor"),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    let mut with_extra_arg = helper();
    with_extra_arg.arg("extra");
    let output = run_bytes(with_extra_arg, &[], &[]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

fn block_syscall(command: &mut Command, syscall: libc::c_long) {
    // SAFETY: the hook only installs a child-local seccomp filter before exec.
    unsafe {
        command.pre_exec(move || {
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
                    k: syscall as u32,
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
}

#[test]
fn non_path_descriptors_are_rejected_even_when_unused() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, "data").unwrap();
    let ordinary = std::fs::File::open(&file).unwrap();
    let mut policy = request(&[], "printf LAUNCHED", &[]);
    let mut fds = policy.fds();
    fds.push(ordinary.as_raw_fd());
    for referenced in [false, true] {
        if referenced {
            policy.request["read_fds"]
                .as_array_mut()
                .unwrap()
                .push(json!(fds.len() + 2));
        }
        let output = run_bytes(
            helper(),
            &serde_json::to_vec(&policy.request).unwrap(),
            &fds,
        );
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid O_PATH rule descriptor"));
    }
}

#[test]
fn descriptor_messages_are_bounded_and_truncation_is_rejected() {
    let policy = request(&[], "printf LAUNCHED", &[]);
    let input = serde_json::to_vec(&policy.request).unwrap();
    let mut fds = policy.fds();
    fds.resize(64, fds[0]);
    let output = run_bytes(helper(), &input, &fds);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"LAUNCHED");
    fds.push(fds[0]);
    let output = run_bytes(helper(), &input, &fds);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("invalid or truncated descriptor control message")
    );

    let (mut sender, receiver) = UnixStream::pair().unwrap();
    let mut command = helper();
    command.stdin(Stdio::from(OwnedFd::from(receiver)));
    let child = command.spawn().unwrap();
    assert_eq!(send_fds(&sender, &input[..1], &fds[..64]).unwrap(), 1);
    let sent = send_fds(&sender, &input[1..], &fds[64..]).unwrap();
    sender.write_all(&input[1 + sent..]).unwrap();
    sender.shutdown(Shutdown::Write).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("too many rule descriptors")
            || stderr.contains("invalid or truncated descriptor control message"),
        "{stderr}"
    );
}

#[test]
fn descriptors_can_arrive_in_multiple_messages() {
    let policy = request(&[], "printf LAUNCHED", &[]);
    let input = serde_json::to_vec(&policy.request).unwrap();
    let fds = policy.fds();
    for &fd in &fds {
        // SAFETY: the caller owns each descriptor throughout this test.
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    let mut command = helper();
    command.stdin(Stdio::from(OwnedFd::from(receiver)));
    let child = command.spawn().unwrap();
    assert_eq!(send_fds(&sender, &input[..1], &fds[..1]).unwrap(), 1);
    let sent = send_fds(&sender, &input[1..], &fds[1..]).unwrap();
    sender.write_all(&input[1 + sent..]).unwrap();
    sender.shutdown(Shutdown::Write).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"LAUNCHED");
    for fd in fds {
        // SAFETY: SCM_RIGHTS does not transfer ownership of the caller's descriptor.
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
}

#[test]
fn closed_descriptor_cannot_be_transferred() {
    use std::os::fd::FromRawFd;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, "data").unwrap();
    let original = std::fs::File::open(file).unwrap();
    // SAFETY: F_DUPFD_CLOEXEC returns a new descriptor owned by this test.
    let raw = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 900) };
    assert!(raw >= 900);
    // SAFETY: raw is a fresh descriptor and is transferred into OwnedFd exactly once.
    drop(unsafe { OwnedFd::from_raw_fd(raw) });

    let (sender, receiver) = UnixStream::pair().unwrap();
    let mut command = helper();
    command.stdin(Stdio::from(OwnedFd::from(receiver)));
    let child = command.spawn().unwrap();
    assert_eq!(
        send_fds(&sender, b"{}", &[raw]).unwrap_err().raw_os_error(),
        Some(libc::EBADF)
    );
    sender.shutdown(Shutdown::Write).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn unavailable_or_failed_restrictions_never_launch() {
    let policy = request(&[], "printf LAUNCHED", &[]);
    for syscall in [
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_restrict_self,
        libc::SYS_prctl,
        libc::SYS_close_range,
    ] {
        let mut command = helper();
        block_syscall(&mut command, syscall);
        let output = run_bytes(
            command,
            &serde_json::to_vec(&policy.request).unwrap(),
            &policy.fds(),
        );
        assert!(!output.status.success(), "syscall {syscall}");
        assert!(output.stdout.is_empty(), "syscall {syscall}");
    }
}

#[test]
fn inherited_descriptors_are_closed_on_exec() {
    use std::io::Seek;

    fn inherit_at_nine(command: &mut Command, source: RawFd) {
        if source == 9 {
            inherit_fds(command, vec![source]);
        } else {
            // SAFETY: source stays open through spawn; dup2 changes only the child.
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(source, 9) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    std::fs::write(&secret, "forbidden-data\n").unwrap();
    let mut source = std::fs::File::open(&secret).unwrap();
    let script = "if IFS= read -r value 2>/dev/null <&9; then printf 'leaked:%s' \"$value\"; else printf closed; fi";
    let mut baseline = Command::new("/bin/sh");
    baseline
        .env_clear()
        .args(["-c", script, "sandbox-test"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    inherit_at_nine(&mut baseline, source.as_raw_fd());
    let output = baseline.output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"leaked:forbidden-data");
    source.rewind().unwrap();

    let policy = request(&[], script, &[]);
    let mut command = helper();
    inherit_at_nine(&mut command, source.as_raw_fd());
    let output = run_bytes(
        command,
        &serde_json::to_vec(&policy.request).unwrap(),
        &policy.fds(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"closed");
}

#[test]
fn approved_root_survives_replacement_before_helper_launch() {
    let dir = tempfile::tempdir().unwrap();
    let approved = dir.path().join("approved");
    let moved = dir.path().join("moved");
    let forbidden = dir.path().join("forbidden");
    std::fs::create_dir(&approved).unwrap();
    std::fs::create_dir(&forbidden).unwrap();
    std::fs::write(approved.join("data"), "approved-data\n").unwrap();
    std::fs::write(forbidden.join("data"), "forbidden-data\n").unwrap();
    let policy = request(
        &[&approved],
        "IFS= read -r value < \"$1\" || exit 10; printf '%s\\n' \"$value\"; if IFS= read -r value < \"$2\" 2>/dev/null; then exit 11; fi; printf redirected-denied",
        &[&moved.join("data"), &approved.join("data")],
    );
    std::fs::rename(&approved, &moved).unwrap();
    symlink(&forbidden, &approved).unwrap();
    let output = run(&policy);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"approved-data\nredirected-denied");
}
