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
            Self::Unenforced => "Landlock or no_new_privs not fully enforced",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SandboxError {}

// The caller must validate approval and identity, bound program I/O, scrub the helper's
// environment before launch, and use controlled pipes for all three stdio streams.
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
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

#[cfg(target_os = "linux")]
// The request ends at stdin EOF; argv contains arguments after the program name.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) read_roots: Vec<String>,
    pub(crate) exec_roots: Vec<String>,
    pub(crate) program: String,
    pub(crate) argv: Vec<String>,
}

#[cfg(target_os = "linux")]
struct PinnedRoot {
    fd: landlock::PathFd,
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
fn read_request() -> anyhow::Result<Request> {
    use std::io::Read;

    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut input)?;
    anyhow::ensure!(
        input.len() <= MAX_REQUEST_BYTES as usize,
        SandboxError::RequestTooLarge
    );
    let request: Request = serde_json::from_slice(&input)?;
    for root in request.read_roots.iter().chain(&request.exec_roots) {
        validate_path(root)?;
    }
    validate_path(&request.program)?;
    anyhow::ensure!(
        request.argv.iter().all(|arg| !arg.contains('\0')),
        SandboxError::InvalidArgument
    );
    Ok(request)
}

#[cfg(target_os = "linux")]
fn pin_roots(request: &Request) -> anyhow::Result<Vec<PinnedRoot>> {
    use std::os::fd::AsFd;

    let mut roots = Vec::new();
    for (paths, executable) in [(&request.read_roots, false), (&request.exec_roots, true)] {
        for path in paths {
            let fd = landlock::PathFd::new(path)?;
            let file = std::fs::File::from(fd.as_fd().try_clone_to_owned()?);
            let metadata = file.metadata()?;
            roots.push(PinnedRoot {
                fd,
                is_directory: metadata.is_dir(),
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
fn restrict_and_exec(request: Request, roots: Vec<PinnedRoot>) -> anyhow::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };
    use std::os::unix::process::CommandExt;

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V3))?
        .create()?;
    for root in &roots {
        if root.executable {
            ruleset = ruleset.add_rule(PathBeneath::new(&root.fd, AccessFs::Execute))?;
        } else if root.is_directory {
            ruleset = ruleset.add_rule(PathBeneath::new(
                &root.fd,
                AccessFs::ReadFile | AccessFs::ReadDir,
            ))?;
        } else {
            ruleset = ruleset.add_rule(PathBeneath::new(&root.fd, AccessFs::ReadFile))?;
        }
    }
    let status = ruleset.restrict_self()?;
    drop(roots);
    ensure_enforced(status.ruleset, status.no_new_privs)?;

    // On glibc, ENOEXEC may invoke /bin/sh; the helper never constructs a shell command string.
    let mut command = std::process::Command::new(&request.program);
    command
        .args(&request.argv)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin");
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
    let request = read_request()?;
    let roots = pin_roots(&request)?;
    restrict_and_exec(request, roots)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::symlink;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::OnceLock;

    use serde_json::{Value, json};

    use super::MARKER;

    fn build_tool(program: &str) -> Command {
        let mut command = Command::new(program);
        command.env_clear().current_dir(env!("CARGO_MANIFEST_DIR"));
        for (key, value) in [
            ("PATH", option_env!("PATH")),
            ("HOME", option_env!("HOME")),
            ("CARGO_HOME", option_env!("CARGO_HOME")),
            ("CARGO_TARGET_DIR", option_env!("CARGO_TARGET_DIR")),
            ("CARGO_BUILD_JOBS", option_env!("CARGO_BUILD_JOBS")),
            ("CARGO_BUILD_TARGET", option_env!("CARGO_BUILD_TARGET")),
            ("RUSTUP_HOME", option_env!("RUSTUP_HOME")),
            ("RUSTUP_TOOLCHAIN", option_env!("RUSTUP_TOOLCHAIN")),
            ("RUSTC", option_env!("RUSTC")),
            ("RUSTC_WRAPPER", option_env!("RUSTC_WRAPPER")),
            (
                "RUSTC_WORKSPACE_WRAPPER",
                option_env!("RUSTC_WORKSPACE_WRAPPER"),
            ),
            ("RUSTFLAGS", option_env!("RUSTFLAGS")),
            (
                "CARGO_ENCODED_RUSTFLAGS",
                option_env!("CARGO_ENCODED_RUSTFLAGS"),
            ),
            ("TMPDIR", option_env!("TMPDIR")),
        ] {
            if let Some(value) = value {
                command.env(key, value);
            }
        }
        command
    }

    fn binary() -> &'static Path {
        static BINARY: OnceLock<PathBuf> = OnceLock::new();
        BINARY.get_or_init(|| {
            let status = build_tool(env!("CARGO"))
                .args(["build", "--locked", "--bin", "kache"])
                .status()
                .unwrap();
            assert!(status.success(), "building production kache binary failed");
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("kache")
        })
    }

    fn request(read_roots: &[&Path], script: &str, args: &[&Path]) -> Value {
        let mut roots: Vec<String> = [
            "/bin/sh",
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/lib64",
            "/etc/ld.so.cache",
        ]
        .iter()
        .map(Path::new)
        .filter(|path| path.exists())
        .map(|path| path.to_str().unwrap().to_owned())
        .collect();
        roots.extend(
            read_roots
                .iter()
                .map(|path| path.to_str().unwrap().to_owned()),
        );
        let mut argv = vec![
            "-c".to_owned(),
            script.to_owned(),
            "sandbox-test".to_owned(),
        ];
        argv.extend(args.iter().map(|path| path.to_str().unwrap().to_owned()));
        let exec_roots: Vec<&str> = ["/bin/sh", "/lib", "/lib64", "/usr/lib", "/usr/lib64"]
            .into_iter()
            .filter(|path| Path::new(path).exists())
            .collect();
        json!({"read_roots": roots, "exec_roots": exec_roots, "program": "/bin/sh", "argv": argv})
    }

    fn helper() -> Command {
        let mut command = Command::new(binary());
        command
            .arg(MARKER)
            .env_clear()
            .env("KACHE_FAMILY_PROBE_ACTIVE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run_bytes(mut command: Command, input: &[u8]) -> Output {
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn run(request: &Value) -> Output {
        run_bytes(helper(), &serde_json::to_vec(request).unwrap())
    }

    fn compile_probe(dir: &Path, code: &str) -> PathBuf {
        let source = dir.join("probe.rs");
        let probe = dir.join("probe");
        std::fs::write(&source, code).unwrap();
        let output = build_tool(option_env!("RUSTC").unwrap_or("rustc"))
            .arg("--edition=2024")
            .arg(&source)
            .arg("-o")
            .arg(&probe)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        probe
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
        list["program"] = json!("/bin/ls");
        list["exec_roots"]
            .as_array_mut()
            .unwrap()
            .push(json!("/bin/ls"));
        list["argv"] = json!([allowed]);
        let output = run(&list);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"visible\n");
        list["argv"] = json!([denied]);
        let output = run(&list);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());

        let executable = allowed.join("sh");
        std::fs::copy("/bin/sh", &executable).unwrap();
        let mut read_only = request(&[&allowed], "printf LAUNCHED", &[]);
        read_only["program"] = json!(executable);
        let output = run(&read_only);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());

        let mut exec_only = request(&[], "printf LAUNCHED", &[]);
        exec_only["program"] = json!(executable);
        exec_only["exec_roots"]
            .as_array_mut()
            .unwrap()
            .push(json!(executable));
        let output = run(&exec_only);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        exec_only["read_roots"]
            .as_array_mut()
            .unwrap()
            .push(json!(executable));
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
        let probe = compile_probe(
            dir.path(),
            r#"
            use std::ffi::{c_char, CString};
            unsafe extern "C" { fn truncate(path: *const c_char, length: i64) -> i32; }
            fn main() {
                let path = CString::new(std::env::args().nth(1).unwrap()).unwrap();
                let result = unsafe { truncate(path.as_ptr(), 0) };
                assert_eq!(result, -1);
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(13));
                print!("denied");
            }
        "#,
        );
        let mut policy = request(&[dir.path()], "", &[]);
        policy["program"] = json!(probe);
        policy["argv"] = json!([data]);
        policy["exec_roots"]
            .as_array_mut()
            .unwrap()
            .push(json!(probe));
        let output = run(&policy);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"denied");
        assert_eq!(std::fs::read(&data).unwrap(), b"original");
    }

    #[test]
    fn approved_non_directory_file_can_be_read() {
        let policy = request(
            &[Path::new("/dev/null")],
            "if : < /dev/null; then printf allowed; else exit 1; fi",
            &[],
        );
        let output = run(&policy);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"allowed");
    }

    #[test]
    fn arguments_are_passed_literally() {
        let mut policy = request(&[Path::new("/bin/echo")], "", &[]);
        policy["program"] = json!("/bin/echo");
        policy["exec_roots"]
            .as_array_mut()
            .unwrap()
            .push(json!("/bin/echo"));
        policy["argv"] = json!(["literal; printf INJECTED"]);
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
        let mut cases = Vec::new();
        for (field, value) in [
            ("program", json!("relative")),
            ("program", json!("/tmp/../bin/bash")),
            ("program", json!("/bin/\u{0}bash")),
            ("program", json!("/does-not-exist")),
            ("read_roots", json!(["relative"])),
            ("read_roots", json!(["/does-not-exist"])),
            ("exec_roots", json!(["/tmp/../bin"])),
            ("argv", json!(["-c", "printf LAUNCHED\u{0}"])),
            ("unexpected", json!(true)),
        ] {
            let mut invalid = base.clone();
            invalid[field] = value;
            cases.push(serde_json::to_vec(&invalid).unwrap());
        }
        cases.extend([
            b"{".to_vec(),
            vec![0xff],
            vec![b' '; (super::MAX_REQUEST_BYTES + 1) as usize],
        ]);
        for input in cases {
            let output = run_bytes(helper(), &input);
            assert!(!output.status.success());
            assert!(output.stdout.is_empty(), "{:?}", output.stdout);
        }
        let mut with_extra_arg = helper();
        with_extra_arg.arg("extra");
        let output = run_bytes(with_extra_arg, &[]);
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
            let output = run_bytes(command, &serde_json::to_vec(&policy).unwrap());
            assert!(!output.status.success(), "syscall {syscall}");
            assert!(output.stdout.is_empty(), "syscall {syscall}");
        }
        use landlock::RulesetStatus::{FullyEnforced, NotEnforced, PartiallyEnforced};
        assert!(super::ensure_enforced(FullyEnforced, true).is_ok());
        assert!(super::ensure_enforced(FullyEnforced, false).is_err());
        assert!(super::ensure_enforced(PartiallyEnforced, true).is_err());
        assert!(super::ensure_enforced(NotEnforced, true).is_err());
    }

    fn inherit_fd(command: &mut Command, source: libc::c_int) {
        // SAFETY: dup2 changes only the child's descriptor table before exec.
        unsafe {
            command.pre_exec(move || {
                if source == 198 {
                    let flags = libc::fcntl(source, libc::F_GETFD);
                    if flags == -1
                        || libc::fcntl(source, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(source, 198) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[test]
    fn inherited_descriptors_are_closed_on_exec() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "forbidden-data\n").unwrap();
        let probe_dir = tempfile::tempdir().unwrap();
        let probe = compile_probe(
            probe_dir.path(),
            r#"
            unsafe extern "C" {
                fn fcntl(fd: i32, command: i32, ...) -> i32;
                fn read(fd: i32, buffer: *mut u8, len: usize) -> isize;
            }
            fn main() {
                if unsafe { fcntl(198, 1) } == -1 {
                    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(9));
                    print!("closed");
                } else {
                    let mut buffer = [0; 128];
                    let len = unsafe { read(198, buffer.as_mut_ptr(), buffer.len()) };
                    assert!(len >= 0);
                    let contents = std::str::from_utf8(&buffer[..len as usize]).unwrap();
                    print!("leaked:{}", contents.trim_end());
                }
            }
        "#,
        );
        let source = std::fs::File::open(&secret).unwrap();
        let mut baseline = Command::new(&probe);
        baseline
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        inherit_fd(&mut baseline, source.as_raw_fd());
        let output = baseline.output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"leaked:forbidden-data");
        drop(source);

        let source = std::fs::File::open(&secret).unwrap();
        let mut command = helper();
        inherit_fd(&mut command, source.as_raw_fd());
        let mut policy = request(&[&probe], "", &[]);
        policy["program"] = json!(probe);
        policy["argv"] = json!([]);
        policy["exec_roots"]
            .as_array_mut()
            .unwrap()
            .push(json!(probe));
        let output = run_bytes(command, &serde_json::to_vec(&policy).unwrap());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"closed");
    }

    #[repr(C)]
    #[derive(Default)]
    struct SyscallInfo {
        op: u8,
        padding: [u8; 3],
        arch: u32,
        instruction_pointer: u64,
        stack_pointer: u64,
        data: [u64; 7],
    }

    struct TracedChild(Option<Child>);

    impl Drop for TracedChild {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn pinned_root_survives_pathname_replacement() {
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
        let mut command = helper();
        // SAFETY: the child requests tracing before its fresh exec; the parent controls it.
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut traced = TracedChild(Some(command.spawn().unwrap()));
        let child = traced.0.as_mut().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&policy).unwrap())
            .unwrap();
        let pid = child.id() as libc::pid_t;
        let mut status = 0;
        // SAFETY: waitpid and ptrace operate only on the stopped child and valid local storage.
        unsafe {
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            assert_eq!(
                libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_TRACESYSGOOD),
                0
            );
            loop {
                assert_eq!(libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0), 0);
                assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
                assert!(
                    libc::WIFSTOPPED(status),
                    "child exited before pinning roots: {status}"
                );
                if libc::WSTOPSIG(status) != (libc::SIGTRAP | 0x80) {
                    continue;
                }
                let mut info = SyscallInfo::default();
                let result = libc::ptrace(
                    0x420e as _,
                    pid,
                    std::mem::size_of::<SyscallInfo>(),
                    &mut info,
                );
                assert!(result >= 0, "{}", std::io::Error::last_os_error());
                // Ruleset probing starts only after every requested root has been pinned.
                if info.op == 1 && info.data[0] == libc::SYS_landlock_create_ruleset as u64 {
                    break;
                }
            }
            std::fs::rename(&approved, &moved).unwrap();
            symlink(&forbidden, &approved).unwrap();
            assert_eq!(libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0), 0);
        }
        let output = traced.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"approved-data\nredirected-denied");
    }
}
