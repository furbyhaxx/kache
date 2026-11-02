#![cfg(target_os = "linux")]

use kache_fs::{MountChange, MountChangeObserver};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "KACHE_FS_MOUNT_OBSERVER_TEST_CHILD";
const BIND_ALIAS_CHILD_ENV: &str = "KACHE_FS_BIND_ALIAS_TEST_ROOT";

const BIND_ALIAS_NAMESPACE_TEST: &str = r#"
set -eu
root=$(mktemp -d /tmp/kache-fs-bind-alias.XXXXXXXX)
cleanup() {
    status=$?
    trap - EXIT
    umount "$root/alias" 2>/dev/null || :
    umount "$root" 2>/dev/null || :
    rmdir "$root" || status=$?
    exit "$status"
}
trap cleanup EXIT
mount_or_skip() {
    local output
    if output=$("$@" 2>&1); then
        return 0
    fi
    case "${output,,}" in
        *"operation not permitted"*|*"permission denied"*|*"not supported"*|*"unknown filesystem type"*|*"no such device"*)
            printf 'private mount unavailable: %s\n' "$output" >&2
            exit 77
            ;;
        *)
            printf 'private mount failed unexpectedly: %s\n' "$output" >&2
            exit 1
            ;;
    esac
}
mount_or_skip mount -t tmpfs -o size=1m tmpfs "$root"
mkdir "$root/source" "$root/alias"
mount_or_skip mount --bind "$root/source" "$root/alias"
status=0
KACHE_FS_BIND_ALIAS_TEST_ROOT="$root" "$1" --exact mount_identity_child --nocapture || status=$?
exit "$status"
"#;

const PRIVATE_NAMESPACE_TEST: &str = r#"
set -eu
root=$(mktemp -d /tmp/kache-fs-mount-observer.XXXXXXXX)
watch_pid=
watch_read=
watch_write=
cleanup() {
    if [ -n "$watch_write" ]; then exec {watch_write}>&- || :; fi
    if [ -n "$watch_read" ]; then exec {watch_read}<&- || :; fi
    if [ -n "$watch_pid" ]; then
        wait "$watch_pid" || :
        printf 'WATCH_REAPED=%s\n' "$watch_pid"
    fi
    umount "$root/target" 2>/dev/null || :
    umount "$root" 2>/dev/null || :
    rmdir "$root"
}
trap cleanup EXIT
mount -t tmpfs -o size=1m tmpfs "$root" || exit 77
mkdir "$root/source" "$root/target"
mount --bind "$root/source" "$root/target" || exit 77
before=$(findmnt -no OPTIONS -T "$root/target")
case ",$before," in *,relatime,*) ;; *) exit 1 ;; esac
coproc WATCH { export KACHE_FS_MOUNT_OBSERVER_TEST_CHILD="$root/target"; exec "$1" --exact mount_observer_child --nocapture; }
watch_pid=${WATCH_PID:-}
watch_read=${WATCH[0]:-}
watch_write=${WATCH[1]:-}
[ -n "$watch_pid" ] && [ -n "$watch_read" ] && [ -n "$watch_write" ]
printf 'WATCH_PID=%s\n' "$watch_pid"
ready=
while IFS= read -r line <&"$watch_read"; do
    printf '%s\n' "$line"
    if [[ "$line" == *WATCH_READY* ]]; then ready=yes; break; fi
done
[ "$ready" = yes ]
remount_target="$root/target"
if [ "$2" = fail-remount ]; then remount_target="$root/missing"; fi
mount -o remount,bind,noatime "$remount_target" || exit 77
mount -o remount,bind,relatime "$root/target" || exit 77
after=$(findmnt -no OPTIONS -T "$root/target")
[ "$before" = "$after" ]
printf 'changed\n' >&"$watch_write"
done_marker=
while IFS= read -r line <&"$watch_read"; do
    printf '%s\n' "$line"
    if [[ "$line" == *WATCH_DONE* ]]; then done_marker=yes; fi
done
exec {watch_write}>&-
watch_write=
status=0
wait "$watch_pid" || status=$?
watch_pid=
[ "$status" -eq 0 ]
[ "$done_marker" = yes ]
"#;

fn bounded_output(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    command
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn()?;
    let group = child.id() as libc::pid_t;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    match receiver.recv_timeout(timeout) {
        Ok(output) => {
            worker.join().map_err(|_| io::Error::other("wait failed"))?;
            output
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // SAFETY: process_group(0) put the child in its own process group.
            unsafe { libc::kill(-group, libc::SIGKILL) };
            let output = receiver.recv_timeout(Duration::from_secs(2)).map_err(|_| {
                io::Error::other("timed-out namespace subprocess could not be reaped")
            })?;
            worker.join().map_err(|_| io::Error::other("wait failed"))?;
            output?;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "private namespace subprocess exceeded its deadline",
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other("wait failed")),
    }
}

fn namespaces_available() -> bool {
    let mut probe = Command::new("unshare");
    probe.args([
        "--user",
        "--map-root-user",
        "--mount",
        "--propagation",
        "private",
        "true",
    ]);
    match bounded_output(&mut probe, Duration::from_secs(10)) {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            eprintln!(
                "private user/mount namespaces unavailable: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            false
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("private namespace test unavailable: {error}");
            false
        }
        Err(error) => panic!("failed to probe private namespaces: {error}"),
    }
}

fn namespace_test(scenario: &str) -> Option<Output> {
    if !namespaces_available() {
        return None;
    }
    let mut command = Command::new("unshare");
    command
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "bash",
            "-c",
            PRIVATE_NAMESPACE_TEST,
            "mount-observer-test",
        ])
        .arg(std::env::current_exe().unwrap())
        .arg(scenario);
    Some(
        bounded_output(&mut command, Duration::from_secs(10))
            .expect("run bounded private namespace test"),
    )
}

#[test]
fn mount_changes_in_a_private_namespace_invalidate_the_observer() {
    let Some(output) = namespace_test("normal") else {
        return;
    };
    if output.status.code() == Some(77) {
        eprintln!(
            "isolated mounts unavailable: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return;
    }
    assert!(
        output.status.success(),
        "private namespace test failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn remount_failure_reaps_observer() {
    let started = Instant::now();
    let Some(output) = namespace_test("fail-remount") else {
        return;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(77),
        "expected remount failure, got {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(8));
    assert!(stdout.contains("WATCH_READY"));
    let pid: libc::pid_t = stdout
        .lines()
        .find_map(|line| line.strip_prefix("WATCH_PID="))
        .expect("watcher PID")
        .parse()
        .unwrap();
    assert!(stdout.contains(&format!("WATCH_REAPED={pid}")));
    // SAFETY: signal zero checks whether a process exists without signaling it.
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    println!("remount failure exited 77 and reaped watcher {pid}");
}

#[test]
fn namespace_subprocess_has_a_deadline() {
    if !namespaces_available() {
        return;
    }
    let mut command = Command::new("unshare");
    command.args([
        "--user",
        "--map-root-user",
        "--mount",
        "--propagation",
        "private",
        "sleep",
        "30",
    ]);
    let started = Instant::now();
    let error = bounded_output(&mut command, Duration::from_millis(250)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(3));
    println!("private namespace subprocess timed out and was reaped");
}

#[test]
fn bind_aliases_preserve_export_handle_but_have_distinct_unique_mount_ids() {
    if !namespaces_available() {
        return;
    }

    let mut command = Command::new("unshare");
    command
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "bash",
            "-c",
            BIND_ALIAS_NAMESPACE_TEST,
            "bind-alias-test",
        ])
        .arg(std::env::current_exe().unwrap());
    let output = bounded_output(&mut command, Duration::from_secs(10))
        .expect("run bounded private bind-alias test");
    if output.status.code() == Some(77) {
        eprintln!(
            "bind-alias identity test skipped: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert!(
        output.status.success(),
        "private bind-alias test failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("BIND_ALIAS_OK"),
        "bind-alias child did not complete its assertions\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{stdout}");
}

#[test]
fn mount_observer_child() {
    let Some(target) = std::env::var_os(CHILD_ENV) else {
        return;
    };

    let mut observer = MountChangeObserver::new().unwrap();
    assert_eq!(observer.check().unwrap(), MountChange::Invalidated);
    observer.acknowledge().unwrap();
    assert_eq!(observer.check().unwrap(), MountChange::Unchanged);
    let original_flags = mount_flags(Path::new(&target));
    assert_eq!(original_flags & libc::ST_NOATIME, 0);

    println!("WATCH_READY");
    io::stdout().flush().unwrap();
    let mut message = String::new();
    io::stdin().lock().read_line(&mut message).unwrap();
    assert_eq!(message.trim(), "changed");
    assert_eq!(mount_flags(Path::new(&target)), original_flags);
    assert_eq!(observer.check().unwrap(), MountChange::Invalidated);
    assert_eq!(observer.check().unwrap(), MountChange::Invalidated);
    observer.acknowledge().unwrap();
    assert_eq!(observer.check().unwrap(), MountChange::Unchanged);
    println!("WATCH_DONE");
}

#[test]
fn mount_identity_child() {
    let Some(root) = std::env::var_os(BIND_ALIAS_CHILD_ENV) else {
        return;
    };

    let source = File::open(Path::new(&root).join("source")).expect("open source directory");
    let alias = File::open(Path::new(&root).join("alias")).expect("open bind alias directory");
    let source_export =
        require_supported_identity(kache_fs::export_file_handle(&source), "export_file_handle");
    let alias_export =
        require_supported_identity(kache_fs::export_file_handle(&alias), "export_file_handle");
    assert_eq!(
        source_export.handle, alias_export.handle,
        "bind aliases should have equal opaque file handles"
    );
    let source_mount_id =
        require_supported_identity(kache_fs::unique_mount_id(&source), "unique_mount_id");
    let alias_mount_id =
        require_supported_identity(kache_fs::unique_mount_id(&alias), "unique_mount_id");
    assert_ne!(
        source_mount_id, alias_mount_id,
        "bind aliases should have distinct unique mount IDs"
    );
    println!("BIND_ALIAS_OK");
}

fn require_supported_identity<T>(result: io::Result<T>, operation: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            eprintln!("{operation} unsupported for the bind-alias fixture: {error}");
            std::process::exit(77);
        }
        Err(error) => panic!("{operation} failed unexpectedly: {error}"),
    }
}

fn mount_flags(path: &Path) -> libc::c_ulong {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is NUL-terminated and stat points to writable statvfs storage.
    assert_eq!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: a successful statvfs initialized the whole structure.
    unsafe { stat.assume_init().f_flag }
}
