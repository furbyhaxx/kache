#![cfg(target_os = "linux")]

use kache_fs::{MountChange, MountChangeObserver};
use std::ffi::CString;
use std::io::{self, BufRead, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

const CHILD_ENV: &str = "KACHE_FS_MOUNT_OBSERVER_TEST_CHILD";

const PRIVATE_NAMESPACE_TEST: &str = r#"
set -eu
root=$(mktemp -d /tmp/kache-fs-mount-observer.XXXXXXXX)
watch_pid=
cleanup() {
    exec 3>&- || :
    if [ -n "$watch_pid" ]; then
        wait "$watch_pid" || :
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
coproc WATCH { KACHE_FS_MOUNT_OBSERVER_TEST_CHILD="$root/target" "$1" --exact mount_observer_child --nocapture; }
watch_pid=$WATCH_PID
exec 3>&"${WATCH[1]}" 4<&"${WATCH[0]}"
ready=
while IFS= read -r line <&4; do
    printf '%s\n' "$line"
    if [[ "$line" == *WATCH_READY* ]]; then ready=yes; break; fi
done
[ "$ready" = yes ]
mount -o remount,bind,noatime "$root/target" || exit 77
mount -o remount,bind,relatime "$root/target" || exit 77
after=$(findmnt -no OPTIONS -T "$root/target")
[ "$before" = "$after" ]
printf 'changed\n' >&3
done_marker=
while IFS= read -r line <&4; do
    printf '%s\n' "$line"
    if [[ "$line" == *WATCH_DONE* ]]; then done_marker=yes; fi
done
exec 3>&-
wait "$watch_pid"
watch_pid=
[ "$done_marker" = yes ]
"#;

#[test]
fn mount_changes_in_a_private_namespace_invalidate_the_observer() {
    let probe = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "true",
        ])
        .output();
    match probe {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            eprintln!(
                "private user/mount namespaces unavailable: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            return;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("private namespace test unavailable: {error}");
            return;
        }
        Err(error) => panic!("failed to probe private namespaces: {error}"),
    }

    let output = Command::new("unshare")
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
        .output()
        .unwrap();
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
