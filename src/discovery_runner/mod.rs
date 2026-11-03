use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::Instant;

use crate::discovery_protocol::{MARKER, MAX_REQUEST_BYTES, MAX_RULE_FDS, Request};

const EXIT_CHECK_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub(crate) enum LaunchError {
    Io(io::Error),
    RequestLimit,
    DescriptorLimit,
    OutputLimit,
    TimedOut,
    Failed(ExitStatus),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "discovery helper I/O: {error}"),
            Self::RequestLimit => f.write_str("discovery helper request exceeds 64 KiB"),
            Self::DescriptorLimit => f.write_str("discovery helper request exceeds 64 descriptors"),
            Self::OutputLimit => f.write_str("discovery helper output limit exceeded"),
            Self::TimedOut => f.write_str("discovery helper deadline exceeded"),
            Self::Failed(status) => write!(f, "discovery helper failed: {status}"),
        }
    }
}

impl std::error::Error for LaunchError {}

impl From<io::Error> for LaunchError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct RequestBuffer(Vec<u8>);

impl Write for RequestBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_REQUEST_BYTES - self.0.len() {
            return Err(io::Error::other("request too large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ChildGroup {
    child: Child,
    pid: libc::pid_t,
    active: bool,
}

impl ChildGroup {
    fn signal(&mut self) -> io::Result<()> {
        let pid = self.pid;
        signal_if_owned(
            &mut self.active,
            || {
                // SAFETY: waitid does not reap the child; a zombie keeps the group ID reserved.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // SAFETY: pid is the ID of our child and info is writable.
                if unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                } == -1
                {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            },
            || {
                // SAFETY: process_group(0) made the still-owned child the group leader.
                if unsafe { libc::kill(-pid, libc::SIGKILL) } == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            },
        )
    }
}

fn signal_if_owned(
    active: &mut bool,
    mut wait: impl FnMut() -> io::Result<()>,
    signal: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    if !*active {
        return Ok(());
    }
    loop {
        match wait() {
            Ok(()) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                if error.raw_os_error() == Some(libc::ECHILD) {
                    *active = false;
                }
                return Err(error);
            }
        }
    }
    signal()?;
    *active = false;
    Ok(())
}

impl Drop for ChildGroup {
    fn drop(&mut self) {
        let _ = self.signal();
    }
}

/// Launch the Landlock helper with caller-approved O_PATH descriptors.
///
/// The caller authorizes the descriptors and must not rely on hidden metadata
/// or stable source topology. The deadline and output limit include helper I/O.
/// Cancellation signals the spawned process group, not descendants that leave it.
pub(crate) async fn launch(
    helper: &Path,
    read_fds: &[&File],
    exec_fds: &[&File],
    program: String,
    argv: Vec<String>,
    output_limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, LaunchError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(LaunchError::TimedOut)?;
    let count = read_fds
        .len()
        .checked_add(exec_fds.len())
        .ok_or(LaunchError::DescriptorLimit)?;
    if count > MAX_RULE_FDS {
        return Err(LaunchError::DescriptorLimit);
    }
    let request = Request {
        read_fds: (3..3 + read_fds.len() as i32).collect(),
        exec_fds: (3 + read_fds.len() as i32..3 + count as i32).collect(),
        program,
        argv,
    };
    let mut buffer = RequestBuffer(Vec::new());
    serde_json::to_writer(&mut buffer, &request).map_err(|_| LaunchError::RequestLimit)?;
    if Instant::now() >= deadline {
        return Err(LaunchError::TimedOut);
    }

    let (sender, receiver) = StdUnixStream::pair()?;
    sender.set_nonblocking(true)?;
    let sender = UnixStream::from_std(sender)?;
    let mut command = Command::new(helper);
    command
        .arg(MARKER)
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(receiver)))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command.as_std_mut().process_group(0);
    let child = command.spawn()?;
    let pid = child
        .id()
        .and_then(|pid| libc::pid_t::try_from(pid).ok())
        .filter(|&pid| pid > 1)
        .ok_or_else(|| io::Error::other("invalid helper process id"))?;
    let mut group = ChildGroup {
        child,
        pid,
        active: true,
    };
    let stdout = group
        .child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing helper stdout"))?;
    let fds: Vec<_> = read_fds
        .iter()
        .chain(exec_fds)
        .map(|fd| fd.as_raw_fd())
        .collect();

    let result = tokio::time::timeout_at(deadline, async {
        let ((), output) = tokio::try_join!(
            send_request(sender, &buffer.0, &fds),
            read_output(stdout, output_limit)
        )?;
        wait_for_exit(pid).await?;
        group.signal()?;
        let status = group
            .child
            .try_wait()?
            .ok_or_else(|| io::Error::other("helper exit disappeared"))?;
        if !status.success() {
            return Err(LaunchError::Failed(status));
        }
        if Instant::now() >= deadline {
            return Err(LaunchError::TimedOut);
        }
        Ok(output)
    })
    .await;
    result.map_err(|_| LaunchError::TimedOut)?
}

async fn send_request(
    mut socket: UnixStream,
    input: &[u8],
    fds: &[RawFd],
) -> Result<(), LaunchError> {
    let mut sent = 0;
    while sent < input.len() {
        socket.writable().await?;
        match socket.try_io(Interest::WRITABLE, || {
            send_message(
                socket.as_raw_fd(),
                &input[sent..],
                if sent == 0 { fds } else { &[] },
            )
        }) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
            Ok(count) => sent += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    socket.shutdown().await?;
    Ok(())
}

fn send_message(socket: RawFd, bytes: &[u8], fds: &[RawFd]) -> io::Result<usize> {
    const CONTROL_BYTES: usize =
        unsafe { libc::CMSG_SPACE((MAX_RULE_FDS * std::mem::size_of::<RawFd>()) as u32) as usize };
    let mut control = [0_usize; CONTROL_BYTES.div_ceil(std::mem::size_of::<usize>())];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: zeroed msghdr is valid and the data and control buffers live through sendmsg.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if !fds.is_empty() {
        let fd_bytes = std::mem::size_of_val(fds) as u32;
        message.msg_control = control.as_mut_ptr().cast();
        // SAFETY: fds is bounded by MAX_RULE_FDS, matching the aligned control buffer.
        message.msg_controllen = unsafe { libc::CMSG_SPACE(fd_bytes) } as usize;
        // SAFETY: the control buffer is aligned and has room for the descriptor array.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(fd_bytes) as usize;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
        }
    }
    // SAFETY: socket is live and message refers to valid immutable buffers.
    let result = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

async fn read_output(
    mut stdout: impl AsyncRead + Unpin,
    limit: usize,
) -> Result<Vec<u8>, LaunchError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let remaining = limit - output.len();
        let size = remaining.saturating_add(1).min(buffer.len());
        let count = stdout.read(&mut buffer[..size]).await?;
        if count == 0 {
            return Ok(output);
        }
        if count > remaining {
            return Err(LaunchError::OutputLimit);
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

async fn wait_for_exit(pid: libc::pid_t) -> io::Result<()> {
    loop {
        // SAFETY: a zeroed siginfo_t is valid for waitid to fill.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: pid is our live or unreaped child, and info is writable.
        if unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } == -1
        {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                tokio::task::yield_now().await;
                continue;
            }
            return Err(error);
        }
        // SAFETY: waitid initialized info; zero means no child has exited yet.
        if unsafe { info.si_pid() } != 0 {
            return Ok(());
        }
        tokio::time::sleep(EXIT_CHECK_INTERVAL).await;
    }
}
