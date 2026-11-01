use std::io;

/// The status of the observation window for a mount namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountChange {
    /// No mount change has been observed since acknowledgment.
    Unchanged,
    /// The previous observation window is invalid and must not be trusted.
    Invalidated,
}

/// Observes mount changes in the namespace selected when the watch is opened.
///
/// A newly opened observer starts an untrusted epoch: call [`Self::check`],
/// discard any earlier observations when it reports [`MountChange::Invalidated`],
/// and then call [`Self::acknowledge`] before taking new observations. Check
/// again after acquiring observations and discard them on invalidation. Repeat
/// this sequence after every invalidation; multiple changes may coalesce into
/// one event. An event-source error invalidates the window permanently; the
/// observer cannot be reused.
///
/// On Linux this opens `/proc/self/mounts` once and retains that descriptor.
/// It observes the process leader's mount namespace at open time, not changes
/// in other namespaces; changing a thread's namespace does not retarget the
/// watch. Mount events can occur immediately after a check, so this is not
/// atomic with deletion or any other operation. Other platforms return
/// [`io::ErrorKind::Unsupported`] when opening a watch.
pub struct MountChangeObserver {
    observer: Observer<PlatformSource>,
}

impl MountChangeObserver {
    /// Opens and initializes an observer in a new untrusted epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if procfs is unavailable, initialization fails, or the
    /// platform does not support mount-namespace observation.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            observer: Observer::new(PlatformSource::open()?)?,
        })
    }

    /// Checks without waiting for a mount event.
    ///
    /// Invalidation is latched: repeated checks return it until it has been
    /// acknowledged. The first check on a new observer returns invalidation.
    ///
    /// # Errors
    ///
    /// Returns an error and invalidates the window if the event source fails,
    /// or if this observer previously encountered an error.
    pub fn check(&mut self) -> io::Result<MountChange> {
        self.observer.check()
    }

    /// Acknowledges an invalidation already returned by [`Self::check`].
    ///
    /// Discard the invalid observations before calling this method. Events up
    /// to this acknowledgment belong to the discarded window; begin taking
    /// new observations only after it succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] without changing the watch if no
    /// invalidation has been reported. An event-source failure invalidates the
    /// window permanently.
    pub fn acknowledge(&mut self) -> io::Result<()> {
        self.observer.acknowledge()
    }
}

trait EventSource {
    fn initialize(&mut self) -> io::Result<()>;
    fn poll(&mut self) -> io::Result<bool>;
    fn acknowledge(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy)]
enum State {
    Unreported,
    Reported,
    Watching,
    Failed,
}

struct Observer<S> {
    source: S,
    state: State,
}

impl<S: EventSource> Observer<S> {
    fn new(mut source: S) -> io::Result<Self> {
        source.initialize()?;
        Ok(Self {
            source,
            state: State::Unreported,
        })
    }

    fn check(&mut self) -> io::Result<MountChange> {
        match self.state {
            State::Unreported | State::Reported => {
                self.state = State::Reported;
                Ok(MountChange::Invalidated)
            }
            State::Watching => match self.source.poll() {
                Ok(false) => Ok(MountChange::Unchanged),
                Ok(true) => {
                    self.state = State::Reported;
                    Ok(MountChange::Invalidated)
                }
                Err(error) => {
                    self.state = State::Failed;
                    Err(error)
                }
            },
            State::Failed => Err(failed_observer()),
        }
    }

    fn acknowledge(&mut self) -> io::Result<()> {
        match self.state {
            State::Reported => match self.source.acknowledge() {
                Ok(()) => {
                    self.state = State::Watching;
                    Ok(())
                }
                Err(error) => {
                    self.state = State::Failed;
                    Err(error)
                }
            },
            State::Unreported | State::Watching => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no mount invalidation has been reported",
            )),
            State::Failed => Err(failed_observer()),
        }
    }
}

fn failed_observer() -> io::Error {
    io::Error::other("mount observer is unusable after an event-source failure")
}

#[cfg(target_os = "linux")]
struct PlatformSource {
    mounts: std::fs::File,
}

#[cfg(target_os = "linux")]
impl PlatformSource {
    fn open() -> io::Result<Self> {
        use std::mem::MaybeUninit;
        use std::os::fd::AsRawFd;

        let mounts = std::fs::File::open("/proc/self/mounts")?;
        let mut stat = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: the descriptor is open and stat points to writable statfs storage.
        if unsafe { libc::fstatfs(mounts.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful fstatfs initialized the whole structure.
        let stat = unsafe { stat.assume_init() };
        if stat.f_type as u64 != libc::PROC_SUPER_MAGIC as u64 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "/proc/self/mounts is not on procfs",
            ));
        }
        Ok(Self { mounts })
    }

    fn read_mounts(&mut self) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};

        self.mounts.seek(SeekFrom::Start(0))?;
        self.mounts.read_exact(&mut [0])
    }
}

#[cfg(target_os = "linux")]
impl EventSource for PlatformSource {
    fn initialize(&mut self) -> io::Result<()> {
        self.read_mounts()
    }

    fn poll(&mut self) -> io::Result<bool> {
        use std::os::fd::AsRawFd;

        let mut fd = libc::pollfd {
            fd: self.mounts.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        // SAFETY: fd is a valid, writable one-element pollfd array with an open descriptor.
        let result = unsafe { libc::poll(&raw mut fd, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if fd.revents & (libc::POLLNVAL | libc::POLLHUP) != 0 {
            return Err(io::Error::other("mount event descriptor is unavailable"));
        }
        if fd.revents & libc::POLLPRI != 0 {
            return Ok(true);
        }
        if fd.revents != 0 || result != 0 {
            return Err(io::Error::other("unexpected mount event poll result"));
        }
        Ok(false)
    }

    fn acknowledge(&mut self) -> io::Result<()> {
        self.read_mounts()?;
        // Some kernels clear the event on read, others on poll.
        self.poll()?;
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
struct PlatformSource;

#[cfg(not(target_os = "linux"))]
impl PlatformSource {
    fn open() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mount-namespace observation is unavailable on this platform",
        ))
    }
}

#[cfg(not(target_os = "linux"))]
impl EventSource for PlatformSource {
    fn initialize(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn poll(&mut self) -> io::Result<bool> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn acknowledge(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(test)]
#[path = "mount_observer_tests.rs"]
mod tests;
