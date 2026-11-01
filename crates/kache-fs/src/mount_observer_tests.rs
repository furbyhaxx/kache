use super::{EventSource, MountChange, Observer};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::rc::Rc;

#[derive(Default)]
struct FakeState {
    initialized: usize,
    polls: usize,
    acknowledgments: usize,
    fail_initialize: bool,
    fail_acknowledge: bool,
    events: VecDeque<io::Result<bool>>,
}

struct FakeSource(Rc<RefCell<FakeState>>);

impl EventSource for FakeSource {
    fn initialize(&mut self) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        state.initialized += 1;
        if state.fail_initialize {
            return Err(io::Error::other("initialization failed"));
        }
        Ok(())
    }

    fn poll(&mut self) -> io::Result<bool> {
        let mut state = self.0.borrow_mut();
        state.polls += 1;
        state.events.pop_front().unwrap_or(Ok(false))
    }

    fn acknowledge(&mut self) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        state.acknowledgments += 1;
        if state.fail_acknowledge {
            return Err(io::Error::other("acknowledgment failed"));
        }
        Ok(())
    }
}

#[test]
fn new_epoch_and_events_remain_invalid_until_reported_and_acknowledged() {
    let state = Rc::new(RefCell::new(FakeState::default()));
    let mut observer = Observer::new(FakeSource(state.clone())).unwrap();
    assert_eq!(state.borrow().initialized, 1);

    assert_eq!(
        observer.acknowledge().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(state.borrow().acknowledgments, 0);
    assert_eq!(observer.check().unwrap(), MountChange::Invalidated);
    assert_eq!(observer.check().unwrap(), MountChange::Invalidated);
    assert_eq!(state.borrow().polls, 0);

    observer.acknowledge().unwrap();
    assert_eq!(observer.check().unwrap(), MountChange::Unchanged);
    assert_eq!(
        observer.acknowledge().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(state.borrow().acknowledgments, 1);

    state.borrow_mut().events.push_back(Ok(true));
    assert_eq!(observer.check().unwrap(), MountChange::Invalidated);
    let polls = state.borrow().polls;
    assert_eq!(observer.check().unwrap(), MountChange::Invalidated);
    assert_eq!(state.borrow().polls, polls);
    assert_eq!(state.borrow().acknowledgments, 1);

    observer.acknowledge().unwrap();
    assert_eq!(state.borrow().acknowledgments, 2);
    assert_eq!(observer.check().unwrap(), MountChange::Unchanged);
}

#[cfg(target_os = "linux")]
#[test]
fn missing_mount_namespace_is_reported_as_unsupported() {
    let path = std::path::Path::new("/proc/self/ns/kache-observer-missing");
    assert_eq!(
        super::require_mount_namespace(path).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(
        super::require_mount_namespace(std::path::Path::new("/"))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EINVAL)
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_cannot_open_an_observer() {
    let error = match super::MountChangeObserver::new() {
        Ok(_) => panic!("unsupported platform unexpectedly opened an observer"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}

#[test]
fn initialization_error_is_returned() {
    let state = Rc::new(RefCell::new(FakeState {
        fail_initialize: true,
        ..FakeState::default()
    }));
    let error = match Observer::new(FakeSource(state.clone())) {
        Ok(_) => panic!("initialization unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "initialization failed");
    assert_eq!(state.borrow().initialized, 1);
}

#[test]
fn poll_error_leaves_epoch_permanently_unknown() {
    let state = Rc::new(RefCell::new(FakeState::default()));
    let mut observer = Observer::new(FakeSource(state.clone())).unwrap();
    assert_eq!(observer.check().unwrap(), MountChange::Invalidated);
    observer.acknowledge().unwrap();
    state
        .borrow_mut()
        .events
        .push_back(Err(io::Error::other("poll failed")));

    assert_eq!(observer.check().unwrap_err().to_string(), "poll failed");
    assert!(observer.check().is_err());
    assert!(observer.acknowledge().is_err());
    assert_eq!(state.borrow().polls, 1);
    assert_eq!(state.borrow().acknowledgments, 1);
}

#[test]
fn acknowledgment_error_leaves_epoch_permanently_unknown() {
    let state = Rc::new(RefCell::new(FakeState {
        fail_acknowledge: true,
        ..FakeState::default()
    }));
    let mut observer = Observer::new(FakeSource(state.clone())).unwrap();
    assert_eq!(observer.check().unwrap(), MountChange::Invalidated);
    assert_eq!(
        observer.acknowledge().unwrap_err().to_string(),
        "acknowledgment failed"
    );
    state.borrow_mut().fail_acknowledge = false;
    assert!(observer.check().is_err());
    assert!(observer.acknowledge().is_err());
    assert_eq!(state.borrow().acknowledgments, 1);
    assert_eq!(state.borrow().polls, 0);
}
