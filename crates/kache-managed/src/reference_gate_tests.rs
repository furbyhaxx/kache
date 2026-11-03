use std::sync::Arc;
use std::thread;

use super::{Error, Gate};

#[test]
fn poisoned_lock_permanently_inhibits_exclusivity() {
    let gate = Gate::new();
    let operation = gate.begin_operation().expect("operation admitted");
    let state = Arc::clone(&gate.state);
    assert!(
        thread::spawn(move || {
            let _guard = state.lock().expect("unpoisoned test lock");
            panic!("poison accounting lock");
        })
        .join()
        .is_err()
    );
    drop(operation);
    assert!(matches!(gate.begin_drain(), Err(Error::Poisoned)));
    assert!(matches!(gate.begin_drain(), Err(Error::Poisoned)));
}

#[test]
fn counter_underflow_on_completion_taints_epoch() {
    let gate = Gate::new();
    let operation = gate.begin_operation().expect("operation admitted");
    gate.state.lock().expect("unpoisoned test lock").in_flight = 0;
    assert!(matches!(
        operation.complete(),
        Err(Error::InvalidTransition)
    ));
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
}
