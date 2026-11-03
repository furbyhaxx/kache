use std::num::NonZeroU64;
use std::sync::{Arc, Barrier};
use std::thread;

use kache_managed::{Error, Gate};

fn credits(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("test credits are nonzero")
}

#[test]
fn prepared_references_and_inflight_reply_both_block_drain() -> Result<(), Error> {
    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_lookup(2, credits(2))?;

    let mut drain = gate.begin_drain()?;
    assert!(matches!(
        drain.try_exclusive(),
        Err(Error::InvalidationPending)
    ));
    drain.invalidation_complete();
    assert!(drain.try_exclusive()?.is_none());

    let publication = producer.begin_publication()?;
    assert!(drain.try_exclusive()?.is_none());
    gate.forget(2, credits(1))?;
    assert!(drain.try_exclusive()?.is_none());
    publication.complete()?;
    assert!(drain.try_exclusive()?.is_none());
    gate.forget(2, credits(1))?;
    drain.try_exclusive()?.expect("drained").complete()?;
    Ok(())
}

#[test]
fn published_forget_before_reply_confirmation_still_waits_for_completion() -> Result<(), Error> {
    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_lookup(2, credits(1))?;
    let publication = producer.begin_publication()?;
    gate.forget(2, credits(1))?;
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    assert!(drain.try_exclusive()?.is_none());
    publication.complete()?;
    drain.try_exclusive()?.expect("drained").complete()?;
    Ok(())
}

#[test]
fn distinct_objects_and_late_preparation_stay_accounted() -> Result<(), Error> {
    let gate = Gate::new();
    let mut first = gate.begin_producer()?;
    let mut late = gate.begin_producer()?;
    first.reserve_lookup(2, credits(1))?;
    first.begin_publication()?.complete()?;
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    late.reserve_lookup(3, credits(1))?;
    let publication = late.begin_publication()?;
    gate.forget(2, credits(1))?;
    assert!(drain.try_exclusive()?.is_none());
    publication.complete()?;
    assert!(drain.try_exclusive()?.is_none());
    gate.forget(3, credits(1))?;
    drain
        .try_exclusive()?
        .expect("both objects drained")
        .complete()?;
    Ok(())
}

#[test]
fn handles_workloads_and_non_reference_operations_block_drain() -> Result<(), Error> {
    let gate = Gate::new();
    let workload = gate.declare_workload()?;
    let operation = gate.begin_operation()?;
    let mut producer = gate.begin_producer()?;
    producer.reserve_handle(2, 17)?;
    producer.begin_publication()?.complete()?;
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    assert!(drain.try_exclusive()?.is_none());
    gate.release_handle(2, 17)?;
    assert!(drain.try_exclusive()?.is_none());
    workload.complete()?;
    assert!(drain.try_exclusive()?.is_none());
    let second_operation = gate.begin_operation()?;
    operation.complete()?;
    assert!(drain.try_exclusive()?.is_none());
    second_operation.complete()?;
    drain.try_exclusive()?.expect("drained").complete()?;
    Ok(())
}

#[test]
fn released_handle_still_waits_for_reply_completion() -> Result<(), Error> {
    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_handle(2, 17)?;
    let publication = producer.begin_publication()?;
    gate.release_handle(2, 17)?;
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    assert!(drain.try_exclusive()?.is_none());
    publication.complete()?;
    drain
        .try_exclusive()?
        .expect("reply completed")
        .complete()?;
    Ok(())
}

#[test]
fn cancellation_before_publication_rolls_back_but_lost_publication_taints() -> Result<(), Error> {
    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_lookup(2, credits(4))?;
    producer.reserve_handle(2, 44)?;
    producer.cancel()?;
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    drain
        .try_exclusive()?
        .expect("cancelled safely")
        .complete()?;

    let mut producer = gate.begin_producer()?;
    producer.reserve_lookup(2, credits(1))?;
    drop(producer.begin_publication()?);
    gate.forget(2, credits(1))?;
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
    gate.begin_operation()?.complete()?;
    Ok(())
}

#[test]
fn abandoned_tokens_never_prove_completion() -> Result<(), Error> {
    let gate = Gate::new();
    drop(gate.declare_workload()?);
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));

    let gate = Gate::new();
    drop(gate.begin_operation()?);
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));

    let gate = Gate::new();
    drop(gate.begin_producer()?);
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));

    let gate = Gate::new();
    drop(gate.begin_drain()?);
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));

    let gate = Gate::new();
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    drop(drain.try_exclusive()?.expect("drained"));
    assert!(matches!(gate.begin_producer(), Err(Error::AdmissionClosed)));
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
    Ok(())
}

#[test]
fn invalid_or_duplicate_callbacks_and_overflow_taint_permanently() -> Result<(), Error> {
    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_lookup(2, credits(1))?;
    producer.begin_publication()?.complete()?;
    assert!(matches!(
        gate.forget(3, credits(1)),
        Err(Error::UnknownLookup)
    ));
    gate.forget(2, credits(1))?;
    assert!(matches!(
        gate.forget(2, credits(1)),
        Err(Error::UnknownLookup)
    ));
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));

    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_lookup(2, credits(1))?;
    producer.begin_publication()?.complete()?;
    assert!(matches!(
        gate.forget(2, credits(2)),
        Err(Error::LookupUnderflow)
    ));
    gate.forget(2, credits(1))?;
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));

    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_lookup(2, credits(u64::MAX))?;
    assert!(matches!(
        producer.reserve_lookup(2, credits(1)),
        Err(Error::Overflow)
    ));
    producer.cancel()?;
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));

    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_lookup(2, credits(u64::MAX))?;
    producer.begin_publication()?.complete()?;
    let mut next = gate.begin_producer()?;
    assert!(matches!(
        next.reserve_lookup(2, credits(1)),
        Err(Error::Overflow)
    ));
    next.cancel()?;
    gate.forget(2, credits(u64::MAX))?;
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));

    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    assert!(matches!(
        producer.reserve_lookup(1, credits(1)),
        Err(Error::InvalidObject)
    ));
    producer.cancel()?;
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
    Ok(())
}

#[test]
fn handle_ownership_cannot_be_released_or_reused_incorrectly() -> Result<(), Error> {
    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_handle(2, 7)?;
    producer.begin_publication()?.complete()?;
    assert!(matches!(
        gate.release_handle(3, 7),
        Err(Error::HandleMismatch)
    ));
    gate.release_handle(2, 7)?;
    assert!(matches!(
        gate.release_handle(2, 7),
        Err(Error::UnknownHandle)
    ));
    let mut second = gate.begin_producer()?;
    assert!(matches!(
        second.reserve_handle(2, 7),
        Err(Error::DuplicateHandle)
    ));
    second.cancel()?;
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
    Ok(())
}

#[test]
fn unpublished_reservations_cannot_be_forgotten_or_released() -> Result<(), Error> {
    let gate = Gate::new();
    let mut producer = gate.begin_producer()?;
    producer.reserve_lookup(2, credits(1))?;
    producer.reserve_handle(2, 9)?;
    assert!(matches!(
        gate.forget(2, credits(1)),
        Err(Error::LookupUnderflow)
    ));
    assert!(matches!(
        gate.release_handle(2, 9),
        Err(Error::UnpublishedHandle)
    ));
    producer.cancel()?;
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
    Ok(())
}

#[test]
fn uncertain_drain_can_be_cancelled_without_revoking_ordinary_io() -> Result<(), Error> {
    let gate = Gate::new();
    let operation = gate.begin_operation()?;
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    drop(operation);
    assert!(matches!(drain.try_exclusive(), Err(Error::Uncertain)));
    gate.begin_operation()?.complete()?;
    drain.cancel()?;
    gate.begin_operation()?.complete()?;
    gate.begin_producer()?.cancel()?;
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
    Ok(())
}

#[test]
fn exclusive_guard_closes_admission_until_explicit_completion_or_cancel() -> Result<(), Error> {
    let gate = Gate::new();
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    let guard = drain.try_exclusive()?.expect("drained");
    assert!(matches!(gate.begin_producer(), Err(Error::AdmissionClosed)));
    assert!(matches!(
        gate.declare_workload(),
        Err(Error::AdmissionClosed)
    ));
    assert!(matches!(
        gate.begin_operation(),
        Err(Error::AdmissionClosed)
    ));
    guard.complete()?;
    gate.begin_producer()?.cancel()?;

    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    drain.try_exclusive()?.expect("drained").cancel()?;
    gate.begin_producer()?.cancel()?;
    Ok(())
}

#[test]
fn detected_external_event_loss_permanently_inhibits_exclusivity() -> Result<(), Error> {
    let gate = Gate::new();
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    gate.mark_uncertain()?;
    assert!(matches!(drain.try_exclusive(), Err(Error::Uncertain)));
    drain.cancel()?;
    gate.begin_operation()?.complete()?;
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
    Ok(())
}

#[test]
fn unexpected_callback_during_exclusivity_taints_the_epoch() -> Result<(), Error> {
    let gate = Gate::new();
    let mut drain = gate.begin_drain()?;
    drain.invalidation_complete();
    let guard = drain.try_exclusive()?.expect("drained");
    assert!(matches!(
        gate.forget(2, credits(1)),
        Err(Error::UnknownLookup)
    ));
    assert!(matches!(guard.complete(), Err(Error::Uncertain)));
    assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
    Ok(())
}

#[test]
fn operation_and_exclusive_acquisition_are_serialized() -> Result<(), Error> {
    for _ in 0..32 {
        let gate = Gate::new();
        let mut drain = gate.begin_drain()?;
        drain.invalidation_complete();
        let other = gate.clone();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            other.begin_operation()
        });
        barrier.wait();
        let guard = drain.try_exclusive()?;
        match worker.join().expect("operation thread") {
            Ok(operation) => {
                assert!(guard.is_none());
                operation.complete()?;
                drain
                    .try_exclusive()?
                    .expect("operation completed")
                    .complete()?;
            }
            Err(Error::AdmissionClosed) => guard.expect("exclusive acquisition won").complete()?,
            Err(error) => panic!("unexpected admission failure: {error}"),
        }
    }
    Ok(())
}

#[test]
fn uncertainty_racing_exclusivity_prevents_reopening() -> Result<(), Error> {
    for _ in 0..32 {
        let gate = Gate::new();
        let mut drain = gate.begin_drain()?;
        drain.invalidation_complete();
        let other = gate.clone();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            other.mark_uncertain()
        });
        barrier.wait();
        let result = drain.try_exclusive();
        worker.join().expect("uncertainty thread")?;
        match result {
            Ok(Some(guard)) => assert!(matches!(guard.complete(), Err(Error::Uncertain))),
            Err(Error::Uncertain) => drain.cancel()?,
            _ => panic!("unexpected exclusive result"),
        }
        assert!(matches!(gate.begin_drain(), Err(Error::Uncertain)));
    }
    Ok(())
}

#[test]
fn producer_and_drain_race_is_serialized() -> Result<(), Error> {
    for _ in 0..32 {
        let gate = Gate::new();
        let other = gate.clone();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            other.begin_producer()
        });
        barrier.wait();
        let mut drain = gate.begin_drain()?;
        drain.invalidation_complete();
        match worker.join().expect("producer thread") {
            Ok(producer) => {
                assert!(drain.try_exclusive()?.is_none());
                producer.cancel()?;
            }
            Err(Error::AdmissionClosed) => {}
            Err(error) => panic!("unexpected admission failure: {error}"),
        }
        drain.try_exclusive()?.expect("race accounted").complete()?;
    }
    Ok(())
}
