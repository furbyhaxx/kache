use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, MutexGuard};

const FUSE_ROOT_ID: u64 = 1;

#[cfg(test)]
#[path = "reference_gate_tests.rs"]
mod tests;

/// An admission or accounting failure for a single target epoch.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The requested work cannot start in the current phase.
    #[error("admission is closed")]
    AdmissionClosed,
    /// The epoch can no longer establish a reliable drain.
    #[error("accounting is permanently uncertain")]
    Uncertain,
    /// The coordinator has not confirmed its external invalidation pass.
    #[error("invalidation is not complete")]
    InvalidationPending,
    /// The object ID is zero or names the global FUSE root.
    #[error("object ID must be greater than the FUSE root ID")]
    InvalidObject,
    /// A forget named an object without any tracked credits.
    #[error("unknown lookup object")]
    UnknownLookup,
    /// A forget exceeded the object's published or publishing credits.
    #[error("lookup credit underflow")]
    LookupUnderflow,
    /// A release named an unknown or already released handle.
    #[error("unknown handle")]
    UnknownHandle,
    /// A release named the wrong owner of a handle.
    #[error("handle owner mismatch")]
    HandleMismatch,
    /// A release preceded publication of the handle.
    #[error("handle has not entered publication")]
    UnpublishedHandle,
    /// A handle ID was already reserved in this epoch.
    #[error("handle ID was already used")]
    DuplicateHandle,
    /// An accounting quantity exceeded its representable range.
    #[error("accounting overflow")]
    Overflow,
    /// A lock was poisoned and the epoch is permanently uncertain.
    #[error("accounting lock poisoned")]
    Poisoned,
    /// An internal accounting invariant or proof transition failed.
    #[error("invalid accounting transition")]
    InvalidTransition,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Open,
    Draining,
    Exclusive,
}

#[derive(Clone, Copy, Default)]
struct LookupCredits {
    prepared: u64,
    exposed: u64,
}

struct Handle {
    object: u64,
    exposed: bool,
}

struct State {
    phase: Phase,
    uncertain: bool,
    lookups: HashMap<u64, LookupCredits>,
    handles: HashMap<u64, Handle>,
    used_handles: HashSet<u64>,
    in_flight: u64,
    workloads: u64,
}

impl State {
    fn new() -> Self {
        Self {
            phase: Phase::Open,
            uncertain: false,
            lookups: HashMap::new(),
            handles: HashMap::new(),
            used_handles: HashSet::new(),
            in_flight: 0,
            workloads: 0,
        }
    }

    fn fault<T>(&mut self, error: Error) -> Result<T, Error> {
        self.uncertain = true;
        Err(error)
    }

    fn check_object(&mut self, object: u64) -> Result<(), Error> {
        if object <= FUSE_ROOT_ID {
            return self.fault(Error::InvalidObject);
        }
        Ok(())
    }

    fn start_flight(&mut self) -> Result<(), Error> {
        let Some(count) = self.in_flight.checked_add(1) else {
            return self.fault(Error::Overflow);
        };
        self.in_flight = count;
        Ok(())
    }

    fn finish_flight(&mut self) -> Result<(), Error> {
        let Some(count) = self.in_flight.checked_sub(1) else {
            return self.fault(Error::InvalidTransition);
        };
        self.in_flight = count;
        Ok(())
    }

    fn expose_lookup(&mut self, object: u64, count: u64) -> Result<(), Error> {
        let Some(lookup) = self.lookups.get_mut(&object) else {
            return self.fault(Error::InvalidTransition);
        };
        let (Some(prepared), Some(exposed)) = (
            lookup.prepared.checked_sub(count),
            lookup.exposed.checked_add(count),
        ) else {
            return self.fault(Error::InvalidTransition);
        };
        lookup.prepared = prepared;
        lookup.exposed = exposed;
        Ok(())
    }

    fn cancel_lookup(&mut self, object: u64, count: u64) -> Result<(), Error> {
        let Some(lookup) = self.lookups.get_mut(&object) else {
            return self.fault(Error::InvalidTransition);
        };
        let Some(prepared) = lookup.prepared.checked_sub(count) else {
            return self.fault(Error::InvalidTransition);
        };
        lookup.prepared = prepared;
        if lookup.prepared == 0 && lookup.exposed == 0 {
            self.lookups.remove(&object);
        }
        Ok(())
    }

    fn drained(&self) -> bool {
        self.lookups.is_empty()
            && self.handles.is_empty()
            && self.in_flight == 0
            && self.workloads == 0
    }
}

/// A shared ledger for exactly one managed target and FUSE connection epoch.
///
/// All producers, callbacks, non-reference operations, and declared workloads for that
/// epoch must use clones of this same gate. Creating another gate does not recover certainty
/// for an existing epoch. The caller must validate event origin, ordering, completeness, and
/// external workload lifetimes. The frontend must validate that object IDs belong to this
/// target and remain stable within the epoch. Handle IDs cannot be reused even after
/// cancellation or release. `FUSE_ROOT_ID` (1) is not the target inode.
///
/// Lookup callbacks carry counts, not individual credit identities; the trusted frontend must
/// prevent duplicate callbacks that are indistinguishable from other outstanding credits.
///
/// This gate does not itself guard ordinary I/O. A frontend must retain the target and may
/// continue non-reference I/O if accounting becomes uncertain; it must not infer deletion
/// authority from either a failed operation or this local ledger.
#[derive(Clone)]
pub struct Gate {
    state: Arc<Mutex<State>>,
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    /// Starts a new, empty epoch. Use only when the external connection boundary is new.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::new())),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, Error> {
        self.state.lock().map_err(|poisoned| {
            poisoned.into_inner().uncertain = true;
            Error::Poisoned
        })
    }

    /// Permanently marks the epoch uncertain after an externally detected loss or fault.
    ///
    /// Use this when the frontend can no longer guarantee callback completeness or the
    /// external workload boundary fails. This never revokes already admitted I/O.
    pub fn mark_uncertain(&self) -> Result<(), Error> {
        self.lock()?.uncertain = true;
        Ok(())
    }

    /// Admits reference-producing work before backend I/O or publication.
    ///
    /// Already admitted producers may prepare and publish while a drain is pending.
    pub fn begin_producer(&self) -> Result<Producer, Error> {
        {
            let mut state = self.lock()?;
            if state.phase != Phase::Open {
                return Err(Error::AdmissionClosed);
            }
            state.start_flight()?;
        }
        Ok(Producer {
            proof: Proof::new(self),
            lookups: HashMap::new(),
            handles: Vec::new(),
        })
    }

    /// Admits an operation that cannot create references, through its reply completion.
    ///
    /// Such work remains admissible while draining or uncertain, but not while an exclusive
    /// guard is held. An accounting error is not a command to revoke existing I/O.
    pub fn begin_operation(&self) -> Result<Operation, Error> {
        {
            let mut state = self.lock()?;
            if state.phase == Phase::Exclusive {
                return Err(Error::AdmissionClosed);
            }
            state.start_flight()?;
        }
        Ok(Operation {
            proof: Proof::new(self),
        })
    }

    /// Declares a workload before it can access the target.
    ///
    /// Only the caller's independently validated lifecycle evidence can justify completion.
    pub fn declare_workload(&self) -> Result<Workload, Error> {
        {
            let mut state = self.lock()?;
            if state.phase != Phase::Open {
                return Err(Error::AdmissionClosed);
            }
            let Some(count) = state.workloads.checked_add(1) else {
                return state.fault(Error::Overflow);
            };
            state.workloads = count;
        }
        Ok(Workload {
            proof: Proof::new(self),
        })
    }

    /// Applies a trusted FORGET for an individual target inode.
    ///
    /// Only credits whose publication has started may be forgotten. A callback must not be
    /// duplicated or misattributed, including when other credits for this object exist.
    pub fn forget(&self, object: u64, count: NonZeroU64) -> Result<(), Error> {
        let mut state = self.lock()?;
        state.check_object(object)?;
        let Some(lookup) = state.lookups.get_mut(&object) else {
            return state.fault(Error::UnknownLookup);
        };
        let Some(exposed) = lookup.exposed.checked_sub(count.get()) else {
            return state.fault(Error::LookupUnderflow);
        };
        lookup.exposed = exposed;
        if lookup.exposed == 0 && lookup.prepared == 0 {
            state.lookups.remove(&object);
        }
        Ok(())
    }

    /// Applies a trusted release for a handle and its owning target inode.
    pub fn release_handle(&self, object: u64, handle: u64) -> Result<(), Error> {
        let mut state = self.lock()?;
        state.check_object(object)?;
        let Some(entry) = state.handles.get(&handle) else {
            return state.fault(Error::UnknownHandle);
        };
        if entry.object != object {
            return state.fault(Error::HandleMismatch);
        }
        if !entry.exposed {
            return state.fault(Error::UnpublishedHandle);
        }
        state.handles.remove(&handle);
        Ok(())
    }

    /// Closes admission of new reference producers and workloads.
    ///
    /// The returned token does not wait or perform invalidation. The coordinator must
    /// invalidate outside this gate and outside frontend callbacks, then confirm the pass.
    pub fn begin_drain(&self) -> Result<Drain, Error> {
        {
            let mut state = self.lock()?;
            if state.uncertain {
                return Err(Error::Uncertain);
            }
            if state.phase != Phase::Open {
                return Err(Error::AdmissionClosed);
            }
            state.phase = Phase::Draining;
        }
        Ok(Drain {
            proof: Proof::new(self),
            invalidated: false,
        })
    }
}

struct Proof {
    gate: Gate,
    active: bool,
}

impl Proof {
    fn new(gate: &Gate) -> Self {
        Self {
            gate: gate.clone(),
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for Proof {
    fn drop(&mut self) {
        if self.active {
            match self.gate.state.lock() {
                Ok(mut state) => state.uncertain = true,
                Err(poisoned) => poisoned.into_inner().uncertain = true,
            }
        }
    }
}

/// Admitted reference-producing work that has not begun publication.
///
/// Reserve every lookup and handle before beginning publication. Explicit cancellation is
/// valid only when nothing from this producer was exposed; dropping it instead taints the
/// epoch. All I/O happens outside gate methods.
#[must_use = "cancel or begin publication; dropping a producer taints accounting"]
pub struct Producer {
    proof: Proof,
    lookups: HashMap<u64, u64>,
    handles: Vec<u64>,
}

impl Producer {
    /// Reserves positive lookup credits for an individual target inode.
    pub fn reserve_lookup(&mut self, object: u64, count: NonZeroU64) -> Result<(), Error> {
        let mut state = self.proof.gate.lock()?;
        state.check_object(object)?;
        let lookup = state.lookups.get(&object).copied().unwrap_or_default();
        let Some(prepared) = lookup.prepared.checked_add(count.get()) else {
            return state.fault(Error::Overflow);
        };
        if prepared.checked_add(lookup.exposed).is_none() {
            return state.fault(Error::Overflow);
        }
        let Some(owned) = self
            .lookups
            .get(&object)
            .copied()
            .unwrap_or_default()
            .checked_add(count.get())
        else {
            return state.fault(Error::Overflow);
        };
        state
            .lookups
            .insert(object, LookupCredits { prepared, ..lookup });
        self.lookups.insert(object, owned);
        Ok(())
    }

    /// Reserves an epoch-unique handle owned by an individual target inode.
    pub fn reserve_handle(&mut self, object: u64, handle: u64) -> Result<(), Error> {
        let mut state = self.proof.gate.lock()?;
        state.check_object(object)?;
        if !state.used_handles.insert(handle) {
            return state.fault(Error::DuplicateHandle);
        }
        state.handles.insert(
            handle,
            Handle {
                object,
                exposed: false,
            },
        );
        self.handles.push(handle);
        Ok(())
    }

    /// Makes reserved references eligible for callbacks, before any reply is exposed.
    ///
    /// From this point cancellation is forbidden: a failed or unconfirmed publication must
    /// be abandoned, which permanently taints the epoch. The returned token tracks the reply
    /// until the frontend confirms its actual completion.
    pub fn begin_publication(mut self) -> Result<Publication, Error> {
        {
            let mut state = self.proof.gate.lock()?;
            for (&object, &count) in &self.lookups {
                state.expose_lookup(object, count)?;
            }
            for handle in &self.handles {
                let Some(entry) = state.handles.get_mut(handle) else {
                    return state.fault(Error::InvalidTransition);
                };
                if entry.exposed {
                    return state.fault(Error::InvalidTransition);
                }
                entry.exposed = true;
            }
        }
        let publication = Publication {
            proof: Proof::new(&self.proof.gate),
        };
        self.proof.disarm();
        Ok(publication)
    }

    /// Rolls back reservations when no part of the reply has been published.
    pub fn cancel(mut self) -> Result<(), Error> {
        {
            let mut state = self.proof.gate.lock()?;
            for (&object, &count) in &self.lookups {
                state.cancel_lookup(object, count)?;
            }
            for handle in &self.handles {
                let Some(entry) = state.handles.get(handle) else {
                    return state.fault(Error::InvalidTransition);
                };
                if entry.exposed {
                    return state.fault(Error::InvalidTransition);
                }
                state.handles.remove(handle);
            }
            state.finish_flight()?;
        }
        self.proof.disarm();
        Ok(())
    }
}

/// A reply whose publication has started but is not yet confirmed complete.
#[must_use = "confirm publication; dropping it taints accounting"]
pub struct Publication {
    proof: Proof,
}

impl Publication {
    /// Confirms actual completion of the whole reply, retaining its reference credits.
    ///
    /// FORGET and release callbacks may already have consumed published credits. Failure,
    /// partial publication, or lost completion must instead drop this token without calling
    /// this method.
    pub fn complete(mut self) -> Result<(), Error> {
        self.proof.gate.lock()?.finish_flight()?;
        self.proof.disarm();
        Ok(())
    }
}

/// An in-flight operation that cannot produce references.
#[must_use = "confirm operation completion; dropping it taints accounting"]
pub struct Operation {
    proof: Proof,
}

impl Operation {
    /// Confirms that the operation and its reply are finished.
    pub fn complete(mut self) -> Result<(), Error> {
        self.proof.gate.lock()?.finish_flight()?;
        self.proof.disarm();
        Ok(())
    }
}

/// A declared workload whose real lifecycle is validated outside this crate.
#[must_use = "confirm externally validated completion; dropping it taints accounting"]
pub struct Workload {
    proof: Proof,
}

impl Workload {
    /// Confirms independently verified workload completion.
    ///
    /// Dropping a token, losing its owner, or observing a timeout is not such evidence.
    pub fn complete(mut self) -> Result<(), Error> {
        {
            let mut state = self.proof.gate.lock()?;
            let Some(count) = state.workloads.checked_sub(1) else {
                return state.fault(Error::InvalidTransition);
            };
            state.workloads = count;
        }
        self.proof.disarm();
        Ok(())
    }
}

/// A pending drain with admission of new reference producers closed.
#[must_use = "cancel or acquire the exclusive guard; dropping a drain taints accounting"]
pub struct Drain {
    proof: Proof,
    invalidated: bool,
}

impl Drain {
    /// Confirms that the coordinator has completed its external invalidation pass.
    ///
    /// Call only after performing invalidation outside the gate lock and frontend callbacks.
    /// This attestation is not by itself a drain proof; outstanding work and credits still
    /// block exclusivity. Additional invalidation may be needed for late replies.
    pub fn invalidation_complete(&mut self) {
        self.invalidated = true;
    }

    /// Attempts to acquire exclusivity without waiting.
    ///
    /// Returns `Ok(None)` while any tracked reference, operation, reply, or workload remains.
    /// Once acquired, this drain token is inert and the guard owns the closed phase.
    pub fn try_exclusive(&mut self) -> Result<Option<ExclusiveGuard>, Error> {
        if !self.proof.active {
            return Err(Error::InvalidTransition);
        }
        if !self.invalidated {
            return Err(Error::InvalidationPending);
        }
        {
            let mut state = self.proof.gate.lock()?;
            if state.uncertain {
                return Err(Error::Uncertain);
            }
            if state.phase != Phase::Draining {
                return state.fault(Error::InvalidTransition);
            }
            if !state.drained() {
                return Ok(None);
            }
            state.phase = Phase::Exclusive;
        }
        let guard = ExclusiveGuard {
            proof: Proof::new(&self.proof.gate),
        };
        self.proof.disarm();
        Ok(Some(guard))
    }

    /// Cancels the drain before exclusivity, reopening reference admission.
    ///
    /// Existing uncertainty is never cleared and still prevents a later exclusive guard.
    pub fn cancel(mut self) -> Result<(), Error> {
        if !self.proof.active {
            return Err(Error::InvalidTransition);
        }
        {
            let mut state = self.proof.gate.lock()?;
            if state.phase != Phase::Draining {
                return state.fault(Error::InvalidTransition);
            }
            state.phase = Phase::Open;
        }
        self.proof.disarm();
        Ok(())
    }
}

/// A local exclusive drain proof which keeps all tracked admission closed.
///
/// This guard alone does not establish OS isolation, workload completion, adoption consent,
/// or authority to delete any target. The caller must maintain all external boundaries for
/// its entire lifetime and stop any exclusive action if accounting reports an error. A later
/// callback can reveal uncertainty after acquisition; this type cannot revoke an external
/// side effect. Dropping it without explicit completion or cancellation permanently taints
/// the epoch and leaves admission closed.
#[must_use = "complete or cancel the guard; dropping it taints accounting"]
pub struct ExclusiveGuard {
    proof: Proof,
}

impl ExclusiveGuard {
    fn reopen(mut self) -> Result<(), Error> {
        {
            let mut state = self.proof.gate.lock()?;
            if state.uncertain {
                return Err(Error::Uncertain);
            }
            if state.phase != Phase::Exclusive || !state.drained() {
                return state.fault(Error::InvalidTransition);
            }
            state.phase = Phase::Open;
        }
        self.proof.disarm();
        Ok(())
    }

    /// Completes the exclusive action and reopens this still-valid target epoch.
    ///
    /// The caller must ensure the action has ended and the epoch remains safe to reopen.
    pub fn complete(self) -> Result<(), Error> {
        self.reopen()
    }

    /// Cancels the exclusive action and reopens this still-valid target epoch.
    ///
    /// The caller must ensure no unfinished exclusive action can conflict with new work.
    pub fn cancel(self) -> Result<(), Error> {
        self.reopen()
    }
}
