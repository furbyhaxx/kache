//! Local admission and reference accounting for one managed target and connection epoch.
//!
//! A trusted frontend must account for every reference-producing request before I/O and
//! publication, validate and deliver all protocol callbacks, and prevent bypass access. A
//! separate trusted boundary must validate actual workload lifetimes. This crate provides no
//! filesystem, isolation, process-lifetime evidence, or authority to delete a target.

#![forbid(unsafe_code)]
#![deny(warnings, missing_docs)]

mod reference_gate;

pub use reference_gate::{
    Drain, Error, ExclusiveGuard, Gate, Operation, Producer, Publication, Workload,
};
