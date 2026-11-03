# kache-managed

Local admission and reference accounting for one managed target and connection epoch.

`Gate` tracks lookup credits by target inode, unique open handles, in-flight work
and declared workloads. A coordinator closes reference admission before
invalidation and can obtain a local exclusive guard only after every tracked
reference and operation completes.

## Usage

Create one `Gate` per externally isolated target/connection epoch and share its
clones with the trusted frontend and coordinator. The frontend must validate that
each inode belongs to the target; the global FUSE root is never the target. A
reference-producing request must call `begin_producer` before backend I/O, reserve all positive lookup
credits and handles, then call `begin_publication` before exposing any reply.
Confirm completed publication with `Publication::complete`; only a producer
that has published nothing may be cancelled. Process validated FORGET and
release callbacks against the same gate. Handle IDs cannot be reused in an
epoch, even after cancellation.

Declare workloads before they can access the target and complete their tokens
only when their actual lifecycles have been independently verified. Track other
in-flight operations with `begin_operation`. Lost tokens, failed or unconfirmed
publication, invalid accounting and lock poisoning permanently prevent an
exclusive drain; they do not justify revoking existing I/O or deleting a target.
Call `mark_uncertain` for externally detected loss of callback or workload
lifecycle evidence.

The coordinator calls `begin_drain`, performs invalidation outside the ledger
lock and frontend callbacks, and then calls `invalidation_complete`. It can
retry `try_exclusive` without waiting inside the ledger. Requests already
admitted may finish after invalidation; their credits still block the guard and
may require further invalidation. Explicitly complete or cancel the guard only
after its action ends and the epoch is safe to reopen. Abandoning a drain or
guard permanently taints the epoch. If a later callback reveals an accounting
error while a guard is held, the coordinator must stop any exclusive action and
retain the target; the ledger cannot revoke an external side effect.

This API consumes trusted, complete callbacks and cannot validate their origin,
OS isolation, external access, or real workload lifetimes. FUSE lookup counts do
not identify individual credits, so the frontend must rule out duplicate or
misattributed FORGETs even when the outstanding count would permit them. A local
guard alone is never authority to delete a target or a managed-store guarantee.

The crate is internal and unpublished (`0.0.1`); it requires Rust 1.95 or newer.
Run the focused checks from the workspace root:

```sh
cargo test --locked -p kache-managed
cargo clippy --locked -p kache-managed --all-targets -- -D warnings
```
