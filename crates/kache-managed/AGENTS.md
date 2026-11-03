# kache-managed

Internal managed-target admission and reference accounting, separate from adoption consent and Cargo-idle evidence.

- The ledger consumes validated protocol events from a trusted frontend; it does not authenticate kernel events or establish OS isolation.
- A local drain guard alone never authorizes deletion of unmanaged targets or proves logical workload lifetimes have ended.
- Register reference-producing operations and credits before exposing replies. Serialize drain decisions with accounting transitions.
- Lost completion, unknown references, underflow, overflow, or poisoned state must prevent retirement; never infer drain from a timeout.
- Keep filesystem I/O, response publication, invalidation and waits outside the accounting mutex.
- Use safe Rust, typed errors, documented public APIs, and tests of real state transitions and races.
- Run `cargo test --locked -p kache-managed` and `cargo clippy --locked -p kache-managed --all-targets -- -D warnings` for a scoped change. Workspace verification belongs to integration.
