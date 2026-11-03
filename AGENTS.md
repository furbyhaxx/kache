# Agent notes

## Repository and branches

- Develop in `furbyhaxx/kache`; `origin` points to that repository.
- The default and integration branch is `dev`.
- Do not open upstream PRs unless the user explicitly requests one.
- Do not run release/tag/publishing recipes: their upstream `main` assumptions do not define this fork's release policy.

## Verification before publishing changes

```sh
just check
```

That is fmt, clippy `-D warnings`, and the workspace tests. Run it before pushing code changes; focused tests alone are not the gate.

If an upstream contribution is explicitly authorized, mutation testing is an additional gate. Open that PR as a draft; the `Mutation testing (diff k/n)` shards test every changed Rust line in parallel on Linux runners and finish in well under an hour. A red shard prints the missed mutants in its log and uploads them as `missed.txt` in its `mutation-diff-report-<k>` artifact; add the test that kills each one, push, and mark the PR ready when every shard is green. A laptop running the same diff at one to three jobs takes hours and the load makes the fixture-based tests flake.

Do not run mutation testing locally by default. If requested, `just pr origin/dev` runs `just check` plus changed-line mutation testing against this fork's remote integration branch. The recipe's implicit `origin/main` default belongs to upstream; pass the base explicitly. Install the pinned tool before using it:

```sh
cargo install --locked cargo-mutants --version 27.1.0
```

Do not invoke `cargo mutants` with `RUSTC_WRAPPER=kache`. The Justfile clears it. Hand-running mutants without `just` wraps kache in itself and the unmutated baseline dies.

## How mutants die here

Prefer tests and deleting dead branches over skip annotations.

- `if !s.is_empty() { print!("{s}") }` — printing `""` is a no-op, so `delete !` is missed. Call a helper that already has empty vs nonempty tests (`replay_cached_diagnostics`).
- `a && b` / `a || b` — one test where the left is false, one where the right is false.
- Named size constants built with `*` (`5 * 1024 * 1024 * 1024`) — do not `assert_eq!` against that same constant. Use an independent literal (`5 << 30`).
- `u64::try_from` on a value that is already `u64` — Linux clippy `-D warnings`. macOS clippy does not type-check `#[cfg(target_os = "linux")]`.
- Unix-only test helpers under `-D warnings` on Windows are unused. Mark them `#[cfg(unix)]`.
- macOS-only helpers Linux never calls: `#[cfg(any(test, target_os = "macos"))]`.
- `Drop` / file locks — a second process must acquire after the first drops.
- New event-log fields — grep `event.schema` in the same commit and bump the tests.
- A test that passes is not a test that kills the mutant. Apply the mutation by hand, watch the test fail, then revert. A stale-record test passed under both `==` and `!=` because a single client refreshed its own record before the branch was ever reached; it took two clients to make the branch observable.
- Moving code without changing it still marks every moved line as changed, so the lane mutates lines your change never touched. Wrapping a 200-line block in a `loop` cost six survivors, four of them in code that predated the branch. Extract a function instead: the call site is one changed line and the body is none.
- Tests that read the live process environment race the rest of the suite, which mutates it (`set_env_for_test`). Take a snapshot and pass it in, or the test passes alone and fails in `just check`.

## PRs

Fork PRs, when requested, target `dev`. Do not stack PRs on each other's branches. After one merges, rebase the others onto `dev`. An explicitly authorized upstream contribution targets upstream's `main`.

Work in a git worktree. Do not mix unrelated dirty-tree WIP into the PR.

People keep running `cargo`. There is no `kache build`. Caching is `kache init` / `RUSTC_WRAPPER`.
