pub(crate) const MARKER: &str = "__kache_discovery_sandbox_v1";

#[cfg(target_os = "linux")]
pub(crate) const MAX_REQUEST_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
pub(crate) const MAX_RULE_FDS: usize = 64;

#[cfg(target_os = "linux")]
// Stdin is a Unix stream: send at most 64 KiB of JSON and 64 caller-pinned O_PATH
// descriptors using SCM_RIGHTS, then shut down the write side. Each rights message carries
// JSON bytes; after a short send, send remaining bytes without resending descriptors. Slots
// follow descriptor arrival order starting at 3 (0..=2 are reserved), not raw helper fds.
// The caller retains ownership.
// Renames and bind aliases of approved objects are allowed. The program needs execute access.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) read_fds: Vec<i32>,
    pub(crate) exec_fds: Vec<i32>,
    pub(crate) program: String,
    pub(crate) argv: Vec<String>,
}
