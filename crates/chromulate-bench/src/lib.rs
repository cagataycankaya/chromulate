//! Shared pieces of the Chromulate benchmark harness.
//!
//! The harness measures client overhead, so the server it talks to has to be
//! cheap enough not to be the thing under measurement: a loopback hyper server
//! answering from a preallocated `Bytes` with no per-request work beyond
//! writing the response.
//!
//! Nothing in this crate is published. It exists so that the numbers in
//! `benches/README.md` can be reproduced by running a command rather than
//! trusted.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod server;
pub mod stats;
#[cfg(feature = "live")]
pub mod tls_server;

use std::process;

/// Resident set size of this process in kibibytes, as the operating system
/// reports it.
///
/// Read from `ps` rather than from a memory API because every portable memory
/// API in Rust either needs `unsafe` or reports the allocator's view rather
/// than the kernel's, and the claim under test — "an idle client is small",
/// "streaming does not buffer" — is a claim about the kernel's view.
///
/// Returns `None` when `ps` is unavailable or prints something unparseable.
#[must_use]
pub fn resident_kib() -> Option<u64> {
    let output = process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(process::id().to_string())
        .output()
        .ok()?;
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

/// Resident set size in mebibytes, for reporting.
#[must_use]
pub fn resident_mib() -> Option<f64> {
    resident_kib().map(|kib| kib as f64 / 1024.0)
}
