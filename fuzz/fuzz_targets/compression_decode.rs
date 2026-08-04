//! Random bytes into a single streaming decoder, with the expansion guard armed.
//!
//! The first input byte picks the coding and the rest is the compressed body, so
//! one corpus covers all four decoders and the identity path. What is under test
//! is not the third-party decoder but the wrapper around it: malformed input has
//! to arrive as `Error::Decode` on the body's next poll, and a body that expands
//! past either bound has to be abandoned mid-stream rather than finished first.

#![no_main]
#![forbid(unsafe_code)]

use bytes::Bytes;
use chromulate_compression::{ContentCoding, ExpansionGuard};
use chromulate_core::Body;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

/// One runtime for the whole process. Building a runtime per input would cost
/// more than the decode it exists to drive, and libFuzzer measures throughput in
/// executions per second.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a current-thread runtime with no I/O driver always builds")
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, compressed)) = data.split_first() else {
        return;
    };

    let coding = match selector % 5 {
        0 => ContentCoding::Gzip,
        1 => ContentCoding::Deflate,
        2 => ContentCoding::Brotli,
        3 => ContentCoding::Zstd,
        _ => ContentCoding::Identity,
    };

    // Far below the shipped defaults of 100 MiB and 100x, and deliberately: a
    // fuzzer will not stumble onto a 100 MiB expansion inside a run's time
    // budget, so the default guard would be dead weight in this target. At 64 KiB
    // and 20x a few hundred input bytes can trip both bounds, which is the point.
    let guard = ExpansionGuard::new(64 * 1024, 20);

    runtime().block_on(async {
        let decoded = guard.decode(Body::fixed(Bytes::copy_from_slice(compressed)), coding);
        // Well above the guard's 64 KiB, so the guard is what rejects an
        // over-expanding body and this limit only backstops a decoder that
        // ignored it.
        let _ = decoded.collect(4 * 1024 * 1024).await;
    });
});
