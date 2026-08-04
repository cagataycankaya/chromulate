//! The capture JSON loader, and the fingerprint arithmetic downstream of it.
//!
//! Capture files are the one input this project treats as authoritative — every
//! profile constant is derived from one — so a malformed capture must be rejected
//! by `Capture::parse` or by the `client_hello()`/`http2()` conversions, never by
//! panicking partway through. Parsing is only half of it: the loader reconciles a
//! document's extension set against the JA3 string it also carries, and the
//! computations below index into whatever that reconciliation produced.

#![no_main]
#![forbid(unsafe_code)]

use chromulate_fingerprint::{
    Capture, akamai_http2, akamai_http2_hash, ja3, ja3_hash, ja4, ja4_raw,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(capture) = Capture::parse(json) else {
        return;
    };

    let _ = capture.extension_order_is_randomised();
    let _ = capture.resumption_extensions();
    let _ = capture.sample_navigate.ja3_extensions();
    let _ = capture.sample_navigate.ja3_extension_order();

    if let Ok(hello) = capture.client_hello() {
        // The hashes take the fingerprint string, not the spec, so this is the
        // whole two-step path a caller walks rather than the hash alone.
        let _ = ja3_hash(&ja3(&hello));
        let _ = ja4(&hello);
        let _ = ja4_raw(&hello);
    }

    if let Ok(http2) = capture.http2() {
        let _ = akamai_http2_hash(&akamai_http2(&http2));
    }
});
