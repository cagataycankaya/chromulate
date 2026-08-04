//! A server-controlled `Content-Encoding` header driving the decoder chain.
//!
//! This is the other half of the compression surface, and the sharper one. The
//! header alone decides how many decoders get stacked, each costing a stack frame
//! per poll and tens of kilobytes of buffers before a single body byte is read.
//! `MAX_CONTENT_CODINGS` exists because without it a few kilobytes of header
//! build a chain deep enough to overflow the polling thread's stack — an abort no
//! caller can catch, which is why it is worth fuzzing rather than reasoning about.
//!
//! The input splits at the first newline: header value, then body.

#![no_main]
#![forbid(unsafe_code)]

use bytes::Bytes;
use chromulate_compression::ExpansionGuard;
use chromulate_core::Body;
use http::HeaderValue;
use http::header::CONTENT_ENCODING;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

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
    let (encoding, body) = match data.iter().position(|&b| b == b'\n') {
        Some(split) => (&data[..split], &data[split + 1..]),
        None => (data, &[][..]),
    };

    let Ok(encoding) = HeaderValue::from_bytes(encoding) else {
        return;
    };

    let Ok(response) = http::Response::builder()
        .header(CONTENT_ENCODING, encoding)
        .body(Body::fixed(Bytes::copy_from_slice(body)))
    else {
        return;
    };

    let guard = ExpansionGuard::new(64 * 1024, 20);

    // Rejection here is a result, not a failure: a chain over the limit is
    // supposed to come back as `Error::Decode`, and the run only proves anything
    // if that happens without a panic or an abort.
    let Ok(decoded) = guard.decode_response(response) else {
        return;
    };

    runtime().block_on(async {
        let _ = decoded.into_body().collect(4 * 1024 * 1024).await;
    });
});
