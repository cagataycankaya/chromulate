//! Per-connection fingerprint work.
//!
//! `wire_extension_order` is the one that matters most here: Chrome permutes
//! its ClientHello extension order on **every** connection, so Chromulate does
//! too, which puts this function on the connection-establishment path rather
//! than in one-off setup. The JA3, JA4 and Akamai strings are computed far less
//! often — they exist mostly so a caller can assert what identity it is
//! presenting — but they share the same input, so measuring them together shows
//! where the cost of that shape actually sits.
//!
//! Run with `cargo bench -p chromulate-fingerprint`.

use std::hint::black_box;

use chromulate_fingerprint::{
    Capture, ClientHelloSpec, Http2Spec, akamai_http2, akamai_http2_hash, ja3, ja3_hash, ja4,
    ja4_raw,
};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use rand::rngs::StdRng;

const CAPTURE: &str = include_str!("../tests/data/chrome-151-macos.json");

fn fixtures() -> (ClientHelloSpec, Http2Spec) {
    let capture = Capture::parse(CAPTURE).expect("the shipped capture must parse");
    (
        capture
            .client_hello()
            .expect("the shipped capture must yield a ClientHello"),
        capture
            .http2()
            .expect("the shipped capture must yield an HTTP/2 spec"),
    )
}

fn benches(c: &mut Criterion) {
    let (hello, http2) = fixtures();

    let mut group = c.benchmark_group("fingerprint");

    // On the connection path.
    group.bench_function("wire_extension_order", |b| {
        let mut rng = StdRng::seed_from_u64(0x5EED);
        b.iter(|| black_box(black_box(&hello).wire_extension_order(&mut rng)));
    });
    group.bench_function("wire_cipher_suites", |b| {
        let mut rng = StdRng::seed_from_u64(0x5EED);
        b.iter(|| black_box(black_box(&hello).wire_cipher_suites(&mut rng)));
    });

    // Reporting and assertion paths.
    group.bench_function("ja3", |b| b.iter(|| black_box(ja3(black_box(&hello)))));
    group.bench_function("ja3_hash", |b| {
        let text = ja3(&hello);
        b.iter(|| black_box(ja3_hash(black_box(&text))));
    });
    group.bench_function("ja4", |b| b.iter(|| black_box(ja4(black_box(&hello)))));
    group.bench_function("ja4_raw", |b| {
        b.iter(|| black_box(ja4_raw(black_box(&hello))));
    });
    group.bench_function("akamai_http2", |b| {
        b.iter(|| black_box(akamai_http2(black_box(&http2))));
    });
    group.bench_function("akamai_http2_hash", |b| {
        let text = akamai_http2(&http2);
        b.iter(|| black_box(akamai_http2_hash(black_box(&text))));
    });

    group.finish();
}

criterion_group! {
    name = fingerprint;
    config = Criterion::default().sample_size(200);
    targets = benches
}
criterion_main!(fingerprint);
