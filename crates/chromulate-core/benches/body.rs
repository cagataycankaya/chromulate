//! `Body::collect` over a chunked stream.
//!
//! Collecting a streamed body is the one place in `core` where a naive
//! implementation turns quadratic: concatenating each arriving chunk onto a
//! `Bytes` copies everything received so far, so cost grows with the square of
//! the chunk count. The chunk counts here span three orders of magnitude at a
//! fixed chunk size, so the per-chunk cost is directly comparable across rows —
//! if it is flat, collection is linear.
//!
//! Run with `cargo bench -p chromulate-core`.

use std::hint::black_box;

use bytes::Bytes;
use chromulate_core::Body;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures_util::stream;

/// Fixed chunk size, so that the only thing varying across rows is how many
/// chunks arrive.
const CHUNK: usize = 1024;

const CHUNK_COUNTS: [usize; 4] = [1, 64, 1024, 16384];

fn benches(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime");

    let chunk = Bytes::from(vec![b'z'; CHUNK]);

    let mut group = c.benchmark_group("body_collect");
    for count in CHUNK_COUNTS {
        group.throughput(Throughput::Bytes((count * CHUNK) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            // Building the chunk vector is setup, not the thing under test:
            // it is linear in `count` and would otherwise be folded into every
            // row's timing.
            b.to_async(&runtime).iter_batched(
                || (0..count).map(|_| Ok(chunk.clone())).collect::<Vec<_>>(),
                |chunks| async move {
                    let body = Body::stream(stream::iter(chunks), None);
                    black_box(body.collect(u64::MAX).await.expect("collect must succeed"))
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    // The same collect with the length declared up front, which is what a
    // response carrying `Content-Length` looks like: `collect` can size its
    // buffer once instead of growing into it. Compare against the undeclared
    // rows above to see what the pre-sizing is worth.
    let mut group = c.benchmark_group("body_collect_sized");
    for count in CHUNK_COUNTS {
        group.throughput(Throughput::Bytes((count * CHUNK) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.to_async(&runtime).iter_batched(
                || (0..count).map(|_| Ok(chunk.clone())).collect::<Vec<_>>(),
                |chunks| async move {
                    let body = Body::stream(stream::iter(chunks), Some((count * CHUNK) as u64));
                    black_box(body.collect(u64::MAX).await.expect("collect must succeed"))
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group! {
    name = body;
    config = Criterion::default().sample_size(100);
    targets = benches
}
criterion_main!(body);
