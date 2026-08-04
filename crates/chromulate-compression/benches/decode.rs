//! Decompression throughput for the codings a browser advertises.
//!
//! The number that matters is MB/s of **decompressed output**, because that is
//! what the caller receives and what bounds how fast a compressed response can
//! be consumed. Two payloads are used for each coding: text, which is what real
//! responses mostly are and which compresses well, and incompressible random
//! bytes, which is the worst case and shows the fixed cost of the framing.
//!
//! Chunk size matters as much as coding here — the decoder is driven by a
//! stream, so a body arriving in many small frames pays more per byte than the
//! same body in few large ones. `chunk16k` and `chunk64k` bracket the sizes a
//! real socket read produces.
//!
//! Run with `cargo bench -p chromulate-compression`.

use std::hint::black_box;

use bytes::Bytes;
use chromulate_compression::{ContentCoding, ExpansionGuard};
use chromulate_core::Body;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures_util::stream;
use tokio::io::AsyncWriteExt as _;

/// Uncompressed payload size for every case.
const PAYLOAD: usize = 1024 * 1024;

const CHUNK_SIZES: [usize; 2] = [16 * 1024, 64 * 1024];

/// Compressible input with a realistic compression ratio.
///
/// A single repeated record would be the obvious thing to write and the wrong
/// thing to measure: it compresses several thousand to one, so the decoder
/// spends its time copying from the match window and the resulting throughput
/// describes no response anyone will ever receive. Varying the field values
/// against a small vocabulary lands the ratio in the range real JSON and HTML
/// actually hit, which is what makes the number transferable.
fn textish() -> Vec<u8> {
    const WORDS: [&str; 8] = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    ];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let mut out = Vec::with_capacity(PAYLOAD + 128);
    let mut id = 0u64;
    while out.len() < PAYLOAD {
        let r = next();
        id += 1;
        out.extend_from_slice(
            format!(
                "{{\"id\":{id},\"sku\":\"{:x}\",\"name\":\"{} {}\",\"price\":{}.{:02},\
                 \"tags\":[\"{}\"]}}\n",
                r & 0xFFFF_FFFF,
                WORDS[(r >> 3) as usize % WORDS.len()],
                WORDS[(r >> 11) as usize % WORDS.len()],
                (r >> 19) % 1000,
                (r >> 29) % 100,
                WORDS[(r >> 37) as usize % WORDS.len()],
            )
            .as_bytes(),
        );
    }
    out.truncate(PAYLOAD);
    out
}

/// Incompressible input, from a cheap deterministic generator so the benchmark
/// does not depend on an RNG crate or on a seed drawn at run time.
fn random() -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..PAYLOAD)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 33) as u8
        })
        .collect()
}

fn compress(runtime: &tokio::runtime::Runtime, coding: ContentCoding, plain: &[u8]) -> Bytes {
    use async_compression::tokio::write::{BrotliEncoder, GzipEncoder, ZlibEncoder, ZstdEncoder};

    runtime.block_on(async {
        let mut out = Vec::new();
        match coding {
            ContentCoding::Gzip => {
                let mut encoder = GzipEncoder::new(&mut out);
                encoder.write_all(plain).await.expect("gzip encode");
                encoder.shutdown().await.expect("gzip finish");
            }
            ContentCoding::Brotli => {
                let mut encoder = BrotliEncoder::new(&mut out);
                encoder.write_all(plain).await.expect("brotli encode");
                encoder.shutdown().await.expect("brotli finish");
            }
            ContentCoding::Zstd => {
                let mut encoder = ZstdEncoder::new(&mut out);
                encoder.write_all(plain).await.expect("zstd encode");
                encoder.shutdown().await.expect("zstd finish");
            }
            ContentCoding::Deflate => {
                let mut encoder = ZlibEncoder::new(&mut out);
                encoder.write_all(plain).await.expect("deflate encode");
                encoder.shutdown().await.expect("deflate finish");
            }
            _ => out.extend_from_slice(plain),
        }
        Bytes::from(out)
    })
}

fn split(payload: &Bytes, chunk: usize) -> Vec<Result<Bytes, chromulate_core::Error>> {
    payload
        .chunks(chunk)
        .map(|slice| Ok(payload.slice_ref(slice)))
        .collect()
}

fn benches(c: &mut Criterion) {
    // The shipped default guard caps expansion at a ratio a benchmark payload
    // deliberately exceeds: 1 MiB of repetitive text compresses far past it. The
    // guard is doing its job; measuring decoder throughput just means stepping
    // around it rather than around the decoder.
    let guard = ExpansionGuard::new(u64::MAX, u64::MAX);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime");

    let inputs = [("text", textish()), ("random", random())];
    let codings = [
        ("gzip", ContentCoding::Gzip),
        ("brotli", ContentCoding::Brotli),
        ("zstd", ContentCoding::Zstd),
        ("deflate", ContentCoding::Deflate),
    ];

    for (shape, plain) in &inputs {
        for (name, coding) in codings {
            let compressed = compress(&runtime, coding, plain);
            let mut group = c.benchmark_group(format!("decode/{name}/{shape}"));
            // Throughput is expressed in decompressed bytes: the ratio between
            // codings is otherwise an artefact of how well each one compressed
            // this particular input.
            group.throughput(Throughput::Bytes(PAYLOAD as u64));
            for chunk in CHUNK_SIZES {
                group.bench_with_input(
                    BenchmarkId::new("chunk", chunk / 1024),
                    &chunk,
                    |b, &chunk| {
                        b.to_async(&runtime).iter_batched(
                            || split(&compressed, chunk),
                            |chunks| async move {
                                let body =
                                    guard.decode(Body::stream(stream::iter(chunks), None), coding);
                                let out = body
                                    .collect(u64::MAX)
                                    .await
                                    .expect("the payload must decode");
                                black_box(out.len())
                            },
                            criterion::BatchSize::SmallInput,
                        );
                    },
                );
            }
            group.finish();
        }
    }

    // Ratio context for the report: how much each coding actually shrank the
    // two payloads on this machine.
    for (shape, plain) in &inputs {
        for (name, coding) in codings {
            let compressed = compress(&runtime, coding, plain);
            eprintln!(
                "compressed size: {name}/{shape} = {} bytes ({:.1}% of {PAYLOAD})",
                compressed.len(),
                compressed.len() as f64 / PAYLOAD as f64 * 100.0
            );
        }
    }
}

criterion_group! {
    name = decode_benches;
    config = Criterion::default().sample_size(50);
    targets = benches
}
criterion_main!(decode_benches);
