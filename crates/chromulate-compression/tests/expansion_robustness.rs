//! The expansion guard against adversarial and malformed input.
//!
//! The guard's job is to stop a decompression bomb, and the unit tests prove it
//! on one hand-built payload per rule. That is enough to show the rule exists
//! and not enough to show it holds: a bomb is chosen by an attacker, not by the
//! person writing the fixture, and the interesting failures are the shapes
//! nobody thought to write down — truncated streams, trailing garbage, a
//! coding that does not match the bytes, ratios tuned to sit exactly on a
//! boundary.
//!
//! So these tests sweep. They are deterministic — a fixed seed, no external
//! input — because a robustness test that fails once a month on a seed nobody
//! recorded is worse than one that fails every time or never.
//!
//! This is **not** coverage-guided fuzzing and does not replace it: it explores
//! a space someone chose rather than the space the code's branches describe.
//! What it does is run in CI on stable, on every push, which `cargo fuzz`
//! cannot.

use std::io;

use async_compression::tokio::write::{BrotliEncoder, GzipEncoder, ZlibEncoder, ZstdEncoder};
use chromulate_compression::{ContentCoding, ExpansionGuard};
use chromulate_core::{Body, Error};
use tokio::io::AsyncWriteExt as _;

/// A tiny deterministic generator, so the sweep is reproducible without a
/// dependency. Values are only used to pick shapes, never as cryptography.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

async fn compress(coding: ContentCoding, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    match coding {
        ContentCoding::Gzip => {
            let mut encoder = GzipEncoder::new(&mut out);
            encoder.write_all(payload).await?;
            encoder.shutdown().await?;
        }
        ContentCoding::Deflate => {
            let mut encoder = ZlibEncoder::new(&mut out);
            encoder.write_all(payload).await?;
            encoder.shutdown().await?;
        }
        ContentCoding::Brotli => {
            let mut encoder = BrotliEncoder::new(&mut out);
            encoder.write_all(payload).await?;
            encoder.shutdown().await?;
        }
        ContentCoding::Zstd => {
            let mut encoder = ZstdEncoder::new(&mut out);
            encoder.write_all(payload).await?;
            encoder.shutdown().await?;
        }
        _ => return Err(io::Error::other("unmodelled coding")),
    }
    Ok(out)
}

const CODINGS: [ContentCoding; 4] = [
    ContentCoding::Gzip,
    ContentCoding::Deflate,
    ContentCoding::Brotli,
    ContentCoding::Zstd,
];

/// Whatever the input, the guard either produces a body within its limit or
/// refuses — it never yields more than it promised and never panics.
///
/// This is the property that matters: a caller sets a limit precisely because
/// it cannot afford to be handed more, so a decoder that overshoots is a
/// vulnerability whatever the input did to provoke it.
#[tokio::test]
async fn no_input_makes_the_guard_exceed_its_size_limit() {
    let mut rng = Rng(0x5eed_1234_9876_abcd);
    let limit = 64 * 1024u64;
    let guard = ExpansionGuard::new(limit, u64::MAX);

    // Round count and payload size are a CI budget, not a coverage target: this
    // sweeps shapes rather than branches, so more rounds buy proportionally
    // less than they cost. Coverage-guided fuzzing is the tool for the tail.
    for round in 0..120 {
        let coding = CODINGS[round % CODINGS.len()];
        // A spread of shapes: incompressible noise, long runs that compress
        // enormously, and mixtures that sit between the two.
        let length = 1 + rng.below(120_000);
        let payload: Vec<u8> = match round % 3 {
            0 => (0..length).map(|_| rng.next() as u8).collect(),
            1 => vec![b'A'; length],
            _ => (0..length)
                .map(|index| if index % 64 == 0 { rng.next() as u8 } else { 0 })
                .collect(),
        };

        let compressed = compress(coding, &payload)
            .await
            .expect("the fixture must compress");
        let decoded = guard.decode(Body::fixed(compressed), coding);

        match decoded.collect(u64::MAX).await {
            Ok(bytes) => assert!(
                bytes.len() as u64 <= limit,
                "round {round}: guard returned {} bytes with a {limit}-byte limit",
                bytes.len()
            ),
            Err(Error::BodyTooLarge { .. }) => {
                assert!(
                    payload.len() as u64 > limit,
                    "round {round}: guard rejected a {}-byte payload under a {limit}-byte limit",
                    payload.len()
                );
            }
            Err(other) => panic!("round {round}: unexpected error {other:?}"),
        }
    }
}

/// Malformed input is rejected or decoded, never a panic.
///
/// Truncation, trailing garbage, bit flips and a coding that does not match the
/// bytes are all things a hostile origin can send for free, and each one lands
/// in a different decoder branch.
#[tokio::test]
async fn malformed_streams_do_not_panic() {
    let mut rng = Rng(0xdead_beef_0bad_f00d);

    for round in 0..300 {
        let coding = CODINGS[round % CODINGS.len()];
        let payload = vec![b'x'; 1 + rng.below(20_000)];
        let mut compressed = compress(coding, &payload)
            .await
            .expect("the fixture must compress");

        match round % 5 {
            0 => compressed.truncate(compressed.len() / 2),
            1 => compressed.truncate(rng.below(compressed.len().max(1))),
            2 => compressed.extend(std::iter::repeat_n(0xff, 1 + rng.below(64))),
            3 if !compressed.is_empty() => {
                let at = rng.below(compressed.len());
                compressed[at] ^= 1 << (rng.below(8));
            }
            // Decode with the wrong coding, which is what a lying
            // `Content-Encoding` header produces.
            _ => {}
        }
        let decode_as = if round % 5 == 4 {
            CODINGS[(round + 1) % CODINGS.len()]
        } else {
            coding
        };

        let guard = ExpansionGuard::new(1024 * 1024, 1000);
        // The assertion is that this returns rather than panics or hangs; both
        // outcomes are acceptable answers to malformed input.
        let _ = guard
            .decode(Body::fixed(compressed), decode_as)
            .collect(u64::MAX)
            .await;
    }
}

/// The ratio limit holds across codings and payload shapes, not just for the
/// one gzip fixture the unit tests use.
#[tokio::test]
async fn the_ratio_limit_holds_for_every_coding() {
    for coding in CODINGS {
        // A long run of one byte compresses far past any sane ratio in every
        // coding, so each should be refused by the ratio rule while staying
        // well under the absolute size limit.
        let payload = vec![b'z'; 200_000];
        let compressed = compress(coding, &payload)
            .await
            .expect("the fixture must compress");
        assert!(
            payload.len() as u64 > compressed.len() as u64 * 20,
            "{coding:?}: fixture must exceed the ratio under test, got {} -> {}",
            compressed.len(),
            payload.len()
        );

        let guard = ExpansionGuard::new(u64::MAX, 20);
        let error = guard
            .decode(Body::fixed(compressed), coding)
            .collect(u64::MAX)
            .await
            .expect_err("a body past the ratio must be refused");
        assert!(
            matches!(error, Error::BodyTooLarge { .. }),
            "{coding:?}: expected BodyTooLarge, got {error:?}"
        );
    }
}
