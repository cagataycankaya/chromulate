use std::time::Duration;

use chromulate_core::reexport::Bytes;
use chromulate_core::{Body, Error};
use futures_util::StreamExt as _;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http_body_util::BodyExt as _;
use tokio::io::AsyncWriteExt as _;

use super::*;

async fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = async_compression::tokio::write::GzipEncoder::new(Vec::new());
    encoder.write_all(data).await.expect("write should succeed");
    encoder.shutdown().await.expect("shutdown should succeed");
    encoder.into_inner()
}

async fn deflate_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = async_compression::tokio::write::ZlibEncoder::new(Vec::new());
    encoder.write_all(data).await.expect("write should succeed");
    encoder.shutdown().await.expect("shutdown should succeed");
    encoder.into_inner()
}

async fn brotli_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = async_compression::tokio::write::BrotliEncoder::new(Vec::new());
    encoder.write_all(data).await.expect("write should succeed");
    encoder.shutdown().await.expect("shutdown should succeed");
    encoder.into_inner()
}

async fn zstd_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
    encoder.write_all(data).await.expect("write should succeed");
    encoder.shutdown().await.expect("shutdown should succeed");
    encoder.into_inner()
}

async fn collect_decoded(body: Body) -> Bytes {
    body.collect(64 * 1024 * 1024)
        .await
        .expect("decoding should succeed")
}

/// A `Content-Encoding` value stacking `count` copies of `gzip`.
///
/// This is the shape a hostile server uses to build an arbitrarily deep decoder chain
/// out of a header: `gzip,` costs five bytes on the wire per layer.
fn stacked_gzip_header(count: usize) -> String {
    vec!["gzip"; count].join(", ")
}

/// Asserts that `err` is the rejection [`MAX_CONTENT_CODINGS`] produces.
fn assert_rejected_for_too_many_codings(err: Error) {
    match err {
        Error::Decode { encoding, source } => {
            assert_eq!(encoding, "content-encoding");
            let cause = source
                .expect("the rejection should carry a cause")
                .downcast::<TooManyCodings>()
                .expect("the cause should be TooManyCodings");
            assert_eq!(cause.limit(), MAX_CONTENT_CODINGS);
        }
        other => panic!("expected Error::Decode carrying TooManyCodings, got {other:?}"),
    }
}

#[tokio::test]
async fn gzip_round_trips_a_known_payload() {
    let payload = b"the quick brown fox jumps over the lazy dog, ".repeat(64);
    let compressed = gzip_compress(&payload).await;

    let decoded = decode(Body::fixed(compressed), ContentCoding::Gzip);

    assert_eq!(collect_decoded(decoded).await, Bytes::from(payload));
}

#[tokio::test]
async fn deflate_round_trips_a_known_payload() {
    let payload = b"the quick brown fox jumps over the lazy dog, ".repeat(64);
    let compressed = deflate_compress(&payload).await;

    let decoded = decode(Body::fixed(compressed), ContentCoding::Deflate);

    assert_eq!(collect_decoded(decoded).await, Bytes::from(payload));
}

#[tokio::test]
async fn brotli_round_trips_a_known_payload() {
    let payload = b"the quick brown fox jumps over the lazy dog, ".repeat(64);
    let compressed = brotli_compress(&payload).await;

    let decoded = decode(Body::fixed(compressed), ContentCoding::Brotli);

    assert_eq!(collect_decoded(decoded).await, Bytes::from(payload));
}

#[tokio::test]
async fn zstd_round_trips_a_known_payload() {
    let payload = b"the quick brown fox jumps over the lazy dog, ".repeat(64);
    let compressed = zstd_compress(&payload).await;

    let decoded = decode(Body::fixed(compressed), ContentCoding::Zstd);

    assert_eq!(collect_decoded(decoded).await, Bytes::from(payload));
}

#[tokio::test]
async fn identity_passes_the_body_through_unchanged() {
    let body = Body::fixed("chromulate");
    let decoded = decode(body, ContentCoding::Identity);
    assert_eq!(
        collect_decoded(decoded).await,
        Bytes::from_static(b"chromulate")
    );
}

#[tokio::test]
async fn the_decoder_yields_output_before_the_source_stream_ends() {
    let payload = b"the quick brown fox jumps over the lazy dog, ".repeat(64);
    let compressed = gzip_compress(&payload).await;
    // Withhold the final byte and never end the source stream. A decoder that
    // buffered the whole body before producing anything would never yield here,
    // since the source is constructed to never signal completion.
    let (prefix, _withheld) = compressed.split_at(compressed.len() - 1);
    let prefix = Bytes::copy_from_slice(prefix);

    let never_ending = futures_util::stream::once(async move { Ok(prefix) }).chain(
        futures_util::stream::pending::<chromulate_core::Result<Bytes>>(),
    );
    let body = Body::stream(never_ending, None);

    let decoded = decode(body, ContentCoding::Gzip);
    let mut decoded_stream = decoded.into_data_stream();

    let first = tokio::time::timeout(Duration::from_millis(500), decoded_stream.next())
        .await
        .expect("the decoder should yield before the source stream ends")
        .expect("the stream should not end without producing a chunk")
        .expect("the chunk should decode without error");

    assert!(!first.is_empty());
}

#[tokio::test]
async fn multiple_codings_decode_in_reverse_of_the_header_order() {
    let payload = b"the quick brown fox jumps over the lazy dog, ".repeat(64);
    let gzipped = gzip_compress(&payload).await;
    let gzipped_then_brotlied = brotli_compress(&gzipped).await;

    let response = http::Response::builder()
        .header(CONTENT_ENCODING, "gzip, br")
        .body(Body::fixed(gzipped_then_brotlied))
        .expect("response should build");

    let decoded = decode_response(response).expect("decoding should succeed");

    assert_eq!(
        collect_decoded(decoded.into_body()).await,
        Bytes::from(payload)
    );
}

#[tokio::test]
async fn decode_response_removes_content_encoding_and_content_length() {
    let payload = b"chromulate".repeat(16);
    let compressed = gzip_compress(&payload).await;
    let compressed_len = compressed.len();

    let response = http::Response::builder()
        .header(CONTENT_ENCODING, "gzip")
        .header(CONTENT_LENGTH, compressed_len)
        .body(Body::fixed(compressed))
        .expect("response should build");

    let decoded = decode_response(response).expect("decoding should succeed");

    assert!(!decoded.headers().contains_key(CONTENT_ENCODING));
    assert!(!decoded.headers().contains_key(CONTENT_LENGTH));
    assert_eq!(
        collect_decoded(decoded.into_body()).await,
        Bytes::from(payload)
    );
}

#[tokio::test]
async fn a_response_without_content_encoding_is_returned_unchanged() {
    let response = http::Response::builder()
        .body(Body::fixed("plain"))
        .expect("response should build");

    let decoded = decode_response(response).expect("decoding should succeed");

    assert_eq!(
        collect_decoded(decoded.into_body()).await,
        Bytes::from_static(b"plain")
    );
}

#[tokio::test]
async fn an_unrecognized_coding_is_rejected_rather_than_passed_through() {
    let response = http::Response::builder()
        .header(CONTENT_ENCODING, "compress")
        .body(Body::fixed("irrelevant"))
        .expect("response should build");

    let err = decode_response(response).expect_err("an unknown coding should not decode");
    assert!(matches!(err, Error::Decode { encoding, .. } if encoding == "compress"));
}

#[tokio::test]
async fn a_content_encoding_header_over_the_coding_cap_is_rejected() {
    let response = http::Response::builder()
        .header(
            CONTENT_ENCODING,
            stacked_gzip_header(MAX_CONTENT_CODINGS + 1),
        )
        .body(Body::fixed("irrelevant"))
        .expect("response should build");

    let err =
        decode_response(response).expect_err("a header past the coding cap should be rejected");

    assert_rejected_for_too_many_codings(err);
}

#[tokio::test]
async fn the_coding_cap_counts_every_repeated_content_encoding_header_together() {
    // Splitting the tokens across repeated header lines costs the attacker *fewer* wire
    // bytes than one long value, and HPACK makes a repeated identical value nearly free
    // over HTTP/2, so the cap has to bind on the flattened total rather than per line.
    let mut builder = http::Response::builder();
    for _ in 0..=MAX_CONTENT_CODINGS {
        builder = builder.header(CONTENT_ENCODING, "gzip");
    }
    let response = builder
        .body(Body::fixed("irrelevant"))
        .expect("response should build");

    let err =
        decode_response(response).expect_err("repeated header lines should share the coding cap");

    assert_rejected_for_too_many_codings(err);
}

#[tokio::test]
async fn the_content_encoding_header_that_overflowed_the_stack_is_rejected() {
    // 400 stacked codings is the measured count at which polling the resulting chain of
    // nested decoders overflowed a Tokio worker thread's 2 MiB stack and aborted the
    // process with SIGABRT, which no `catch_unwind` or supervisor can recover. The
    // header is about 2.4 KB, trivial for a hostile server to send.
    const CODINGS_THAT_OVERFLOWED: usize = 400;

    let response = http::Response::builder()
        .header(
            CONTENT_ENCODING,
            stacked_gzip_header(CODINGS_THAT_OVERFLOWED),
        )
        .body(Body::fixed("irrelevant"))
        .expect("response should build");

    let err = decode_response(response)
        .expect_err("a header deep enough to overflow the stack should be rejected");

    assert_rejected_for_too_many_codings(err);
}

#[tokio::test]
async fn a_response_stacking_exactly_the_coding_cap_still_decodes() {
    let payload = b"chromulate".repeat(8);
    let mut encoded = payload.clone();
    for _ in 0..MAX_CONTENT_CODINGS {
        encoded = gzip_compress(&encoded).await;
    }

    let response = http::Response::builder()
        .header(CONTENT_ENCODING, stacked_gzip_header(MAX_CONTENT_CODINGS))
        .body(Body::fixed(encoded))
        .expect("response should build");

    let decoded = decode_response(response).expect("a response at the cap should decode");

    assert_eq!(
        collect_decoded(decoded.into_body()).await,
        Bytes::from(payload)
    );
}

#[tokio::test]
async fn nested_codings_do_not_multiply_the_permitted_expansion_ratio() {
    // Three gzip layers over 8 MiB of one repeated byte. Each layer stays comfortably
    // under the ratio when measured against its own input, so measuring per layer let
    // the chain expand by `max_ratio` cubed end to end; only measuring every layer
    // against the bytes that actually arrived on the wire bounds it at `max_ratio`.
    let payload = vec![0u8; 8 * 1024 * 1024];
    let inner = gzip_compress(&payload).await;
    let middle = gzip_compress(&inner).await;
    let wire = gzip_compress(&middle).await;
    let wire_len = wire.len() as u64;

    let response = http::Response::builder()
        .header(CONTENT_ENCODING, "gzip, gzip, gzip")
        .body(Body::fixed(wire))
        .expect("response should build");

    let guard = ExpansionGuard::new(DEFAULT_MAX_DECOMPRESSED_SIZE, 100);
    let decoded = guard
        .decode_response(response)
        .expect("three codings are within the cap");

    let mut stream = decoded.into_body().into_data_stream();
    let mut delivered = 0u64;
    let mut rejection = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => delivered += chunk.len() as u64,
            Err(err) => {
                rejection = Some(err);
                break;
            }
        }
    }

    assert!(
        rejection.is_some(),
        "a bomb that expands {}x end to end must still be rejected",
        payload.len() as u64 / wire_len
    );
    // The guard can only fire once a chunk has pushed the total past the bound, so one
    // decoder chunk of overshoot is expected; anything beyond that is the ratio being
    // enforced against the wrong denominator.
    const ONE_DECODER_CHUNK: u64 = 64 * 1024;
    assert!(
        delivered <= wire_len * 100 + ONE_DECODER_CHUNK,
        "delivered {delivered} bytes from {wire_len} wire bytes, past the configured 100x ratio"
    );
}

#[tokio::test]
async fn an_identity_coding_does_not_take_over_the_wire_byte_count() {
    // `Content-Encoding: gzip, identity` is decoded identity-first, and identity builds
    // no decoder. If it were still treated as the layer that reads the wire, the gzip
    // layer would measure itself against a counter nothing ever increments, and the
    // ratio guard would never fire — a one-token way for a hostile server to switch it
    // off.
    let payload = vec![b'a'; 100_000];
    let compressed = gzip_compress(&payload).await;

    let response = http::Response::builder()
        .header(CONTENT_ENCODING, "gzip, identity")
        .body(Body::fixed(compressed))
        .expect("response should build");

    let guard = ExpansionGuard::new(DEFAULT_MAX_DECOMPRESSED_SIZE, 10);
    let decoded = guard
        .decode_response(response)
        .expect("two codings are within the cap");

    let err = decoded
        .into_body()
        .collect(u64::MAX)
        .await
        .expect_err("the ratio guard must still fire behind an identity coding");
    assert!(matches!(err, Error::BodyTooLarge { .. }));
}

#[tokio::test]
async fn a_ratio_violation_reports_the_ratio_bound_rather_than_the_size_bound() {
    // The two limits have different fixes for whoever reads the error: one wants
    // `max_decompressed_size` raised, the other wants `max_ratio` raised. Reporting the
    // absolute limit for a ratio rejection points at the wrong one.
    let payload = vec![b'a'; 100_000];
    let compressed = gzip_compress(&payload).await;
    let compressed_len = compressed.len() as u64;

    let guard = ExpansionGuard::new(DEFAULT_MAX_DECOMPRESSED_SIZE, 10);
    let decoded = guard.decode(Body::fixed(compressed), ContentCoding::Gzip);

    let err = decoded
        .collect(u64::MAX)
        .await
        .expect_err("a body that expands past the configured ratio should be rejected");

    match err {
        Error::BodyTooLarge { limit } => {
            assert_ne!(
                limit, DEFAULT_MAX_DECOMPRESSED_SIZE,
                "a ratio rejection must not report the absolute size limit"
            );
            assert!(
                limit <= compressed_len * 10,
                "reported limit {limit} should be the ratio bound over at most \
                 {compressed_len} compressed bytes"
            );
        }
        other => panic!("expected Error::BodyTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn decompressing_past_the_absolute_size_limit_is_rejected() {
    // 100,000 compressible bytes so the ratio guard (checked separately below) does
    // not also fire and mask which limit actually triggered.
    let payload = vec![b'a'; 100_000];
    let compressed = gzip_compress(&payload).await;

    let guard = ExpansionGuard::new(1024, 1_000_000);
    let decoded = guard.decode(Body::fixed(compressed), ContentCoding::Gzip);

    let err = decoded
        .collect(u64::MAX)
        .await
        .expect_err("a body over the configured size limit should be rejected");
    assert!(matches!(err, Error::BodyTooLarge { limit: 1024 }));
}

#[tokio::test]
async fn decompressing_past_the_expansion_ratio_is_rejected() {
    // Highly compressible input reaches a very high ratio at a small absolute size,
    // so the default (100 MiB) size limit stays well out of the way and only the
    // ratio guard can be responsible for the rejection.
    let payload = vec![b'a'; 100_000];
    let compressed = gzip_compress(&payload).await;
    assert!(
        (payload.len() as u64) > (compressed.len() as u64) * 50,
        "fixture should exceed the ratio under test"
    );

    let guard = ExpansionGuard::new(DEFAULT_MAX_DECOMPRESSED_SIZE, 10);
    let decoded = guard.decode(Body::fixed(compressed), ContentCoding::Gzip);

    let err = decoded
        .collect(u64::MAX)
        .await
        .expect_err("a body that expands past the configured ratio should be rejected");
    assert!(matches!(err, Error::BodyTooLarge { .. }));
}
