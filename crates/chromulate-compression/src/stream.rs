//! The streaming pipeline that bridges an [`http_body::Body`] to an async-compression
//! decoder and back, with byte counting for the expansion guard.
//!
//! Nothing here uses `pin-project-lite`: every adapter is boxed (`Pin<Box<dyn ..>>`),
//! which is unconditionally [`Unpin`] regardless of what it contains, so no pin
//! projection macro is needed to implement [`Stream`] or [`AsyncRead`] by hand.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use chromulate_core::{Error, Result};
use futures_core::Stream;
use tokio::io::AsyncRead;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::coding::ContentCoding;

/// A reader compressed bytes are pulled from, counting how many have passed through.
type RawReader = StreamReader<CountingStream, Bytes>;

/// A boxed, type-erased decoder output.
type BoxedAsyncRead = Pin<Box<dyn AsyncRead + Send>>;

/// A boxed, type-erased byte stream, used at each stage of the pipeline.
type BoxedByteStream<T> = Pin<Box<dyn Stream<Item = T> + Send>>;

/// The compressed-byte total every stage of a decoder chain measures its output
/// against.
///
/// The count must reflect exactly how much compressed input has been consumed *so far*,
/// not the body's total advertised length (which may be absent for a chunked response,
/// and which would defeat the point of checking the ratio incrementally rather than
/// only after the fact).
///
/// One total is shared by the whole chain, and only the stage that reads the wire adds
/// to it. An outer stage's input is an inner stage's already-decoded output, so counting
/// that as well would inflate the denominator the ratio is measured against — which is
/// how a response with N stacked codings came to be permitted an end-to-end expansion of
/// `max_ratio` raised to the Nth power instead of `max_ratio`.
#[derive(Clone)]
pub(crate) struct WireBytes {
    total: Arc<AtomicU64>,
    counts_input: bool,
}

impl WireBytes {
    /// A fresh total, for the stage that reads the compressed bytes off the wire.
    pub(crate) fn reading_the_wire() -> Self {
        Self {
            total: Arc::new(AtomicU64::new(0)),
            counts_input: true,
        }
    }

    /// The same total, for a stage layered on top of one that already counts it.
    pub(crate) fn shared_by_an_outer_layer(&self) -> Self {
        Self {
            total: Arc::clone(&self.total),
            counts_input: false,
        }
    }
}

/// Wraps the compressed-body stream, counting bytes as they are pulled by the decoder.
struct CountingStream {
    inner: BoxedByteStream<io::Result<Bytes>>,
    counted: Option<Arc<AtomicU64>>,
}

impl Stream for CountingStream {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let polled = this.inner.as_mut().poll_next(cx);
        if let (Poll::Ready(Some(Ok(chunk))), Some(counted)) = (&polled, &this.counted) {
            counted.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
        polled
    }
}

/// Enforces the expansion guard and converts decoder I/O errors back into
/// [`chromulate_core::Error`], preserving the original error when the decoder's failure
/// was itself caused by the upstream body rather than by malformed compressed data.
struct GuardedStream {
    inner: BoxedByteStream<io::Result<Bytes>>,
    encoded_so_far: Arc<AtomicU64>,
    decoded_so_far: u64,
    max_decompressed_size: u64,
    max_ratio: u64,
    coding: ContentCoding,
}

impl Stream for GuardedStream {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(io_err))) => {
                Poll::Ready(Some(Err(this.classify_io_error(io_err))))
            }
            Poll::Ready(Some(Ok(chunk))) => {
                this.decoded_so_far += chunk.len() as u64;
                if let Some(err) = this.check_limits() {
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Ready(Some(Ok(chunk)))
            }
        }
    }
}

impl GuardedStream {
    /// An upstream body error was wrapped in an `io::Error` to satisfy
    /// [`StreamReader`]'s bound; unwrap it so callers see the original error class
    /// (a connection failure, say) instead of a misleading decode failure.
    fn classify_io_error(&self, io_err: io::Error) -> Error {
        match io_err.into_inner() {
            None => Error::Decode {
                encoding: self.coding.to_string(),
                source: None,
            },
            Some(source) => match source.downcast::<Error>() {
                Ok(original) => *original,
                Err(source) => Error::Decode {
                    encoding: self.coding.to_string(),
                    source: Some(source),
                },
            },
        }
    }

    fn check_limits(&self) -> Option<Error> {
        if self.decoded_so_far > self.max_decompressed_size {
            return Some(Error::BodyTooLarge {
                limit: self.max_decompressed_size,
            });
        }
        let encoded = self.encoded_so_far.load(Ordering::Relaxed);
        // The reported limit is the ratio bound over the compressed bytes seen so far,
        // not `max_decompressed_size`. The two limits have different remedies for
        // whoever reads the error — one wants the absolute size raised, the other wants
        // the ratio raised — so reporting the absolute limit for a ratio rejection
        // points at the wrong knob.
        let ratio_limit = encoded.saturating_mul(self.max_ratio);
        if encoded > 0 && self.decoded_so_far > ratio_limit {
            return Some(Error::BodyTooLarge { limit: ratio_limit });
        }
        None
    }
}

/// The error reported when a coding is recognized but its decoder was not compiled in.
///
/// Used only by the `wrap_*` fallback below for a coding whose feature is disabled;
/// with every coding feature enabled (the default), nothing references it, which is
/// expected rather than dead code in the usual sense.
#[derive(Debug)]
#[allow(dead_code)]
struct CodingNotCompiled(ContentCoding);

impl fmt::Display for CodingNotCompiled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the `{}` cargo feature is not enabled in this build",
            self.0
        )
    }
}

impl std::error::Error for CodingNotCompiled {}

#[allow(dead_code)]
fn unsupported(coding: ContentCoding) -> Error {
    Error::Decode {
        encoding: coding.to_string(),
        source: Some(Box::new(CodingNotCompiled(coding))),
    }
}

#[cfg(feature = "gzip")]
fn wrap_gzip(reader: RawReader) -> Result<BoxedAsyncRead> {
    Ok(Box::pin(
        async_compression::tokio::bufread::GzipDecoder::new(reader),
    ))
}
#[cfg(not(feature = "gzip"))]
fn wrap_gzip(_reader: RawReader) -> Result<BoxedAsyncRead> {
    Err(unsupported(ContentCoding::Gzip))
}

#[cfg(feature = "deflate")]
fn wrap_deflate(reader: RawReader) -> Result<BoxedAsyncRead> {
    // HTTP's "deflate" coding is the zlib-wrapped format; see the crate manifest.
    Ok(Box::pin(
        async_compression::tokio::bufread::ZlibDecoder::new(reader),
    ))
}
#[cfg(not(feature = "deflate"))]
fn wrap_deflate(_reader: RawReader) -> Result<BoxedAsyncRead> {
    Err(unsupported(ContentCoding::Deflate))
}

#[cfg(feature = "brotli")]
fn wrap_brotli(reader: RawReader) -> Result<BoxedAsyncRead> {
    Ok(Box::pin(
        async_compression::tokio::bufread::BrotliDecoder::new(reader),
    ))
}
#[cfg(not(feature = "brotli"))]
fn wrap_brotli(_reader: RawReader) -> Result<BoxedAsyncRead> {
    Err(unsupported(ContentCoding::Brotli))
}

#[cfg(feature = "zstd")]
fn wrap_zstd(reader: RawReader) -> Result<BoxedAsyncRead> {
    Ok(Box::pin(
        async_compression::tokio::bufread::ZstdDecoder::new(reader),
    ))
}
#[cfg(not(feature = "zstd"))]
fn wrap_zstd(_reader: RawReader) -> Result<BoxedAsyncRead> {
    Err(unsupported(ContentCoding::Zstd))
}

/// The non-identity codings this module can dispatch a decoder for.
///
/// Kept distinct from [`ContentCoding`] so the dispatcher below is exhaustive without
/// an `Identity` arm that could never be reached: callers filter `Identity` out before
/// building a pipeline at all, since there is nothing to decode.
pub(crate) enum Encoded {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl ContentCoding {
    pub(crate) fn as_encoded(self) -> Option<Encoded> {
        match self {
            Self::Gzip => Some(Encoded::Gzip),
            Self::Deflate => Some(Encoded::Deflate),
            Self::Brotli => Some(Encoded::Brotli),
            Self::Zstd => Some(Encoded::Zstd),
            Self::Identity => None,
        }
    }
}

fn wrap_decoder(reader: RawReader, encoded: &Encoded) -> Result<BoxedAsyncRead> {
    match encoded {
        Encoded::Gzip => wrap_gzip(reader),
        Encoded::Deflate => wrap_deflate(reader),
        Encoded::Brotli => wrap_brotli(reader),
        Encoded::Zstd => wrap_zstd(reader),
    }
}

/// Builds a decoded byte stream from a compressed body stream.
///
/// `source` must already be the raw compressed bytes; nothing is buffered beyond what
/// the underlying decoder needs to make progress. On success, the returned stream's
/// items are the decoded chunks, guarded by `max_decompressed_size` and `max_ratio`.
/// When the coding's cargo feature was not compiled in, the returned stream is not an
/// error itself: it defers the [`Error::Decode`] to the first poll, matching `decode`'s
/// infallible signature while still surfacing the failure to whoever reads the body.
///
/// `coding` and `encoded` describe the same coding; `encoded` proves at the type level
/// that the caller has already excluded `ContentCoding::Identity`, which needs no
/// pipeline at all, while `coding` is retained for error messages.
///
/// `wire_bytes` is the compressed-byte total the ratio guard divides by. For a chain of
/// stacked codings the caller passes the same total to every stage; see [`WireBytes`].
pub(crate) fn decode_stream<S>(
    source: S,
    coding: ContentCoding,
    encoded: Encoded,
    max_decompressed_size: u64,
    max_ratio: u64,
    wire_bytes: WireBytes,
) -> BoxedByteStream<Result<Bytes>>
where
    S: Stream<Item = Result<Bytes>> + Send + 'static,
{
    use futures_util::StreamExt as _;

    let mapped: BoxedByteStream<io::Result<Bytes>> =
        Box::pin(source.map(|item| item.map_err(io::Error::other)));
    let counting = CountingStream {
        inner: mapped,
        counted: wire_bytes
            .counts_input
            .then(|| Arc::clone(&wire_bytes.total)),
    };
    let reader = StreamReader::new(counting);

    match wrap_decoder(reader, &encoded) {
        Ok(decoder) => {
            let byte_stream: BoxedByteStream<io::Result<Bytes>> =
                Box::pin(ReaderStream::new(decoder));
            Box::pin(GuardedStream {
                inner: byte_stream,
                encoded_so_far: wire_bytes.total,
                decoded_so_far: 0,
                max_decompressed_size,
                max_ratio,
                coding,
            })
        }
        Err(err) => Box::pin(futures_util::stream::once(async move { Err(err) })),
    }
}
