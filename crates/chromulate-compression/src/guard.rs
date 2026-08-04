//! Bounds on how far a response body may expand during decompression.

use std::fmt;

use chromulate_core::reexport::HeaderValue;
use chromulate_core::{Body, Error, Response, Result};
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};

use crate::coding::ContentCoding;
use crate::stream::{WireBytes, decode_stream};

/// A decompressed response is larger than 100 MiB.
///
/// A single crawled page or API response is very rarely legitimately larger than
/// this. Callers with a genuine need for larger bodies raise the limit explicitly with
/// [`ExpansionGuard::new`]; the default favors catching runaway decompression over
/// accommodating an unusual workload.
pub const DEFAULT_MAX_DECOMPRESSED_SIZE: u64 = 100 * 1024 * 1024;

/// A decompressed response is more than 100 times the size of its compressed form.
///
/// Ordinary HTML, JSON, and text achieve gzip/brotli/zstd ratios in the 3-10x range;
/// even unusually repetitive legitimate content rarely exceeds a few dozen times its
/// compressed size. A hostile "zip bomb" response, by contrast, is built specifically
/// to maximize this ratio and routinely reaches ratios in the thousands. 100x sits
/// well above realistic legitimate traffic and well below adversarial payloads, so it
/// catches the failure mode this guard exists for without false-positiving on
/// legitimate responses.
pub const DEFAULT_MAX_RATIO: u64 = 100;

/// The most content codings a single response may stack.
///
/// Every coding named in `Content-Encoding` adds a layer to a chain of nested decoders
/// that is polled recursively, one stack frame per layer, and costs tens of kilobytes
/// of decoder buffers before a single body byte is read. Both costs are driven purely
/// by a response header, so without a bound a few kilobytes of header build a chain
/// deep enough to overflow the polling thread's stack — which aborts the process
/// outright rather than raising an error any caller could catch.
///
/// RFC 9110 §8.4 places no limit on the count, but describes no use for more than a
/// handful, and real responses stack one or two. Eight is far above anything observed
/// in practice and far below the depth at which the chain costs anything.
pub const MAX_CONTENT_CODINGS: usize = 8;

/// The cause attached to [`Error::Decode`] when a response stacks more content codings
/// than [`MAX_CONTENT_CODINGS`] allows.
///
/// The response is rejected rather than decoded to the limit and truncated: handing the
/// caller bytes that are still encoded, under a claim of having decoded them, is worse
/// than failing loudly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyCodings {
    limit: usize,
}

impl TooManyCodings {
    /// The largest number of codings that would have been accepted.
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

impl fmt::Display for TooManyCodings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a response may stack at most {} content codings",
            self.limit
        )
    }
}

impl std::error::Error for TooManyCodings {}

/// Bounds enforced while decompressing a response body.
///
/// Decompression of an untrusted, attacker-controlled body is a memory-safety
/// concern, not just a resource-usage one: without a bound, a small compressed
/// response can be crafted to expand to any size the decoder is willing to produce.
/// Both bounds are checked incrementally as bytes are decoded, so an oversized body is
/// abandoned mid-stream rather than fully decoded and then rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpansionGuard {
    max_decompressed_size: u64,
    max_ratio: u64,
}

impl Default for ExpansionGuard {
    fn default() -> Self {
        Self {
            max_decompressed_size: DEFAULT_MAX_DECOMPRESSED_SIZE,
            max_ratio: DEFAULT_MAX_RATIO,
        }
    }
}

impl ExpansionGuard {
    /// Builds a guard with explicit limits.
    ///
    /// `max_decompressed_size` bounds the absolute decoded size, in bytes.
    /// `max_ratio` bounds decoded bytes as a multiple of compressed bytes consumed so
    /// far; it is not checked until at least one compressed byte has been read, so it
    /// cannot reject a body based on a division by zero or an unrepresentative first
    /// chunk.
    pub const fn new(max_decompressed_size: u64, max_ratio: u64) -> Self {
        Self {
            max_decompressed_size,
            max_ratio,
        }
    }

    /// The configured maximum decompressed size, in bytes.
    pub const fn max_decompressed_size(&self) -> u64 {
        self.max_decompressed_size
    }

    /// The configured maximum expansion ratio.
    pub const fn max_ratio(&self) -> u64 {
        self.max_ratio
    }

    /// Wraps `body` in a streaming decoder for `coding`, enforcing this guard.
    ///
    /// `ContentCoding::Identity` is returned unchanged: there is nothing to decode,
    /// and no expansion is possible. For every other coding, decoding happens lazily
    /// as the returned body is polled; nothing is buffered ahead of what the decoder
    /// needs to make progress. If the coding's decoder was not compiled into this
    /// build, the returned body defers an [`Error::Decode`] to its first poll rather
    /// than failing here, since this function's signature is infallible.
    pub fn decode(&self, body: Body, coding: ContentCoding) -> Body {
        self.decode_layer(body, coding, WireBytes::reading_the_wire())
    }

    /// Wraps `body` in a decoder for one coding of a chain, measuring its output against
    /// `wire_bytes` rather than against its own input.
    fn decode_layer(&self, body: Body, coding: ContentCoding, wire_bytes: WireBytes) -> Body {
        use http_body_util::BodyExt as _;

        let Some(encoded) = coding.as_encoded() else {
            return body;
        };
        let source = body.into_data_stream();
        let decoded = decode_stream(
            source,
            coding,
            encoded,
            self.max_decompressed_size,
            self.max_ratio,
            wire_bytes,
        );
        Body::stream(decoded, None)
    }

    /// Decodes a response body according to its `Content-Encoding` header.
    ///
    /// Multiple codings (`Content-Encoding: gzip, br`) are applied in reverse order,
    /// undoing the last-applied coding first, per RFC 9110 §8.4.1, and at most
    /// [`MAX_CONTENT_CODINGS`] of them; a response stacking more is rejected with
    /// [`TooManyCodings`] before any decoder is built. On success, `Content-Encoding`
    /// and `Content-Length` are removed from the response: both describe the encoded
    /// form on the wire and are no longer accurate once the body has been decoded. An
    /// unrecognized coding is an error rather than a silent pass-through, since
    /// forwarding undecoded bytes under a claim of having decoded them would be worse
    /// than failing loudly.
    ///
    /// The expansion guard bounds the chain end to end: every layer's output is measured
    /// against the bytes that arrived on the wire, so stacking codings cannot multiply
    /// the permitted ratio.
    pub fn decode_response(&self, response: Response) -> Result<Response> {
        let (mut parts, body) = response.into_parts();

        if !parts.headers.contains_key(CONTENT_ENCODING) {
            return Ok(Response::from_parts(parts, body));
        }

        let codings = parse_content_encoding(parts.headers.get_all(CONTENT_ENCODING))?;

        let wire_bytes = WireBytes::reading_the_wire();
        let mut reads_the_wire = true;
        let mut body = body;
        for coding in codings.into_iter().rev() {
            let stage = if reads_the_wire {
                wire_bytes.clone()
            } else {
                wire_bytes.shared_by_an_outer_layer()
            };
            // An `Identity` coding builds no decoder and leaves the body untouched, so
            // the next real coding is still the one that reads the wire.
            if coding != ContentCoding::Identity {
                reads_the_wire = false;
            }
            body = self.decode_layer(body, coding, stage);
        }

        parts.headers.remove(CONTENT_ENCODING);
        parts.headers.remove(CONTENT_LENGTH);

        Ok(Response::from_parts(parts, body))
    }
}

/// Parses every `Content-Encoding` header value into an ordered list of codings, of at
/// most [`MAX_CONTENT_CODINGS`] entries.
///
/// A response may repeat the header, and a single header value may itself carry a
/// comma-separated list; both are flattened into one ordered sequence, left to right,
/// matching how the codings were applied when the body was produced. The cap therefore
/// binds on that flattened total rather than per header line — splitting the tokens
/// across repeated lines costs a hostile server fewer wire bytes, not more.
///
/// The cap is checked before each token is parsed or stored, so a header naming
/// thousands of codings is rejected having allocated almost nothing and having built no
/// decoder at all.
fn parse_content_encoding<'a>(
    values: impl IntoIterator<Item = &'a HeaderValue>,
) -> Result<Vec<ContentCoding>> {
    let mut codings = Vec::new();
    for value in values {
        let text = value.to_str().map_err(|source| Error::Decode {
            encoding: "content-encoding".to_string(),
            source: Some(Box::new(source)),
        })?;
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if codings.len() == MAX_CONTENT_CODINGS {
                return Err(Error::Decode {
                    encoding: "content-encoding".to_string(),
                    source: Some(Box::new(TooManyCodings {
                        limit: MAX_CONTENT_CODINGS,
                    })),
                });
            }
            let coding = ContentCoding::parse(token).ok_or_else(|| Error::Decode {
                encoding: token.to_string(),
                source: None,
            })?;
            codings.push(coding);
        }
    }
    Ok(codings)
}

/// Decodes a response body using the default [`ExpansionGuard`].
///
/// See [`ExpansionGuard::decode_response`] for the full behaviour.
pub fn decode_response(response: Response) -> Result<Response> {
    ExpansionGuard::default().decode_response(response)
}

/// Wraps `body` in a streaming decoder for `coding`, using the default
/// [`ExpansionGuard`].
///
/// See [`ExpansionGuard::decode`] for the full behaviour.
pub fn decode(body: Body, coding: ContentCoding) -> Body {
    ExpansionGuard::default().decode(body, coding)
}
