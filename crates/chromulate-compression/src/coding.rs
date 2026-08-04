//! The content codings this crate knows how to negotiate and decode.

use std::fmt;

use chromulate_core::reexport::HeaderValue;

/// A content coding as it appears in `Accept-Encoding` and `Content-Encoding`.
///
/// This covers the codings a modern browser advertises. Parsing accepts the standard
/// HTTP tokens; unrecognized tokens do not parse to a variant, so callers can decide
/// whether an unknown coding is an error or something to pass through unread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ContentCoding {
    /// The `gzip` coding (RFC 1952).
    Gzip,
    /// The `deflate` coding, which HTTP defines as the zlib-wrapped DEFLATE format
    /// (RFC 9110 §8.4.1.2, RFC 1950), not raw DEFLATE (RFC 1951).
    Deflate,
    /// The `br` coding (Brotli, RFC 7932).
    Brotli,
    /// The `zstd` coding (Zstandard, RFC 8878).
    Zstd,
    /// No coding: the body is carried as-is.
    Identity,
}

/// The four real codings, in the order a Chrome-family browser advertises them.
///
/// This is the full set this crate can decode when compiled with default features. It
/// is independent of [`compiled_codings`], which reflects only the algorithms whose
/// cargo feature is actually enabled in this build.
pub const BROWSER_CODING_ORDER: [ContentCoding; 4] = [
    ContentCoding::Gzip,
    ContentCoding::Deflate,
    ContentCoding::Brotli,
    ContentCoding::Zstd,
];

impl ContentCoding {
    /// Parses an `Accept-Encoding` or `Content-Encoding` token.
    ///
    /// Matching is case-insensitive and ignores leading and trailing whitespace, as
    /// tokens in these headers commonly carry both after being split on commas.
    /// Returns `None` for tokens this crate does not recognize, including quality
    /// values such as `gzip;q=0.5` (split those off before calling this).
    pub fn parse(token: &str) -> Option<Self> {
        match token.trim() {
            t if t.eq_ignore_ascii_case("gzip") => Some(Self::Gzip),
            t if t.eq_ignore_ascii_case("x-gzip") => Some(Self::Gzip),
            t if t.eq_ignore_ascii_case("deflate") => Some(Self::Deflate),
            t if t.eq_ignore_ascii_case("br") => Some(Self::Brotli),
            t if t.eq_ignore_ascii_case("zstd") => Some(Self::Zstd),
            t if t.eq_ignore_ascii_case("identity") => Some(Self::Identity),
            _ => None,
        }
    }

    /// The wire token for this coding, as written in an HTTP header.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
            Self::Identity => "identity",
        }
    }
}

impl fmt::Display for ContentCoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The codings this build can actually decode, in browser order.
///
/// Each coding behind a disabled cargo feature is skipped. A client should advertise
/// exactly this set in `Accept-Encoding`; advertising a coding this build cannot
/// decode would force the server to send a body the client can only reject.
#[allow(
    unused_mut,
    reason = "codings is unused with every algorithm feature disabled"
)]
pub fn compiled_codings() -> Vec<ContentCoding> {
    let mut codings = Vec::with_capacity(BROWSER_CODING_ORDER.len());
    #[cfg(feature = "gzip")]
    codings.push(ContentCoding::Gzip);
    #[cfg(feature = "deflate")]
    codings.push(ContentCoding::Deflate);
    #[cfg(feature = "brotli")]
    codings.push(ContentCoding::Brotli);
    #[cfg(feature = "zstd")]
    codings.push(ContentCoding::Zstd);
    codings
}

/// Builds the `Accept-Encoding` header value for the given codings, preserving order.
///
/// The order matters: it is part of the observable fingerprint a server or middlebox
/// can use to distinguish clients. The tokens this crate emits are always valid header
/// bytes, so the only realistic failure is an empty slice, for which this returns
/// `identity` rather than an empty header value.
pub fn accept_encoding_value(codings: &[ContentCoding]) -> HeaderValue {
    if codings.is_empty() {
        return HeaderValue::from_static("identity");
    }
    let joined = codings
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    HeaderValue::from_str(&joined).unwrap_or_else(|_| HeaderValue::from_static("identity"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tokens_parse_case_insensitively_with_surrounding_whitespace() {
        assert_eq!(ContentCoding::parse(" GzIp "), Some(ContentCoding::Gzip));
        assert_eq!(ContentCoding::parse("br"), Some(ContentCoding::Brotli));
        assert_eq!(ContentCoding::parse("ZSTD"), Some(ContentCoding::Zstd));
        assert_eq!(
            ContentCoding::parse("Deflate"),
            Some(ContentCoding::Deflate)
        );
        assert_eq!(
            ContentCoding::parse("identity"),
            Some(ContentCoding::Identity)
        );
    }

    #[test]
    fn unknown_tokens_do_not_parse() {
        assert_eq!(ContentCoding::parse("compress"), None);
        assert_eq!(ContentCoding::parse("gzip;q=0.5"), None);
    }

    #[test]
    fn display_round_trips_through_parse() {
        for coding in BROWSER_CODING_ORDER {
            assert_eq!(ContentCoding::parse(&coding.to_string()), Some(coding));
        }
    }

    #[test]
    fn the_default_accept_encoding_value_matches_the_captured_browser_header() {
        let value = accept_encoding_value(&compiled_codings());
        assert_eq!(
            value.to_str().expect("value should be ASCII"),
            "gzip, deflate, br, zstd"
        );
    }

    #[test]
    fn an_empty_coding_list_advertises_identity() {
        assert_eq!(
            accept_encoding_value(&[]),
            HeaderValue::from_static("identity")
        );
    }
}
