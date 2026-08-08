//! Streaming response-body decompression for the content codings a browser advertises.
//!
//! A browser's `Accept-Encoding` header is part of its observable network fingerprint,
//! and so is its willingness to actually decode what it asked for. This crate provides
//! both halves: [`accept_encoding_value`] builds the header a Chrome-family browser
//! sends, and [`decode_response`] undoes whatever the server actually used, streaming
//! the whole way so a multi-gigabyte response never sits fully buffered in memory.
//!
//! Decompressing an untrusted body without a bound is a memory-safety incident
//! waiting to happen: a small, cheaply-produced compressed response can be crafted to
//! expand to an arbitrary size. [`ExpansionGuard`] bounds both the absolute
//! decompressed size and the expansion ratio, checked incrementally as bytes are
//! decoded rather than after the fact.
//!
//! ```
//! use chromulate_compression::{ContentCoding, accept_encoding_value};
//!
//! let value = accept_encoding_value(&[
//!     ContentCoding::Gzip,
//!     ContentCoding::Deflate,
//!     ContentCoding::Brotli,
//!     ContentCoding::Zstd,
//! ]);
//! assert_eq!(value, "gzip, deflate, br, zstd");
//! ```
//!
//! Each coding lives behind its own cargo feature (`gzip`, `deflate`, `brotli`,
//! `zstd`), all enabled by default. Disabling one shrinks the dependency tree at the
//! cost of no longer being able to decode that coding; [`compiled_codings`] reports
//! exactly what a given build supports, so a client can advertise only what it can
//! actually decode.

#![doc(html_root_url = "https://docs.rs/chromulate-compression/0.3.0")]
#![warn(missing_docs)]

mod coding;
mod guard;
mod stream;

pub use coding::{BROWSER_CODING_ORDER, ContentCoding, accept_encoding_value, compiled_codings};
pub use guard::{
    DEFAULT_MAX_DECOMPRESSED_SIZE, DEFAULT_MAX_RATIO, ExpansionGuard, MAX_CONTENT_CODINGS,
    TooManyCodings, decode, decode_response,
};

#[cfg(test)]
mod tests;
