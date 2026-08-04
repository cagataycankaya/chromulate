//! Models of what a TLS and HTTP/2 client looks like from the outside, and the
//! fingerprints an observer computes from that.
//!
//! A server never sees a browser; it sees a ClientHello and a connection
//! preface. This crate is the vocabulary for describing exactly that surface —
//! cipher order, extension set, GREASE placement, SETTINGS order,
//! pseudo-header order — and the arithmetic that turns it into JA3, JA4 and the
//! Akamai HTTP/2 fingerprint. Without it, a browser profile would be a pile of
//! constants nobody could check; with it, a profile can be proven to reproduce
//! a real capture before a single byte is sent.
//!
//! The types are deliberately shaped around one awkward fact: **Chrome permutes
//! its ClientHello extension order on every connection**. A profile that froze
//! one order would describe a browser that does not exist, so
//! [`ClientHelloSpec`] holds an [`ExtensionSet`] plus an [`ExtensionOrder`]
//! rule, and a wire order is generated per connection under invariants that
//! [`WireExtensionOrder`] enforces.
//!
//! ```
//! use chromulate_fingerprint::{Capture, akamai_http2, ja4};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let json = include_str!("../tests/data/chrome-151-macos.json");
//! let capture = Capture::parse(json)?;
//!
//! assert_eq!(ja4(&capture.client_hello()?), capture.sample_navigate.ja4);
//! assert_eq!(
//!     akamai_http2(&capture.http2()?),
//!     capture.sample_navigate.akamai_fingerprint
//! );
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod akamai;
pub mod capture;
pub mod client_hello;
pub mod error;
pub mod grease;
pub mod http2;
pub mod ids;
pub mod ja3;
pub mod ja4;

pub use akamai::{akamai_http2, akamai_http2_hash};
pub use capture::{Capture, Provenance, Sample};
pub use client_hello::{
    ClientHelloSpec, ExtensionOrder, ExtensionSet, GreasePlacement, ShufflePins, WireExtensionOrder,
};
pub use error::{CaptureError, SpecError};
pub use grease::GreaseValue;
pub use http2::{
    HeadersPriority, Http2Spec, PriorityFrame, PseudoHeader, PseudoHeaderOrder, Setting, SettingId,
};
pub use ids::{
    CertificateCompression, CipherSuite, EcPointFormat, ExtensionId, NamedGroup,
    PskKeyExchangeMode, SignatureScheme, TlsVersion, Transport,
};
pub use ja3::{ja3, ja3_hash, ja3_with_extension_order};
pub use ja4::{ja4, ja4_raw};
