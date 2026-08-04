//! Browser identities that were recorded rather than invented.
//!
//! A fingerprint model is only worth having if something fills it in with real
//! values. This crate is that something: a [`Profile`] is one browser build's
//! complete observable identity — ClientHello shape, HTTP/2 preface, user
//! agent, client hints, and header order — so the rest of Chromulate can ask
//! "what would Chrome have sent?" instead of guessing.
//!
//! # Only Chrome ships with captured data
//!
//! [`Profile::chrome_stable`] is populated entirely from
//! `data/chrome-151-macos.json`, a live capture of Chrome 151 on macOS. There
//! is deliberately **no `firefox()` or `safari()`**: no capture of those
//! browsers exists in this repository, and a hand-written fingerprint would be
//! a fabrication that quietly fails the moment anyone checks it against a real
//! browser. The types here are shaped so those profiles can be added the day
//! someone records them — either as another constant module, or at runtime
//! through [`Profile::from_capture`].
//!
//! # Why the shipped profile is Rust constants
//!
//! The Chrome profile is built from `const` tables in code, not parsed from
//! JSON at run time, so that using it cannot fail, needs no file to be
//! installed beside the binary, and costs nothing at startup. The capture file
//! still ships in `data/` as the provenance record, and
//! `tests/chrome_profile_matches_capture.rs` rebuilds the profile from it and
//! asserts the two are byte-for-byte the same value — so the constants cannot
//! drift away from the recording that justifies them.
//!
//! ```
//! use chromulate_profile::{Profile, ProfileRegistry};
//!
//! let chrome = Profile::chrome_stable();
//! assert_eq!(chrome.ja4(), "t13d1516h2_8daaf6152771_806a8c22fdea");
//! assert_eq!(
//!     chrome.akamai_http2(),
//!     "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
//! );
//!
//! let registry = ProfileRegistry::with_builtin();
//! assert!(registry.get("chrome").is_some());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod chrome;
pub mod profile;
pub mod registry;

pub use profile::{Brand, HeaderOrder, Platform, Profile, parse_brand_list, render_brand_list};
pub use registry::ProfileRegistry;

/// The capture the shipped Chrome profile was transcribed from.
///
/// Exposed so that a caller can inspect the provenance of what it is sending,
/// or feed it back through [`Profile::from_capture`].
pub const CHROME_STABLE_CAPTURE: &str = include_str!("../data/chrome-151-macos.json");
