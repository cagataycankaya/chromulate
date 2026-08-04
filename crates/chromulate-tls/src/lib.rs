//! A TLS client configured from a browser profile — and an honest account of
//! how far that gets you.
//!
//! Every other crate in Chromulate can reproduce its part of a browser's
//! network surface exactly: the header order is the captured order, the HTTP/2
//! preface is the captured preface. TLS is the exception, and this crate is
//! where that exception is stated rather than hidden. It builds a
//! [`TlsEngine`] from a [`Profile`](chromulate_profile::Profile): the cipher
//! suites the profile lists, in the profile's order, as far as rustls
//! implements them; ALPN exactly as captured; verified certificates by default;
//! and a session store so the second connection to a host resumes the way a
//! browser's does.
//!
//! # Fidelity limits
//!
//! There are two halves to this, and they are both true at once.
//!
//! **Chromulate models the target ClientHello exactly.** The
//! [`ClientHelloSpec`](chromulate_fingerprint::ClientHelloSpec) a profile
//! carries is a faithful model of the captured browser, down to GREASE
//! placement and the extension permutation rule, and the golden tests in
//! `chromulate-fingerprint` and `chromulate-profile` prove it by reproducing
//! the capture's own recorded JA3, JA4 and Akamai fingerprints from it. That
//! model is what [`TlsEngine::target_client_hello`] hands back, and it is not
//! aspirational.
//!
//! **The bytes rustls emits are not that ClientHello, and no configuration
//! makes them so.** rustls builds its own ClientHello and exposes no hook for
//! the shape of it. Against the Chrome 151 profile, on a default (ring) build,
//! the differences are these — every one of them measured by decoding the bytes
//! a real connection writes, in `tests/emitted_client_hello.rs`, rather than
//! inferred from reading rustls:
//!
//! - **No GREASE.** The profile marks five GREASE slots — first cipher, first
//!   and last extension, first supported group, first key share, first
//!   supported version. rustls fills none of them.
//! - **Four extensions are missing** of the profile's sixteen:
//!   `signed_certificate_timestamp`, `application_settings` (ALPS — rustls
//!   states it does not implement it, `src/manual/features.rs:98`) and
//!   `encrypted_client_hello` have no rustls equivalent, and
//!   `renegotiation_info` is signalled the other way round — by the
//!   `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` cipher suite, which rustls appends
//!   whenever TLS 1.2 is enabled and which cannot be turned off. That shifts
//!   both the JA3 cipher field and the JA4 cipher count. Nothing else is added:
//!   rustls sends no extension the profile lacks.
//! - **Cipher suites are a subset.** rustls implements no CBC or static-RSA
//!   suites, so 9 of the profile's 15 survive. Those 9 keep the profile's
//!   relative order, and [`Fidelity`] names the 6 that were dropped.
//! - **One key share, not two.** The capture shows Chrome offering shares for
//!   both `X25519MLKEM768` and `X25519`; a default build sends a share for its
//!   first group only.
//! - **`X25519MLKEM768` depends on the provider.** Chrome 151 offers it first.
//!   The ring provider — the default — does not implement it, so it is dropped
//!   and reported in [`Fidelity::dropped_groups`]. The opt-in `aws-lc-rs`
//!   feature switches providers and does implement it; on that build all four
//!   of the profile's groups are offered and the key shares become exactly the
//!   pair the capture shows, because a hybrid group carries its classical
//!   companion. That feature is off by default deliberately: a pure-Rust build
//!   needing no C toolchain is part of what this project is, and one named
//!   group does not buy back GREASE, ALPS, SCT, the six missing cipher suites
//!   or the SCSV. Do not take any of this on trust —
//!   [`available_named_groups`] reads the list out of the provider this binary
//!   actually links.
//! - **`signature_algorithms` is the provider's list**, in the provider's
//!   order, not the profile's.
//!
//! One thing that is *not* a difference, and is worth knowing because it is
//! easy to assume otherwise: rustls 0.23 **does** randomise its extension order
//! per connection, as Chrome does. The permutation rule differs and there are
//! no GREASE brackets around it, but neither client sends a stable extension
//! order, so an unstable JA3 is the correct behaviour here rather than a bug.
//!
//! The measured result: a connection from a default build fingerprints as JA4
//! `t13d1012h2_61a7ad8aa9b6_69ed562cf35e`, and from an `aws-lc-rs` build as
//! `t13d1012h2_61a7ad8aa9b6_41631feb4e62`, where the Chrome 151 profile's
//! target is `t13d1516h2_8daaf6152771_806a8c22fdea`. **Neither matches, and a
//! server comparing them will see a client that is not Chrome.** Run
//! `cargo run -p chromulate-tls --example capabilities` to print the same
//! numbers for your own build.
//!
//! [`STRUCTURAL_LIMITS`] carries the list above as data, and
//! [`TlsEngine::fidelity`] reports what a specific engine dropped. The target
//! identity is exposed anyway, because logging it beside what an echo endpoint
//! reports is how the remaining distance gets measured — and because it is the
//! contract a future backend that encodes its own ClientHello has to meet.
//! [`TlsBackend`] is where such a backend plugs in.
//!
//! What this crate *does* reproduce faithfully: the ALPN list, the cipher suite
//! ordering within rustls's subset, the named group ordering within the
//! provider's subset, TLS 1.3-then-1.2 version preference, per-connection
//! extension reordering, resumption behaviour, and SNI — including sending none
//! for an IP-literal target.
//!
//! # Example
//!
//! ```
//! use chromulate_profile::Profile;
//! use chromulate_tls::TlsEngine;
//!
//! # fn main() -> Result<(), chromulate_core::Error> {
//! let engine = TlsEngine::new(&Profile::chrome_stable())?;
//!
//! // ALPN is captured, so it is exact.
//! assert_eq!(engine.fidelity().alpn, ["h2", "http/1.1"]);
//!
//! // The identity being aimed at, which the wire form does not match.
//! assert_eq!(engine.target_identity().ja4, "t13d1516h2_8daaf6152771_806a8c22fdea");
//!
//! // And the gap, as data rather than a footnote.
//! let (offered, wanted) = engine.fidelity().cipher_coverage();
//! assert!(offered < wanted, "rustls has no CBC suites");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod engine;
pub mod fidelity;
pub mod provider;
pub mod resumption;
pub mod server_name;
pub mod trust;

pub use backend::{TlsBackend, TlsConnection, TlsIo};
pub use engine::{Alpn, HandshakeInfo, TlsEngine, TlsEngineBuilder};
pub use fidelity::{
    Fidelity, STRUCTURAL_LIMITS, TargetIdentity, target_client_hello, target_identity,
};
pub use provider::{
    PROVIDER_NAME, available_cipher_suites, available_named_groups, supports_cipher_suite,
    supports_named_group,
};
pub use resumption::{DEFAULT_CAPACITY, SessionStore};
pub use server_name::{sends_sni, server_name};
pub use trust::{RootSource, TrustPolicy};

/// The stream a successful handshake produces.
///
/// This is `tokio_rustls`'s own client stream, re-exported so a caller does not
/// have to depend on `tokio-rustls` to name the return type of
/// [`TlsEngine::connect`].
pub type TlsStream<IO> = tokio_rustls::client::TlsStream<IO>;
