//! The QUIC spike: enough code to observe what this stack would put on the wire.
//!
//! This module is not a transport and is not wired into `chromulate-http`. It exists
//! to answer one question with observations rather than argument: *if Chromulate spoke
//! HTTP/3 over `quinn`, what would a server see, and how far is that from Chrome?*
//! The answer, the measurements and the recommendation are in
//! `docs/architecture/04-http3-assessment.md`.
//!
//! Three pieces:
//!
//! - [`probe`] plugs a recorder into `quinn`'s public crypto seam and captures the
//!   exact bytes `quinn` hands to TLS: the QUIC transport parameters and the
//!   ClientHello. No decryption, no packet capture, no forked dependency — the seam is
//!   `quinn_proto::crypto::ClientConfig`, which is public and unsealed.
//! - [`transport_params`] and [`client_hello`] decode those bytes into something
//!   comparable with a captured browser profile.
//! - [`request`] performs one real HTTP/3 `GET`, behind `network-tests`, to establish
//!   that the functional half works before the fidelity half is judged.
//!
//! ## Why this is a spike and not a crate feature
//!
//! `quic-spike` is off by default. Turning it on pulls `quinn-udp`, whose portable
//! datapath is 60-odd `unsafe` blocks of `sendmmsg`/`recvmmsg`, GSO and control-message
//! handling — measured below in the assessment. Nothing here changes this crate's own
//! `#![forbid(unsafe_code)]`; a dependency's `unsafe` is its own business. It is
//! recorded because "no `unsafe` in any shipped crate" is a claim this project makes
//! about itself, and a reader deserves to know when a feature flag changes the shape of
//! what gets linked underneath it.

pub mod client_hello;
pub mod error;
pub mod probe;
pub mod transport_params;

#[cfg(feature = "network-tests")]
pub mod request;

pub use client_hello::ObservedClientHello;
pub use error::SpikeError;
pub use probe::{HandshakeRecorder, RecordedHandshake};
pub use transport_params::{TransportParameter, decode_transport_parameters};
