//! Bot-challenge detectors for Chromulate: the laws behind the engine's
//! detection seam.
//!
//! [`chromulate_http::challenge`] holds the seam — [`ChallengeDetector`],
//! [`Observation`] and [`Detection`] — and no policy at all. This crate holds
//! the policy: detectors written against a specific vendor's *documented*
//! signals, on the standard `CLAUDE.md` sets for a fingerprint constant: a
//! rule must cite a documented signal or a captured response, never a guess
//! tuned against a live classifier.
//!
//! - [`CloudflareDetector`] reads `cf-mitigated`, the header Cloudflare
//!   documents for exactly this purpose, plus two body rules written against
//!   real captured Cloudflare pages. See its own documentation for every
//!   citation and for what this crate still does **not** claim.
//!
//! # Why this is a separate crate
//!
//! A trait with one implementation is a trait shaped like that
//! implementation, and a trait that ships in the same module as its
//! implementation is one whose users cannot tell which parts are the
//! boundary. Splitting the two makes the boundary checkable:
//! `chromulate-http` does not depend on this crate, so nothing here can be
//! reached from the engine, and a third-party detector needs
//! `chromulate-http` alone.
//!
//! Depending on this crate is therefore a choice to take the shipped rules. A
//! caller who wants none of them implements [`ChallengeDetector`] against
//! `chromulate-http` and never names this crate at all.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use chromulate_challenge::CloudflareDetector;
//! use chromulate_http::challenge::ChallengeDetector;
//!
//! let detector: Arc<dyn ChallengeDetector> = Arc::new(CloudflareDetector::new());
//!
//! // A `Middleware` installed with this detector asks it exactly this,
//! // once per terminal response.
//! # let _ = detector;
//! ```
//!
//! # Scope
//!
//! No solver. Nothing here mints a token or reimplements a challenge
//! platform's script. Body reads are bounded and gated behind
//! [`Detection::Suspect`] — see [`CloudflareDetector`]'s documentation for
//! exactly which bytes are read for, which two captures back that rule, and
//! for an open question this crate does not resolve on its own: whether
//! [`Detection`] needs a fourth arm for "detected, but nothing here can
//! carry it" (a WAF block, today reported as [`Detection::Clear`]). See the
//! scope boundary in `CLAUDE.md`.

#![doc(html_root_url = "https://docs.rs/chromulate-challenge/0.3.0")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cloudflare;

pub use cloudflare::CloudflareDetector;

/// The seam this crate's detectors implement, re-exported so a caller who
/// names this crate does not have to name `chromulate-http` as well to write
/// `Arc<dyn ChallengeDetector>` or to read a [`Detection`].
///
/// [`Detection`] and [`Observation`] are re-exported for the same reason:
/// [`Detection`] is what every detector here returns, and [`Observation`] is
/// what every one of them reads.
pub use chromulate_http::challenge::{ChallengeDetector, Detection, Observation};
