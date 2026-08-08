//! Per-origin concurrency control laws for Chromulate.
//!
//! The engine holds the *seam* — [`ConcurrencyController`], [`Lease`] and
//! [`Outcome`], in [`chromulate_http::concurrency`] — and no policy at all. This
//! crate holds the policy: two implementations of that trait, and the shared
//! vocabulary they need.
//!
//! - [`AdaptiveConcurrency`] learns a limit per origin from latency and treats a
//!   refusal as a one-way ratchet. It is what a caller who asks for adaptive
//!   concurrency and names nothing else gets.
//! - [`FixedConcurrency`] bounds in-flight requests per origin at a number the
//!   caller chose and never moves it.
//!
//! Both take a [`Ceiling`], which is how a caller's rate limit reaches them, and
//! neither can be constructed without saying in writing what that ceiling is.
//!
//! # Why this is a separate crate
//!
//! A trait with one implementation is a trait shaped like that implementation,
//! and a trait that ships in the same module as its implementation is one whose
//! users cannot tell which parts are the boundary. Splitting the two makes the
//! boundary checkable: `chromulate-http` does not depend on this crate, so
//! nothing here can be reached from the engine, and a third-party controller
//! needs `chromulate-http` alone.
//!
//! Depending on this crate is therefore a choice to take the shipped laws. A
//! caller who wants none of them implements
//! [`ConcurrencyController`] against `chromulate-http` and never names this
//! crate at all.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use chromulate_concurrency::{AdaptiveConcurrency, Ceiling};
//! use chromulate_http::concurrency::ConcurrencyController;
//!
//! # async fn run() {
//! let controller: Arc<dyn ConcurrencyController> =
//!     Arc::new(AdaptiveConcurrency::new(Ceiling::Unlimited));
//!
//! // `EngineBuilder::concurrency` takes exactly this, and the engine asks it
//! // for permission before every hop.
//! # let _ = controller;
//! # }
//! ```
//!
//! # Scope
//!
//! Nothing here varies a profile, a fingerprint, a header set or an identity in
//! response to a status code, and nothing here retries a refusal. These
//! controllers read what a server signals and stay *under* it. See the scope
//! boundary in `CLAUDE.md`.

#![doc(html_root_url = "https://docs.rs/chromulate-concurrency/0.3.0")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adaptive;
mod ceiling;
pub mod fixed;

pub use adaptive::{
    AdaptiveConcurrency, ConcurrencyConfig, DEFAULT_ORIGIN_CAPACITY, OriginSnapshot, Permit,
    Signal, retry_after_delay,
};
pub use ceiling::Ceiling;
pub use fixed::{DEFAULT_FIXED_CAPACITY, FixedConcurrency, FixedLease};

/// The seam these laws sit behind, re-exported so a caller who names this crate
/// does not have to name `chromulate-http` as well to write `Arc<dyn
/// ConcurrencyController>` or to read an [`Outcome`].
///
/// [`authority_of`] is here for the same reason: it is the key both laws below
/// use, and it belongs to the seam rather than to either of them.
pub use chromulate_http::concurrency::{
    ConcurrencyController, Lease, Outcome, Unlimited, authority_of,
};
