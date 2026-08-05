//! The Chromulate HTTP engine.
//!
//! Every other crate in the workspace models one part of what a browser puts on
//! the wire. This one is where those parts become a request: it opens the
//! connection with [`chromulate_tls`], orders the headers with
//! [`chromulate_header`], follows redirects, reads and replays cookies,
//! decodes the body with [`chromulate_compression`], and pools what it opened
//! for the next request.
//!
//! # The pool key is the whole point
//!
//! A connection carries the TLS handshake and the HTTP/2 SETTINGS preface that
//! were sent when it was opened, once, for one identity. Reuse it for a request
//! configured with a different profile and that request is observed with the
//! *first* profile's fingerprint. [`PoolKey`] therefore covers the origin, the
//! proxy, the profile identity and the protocol together, and narrowing it to
//! the origin — the obvious simplification — silently destroys the property the
//! project exists to provide.
//!
//! # What this crate cannot reproduce
//!
//! hyper's HTTP/2 client accepts some of a profile's preface and hard-codes the
//! rest. Rather than apply what fits and stay quiet about the remainder,
//! [`Engine::http2_fidelity`] reports every part of the profile's preface this
//! build cannot send — including the pseudo-header order, which h2 emits as
//! `:method :scheme :authority :path` from a fixed struct order while Chrome
//! sends `:method :authority :scheme :path`. That gap holds for the profile
//! this workspace ships, so the reported list is never empty.
//! [`chromulate_tls::TlsEngine::fidelity`] reports the equivalent gap in the
//! handshake.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use chromulate_core::Body;
//! use chromulate_http::{Engine, EngineConfig};
//! use chromulate_profile::Profile;
//!
//! # async fn run() -> Result<(), chromulate_core::Error> {
//! let engine = Engine::builder(EngineConfig::new(Arc::new(Profile::chrome_stable()))).build()?;
//!
//! // `chromulate_core::Request` is an alias for `http::Request<Body>`, and
//! // `builder()` is only defined on `http::Request<()>`.
//! let request = http::Request::builder()
//!     .uri("https://example.com/")
//!     .body(Body::empty())
//!     .map_err(|error| chromulate_core::Error::builder(error.to_string()))?;
//!
//! let response = engine.send(request).await?;
//! println!("{} over {:?}", response.status(), response.version());
//! # Ok(())
//! # }
//! ```

#![doc(html_root_url = "https://docs.rs/chromulate-http/0.1.0")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "adaptive-concurrency")]
pub mod adaptive;
mod body;
mod connect;
mod deadline;
mod engine;
pub mod hsts;
pub mod http2;
pub mod middleware;
pub mod pool;
pub mod redirect;
pub mod session;
pub mod time;
#[cfg(feature = "validator-store")]
pub mod validators;

#[cfg(feature = "adaptive-concurrency")]
pub use adaptive::{
    AdaptiveConcurrency, Ceiling, ConcurrencyConfig, DEFAULT_ORIGIN_CAPACITY, Permit, Signal,
};
#[cfg(feature = "early-stop")]
pub use body::{Prefix, Stop, StopReason};
pub use engine::{Engine, EngineBuilder, EngineConfig, RequestUrl, ResponseInfo};
pub use hsts::{DEFAULT_HOST_CAPACITY, HstsStore};
pub use http2::{DEFAULT_CONNECTION_WINDOW, Http2Fidelity, UnsupportedSetting};
pub use middleware::{RateLimit, RateLimiter, Retry, RetryOn, RetryPolicy};
pub use pool::{ConnectionIdentity, Pool, PoolConfig, PoolKey, Protocol};
pub use redirect::{CREDENTIAL_HEADERS, crosses_origin, is_redirect, method_after};
pub use session::{ProxyIsolation, SessionFactory};
pub use time::{Clock, Sleeper, SystemClock, TimeSource, TokioSleeper};
#[cfg(feature = "validator-store")]
pub use validators::{DEFAULT_URL_CAPACITY, ValidatorStore, Validators};

/// The cache this engine drives, re-exported so a caller enabling the `cache`
/// feature does not have to name `chromulate-cache` in their own manifest.
///
/// Read its documentation before turning the feature on: it lists what of
/// RFC 9111 it deliberately does not implement.
#[cfg(feature = "cache")]
pub use chromulate_cache::{CacheConfig, CacheStatus, CacheStorage, HttpCache, MemoryStore};
