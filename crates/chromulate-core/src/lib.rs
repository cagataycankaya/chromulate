//! Core types shared by every Chromulate engine.
//!
//! This crate deliberately contains no I/O. It defines the vocabulary the other crates
//! agree on - the error hierarchy, the streaming body, per-request browser fetch
//! context, and the traits third parties implement - so that the engines can be
//! developed, tested, and replaced independently of one another.
//!
//! ```
//! use chromulate_core::{Body, Error, Phase};
//!
//! let body = Body::fixed("hello");
//! assert_eq!(body.content_length(), Some(5));
//!
//! // Transport faults before the origin saw the request are worth retrying.
//! assert!(Error::Timeout(Phase::Connect).is_retryable());
//! ```

#![doc(html_root_url = "https://docs.rs/chromulate-core/0.3.0")]
#![warn(missing_docs)]

pub mod body;
pub mod error;
pub mod request;
pub mod timings;
pub mod traits;
pub mod uri;

pub use body::{Body, body_error};
pub use error::{BoxError, Error, Phase, Result};
pub use request::{
    CookieContext, FetchDest, FetchMode, RedirectPolicy, Request, RequestOptions, Response,
};
pub use timings::Timings;
pub use traits::{BoxFuture, CookieStore, Exchange, HostPort, Middleware, Next, Resolve};
pub use uri::{Origin, referrer_for};

/// Re-exports of the third-party types that appear in Chromulate's public API.
///
/// Depending on these through Chromulate rather than directly keeps a downstream crate
/// from accidentally linking two incompatible versions of `http` or `bytes`.
pub mod reexport {
    pub use bytes::{Bytes, BytesMut};
    pub use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version};
    pub use url::Url;
}
