//! A browser-grade networking engine for Rust.
//!
//! Chromulate sends requests that look, on the wire, like the requests a modern
//! browser sends — the TLS ClientHello shape, the HTTP/2 settings and frame
//! behaviour, the header set and its ordering, the cookie semantics, the
//! compression negotiation — without embedding a browser. There is no Chromium,
//! no Blink, no V8, no DOM, and no JavaScript engine.
//!
//! # A caller picks an identity, and everything else follows
//!
//! ```no_run
//! use chromulate::Client;
//!
//! # async fn run() -> chromulate::Result<()> {
//! let client = Client::chrome()?;
//! let response = client.get("https://example.com").send().await?;
//!
//! println!("{} {:?}", response.status(), response.version());
//! println!("{}", response.text().await?);
//! # Ok(())
//! # }
//! ```
//!
//! That one call settles the TLS shape, the HTTP/2 settings and window sizes,
//! the header set and its exact order, the client hint brands, the `Accept`,
//! `Accept-Language` and `Accept-Encoding` values, and the cookie policy, as one
//! coherent profile. Coherence is the point: a client sending a Chrome user
//! agent over a non-Chrome handshake has not emulated a browser, it has
//! produced an identity that exists nowhere and is more distinctive than either
//! of the things it mixed.
//!
//! # How close does it actually get?
//!
//! Not all the way, and the crate says so in code rather than in a footnote.
//! Two accessors report the distance between the profile's target and what this
//! stack puts on the wire:
//!
//! ```no_run
//! use chromulate::tls::TlsBackendConfig;
//!
//! # async fn run() -> chromulate::Result<()> {
//! let client = chromulate::Client::chrome()?;
//!
//! // The handshake: rustls builds its own ClientHello and takes no
//! // instruction on its shape. `fidelity` is a trait method, so the trait is
//! // in scope — the default backend also has an inherent one, and relying on
//! // that is what breaks a build whose `ActiveBackend` is something else.
//! println!("{}", TlsBackendConfig::fidelity(client.engine().tls()));
//!
//! // The HTTP/2 preface: hyper accepts some of it and hard-codes the rest.
//! for gap in &client.engine().http2_fidelity().unsupported {
//!     println!("cannot reproduce: {gap}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Neither list is empty for the profile this workspace ships. The header
//! ordering, cookie semantics, compression negotiation and HTTP/2 SETTINGS
//! values *are* reproduced exactly; the ClientHello byte layout and the HTTP/2
//! pseudo-header order are not. See the crate-level docs of
//! [`chromulate_tls`] and [`chromulate_http`] for the measured detail.
//!
//! # Configuring explicitly
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use chromulate::{Client, Profile};
//!
//! # fn run() -> chromulate::Result<()> {
//! let client = Client::builder()
//!     .profile(Profile::chrome_stable())
//!     .cookie_store(true)
//!     .timeout(Duration::from_secs(30))
//!     .proxy("socks5h://user:pass@127.0.0.1:1080")?
//!     .build()?;
//! # let _ = client;
//! # Ok(())
//! # }
//! ```
//!
//! # Streaming
//!
//! ```no_run
//! use futures_util::StreamExt;
//!
//! # async fn run(client: chromulate::Client, url: &str) -> chromulate::Result<()> {
//! let mut stream = client.get(url).send().await?.bytes_stream();
//! while let Some(chunk) = stream.next().await {
//!     let chunk = chunk?;
//!     // write it somewhere; nothing is buffered in memory
//!     let _ = chunk.len();
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Scope
//!
//! Chromulate reproduces standards-compliant browser networking behaviour so
//! that crawlers, monitors, and research tools observe the same protocol
//! surface a browser would. It is not built to defeat security controls, and
//! contributions framed around evading a specific defence are out of scope.

#![doc(html_root_url = "https://docs.rs/chromulate/0.3.0")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
#[cfg(feature = "multipart")]
pub mod multipart;
mod request;
mod response;

pub use client::{Client, ClientBuilder, DEFAULT_MAX_RESPONSE_SIZE};
pub use request::RequestBuilder;
pub use response::{BodyStream, Response};
#[cfg(feature = "early-stop")]
pub use response::{Prefix, Stop, StopReason};

pub use chromulate_core::{
    Body, BoxError, BoxFuture, Error, Exchange, FetchDest, FetchMode, Middleware, Next, Origin,
    RedirectPolicy, Request, RequestOptions, Resolve, Response as HttpResponse, Result, Timings,
};
/// Re-exported beside [`Client`] rather than left in the `engine` module: it is
/// the answer to "does each of my proxies get its own cookies", which is a
/// question asked at the same call site as `proxy_pool`.
pub use chromulate_http::ProxyIsolation;
pub use chromulate_profile::{CHROME_STABLE_CAPTURE, Platform, Profile, ProfileRegistry};

/// The cookie jar and its vocabulary.
pub mod cookie {
    pub use chromulate_cookie::{
        Clock, CookieContext, CookieRecord, CookieStore, Jar, JarLimits, JarSnapshot, SameSite,
        SystemClock,
    };
}

/// Connection pooling, retries, and rate limiting.
pub mod engine {
    /// Also [`crate::challenge::Hop`], and deliberately in both places: `Hop` is
    /// defined beside the detection vocabulary, but the reason a caller needs to
    /// *name* it is [`ResponseInfo::hops`], which is here. A type you can only
    /// reach through the module you were not looking in is a type callers
    /// re-declare.
    pub use chromulate_http::challenge::Hop;
    /// The challenge middleware and its cleared-origin callback.
    ///
    /// Here rather than in [`crate::challenge`] because this is where the other
    /// middleware live, and installing one is the same call site as installing
    /// [`Retry`] or [`RateLimiter`].
    pub use chromulate_http::middleware::{ChallengeHandoff, Cleared};
    pub use chromulate_http::{
        ConnectionIdentity, Engine, EngineBuilder, EngineConfig, HstsStore, Http2Fidelity, Pool,
        PoolConfig, PoolKey, Protocol, RateLimit, RateLimiter, RequestUrl, ResponseInfo, Retry,
        RetryOn, RetryPolicy, RouteSession, SessionFactory, UnsupportedSetting,
    };
}

/// Detecting a bot challenge, and handing the page to a browser you installed.
///
/// The whole seam is always here — [`ChallengeDetector`](challenge::ChallengeDetector)
/// and [`BrowserFallback`](challenge::BrowserFallback), the
/// [`Observation`](challenge::Observation) a detector reads, and the
/// [`Handoff`](challenge::Handoff) / [`Handback`](challenge::Handback) pair a
/// fallback speaks. Writing either half against a browser this project has never
/// heard of needs no feature. `CloudflareDetector`, the one shipped detector,
/// arrives with the `challenge-detectors` feature, which pulls in
/// `chromulate-challenge`.
///
/// # This does not clear challenges by itself
///
/// Chromulate cannot execute JavaScript and does not pretend to. What the seam
/// does is notice a challenge, name it precisely, and hand it to something the
/// caller chose — a real browser, a service, a queue a person works through. No
/// solver ships here, no browser is bundled, and there is no flag that makes a
/// request undetectable. A client with a detector installed and no fallback
/// stops at the challenge, which is the honest outcome and a supported one.
///
/// # Installing it
///
/// By hand, as a middleware, for this release. There is deliberately no
/// `ClientBuilder::challenge(...)`: a builder method is permanent public surface
/// and the measurement that would say what its arguments should be has not been
/// run. See [`crate::engine::ChallengeHandoff`].
///
/// # Writing a detector without enabling anything
///
/// This example is compiled under the crate's **default** features, which do not
/// include `challenge-detectors`. That is the point of it: if the seam ever stops
/// being reachable without the feature, this stops compiling.
///
/// ```
/// use chromulate::challenge::{
///     Challenge, ChallengeDetector, ChallengeKind, Detection, Evidence, Observation,
/// };
///
/// /// One header the vendor documents, and no conclusion it did not state.
/// #[derive(Debug)]
/// struct Mitigated;
///
/// impl ChallengeDetector for Mitigated {
///     fn inspect(&self, observation: &Observation<'_>) -> Detection {
///         if observation.headers().get("cf-mitigated").map(|v| v.as_bytes())
///             != Some(b"challenge".as_slice())
///         {
///             return Detection::Clear;
///         }
///         Detection::Challenged(Challenge::new(
///             ChallengeKind::Unknown,
///             observation.origin().clone(),
///             Evidence::from_signal("cf-mitigated: challenge"),
///         ))
///     }
/// }
/// ```
///
/// Note what is *not* in that example: no `Origin::of`, and so no error branch
/// for a URL that cannot have one. The origin arrives with the observation. Note
/// also [`ChallengeKind::Unknown`](challenge::ChallengeKind::Unknown) rather than
/// a guess — `cf-mitigated: challenge` proves a challenge happened and says
/// nothing about which kind, and inventing the kind would be inventing a fact.
pub mod challenge {
    #[cfg(feature = "challenge-detectors")]
    pub use chromulate_challenge::{CloudflareDetector, cloudflare};
    pub use chromulate_http::challenge::{
        BrowserFallback, Challenge, ChallengeDetector, ChallengeKind, ChallengeKinds, Content,
        DeclineReason, Detection, Evidence, FallbackIdentity, Handback, Handoff, HandoffPolicy,
        Hop, Observation, ProxyExit,
    };
}

/// Per-origin concurrency: the seam, and the two laws behind it.
///
/// `ConcurrencyController`, `Lease`, `Outcome` and `Unlimited` are always here —
/// they are the trait
/// [`ClientBuilder::concurrency`](crate::ClientBuilder::concurrency) takes, and a
/// caller writing a controller of their own needs nothing else. The two shipped
/// laws — `AdaptiveConcurrency`, `FixedConcurrency`, and the `Ceiling` they take
/// — arrive with the `adaptive-concurrency` feature, which pulls in
/// `chromulate-concurrency`.
pub mod concurrency {
    #[cfg(feature = "adaptive-concurrency")]
    pub use chromulate_concurrency::{
        AdaptiveConcurrency, Ceiling, ConcurrencyConfig, DEFAULT_FIXED_CAPACITY,
        DEFAULT_ORIGIN_CAPACITY, FixedConcurrency, FixedLease, OriginSnapshot, Permit, Signal,
        adaptive, fixed,
    };
    pub use chromulate_http::concurrency::{
        ConcurrencyController, Lease, Outcome, Unlimited, authority_of,
    };
}

/// Proxy configuration and rotation.
pub mod proxy {
    pub use chromulate_proxy::{
        NoProxy, Proxy, ProxyEnvironment, ProxyProvider, ProxyScheme, ProxyUrl, Random, RoundRobin,
        Single,
    };
}

/// DNS resolution.
pub mod dns {
    pub use chromulate_dns::{
        CachingResolver, IpVersionPreference, StaticResolver, SystemResolver,
    };
}

/// TLS configuration, and the fidelity report that goes with it.
pub mod tls {
    pub use chromulate_tls::{
        ActiveBackend, Fidelity, HandshakeInfo, RootSource, STRUCTURAL_LIMITS, SessionStore,
        TargetIdentity, TlsBackend, TlsBackendConfig, TlsEngine, TlsEngineBuilder, TrustPolicy,
    };
}

/// Fingerprint computation, for reporting what a profile targets.
pub mod fingerprint {
    pub use chromulate_fingerprint::{
        ClientHelloSpec, Http2Spec, akamai_http2, akamai_http2_hash, ja3, ja3_hash, ja4, ja4_raw,
    };
}

/// Response decompression limits.
pub mod compression {
    pub use chromulate_compression::{
        BROWSER_CODING_ORDER, ContentCoding, ExpansionGuard, accept_encoding_value,
    };
}

/// The `http` and `url` types that appear in this crate's signatures.
///
/// Depending on them through Chromulate rather than directly stops a dependent
/// crate from accidentally linking two incompatible versions.
pub mod header {
    pub use chromulate_core::reexport::{
        Bytes, BytesMut, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Url, Version,
    };
}

pub use chromulate_core::reexport::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Url, Version,
};

/// The README's Rust examples, compiled.
///
/// The status banner claims the examples compile. That was an assertion about
/// a file nothing checked — `README.md` is not otherwise wired into rustdoc, so
/// its code blocks were prose that happened to look like Rust, and one of them
/// did not compile, using three variables it never declared.
///
/// Attaching the file as documentation turns each Rust block into a doctest, so
/// a change that breaks an example fails `cargo test` rather than being found
/// by whoever copies it first. The module is private and hidden: it exists for
/// the doctests, not to duplicate the README into the API documentation.
#[doc = include_str!("../../../README.md")]
#[doc(hidden)]
mod readme_examples {}
