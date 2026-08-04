//! The extension points third parties implement without forking the engine.
//!
//! Every trait here is object safe and returns a boxed future rather than using an
//! `async fn` in trait position. That choice costs one allocation per call at the
//! extension boundary and buys the ability to store heterogeneous implementations in a
//! `Vec`, swap them at runtime, and keep the engine's own generics from leaking into
//! plugin signatures.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use http::HeaderValue;
use url::Url;

use crate::error::Result;
use crate::request::{CookieContext, Request, Response};

/// A boxed future returned by the extension traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A hostname and port awaiting resolution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostPort {
    host: Arc<str>,
    port: u16,
}

impl HostPort {
    /// Creates a resolution target.
    pub fn new(host: impl Into<Arc<str>>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// The hostname, without brackets for IPv6 literals.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Turns hostnames into socket addresses.
///
/// Implement this to plug in DNS-over-HTTPS, a fixed host map for testing, or a
/// service-discovery backend.
pub trait Resolve: Send + Sync + 'static {
    /// Resolves a target to one or more addresses, in the order they should be tried.
    fn resolve(&self, target: HostPort) -> BoxFuture<'_, Result<Vec<SocketAddr>>>;
}

/// Stores and replays cookies across requests.
pub trait CookieStore: Send + Sync + 'static {
    /// The `Cookie` header value to send with a request to `url`, if any.
    ///
    /// `context` carries what `SameSite` eligibility needs beyond the target URL: who
    /// initiated the request, and whether it is a top-level navigation. An
    /// implementation that does not model `SameSite` is free to ignore it. One that does
    /// should read [`CookieContext::conservative_default`] as "the caller knows nothing
    /// about the site relationship", not as "this request is cross-site".
    fn cookies_for(&self, url: &Url, context: &CookieContext) -> Option<HeaderValue>;

    /// Records the `Set-Cookie` headers from a response.
    fn store(&self, url: &Url, set_cookie: &mut dyn Iterator<Item = &HeaderValue>);
}

/// The terminal stage of the middleware chain: the component that actually performs the
/// network exchange.
pub trait Exchange: Send + Sync {
    /// Sends the request and returns the response head with a streaming body.
    fn exchange(&self, request: Request) -> BoxFuture<'_, Result<Response>>;
}

/// The remainder of the middleware chain.
///
/// Call [`Next::run`] to continue, or return early to short-circuit the request. A
/// middleware that never calls `run` is a valid cache or mock.
///
/// `Next` is [`Copy`], so `run` may be called more than once. That is deliberate and it is
/// what makes retry, hedging, circuit-breaking, and fallback middleware expressible: each
/// needs to drive the rest of the chain several times from one `handle` call. Both fields
/// are shared references, so copying is free.
///
/// Re-running the chain re-runs every middleware below this one, which is usually what a
/// retry wants. The request itself is not copied — the caller is responsible for producing
/// each attempt's `Request`, and [`crate::Body::try_clone`] is how it finds out whether the
/// body can be replayed at all.
#[derive(Clone, Copy)]
pub struct Next<'a> {
    remaining: &'a [Arc<dyn Middleware>],
    terminal: &'a dyn Exchange,
}

impl fmt::Debug for Next<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Next")
            .field("remaining", &self.remaining.len())
            .finish_non_exhaustive()
    }
}

impl<'a> Next<'a> {
    /// Builds the head of a chain over `middleware`, terminating at `terminal`.
    pub fn new(middleware: &'a [Arc<dyn Middleware>], terminal: &'a dyn Exchange) -> Self {
        Self {
            remaining: middleware,
            terminal,
        }
    }

    /// Passes the request to the next middleware, or to the transport when the chain is
    /// exhausted.
    pub fn run(self, request: Request) -> BoxFuture<'a, Result<Response>> {
        match self.remaining.split_first() {
            Some((head, tail)) => head.handle(
                request,
                Next {
                    remaining: tail,
                    terminal: self.terminal,
                },
            ),
            None => self.terminal.exchange(request),
        }
    }
}

/// Observes or rewrites requests and responses as they pass through the engine.
///
/// Middleware runs outside the redirect loop, so a chain sees one logical request even
/// when the engine follows several hops to satisfy it.
pub trait Middleware: Send + Sync + 'static {
    /// A stable name used in error messages, logs, and metrics.
    fn name(&self) -> &'static str;

    /// Handles the request, optionally delegating to the rest of the chain.
    fn handle<'a>(&'a self, request: Request, next: Next<'a>) -> BoxFuture<'a, Result<Response>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::Body;
    use http::StatusCode;

    struct DirectExchange;

    impl Exchange for DirectExchange {
        fn exchange(&self, _request: Request) -> BoxFuture<'_, Result<Response>> {
            Box::pin(async {
                Ok(http::Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::fixed("origin"))
                    .expect("response should build"))
            })
        }
    }

    struct TagHeader(&'static str);

    impl Middleware for TagHeader {
        fn name(&self) -> &'static str {
            "tag-header"
        }

        fn handle<'a>(
            &'a self,
            mut request: Request,
            next: Next<'a>,
        ) -> BoxFuture<'a, Result<Response>> {
            Box::pin(async move {
                request
                    .headers_mut()
                    .insert("x-tag", HeaderValue::from_static("seen"));
                let mut response = next.run(request).await?;
                response
                    .headers_mut()
                    .insert("x-handled-by", HeaderValue::from_static(self.0));
                Ok(response)
            })
        }
    }

    struct ShortCircuit;

    impl Middleware for ShortCircuit {
        fn name(&self) -> &'static str {
            "short-circuit"
        }

        fn handle<'a>(
            &'a self,
            _request: Request,
            _next: Next<'a>,
        ) -> BoxFuture<'a, Result<Response>> {
            Box::pin(async {
                Ok(http::Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Body::empty())
                    .expect("response should build"))
            })
        }
    }

    #[tokio::test]
    async fn a_chain_runs_in_order_and_reaches_the_transport() {
        let chain: Vec<Arc<dyn Middleware>> = vec![Arc::new(TagHeader("outer"))];
        let terminal = DirectExchange;
        let next = Next::new(&chain, &terminal);

        let response = next
            .run(http::Request::new(Body::empty()))
            .await
            .expect("chain should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-handled-by"], "outer");
    }

    #[tokio::test]
    async fn a_middleware_can_short_circuit_without_touching_the_network() {
        let chain: Vec<Arc<dyn Middleware>> =
            vec![Arc::new(ShortCircuit), Arc::new(TagHeader("unreached"))];
        let terminal = DirectExchange;
        let next = Next::new(&chain, &terminal);

        let response = next
            .run(http::Request::new(Body::empty()))
            .await
            .expect("chain should succeed");

        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(!response.headers().contains_key("x-handled-by"));
    }

    struct RetryTwice;

    impl Middleware for RetryTwice {
        fn name(&self) -> &'static str {
            "retry-twice"
        }

        fn handle<'a>(
            &'a self,
            request: Request,
            next: Next<'a>,
        ) -> BoxFuture<'a, Result<Response>> {
            Box::pin(async move {
                // The whole point of `Next: Copy`: drive the rest of the chain more than
                // once from a single `handle` call.
                let first = next.run(http::Request::new(Body::empty())).await?;
                drop(first);
                next.run(request).await
            })
        }
    }

    #[tokio::test]
    async fn a_middleware_can_run_the_rest_of_the_chain_more_than_once() {
        let chain: Vec<Arc<dyn Middleware>> = vec![Arc::new(RetryTwice)];
        let terminal = CountingExchange::default();
        let next = Next::new(&chain, &terminal);

        let response = next
            .run(http::Request::new(Body::empty()))
            .await
            .expect("chain should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            terminal.calls.load(Ordering::SeqCst),
            2,
            "a retry middleware must be able to reach the transport twice"
        );
    }

    #[derive(Default)]
    struct CountingExchange {
        calls: AtomicUsize,
    }

    impl Exchange for CountingExchange {
        fn exchange(&self, _request: Request) -> BoxFuture<'_, Result<Response>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(http::Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .expect("response should build"))
            })
        }
    }

    #[test]
    fn ipv6_targets_are_bracketed_when_displayed() {
        assert_eq!(HostPort::new("::1", 443).to_string(), "[::1]:443");
        assert_eq!(
            HostPort::new("example.com", 80).to_string(),
            "example.com:80"
        );
    }
}
