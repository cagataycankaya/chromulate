//! How many requests may be in flight, and who decides.
//!
//! The engine needs two things from whoever answers that question: permission
//! to send one request, and somewhere to report what came back. Everything else
//! — how the number is chosen, what a `429` means, whether a limit ever
//! recovers — is policy, and policy is not in this crate.
//!
//! [`ConcurrencyController`] is that boundary, and this module is the whole of
//! it: a trait, a lease, an observation, and the two helpers the engine wires
//! in. There is deliberately no control law here to compare an implementation
//! against, because a seam that ships beside its own implementation is one whose
//! users cannot tell which parts are the boundary.
//!
//! Two laws are published in the `chromulate-concurrency` crate —
//! `AdaptiveConcurrency`, which learns a limit per origin from latency and
//! treats a refusal as a one-way ratchet, and `FixedConcurrency`, which bounds
//! in-flight requests per origin at a number the caller chose. That crate
//! depends on this one; nothing here depends on it, which is what makes the
//! boundary checkable rather than asserted.
//!
//! [`Unlimited`] is here rather than there because it is not a law: it is the
//! absence of one, written down.
//!
//! # What the engine will not let a controller do
//!
//! A controller is consulted **inside** the engine's redirect loop, which sits
//! below the entire middleware chain. A [`crate::middleware::RateLimiter`] the
//! caller installed has therefore already spent its token before any controller
//! is asked, and the only thing a controller can do with the request afterwards
//! is make it wait longer. Nothing in this trait returns "send now regardless"
//! and nothing in it reaches the limiter. A seam that let a third-party
//! controller outrun a rate limit the caller configured would be a worse defect
//! than the one it was introduced to fix.
//!
//! # Writing one
//!
//! ```
//! use std::sync::Arc;
//!
//! use chromulate_core::BoxFuture;
//! use chromulate_http::concurrency::{ConcurrencyController, Lease, Outcome};
//! use tokio::sync::{OwnedSemaphorePermit, Semaphore};
//! use url::Url;
//!
//! /// Four requests in flight across every origin together.
//! #[derive(Debug)]
//! struct Global {
//!     slots: Arc<Semaphore>,
//! }
//!
//! /// The lease outlives the `&self` that produced it, so the state it needs is
//! /// held by `Arc` rather than borrowed.
//! #[derive(Debug)]
//! struct GlobalLease(Option<OwnedSemaphorePermit>);
//!
//! impl Lease for GlobalLease {
//!     fn complete(self: Box<Self>, _outcome: &Outcome<'_>) {
//!         // Nothing to learn: dropping the permit returns the slot.
//!     }
//! }
//!
//! impl ConcurrencyController for Global {
//!     fn acquire<'a>(&'a self, _url: &'a Url) -> BoxFuture<'a, Box<dyn Lease>> {
//!         let slots = Arc::clone(&self.slots);
//!         Box::pin(async move { Box::new(GlobalLease(slots.acquire_owned().await.ok())) as _ })
//!     }
//! }
//! ```

use std::fmt;

use chromulate_core::BoxFuture;
use http::{HeaderMap, StatusCode};
use url::{Position, Url};

/// The authority a controller keys an origin by: `host` or `host:port`.
///
/// The server's address rather than the web origin, because a server's capacity
/// is not per-scheme — `http://example.com` and `https://example.com` are one
/// machine with one budget. Userinfo is excluded, so a URL carrying credentials
/// does not put a password in a map key or in `Debug` output.
///
/// It sits with the trait rather than with either published law because it is
/// the key convention [`ConcurrencyController::acquire`] offers *every*
/// implementation, and a third-party controller that wants the same one must not
/// have to depend on somebody else's law to get it.
///
/// ```
/// use chromulate_http::concurrency::authority_of;
/// use url::Url;
///
/// let url = Url::parse("https://user:secret@example.com/a/b?c=d").unwrap();
/// assert_eq!(authority_of(&url), "example.com");
///
/// let url = Url::parse("https://example.com:8443/").unwrap();
/// assert_eq!(authority_of(&url), "example.com:8443");
/// ```
#[must_use]
pub fn authority_of(url: &Url) -> &str {
    &url[Position::BeforeHost..Position::BeforePath]
}

/// Decides how many requests to an origin may be in flight at once.
///
/// The engine asks for a [`Lease`] before each hop and reports the outcome
/// against it afterwards. It never inspects a limit, never learns one, and has
/// no opinion about what a status code means — that is the whole point of this
/// being a trait.
///
/// `acquire` takes the target [`Url`] rather than an authority so an
/// implementation may key on whatever it likes: a host, a host and port, a path
/// prefix, one bucket for everything. [`authority_of`] is the key the published
/// laws use, for an implementation that wants the same one.
///
/// # Cancellation
///
/// A lease that is dropped without [`Lease::complete`] must still return
/// whatever it took. The engine drops one on every transport error, because a
/// failure to connect may be this host's network rather than the origin's load,
/// and a controller that only released on `complete` would leak a slot per
/// failed request.
pub trait ConcurrencyController: Send + Sync + 'static {
    /// Waits for permission to send one request to `url`.
    ///
    /// Called once per hop — a redirect that crosses origins asks again for the
    /// origin it actually reaches — and never for a request answered from cache,
    /// because nothing was asked of the origin.
    fn acquire<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Box<dyn Lease>>;
}

impl fmt::Debug for dyn ConcurrencyController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConcurrencyController")
    }
}

/// Permission to have one request in flight, held for the length of that
/// request.
///
/// Dropping one must return whatever it took without teaching the controller
/// anything. [`Lease::complete`] returns it *and* reports what the origin did,
/// which is the only way a limit ever moves.
pub trait Lease: Send + 'static {
    /// Returns the lease and reports what came back.
    ///
    /// Consuming rather than borrowing, so a lease cannot be reported twice. An
    /// implementation whose `Drop` also releases must record that this ran.
    fn complete(self: Box<Self>, outcome: &Outcome<'_>);
}

impl fmt::Debug for dyn Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lease")
    }
}

/// What one completed request is known to have produced.
///
/// Deliberately not a verdict. A pre-classified signal — "healthy", "back off",
/// "refused" — is one control law's reading of a response, and handing that
/// across the seam would mean every third-party controller inherits some other
/// law's opinions about the status codes it happens to care about. `503` is
/// backpressure to the adaptive law in `chromulate-concurrency` and an ordinary
/// server error to a caller whose origin returns it while a deploy rolls; `403`
/// is a refusal there and an expired token elsewhere. Neither reading belongs in
/// the type both of them have to speak.
///
/// So this carries what was observed and nothing that was concluded: the status
/// code, and the response headers so a controller can read `Retry-After`,
/// `RateLimit-Remaining` or whatever its own policy is written against.
///
/// Latency is deliberately **absent**. A controller that wants it measures it
/// itself between `acquire` and `complete`, against its own clock — which is
/// what makes a controller with an injected clock testable without waiting.
/// Timing it in the engine would impose the engine's clock on every
/// implementation.
#[derive(Debug, Clone, Copy)]
pub struct Outcome<'a> {
    status: Option<StatusCode>,
    headers: Option<&'a HeaderMap>,
}

impl<'a> Outcome<'a> {
    /// The origin answered.
    ///
    /// ```
    /// use chromulate_http::concurrency::Outcome;
    /// use http::{HeaderMap, StatusCode};
    ///
    /// let headers = HeaderMap::new();
    /// let outcome = Outcome::answered(StatusCode::OK, &headers);
    /// assert_eq!(outcome.status(), Some(StatusCode::OK));
    /// ```
    #[must_use]
    pub fn answered(status: StatusCode, headers: &'a HeaderMap) -> Self {
        Self {
            status: Some(status),
            headers: Some(headers),
        }
    }

    /// The origin answered, read from the response itself.
    #[must_use]
    pub fn of<T>(response: &'a http::Response<T>) -> Self {
        Self::answered(response.status(), response.headers())
    }

    /// The request produced no response at all.
    ///
    /// The engine never reports this: a transport failure may be this host's
    /// network rather than the origin's load, so it drops the lease instead and
    /// teaches nothing. A caller who knows better can say so.
    ///
    /// ```
    /// use chromulate_http::concurrency::Outcome;
    ///
    /// assert_eq!(Outcome::failed().status(), None);
    /// ```
    #[must_use]
    pub fn failed() -> Self {
        Self {
            status: None,
            headers: None,
        }
    }

    /// What the origin answered with, or `None` when there was no response.
    #[must_use]
    pub fn status(&self) -> Option<StatusCode> {
        self.status
    }

    /// The response headers, or `None` when there was no response.
    #[must_use]
    pub fn headers(&self) -> Option<&'a HeaderMap> {
        self.headers
    }
}

/// A controller that never makes anything wait.
///
/// Behaviourally this is exactly equivalent to installing no controller at all:
/// every `acquire` resolves immediately and every `complete` does nothing. It is
/// not the cheaper of the two, though — an installed controller costs the
/// erasure the seam is built from, one boxed future and one boxed lease per hop,
/// which was measured at roughly 47 ns and two allocations. A caller who wants
/// no concurrency control should therefore install nothing rather than install
/// this.
///
/// It exists for the two cases where saying so out loud is worth those two
/// allocations:
///
/// - a configuration that chooses between controllers at run time and would
///   otherwise carry an `Option` through every layer to express "none";
/// - a third-party controller that delegates — a wrapper adding metrics, tracing
///   or a kill switch needs something to wrap when its own policy is disabled,
///   and this is that something.
///
/// ```
/// use chromulate_http::concurrency::{ConcurrencyController, Outcome, Unlimited};
/// use url::Url;
///
/// # async fn run() {
/// let url = Url::parse("https://example.com/").unwrap();
///
/// // A thousand outstanding leases would be as immediate as the first.
/// let first = Unlimited.acquire(&url).await;
/// let second = Unlimited.acquire(&url).await;
///
/// first.complete(&Outcome::failed());
/// drop(second);
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Unlimited;

/// The lease [`Unlimited`] issues, which holds nothing and returns nothing.
///
/// Private because there is nothing to do with one but complete it or drop it,
/// and the trait already says how.
#[derive(Debug)]
struct UnlimitedLease;

impl Lease for UnlimitedLease {
    fn complete(self: Box<Self>, _outcome: &Outcome<'_>) {
        // Nothing was taken, so there is nothing to return, and nothing here
        // learns. An `Unlimited` that recorded anything would be a law.
    }
}

impl ConcurrencyController for Unlimited {
    fn acquire<'a>(&'a self, _url: &'a Url) -> BoxFuture<'a, Box<dyn Lease>> {
        Box::pin(std::future::ready(
            Box::new(UnlimitedLease) as Box<dyn Lease>
        ))
    }
}

/// Takes a lease from a controller the caller may not have installed.
///
/// This and [`complete_from`] are the pair the engine wires in: one line before
/// the request and one after, the same two lines whether or not a controller is
/// configured. Without that, a call site holding an `Option` writes a `match` on
/// both sides and the wiring stops being something anyone wants to add.
///
/// ```
/// use std::sync::Arc;
///
/// use chromulate_http::concurrency::{self, ConcurrencyController, Unlimited};
/// use url::Url;
///
/// # async fn run() {
/// let installed: Arc<dyn ConcurrencyController> = Arc::new(Unlimited);
/// let url = Url::parse("https://example.com/").unwrap();
///
/// let lease = concurrency::acquire_from(Some(&*installed), &url).await;
/// assert!(lease.is_some());
///
/// // And with nothing configured, the same line costs nothing.
/// assert!(concurrency::acquire_from(None, &url).await.is_none());
/// # }
/// ```
pub async fn acquire_from(
    controller: Option<&dyn ConcurrencyController>,
    url: &Url,
) -> Option<Box<dyn Lease>> {
    match controller {
        Some(controller) => Some(controller.acquire(url).await),
        None => None,
    }
}

/// Reports a response against a lease the caller may not have taken.
///
/// The counterpart to [`acquire_from`]. A request that produced no response at
/// all reports nothing: dropping the lease returns the slot without teaching the
/// controller a verdict, which is the right answer when a transport failure
/// could equally be this host's network.
pub fn complete_from<T>(lease: Option<Box<dyn Lease>>, response: &http::Response<T>) {
    if let Some(lease) = lease {
        lease.complete(&Outcome::of(response));
    }
}
