//! What a permit may not exceed, however much a controller learns.

use std::fmt;
use std::sync::Arc;

use chromulate_http::middleware::RateLimiter;
use chromulate_http::time::TimeSource;

/// What a permit may not exceed however much a controller learns.
///
/// A caller who configured a rate limit configured a ceiling, and a controller's
/// job is to stay at or under it — never to discover it could go faster. Passing
/// one of these to a controller's constructor is not optional, and there is
/// deliberately no `Default`: a ceiling that can be forgotten is a rule someone
/// has to remember, and this is meant to be structural.
///
/// Every permit the controllers in this crate issue spends a token from the
/// limiter *before* it is granted, so a request that has not paid the caller's
/// rate cannot exist.
///
/// This belongs to the laws rather than to the seam. Nothing in
/// [`chromulate_http::concurrency`] mentions it, and a third-party controller is
/// free to have no ceiling concept at all — what the engine guarantees is that a
/// controller runs *below* the middleware chain, so a
/// [`RateLimiter`] the caller installed has already been paid before any
/// controller is asked.
#[derive(Clone)]
pub enum Ceiling {
    /// The caller configured no rate limit, so there is none to respect.
    ///
    /// A written choice rather than a defaulted one.
    Unlimited,
    /// Every permit spends a token from this limiter before it is issued.
    ///
    /// Share the same `Arc` the engine's [`RateLimiter`] middleware holds, so
    /// the two cannot disagree about how many requests have been spent.
    RateLimit(Arc<RateLimiter>),
}

impl Ceiling {
    /// Spends a token and waits for it, when there is a limiter to spend one
    /// from.
    pub(crate) async fn pay(&self, time: &TimeSource) {
        if let Self::RateLimit(limiter) = self {
            let wait = limiter.reserve();
            if !wait.is_zero() {
                time.sleep(wait).await;
            }
        }
    }
}

impl fmt::Debug for Ceiling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlimited => f.write_str("Unlimited"),
            Self::RateLimit(limiter) => f
                .debug_tuple("RateLimit")
                .field(&limiter.limit().per_second)
                .finish(),
        }
    }
}
