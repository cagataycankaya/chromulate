//! The two policies every client ends up needing.
//!
//! [`RateLimiter`] is a [`chromulate_core::Middleware`]. [`Retry`] is not, and
//! cannot be — see its module documentation for why, and
//! [`crate::EngineBuilder::retry`] for how it is installed instead.

pub mod rate_limit;
pub mod retry;

pub use rate_limit::{RateLimit, RateLimiter, middleware_error};
pub use retry::{Retry, RetryOn, RetryPolicy, Retrying};
