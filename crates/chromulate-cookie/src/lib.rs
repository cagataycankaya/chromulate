//! A browser-grade cookie jar implementing [`chromulate_core::CookieStore`].
//!
//! The hard part of a cookie jar is not storage, it is deciding which cookies apply: RFC
//! 6265 domain and path matching, the public-suffix rejection browsers layered on top of
//! it, `Secure`/`SameSite` eligibility, and a lenient date parser for the `Expires`
//! formats real servers still send. This crate implements those rules, plus the
//! eviction and ordering behaviour that keeps a long-running jar bounded and its
//! `Cookie` header deterministic.
//!
//! ```
//! use chromulate_core::{CookieContext, CookieStore};
//! use chromulate_cookie::Jar;
//! use http::HeaderValue;
//! use url::Url;
//!
//! let jar = Jar::new();
//! let url = Url::parse("https://example.com/").unwrap();
//! let set_cookie = HeaderValue::from_static("session=abc123; Path=/; HttpOnly");
//! jar.store(&url, &mut std::iter::once(&set_cookie));
//!
//! let context = CookieContext::conservative_default();
//! assert_eq!(jar.cookies_for(&url, &context).unwrap(), "session=abc123");
//! ```
//!
//! # `SameSite` and the trait boundary
//!
//! `SameSite` eligibility needs more than a target URL: it depends on the request's
//! initiator and on whether the request is a top-level navigation. Those two facts
//! reach the jar as the [`CookieContext`] every [`CookieStore::cookies_for`] call
//! carries. A caller that tracks neither passes
//! [`CookieContext::conservative_default`], whose trade-off is documented on that type;
//! a caller driving the engine gets one built from its request metadata by
//! `RequestOptions::cookie_context`.
//!
//! # Simplifications from the full standard
//!
//! - Same-site comparisons use the registrable domain only ("classic" same-site), not
//!   scheme as well ("schemeful" same-site).
//! - `SameSite=Lax`'s carve-out for cross-site top-level navigations is not additionally
//!   restricted to "safe" HTTP methods, because [`CookieStore::cookies_for`]'s signature
//!   carries no method.
//! - Cookie lifetime is capped at 400 days from the time it is set, matching Chrome's
//!   anti-tracking policy rather than RFC 6265, which places no ceiling on it.
//! - The `__Host-` name prefix (RFC 6265bis §5.7 step 21) is enforced against the
//!   cookie's *resolved* path rather than requiring a literal `Path` attribute, matching
//!   Chromium. `__Host-x=1; Secure` set from `/` resolves to `Path=/` and is accepted.

#![doc(html_root_url = "https://docs.rs/chromulate-cookie/0.3.0")]
#![warn(missing_docs)]

mod clock;
mod cookie;
mod date;
mod domain;
mod jar;
mod path;
mod same_site;

pub use chromulate_core::{CookieContext, CookieStore};
pub use clock::{Clock, SystemClock};
pub use jar::{CookieRecord, Jar, JarLimits, JarSnapshot};
pub use same_site::SameSite;
