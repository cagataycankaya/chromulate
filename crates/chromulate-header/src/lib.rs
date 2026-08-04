//! Turning a captured browser [`chromulate_profile::Profile`] plus a
//! request's context into the exact, ordered header list that browser would
//! have sent.
//!
//! # Header order is the point
//!
//! `http::HeaderMap` is not an ordered map. Two headers inserted in one
//! order can iterate back out in a different one, because it stores entries
//! bucketed by name rather than as a list keyed by insertion. That is
//! invisible to virtually every HTTP client, since nothing in the HTTP/1.1
//! or HTTP/2 specifications gives header order any semantic meaning. It is
//! not invisible here: header order is one of the most reliable signals a
//! server-side fingerprinting tool uses to tell a real Chrome from an
//! impersonator, because real Chrome sends the same order every time and
//! most HTTP clients do not reproduce it at all.
//!
//! Because of that, [`HeaderEngine::apply`] cannot hand back a `HeaderMap`
//! as its authoritative result — doing so would silently discard the one
//! property this crate exists to get right. It returns a
//! `Vec<(HeaderName, HeaderValue)>` instead: an explicit, ordered list that
//! is the real answer to "what does this request send, and in what order?".
//! It also writes the same values onto the `http::Request` it is given, but
//! that is only a convenience for code that wants to look a header up by
//! name afterwards — the `Vec` is what a transport layer must serialize
//! headers from to actually reproduce the fingerprint on the wire.
//!
//! # What this crate computes
//!
//! - The low-entropy `Sec-CH-UA*` client hints, sent on every request, and
//!   the high-entropy ones (`Sec-CH-UA-Arch` and friends), sent only after a
//!   server asks for them with `Accept-CH` — see [`AcceptChStore`].
//! - `Sec-Fetch-Site`, by comparing registrable domains, not raw hostnames —
//!   see [`FetchSite`].
//! - `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, and `Sec-Fetch-User`, the last from
//!   [`UserActivatedNavigation`] since `chromulate_core::RequestOptions` has
//!   no field for it.
//! - `Accept` and `Priority`, which both vary by fetch destination.
//! - `Referer`, via `chromulate_core::referrer_for`, and `Origin` on
//!   cross-origin and unsafe-method requests.
//! - `Host`, present only on HTTP/1.x — HTTP/2 carries the authority in the
//!   `:authority` pseudo-header and never sends `Host` at all.
//!
//! Everything computed here is either transcribed from
//! `chromulate-fingerprint/tests/data/chrome-151-macos.json` through
//! `chromulate_profile::Profile`, or documented in the source as a decision
//! this crate made because that capture had nothing to observe for it — see
//! the crate's report for the specific gaps that leaves.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod accept;
mod client_hints;
mod engine;
mod fetch_site;
mod order;
mod priority;

pub use client_hints::{
    AcceptChLimits, AcceptChStore, DEFAULT_ORIGIN_CAPACITY, HighEntropyHint, HighEntropyHints,
    parse_accept_ch,
};
pub use engine::{HeaderEngine, UserActivatedNavigation};
pub use fetch_site::FetchSite;
