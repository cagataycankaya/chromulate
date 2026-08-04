//! Per-destination `Accept` header values.
//!
//! A browser asks for a different media type depending on what it is
//! fetching: a navigation wants HTML, a stylesheet request wants CSS, and so
//! on. `chrome-151-macos.json` recorded exactly one request — a navigation —
//! so only the document row below has a capture behind it:
//!
//! | Destination | Value | Status |
//! |---|---|---|
//! | [`FetchDest::Document`], [`FetchDest::Iframe`] | the profile's own `accept` field | **Captured** — this is `chrome-151-macos.json`'s `observed_header_values.accept`, used verbatim |
//! | [`FetchDest::Style`] | `text/css,*/*;q=0.1` | NOT captured — general protocol knowledge pending a capture |
//! | [`FetchDest::Image`] | `image/avif,image/webp,image/apng,image/svg+xml,*/*;q=0.8` | NOT captured — general protocol knowledge pending a capture |
//! | [`FetchDest::Script`], [`FetchDest::Font`], [`FetchDest::Empty`] | `*/*` | NOT captured — general protocol knowledge pending a capture |
//!
//! The non-document rows exist because [`crate::HeaderEngine`] needs *some*
//! `Accept` value for every destination it can be asked to build a request
//! for, and a request with the right shape of value is more useful than one
//! with none — but they are a modeling choice, not a fact this repository
//! has verified against a real browser. Treat them as a tracked gap (see the
//! crate's report) rather than as fingerprint data, and do not write a test
//! that asserts one of them against a browser: there is nothing in this
//! repository to check it against.

use chromulate_core::FetchDest;

/// The stylesheet `Accept` value Chromium browsers send.
const STYLE: &str = "text/css,*/*;q=0.1";

/// The image `Accept` value Chromium browsers send.
const IMAGE: &str = "image/avif,image/webp,image/apng,image/svg+xml,*/*;q=0.8";

/// The `Accept` value Chromium browsers send for a destination with no
/// distinct media type of its own, such as a script or a programmatic
/// fetch.
const WILDCARD: &str = "*/*";

/// Returns the uncaptured fallback `Accept` value for `dest`, or `None` for
/// the destinations whose value is the profile's own captured `accept` —
/// [`FetchDest::Document`] and [`FetchDest::Iframe`], since a nested
/// document is fetched the same way a top-level one is.
///
/// Every returned value is a static, so the engine can encode it without
/// allocating.
pub(crate) const fn accept_fallback(dest: FetchDest) -> Option<&'static str> {
    match dest {
        FetchDest::Document | FetchDest::Iframe => None,
        FetchDest::Style => Some(STYLE),
        FetchDest::Image => Some(IMAGE),
        // `FetchDest::Script | Font | Empty`, plus any destination a future
        // version of `FetchDest` adds (it is `#[non_exhaustive]`): all get
        // the same wildcard a script or a programmatic fetch gets, which is
        // also Chromium's own fallback.
        _ => Some(WILDCARD),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_documents_and_iframes_use_the_profiles_captured_value() {
        // `None` routes the engine to the profile's own captured `accept`;
        // that the engine really emits it verbatim is asserted by the
        // integration test against the capture, not here.
        assert_eq!(accept_fallback(FetchDest::Document), None);
        assert_eq!(accept_fallback(FetchDest::Iframe), None);
    }

    #[test]
    fn script_style_and_image_each_get_a_distinct_fallback_value() {
        // This test checks the mechanism — that each destination routes to
        // its own value and no two collide — not the fidelity of the
        // uncaptured constants themselves; see the module docs for why they
        // are not asserted against fixed strings.
        let script = accept_fallback(FetchDest::Script).expect("scripts use a fallback");
        let style = accept_fallback(FetchDest::Style).expect("styles use a fallback");
        let image = accept_fallback(FetchDest::Image).expect("images use a fallback");

        let values = [script, style, image];
        for (i, a) in values.iter().enumerate() {
            for (j, b) in values.iter().enumerate() {
                assert!(i == j || a != b, "accept values must be pairwise distinct");
            }
        }
    }
}
