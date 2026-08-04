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

/// Returns the `Accept` value for `dest`.
///
/// `document_accept` is the profile's own captured value for a document
/// navigation, reused verbatim for [`FetchDest::Document`] and
/// [`FetchDest::Iframe`] since a nested document is fetched the same way a
/// top-level one is.
pub(crate) fn accept_for(dest: FetchDest, document_accept: &str) -> String {
    match dest {
        FetchDest::Document | FetchDest::Iframe => document_accept.to_owned(),
        FetchDest::Style => STYLE.to_owned(),
        FetchDest::Image => IMAGE.to_owned(),
        // `FetchDest::Script | Font | Empty`, plus any destination a future
        // version of `FetchDest` adds (it is `#[non_exhaustive]`): all get
        // the same wildcard a script or a programmatic fetch gets, which is
        // also Chromium's own fallback.
        _ => WILDCARD.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT_ACCEPT: &str = "text/html,application/xhtml+xml";

    #[test]
    fn document_script_style_and_image_each_get_a_distinct_accept_value() {
        // This test checks the mechanism — that each destination routes to
        // its own value and no two collide — not the fidelity of the
        // uncaptured constants themselves. `document` is the only one
        // checked against a specific expected string, because it is the
        // only one this crate's capture actually observed; see the module
        // docs for why the others are not asserted against a fixed value.
        let document = accept_for(FetchDest::Document, DOCUMENT_ACCEPT);
        let script = accept_for(FetchDest::Script, DOCUMENT_ACCEPT);
        let style = accept_for(FetchDest::Style, DOCUMENT_ACCEPT);
        let image = accept_for(FetchDest::Image, DOCUMENT_ACCEPT);

        assert_eq!(
            document, DOCUMENT_ACCEPT,
            "the document value must be the profile's captured value, verbatim"
        );

        let values = [&document, &script, &style, &image];
        for (i, a) in values.iter().enumerate() {
            for (j, b) in values.iter().enumerate() {
                assert!(i == j || a != b, "accept values must be pairwise distinct");
            }
        }
    }

    #[test]
    fn an_iframe_is_fetched_like_a_document() {
        assert_eq!(
            accept_for(FetchDest::Iframe, DOCUMENT_ACCEPT),
            DOCUMENT_ACCEPT
        );
    }
}
