//! Per-destination `Priority` header values (RFC 9218).
//!
//! `chrome-151-macos.json` recorded exactly one request — a navigation — so
//! only the document row below has a capture behind it:
//!
//! | Destination | Value | Status |
//! |---|---|---|
//! | [`FetchDest::Document`], [`FetchDest::Iframe`] | `u=0, i` | **Captured** — `chrome-151-macos.json`'s `observed_header_values.priority`, verbatim |
//! | [`FetchDest::Style`], [`FetchDest::Font`] | `u=0` | NOT captured — general protocol knowledge pending a capture |
//! | [`FetchDest::Script`] | `u=1` | NOT captured — general protocol knowledge pending a capture |
//! | [`FetchDest::Image`], [`FetchDest::Empty`], anything else | `u=3` | NOT captured — general protocol knowledge pending a capture |
//!
//! The non-document rows are Chromium's long-published mapping from its
//! internal resource priority to an RFC 9218 urgency (`VeryHigh` down to
//! `VeryLow` maps to `u=0` through `u=4`), not a value this repository's own
//! capture observed. Treat them as a tracked gap (see the crate's report),
//! and do not write a test asserting one of them against a browser: nothing
//! in this repository verifies it.

use chromulate_core::FetchDest;

/// Returns the `Priority` header value for `dest`.
pub(crate) const fn priority_for(dest: FetchDest) -> &'static str {
    match dest {
        FetchDest::Document | FetchDest::Iframe => "u=0, i",
        FetchDest::Style | FetchDest::Font => "u=0",
        FetchDest::Script => "u=1",
        // `FetchDest::Image | Empty`, plus any destination a future version
        // of `FetchDest` adds (it is `#[non_exhaustive]`).
        _ => "u=3",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_gets_the_captured_top_priority_value() {
        assert_eq!(priority_for(FetchDest::Document), "u=0, i");
    }

    #[test]
    fn subresources_do_not_all_share_the_document_priority() {
        assert_ne!(
            priority_for(FetchDest::Image),
            priority_for(FetchDest::Document)
        );
    }
}
