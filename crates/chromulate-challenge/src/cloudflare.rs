//! A [`ChallengeDetector`] for Cloudflare, built on the one header Cloudflare
//! documents for the purpose.
//!
//! # The rule this wave ships, and its source
//!
//! `cf-mitigated: challenge` — Cloudflare's own documentation states that
//! "the Challenge Page response (regardless of the Challenge Page type) will
//! have the `cf-mitigated` header present and set to `challenge`", that the
//! header "is set for all Challenge Page types", and that `challenge` is its
//! only documented value
//! (`developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response`,
//! fetched and confirmed 2026-08-08). That is enough, alone, for
//! [`Detection::Challenged`]: no other header, and no status code, needs to
//! agree with it.
//!
//! # Corroboration for [`Detection::Suspect`], and why `server: cloudflare` is not here
//!
//! Two supporting signals, neither sufficient alone, combine to a `Suspect`
//! verdict when `cf-mitigated` did not fire:
//!
//! - **`cf-ray` presence.** Cloudflare's own documentation states it adds
//!   this header to every response its network serves
//!   (`developers.cloudflare.com/fundamentals/reference/http-headers/`,
//!   "Cf-Ray"). It says nothing about challenges — it is on ordinary
//!   Cloudflare-proxied traffic too — which is why it never appears alone in
//!   this module's answer.
//! - **status `403` or `503`.** Cloudflare's own status-code documentation
//!   associates a WAF rule's "challenge or block" action with a `403`
//!   response
//!   (`developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-403/`).
//!   `503` has no equivalent citation found for this wave; it is kept
//!   because Cloudflare serves it for other edge-side holds that share the
//!   same shape (rate limiting, "I'm Under Attack Mode") and are worth the
//!   same second look. Neither status implies a challenge without `cf-ray`
//!   alongside it — see the test that asserts an ordinary `403` with no
//!   Cloudflare header at all stays [`Detection::Clear`].
//!
//! **`server: cloudflare` was suggested for this list and is deliberately not
//! implemented.** Checked against three Cloudflare documentation pages —
//! `fundamentals/reference/http-headers/`,
//! `fundamentals/reference/http-request-headers/`, and
//! `cloudflare-challenges/challenge-types/challenge-pages/` — on 2026-08-08;
//! none of them document Cloudflare setting this header, unlike `cf-ray`,
//! which the first of those three pages does. `CLAUDE.md`'s rule for a
//! detector rule is the same one it sets for a fingerprint constant: cite a
//! documented signal or a captured response. This one currently has neither,
//! so it stays out until one shows up. See the
//! `server_cloudflare_header_alone_is_not_treated_as_a_signal` unit test for
//! what that means for a response that only carries it.
//!
//! # What this detector does not, and cannot yet, do
//!
//! No captured Cloudflare challenge page exists anywhere in this repository
//! (`rg -i 'cf-mitigated|cf_clearance|challenge'` found nothing before this
//! wave). `CLAUDE.md`'s rule for fingerprint data — captured, never invented
//! — applies here on the same terms, so this detector reads **no** body:
//! no `<title>Just a moment…`, no `/cdn-cgi/challenge-platform/` path, no
//! marker of any kind. A response whose headers do not settle the question
//! gets [`Detection::Suspect`] on the terms above and [`Detection::Clear`]
//! otherwise; it never reads further, because there is no rule here to spend
//! a body read on. Adding one is future work that starts from a capture, not
//! from this comment.
//!
//! # Why [`ChallengeKind::Unknown`], not a guess
//!
//! Cloudflare's documentation says `cf-mitigated: challenge` is set for
//! *every* Challenge Page type — the non-interactive JS interstitial, the
//! interactive one, and the managed challenge that silently picks between
//! them — and gives this detector no way to tell which one fired. The three
//! more specific kinds this crate could return —
//! [`ChallengeKind::JsRequired`], [`ChallengeKind::CookieRequired`],
//! [`ChallengeKind::Interactive`] — are each a claim this detector has no
//! evidence for, and picking one anyway would be inventing exactly the kind
//! of fact `CLAUDE.md` prohibits for a fingerprint constant. Consider what
//! guessing wrong would cost: telling a fallback "js required" when a human
//! must actually act sends a headless browser to sit forever against a page
//! it cannot clear, and a caller reading the evidence trusts a claim this
//! detector never actually established.
//!
//! [`ChallengeKind::Unknown`] is exactly what this detector has: a
//! challenge, and this build does not know what kind of work it needs. Its
//! own documentation names this as the honest answer from *every*
//! header-only rule, because the headers that announce a challenge do not
//! describe it — this detector is not a special case, it is the case the
//! variant was named for. It is handed off like any other kind, not
//! withheld: a `BrowserFallback` that claims `Unknown` in `handles()` gets
//! it and finds out by navigating, and one that needs the kind decided in
//! advance is free to decline with `DeclineReason::UnsupportedKind` — which
//! is the fallback's call to make about the fallback it is, not this
//! detector's to make on its behalf. A later wave that captures a response
//! distinguishing the Challenge Page types can sharpen this without changing
//! the shape of anything that depends on it today.

use chromulate_http::challenge::{
    Challenge, ChallengeDetector, ChallengeKind, Detection, Evidence, Observation,
};
use http::{HeaderMap, HeaderValue, StatusCode};

/// The header Cloudflare documents for detecting a Challenge Page response.
/// See the module documentation for the exact citation.
const CF_MITIGATED: &str = "cf-mitigated";

/// The only value Cloudflare documents `cf-mitigated` as taking.
const CF_MITIGATED_CHALLENGE: &[u8] = b"challenge";

/// The evidence label recorded on a [`Detection::Challenged`] this detector
/// produces. Kept as one constant so the label in [`Evidence`] and the one in
/// this module's doc comment and tests cannot drift apart.
const SIGNAL_CF_MITIGATED: &str = "cf-mitigated: challenge";

/// A header Cloudflare's own documentation states it adds to every response
/// its network serves. Corroborating only — see the module documentation.
const CF_RAY: &str = "cf-ray";

/// Detects a Cloudflare Challenge Page from the one response header
/// Cloudflare documents for the purpose.
///
/// See the module documentation for exactly which signals this reads, which
/// ones were considered and rejected for lack of a citable source, and why
/// [`Detection::Challenged`] here always carries [`ChallengeKind::Unknown`]
/// rather than a guess.
///
/// # Example
///
/// ```
/// use chromulate_challenge::CloudflareDetector;
/// use chromulate_core::Origin;
/// use chromulate_http::challenge::{ChallengeDetector, Detection, Observation};
/// use http::{HeaderMap, HeaderValue, StatusCode};
/// use url::Url;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("cf-mitigated", HeaderValue::from_static("challenge"));
/// let url = Url::parse("https://example.com/").unwrap();
/// let origin = Origin::of(&url).unwrap();
/// let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &url, &origin);
///
/// let Detection::Challenged(challenge) = CloudflareDetector::new().inspect(&observation) else {
///     panic!("the documented header should settle this without a body read");
/// };
/// assert_eq!(challenge.evidence().signals().next(), Some("cf-mitigated: challenge"));
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CloudflareDetector;

impl CloudflareDetector {
    /// Builds the detector.
    ///
    /// Takes no configuration: every rule it applies is fixed by what
    /// Cloudflare documents, not by a caller's tuning. A detector that could
    /// be tuned per caller would be a detector this repository could not
    /// hold to the "documented signal or capture" standard.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ChallengeDetector for CloudflareDetector {
    fn inspect(&self, observation: &Observation<'_>) -> Detection {
        let headers = observation.headers();

        if is_cf_mitigated_challenge(headers) {
            // `observation.origin()` is infallible — see
            // `Observation`'s own "Why the origin is carried rather than
            // derived" for why this no longer calls `Origin::of` itself.
            return Detection::Challenged(Challenge::new(
                ChallengeKind::Unknown,
                observation.origin().clone(),
                Evidence::from_signal(SIGNAL_CF_MITIGATED),
            ));
        }

        if observation.body_prefix().is_some() {
            // This detector has no body rule to spend a second look on (see
            // the module documentation). A `Suspect` verdict here would be
            // the identical header-only answer as the first pass, and the
            // layer would ask again forever. Say `Clear` and stop.
            return Detection::Clear;
        }

        if is_corroborated(observation.status(), headers) {
            return Detection::Suspect;
        }

        Detection::Clear
    }
}

/// Whether `headers` carries the one documented signal, at its one
/// documented value.
fn is_cf_mitigated_challenge(headers: &HeaderMap) -> bool {
    headers
        .get(CF_MITIGATED)
        .map(HeaderValue::as_bytes)
        .is_some_and(|value| value == CF_MITIGATED_CHALLENGE)
}

/// Whether the two corroborating signals — `cf-ray` and a challenge-shaped
/// status — are both present. See the module documentation for why each one
/// is here and why `server: cloudflare` is not.
fn is_corroborated(status: StatusCode, headers: &HeaderMap) -> bool {
    let status_matches = matches!(
        status,
        StatusCode::FORBIDDEN | StatusCode::SERVICE_UNAVAILABLE
    );
    status_matches && headers.contains_key(CF_RAY)
}

#[cfg(test)]
mod tests {
    use chromulate_core::Origin;
    use http::HeaderValue;
    use url::Url;

    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("test URL should parse")
    }

    /// Every test targets the same URL, so its `Origin` is built once here
    /// rather than duplicated at every call site — `Observation::new` takes
    /// it as a separate, infallible argument (see the comment in `inspect`).
    fn origin() -> Origin {
        Origin::of(&url("https://example.com/")).expect("test URL should have an origin")
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        headers
    }

    /// The primary rule. This is the only signal this wave needs: Cloudflare
    /// documents it as sufficient on its own, for every Challenge Page type.
    #[test]
    fn cf_mitigated_challenge_is_challenged() {
        let headers = headers(&[("cf-mitigated", "challenge")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &origin);

        let Detection::Challenged(challenge) = CloudflareDetector::new().inspect(&observation)
        else {
            panic!("cf-mitigated: challenge should settle this without a body read");
        };

        assert_eq!(challenge.kind(), ChallengeKind::Unknown);
        assert_eq!(challenge.origin(), &origin);
        assert_eq!(
            challenge.evidence().signals().collect::<Vec<_>>(),
            vec![SIGNAL_CF_MITIGATED],
        );
    }

    /// `cf-ray` plus a challenge-shaped status, with no `cf-mitigated` at
    /// all, is corroboration for `Suspect` — never enough for `Challenged`.
    /// (The brief's proposed pairing for this test was `server: cloudflare`
    /// rather than `cf-ray`; see `server_cloudflare_header_alone_is_not_treated_as_a_signal`
    /// for why that header was replaced.)
    #[test]
    fn cf_ray_and_forbidden_status_without_mitigated_header_is_suspect() {
        let headers = headers(&[("cf-ray", "83f9a5c1a7b2e1a1-IAD")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &origin);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Suspect);
    }

    /// The single most important test in this file: an origin returning
    /// `403` for an ordinary reason — an expired token is the common one —
    /// must not be mistaken for a challenge, or a browser launches on every
    /// auth failure of every crawl. No Cloudflare header is present at all.
    #[test]
    fn plain_forbidden_with_no_cloudflare_signal_is_clear() {
        let headers = HeaderMap::new();
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &origin);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Clear);
    }

    /// `challenge` is documented as the header's only valid value. Anything
    /// else is not this detector's signal to read, and — with no other
    /// corroborating header present — settles at `Clear`, not `Suspect`.
    #[test]
    fn cf_mitigated_with_a_different_value_is_not_challenged() {
        let headers = headers(&[("cf-mitigated", "bypass")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &origin);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert!(!matches!(detection, Detection::Challenged(_)));
        assert_eq!(detection, Detection::Clear);
    }

    /// `server: cloudflare` was in the brief's suggested corroboration list.
    /// It is not implemented — see the module documentation for the three
    /// Cloudflare documentation pages checked and found silent on it — so a
    /// response carrying only that header, even alongside a challenge-shaped
    /// status, must not move past `Clear`. This is the test that would go
    /// red if that rejected rule were added back without a citation.
    #[test]
    fn server_cloudflare_header_alone_is_not_treated_as_a_signal() {
        let headers = headers(&[("server", "cloudflare")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &origin);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Clear);
    }

    /// `cf-ray` alone, on an ordinary `200`, is just Cloudflare-proxied
    /// traffic — the header is documented as present on every response, not
    /// only challenged ones. Status must agree too.
    #[test]
    fn cf_ray_without_a_challenge_shaped_status_is_clear() {
        let headers = headers(&[("cf-ray", "83f9a5c1a7b2e1a1-IAD")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::OK, &headers, &target, &origin);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Clear);
    }

    /// `cf-ray` plus `503` is the other half of the corroboration pair.
    #[test]
    fn cf_ray_and_service_unavailable_is_suspect() {
        let headers = headers(&[("cf-ray", "83f9a5c1a7b2e1a1-IAD")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation =
            Observation::new(StatusCode::SERVICE_UNAVAILABLE, &headers, &target, &origin);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Suspect);
    }

    /// A `Suspect` returned from an observation that already carries a body
    /// prefix has nothing left to buy — `Observation`'s own documentation
    /// says so, and this detector has no body rule to apply regardless. The
    /// headers here would trigger `Suspect` on a first pass; a second pass
    /// with a prefix attached must not repeat it, or the layer loops.
    #[test]
    fn a_suspect_verdict_is_never_repeated_once_a_body_prefix_is_attached() {
        let headers = headers(&[("cf-ray", "83f9a5c1a7b2e1a1-IAD")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &origin)
            .with_body_prefix(&[]);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Clear);
    }
}
