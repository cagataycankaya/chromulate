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
//! - **status `200`, `403`, or `503`.** `403` is Cloudflare's own status-code
//!   documentation, associating a WAF rule's "challenge or block" action
//!   with a `403` response
//!   (`developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-403/`).
//!   `503` has no equivalent citation; it is kept because Cloudflare serves
//!   it for other edge-side holds that share the same shape (rate limiting,
//!   "I'm Under Attack Mode") and are worth the same second look. `200` is
//!   captured, not documented — `tests/data/cloudflare-js-interstitial-200.html`
//!   is a live JS interstitial served with an ordinary `200 OK`, so a
//!   `Suspect` rule that only watched 403/503 would never buy a body read
//!   for the exact page this crate exists to catch. Neither status implies a
//!   challenge without `cf-ray` alongside it, and the set is closed to these
//!   three — see the tests that assert an ordinary `403` with no Cloudflare
//!   header stays [`Detection::Clear`], and that `cf-ray` with a fourth
//!   status (`500`) does too.
//!
//! **Cost this creates, worth stating plainly:** `cf-ray` is present on
//! essentially every response any Cloudflare-fronted site serves, so adding
//! `200` to the corroborating set means a `Suspect` verdict — and the bounded
//! body read it buys, per `chromulate-http`'s own body-sniffing design — now
//! fires on **every ordinary `200` from a Cloudflare-fronted origin**, not
//! only on challenge pages. That is the honest price of catching a
//! non-error-status interstitial with header-only corroboration; whether a
//! narrower rule (a content-length ceiling, say — a challenge interstitial
//! is kilobytes) is worth the risk of an unmeasured threshold is an open
//! question this wave does not answer. See §6 of the B2b report.
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
//! # Body rules — now backed by two captures
//!
//! This crate shipped with no body rules at first: no capture existed
//! anywhere in the repository, and `CLAUDE.md`'s rule for fingerprint data —
//! captured, never invented — applies to a detection rule on the same terms.
//! That refusal turned out to be the right call given what was known at the
//! time, and the wrong call to leave standing: shipping the header rule
//! *alone* as if it settled the question let a real, silent miss reach
//! production. `incehesap.com` serves its JS interstitial with **no
//! `cf-mitigated` header at all**, which this crate's header-only release
//! reported as [`Detection::Clear`] — a crawler trusting that verdict stores
//! "Just a moment…" as the page. Two live captures now exist
//! (`tests/data/`, provenance in `tests/data/README.md`), so the rule that
//! was correctly withheld before can be written the way this project
//! requires: against an observed response.
//!
//! **The rule:** on the second pass — [`Observation::body_prefix`] is
//! `Some` — a body containing `Just a moment` (the interstitial's
//! `<title>`) **or** `/cdn-cgi/challenge-platform/` (the path the
//! interstitial injects a `<script>` at) is [`Detection::Challenged`].
//! Either marker alone is treated as sufficient, on purpose: they are
//! observed together in the one capture this crate has, but requiring both
//! would silently miss a future page variant that kept only one of them,
//! which is exactly the failure mode that reopened this crate. Evidence:
//! `tests/data/cloudflare-js-interstitial-200.html:1` (the whole capture is
//! one minified line).
//!
//! **What is still not written:** anything not observed. No `cf_clearance`
//! cookie shape, no Turnstile widget marker, no other vendor's interstitial.
//! A rule here traces to one of the two files in `tests/data/` or it does
//! not exist.
//!
//! # The WAF block is not a challenge, and the seam has no arm that says so
//!
//! `n11.com` answers some requests with Cloudflare's WAF block page —
//! `<title>Attention Required! | Cloudflare</title>`, "Sorry, you have been
//! blocked" (`tests/data/cloudflare-waf-block-403.html:7,35`) — carrying the
//! same `cf-ray` and `403` this crate treats as challenge corroboration.
//! **This is not a challenge.** Cloudflare has already decided to refuse the
//! client; no JavaScript execution changes that decision, and no browser
//! this layer could hand the page to would come back with anything but the
//! same refusal. Reporting it as [`Detection::Challenged`] would launch a
//! `BrowserFallback` and spend its budget for nothing.
//!
//! On a body pass, this detector checks for the block page's markers —
//! `Attention Required! | Cloudflare` or `Sorry, you have been blocked` —
//! **before** the challenge markers, and returns [`Detection::Clear`] if
//! either matches, regardless of what else is true of the response.
//!
//! **[`Detection`] has no arm meaning "blocked".** `Clear` here does not mean
//! "nothing happened" the way it does on the default path — it means "this
//! layer has nothing that can carry what happened". That is a real
//! difference a caller reading only the enum cannot see, and it is recorded
//! as an **open requirement, not silently worked around**: whether the seam
//! needs a fourth [`Detection`] arm — `Blocked`, say, distinct from `Clear`
//! — is the maintainer's call, not this crate's to make by picking a
//! variant and hoping it reads correctly. Filed as such in the B2b report
//! rather than resolved here.
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
//! The captured interstitial makes this concrete rather than hypothetical:
//! its injected script sets `window._cf_chl_opt.cType: 'managed'`
//! (`tests/data/cloudflare-js-interstitial-200.html:1`) — Cloudflare's own
//! label for a **managed challenge**, which dynamically escalates from a
//! non-interactive check to an interactive one depending on a risk score
//! computed after this page loads. The page does not yet know which kind of
//! work it is; neither, correctly, does this detector.
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

/// The JS interstitial's `<title>`. Captured at
/// `tests/data/cloudflare-js-interstitial-200.html:1`; see the module
/// documentation, "Body rules — now backed by two captures".
const JS_INTERSTITIAL_TITLE: &[u8] = b"Just a moment";

/// The path the JS interstitial injects a `<script>` at to run the actual
/// challenge. Same capture as [`JS_INTERSTITIAL_TITLE`].
const JS_INTERSTITIAL_SCRIPT_PATH: &[u8] = b"/cdn-cgi/challenge-platform/";

/// The evidence label for a body-detected challenge. One constant, for the
/// same reason as [`SIGNAL_CF_MITIGATED`]: the label in [`Evidence`] and the
/// one anyone greps for should not be able to drift apart.
const SIGNAL_JS_INTERSTITIAL_BODY: &str =
    "body: js interstitial title or /cdn-cgi/challenge-platform/ path";

/// The WAF block page's `<title>`. Captured at
/// `tests/data/cloudflare-waf-block-403.html:7`; see the module
/// documentation, "The WAF block is not a challenge".
const WAF_BLOCK_TITLE: &[u8] = b"Attention Required! | Cloudflare";

/// The WAF block page's headline. Same capture as [`WAF_BLOCK_TITLE`],
/// `:35`.
const WAF_BLOCK_HEADLINE: &[u8] = b"Sorry, you have been blocked";

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

        if let Some(body) = observation.body_prefix() {
            // Second pass: a `Suspect` verdict already spent the one body
            // read this detector gets, so this either settles the question
            // or stops — it never asks again. The WAF block check runs
            // first and unconditionally: see the module documentation, "The
            // WAF block is not a challenge", for why a block must never
            // become `Challenged` even if some future body rule broadened
            // enough to coincidentally match one too.
            if is_cloudflare_waf_block_body(body) {
                return Detection::Clear;
            }
            if is_cloudflare_js_interstitial_body(body) {
                return Detection::Challenged(Challenge::new(
                    ChallengeKind::Unknown,
                    observation.origin().clone(),
                    Evidence::from_signal(SIGNAL_JS_INTERSTITIAL_BODY),
                ));
            }
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
/// is here, why `200` joined `403`/`503`, and why `server: cloudflare` is
/// not.
fn is_corroborated(status: StatusCode, headers: &HeaderMap) -> bool {
    let status_matches = matches!(
        status,
        StatusCode::OK | StatusCode::FORBIDDEN | StatusCode::SERVICE_UNAVAILABLE
    );
    status_matches && headers.contains_key(CF_RAY)
}

/// Whether `body` contains either marker of the captured JS interstitial.
/// See the module documentation, "Body rules — now backed by two captures".
fn is_cloudflare_js_interstitial_body(body: &[u8]) -> bool {
    contains_bytes(body, JS_INTERSTITIAL_TITLE) || contains_bytes(body, JS_INTERSTITIAL_SCRIPT_PATH)
}

/// Whether `body` contains either marker of the captured WAF block page.
/// See the module documentation, "The WAF block is not a challenge".
fn is_cloudflare_waf_block_body(body: &[u8]) -> bool {
    contains_bytes(body, WAF_BLOCK_TITLE) || contains_bytes(body, WAF_BLOCK_HEADLINE)
}

/// Whether `haystack` contains `needle` as a contiguous byte sequence.
/// Written over raw bytes rather than `str::contains` so a body this
/// detector does not otherwise touch never needs UTF-8 validation just to be
/// checked for a marker.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
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

    fn origin_of(target: &Url) -> Origin {
        Origin::of(target).expect("test URL should have an origin")
    }

    /// Most tests target the same URL, so its `Origin` is built once here
    /// rather than duplicated at every call site — `Observation::new` takes
    /// it as a separate, infallible argument (see the comment in `inspect`).
    /// The B2b capture tests target the captured site instead, via
    /// [`origin_of`] directly.
    fn origin() -> Origin {
        origin_of(&url("https://example.com/"))
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

    /// An empty body prefix matches neither body rule, so this settles at
    /// `Clear` rather than `Suspect` again — the second pass never asks a
    /// third time regardless of what it found, which is what keeps the
    /// layer from looping. The headers here would trigger `Suspect` on a
    /// first pass; this observation simulates the second.
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

    // --- B2b: real captures. See `tests/data/README.md` for provenance. ---

    /// `incehesap.com`, live `GET`, 2026-08-08: `200 OK`, `cf-ray` present,
    /// no `cf-mitigated`. The body is Cloudflare's JS interstitial. THIS IS
    /// THE MISSING-CASE TEST: against the detector as first shipped (header
    /// rule only, `Suspect` gated on 403/503), this returns `Detection::
    /// Clear` — confirmed red before any fix (see the B2b report for the
    /// failure output). A crawler that trusts `Clear` here stores "Just a
    /// moment…" as the page.
    const INTERSTITIAL_CAPTURE: &[u8] =
        include_bytes!("../tests/data/cloudflare-js-interstitial-200.html");

    #[test]
    fn cloudflare_js_interstitial_capture_is_challenged() {
        let headers = headers(&[
            ("cf-ray", "a280606e4b43dc96-IAD"),
            ("server", "cloudflare"),
            ("content-type", "text/html; charset=UTF-8"),
        ]);
        let target = url("https://incehesap.com/");
        let origin = origin_of(&target);
        let observation = Observation::new(StatusCode::OK, &headers, &target, &origin)
            .with_body_prefix(INTERSTITIAL_CAPTURE);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert!(
            matches!(detection, Detection::Challenged(_)),
            "expected the real Cloudflare JS interstitial capture to be Challenged, got {detection:?}"
        );
    }

    /// Same capture's headers, no body yet: the first pass must return
    /// `Suspect` so the layer bothers to read one — this is the part of the
    /// fix that widens `is_corroborated` to include `200`, not only
    /// `403`/`503`.
    #[test]
    fn cloudflare_js_interstitial_headers_alone_are_suspect() {
        let headers = headers(&[("cf-ray", "a280606e4b43dc96-IAD"), ("server", "cloudflare")]);
        let target = url("https://incehesap.com/");
        let origin = origin_of(&target);
        let observation = Observation::new(StatusCode::OK, &headers, &target, &origin);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Suspect);
    }

    /// `n11.com`, live `GET`, 2026-08-08: `403 Forbidden`, `cf-ray` present,
    /// no `cf-mitigated`. The body is Cloudflare's WAF block page — the
    /// client has been refused, not challenged, and no browser can change
    /// that. Must not become `Detection::Challenged`.
    const WAF_BLOCK_CAPTURE: &[u8] = include_bytes!("../tests/data/cloudflare-waf-block-403.html");

    #[test]
    fn cloudflare_waf_block_capture_is_not_challenged() {
        let headers = headers(&[("cf-ray", "a2805fc4ebe3d284-IAD"), ("server", "cloudflare")]);
        let target = url("https://n11.com/");
        let origin = origin_of(&target);
        let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &origin)
            .with_body_prefix(WAF_BLOCK_CAPTURE);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(
            detection,
            Detection::Clear,
            "a WAF block must stay Clear — Cloudflare has already refused this client"
        );
    }

    /// The two real captures never overlap, so
    /// `cloudflare_waf_block_capture_is_not_challenged` alone cannot tell
    /// "the block check runs and wins" apart from "the challenge markers
    /// just never matched this body anyway" — both explanations produce the
    /// same `Clear` for that one file. This body is synthetic, built to
    /// contain both marker sets at once, specifically to force that
    /// distinction: if the block check did not exist, or ran after the
    /// challenge check, this would be `Challenged`.
    #[test]
    fn a_body_matching_both_marker_sets_stays_clear() {
        let mut body = WAF_BLOCK_TITLE.to_vec();
        body.extend_from_slice(b" ... ");
        body.extend_from_slice(JS_INTERSTITIAL_TITLE);
        let headers = headers(&[("cf-ray", "83f9a5c1a7b2e1a1-IAD")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &origin)
            .with_body_prefix(&body);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Clear);
    }

    /// The module doc claims either challenge marker is independently
    /// sufficient — deliberately, so a future page keeping only one of them
    /// is still caught. The one real capture has both together, which
    /// cannot prove that claim; these two synthetic bodies isolate each
    /// marker to prove the `||` is load-bearing rather than incidental.
    #[test]
    fn the_interstitial_title_alone_is_challenged() {
        let headers = headers(&[("cf-ray", "83f9a5c1a7b2e1a1-IAD")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::OK, &headers, &target, &origin)
            .with_body_prefix(JS_INTERSTITIAL_TITLE);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert!(matches!(detection, Detection::Challenged(_)));
    }

    #[test]
    fn the_challenge_platform_path_alone_is_challenged() {
        let headers = headers(&[("cf-ray", "83f9a5c1a7b2e1a1-IAD")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::OK, &headers, &target, &origin)
            .with_body_prefix(JS_INTERSTITIAL_SCRIPT_PATH);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert!(matches!(detection, Detection::Challenged(_)));
    }

    /// An ordinary `200` with no Cloudflare signal at all — the case
    /// `teknosa.com` exercised live (real content, 385 KB, no `cf-mitigated`,
    /// no `cf-ray`) — must not become `Suspect`: nothing here suggests
    /// Cloudflare is even in the path.
    #[test]
    fn plain_ok_with_no_cloudflare_signal_is_clear() {
        let headers = HeaderMap::new();
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(StatusCode::OK, &headers, &target, &origin);

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Clear);
    }

    /// `cf-ray` plus a status outside the corroborating set (`200`, `403`,
    /// `503`) must still be `Clear` on a headers-only pass — the set is
    /// bounded, not "any status with `cf-ray`".
    #[test]
    fn cf_ray_with_an_uncorroborated_status_is_clear() {
        let headers = headers(&[("cf-ray", "83f9a5c1a7b2e1a1-IAD")]);
        let target = url("https://example.com/");
        let origin = origin();
        let observation = Observation::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            &headers,
            &target,
            &origin,
        );

        let detection = CloudflareDetector::new().inspect(&observation);

        assert_eq!(detection, Detection::Clear);
    }
}
