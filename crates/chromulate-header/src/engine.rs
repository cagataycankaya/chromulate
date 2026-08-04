//! [`HeaderEngine`]: turning a profile and a request's context into the
//! exact, ordered header list Chrome would have sent.
//!
//! See the crate documentation for why the authoritative result is a `Vec`
//! rather than the request's own `HeaderMap`.

use std::collections::HashSet;
use std::sync::Arc;

use chromulate_core::{Error, FetchMode, Origin, Request, RequestOptions, Result, referrer_for};
use chromulate_profile::Profile;
use http::{HeaderName, HeaderValue, Method, Version};
use url::Url;

use crate::accept::accept_for;
use crate::client_hints::{AcceptChStore, HighEntropyHint, HighEntropyHints};
use crate::fetch_site::FetchSite;
use crate::order::{contains, insert_after, insert_before};
use crate::priority::priority_for;

/// Marks a navigation as caused by a direct user activation — a clicked
/// link, or a typed URL followed by pressing enter — which is what sets
/// `Sec-Fetch-User: ?1`.
///
/// `chromulate_core::RequestOptions` has no field for this because it is
/// not a per-request *setting* the way `mode` or `dest` are; it is a fact
/// about how the request came to exist, alongside the request rather than
/// inside its options. Insert this into the request's `http::Extensions`
/// the same way `RequestOptions` itself travels there; its absence means no
/// activation, matching the browser default of omitting the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserActivatedNavigation;

/// Computes the ordered, populated header set a captured browser profile
/// sends for a request.
#[derive(Debug, Clone)]
pub struct HeaderEngine {
    profile: Arc<Profile>,
    high_entropy: HighEntropyHints,
}

impl HeaderEngine {
    /// Builds an engine for `profile`.
    ///
    /// High-entropy client hints start empty; attach real values with
    /// [`HeaderEngine::with_high_entropy_hints`] if you have a capture that
    /// records them.
    #[must_use]
    pub fn new(profile: Arc<Profile>) -> Self {
        Self {
            profile,
            high_entropy: HighEntropyHints::default(),
        }
    }

    /// Attaches high-entropy client hint values this profile can send once
    /// a server asks for them.
    #[must_use]
    pub fn with_high_entropy_hints(mut self, hints: HighEntropyHints) -> Self {
        self.high_entropy = hints;
        self
    }

    /// The profile this engine builds headers from.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Computes the header list for a request to `url` and writes it onto
    /// `request`.
    ///
    /// `request` supplies the method (for the `Origin` and `Sec-Fetch-*`
    /// computation), the HTTP version (for whether `Host` is sent), any
    /// headers the caller already set — which win over the profile, kept in
    /// the profile's positional slot when the name is one the profile
    /// orders — and an optional [`UserActivatedNavigation`] extension.
    ///
    /// The returned `Vec` is the authoritative wire order; `request`'s
    /// `HeaderMap` is updated too, but only for lookup convenience, since a
    /// `HeaderMap` cannot carry that order itself.
    ///
    /// A header the caller set more than once keeps every value, emitted
    /// together at the profile's positional slot.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` has no host, the same case in which
    /// `chromulate_core::Origin::of` fails, and when a value this engine
    /// computes from the profile is not a valid `http::HeaderValue`.
    pub fn apply(
        &self,
        request: &mut Request,
        url: &Url,
        options: &RequestOptions,
        accept_ch: &AcceptChStore,
    ) -> Result<Vec<(HeaderName, HeaderValue)>> {
        let target = Origin::of(url)?;
        let method = request.method().clone();
        let fetch_site = FetchSite::compute(options.initiator.as_ref(), &target);
        let origin_header =
            origin_header_value(options.mode, &method, options.initiator.as_ref(), &target);
        let referer = options
            .referrer
            .as_ref()
            .and_then(|from| referrer_for(from, url));
        let host_value = if needs_host(request.version()) {
            host_header_value(url)
        } else {
            None
        };
        let user_activated = request
            .extensions()
            .get::<UserActivatedNavigation>()
            .is_some();
        let granted = accept_ch.granted_for(&target);
        let granted_order: Vec<HighEntropyHint> = HighEntropyHint::ALL_IN_EMIT_ORDER
            .into_iter()
            .filter(|hint| granted.contains(hint))
            .collect();

        let order = build_order(
            self.navigate_order(options.mode),
            host_value.is_some(),
            origin_header.is_some(),
            referer.is_some(),
            user_activated,
            &granted_order,
        );

        let ctx = Ctx {
            options,
            fetch_site,
            referer,
            origin_header,
            host_value,
            user_activated,
            granted,
        };

        let caller_headers = request.headers().clone();
        let mut known_names = HashSet::with_capacity(order.len());
        let mut result = Vec::with_capacity(order.len());

        for name in &order {
            let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            // `build_order` keeps a name out of the order when the capture
            // already places it, but a capture that lists one twice would
            // still reach here twice, and this loop walks positionally.
            if !known_names.insert(header_name.clone()) {
                continue;
            }

            let mut caller_values = caller_headers.get_all(&header_name).into_iter();
            if let Some(first) = caller_values.next() {
                // The caller wins over the profile, in the profile's slot —
                // for every value they supplied, not just the first.
                request
                    .headers_mut()
                    .insert(header_name.clone(), first.clone());
                result.push((header_name.clone(), first.clone()));
                for extra in caller_values {
                    request
                        .headers_mut()
                        .append(header_name.clone(), extra.clone());
                    result.push((header_name.clone(), extra.clone()));
                }
            } else if let Some(value) = self.engine_value(name, &ctx)? {
                request
                    .headers_mut()
                    .insert(header_name.clone(), value.clone());
                result.push((header_name, value));
            }
        }

        for (name, value) in &caller_headers {
            if !known_names.contains(name) {
                result.push((name.clone(), value.clone()));
            }
        }

        Ok(result)
    }

    /// The header order to start from.
    ///
    /// Navigations use the captured navigation order directly — this is the
    /// one order `chrome-151-macos.json` actually observed. Everything else
    /// falls back to that same order through
    /// `chromulate_profile::HeaderOrder::subresource_or_navigate`, because
    /// the capture only exercised a navigation and recorded no subresource
    /// order at all. That fallback is **derived, not observed**: it is a
    /// placeholder built from the one order this crate has, not a claim
    /// that a real subresource fetch orders its headers the same way. See
    /// the crate's report for this as a tracked gap.
    fn navigate_order(&self, mode: FetchMode) -> &[String] {
        if mode == FetchMode::Navigate {
            &self.profile.header_order.navigate
        } else {
            self.profile.header_order.subresource_or_navigate()
        }
    }

    /// Computes the value this engine would send for `name`.
    ///
    /// `Ok(None)` means the header does not apply to this request. An error
    /// means the profile carries a value the `http` crate cannot encode —
    /// a control character transcribed into a capture, say. Those two used to
    /// be the same answer, so an unencodable `user-agent` simply vanished
    /// from the wire order with nothing raised and nothing logged; the
    /// loudest fidelity break this crate can have, delivered silently.
    ///
    /// # Errors
    ///
    /// Returns [`chromulate_core::Error::Config`] naming `name` when the
    /// computed value is not a valid header value.
    fn engine_value(&self, name: &str, ctx: &Ctx<'_>) -> Result<Option<HeaderValue>> {
        let Some(value) = self.engine_value_string(name, ctx) else {
            return Ok(None);
        };
        HeaderValue::from_str(&value).map(Some).map_err(|_| {
            Error::config(format!(
                "the profile's value for header `{name}` is not a valid HTTP header value: {value:?}"
            ))
        })
    }

    /// The unencoded value for `name`, or `None` when the header does not
    /// apply to this request.
    fn engine_value_string(&self, name: &str, ctx: &Ctx<'_>) -> Option<String> {
        let value = match name {
            // `Profile::sec_ch_ua` renders the GREASE brand entry
            // (`"Not=A?Brand";v="99"` in the capture) verbatim from static
            // profile data. This engine does not model whether Chrome
            // varies that entry's separator characters or list position per
            // request, per session, or per build — a single capture cannot
            // show that, and inventing a permutation rule would be
            // fabricating fingerprint data. Tracked as a gap in the crate's
            // report.
            "sec-ch-ua" => self.profile.sec_ch_ua(),
            "sec-ch-ua-mobile" => self
                .profile
                .observed_headers
                .get("sec-ch-ua-mobile")?
                .clone(),
            "sec-ch-ua-platform" => self.profile.sec_ch_ua_platform(),
            "sec-ch-ua-platform-version" => {
                self.high_entropy_value(HighEntropyHint::PlatformVersion, ctx)?
            }
            "sec-ch-ua-arch" => self.high_entropy_value(HighEntropyHint::Arch, ctx)?,
            "sec-ch-ua-bitness" => self.high_entropy_value(HighEntropyHint::Bitness, ctx)?,
            "sec-ch-ua-full-version-list" => {
                self.high_entropy_value(HighEntropyHint::FullVersionList, ctx)?
            }
            "sec-ch-ua-model" => self.high_entropy_value(HighEntropyHint::Model, ctx)?,
            "upgrade-insecure-requests" if ctx.options.mode == FetchMode::Navigate => {
                "1".to_owned()
            }
            "upgrade-insecure-requests" => return None,
            "user-agent" => self.profile.user_agent.clone(),
            "accept" => accept_for(ctx.options.dest, &self.profile.accept),
            "sec-fetch-site" => ctx.fetch_site.as_str().to_owned(),
            "sec-fetch-mode" => ctx.options.mode.as_str().to_owned(),
            "sec-fetch-user" if ctx.user_activated => "?1".to_owned(),
            "sec-fetch-user" => return None,
            "sec-fetch-dest" => ctx.options.dest.as_str().to_owned(),
            "referer" => ctx.referer.clone()?,
            "origin" => ctx.origin_header.clone()?,
            "accept-encoding" => self.profile.accept_encoding.clone(),
            "accept-language" => self.profile.accept_language.clone(),
            "priority" => priority_for(ctx.options.dest).to_owned(),
            "host" => ctx.host_value.clone()?,
            _ => return None,
        };
        Some(value)
    }

    /// The value for a high-entropy hint, if it has been granted by
    /// `Accept-CH` for this origin and this profile has data for it.
    fn high_entropy_value(&self, hint: HighEntropyHint, ctx: &Ctx<'_>) -> Option<String> {
        if !ctx.granted.contains(&hint) {
            return None;
        }
        self.high_entropy.value_for(hint).map(str::to_owned)
    }
}

/// Per-request facts the engine needs while resolving header values, kept
/// off the request itself since most of them are derived, not stored.
struct Ctx<'a> {
    options: &'a RequestOptions,
    fetch_site: FetchSite,
    referer: Option<String>,
    origin_header: Option<String>,
    host_value: Option<String>,
    user_activated: bool,
    granted: HashSet<HighEntropyHint>,
}

/// Whether `Host` belongs on the wire for `version`.
///
/// HTTP/2 and HTTP/3 carry the authority in the `:authority` pseudo-header
/// and never send `Host`; only HTTP/1.x requires it.
fn needs_host(version: Version) -> bool {
    matches!(
        version,
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
    )
}

/// The `Host` header value for `url`: the host, plus a port only when one
/// was explicit and non-default — exactly the shape `url::Url::port`
/// already normalises to, since it returns `None` for a scheme's default
/// port.
fn host_header_value(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

/// Whether the `Origin` header belongs on this request.
///
/// A plain cross-site navigation — someone clicking a link to here from
/// another site — never carries `Origin`; the capture this crate is built
/// from is exactly that case, and its header order has no `origin` entry
/// despite `sec-fetch-site: cross-site`. `Origin` is reserved for
/// subresource fetches, where CORS makes the initiator's identity
/// load-bearing, and for navigations with an unsafe method, such as a
/// cross-origin form submission.
fn origin_header_value(
    mode: FetchMode,
    method: &Method,
    initiator: Option<&Origin>,
    target: &Origin,
) -> Option<String> {
    let initiator = initiator?;
    let unsafe_method = !matches!(*method, Method::GET | Method::HEAD);
    let needed = match mode {
        FetchMode::Navigate => unsafe_method,
        _ => unsafe_method || initiator != target,
    };
    needed.then(|| initiator.ascii_serialization())
}

/// Builds the final header name order: the profile's captured order, plus
/// whatever this specific request needs that the capture did not carry.
///
/// The insertion points for `host`, `origin`, `sec-fetch-user`, and
/// `referer` are NOT captured — general protocol knowledge pending a
/// capture, not fingerprint data. `chrome-151-macos.json` recorded a GET
/// navigation with no prior `Accept-CH` grant, so none of these four headers
/// were present in it for this crate to record a position from. The
/// positions used here (`sec-fetch-site`, `sec-fetch-mode`, `sec-fetch-user`,
/// `sec-fetch-dest`, then `referer`) are a plausible ordering, not a
/// verified one; a future capture that exercises any of them should be used
/// to confirm or correct this function rather than trusted as-is. See the
/// crate's report for this as a tracked gap.
///
/// Because those positions are guesses, a capture that already places one of
/// these headers wins: every insertion below is skipped when `base` already
/// lists the name. The shipped Chrome capture is an HTTP/2 GET navigation, so
/// it carries neither `host` nor `origin` and none of this shows — but any
/// capture taken over HTTP/1.1 necessarily records `host`, and any capture of
/// a CORS fetch or a form POST records `origin`, and `Profile::from_capture`
/// is the documented way to add a browser.
fn build_order(
    base: &[String],
    needs_host: bool,
    needs_origin: bool,
    needs_referer: bool,
    user_activated: bool,
    granted_high_entropy: &[HighEntropyHint],
) -> Vec<String> {
    let mut order = base.to_vec();

    if needs_host && !contains(&order, "host") {
        order.insert(0, "host".to_owned());
    }

    // High-entropy hints join the low-entropy group Chrome already sends.
    let anchor = order.iter().position(|name| name == "sec-ch-ua-platform");
    let mut inserted = 0;
    for hint in granted_high_entropy {
        let name = hint.header_name();
        if contains(&order, name) {
            continue;
        }
        match anchor {
            Some(anchor) => {
                order.insert(anchor + 1 + inserted, name.to_owned());
                inserted += 1;
            }
            None => order.push(name.to_owned()),
        }
    }

    if needs_origin {
        insert_before(&mut order, "sec-fetch-site", "origin");
    }

    if user_activated {
        insert_before(&mut order, "sec-fetch-dest", "sec-fetch-user");
    }

    if needs_referer {
        insert_after(&mut order, "sec-fetch-dest", "referer");
    }

    order
}

#[cfg(test)]
mod tests {
    use chromulate_core::Body;

    use super::*;

    fn origin(url: &str) -> Origin {
        Origin::of(&url::Url::parse(url).expect("test url should parse"))
            .expect("test url should have an origin")
    }

    fn navigation_to(url: &str, version: Version) -> (Request, Url, RequestOptions) {
        let target = Url::parse(url).expect("test url should parse");
        let request = http::Request::builder()
            .method(Method::GET)
            .uri(target.as_str())
            .version(version)
            .body(Body::empty())
            .expect("request should build");
        (request, target, RequestOptions::navigation())
    }

    fn names_of(emitted: &[(HeaderName, HeaderValue)]) -> Vec<&str> {
        emitted.iter().map(|(name, _)| name.as_str()).collect()
    }

    fn values_of<'a>(emitted: &'a [(HeaderName, HeaderValue)], wanted: &str) -> Vec<&'a str> {
        emitted
            .iter()
            .filter(|(name, _)| name.as_str() == wanted)
            .map(|(_, value)| value.to_str().expect("test values are ascii"))
            .collect()
    }

    #[test]
    fn a_cross_site_get_navigation_never_carries_origin() {
        let initiator = origin("https://other.test");
        let target = origin("https://example.com");
        assert_eq!(
            origin_header_value(FetchMode::Navigate, &Method::GET, Some(&initiator), &target),
            None,
            "matches the capture: cross-site GET navigations never send Origin"
        );
    }

    #[test]
    fn a_cross_origin_form_post_navigation_carries_origin() {
        let initiator = origin("https://other.test");
        let target = origin("https://example.com");
        assert_eq!(
            origin_header_value(
                FetchMode::Navigate,
                &Method::POST,
                Some(&initiator),
                &target
            ),
            Some("https://other.test".to_owned())
        );
    }

    #[test]
    fn a_same_origin_cors_fetch_with_an_unsafe_method_carries_origin() {
        let same = origin("https://example.com");
        assert_eq!(
            origin_header_value(FetchMode::Cors, &Method::POST, Some(&same), &same),
            Some("https://example.com".to_owned())
        );
    }

    #[test]
    fn a_same_origin_get_fetch_never_carries_origin() {
        let same = origin("https://example.com");
        assert_eq!(
            origin_header_value(FetchMode::Cors, &Method::GET, Some(&same), &same),
            None
        );
    }

    #[test]
    fn host_is_only_needed_for_http1() {
        assert!(needs_host(Version::HTTP_11));
        assert!(!needs_host(Version::HTTP_2));
    }

    #[test]
    fn a_default_https_port_is_omitted_from_host() {
        let url = url::Url::parse("https://example.com/").expect("test url should parse");
        assert_eq!(host_header_value(&url).as_deref(), Some("example.com"));
    }

    #[test]
    fn a_non_default_port_is_kept_in_host() {
        let url = url::Url::parse("https://example.com:8443/").expect("test url should parse");
        assert_eq!(host_header_value(&url).as_deref(), Some("example.com:8443"));
    }

    #[test]
    fn a_capture_that_already_orders_host_emits_it_once_where_the_capture_put_it() {
        let mut profile = Profile::chrome_stable();
        // Any capture taken over HTTP/1.1 records `host`; put it where such a
        // capture would rather than at the front this crate otherwise guesses.
        profile.header_order.navigate.insert(1, "host".to_owned());
        let expected = profile.header_order.navigate.clone();
        let engine = HeaderEngine::new(Arc::new(profile));

        let (mut request, url, options) = navigation_to("https://example.com/", Version::HTTP_11);
        let emitted = engine
            .apply(&mut request, &url, &options, &AcceptChStore::new())
            .expect("header planning should succeed");

        assert_eq!(names_of(&emitted), expected);
    }

    #[test]
    fn a_capture_that_already_orders_origin_emits_it_once_where_the_capture_put_it() {
        let mut profile = Profile::chrome_stable();
        // A capture of a CORS fetch or a form POST records `origin`.
        let slot = profile
            .header_order
            .navigate
            .iter()
            .position(|name| name == "accept")
            .expect("the captured order includes accept");
        profile
            .header_order
            .navigate
            .insert(slot + 1, "origin".to_owned());
        let expected = profile.header_order.navigate.clone();
        let engine = HeaderEngine::new(Arc::new(profile));

        let target = Url::parse("https://example.com/").expect("test url should parse");
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri(target.as_str())
            .version(Version::HTTP_2)
            .body(Body::empty())
            .expect("request should build");
        let mut options = RequestOptions::navigation();
        options.initiator = Some(origin("https://other.test"));

        let emitted = engine
            .apply(&mut request, &target, &options, &AcceptChStore::new())
            .expect("header planning should succeed");

        assert_eq!(names_of(&emitted), expected);
    }

    #[test]
    fn a_capture_that_already_orders_a_granted_hint_emits_it_once() {
        let mut profile = Profile::chrome_stable();
        let slot = profile
            .header_order
            .navigate
            .iter()
            .position(|name| name == "sec-ch-ua-platform")
            .expect("the captured order includes sec-ch-ua-platform");
        profile
            .header_order
            .navigate
            .insert(slot + 1, "sec-ch-ua-arch".to_owned());
        let expected = profile.header_order.navigate.clone();
        let engine =
            HeaderEngine::new(Arc::new(profile)).with_high_entropy_hints(HighEntropyHints {
                arch: Some("arm".to_owned()),
                ..HighEntropyHints::default()
            });

        let (mut request, url, options) = navigation_to("https://example.com/", Version::HTTP_2);
        let mut store = AcceptChStore::new();
        store.record(
            Origin::of(&url).expect("target should have an origin"),
            "Sec-CH-UA-Arch",
        );

        let emitted = engine
            .apply(&mut request, &url, &options, &store)
            .expect("header planning should succeed");

        assert_eq!(names_of(&emitted), expected);
    }

    #[test]
    fn every_caller_value_for_a_profile_ordered_header_is_emitted() {
        let engine = HeaderEngine::new(Arc::new(Profile::chrome_stable()));
        let (mut request, url, options) = navigation_to("https://example.com/", Version::HTTP_2);
        request
            .headers_mut()
            .append("accept-encoding", HeaderValue::from_static("gzip"));
        request
            .headers_mut()
            .append("accept-encoding", HeaderValue::from_static("br"));
        request
            .headers_mut()
            .append("x-trace", HeaderValue::from_static("a"));
        request
            .headers_mut()
            .append("x-trace", HeaderValue::from_static("b"));

        let emitted = engine
            .apply(&mut request, &url, &options, &AcceptChStore::new())
            .expect("header planning should succeed");

        assert_eq!(
            values_of(&emitted, "accept-encoding"),
            ["gzip", "br"],
            "a profile-ordered header must keep every value the caller appended"
        );
        assert_eq!(values_of(&emitted, "x-trace"), ["a", "b"]);
    }

    #[test]
    fn a_callers_repeated_values_stay_together_in_the_profiles_slot() {
        let engine = HeaderEngine::new(Arc::new(Profile::chrome_stable()));
        let (mut request, url, options) = navigation_to("https://example.com/", Version::HTTP_2);
        request
            .headers_mut()
            .append("accept-encoding", HeaderValue::from_static("gzip"));
        request
            .headers_mut()
            .append("accept-encoding", HeaderValue::from_static("br"));

        let emitted = engine
            .apply(&mut request, &url, &options, &AcceptChStore::new())
            .expect("header planning should succeed");

        let names = names_of(&emitted);
        let first = names
            .iter()
            .position(|name| *name == "accept-encoding")
            .expect("accept-encoding should be emitted");
        assert_eq!(names[first + 1], "accept-encoding");
        let expected_slot = Profile::chrome_stable()
            .header_order
            .navigate
            .iter()
            .position(|name| name == "accept-encoding")
            .expect("the captured order includes accept-encoding");
        assert_eq!(first, expected_slot);
    }

    #[test]
    fn a_profile_value_the_http_crate_cannot_encode_is_reported_not_dropped() {
        let mut profile = Profile::chrome_stable();
        profile.user_agent = "Mozilla/5.0 (Macintosh)\nX-Injected: 1".to_owned();
        let engine = HeaderEngine::new(Arc::new(profile));

        let (mut request, url, options) = navigation_to("https://example.com/", Version::HTTP_2);
        let error = engine
            .apply(&mut request, &url, &options, &AcceptChStore::new())
            .expect_err("an unencodable profile value must not be swallowed");

        assert!(
            error.to_string().contains("user-agent"),
            "the error must name the header that could not be encoded, got: {error}"
        );
    }
}
