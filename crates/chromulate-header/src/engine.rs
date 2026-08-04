//! [`HeaderEngine`]: turning a profile and a request's context into the
//! exact, ordered header list Chrome would have sent.
//!
//! See the crate documentation for why the authoritative result is a `Vec`
//! rather than the request's own `HeaderMap`.
//!
//! Everything about a profile that does not change between requests — the
//! parsed header names, the constant values, the invalid-value diagnostics —
//! is computed once, when the engine is built. `apply` only resolves the
//! handful of values that genuinely depend on the request: `host`, `origin`,
//! `referer`, the `sec-fetch-*` family, and granted client hints.

use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use chromulate_core::{Error, FetchMode, Origin, Request, RequestOptions, Result, referrer_for};
use chromulate_profile::Profile;
use http::{HeaderName, HeaderValue, Method, Version};
use url::Url;

use crate::accept::accept_fallback;
use crate::client_hints::{AcceptChStore, HighEntropyHint, HighEntropyHints};
use crate::fetch_site::FetchSite;
use crate::order::{Named, contains, insert_after, insert_before};
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
    prepared: Prepared,
}

impl HeaderEngine {
    /// Builds an engine for `profile`.
    ///
    /// High-entropy client hints start empty; attach real values with
    /// [`HeaderEngine::with_high_entropy_hints`] if you have a capture that
    /// records them.
    #[must_use]
    pub fn new(profile: Arc<Profile>) -> Self {
        let prepared = Prepared::build(&profile, &HighEntropyHints::default());
        Self {
            profile,
            high_entropy: HighEntropyHints::default(),
            prepared,
        }
    }

    /// Attaches high-entropy client hint values this profile can send once
    /// a server asks for them.
    #[must_use]
    pub fn with_high_entropy_hints(mut self, hints: HighEntropyHints) -> Self {
        self.high_entropy = hints;
        self.prepared = Prepared::build(&self.profile, &self.high_entropy);
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
            origin_header_value(options.mode, &method, options.initiator.as_ref(), &target)
                .map(|value| request_value("origin", value))
                .transpose()?;
        let referer = options
            .referrer
            .as_ref()
            .and_then(|from| referrer_for(from, url))
            .map(|value| request_value("referer", value))
            .transpose()?;
        let host_value = if needs_host(request.version()) {
            host_header_value(url)
                .map(|value| request_value("host", value))
                .transpose()?
        } else {
            None
        };
        let user_activated = request
            .extensions()
            .get::<UserActivatedNavigation>()
            .is_some();
        let granted = accept_ch.granted_for(&target);

        let base = if options.mode == FetchMode::Navigate {
            &self.prepared.navigate
        } else {
            &self.prepared.subresource
        };
        let order = build_order(
            base,
            &self.prepared,
            host_value.is_some(),
            origin_header.is_some(),
            referer.is_some(),
            user_activated,
            &granted,
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

        let caller_headers = std::mem::take(request.headers_mut());
        let headers = request.headers_mut();
        headers.reserve(order.len() + caller_headers.len());
        let mut result = Vec::with_capacity(order.len() + caller_headers.len());

        for (position, slot) in order.iter().enumerate() {
            // `build_order` keeps a name out of the order when the capture
            // already places it, but a capture that lists one twice would
            // still reach here twice, and this loop walks positionally.
            if order[..position]
                .iter()
                .any(|earlier| earlier.header_name == slot.header_name)
            {
                continue;
            }

            let mut caller_values = caller_headers.get_all(&slot.header_name).into_iter();
            if let Some(first) = caller_values.next() {
                // The caller wins over the profile, in the profile's slot —
                // for every value they supplied, not just the first.
                headers.insert(slot.header_name.clone(), first.clone());
                result.push((slot.header_name.clone(), first.clone()));
                for extra in caller_values {
                    headers.append(slot.header_name.clone(), extra.clone());
                    result.push((slot.header_name.clone(), extra.clone()));
                }
            } else if let Some(value) = self.slot_value(slot, &ctx)? {
                headers.insert(slot.header_name.clone(), value.clone());
                result.push((slot.header_name.clone(), value));
            }
        }

        for (name, value) in &caller_headers {
            if !order.iter().any(|slot| slot.header_name == *name) {
                headers.append(name.clone(), value.clone());
                result.push((name.clone(), value.clone()));
            }
        }

        Ok(result)
    }

    /// Resolves the value a slot contributes to this request, or `None` when
    /// the header does not apply.
    ///
    /// # Errors
    ///
    /// Returns [`chromulate_core::Error::Config`] naming the header when the
    /// profile's value for it could not be encoded — the loudest fidelity
    /// break this crate can have, reported rather than silently dropped.
    fn slot_value(&self, slot: &Slot, ctx: &Ctx<'_>) -> Result<Option<HeaderValue>> {
        match &slot.value {
            SlotValue::Constant(value) => Ok(Some(value.clone())),
            SlotValue::Absent => Ok(None),
            SlotValue::Invalid(value) => Err(invalid_value_error(&slot.name, value)),
            SlotValue::Dynamic(dynamic) => self.dynamic_value(*dynamic, ctx),
        }
    }

    /// Resolves a value that depends on the request rather than the profile.
    fn dynamic_value(&self, dynamic: DynamicValue, ctx: &Ctx<'_>) -> Result<Option<HeaderValue>> {
        Ok(match dynamic {
            DynamicValue::Accept => Some(self.accept_value(ctx)?),
            DynamicValue::SecFetchSite => Some(HeaderValue::from_static(ctx.fetch_site.as_str())),
            DynamicValue::SecFetchMode => Some(HeaderValue::from_static(ctx.options.mode.as_str())),
            DynamicValue::SecFetchDest => Some(HeaderValue::from_static(ctx.options.dest.as_str())),
            DynamicValue::SecFetchUser => {
                ctx.user_activated.then(|| HeaderValue::from_static("?1"))
            }
            DynamicValue::UpgradeInsecureRequests => {
                (ctx.options.mode == FetchMode::Navigate).then(|| HeaderValue::from_static("1"))
            }
            DynamicValue::Priority => {
                Some(HeaderValue::from_static(priority_for(ctx.options.dest)))
            }
            DynamicValue::Referer => ctx.referer.clone(),
            DynamicValue::Origin => ctx.origin_header.clone(),
            DynamicValue::Host => ctx.host_value.clone(),
            DynamicValue::Hint(hint) => {
                if !ctx.granted.contains(&hint) {
                    return Ok(None);
                }
                match self.prepared.hint_value(hint) {
                    PreparedValue::Valid(value) => Some(value.clone()),
                    PreparedValue::Invalid(value) => {
                        return Err(invalid_value_error(hint.header_name(), value));
                    }
                    PreparedValue::Missing => None,
                }
            }
        })
    }

    /// The `Accept` value for this request's destination.
    ///
    /// A document (or iframe) gets the profile's own captured value; every
    /// other destination gets the uncaptured fallback from [`crate::accept`].
    fn accept_value(&self, ctx: &Ctx<'_>) -> Result<HeaderValue> {
        match accept_fallback(ctx.options.dest) {
            Some(fallback) => Ok(HeaderValue::from_static(fallback)),
            None => match &self.prepared.document_accept {
                PreparedValue::Valid(value) => Ok(value.clone()),
                PreparedValue::Invalid(value) => Err(invalid_value_error("accept", value)),
                // `Prepared::build` always encodes the profile's `accept`
                // into `Valid` or `Invalid`; `Missing` exists for hints.
                PreparedValue::Missing => Err(invalid_value_error("accept", "")),
            },
        }
    }
}

/// The error for a profile value the `http` crate cannot encode. Those used
/// to be silently dropped, so an unencodable `user-agent` simply vanished
/// from the wire order with nothing raised and nothing logged; the loudest
/// fidelity break this crate can have, delivered silently.
fn invalid_value_error(name: &str, value: &str) -> Error {
    Error::config(format!(
        "the profile's value for header `{name}` is not a valid HTTP header value: {value:?}"
    ))
}

/// Encodes a per-request derived value — `host`, `origin`, `referer` —
/// reusing the `String`'s own buffer rather than copying it.
fn request_value(name: &str, value: String) -> Result<HeaderValue> {
    HeaderValue::from_maybe_shared(Bytes::from(value.into_bytes())).map_err(|_| {
        Error::config(format!(
            "the computed value for header `{name}` is not a valid HTTP header value"
        ))
    })
}

/// Everything about the profile that `apply` would otherwise re-derive on
/// every request: parsed names, constant values, and the two plans the
/// profile's captured orders describe.
#[derive(Debug, Clone)]
struct Prepared {
    /// The navigation order, one slot per captured name.
    navigate: Vec<Slot>,
    /// The subresource order, which for the shipped capture falls back to
    /// the navigation order (see [`HeaderEngine`]'s order documentation).
    subresource: Vec<Slot>,
    /// `host`, inserted at the front when HTTP/1.x needs it.
    host: Slot,
    /// `origin`, inserted before `sec-fetch-site` when the request carries one.
    origin: Slot,
    /// `referer`, inserted after `sec-fetch-dest` when the request carries one.
    referer: Slot,
    /// `sec-fetch-user`, inserted before `sec-fetch-dest` on user activation.
    sec_fetch_user: Slot,
    /// One slot per high-entropy hint, in emit order.
    hints: Vec<Slot>,
    /// The profile's captured `accept` value for a document navigation.
    document_accept: PreparedValue,
    /// Per-hint values, aligned with [`HighEntropyHint::ALL_IN_EMIT_ORDER`].
    hint_values: Vec<PreparedValue>,
}

impl Prepared {
    fn build(profile: &Profile, high_entropy: &HighEntropyHints) -> Self {
        let navigate = plan_of(&profile.header_order.navigate, profile);
        let subresource = plan_of(profile.header_order.subresource_or_navigate(), profile);
        let hints = HighEntropyHint::ALL_IN_EMIT_ORDER
            .into_iter()
            .filter_map(|hint| {
                slot(
                    hint.header_name(),
                    SlotValue::Dynamic(DynamicValue::Hint(hint)),
                )
            })
            .collect();
        let hint_values = HighEntropyHint::ALL_IN_EMIT_ORDER
            .into_iter()
            .map(|hint| match high_entropy.value_for(hint) {
                Some(value) => prepared_value(value.to_owned()),
                None => PreparedValue::Missing,
            })
            .collect();
        Self {
            navigate,
            subresource,
            host: known_slot("host", DynamicValue::Host),
            origin: known_slot("origin", DynamicValue::Origin),
            referer: known_slot("referer", DynamicValue::Referer),
            sec_fetch_user: known_slot("sec-fetch-user", DynamicValue::SecFetchUser),
            hints,
            document_accept: prepared_value(profile.accept.clone()),
            hint_values,
        }
    }

    /// The prepared value for `hint`.
    fn hint_value(&self, hint: HighEntropyHint) -> &PreparedValue {
        let position = HighEntropyHint::ALL_IN_EMIT_ORDER
            .into_iter()
            .position(|candidate| candidate == hint)
            .unwrap_or(0);
        &self.hint_values[position]
    }
}

/// One name in a header order: its parsed form plus how its value is found.
#[derive(Debug, Clone)]
struct Slot {
    /// The lowercase wire name, as the capture spells it.
    name: Box<str>,
    /// The name parsed once, so the request path never re-parses it.
    header_name: HeaderName,
    value: SlotValue,
}

impl Named for &Slot {
    fn order_name(&self) -> &str {
        &self.name
    }
}

/// How a slot's value is produced.
#[derive(Debug, Clone)]
enum SlotValue {
    /// A constant of the profile, encoded and promoted once.
    Constant(HeaderValue),
    /// Computed per request.
    Dynamic(DynamicValue),
    /// The profile carries a value the `http` crate cannot encode; emitting
    /// this slot reports it. Kept for the diagnostic, not for the wire.
    Invalid(String),
    /// The engine has no value for this name; only a caller can supply one.
    Absent,
}

/// A per-profile value that may be missing or unencodable.
#[derive(Debug, Clone)]
enum PreparedValue {
    Valid(HeaderValue),
    Invalid(String),
    Missing,
}

/// The per-request computations `apply` can be asked for.
#[derive(Debug, Clone, Copy)]
enum DynamicValue {
    Accept,
    SecFetchSite,
    SecFetchMode,
    SecFetchDest,
    SecFetchUser,
    UpgradeInsecureRequests,
    Priority,
    Referer,
    Origin,
    Host,
    Hint(HighEntropyHint),
}

/// Builds the slots for one captured order.
fn plan_of(order: &[String], profile: &Profile) -> Vec<Slot> {
    order
        .iter()
        .filter_map(|name| slot(name, classify(name, profile)))
        .collect()
}

/// A slot for `name`, or `None` when the name is not a valid header name —
/// the same names the previous per-request parse skipped.
fn slot(name: &str, value: SlotValue) -> Option<Slot> {
    let header_name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    Some(Slot {
        name: name.into(),
        header_name: promoted(header_name),
        value,
    })
}

/// A slot for a name this crate itself supplies, which is always valid.
fn known_slot(name: &'static str, dynamic: DynamicValue) -> Slot {
    slot(name, SlotValue::Dynamic(dynamic))
        .expect("names supplied by this crate are valid header names")
}

/// How the engine finds a value for `name` — the classification that
/// `engine_value_string` used to redo on every request.
fn classify(name: &str, profile: &Profile) -> SlotValue {
    match name {
        // `Profile::sec_ch_ua` renders the GREASE brand entry
        // (`"Not=A?Brand";v="99"` in the capture) verbatim from static
        // profile data. This engine does not model whether Chrome
        // varies that entry's separator characters or list position per
        // request, per session, or per build — a single capture cannot
        // show that, and inventing a permutation rule would be
        // fabricating fingerprint data. Tracked as a gap in the crate's
        // report.
        "sec-ch-ua" => constant(profile.sec_ch_ua()),
        "sec-ch-ua-mobile" => match profile.observed_headers.get("sec-ch-ua-mobile") {
            Some(value) => constant(value.clone()),
            None => SlotValue::Absent,
        },
        "sec-ch-ua-platform" => constant(profile.sec_ch_ua_platform()),
        "sec-ch-ua-platform-version" => {
            SlotValue::Dynamic(DynamicValue::Hint(HighEntropyHint::PlatformVersion))
        }
        "sec-ch-ua-arch" => SlotValue::Dynamic(DynamicValue::Hint(HighEntropyHint::Arch)),
        "sec-ch-ua-bitness" => SlotValue::Dynamic(DynamicValue::Hint(HighEntropyHint::Bitness)),
        "sec-ch-ua-full-version-list" => {
            SlotValue::Dynamic(DynamicValue::Hint(HighEntropyHint::FullVersionList))
        }
        "sec-ch-ua-model" => SlotValue::Dynamic(DynamicValue::Hint(HighEntropyHint::Model)),
        "upgrade-insecure-requests" => SlotValue::Dynamic(DynamicValue::UpgradeInsecureRequests),
        "user-agent" => constant(profile.user_agent.clone()),
        "accept" => SlotValue::Dynamic(DynamicValue::Accept),
        "sec-fetch-site" => SlotValue::Dynamic(DynamicValue::SecFetchSite),
        "sec-fetch-mode" => SlotValue::Dynamic(DynamicValue::SecFetchMode),
        "sec-fetch-user" => SlotValue::Dynamic(DynamicValue::SecFetchUser),
        "sec-fetch-dest" => SlotValue::Dynamic(DynamicValue::SecFetchDest),
        "referer" => SlotValue::Dynamic(DynamicValue::Referer),
        "origin" => SlotValue::Dynamic(DynamicValue::Origin),
        "accept-encoding" => constant(profile.accept_encoding.clone()),
        "accept-language" => constant(profile.accept_language.clone()),
        "priority" => SlotValue::Dynamic(DynamicValue::Priority),
        "host" => SlotValue::Dynamic(DynamicValue::Host),
        _ => SlotValue::Absent,
    }
}

/// Encodes a profile constant, keeping the diagnostic when it cannot be.
fn constant(value: String) -> SlotValue {
    match HeaderValue::from_str(&value) {
        Ok(encoded) => SlotValue::Constant(promoted(encoded)),
        Err(_) => SlotValue::Invalid(value),
    }
}

/// Encodes a per-profile value that may also be absent.
fn prepared_value(value: String) -> PreparedValue {
    match HeaderValue::from_str(&value) {
        Ok(encoded) => PreparedValue::Valid(promoted(encoded)),
        Err(_) => PreparedValue::Invalid(value),
    }
}

/// Pays a `Bytes`-backed value's promotion cost here, at construction.
///
/// A `HeaderName` or `HeaderValue` built from a `&str` is backed by a
/// vec-backed `Bytes`, whose *first* clone allocates a shared header and
/// converts both copies to the reference-counted representation; every
/// clone after that is a count bump. Cloning once here moves that one
/// allocation off the per-request path.
fn promoted<T: Clone>(value: T) -> T {
    let shared = value.clone();
    drop(value);
    shared
}

/// Per-request facts the engine needs while resolving header values, kept
/// off the request itself since most of them are derived, not stored.
struct Ctx<'a> {
    options: &'a RequestOptions,
    fetch_site: FetchSite,
    referer: Option<HeaderValue>,
    origin_header: Option<HeaderValue>,
    host_value: Option<HeaderValue>,
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

/// Builds the final header order: the profile's captured order, plus
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
fn build_order<'plan>(
    base: &'plan [Slot],
    prepared: &'plan Prepared,
    needs_host: bool,
    needs_origin: bool,
    needs_referer: bool,
    user_activated: bool,
    granted: &HashSet<HighEntropyHint>,
) -> Vec<&'plan Slot> {
    let mut order: Vec<&Slot> = base.iter().collect();

    if needs_host && !contains(&order, "host") {
        order.insert(0, &prepared.host);
    }

    // High-entropy hints join the low-entropy group Chrome already sends.
    if !granted.is_empty() {
        let anchor = order
            .iter()
            .position(|slot| slot.order_name() == "sec-ch-ua-platform");
        let mut inserted = 0;
        for hint_slot in &prepared.hints {
            let SlotValue::Dynamic(DynamicValue::Hint(hint)) = hint_slot.value else {
                continue;
            };
            if !granted.contains(&hint) || contains(&order, &hint_slot.name) {
                continue;
            }
            match anchor {
                Some(anchor) => {
                    order.insert(anchor + 1 + inserted, hint_slot);
                    inserted += 1;
                }
                None => order.push(hint_slot),
            }
        }
    }

    if needs_origin {
        insert_before(&mut order, "sec-fetch-site", &prepared.origin);
    }

    if user_activated {
        insert_before(&mut order, "sec-fetch-dest", &prepared.sec_fetch_user);
    }

    if needs_referer {
        insert_after(&mut order, "sec-fetch-dest", &prepared.referer);
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

    #[test]
    fn the_map_after_apply_carries_every_emitted_header_and_the_callers_extras() {
        let engine = HeaderEngine::new(Arc::new(Profile::chrome_stable()));
        let (mut request, url, options) = navigation_to("https://example.com/", Version::HTTP_2);
        request
            .headers_mut()
            .append("x-trace", HeaderValue::from_static("a"));

        let emitted = engine
            .apply(&mut request, &url, &options, &AcceptChStore::new())
            .expect("header planning should succeed");

        for (name, value) in &emitted {
            assert!(
                request
                    .headers()
                    .get_all(name)
                    .into_iter()
                    .any(|held| held == value),
                "the request map must hold `{name}` after apply"
            );
        }
        assert_eq!(request.headers().len(), emitted.len());
    }
}
