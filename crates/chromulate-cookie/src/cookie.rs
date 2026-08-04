//! A single stored cookie: `Set-Cookie` parsing and the per-request eligibility checks
//! that do not depend on jar-wide bookkeeping (creation order, last access).

use std::time::{Duration, SystemTime};

use chromulate_core::CookieContext;
use http::HeaderValue;

use crate::same_site::SameSite;
use crate::{date, domain, path};

/// Chrome caps a cookie's lifetime at 400 days from when it is set, regardless of what
/// `Expires`/`Max-Age` requests, to blunt cookie-lifetime-based tracking. This crate
/// matches that cap; RFC 6265 itself places no ceiling on cookie lifetime.
const MAX_COOKIE_LIFETIME: Duration = Duration::from_secs(400 * 24 * 60 * 60);

/// RFC 6265bis §4.1.3: a `__Secure-` name promises the cookie was set with the `Secure`
/// attribute, from a secure origin.
const SECURE_PREFIX: &str = "__Secure-";

/// RFC 6265bis §4.1.3: a `__Host-` name promises everything `__Secure-` does, and in
/// addition that the cookie is host-only (no `Domain` attribute at all) and scoped to
/// `/`, so no other host under the same registrable domain can have written it.
const HOST_PREFIX: &str = "__Host-";

/// A cookie's attributes, already validated and resolved against the request that set
/// it. Jar-wide bookkeeping (creation order, last-access order) lives alongside this in
/// `jar::Entry`, not here, so this type stays testable without a jar.
#[derive(Debug, Clone)]
pub(crate) struct Cookie {
    pub(crate) name: String,
    pub(crate) value: String,
    /// The exact host for a host-only cookie, or the (lowercased, dot-stripped) `Domain`
    /// attribute value otherwise.
    pub(crate) domain: String,
    pub(crate) host_only: bool,
    pub(crate) path: String,
    pub(crate) secure: bool,
    pub(crate) http_only: bool,
    pub(crate) same_site: SameSite,
    pub(crate) partitioned: bool,
    /// `None` means a session cookie: it never expires by time, only by eviction.
    pub(crate) expires: Option<SystemTime>,
}

impl Cookie {
    /// Parses one `Set-Cookie` header value into a validated [`Cookie`], or returns
    /// `None` if it is malformed or fails a browser eligibility rule (public-suffix
    /// `Domain`, a `Domain` the request host is not within, `SameSite=None` without
    /// `Secure`, or a name prefix whose guarantee the cookie does not keep). Per RFC
    /// 6265 §5.3, a set-cookie-string that fails validation is ignored entirely rather
    /// than partially applied.
    ///
    /// `request_is_secure` is needed for the RFC 6265bis §4.1.3 name prefixes, both of
    /// which require a secure origin; it does not otherwise restrict what a response may
    /// set.
    ///
    /// `now` resolves `Max-Age` and the 400-day lifetime cap; it does not affect
    /// `Expires`, which is parsed as an absolute date.
    pub(crate) fn parse(
        header: &HeaderValue,
        request_host: &str,
        request_path: &str,
        request_is_secure: bool,
        now: SystemTime,
    ) -> Option<Cookie> {
        // `to_str` already rejects control characters and non-ASCII bytes (anything
        // `HeaderValue` doesn't consider visible ASCII), which covers the cookie-octet
        // grammar's ban on control characters. It does not enforce the *rest* of that
        // grammar (no space, comma, DQUOTE, backslash) - real browsers are far more
        // permissive than the ABNF here, and this crate matches that leniency rather
        // than the strict grammar.
        let raw = header.to_str().ok()?;
        let mut segments = raw.split(';');

        let first = segments.next()?.trim();
        let eq = first.find('=')?;
        let name = first[..eq].trim();
        let mut value = first[eq + 1..].trim();
        if name.is_empty() {
            return None;
        }
        if let Some(unquoted) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            value = unquoted;
        }

        let mut expires: Option<SystemTime> = None;
        let mut max_age: Option<i64> = None;
        let mut domain_attr: Option<String> = None;
        let mut path_attr: Option<String> = None;
        let mut secure = false;
        let mut http_only = false;
        let mut same_site: Option<SameSite> = None;
        let mut partitioned = false;

        for segment in segments {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            let (attr_name, attr_value) = match segment.find('=') {
                Some(idx) => (&segment[..idx], Some(segment[idx + 1..].trim())),
                None => (segment, None),
            };
            match attr_name.trim().to_ascii_lowercase().as_str() {
                "expires" => {
                    if let Some(v) = attr_value {
                        if let Some(t) = date::parse_cookie_date(v) {
                            expires = Some(t);
                        }
                    }
                }
                "max-age" => {
                    if let Some(v) = attr_value {
                        if let Ok(n) = v.parse::<i64>() {
                            max_age = Some(n);
                        }
                    }
                }
                "domain" => {
                    if let Some(v) = attr_value {
                        let stripped = v.strip_prefix('.').unwrap_or(v);
                        if !stripped.is_empty() {
                            domain_attr = Some(stripped.to_ascii_lowercase());
                        }
                    }
                }
                "path" => {
                    if let Some(v) = attr_value {
                        path_attr = Some(v.to_owned());
                    }
                }
                "secure" => secure = true,
                "httponly" => http_only = true,
                "samesite" => {
                    if let Some(v) = attr_value {
                        // An unrecognised value is treated the same as an absent
                        // attribute (falls through to the `Lax` default below), matching
                        // browser behaviour: a typo in `SameSite` should not silently
                        // turn into `Strict`-like blocking.
                        same_site = match v.to_ascii_lowercase().as_str() {
                            "strict" => Some(SameSite::Strict),
                            "lax" => Some(SameSite::Lax),
                            "none" => Some(SameSite::None),
                            _ => None,
                        };
                    }
                }
                "partitioned" => partitioned = true,
                // Unknown attributes are ignored, not errors.
                _ => {}
            }
        }

        // Whether a `Domain` attribute was present at all, which is not the same question
        // as `host_only`: the IP-literal branch below records an exact-match `Domain` as
        // host-only, and `__Host-` requires no `Domain` attribute whatsoever.
        let has_domain_attribute = domain_attr.is_some();

        let (domain, host_only) = match domain_attr {
            None => (request_host.to_owned(), true),
            // The public suffix list does not apply to IP addresses; an IP host may only
            // set a cookie for itself, exactly (RFC 6265 §5.1.3 domain matching
            // implicitly excludes IP literals from subdomain scoping).
            Some(d) if domain::is_ip_literal(request_host) => {
                if d == request_host {
                    (request_host.to_owned(), true)
                } else {
                    return None;
                }
            }
            Some(d) => {
                if domain::is_public_suffix(&d) || !domain::domain_matches(request_host, &d) {
                    return None;
                }
                (d, false)
            }
        };

        let path = match &path_attr {
            Some(p) if p.starts_with('/') => p.clone(),
            _ => path::default_path(request_path),
        };

        let same_site = same_site.unwrap_or(SameSite::Lax);
        if same_site == SameSite::None && !secure {
            return None;
        }

        // RFC 6265bis §5.7 steps 20 and 21. A cookie whose name carries a prefix it does
        // not satisfy is rejected outright rather than accepted with its attributes
        // corrected: the whole value of a prefix is that a server can trust the
        // guarantee, and a guarantee that is quietly repaired on the way in cannot be
        // trusted at all.
        //
        // The prefixes are disjoint, so at most one arm can apply. The match is
        // case-insensitive, which the spec is explicit about and gives the reason for: a
        // server that compares names case-insensitively would treat `__SeCuRe-x` as a
        // prefixed cookie, so a user agent matching case-sensitively would let an
        // attacker forge one.
        //
        // One deliberate narrowing of step 21: the spec asks for a `Path` attribute to be
        // present *and* the resolved path to be `/`. This checks only the resolved path,
        // which is what Chromium does, and admits `__Host-x=1; Secure` from a request to
        // `/` — whose path resolves to `/` anyway, so the guarantee still holds.
        // Rejecting it would mean rejecting a cookie browsers accept.
        if carries_a_name_prefix(name) {
            // The origin half of the rule, which only this path can judge: a snapshot
            // being imported has no record of the request that first set the cookie.
            if !request_is_secure {
                return None;
            }
            // The cookie-state half, shared with `Jar::import` so that the second door
            // into the jar cannot skip it. `host_only` is passed as "no `Domain`
            // attribute was present" rather than the resolved flag, because the
            // IP-literal branch above records an exact-match `Domain` as host-only.
            if !keeps_name_prefix_promise(name, secure, !has_domain_attribute, &path) {
                return None;
            }
        }

        let lifetime_cap = now.checked_add(MAX_COOKIE_LIFETIME).unwrap_or(now);
        let resolved_expires = match max_age {
            // Max-Age wins over Expires when both are present. Zero or negative expires
            // the cookie immediately.
            Some(seconds) if seconds <= 0 => Some(now),
            Some(seconds) => {
                let requested_secs = u64::try_from(seconds).unwrap_or(u64::MAX);
                let requested = now
                    .checked_add(Duration::from_secs(requested_secs))
                    .unwrap_or(lifetime_cap);
                Some(requested.min(lifetime_cap))
            }
            None => expires.map(|e| e.min(lifetime_cap)),
        };

        Some(Cookie {
            name: name.to_owned(),
            value: value.to_owned(),
            domain,
            host_only,
            path,
            secure,
            http_only,
            same_site,
            partitioned,
            expires: resolved_expires,
        })
    }

    /// Whether this cookie has expired as of `now`. Session cookies (`expires: None`)
    /// are never expired by time; they only leave the jar through eviction.
    pub(crate) fn is_expired(&self, now: SystemTime) -> bool {
        matches!(self.expires, Some(expiry) if expiry <= now)
    }

    /// Whether this cookie is in scope for a request to `request_host`/`request_path`
    /// over a secure or insecure origin. Does not check `SameSite`; see
    /// [`Cookie::same_site_eligible`].
    pub(crate) fn applies_to(
        &self,
        request_host: &str,
        request_path: &str,
        request_is_secure: bool,
    ) -> bool {
        if self.secure && !request_is_secure {
            return false;
        }
        let host_matches = if self.host_only {
            request_host == self.domain
        } else {
            domain::domain_matches(request_host, &self.domain)
        };
        host_matches && path::path_matches(request_path, &self.path)
    }

    /// Whether `context` makes this cookie's `SameSite` attribute eligible for a request
    /// to `request_host`.
    pub(crate) fn same_site_eligible(&self, request_host: &str, context: &CookieContext) -> bool {
        let is_same_site = context
            .initiator
            .as_ref()
            .is_some_and(|initiator| domain::is_same_site(initiator.host(), request_host));

        match self.same_site {
            SameSite::None => true,
            SameSite::Lax => is_same_site || context.is_top_level_navigation,
            SameSite::Strict => is_same_site,
        }
    }
}

/// Whether `name` carries either RFC 6265bis §4.1.3 name prefix.
pub(crate) fn carries_a_name_prefix(name: &str) -> bool {
    starts_with_ignore_ascii_case(name, HOST_PREFIX)
        || starts_with_ignore_ascii_case(name, SECURE_PREFIX)
}

/// Whether a cookie's own state keeps the promise its name prefix makes.
///
/// This is the part of RFC 6265bis §5.7 steps 20-21 that can be judged from a stored
/// cookie alone, without knowing anything about the request that set it. It is shared by
/// the two ways a cookie gets into the jar — [`Cookie::parse`] and `Jar::import` — because
/// a guarantee enforced on only one of them is not a guarantee: `import` builds a `Cookie`
/// directly, and a hand-written [`CookieRecord`](crate::CookieRecord) naming itself
/// `__Host-session` with a `Domain` scope and no `Secure` would otherwise be served to
/// every subdomain over plaintext.
///
/// `host_only` means "no `Domain` scope", which is what `__Host-` actually forbids.
pub(crate) fn keeps_name_prefix_promise(
    name: &str,
    secure: bool,
    host_only: bool,
    path: &str,
) -> bool {
    if starts_with_ignore_ascii_case(name, HOST_PREFIX) {
        return secure && host_only && path == "/";
    }
    if starts_with_ignore_ascii_case(name, SECURE_PREFIX) {
        return secure;
    }
    true
}

/// Whether `text` begins with `prefix`, ignoring ASCII case.
///
/// Compared as bytes rather than through string slicing, so a name that is not ASCII
/// cannot land the comparison in the middle of a UTF-8 character.
fn starts_with_ignore_ascii_case(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).expect("test header should be valid")
    }

    fn parse(s: &str) -> Option<Cookie> {
        Cookie::parse(&header(s), "example.com", "/", true, SystemTime::UNIX_EPOCH)
    }

    fn parse_over_plaintext(s: &str) -> Option<Cookie> {
        Cookie::parse(
            &header(s),
            "example.com",
            "/",
            false,
            SystemTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn a_bare_name_value_pair_parses_as_a_host_only_session_cookie() {
        let cookie = parse("session=abc123").expect("should parse");
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "abc123");
        assert!(cookie.host_only);
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/");
        assert_eq!(cookie.same_site, SameSite::Lax);
        assert!(cookie.expires.is_none());
    }

    #[test]
    fn a_quoted_value_is_unquoted() {
        let cookie = parse(r#"name="quoted value""#).expect("should parse");
        assert_eq!(cookie.value, "quoted value");
    }

    #[test]
    fn leading_and_trailing_whitespace_around_the_pair_and_attributes_is_trimmed() {
        let cookie = parse("  name = value  ;  Secure  ;  HttpOnly  ").expect("should parse");
        assert_eq!(cookie.name, "name");
        assert_eq!(cookie.value, "value");
        assert!(cookie.secure);
        assert!(cookie.http_only);
    }

    #[test]
    fn unknown_attributes_are_ignored_without_invalidating_the_cookie() {
        let cookie = parse("name=value; Foo=Bar; Secure").expect("should parse");
        assert!(cookie.secure);
    }

    #[test]
    fn empty_attribute_segments_from_doubled_semicolons_are_skipped() {
        let cookie = parse("name=value;; Secure").expect("should parse");
        assert!(cookie.secure);
    }

    #[test]
    fn attribute_names_are_case_insensitive() {
        let cookie = parse("name=value; SECURE; HTTPONLY; SameSite=STRICT").expect("should parse");
        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site, SameSite::Strict);
    }

    #[test]
    fn a_pair_with_no_equals_sign_is_rejected() {
        assert!(parse("just-a-value").is_none());
    }

    #[test]
    fn a_pair_with_an_empty_name_is_rejected() {
        assert!(parse("=value").is_none());
    }

    #[test]
    fn a_secure_prefixed_name_requires_the_secure_attribute_and_a_secure_origin() {
        assert!(parse("__Secure-a=1").is_none());
        assert!(parse_over_plaintext("__Secure-a=1; Secure").is_none());
        assert!(parse("__Secure-a=1; Secure").is_some());
    }

    #[test]
    fn a_host_prefixed_name_requires_secure_no_domain_attribute_and_a_root_path() {
        assert!(parse("__Host-a=1").is_none());
        assert!(parse_over_plaintext("__Host-a=1; Secure").is_none());
        assert!(parse("__Host-a=1; Secure; Domain=example.com").is_none());
        assert!(parse("__Host-a=1; Secure; Path=/admin").is_none());
        assert!(parse("__Host-a=1; Secure").is_some());
        assert!(parse("__Host-a=1; Secure; Path=/").is_some());
    }

    #[test]
    fn a_host_prefixed_name_is_rejected_when_the_default_path_is_not_the_root() {
        // No `Path` attribute, so the default path is the request's directory. That is
        // not `/`, and `__Host-` promises `/`.
        let cookie = Cookie::parse(
            &header("__Host-a=1; Secure"),
            "example.com",
            "/accounts/login",
            true,
            SystemTime::UNIX_EPOCH,
        );
        assert!(cookie.is_none());
    }

    #[test]
    fn a_host_prefixed_name_on_an_ip_host_still_needs_no_domain_attribute() {
        // The IP-literal branch records an exact-match `Domain` as host-only, so a check
        // written against `host_only` rather than the attribute would wave this through.
        let cookie = Cookie::parse(
            &header("__Host-a=1; Secure; Domain=127.0.0.1"),
            "127.0.0.1",
            "/",
            true,
            SystemTime::UNIX_EPOCH,
        );
        assert!(cookie.is_none());
    }

    #[test]
    fn a_prefix_written_in_a_different_case_is_still_enforced() {
        assert!(parse("__HOST-a=1; Secure; Domain=example.com").is_none());
        assert!(parse("__host-a=1; Secure; Path=/admin").is_none());
        assert!(parse_over_plaintext("__secure-a=1").is_none());
        assert!(parse_over_plaintext("__SeCuRe-a=1").is_none());
    }

    #[test]
    fn a_name_that_merely_resembles_a_prefix_is_left_alone() {
        assert!(parse_over_plaintext("__Host=1").is_some());
        assert!(parse_over_plaintext("__Secure=1").is_some());
        assert!(parse_over_plaintext("_Host-a=1").is_some());
        assert!(parse_over_plaintext("x__Host-a=1").is_some());
    }

    #[test]
    fn samesite_none_without_secure_is_rejected() {
        assert!(parse("name=value; SameSite=None").is_none());
    }

    #[test]
    fn samesite_none_with_secure_is_accepted() {
        let cookie = parse("name=value; SameSite=None; Secure").expect("should parse");
        assert_eq!(cookie.same_site, SameSite::None);
    }

    #[test]
    fn an_unrecognised_samesite_value_falls_back_to_the_lax_default() {
        let cookie = parse("name=value; SameSite=Bogus").expect("should parse");
        assert_eq!(cookie.same_site, SameSite::Lax);
    }

    #[test]
    fn a_domain_attribute_that_is_a_public_suffix_is_rejected() {
        let cookie = Cookie::parse(
            &header("name=value; Domain=co.uk"),
            "a.co.uk",
            "/",
            true,
            SystemTime::UNIX_EPOCH,
        );
        assert!(cookie.is_none());
    }

    #[test]
    fn a_domain_attribute_under_the_public_suffix_is_accepted() {
        let cookie = Cookie::parse(
            &header("name=value; Domain=.example.co.uk"),
            "www.example.co.uk",
            "/",
            true,
            SystemTime::UNIX_EPOCH,
        )
        .expect("should parse");
        assert_eq!(cookie.domain, "example.co.uk");
        assert!(!cookie.host_only);
    }

    #[test]
    fn a_domain_attribute_the_request_host_is_not_within_is_rejected() {
        let cookie = Cookie::parse(
            &header("name=value; Domain=other.test"),
            "example.com",
            "/",
            true,
            SystemTime::UNIX_EPOCH,
        );
        assert!(cookie.is_none());
    }

    #[test]
    fn max_age_wins_over_expires_when_both_are_present() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let cookie = Cookie::parse(
            &header("name=value; Max-Age=60; Expires=Sun, 06 Nov 1994 08:49:37 GMT"),
            "example.com",
            "/",
            true,
            now,
        )
        .expect("should parse");
        assert_eq!(cookie.expires, Some(now + Duration::from_secs(60)));
    }

    #[test]
    fn a_zero_max_age_expires_the_cookie_immediately() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let cookie = Cookie::parse(
            &header("name=value; Max-Age=0"),
            "example.com",
            "/",
            true,
            now,
        )
        .expect("should parse");
        assert!(cookie.is_expired(now));
    }

    #[test]
    fn a_negative_max_age_expires_the_cookie_immediately() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let cookie = Cookie::parse(
            &header("name=value; Max-Age=-1"),
            "example.com",
            "/",
            true,
            now,
        )
        .expect("should parse");
        assert!(cookie.is_expired(now));
    }

    #[test]
    fn a_non_numeric_max_age_is_ignored_leaving_the_cookie_a_session_cookie() {
        let cookie = parse("name=value; Max-Age=not-a-number").expect("should parse");
        assert!(cookie.expires.is_none());
    }

    #[test]
    fn an_extreme_max_age_is_capped_at_400_days() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let cookie = Cookie::parse(
            &header("name=value; Max-Age=99999999999"),
            "example.com",
            "/",
            true,
            now,
        )
        .expect("should parse");
        assert_eq!(cookie.expires, Some(now + MAX_COOKIE_LIFETIME));
    }

    #[test]
    fn secure_cookies_are_withheld_from_an_insecure_request() {
        let cookie = parse("name=value; Secure").expect("should parse");
        assert!(!cookie.applies_to("example.com", "/", false));
        assert!(cookie.applies_to("example.com", "/", true));
    }

    #[test]
    fn a_host_only_cookie_does_not_apply_to_a_subdomain() {
        let cookie = parse("name=value").expect("should parse");
        assert!(!cookie.applies_to("sub.example.com", "/", true));
    }

    #[test]
    fn a_longer_cookie_path_does_not_apply_to_a_shorter_request_path() {
        let cookie = Cookie::parse(
            &header("name=value; Path=/accounts"),
            "example.com",
            "/accounts",
            true,
            SystemTime::UNIX_EPOCH,
        )
        .expect("should parse");
        assert!(!cookie.applies_to("example.com", "/", true));
        assert!(cookie.applies_to("example.com", "/accounts/login", true));
    }

    #[test]
    fn strict_cookies_are_withheld_from_a_cross_site_request() {
        use chromulate_core::Origin;
        use url::Url;

        let cookie = parse("name=value; SameSite=Strict").expect("should parse");
        let same_site_context = CookieContext {
            initiator: Some(Origin::of(&Url::parse("https://example.com/").unwrap()).unwrap()),
            is_top_level_navigation: false,
        };
        let cross_site_context = CookieContext {
            initiator: Some(Origin::of(&Url::parse("https://other.test/").unwrap()).unwrap()),
            is_top_level_navigation: true,
        };
        assert!(cookie.same_site_eligible("example.com", &same_site_context));
        assert!(!cookie.same_site_eligible("example.com", &cross_site_context));
    }

    #[test]
    fn lax_cookies_ride_along_on_a_cross_site_top_level_navigation_but_not_a_subresource() {
        use chromulate_core::Origin;
        use url::Url;

        let cookie = parse("name=value; SameSite=Lax").expect("should parse");
        let cross_site_navigation = CookieContext {
            initiator: Some(Origin::of(&Url::parse("https://other.test/").unwrap()).unwrap()),
            is_top_level_navigation: true,
        };
        let cross_site_subresource = CookieContext {
            initiator: Some(Origin::of(&Url::parse("https://other.test/").unwrap()).unwrap()),
            is_top_level_navigation: false,
        };
        assert!(cookie.same_site_eligible("example.com", &cross_site_navigation));
        assert!(!cookie.same_site_eligible("example.com", &cross_site_subresource));
    }
}
