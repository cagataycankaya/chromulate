//! `Cache-Control` (RFC 9111 §5.2), parsed once into a struct.
//!
//! Two directives in this file are routinely conflated and are not the same
//! thing:
//!
//! - **`no-store`** means *do not keep a copy*. A response carrying it never
//!   enters the cache, and one already stored for that target is dropped.
//! - **`no-cache`** means *keep a copy, but never hand it out without asking the
//!   origin first*. A `no-cache` response is stored and is always revalidated.
//!
//! Reading `no-cache` as `no-store` throws away every conditional request the
//! origin was inviting; reading `no-store` as `no-cache` keeps data the origin
//! asked nobody to keep.

use std::time::Duration;

use http::HeaderMap;
use http::header::{CACHE_CONTROL, PRAGMA};

/// The directives this cache understands, collected from every `Cache-Control`
/// field line on one message.
///
/// Directives this cache does not implement (`stale-while-revalidate`,
/// `stale-if-error`, `min-fresh`, `max-stale`, `only-if-cached`,
/// `proxy-revalidate`, `must-understand`) are parsed as unknown and ignored,
/// which is what RFC 9111 §5.2 requires of a cache that does not implement
/// them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheControl {
    /// `no-store`: do not keep any part of this message.
    pub no_store: bool,
    /// `no-cache`: a stored copy must be revalidated before every reuse.
    ///
    /// The argued form (`no-cache="set-cookie"`) is treated as the bare form,
    /// which is stricter than the specification allows and never unsafe.
    pub no_cache: bool,
    /// `private`: intended for a single user.
    pub private: bool,
    /// `public`: storable even when the request carried `Authorization`.
    pub public: bool,
    /// `must-revalidate`: a stale copy must not be served.
    pub must_revalidate: bool,
    /// `immutable`: the body will not change while it is fresh.
    ///
    /// Recorded but not acted on: this cache never serves a stale response, so
    /// there is no revalidation for `immutable` to suppress.
    pub immutable: bool,
    /// `max-age`, in seconds.
    pub max_age: Option<u64>,
    /// `s-maxage`, in seconds.
    ///
    /// A shared-cache directive (§5.2.2.10). It does not contribute to
    /// freshness here — this is a private cache — but its presence is one of
    /// the three things that make a response to an `Authorization` request
    /// storable by a cache that might be shared (§3.5).
    pub s_maxage: Option<u64>,
}

impl CacheControl {
    /// Parses every `Cache-Control` line on a message.
    ///
    /// Later lines are merged into earlier ones rather than replacing them: a
    /// message with two `Cache-Control` fields means the same as one with their
    /// comma-joined value.
    #[must_use]
    pub fn of(headers: &HeaderMap) -> Self {
        let mut parsed = Self::default();
        for value in headers.get_all(CACHE_CONTROL) {
            if let Ok(text) = value.to_str() {
                parsed.absorb(text);
            }
        }
        parsed
    }

    /// Parses a request's directives, honouring `Pragma: no-cache`.
    ///
    /// RFC 9111 §5.4: a cache reads `Pragma: no-cache` as
    /// `Cache-Control: no-cache` **only** when the request carries no
    /// `Cache-Control` at all. An HTTP/1.0 client that sends `Pragma` and
    /// nothing else still gets its revalidation.
    #[must_use]
    pub fn of_request(headers: &HeaderMap) -> Self {
        let mut parsed = Self::of(headers);
        if !headers.contains_key(CACHE_CONTROL) {
            for value in headers.get_all(PRAGMA) {
                if value.to_str().is_ok_and(|text| {
                    text.split(',')
                        .any(|t| t.trim().eq_ignore_ascii_case("no-cache"))
                }) {
                    parsed.no_cache = true;
                }
            }
        }
        parsed
    }

    /// The freshness lifetime this header alone dictates, if any.
    ///
    /// `s-maxage` is deliberately absent: it applies to shared caches, and
    /// honouring it here would make a response the origin wanted a browser to
    /// hold for a day expire in whatever the CDN was told.
    #[must_use]
    pub fn explicit_lifetime(&self) -> Option<Duration> {
        self.max_age.map(Duration::from_secs)
    }

    fn absorb(&mut self, text: &str) {
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let (name, argument) = match token.split_once('=') {
                Some((name, argument)) => (name.trim(), Some(unquote(argument.trim()))),
                None => (token, None),
            };

            // A directive with an argument still counts as present: RFC 9111
            // §5.2.2.4 lets `private` and `no-cache` name specific fields, and
            // ignoring the argument makes them apply to the whole message.
            match name.to_ascii_lowercase().as_str() {
                "no-store" => self.no_store = true,
                "no-cache" => self.no_cache = true,
                "private" => self.private = true,
                "public" => self.public = true,
                "must-revalidate" => self.must_revalidate = true,
                "immutable" => self.immutable = true,
                "max-age" => self.max_age = argument.and_then(delta_seconds).or(self.max_age),
                "s-maxage" => self.s_maxage = argument.and_then(delta_seconds).or(self.s_maxage),
                _ => {}
            }
        }
    }
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
}

/// Parses a `delta-seconds` value.
///
/// RFC 9111 §1.2.2: a value larger than the recipient can represent is taken as
/// the largest it can represent, so an overlong `max-age` saturates instead of
/// being discarded — the origin asked for "effectively forever" and that is
/// what it gets. `Duration::from_secs(u64::MAX)` is representable, so nothing
/// downstream has to defend against this number.
fn delta_seconds(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(value.parse().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).expect("a valid header name"),
                http::HeaderValue::from_str(value).expect("a valid header value"),
            );
        }
        map
    }

    #[test]
    fn directives_are_case_insensitive_and_tolerate_whitespace() {
        let parsed = CacheControl::of(&headers(&[("cache-control", " No-Store , MAX-AGE=60 ")]));
        assert!(parsed.no_store);
        assert_eq!(parsed.max_age, Some(60));
    }

    #[test]
    fn no_cache_and_no_store_are_not_the_same_directive() {
        let no_cache = CacheControl::of(&headers(&[("cache-control", "no-cache")]));
        assert!(no_cache.no_cache);
        assert!(
            !no_cache.no_store,
            "`no-cache` must not be read as `no-store`: it asks for revalidation, not for deletion"
        );

        let no_store = CacheControl::of(&headers(&[("cache-control", "no-store")]));
        assert!(no_store.no_store);
        assert!(!no_store.no_cache);
    }

    #[test]
    fn two_header_lines_merge_rather_than_replace() {
        let parsed = CacheControl::of(&headers(&[
            ("cache-control", "max-age=30"),
            ("cache-control", "private"),
        ]));
        assert_eq!(parsed.max_age, Some(30));
        assert!(parsed.private);
    }

    #[test]
    fn an_argued_no_cache_applies_to_the_whole_message() {
        let parsed = CacheControl::of(&headers(&[("cache-control", "no-cache=\"set-cookie\"")]));
        assert!(parsed.no_cache);
    }

    /// `max-age` is server-controlled and the grammar puts no ceiling on it.
    /// Saturating keeps the arithmetic total; discarding would have turned an
    /// absurd value into "no freshness information", which is a different
    /// answer.
    #[test]
    fn an_unrepresentable_max_age_saturates_instead_of_being_discarded() {
        let parsed = CacheControl::of(&headers(&[(
            "cache-control",
            "max-age=99999999999999999999999",
        )]));
        assert_eq!(parsed.max_age, Some(u64::MAX));
        assert_eq!(
            parsed.explicit_lifetime(),
            Some(Duration::from_secs(u64::MAX))
        );
    }

    #[test]
    fn a_non_numeric_max_age_is_ignored_rather_than_read_as_zero() {
        let parsed = CacheControl::of(&headers(&[("cache-control", "max-age=soon")]));
        assert_eq!(parsed.max_age, None);
    }

    #[test]
    fn s_maxage_is_recorded_but_never_becomes_a_freshness_lifetime_here() {
        let parsed = CacheControl::of(&headers(&[("cache-control", "s-maxage=600")]));
        assert_eq!(parsed.s_maxage, Some(600));
        assert_eq!(
            parsed.explicit_lifetime(),
            None,
            "s-maxage is a shared-cache directive and this is a private cache"
        );
    }

    #[test]
    fn pragma_no_cache_only_speaks_when_cache_control_is_silent() {
        let alone = CacheControl::of_request(&headers(&[("pragma", "no-cache")]));
        assert!(alone.no_cache);

        let outvoted = CacheControl::of_request(&headers(&[
            ("pragma", "no-cache"),
            ("cache-control", "max-age=60"),
        ]));
        assert!(
            !outvoted.no_cache,
            "`Cache-Control` present means `Pragma` is not consulted at all"
        );
        assert_eq!(outvoted.max_age, Some(60));
    }
}
