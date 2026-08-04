//! The decisions: may this be stored, and is a stored copy still fresh.
//!
//! Every function here is pure and takes its `now` as an argument, so the rules
//! can be tested at the boundary rather than around it.
//!
//! # Clock arithmetic is total
//!
//! `SystemTime + Duration` panics on overflow, and `Age`, `max-age`, and
//! `Expires` are all server-controlled and unbounded. Nothing in this file adds
//! a `Duration` to a `SystemTime`. Ages and lifetimes are both `Duration`s and
//! are compared as such; every subtraction goes through `duration_since(..)`
//! with an explicit answer for the negative case. A hostile `max-age` is
//! therefore a very large `Duration`, not a panic.

use std::time::{Duration, SystemTime};

use http::header::{AUTHORIZATION, ETAG, LAST_MODIFIED, SET_COOKIE};
use http::{HeaderMap, HeaderName, Method, StatusCode};

use crate::directive::CacheControl;
use crate::entry::{CacheEntry, vary_names};

/// How the cache behaves, beyond what the messages themselves say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheConfig {
    /// The largest body this cache will store.
    ///
    /// A response longer than this streams to the caller untouched and is not
    /// stored: a cache that buffered every body would turn a constant-memory
    /// download into a resident one. Eight megabytes by default.
    ///
    /// This budget and the store's are set independently and do not have to
    /// agree, but a body that passes here and does not fit in a shard of
    /// [`MemoryLimits`](crate::MemoryLimits) is buffered and then refused,
    /// which is the cost of the buffer for none of the benefit. The defaults
    /// are in that position: eight megabytes here against a default shard's
    /// two. Lower this, or raise `max_bytes`, if the origin serves bodies in
    /// between and the hit is worth having.
    pub max_body_bytes: u64,
    /// Whether a response marked `Cache-Control: private` may be stored.
    ///
    /// **`false` by default, which is not what a browser does.** A browser's
    /// cache belongs to one person, so `private` is exactly the case it is for.
    /// A `chromulate` engine is frequently shared — one client, many crawled
    /// identities, or a proxy in front of several users — and this crate cannot
    /// tell the two deployments apart. The safe default is the one where a
    /// mistake costs a cache miss rather than one user's page.
    ///
    /// Set it to `true` when the engine belongs to a single identity. Doing so
    /// also enables storing responses to requests that carried `Authorization`,
    /// for the same reason and with the same caveat.
    pub store_private: bool,
    /// The ceiling on a heuristic freshness lifetime (RFC 9111 §4.2.2).
    ///
    /// The heuristic itself is the widely implemented one: a tenth of the time
    /// since `Last-Modified`. The specification leaves the cap to the
    /// implementation; twenty-four hours is what this cache uses, so a document
    /// last touched years ago is still re-checked daily.
    pub heuristic_cap: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 8 * 1024 * 1024,
            store_private: false,
            heuristic_cap: Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// Why a response was not stored.
///
/// Carried so that the trace line says which rule fired; a cache that silently
/// stores nothing and a cache that silently stores everything look identical
/// from the outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotStorable {
    Method,
    RequestNoStore,
    ResponseNoStore,
    Status,
    SetCookie,
    VaryStar,
    VaryUnselectable,
    Private,
    Authorization,
    NoFreshnessAndNoValidator,
}

impl std::fmt::Display for NotStorable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::Method => "the method is not GET",
            Self::RequestNoStore => "the request carried Cache-Control: no-store",
            Self::ResponseNoStore => "the response carried Cache-Control: no-store",
            Self::Status => "the status code is not cacheable",
            Self::SetCookie => "the response carried Set-Cookie",
            Self::VaryStar => "the response carried Vary: *",
            Self::VaryUnselectable => "Vary names a header this cache cannot select on",
            Self::Private => "the response is private and store_private is off",
            Self::Authorization => {
                "the request carried Authorization and the response is not \
                                   explicitly shareable"
            }
            Self::NoFreshnessAndNoValidator => {
                "the response carries neither a freshness lifetime nor a validator"
            }
        };
        f.write_str(reason)
    }
}

/// Statuses this cache will store.
///
/// The heuristically cacheable set from RFC 9110 §15.1, minus `206` — partial
/// content needs range reassembly, which this cache does not do — plus `302`
/// and `307`, which are cacheable when the origin says so explicitly.
fn is_cacheable_status(status: StatusCode) -> bool {
    matches!(
        status.as_u16(),
        200 | 203 | 204 | 300 | 301 | 302 | 307 | 308 | 404 | 405 | 410 | 414 | 501
    )
}

/// Statuses whose freshness may be guessed when the origin gave none.
///
/// `302` and `307` are absent deliberately: a redirect with no expiry is not a
/// redirect a cache may invent a lifetime for.
fn is_heuristically_cacheable(status: StatusCode) -> bool {
    matches!(
        status.as_u16(),
        200 | 203 | 204 | 300 | 301 | 308 | 404 | 405 | 410 | 414 | 501
    )
}

/// Request header fields this cache cannot select on.
///
/// [`crate::HttpCache::before`] sees a request *before*
/// `chromulate_header::HeaderEngine` and the cookie jar have written it, so the
/// selector it records for `Vary` is built from the caller's own headers. For
/// most names that is harmless, because the value the engine goes on to write
/// is a profile constant — `user-agent`, `accept-encoding`, `accept-language`
/// and the low-entropy client hints are the same on every request this engine
/// makes, so matching two requests on "absent" is matching them on the same
/// eventual value.
///
/// The names below are the ones where that reasoning fails: they are derived
/// per request from the cookie jar or from
/// [`chromulate_core::RequestOptions`], they differ between two requests the
/// cache would otherwise consider equivalent, and the cache cannot see them.
/// A response that selects on one of them is not stored at all.
///
/// `Vary: Cookie` is the case that matters. Treating two requests with
/// different session cookies as one variant is how a cache serves one user's
/// page to another.
const UNSELECTABLE: &[&str] = &[
    "cookie",
    "accept",
    "referer",
    "origin",
    "priority",
    "upgrade-insecure-requests",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-full-version-list",
];

/// Whether a response carries something a conditional request can be built on.
pub(crate) fn has_validator(headers: &HeaderMap) -> bool {
    headers.contains_key(ETAG) || headers.contains_key(LAST_MODIFIED)
}

/// Whether this exchange may be stored, and the `Vary` names to select it by.
///
/// # Errors
///
/// Returns the rule that refused it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn storable(
    config: &CacheConfig,
    method: &Method,
    request_headers: &HeaderMap,
    request_cc: &CacheControl,
    status: StatusCode,
    response_headers: &HeaderMap,
    response_cc: &CacheControl,
) -> Result<Vec<HeaderName>, NotStorable> {
    // Only GET. `HEAD` is cacheable per RFC 9111 and is not implemented here;
    // see the crate documentation's list of gaps.
    if method != Method::GET {
        return Err(NotStorable::Method);
    }
    // Unreachable through `HttpCache`, and kept anyway. `HttpCache::before`
    // already sets a request carrying `no-store` aside, so `after` never brings
    // one here — mutating this branch alone leaves every behavioural test
    // green, which is exactly the situation that is worth saying out loud
    // rather than leaving for someone to rediscover. It stays because
    // `storable` is meant to be the whole of §3, and a second caller of it (a
    // different front end, a backend deciding what to admit) must not have to
    // know that one of the rules lives somewhere else. `storable`'s own
    // `no_store_on_either_message_refuses_storage` is what proves it works.
    if request_cc.no_store {
        return Err(NotStorable::RequestNoStore);
    }
    if response_cc.no_store {
        return Err(NotStorable::ResponseNoStore);
    }
    if !is_cacheable_status(status) {
        return Err(NotStorable::Status);
    }
    // Not an RFC rule. A `Set-Cookie` is per-identity state, and replaying a
    // stored response would either re-apply somebody else's cookie or silently
    // drop the one the origin sent. Neither is worth a hit.
    if response_headers.contains_key(SET_COOKIE) {
        return Err(NotStorable::SetCookie);
    }

    let names = vary_names(response_headers).ok_or(NotStorable::VaryStar)?;
    if names
        .iter()
        .any(|name| UNSELECTABLE.contains(&name.as_str()))
    {
        return Err(NotStorable::VaryUnselectable);
    }

    if response_cc.private && !config.store_private {
        return Err(NotStorable::Private);
    }

    // RFC 9111 §3.5. A private cache may store this; a shared one may not
    // unless the response says otherwise. `store_private` is this crate's one
    // signal about which it is.
    if request_headers.contains_key(AUTHORIZATION)
        && !config.store_private
        && !(response_cc.public || response_cc.must_revalidate || response_cc.s_maxage.is_some())
    {
        return Err(NotStorable::Authorization);
    }

    // A response with no expiry, no validator, and no basis for a heuristic can
    // never produce a hit or a conditional request. Storing it is pure cost.
    let usable = response_cc.max_age.is_some()
        || response_headers.contains_key(http::header::EXPIRES)
        || has_validator(response_headers)
        || (is_heuristically_cacheable(status) && response_headers.contains_key(LAST_MODIFIED));
    if !usable {
        return Err(NotStorable::NoFreshnessAndNoValidator);
    }

    Ok(names)
}

/// A stored response's age, by RFC 9111 §4.2.3.
///
/// The `Age` field alone is not the answer, and reading it as though it were is
/// the classic bug: it describes the response's age when the origin (or an
/// intermediary) emitted it, and knows nothing about the round trip that
/// followed or the time the entry has since sat in this cache. Both are added
/// here.
pub(crate) fn current_age(entry: &CacheEntry, now: SystemTime) -> Duration {
    let received = entry.received_at();

    // How old the response looked on arrival, from the origin's own clock.
    // Negative when the two clocks disagree, which is read as zero.
    let apparent_age = received
        .duration_since(entry.effective_date())
        .unwrap_or(Duration::ZERO);

    // The `Age` field predates the request's own round trip, so the trip is
    // added back on.
    let response_delay = received
        .duration_since(entry.requested_at())
        .unwrap_or(Duration::ZERO);
    let corrected_age = entry
        .age_field()
        .unwrap_or(Duration::ZERO)
        .saturating_add(response_delay);

    let initial_age = apparent_age.max(corrected_age);
    let resident_time = now.duration_since(received).unwrap_or(Duration::ZERO);
    initial_age.saturating_add(resident_time)
}

/// A stored response's freshness lifetime, by RFC 9111 §4.2.1 and §4.2.2.
///
/// `None` means the response carries no lifetime and no basis to guess one, so
/// it is stale the moment it is stored and only useful for revalidation.
pub(crate) fn freshness_lifetime(
    entry: &CacheEntry,
    response_cc: &CacheControl,
    config: &CacheConfig,
) -> Option<Duration> {
    if let Some(explicit) = response_cc.explicit_lifetime() {
        return Some(explicit);
    }

    // `Expires` present but unparseable means stale, not "no expiry stated" —
    // so this branch must be taken on presence, not on a successful parse.
    if let Some(expires) = entry.expires_field() {
        return Some(
            expires
                .duration_since(entry.effective_date())
                .unwrap_or(Duration::ZERO),
        );
    }

    if !is_heuristically_cacheable(entry.status()) {
        return None;
    }
    let last_modified = entry.last_modified()?;
    let since = entry
        .effective_date()
        .duration_since(last_modified)
        .ok()?
        .checked_div(10)?;
    Some(since.min(config.heuristic_cap))
}

/// Whether a stored response may be served without asking the origin.
pub(crate) fn is_fresh(
    entry: &CacheEntry,
    response_cc: &CacheControl,
    config: &CacheConfig,
    now: SystemTime,
) -> bool {
    // `no-cache` is not `no-store`: the entry is kept, it is simply never fresh.
    if response_cc.no_cache {
        return false;
    }
    match freshness_lifetime(entry, response_cc, config) {
        Some(lifetime) => current_age(entry, now) < lifetime,
        None => false,
    }
}

/// Whether the request's own directives forbid serving a stored response
/// without revalidating it (RFC 9111 §5.2.1).
pub(crate) fn request_forces_revalidation(request_cc: &CacheControl) -> bool {
    request_cc.no_cache || request_cc.max_age == Some(0)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{HeaderValue, Version};

    use super::*;
    use crate::entry::Selector;

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("a valid name"),
                HeaderValue::from_str(value).expect("a valid value"),
            );
        }
        headers
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn stored(headers: &[(&str, &str)], requested: u64, received: u64) -> CacheEntry {
        CacheEntry::new(
            StatusCode::OK,
            Version::HTTP_11,
            map(headers),
            Bytes::from_static(b"body"),
            Selector::any(),
            at(requested),
            at(received),
        )
    }

    fn decide(
        config: &CacheConfig,
        method: &Method,
        request: &[(&str, &str)],
        status: StatusCode,
        response: &[(&str, &str)],
    ) -> Result<Vec<HeaderName>, NotStorable> {
        let request_headers = map(request);
        let response_headers = map(response);
        storable(
            config,
            method,
            &request_headers,
            &CacheControl::of_request(&request_headers),
            status,
            &response_headers,
            &CacheControl::of(&response_headers),
        )
    }

    #[test]
    fn a_plain_cacheable_get_is_storable() {
        assert!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                &[("cache-control", "max-age=60")],
            )
            .is_ok()
        );
    }

    #[test]
    fn no_store_on_either_message_refuses_storage() {
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                &[("cache-control", "max-age=60, no-store")],
            ),
            Err(NotStorable::ResponseNoStore)
        );
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[("cache-control", "no-store")],
                StatusCode::OK,
                &[("cache-control", "max-age=60")],
            ),
            Err(NotStorable::RequestNoStore)
        );
    }

    /// The distinction this cache exists to get right: `no-cache` keeps the
    /// entry and revalidates it, `no-store` keeps nothing.
    #[test]
    fn no_cache_is_storable_and_never_fresh() {
        assert!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                &[
                    ("cache-control", "no-cache, max-age=600"),
                    ("etag", "\"v\"")
                ],
            )
            .is_ok(),
            "`no-cache` asks for revalidation, so the entry has to exist to be revalidated"
        );

        let entry = stored(&[("cache-control", "no-cache, max-age=600")], 0, 0);
        let cc = CacheControl::of(entry.headers());
        assert!(!is_fresh(&entry, &cc, &CacheConfig::default(), at(1)));
    }

    #[test]
    fn a_private_response_is_refused_by_default_and_kept_when_asked_for() {
        let response = &[("cache-control", "private, max-age=60")];
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                response
            ),
            Err(NotStorable::Private)
        );

        let permissive = CacheConfig {
            store_private: true,
            ..CacheConfig::default()
        };
        assert!(decide(&permissive, &Method::GET, &[], StatusCode::OK, response).is_ok());
    }

    #[test]
    fn an_authorized_request_is_only_stored_when_the_response_says_it_may_be() {
        let authorized = &[("authorization", "Bearer token")];
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                authorized,
                StatusCode::OK,
                &[("cache-control", "max-age=60")],
            ),
            Err(NotStorable::Authorization)
        );

        for allowance in ["public", "must-revalidate", "s-maxage=60"] {
            assert!(
                decide(
                    &CacheConfig::default(),
                    &Method::GET,
                    authorized,
                    StatusCode::OK,
                    &[("cache-control", &format!("max-age=60, {allowance}"))],
                )
                .is_ok(),
                "`{allowance}` is one of RFC 9111 §3.5's allowances"
            );
        }
    }

    #[test]
    fn vary_star_and_an_unselectable_vary_are_both_refused() {
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                &[("cache-control", "max-age=60"), ("vary", "*")],
            ),
            Err(NotStorable::VaryStar)
        );
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                &[("cache-control", "max-age=60"), ("vary", "cookie")],
            ),
            Err(NotStorable::VaryUnselectable)
        );
        assert!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                &[
                    ("cache-control", "max-age=60"),
                    ("vary", "accept-encoding, accept-language"),
                ],
            )
            .is_ok(),
            "the profile writes these and writes them identically on every request"
        );
    }

    #[test]
    fn a_set_cookie_response_is_never_stored() {
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                &[("cache-control", "max-age=60"), ("set-cookie", "s=1")],
            ),
            Err(NotStorable::SetCookie)
        );
    }

    #[test]
    fn an_uncacheable_status_and_a_non_get_method_are_both_refused() {
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::CREATED,
                &[("cache-control", "max-age=60")],
            ),
            Err(NotStorable::Status)
        );
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::POST,
                &[],
                StatusCode::OK,
                &[("cache-control", "max-age=60")],
            ),
            Err(NotStorable::Method)
        );
    }

    #[test]
    fn a_response_with_nothing_to_offer_is_not_stored() {
        assert_eq!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                &[]
            ),
            Err(NotStorable::NoFreshnessAndNoValidator)
        );
        assert!(
            decide(
                &CacheConfig::default(),
                &Method::GET,
                &[],
                StatusCode::OK,
                &[("etag", "\"v\"")],
            )
            .is_ok(),
            "a validator alone is worth storing: it buys a 304"
        );
    }

    /// RFC 9111 §4.2.3's worked shape: the `Age` the origin stated, plus the
    /// round trip it could not know about, plus the time since.
    #[test]
    fn age_adds_the_round_trip_and_the_residency_to_the_age_field() {
        // Sent at t=100, arrived at t=110, origin said it was already 30s old.
        let entry = stored(
            &[("date", "Thu, 01 Jan 1970 00:01:50 GMT"), ("age", "30")],
            100,
            110,
        );
        // corrected = 30 + (110 - 100) = 40; apparent = 110 - 110 = 0.
        assert_eq!(current_age(&entry, at(110)), Duration::from_secs(40));
        // Twenty seconds of residency on top.
        assert_eq!(current_age(&entry, at(130)), Duration::from_secs(60));
    }

    #[test]
    fn a_response_that_arrived_later_than_its_date_is_at_least_that_old() {
        // Date says t=0, arrived at t=50, no `Age` at all.
        let entry = stored(&[("date", "Thu, 01 Jan 1970 00:00:00 GMT")], 45, 50);
        assert_eq!(current_age(&entry, at(50)), Duration::from_secs(50));
    }

    /// Three of the four subtractions in §4.2.3 can go negative when the
    /// origin's clock and this one disagree, and `Duration` has no negative
    /// values to represent the result with. Each is read as zero rather than
    /// wrapping to something enormous, which would make a fresh response
    /// eternally stale.
    #[test]
    fn a_clock_that_runs_backwards_never_produces_a_negative_age() {
        // `Date` an hour in the future relative to arrival, and `now` before
        // arrival too. No round trip, so nothing is left to count.
        let instant = stored(&[("date", "Thu, 01 Jan 1970 01:00:00 GMT")], 20, 20);
        assert_eq!(current_age(&instant, at(5)), Duration::ZERO);

        // The same, but the request did take ten seconds. That much is real
        // even when every clock disagrees, and it is what remains.
        let with_round_trip = stored(&[("date", "Thu, 01 Jan 1970 01:00:00 GMT")], 10, 20);
        assert_eq!(
            current_age(&with_round_trip, at(5)),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn an_absurd_age_field_saturates_rather_than_overflowing() {
        let entry = stored(&[("age", "18446744073709551615")], 0, 0);
        let age = current_age(&entry, at(1_000));
        assert!(age >= Duration::from_secs(u64::MAX - 1));
    }

    #[test]
    fn max_age_beats_expires_and_expires_beats_the_heuristic() {
        let both = stored(
            &[
                ("cache-control", "max-age=60"),
                ("expires", "Thu, 01 Jan 1970 10:00:00 GMT"),
                ("date", "Thu, 01 Jan 1970 00:00:00 GMT"),
            ],
            0,
            0,
        );
        assert_eq!(
            freshness_lifetime(
                &both,
                &CacheControl::of(both.headers()),
                &CacheConfig::default()
            ),
            Some(Duration::from_secs(60))
        );

        let expires_only = stored(
            &[
                ("expires", "Thu, 01 Jan 1970 00:10:00 GMT"),
                ("date", "Thu, 01 Jan 1970 00:00:00 GMT"),
                ("last-modified", "Thu, 01 Jan 1960 00:00:00 GMT"),
            ],
            0,
            0,
        );
        assert_eq!(
            freshness_lifetime(
                &expires_only,
                &CacheControl::of(expires_only.headers()),
                &CacheConfig::default()
            ),
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn an_expires_in_the_past_is_a_zero_lifetime_rather_than_a_negative_one() {
        let entry = stored(
            &[
                ("expires", "Thu, 01 Jan 1970 00:00:00 GMT"),
                ("date", "Thu, 01 Jan 1970 01:00:00 GMT"),
            ],
            3_600,
            3_600,
        );
        assert_eq!(
            freshness_lifetime(
                &entry,
                &CacheControl::of(entry.headers()),
                &CacheConfig::default()
            ),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn the_heuristic_is_a_tenth_of_the_age_capped_at_a_day() {
        // Last modified 1000s before `Date`.
        let recent = stored(
            &[
                ("date", "Thu, 01 Jan 1970 00:16:40 GMT"),
                ("last-modified", "Thu, 01 Jan 1970 00:00:00 GMT"),
            ],
            1_000,
            1_000,
        );
        assert_eq!(
            freshness_lifetime(
                &recent,
                &CacheControl::of(recent.headers()),
                &CacheConfig::default()
            ),
            Some(Duration::from_secs(100))
        );

        // Last modified ten years before `Date`: a tenth is a year, capped to a day.
        let ancient = stored(
            &[
                ("date", "Fri, 01 Jan 1988 00:00:00 GMT"),
                ("last-modified", "Wed, 01 Jan 1975 00:00:00 GMT"),
            ],
            0,
            0,
        );
        assert_eq!(
            freshness_lifetime(
                &ancient,
                &CacheControl::of(ancient.headers()),
                &CacheConfig::default()
            ),
            Some(Duration::from_secs(24 * 60 * 60))
        );
    }

    #[test]
    fn freshness_is_a_strict_comparison_at_the_boundary() {
        let entry = stored(
            &[
                ("cache-control", "max-age=60"),
                ("date", "Thu, 01 Jan 1970 00:00:00 GMT"),
            ],
            0,
            0,
        );
        let cc = CacheControl::of(entry.headers());
        let config = CacheConfig::default();

        assert!(is_fresh(&entry, &cc, &config, at(59)));
        assert!(
            !is_fresh(&entry, &cc, &config, at(60)),
            "an age equal to the lifetime is stale, not fresh"
        );
    }

    #[test]
    fn a_request_may_force_revalidation_of_a_perfectly_fresh_entry() {
        assert!(request_forces_revalidation(&CacheControl::of_request(
            &map(&[("cache-control", "no-cache")])
        )));
        assert!(request_forces_revalidation(&CacheControl::of_request(
            &map(&[("cache-control", "max-age=0")])
        )));
        assert!(request_forces_revalidation(&CacheControl::of_request(
            &map(&[("pragma", "no-cache")])
        )));
        assert!(!request_forces_revalidation(&CacheControl::of_request(
            &HeaderMap::new()
        )));
    }
}
