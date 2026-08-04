//! `Alt-Svc` parsing and the alternative-service cache (RFC 7838).
//!
//! This is the discovery half of HTTP/3, and it is worth having on its own. An origin
//! that answers with `Alt-Svc: h3=":443"` is telling every client that it speaks
//! HTTP/3; recording that is an observation about the origin, and it is what a browser
//! acts on before it opens a single UDP socket. Nothing here needs a QUIC stack.
//!
//! Two conventions run through the module. Time is a parameter, never read from the
//! clock: every method that cares takes `now: SystemTime`, which is the pattern
//! `chromulate-cookie` already uses for expiry (`crates/chromulate-cookie/src/jar.rs`)
//! and what makes the expiry rules testable without sleeping. And parsing does not
//! fail: RFC 7838 section 3 tells a client to ignore what it cannot use, so an
//! unparseable `alt-value` is skipped and the rest of the field survives.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use chromulate_core::Origin;

use crate::error::AltSvcError;

/// The default `ma` when a field value omits it: 24 hours (RFC 7838 section 3.1).
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(86_400);

/// The ALPN protocol identifier for HTTP/3 (RFC 9114 section 3.1).
pub const H3_ALPN: &str = "h3";

/// One `alt-value` from an `Alt-Svc` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alternative {
    protocol_id: String,
    host: Option<String>,
    port: u16,
    max_age: Duration,
    persist: bool,
}

impl Alternative {
    /// The ALPN protocol identifier, percent-decoded.
    #[must_use]
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// The alternative host, or `None` when the field named only a port.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// The alternative port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// How long the alternative may be cached.
    #[must_use]
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Whether the origin asked for the entry to survive a network change.
    #[must_use]
    pub fn persist(&self) -> bool {
        self.persist
    }
}

/// A parsed `Alt-Svc` field value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltSvc {
    /// `Alt-Svc: clear` — forget every alternative for this origin.
    Clear,
    /// One or more alternatives, in the order the origin listed them.
    Alternatives(Vec<Alternative>),
}

impl AltSvc {
    /// Parses one `Alt-Svc` field value.
    ///
    /// Never fails. An `alt-value` this crate cannot use is dropped and the remaining
    /// ones are kept, which is what RFC 7838 section 3 asks of a client and what makes
    /// the field extensible: an origin advertising a protocol from the future should
    /// not cost it the alternative it advertised alongside.
    ///
    /// ```
    /// use chromulate_h3::AltSvc;
    ///
    /// let AltSvc::Alternatives(list) = AltSvc::parse(r#"h3=":443"; ma=3600"#) else {
    ///     panic!("not a reset");
    /// };
    /// assert_eq!(list[0].protocol_id(), "h3");
    /// assert_eq!(list[0].port(), 443);
    /// ```
    #[must_use]
    pub fn parse(value: &str) -> Self {
        let trimmed = value.trim();
        // RFC 7838 section 3 spells this `%s"clear"`: RFC 7405 case-sensitive.
        if trimmed == "clear" {
            return Self::Clear;
        }

        let alternatives = split_outside_quotes(trimmed, b',')
            .filter_map(|element| parse_alt_value(element.trim()))
            .collect();
        Self::Alternatives(alternatives)
    }
}

/// Splits on `sep`, ignoring separators inside a quoted-string.
///
/// The `alt-authority` and any parameter value may be a quoted-string, and a
/// quoted-string may legally contain a comma or a semicolon. Splitting the field before
/// understanding quoting is the classic way to mis-parse this header.
fn split_outside_quotes(input: &str, sep: u8) -> impl Iterator<Item = &str> {
    let mut in_quotes = false;
    let mut escaped = false;
    let mut start = 0usize;
    let mut cuts = Vec::new();

    for (index, byte) in input.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if in_quotes && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            in_quotes = !in_quotes;
        } else if byte == sep && !in_quotes {
            cuts.push(&input[start..index]);
            start = index + 1;
        }
    }
    cuts.push(&input[start..]);
    cuts.into_iter()
}

/// Parses one `alt-value`: `protocol-id "=" alt-authority *( ";" parameter )`.
fn parse_alt_value(element: &str) -> Option<Alternative> {
    if element.is_empty() {
        return None;
    }

    let mut parts = split_outside_quotes(element, b';');
    let head = parts.next()?.trim();

    let (protocol_id, authority) = head.split_once('=')?;
    let protocol_id = decode_protocol_id(protocol_id.trim())?;
    let (host, port) = parse_alt_authority(&unquote(authority.trim())?)?;

    let mut max_age = DEFAULT_MAX_AGE;
    let mut persist = false;
    for parameter in parts {
        let Some((name, raw)) = parameter.trim().split_once('=') else {
            continue;
        };
        let Some(value) = unquote(raw.trim()) else {
            continue;
        };
        // RFC 7838 names both parameters in lower case and does not say they are
        // case-insensitive. Every implementation that matters treats them as such,
        // and a client that ignored `MA=0` would keep an alternative the origin had
        // just withdrawn, so this matches case-insensitively.
        match name.trim().to_ascii_lowercase().as_str() {
            "ma" => {
                if let Ok(seconds) = value.parse::<u64>() {
                    max_age = Duration::from_secs(seconds);
                }
            }
            "persist" => persist = value == "1",
            _ => {}
        }
    }

    Some(Alternative {
        protocol_id,
        host,
        port,
        max_age,
        persist,
    })
}

/// Percent-decodes a `protocol-id`, which RFC 7838 section 3 defines as a
/// percent-encoded ALPN protocol name carried as a token.
fn decode_protocol_id(raw: &str) -> Option<String> {
    if raw.is_empty() || !raw.bytes().all(is_tchar) {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .ok()?;
    if decoded.is_empty() {
        return None;
    }
    Some(decoded.into_owned())
}

/// Removes the surrounding quotes from a quoted-string, resolving quoted-pairs.
///
/// A bare token is returned unchanged; an unterminated quoted-string is rejected.
fn unquote(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Some(raw.to_owned());
    }
    if bytes.len() < 2 || bytes.last() != Some(&b'"') {
        return None;
    }

    let mut out = String::with_capacity(raw.len() - 2);
    let mut escaped = false;
    for character in raw[1..raw.len() - 1].chars() {
        if escaped {
            out.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            // A bare quote inside the string means the value ended early and this is
            // not one quoted-string at all.
            return None;
        } else {
            out.push(character);
        }
    }
    if escaped { None } else { Some(out) }
}

/// Splits an `alt-authority` — `[ uri-host ] ":" port` — into its two halves.
///
/// The separator is the last colon outside square brackets, because an IPv6 literal
/// host contains colons of its own.
fn parse_alt_authority(authority: &str) -> Option<(Option<String>, u16)> {
    let mut depth = 0i32;
    let mut split_at = None;
    for (index, byte) in authority.bytes().enumerate() {
        match byte {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b':' if depth == 0 => split_at = Some(index),
            _ => {}
        }
    }

    let split_at = split_at?;
    let host = &authority[..split_at];
    let port: u16 = authority[split_at + 1..].parse().ok()?;

    let host = if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    };
    Some((host, port))
}

/// The `tchar` set of RFC 9110 section 5.6.2.
const fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// An alternative remembered for an origin, with the instant it stops applying.
#[derive(Debug, Clone)]
pub struct CachedAlternative {
    alternative: Alternative,
    expires_at: SystemTime,
}

impl CachedAlternative {
    /// The alternative as the origin described it.
    #[must_use]
    pub fn alternative(&self) -> &Alternative {
        &self.alternative
    }

    /// When the entry stops applying.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// The authority to dial, resolving an omitted host against the origin.
    #[must_use]
    pub fn authority_for(&self, origin: &Origin) -> String {
        let host = self.alternative.host.as_deref().unwrap_or(origin.host());
        format!("{host}:{}", self.alternative.port)
    }
}

impl CachedAlternative {
    /// Whether the entry still applies at `now`.
    fn is_live(&self, now: SystemTime) -> bool {
        self.expires_at > now
    }
}

/// How many origins a cache remembers before it starts forgetting.
///
/// `Alt-Svc` is a response header, so the set of origins in here is chosen by
/// the servers a crawl visits rather than by the caller. An unbounded map is
/// memory those servers can make a long-running process spend and never give
/// back. Ten thousand matches the bound the HSTS store carries for the same
/// reason.
pub const DEFAULT_ORIGIN_CAPACITY: usize = 10_000;

/// Per-origin memory of advertised alternative services.
///
/// This is the state a browser keeps so that the *second* request to an origin can go
/// over HTTP/3 when the first one learned that it could. It holds no clock: callers
/// pass `now`, which is what lets the expiry rules be tested without waiting.
///
/// Bounded at [`DEFAULT_ORIGIN_CAPACITY`] origins, because what fills it is
/// chosen by the servers visited rather than by the caller.
#[derive(Debug)]
pub struct AltSvcCache {
    entries: HashMap<Origin, Vec<CachedAlternative>>,
    capacity: usize,
}

impl Default for AltSvcCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AltSvcCache {
    /// An empty cache holding at most [`DEFAULT_ORIGIN_CAPACITY`] origins.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_ORIGIN_CAPACITY)
    }

    /// An empty cache holding at most `capacity` origins.
    ///
    /// A capacity of zero is raised to one: a cache that cannot hold the entry it
    /// was just given would drop every write, which is a configuration mistake
    /// rather than an instruction.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// The most origins this cache will hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Records an `Alt-Svc` field observed on a response from `origin`.
    ///
    /// A field replaces whatever the origin advertised before rather than adding to
    /// it, which is what RFC 7838 section 3 specifies, and `clear` empties the origin.
    ///
    /// # Errors
    ///
    /// [`AltSvcError::InsecureOrigin`] when the response came over a transport that
    /// cannot authenticate the origin. RFC 7838 section 2.1 requires reasonable
    /// assurance that the alternative is under the origin's control, and a cleartext
    /// response provides none: anyone on the path could redirect the client to a host
    /// of their choosing for the next 24 hours.
    pub fn record(
        &mut self,
        origin: &Origin,
        value: &str,
        now: SystemTime,
    ) -> Result<(), AltSvcError> {
        if !origin.is_secure() {
            return Err(AltSvcError::InsecureOrigin {
                origin: origin.to_string(),
            });
        }

        let advertised = match AltSvc::parse(value) {
            AltSvc::Clear => Vec::new(),
            AltSvc::Alternatives(list) => list,
        };

        let cached: Vec<CachedAlternative> = advertised
            .into_iter()
            .filter_map(|alternative| {
                // An `ma` large enough to overflow `SystemTime` cannot be represented,
                // so the entry is dropped rather than clamped to a number this crate
                // would have invented.
                let expires_at = now.checked_add(alternative.max_age)?;
                Some(CachedAlternative {
                    alternative,
                    expires_at,
                })
            })
            .collect();

        if cached.is_empty() {
            self.entries.remove(origin);
        } else {
            self.make_room_for(origin, now);
            self.entries.insert(origin.clone(), cached);
        }
        Ok(())
    }

    /// Every unexpired alternative for `origin`, in advertised order.
    #[must_use]
    pub fn alternatives(&self, origin: &Origin, now: SystemTime) -> Vec<&CachedAlternative> {
        self.entries
            .get(origin)
            .map(|list| list.iter().filter(|entry| entry.is_live(now)).collect())
            .unwrap_or_default()
    }

    /// The first unexpired HTTP/3 alternative for `origin`.
    ///
    /// Order matters: an origin lists its alternatives in preference order, so the
    /// first `h3` entry is the one a browser would try.
    #[must_use]
    pub fn h3_alternative(&self, origin: &Origin, now: SystemTime) -> Option<&CachedAlternative> {
        self.entries
            .get(origin)?
            .iter()
            .find(|entry| entry.is_live(now) && entry.alternative.protocol_id() == H3_ALPN)
    }

    /// Makes space for `origin` if the cache is full and does not already hold it.
    ///
    /// Expiry first: an entry nobody can use any more is the cheapest thing to
    /// lose, and on a long crawl it is usually enough. Only when that frees
    /// nothing does an entry get dropped that is still live, and the one chosen
    /// is the soonest to expire — it is the one whose loss costs the least
    /// remaining usefulness. There is no recency here because the cache records
    /// no reads; adding a clock to rank them would cost more than it saves for a
    /// hint that a request can simply re-learn from the next response.
    fn make_room_for(&mut self, origin: &Origin, now: SystemTime) {
        if self.entries.len() < self.capacity || self.entries.contains_key(origin) {
            return;
        }

        self.purge_expired(now);
        if self.entries.len() < self.capacity {
            return;
        }

        let soonest = self
            .entries
            .iter()
            .filter_map(|(key, list)| {
                list.iter()
                    .map(|entry| entry.expires_at())
                    .min()
                    .map(|at| (at, key.clone()))
            })
            .min_by(|left, right| left.0.cmp(&right.0))
            .map(|(_, key)| key);
        if let Some(key) = soonest {
            self.entries.remove(&key);
        }
    }

    /// Drops every entry that has expired at `now`, and every origin left with none.
    pub fn purge_expired(&mut self, now: SystemTime) {
        self.entries.retain(|_, list| {
            list.retain(|entry| entry.is_live(now));
            !list.is_empty()
        });
    }

    /// The number of origins with at least one remembered alternative.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(url: &str) -> Origin {
        Origin::of(&url.parse().expect("test url parses")).expect("test url has an origin")
    }

    fn alternatives(value: &str) -> Vec<Alternative> {
        match AltSvc::parse(value) {
            AltSvc::Alternatives(list) => list,
            AltSvc::Clear => panic!("expected alternatives, got `clear`"),
        }
    }

    #[test]
    fn the_cache_is_bounded_by_the_number_of_origins() {
        // `Alt-Svc` is a response header, so the origins in here are chosen by
        // the servers a crawl visits. Before this bound existed the map grew
        // without limit and only an explicit `purge_expired` reclaimed anything.
        let mut cache = AltSvcCache::with_capacity(3);
        for n in 0..20 {
            let origin = origin(&format!("https://host{n}.test"));
            cache
                .record(&origin, "h3=\":443\"; ma=3600", at(0))
                .expect("a secure origin may advertise");
        }
        assert_eq!(cache.len(), 3, "the cache grew past its capacity");
    }

    #[test]
    fn a_full_cache_drops_an_expired_origin_before_a_live_one() {
        let mut cache = AltSvcCache::with_capacity(2);
        let short = origin("https://short.test");
        let long = origin("https://long.test");
        cache
            .record(&short, "h3=\":443\"; ma=10", at(0))
            .expect("secure");
        cache
            .record(&long, "h3=\":443\"; ma=100000", at(0))
            .expect("secure");

        // At this instant `short` has expired and `long` has not, so the arriving
        // origin must cost the dead entry rather than the live one.
        let fresh = origin("https://fresh.test");
        cache
            .record(&fresh, "h3=\":443\"; ma=3600", at(50))
            .expect("secure");

        assert!(
            cache.h3_alternative(&long, at(50)).is_some(),
            "live entry lost"
        );
        assert!(
            cache.h3_alternative(&fresh, at(50)).is_some(),
            "new entry lost"
        );
        assert!(
            cache.h3_alternative(&short, at(50)).is_none(),
            "expired entry kept"
        );
    }

    #[test]
    fn a_sweep_reclaims_every_dead_origin_rather_than_one_per_insert() {
        // This is what separates the two layers. When a single entry is dead,
        // sweeping and picking-the-soonest choose the same victim, so a test with
        // one dead entry passes either way and proves nothing about the sweep.
        // With several dead, the sweep frees them all at once while the pick frees
        // exactly one — and a cache that reclaims one slot per insert stays
        // permanently full of corpses.
        let mut cache = AltSvcCache::with_capacity(5);
        for n in 0..5 {
            let origin = origin(&format!("https://dead{n}.test"));
            cache
                .record(&origin, "h3=\":443\"; ma=10", at(0))
                .expect("secure");
        }
        assert_eq!(cache.len(), 5);

        let fresh = origin("https://fresh.test");
        cache
            .record(&fresh, "h3=\":443\"; ma=3600", at(50))
            .expect("secure");

        assert_eq!(
            cache.len(),
            1,
            "the sweep should have reclaimed all five dead origins, not just one"
        );
    }

    #[test]
    fn a_full_cache_of_live_origins_drops_the_one_expiring_soonest() {
        let mut cache = AltSvcCache::with_capacity(2);
        let soon = origin("https://soon.test");
        let later = origin("https://later.test");
        cache
            .record(&soon, "h3=\":443\"; ma=100", at(0))
            .expect("secure");
        cache
            .record(&later, "h3=\":443\"; ma=100000", at(0))
            .expect("secure");

        let fresh = origin("https://fresh.test");
        cache
            .record(&fresh, "h3=\":443\"; ma=3600", at(0))
            .expect("secure");

        assert_eq!(cache.len(), 2);
        assert!(
            cache.h3_alternative(&soon, at(0)).is_none(),
            "soonest should go"
        );
        assert!(cache.h3_alternative(&later, at(0)).is_some());
    }

    #[test]
    fn re_recording_a_known_origin_does_not_evict_anything() {
        // The bound must not turn a refresh into a loss: a full cache being told
        // again about an origin it already holds has nothing to make room for.
        let mut cache = AltSvcCache::with_capacity(2);
        let a = origin("https://a.test");
        let b = origin("https://b.test");
        cache
            .record(&a, "h3=\":443\"; ma=3600", at(0))
            .expect("secure");
        cache
            .record(&b, "h3=\":443\"; ma=3600", at(0))
            .expect("secure");
        cache
            .record(&a, "h3=\":8443\"; ma=3600", at(0))
            .expect("secure");

        assert_eq!(cache.len(), 2);
        assert!(
            cache.h3_alternative(&b, at(0)).is_some(),
            "sibling evicted by a refresh"
        );
    }

    #[test]
    fn a_capacity_of_zero_is_raised_to_one() {
        let mut cache = AltSvcCache::with_capacity(0);
        assert_eq!(cache.capacity(), 1);
        let only = origin("https://only.test");
        cache
            .record(&only, "h3=\":443\"; ma=3600", at(0))
            .expect("secure");
        assert!(
            cache.h3_alternative(&only, at(0)).is_some(),
            "a zero capacity dropped every write"
        );
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    // -- parsing --------------------------------------------------------------

    #[test]
    fn parses_the_common_h3_advertisement() {
        let list = alternatives(r#"h3=":443"; ma=86400"#);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].protocol_id(), "h3");
        assert_eq!(list[0].host(), None);
        assert_eq!(list[0].port(), 443);
        assert_eq!(list[0].max_age(), Duration::from_secs(86_400));
        assert!(!list[0].persist());
    }

    #[test]
    fn an_omitted_ma_defaults_to_twenty_four_hours() {
        let list = alternatives(r#"h3=":443""#);
        assert_eq!(list[0].max_age(), DEFAULT_MAX_AGE);
    }

    #[test]
    fn parses_an_explicit_alternative_host() {
        let list = alternatives(r#"h2="alt.example.net:8443"; ma=60"#);
        assert_eq!(list[0].protocol_id(), "h2");
        assert_eq!(list[0].host(), Some("alt.example.net"));
        assert_eq!(list[0].port(), 8443);
        assert_eq!(list[0].max_age(), Duration::from_secs(60));
    }

    #[test]
    fn parses_a_bracketed_ipv6_alternative_host() {
        let list = alternatives(r#"h3="[2001:db8::1]:443""#);
        assert_eq!(list[0].host(), Some("[2001:db8::1]"));
        assert_eq!(list[0].port(), 443);
    }

    #[test]
    fn the_port_separator_is_the_last_colon_not_the_first() {
        // Added because mutation checking found this guard unprotected: the bracketed
        // case above cannot reach it, since inside brackets the colons are skipped by
        // the depth counter and the one that remains is both the first and the last.
        // An unbracketed IPv6 authority is malformed, but it is what a
        // misconfigured origin emits, and the last-colon rule is what RFC 3986
        // authority parsing does — taking the first colon would drop the entry.
        let list = alternatives(r#"h3="2001:db8::1:8443""#);
        assert_eq!(list[0].host(), Some("2001:db8::1"));
        assert_eq!(list[0].port(), 8443);
    }

    #[test]
    fn keeps_every_alternative_in_advertised_order() {
        let list = alternatives(r#"h3=":443"; ma=3600, h3-29=":443"; ma=3600, h2=":443""#);
        let ids: Vec<_> = list.iter().map(Alternative::protocol_id).collect();
        assert_eq!(ids, ["h3", "h3-29", "h2"]);
    }

    #[test]
    fn percent_decodes_the_protocol_id() {
        // RFC 7838 section 3: the protocol-id is a percent-encoded ALPN name, so a
        // name containing a character that is not a token character arrives escaped.
        let list = alternatives(r#"%68%33=":443""#);
        assert_eq!(list[0].protocol_id(), "h3");
    }

    #[test]
    fn recognises_clear() {
        assert_eq!(AltSvc::parse("clear"), AltSvc::Clear);
        assert_eq!(AltSvc::parse("  clear  "), AltSvc::Clear);
    }

    #[test]
    fn clear_is_case_sensitive() {
        // RFC 7838 section 3 spells it `%s"clear"`, which RFC 7405 defines as a
        // case-sensitive string. `CLEAR` is an unparseable alt-value, not a reset.
        assert_eq!(AltSvc::parse("CLEAR"), AltSvc::Alternatives(Vec::new()));
    }

    #[test]
    fn persist_one_is_recognised() {
        let list = alternatives(r#"h3=":443"; ma=3600; persist=1"#);
        assert!(list[0].persist());
    }

    #[test]
    fn a_comma_inside_a_quoted_parameter_does_not_split_the_list() {
        // A parser that splits the field on commas before it understands quoting cuts
        // this into three pieces and loses the `h3` entry entirely.
        let list = alternatives(r#"h3=":443"; ma=3600; note="a,b", h2=":443""#);
        let ids: Vec<_> = list.iter().map(Alternative::protocol_id).collect();
        assert_eq!(ids, ["h3", "h2"]);
        assert_eq!(list[0].max_age(), Duration::from_secs(3600));
    }

    #[test]
    fn a_semicolon_inside_a_quoted_parameter_does_not_split_the_parameters() {
        let list = alternatives(r#"h3=":443"; note="x;ma=1"; ma=7"#);
        assert_eq!(list[0].max_age(), Duration::from_secs(7));
    }

    #[test]
    fn an_unterminated_quoted_authority_is_skipped() {
        let list = alternatives(r#"h3=":443, h2=":443""#);
        let ids: Vec<_> = list.iter().map(Alternative::protocol_id).collect();
        assert!(ids.is_empty(), "got {ids:?}");
    }

    #[test]
    fn a_non_numeric_ma_falls_back_to_the_default() {
        let list = alternatives(r#"h3=":443"; ma=soon"#);
        assert_eq!(list[0].max_age(), DEFAULT_MAX_AGE);
    }

    #[test]
    fn ma_is_matched_case_insensitively() {
        let list = alternatives(r#"h3=":443"; MA=5"#);
        assert_eq!(list[0].max_age(), Duration::from_secs(5));
    }

    #[test]
    fn skips_entries_it_cannot_parse_and_keeps_the_rest() {
        let list = alternatives(r#"h3=nonsense, h2=":443", h3-29="::""#);
        let ids: Vec<_> = list.iter().map(Alternative::protocol_id).collect();
        assert_eq!(ids, ["h2"]);
    }

    #[test]
    fn rejects_a_port_outside_the_sixteen_bit_range() {
        assert_eq!(
            AltSvc::parse(r#"h3=":70000""#),
            AltSvc::Alternatives(Vec::new())
        );
    }

    #[test]
    fn an_unknown_parameter_is_ignored_rather_than_failing_the_entry() {
        let list = alternatives(r#"h3=":443"; ma=10; unknown="x"; persist=1"#);
        assert_eq!(list[0].max_age(), Duration::from_secs(10));
        assert!(list[0].persist());
    }

    #[test]
    fn an_empty_field_value_yields_no_alternatives() {
        assert_eq!(AltSvc::parse(""), AltSvc::Alternatives(Vec::new()));
    }

    // -- cache ----------------------------------------------------------------

    #[test]
    fn a_recorded_h3_alternative_is_returned() {
        let mut cache = AltSvcCache::new();
        let o = origin("https://example.com/");
        cache
            .record(&o, r#"h3=":443"; ma=3600"#, at(0))
            .expect("https origin is allowed to advertise");

        let found = cache.h3_alternative(&o, at(10)).expect("entry is live");
        assert_eq!(found.authority_for(&o), "example.com:443");
    }

    #[test]
    fn an_expired_alternative_is_not_returned() {
        let mut cache = AltSvcCache::new();
        let o = origin("https://example.com/");
        cache
            .record(&o, r#"h3=":443"; ma=60"#, at(0))
            .expect("https origin is allowed to advertise");

        assert!(cache.h3_alternative(&o, at(59)).is_some());
        assert!(cache.h3_alternative(&o, at(61)).is_none());
    }

    #[test]
    fn ma_zero_expires_immediately() {
        let mut cache = AltSvcCache::new();
        let o = origin("https://example.com/");
        cache
            .record(&o, r#"h3=":443"; ma=0"#, at(0))
            .expect("https origin is allowed to advertise");

        assert!(cache.h3_alternative(&o, at(0)).is_none());
    }

    #[test]
    fn clear_forgets_the_origins_alternatives() {
        let mut cache = AltSvcCache::new();
        let o = origin("https://example.com/");
        cache
            .record(&o, r#"h3=":443"; ma=3600"#, at(0))
            .expect("https origin is allowed to advertise");
        assert_eq!(cache.len(), 1);

        cache
            .record(&o, "clear", at(1))
            .expect("https origin is allowed to advertise");
        assert!(cache.h3_alternative(&o, at(1)).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_later_field_replaces_the_earlier_one_for_the_same_origin() {
        // RFC 7838 section 3: a new Alt-Svc field for an origin invalidates the
        // alternatives previously advertised, rather than adding to them.
        let mut cache = AltSvcCache::new();
        let o = origin("https://example.com/");
        cache
            .record(&o, r#"h3=":443"; ma=3600"#, at(0))
            .expect("https origin is allowed to advertise");
        cache
            .record(&o, r#"h2="alt.example.com:8443"; ma=3600"#, at(1))
            .expect("https origin is allowed to advertise");

        assert!(cache.h3_alternative(&o, at(2)).is_none());
        assert_eq!(cache.alternatives(&o, at(2)).len(), 1);
    }

    #[test]
    fn alternatives_are_kept_per_origin() {
        let mut cache = AltSvcCache::new();
        let a = origin("https://a.example/");
        let b = origin("https://b.example/");
        cache
            .record(&a, r#"h3=":443"; ma=3600"#, at(0))
            .expect("https origin is allowed to advertise");

        assert!(cache.h3_alternative(&a, at(1)).is_some());
        assert!(cache.h3_alternative(&b, at(1)).is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn an_insecure_origin_may_not_advertise_an_alternative() {
        // RFC 7838 section 2.1 requires reasonable assurance that the alternative is
        // under the origin's control. A cleartext origin cannot provide it, and every
        // browser drops the field there.
        let mut cache = AltSvcCache::new();
        let o = origin("http://example.com/");
        let err = cache
            .record(&o, r#"h3=":443"; ma=3600"#, at(0))
            .expect_err("a cleartext origin must be refused");
        assert!(matches!(err, AltSvcError::InsecureOrigin { .. }));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_field_with_no_usable_alternative_leaves_no_origin_entry() {
        let mut cache = AltSvcCache::new();
        let o = origin("https://example.com/");
        cache
            .record(&o, "h3=nonsense", at(0))
            .expect("https origin is allowed to advertise");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn purge_expired_reclaims_the_origin_entry() {
        let mut cache = AltSvcCache::new();
        let o = origin("https://example.com/");
        cache
            .record(&o, r#"h3=":443"; ma=60"#, at(0))
            .expect("https origin is allowed to advertise");

        cache.purge_expired(at(30));
        assert_eq!(cache.len(), 1);
        cache.purge_expired(at(61));
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    // -- attack surface: grammar edge cases --------------------------------

    #[test]
    fn an_escaped_quote_inside_a_quoted_authority_is_unescaped() {
        // A quoted-pair inside the quoted-string alt-authority must not be mistaken
        // for the string's closing quote.
        let list = alternatives(r#"h3="ex\"ample.com:443""#);
        assert_eq!(list[0].host(), Some("ex\"ample.com"));
        assert_eq!(list[0].port(), 443);
    }

    #[test]
    fn percent_decoding_the_protocol_id_is_single_pass_not_recursive() {
        // A doubly-encoded protocol-id must decode once, not twice. Decoding twice
        // would turn `%2568` into `h` instead of the single-pass `%68`, which is the
        // classic double-decode smuggling bug.
        let list = alternatives(r#"%2568=":443""#);
        assert_eq!(list[0].protocol_id(), "%68");
    }

    #[test]
    fn a_percent_encoded_percent_sign_decodes_correctly() {
        let list = alternatives(r#"%25=":443""#);
        assert_eq!(list[0].protocol_id(), "%");
    }

    #[test]
    fn protocol_id_bytes_that_are_not_valid_utf8_after_decoding_are_skipped() {
        // `%ff` alone is not a valid UTF-8 continuation byte on its own.
        assert_eq!(
            AltSvc::parse(r#"%ff=":443""#),
            AltSvc::Alternatives(Vec::new())
        );
    }

    #[test]
    fn a_bare_clear_token_mixed_with_other_alt_values_is_not_a_reset() {
        // RFC 7838's ABNF makes `clear` an alternative to the whole list, not a
        // member of it: `Alt-Svc-Field-Value = clear / 1#alt-value`. A field that
        // is not literally `clear` must be parsed as a list, and the malformed
        // `clear` element (no `=`) is simply dropped like any other unparseable one.
        let list = alternatives(r#"clear, h3=":443""#);
        let ids: Vec<_> = list.iter().map(Alternative::protocol_id).collect();
        assert_eq!(ids, ["h3"]);
    }

    #[test]
    fn a_duplicate_parameter_lets_the_last_value_win() {
        let list = alternatives(r#"h3=":443"; ma=10; ma=20"#);
        assert_eq!(list[0].max_age(), Duration::from_secs(20));
    }

    #[test]
    fn a_negative_ma_falls_back_to_the_default() {
        let list = alternatives(r#"h3=":443"; ma=-5"#);
        assert_eq!(list[0].max_age(), DEFAULT_MAX_AGE);
    }

    #[test]
    fn a_field_value_that_is_only_whitespace_yields_no_alternatives() {
        assert_eq!(AltSvc::parse("   "), AltSvc::Alternatives(Vec::new()));
    }

    #[test]
    fn an_unbracketed_ipv6_literal_missing_its_closing_bracket_is_rejected() {
        // The depth counter never returns to zero, so no colon is ever treated as
        // the port separator and the entry is dropped rather than mis-split.
        assert_eq!(
            AltSvc::parse(r#"h3="[2001:db8::1:443""#),
            AltSvc::Alternatives(Vec::new())
        );
    }

    #[test]
    fn unbalanced_brackets_do_not_panic_and_still_split_on_the_last_colon() {
        // Not valid IPv6 syntax, but the depth counter tolerates it defensively:
        // a leading `]` and a mid-string `[` still let the trailing `:port` split.
        let list = alternatives(r#"h3="]not-real[:443""#);
        assert_eq!(list[0].host(), Some("]not-real["));
        assert_eq!(list[0].port(), 443);
    }

    #[test]
    fn multi_byte_utf8_in_a_quoted_host_or_parameter_does_not_panic() {
        // `unquote` slices `&str` by byte index around the quote characters; ASCII
        // quote/backslash bytes never collide with UTF-8 continuation bytes, so this
        // must stay panic-free with non-ASCII content in either position.
        let list = alternatives("h3=\"\u{1f980}:443\"; note=\"\u{1f980}\"");
        assert_eq!(list[0].host(), Some("\u{1f980}"));
        assert_eq!(list[0].port(), 443);
    }

    #[test]
    fn ten_thousand_alt_values_in_one_field_parse_without_pathological_slowdown() {
        // Not a timing assertion (that would be flaky under CI load); the point is
        // that this completes at all and returns the expected count, exercising the
        // splitter and per-element parser at a scale a hostile origin could send.
        let long_value: String = (0..10_000)
            .map(|i| format!(r#"h3-{i}=":443"; ma=1"#))
            .collect::<Vec<_>>()
            .join(", ");
        let list = alternatives(&long_value);
        assert_eq!(list.len(), 10_000);
    }

    #[test]
    fn an_ma_large_enough_to_overflow_systemtime_is_dropped_not_panicked() {
        // `record` documents that it drops rather than clamps an overflowing `ma`;
        // this is the live proof, going through the cache rather than just `parse`,
        // since the overflow can only happen at the `SystemTime + Duration` step.
        let mut cache = AltSvcCache::new();
        let o = origin("https://example.com/");
        cache
            .record(
                &o,
                &format!(r#"h3=":443"; ma={}"#, u64::MAX),
                SystemTime::UNIX_EPOCH,
            )
            .expect("https origin is allowed to advertise");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_wss_origin_may_advertise_like_an_https_one() {
        // The inverse of the cleartext-refusal check: `Origin::is_secure` treats
        // `wss` as secure alongside `https`, and the cache must honour that rather
        // than hard-coding a scheme check of its own.
        let mut cache = AltSvcCache::new();
        let o = origin("wss://example.com/");
        cache
            .record(&o, r#"h3=":443"; ma=3600"#, at(0))
            .expect("wss origin is secure and may advertise");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_ws_origin_may_not_advertise() {
        // The plaintext WebSocket counterpart of the existing `http` refusal check:
        // `ws` must be refused for the same reason `http` is.
        let mut cache = AltSvcCache::new();
        let o = origin("ws://example.com/");
        let err = cache
            .record(&o, r#"h3=":443"; ma=3600"#, at(0))
            .expect_err("a plaintext ws origin must be refused");
        assert!(matches!(err, AltSvcError::InsecureOrigin { .. }));
    }

    #[test]
    fn the_alternative_host_wins_over_the_origin_host() {
        let mut cache = AltSvcCache::new();
        let o = origin("https://example.com/");
        cache
            .record(&o, r#"h3="edge.example.net:8443"; ma=60"#, at(0))
            .expect("https origin is allowed to advertise");

        let found = cache.h3_alternative(&o, at(1)).expect("entry is live");
        assert_eq!(found.authority_for(&o), "edge.example.net:8443");
    }
}
