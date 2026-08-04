//! What gets stored: the key, the selecting headers, and the response itself.

use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::header::{AGE, DATE, EXPIRES, LAST_MODIFIED, VARY};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use url::{Position, Url};

use crate::date::parse_http_date;

/// The primary cache key: a method and a target URI (RFC 9111 §2).
///
/// The fragment is excluded — it never reaches the server, so two URLs that
/// differ only in their fragment address the same stored response. The query
/// string is included, because it does.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    method: Method,
    target: Box<str>,
}

impl CacheKey {
    /// The key for a request.
    #[must_use]
    pub fn new(method: &Method, url: &Url) -> Self {
        Self {
            method: method.clone(),
            target: url[..Position::AfterQuery].into(),
        }
    }

    /// The method half of the key.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The target URI half of the key, without its fragment.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Roughly how much memory this key occupies.
    pub(crate) fn size(&self) -> usize {
        std::mem::size_of::<Self>() + self.target.len()
    }
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.method, self.target)
    }
}

/// The request-header values a stored response was selected by (RFC 9111 §4.1).
///
/// A response with no `Vary` has an empty selector, which matches every
/// request. A response with `Vary: accept-language` records the request's
/// `accept-language` — including its *absence*, which is a value like any
/// other and must not be confused with "matches anything".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selector {
    fields: Vec<(HeaderName, Vec<HeaderValue>)>,
}

impl Selector {
    /// The selector that matches every request.
    #[must_use]
    pub fn any() -> Self {
        Self::default()
    }

    /// Records `names`' values as they appear in `request`.
    #[must_use]
    pub fn of(names: &[HeaderName], request: &HeaderMap) -> Self {
        Self {
            fields: names
                .iter()
                .map(|name| {
                    (
                        name.clone(),
                        request.get_all(name).iter().cloned().collect(),
                    )
                })
                .collect(),
        }
    }

    /// Whether `request` presents the same values this selector recorded.
    #[must_use]
    pub fn matches(&self, request: &HeaderMap) -> bool {
        self.fields.iter().all(|(name, stored)| {
            let mut offered = request.get_all(name).iter();
            let mut expected = stored.iter();
            loop {
                match (offered.next(), expected.next()) {
                    (None, None) => return true,
                    (Some(a), Some(b)) if a == b => {}
                    _ => return false,
                }
            }
        })
    }

    /// The header names this selector was built from.
    pub fn names(&self) -> impl Iterator<Item = &HeaderName> {
        self.fields.iter().map(|(name, _)| name)
    }

    fn size(&self) -> usize {
        self.fields
            .iter()
            .map(|(name, values)| {
                name.as_str().len() + values.iter().map(HeaderValue::len).sum::<usize>()
            })
            .sum()
    }
}

/// One stored response.
///
/// The body is held as [`Bytes`], because a stream cannot be stored and a
/// stream cannot be replayed. Serving a hit is therefore a reference-count bump
/// rather than a copy; the cost is that a response is only ever stored if its
/// body fits in [`crate::CacheConfig::max_body_bytes`].
#[derive(Debug, Clone)]
pub struct CacheEntry {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    selector: Selector,
    requested_at: SystemTime,
    received_at: SystemTime,
}

impl CacheEntry {
    /// Assembles an entry from an exchange.
    ///
    /// `requested_at` is when the request went out and `received_at` is when
    /// the response head arrived. Both are needed, and not just the `Date`
    /// header: RFC 9111 §4.2.3's age arithmetic corrects the origin's `Age` by
    /// the round trip it did not know about.
    #[must_use]
    pub fn new(
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        selector: Selector,
        requested_at: SystemTime,
        received_at: SystemTime,
    ) -> Self {
        Self {
            status,
            version,
            headers,
            body,
            selector,
            requested_at,
            received_at,
        }
    }

    /// The stored status code.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The HTTP version the stored response arrived on.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// The stored header fields.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The stored body.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// The values this entry was selected by.
    #[must_use]
    pub fn selector(&self) -> &Selector {
        &self.selector
    }

    /// When the request that produced this entry was sent.
    #[must_use]
    pub fn requested_at(&self) -> SystemTime {
        self.requested_at
    }

    /// When the response head arrived.
    #[must_use]
    pub fn received_at(&self) -> SystemTime {
        self.received_at
    }

    /// Roughly how much memory this entry occupies, for the store's byte
    /// budget.
    ///
    /// An estimate, not a measurement: it counts the body exactly and the
    /// headers by their name and value lengths, ignoring `HeaderMap`'s own
    /// overhead. A bound that is approximately right and cheap to compute is
    /// what a cache budget needs.
    #[must_use]
    pub fn size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.body.len()
            + self
                .headers
                .iter()
                .map(|(name, value)| name.as_str().len() + value.len())
                .sum::<usize>()
            + self.selector.size()
    }

    /// The `Date` field, when it parses.
    #[must_use]
    pub fn date(&self) -> Option<SystemTime> {
        header_date(&self.headers, DATE)
    }

    /// The `Last-Modified` field, when it parses.
    #[must_use]
    pub fn last_modified(&self) -> Option<SystemTime> {
        header_date(&self.headers, LAST_MODIFIED)
    }

    /// The origin's `Date`, or the moment the response arrived when there is
    /// none.
    pub(crate) fn effective_date(&self) -> SystemTime {
        self.date().unwrap_or(self.received_at)
    }

    /// The `Age` field, when it is a valid `delta-seconds`.
    pub(crate) fn age_field(&self) -> Option<Duration> {
        let value = self.headers.get(AGE)?.to_str().ok()?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            // RFC 9111 §5.1: a non-numeric `Age` is invalid, and an invalid
            // field is no field.
            return None;
        }
        Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)))
    }

    /// The `Expires` field: `Some(instant)` when it parses, `Some(the epoch)`
    /// when the field is present but invalid, `None` when it is absent.
    ///
    /// RFC 9111 §5.3 requires an invalid `Expires` — "especially the value
    /// `0`" — to be read as a time in the past, so the two absent-ish cases
    /// must stay distinguishable: an unparseable `Expires` means *stale*, a
    /// missing one means *no explicit expiry, try the heuristic*.
    pub(crate) fn expires_field(&self) -> Option<SystemTime> {
        let value = self.headers.get(EXPIRES)?;
        Some(
            value
                .to_str()
                .ok()
                .and_then(parse_http_date)
                .unwrap_or(SystemTime::UNIX_EPOCH),
        )
    }

    /// Replaces the stored fields with those a `304` carried, and restarts the
    /// entry's age (RFC 9111 §4.3.4).
    ///
    /// Restarting the age is the half that is easy to forget and impossible to
    /// notice: without it a revalidated entry stays exactly as stale as it was,
    /// and every subsequent request revalidates again.
    #[must_use]
    pub fn refreshed(
        &self,
        not_modified: &HeaderMap,
        requested_at: SystemTime,
        received_at: SystemTime,
    ) -> Self {
        let mut headers = self.headers.clone();
        for name in not_modified.keys() {
            if is_hop_by_hop(name) || name == http::header::CONTENT_LENGTH {
                // The 304 describes itself, not the stored body. Copying its
                // `Content-Length` — zero — over the stored one would hand the
                // next caller a body it is told does not exist.
                continue;
            }
            let mut values = not_modified.get_all(name).iter();
            if let Some(first) = values.next() {
                headers.insert(name, first.clone());
                for extra in values {
                    headers.append(name, extra.clone());
                }
            }
        }

        Self {
            status: self.status,
            version: self.version,
            headers,
            body: self.body.clone(),
            selector: self.selector.clone(),
            requested_at,
            received_at,
        }
    }
}

fn header_date(headers: &HeaderMap, name: HeaderName) -> Option<SystemTime> {
    headers.get(name)?.to_str().ok().and_then(parse_http_date)
}

/// The `Vary` field names, or `None` when the response carries `Vary: *`.
///
/// `Vary: *` means the response is selected by something the request headers do
/// not express, so no future request can be proved equivalent and the response
/// is not storable at all.
#[must_use]
pub fn vary_names(headers: &HeaderMap) -> Option<Vec<HeaderName>> {
    let mut names = Vec::new();
    for value in headers.get_all(VARY) {
        let Ok(text) = value.to_str() else {
            // A `Vary` this cache cannot read is a selection rule it cannot
            // apply, which is the same situation as `*`.
            return None;
        };
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if token == "*" {
                return None;
            }
            match HeaderName::from_bytes(token.as_bytes()) {
                Ok(name) => names.push(name),
                Err(_) => return None,
            }
        }
    }
    names.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
    names.dedup();
    Some(names)
}

/// Whether a field is connection-specific and must not be stored or replayed.
///
/// A stored `Transfer-Encoding: chunked` served alongside a fully buffered body
/// describes a framing that is not there; a stored `Connection: keep-alive`
/// describes a connection that is long gone.
#[must_use]
pub fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Removes every hop-by-hop field, including the ones `Connection` names.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|text| text.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();

    let hop: Vec<HeaderName> = headers
        .keys()
        .filter(|name| is_hop_by_hop(name))
        .cloned()
        .chain(named)
        .collect();

    for name in hop {
        headers.remove(&name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn a_key_ignores_the_fragment_and_keeps_the_query() {
        let with_fragment = Url::parse("https://a.test/p?x=1#top").expect("a valid url");
        let without = Url::parse("https://a.test/p?x=1").expect("a valid url");
        let other_query = Url::parse("https://a.test/p?x=2").expect("a valid url");

        assert_eq!(
            CacheKey::new(&Method::GET, &with_fragment),
            CacheKey::new(&Method::GET, &without)
        );
        assert_ne!(
            CacheKey::new(&Method::GET, &without),
            CacheKey::new(&Method::GET, &other_query)
        );
        assert_ne!(
            CacheKey::new(&Method::GET, &without),
            CacheKey::new(&Method::HEAD, &without)
        );
    }

    #[test]
    fn an_empty_selector_matches_every_request() {
        assert!(Selector::any().matches(&map(&[("accept-language", "tr")])));
        assert!(Selector::any().matches(&HeaderMap::new()));
    }

    #[test]
    fn a_selector_distinguishes_an_absent_header_from_a_present_one() {
        let names = [HeaderName::from_static("accept-language")];
        let recorded = Selector::of(&names, &HeaderMap::new());

        assert!(recorded.matches(&HeaderMap::new()));
        assert!(
            !recorded.matches(&map(&[("accept-language", "tr")])),
            "a stored response selected on an absent header must not serve a request that has it"
        );
    }

    #[test]
    fn a_selector_compares_every_value_of_a_repeated_field() {
        let names = [HeaderName::from_static("accept-language")];
        let recorded = Selector::of(
            &names,
            &map(&[("accept-language", "tr"), ("accept-language", "en")]),
        );

        assert!(recorded.matches(&map(&[
            ("accept-language", "tr"),
            ("accept-language", "en")
        ])));
        assert!(!recorded.matches(&map(&[("accept-language", "tr")])));
        assert!(!recorded.matches(&map(&[
            ("accept-language", "en"),
            ("accept-language", "tr")
        ])));
    }

    #[test]
    fn vary_star_yields_no_names_at_all() {
        assert_eq!(vary_names(&map(&[("vary", "*")])), None);
        assert_eq!(vary_names(&map(&[("vary", "accept-encoding, *")])), None);
    }

    #[test]
    fn vary_names_are_normalised_across_lines() {
        let names = vary_names(&map(&[
            ("vary", "Accept-Language, accept-encoding"),
            ("vary", "accept-language"),
        ]))
        .expect("no star means names");
        let names: Vec<&str> = names.iter().map(HeaderName::as_str).collect();
        assert_eq!(names, vec!["accept-encoding", "accept-language"]);
    }

    #[test]
    fn hop_by_hop_fields_and_the_ones_connection_names_are_stripped() {
        let mut headers = map(&[
            ("connection", "keep-alive, x-private"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("x-private", "secret"),
            ("content-type", "text/plain"),
        ]);
        strip_hop_by_hop(&mut headers);

        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("transfer-encoding"));
        assert!(!headers.contains_key("x-private"));
        assert_eq!(headers["content-type"], "text/plain");
    }

    #[test]
    fn a_304_updates_the_stored_fields_but_never_the_stored_content_length() {
        let entry = CacheEntry::new(
            StatusCode::OK,
            Version::HTTP_11,
            map(&[
                ("content-length", "5"),
                ("etag", "\"one\""),
                ("cache-control", "max-age=0"),
            ]),
            Bytes::from_static(b"hello"),
            Selector::any(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        );

        let refreshed = entry.refreshed(
            &map(&[
                ("content-length", "0"),
                ("cache-control", "max-age=600"),
                ("x-new", "1"),
            ]),
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
            SystemTime::UNIX_EPOCH + Duration::from_secs(11),
        );

        assert_eq!(refreshed.headers()["content-length"], "5");
        assert_eq!(refreshed.headers()["cache-control"], "max-age=600");
        assert_eq!(refreshed.headers()["x-new"], "1");
        assert_eq!(refreshed.headers()["etag"], "\"one\"");
        assert_eq!(refreshed.body(), &Bytes::from_static(b"hello"));
        assert_eq!(
            refreshed.received_at(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(11)
        );
    }

    #[test]
    fn an_invalid_expires_is_a_time_in_the_past_while_an_absent_one_is_nothing() {
        let with_zero = CacheEntry::new(
            StatusCode::OK,
            Version::HTTP_11,
            map(&[("expires", "0")]),
            Bytes::new(),
            Selector::any(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        );
        assert_eq!(with_zero.expires_field(), Some(SystemTime::UNIX_EPOCH));

        let without = CacheEntry::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::new(),
            Selector::any(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        );
        assert_eq!(without.expires_field(), None);
    }

    #[test]
    fn a_non_numeric_age_field_is_ignored() {
        let entry = CacheEntry::new(
            StatusCode::OK,
            Version::HTTP_11,
            map(&[("age", "soon")]),
            Bytes::new(),
            Selector::any(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        );
        assert_eq!(entry.age_field(), None);
    }
}
