//! The cache itself: what to do before a request, and what to do with what
//! came back.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use chromulate_core::{Body, Request, Response, Result};
use futures_core::Stream;
use http::header::{
    AGE, CONTENT_LENGTH, CONTENT_LOCATION, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
    LOCATION, RANGE, VARY,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Version};
use http_body::Body as _;
use url::Url;

use crate::clock::{SystemWallClock, WallClock};
use crate::directive::CacheControl;
use crate::entry::{CacheEntry, CacheKey, Selector, strip_hop_by_hop, vary_names};
use crate::policy::{
    CacheConfig, current_age, has_validator, is_fresh, request_forces_revalidation, storable,
};
use crate::storage::{CacheStorage, MemoryStore};

/// How a response reached the caller, placed in the response's extensions when
/// the cache had a hand in producing it.
///
/// Absent on an ordinary network response, so `get::<CacheStatus>()` answering
/// `None` means the cache was not involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    /// Served from store without contacting the origin.
    Hit,
    /// The origin was asked and answered `304`; the stored body was served.
    Revalidated,
}

/// An RFC 9111 HTTP cache.
///
/// ```
/// use std::sync::Arc;
/// use std::time::{Duration, SystemTime};
///
/// use chromulate_cache::{CacheStatus, HttpCache, ManualClock};
/// use chromulate_core::Body;
/// use url::Url;
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let clock = ManualClock::at(SystemTime::UNIX_EPOCH);
/// let cache = HttpCache::builder().clock(Arc::clone(&clock) as _).build();
/// let url = Url::parse("https://example.com/style.css").unwrap();
/// let get = || {
///     http::Request::builder()
///         .uri(url.as_str())
///         .body(Body::empty())
///         .unwrap()
/// };
///
/// // Nothing is stored yet, so there is nothing to serve.
/// let mut first = get();
/// let (pending, hit) = cache.before(&mut first, &url);
/// assert!(hit.is_none());
///
/// let from_origin = http::Response::builder()
///     .header("cache-control", "max-age=600")
///     .body(Body::fixed("body { }"))
///     .unwrap();
///
/// // The entry is committed as the caller reads the body, not before it.
/// let recorded = cache.after(pending, &url, from_origin);
/// let _ = recorded.into_body().collect(4096).await.unwrap();
///
/// let mut second = get();
/// let (_, hit) = cache.before(&mut second, &url);
/// let hit = hit.expect("a fresh entry is served without asking the origin");
/// assert_eq!(hit.extensions().get::<CacheStatus>(), Some(&CacheStatus::Hit));
/// assert_eq!(hit.headers()["age"], "0");
///
/// // Ten minutes later it is stale, and the request goes out conditionally.
/// clock.advance(Duration::from_secs(600));
/// let mut third = get();
/// let (_, hit) = cache.before(&mut third, &url);
/// assert!(hit.is_none());
/// # });
/// ```
pub struct HttpCache {
    storage: Arc<dyn CacheStorage>,
    clock: Arc<dyn WallClock>,
    config: CacheConfig,
}

impl HttpCache {
    /// A cache with an in-memory store, the system clock, and default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Starts a builder.
    #[must_use]
    pub fn builder() -> HttpCacheBuilder {
        HttpCacheBuilder::default()
    }

    /// The backend this cache stores into.
    #[must_use]
    pub fn storage(&self) -> &Arc<dyn CacheStorage> {
        &self.storage
    }

    /// The limits this cache runs under.
    #[must_use]
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Consulted before a request is sent.
    ///
    /// Returns the state [`after`](HttpCache::after) needs, and the stored
    /// response when one may be served without contacting the origin. When a
    /// stored response exists but is stale, `request` is given `If-None-Match`
    /// and `If-Modified-Since` and the caller sends it as usual.
    #[must_use]
    pub fn before(&self, request: &mut Request, url: &Url) -> (Pending, Option<Response>) {
        let now = self.clock.now();
        let method = request.method().clone();

        // A caller running its own conditional or range request owns that
        // exchange. Layering a second `If-None-Match` over theirs produces a
        // `304` neither side can interpret.
        let caller_owns_it = request.headers().contains_key(IF_NONE_MATCH)
            || request.headers().contains_key(IF_MODIFIED_SINCE)
            || request.headers().contains_key(RANGE);

        let request_cc = CacheControl::of_request(request.headers());
        if caller_owns_it || method != Method::GET || request_cc.no_store {
            return (Pending::aside(&method), None);
        }

        let key = CacheKey::new(&method, url);
        let mut state = Box::new(PendingInner {
            key,
            request_headers: request.headers().clone(),
            request_cc,
            requested_at: now,
            revalidating: None,
        });

        let Some(entry) = self.select(&state.key, request.headers()) else {
            return (Pending::store(state), None);
        };

        let response_cc = CacheControl::of(entry.headers());
        if is_fresh(&entry, &response_cc, &self.config, now)
            && !request_forces_revalidation(&state.request_cc)
        {
            tracing::trace!(key = %state.key, "serving a fresh stored response");
            let age = current_age(&entry, now);
            let served = to_response(&entry, age, CacheStatus::Hit);
            return (Pending::store(state), Some(served));
        }

        if !has_validator(entry.headers()) {
            // Stale, with nothing to revalidate against. The entry cannot help,
            // and the response that comes back will simply replace it.
            return (Pending::store(state), None);
        }

        if let Some(etag) = entry.headers().get(ETAG) {
            request.headers_mut().insert(IF_NONE_MATCH, etag.clone());
        }
        if let Some(last_modified) = entry.headers().get(LAST_MODIFIED) {
            // Sent alongside `If-None-Match`, exactly as a browser sends it.
            // RFC 9110 §13.1.3 tells the origin to ignore it when an entity tag
            // is present, so the pair is not ambiguous.
            request
                .headers_mut()
                .insert(IF_MODIFIED_SINCE, last_modified.clone());
        }
        tracing::trace!(key = %state.key, "revalidating a stored response");
        state.revalidating = Some(entry);
        (Pending::store(state), None)
    }

    /// Records what the origin answered, returning the response the caller
    /// should use.
    ///
    /// On a `304` that is the stored response; on anything else it is the
    /// origin's own, with its body wrapped so that what the caller reads is
    /// also what gets stored.
    #[must_use]
    pub fn after(&self, pending: Pending, url: &Url, response: Response) -> Response {
        let state = match pending.kind {
            Kind::Aside => return response,
            // RFC 9111 §4.4. A successful unsafe method has changed the
            // target, so whatever is stored for it is now a lie.
            Kind::Invalidate => {
                if response.status().as_u16() < 400 {
                    self.invalidate(url);
                    self.invalidate_referenced(url, response.headers());
                }
                return response;
            }
            Kind::Store(state) => *state,
        };
        let received_at = self.clock.now();

        // A `304` that names a representation this cache does not hold, or that
        // selects its representations by fields other than the ones the stored
        // entry was selected by, is not a revalidation of anything here.
        // Falling through rather than merging sends it to the not-storable path
        // below, which drops the superseded entry — a `304` is not a cacheable
        // status — and hands the origin's own answer back.
        if let Some(entry) = &state.revalidating
            && response.status() == StatusCode::NOT_MODIFIED
            && validators_agree(entry.headers(), response.headers())
            && selects_the_same_way(entry.headers(), response.headers())
        {
            let refreshed =
                Arc::new(entry.refreshed(response.headers(), state.requested_at, received_at));

            // The merge produces a response this cache has never applied §3 to.
            // A `304` may add `no-store`, `Set-Cookie`, or `private`, and every
            // one of those would have refused the response on the way in; none
            // of them is weaker for arriving on a revalidation instead.
            let merged_cc = CacheControl::of(refreshed.headers());
            match storable(
                &self.config,
                &Method::GET,
                &state.request_headers,
                &state.request_cc,
                refreshed.status(),
                refreshed.headers(),
                &merged_cc,
            ) {
                Ok(_) => {
                    self.store(&state.key, Arc::clone(&refreshed));
                    tracing::trace!(key = %state.key, "revalidated a stored response");
                }
                // Served, but not kept: the caller still needs the body and
                // whatever state the `304` carried, and dropping either
                // silently would lose what the origin sent.
                Err(reason) => {
                    tracing::trace!(
                        key = %state.key,
                        %reason,
                        "a 304 refreshed an entry into one that may not be stored"
                    );
                    self.remove(&state.key);
                }
            }

            let age = current_age(&refreshed, received_at);
            return revalidated(&refreshed, age, response.into_body());
        }

        let response_cc = CacheControl::of(response.headers());
        let names = match storable(
            &self.config,
            &Method::GET,
            &state.request_headers,
            &state.request_cc,
            response.status(),
            response.headers(),
            &response_cc,
        ) {
            Ok(names) => names,
            Err(reason) => {
                tracing::trace!(key = %state.key, %reason, "not storing a response");
                // §5.2.2.5's intent applied strictly, and the revalidation case
                // that follows from it: a target the origin has just refused to
                // let anyone keep must not keep the copy taken a minute ago,
                // and an entry whose revalidation came back unstorable is
                // superseded rather than still valid.
                if response_cc.no_store || state.revalidating.is_some() {
                    self.remove(&state.key);
                }
                return response;
            }
        };

        // An optimisation, not a guard, and it is worth being plain about
        // which: `Recording` below enforces the same budget while the body
        // streams, and it is what catches a body whose length was never
        // declared. Mutating this branch alone leaves every test green,
        // because the only thing it changes is how many bytes are buffered
        // before the same decision is reached. It stays because those bytes
        // are the whole cost the budget exists to avoid.
        let length = response.body().size_hint().exact();
        if length.is_some_and(|length| length > self.config.max_body_bytes) {
            tracing::trace!(key = %state.key, "not storing a body larger than the budget");
            return response;
        }

        let (parts, body) = response.into_parts();
        let mut stored_headers = parts.headers.clone();
        strip_hop_by_hop(&mut stored_headers);

        let recording = Recording {
            inner: body,
            buffered: BytesMut::new(),
            commit: Some(Commit {
                storage: Arc::clone(&self.storage),
                selector: Selector::of(&names, &state.request_headers),
                key: state.key,
                status: parts.status,
                version: parts.version,
                headers: stored_headers,
                requested_at: state.requested_at,
                received_at,
                limit: self.config.max_body_bytes,
            }),
        };

        Response::from_parts(parts, Body::stream(recording, length))
    }

    /// Drops everything stored for a target.
    pub fn invalidate(&self, url: &Url) {
        self.remove(&CacheKey::new(&Method::GET, url));
    }

    /// The stored variant that matches this request, if any.
    fn select(&self, key: &CacheKey, request: &HeaderMap) -> Option<Arc<CacheEntry>> {
        let variants = match self.storage.get(key) {
            Ok(variants) => variants,
            Err(error) => {
                // A backend that cannot be read is a miss, never a failure: a
                // broken cache must not become a broken request.
                tracing::debug!(%key, %error, "the cache backend refused a lookup");
                return None;
            }
        };
        variants
            .iter()
            .find(|entry| entry.selector().matches(request))
            .map(Arc::clone)
    }

    fn store(&self, key: &CacheKey, entry: Arc<CacheEntry>) {
        if let Err(error) = self.storage.put(key, entry) {
            tracing::debug!(%key, %error, "the cache backend refused a store");
        }
    }

    fn remove(&self, key: &CacheKey) {
        if let Err(error) = self.storage.remove(key) {
            tracing::debug!(%key, %error, "the cache backend refused a removal");
        }
    }

    /// Invalidates the same-origin targets a response points at (§4.4).
    fn invalidate_referenced(&self, url: &Url, headers: &HeaderMap) {
        for name in [LOCATION, CONTENT_LOCATION] {
            let Some(target) = headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|text| url.join(text).ok())
            else {
                continue;
            };
            // Cross-origin invalidation would let one origin evict another's
            // entries just by naming them.
            if target.origin() == url.origin() {
                self.invalidate(&target);
            }
        }
    }
}

impl Default for HttpCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HttpCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpCache")
            .field("storage", &self.storage)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Assembles an [`HttpCache`].
#[derive(Default)]
pub struct HttpCacheBuilder {
    storage: Option<Arc<dyn CacheStorage>>,
    clock: Option<Arc<dyn WallClock>>,
    config: Option<CacheConfig>,
}

impl fmt::Debug for HttpCacheBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpCacheBuilder")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl HttpCacheBuilder {
    /// Stores into a backend other than the in-memory one.
    #[must_use]
    pub fn storage(mut self, storage: Arc<dyn CacheStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Reads time from somewhere other than the system clock.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn WallClock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Sets the limits.
    #[must_use]
    pub fn config(mut self, config: CacheConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Builds the cache.
    #[must_use]
    pub fn build(self) -> HttpCache {
        HttpCache {
            storage: self
                .storage
                .unwrap_or_else(|| Arc::new(MemoryStore::new()) as Arc<dyn CacheStorage>),
            clock: self
                .clock
                .unwrap_or_else(|| Arc::new(SystemWallClock) as Arc<dyn WallClock>),
            config: self.config.unwrap_or_default(),
        }
    }
}

/// What [`HttpCache::before`] learned, carried to [`HttpCache::after`].
///
/// Opaque, and free when the cache decided not to participate.
#[derive(Debug, Default)]
pub struct Pending {
    kind: Kind,
}

#[derive(Debug, Default)]
enum Kind {
    /// Nothing to do: the request is neither storable nor invalidating.
    #[default]
    Aside,
    /// An unsafe method. Nothing is stored, but a successful response
    /// invalidates whatever was.
    Invalidate,
    /// A cacheable request, with everything the store decision needs.
    Store(Box<PendingInner>),
}

impl Pending {
    fn aside(method: &Method) -> Self {
        Self {
            kind: if is_safe(method) {
                Kind::Aside
            } else {
                Kind::Invalidate
            },
        }
    }

    fn store(state: Box<PendingInner>) -> Self {
        Self {
            kind: Kind::Store(state),
        }
    }
}

#[derive(Debug)]
struct PendingInner {
    key: CacheKey,
    /// The request's headers as the caller wrote them, which is what the
    /// `Vary` selector is built from. `crate::policy`'s `UNSELECTABLE` list
    /// says what that costs and which responses it makes unstorable.
    request_headers: HeaderMap,
    request_cc: CacheControl,
    requested_at: SystemTime,
    revalidating: Option<Arc<CacheEntry>>,
}

/// Whether a `304` names the representation this cache stored.
///
/// RFC 9111 §4.3.4: the validator on a `304` identifies which stored response
/// it updates, and if none of them carries that validator the cache must not
/// use the `304` to update any of them. An origin that answers
/// `If-None-Match: "v1"` with a `304` carrying `ETag: "v2"` is confirming a
/// representation this cache does not hold; merging it would label the stored
/// body with a tag that was never its own, and every later revalidation would
/// then confirm the wrong one — a body frozen under a name it does not have.
///
/// The comparison is on the opaque tag alone, so `W/"v1"` and `"v1"` are the
/// same representation and a weak tag that *changed* is still a change. A `304`
/// carrying no `ETag`, or one answering an entry that had none, is accepted:
/// the origin validated it against the `Last-Modified` this cache sent, and
/// refusing there would throw away every `If-Modified-Since` hit.
fn validators_agree(stored: &HeaderMap, not_modified: &HeaderMap) -> bool {
    match (stored.get(ETAG), not_modified.get(ETAG)) {
        (Some(stored), Some(confirmed)) => opaque_tag(stored) == opaque_tag(confirmed),
        _ => true,
    }
}

/// An entity tag without its weakness prefix.
fn opaque_tag(value: &HeaderValue) -> &[u8] {
    let bytes = value.as_bytes();
    bytes.strip_prefix(b"W/").unwrap_or(bytes)
}

/// Whether a `304` selects its representations the way the stored entry was
/// selected.
///
/// A [`Selector`] records the values the *stored* `Vary` named, taken from the
/// request that fetched the body. A `304` naming different fields describes a
/// resource whose selection rules have moved, and this cache cannot place the
/// body it holds under the new ones: keeping the entry would leave a response
/// fetched for one `Accept-Language` matching a request for another, and
/// rebuilding the selector from the current request would leave the same body
/// stored twice, once under each rule.
///
/// A `304` that says nothing about `Vary` is the common case and changes
/// nothing — RFC 9110 §15.4.5 asks for the field but plenty of origins omit it,
/// and an omission is not a statement that selection stopped.
fn selects_the_same_way(stored: &HeaderMap, not_modified: &HeaderMap) -> bool {
    if !not_modified.contains_key(VARY) {
        return true;
    }
    // A stored entry can never carry `Vary: *`, so the `None` on the left is
    // unreachable; the `None` on the right — `*`, or a `Vary` this cache cannot
    // read — never matches it.
    vary_names(stored).is_some_and(|stored| vary_names(not_modified) == Some(stored))
}

/// Whether a recorded body is the length its own headers promised.
///
/// RFC 9110 §6.3: a message whose declared length is not its length is
/// malformed. Storing one freezes the disagreement rather than ending it — the
/// body becomes [`Bytes`] and the `Content-Length` stays a claim about it, and
/// nothing downstream re-derives the second from the first, so every later hit
/// serves the same corrupt pair.
fn declares_its_length(headers: &HeaderMap, length: usize) -> bool {
    let Some(declared) = headers.get(CONTENT_LENGTH) else {
        return true;
    };
    declared
        .to_str()
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .is_some_and(|declared| declared == length as u64)
}

/// The methods RFC 9110 §9.2.1 calls safe.
fn is_safe(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// Rebuilds a stored response.
fn to_response(entry: &CacheEntry, age: Duration, status: CacheStatus) -> Response {
    // `Bytes::clone` is a reference count, so a hit copies no body bytes.
    let mut response = http::Response::new(Body::fixed(entry.body().clone()));
    *response.status_mut() = entry.status();
    *response.version_mut() = entry.version();
    *response.headers_mut() = entry.headers().clone();
    stamp(&mut response, age, status);
    response
}

/// A stored response whose body first drains the `304` that revalidated it.
///
/// A `304` carries no body, but it still has to be polled to completion: this
/// crate's caller returns an HTTP/1.1 connection to the pool when its response
/// body ends, and a body dropped instead takes the connection with it.
/// Chaining rather than awaiting is what keeps [`HttpCache::after`]
/// synchronous, and the caller's request path free of another future.
fn revalidated(entry: &CacheEntry, age: Duration, not_modified: Body) -> Response {
    let stored = entry.body().clone();
    let length = stored.len() as u64;
    let mut response = http::Response::new(Body::stream(
        Draining {
            inner: Some(not_modified),
            stored: Some(stored),
        },
        Some(length),
    ));
    *response.status_mut() = entry.status();
    *response.version_mut() = entry.version();
    *response.headers_mut() = entry.headers().clone();
    stamp(&mut response, age, CacheStatus::Revalidated);
    response
}

/// Writes the `Age` that RFC 9111 §5.1 requires of a cache, and records how the
/// response was produced.
fn stamp(response: &mut Response, age: Duration, status: CacheStatus) {
    response
        .headers_mut()
        .insert(AGE, HeaderValue::from(age.as_secs()));
    response.extensions_mut().insert(status);
}

struct Draining {
    inner: Option<Body>,
    stored: Option<Bytes>,
}

impl Stream for Draining {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        while let Some(body) = this.inner.as_mut() {
            match Pin::new(body).poll_frame(cx) {
                // Whatever a `304` carries is discarded; reaching the end, or
                // failing, both mean the connection has been dealt with.
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(_)) | None) => this.inner = None,
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(this.stored.take().map(Ok))
    }
}

/// A response body that stores itself as the caller reads it.
///
/// The alternative — collecting the body and only then handing it over — would
/// turn every cacheable response into a buffered one, which is not what this
/// project means by "stream by default". This records what passes through, so
/// a caller that abandons a body halfway leaves nothing stored. That is also
/// the right answer: a half-read response is not a response.
struct Recording {
    inner: Body,
    buffered: BytesMut,
    commit: Option<Commit>,
}

struct Commit {
    storage: Arc<dyn CacheStorage>,
    key: CacheKey,
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    selector: Selector,
    requested_at: SystemTime,
    received_at: SystemTime,
    limit: u64,
}

impl Stream for Recording {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    let Ok(chunk) = frame.into_data() else {
                        // Trailers. Nothing here stores them, so the loop asks
                        // for the next frame rather than ending the body.
                        continue;
                    };
                    if let Some(commit) = &this.commit {
                        let total = this.buffered.len() as u64 + chunk.len() as u64;
                        if total > commit.limit {
                            // Over budget. What was buffered is released now
                            // rather than at the end, because the rest of the
                            // body may be very long.
                            this.commit = None;
                            this.buffered = BytesMut::new();
                        } else {
                            this.buffered.extend_from_slice(&chunk);
                        }
                    }
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Poll::Ready(Some(Err(error))) => {
                    // A body that failed is a body whose end this cache never
                    // saw, and half a response is not a response.
                    this.commit = None;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    if let Some(commit) = this.commit.take() {
                        let body = std::mem::take(&mut this.buffered).freeze();
                        if !declares_its_length(&commit.headers, body.len()) {
                            tracing::debug!(
                                key = %commit.key,
                                "not storing a body that is not the length it declared"
                            );
                            return Poll::Ready(None);
                        }
                        let entry = Arc::new(CacheEntry::new(
                            commit.status,
                            commit.version,
                            commit.headers,
                            body,
                            commit.selector,
                            commit.requested_at,
                            commit.received_at,
                        ));
                        match commit.storage.put(&commit.key, entry) {
                            Ok(()) => tracing::trace!(key = %commit.key, "stored a response"),
                            Err(error) => tracing::debug!(
                                key = %commit.key,
                                %error,
                                "the cache backend refused a store"
                            ),
                        }
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
