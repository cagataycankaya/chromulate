//! Per-URL `ETag` and `Last-Modified` memory, replayed as a conditional
//! request on the next visit to the same URL.
//!
//! # This is not what a browser does
//!
//! Chrome revalidates a *stored* response. It stores according to RFC 9111, so
//! a response carrying `no-store` is not written down and is therefore never
//! revalidated: the next visit is a plain unconditional request. This module
//! deliberately does the other thing. It keeps the validator whatever the
//! response's `Cache-Control` said, and replays it, because the validator is
//! the only part of the exchange a repeat visitor needs and storability is a
//! rule about *bodies*.
//!
//! That divergence is the reason the whole module sits behind the
//! `validator-store` cargo feature and is off by default. An engine with it
//! switched on sends a request Chrome would not send, which is an observable
//! difference on the wire, and the rest of this crate exists to avoid exactly
//! that. Leave it off unless the caller is a crawler or a monitor that revisits
//! the same URLs and wants to know whether anything changed.
//!
//! There is a second, sharper divergence in *where* the headers go. The profile
//! does not name `If-None-Match` or `If-Modified-Since`, so the header engine
//! appends them after everything it does name — measured on 2026-08-04 as
//! `… accept-language, priority, if-none-match, if-modified-since`. The
//! profile's own captured order is untouched, and
//! `tests/validator_store.rs::the_conditional_headers_are_appended_and_leave_the_profile_order_untouched`
//! holds it that way. But no capture of Chrome sending a conditional request
//! was available when this was written, so the trailing placement is a guess by
//! omission rather than an observed fact, and an origin that compares header
//! order can see it. Fixing that needs a capture, not a decision.
//!
//! # How often it can possibly help
//!
//! Six Turkish marketplace product pages were probed on 2026-08-04. One of the
//! six sent a validator at all — mediamarkt, with `Last-Modified` — and none of
//! the six sent an `ETag`. Two forbade storage outright and the rest were fresh
//! for two to five minutes, which is why an RFC 9111 cache is close to useless
//! on this workload and why revalidation, which does not need the response to
//! have been storable, is the part worth keeping.
//!
//! The measurement on the one origin that answers: `If-Modified-Since` returned
//! `304` in 60 ms with 0 bytes, against a full body of 1,106,803 bytes. That is
//! the ceiling of what this buys, on one origin in six. It is not a general
//! bandwidth saving and nothing here should be read as one.
//!
//! # What is stored, and what is not
//!
//! Validators only, never bodies. A `304` therefore means "unchanged since you
//! last saw it" and the caller skips its parsing; it cannot be turned back into
//! a full response, because there is nothing to turn it into. See
//! [`ValidatorStore`] for the memory consequence of the other choice.
//!
//! # No date is ever parsed
//!
//! `Last-Modified` is stored and replayed as opaque bytes. RFC 9111 §4.3.1 asks
//! for exactly that — the `If-Modified-Since` a client sends is the stored
//! `Last-Modified` value, not a re-rendering of it — and an origin comparing
//! the two byte for byte is entitled to. Parsing would buy nothing and cost
//! something real: the value is server-controlled, and turning server-controlled
//! text into a `SystemTime` is the bug this repository fixed in `hsts.rs`,
//! `deadline.rs` and `chromulate-dns/src/caching.rs` on one day. There is no
//! date arithmetic in this module to get wrong.

use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use http::header::{
    ETAG, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE, LAST_MODIFIED,
    VARY,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use url::{Position, Url};

/// How many URLs a store remembers before evicting the least recently used.
///
/// Ordinary configuration rather than a captured constant; pick whatever suits
/// the workload via [`ValidatorStore::with_capacity`]. The default is sized by
/// what an entry costs rather than by a round number.
///
/// Measured, not estimated: a full store of 4096 entries — 100-byte URLs,
/// 32-byte `ETag`s and the 29 bytes an IMF-fixdate always occupies — held
/// **1,335,304 heap bytes, or 326 bytes per entry**, under a counting allocator
/// on 2026-08-04 (identical across three runs). So the default bound is about
/// 1.3 MB: small enough to leave on, large enough for one site's catalogue.
/// The per-entry figure is roughly twice the stored bytes, which is what a
/// `HashMap`'s load factor and a `String`'s capacity rounding cost.
pub const DEFAULT_URL_CAPACITY: usize = 4_096;

/// What a response said about the identity of its representation.
///
/// Both fields are the origin's own header values, byte for byte. Nothing here
/// is normalised, re-rendered, or parsed as a date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validators {
    /// The response's `ETag`, replayed as `If-None-Match`.
    pub etag: Option<HeaderValue>,
    /// The response's `Last-Modified`, replayed as `If-Modified-Since`.
    pub last_modified: Option<HeaderValue>,
}

impl Validators {
    /// Reads the validators out of a response's headers.
    ///
    /// Returns `None` when neither field is present with a usable value; an
    /// empty field value is not a validator, and replaying one would put a
    /// header on every later request that can never produce a `304`.
    ///
    /// ```
    /// use chromulate_http::Validators;
    /// use http::{HeaderMap, HeaderValue};
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.insert("etag", HeaderValue::from_static("\"v1\""));
    ///
    /// let validators = Validators::from_headers(&headers).expect("an ETag is a validator");
    /// assert_eq!(validators.etag, Some(HeaderValue::from_static("\"v1\"")));
    /// assert_eq!(validators.last_modified, None);
    ///
    /// assert!(Validators::from_headers(&HeaderMap::new()).is_none());
    /// ```
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let validators = Self {
            etag: usable(headers.get(ETAG)),
            last_modified: usable(headers.get(LAST_MODIFIED)),
        };
        (!validators.is_empty()).then_some(validators)
    }

    /// Whether neither validator is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

/// One remembered URL, plus the bookkeeping eviction ranks on.
///
/// `last_use_seq` is an [`AtomicU64`] rather than a plain field so
/// [`ValidatorStore::condition`] can record that it just used an entry while
/// holding only a read lock. The alternative — a write lock on the request path
/// — is the shape `CLAUDE.md` warns about and the connection pool already pays
/// for. `chromulate-cookie`'s jar records cookie access the same way and for
/// the same reason.
#[derive(Debug)]
struct Entry {
    validators: Validators,
    last_use_seq: AtomicU64,
}

#[derive(Debug, Default)]
struct Inner {
    entries: HashMap<String, Entry>,
}

impl Inner {
    /// When the store holds more than `capacity`, evicts down to `target`,
    /// least recently used first.
    ///
    /// One pass, holding on to no more than the `doomed` worst candidates seen
    /// so far, so the store is never flattened into a temporary its own size.
    /// `target` sits a purge batch below `capacity`, so a store under sustained
    /// pressure pays this scan once per batch rather than once per insert —
    /// the same amortisation, and the same reasoning, as
    /// `chromulate_cookie::JarLimits::purge_batch`.
    fn evict(&mut self, capacity: usize, target: usize) {
        if self.entries.len() <= capacity {
            return;
        }
        let doomed = self.entries.len() - target;

        let mut worst: BinaryHeap<(u64, &str)> = BinaryHeap::with_capacity(doomed + 1);
        for (key, entry) in &self.entries {
            let candidate = (entry.last_use_seq.load(Ordering::Relaxed), key.as_str());
            if worst.len() < doomed {
                worst.push(candidate);
            } else if worst.peek().is_some_and(|held| *held > candidate) {
                worst.pop();
                worst.push(candidate);
            }
        }
        let victims: Vec<String> = worst.into_iter().map(|(_, key)| key.to_owned()).collect();

        for key in victims {
            self.entries.remove(&key);
        }
    }
}

/// Per-URL memory of `ETag` and `Last-Modified`, bounded and least-recently-used.
///
/// One of these belongs to a client rather than to a connection: the point is
/// that a *later* request to a URL remembers what an earlier response said
/// about it. Methods take `&self`, so an engine holds one directly and needs no
/// lock of its own.
///
/// # Not browser behaviour
///
/// Chrome would not send these requests. It revalidates responses it stored,
/// and it stores by RFC 9111, so an origin answering `no-store` is refetched in
/// full every time. This store keeps the validator regardless of what
/// `Cache-Control` said, which is why it lives behind a feature flag that is
/// off by default. See the [module documentation](self) for the measured hit
/// rate, which is one origin in six.
///
/// # No bodies
///
/// A `304` here means "unchanged"; it is not turned back into a full response,
/// because the body was never kept. That is a deliberate trade against the
/// alternative:
///
/// - **Keeping bodies** would let a `304` be served as a complete response,
///   which is more useful. It also means storing bodies the origin said
///   `no-store` about — on a marketplace, plausibly per-user content — and the
///   memory is set by the origin, not by this store. The one body measured for
///   this feature was 1,106,803 bytes; a price tracker over ten thousand URLs
///   would be holding something like eleven gigabytes.
/// - **Keeping validators only** costs the URL's bytes plus at most two header
///   values per entry, bounded by [`ValidatorStore::capacity`], and answers the
///   question a repeat visitor actually asks: did this change?
///
/// The second is what this is. A caller that wants the first wants an RFC 9111
/// cache, which is a different thing and should say so.
///
/// # `Vary`
///
/// A response carrying `Vary` with any field name is **not stored**, and a
/// `Vary` on a later response evicts what an earlier one stored. The store is
/// keyed by URL alone, so it cannot evaluate a secondary cache key; replaying a
/// validator that belongs to one variant would let the origin answer `304` for
/// a representation the caller never saw, which is silent corruption a scraper
/// would never notice. Refusing is the only thing this design can do honestly.
///
/// This is cheaper than it sounds on the workload it was built for: the one
/// origin of six that offered a validator, mediamarkt on 2026-08-04, sent no
/// `Vary` header at all on the page that carried `Last-Modified`.
///
/// # What it costs on the request path
///
/// There is one `RwLock` here, and `CLAUDE.md` is right to ask for the number
/// before anyone puts one in front of every request. Measured on an Apple M1
/// Pro (10 cores) on 2026-08-04, best of seven passes over a million calls,
/// three runs:
///
/// | case | ns per `condition` call |
/// | --- | --- |
/// | empty store — no lock taken at all | 2.31 / 2.21 / 2.31 |
/// | 4096 entries, URL absent — read lock, no match | 42.6 / 29.8 / 30.6 |
/// | 4096 entries, URL present — read lock, two header inserts | 88.3 / 82.8 / 84.4 |
///
/// The empty-store path is the one that matters, because five origins in six
/// never store anything, and it does not touch the lock. Against the 60 ms a
/// `304` was measured saving, even the hit path is five parts in a million.
///
/// The lock is not free under contention: eight threads hammering one store
/// with no other work took the per-call cost from 77–87 ns to 259–311 ns, about
/// 3.5x, so aggregate throughput still rises but sub-linearly. That is the
/// shared read-counter cache line, exactly as `engine.rs` describes for
/// `accept_ch`. Sharding would fix it and is deliberately not done here: no
/// workload has been measured where 300 ns beside a network round trip is worth
/// the complexity. If one turns up, that is the change to make.
///
/// Looking a URL up allocates nothing — `HashMap<String, _>` hashes a borrowed
/// `&str` — so a request that finds no validator costs no heap traffic. Only
/// storing one allocates.
///
/// # Example
///
/// ```
/// use chromulate_http::{ValidatorStore, Validators};
/// use http::HeaderValue;
/// use url::Url;
///
/// let store = ValidatorStore::new();
/// let url = Url::parse("https://example.com/product/1").unwrap();
///
/// // Normally learned from a response; seeded here so the example is offline.
/// store.insert(
///     &url,
///     Validators {
///         etag: None,
///         last_modified: Some(HeaderValue::from_static("Tue, 04 Aug 2026 16:32:20 GMT")),
///     },
/// );
///
/// let mut request = http::Request::get(url.as_str()).body(()).unwrap();
/// store.condition(&url, &mut request);
///
/// assert_eq!(
///     request.headers().get("if-modified-since"),
///     Some(&HeaderValue::from_static("Tue, 04 Aug 2026 16:32:20 GMT")),
/// );
/// ```
pub struct ValidatorStore {
    inner: RwLock<Inner>,
    /// How many entries the store holds, readable without taking the lock.
    ///
    /// Most requests will never find a validator — one origin in six offered
    /// one — and `RwLock::read` is still an atomic read-modify-write on a
    /// shared cache line, so an empty store would otherwise charge coherence
    /// traffic to every request in the process. This is the same trick, for the
    /// same reason, as `accept_ch_used` in `engine.rs`.
    ///
    /// It is a hint, not a gate on correctness. A reader that sees a stale zero
    /// skips one conditional header and pays for one full body; a reader that
    /// sees a stale non-zero takes the lock and finds nothing. Neither can
    /// produce a wrong answer.
    stored: AtomicUsize,
    /// Ticks once per use, so eviction can rank entries by recency without a
    /// clock.
    ///
    /// A counter rather than an `Instant` on purpose: `Instant + Duration`
    /// panics on overflow, and this module handles server-controlled input.
    /// `fetch_add` wraps rather than panicking, and at a billion uses a second
    /// a wrap is five centuries away — after which the only consequence is that
    /// eviction picks a poor victim.
    seq: AtomicU64,
    capacity: usize,
}

impl Default for ValidatorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ValidatorStore {
    /// Without the URLs it remembers.
    ///
    /// A store holds a whole crawl's worth of them, a query string routinely
    /// carries tokens, and `Debug` output ends up in logs — the same reason
    /// `chromulate::Response` prints its host and not its path and query. The
    /// userinfo is part of the key too, so a derived `Debug` printed passwords.
    ///
    /// The count is the lock-free hint rather than [`ValidatorStore::len`], so
    /// printing a store never blocks on a writer and cannot deadlock against
    /// one — a `Debug` that takes a lock is a trap in exactly the place it gets
    /// used, which is inside a panic or an error path.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatorStore")
            .field("stored", &self.stored.load(Ordering::Relaxed))
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl ValidatorStore {
    /// An empty store with the default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_URL_CAPACITY)
    }

    /// An empty store holding at most `capacity` URLs.
    ///
    /// A capacity of zero is raised to one: a store that can hold nothing is
    /// almost certainly a configuration mistake, and answering it with a panic
    /// helps nobody.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            stored: AtomicUsize::new(0),
            seq: AtomicU64::new(0),
            capacity: capacity.max(1),
        }
    }

    /// The most URLs this store will hold at rest.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How far below [`ValidatorStore::capacity`] an overflowing store is
    /// purged in one pass.
    ///
    /// A tenth, matching `chromulate_cookie::JarLimits::purge_batch`. Evicting
    /// exactly one entry per overflowing insert would rank the whole store on
    /// every insert for the rest of a crawl; a batch amortises that scan over
    /// the next `purge_batch` inserts. Capacities under ten purge one at a
    /// time, which is the exact-bound behaviour small stores want.
    #[must_use]
    pub fn purge_batch(&self) -> usize {
        (self.capacity / 10).max(1)
    }

    /// The level an overflowing store is purged down to.
    ///
    /// Never zero. At a capacity of one the batch is the whole store, and
    /// purging to zero would throw away the entry that had just been inserted —
    /// a store that holds nothing however small you asked for.
    fn purge_target(&self) -> usize {
        self.capacity.saturating_sub(self.purge_batch()).max(1)
    }

    /// How many URLs currently have a validator.
    #[must_use]
    pub fn len(&self) -> usize {
        self.read().entries.len()
    }

    /// Whether no URL has a validator.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds the conditional headers a stored validator calls for. **Engine
    /// wiring, line one.**
    ///
    /// Call this before the header engine runs, so the headers travel by the
    /// same path a caller's own headers do and land in the same place in the
    /// wire order.
    ///
    /// Does nothing, and takes no lock, when:
    ///
    /// - the store is empty;
    /// - the method is not `GET` or `HEAD` — a conditional `POST` asks the
    ///   origin about a representation the request is not retrieving;
    /// - the request already carries any of the RFC 9110 §13.1 conditional
    ///   header fields, in which case the caller is asking its own question and
    ///   is entitled to its own answer;
    /// - nothing is stored for the URL.
    ///
    /// When both validators are held, both headers are sent: RFC 9111 §4.3.1
    /// asks for both so an origin that understands only one still answers.
    pub fn condition<T>(&self, url: &Url, request: &mut Request<T>) {
        // The common case, and the only one that must stay free: a store that
        // has never seen a validator does not touch the lock at all.
        if self.stored.load(Ordering::Acquire) == 0 {
            return;
        }
        if !is_revalidatable(request.method()) || is_already_conditional(request.headers()) {
            return;
        }

        let (etag, last_modified) = {
            let guard = self.read();
            // `borrowed_key` rather than `key_for`: the request path must not
            // allocate a `String` per request just to hash it. `HashMap<String,
            // _>` looks up by `&str`, and only `put` needs an owned key.
            let Some(entry) = guard.entries.get(borrowed_key(url)) else {
                return;
            };
            entry.last_use_seq.store(self.next_seq(), Ordering::Relaxed);
            (
                entry.validators.etag.clone(),
                entry.validators.last_modified.clone(),
            )
        };

        let headers = request.headers_mut();
        if let Some(etag) = etag {
            headers.insert(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = last_modified {
            headers.insert(IF_MODIFIED_SINCE, last_modified);
        }
    }

    /// Records what a response said about its representation. **Engine wiring,
    /// line two.**
    ///
    /// Only `200` and `304` describe a representation, so only those two touch
    /// the store; a `404`, a `500` or a redirect leaves what the caller last saw
    /// alone.
    ///
    /// - **`200`** replaces the stored validators wholesale, and a `200`
    ///   carrying none clears the entry: the caller now holds a representation
    ///   with no validator, and the old one describes something it no longer
    ///   has.
    /// - **`304`** updates the stored fields from the ones the `304` carries,
    ///   per RFC 9110 §15.4.5, and leaves the fields it does not carry alone.
    ///   Most origins send a bare `304`, and forgetting the validator there
    ///   would cost a full body on every other visit.
    /// - **Either, carrying `Vary`**, evicts the entry and stores nothing; see
    ///   the type documentation.
    pub fn observe<T>(&self, url: &Url, method: &Method, response: &Response<T>) {
        if !is_revalidatable(method) {
            return;
        }
        let headers = response.headers();

        match response.status() {
            StatusCode::OK => {
                match Validators::from_headers(headers).filter(|_| !varies(headers)) {
                    Some(validators) => self.put(url, validators),
                    None => {
                        self.remove(url);
                    }
                }
            }
            StatusCode::NOT_MODIFIED => {
                if varies(headers) {
                    self.remove(url);
                } else {
                    self.refresh(url, headers);
                }
            }
            _ => {}
        }
    }

    /// The validators stored for `url`, if any.
    ///
    /// Inspection rather than use: unlike [`ValidatorStore::condition`] this
    /// does not count as having used the entry, so it cannot rescue one from
    /// eviction.
    #[must_use]
    pub fn get(&self, url: &Url) -> Option<Validators> {
        if self.stored.load(Ordering::Acquire) == 0 {
            return None;
        }
        self.read()
            .entries
            .get(borrowed_key(url))
            .map(|entry| entry.validators.clone())
    }

    /// Stores validators for `url` directly.
    ///
    /// This is how a process that ran before hands its knowledge to the one
    /// running now. A price tracker revisiting hours apart is usually a fresh
    /// process each time, and a store that only ever learns from live responses
    /// is empty on exactly the request that would have benefited.
    ///
    /// An empty [`Validators`] removes the entry rather than storing a record
    /// that can never produce a conditional request.
    pub fn insert(&self, url: &Url, validators: Validators) {
        if validators.is_empty() {
            self.remove(url);
        } else {
            self.put(url, validators);
        }
    }

    /// Forgets `url`, returning what was stored for it.
    pub fn remove(&self, url: &Url) -> Option<Validators> {
        // The same hint `condition` and `get` read, and for a sharper reason: a
        // `200` carrying no validator calls this, and most responses are that.
        // A store that has never held anything would otherwise take an
        // *exclusive* lock on every response in the process — worse than the
        // read lock the type documentation measures, and on a path that can
        // never have anything to do.
        //
        // A stale zero forgets nothing, which is what a `remove` racing an
        // `insert` from another thread may do in either order anyway.
        if self.stored.load(Ordering::Acquire) == 0 {
            return None;
        }
        let (removed, len) = {
            let mut guard = self.write();
            let removed = guard.entries.remove(borrowed_key(url));
            let len = guard.entries.len();
            (removed, len)
        };
        self.stored.store(len, Ordering::Release);
        removed.map(|entry| entry.validators)
    }

    /// Forgets everything.
    pub fn clear(&self) {
        self.write().entries.clear();
        self.stored.store(0, Ordering::Release);
    }

    fn put(&self, url: &Url, validators: Validators) {
        let key = key_for(url);
        let entry = Entry {
            validators,
            last_use_seq: AtomicU64::new(self.next_seq()),
        };

        let len = {
            let mut guard = self.write();
            guard.entries.insert(key, entry);
            guard.evict(self.capacity, self.purge_target());
            guard.entries.len()
        };
        // After the guard is dropped, so a reader that sees a non-zero count
        // finds the entry behind it.
        self.stored.store(len, Ordering::Release);
    }

    /// RFC 9110 §15.4.5: update the stored header fields from the `304`.
    fn refresh(&self, url: &Url, headers: &HeaderMap) {
        let etag = usable(headers.get(ETAG));
        let last_modified = usable(headers.get(LAST_MODIFIED));
        let seq = self.next_seq();

        let mut guard = self.write();
        let Some(entry) = guard.entries.get_mut(borrowed_key(url)) else {
            // A `304` for something this store never held. The response was
            // answering somebody else's conditional request.
            return;
        };
        if etag.is_some() {
            entry.validators.etag = etag;
        }
        if last_modified.is_some() {
            entry.validators.last_modified = last_modified;
        }
        entry.last_use_seq.store(seq, Ordering::Relaxed);
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The store's key: everything a request identifies a resource by, and nothing
/// else.
///
/// Scheme, host, port, path and query. The fragment is excluded because it is
/// never sent, so two URLs differing only in their fragment ask the origin the
/// same question and must share one entry.
///
/// Borrowed from the `Url`, which already holds the serialised form, so a
/// lookup costs no allocation. Only [`ValidatorStore::put`] needs an owned key.
fn borrowed_key(url: &Url) -> &str {
    &url[..Position::AfterQuery]
}

/// [`borrowed_key`], owned, for the one path that has to store it.
fn key_for(url: &Url) -> String {
    borrowed_key(url).to_owned()
}

/// Whether a method retrieves a representation this store can revalidate.
///
/// `HEAD` shares `GET`'s entry deliberately: RFC 9110 §9.3.2 makes a `HEAD`
/// response's header fields the ones the equivalent `GET` would have sent, so a
/// validator learned from either describes the same representation.
fn is_revalidatable(method: &Method) -> bool {
    method == Method::GET || method == Method::HEAD
}

/// Whether the caller already asked the origin a conditional question of its
/// own (RFC 9110 §13.1).
fn is_already_conditional(headers: &HeaderMap) -> bool {
    headers.contains_key(IF_NONE_MATCH)
        || headers.contains_key(IF_MODIFIED_SINCE)
        || headers.contains_key(IF_MATCH)
        || headers.contains_key(IF_UNMODIFIED_SINCE)
        || headers.contains_key(IF_RANGE)
}

/// Whether a response's `Vary` names any field at all.
///
/// `Vary:` with nothing in it, and a `Vary` made only of empty list elements,
/// name nothing and select nothing, so they are not a reason to refuse.
fn varies(headers: &HeaderMap) -> bool {
    headers.get_all(VARY).iter().any(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b',')
            .any(|field| !field.trim_ascii().is_empty())
    })
}

/// A header value that is actually a validator, which an empty one is not.
fn usable(value: Option<&HeaderValue>) -> Option<HeaderValue> {
    value
        .filter(|value| !value.as_bytes().trim_ascii().is_empty())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("test url should parse")
    }

    fn etag(text: &'static str) -> Validators {
        Validators {
            etag: Some(HeaderValue::from_static(text)),
            last_modified: None,
        }
    }

    fn response(status: u16, headers: &[(&str, &str)]) -> Response<()> {
        let mut builder = http::Response::builder().status(status);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).expect("test response should build")
    }

    fn conditioned(store: &ValidatorStore, target: &Url) -> HeaderMap {
        let mut request = http::Request::get(target.as_str())
            .body(())
            .expect("test request should build");
        store.condition(target, &mut request);
        request.headers().clone()
    }

    // ------------------------------------------------------------- the key

    #[test]
    fn two_urls_differing_only_in_their_fragment_share_one_entry() {
        let store = ValidatorStore::new();
        store.insert(&url("https://example.com/p?a=1#top"), etag("\"v\""));

        assert_eq!(store.len(), 1);
        assert!(
            store
                .get(&url("https://example.com/p?a=1#bottom"))
                .is_some(),
            "a fragment is never sent, so it cannot distinguish two requests"
        );
    }

    #[test]
    fn the_query_is_part_of_the_key() {
        let store = ValidatorStore::new();
        store.insert(&url("https://example.com/p?a=1"), etag("\"one\""));
        store.insert(&url("https://example.com/p?a=2"), etag("\"two\""));

        assert_eq!(store.len(), 2);
        assert_eq!(
            store.get(&url("https://example.com/p?a=1")),
            Some(etag("\"one\""))
        );
    }

    #[test]
    fn the_scheme_and_port_are_part_of_the_key() {
        let store = ValidatorStore::new();
        store.insert(&url("https://example.com/p"), etag("\"tls\""));

        assert!(store.get(&url("http://example.com/p")).is_none());
        assert!(store.get(&url("https://example.com:8443/p")).is_none());
    }

    // ----------------------------------------------------------- the bound

    #[test]
    fn the_store_never_holds_more_urls_than_its_capacity() {
        let store = ValidatorStore::with_capacity(40);
        for index in 0..500u32 {
            store.insert(&url(&format!("https://example.com/{index}")), etag("\"v\""));
            assert!(
                store.len() <= 40,
                "after {index} inserts the store held {}",
                store.len()
            );
        }
    }

    #[test]
    fn eviction_drops_the_least_recently_used_and_keeps_what_is_being_used() {
        let store = ValidatorStore::with_capacity(10);
        let kept = url("https://example.com/kept");
        store.insert(&kept, etag("\"kept\""));

        for index in 0..9u32 {
            store.insert(&url(&format!("https://example.com/{index}")), etag("\"v\""));
            // Using the entry is what rescues it; `get` deliberately does not.
            conditioned(&store, &kept);
        }
        // One more than the capacity, which triggers the purge.
        for index in 100..120u32 {
            store.insert(&url(&format!("https://example.com/{index}")), etag("\"v\""));
            conditioned(&store, &kept);
        }

        assert!(
            store.get(&kept).is_some(),
            "the entry used on every pass must survive eviction"
        );
        assert!(
            store.get(&url("https://example.com/0")).is_none(),
            "the entry never used again must not"
        );
    }

    #[test]
    fn an_overflowing_store_purges_a_batch_rather_than_a_single_entry() {
        let store = ValidatorStore::with_capacity(100);
        assert_eq!(store.purge_batch(), 10);

        for index in 0..101u32 {
            store.insert(&url(&format!("https://example.com/{index}")), etag("\"v\""));
        }
        assert_eq!(
            store.len(),
            90,
            "one insert past the bound purges a batch, so the scan is paid once \
             per batch rather than once per insert"
        );
    }

    /// The bound at the capacity a caller actually gets, rather than at the
    /// small one the tests above pick to stay quick.
    #[test]
    fn the_default_capacity_holds_when_it_is_filled_well_past() {
        let store = ValidatorStore::new();
        for index in 0..(DEFAULT_URL_CAPACITY as u32 * 2) {
            store.insert(&url(&format!("https://example.com/{index}")), etag("\"v\""));
        }

        assert!(
            store.len() <= DEFAULT_URL_CAPACITY,
            "the store held {} entries against a capacity of {DEFAULT_URL_CAPACITY}",
            store.len()
        );
        assert!(
            store.len() > DEFAULT_URL_CAPACITY - store.purge_batch() - 1,
            "a purge must take a batch and stop, not keep going: {} left",
            store.len()
        );
    }

    /// A purge may never empty the store, and may never throw away the insert
    /// that triggered it — which at a capacity of one is the only entry there
    /// is.
    #[test]
    fn a_purge_never_empties_the_store_or_evicts_what_triggered_it() {
        for capacity in [1usize, 2, 3, 9, 10, 11, 100, DEFAULT_URL_CAPACITY] {
            let store = ValidatorStore::with_capacity(capacity);
            assert!(
                store.purge_target() >= 1,
                "capacity {capacity} purges to {}",
                store.purge_target()
            );
            assert!(store.purge_target() <= capacity);

            let overflow = u32::try_from(capacity).expect("test capacity fits") + 3;
            for index in 0..overflow {
                store.insert(&url(&format!("https://example.com/{index}")), etag("\"v\""));
            }

            assert!(
                !store.is_empty(),
                "capacity {capacity} purged itself to nothing"
            );
            assert!(store.len() <= capacity, "capacity {capacity} overflowed");
            assert!(
                store
                    .get(&url(&format!("https://example.com/{}", overflow - 1)))
                    .is_some(),
                "capacity {capacity}: the entry whose insert triggered the purge \
                 must not be its victim"
            );
        }
    }

    #[test]
    fn a_capacity_of_zero_is_raised_to_one_rather_than_panicking() {
        let store = ValidatorStore::with_capacity(0);
        assert_eq!(store.capacity(), 1);
        assert_eq!(store.purge_batch(), 1);

        store.insert(&url("https://example.com/a"), etag("\"a\""));
        store.insert(&url("https://example.com/b"), etag("\"b\""));
        assert_eq!(store.len(), 1);
    }

    // ------------------------------------------------------------- storing

    #[test]
    fn a_200_with_no_validator_clears_what_was_stored() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");
        store.insert(&target, etag("\"old\""));

        store.observe(&target, &Method::GET, &response(200, &[]));
        assert!(store.get(&target).is_none());
    }

    #[test]
    fn a_200_with_a_validator_replaces_what_was_stored_wholesale() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");
        store.insert(
            &target,
            Validators {
                etag: Some(HeaderValue::from_static("\"old\"")),
                last_modified: Some(HeaderValue::from_static("Tue, 04 Aug 2026 16:32:20 GMT")),
            },
        );

        store.observe(
            &target,
            &Method::GET,
            &response(200, &[("etag", "\"new\"")]),
        );
        assert_eq!(
            store.get(&target),
            Some(etag("\"new\"")),
            "the old Last-Modified belongs to a representation the caller no \
             longer holds"
        );
    }

    #[test]
    fn a_304_updates_only_the_fields_it_carries() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");
        store.insert(
            &target,
            Validators {
                etag: Some(HeaderValue::from_static("\"old\"")),
                last_modified: Some(HeaderValue::from_static("Tue, 04 Aug 2026 16:32:20 GMT")),
            },
        );

        store.observe(
            &target,
            &Method::GET,
            &response(304, &[("etag", "\"new\"")]),
        );

        assert_eq!(
            store.get(&target),
            Some(Validators {
                etag: Some(HeaderValue::from_static("\"new\"")),
                last_modified: Some(HeaderValue::from_static("Tue, 04 Aug 2026 16:32:20 GMT")),
            }),
            "RFC 9110 15.4.5 updates the stored fields from the 304, and leaves \
             the ones it does not carry alone"
        );
    }

    #[test]
    fn a_304_for_a_url_that_was_never_stored_stores_nothing() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");

        store.observe(&target, &Method::GET, &response(304, &[("etag", "\"x\"")]));
        assert!(
            store.is_empty(),
            "that 304 was answering somebody else's conditional request"
        );
    }

    #[test]
    fn statuses_other_than_200_and_304_leave_the_entry_alone() {
        for status in [201, 204, 301, 400, 404, 410, 500, 503] {
            let store = ValidatorStore::new();
            let target = url("https://example.com/p");
            store.insert(&target, etag("\"kept\""));

            store.observe(&target, &Method::GET, &response(status, &[]));
            assert_eq!(
                store.get(&target),
                Some(etag("\"kept\"")),
                "status {status} does not describe a representation"
            );
        }
    }

    #[test]
    fn a_head_shares_the_entry_a_get_would_use() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");

        store.observe(&target, &Method::HEAD, &response(200, &[("etag", "\"h\"")]));
        assert_eq!(store.get(&target), Some(etag("\"h\"")));
    }

    #[test]
    fn a_non_idempotent_method_neither_stores_nor_clears() {
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let store = ValidatorStore::new();
            let target = url("https://example.com/p");
            store.insert(&target, etag("\"kept\""));

            store.observe(&target, &method, &response(200, &[("etag", "\"posted\"")]));
            assert_eq!(
                store.get(&target),
                Some(etag("\"kept\"")),
                "{method} does not retrieve the representation it answered about"
            );
        }
    }

    #[test]
    fn an_empty_field_value_is_not_a_validator() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");

        store.observe(
            &target,
            &Method::GET,
            &response(200, &[("etag", ""), ("last-modified", "   ")]),
        );
        assert!(store.is_empty());
    }

    #[test]
    fn an_empty_validators_insert_removes_rather_than_storing_a_useless_record() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");
        store.insert(&target, etag("\"old\""));

        store.insert(
            &target,
            Validators {
                etag: None,
                last_modified: None,
            },
        );
        assert!(store.is_empty());
    }

    // ---------------------------------------------------------------- vary

    #[test]
    fn a_response_naming_any_vary_field_is_not_stored() {
        for vary in [
            "*",
            "Accept-Encoding",
            "Cookie, Accept-Language",
            " User-Agent ",
        ] {
            let store = ValidatorStore::new();
            let target = url("https://example.com/p");

            store.observe(
                &target,
                &Method::GET,
                &response(200, &[("etag", "\"v\""), ("vary", vary)]),
            );
            assert!(store.is_empty(), "Vary: {vary} must not be stored");
        }
    }

    #[test]
    fn a_vary_naming_nothing_is_not_a_reason_to_refuse() {
        for vary in ["", " ", ",", " , , "] {
            let store = ValidatorStore::new();
            let target = url("https://example.com/p");

            store.observe(
                &target,
                &Method::GET,
                &response(200, &[("etag", "\"v\""), ("vary", vary)]),
            );
            assert_eq!(
                store.get(&target),
                Some(etag("\"v\"")),
                "Vary: {vary:?} selects on nothing"
            );
        }
    }

    #[test]
    fn a_vary_split_across_two_header_lines_is_still_a_refusal() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");

        let mut builder = http::Response::builder()
            .status(200)
            .header("etag", "\"v\"");
        builder = builder.header("vary", "");
        builder = builder.header("vary", "Cookie");
        let response = builder.body(()).expect("response");

        store.observe(&target, &Method::GET, &response);
        assert!(store.is_empty());
    }

    #[test]
    fn a_vary_on_a_later_response_evicts_what_an_earlier_one_stored() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");
        store.insert(&target, etag("\"v1\""));

        store.observe(&target, &Method::GET, &response(304, &[("vary", "Cookie")]));
        assert!(
            store.is_empty(),
            "an origin that starts varying makes what we hold unsafe to replay"
        );
    }

    // ----------------------------------------------------------- replaying

    #[test]
    fn both_headers_go_out_when_both_validators_are_held() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");
        store.insert(
            &target,
            Validators {
                etag: Some(HeaderValue::from_static("\"v\"")),
                last_modified: Some(HeaderValue::from_static("Tue, 04 Aug 2026 16:32:20 GMT")),
            },
        );

        let headers = conditioned(&store, &target);
        assert_eq!(
            headers.get(IF_NONE_MATCH),
            Some(&HeaderValue::from_static("\"v\""))
        );
        assert_eq!(
            headers.get(IF_MODIFIED_SINCE),
            Some(&HeaderValue::from_static("Tue, 04 Aug 2026 16:32:20 GMT")),
            "RFC 9111 4.3.1 sends both, so an origin that understands only one \
             still answers"
        );
    }

    #[test]
    fn an_empty_store_adds_nothing() {
        let store = ValidatorStore::new();
        assert!(conditioned(&store, &url("https://example.com/p")).is_empty());
    }

    #[test]
    fn a_url_with_no_entry_adds_nothing() {
        let store = ValidatorStore::new();
        store.insert(&url("https://example.com/other"), etag("\"v\""));

        assert!(conditioned(&store, &url("https://example.com/p")).is_empty());
    }

    #[test]
    fn the_callers_own_conditional_header_is_never_overwritten() {
        for existing in [
            IF_NONE_MATCH,
            IF_MODIFIED_SINCE,
            IF_MATCH,
            IF_UNMODIFIED_SINCE,
            IF_RANGE,
        ] {
            let store = ValidatorStore::new();
            let target = url("https://example.com/p");
            store.insert(&target, etag("\"ours\""));

            let mut request = http::Request::get(target.as_str())
                .header(existing.clone(), "\"theirs\"")
                .body(())
                .expect("request");
            store.condition(&target, &mut request);

            assert_eq!(
                request.headers().get(&existing).map(HeaderValue::as_bytes),
                Some(&b"\"theirs\""[..]),
                "{existing} was the caller's own question"
            );
            assert_eq!(
                request.headers().len(),
                1,
                "{existing} present means nothing of ours may be added either"
            );
        }
    }

    #[test]
    fn a_non_idempotent_method_is_never_conditioned() {
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let store = ValidatorStore::new();
            let target = url("https://example.com/p");
            store.insert(&target, etag("\"v\""));

            let mut request = http::Request::builder()
                .method(method.clone())
                .uri(target.as_str())
                .body(())
                .expect("request");
            store.condition(&target, &mut request);

            assert!(
                request.headers().is_empty(),
                "{method} is not retrieving this representation"
            );
        }
    }

    #[test]
    fn an_absurd_last_modified_is_replayed_byte_for_byte() {
        // Nothing here is a date. Nothing here is parsed as one. The point is
        // that a store which never converts server text into a `SystemTime`
        // cannot overflow one.
        for text in [
            "Thu, 99 Xxx 999999999999999999999 25:99:99 GMT",
            "-9223372036854775808",
            "0",
            "Tue, 04 Aug 292277026596 16:32:20 GMT",
            "not a date at all",
        ] {
            let store = ValidatorStore::new();
            let target = url("https://example.com/p");

            store.observe(
                &target,
                &Method::GET,
                &response(200, &[("last-modified", text)]),
            );
            let headers = conditioned(&store, &target);
            assert_eq!(
                headers.get(IF_MODIFIED_SINCE).map(HeaderValue::as_bytes),
                Some(text.as_bytes()),
                "{text} must go back exactly as it arrived"
            );
        }
    }

    // --------------------------------------------------- what it costs

    /// The empty-store path takes no lock — and `observe` is on that path too.
    ///
    /// Five origins in six send no validator at all, so the ordinary response
    /// is a `200` carrying nothing to store. That reaches `remove`, and a write
    /// lock there puts every response in the process behind every other,
    /// exclusively, on a store that has never held anything.
    ///
    /// Observed rather than reasoned: another thread holds the lock, and this
    /// asserts the call comes back anyway.
    #[test]
    fn a_response_with_no_validator_takes_no_lock_on_an_empty_store() {
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::time::Duration;

        let store = Arc::new(ValidatorStore::new());
        let held = store.write();

        let (finished, waited) = mpsc::channel();
        let worker = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                store.observe(
                    &url("https://example.com/p"),
                    &Method::GET,
                    &response(200, &[]),
                );
                let _ = finished.send(());
            })
        };

        let outcome = waited.recv_timeout(Duration::from_secs(5));
        drop(held);
        worker.join().expect("the worker must not panic");

        assert!(
            outcome.is_ok(),
            "observing a 200 with no validator blocked on the write lock, so \
             the empty-store path is not lock-free after all"
        );
    }

    /// The same for a direct `remove`, which is the call underneath it.
    #[test]
    fn removing_from_an_empty_store_takes_no_lock() {
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::time::Duration;

        let store = Arc::new(ValidatorStore::new());
        let held = store.write();

        let (finished, waited) = mpsc::channel();
        let worker = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                let removed = store.remove(&url("https://example.com/p"));
                let _ = finished.send(removed);
            })
        };

        let outcome = waited.recv_timeout(Duration::from_secs(5));
        drop(held);
        worker.join().expect("the worker must not panic");

        assert_eq!(
            outcome.ok(),
            Some(None),
            "removing from a store that holds nothing must neither block nor \
             claim to have forgotten something"
        );
    }

    /// A store's `Debug` must not print the URLs it remembers.
    ///
    /// `Response`'s own `Debug` omits the path and query for exactly this
    /// reason — a query string routinely carries tokens and `Debug` output ends
    /// up in logs — and this type holds a whole crawl's worth of them.
    #[test]
    fn the_debug_rendering_carries_no_stored_url() {
        let store = ValidatorStore::with_capacity(64);
        store.insert(
            &url("https://user:hunter2@example.com/p?session=SUPERSECRET"),
            etag("\"v\""),
        );

        let rendered = format!("{store:?}");
        assert!(
            !rendered.contains("SUPERSECRET"),
            "a stored query string reached Debug output: {rendered}"
        );
        assert!(
            !rendered.contains("hunter2"),
            "stored credentials reached Debug output: {rendered}"
        );
        assert!(
            rendered.contains("64"),
            "the shape of the store is still worth printing: {rendered}"
        );
    }

    /// A validator is server-controlled text, and the one thing it must never
    /// become is a second header. It cannot: the store holds `HeaderValue`s,
    /// and a `HeaderValue` cannot contain CR, LF or NUL — so a hostile
    /// `Last-Modified` is refused at the door rather than sanitised on the way
    /// out.
    #[test]
    fn a_delimiter_cannot_reach_the_store_let_alone_be_replayed() {
        for hostile in [
            &b"Tue, 04 Aug 2026 16:32:20 GMT\r\nX-Injected: yes"[..],
            b"line\rone",
            b"line\none",
            b"nul\0byte",
        ] {
            assert!(
                HeaderValue::from_bytes(hostile).is_err(),
                "a header value must refuse {hostile:?}"
            );

            let built = http::Response::builder()
                .status(200)
                .header(LAST_MODIFIED, hostile)
                .body(());
            assert!(
                built.is_err(),
                "a response carrying {hostile:?} cannot even be constructed, so \
                 nothing can observe one"
            );
        }
    }

    /// An absurdly long validator is replayed whole rather than truncated: a
    /// value cut in half would be a different validator, and the origin would
    /// answer `200` to a question nobody asked.
    ///
    /// What this costs is the honest caveat on the capacity constant's 1.3 MB
    /// figure — that number is for the 100-byte URLs and 32-byte `ETag`s it
    /// names, and an entry's size is the origin's choice, not this store's.
    #[test]
    fn an_absurdly_long_validator_survives_intact() {
        let long = "x".repeat(64 * 1024);
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");

        store.observe(
            &target,
            &Method::GET,
            &response(200, &[("last-modified", &long)]),
        );

        let headers = conditioned(&store, &target);
        assert_eq!(
            headers
                .get(IF_MODIFIED_SINCE)
                .map(|value| value.as_bytes().len()),
            Some(long.len()),
            "a truncated validator is a different validator"
        );
        assert_eq!(
            headers.get(IF_MODIFIED_SINCE).map(HeaderValue::as_bytes),
            Some(long.as_bytes())
        );
    }

    // ---------------------------------------------------------- management

    #[test]
    fn remove_returns_what_it_forgot() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");
        store.insert(&target, etag("\"v\""));

        assert_eq!(store.remove(&target), Some(etag("\"v\"")));
        assert_eq!(store.remove(&target), None);
        assert!(store.is_empty());
    }

    #[test]
    fn clear_empties_the_store_and_stops_it_replaying() {
        let store = ValidatorStore::new();
        let target = url("https://example.com/p");
        store.insert(&target, etag("\"v\""));

        store.clear();
        assert!(store.is_empty());
        assert!(conditioned(&store, &target).is_empty());
    }

    #[test]
    fn a_store_shared_across_threads_stays_consistent() {
        use std::sync::Arc;

        let store = Arc::new(ValidatorStore::with_capacity(64));
        let mut handles = Vec::new();
        for worker in 0..8u32 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                for index in 0..200u32 {
                    let target = url(&format!("https://example.com/{worker}/{index}"));
                    store.insert(&target, etag("\"v\""));
                    let mut request = http::Request::get(target.as_str())
                        .body(())
                        .expect("request");
                    store.condition(&target, &mut request);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("worker should not panic");
        }

        assert!(store.len() <= 64, "the bound holds under concurrency");
    }
}
