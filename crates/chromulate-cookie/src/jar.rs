//! The in-memory cookie jar: storage, eviction, and the [`CookieStore`] implementation.

use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::SystemTime;

use chromulate_core::{CookieContext, CookieStore, Origin};
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::clock::{Clock, SystemClock};
use crate::cookie::{Cookie, keeps_name_prefix_promise};
use crate::date;
use crate::domain;
use crate::same_site::SameSite;

/// Capacity limits enforced during eviction.
///
/// The defaults mirror the ballpark of Chromium's own cookie jar
/// (`kMaxCookiesPerHost = 180`, `kMaxCookies = 3300` in `net::CookieMonster`), rounded
/// down for `total`. These are ordinary configuration, not captured fingerprint
/// constants: pick whatever fits the caller's workload via [`Jar::with_limits`].
#[derive(Debug, Clone, Copy)]
pub struct JarLimits {
    /// Maximum cookies kept for a single registrable domain (a domain and all of its
    /// subdomains share one bucket, so `Domain=example.com` and a host-only cookie on
    /// `api.example.com` count against the same limit).
    ///
    /// Like [`JarLimits::total`], a ceiling rather than a level: a store that pushes a
    /// bucket past it purges one sixth below it in a single pass (Chromium's
    /// `kDomainPurgeCookies = 30` against `kMaxCookiesPerHost = 180`, the same ratio),
    /// so a bucket under sustained pressure oscillates between five sixths of the cap
    /// and the cap.
    pub per_domain: usize,
    /// Maximum cookies kept across the whole jar, regardless of domain.
    ///
    /// This is a ceiling the jar never exceeds at rest, not a level it sits at: a store
    /// that pushes past it purges one [`JarLimits::purge_batch`] below it in a single
    /// pass, so a jar under sustained pressure oscillates between `total - purge_batch`
    /// and `total`.
    pub total: usize,
}

impl JarLimits {
    /// How far below [`JarLimits::total`] an overflowing jar is purged in one pass.
    ///
    /// Evicting exactly one cookie per overflowing store would scan the whole jar for
    /// the least-recently-used victim on every store — the permanent state of a
    /// long-running crawl once the jar fills. Purging a batch amortises that scan over
    /// the next `purge_batch` stores. Chromium's `CookieMonster` batches for the same
    /// reason (`kPurgeCookies = 300` against `kMaxCookies = 3300`); the tenth used here
    /// keeps the same ratio. Totals under ten purge in batches of one, which is the
    /// exact-cap behaviour small test jars rely on.
    #[must_use]
    pub const fn purge_batch(&self) -> usize {
        self.total / 10
    }

    /// The level an overflowing jar is purged down to.
    const fn purge_target(&self) -> usize {
        self.total.saturating_sub(self.purge_batch())
    }

    /// How far below [`JarLimits::per_domain`] an overflowing bucket is trimmed in one
    /// pass — one sixth, Chromium's `kDomainPurgeCookies` to `kMaxCookiesPerHost`
    /// ratio. Per-domain caps under six trim exactly to the cap.
    #[must_use]
    pub const fn domain_purge_batch(&self) -> usize {
        self.per_domain / 6
    }

    /// The level an overflowing bucket is trimmed down to.
    const fn domain_purge_target(&self) -> usize {
        self.per_domain.saturating_sub(self.domain_purge_batch())
    }
}

impl Default for JarLimits {
    fn default() -> Self {
        Self {
            per_domain: 180,
            total: 3000,
        }
    }
}

/// One stored cookie plus the jar-wide bookkeeping needed for RFC 6265 §5.4 ordering
/// (creation order) and least-recently-used eviction (access order).
///
/// `last_access_seq` is a plain [`AtomicU64`] rather than a field behind the jar's
/// `RwLock`, so [`CookieStore::cookies_for`] can record which cookies it just served
/// while holding only a read lock: reads vastly outnumber writes on a crawl, and a
/// write lock on every lookup would defeat the point of using an `RwLock` at all.
#[derive(Debug)]
struct Entry {
    cookie: Cookie,
    creation_seq: u64,
    last_access_seq: AtomicU64,
}

/// The triple RFC 6265 §5.3 uses to decide whether an incoming cookie replaces a stored
/// one, rather than joining it.
type Identity = (String, String, String);

fn identity_of(cookie: &Cookie) -> Identity {
    (
        cookie.name.clone(),
        cookie.domain.clone(),
        cookie.path.clone(),
    )
}

/// One registrable domain's cookies, plus an index from each cookie's identity to its
/// position, so that finding the entry a `Set-Cookie` replaces costs a hash lookup rather
/// than a scan of the bucket.
///
/// The index is why every mutation lives behind a method here: a `Vec` and a map of
/// positions into it drift apart the moment one of them is updated somewhere the other is
/// not. Removal is by `swap_remove`, so bucket order carries no meaning — the `Cookie`
/// header's order comes from an explicit sort in [`CookieStore::cookies_for`].
#[derive(Debug, Default)]
struct Bucket {
    entries: Vec<Entry>,
    index: HashMap<Identity, usize>,
}

impl Bucket {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn iter(&self) -> std::slice::Iter<'_, Entry> {
        self.entries.iter()
    }

    fn get(&self, position: usize) -> Option<&Entry> {
        self.entries.get(position)
    }

    /// The position of the entry with this identity, if the bucket holds one.
    ///
    /// This index and the in-response trim in [`CookieStore::store`] are load-bearing
    /// *together*, and each one alone looks redundant. Reverting this index to a linear
    /// scan leaves `storing_one_response_with_many_cookies_stays_linear_in_the_number_of_cookies`
    /// green, because the trim still caps the bucket; reverting the trim leaves it green
    /// too, because this index makes the scan constant-time. Only removing both turns it
    /// red. A passing suite is therefore not evidence that dropping one of them was
    /// harmless — verified by mutation, both ways round.
    fn position_of(&self, name: &str, domain: &str, path: &str) -> Option<usize> {
        examined(1);
        self.index
            .get(&(name.to_owned(), domain.to_owned(), path.to_owned()))
            .copied()
    }

    fn push(&mut self, entry: Entry) {
        self.index
            .insert(identity_of(&entry.cookie), self.entries.len());
        self.entries.push(entry);
    }

    /// Replaces the entry at `position` with one of the same identity, leaving the index
    /// untouched because the key it maps has not changed.
    fn replace(&mut self, position: usize, entry: Entry) {
        debug_assert_eq!(
            identity_of(&entry.cookie),
            identity_of(&self.entries[position].cookie),
            "replace must not change an entry's identity"
        );
        self.entries[position] = entry;
    }

    /// Removes one entry, repairing the index for the entry that `swap_remove` moved into
    /// its place.
    fn remove(&mut self, position: usize) {
        let removed = self.entries.swap_remove(position);
        self.index.remove(&identity_of(&removed.cookie));
        if position < self.entries.len() {
            let moved = identity_of(&self.entries[position].cookie);
            self.index.insert(moved, position);
        }
    }

    /// Drops every entry expired as of `now`, in a single pass.
    fn remove_expired(&mut self, now: SystemTime) {
        examined(self.entries.len());
        let before = self.entries.len();
        self.entries.retain(|entry| !entry.cookie.is_expired(now));
        if self.entries.len() != before {
            self.reindex();
        }
    }

    /// Keeps the `keep` most recently accessed entries and drops the rest.
    ///
    /// One partial selection over the whole bucket, rather than one full scan per evicted
    /// cookie: a response carrying thousands of `Set-Cookie` headers used to pay the
    /// latter for every cookie past the cap.
    fn trim_to(&mut self, keep: usize) {
        if self.entries.len() <= keep {
            return;
        }
        examined(self.entries.len());
        let doomed_count = self.entries.len() - keep;

        let mut ranked: Vec<usize> = (0..self.entries.len()).collect();
        let entries = &self.entries;
        ranked.select_nth_unstable_by_key(doomed_count - 1, |&position| {
            entries[position].last_access_seq.load(Ordering::Relaxed)
        });
        let doomed = ranked[..doomed_count].to_vec();
        self.remove_all(&doomed);
    }

    /// Removes the entries at `positions`, which must be distinct, in a single pass.
    fn remove_all(&mut self, positions: &[usize]) {
        if positions.is_empty() {
            return;
        }
        let mut doomed = vec![false; self.entries.len()];
        for &position in positions {
            if let Some(slot) = doomed.get_mut(position) {
                *slot = true;
            }
        }
        let kept: Vec<Entry> = self
            .entries
            .drain(..)
            .enumerate()
            .filter_map(|(position, entry)| (!doomed[position]).then_some(entry))
            .collect();
        self.entries = kept;
        self.reindex();
    }

    /// Rebuilds the position index after a bulk removal reshuffled the entries.
    fn reindex(&mut self) {
        self.index.clear();
        for (position, entry) in self.entries.iter().enumerate() {
            self.index.insert(identity_of(&entry.cookie), position);
        }
    }
}

/// Every cookie in the jar, grouped by registrable domain.
///
/// `total` is maintained as buckets change rather than recomputed on demand. Summing
/// every bucket's length is itself linear in the size of the jar, and doing that on every
/// `store` is what made an ordinary crawl across many sites cost quadratic time.
#[derive(Debug, Default)]
struct Store {
    sites: HashMap<String, Bucket>,
    total: usize,
}

impl Store {
    /// Runs `change` against the bucket for `site`, creating the bucket if there is none
    /// and dropping it if `change` leaves it empty, and keeps [`Store::total`] in step.
    ///
    /// Every mutation of a bucket goes through here, which is the only reason `total` can
    /// be trusted.
    fn with_site<R>(&mut self, site: &str, change: impl FnOnce(&mut Bucket) -> R) -> R {
        let bucket = self.sites.entry(site.to_owned()).or_default();
        let before = bucket.len();
        let outcome = change(bucket);
        let after = bucket.len();
        self.total = self.total - before + after;
        if after == 0 {
            self.sites.remove(site);
        }
        outcome
    }

    /// Drops expired cookies and applies the per-domain cap everywhere.
    ///
    /// [`Jar::import`] can touch any number of sites at once and uses this; `store` can
    /// only ever touch one (every cookie in a response scopes to the request host's
    /// registrable domain) and tidies just that one.
    fn tidy_every_site(&mut self, now: SystemTime, per_domain: usize) {
        examined(self.sites.len());
        for bucket in self.sites.values_mut() {
            bucket.remove_expired(now);
            bucket.trim_to(per_domain);
        }
        self.sites.retain(|_, bucket| !bucket.is_empty());
        self.recount();
    }

    fn recount(&mut self) {
        examined(self.sites.len());
        self.total = self.sites.values().map(Bucket::len).sum();
    }

    /// When the jar holds more than `cap`, evicts down to `target`: expired cookies
    /// first, then least recently used.
    ///
    /// One pass over the jar, holding on to no more than the `doomed_count` worst
    /// candidates seen so far. The jar is never flattened into a temporary its own size,
    /// and ranking expired cookies below every live one drops them ahead of anything
    /// still in use without a separate sweep of every bucket.
    ///
    /// `target` sits a purge batch below `cap` (see [`JarLimits::purge_batch`]), so a
    /// jar under sustained store pressure pays this scan once per batch rather than once
    /// per store. The previous implementation evicted exactly to the cap, which meant
    /// one full scan per stored cookie for the whole life of a full jar.
    fn enforce_total(&mut self, now: SystemTime, cap: usize, target: usize) {
        if self.total <= cap {
            return;
        }
        let doomed_count = self.total - target;

        let mut worst: BinaryHeap<(EvictionRank, &str, usize)> =
            BinaryHeap::with_capacity(doomed_count + 1);
        let mut scanned = 0usize;
        for (site, bucket) in &self.sites {
            for (position, entry) in bucket.iter().enumerate() {
                scanned += 1;
                let candidate = (rank_for_eviction(entry, now), site.as_str(), position);
                if worst.len() < doomed_count {
                    worst.push(candidate);
                } else if worst.peek().is_some_and(|held| *held > candidate) {
                    worst.pop();
                    worst.push(candidate);
                }
            }
        }
        examined(scanned);

        let mut victims: HashMap<String, Vec<usize>> = HashMap::new();
        for (_, site, position) in worst {
            victims.entry(site.to_owned()).or_default().push(position);
        }

        for (site, positions) in victims {
            self.with_site(&site, |bucket| bucket.remove_all(&positions));
        }
    }
}

/// How badly an entry deserves eviction: lower is worse. Expired entries rank below every
/// live one, and live entries rank by how recently they were last sent.
type EvictionRank = (u8, u64);

fn rank_for_eviction(entry: &Entry, now: SystemTime) -> EvictionRank {
    (
        u8::from(!entry.cookie.is_expired(now)),
        entry.last_access_seq.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
thread_local! {
    /// Counts the stored entries the jar has looked at on this thread.
    ///
    /// Storing a cookie should cost work proportional to the cookies being stored, not
    /// to the size of the jar. A wall-clock assertion for that would be flaky on shared
    /// CI, so the jar counts the entries it examines instead and a test asserts the
    /// shape of the curve. Each test gets its own thread, so the count needs no
    /// synchronisation, and the whole thing compiles away outside `cfg(test)`.
    static ENTRIES_EXAMINED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Records that `_count` stored entries were examined. See [`ENTRIES_EXAMINED`].
#[inline]
fn examined(_count: usize) {
    #[cfg(test)]
    ENTRIES_EXAMINED.with(|counter| counter.set(counter.get() + _count as u64));
}

/// An in-memory, browser-grade cookie jar implementing
/// [`chromulate_core::CookieStore`].
///
/// Cookies are grouped by registrable domain ("site") rather than exact host, so a
/// `Domain=example.com` cookie and a host-only cookie on `api.example.com` share one
/// bucket; this is also the unit [`JarLimits::per_domain`] caps. Within a bucket,
/// eligibility for a given request is decided by domain, path, and `Secure` matching,
/// plus `SameSite` eligibility against the request's [`CookieContext`].
///
/// Persistence is out of scope: [`Jar::export`] and [`Jar::import`] hand a serialisable
/// snapshot to and from the caller, who decides where (if anywhere) it is written.
///
/// ```
/// use chromulate_cookie::Jar;
/// use chromulate_core::{CookieContext, CookieStore};
/// use http::HeaderValue;
/// use url::Url;
///
/// let jar = Jar::new();
/// let url = Url::parse("https://example.com/").unwrap();
/// let set_cookie = HeaderValue::from_static("session=abc123");
/// jar.store(&url, &mut std::iter::once(&set_cookie));
///
/// // Nothing is known about who is asking, so the conservative fallback applies.
/// let header = jar
///     .cookies_for(&url, &CookieContext::conservative_default())
///     .unwrap();
/// assert_eq!(header, "session=abc123");
/// ```
pub struct Jar {
    entries: RwLock<Store>,
    clock: Arc<dyn Clock>,
    limits: JarLimits,
    next_creation_seq: AtomicU64,
    next_access_seq: AtomicU64,
}

impl Jar {
    /// Creates an empty jar with the default [`JarLimits`] and the real system clock.
    pub fn new() -> Self {
        Self::with_clock_and_limits(Arc::new(SystemClock), JarLimits::default())
    }

    /// Creates an empty jar with an injected clock, so expiry can be tested without
    /// sleeping.
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::with_clock_and_limits(clock, JarLimits::default())
    }

    /// Creates an empty jar with custom capacity limits and the real system clock.
    pub fn with_limits(limits: JarLimits) -> Self {
        Self::with_clock_and_limits(Arc::new(SystemClock), limits)
    }

    /// Creates an empty jar with both an injected clock and custom capacity limits.
    pub fn with_clock_and_limits(clock: Arc<dyn Clock>, limits: JarLimits) -> Self {
        Self {
            entries: RwLock::new(Store::default()),
            clock,
            limits,
            next_creation_seq: AtomicU64::new(0),
            next_access_seq: AtomicU64::new(0),
        }
    }

    /// A snapshot of every cookie currently in the jar, suitable for persistence by the
    /// caller (chromulate itself never reads or writes it to disk).
    ///
    /// Expired cookies are left out: the jar sweeps them lazily rather than on every
    /// store, and a snapshot of cookies that are already dead is of no use to anyone.
    pub fn export(&self) -> JarSnapshot {
        let now = self.clock.now();
        let store = self.read();
        let cookies = store
            .sites
            .values()
            .flat_map(|bucket| bucket.iter())
            .filter(|entry| !entry.cookie.is_expired(now))
            .map(|entry| CookieRecord {
                name: entry.cookie.name.clone(),
                value: entry.cookie.value.clone(),
                domain: entry.cookie.domain.clone(),
                host_only: entry.cookie.host_only,
                path: entry.cookie.path.clone(),
                secure: entry.cookie.secure,
                http_only: entry.cookie.http_only,
                same_site: entry.cookie.same_site,
                partitioned: entry.cookie.partitioned,
                expires: entry.cookie.expires.map(date::system_time_to_epoch_seconds),
                creation_seq: entry.creation_seq,
                last_access_seq: entry.last_access_seq.load(Ordering::Relaxed),
            })
            .collect();
        JarSnapshot { cookies }
    }

    /// Restores cookies from a snapshot previously produced by [`Jar::export`], merging
    /// them into whatever this jar already holds.
    ///
    /// [`CookieRecord`] is a public `Deserialize` type, so a snapshot can hold things
    /// `Cookie::parse` would never have produced. What this method does and does not
    /// check about such a record is deliberately asymmetric, and the line between the two
    /// is what a record can be checked *against*.
    ///
    /// **Validated, because the record contains everything needed to judge it.** A record
    /// that is already expired against the current clock is dropped. So is one whose name
    /// or value could not go in a `Cookie` header — one of those used to take every cookie
    /// for its site down with it. So is one that breaks the promise its own name prefix
    /// makes: `Secure`, `Domain` and `Path` are all right there in the record, so a
    /// `__Host-` record carrying a `Domain` scope is self-evidently malformed and can be
    /// rejected with certainty. That check is
    /// `cookie::keeps_name_prefix_promise`, shared with `Cookie::parse`, because a prefix
    /// whose guarantee holds on only one of the two
    /// ways into the jar is not a guarantee. Each of these drops one record and leaves the
    /// rest of the snapshot to load.
    ///
    /// **Not validated, because there is nothing to check it against.** An imported record
    /// replaces an existing cookie of the same identity (name, domain, path) outright,
    /// without the `Secure`-overwrite protection [`CookieStore::store`] applies. That rule
    /// is a claim about *the request that set the cookie* — was it secure? — and a snapshot
    /// carries no record of any request. Enforcing it here would mean inventing the fact it
    /// tests. The same reasoning explains why the `__Secure-` and `__Host-` checks above
    /// cover only their cookie-state half and not their secure-origin half.
    ///
    /// The rule, in short: reject what the record proves wrong about itself, and do not
    /// pretend to check what the record cannot show. The capacity limits still apply
    /// afterwards, via the normal eviction pass.
    pub fn import(&self, snapshot: &JarSnapshot) {
        let now = self.clock.now();
        let mut store = self.write();

        for record in &snapshot.cookies {
            let expires = record.expires.map(date::epoch_seconds_to_system_time);
            if matches!(expires, Some(expiry) if expiry <= now) {
                continue;
            }
            if !is_representable(&record.name, &record.value) {
                tracing::debug!(
                    target: "chromulate_cookie",
                    name = %record.name.escape_debug(),
                    "dropped an imported cookie record that cannot be put in a Cookie header"
                );
                continue;
            }
            if !keeps_name_prefix_promise(
                &record.name,
                record.secure,
                record.host_only,
                &record.path,
            ) {
                tracing::debug!(
                    target: "chromulate_cookie",
                    name = %record.name.escape_debug(),
                    "dropped an imported cookie record that breaks its own name prefix promise"
                );
                continue;
            }

            let cookie = Cookie {
                name: record.name.clone(),
                value: record.value.clone(),
                domain: record.domain.clone(),
                host_only: record.host_only,
                path: record.path.clone(),
                secure: record.secure,
                http_only: record.http_only,
                same_site: record.same_site,
                partitioned: record.partitioned,
                expires,
            };

            // Saturating, because `creation_seq` comes from the caller and `u64::MAX`
            // would otherwise panic in a debug build and, worse, wrap the counter back to
            // zero in a release build, corrupting RFC 6265 §5.4 ordering for every cookie
            // stored afterwards.
            self.next_creation_seq
                .fetch_max(record.creation_seq.saturating_add(1), Ordering::Relaxed);
            self.next_access_seq
                .fetch_max(record.last_access_seq.saturating_add(1), Ordering::Relaxed);

            let site = domain::site_of(&cookie.domain).to_owned();
            let entry = Entry {
                cookie,
                creation_seq: record.creation_seq,
                last_access_seq: AtomicU64::new(record.last_access_seq),
            };
            store.with_site(&site, |bucket| {
                let existing = bucket.position_of(
                    &entry.cookie.name,
                    &entry.cookie.domain,
                    &entry.cookie.path,
                );
                if let Some(position) = existing {
                    bucket.remove(position);
                }
                bucket.push(entry);
            });
        }

        store.tidy_every_site(now, self.limits.per_domain);
        store.enforce_total(now, self.limits.total, self.limits.purge_target());
    }

    /// Recovers the read lock even if a prior holder panicked: a panic elsewhere does
    /// not corrupt cookie state, so poisoning every later call would only make things
    /// worse.
    fn read(&self) -> RwLockReadGuard<'_, Store> {
        self.entries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// See [`Jar::read`]; the write-lock equivalent.
    fn write(&self) -> RwLockWriteGuard<'_, Store> {
        self.entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for Jar {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Jar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.read().total;
        f.debug_struct("Jar")
            .field("cookie_count", &count)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl CookieStore for Jar {
    fn cookies_for(&self, url: &Url, context: &CookieContext) -> Option<HeaderValue> {
        let origin = Origin::of(url).ok()?;
        let host = origin.host();
        let request_path = url.path();
        let request_is_secure = origin.is_secure();
        let now = self.clock.now();

        let site = domain::site_of(host);
        let store = self.read();
        let bucket = store.sites.get(site)?;

        let mut matches: Vec<&Entry> = bucket
            .iter()
            .filter(|entry| !entry.cookie.is_expired(now))
            .filter(|entry| {
                entry
                    .cookie
                    .applies_to(host, request_path, request_is_secure)
            })
            .filter(|entry| entry.cookie.same_site_eligible(host, context))
            .collect();

        if matches.is_empty() {
            return None;
        }

        // RFC 6265 §5.4: longer paths first; ties broken by earlier creation first.
        matches.sort_by(|a, b| {
            b.cookie
                .path
                .len()
                .cmp(&a.cookie.path.len())
                .then(a.creation_seq.cmp(&b.creation_seq))
        });

        // Every cookie returned here was accessed at the same moment, so they all get
        // the same access rank - one atomic add for the whole batch, not one per cookie.
        // Ranking them relative to each other by list position would fabricate a
        // recency difference between cookies that were, in fact, read together.
        let access_seq = self.next_access_seq.fetch_add(1, Ordering::Relaxed);
        for entry in &matches {
            entry.last_access_seq.store(access_seq, Ordering::Relaxed);
        }

        let join = |entries: &[&Entry]| {
            entries
                .iter()
                .map(|entry| format!("{}={}", entry.cookie.name, entry.cookie.value))
                .collect::<Vec<_>>()
                .join("; ")
        };

        match HeaderValue::from_str(&join(&matches)) {
            Ok(header) => Some(header),
            Err(_) => {
                // Every route into the jar rejects a cookie that cannot go in a header -
                // `Cookie::parse` through `HeaderValue::to_str`, `Jar::import` through
                // `is_representable` - so this should be unreachable. Should one ever get
                // in anyway, drop that cookie rather than every cookie for the site: a
                // whole site silently losing its cookies is a miserable thing to debug.
                tracing::debug!(
                    target: "chromulate_cookie",
                    site,
                    "a stored cookie could not be represented in a Cookie header"
                );
                matches.retain(|entry| is_representable(&entry.cookie.name, &entry.cookie.value));
                if matches.is_empty() {
                    return None;
                }
                HeaderValue::from_str(&join(&matches)).ok()
            }
        }
    }

    fn store(&self, url: &Url, set_cookie: &mut dyn Iterator<Item = &HeaderValue>) {
        let Ok(origin) = Origin::of(url) else {
            return;
        };
        let host = origin.host();
        let request_path = url.path();
        let request_is_secure = origin.is_secure();
        let now = self.clock.now();

        let mut store = self.write();
        // Every cookie in one response scopes to the request host or a parent domain of
        // it, so they all land in the registrable domain's single bucket. This is still
        // written as a set, because relying on that silently would be the kind of
        // assumption that stops holding without anyone noticing.
        let mut touched: Vec<String> = Vec::new();

        for header in set_cookie {
            let Some(cookie) = Cookie::parse(header, host, request_path, request_is_secure, now)
            else {
                tracing::debug!(
                    target: "chromulate_cookie",
                    host,
                    "rejected a malformed or ineligible Set-Cookie header"
                );
                continue;
            };

            let site = domain::site_of(&cookie.domain);
            let site = match touched.iter().position(|seen| seen == site) {
                Some(position) => position,
                None => {
                    touched.push(site.to_owned());
                    touched.len() - 1
                }
            };

            let per_domain = self.limits.per_domain;
            store.with_site(&touched[site], |bucket| {
                apply_set_cookie(
                    bucket,
                    cookie,
                    now,
                    request_is_secure,
                    &self.next_creation_seq,
                    &self.next_access_seq,
                );

                // Hold the bucket down while the response is still being applied, so a
                // hostile response carrying thousands of `Set-Cookie` headers cannot grow
                // it without bound. Trimming in one pass at twice the cap, rather than on
                // every insert past it, keeps the cost per cookie constant.
                //
                // This trim and `Bucket::position_of`'s index are load-bearing together:
                // the linearity test stays green if either is reverted alone and only
                // fails when both are, so do not take a passing suite as permission to
                // drop this. See the note on `Bucket::position_of`.
                if bucket.len() > per_domain.saturating_mul(2) {
                    bucket.remove_expired(now);
                    bucket.trim_to(per_domain);
                }
            });
        }

        // Tidying a bucket rescans it, so it runs only when the bucket has
        // actually outgrown its cap, and then trims one purge batch below the
        // cap — expired cookies first, since `remove_expired` runs ahead of
        // the trim — so the next batch of stores into the same bucket does
        // not rescan it. An under-cap bucket keeps any expired cookies until
        // it fills; lookups already filter them and the global purge ranks
        // them first.
        for site in &touched {
            let per_domain = self.limits.per_domain;
            let trim_target = self.limits.domain_purge_target();
            store.with_site(site, |bucket| {
                if bucket.len() > per_domain {
                    bucket.remove_expired(now);
                    bucket.trim_to(trim_target);
                }
            });
        }
        store.enforce_total(now, self.limits.total, self.limits.purge_target());
    }
}

/// Applies one parsed `Set-Cookie` to `bucket`.
///
/// An already-expired cookie (`Max-Age=0`, or an `Expires` in the past) is a deletion;
/// anything else inserts the cookie, or replaces the entry with the same (name, domain,
/// path) identity per RFC 6265 §5.3 while keeping that entry's original creation order.
///
/// Both routes go through the one "Leave Secure Cookies Alone" check below, because when
/// that check lived only on the overwrite path a plaintext response could still delete a
/// `Secure` cookie by sending `Max-Age=0` — the guard has to sit where every path to a
/// stored entry passes through it, not on each path separately.
fn apply_set_cookie(
    bucket: &mut Bucket,
    cookie: Cookie,
    now: SystemTime,
    request_is_secure: bool,
    next_creation_seq: &AtomicU64,
    next_access_seq: &AtomicU64,
) {
    let existing = bucket.position_of(&cookie.name, &cookie.domain, &cookie.path);

    if let Some(position) = existing {
        // A `Secure` cookie was set over HTTPS and is out of a plaintext response's reach
        // entirely. An attacker who can inject into cleartext must not be able to evict a
        // secure session cookie any more than they can overwrite it.
        let is_secure_cookie = bucket
            .get(position)
            .is_some_and(|entry| entry.cookie.secure);
        if is_secure_cookie && !request_is_secure {
            return;
        }
    }

    if cookie.is_expired(now) {
        if let Some(position) = existing {
            bucket.remove(position);
        }
        return;
    }

    match existing {
        Some(position) => {
            let creation_seq = bucket.get(position).map_or(0, |entry| entry.creation_seq);
            bucket.replace(
                position,
                Entry {
                    cookie,
                    creation_seq,
                    last_access_seq: AtomicU64::new(
                        next_access_seq.fetch_add(1, Ordering::Relaxed),
                    ),
                },
            );
        }
        None => bucket.push(Entry {
            cookie,
            creation_seq: next_creation_seq.fetch_add(1, Ordering::Relaxed),
            last_access_seq: AtomicU64::new(next_access_seq.fetch_add(1, Ordering::Relaxed)),
        }),
    }
}

/// Whether a cookie name and value can be put in a `Cookie` request header without
/// corrupting it.
///
/// `Cookie::parse` gets this for free: a `Set-Cookie` header value is already restricted
/// to visible ASCII, and the parser splits on `;` and then on the first `=`. [`Jar::import`]
/// does not, because [`CookieRecord`] is a public `Deserialize` type whose fields the
/// caller fills in directly, so it checks here instead — a value containing `\r\n` used to
/// make the entire joined header unrepresentable, and a value containing `;` would smuggle
/// an extra cookie into the header.
fn is_representable(name: &str, value: &str) -> bool {
    fn header_safe(text: &str) -> bool {
        text.bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    }

    !name.is_empty()
        && header_safe(name)
        && header_safe(value)
        && !name.contains([';', '='])
        && !value.contains(';')
}

/// A serialisable snapshot of one stored cookie, produced by [`Jar::export`] and
/// consumed by [`Jar::import`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieRecord {
    /// The cookie name.
    pub name: String,
    /// The cookie value.
    pub value: String,
    /// The exact host for a host-only cookie, or the `Domain` attribute value otherwise.
    pub domain: String,
    /// Whether this cookie is host-only (no `Domain` attribute was set).
    pub host_only: bool,
    /// The cookie's scoping path.
    pub path: String,
    /// Whether this cookie requires a secure origin.
    pub secure: bool,
    /// Whether this cookie is hidden from script-visible APIs (not enforced by this
    /// crate, which has no script layer; recorded for a caller that has one).
    pub http_only: bool,
    /// The cookie's `SameSite` attribute.
    pub same_site: SameSite,
    /// Whether this cookie carried the `Partitioned` attribute (CHIPS).
    pub partitioned: bool,
    /// Seconds since the Unix epoch, negative for a date before 1970. `None` for a
    /// session cookie that never expires by time.
    pub expires: Option<i64>,
    /// This cookie's position in the jar's creation order, used for RFC 6265 §5.4
    /// header ordering and preserved across a `Set-Cookie` that updates it in place.
    pub creation_seq: u64,
    /// This cookie's position in the jar's access order, used for least-recently-used
    /// eviction.
    pub last_access_seq: u64,
}

/// A point-in-time snapshot of every cookie in a [`Jar`].
///
/// Chromulate itself never reads or writes this to disk; persistence is entirely up to
/// the caller.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JarSnapshot {
    /// The snapshotted cookies, in no particular order.
    pub cookies: Vec<CookieRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64 as StdAtomicU64;
    use std::time::Duration;

    #[derive(Debug)]
    struct TestClock(StdAtomicU64);

    impl TestClock {
        fn at(seconds_since_epoch: u64) -> Arc<Self> {
            Arc::new(Self(StdAtomicU64::new(seconds_since_epoch)))
        }

        fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds, Ordering::Relaxed);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(self.0.load(Ordering::Relaxed))
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test url should parse")
    }

    fn header(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).expect("test header should be valid")
    }

    fn set(jar: &Jar, target: &str, set_cookie: &str) {
        let h = header(set_cookie);
        jar.store(&url(target), &mut std::iter::once(&h));
    }

    /// The lookup a caller that tracks no site information makes: everything below is
    /// about domain, path, `Secure`, ordering, or eviction rather than `SameSite`, so
    /// the conservative fallback is the context they all want.
    fn cookies_for_no_context(jar: &Jar, target: &Url) -> Option<HeaderValue> {
        jar.cookies_for(target, &CookieContext::conservative_default())
    }

    /// A session cookie record on `example.com`, for tests that need to hand [`Jar::import`]
    /// something a well-behaved [`Jar::export`] would never produce.
    fn record(name: &str, value: &str) -> CookieRecord {
        CookieRecord {
            name: name.into(),
            value: value.into(),
            domain: "example.com".into(),
            host_only: true,
            path: "/".into(),
            secure: false,
            http_only: false,
            same_site: SameSite::Lax,
            partitioned: false,
            expires: None,
            creation_seq: 0,
            last_access_seq: 0,
        }
    }

    /// How many stored entries the jar has examined on this thread so far.
    fn entries_examined() -> u64 {
        ENTRIES_EXAMINED.with(std::cell::Cell::get)
    }

    #[test]
    fn a_stored_cookie_is_sent_back_on_the_next_request() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "session=abc123");
        assert_eq!(
            cookies_for_no_context(&jar, &url("https://example.com/")),
            Some(HeaderValue::from_static("session=abc123"))
        );
    }

    #[test]
    fn a_cookie_is_withheld_from_an_unrelated_domain() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "session=abc123");
        assert!(cookies_for_no_context(&jar, &url("https://other.test/")).is_none());
    }

    #[test]
    fn a_longer_path_is_ordered_before_a_shorter_one() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "root=1");
        set(&jar, "https://example.com/a/b", "deep=2; Path=/a/b");
        let header = cookies_for_no_context(&jar, &url("https://example.com/a/b/c"))
            .expect("both cookies should apply");
        assert_eq!(header, "deep=2; root=1");
    }

    #[test]
    fn equal_length_paths_are_ordered_by_earlier_creation_first() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "first=1");
        set(&jar, "https://example.com/", "second=2");
        let header = cookies_for_no_context(&jar, &url("https://example.com/"))
            .expect("both cookies should apply");
        assert_eq!(header, "first=1; second=2");
    }

    #[test]
    fn a_cookie_expires_using_an_injected_clock_with_no_sleeping() {
        let clock = TestClock::at(1000);
        let jar = Jar::with_clock(clock.clone());
        set(&jar, "https://example.com/", "session=abc; Max-Age=10");

        assert!(cookies_for_no_context(&jar, &url("https://example.com/")).is_some());
        clock.advance(11);
        assert!(cookies_for_no_context(&jar, &url("https://example.com/")).is_none());
    }

    #[test]
    fn a_later_max_age_zero_deletes_a_previously_stored_cookie() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "session=abc123");
        assert!(cookies_for_no_context(&jar, &url("https://example.com/")).is_some());

        set(&jar, "https://example.com/", "session=deleted; Max-Age=0");
        assert!(cookies_for_no_context(&jar, &url("https://example.com/")).is_none());
    }

    #[test]
    fn a_secure_cookie_is_withheld_from_a_plaintext_request() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "session=abc123; Secure");
        assert!(cookies_for_no_context(&jar, &url("http://example.com/")).is_none());
        assert!(cookies_for_no_context(&jar, &url("https://example.com/")).is_some());
    }

    #[test]
    fn a_plaintext_response_may_not_overwrite_an_existing_secure_cookie() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "session=secure-value; Secure");
        set(&jar, "http://example.com/", "session=overwritten");

        let header = cookies_for_no_context(&jar, &url("https://example.com/"))
            .expect("the original secure cookie should survive");
        assert_eq!(header, "session=secure-value");
    }

    #[test]
    fn strict_cookies_turn_on_the_initiator_the_context_names() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "session=abc; SameSite=Strict");

        let cross_site = CookieContext {
            initiator: Some(Origin::of(&url("https://attacker.test/")).unwrap()),
            is_top_level_navigation: true,
        };
        assert!(
            jar.cookies_for(&url("https://example.com/"), &cross_site)
                .is_none()
        );

        let same_site = CookieContext {
            initiator: Some(Origin::of(&url("https://example.com/other")).unwrap()),
            is_top_level_navigation: false,
        };
        assert!(
            jar.cookies_for(&url("https://example.com/"), &same_site)
                .is_some()
        );
    }

    #[test]
    fn the_conservative_default_sends_lax_cookies_but_withholds_strict_ones() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "lax-cookie=abc");
        set(
            &jar,
            "https://example.com/",
            "strict-cookie=xyz; SameSite=Strict",
        );

        // The caller knows nothing about who is asking, so the fallback context decides.
        let header = cookies_for_no_context(&jar, &url("https://example.com/"))
            .expect("the default-SameSite cookie should still be sent");
        assert!(header.to_str().unwrap().contains("lax-cookie=abc"));
        assert!(!header.to_str().unwrap().contains("strict-cookie=xyz"));
    }

    #[test]
    fn a_domain_cookie_is_visible_to_a_different_subdomain() {
        let jar = Jar::new();
        set(
            &jar,
            "https://www.example.com/",
            "session=abc; Domain=example.com",
        );
        assert_eq!(
            cookies_for_no_context(&jar, &url("https://other.example.com/")),
            Some(HeaderValue::from_static("session=abc"))
        );
    }

    #[test]
    fn exceeding_the_per_domain_limit_evicts_the_least_recently_used_cookie_first() {
        let jar = Jar::with_limits(JarLimits {
            per_domain: 2,
            total: 100,
        });
        set(&jar, "https://example.com/", "a=1");
        set(&jar, "https://example.com/", "b=2");
        // The server refreshes `a`, which counts as an access and makes `b` the least
        // recently used. (A plain read would touch both at once and not distinguish
        // them - see the "shares one access timestamp" note on `cookies_for`.)
        set(&jar, "https://example.com/", "a=1");
        set(&jar, "https://example.com/", "c=3");

        let header = cookies_for_no_context(&jar, &url("https://example.com/"))
            .expect("two cookies should remain");
        assert!(header.to_str().unwrap().contains("a=1"));
        assert!(header.to_str().unwrap().contains("c=3"));
        assert!(!header.to_str().unwrap().contains("b=2"));
    }

    #[test]
    fn exceeding_the_total_limit_evicts_across_domains() {
        let jar = Jar::with_limits(JarLimits {
            per_domain: 100,
            total: 1,
        });
        set(&jar, "https://a.test/", "a=1");
        set(&jar, "https://b.test/", "b=2");

        let total: usize = jar.export().cookies.len();
        assert_eq!(total, 1);
        // The most recently stored cookie (b) survives; a was least recently used.
        assert!(cookies_for_no_context(&jar, &url("https://b.test/")).is_some());
    }

    #[test]
    fn eviction_cost_amortises_across_inserts_once_the_jar_is_full() {
        let jar = Jar::with_limits(JarLimits {
            per_domain: 1000,
            total: 100,
        });
        for i in 0..100 {
            set(&jar, &format!("https://s{i}.test/"), "c=1");
        }
        assert_eq!(
            jar.export().cookies.len(),
            100,
            "the fixture must sit at the cap"
        );

        let baseline = entries_examined();
        for i in 100..130 {
            set(&jar, &format!("https://s{i}.test/"), "c=1");
        }
        let examined = entries_examined() - baseline;

        // Evicting exactly one cookie per insert scans the whole jar every
        // time: 30 inserts examine >= 30 * 100 entries. A batched purge pays
        // one scan per batch of total/10, so the same 30 inserts examine a few
        // hundred. The threshold sits between the two regimes.
        assert!(
            examined < 1500,
            "storing 30 cookies into a full jar examined {examined} entries — eviction is not amortised"
        );
    }

    #[test]
    fn a_purge_evicts_the_least_recently_used_batch_and_keeps_the_newcomer() {
        let jar = Jar::with_limits(JarLimits {
            per_domain: 1000,
            total: 20,
        });
        for i in 0..20 {
            set(&jar, &format!("https://s{i}.test/"), "c=1");
        }
        // Refresh the first five, which counts as an access: s5 is now the
        // least recently used.
        for i in 0..5 {
            set(&jar, &format!("https://s{i}.test/"), "c=1");
        }

        set(&jar, "https://newcomer.test/", "c=1");

        // The overflow purges one batch (total / 10 = 2) below the cap: the
        // jar drops from 21 to 18, and the three evicted are the three least
        // recently used — s5, s6, s7.
        assert_eq!(jar.export().cookies.len(), 18);
        assert!(cookies_for_no_context(&jar, &url("https://newcomer.test/")).is_some());
        assert!(cookies_for_no_context(&jar, &url("https://s0.test/")).is_some());
        assert!(cookies_for_no_context(&jar, &url("https://s8.test/")).is_some());
        for evicted in 5..8 {
            assert!(
                cookies_for_no_context(&jar, &url(&format!("https://s{evicted}.test/"))).is_none(),
                "s{evicted} was among the least recently used and must be purged"
            );
        }
    }

    #[test]
    fn per_domain_eviction_cost_amortises_once_a_bucket_is_full() {
        let jar = Jar::with_limits(JarLimits {
            per_domain: 60,
            total: 100_000,
        });
        for i in 0..60 {
            set(&jar, "https://example.com/", &format!("c{i}=1"));
        }
        assert_eq!(
            jar.export().cookies.len(),
            60,
            "the bucket must sit at its cap"
        );

        let baseline = entries_examined();
        for i in 60..90 {
            set(&jar, "https://example.com/", &format!("c{i}=1"));
        }
        let examined = entries_examined() - baseline;

        // Rescanning the whole bucket on every store costs 30 inserts about
        // 30 * 2 * 60 entries. A batched purge (per_domain / 6, Chromium's
        // kDomainPurgeCookies ratio) pays one scan per 10 inserts. The
        // threshold sits between the two regimes.
        assert!(
            examined < 1200,
            "storing 30 cookies into a full bucket examined {examined} entries — per-domain eviction is not amortised"
        );
    }

    #[test]
    fn export_then_import_round_trips_a_cookie_into_a_fresh_jar() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "session=abc123; Path=/api");

        let snapshot = jar.export();
        let json = serde_json::to_string(&snapshot).expect("snapshot should serialize");
        let restored: JarSnapshot =
            serde_json::from_str(&json).expect("snapshot should deserialize");

        let other = Jar::new();
        other.import(&restored);

        assert_eq!(
            cookies_for_no_context(&other, &url("https://example.com/api/list")),
            cookies_for_no_context(&jar, &url("https://example.com/api/list")),
        );
    }

    #[test]
    fn import_drops_a_record_that_has_already_expired() {
        let clock = TestClock::at(1000);
        let jar = Jar::with_clock(clock);
        jar.import(&JarSnapshot {
            cookies: vec![CookieRecord {
                name: "session".into(),
                value: "abc".into(),
                domain: "example.com".into(),
                host_only: true,
                path: "/".into(),
                secure: false,
                http_only: false,
                same_site: SameSite::Lax,
                partitioned: false,
                expires: Some(500),
                creation_seq: 0,
                last_access_seq: 0,
            }],
        });
        assert!(cookies_for_no_context(&jar, &url("https://example.com/")).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_stores_and_reads_do_not_panic_and_leave_a_consistent_state() {
        let jar = Arc::new(Jar::with_limits(JarLimits {
            per_domain: 50,
            total: 200,
        }));
        let mut tasks = Vec::new();

        for worker in 0..8u32 {
            let jar = Arc::clone(&jar);
            tasks.push(tokio::spawn(async move {
                for i in 0..200u32 {
                    let name = format!("cookie{}", i % 20);
                    let set_cookie = header(&format!("{name}=value{worker}-{i}"));
                    let target = url("https://example.com/");
                    jar.store(&target, &mut std::iter::once(&set_cookie));
                    let _ = cookies_for_no_context(&jar, &target);
                }
            }));
        }

        for task in tasks {
            task.await.expect("worker task should not panic");
        }

        let total = jar.export().cookies.len();
        assert!(total <= 50, "per-domain cap should still hold: {total}");
    }

    // RFC 6265bis §4.1.3 cookie name prefixes.

    #[test]
    fn a_host_prefixed_cookie_carrying_a_domain_attribute_is_rejected() {
        let jar = Jar::new();
        set(
            &jar,
            "https://evil.example.com/admin",
            "__Host-session=attacker; Domain=example.com; Path=/admin; Secure",
        );

        assert!(
            cookies_for_no_context(&jar, &url("https://victim.example.com/admin/panel")).is_none(),
            "a __Host- cookie carrying Domain= must not reach a sibling subdomain"
        );
        assert!(
            cookies_for_no_context(&jar, &url("https://evil.example.com/admin")).is_none(),
            "a __Host- cookie carrying Domain= must be rejected outright, not corrected"
        );
    }

    #[test]
    fn a_host_prefixed_cookie_with_a_path_other_than_root_is_rejected() {
        let jar = Jar::new();
        set(
            &jar,
            "https://example.com/admin",
            "__Host-session=attacker; Path=/admin; Secure",
        );
        assert!(cookies_for_no_context(&jar, &url("https://example.com/admin/panel")).is_none());
    }

    #[test]
    fn a_host_prefixed_cookie_without_secure_is_rejected() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "__Host-session=attacker");
        assert!(cookies_for_no_context(&jar, &url("https://example.com/")).is_none());
    }

    #[test]
    fn a_host_prefixed_cookie_that_keeps_its_promise_is_accepted() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "__Host-session=good; Secure");
        assert_eq!(
            cookies_for_no_context(&jar, &url("https://example.com/anywhere")),
            Some(HeaderValue::from_static("__Host-session=good"))
        );
    }

    #[test]
    fn a_secure_prefixed_cookie_set_over_plaintext_is_rejected() {
        let jar = Jar::new();
        set(
            &jar,
            "http://plain.example.com/",
            "__Secure-token=attacker; Domain=example.com",
        );
        assert!(
            cookies_for_no_context(&jar, &url("http://plain.example.com/")).is_none(),
            "a __Secure- cookie must not be settable over plaintext"
        );
    }

    #[test]
    fn a_secure_prefixed_cookie_that_keeps_its_promise_is_accepted() {
        let jar = Jar::new();
        set(
            &jar,
            "https://www.example.com/",
            "__Secure-token=good; Domain=example.com; Secure",
        );
        assert_eq!(
            cookies_for_no_context(&jar, &url("https://other.example.com/")),
            Some(HeaderValue::from_static("__Secure-token=good"))
        );
    }

    #[test]
    fn a_prefix_in_a_different_case_is_still_enforced() {
        let jar = Jar::new();
        set(
            &jar,
            "https://evil.example.com/",
            "__host-session=attacker; Domain=example.com; Secure",
        );
        set(&jar, "http://plain.example.com/", "__SECURE-token=attacker");

        assert!(
            cookies_for_no_context(&jar, &url("https://victim.example.com/")).is_none(),
            "the __Host- rules apply whatever the case of the prefix"
        );
        assert!(
            cookies_for_no_context(&jar, &url("http://plain.example.com/")).is_none(),
            "the __Secure- rules apply whatever the case of the prefix"
        );
    }

    // "Leave Secure Cookies Alone" on the deletion path.

    #[test]
    fn a_plaintext_response_may_not_delete_an_existing_secure_cookie() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "session=secret; Secure");
        set(&jar, "http://example.com/", "session=x; Max-Age=0");

        assert_eq!(
            cookies_for_no_context(&jar, &url("https://example.com/")),
            Some(HeaderValue::from_static("session=secret")),
            "a plaintext response must not be able to evict a Secure cookie either"
        );
    }

    #[test]
    fn a_secure_response_may_still_delete_a_secure_cookie() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "session=secret; Secure");
        set(&jar, "https://example.com/", "session=x; Secure; Max-Age=0");

        assert!(cookies_for_no_context(&jar, &url("https://example.com/")).is_none());
    }

    // Import robustness.

    #[test]
    fn import_of_a_record_with_a_maximal_sequence_number_does_not_overflow() {
        let jar = Jar::new();
        jar.import(&JarSnapshot {
            cookies: vec![CookieRecord {
                creation_seq: u64::MAX,
                last_access_seq: u64::MAX,
                ..record("session", "abc")
            }],
        });

        assert_eq!(
            cookies_for_no_context(&jar, &url("https://example.com/")),
            Some(HeaderValue::from_static("session=abc"))
        );
        // The jar is still usable afterwards: a wrapped sequence counter would corrupt
        // RFC 6265 §5.4 ordering for everything stored from here on.
        set(&jar, "https://example.com/", "later=1");
        assert!(cookies_for_no_context(&jar, &url("https://example.com/")).is_some());
    }

    #[test]
    fn import_will_not_load_a_record_that_breaks_its_own_name_prefix_promise() {
        // `import` builds a `Cookie` directly instead of going through `Cookie::parse`,
        // so it is a second door into the jar that the prefix rules have to cover too.
        // This record could never have been set over the wire: `__Host-` forbids a
        // `Domain` scope, requires `Path=/`, and requires `Secure`.
        let jar = Jar::new();
        jar.import(&JarSnapshot {
            cookies: vec![CookieRecord {
                name: "__Host-session".into(),
                value: "forged".into(),
                domain: "example.com".into(),
                host_only: false,
                path: "/admin".into(),
                secure: false,
                ..record("unused", "unused")
            }],
        });

        assert!(
            cookies_for_no_context(&jar, &url("http://other.example.com/admin/panel")).is_none(),
            "a forged __Host- record must not reach a sibling subdomain over plaintext"
        );
        assert!(
            cookies_for_no_context(&jar, &url("https://example.com/admin")).is_none(),
            "a record that breaks its prefix promise must be dropped, not merely scoped down"
        );
    }

    #[test]
    fn import_still_loads_a_prefixed_cookie_that_keeps_its_promise() {
        // The guard must not break the ordinary round trip: anything `export` produces
        // came through `Cookie::parse` and therefore already keeps its promise.
        let jar = Jar::new();
        set(&jar, "https://example.com/", "__Host-session=good; Secure");
        let snapshot = jar.export();
        assert_eq!(
            snapshot.cookies.len(),
            1,
            "the cookie should have been stored"
        );

        let restored = Jar::new();
        restored.import(&snapshot);
        assert_eq!(
            cookies_for_no_context(&restored, &url("https://example.com/")),
            Some(HeaderValue::from_static("__Host-session=good"))
        );
    }

    #[test]
    fn one_unrepresentable_imported_record_does_not_suppress_the_other_cookies() {
        let jar = Jar::new();
        set(&jar, "https://example.com/", "good=1");
        jar.import(&JarSnapshot {
            cookies: vec![record("poisoned", "a\r\nb")],
        });

        assert_eq!(
            cookies_for_no_context(&jar, &url("https://example.com/")),
            Some(HeaderValue::from_static("good=1")),
            "one unusable record must not take every cookie for the site with it"
        );
    }

    #[test]
    fn an_expired_cookie_is_evicted_before_a_live_one_when_the_total_cap_binds() {
        let clock = TestClock::at(1000);
        let jar = Jar::with_clock_and_limits(
            clock.clone(),
            JarLimits {
                per_domain: 180,
                total: 2,
            },
        );
        set(&jar, "https://short.test/", "a=1; Max-Age=10");
        set(&jar, "https://long.test/", "b=2");
        clock.advance(11);
        // `a` is now dead. Storing `c` puts the jar one over its cap, and the dead cookie
        // should go rather than the live one that has been there longer.
        set(&jar, "https://third.test/", "c=3");

        assert!(cookies_for_no_context(&jar, &url("https://short.test/")).is_none());
        assert!(cookies_for_no_context(&jar, &url("https://long.test/")).is_some());
        assert!(cookies_for_no_context(&jar, &url("https://third.test/")).is_some());
    }

    #[test]
    fn export_leaves_out_a_cookie_that_has_already_expired() {
        let clock = TestClock::at(1000);
        let jar = Jar::with_clock(clock.clone());
        set(&jar, "https://example.com/", "a=1; Max-Age=10");
        set(&jar, "https://other.test/", "b=2");
        clock.advance(11);

        let names: Vec<String> = jar.export().cookies.into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["b".to_owned()]);
    }

    #[test]
    fn repeated_sets_and_deletes_under_eviction_pressure_keep_one_entry_per_identity() {
        // Exercises every path that moves entries around inside a bucket - replace,
        // delete, per-domain trim, total-cap eviction - and then checks the invariant the
        // bucket's position index depends on.
        let jar = Jar::with_limits(JarLimits {
            per_domain: 8,
            total: 12,
        });
        let sites = ["https://a.test/", "https://b.test/"];

        for round in 0..400u32 {
            let site = sites[round as usize % sites.len()];
            let name = format!("cookie{}", round % 11);
            set(&jar, site, &format!("{name}=value{round}"));
            if round % 5 == 0 {
                set(&jar, site, &format!("{name}=gone; Max-Age=0"));
            }
            let _ = cookies_for_no_context(&jar, &url(site));
        }

        let snapshot = jar.export();
        assert!(
            snapshot.cookies.len() <= 12,
            "the total cap should still hold: {}",
            snapshot.cookies.len()
        );

        let mut identities: Vec<(String, String, String)> = snapshot
            .cookies
            .iter()
            .map(|entry| (entry.name.clone(), entry.domain.clone(), entry.path.clone()))
            .collect();
        identities.sort();
        let stored = identities.len();
        identities.dedup();
        assert_eq!(
            identities.len(),
            stored,
            "no identity may appear twice: a stale position index would let a second \
             copy of a cookie in, and both would then be sent"
        );
    }

    // Cost of storing, asserted as a shape rather than a wall-clock bound.

    #[test]
    fn storing_one_response_with_many_cookies_stays_linear_in_the_number_of_cookies() {
        fn work_for(count: usize) -> u64 {
            let jar = Jar::new();
            let headers: Vec<HeaderValue> = (0..count)
                .map(|index| header(&format!("cookie{index}=value")))
                .collect();
            let target = url("https://example.com/");

            let before = entries_examined();
            jar.store(&target, &mut headers.iter());
            entries_examined() - before
        }

        let small = work_for(1_000);
        let large = work_for(4_000);
        println!("one response: 1000 cookies examined {small}, 4000 examined {large}");
        assert!(
            large < small * 8,
            "four times the cookies cost {large} against {small}, which is quadratic, \
             not linear: one response with a few thousand Set-Cookie headers is then a \
             cheap denial of service"
        );
    }

    #[test]
    fn storing_a_cookie_for_each_of_many_sites_stays_linear_in_the_number_of_sites() {
        fn work_for(sites: usize) -> u64 {
            // A cap the walk never reaches, so this measures the cost of an ordinary
            // crawl rather than the cost of eviction.
            let jar = Jar::with_limits(JarLimits {
                per_domain: 180,
                total: 100_000,
            });
            let targets: Vec<Url> = (0..sites)
                .map(|index| url(&format!("https://site{index}.test/")))
                .collect();
            let set_cookie = header("session=abc");

            let before = entries_examined();
            for target in &targets {
                jar.store(target, &mut std::iter::once(&set_cookie));
            }
            entries_examined() - before
        }

        let small = work_for(1_000);
        let large = work_for(4_000);
        println!("many sites: 1000 sites examined {small}, 4000 examined {large}");
        assert!(
            large < small * 8,
            "four times the sites cost {large} against {small}: storing a cookie must \
             not cost work proportional to the size of the whole jar"
        );
    }
}
