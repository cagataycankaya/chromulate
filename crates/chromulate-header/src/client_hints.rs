//! High-entropy client hint escalation via `Accept-CH`.
//!
//! Chrome sends the three low-entropy `Sec-CH-UA*` hints on every request,
//! but keeps the more identifying ones — architecture, exact platform
//! version, the full brand-and-version list, device model — back until a
//! server opts in with `Accept-CH`. This module implements that round trip:
//! parsing the response header, remembering which origin asked for what,
//! and letting [`crate::HeaderEngine`] consult that memory on the next
//! request.
//!
//! The Chrome 151 capture this crate is built from
//! (`chromulate-fingerprint/tests/data/chrome-151-macos.json`) never
//! exercised an `Accept-CH` round trip, so it carries no high-entropy
//! values. [`HighEntropyHints`] is therefore empty by default: the
//! escalation mechanism works, but the shipped Chrome profile has nothing
//! to escalate to until someone captures it. Supplying real values is a
//! matter of constructing a [`HighEntropyHints`] from a future, richer
//! capture and attaching it with
//! [`HeaderEngine::with_high_entropy_hints`][crate::HeaderEngine::with_high_entropy_hints].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use chromulate_core::Origin;

/// A high-entropy client hint, sent only after a server requests it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HighEntropyHint {
    /// `Sec-CH-UA-Platform-Version`.
    PlatformVersion,
    /// `Sec-CH-UA-Arch`.
    Arch,
    /// `Sec-CH-UA-Bitness`.
    Bitness,
    /// `Sec-CH-UA-Full-Version-List`.
    FullVersionList,
    /// `Sec-CH-UA-Model`.
    Model,
}

impl HighEntropyHint {
    /// Every high-entropy hint this crate models, in the order Chromulate
    /// places them once granted.
    pub(crate) const ALL_IN_EMIT_ORDER: [Self; 5] = [
        Self::PlatformVersion,
        Self::Arch,
        Self::Bitness,
        Self::Model,
        Self::FullVersionList,
    ];

    /// The lowercase wire name of the header this hint controls.
    #[must_use]
    pub const fn header_name(self) -> &'static str {
        match self {
            Self::PlatformVersion => "sec-ch-ua-platform-version",
            Self::Arch => "sec-ch-ua-arch",
            Self::Bitness => "sec-ch-ua-bitness",
            Self::FullVersionList => "sec-ch-ua-full-version-list",
            Self::Model => "sec-ch-ua-model",
        }
    }

    /// Matches a single `Accept-CH` token against the hint it names, if any.
    fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "sec-ch-ua-platform-version" => Some(Self::PlatformVersion),
            "sec-ch-ua-arch" => Some(Self::Arch),
            "sec-ch-ua-bitness" => Some(Self::Bitness),
            "sec-ch-ua-full-version-list" => Some(Self::FullVersionList),
            "sec-ch-ua-model" => Some(Self::Model),
            _ => None,
        }
    }
}

/// Parses an `Accept-CH` response header value into the hints it names.
///
/// Tokens this crate does not model — low-entropy hints, or hint names from
/// a future spec revision — are ignored rather than rejected, since a
/// server is free to ask for hints this crate has no data for.
#[must_use]
pub fn parse_accept_ch(value: &str) -> HashSet<HighEntropyHint> {
    value
        .split(',')
        .filter_map(HighEntropyHint::from_token)
        .collect()
}

/// The number of origins an [`AcceptChStore`] remembers before it starts
/// evicting the least recently used one.
///
/// This is ordinary configuration, not a captured fingerprint constant.
/// Chrome bounds the equivalent state too — client hint grants live in the
/// per-origin content settings store alongside other site data and are
/// subject to its eviction and data-lifetime rules — but Chromium exposes no
/// single origin count this crate could transcribe, so the number here is a
/// budget rather than an observation.
///
/// A grant costs 583 bytes per origin, measured over three runs of 100,000
/// origins each, so this default holds the store to roughly 6 MB: far more
/// origins than one session revisits, and still a ceiling. Pick a different
/// one with [`AcceptChStore::with_limits`].
pub const DEFAULT_ORIGIN_CAPACITY: usize = 10_000;

/// Capacity limits an [`AcceptChStore`] enforces during eviction.
///
/// The same shape `chromulate_cookie::JarLimits` uses for the same problem:
/// a bound the caller can set, with a documented default.
#[derive(Debug, Clone, Copy)]
pub struct AcceptChLimits {
    /// Maximum number of origins whose grants are remembered at once.
    pub origins: usize,
}

impl Default for AcceptChLimits {
    fn default() -> Self {
        Self {
            origins: DEFAULT_ORIGIN_CAPACITY,
        }
    }
}

/// One origin's grant, plus the bookkeeping least-recently-used eviction
/// needs.
#[derive(Debug)]
struct Grant {
    hints: HashSet<HighEntropyHint>,
    /// The key this grant currently occupies in [`AcceptChStore::by_access`].
    filed_seq: u64,
    /// Bumped by every read.
    ///
    /// An atomic rather than a plain field because [`AcceptChStore::granted_for`]
    /// takes `&self`: it runs once per request, and a `&mut self` there would
    /// put every reader behind a write lock. `chromulate_cookie::Jar` uses an
    /// atomic access sequence for exactly this reason.
    last_access_seq: AtomicU64,
}

impl Clone for Grant {
    fn clone(&self) -> Self {
        Self {
            hints: self.hints.clone(),
            filed_seq: self.filed_seq,
            last_access_seq: AtomicU64::new(self.last_access_seq.load(Ordering::Relaxed)),
        }
    }
}

/// Per-origin memory of which high-entropy hints a server has asked for.
///
/// A caller owns one of these per client, not per connection — the whole
/// point is that the *second* connection to an origin remembers what the
/// first one learned. [`crate::HeaderEngine::apply`] only ever reads it;
/// recording a grant is a separate step, run when a response carrying
/// `Accept-CH` comes back.
///
/// The store is bounded. It lives as long as the client does, one entry per
/// origin, and a server that controls a wildcard domain can mint fresh
/// subdomains that each return `Accept-CH` — so an unbounded map here is
/// memory one hostile origin can make a long-running crawler spend and never
/// give back. Past [`AcceptChLimits::origins`] the least recently used origin
/// is dropped; see [`DEFAULT_ORIGIN_CAPACITY`] for the default and
/// [`AcceptChStore::with_limits`] for setting your own. Losing a grant is not
/// a correctness failure: the origin simply stops receiving high-entropy
/// hints until its next `Accept-CH`, which is what a browser does when its
/// client hint storage is cleared.
#[derive(Debug)]
pub struct AcceptChStore {
    granted: HashMap<Origin, Grant>,
    /// Eviction index: access sequence to origin, lowest first.
    ///
    /// A key here can be stale — lower than the grant's current
    /// `last_access_seq` — because a read refreshes the grant through `&self`
    /// and cannot touch this map. [`AcceptChStore::evict`] reconciles lazily:
    /// a candidate that has been read since it was filed is re-filed under
    /// its current sequence and the next candidate is considered instead.
    by_access: BTreeMap<u64, Origin>,
    next_seq: AtomicU64,
    limits: AcceptChLimits,
}

impl Default for AcceptChStore {
    fn default() -> Self {
        Self::with_limits(AcceptChLimits::default())
    }
}

impl Clone for AcceptChStore {
    fn clone(&self) -> Self {
        Self {
            granted: self.granted.clone(),
            by_access: self.by_access.clone(),
            next_seq: AtomicU64::new(self.next_seq.load(Ordering::Relaxed)),
            limits: self.limits,
        }
    }
}

impl AcceptChStore {
    /// An empty store with the default [`AcceptChLimits`]: no origin has
    /// asked for anything yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty store with custom capacity limits.
    #[must_use]
    pub fn with_limits(limits: AcceptChLimits) -> Self {
        Self {
            granted: HashMap::new(),
            by_access: BTreeMap::new(),
            next_seq: AtomicU64::new(0),
            limits,
        }
    }

    /// The capacity limits this store enforces.
    #[must_use]
    pub fn limits(&self) -> AcceptChLimits {
        self.limits
    }

    /// How many origins currently have a grant.
    #[must_use]
    pub fn len(&self) -> usize {
        self.granted.len()
    }

    /// Whether no origin has a grant.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.granted.is_empty()
    }

    /// Forgets every grant.
    pub fn clear(&mut self) {
        self.granted.clear();
        self.by_access.clear();
    }

    /// Forgets one origin's grant, reporting whether there was one.
    pub fn forget(&mut self, origin: &Origin) -> bool {
        match self.granted.remove(origin) {
            Some(grant) => {
                self.by_access.remove(&grant.filed_seq);
                true
            }
            None => false,
        }
    }

    /// Records an `Accept-CH` response header value seen from `origin`.
    ///
    /// The value **replaces** whatever that origin was granted before rather
    /// than adding to it. RFC 8942 §3.1: "An opt-in overrides previous
    /// persisted opt-in values and SHOULD be persisted in its stead." The
    /// WICG client-hints-infrastructure algorithm sets the cached set to one
    /// built fresh from the current response, and Chromium's
    /// `ClientHints::PersistClientHints` overwrites the origin's stored
    /// dictionary wholesale with no read-then-merge.
    ///
    /// So a later `Accept-CH` that omits a hint revokes it, and an
    /// `Accept-CH` that names no hint this crate models — including an empty
    /// one — clears the origin entirely. Under the union this used to do
    /// there was no way for a server to narrow or withdraw a request, so the
    /// client kept sending a high-entropy hint after the site had stopped
    /// asking: a divergence from the browser being emulated, in the
    /// more-identifying direction.
    ///
    /// Recording an origin the store does not already hold may evict the
    /// least recently used one; see [`AcceptChLimits`].
    pub fn record(&mut self, origin: Origin, accept_ch_value: &str) {
        let hints = parse_accept_ch(accept_ch_value);
        if hints.is_empty() {
            self.forget(&origin);
            return;
        }

        let seq = self.next_seq();
        if let Some(previous) = self.granted.remove(&origin) {
            self.by_access.remove(&previous.filed_seq);
        }
        self.by_access.insert(seq, origin.clone());
        self.granted.insert(
            origin,
            Grant {
                hints,
                filed_seq: seq,
                last_access_seq: AtomicU64::new(seq),
            },
        );
        self.evict();
    }

    /// The hints `origin` is currently granted, empty if none.
    ///
    /// Reading an origin marks it as recently used, so an origin the client
    /// keeps requesting is not evicted ahead of one it has not touched since
    /// the grant was made.
    #[must_use]
    pub fn granted_for(&self, origin: &Origin) -> HashSet<HighEntropyHint> {
        match self.granted.get(origin) {
            Some(grant) => {
                grant
                    .last_access_seq
                    .store(self.next_seq(), Ordering::Relaxed);
                grant.hints.clone()
            }
            None => HashSet::new(),
        }
    }

    /// The next value in the monotonic access sequence.
    fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Drops least recently used grants until the store is within its limit.
    ///
    /// Terminates: each turn either removes a grant or re-files one under a
    /// sequence equal to its last read, and a re-filed grant cannot be
    /// re-filed twice in one pass because nothing reads the store while this
    /// runs.
    fn evict(&mut self) {
        while self.granted.len() > self.limits.origins {
            let Some((filed_seq, origin)) = self.by_access.pop_first() else {
                break;
            };
            let Some(grant) = self.granted.get_mut(&origin) else {
                continue;
            };
            let last_access = grant.last_access_seq.load(Ordering::Relaxed);
            if last_access > filed_seq {
                grant.filed_seq = last_access;
                self.by_access.insert(last_access, origin);
                continue;
            }
            self.granted.remove(&origin);
        }
    }
}

/// The high-entropy client hint values a profile can supply, if any.
///
/// See the module documentation for why this is empty by default for the
/// shipped Chrome profile.
#[derive(Debug, Clone, Default)]
pub struct HighEntropyHints {
    /// `Sec-CH-UA-Platform-Version`, such as `"15.6.0"`.
    pub platform_version: Option<String>,
    /// `Sec-CH-UA-Arch`, such as `"arm"`.
    pub arch: Option<String>,
    /// `Sec-CH-UA-Bitness`, such as `"64"`.
    pub bitness: Option<String>,
    /// `Sec-CH-UA-Full-Version-List`, the brand list with exact versions.
    pub full_version_list: Option<String>,
    /// `Sec-CH-UA-Model`, empty on desktop platforms.
    pub model: Option<String>,
}

impl HighEntropyHints {
    /// The value this profile has for `hint`, if it has one at all.
    pub(crate) fn value_for(&self, hint: HighEntropyHint) -> Option<&str> {
        match hint {
            HighEntropyHint::PlatformVersion => self.platform_version.as_deref(),
            HighEntropyHint::Arch => self.arch.as_deref(),
            HighEntropyHint::Bitness => self.bitness.as_deref(),
            HighEntropyHint::FullVersionList => self.full_version_list.as_deref(),
            HighEntropyHint::Model => self.model.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(url: &str) -> Origin {
        Origin::of(&url::Url::parse(url).expect("test url should parse"))
            .expect("test url should have an origin")
    }

    #[test]
    fn accept_ch_parsing_ignores_names_this_crate_does_not_model() {
        let hints = parse_accept_ch("Sec-CH-UA-Arch, Sec-CH-UA-Mobile, Sec-CH-UA-Bitness");
        assert_eq!(
            hints,
            HashSet::from([HighEntropyHint::Arch, HighEntropyHint::Bitness])
        );
    }

    #[test]
    fn a_store_remembers_grants_per_origin() {
        let mut store = AcceptChStore::new();
        let a = origin("https://a.example.com");
        let b = origin("https://b.example.com");

        store.record(a.clone(), "Sec-CH-UA-Arch");

        assert!(store.granted_for(&a).contains(&HighEntropyHint::Arch));
        assert!(store.granted_for(&b).is_empty());
    }

    #[test]
    fn a_later_accept_ch_replaces_the_grant_an_earlier_one_made() {
        let mut store = AcceptChStore::new();
        let target = origin("https://example.com");

        store.record(target.clone(), "Sec-CH-UA-Arch");
        store.record(target.clone(), "Sec-CH-UA-Bitness");

        assert_eq!(
            store.granted_for(&target),
            HashSet::from([HighEntropyHint::Bitness]),
            "RFC 8942 §3.1: an opt-in overrides previous persisted opt-in values"
        );
    }

    #[test]
    fn a_narrowed_accept_ch_drops_the_hint_it_omits_and_keeps_the_rest() {
        let mut store = AcceptChStore::new();
        let target = origin("https://example.com");

        store.record(target.clone(), "Sec-CH-UA-Arch, Sec-CH-UA-Bitness");
        store.record(target.clone(), "Sec-CH-UA-Bitness");

        assert_eq!(
            store.granted_for(&target),
            HashSet::from([HighEntropyHint::Bitness])
        );
    }

    #[test]
    fn an_empty_accept_ch_clears_the_origin() {
        let mut store = AcceptChStore::new();
        let target = origin("https://example.com");

        store.record(target.clone(), "Sec-CH-UA-Arch");
        store.record(target.clone(), "");

        assert!(
            store.granted_for(&target).is_empty(),
            "an empty Accept-CH clears the origin's set"
        );
    }

    #[test]
    fn an_accept_ch_naming_only_unmodelled_hints_clears_the_origin() {
        let mut store = AcceptChStore::new();
        let target = origin("https://example.com");

        store.record(target.clone(), "Sec-CH-UA-Arch");
        store.record(target.clone(), "Sec-CH-UA-Mobile");

        assert!(
            store.granted_for(&target).is_empty(),
            "the second response asked for no high-entropy hint, so none stays granted"
        );
    }

    #[test]
    fn a_store_stops_growing_once_it_is_full() {
        let mut store = AcceptChStore::new();
        let first = origin("https://first.example/");
        store.record(first.clone(), "Sec-CH-UA-Arch");

        for n in 0..(DEFAULT_ORIGIN_CAPACITY as u32) {
            store.record(origin(&format!("https://s{n}.example/")), "Sec-CH-UA-Arch");
        }

        assert!(
            store.granted_for(&first).is_empty(),
            "the oldest origin survived {DEFAULT_ORIGIN_CAPACITY} newer ones: the store has no bound"
        );
    }

    #[test]
    fn a_store_never_holds_more_origins_than_its_limit() {
        let mut store = AcceptChStore::with_limits(AcceptChLimits { origins: 3 });

        for n in 0..50u32 {
            store.record(origin(&format!("https://s{n}.example/")), "Sec-CH-UA-Arch");
            assert!(
                store.len() <= 3,
                "after {n} records the store holds {}",
                store.len()
            );
        }

        assert_eq!(store.len(), 3);
    }

    #[test]
    fn recording_past_the_limit_evicts_the_least_recently_used_origin() {
        let mut store = AcceptChStore::with_limits(AcceptChLimits { origins: 2 });
        let oldest = origin("https://oldest.example/");
        let middle = origin("https://middle.example/");
        let newest = origin("https://newest.example/");

        store.record(oldest.clone(), "Sec-CH-UA-Arch");
        store.record(middle.clone(), "Sec-CH-UA-Arch");
        store.record(newest.clone(), "Sec-CH-UA-Arch");

        assert!(store.granted_for(&oldest).is_empty());
        assert!(!store.granted_for(&middle).is_empty());
        assert!(!store.granted_for(&newest).is_empty());
    }

    #[test]
    fn reading_an_origin_protects_it_from_being_evicted_first() {
        let mut store = AcceptChStore::with_limits(AcceptChLimits { origins: 2 });
        let early = origin("https://early.example/");
        let later = origin("https://later.example/");

        store.record(early.clone(), "Sec-CH-UA-Arch");
        store.record(later.clone(), "Sec-CH-UA-Arch");

        // A request to the older origin: the grant is read but not re-recorded.
        assert!(!store.granted_for(&early).is_empty());

        store.record(origin("https://newest.example/"), "Sec-CH-UA-Arch");

        assert!(
            !store.granted_for(&early).is_empty(),
            "the origin read most recently must outlive the one nothing has touched"
        );
        assert!(store.granted_for(&later).is_empty());
    }

    #[test]
    fn a_single_origin_can_be_forgotten_without_disturbing_the_others() {
        let mut store = AcceptChStore::new();
        let target = origin("https://example.com");
        let other = origin("https://other.test");
        store.record(target.clone(), "Sec-CH-UA-Arch");
        store.record(other.clone(), "Sec-CH-UA-Arch");

        assert!(store.forget(&target));
        assert!(
            !store.forget(&target),
            "forgetting twice reports nothing to forget"
        );
        assert!(store.granted_for(&target).is_empty());
        assert!(!store.granted_for(&other).is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_store_reports_its_size_and_can_be_emptied() {
        let mut store = AcceptChStore::new();
        assert!(store.is_empty());

        store.record(origin("https://a.example"), "Sec-CH-UA-Arch");
        store.record(origin("https://b.example"), "Sec-CH-UA-Arch");
        assert_eq!(store.len(), 2);

        store.clear();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn re_recording_an_origin_does_not_grow_the_store() {
        let mut store = AcceptChStore::new();
        let target = origin("https://example.com");

        for _ in 0..100 {
            store.record(target.clone(), "Sec-CH-UA-Arch");
        }

        assert_eq!(store.len(), 1);
    }
}
