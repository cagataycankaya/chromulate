//! HTTP Strict Transport Security (RFC 6797).
//!
//! A browser that has seen `Strict-Transport-Security` from an origin never
//! speaks plaintext to it again, whatever the caller asked for. Without that,
//! this client makes a request a browser would not make — which is both an
//! observable behaviour difference and a real downgrade exposure, because the
//! plaintext request goes out before any redirect can correct it.
//!
//! Three rules from the specification are easy to get wrong and each is
//! implemented deliberately here:
//!
//! - **A header received over plaintext is ignored** (§8.1). Honouring it would
//!   let anyone who can inject into cleartext pin an origin, or clear a pin.
//! - **Host names that are IP literals are never pinned** (§8.1.1), because
//!   there is no name to attach the policy to.
//! - **`max-age=0` removes the policy** rather than refreshing it (§6.1.1), so
//!   an origin can turn HSTS off.
//! - **The name is canonicalised before anything is stored or read** (§8.1.1,
//!   §2.3), by `canonical_name`. Without it `example.com` and `example.com.`
//!   are two hosts to this store and one host to DNS, which is a downgrade
//!   anyone can ask for by spelling the name the other way.
//!
//! What none of that can do is protect the *first* request to an origin this
//! process has never visited, because the plaintext request is what teaches the
//! store. The `hsts-preload` feature adds the other half — Chromium's preload
//! list, compiled in. The `preload` module, which exists only under that feature
//! and so is deliberately not linked here, documents what it costs and where the
//! data came from. It is off by default. Callers see no difference either way:
//! [`HstsStore::applies_to`] answers the question and never says which half
//! answered it.

#[cfg(feature = "hsts-preload")]
pub mod preload;

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use url::Url;

/// How many hosts a store remembers before evicting the one expiring soonest.
///
/// Ordinary configuration rather than a captured constant. A hostile origin
/// controlling a wildcard domain can mint fresh subdomains that each return an
/// `STS` header, so an unbounded map here is memory one origin can make a
/// long-running crawler spend and never give back.
pub const DEFAULT_HOST_CAPACITY: usize = 10_000;

/// Seconds from the Unix epoch to roughly the year 4000 — far enough that no
/// process outlives it, near enough to stay inside what every platform can
/// represent.
const FAR_FUTURE_SECS: u64 = 64_000_000_000;

/// The expiry used when the requested `max-age` cannot be added to the current
/// time without overflowing.
///
/// A function rather than a `const` because `SystemTime::checked_add` cannot be
/// called in one.
fn far_future() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(FAR_FUTURE_SECS))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// One origin's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Policy {
    expires: SystemTime,
    include_subdomains: bool,
}

/// Per-host memory of which origins have demanded HTTPS.
///
/// One of these belongs to a client, not to a connection: the point is that a
/// *later* request to an origin remembers what an earlier response said.
#[derive(Debug, Clone)]
pub struct HstsStore {
    hosts: HashMap<String, Policy>,
    capacity: usize,
}

impl Default for HstsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HstsStore {
    /// An empty store with the default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_HOST_CAPACITY)
    }

    /// An empty store with a custom capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            hosts: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// How many hosts currently have a policy.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Whether no host has a policy.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Records a `Strict-Transport-Security` header value seen from `host`.
    ///
    /// `over_tls` must be whether the response that carried it arrived over
    /// HTTPS; a header from a plaintext response is discarded, per §8.1.
    pub fn record(&mut self, host: &str, value: &str, over_tls: bool, now: SystemTime) {
        if !over_tls {
            return;
        }
        // Canonicalise before the IP check as well as before the key: without it
        // `127.0.0.1.` is a name to `is_ip_literal` and takes a policy §8.1.1
        // says it must not.
        let Some(host) = canonical_name(host) else {
            return;
        };
        if is_ip_literal(host) {
            return;
        }
        let Some(directive) = parse(value) else {
            return;
        };

        let host = host.to_ascii_lowercase();
        if directive.max_age == 0 {
            self.hosts.remove(&host);
            return;
        }

        // `max-age` is server-controlled and the grammar puts no ceiling on it,
        // while `SystemTime + Duration` panics on overflow rather than
        // saturating — so a single `max-age=9223372036854775807` response took
        // the process down. The addition is checked, and a value too large to
        // represent becomes the longest one that can be: the directive is
        // asking for a policy that lasts effectively forever, and that is what
        // forever means here.
        let expires = now
            .checked_add(Duration::from_secs(directive.max_age))
            .unwrap_or_else(far_future);

        self.hosts.insert(
            host,
            Policy {
                expires,
                include_subdomains: directive.include_subdomains,
            },
        );
        self.evict(now);
    }

    /// Whether requests to `host` must use HTTPS.
    ///
    /// The answer folds together what responses have taught this store and, when
    /// the `hsts-preload` feature is on, the compiled-in preload list. Callers
    /// are not told which one answered, and do not need a second call to find
    /// out.
    #[must_use]
    pub fn applies_to(&self, host: &str, now: SystemTime) -> bool {
        let Some(host) = canonical_name(host) else {
            return false;
        };
        if is_ip_literal(host) {
            return false;
        }
        let host = host.to_ascii_lowercase();

        if let Some(policy) = self.hosts.get(&host)
            && policy.expires > now
        {
            return true;
        }

        // A parent domain's policy reaches this host only when that parent said
        // `includeSubDomains`. `canonical_name` has already established that no
        // label is empty, so every parent this yields is a real one and the walk
        // needs no guard of its own.
        let mut rest = host.as_str();
        while let Some((_, parent)) = rest.split_once('.') {
            if let Some(policy) = self.hosts.get(parent)
                && policy.include_subdomains
                && policy.expires > now
            {
                return true;
            }
            rest = parent;
        }

        // Precedence between what a response taught this store and what the
        // preload list says. Everything above is the dynamic answer; this is the
        // preloaded one, written in Chromium's order —
        // `GetDynamicSTSState(host, result) || GetStaticSTSState(host, result)`
        // in `net/http/transport_security_state.cc`, revision
        // 7be0edc636b0e7b0143e2700ecf5c8af750d09ec.
        //
        // Being honest about what that order buys: nothing observable. Moving
        // `preload_covers` above the dynamic lookups was tried as a mutation and
        // the whole suite stayed green, because `a || b` and `b || a` answer the
        // same question and this function answers a `bool`. The order is here
        // because it is the one the reference implementation uses and because it
        // is the cheaper branch second, not because a test can tell.
        //
        // What *is* observable, and what the precedence rule actually decides, is
        // that neither answer can be a *negative* that cancels the other. RFC 6797
        // §8.1 says a zero `max-age` means the UA "MUST remove its cached HSTS
        // Policy information", and `record` above does exactly that — to this
        // store. A pre-loaded list is not that cache; §12.3 describes it as
        // configured into the user agent "in a manner similar to how root CA
        // certificates are embedded in browsers 'at the factory'". So removing
        // the dynamic entry leaves the preloaded one standing and an origin
        // cannot take itself off the list with a response header. Chromium
        // arrives from the other side: `AddHSTSInternal` erases the dynamic entry
        // when `max-age` is zero rather than storing a negative one, so there is
        // never a dynamic "no" for a static "yes" to lose to.
        //
        // Two layers, and they are guarded separately. Deleting this call turns
        // `max_age_zero_cannot_take_a_host_off_the_preload_list` red and leaves
        // `max_age_zero_still_removes_a_dynamic_policy_for_a_host_that_is_not_preloaded`
        // green; stopping `record` from removing does the reverse. Both were run.
        preload_covers(&host)
    }

    /// Rewrites `url` to HTTPS when a policy demands it, reporting whether it
    /// changed anything.
    ///
    /// The port is moved from 80 to the scheme default alongside the scheme,
    /// which is what §8.3 requires: an explicit port that is not 80 is left
    /// alone, because the policy is about the scheme rather than the port.
    pub fn upgrade(&self, url: &mut Url, now: SystemTime) -> bool {
        if url.scheme() != "http" {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        if !self.applies_to(host, now) {
            return false;
        }

        let explicit_port = url.port();
        if url.set_scheme("https").is_err() {
            return false;
        }
        if explicit_port == Some(80) {
            let _ = url.set_port(None);
        }
        true
    }

    /// Drops policies until the store is within its capacity, expired ones
    /// first and then those expiring soonest.
    fn evict(&mut self, now: SystemTime) {
        if self.hosts.len() <= self.capacity {
            return;
        }
        self.hosts.retain(|_, policy| policy.expires > now);
        while self.hosts.len() > self.capacity {
            let Some(soonest) = self
                .hosts
                .iter()
                .min_by_key(|(_, policy)| policy.expires)
                .map(|(host, _)| host.clone())
            else {
                break;
            };
            self.hosts.remove(&soonest);
        }
    }
}

/// Whether the compiled-in preload list demands HTTPS for `host`.
///
/// The seam that keeps `applies_to` — and therefore every call site above it —
/// the same function in both builds. Without the feature the `preload` module
/// does not exist, the blob is not linked, and this is the `false` below.
#[cfg(feature = "hsts-preload")]
fn preload_covers(host: &str) -> bool {
    preload::covers(host)
}

/// Whether the compiled-in preload list demands HTTPS for `host`.
///
/// The default build has no preload list, so nothing is preloaded.
#[cfg(not(feature = "hsts-preload"))]
fn preload_covers(_host: &str) -> bool {
    false
}

/// The directives this crate models from an `STS` header value.
struct Directive {
    max_age: u64,
    include_subdomains: bool,
}

/// Parses a `Strict-Transport-Security` value.
///
/// Returns `None` when `max-age` is absent or unparseable, which §6.1.1 makes a
/// reason to ignore the header entirely rather than to assume a default.
fn parse(value: &str) -> Option<Directive> {
    let mut max_age = None;
    let mut include_subdomains = false;

    for token in value.split(';') {
        let token = token.trim();
        let (name, argument) = match token.split_once('=') {
            Some((name, argument)) => (name.trim(), Some(argument.trim())),
            None => (token, None),
        };

        if name.eq_ignore_ascii_case("max-age") {
            // Quoted forms are legal: `max-age="31536000"`.
            let argument = argument?.trim_matches('"');
            max_age = argument.parse::<u64>().ok();
        } else if name.eq_ignore_ascii_case("includeSubDomains") {
            include_subdomains = true;
        }
    }

    Some(Directive {
        max_age: max_age?,
        include_subdomains,
    })
}

/// `host` with its root label removed, or `None` when it is not a name at all.
///
/// Two separate corrections, both of which RFC 6797 §8.1.1 folds into "convert
/// the host to a canonicalized form" before a policy is stored or consulted, and
/// both of which Chromium gets from `TransportSecurityState::CanonicalizeHost`
/// putting the name into DNS wire form first.
///
/// **A trailing root label is dropped.** A fully qualified name may be written
/// with the empty root label present, and `url` keeps it: `http://gmail.com./`
/// arrives here as the host `gmail.com.`, which every resolver treats as
/// `gmail.com`. Matched literally it is a different string, so a preloaded host
/// is not upgraded and a learned policy is filed under a key the next request
/// misses — a downgrade available to anyone who can put one extra dot in a URL.
///
/// **Any other empty label rejects the name.** `a..app` and `.app` are names DNS
/// cannot resolve and `CanonicalizeHost` refuses; here they matter because the
/// ancestor walk drops leading labels and would reach the `app` entry *through*
/// the empty one, inventing a match for a host that never asked for one.
///
/// Case is left alone: both callers lowercase, and the preload table folds case
/// as it compares, so doing it here would only mean an allocation neither needs.
fn canonical_name(host: &str) -> Option<&str> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.split('.').any(str::is_empty) {
        return None;
    }
    Some(host)
}

/// Whether `host` is an IP address literal rather than a name.
fn is_ip_literal(host: &str) -> bool {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    fn url(text: &str) -> Url {
        Url::parse(text).expect("test url should parse")
    }

    #[test]
    fn a_header_over_tls_pins_the_host_and_upgrades_a_later_plaintext_request() {
        let mut store = HstsStore::new();
        store.record("example.com", "max-age=31536000", true, now());

        let mut target = url("http://example.com/page");
        assert!(store.upgrade(&mut target, now()));
        assert_eq!(target.as_str(), "https://example.com/page");
    }

    #[test]
    fn a_header_over_plaintext_is_ignored() {
        let mut store = HstsStore::new();
        store.record("example.com", "max-age=31536000", false, now());

        let mut target = url("http://example.com/");
        assert!(
            !store.upgrade(&mut target, now()),
            "honouring an STS header from a plaintext response would let an injector pin \
             or unpin an origin"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn max_age_zero_removes_the_policy() {
        let mut store = HstsStore::new();
        store.record("example.com", "max-age=31536000", true, now());
        store.record("example.com", "max-age=0", true, now());

        let mut target = url("http://example.com/");
        assert!(!store.upgrade(&mut target, now()));
    }

    #[test]
    fn an_expired_policy_does_not_upgrade() {
        let mut store = HstsStore::new();
        store.record("example.com", "max-age=10", true, now());

        let mut target = url("http://example.com/");
        assert!(!store.upgrade(&mut target, now() + Duration::from_secs(11)));
    }

    #[test]
    fn subdomains_are_covered_only_when_the_directive_says_so() {
        let mut bare = HstsStore::new();
        bare.record("example.com", "max-age=100", true, now());
        assert!(!bare.applies_to("api.example.com", now()));

        let mut inclusive = HstsStore::new();
        inclusive.record("example.com", "max-age=100; includeSubDomains", true, now());
        assert!(inclusive.applies_to("api.example.com", now()));
        assert!(inclusive.applies_to("deep.api.example.com", now()));
        assert!(
            !inclusive.applies_to("notexample.com", now()),
            "a suffix match is not a subdomain match"
        );
    }

    #[test]
    fn the_root_label_makes_no_difference_to_a_learned_policy() {
        // One host, two spellings. Keyed literally the store learns under
        // whichever spelling the response used and misses under the other, which
        // is a downgrade anyone can ask for by adding a dot.
        let mut learned_bare = HstsStore::new();
        learned_bare.record("example.com", "max-age=100; includeSubDomains", true, now());
        assert!(learned_bare.applies_to("example.com.", now()));
        assert!(learned_bare.applies_to("api.example.com.", now()));

        let mut learned_rooted = HstsStore::new();
        learned_rooted.record("example.com.", "max-age=100", true, now());
        assert!(learned_rooted.applies_to("example.com", now()));
        assert_eq!(learned_rooted.len(), 1, "one host, not two keys");

        // And the removal path canonicalises too, or `max-age=0` from a response
        // that spells the name the other way leaves the policy standing.
        learned_rooted.record("example.com", "max-age=0", true, now());
        assert!(!learned_rooted.applies_to("example.com.", now()));
        assert!(learned_rooted.is_empty());
    }

    #[test]
    fn a_host_with_an_empty_label_takes_and_matches_no_policy() {
        let mut store = HstsStore::new();
        store.record("a..example", "max-age=100", true, now());
        assert!(
            store.is_empty(),
            "a name DNS cannot resolve takes no policy"
        );

        let mut inclusive = HstsStore::new();
        inclusive.record("example.com", "max-age=100; includeSubDomains", true, now());
        assert!(
            !inclusive.applies_to("a..example.com", now()),
            "the walk must not reach example.com through an empty label"
        );
        assert!(
            !inclusive.applies_to(".example.com", now()),
            "nor through a leading empty label"
        );
        assert!(inclusive.applies_to("a.example.com", now()));
    }

    #[test]
    fn an_ip_literal_written_with_a_root_label_is_still_an_ip_literal() {
        let mut store = HstsStore::new();
        store.record("127.0.0.1.", "max-age=100", true, now());
        assert!(
            store.is_empty(),
            "RFC 6797 8.1.1 canonicalises before it decides the host is an address"
        );
    }

    #[test]
    fn an_ip_literal_is_never_pinned() {
        let mut store = HstsStore::new();
        store.record("127.0.0.1", "max-age=100", true, now());
        assert!(
            store.is_empty(),
            "RFC 6797 8.1.1: an IP host takes no policy"
        );

        let mut target = url("http://127.0.0.1/");
        assert!(!store.upgrade(&mut target, now()));
    }

    #[test]
    fn the_default_port_is_dropped_but_an_explicit_one_is_kept() {
        let mut store = HstsStore::new();
        store.record("example.com", "max-age=100", true, now());

        let mut plain = url("http://example.com:80/x");
        assert!(store.upgrade(&mut plain, now()));
        assert_eq!(plain.as_str(), "https://example.com/x");

        let mut odd = url("http://example.com:8080/x");
        assert!(store.upgrade(&mut odd, now()));
        assert_eq!(
            odd.as_str(),
            "https://example.com:8080/x",
            "the policy is about the scheme, not about relocating a non-default port"
        );
    }

    #[test]
    fn an_enormous_max_age_is_clamped_rather_than_overflowing() {
        // `SystemTime + Duration` panics on overflow and `max-age` has no
        // ceiling in the grammar, so this exact header took the process down
        // with one response. The value is the one an attacker would send rather
        // than a tidy round number, because that is what was reached for.
        let mut store = HstsStore::new();
        store.record("evil.example", "max-age=9223372036854775807", true, now());
        assert!(
            store.applies_to("evil.example", now()),
            "a clamped policy must still be a live policy"
        );

        let mut store = HstsStore::new();
        store.record(
            "evil.example",
            &format!("max-age={}", u64::MAX),
            true,
            now(),
        );
        assert!(store.applies_to("evil.example", now()));
    }

    #[test]
    fn a_clamped_policy_expires_in_the_future_rather_than_at_the_epoch() {
        // The failure this guards is a fallback that saturates downwards: the
        // store would hold an entry `applies_to` reads as already expired, so
        // the origin would silently lose its protection instead of gaining a
        // very long one — a downgrade produced by the overflow fix itself.
        let mut store = HstsStore::new();
        store.record(
            "evil.example",
            &format!("max-age={}", u64::MAX),
            true,
            now(),
        );
        assert!(
            store.applies_to(
                "evil.example",
                SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)
            ),
            "the clamp must land far in the future, not at the epoch"
        );
    }

    #[test]
    fn a_header_without_a_usable_max_age_is_ignored() {
        let mut store = HstsStore::new();
        for value in ["includeSubDomains", "max-age", "max-age=abc", ""] {
            store.record("example.com", value, true, now());
        }
        assert!(store.is_empty());
    }

    #[test]
    fn a_quoted_max_age_is_accepted() {
        let mut store = HstsStore::new();
        store.record("example.com", "max-age=\"100\"", true, now());
        assert!(store.applies_to("example.com", now()));
    }

    #[test]
    fn the_store_never_holds_more_hosts_than_its_capacity() {
        let mut store = HstsStore::with_capacity(4);
        for index in 0..50u32 {
            store.record(
                &format!("host{index}.example"),
                &format!("max-age={}", 100 + index),
                true,
                now(),
            );
            assert!(store.len() <= 4, "after {index} records: {}", store.len());
        }
    }

    #[test]
    fn an_https_url_is_left_alone() {
        let mut store = HstsStore::new();
        store.record("example.com", "max-age=100", true, now());
        let mut target = url("https://example.com/");
        assert!(!store.upgrade(&mut target, now()));
    }
}
