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
        if !over_tls || is_ip_literal(host) {
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

        self.hosts.insert(
            host,
            Policy {
                expires: now + Duration::from_secs(directive.max_age),
                include_subdomains: directive.include_subdomains,
            },
        );
        self.evict(now);
    }

    /// Whether requests to `host` must use HTTPS.
    #[must_use]
    pub fn applies_to(&self, host: &str, now: SystemTime) -> bool {
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
        // `includeSubDomains`.
        let mut rest = host.as_str();
        while let Some((_, parent)) = rest.split_once('.') {
            if parent.is_empty() {
                break;
            }
            if let Some(policy) = self.hosts.get(parent)
                && policy.include_subdomains
                && policy.expires > now
            {
                return true;
            }
            rest = parent;
        }
        false
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
