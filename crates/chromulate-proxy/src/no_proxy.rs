//! The `NO_PROXY` / `no_proxy` environment variable convention.

use std::net::IpAddr;

use chromulate_core::{Error, Result};

/// A set of bypass rules parsed from the `no_proxy` environment variable convention.
///
/// Supports the entries in common use across HTTP clients: comma-separated hosts, a
/// leading-dot suffix match (`.example.com` matches `example.com` and any subdomain),
/// CIDR blocks (matched against literal IP addresses only, never by resolving a
/// hostname), the literal `localhost` (matching the string `"localhost"` and any
/// loopback IP address), and `*` to bypass the proxy for everything.
///
/// ```
/// use chromulate_proxy::NoProxy;
///
/// let no_proxy = NoProxy::parse(".internal.example.com,10.0.0.0/8,localhost").unwrap();
/// assert!(no_proxy.matches("service.internal.example.com"));
/// assert!(no_proxy.matches("10.1.2.3"));
/// assert!(no_proxy.matches("127.0.0.1"));
/// assert!(!no_proxy.matches("example.com"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoProxy {
    entries: Vec<Entry>,
    match_all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Exact(String),
    Suffix(String),
    Localhost,
    Cidr(IpAddr, u8),
}

impl NoProxy {
    /// A rule set that never bypasses the proxy.
    pub const fn none() -> Self {
        Self {
            entries: Vec::new(),
            match_all: false,
        }
    }

    /// Parses a comma-separated `no_proxy` value.
    ///
    /// Returns [`Error::Config`] if a CIDR entry has an invalid network address or a
    /// prefix length out of range for its address family.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut entries = Vec::new();
        let mut match_all = false;

        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if token == "*" {
                match_all = true;
                continue;
            }
            if token.eq_ignore_ascii_case("localhost") {
                entries.push(Entry::Localhost);
                continue;
            }
            if let Some((network, prefix)) = token.split_once('/') {
                entries.push(parse_cidr(token, network, prefix)?);
                continue;
            }
            if let Some(suffix) = token.strip_prefix('.') {
                entries.push(Entry::Suffix(suffix.to_ascii_lowercase()));
                continue;
            }
            entries.push(Entry::Exact(token.to_ascii_lowercase()));
        }

        Ok(Self { entries, match_all })
    }

    /// Whether `host` should bypass the proxy.
    ///
    /// `host` may be a hostname or a literal IP address; CIDR entries only ever match
    /// literal IP addresses; a hostname is never resolved to check it against a CIDR
    /// block.
    pub fn matches(&self, host: &str) -> bool {
        if self.match_all {
            return true;
        }

        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let as_ip = host.parse::<IpAddr>().ok();

        for entry in &self.entries {
            let hit = match entry {
                Entry::Exact(exact) => host == *exact,
                Entry::Suffix(suffix) => host == *suffix || host.ends_with(&format!(".{suffix}")),
                Entry::Localhost => host == "localhost" || as_ip.is_some_and(|ip| ip.is_loopback()),
                Entry::Cidr(network, prefix) => {
                    as_ip.is_some_and(|ip| ip_in_cidr(ip, *network, *prefix))
                }
            };
            if hit {
                return true;
            }
        }

        false
    }
}

fn parse_cidr(token: &str, network: &str, prefix: &str) -> Result<Entry> {
    let ip: IpAddr = network.parse().map_err(|_| {
        Error::config(format!(
            "invalid no_proxy CIDR entry `{token}`: not an IP network"
        ))
    })?;
    let prefix: u8 = prefix.parse().map_err(|_| {
        Error::config(format!(
            "invalid no_proxy CIDR entry `{token}`: not a prefix length"
        ))
    })?;
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(Error::config(format!(
            "invalid no_proxy CIDR entry `{token}`: prefix length {prefix} exceeds {max_prefix}"
        )));
    }
    Ok(Entry::Cidr(ip, prefix))
}

fn ip_in_cidr(candidate: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (candidate, network) {
        (IpAddr::V4(candidate), IpAddr::V4(network)) => {
            let mask = mask_u32(prefix);
            u32::from(candidate) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(candidate), IpAddr::V6(network)) => {
            let mask = mask_u128(prefix);
            u128::from(candidate) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

fn mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

fn mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_host_matches_only_itself() {
        let no_proxy = NoProxy::parse("example.com").expect("valid entry");
        assert!(no_proxy.matches("example.com"));
        assert!(no_proxy.matches("EXAMPLE.COM"));
        assert!(!no_proxy.matches("api.example.com"));
    }

    #[test]
    fn leading_dot_matches_suffix_and_bare_domain() {
        let no_proxy = NoProxy::parse(".example.com").expect("valid entry");
        assert!(no_proxy.matches("example.com"));
        assert!(no_proxy.matches("api.example.com"));
        assert!(no_proxy.matches("deep.api.example.com"));
        assert!(!no_proxy.matches("notexample.com"));
    }

    #[test]
    fn cidr_block_matches_contained_ipv4_addresses_only() {
        let no_proxy = NoProxy::parse("10.0.0.0/8").expect("valid entry");
        assert!(no_proxy.matches("10.1.2.3"));
        assert!(!no_proxy.matches("11.0.0.1"));
        assert!(!no_proxy.matches("internal.example.com"));
    }

    #[test]
    fn cidr_block_matches_contained_ipv6_addresses() {
        let no_proxy = NoProxy::parse("2001:db8::/32").expect("valid entry");
        assert!(no_proxy.matches("2001:db8::1"));
        assert!(!no_proxy.matches("2001:db9::1"));
    }

    #[test]
    fn wildcard_matches_everything() {
        let no_proxy = NoProxy::parse("*").expect("valid entry");
        assert!(no_proxy.matches("anything.example"));
        assert!(no_proxy.matches("127.0.0.1"));
    }

    #[test]
    fn localhost_matches_the_name_and_loopback_addresses() {
        let no_proxy = NoProxy::parse("localhost").expect("valid entry");
        assert!(no_proxy.matches("localhost"));
        assert!(no_proxy.matches("LOCALHOST"));
        assert!(no_proxy.matches("127.0.0.1"));
        assert!(no_proxy.matches("::1"));
        assert!(!no_proxy.matches("example.com"));
    }

    #[test]
    fn empty_rule_set_matches_nothing() {
        let no_proxy = NoProxy::none();
        assert!(!no_proxy.matches("example.com"));
        assert!(!no_proxy.matches("127.0.0.1"));
    }

    #[test]
    fn combined_entries_are_all_considered() {
        let no_proxy = NoProxy::parse(" example.com , .internal.example , 192.168.0.0/16 ")
            .expect("valid entries");
        assert!(no_proxy.matches("example.com"));
        assert!(no_proxy.matches("service.internal.example"));
        assert!(no_proxy.matches("192.168.1.1"));
        assert!(!no_proxy.matches("other.example"));
    }

    #[test]
    fn rejects_cidr_entry_with_invalid_network() {
        let err = NoProxy::parse("not-an-ip/8").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn rejects_cidr_entry_with_prefix_out_of_range() {
        let err = NoProxy::parse("10.0.0.0/33").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }
}
