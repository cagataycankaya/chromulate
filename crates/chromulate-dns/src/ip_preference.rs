//! Which IP address family a resolver should try first.

use std::net::SocketAddr;

/// Controls how a resolver orders or filters addresses of mixed IP families.
///
/// A host commonly has both an `A` (IPv4) and an `AAAA` (IPv6) record. This decides
/// what a resolver does with that: try only one family, or offer both while choosing
/// which one a connector should attempt first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpVersionPreference {
    /// Keep only IPv4 addresses, dropping any IPv6 results.
    Ipv4Only,
    /// Keep only IPv6 addresses, dropping any IPv4 results.
    Ipv6Only,
    /// Keep every address, ordered with IPv6 first.
    ///
    /// This matches the address-family preference modern browsers apply: when a host
    /// resolves to both families, IPv6 is tried first, with IPv4 available as a
    /// fallback rather than discarded.
    #[default]
    PreferIpv6,
}

impl IpVersionPreference {
    /// Filters and orders `addrs` in place according to this preference.
    ///
    /// Ordering is stable: addresses within the same family keep the relative order
    /// the resolver returned them in, since that order can itself carry meaning (for
    /// example, a resolver may already rank addresses by observed latency).
    pub fn reorder(self, mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        match self {
            Self::Ipv4Only => {
                addrs.retain(SocketAddr::is_ipv4);
                addrs
            }
            Self::Ipv6Only => {
                addrs.retain(SocketAddr::is_ipv6);
                addrs
            }
            Self::PreferIpv6 => {
                addrs.sort_by_key(|addr| u8::from(addr.is_ipv4()));
                addrs
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from(([93, 184, 216, 34], port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::from((
            [0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946],
            port,
        ))
    }

    #[test]
    fn ipv4_only_drops_ipv6_addresses() {
        let addrs = vec![v6(443), v4(443), v6(80)];
        assert_eq!(IpVersionPreference::Ipv4Only.reorder(addrs), vec![v4(443)]);
    }

    #[test]
    fn ipv6_only_drops_ipv4_addresses() {
        let addrs = vec![v4(443), v6(443), v4(80)];
        assert_eq!(IpVersionPreference::Ipv6Only.reorder(addrs), vec![v6(443)]);
    }

    #[test]
    fn prefer_ipv6_moves_ipv6_addresses_first_while_preserving_relative_order() {
        let addrs = vec![v4(1), v4(2), v6(3), v4(4), v6(5)];
        let reordered = IpVersionPreference::PreferIpv6.reorder(addrs);
        assert_eq!(reordered, vec![v6(3), v6(5), v4(1), v4(2), v4(4)]);
    }

    #[test]
    fn the_browser_default_prefers_ipv6() {
        assert_eq!(
            IpVersionPreference::default(),
            IpVersionPreference::PreferIpv6
        );
    }
}
