//! Domain matching, public-suffix rejection, and the coarser same-site notion of "site"
//! that `SameSite` eligibility needs.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Whether `host` is an IP address literal rather than a domain name.
///
/// The public suffix list only makes sense for domain names; an IP address has no
/// registrable domain, and `Domain` attributes on IP-addressed responses are handled
/// as an exact-match special case instead (RFC 6265 §5.1.3).
///
/// `host` is expected in the form produced by [`chromulate_core::Origin::host`], where an
/// IPv6 literal keeps its `[...]` brackets.
pub(crate) fn is_ip_literal(host: &str) -> bool {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner.parse::<Ipv6Addr>().is_ok();
    }
    host.parse::<Ipv4Addr>().is_ok()
}

/// Whether `domain` (already lowercased, with any leading dot stripped) is itself a
/// public suffix, such as `com` or `co.uk`.
///
/// A cookie may not set a `Domain` attribute that is a bare public suffix: doing so
/// would let `evil.example` set a cookie visible to every `.com` site. `psl::domain`
/// returns `None` exactly when the input has no label to spare in front of its suffix,
/// which is the condition we want.
pub(crate) fn is_public_suffix(domain: &str) -> bool {
    psl::domain(domain.as_bytes()).is_none()
}

/// Whether a cookie whose `Domain` attribute is `cookie_domain` may be scoped to a
/// request against `host`, per RFC 6265 §5.1.3.
///
/// This is suffix matching on domain labels, not a public-suffix-aware "site"
/// comparison: `Domain=example.com` matches `host=api.example.com`, but a bare IP
/// address host never domain-matches (IP addresses have no subdomains).
pub(crate) fn domain_matches(host: &str, cookie_domain: &str) -> bool {
    if host == cookie_domain {
        return true;
    }
    if is_ip_literal(host) {
        return false;
    }
    match host.strip_suffix(cookie_domain) {
        Some(prefix) => prefix.ends_with('.'),
        None => false,
    }
}

/// The coarse "site" of a host: its registrable domain (eTLD+1), or the host itself when
/// no registrable domain applies (an IP literal, or a host with no listed public suffix,
/// such as `localhost`).
///
/// This is the notion `SameSite` eligibility uses. It is deliberately coarser than
/// [`domain_matches`]: two different subdomains of `example.com` are different cookie
/// domains but the same site.
pub(crate) fn site_of(host: &str) -> &str {
    if is_ip_literal(host) {
        return host;
    }
    psl::domain_str(host).unwrap_or(host)
}

/// Whether `a` and `b` belong to the same site.
///
/// This compares registrable domains only ("classic" same-site), not scheme as well
/// ("schemeful" same-site from the SameSite living standard). See the crate-level
/// documentation for why that simplification was made.
pub(crate) fn is_same_site(a: &str, b: &str) -> bool {
    site_of(a) == site_of(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_and_bracketed_ipv6_hosts_are_recognised_as_ip_literals() {
        assert!(is_ip_literal("127.0.0.1"));
        assert!(is_ip_literal("[::1]"));
        assert!(!is_ip_literal("example.com"));
        assert!(!is_ip_literal("1.2.3.4.example.com"));
    }

    #[test]
    fn a_bare_public_suffix_domain_is_rejected() {
        assert!(is_public_suffix("co.uk"));
        assert!(is_public_suffix("com"));
    }

    #[test]
    fn a_registrable_domain_under_a_multi_label_suffix_is_accepted() {
        assert!(!is_public_suffix("example.co.uk"));
        assert!(!is_public_suffix("example.com"));
    }

    #[test]
    fn a_domain_matches_itself_and_its_subdomains() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("api.example.com", "example.com"));
    }

    #[test]
    fn a_domain_does_not_match_an_unrelated_host_with_a_shared_suffix() {
        assert!(!domain_matches("notexample.com", "example.com"));
    }

    #[test]
    fn an_ip_literal_host_never_domain_matches_by_suffix() {
        assert!(!domain_matches("127.0.0.1", "0.0.1"));
    }

    #[test]
    fn site_of_collapses_subdomains_to_the_registrable_domain() {
        assert_eq!(site_of("api.example.co.uk"), "example.co.uk");
        assert_eq!(site_of("example.co.uk"), "example.co.uk");
    }

    #[test]
    fn site_of_falls_back_to_the_whole_host_when_there_is_no_registrable_domain() {
        assert_eq!(site_of("localhost"), "localhost");
        assert_eq!(site_of("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn is_same_site_ignores_the_subdomain() {
        assert!(is_same_site("a.example.com", "b.example.com"));
        assert!(!is_same_site("a.example.com", "a.other.test"));
    }
}
