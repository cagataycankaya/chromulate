//! Computing the `Sec-Fetch-Site` header value.
//!
//! A browser tells the server how the current request relates to the page
//! that triggered it. Getting this right requires comparing *registrable
//! domains*, not raw hostnames: `a.example.com` and `b.example.com` are
//! same-site even though they are different origins, while `example.com`
//! and `example.co.uk` share no site at all despite both being a single
//! `example` label under a different public suffix. The `psl` crate is what
//! makes that distinction possible without hand-rolling a suffix list.

use std::net::IpAddr;

use chromulate_core::Origin;

/// The `Sec-Fetch-Site` value for a request, computed by comparing the
/// origin that initiated it to the origin it targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchSite {
    /// No initiator: a typed URL, a bookmark, or any other navigation with
    /// nothing to compare against.
    None,
    /// The initiator and the target are the same origin.
    SameOrigin,
    /// The initiator and the target share a scheme and a registrable
    /// domain, but are not the same origin.
    SameSite,
    /// The initiator and the target share neither an origin nor a site.
    CrossSite,
}

impl FetchSite {
    /// The wire value for the `Sec-Fetch-Site` header.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SameOrigin => "same-origin",
            Self::SameSite => "same-site",
            Self::CrossSite => "cross-site",
        }
    }

    /// Computes the value for a request to `target`, initiated by
    /// `initiator`.
    ///
    /// `initiator` is `None` for a navigation nothing else caused, such as a
    /// typed URL: the browser has no origin to compare against, so the
    /// value is [`FetchSite::None`].
    #[must_use]
    pub fn compute(initiator: Option<&Origin>, target: &Origin) -> Self {
        let Some(initiator) = initiator else {
            return Self::None;
        };
        if initiator == target {
            Self::SameOrigin
        } else if schemeful_same_site(initiator, target) {
            Self::SameSite
        } else {
            Self::CrossSite
        }
    }
}

/// Whether two origins share a scheme and a registrable domain.
///
/// Chrome has enforced *schemeful* same-site since version 89: `http://a.example.com`
/// and `https://a.example.com` are same-site by hostname but cross-site by
/// this rule, because the scheme differs too.
fn schemeful_same_site(a: &Origin, b: &Origin) -> bool {
    a.scheme() == b.scheme() && registrable_domain(a.host()) == registrable_domain(b.host())
}

/// The registrable domain (eTLD+1) of a host, or the host itself when there
/// is no registrable domain to speak of — `localhost` and literal IP
/// addresses, where same-site reduces to "identical host".
///
/// IP literals are recognised *before* the public suffix list is consulted,
/// not left to it. The PSL algorithm falls back to a wildcard rule for an
/// unknown top-level domain, so `psl::domain_str("1.2.3.4")` returns
/// `Some("3.4")` — it reads the last two dotted labels of an IPv4 address as
/// an eTLD+1. Two unrelated addresses sharing their final octets would then
/// compare as one site, and `https://1.2.3.4/` requesting `https://5.6.3.4/`
/// would be labelled `same-site` where a browser sends `cross-site`. Since
/// `Sec-Fetch-Site` exists largely so a server can treat `same-site` as a
/// CSRF signal, that is a wrong answer in the dangerous direction.
fn registrable_domain(host: &str) -> &str {
    if is_ip_literal(host) {
        return host;
    }
    psl::domain_str(host).unwrap_or(host)
}

/// Whether `host` is an IP address literal rather than a name.
///
/// `chromulate_core::Origin` keeps the brackets on an IPv6 host, so they come
/// off before parsing. IPv6 literals happen to survive the public suffix list
/// unscathed today — they contain no dots for it to split on — but they are
/// checked here too so both families answer for the same stated reason
/// instead of one of them being accidentally right.
fn is_ip_literal(host: &str) -> bool {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(url: &str) -> Origin {
        Origin::of(&url::Url::parse(url).expect("test url should parse"))
            .expect("test url should have an origin")
    }

    #[test]
    fn no_initiator_means_no_fetch_site() {
        assert_eq!(
            FetchSite::compute(None, &origin("https://example.com")),
            FetchSite::None
        );
    }

    #[test]
    fn identical_origins_are_same_origin() {
        let a = origin("https://example.com/a");
        let b = origin("https://example.com/b");
        assert_eq!(FetchSite::compute(Some(&a), &b), FetchSite::SameOrigin);
    }

    #[test]
    fn sibling_subdomains_are_same_site_not_same_origin() {
        let a = origin("https://a.example.com");
        let b = origin("https://b.example.com");
        assert_eq!(FetchSite::compute(Some(&a), &b), FetchSite::SameSite);
    }

    #[test]
    fn different_public_suffixes_are_cross_site_even_with_the_same_label() {
        let a = origin("https://example.com");
        let b = origin("https://example.co.uk");
        assert_eq!(FetchSite::compute(Some(&a), &b), FetchSite::CrossSite);
    }

    #[test]
    fn unrelated_domains_are_cross_site() {
        let a = origin("https://example.com");
        let b = origin("https://other.test");
        assert_eq!(FetchSite::compute(Some(&a), &b), FetchSite::CrossSite);
    }

    #[test]
    fn a_scheme_change_on_the_same_host_is_cross_site_under_schemeful_same_site() {
        let a = origin("http://example.com");
        let b = origin("https://example.com");
        assert_eq!(FetchSite::compute(Some(&a), &b), FetchSite::CrossSite);
    }

    #[test]
    fn two_unrelated_ipv4_literals_are_cross_site() {
        let a = origin("https://93.184.216.34/");
        let b = origin("https://10.0.216.34/");
        assert_eq!(
            FetchSite::compute(Some(&a), &b),
            FetchSite::CrossSite,
            "sharing the last two octets is not sharing a site"
        );
    }

    #[test]
    fn every_pair_of_distinct_ipv4_literals_is_cross_site() {
        let pairs = [
            ("https://8.8.8.8/", "https://1.8.8.8/"),
            ("https://1.2.3.4/", "https://5.6.3.4/"),
            ("https://127.0.0.1/", "https://10.0.0.1/"),
            ("https://192.168.1.1/", "https://172.16.1.1/"),
        ];
        for (from, to) in pairs {
            let a = origin(from);
            let b = origin(to);
            assert_eq!(
                FetchSite::compute(Some(&a), &b),
                FetchSite::CrossSite,
                "{from} -> {to}"
            );
        }
    }

    #[test]
    fn an_ipv4_literal_is_same_site_with_itself_on_another_port() {
        let a = origin("https://93.184.216.34/");
        let b = origin("https://93.184.216.34:8443/");
        assert_eq!(FetchSite::compute(Some(&a), &b), FetchSite::SameSite);
    }

    #[test]
    fn two_unrelated_ipv6_literals_are_cross_site() {
        let a = origin("https://[2001:db8::1]/");
        let b = origin("https://[2001:db8::2]/");
        assert_eq!(FetchSite::compute(Some(&a), &b), FetchSite::CrossSite);
    }

    #[test]
    fn an_ipv6_literal_is_same_site_with_itself_on_another_port() {
        let a = origin("https://[2001:db8::1]/");
        let b = origin("https://[2001:db8::1]:8443/");
        assert_eq!(FetchSite::compute(Some(&a), &b), FetchSite::SameSite);
    }

    #[test]
    fn a_single_label_host_is_same_site_only_with_itself() {
        let localhost = origin("https://localhost/");
        let other_port = origin("https://localhost:8443/");
        let intranet = origin("https://intranet/");
        assert_eq!(
            FetchSite::compute(Some(&localhost), &other_port),
            FetchSite::SameSite
        );
        assert_eq!(
            FetchSite::compute(Some(&localhost), &intranet),
            FetchSite::CrossSite
        );
    }
}
