//! Turning a host string into the name that goes in SNI.

use std::net::IpAddr;

use chromulate_core::{Error, Result};
use rustls_pki_types::{DnsName, ServerName};
use url::Host;

/// Parses a host into the name a ClientHello is addressed to.
///
/// The host is normalised the way a browser normalises it before opening a
/// connection: an internationalised name is converted to its A-label form,
/// letters are lowercased, a single trailing root dot is dropped, and a
/// bracketed IPv6 literal loses its brackets. An IP literal comes back as
/// [`ServerName::IpAddress`], which is how [`sends_sni`] knows not to send SNI
/// for it.
///
/// # Errors
///
/// Returns [`Error::Url`] when the host is empty, is not a valid domain or IP
/// literal, or converts to a domain rustls will not accept.
///
/// ```
/// use chromulate_tls::{sends_sni, server_name};
///
/// let unicode = server_name("bücher.example")?;
/// assert_eq!(format!("{unicode:?}"), r#"DnsName("xn--bcher-kva.example")"#);
/// assert!(sends_sni(&unicode));
///
/// assert!(!sends_sni(&server_name("93.184.215.14")?));
/// # Ok::<(), chromulate_core::Error>(())
/// ```
pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.is_empty() {
        return Err(Error::url("a TLS target needs a host"));
    }

    let parsed = Host::parse(trimmed).map_err(|error| {
        Error::url(format!(
            "host {host:?} is not usable as a TLS name: {error}"
        ))
    })?;

    match parsed {
        Host::Domain(domain) => {
            let name = DnsName::try_from(domain).map_err(|_| {
                Error::url(format!(
                    "host {host:?} is not a DNS name rustls will accept"
                ))
            })?;
            Ok(ServerName::DnsName(name.to_owned()))
        }
        Host::Ipv4(address) => Ok(ServerName::IpAddress(IpAddr::V4(address).into())),
        Host::Ipv6(address) => Ok(ServerName::IpAddress(IpAddr::V6(address).into())),
    }
}

/// Returns `true` when a ClientHello for this name carries the `server_name`
/// extension.
///
/// RFC 6066 section 3 forbids an IP literal in SNI, and browsers obey it, so an
/// address target is answered `false`. rustls applies the same rule internally;
/// this function exists so a caller can predict what will be sent without
/// opening a connection.
#[must_use]
pub fn sends_sni(name: &ServerName<'_>) -> bool {
    matches!(name, ServerName::DnsName(_))
}

/// Renders a name for an error message or a log line.
pub(crate) fn describe(name: &ServerName<'_>) -> String {
    match name {
        ServerName::DnsName(dns) => dns.as_ref().to_owned(),
        ServerName::IpAddress(address) => IpAddr::from(*address).to_string(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns(host: &str) -> String {
        match server_name(host).expect("host should parse") {
            ServerName::DnsName(name) => name.as_ref().to_owned(),
            other => panic!("{host:?} should be a DNS name, got {other:?}"),
        }
    }

    #[test]
    fn a_domain_becomes_a_lowercase_dns_name() {
        assert_eq!(dns("Example.COM"), "example.com");
    }

    #[test]
    fn a_unicode_domain_is_converted_to_its_a_label_form() {
        assert_eq!(dns("bücher.example"), "xn--bcher-kva.example");
        assert_eq!(dns("münchen.de"), "xn--mnchen-3ya.de");
    }

    #[test]
    fn a_trailing_root_dot_is_dropped_before_the_name_is_sent() {
        assert_eq!(dns("example.com."), "example.com");
    }

    #[test]
    fn an_ip_literal_target_does_not_send_sni() {
        for host in ["127.0.0.1", "93.184.215.14", "[::1]", "[2606:2800:21f::1]"] {
            let name = server_name(host).expect("an IP literal should parse");
            assert!(
                matches!(name, ServerName::IpAddress(_)),
                "{host:?} should parse as an address, got {name:?}"
            );
            assert!(!sends_sni(&name), "{host:?} must not be sent in SNI");
        }
    }

    #[test]
    fn a_domain_target_does_send_sni() {
        let name = server_name("example.com").expect("a domain should parse");
        assert!(sends_sni(&name));
    }

    #[test]
    fn an_unusable_host_is_rejected_rather_than_guessed_at() {
        for host in ["", ".", "exa mple.com", "http://example.com/"] {
            assert!(
                server_name(host).is_err(),
                "{host:?} should not produce a TLS name"
            );
        }
    }
}
