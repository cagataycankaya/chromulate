//! URL and origin helpers shared by the header, cookie, and redirect engines.

use std::fmt;

use url::Url;

use crate::error::{Error, Result};

/// A tuple origin: scheme, host, and port.
///
/// Origins compare by their normalised form, so `https://example.com` and
/// `https://example.com:443` are the same origin. Chromulate keeps the port explicit
/// rather than optional because the default depends on the scheme and re-deriving it at
/// every comparison site is where bugs live.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// Extracts the origin of a URL.
    ///
    /// Fails for URLs that have no host, such as `data:` or `mailto:`, and for schemes
    /// with no known default port.
    pub fn of(url: &Url) -> Result<Self> {
        let host = url
            .host_str()
            .ok_or_else(|| Error::url(format!("`{url}` has no host")))?;
        let scheme = url.scheme();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error::url(format!("scheme `{scheme}` has no default port")))?;

        Ok(Self {
            scheme: scheme.to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// The scheme, lowercased and without the trailing colon.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host, lowercased. IPv6 hosts keep their brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, resolved to the scheme default when the URL omitted it.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether this origin is served over a transport the platform treats as secure.
    pub fn is_secure(&self) -> bool {
        matches!(self.scheme.as_str(), "https" | "wss")
    }

    /// The serialisation a browser would send in an `Origin` header.
    pub fn ascii_serialization(&self) -> String {
        let default_port = match self.scheme.as_str() {
            "http" | "ws" => 80,
            "https" | "wss" => 443,
            _ => 0,
        };
        if self.port == default_port {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.ascii_serialization())
    }
}

/// Strips the fragment and, for cross-origin requests, the path, exactly as the default
/// `strict-origin-when-cross-origin` referrer policy requires.
///
/// Returns `None` when the referrer must be suppressed entirely, which happens when a
/// secure origin would otherwise leak into a plaintext request.
pub fn referrer_for(from: &Url, to: &Url) -> Option<String> {
    let from_origin = Origin::of(from).ok()?;
    let to_origin = Origin::of(to).ok()?;

    // Downgrades from a secure to an insecure origin send no referrer at all.
    if from_origin.is_secure() && !to_origin.is_secure() {
        return None;
    }

    if from_origin == to_origin {
        let mut url = from.clone();
        url.set_fragment(None);
        let _ = url.set_username("");
        let _ = url.set_password(None);
        Some(url.to_string())
    } else {
        Some(format!("{}/", from_origin.ascii_serialization()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test url should parse")
    }

    #[test]
    fn default_ports_are_filled_in_and_hidden_again_on_serialisation() {
        let origin = Origin::of(&url("https://Example.COM/path?q=1")).unwrap();
        assert_eq!(origin.host(), "example.com");
        assert_eq!(origin.port(), 443);
        assert_eq!(origin.ascii_serialization(), "https://example.com");
        assert!(origin.is_secure());
    }

    #[test]
    fn explicit_non_default_ports_are_kept() {
        let origin = Origin::of(&url("http://example.com:8080/")).unwrap();
        assert_eq!(origin.ascii_serialization(), "http://example.com:8080");
        assert!(!origin.is_secure());
    }

    #[test]
    fn same_origin_urls_compare_equal_regardless_of_path() {
        let a = Origin::of(&url("https://example.com/a")).unwrap();
        let b = Origin::of(&url("https://example.com:443/b?c=d#e")).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn referrer_keeps_the_path_within_an_origin() {
        let referrer = referrer_for(
            &url("https://example.com/page?q=1#frag"),
            &url("https://example.com/other"),
        );
        assert_eq!(referrer.as_deref(), Some("https://example.com/page?q=1"));
    }

    #[test]
    fn referrer_is_trimmed_to_the_origin_when_crossing_origins() {
        let referrer = referrer_for(
            &url("https://example.com/secret/path"),
            &url("https://other.test/"),
        );
        assert_eq!(referrer.as_deref(), Some("https://example.com/"));
    }

    #[test]
    fn referrer_is_suppressed_on_a_secure_to_insecure_downgrade() {
        let referrer = referrer_for(&url("https://example.com/page"), &url("http://other.test/"));
        assert_eq!(referrer, None);
    }

    #[test]
    fn urls_without_a_host_are_rejected() {
        assert!(Origin::of(&url("data:text/plain,hello")).is_err());
    }
}
