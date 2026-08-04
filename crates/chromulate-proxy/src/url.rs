//! Parsing and redacted formatting of proxy URLs.

use std::fmt;

use chromulate_core::{Error, HostPort, Result};
use percent_encoding::percent_decode_str;
use url::Url;

/// The proxying protocol spoken to reach the target through a proxy.
///
/// `Socks5` and `Socks5h` differ only in who resolves the target hostname: see
/// [`ProxyScheme::client_resolves_target`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProxyScheme {
    /// Plain-text connection to the proxy, tunnelled with HTTP `CONNECT`.
    Http,
    /// Same tunnelling as [`ProxyScheme::Http`]; the scheme exists for URL
    /// compatibility with tools that use `https://` to mark a proxy meant for HTTPS
    /// targets. This crate never performs TLS to the proxy itself (see the crate docs).
    Https,
    /// SOCKS5 (RFC 1928) where the *client* resolves the target hostname before
    /// sending the address to the proxy. Resolving locally leaks the hostname to
    /// whichever resolver the client uses, which may not be the proxy's network view.
    Socks5,
    /// SOCKS5 (RFC 1928) where the *proxy* resolves the target hostname. The client
    /// sends the domain name address type and never performs its own DNS lookup for
    /// the target, avoiding a DNS leak.
    Socks5h,
}

impl ProxyScheme {
    /// Parses the scheme component of a proxy URL, case-insensitively.
    pub fn parse(scheme: &str) -> Result<Self> {
        match scheme.to_ascii_lowercase().as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "socks5" => Ok(Self::Socks5),
            "socks5h" => Ok(Self::Socks5h),
            other => Err(Error::UnsupportedScheme(other.to_string())),
        }
    }

    /// The lowercase scheme name, as it would appear in a proxy URL.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks5 => "socks5",
            Self::Socks5h => "socks5h",
        }
    }

    /// Whether this scheme requires the client to resolve the target hostname itself
    /// before contacting the proxy.
    ///
    /// Only `socks5://` resolves locally. `socks5h://` always sends the domain name to
    /// the proxy, and the HTTP `CONNECT` schemes always send the hostname in the
    /// request line and let the proxy resolve it; there is no local-resolution variant
    /// of HTTP `CONNECT` to begin with.
    pub const fn client_resolves_target(self) -> bool {
        matches!(self, Self::Socks5)
    }

    /// Whether this scheme tunnels with SOCKS5 rather than HTTP `CONNECT`.
    pub const fn is_socks5(self) -> bool {
        matches!(self, Self::Socks5 | Self::Socks5h)
    }

    const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
            Self::Socks5 | Self::Socks5h => 1080,
        }
    }
}

impl fmt::Display for ProxyScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed proxy URL: scheme, host, port, and optional credentials.
///
/// `Debug` and [`Display`](fmt::Display) never print the username or password, even
/// when credentials are present; both are manually implemented for that reason. Use
/// [`ProxyUrl::username`] and [`ProxyUrl::password`] to read the raw values.
///
/// ```
/// use chromulate_proxy::ProxyUrl;
///
/// let proxy = ProxyUrl::parse("http://user:secret@proxy.example.com:8080").unwrap();
/// assert_eq!(proxy.host(), "proxy.example.com");
/// assert!(!format!("{proxy:?}").contains("secret"));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyUrl {
    scheme: ProxyScheme,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl ProxyUrl {
    /// Parses a proxy URL of the form `scheme://[user[:pass]@]host[:port]`.
    ///
    /// Accepts the `http`, `https`, `socks5`, and `socks5h` schemes. A missing port
    /// falls back to the scheme's conventional default (80, 443, or 1080 for either
    /// SOCKS5 variant).
    pub fn parse(input: &str) -> Result<Self> {
        let url =
            Url::parse(input).map_err(|err| Error::url(format!("invalid proxy URL: {err}")))?;
        let scheme = ProxyScheme::parse(url.scheme())?;

        // `Url::host_str` returns IPv6 literals bracketed (`"[::1]"`), matching the
        // URL spec's serialization; strip the brackets so `ProxyUrl::host` follows the
        // same unbracketed convention as `HostPort::host`.
        let host = url
            .host_str()
            .ok_or_else(|| Error::url("proxy URL is missing a host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = url.port().unwrap_or_else(|| scheme.default_port());

        let username = decode_userinfo(url.username())?;
        let password = match url.password() {
            Some(raw) => Some(decode_userinfo(raw)?.unwrap_or_default()),
            None => None,
        };

        Ok(Self {
            scheme,
            host,
            port,
            username,
            password,
        })
    }

    /// The proxying protocol.
    pub const fn scheme(&self) -> ProxyScheme {
        self.scheme
    }

    /// The proxy's hostname or IP literal, without brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The proxy's port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The decoded username, if the URL carried one.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// The decoded password, if the URL carried one.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Whether this proxy was configured with a username, a password, or both.
    pub const fn has_credentials(&self) -> bool {
        self.username.is_some() || self.password.is_some()
    }

    /// The proxy address as a [`HostPort`], for use with connection APIs that take one.
    pub fn host_port(&self) -> HostPort {
        HostPort::new(self.host.clone(), self.port)
    }

    /// The value of a `Proxy-Authorization: Basic ...` header for these credentials, or
    /// `None` if no credentials are set.
    pub fn basic_auth_header_value(&self) -> Option<String> {
        if !self.has_credentials() {
            return None;
        }
        let username = self.username.as_deref().unwrap_or("");
        let password = self.password.as_deref().unwrap_or("");
        let encoded = base64_encode(format!("{username}:{password}").as_bytes());
        Some(format!("Basic {encoded}"))
    }
}

impl fmt::Display for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.scheme)?;
        if self.has_credentials() {
            write!(f, "***@")?;
        }
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyUrl")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username.as_ref().map(|_| "REDACTED"))
            .field("password", &self.password.as_ref().map(|_| "REDACTED"))
            .finish()
    }
}

/// Percent-decodes a URL userinfo component, returning `None` for an empty string.
fn decode_userinfo(raw: &str) -> Result<Option<String>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|err| Error::url(format!("proxy credentials are not valid UTF-8: {err}")))?;
    Ok(Some(decoded.into_owned()))
}

/// A tiny, dependency-local base64 encoder wrapper so the choice of `base64` crate API
/// version stays in one place.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_scheme_with_default_port() {
        let proxy = ProxyUrl::parse("http://proxy.example.com").expect("valid URL");
        assert_eq!(proxy.scheme(), ProxyScheme::Http);
        assert_eq!(proxy.host(), "proxy.example.com");
        assert_eq!(proxy.port(), 80);
        assert!(!proxy.has_credentials());
    }

    #[test]
    fn parses_https_scheme_with_explicit_port() {
        let proxy = ProxyUrl::parse("https://proxy.example.com:9443").expect("valid URL");
        assert_eq!(proxy.scheme(), ProxyScheme::Https);
        assert_eq!(proxy.port(), 9443);
    }

    #[test]
    fn parses_socks5_scheme_with_default_port() {
        let proxy = ProxyUrl::parse("socks5://127.0.0.1").expect("valid URL");
        assert_eq!(proxy.scheme(), ProxyScheme::Socks5);
        assert_eq!(proxy.port(), 1080);
        assert!(proxy.scheme().client_resolves_target());
    }

    #[test]
    fn parses_socks5h_scheme_and_marks_it_as_proxy_resolved() {
        let proxy = ProxyUrl::parse("socks5h://proxy.example.com:1080").expect("valid URL");
        assert_eq!(proxy.scheme(), ProxyScheme::Socks5h);
        assert!(!proxy.scheme().client_resolves_target());
    }

    #[test]
    fn parses_credentials_and_decodes_percent_escapes() {
        let proxy =
            ProxyUrl::parse("http://us%40er:p%40ss@proxy.example.com:8080").expect("valid URL");
        assert_eq!(proxy.username(), Some("us@er"));
        assert_eq!(proxy.password(), Some("p@ss"));
        assert!(proxy.has_credentials());
    }

    #[test]
    fn parses_password_only_credentials() {
        let proxy = ProxyUrl::parse("http://:secret@proxy.example.com").expect("valid URL");
        assert_eq!(proxy.username(), None);
        assert_eq!(proxy.password(), Some("secret"));
        assert!(proxy.has_credentials());
    }

    #[test]
    fn parses_ipv6_literal_host() {
        let proxy = ProxyUrl::parse("http://[::1]:8080").expect("valid URL");
        assert_eq!(proxy.host(), "::1");
        assert_eq!(proxy.port(), 8080);
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let err = ProxyUrl::parse("ftp://proxy.example.com").unwrap_err();
        assert!(matches!(err, Error::UnsupportedScheme(scheme) if scheme == "ftp"));
    }

    #[test]
    fn rejects_missing_host() {
        // A `data:` URL is syntactically valid but has no host component at all.
        let err = ProxyUrl::parse("data:text/plain,hello").unwrap_err();
        assert!(matches!(err, Error::UnsupportedScheme(_) | Error::Url(_)));
    }

    #[test]
    fn rejects_garbage_input() {
        let err = ProxyUrl::parse("not a url").unwrap_err();
        assert!(matches!(err, Error::Url(_)));
    }

    #[test]
    fn display_redacts_credentials() {
        let proxy =
            ProxyUrl::parse("http://alice:hunter2@proxy.example.com:3128").expect("valid URL");
        let rendered = proxy.to_string();
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("hunter2"));
        assert_eq!(rendered, "http://***@proxy.example.com:3128");
    }

    #[test]
    fn debug_redacts_credentials() {
        let proxy =
            ProxyUrl::parse("socks5://alice:hunter2@proxy.example.com:1080").expect("valid URL");
        let rendered = format!("{proxy:?}");
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn display_without_credentials_has_no_at_sign() {
        let proxy = ProxyUrl::parse("http://proxy.example.com:8080").expect("valid URL");
        assert_eq!(proxy.to_string(), "http://proxy.example.com:8080");
    }

    #[test]
    fn basic_auth_header_matches_a_known_encoding() {
        let proxy =
            ProxyUrl::parse("http://aladdin:opensesame@proxy.example.com").expect("valid URL");
        // Cross-checked against the RFC 7617 example value for "aladdin:opensesame".
        assert_eq!(
            proxy.basic_auth_header_value(),
            Some("Basic YWxhZGRpbjpvcGVuc2VzYW1l".to_string())
        );
    }

    #[test]
    fn no_credentials_means_no_basic_auth_header() {
        let proxy = ProxyUrl::parse("http://proxy.example.com").expect("valid URL");
        assert_eq!(proxy.basic_auth_header_value(), None);
    }
}
