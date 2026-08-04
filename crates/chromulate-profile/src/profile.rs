//! The `Profile` type: one browser's complete observable network identity.

use std::collections::BTreeMap;

use chromulate_core::{Error, Result};
use chromulate_fingerprint::{
    Capture, ClientHelloSpec, Http2Spec, Provenance, ja3, ja3_hash, ja4, ja4_raw,
};
use serde::{Deserialize, Serialize};

/// The operating system a profile presents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
    /// Linux.
    Linux,
    /// Android.
    Android,
    /// iOS.
    Ios,
    /// A platform this crate does not model, carrying its client hint spelling.
    Other(String),
}

impl Platform {
    /// Returns the spelling used in the `Sec-CH-UA-Platform` client hint,
    /// without the quotes the header itself carries.
    #[must_use]
    pub fn client_hint(&self) -> &str {
        match self {
            Self::MacOs => "macOS",
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::Android => "Android",
            Self::Ios => "iOS",
            Self::Other(name) => name,
        }
    }

    /// Infers the platform from a user agent string.
    ///
    /// Android is checked before Linux because an Android user agent contains
    /// both tokens.
    #[must_use]
    pub fn from_user_agent(user_agent: &str) -> Option<Self> {
        if user_agent.contains("Android") {
            Some(Self::Android)
        } else if user_agent.contains("iPhone")
            || user_agent.contains("iPad")
            || user_agent.contains("iPod")
        {
            Some(Self::Ios)
        } else if user_agent.contains("Macintosh") || user_agent.contains("Mac OS X") {
            Some(Self::MacOs)
        } else if user_agent.contains("Windows") {
            Some(Self::Windows)
        } else if user_agent.contains("Linux") || user_agent.contains("X11") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

/// One entry of the `Sec-CH-UA` brand list.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Brand {
    /// The brand name, such as `Google Chrome`.
    pub brand: String,
    /// The significant version, such as `151`.
    pub version: String,
}

impl Brand {
    /// Builds a brand entry.
    pub fn new(brand: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            brand: brand.into(),
            version: version.into(),
        }
    }
}

/// The order a profile emits request headers in.
///
/// Header order is part of what an observer sees, so it is captured rather than
/// chosen. `subresource` is `None` when the capture only recorded a navigation,
/// which is the case for the Chrome 151 capture that ships with this crate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderOrder {
    /// The order observed on a top level navigation, lowercase as sent over
    /// HTTP/2.
    pub navigate: Vec<String>,
    /// The order observed on a subresource fetch, when one was captured.
    pub subresource: Option<Vec<String>>,
}

impl HeaderOrder {
    /// Returns the order to use for a subresource fetch, falling back to the
    /// navigation order when no subresource capture exists.
    #[must_use]
    pub fn subresource_or_navigate(&self) -> &[String] {
        self.subresource.as_deref().unwrap_or(&self.navigate)
    }
}

/// A complete browser network identity.
///
/// Everything here is observable by a server: the handshake shape, the HTTP/2
/// preface, and the headers with their order. Nothing here is a preference —
/// each field is a recording of what one browser build actually sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// The short lookup name, such as `chrome`.
    pub name: String,
    /// The browser version, such as `151.0.0.0`.
    pub version: String,
    /// The platform presented.
    pub platform: Platform,
    /// The `User-Agent` header value.
    pub user_agent: String,
    /// The `Sec-CH-UA` brand list, in order.
    pub client_hint_brands: Vec<Brand>,
    /// The TLS ClientHello shape.
    pub client_hello: ClientHelloSpec,
    /// The HTTP/2 connection shape.
    pub http2: Http2Spec,
    /// The `Accept` header sent on navigations.
    pub accept: String,
    /// The `Accept-Language` header.
    pub accept_language: String,
    /// The `Accept-Encoding` header.
    pub accept_encoding: String,
    /// The request header order.
    pub header_order: HeaderOrder,
    /// Every header value observed during capture, keyed by lowercase name.
    pub observed_headers: BTreeMap<String, String>,
    /// Where the data came from, when the profile was built from a capture.
    pub provenance: Option<Provenance>,
}

impl Profile {
    /// Chrome on macOS, populated from the capture that ships with this crate.
    ///
    /// This is the only profile with captured data. See the crate docs for why
    /// there is no `firefox()` or `safari()`.
    #[must_use]
    pub fn chrome_stable() -> Self {
        crate::chrome::profile()
    }

    /// Builds a profile from a capture document.
    ///
    /// This is how a caller adds a browser this crate does not ship: record a
    /// real handshake into the capture schema and load it here. Identity fields
    /// the schema does not carry directly are derived mechanically from the
    /// captured user agent and `Sec-CH-UA` header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the document cannot be parsed, when it
    /// describes a handshake that violates a wire invariant, or when the user
    /// agent does not identify a browser and version.
    pub fn from_capture(json: &str) -> Result<Self> {
        let capture = Capture::parse(json).map_err(Error::config)?;
        Self::from_parsed_capture(&capture)
    }

    /// Builds a profile from an already parsed capture.
    ///
    /// # Errors
    ///
    /// As [`Profile::from_capture`].
    pub fn from_parsed_capture(capture: &Capture) -> Result<Self> {
        let user_agent = capture.provenance.user_agent.clone();
        let (name, version) = browser_identity(&user_agent).ok_or_else(|| {
            Error::config(format!(
                "capture user agent {user_agent:?} does not identify a browser and version"
            ))
        })?;
        let platform = Platform::from_user_agent(&user_agent).ok_or_else(|| {
            Error::config(format!(
                "capture user agent {user_agent:?} does not identify a platform"
            ))
        })?;

        let headers = &capture.http2.observed_header_values;
        let client_hint_brands = match headers.get("sec-ch-ua") {
            Some(value) => parse_brand_list(value)?,
            None => Vec::new(),
        };

        Ok(Self {
            name,
            version,
            platform,
            user_agent,
            client_hint_brands,
            client_hello: capture.client_hello().map_err(Error::config)?,
            http2: capture.http2().map_err(Error::config)?,
            accept: header(headers, "accept"),
            accept_language: header(headers, "accept-language"),
            accept_encoding: header(headers, "accept-encoding"),
            header_order: HeaderOrder {
                navigate: capture.http2.navigate_request_header_order.clone(),
                subresource: capture.http2.subresource_request_header_order.clone(),
            },
            observed_headers: headers.clone(),
            provenance: Some(capture.provenance.clone()),
        })
    }

    /// Renders the `Sec-CH-UA` header value from the brand list.
    #[must_use]
    pub fn sec_ch_ua(&self) -> String {
        render_brand_list(&self.client_hint_brands)
    }

    /// Renders the `Sec-CH-UA-Platform` header value, quotes included.
    #[must_use]
    pub fn sec_ch_ua_platform(&self) -> String {
        format!("\"{}\"", self.platform.client_hint())
    }

    /// Returns this profile as it looks on a resumed connection, which adds
    /// `pre_shared_key` to the ClientHello.
    #[must_use]
    pub fn with_session_resumption(&self) -> Self {
        let mut profile = self.clone();
        profile.client_hello = self.client_hello.with_pre_shared_key();
        profile
    }

    /// Computes the JA3 string of this profile's ClientHello.
    ///
    /// For a profile whose extension order is shuffled, this is one of the many
    /// JA3 strings it produces rather than a stable identity; [`Profile::ja4`]
    /// is the stable one.
    #[must_use]
    pub fn ja3(&self) -> String {
        ja3(&self.client_hello)
    }

    /// Computes the MD5 of this profile's JA3 string.
    #[must_use]
    pub fn ja3_hash(&self) -> String {
        ja3_hash(&self.ja3())
    }

    /// Computes the JA4 fingerprint of this profile's ClientHello.
    #[must_use]
    pub fn ja4(&self) -> String {
        ja4(&self.client_hello)
    }

    /// Computes the raw JA4 of this profile's ClientHello.
    #[must_use]
    pub fn ja4_raw(&self) -> String {
        ja4_raw(&self.client_hello)
    }

    /// Computes the Akamai HTTP/2 fingerprint of this profile.
    #[must_use]
    pub fn akamai_http2(&self) -> String {
        chromulate_fingerprint::akamai_http2(&self.http2)
    }
}

fn header(headers: &BTreeMap<String, String>, name: &str) -> String {
    headers.get(name).cloned().unwrap_or_default()
}

/// Extracts the browser name and version from a user agent.
///
/// Chromium forks are checked before Chrome because their user agents contain
/// the Chrome token as well.
fn browser_identity(user_agent: &str) -> Option<(String, String)> {
    const PRODUCTS: [(&str, &str); 5] = [
        ("Edg/", "edge"),
        ("OPR/", "opera"),
        ("Chrome/", "chrome"),
        ("Firefox/", "firefox"),
        ("Version/", "safari"),
    ];

    for (token, name) in PRODUCTS {
        if let Some(rest) = user_agent.split(token).nth(1) {
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !version.is_empty() {
                return Some((name.to_owned(), version));
            }
        }
    }
    None
}

/// Parses a `Sec-CH-UA` value into its brand list.
///
/// # Errors
///
/// Returns [`Error::Config`] when an entry is not `"brand";v="version"`.
pub fn parse_brand_list(value: &str) -> Result<Vec<Brand>> {
    let mut brands = Vec::new();
    for entry in split_outside_quotes(value) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (brand, rest) = read_quoted(entry)?;
        let rest = rest
            .trim_start()
            .strip_prefix(';')
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix("v="))
            .ok_or_else(|| {
                Error::config(format!("brand entry {entry:?} has no v= version parameter"))
            })?;
        let (version, tail) = read_quoted(rest)?;
        if !tail.trim().is_empty() {
            return Err(Error::config(format!(
                "brand entry {entry:?} has trailing text {tail:?}"
            )));
        }
        brands.push(Brand { brand, version });
    }
    Ok(brands)
}

/// Renders a brand list as a `Sec-CH-UA` value.
#[must_use]
pub fn render_brand_list(brands: &[Brand]) -> String {
    brands
        .iter()
        .map(|entry| format!("\"{}\";v=\"{}\"", entry.brand, entry.version))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Splits on commas that are not inside a quoted string, because a brand name
/// may legitimately contain a comma.
fn split_outside_quotes(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                parts.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

/// Reads a leading quoted string, returning it and the remainder.
fn read_quoted(input: &str) -> Result<(String, &str)> {
    let rest = input
        .strip_prefix('"')
        .ok_or_else(|| Error::config(format!("expected a quoted string at {input:?}")))?;
    let end = rest
        .find('"')
        .ok_or_else(|| Error::config(format!("unterminated quoted string at {input:?}")))?;
    Ok((rest[..end].to_owned(), &rest[end + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                             (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";

    #[test]
    fn the_browser_name_and_version_come_out_of_the_user_agent() {
        assert_eq!(
            browser_identity(CHROME_UA),
            Some(("chrome".to_owned(), "151.0.0.0".to_owned()))
        );
    }

    #[test]
    fn a_chromium_fork_is_not_mistaken_for_chrome() {
        let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/151.0.0.0 Edg/151.0.3179.54";
        assert_eq!(
            browser_identity(edge),
            Some(("edge".to_owned(), "151.0.3179.54".to_owned()))
        );
    }

    #[test]
    fn a_user_agent_without_a_product_version_identifies_nothing() {
        assert_eq!(browser_identity("curl"), None);
    }

    #[test]
    fn the_platform_comes_out_of_the_user_agent() {
        assert_eq!(Platform::from_user_agent(CHROME_UA), Some(Platform::MacOs));
        assert_eq!(
            Platform::from_user_agent("Mozilla/5.0 (Linux; Android 15) Chrome/151.0.0.0"),
            Some(Platform::Android),
            "an Android user agent also contains Linux"
        );
        assert_eq!(Platform::from_user_agent("curl/8.0"), None);
    }

    #[test]
    fn a_brand_list_round_trips_through_parse_and_render() {
        let value = "\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"";
        let brands = parse_brand_list(value).expect("the observed brand list must parse");

        assert_eq!(
            brands,
            vec![
                Brand::new("Not=A?Brand", "99"),
                Brand::new("Google Chrome", "151"),
                Brand::new("Chromium", "151"),
            ]
        );
        assert_eq!(render_brand_list(&brands), value);
    }

    #[test]
    fn a_brand_name_containing_a_comma_survives_the_split() {
        let value = "\"Weird, Brand\";v=\"2\"";
        let brands = parse_brand_list(value).expect("a quoted comma must not split the list");
        assert_eq!(brands, vec![Brand::new("Weird, Brand", "2")]);
        assert_eq!(render_brand_list(&brands), value);
    }

    #[test]
    fn a_brand_entry_without_a_version_is_rejected() {
        assert!(parse_brand_list("\"Google Chrome\"").is_err());
    }

    #[test]
    fn the_platform_client_hint_is_quoted_on_the_wire() {
        let profile = Profile::chrome_stable();
        assert_eq!(profile.sec_ch_ua_platform(), "\"macOS\"");
    }
}
