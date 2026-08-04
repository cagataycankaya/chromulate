//! Deciding what a 3xx means, kept separate from performing the next hop.
//!
//! All of this is pure: a status, a `Location`, and the request that produced
//! them in, a decision out. That is deliberate — the rules here are the ones
//! with a history of subtle, security-relevant bugs (credentials surviving an
//! origin change, a `POST` body silently replayed to a third party), and rules
//! like that should be testable without a socket.

use chromulate_core::{Error, Origin, Result};
use http::header::{AUTHORIZATION, COOKIE, HeaderMap, PROXY_AUTHORIZATION};
use http::{HeaderValue, Method, StatusCode};
use url::Url;

/// Headers dropped when a redirect crosses an origin boundary.
///
/// Following a redirect to a different origin while still holding the first
/// origin's credentials hands them to whoever controls the second one. The
/// redirect target is chosen by the server, so this is not a hypothetical: an
/// open redirect on a trusted host becomes credential exfiltration.
pub const CREDENTIAL_HEADERS: [http::HeaderName; 3] = [AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION];

/// What the engine should do with a 3xx response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Return the response to the caller.
    Stop,
    /// Perform another hop.
    Follow(Hop),
}

/// The next request in a redirect chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hop {
    /// Where to go.
    pub(crate) url: Url,
    /// The method to use, which may differ from the previous hop's.
    pub(crate) method: Method,
    /// Whether the body must be dropped rather than replayed.
    pub(crate) drop_body: bool,
    /// Whether this hop leaves the previous origin.
    pub(crate) cross_origin: bool,
}

/// Whether a status code redirects at all.
#[must_use]
pub fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

/// The method the next hop uses, following the Fetch standard's
/// "HTTP-redirect fetch" step 11.
///
/// 301 and 302 rewrite only `POST`, which is a historical concession: the
/// standard describes it as matching what browsers already did rather than
/// what the original specification said. 303 rewrites everything except `GET`
/// and `HEAD`, which is what it was introduced for. 307 and 308 exist
/// precisely so that the method survives.
#[must_use]
pub fn method_after(status: StatusCode, method: &Method) -> Method {
    match status {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND if method == Method::POST => Method::GET,
        StatusCode::SEE_OTHER if method != Method::GET && method != Method::HEAD => Method::GET,
        _ => method.clone(),
    }
}

/// Whether two URLs are on different origins.
#[must_use]
pub fn crosses_origin(from: &Url, to: &Url) -> bool {
    match (Origin::of(from), Origin::of(to)) {
        (Ok(from), Ok(to)) => from != to,
        // An origin that cannot be computed is treated as a different one:
        // guessing "same" here would be the failure that leaks credentials.
        _ => true,
    }
}

/// Removes every header that must not survive an origin change.
pub fn strip_credentials(headers: &mut HeaderMap<HeaderValue>) {
    for name in CREDENTIAL_HEADERS {
        headers.remove(name);
    }
}

/// Resolves a `Location` against the URL that produced it.
fn resolve_location(current: &Url, location: &HeaderValue) -> Result<Url> {
    let raw = location
        .to_str()
        .map_err(|_| Error::Redirect("the Location header is not valid text".to_owned()))?;
    current.join(raw.trim()).map_err(|error| {
        Error::Redirect(format!("the Location header is not a usable URL: {error}"))
    })
}

/// Works out what to do with a response.
///
/// `hops` is the number of redirects already followed.
pub(crate) fn decide(
    status: StatusCode,
    headers: &HeaderMap<HeaderValue>,
    current: &Url,
    method: &Method,
    limit: Option<usize>,
    hops: usize,
) -> Result<Decision> {
    if !is_redirect(status) {
        return Ok(Decision::Stop);
    }
    let Some(limit) = limit else {
        return Ok(Decision::Stop);
    };
    let Some(location) = headers.get(http::header::LOCATION) else {
        // A 3xx with no Location is not a redirect anyone can follow; the
        // response body is what the caller gets.
        return Ok(Decision::Stop);
    };
    if hops >= limit {
        return Err(Error::TooManyRedirects { limit });
    }

    let url = resolve_location(current, location)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(Error::Redirect(format!(
            "refusing to follow a redirect to the `{}` scheme",
            url.scheme()
        )));
    }

    let next_method = method_after(status, method);
    let drop_body = next_method != *method;

    Ok(Decision::Follow(Hop {
        cross_origin: crosses_origin(current, &url),
        url,
        method: next_method,
        drop_body,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("a valid url")
    }

    fn location(value: &str) -> HeaderMap<HeaderValue> {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::LOCATION,
            HeaderValue::from_str(value).expect("a valid header value"),
        );
        headers
    }

    fn follow(status: u16, method: Method, from: &str, to: &str) -> Hop {
        let decision = decide(
            StatusCode::from_u16(status).expect("a valid status"),
            &location(to),
            &url(from),
            &method,
            Some(20),
            0,
        )
        .expect("the redirect must be followable");
        match decision {
            Decision::Follow(hop) => hop,
            Decision::Stop => panic!("expected a redirect to be followed"),
        }
    }

    #[test]
    fn a_post_becomes_a_get_and_loses_its_body_on_301_302_and_303() {
        for status in [301, 302, 303] {
            let hop = follow(status, Method::POST, "https://a.test/x", "/y");
            assert_eq!(hop.method, Method::GET, "status {status}");
            assert!(hop.drop_body, "status {status}");
        }
    }

    #[test]
    fn a_post_keeps_its_method_and_body_on_307_and_308() {
        for status in [307, 308] {
            let hop = follow(status, Method::POST, "https://a.test/x", "/y");
            assert_eq!(hop.method, Method::POST, "status {status}");
            assert!(!hop.drop_body, "status {status}");
        }
    }

    #[test]
    fn a_303_rewrites_every_method_except_get_and_head() {
        assert_eq!(
            method_after(StatusCode::SEE_OTHER, &Method::PUT),
            Method::GET
        );
        assert_eq!(
            method_after(StatusCode::SEE_OTHER, &Method::DELETE),
            Method::GET
        );
        assert_eq!(
            method_after(StatusCode::SEE_OTHER, &Method::GET),
            Method::GET
        );
        assert_eq!(
            method_after(StatusCode::SEE_OTHER, &Method::HEAD),
            Method::HEAD
        );
    }

    #[test]
    fn a_301_leaves_a_put_alone_even_though_it_rewrites_a_post() {
        assert_eq!(
            method_after(StatusCode::MOVED_PERMANENTLY, &Method::PUT),
            Method::PUT
        );
        assert_eq!(
            method_after(StatusCode::MOVED_PERMANENTLY, &Method::POST),
            Method::GET
        );
    }

    #[test]
    fn a_relative_location_resolves_against_the_url_that_sent_it() {
        let hop = follow(302, Method::GET, "https://a.test/one/two", "../three");
        assert_eq!(hop.url.as_str(), "https://a.test/three");
        assert!(!hop.cross_origin);
    }

    #[test]
    fn a_hop_to_another_host_is_flagged_as_cross_origin() {
        let hop = follow(302, Method::GET, "https://a.test/x", "https://b.test/y");
        assert!(hop.cross_origin);
    }

    #[test]
    fn a_port_or_scheme_change_alone_is_still_cross_origin() {
        assert!(crosses_origin(
            &url("https://a.test/x"),
            &url("https://a.test:8443/x")
        ));
        assert!(crosses_origin(
            &url("https://a.test/x"),
            &url("http://a.test/x")
        ));
        assert!(!crosses_origin(
            &url("https://a.test/x"),
            &url("https://a.test/y?q=1")
        ));
    }

    #[test]
    fn the_default_https_port_is_not_a_different_origin_from_an_implicit_one() {
        assert!(!crosses_origin(
            &url("https://a.test/x"),
            &url("https://a.test:443/y")
        ));
    }

    #[test]
    fn stripping_removes_all_three_credential_headers_and_nothing_else() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        headers.insert(COOKIE, HeaderValue::from_static("session=abc"));
        headers.insert(PROXY_AUTHORIZATION, HeaderValue::from_static("Basic zzz"));
        headers.insert(http::header::ACCEPT, HeaderValue::from_static("*/*"));

        strip_credentials(&mut headers);

        assert!(headers.get(AUTHORIZATION).is_none());
        assert!(headers.get(COOKIE).is_none());
        assert!(headers.get(PROXY_AUTHORIZATION).is_none());
        assert_eq!(
            headers.get(http::header::ACCEPT).map(|v| v.as_bytes()),
            Some(&b"*/*"[..])
        );
    }

    #[test]
    fn exhausting_the_limit_is_an_error_rather_than_a_returned_redirect() {
        let error = decide(
            StatusCode::FOUND,
            &location("/next"),
            &url("https://a.test/"),
            &Method::GET,
            Some(3),
            3,
        )
        .expect_err("the limit must be enforced");
        assert!(
            matches!(error, Error::TooManyRedirects { limit: 3 }),
            "{error:?}"
        );
    }

    #[test]
    fn a_policy_that_follows_nothing_returns_the_redirect_to_the_caller() {
        let decision = decide(
            StatusCode::FOUND,
            &location("/next"),
            &url("https://a.test/"),
            &Method::GET,
            None,
            0,
        )
        .expect("not following is not an error");
        assert_eq!(decision, Decision::Stop);
    }

    #[test]
    fn a_3xx_without_a_location_is_returned_rather_than_followed() {
        let decision = decide(
            StatusCode::FOUND,
            &HeaderMap::new(),
            &url("https://a.test/"),
            &Method::GET,
            Some(20),
            0,
        )
        .expect("a Location-less 3xx is not an error");
        assert_eq!(decision, Decision::Stop);
    }

    #[test]
    fn a_redirect_to_a_non_http_scheme_is_refused() {
        let error = decide(
            StatusCode::FOUND,
            &location("file:///etc/passwd"),
            &url("https://a.test/"),
            &Method::GET,
            Some(20),
            0,
        )
        .expect_err("only http and https may be followed");
        assert!(matches!(error, Error::Redirect(_)), "{error:?}");
    }

    #[test]
    fn a_204_is_not_a_redirect_even_though_it_carries_no_body() {
        assert!(!is_redirect(StatusCode::NO_CONTENT));
        assert!(!is_redirect(StatusCode::NOT_MODIFIED));
        assert!(!is_redirect(StatusCode::OK));
        assert!(is_redirect(StatusCode::PERMANENT_REDIRECT));
    }
}
