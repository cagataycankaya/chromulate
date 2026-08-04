//! Building one request.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use chromulate_core::{
    Body, Error, RequestOptions, Result,
    reexport::{HeaderValue, Url},
};
use http::Method;
use http::header::{HeaderMap, HeaderName};

use crate::client::ClientInner;
use crate::response::Response;

/// A request under construction.
///
/// Errors are collected rather than returned as each part is added, so a chain
/// of calls stays readable and the first failure surfaces from
/// [`RequestBuilder::send`].
pub struct RequestBuilder {
    client: Arc<ClientInner>,
    state: Result<Parts>,
}

struct Parts {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Body,
    options: RequestOptions,
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            Ok(parts) => f
                .debug_struct("RequestBuilder")
                .field("method", &parts.method)
                // The path and query are omitted: a query string routinely
                // carries tokens, and `Debug` output ends up in logs.
                .field("host", &parts.url.host_str().unwrap_or_default())
                .finish_non_exhaustive(),
            Err(error) => f
                .debug_struct("RequestBuilder")
                .field("error", &error.to_string())
                .finish_non_exhaustive(),
        }
    }
}

impl RequestBuilder {
    pub(crate) fn new(client: Arc<ClientInner>, method: Method, url: &str) -> Self {
        let state = Url::parse(url)
            .map_err(|error| Error::url(format!("`{url}` is not a URL: {error}")))
            .and_then(|url| match url.scheme() {
                "http" | "https" => Ok(url),
                other => Err(Error::UnsupportedScheme(other.to_owned())),
            })
            .map(|url| Parts {
                method,
                url,
                headers: HeaderMap::new(),
                body: Body::empty(),
                // A request made through this API is a programmatic fetch, not
                // a navigation, so it gets the `fetch()` fetch context rather
                // than the address-bar one.
                options: RequestOptions::api(),
            });

        Self { client, state }
    }

    fn with(mut self, apply: impl FnOnce(&mut Parts) -> Result<()>) -> Self {
        if let Ok(parts) = &mut self.state
            && let Err(error) = apply(parts)
        {
            self.state = Err(error);
        }
        self
    }

    /// Adds a header.
    #[must_use]
    pub fn header<N>(self, name: N, value: impl AsRef<str>) -> Self
    where
        N: TryInto<HeaderName>,
        N::Error: fmt::Display,
    {
        let value = value.as_ref().to_owned();
        self.with(move |parts| {
            let name = name
                .try_into()
                .map_err(|error| Error::builder(format!("invalid header name: {error}")))?;
            let value = HeaderValue::from_str(&value)
                .map_err(|error| Error::builder(format!("invalid header value: {error}")))?;
            parts.headers.insert(name, value);
            Ok(())
        })
    }

    /// Sets `Authorization: Basic`, encoding the credentials as RFC 7617 requires.
    ///
    /// The password is optional because the scheme allows an empty one, and the
    /// colon is always sent: `user:` and `user` are different credentials on
    /// the wire, so omitting the separator would quietly send the wrong one.
    ///
    /// The value is marked sensitive, so `HeaderMap`'s `Debug` renders it as
    /// `Sensitive` rather than putting the credential in a log line.
    #[must_use]
    pub fn basic_auth(self, username: impl AsRef<str>, password: Option<impl AsRef<str>>) -> Self {
        use base64::Engine as _;

        let raw = format!(
            "{}:{}",
            username.as_ref(),
            password.as_ref().map_or("", AsRef::as_ref)
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        self.sensitive_header(http::header::AUTHORIZATION, format!("Basic {encoded}"))
    }

    /// Sets `Authorization: Bearer`.
    ///
    /// The value is marked sensitive; see [`RequestBuilder::basic_auth`].
    #[must_use]
    pub fn bearer_auth(self, token: impl AsRef<str>) -> Self {
        self.sensitive_header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", token.as_ref()),
        )
    }

    /// Sets a header whose value must never reach a log.
    fn sensitive_header(self, name: HeaderName, value: String) -> Self {
        self.with(move |parts| {
            // The value is never quoted into the error: it is the credential.
            let mut value = HeaderValue::from_str(&value).map_err(|_| {
                Error::builder(format!(
                    "the value for `{name}` is not a valid header value"
                ))
            })?;
            value.set_sensitive(true);
            parts.headers.insert(name, value);
            Ok(())
        })
    }

    /// Adds several headers at once.
    #[must_use]
    pub fn headers(self, headers: HeaderMap) -> Self {
        self.with(move |parts| {
            for (name, value) in &headers {
                parts.headers.insert(name.clone(), value.clone());
            }
            Ok(())
        })
    }

    /// Appends query parameters, keeping any the URL already carries.
    #[must_use]
    pub fn query<K, V, I>(self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let params: Vec<(String, String)> = params
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.as_ref().to_owned()))
            .collect();
        self.with(move |parts| {
            let mut pairs = parts.url.query_pairs_mut();
            for (key, value) in params {
                pairs.append_pair(&key, &value);
            }
            drop(pairs);
            Ok(())
        })
    }

    /// Sets the request body.
    #[must_use]
    pub fn body(self, body: impl Into<Body>) -> Self {
        let body = body.into();
        self.with(move |parts| {
            parts.body = body;
            Ok(())
        })
    }

    /// Serialises `value` as JSON and sets `Content-Type: application/json`.
    #[cfg(feature = "json")]
    #[must_use]
    pub fn json<T: serde::Serialize + ?Sized>(self, value: &T) -> Self {
        let encoded = serde_json::to_vec(value);
        self.with(move |parts| {
            let encoded = encoded.map_err(|error| {
                Error::builder(format!("the body is not serialisable: {error}"))
            })?;
            parts.headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            parts.body = Body::fixed(encoded);
            Ok(())
        })
    }

    /// Serialises `value` as a URL-encoded form body.
    #[cfg(feature = "form")]
    #[must_use]
    pub fn form<T: serde::Serialize + ?Sized>(self, value: &T) -> Self {
        let encoded = serde_urlencoded::to_string(value);
        self.with(move |parts| {
            let encoded = encoded.map_err(|error| {
                Error::builder(format!("the form is not serialisable: {error}"))
            })?;
            parts.headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            parts.body = Body::fixed(encoded);
            Ok(())
        })
    }

    /// Bounds this request, overriding the client's timeout.
    #[must_use]
    pub fn timeout(self, timeout: Duration) -> Self {
        self.with(move |parts| {
            parts.options.timeout = Some(timeout);
            Ok(())
        })
    }

    /// Replaces the browser fetch context.
    ///
    /// This is what decides `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, the `Accept`
    /// value, and which header order applies. Use
    /// [`RequestOptions::navigation`] for a request that should look like an
    /// address-bar load rather than a `fetch()`.
    #[must_use]
    pub fn fetch_context(self, options: RequestOptions) -> Self {
        self.with(move |parts| {
            parts.options = options;
            Ok(())
        })
    }

    /// Sets the redirect policy for this request only.
    #[must_use]
    pub fn redirect(self, policy: chromulate_core::RedirectPolicy) -> Self {
        self.with(move |parts| {
            parts.options.redirect = policy;
            Ok(())
        })
    }

    /// Builds the request without sending it.
    ///
    /// The already-parsed URL travels in the request's extensions as
    /// [`chromulate_http::RequestUrl`], so the engine does not have to parse
    /// the `Uri` back into one.
    ///
    /// # Errors
    ///
    /// Returns the first error collected while the request was assembled.
    pub fn build(self) -> Result<chromulate_core::Request> {
        self.build_with_url().map(|(request, _)| request)
    }

    /// Builds the request and hands back the parsed URL it was built from.
    fn build_with_url(self) -> Result<(chromulate_core::Request, Url)> {
        let parts = self.state?;
        let mut request = http::Request::builder()
            .method(parts.method)
            .uri(parts.url.as_str())
            .body(parts.body)
            .map_err(|error| Error::builder(error.to_string()))?;

        // Client defaults first, so a per-request header of the same name wins.
        let headers = request.headers_mut();
        for (name, value) in &self.client.default_headers {
            headers.insert(name.clone(), value.clone());
        }
        for (name, value) in &parts.headers {
            headers.insert(name.clone(), value.clone());
        }
        request.extensions_mut().insert(parts.options);
        request
            .extensions_mut()
            .insert(chromulate_http::RequestUrl(parts.url.clone()));
        Ok((request, parts.url))
    }

    /// Sends the request.
    ///
    /// # Errors
    ///
    /// Returns the first error collected while the request was assembled, or
    /// whatever the transport produced.
    pub async fn send(self) -> Result<Response> {
        let client = Arc::clone(&self.client);
        let (request, requested) = self.build_with_url()?;

        let response = client.engine.send(request).await?;
        Ok(Response::new(response, requested, client.max_response_size))
    }
}
