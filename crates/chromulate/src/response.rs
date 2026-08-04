//! The response, and reading its body.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use chromulate_core::{
    Body, Error, Result, Timings,
    reexport::{HeaderMap, StatusCode, Url, Version},
};
use chromulate_http::ResponseInfo;
use futures_core::Stream;

/// A response, with the URL that produced it and what it cost.
pub struct Response {
    inner: chromulate_core::Response,
    url: Url,
    timings: Option<Timings>,
    max_size: u64,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.inner.status())
            .field("version", &self.inner.version())
            // The path and query are omitted: a query string routinely carries
            // tokens, and `Debug` output ends up in logs.
            .field("host", &self.url.host_str().unwrap_or_default())
            .finish_non_exhaustive()
    }
}

impl Response {
    pub(crate) fn new(mut inner: chromulate_core::Response, requested: Url, max_size: u64) -> Self {
        // The engine records which URL actually answered, which after a
        // redirect chain is not the one the caller asked for, and how long each
        // phase took. Taken by value: this facade is the extension's one
        // consumer.
        let info = inner.extensions_mut().remove::<ResponseInfo>();
        let (url, timings) = match info {
            Some(info) => (info.url, Some(info.timings)),
            None => (requested, None),
        };
        Self {
            inner,
            url,
            timings,
            max_size,
        }
    }

    /// The status code.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    /// The HTTP version the response arrived over.
    #[must_use]
    pub fn version(&self) -> Version {
        self.inner.version()
    }

    /// The response headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    /// The URL that produced this response.
    ///
    /// After a redirect chain this is the final hop, not the URL the caller
    /// asked for, which is what a caller resolving relative links needs.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Where this request spent its time.
    ///
    /// `None` when the response did not come from the engine — a middleware
    /// that answers from a cache produces a response that never touched the
    /// network, and there is nothing honest to report for it.
    ///
    /// [`Timings`] is `Copy`, so take one before reading the body and read
    /// [`Timings::elapsed`] afterwards to learn when the body finished:
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), chromulate::Error> {
    /// let client = chromulate::Client::chrome()?;
    /// let response = client.get("https://example.com/").send().await?;
    ///
    /// let timings = response.timings().expect("an engine response is timed");
    /// let body = response.bytes().await?;
    ///
    /// println!("connect {:?}, head {:?}", timings.connect(), timings.head());
    /// println!("{} bytes complete after {:?}", body.len(), timings.elapsed());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn timings(&self) -> Option<Timings> {
        self.timings
    }

    /// Whether the status is in the 2xx range.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.inner.status().is_success()
    }

    /// Turns a non-2xx status into an error, leaving a 2xx untouched.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] carrying the status and the URL.
    pub fn error_for_status(self) -> Result<Self> {
        if self.is_success() {
            Ok(self)
        } else {
            Err(Error::protocol(format!(
                "{} responded {}",
                self.url,
                self.status()
            )))
        }
    }

    /// The `Content-Length` the server declared, if any.
    ///
    /// A decoded body does not carry one: the encoded length no longer
    /// describes it.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.inner.body().content_length()
    }

    /// Reads the whole body into memory.
    ///
    /// Bounded by the client's `max_response_size`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BodyTooLarge`] when the body exceeds the limit, or a
    /// body error when the stream fails.
    pub async fn bytes(self) -> Result<Bytes> {
        let limit = self.max_size;
        self.inner.into_body().collect(limit).await
    }

    /// Reads the whole body and decodes it as text.
    ///
    /// The character set comes from the `Content-Type` header. An unknown or
    /// absent charset is decoded as UTF-8, replacing anything invalid, so this
    /// never fails on encoding alone.
    ///
    /// A byte-order mark at the start of the body overrides the declared
    /// charset, which is what the WHATWG Encoding Standard requires and what a
    /// browser does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BodyTooLarge`] when the body exceeds the client's
    /// limit, or a body error when the stream fails.
    pub async fn text(self) -> Result<String> {
        let encoding = charset_of(self.headers());
        let bytes = self.bytes().await?;
        let (text, _actual, _had_errors) = encoding.decode(&bytes);
        Ok(text.into_owned())
    }

    /// Reads the whole body and parses it as JSON.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when the body is not valid JSON for `T`.
    #[cfg(feature = "json")]
    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        let bytes = self.bytes().await?;
        serde_json::from_slice(&bytes).map_err(|error| Error::Decode {
            encoding: "json".to_owned(),
            source: Some(Box::new(error)),
        })
    }

    /// Streams the body without buffering it.
    #[must_use]
    pub fn bytes_stream(self) -> BodyStream {
        BodyStream {
            inner: Box::pin(chunks_of(self.inner.into_body())),
        }
    }

    /// Discards the body and hands back the underlying response.
    #[must_use]
    pub fn into_inner(self) -> chromulate_core::Response {
        self.inner
    }
}

/// The body as a stream of chunks.
pub struct BodyStream {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>,
}

impl fmt::Debug for BodyStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyStream").finish_non_exhaustive()
    }
}

impl Stream for BodyStream {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // The inner stream is already boxed and therefore `Unpin`, so the
        // struct projects with `get_mut` and needs no projection macro — the
        // workspace forbids `unsafe`, which rules out `pin-project-lite`.
        self.get_mut().inner.as_mut().poll_next(cx)
    }
}

fn chunks_of(body: Body) -> impl Stream<Item = Result<Bytes>> + Send + 'static {
    use futures_core::ready;
    use http_body::Body as _;

    struct Frames(Body);

    impl Stream for Frames {
        type Item = Result<Bytes>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            loop {
                match ready!(Pin::new(&mut this.0).poll_frame(cx)) {
                    None => return Poll::Ready(None),
                    Some(Err(error)) => return Poll::Ready(Some(Err(error))),
                    Some(Ok(frame)) => match frame.into_data() {
                        Ok(chunk) => return Poll::Ready(Some(Ok(chunk))),
                        // A trailers frame carries no body bytes; keep reading.
                        Err(_trailers) => continue,
                    },
                }
            }
        }
    }

    Frames(body)
}

/// Reads the charset out of a `Content-Type`, defaulting to UTF-8.
fn charset_of(headers: &HeaderMap) -> &'static encoding_rs::Encoding {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(charset_parameter)
        .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8)
}

/// Pulls the `charset` parameter out of a media type.
fn charset_parameter(content_type: &str) -> Option<String> {
    for parameter in content_type.split(';').skip(1) {
        let (name, value) = parameter.split_once('=')?;
        if name.trim().eq_ignore_ascii_case("charset") {
            return Some(value.trim().trim_matches('"').to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_str(content_type).expect("a valid header value"),
        );
        headers
    }

    #[test]
    fn a_declared_charset_is_honoured() {
        assert_eq!(
            charset_of(&headers_with("text/html; charset=iso-8859-9")).name(),
            "windows-1254",
            "the Turkish legacy label maps to the encoding the standard aliases it to"
        );
        assert_eq!(
            charset_of(&headers_with("text/plain; charset=Shift_JIS")).name(),
            "Shift_JIS"
        );
    }

    #[test]
    fn a_quoted_charset_is_unwrapped() {
        assert_eq!(
            charset_of(&headers_with("text/html; charset=\"windows-1252\"")).name(),
            "windows-1252"
        );
    }

    #[test]
    fn a_missing_or_unknown_charset_falls_back_to_utf8() {
        assert_eq!(charset_of(&HeaderMap::new()).name(), "UTF-8");
        assert_eq!(charset_of(&headers_with("text/html")).name(), "UTF-8");
        assert_eq!(
            charset_of(&headers_with("text/html; charset=not-a-real-encoding")).name(),
            "UTF-8"
        );
    }

    #[test]
    fn a_charset_after_another_parameter_is_still_found() {
        assert_eq!(
            charset_of(&headers_with(
                "text/html; boundary=xyz; charset=windows-1251"
            ))
            .name(),
            "windows-1251"
        );
    }

    #[test]
    fn latin1_bytes_decode_through_the_declared_charset_rather_than_as_utf8() {
        // 0xFC is `ü` in ISO-8859-1 and invalid on its own in UTF-8.
        let encoding = charset_of(&headers_with("text/plain; charset=iso-8859-1"));
        let (text, _, _) = encoding.decode(&[b'g', b'r', 0xFC, b'n']);
        assert_eq!(text, "grün");

        let (lossy, _, had_errors) = encoding_rs::UTF_8.decode(&[b'g', b'r', 0xFC, b'n']);
        assert!(had_errors, "the same bytes are not valid UTF-8");
        assert_ne!(lossy, "grün");
    }
}
