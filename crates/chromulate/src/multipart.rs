//! `multipart/form-data` request bodies, as RFC 7578 defines them and as Chrome
//! writes them.
//!
//! ```no_run
//! use chromulate::multipart::{Form, Part};
//!
//! # async fn run(client: chromulate::Client) -> chromulate::Result<()> {
//! let form = Form::new()
//!     .text("caption", "a holiday photo")
//!     .part("photo", Part::file("holiday.jpg").await?.mime_str("image/jpeg"));
//!
//! let response = client
//!     .post("https://example.com/upload")
//!     .multipart(form)
//!     .send()
//!     .await?;
//! # let _ = response;
//! # Ok(())
//! # }
//! ```
//!
//! # What was captured, and what was decided
//!
//! Every wire-format constant here comes from
//! `crates/chromulate/tests/data/chrome-151-multipart.txt`, a capture of Chrome
//! 151 on macOS submitting a real form and building a real `FormData` request.
//! Nothing in the encoder was written from the RFC alone where the RFC and the
//! browser disagree, because it is the browser this crate exists to resemble.
//!
//! What the capture establishes:
//!
//! - the boundary is the literal `----WebKitFormBoundary` followed by sixteen
//!   characters drawn from `[0-9A-Za-z]`, redrawn per request;
//! - exactly three bytes are escaped in a field name or a filename — `"` to
//!   `%22`, CR to `%0D`, LF to `%0A` — and nothing else is, so a semicolon or a
//!   colon travels literally;
//! - non-ASCII filenames are sent as raw UTF-8, and there is no RFC 5987
//!   `filename*` parameter anywhere in the output;
//! - a part carries a `Content-Type` if and only if it has a filename, falling
//!   back to `application/octet-stream`;
//! - parts keep the order they were added, and the framing is
//!   `--boundary CRLF headers CRLF content CRLF … --boundary-- CRLF`.
//!
//! Two things here are decisions rather than observations, and are marked as
//! such so nobody later mistakes them for captured facts:
//!
//! - **No MIME sniffing.** Chrome derived `text/plain` from a `.txt` extension.
//!   Chromulate links no MIME database, so [`Part::file`] uses
//!   `application/octet-stream` and leaves [`Part::mime_str`] to the caller. The
//!   fallback itself *is* captured; choosing it for a `.txt` file is not what
//!   Chrome would do.
//! - **Boundary randomness.** The capture shows the length, the alphabet and the
//!   prefix. Forty samples cannot show that the draw is uniform or that its
//!   source is a CSPRNG, so this module claims neither about Chrome. It uses
//!   `rand`'s thread RNG for its own draw.
//!
//! # Why a hostile filename cannot forge a header
//!
//! A field name and a filename are the only attacker-influenced text that lands
//! in a header line. Escaping `"`, CR and LF removes every byte that could close
//! the quoted string or end the line, so a name is inert text no matter what it
//! contains. The escape is applied by `escape_parameter` in exactly one place
//! for both slots — if it ever became two functions, the paired tests
//! `crlf_in_a_filename_cannot_forge_a_header_or_an_extra_part` and
//! `crlf_in_a_field_name_cannot_forge_a_header_or_an_extra_part` would have to
//! be reasoned about separately.
//!
//! # What the boundary check actually guarantees
//!
//! For parts whose bytes are already in memory the guarantee is total: the
//! encoder searches every header block and every in-memory part for the
//! candidate boundary and redraws until it finds one that occurs nowhere. The
//! content is fixed before the draw, so an adversary cannot steer it.
//!
//! For a streaming part there is no guarantee, only an argument. The bytes
//! cannot be inspected without consuming them, and consuming them is the thing
//! streaming exists to avoid. The argument is that sixteen characters from a
//! 62-symbol alphabet is about 95 bits, so a stream that was not built to
//! contain the boundary will not. A stream that *was* — a proxy relaying
//! attacker-chosen bytes that echo a boundary the attacker has observed — is
//! outside what this can defend. Buffer such a part with [`Part::bytes`] if that
//! is the situation you are in.

use std::borrow::Cow;
use std::fmt;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut as _, Bytes, BytesMut};
use chromulate_core::reexport::HeaderValue;
use chromulate_core::{Body, Error, Phase, Result, body_error};
use futures_core::Stream;

/// The fixed part of the boundary, captured from Chrome 151.
const BOUNDARY_PREFIX: &str = "----WebKitFormBoundary";

/// How many random characters follow the prefix. Captured: always sixteen.
const BOUNDARY_TAIL: usize = 16;

/// The symbols the captured tails were drawn from: exactly `[0-9A-Za-z]`, with
/// none missing across 640 observed characters and none outside it.
const BOUNDARY_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\
abcdefghijklmnopqrstuvwxyz";

type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send + 'static>>;

/// Where one part's content comes from.
enum Source {
    /// Already in memory, so its length is known and it can be searched for a
    /// candidate boundary.
    Bytes(Option<Bytes>),
    /// Produced lazily. `length` is `Some` only when the caller declared it.
    Stream {
        stream: ChunkStream,
        length: Option<u64>,
    },
}

impl Source {
    fn length(&self) -> Option<u64> {
        match self {
            Self::Bytes(chunk) => Some(chunk.as_ref().map_or(0, Bytes::len) as u64),
            Self::Stream { length, .. } => *length,
        }
    }

    /// The bytes a boundary search can see, which is nothing for a stream.
    fn inspectable(&self) -> Option<&Bytes> {
        match self {
            Self::Bytes(chunk) => chunk.as_ref(),
            Self::Stream { .. } => None,
        }
    }
}

impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(chunk) => f
                .debug_struct("Bytes")
                .field("len", &chunk.as_ref().map_or(0, Bytes::len))
                .finish(),
            Self::Stream { length, .. } => {
                f.debug_struct("Stream").field("length", length).finish()
            }
        }
    }
}

/// One field of a form.
///
/// A part is content plus, optionally, a filename and a MIME type. Giving it a
/// filename is what makes a server treat it as an upload rather than a text
/// field, and — following the capture — is also what makes it carry a
/// `Content-Type`.
///
/// ```
/// use chromulate::multipart::Part;
///
/// let part = Part::text("hello").file_name("greeting.txt").mime_str("text/plain");
/// # let _ = part;
/// ```
pub struct Part {
    file_name: Option<String>,
    mime: Option<HeaderValue>,
    /// Collected rather than returned, so a chain of calls stays readable. It
    /// surfaces from [`Form::into_body`], and therefore from `send`.
    error: Option<Error>,
    source: Source,
}

impl fmt::Debug for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The content is deliberately absent: a part is routinely an uploaded
        // document, and `Debug` output ends up in logs.
        f.debug_struct("Part")
            .field("file_name", &self.file_name)
            .field("mime", &self.mime)
            .field("source", &self.source)
            .finish()
    }
}

impl Part {
    fn from_source(source: Source) -> Self {
        Self {
            file_name: None,
            mime: None,
            error: None,
            source,
        }
    }

    /// A part whose content is already in memory.
    pub fn bytes(content: impl Into<Bytes>) -> Self {
        Self::from_source(Source::Bytes(Some(content.into())))
    }

    /// A part whose content is a string.
    pub fn text(content: impl Into<String>) -> Self {
        Self::bytes(Bytes::from(content.into().into_bytes()))
    }

    /// A part whose content is produced lazily and whose length is not known.
    ///
    /// A form containing one of these has no computable length, so the request
    /// goes out with `Transfer-Encoding: chunked` rather than a
    /// `Content-Length`. Use [`Part::stream_with_length`] when the total is
    /// known ahead of time.
    pub fn stream<S>(content: S) -> Self
    where
        S: Stream<Item = Result<Bytes>> + Send + 'static,
    {
        Self::from_source(Source::Stream {
            stream: Box::pin(content),
            length: None,
        })
    }

    /// A part produced lazily whose total length is known in advance.
    ///
    /// The declared length is what the request's `Content-Length` is computed
    /// from. A stream that then yields a different number of bytes desynchronises
    /// the framing, exactly as it would for any other declared-length body.
    pub fn stream_with_length<S>(content: S, length: u64) -> Self
    where
        S: Stream<Item = Result<Bytes>> + Send + 'static,
    {
        Self::from_source(Source::Stream {
            stream: Box::pin(content),
            length: Some(length),
        })
    }

    /// A part that streams a file from disk.
    ///
    /// The file is opened and measured, never read into memory: the returned
    /// part carries a known length, so the request can still declare a
    /// `Content-Length`, while the bytes travel from the file to the socket in
    /// chunks. The filename defaults to the path's last component and the MIME
    /// type to `application/octet-stream`; override the latter with
    /// [`Part::mime_str`], since no MIME database is linked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Builder`] if the file cannot be opened.
    pub async fn file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = tokio::fs::File::open(path).await.map_err(|error| {
            Error::builder(format!("cannot open `{}`: {error}", path.display()))
        })?;
        // A directory or a device has no meaningful length to declare, and
        // `Some(0)` would be a lie the transport acts on. `None` degrades to
        // chunked instead.
        let length = match file.metadata().await {
            Ok(metadata) if metadata.is_file() => Some(metadata.len()),
            _ => None,
        };

        let mut part = Self::from_source(Source::Stream {
            stream: Box::pin(IoChunks(Box::pin(tokio_util::io::ReaderStream::new(file)))),
            length,
        });
        part.file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        part.mime = Some(HeaderValue::from_static("application/octet-stream"));
        Ok(part)
    }

    /// Sets the filename reported in `Content-Disposition`.
    ///
    /// Quotes and line breaks in `name` are escaped, so any string is safe to
    /// pass; see the module documentation for what that escape is and why it is
    /// enough.
    #[must_use]
    pub fn file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    /// Sets the part's `Content-Type`.
    ///
    /// An unrepresentable value is collected rather than returned, and surfaces
    /// as [`Error::Builder`] when the request is sent.
    #[must_use]
    pub fn mime_str(mut self, mime: &str) -> Self {
        match HeaderValue::from_str(mime) {
            Ok(value) => self.mime = Some(value),
            Err(error) => {
                if self.error.is_none() {
                    self.error = Some(Error::builder(format!(
                        "`{mime}` is not a usable media type: {error}"
                    )));
                }
            }
        }
        self
    }
}

/// Adapts `tokio_util`'s reader stream to this crate's error type.
///
/// The inner stream is boxed so this wrapper is `Unpin` and needs no pin
/// projection; a file part boxes once either way.
struct IoChunks(Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send + 'static>>);

impl Stream for IoChunks {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut()
            .0
            .as_mut()
            .poll_next(cx)
            .map(|item| item.map(|chunk| chunk.map_err(|error| body_error(Phase::Send, error))))
    }
}

/// A `multipart/form-data` body under construction.
///
/// ```
/// use chromulate::multipart::{Form, Part};
///
/// let form = Form::new()
///     .text("title", "a report")
///     .part("file", Part::text("body").file_name("report.txt"));
///
/// let (content_type, body) = form.into_body()?;
/// assert!(
///     content_type
///         .to_str()
///         .unwrap_or_default()
///         .starts_with("multipart/form-data; boundary=----WebKitFormBoundary")
/// );
/// assert!(body.content_length().is_some());
/// # Ok::<(), chromulate::Error>(())
/// ```
#[derive(Debug)]
pub struct Form {
    parts: Vec<(String, Part)>,
    error: Option<Error>,
}

impl Default for Form {
    fn default() -> Self {
        Self::new()
    }
}

impl Form {
    /// An empty form.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            parts: Vec::new(),
            error: None,
        }
    }

    /// Adds a text field.
    #[must_use]
    pub fn text(self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.part(name, Part::text(value))
    }

    /// Adds a field.
    ///
    /// Quotes and line breaks in `name` are escaped, so any string is safe to
    /// pass.
    #[must_use]
    pub fn part(mut self, name: impl Into<String>, mut part: Part) -> Self {
        if self.error.is_none() {
            self.error = part.error.take();
        }
        self.parts.push((name.into(), part));
        self
    }

    /// How many fields the form carries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Whether the form carries no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Draws a boundary and encodes the form.
    ///
    /// Returns the `Content-Type` header value the request must carry, which
    /// names the boundary, and the body encoded against it. The two are produced
    /// together because a body encoded against one boundary and a header naming
    /// another is unparseable.
    ///
    /// The body streams. A form of in-memory parts reports a length, so the
    /// request declares a `Content-Length`; a form containing a part of unknown
    /// length does not, and the request falls back to chunked transfer encoding.
    ///
    /// # Errors
    ///
    /// Returns the first error collected while the form was assembled — today,
    /// only an unusable media type passed to [`Part::mime_str`].
    pub fn into_body(self) -> Result<(HeaderValue, Body)> {
        self.encode_with(draw_boundary)
    }

    /// [`Form::into_body`] with the boundary source injected, so a test can
    /// drive the redraw path with a boundary that is known to collide.
    fn encode_with(self, mut draw: impl FnMut() -> String) -> Result<(HeaderValue, Body)> {
        if let Some(error) = self.error {
            return Err(error);
        }

        // The header block is encoded before a boundary exists, because the
        // block is where a hostile name or filename lands and so is one of the
        // things the boundary has to avoid.
        let mut blocks = Vec::with_capacity(self.parts.len());
        let mut sources = Vec::with_capacity(self.parts.len());
        for (name, part) in self.parts {
            blocks.push(header_block(
                &name,
                part.file_name.as_deref(),
                part.mime.as_ref(),
            ));
            sources.push(part.source);
        }

        let boundary = loop {
            let candidate = draw();
            if !collides(candidate.as_bytes(), &blocks, &sources) {
                break candidate;
            }
        };

        let content_type =
            HeaderValue::try_from(format!("multipart/form-data; boundary={boundary}"))
                // The boundary is drawn from `[0-9A-Za-z]` and the rest is a
                // literal, so this cannot fail. It is mapped rather than unwrapped
                // because `unwrap` is not allowed outside tests, and no test
                // reaches this arm.
                .map_err(|error| Error::builder(format!("unusable boundary: {error}")))?;

        let mut parts = Vec::with_capacity(blocks.len());
        let mut total: Option<u64> = Some(0);
        for (index, (block, source)) in blocks.into_iter().zip(sources).enumerate() {
            // The CRLF that terminates a part's content is folded into the
            // *next* delimiter rather than emitted as a frame of its own, so a
            // part costs one frame plus its content rather than two;
            // `an_empty_field_costs_no_data_frame` counts them. The first
            // delimiter therefore has no leading CRLF, matching the capture.
            let leading: &[u8] = if index == 0 { b"" } else { b"\r\n" };
            let mut head =
                BytesMut::with_capacity(leading.len() + boundary.len() + 4 + block.len());
            head.put_slice(leading);
            head.put_slice(b"--");
            head.put_slice(boundary.as_bytes());
            head.put_slice(b"\r\n");
            head.put_slice(&block);

            // `checked_add`, not `+`: a caller can declare `u64::MAX` on a
            // stream part, and two of those would wrap to a `Content-Length`
            // far smaller than the body. An unrepresentable total is exactly
            // an unknown one, so it degrades to chunked like any other.
            total = match (total, source.length()) {
                (Some(sum), Some(length)) => sum
                    .checked_add(head.len() as u64)
                    .and_then(|sum| sum.checked_add(length)),
                _ => None,
            };
            parts.push(EncodedPart {
                head: head.freeze(),
                source,
            });
        }

        let mut closing = BytesMut::with_capacity(boundary.len() + 8);
        if !parts.is_empty() {
            closing.put_slice(b"\r\n");
        }
        closing.put_slice(b"--");
        closing.put_slice(boundary.as_bytes());
        closing.put_slice(b"--\r\n");
        let total = total.and_then(|sum| sum.checked_add(closing.len() as u64));

        let stream = FormStream {
            parts: parts.into_iter(),
            current: None,
            closing: Some(closing.freeze()),
        };
        Ok((content_type, Body::stream(stream, total)))
    }
}

/// The header lines of one part, terminated by the blank line before its content.
///
/// The `Content-Type` is present exactly when the filename is, which is what the
/// capture shows Chrome doing; the fallback media type is captured too.
fn header_block(name: &str, file_name: Option<&str>, mime: Option<&HeaderValue>) -> Bytes {
    let mut block = BytesMut::with_capacity(64 + name.len());
    block.put_slice(b"Content-Disposition: form-data; name=\"");
    block.put_slice(escape_parameter(name).as_bytes());
    block.put_slice(b"\"");
    if let Some(file_name) = file_name {
        block.put_slice(b"; filename=\"");
        block.put_slice(escape_parameter(file_name).as_bytes());
        block.put_slice(b"\"");
    }
    block.put_slice(b"\r\n");
    if file_name.is_some() {
        block.put_slice(b"Content-Type: ");
        block.put_slice(mime.map_or(&b"application/octet-stream"[..], HeaderValue::as_bytes));
        block.put_slice(b"\r\n");
    }
    block.put_slice(b"\r\n");
    block.freeze()
}

/// Percent-escapes the three bytes that could break out of a header parameter.
///
/// `"` closes the quoted string; CR and LF end the header line. Chrome escapes
/// these three and, as the capture shows, nothing else — a semicolon, a colon
/// and a space all travel literally, and non-ASCII travels as raw UTF-8. Doing
/// more would diverge from the browser; doing less would let a filename forge a
/// header.
fn escape_parameter(value: &str) -> Cow<'_, str> {
    if !value
        .bytes()
        .any(|byte| matches!(byte, b'"' | b'\r' | b'\n'))
    {
        return Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(value.len() + 8);
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("%22"),
            '\r' => escaped.push_str("%0D"),
            '\n' => escaped.push_str("%0A"),
            other => escaped.push(other),
        }
    }
    Cow::Owned(escaped)
}

/// Whether `boundary` occurs anywhere the encoder can see.
///
/// That is every part's header block and every part whose bytes are in memory.
/// A streaming part contributes nothing, because inspecting it would mean
/// consuming it; the module documentation says what that leaves unguaranteed.
fn collides(boundary: &[u8], blocks: &[Bytes], sources: &[Source]) -> bool {
    let occurs = |haystack: &[u8]| {
        haystack.len() >= boundary.len()
            && haystack
                .windows(boundary.len())
                .any(|window| window == boundary)
    };
    blocks.iter().any(|block| occurs(block))
        || sources
            .iter()
            .filter_map(Source::inspectable)
            .any(|content| occurs(content))
}

/// Draws a boundary of the captured shape.
fn draw_boundary() -> String {
    let mut boundary = String::with_capacity(BOUNDARY_PREFIX.len() + BOUNDARY_TAIL);
    boundary.push_str(BOUNDARY_PREFIX);
    for _ in 0..BOUNDARY_TAIL {
        let index = rand::random_range(0..BOUNDARY_ALPHABET.len());
        boundary.push(char::from(BOUNDARY_ALPHABET[index]));
    }
    boundary
}

struct EncodedPart {
    /// The delimiter, the header lines, and the blank line before the content.
    head: Bytes,
    source: Source,
}

/// Emits the encoded form: for each part its head then its content, then the
/// closing delimiter. Nothing is buffered beyond the chunk in flight.
struct FormStream {
    parts: std::vec::IntoIter<EncodedPart>,
    current: Option<Source>,
    closing: Option<Bytes>,
}

impl Stream for FormStream {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        match this.current.as_mut() {
            None => {}
            Some(Source::Bytes(chunk)) => match chunk.take() {
                // A zero-length field is legal and still produces its headers
                // and delimiters; only the empty frame is skipped. This is not
                // a truncation guard -- hyper drops empty chunks before they
                // reach the socket, which was checked by removing this and
                // watching the chunked test stay green. It is observable on the
                // `Body` that `Form::into_body` hands back, which is public, so
                // `an_empty_field_costs_no_data_frame` counts frames there.
                Some(content) if !content.is_empty() => return Poll::Ready(Some(Ok(content))),
                _ => {}
            },
            Some(Source::Stream { stream, .. }) => match stream.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                Poll::Ready(None) => {}
            },
        }

        this.current = None;
        match this.parts.next() {
            Some(part) => {
                this.current = Some(part.source);
                Poll::Ready(Some(Ok(part.head)))
            }
            None => Poll::Ready(this.closing.take().map(Ok)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(form: Form) -> (String, Vec<u8>) {
        let (content_type, body) = form.into_body().expect("the form must encode");
        let content_type = content_type
            .to_str()
            .expect("the content type is ASCII")
            .to_owned();
        let boundary = content_type
            .split_once("; boundary=")
            .expect("the content type names a boundary")
            .1
            .to_owned();
        (boundary, collect(body))
    }

    /// Every data frame the body produces, in order.
    ///
    /// `collect` cannot see frame boundaries and neither can a server behind
    /// hyper, which drops empty chunks before they reach the socket. Driving
    /// `poll_frame` is the only place the shape of the stream is observable,
    /// and `Form::into_body` is public, so it is observable to callers too.
    fn frames(body: Body) -> Vec<Bytes> {
        use http_body::Body as HttpBody;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime must build");
        runtime.block_on(async {
            let mut body = std::pin::pin!(body);
            let mut frames = Vec::new();
            while let Some(frame) = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
                if let Ok(data) = frame.expect("the body must not error").into_data() {
                    frames.push(data);
                }
            }
            frames
        })
    }

    fn collect(body: Body) -> Vec<u8> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime must build");
        runtime
            .block_on(body.collect(u64::MAX))
            .expect("the body must collect")
            .to_vec()
    }

    #[test]
    fn escaping_touches_only_the_quote_and_the_line_breaks() {
        // Captured: exactly these three, and nothing else. A borrowed return
        // proves the untouched case allocates nothing.
        assert!(matches!(
            escape_parameter("plain; name=x: y (é—)"),
            Cow::Borrowed("plain; name=x: y (é—)")
        ));
        assert_eq!(escape_parameter("a\"b"), "a%22b");
        assert_eq!(escape_parameter("a\r\nb"), "a%0D%0Ab");
        assert_eq!(
            escape_parameter("rép\"ort—ünïcode.txt"),
            "rép%22ort—ünïcode.txt"
        );
    }

    #[test]
    fn the_drawn_boundary_has_the_captured_shape() {
        for _ in 0..64 {
            let boundary = draw_boundary();
            assert_eq!(boundary.len(), BOUNDARY_PREFIX.len() + BOUNDARY_TAIL);
            let tail = boundary
                .strip_prefix(BOUNDARY_PREFIX)
                .expect("the prefix is literal");
            assert!(tail.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn a_boundary_found_in_a_part_is_redrawn() {
        // The first candidate is a substring of the field's value, so it must
        // be discarded; the second is not, so it must be used. Without the
        // redraw the first is what the header would name.
        let mut drawn = ["----WebKitFormBoundaryCOLLIDES0".to_owned()]
            .into_iter()
            .chain(["----WebKitFormBoundaryCLEAN00000".to_owned()])
            .collect::<Vec<_>>()
            .into_iter();

        let form = Form::new().text("field", "prefix ----WebKitFormBoundaryCOLLIDES0 suffix");
        let (content_type, body) = form
            .encode_with(|| drawn.next().expect("no more boundaries were prepared"))
            .expect("the form must encode");

        assert_eq!(
            content_type,
            "multipart/form-data; boundary=----WebKitFormBoundaryCLEAN00000"
        );
        let encoded = collect(body);
        assert_eq!(
            encoded
                .windows(30)
                .filter(|window| *window == b"----WebKitFormBoundaryCOLLIDES".as_slice())
                .count(),
            1,
            "the colliding text stays in the content and nowhere else"
        );
    }

    #[test]
    fn a_boundary_found_in_a_header_block_is_redrawn() {
        // The other half of the search: a field *name* can carry a
        // boundary-shaped string too, and it lands in the header block rather
        // than in any part's content.
        let mut drawn = vec![
            "----WebKitFormBoundaryINNAME000".to_owned(),
            "----WebKitFormBoundaryCLEAN0000".to_owned(),
        ]
        .into_iter();

        let form = Form::new().text("x----WebKitFormBoundaryINNAME000y", "value");
        let (content_type, _) = form
            .encode_with(|| drawn.next().expect("no more boundaries were prepared"))
            .expect("the form must encode");

        assert_eq!(
            content_type,
            "multipart/form-data; boundary=----WebKitFormBoundaryCLEAN0000"
        );
    }

    #[test]
    fn a_streaming_part_cannot_be_searched_so_it_never_forces_a_redraw() {
        // Stated so the limit is visible in a test rather than only in prose:
        // a stream whose bytes contain the boundary does not collide, because
        // nothing looked.
        let colliding = Bytes::from_static(b"----WebKitFormBoundaryUNSEEN0000");
        let sources = vec![Source::Stream {
            stream: Box::pin(FixedStream(Some(Ok(colliding)))),
            length: None,
        }];
        assert!(!collides(
            b"----WebKitFormBoundaryUNSEEN0000",
            &[],
            &sources
        ));

        // The same bytes in an in-memory part do collide.
        let sources = vec![Source::Bytes(Some(Bytes::from_static(
            b"----WebKitFormBoundaryUNSEEN0000",
        )))];
        assert!(collides(b"----WebKitFormBoundaryUNSEEN0000", &[], &sources));
    }

    struct FixedStream(Option<Result<Bytes>>);

    impl Stream for FixedStream {
        type Item = Result<Bytes>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.get_mut().0.take())
        }
    }

    #[test]
    fn a_declared_length_matches_the_bytes_the_stream_produces() {
        // The Content-Length arithmetic and the encoder are two independent
        // pieces of code; this is the only test that makes them agree.
        let form = Form::new()
            .text("plain", "ordinary")
            .part(
                "upload",
                Part::bytes(Bytes::from_static(b"0123456789")).file_name("f.bin"),
            )
            .text("empty", "");

        let (_, body) = form.into_body().expect("the form must encode");
        let declared = body.content_length().expect("every part has a length");
        assert_eq!(declared, collect(body).len() as u64);
    }

    #[test]
    fn a_total_length_that_would_overflow_is_reported_as_unknown() {
        // Reachable from the public API: nothing stops a caller declaring
        // `u64::MAX` twice. Wrapping would put a `Content-Length` on the wire
        // that is smaller than the body, which desynchronises the connection.
        let form = Form::new()
            .part(
                "a",
                Part::stream_with_length(FixedStream(None), u64::MAX - 1),
            )
            .part(
                "b",
                Part::stream_with_length(FixedStream(None), u64::MAX - 1),
            );
        let (_, body) = form.into_body().expect("the form must encode");
        assert_eq!(body.content_length(), None);
    }

    #[test]
    fn a_total_that_only_overflows_on_the_closing_delimiter_is_unknown_too() {
        // The sibling of the test above, and the reason both exist. There are
        // two additions -- one per part, one for the closing delimiter -- and a
        // single test cannot show that either is checked, because the first
        // overflowing makes the second unreachable. This length is chosen to
        // fit after the part is added and to overflow only when the closing
        // delimiter is: reverting either `checked_add` alone turns exactly one
        // of these two tests red.
        let form = Form::new().part(
            "a",
            Part::stream_with_length(FixedStream(None), u64::MAX - 100),
        );
        let (_, body) = form.into_body().expect("the form must encode");
        assert_eq!(body.content_length(), None);
    }

    #[test]
    fn one_part_of_unknown_length_makes_the_whole_form_unknown() {
        let form = Form::new()
            .text("plain", "ordinary")
            .part("upload", Part::stream(FixedStream(None)));
        let (_, body) = form.into_body().expect("the form must encode");
        assert_eq!(body.content_length(), None);
    }

    #[test]
    fn a_declared_stream_length_keeps_the_total_computable() {
        let form = Form::new().part(
            "upload",
            Part::stream_with_length(FixedStream(Some(Ok(Bytes::from_static(b"012345")))), 6),
        );
        let (_, body) = form.into_body().expect("the form must encode");
        let declared = body.content_length().expect("the length was declared");
        assert_eq!(declared, collect(body).len() as u64);
    }

    #[test]
    fn an_unusable_media_type_surfaces_from_into_body() {
        let error = Form::new()
            .part(
                "a",
                Part::text("x").mime_str("text/plain\r\nX-Injected: yes"),
            )
            .into_body()
            .expect_err("the media type is not a header value");
        assert!(matches!(error, Error::Builder(_)), "{error:?}");
    }

    #[test]
    fn a_part_without_a_filename_gets_no_content_type_line() {
        let block = header_block("field", None, None);
        assert_eq!(
            &block[..],
            b"Content-Disposition: form-data; name=\"field\"\r\n\r\n"
        );
    }

    #[test]
    fn a_multipart_body_is_not_replayable() {
        // It is a stream, so a redirect or a retry must not silently re-send it
        // as an empty body. `Body::try_clone` is what the engines ask.
        let (_, body) = Form::new()
            .text("a", "b")
            .into_body()
            .expect("the form must encode");
        assert!(body.try_clone().is_none());
    }

    #[tokio::test]
    async fn a_directory_has_no_declarable_length() {
        // `File::open` succeeds on a directory on Unix, and its metadata
        // carries a size that is not a byte count. Declaring it would put a
        // `Content-Length` on the wire that the body cannot honour, so the
        // length has to come back unknown and the request fall to chunked.
        let part = Part::file(std::env::temp_dir())
            .await
            .expect("a directory opens");
        assert_eq!(part.source.length(), None);
    }

    #[tokio::test]
    async fn a_missing_file_is_a_builder_error() {
        let error = Part::file(std::env::temp_dir().join("chromulate-no-such-file-here"))
            .await
            .expect_err("the file does not exist");
        assert!(matches!(error, Error::Builder(_)), "{error:?}");
        assert!(error.is_user_error());
    }

    #[test]
    fn an_empty_field_costs_no_data_frame() {
        let (_, body) = Form::new()
            .text("empty", "")
            .text("full", "x")
            .into_body()
            .expect("the form must encode");

        // Two heads, one content, one closing delimiter. An empty field
        // contributes its head and nothing else.
        let frames = frames(body);
        assert_eq!(frames.len(), 4, "{frames:?}");
        assert!(
            frames.iter().all(|frame| !frame.is_empty()),
            "an empty field must not become an empty frame: {frames:?}"
        );
    }

    #[test]
    fn a_file_sized_part_is_not_buffered_into_one_frame() {
        // The claim "stream by default" reduced to something checkable: a part
        // handed over as several chunks reaches the wire as several frames,
        // rather than being concatenated first.
        let chunks = vec![
            Ok(Bytes::from_static(b"aaaa")),
            Ok(Bytes::from_static(b"bbbb")),
            Ok(Bytes::from_static(b"cccc")),
        ];
        let (_, body) = Form::new()
            .part("upload", Part::stream(ChunkedStream(chunks.into())))
            .into_body()
            .expect("the form must encode");

        let frames = frames(body);
        // head, three content chunks, closing.
        assert_eq!(frames.len(), 5, "{frames:?}");
        assert_eq!(frames[1], Bytes::from_static(b"aaaa"));
        assert_eq!(frames[3], Bytes::from_static(b"cccc"));
    }

    struct ChunkedStream(std::collections::VecDeque<Result<Bytes>>);

    impl Stream for ChunkedStream {
        type Item = Result<Bytes>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.get_mut().0.pop_front())
        }
    }

    #[test]
    fn a_form_reports_how_many_parts_it_holds() {
        assert!(Form::new().is_empty());
        assert_eq!(Form::new().text("a", "1").text("b", "2").len(), 2);
    }

    #[test]
    fn debug_does_not_print_a_parts_content() {
        let rendered = format!("{:?}", Part::text("a secret document"));
        assert!(!rendered.contains("secret"), "{rendered}");
    }

    #[test]
    fn the_encoded_form_matches_the_captured_framing() {
        let (boundary, encoded) = body_of(
            Form::new()
                .text("plain", "ordinary")
                .part(
                    "upload",
                    Part::bytes(Bytes::from_static(b"file body bytes\n"))
                        .file_name("report.txt")
                        .mime_str("text/plain"),
                )
                .text("after", "tail"),
        );

        assert_eq!(
            String::from_utf8(encoded).expect("the encoding is UTF-8 here"),
            format!(
                "--{boundary}\r\n\
                 Content-Disposition: form-data; name=\"plain\"\r\n\
                 \r\n\
                 ordinary\r\n\
                 --{boundary}\r\n\
                 Content-Disposition: form-data; name=\"upload\"; filename=\"report.txt\"\r\n\
                 Content-Type: text/plain\r\n\
                 \r\n\
                 file body bytes\n\r\n\
                 --{boundary}\r\n\
                 Content-Disposition: form-data; name=\"after\"\r\n\
                 \r\n\
                 tail\r\n\
                 --{boundary}--\r\n"
            )
        );
    }
}
