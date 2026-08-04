//! The streaming body type used for both requests and responses.
//!
//! Bodies are streams of [`Bytes`] chunks. Nothing is buffered unless the caller asks
//! for it, which keeps a multi-gigabyte download at a constant memory cost. The three
//! internal shapes exist so that the common cases stay allocation free: an empty body
//! carries no state, a fixed body hands out its single chunk by reference count, and
//! only a genuinely streaming body pays for a boxed stream.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use http_body::{Body as HttpBody, Frame, SizeHint};

use crate::error::{Error, Phase, Result};

type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send + 'static>>;

enum Inner {
    Empty,
    Fixed(Option<Bytes>),
    Stream {
        stream: ChunkStream,
        length: Option<u64>,
    },
}

/// A request or response body.
pub struct Body {
    inner: Inner,
}

impl Body {
    /// A body with no bytes at all.
    ///
    /// Distinct from a zero length fixed body: an empty body advertises no
    /// `Content-Length` for methods where a browser would omit it entirely.
    pub const fn empty() -> Self {
        Self {
            inner: Inner::Empty,
        }
    }

    /// A body whose full contents are already in memory.
    pub fn fixed(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Self::empty();
        }
        Self {
            inner: Inner::Fixed(Some(bytes)),
        }
    }

    /// A body produced by a stream of chunks, with an optional known length.
    ///
    /// Pass `length` when the total size is known ahead of time so the engine can send
    /// `Content-Length` instead of falling back to chunked transfer encoding.
    pub fn stream<S>(stream: S, length: Option<u64>) -> Self
    where
        S: Stream<Item = Result<Bytes>> + Send + 'static,
    {
        Self {
            inner: Inner::Stream {
                stream: Box::pin(stream),
                length,
            },
        }
    }

    /// Whether this body is known to carry no bytes.
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            Inner::Empty => true,
            Inner::Fixed(chunk) => chunk.as_ref().is_none_or(Bytes::is_empty),
            Inner::Stream { .. } => false,
        }
    }

    /// The exact body length, when it is known without consuming the body.
    pub fn content_length(&self) -> Option<u64> {
        match &self.inner {
            Inner::Empty => Some(0),
            Inner::Fixed(chunk) => Some(chunk.as_ref().map_or(0, |b| b.len() as u64)),
            Inner::Stream { length, .. } => *length,
        }
    }

    /// Clones the body when doing so is free *and* the clone would carry the same bytes.
    ///
    /// Returns `None` for streaming bodies, which cannot be replayed, and for a fixed body
    /// whose chunk has already been handed to the transport. The redirect and retry engines
    /// use this to decide whether a request can be safely re-sent, so a drained body must
    /// answer `None` rather than `Some` of an empty body: the alternative is a retried
    /// `POST` that silently goes out with no payload and `Content-Length: 0`.
    pub fn try_clone(&self) -> Option<Self> {
        match &self.inner {
            Inner::Empty => Some(Self::empty()),
            Inner::Fixed(chunk) => chunk.as_ref().map(|bytes| Self {
                inner: Inner::Fixed(Some(bytes.clone())),
            }),
            Inner::Stream { .. } => None,
        }
    }

    /// Reads the whole body into memory, refusing to exceed `limit` bytes.
    ///
    /// The limit is enforced while streaming, so an oversized response is abandoned
    /// rather than buffered and then rejected.
    pub async fn collect(mut self, limit: u64) -> Result<Bytes> {
        use futures_util::StreamExt as _;

        match &mut self.inner {
            Inner::Empty => Ok(Bytes::new()),
            Inner::Fixed(chunk) => {
                let bytes = chunk.take().unwrap_or_default();
                if bytes.len() as u64 > limit {
                    Err(Error::BodyTooLarge { limit })
                } else {
                    Ok(bytes)
                }
            }
            Inner::Stream { stream, .. } => {
                let mut buf = BytesMut::new();
                let mut total: u64 = 0;
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    total += chunk.len() as u64;
                    if total > limit {
                        return Err(Error::BodyTooLarge { limit });
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(buf.freeze())
            }
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Body");
        match &self.inner {
            Inner::Empty => s.field("kind", &"empty"),
            Inner::Fixed(chunk) => s
                .field("kind", &"fixed")
                .field("len", &chunk.as_ref().map_or(0, Bytes::len)),
            Inner::Stream { length, .. } => s.field("kind", &"stream").field("length", length),
        };
        s.finish()
    }
}

impl From<Bytes> for Body {
    fn from(value: Bytes) -> Self {
        Self::fixed(value)
    }
}

impl From<Vec<u8>> for Body {
    fn from(value: Vec<u8>) -> Self {
        Self::fixed(value)
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Self::fixed(value)
    }
}

impl From<&'static str> for Body {
    fn from(value: &'static str) -> Self {
        Self::fixed(Bytes::from_static(value.as_bytes()))
    }
}

impl From<()> for Body {
    fn from((): ()) -> Self {
        Self::empty()
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        // Every `Inner` variant is `Unpin`, including the already-pinned boxed stream,
        // so the body can be projected without any pin projection machinery.
        let this = self.get_mut();
        match &mut this.inner {
            Inner::Empty => Poll::Ready(None),
            Inner::Fixed(chunk) => Poll::Ready(chunk.take().map(|b| Ok(Frame::data(b)))),
            Inner::Stream { stream, .. } => match stream.as_mut().poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
                Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Inner::Empty => true,
            Inner::Fixed(chunk) => chunk.is_none(),
            Inner::Stream { .. } => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.content_length() {
            Some(len) => SizeHint::with_exact(len),
            None => SizeHint::default(),
        }
    }
}

/// Wraps a body error that surfaced while reading a response.
pub fn body_error(phase: Phase, source: impl Into<crate::error::BoxError>) -> Error {
    Error::Body {
        phase,
        source: Some(source.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;

    #[test]
    fn empty_and_fixed_bodies_report_their_length() {
        assert_eq!(Body::empty().content_length(), Some(0));
        assert_eq!(Body::fixed("hello").content_length(), Some(5));
        assert!(Body::empty().is_empty());
        assert!(!Body::fixed("hello").is_empty());
    }

    #[test]
    fn a_zero_length_fixed_body_collapses_to_empty() {
        let body = Body::fixed(Bytes::new());
        assert!(body.is_empty());
        assert!(body.try_clone().is_some());
    }

    #[tokio::test]
    async fn a_drained_fixed_body_is_not_replayable() {
        use http_body_util::BodyExt as _;

        let mut body = Body::fixed("username=alice&amount=1000");
        assert_eq!(body.content_length(), Some(26));

        let frame = body
            .frame()
            .await
            .expect("the body yields one frame")
            .expect("the frame is not an error");
        assert_eq!(frame.into_data().expect("a data frame").len(), 26);

        // The bytes are already on the wire. Reporting this body as replayable would let a
        // retry re-send the request with an empty body and a `Content-Length` of zero.
        assert!(
            body.try_clone().is_none(),
            "a fixed body whose chunk has been taken must not claim to be replayable"
        );
    }

    #[test]
    fn streaming_bodies_are_not_replayable() {
        let body = Body::stream(stream::empty(), None);
        assert!(body.try_clone().is_none());
        assert_eq!(body.content_length(), None);
    }

    #[tokio::test]
    async fn collect_concatenates_stream_chunks() {
        let chunks = vec![
            Ok(Bytes::from_static(b"chro")),
            Ok(Bytes::from_static(b"mulate")),
        ];
        let body = Body::stream(stream::iter(chunks), None);
        let collected = body.collect(1024).await.expect("collect should succeed");
        assert_eq!(collected, Bytes::from_static(b"chromulate"));
    }

    #[tokio::test]
    async fn collect_rejects_bodies_over_the_limit_while_streaming() {
        let chunks = vec![
            Ok(Bytes::from_static(b"aaaaa")),
            Ok(Bytes::from_static(b"bbbbb")),
        ];
        let body = Body::stream(stream::iter(chunks), None);
        let err = body.collect(6).await.expect_err("limit should be enforced");
        assert!(matches!(err, Error::BodyTooLarge { limit: 6 }));
    }

    #[tokio::test]
    async fn collect_rejects_oversized_fixed_bodies() {
        let err = Body::fixed("0123456789")
            .collect(4)
            .await
            .expect_err("limit should be enforced");
        assert!(matches!(err, Error::BodyTooLarge { limit: 4 }));
    }
}
