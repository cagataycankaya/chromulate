//! Response body plumbing: adapting hyper's body, bounding it by the request
//! deadline, and returning the connection to the pool at the right moment.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use chromulate_core::{Body, Error, Phase, Result, body_error};
use futures_core::Stream;
use futures_util::StreamExt as _;
use http_body::Body as _;
use http_body_util::BodyExt as _;

use crate::deadline::Deadline;
use crate::pool::{Connection, Pool, PoolKey};

/// Turns hyper's response body into a Chromulate body.
///
/// The declared length — hyper's size hint is exact when the response carries
/// a `Content-Length` — travels with the body so `Body::collect` can size its
/// buffer once instead of growing into it.
///
/// Trailers are dropped: `Body` has no way to carry them, and no browser-facing
/// behaviour in this crate depends on them.
pub(crate) fn from_incoming(incoming: hyper::body::Incoming) -> Body {
    let length = incoming.size_hint().exact();
    let stream = incoming
        .into_data_stream()
        .map(|chunk| chunk.map_err(|error| body_error(Phase::ReceiveBody, error)));
    Body::stream(stream, length)
}

/// Polls the next **data** chunk out of a body, skipping non-data frames.
///
/// `Body` is `Unpin` and implements [`http_body::Body`] itself, so the
/// wrappers below hold it directly and poll its frames — no intermediate
/// `BodyStream` adapter, no extra boxed stream per response.
fn poll_data(body: &mut Body, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes>>> {
    loop {
        match Pin::new(&mut *body).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => return Poll::Ready(Some(Ok(data))),
                // A trailers frame; nothing here consumes them.
                Err(_) => {}
            },
            Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
        }
    }
}

/// Holds an HTTP/1.1 connection until its response body is finished with.
///
/// An HTTP/1.1 connection carries one exchange at a time and cannot be handed
/// to another request until the current response has been read off the socket.
/// Returning it to the pool when the response *head* arrives would let the next
/// request queue behind a body that is still arriving, so the connection
/// travels with the body and goes back only when the body ends cleanly.
///
/// A body that is dropped early, or that fails, takes the connection with it:
/// there is no way to know how many unread bytes are still in flight, and a
/// pooled connection with a partial response on it corrupts the next request.
struct PoolSlot {
    pool: Pool,
    key: PoolKey,
    connection: Option<Connection>,
}

impl PoolSlot {
    fn release(&mut self) {
        if let Some(connection) = self.connection.take() {
            self.pool.release(&self.key, connection);
        }
    }
}

/// Wraps a body so the connection returns to the pool when the body ends.
pub(crate) fn returning_to_pool(
    body: Body,
    pool: Pool,
    key: PoolKey,
    connection: Connection,
) -> Body {
    let length = body.content_length();
    Body::stream(
        ReleasingStream {
            inner: body,
            slot: Some(PoolSlot {
                pool,
                key,
                connection: Some(connection),
            }),
        },
        length,
    )
}

struct ReleasingStream {
    inner: Body,
    slot: Option<PoolSlot>,
}

impl Stream for ReleasingStream {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match poll_data(&mut this.inner, cx) {
            Poll::Ready(None) => {
                if let Some(mut slot) = this.slot.take() {
                    slot.release();
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                // Dropping the slot without releasing discards the connection.
                this.slot = None;
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }
}

/// Wraps a body so the whole-request deadline still applies while it streams.
///
/// Without this a deadline would bound only the response head, and a server
/// that sends a head and then stalls would hold the caller indefinitely.
pub(crate) fn bounded_by(body: Body, deadline: Deadline) -> Body {
    let Some(remaining) = deadline.remaining() else {
        return body;
    };
    let length = body.content_length();
    Body::stream(
        BoundedStream {
            inner: body,
            timer: Box::pin(tokio::time::sleep(remaining)),
            expired: false,
        },
        length,
    )
}

struct BoundedStream {
    inner: Body,
    timer: Pin<Box<tokio::time::Sleep>>,
    expired: bool,
}

impl Stream for BoundedStream {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.expired {
            return Poll::Ready(None);
        }
        if std::future::Future::poll(this.timer.as_mut(), cx).is_ready() {
            this.expired = true;
            return Poll::Ready(Some(Err(Error::Timeout(Phase::ReceiveBody))));
        }
        poll_data(&mut this.inner, cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures_util::stream;

    use super::*;

    #[tokio::test]
    async fn a_body_that_arrives_in_time_is_passed_through_untouched() {
        let body = Body::fixed("chromulate");
        let bounded = bounded_by(body, Deadline::starting_now(Some(Duration::from_secs(30))));
        let collected = bounded.collect(1024).await.expect("the body must arrive");
        assert_eq!(collected, Bytes::from_static(b"chromulate"));
    }

    #[tokio::test]
    async fn a_body_that_stalls_past_the_deadline_fails_in_the_receive_phase() {
        let stalled = stream::once(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(Bytes::from_static(b"never"))
        });
        let bounded = bounded_by(
            Body::stream(stalled, None),
            Deadline::starting_now(Some(Duration::from_millis(20))),
        );

        let error = bounded
            .collect(1024)
            .await
            .expect_err("a stalled body must not hold the caller");
        assert!(
            matches!(error, Error::Timeout(Phase::ReceiveBody)),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn an_unbounded_deadline_leaves_the_body_alone() {
        let bounded = bounded_by(Body::fixed("x"), Deadline::starting_now(None));
        assert_eq!(bounded.content_length(), Some(1));
    }
}
