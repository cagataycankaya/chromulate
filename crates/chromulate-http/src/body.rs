//! Response body plumbing: adapting hyper's body, bounding it by the request
//! deadline, returning the connection to the pool at the right moment, and
//! stopping a read once the caller has seen what it came for.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
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
            // A non-data frame is trailers; nothing here consumes them, so
            // the loop just polls for the next frame.
            Poll::Ready(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    return Poll::Ready(Some(Ok(data)));
                }
            }
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
/// That cost is real and it is not shared by HTTP/2 — see [`Stop`], which
/// documents the measured asymmetry and the test that holds each half of it.
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

// ------------------------------------------------- stopping a read early

/// Why an early-stopping body read ended.
///
/// A caller that cannot tell "the marker is not on this page" from "found it"
/// will parse the wrong thing and not know, so the reason travels with the
/// bytes rather than being inferred from their length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopReason {
    /// The body ended before anything stopped the read, and the condition —
    /// if there was one — never matched. The prefix is the whole body.
    EndOfBody,
    /// The condition matched. The read then took the trailing window [`Stop`]
    /// asked for, or as much of it as the body and the budget allowed.
    Matched,
    /// The byte budget ran out while the condition still had not matched, or
    /// there was no condition and the budget was the whole instruction.
    Budget,
}

/// The front of a body, and why the read stopped there.
#[derive(Debug, Clone)]
pub struct Prefix {
    bytes: Bytes,
    reason: StopReason,
    complete: bool,
}

impl Prefix {
    /// The bytes that were read.
    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Takes the bytes out.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    /// Why the read stopped.
    #[must_use]
    pub fn reason(&self) -> StopReason {
        self.reason
    }

    /// Whether the condition matched.
    ///
    /// The question a scraper actually asks: `false` means the marker is not in
    /// what was read, whether because the page does not contain it or because
    /// the budget ran out first.
    #[must_use]
    pub fn matched(&self) -> bool {
        self.reason == StopReason::Matched
    }

    /// Whether the body was read to its end, so nothing was abandoned.
    ///
    /// [`StopReason::EndOfBody`] always implies this; [`StopReason::Matched`]
    /// may, when the condition matched on the final chunk. When this is
    /// `false` the rest of the body was discarded, which on HTTP/1.1 also
    /// discards the connection — see [`Stop`].
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

/// What a read is looking for, and how far it will go to find it.
///
/// Structured product data sits at the front of a page: across six Turkish
/// marketplace product pages measured on 2026-08-04 the `application/ld+json`
/// block carrying price and stock began between 0.3% and 17.1% of the way into
/// bodies of 453 KB to 1.08 MB. Reading to the marker plus a 32 KiB window took
/// 4040 KB down to 744 KB across those six pages, and the median page from 177
/// ms to 114 ms.
///
/// # The chunk boundary
///
/// A marker split across two chunks is still found. That is the bug every
/// hand-rolled version of this has, which is why it is here rather than in
/// every caller: the scan re-examines the last `marker.len() - 1` bytes of what
/// was already buffered, and
/// `a_marker_split_across_a_chunk_boundary_is_still_found` constructs the split
/// deliberately rather than hoping the network produces one.
///
/// # What stopping early costs
///
/// Abandoning the rest of a body is not free on every protocol, and the
/// difference is large enough to decide whether stopping early is worth it:
///
/// - **HTTP/1.1**: the connection is discarded. A socket is one byte stream and
///   there is no way to know how many unread bytes are still in flight, so the
///   next request to that origin pays a fresh TCP connection and TLS handshake.
///   `an_abandoned_http1_body_does_not_return_its_connection_to_the_pool`
///   holds this, and it is the more important of the two: handing a half-read
///   socket to the next request is a correctness bug, not an optimisation.
/// - **HTTP/2**: the connection is kept. A body is one stream on a multiplexed
///   connection; dropping it drops h2's `RecvStream`, whose last reference
///   schedules `RST_STREAM(CANCEL)` for that stream alone, and the connection
///   stays open and pooled.
///   `an_abandoned_http2_body_leaves_its_connection_pooled_and_reusable`
///   observes the `RST_STREAM` at a real h2 server and then reuses the
///   connection.
///
/// # Example
///
/// ```
/// use chromulate_core::Body;
/// use chromulate_http::{Stop, StopReason};
///
/// # fn main() -> chromulate_core::Result<()> {
/// let page = Body::fixed("<head><script>{\"price\":42}</script>...another 500 KB...");
/// let runtime = tokio::runtime::Builder::new_current_thread()
///     .build()
///     .expect("a current-thread runtime must build");
///
/// let prefix = runtime.block_on(Stop::marker("\"price\"").plus(3).read(page))?;
///
/// assert_eq!(prefix.reason(), StopReason::Matched);
/// assert_eq!(prefix.bytes(), "<head><script>{\"price\":42");
/// assert!(!prefix.is_complete(), "the rest of the page was never read");
/// # Ok(())
/// # }
/// ```
pub struct Stop {
    condition: Option<Condition>,
    /// Bytes to keep reading after the condition matches.
    extra: u64,
    budget: Option<u64>,
}

/// A caller's condition, boxed because it is one per read and the read is
/// already awaiting a socket.
type Predicate = Box<dyn FnMut(&[u8]) -> bool + Send>;

enum Condition {
    Marker(Bytes),
    Predicate(Predicate),
}

impl fmt::Debug for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let condition = match &self.condition {
            None => "none",
            Some(Condition::Marker(_)) => "marker",
            Some(Condition::Predicate(_)) => "predicate",
        };
        f.debug_struct("Stop")
            .field("condition", &condition)
            .field("plus", &self.extra)
            .field("budget", &self.budget)
            .finish()
    }
}

impl Stop {
    /// Stops when `marker` appears in the decoded body.
    ///
    /// The marker is matched against the bytes the caller would have received,
    /// so a `Content-Encoding: gzip` response is searched after it is decoded,
    /// not on the wire.
    ///
    /// A marker past the byte budget set by [`Stop::within`] does not count as
    /// found: the budget is what the caller asked to be looked at, and a match
    /// outside it would make the answer depend on where the network split the
    /// body.
    ///
    /// An empty marker matches at the front of the first chunk, which stops the
    /// read having kept nothing. A body that never produces a chunk at all is
    /// never scanned, so it reports [`StopReason::EndOfBody`] — the condition
    /// only ever sees bytes that arrived.
    #[must_use]
    pub fn marker(marker: impl Into<Bytes>) -> Self {
        Self::with(Some(Condition::Marker(marker.into())))
    }

    /// Stops when `predicate` returns `true`.
    ///
    /// It is called once per chunk with **every byte read so far**, not with
    /// the chunk on its own, so a condition spanning a chunk boundary needs no
    /// handling from the caller. The cost of that is a predicate which rescans
    /// from the start each time; a plain byte marker is better served by
    /// [`Stop::marker`], which does not.
    #[must_use]
    pub fn when(predicate: impl FnMut(&[u8]) -> bool + Send + 'static) -> Self {
        Self::with(Some(Condition::Predicate(Box::new(predicate))))
    }

    /// Stops after `bytes`, with no condition to look for.
    ///
    /// The outcome is always [`StopReason::Budget`] unless the body ends first.
    #[must_use]
    pub fn after(bytes: u64) -> Self {
        Self::with(None).within(bytes)
    }

    fn with(condition: Option<Condition>) -> Self {
        Self {
            condition,
            extra: 0,
            budget: None,
        }
    }

    /// Keeps reading `bytes` more once the condition matches.
    ///
    /// The prefix then ends exactly `bytes` past the match — past the marker's
    /// last byte, or past everything read when a predicate returned `true` —
    /// unless the body or the budget ends it sooner. Without a condition there
    /// is nothing to count from and this has no effect.
    #[must_use]
    pub fn plus(mut self, bytes: u64) -> Self {
        self.extra = bytes;
        self
    }

    /// Gives up on the condition after `bytes`, and stops there.
    #[must_use]
    pub fn within(mut self, bytes: u64) -> Self {
        self.budget = Some(bytes);
        self
    }

    /// The byte budget, if one was set.
    ///
    /// A caller that imposes its own ceiling — a client's maximum response
    /// size, say — needs to know whether this one is already tighter.
    #[must_use]
    pub fn budget(&self) -> Option<u64> {
        self.budget
    }

    /// Reads `body` up to wherever this says to stop.
    ///
    /// The rest of the body is dropped, with the per-protocol consequences
    /// described on [`Stop`].
    ///
    /// # Errors
    ///
    /// Returns whatever the body stream produced. There is no
    /// [`Error::BodyTooLarge`]: a budget here is an instruction to stop, not a
    /// limit to fail on.
    pub async fn read(mut self, mut body: Body) -> Result<Prefix> {
        let budget = self.budget.unwrap_or(u64::MAX);
        // Sized like `Body::collect` does it: from the declared length when
        // there is one, clamped so a lying `Content-Length` cannot become an
        // allocation the peer never has to back with data, and clamped again
        // by the budget because nothing beyond it will be kept.
        let hint = body
            .content_length()
            .and_then(|declared| usize::try_from(declared.min(budget)).ok())
            .unwrap_or(0);
        let mut buf = BytesMut::with_capacity(hint);
        // Once the condition matches this is the length the prefix must reach
        // before the read stops: the match point plus the trailing window,
        // never past the budget.
        let mut target: Option<u64> = None;

        loop {
            if let Some(target) = target
                && buf.len() as u64 >= target
            {
                return Ok(Prefix {
                    bytes: cut(buf, target),
                    reason: StopReason::Matched,
                    complete: false,
                });
            }
            if buf.len() as u64 >= budget {
                return Ok(Prefix {
                    bytes: cut(buf, budget),
                    // A match inside the budget has already set a target, and
                    // that target is itself no larger than the budget, so the
                    // branch above returned it. Reaching here means nothing
                    // matched within the budget.
                    reason: StopReason::Budget,
                    complete: false,
                });
            }

            let Some(chunk) = std::future::poll_fn(|cx| poll_data(&mut body, cx)).await else {
                return Ok(Prefix {
                    bytes: buf.freeze(),
                    reason: if target.is_some() {
                        StopReason::Matched
                    } else {
                        StopReason::EndOfBody
                    },
                    complete: true,
                });
            };

            let previous = buf.len();
            buf.extend_from_slice(&chunk?);

            if target.is_none()
                && let Some(point) = self.match_point(&buf, previous)
                // A chunk arrives whole, so the scan can see a match the budget
                // said to stop short of. The caller asked about the first
                // `budget` bytes and this one is not in them: reporting it
                // would make the answer depend on where the network split the
                // body, and `matched()` true of bytes the marker is not in.
                && point as u64 <= budget
            {
                // Clamped, because the trailing window is not a licence to read
                // past the budget either — `Response::bytes_until` passes the
                // client's `max_response_size` through here.
                target = Some((point as u64).saturating_add(self.extra).min(budget));
            }
        }
    }

    /// Where the condition matched in `buf`, given that everything below
    /// `previous` was scanned on an earlier round.
    ///
    /// The marker scan restarts `marker.len() - 1` bytes before the new data
    /// so a marker straddling the boundary is found. Dropping that overlap is
    /// the whole bug, and it is invisible until a chunk happens to split a
    /// marker — which on a real connection is rare enough to reach production.
    fn match_point(&mut self, buf: &[u8], previous: usize) -> Option<usize> {
        match self.condition.as_mut()? {
            Condition::Marker(marker) => {
                let from = previous.saturating_sub(marker.len().saturating_sub(1));
                find(&buf[from..], marker).map(|at| from + at + marker.len())
            }
            Condition::Predicate(predicate) => predicate(buf).then_some(buf.len()),
        }
    }
}

/// Freezes `buf` and keeps its first `length` bytes, sharing the allocation
/// rather than copying.
fn cut(buf: BytesMut, length: u64) -> Bytes {
    let bytes = buf.freeze();
    let keep = usize::try_from(length)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    bytes.slice(..keep)
}

/// The first position of `needle` in `haystack`.
///
/// Scans for the first byte and only then compares, which keeps the common
/// case — a marker whose first byte is rare in HTML — a single pass over the
/// buffer rather than one comparison per offset.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let Some((&first, rest)) = needle.split_first() else {
        return Some(0);
    };
    let last_start = haystack.len().checked_sub(needle.len())?;
    let mut at = 0;
    while at <= last_start {
        let offset = haystack[at..=last_start].iter().position(|&b| b == first)?;
        let start = at + offset;
        if &haystack[start + 1..start + needle.len()] == rest {
            return Some(start);
        }
        at = start + 1;
    }
    None
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

    // ------------------------------------------------------- stopping early

    /// A body whose chunk boundaries the test chooses, rather than whichever
    /// ones a socket happened to produce.
    fn chunked(chunks: &[&'static str]) -> Body {
        let chunks: Vec<Result<Bytes>> = chunks
            .iter()
            .map(|chunk| Ok(Bytes::from_static(chunk.as_bytes())))
            .collect();
        Body::stream(stream::iter(chunks), None)
    }

    /// The bug every hand-rolled early stop has. The marker is cut in half by
    /// the chunk boundary on purpose: scanning each chunk on its own, or
    /// scanning the accumulated buffer only from where the new bytes begin,
    /// finds nothing here and reads the whole body.
    #[tokio::test]
    async fn a_marker_split_across_a_chunk_boundary_is_still_found() {
        let body = chunked(&["<head>application/l", "d+json{\"price\":42}", "tail"]);

        let prefix = Stop::marker("application/ld+json")
            .read(body)
            .await
            .expect("the body must read");

        assert_eq!(prefix.reason(), StopReason::Matched);
        assert_eq!(prefix.bytes(), "<head>application/ld+json");
        assert!(!prefix.is_complete());
    }

    /// The same split, one byte at a time, so the boundary lands at every
    /// possible offset inside the marker instead of only the one a single
    /// fixture picks.
    #[tokio::test]
    async fn a_marker_is_found_wherever_the_boundary_falls_inside_it() {
        let marker = "ld+json";
        let page = "<head>ld+json{}";
        for split in 0..page.len() {
            let (head, tail) = page.split_at(split);
            let chunks: Vec<Result<Bytes>> = vec![
                Ok(Bytes::from_static(head.as_bytes())),
                Ok(Bytes::from_static(tail.as_bytes())),
            ];
            let prefix = Stop::marker(marker)
                .read(Body::stream(stream::iter(chunks), None))
                .await
                .expect("the body must read");
            assert_eq!(
                prefix.reason(),
                StopReason::Matched,
                "a boundary at byte {split} hid the marker"
            );
            assert_eq!(prefix.bytes(), "<head>ld+json", "boundary at byte {split}");
        }
    }

    /// Two chunks is the case the overlap rescan was written for; three is the
    /// case that catches an overlap measured against the last chunk rather than
    /// against everything already buffered.
    #[tokio::test]
    async fn a_marker_spread_over_three_chunks_is_still_found() {
        let prefix = Stop::marker("application/ld+json")
            .read(chunked(&["<head>applicat", "ion/", "ld+json{}"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.reason(), StopReason::Matched);
        assert_eq!(prefix.bytes(), "<head>application/ld+json");
    }

    /// A marker whose first byte repeats inside itself, split at every
    /// boundary. The naive scan restarts past the whole failed candidate and
    /// misses the match that begins inside it.
    #[tokio::test]
    async fn a_marker_that_repeats_its_own_first_byte_is_found_at_every_boundary() {
        let page = "xaaab";
        for split in 0..=page.len() {
            let (head, tail) = page.split_at(split);
            let chunks: Vec<Result<Bytes>> = vec![
                Ok(Bytes::copy_from_slice(head.as_bytes())),
                Ok(Bytes::copy_from_slice(tail.as_bytes())),
            ];
            let prefix = Stop::marker("aab")
                .read(Body::stream(stream::iter(chunks), None))
                .await
                .expect("the body must read");

            assert_eq!(
                prefix.reason(),
                StopReason::Matched,
                "a boundary at byte {split} hid a marker that repeats its first byte"
            );
            assert_eq!(prefix.bytes(), "xaaab", "boundary at byte {split}");
        }
    }

    /// The first chunk is shorter than the marker, so a scan that gives up when
    /// the buffer is too short to hold the needle must not give up for good.
    #[tokio::test]
    async fn a_marker_longer_than_the_first_chunk_is_still_found() {
        let prefix = Stop::marker("application/ld+json")
            .read(chunked(&["<", "h", "ead>application/ld+json tail"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.reason(), StopReason::Matched);
        assert_eq!(prefix.bytes(), "<head>application/ld+json");
    }

    #[tokio::test]
    async fn a_marker_at_the_very_first_byte_is_found() {
        let prefix = Stop::marker("ld+json")
            .read(chunked(&["ld+json{\"price\":42}"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.reason(), StopReason::Matched);
        assert_eq!(prefix.bytes(), "ld+json");
    }

    /// The marker ends on the body's last byte, so the window is empty and the
    /// stream is never polled again.
    #[tokio::test]
    async fn a_marker_in_the_last_two_bytes_is_found() {
        let prefix = Stop::marker("ab")
            .read(chunked(&["xxxx", "xxab"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.reason(), StopReason::Matched);
        assert_eq!(prefix.bytes(), "xxxxxxab");
        assert!(
            !prefix.is_complete(),
            "the stream was never polled to its end, so the connection cannot \
             be trusted however few bytes were left"
        );
    }

    /// An empty marker matches at the front of the first chunk, so the read
    /// stops having consumed nothing.
    ///
    /// The condition is only ever evaluated against bytes that arrived, which
    /// is why the empty body below reports `EndOfBody` instead: there was never
    /// a chunk to scan. Both are asserted together because the difference is
    /// the whole of this edge, and `Stop::marker` says so.
    #[tokio::test]
    async fn an_empty_marker_matches_at_the_front_of_the_first_chunk() {
        let prefix = Stop::marker("")
            .read(chunked(&["abc", "def"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.reason(), StopReason::Matched);
        assert!(prefix.bytes().is_empty());
        assert!(!prefix.is_complete());

        let prefix = Stop::marker("")
            .read(Body::empty())
            .await
            .expect("an empty body must read");

        assert_eq!(
            prefix.reason(),
            StopReason::EndOfBody,
            "a body that never produced a chunk was never scanned, and the read \
             is complete rather than stopped"
        );
        assert!(prefix.bytes().is_empty());
        assert!(prefix.is_complete());
    }

    #[tokio::test]
    async fn a_trailing_window_is_taken_after_the_marker_and_cut_to_length() {
        let body = chunked(&["aaa", "MARKER", "0123456789", "never read"]);

        let prefix = Stop::marker("MARKER")
            .plus(4)
            .read(body)
            .await
            .expect("the body must read");

        assert_eq!(prefix.bytes(), "aaaMARKER0123");
        assert_eq!(prefix.reason(), StopReason::Matched);
    }

    #[tokio::test]
    async fn a_window_the_body_is_too_short_for_still_reports_a_match() {
        let prefix = Stop::marker("MARKER")
            .plus(4096)
            .read(chunked(&["aaaMARKERbb"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.bytes(), "aaaMARKERbb");
        assert_eq!(prefix.reason(), StopReason::Matched);
        assert!(
            prefix.is_complete(),
            "the window ran past the end, so the whole body was read"
        );
    }

    #[tokio::test]
    async fn a_body_without_the_marker_reports_that_rather_than_a_short_read() {
        let prefix = Stop::marker("application/ld+json")
            .read(chunked(&["a page", " with no", " structured data"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.reason(), StopReason::EndOfBody);
        assert!(
            !prefix.matched(),
            "nothing matched, and the caller must know"
        );
        assert!(prefix.is_complete());
        assert_eq!(prefix.bytes(), "a page with no structured data");
    }

    #[tokio::test]
    async fn a_budget_stops_the_read_and_says_the_marker_was_not_found() {
        let prefix = Stop::marker("MARKER")
            .within(8)
            .read(chunked(&["0123456", "789", "MARKER"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.bytes(), "01234567");
        assert_eq!(prefix.reason(), StopReason::Budget);
        assert!(!prefix.is_complete());
    }

    #[tokio::test]
    async fn a_budget_that_cuts_the_window_short_still_reports_the_match() {
        let prefix = Stop::marker("MARKER")
            .plus(1024)
            .within(12)
            .read(chunked(&["aaMARKER", "0123456789"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.bytes(), "aaMARKER0123");
        assert_eq!(
            prefix.reason(),
            StopReason::Matched,
            "the marker was found; only the window was cut short"
        );
    }

    /// The budget is a ceiling on what comes back, and where the socket
    /// happened to split the body may not change the answer.
    ///
    /// One chunk or two, the marker starts at byte 7 and the budget stops the
    /// read at byte 8, so it is not in what was read and the caller must be
    /// told so. Scanning whatever arrived and only then applying the budget
    /// makes the same body report `Matched` or `Budget` depending on the
    /// network.
    #[tokio::test]
    async fn a_marker_past_the_budget_is_not_a_match_however_the_chunks_fall() {
        let page = "0123456MARKER";
        for split in 0..=page.len() {
            let (head, tail) = page.split_at(split);
            let chunks: Vec<Result<Bytes>> = vec![
                Ok(Bytes::copy_from_slice(head.as_bytes())),
                Ok(Bytes::copy_from_slice(tail.as_bytes())),
            ];
            let prefix = Stop::marker("MARKER")
                .within(8)
                .read(Body::stream(stream::iter(chunks), None))
                .await
                .expect("the body must read");

            assert_eq!(prefix.bytes(), "0123456M", "boundary at byte {split}");
            assert_eq!(
                prefix.reason(),
                StopReason::Budget,
                "the marker is past the budget, so a boundary at byte {split} \
                 must not turn it into a match"
            );
        }
    }

    /// `matched()` is the question a scraper asks, so it may never be true of
    /// bytes the marker is not in.
    #[tokio::test]
    async fn a_budget_that_cuts_the_marker_in_half_is_not_a_match() {
        let prefix = Stop::marker("MARKER")
            .plus(1024)
            .within(6)
            .read(chunked(&["aaMARKER0123"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.bytes(), "aaMARK");
        assert!(
            !prefix.matched(),
            "the marker is not in what came back, and a caller that parses on \
             `matched` would parse half a marker"
        );
        assert_eq!(prefix.reason(), StopReason::Budget);
    }

    /// The trailing window is bounded by the budget, whether or not it all
    /// arrived in one chunk. `within` is what a caller compares against its own
    /// ceiling — `Response::bytes_until` passes `max_response_size` through it —
    /// so a prefix longer than the budget is a limit that did not hold.
    #[tokio::test]
    async fn a_trailing_window_never_runs_past_the_budget() {
        let mut page = b"aaMARKER".to_vec();
        page.resize(2048, b'x');
        let chunks: Vec<Result<Bytes>> = vec![Ok(Bytes::from(page))];

        let prefix = Stop::marker("MARKER")
            .plus(1024)
            .within(12)
            .read(Body::stream(stream::iter(chunks), None))
            .await
            .expect("the body must read");

        assert_eq!(prefix.bytes(), "aaMARKERxxxx");
        assert_eq!(prefix.reason(), StopReason::Matched);
    }

    /// The property both of the above are instances of, over every budget and
    /// every chunk boundary this fixture can produce.
    #[tokio::test]
    async fn nothing_read_is_ever_longer_than_the_budget() {
        let page = "aaMARKERbbbbbbbbbb";
        for budget in 0..=20u64 {
            for extra in [0u64, 1, 4, 1024] {
                for split in 0..=page.len() {
                    let (head, tail) = page.split_at(split);
                    let chunks: Vec<Result<Bytes>> = vec![
                        Ok(Bytes::copy_from_slice(head.as_bytes())),
                        Ok(Bytes::copy_from_slice(tail.as_bytes())),
                    ];
                    let prefix = Stop::marker("MARKER")
                        .plus(extra)
                        .within(budget)
                        .read(Body::stream(stream::iter(chunks), None))
                        .await
                        .expect("the body must read");

                    assert!(
                        prefix.bytes().len() as u64 <= budget,
                        "budget {budget}, plus {extra}, boundary at {split} \
                         returned {} bytes",
                        prefix.bytes().len()
                    );
                }
            }
        }
    }

    /// The same body, budget and marker must give the same answer whoever split
    /// the chunks — the reason as well as the bytes.
    #[tokio::test]
    async fn the_outcome_does_not_depend_on_where_the_chunks_fall() {
        let page = "aaMARKERbbbbbbbbbb";
        for budget in 0..=20u64 {
            for extra in [0u64, 1, 4, 1024] {
                let mut outcomes = Vec::new();
                for split in 0..=page.len() {
                    let (head, tail) = page.split_at(split);
                    let chunks: Vec<Result<Bytes>> = vec![
                        Ok(Bytes::copy_from_slice(head.as_bytes())),
                        Ok(Bytes::copy_from_slice(tail.as_bytes())),
                    ];
                    let prefix = Stop::marker("MARKER")
                        .plus(extra)
                        .within(budget)
                        .read(Body::stream(stream::iter(chunks), None))
                        .await
                        .expect("the body must read");
                    outcomes.push((prefix.bytes().clone(), prefix.reason()));
                }
                let first = &outcomes[0];
                for (split, outcome) in outcomes.iter().enumerate() {
                    assert_eq!(
                        outcome, first,
                        "budget {budget}, plus {extra}: a boundary at byte \
                         {split} changed the answer"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn a_bare_budget_reads_a_fixed_prefix_and_nothing_else() {
        let prefix = Stop::after(5)
            .read(chunked(&["0123456789"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.bytes(), "01234");
        assert_eq!(prefix.reason(), StopReason::Budget);
        assert!(!prefix.is_complete());
    }

    #[tokio::test]
    async fn a_budget_larger_than_the_body_reads_all_of_it() {
        let prefix = Stop::after(4096)
            .read(chunked(&["short"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.bytes(), "short");
        assert_eq!(prefix.reason(), StopReason::EndOfBody);
        assert!(prefix.is_complete());
    }

    /// The predicate is handed every byte read so far, which is what removes
    /// the boundary problem for a caller who needs more than a byte marker.
    #[tokio::test]
    async fn a_predicate_sees_the_whole_prefix_and_not_one_chunk() {
        let widest = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&widest);

        let prefix = Stop::when(move |prefix: &[u8]| {
            seen.fetch_max(prefix.len(), std::sync::atomic::Ordering::SeqCst);
            prefix.iter().filter(|byte| **byte == b'{').count() >= 2
        })
        .read(chunked(&["a{b", "c{d", "e{f"]))
        .await
        .expect("the body must read");

        assert_eq!(prefix.reason(), StopReason::Matched);
        assert_eq!(prefix.bytes(), "a{bc{d");
        assert_eq!(
            widest.load(std::sync::atomic::Ordering::SeqCst),
            6,
            "the predicate must be given the accumulated prefix, not the chunk"
        );
    }

    #[tokio::test]
    async fn a_predicate_that_never_fires_reads_to_the_end() {
        let prefix = Stop::when(|_| false)
            .read(chunked(&["one", "two"]))
            .await
            .expect("the body must read");

        assert_eq!(prefix.bytes(), "onetwo");
        assert_eq!(prefix.reason(), StopReason::EndOfBody);
    }

    #[tokio::test]
    async fn a_failing_body_reports_its_error_rather_than_a_short_prefix() {
        let chunks: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"first")),
            Err(Error::Timeout(Phase::ReceiveBody)),
        ];
        let error = Stop::marker("never")
            .read(Body::stream(stream::iter(chunks), None))
            .await
            .expect_err("the body failed");

        assert!(
            matches!(error, Error::Timeout(Phase::ReceiveBody)),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_body_is_a_complete_read_of_nothing() {
        let prefix = Stop::marker("anything")
            .read(Body::empty())
            .await
            .expect("an empty body must read");

        assert!(prefix.bytes().is_empty());
        assert_eq!(prefix.reason(), StopReason::EndOfBody);
        assert!(prefix.is_complete());
    }

    #[test]
    fn a_stop_reports_the_budget_a_caller_has_to_compare_against_its_own() {
        assert_eq!(Stop::marker("x").budget(), None);
        assert_eq!(Stop::marker("x").within(64).budget(), Some(64));
        assert_eq!(Stop::after(64).budget(), Some(64));
    }

    #[test]
    fn find_locates_a_needle_that_repeats_its_own_first_byte() {
        // The naive "first byte then compare, and restart past the whole
        // needle" scan misses this: the match starts inside the failed one.
        assert_eq!(find(b"aaab", b"aab"), Some(1));
        assert_eq!(find(b"abc", b""), Some(0));
        assert_eq!(find(b"ab", b"abc"), None);
        assert_eq!(find(b"", b"a"), None);
        assert_eq!(find(b"xxabc", b"abc"), Some(2));
    }
}
