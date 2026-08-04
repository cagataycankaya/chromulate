//! Where one request spent its time.
//!
//! A caller looking at a slow request needs to know which part was slow before
//! they can do anything about it: a cold DNS answer, an unreachable first
//! address, a TLS handshake against a distant origin and an origin that simply
//! thinks for two seconds all present as "the request took two seconds".
//!
//! The whole toolkit here is [`Instant`]. There is no metrics crate and no
//! exporter behind this type — those are a caller's decision, and every one of
//! them can be built from these numbers.

use std::fmt;
use std::time::{Duration, Instant};

/// Where one logical request spent its time.
///
/// A logical request is what the caller asked for, redirects included, so one
/// `Timings` can describe several network hops. It reports the phases of the
/// **final** hop — the one that produced the response the caller is holding —
/// and folds everything before it into [`Timings::redirect`]. Reporting a sum
/// instead would hide the shape of the chain (four connects averaged together
/// look like one slow connect), and reporting every hop separately would need
/// an allocation per request to hold the list. The final hop is also the one a
/// caller can act on: it is the origin that actually answered.
///
/// # Phases that did not happen report `None`
///
/// [`Timings::resolve`], [`Timings::connect`] and [`Timings::handshake`] are
/// `Option<Duration>` rather than `Duration`. A request served from a pooled
/// connection performs none of them, and a plaintext origin performs no
/// handshake; `Some(Duration::ZERO)` there would read as "the handshake was
/// instant" when the truth is that there was no handshake to time.
///
/// # Everything is measured from the start of the request
///
/// [`Timings::redirect`], [`Timings::head`] and [`Timings::elapsed`] all count
/// from the moment the logical request began, so they compare directly:
/// `redirect <= head <= elapsed()`. The final hop's own time to a response head
/// is `head - redirect`.
///
/// # Time to body complete
///
/// A body is a stream, and a stream ends when the caller stops reading it — on
/// a `Content-Length` response that is when the last byte arrives, but on a
/// chunked or early-dropped body it is not. Only the caller knows that moment,
/// so it is read rather than stored: [`Timings::elapsed`] called once the body
/// is finished *is* the time to body complete. Storing it instead would mean
/// sharing a cell between the response and its body, which costs a heap
/// allocation on every request — more than the measurement is worth.
///
/// ```
/// use chromulate_core::Timings;
///
/// let timings = Timings::starting_now();
///
/// // Nothing was recorded, which is what a request served entirely from the
/// // connection pool looks like.
/// assert!(timings.resolve().is_none());
/// assert!(timings.handshake().is_none());
/// assert!(timings.elapsed() >= timings.head());
/// ```
#[derive(Clone, Copy)]
pub struct Timings {
    /// When the logical request began. Every reported duration counts from
    /// here, which is what makes them comparable to one another.
    started: Instant,
    redirect: Duration,
    resolve: Option<Duration>,
    connect: Option<Duration>,
    handshake: Option<Duration>,
    head: Duration,
}

impl Timings {
    /// Starts the clock for a logical request.
    #[must_use]
    pub fn starting_now() -> Self {
        Self {
            started: Instant::now(),
            redirect: Duration::ZERO,
            resolve: None,
            connect: None,
            handshake: None,
            head: Duration::ZERO,
        }
    }

    /// Marks the start of a hop, making every hop before it redirect time.
    ///
    /// This clears the connection phases as well as stamping the boundary. A
    /// redirect chain can open a connection on its first hop and then be served
    /// from the pool on its second, and carrying the first hop's handshake into
    /// the second hop's report would attribute work to a hop that never did it.
    pub fn record_hop_start(&mut self) {
        self.redirect = self.elapsed();
        self.resolve = None;
        self.connect = None;
        self.handshake = None;
    }

    /// Records how long resolving the hostname took.
    pub fn record_resolve(&mut self, elapsed: Duration) {
        self.resolve = Some(elapsed);
    }

    /// Records how long establishing the transport took.
    pub fn record_connect(&mut self, elapsed: Duration) {
        self.connect = Some(elapsed);
    }

    /// Records how long the TLS handshake took.
    pub fn record_handshake(&mut self, elapsed: Duration) {
        self.handshake = Some(elapsed);
    }

    /// Marks the arrival of the response head.
    pub fn record_head(&mut self) {
        self.head = self.elapsed();
    }

    /// How long resolving the final hop's hostname took.
    ///
    /// `None` when the hop reused a pooled connection, or when a proxy resolved
    /// the name on the client's behalf.
    #[must_use]
    pub fn resolve(&self) -> Option<Duration> {
        self.resolve
    }

    /// How long opening the final hop's transport took, proxy tunnel included.
    ///
    /// `None` when the hop reused a pooled connection.
    #[must_use]
    pub fn connect(&self) -> Option<Duration> {
        self.connect
    }

    /// How long the final hop's TLS handshake took.
    ///
    /// `None` when the hop reused a pooled connection or spoke plaintext. This
    /// covers the TLS handshake alone; the HTTP/2 preface exchange that follows
    /// it is counted in [`Timings::head`] along with the rest of the hop.
    #[must_use]
    pub fn handshake(&self) -> Option<Duration> {
        self.handshake
    }

    /// How long every hop before the final one took, from the start of the
    /// request.
    ///
    /// [`Duration::ZERO`] when no redirect was followed.
    #[must_use]
    pub fn redirect(&self) -> Duration {
        self.redirect
    }

    /// How long the response head took to arrive, from the start of the
    /// request.
    ///
    /// Redirect hops are included, so `head - redirect` is the final hop's own
    /// time to a response head.
    #[must_use]
    pub fn head(&self) -> Duration {
        self.head
    }

    /// How long ago the request began.
    ///
    /// Read once the response body is finished, this is the time to body
    /// complete; see the type documentation for why it is read rather than
    /// stored.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        Instant::now().saturating_duration_since(self.started)
    }
}

impl fmt::Debug for Timings {
    /// Prints the durations rather than the `Instant` they are measured from,
    /// which is an opaque platform value that says nothing on its own.
    ///
    /// `elapsed` is read as this runs, so printing a `Timings` after the body
    /// has been read shows the whole request.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Timings")
            .field("resolve", &self.resolve)
            .field("connect", &self.connect)
            .field("handshake", &self.handshake)
            .field("redirect", &self.redirect)
            .field("head", &self.head)
            .field("elapsed", &self.elapsed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_record_has_performed_no_phases() {
        let timings = Timings::starting_now();

        assert_eq!(timings.resolve(), None);
        assert_eq!(timings.connect(), None);
        assert_eq!(timings.handshake(), None);
        assert_eq!(timings.redirect(), Duration::ZERO);
        assert_eq!(timings.head(), Duration::ZERO);
    }

    #[test]
    fn the_phases_are_reported_as_they_were_recorded() {
        let mut timings = Timings::starting_now();
        timings.record_resolve(Duration::from_millis(3));
        timings.record_connect(Duration::from_millis(11));
        timings.record_handshake(Duration::from_millis(40));

        assert_eq!(timings.resolve(), Some(Duration::from_millis(3)));
        assert_eq!(timings.connect(), Some(Duration::from_millis(11)));
        assert_eq!(timings.handshake(), Some(Duration::from_millis(40)));
    }

    #[test]
    fn a_new_hop_drops_the_previous_hops_connection_phases() {
        // The sharp case: hop one opens a connection, hop two is served from
        // the pool. Reporting hop one's handshake against hop two would claim a
        // handshake happened on a request that never made one.
        let mut timings = Timings::starting_now();
        timings.record_resolve(Duration::from_millis(3));
        timings.record_connect(Duration::from_millis(11));
        timings.record_handshake(Duration::from_millis(40));

        timings.record_hop_start();

        assert_eq!(timings.resolve(), None);
        assert_eq!(timings.connect(), None);
        assert_eq!(timings.handshake(), None);
    }

    #[test]
    fn a_hop_boundary_becomes_redirect_time() {
        let mut timings = Timings::starting_now();
        assert_eq!(timings.redirect(), Duration::ZERO);

        std::thread::sleep(Duration::from_millis(20));
        timings.record_hop_start();

        assert!(
            timings.redirect() >= Duration::from_millis(20),
            "everything before the final hop is redirect time: {:?}",
            timings.redirect()
        );
    }

    #[test]
    fn the_milestones_are_ordered_because_they_share_one_origin() {
        let mut timings = Timings::starting_now();
        std::thread::sleep(Duration::from_millis(10));
        timings.record_hop_start();
        std::thread::sleep(Duration::from_millis(10));
        timings.record_head();

        assert!(
            timings.redirect() <= timings.head(),
            "{:?} then {:?}",
            timings.redirect(),
            timings.head()
        );
        assert!(
            timings.head() <= timings.elapsed(),
            "{:?} then {:?}",
            timings.head(),
            timings.elapsed()
        );
        assert!(
            timings.head() - timings.redirect() >= Duration::from_millis(10),
            "the final hop's own time to head is head - redirect"
        );
    }

    #[test]
    fn elapsed_keeps_growing_after_the_head_because_the_body_is_still_arriving() {
        let mut timings = Timings::starting_now();
        timings.record_head();
        let head = timings.head();
        let at_head = timings.elapsed();

        std::thread::sleep(Duration::from_millis(20));

        // This is the time to body complete: the head is fixed, `elapsed` is not.
        assert!(
            timings.elapsed() >= at_head + Duration::from_millis(20),
            "elapsed must keep counting while the body streams"
        );
        assert_eq!(timings.head(), head, "the head milestone must not move");
    }

    #[test]
    fn the_debug_output_names_the_phases_rather_than_an_opaque_instant() {
        let mut timings = Timings::starting_now();
        timings.record_connect(Duration::from_millis(7));

        let printed = format!("{timings:?}");
        for phase in [
            "resolve",
            "connect",
            "handshake",
            "redirect",
            "head",
            "elapsed",
        ] {
            assert!(printed.contains(phase), "{printed}");
        }
    }
}
