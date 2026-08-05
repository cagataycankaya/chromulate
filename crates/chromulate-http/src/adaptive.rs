//! Per-origin concurrency, discovered from what an origin is comfortable
//! serving.
//!
//! # Why a fixed number is wrong
//!
//! Issued on one HTTP/2 connection, with `bytes_until` stopping at a product
//! marker, four Turkish marketplaces answered like this — one request in flight
//! against eight, zero errors throughout:
//!
//! | origin | 1 in flight | 8 in flight, per request | ratio |
//! | --- | --- | --- | --- |
//! | hepsiburada.com | 57 ms | 11 ms | 5.2x |
//! | trendyol.com | 409 ms | 63 ms | 6.5x |
//! | mediamarkt.com.tr | 61 ms | 16 ms | 3.8x |
//! | pazarama.com | 73 ms | 25 ms | 2.9x |
//!
//! The ratios differ because the origins saturate at different points:
//! pazarama's *total* went from 73 ms to 202 ms for eight times the work, so it
//! is already past its knee at eight, while hepsiburada is still close to
//! linear. One number cannot be right for both, which is what this module is
//! for.
//!
//! # What this is not
//!
//! This is not a way to find a rate that slips under a control, and it must
//! never become one. It treats the origin as the authority on its own limits:
//! it reads what a server signals and stays *under* it. Nothing here varies a
//! profile, a fingerprint, a header set or an identity in response to a status
//! code, and nothing here retries a refusal. See the scope boundary in
//! `CLAUDE.md`.
//!
//! # The control law
//!
//! **Latency is the primary signal.** Congestion shows up as a rising response
//! time long before an origin decides to refuse anyone, so a controller that
//! waits for a status code to stop its ramp has already been too slow. Classic
//! additive-increase/multiplicative-decrease *finds* the limit by hitting it,
//! which would mean earning a `429` on every origin periodically, forever. That
//! is the opposite of the goal.
//!
//! So the sawtooth runs on latency, where overshooting costs milliseconds, and
//! a refusal is a one-way ratchet, where overshooting costs the crawl:
//!
//! - **Increase** — one slot, after [`ConcurrencyConfig::clean_probes_before_increase`]
//!   consecutive clean probes of [`ConcurrencyConfig::probe`] healthy responses
//!   each (20 responses by default). Every one of the conditions in
//!   [`AdaptiveConcurrency`]'s *Increase rule* must hold.
//! - **Decrease on latency** — halve, immediately, the moment one probe's mean
//!   exceeds the baseline by [`ConcurrencyConfig::degradation`]. Transient: the
//!   ceiling is untouched, because a slow origin may be slow for reasons that
//!   have nothing to do with this client.
//! - **Decrease on a refusal** — a `429` or `503` lowers the origin's *ceiling*
//!   to half the level that earned it, permanently, for as long as the entry
//!   lives. The controller never approaches that level again. Re-probing a
//!   level known to refuse is choosing to be refused on a schedule.
//! - **A `403` is not a rate signal.** It is a refusal. The limit freezes where
//!   it is, the origin is flagged, and the caller decides. Nothing backs off
//!   into it, retries it, or changes anything about the request to get a
//!   different answer.
//!
//! # Which of those are this law's opinion, and what to do about it
//!
//! All of them. They were chosen for one workload — a crawl that must not earn
//! `429`s — and a caller with a different one may disagree. One of those
//! disagreements is answered here, one is deliberately refused, and everything
//! else is answered by the seam:
//!
//! - the permanent ceiling is opt-out, through
//!   [`AdaptiveConcurrency::with_ceiling_recovery`], which is off by default and
//!   turns the ratchet into classic AIMD when it is on;
//! - the `403` freeze is not configurable, because the knob would be "keep
//!   ramping against an origin that has refused you" and that is outside this
//!   project's scope. [`AdaptiveConcurrency::forget`] is how a caller who has
//!   dealt with a refusal says so;
//! - anything else — a different signal, a different ramp, no learning at all —
//!   is a [`crate::concurrency::ConcurrencyController`] of the caller's own.
//!   That trait is the seam, and this module is one implementation behind it.
//!
//! # A new origin
//!
//! The first request to an origin this process has not seen goes out at
//! [`ConcurrencyConfig::min`] — one, by default — and the limit cannot move
//! until a latency baseline exists, which takes one completed probe. The
//! earliest an origin's second slot can be granted is therefore after
//! `probe * (clean_probes_before_increase + 1)` healthy responses: 25, with the
//! defaults. That is deliberately boring. Being one slot too slow costs a few
//! milliseconds; being one slot too fast costs a block.
//!
//! # What this cannot promise
//!
//! **It cannot guarantee zero `429`s.** An origin's threshold can change
//! between one request and the next, it is frequently shared with every other
//! client behind the same address, and it may not be a function of concurrency
//! at all — a per-day quota answers `429` to the politest possible client. What
//! this can promise is narrower and is the whole design: the controller never
//! *chooses* to find a limit by hitting it, and it never returns to a level
//! that has already been refused.

use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant, SystemTime};

use chromulate_core::BoxFuture;
use http::header::{DATE, RETRY_AFTER};
use http::{HeaderMap, StatusCode};
use tokio::sync::Notify;
use url::{Position, Url};

pub use crate::concurrency::Ceiling;
use crate::concurrency::{ConcurrencyController, Lease, Outcome};
use crate::time::TimeSource;

/// How many origins a controller remembers before evicting.
///
/// The key is an authority chosen by the servers a crawl visits rather than by
/// the caller, so this pairs a capacity with an eviction policy exactly as
/// [`crate::hsts::HstsStore`], [`crate::validators::ValidatorStore`] and the
/// `AltSvcCache` do. 4,096 matches `ValidatorStore` rather than `HstsStore`'s
/// 10,000 because an entry here is fatter — it carries the latency state — and
/// because a single crawl talking to four thousand distinct authorities at once
/// is already extraordinary.
pub const DEFAULT_ORIGIN_CAPACITY: usize = 4_096;

/// How fast the latency baseline may drift upwards, per clean probe.
///
/// The baseline follows a *faster* origin immediately and a slower one at five
/// percent per probe. Without the upward drift an origin that is simply slower
/// this afternoon than it was this morning would read as permanently degraded
/// and be driven to [`ConcurrencyConfig::min`] forever; with it, a genuine step
/// change is re-learned in about fifteen probes, while an origin whose latency
/// is still climbing outruns the drift and keeps being cut. Five percent is the
/// smallest round number that re-learns a doubling inside a crawl.
const BASELINE_DRIFT: f64 = 1.05;

/// How far above the baseline a probe must be before the ratio is consulted.
///
/// A ratio on its own is unusable at the fast end. An origin answering in 40 µs
/// — a loopback server, a cached response, an HTTP/2 stream on a warm
/// connection — has a baseline of 40 µs, and
/// [`ConcurrencyConfig::degradation`] then calls 80 µs a degradation. That is
/// scheduler noise, not congestion, and a controller reading it as congestion
/// halves itself over nothing and never recovers, because the next probe is
/// noisy too. A probe must clear *both* the ratio and this absolute margin, so
/// below a few milliseconds of movement there is no verdict to get wrong.
///
/// Five milliseconds is well under the 11 ms the fastest origin in the table
/// above managed, so nothing this is meant to detect hides beneath it.
const DEGRADATION_FLOOR: Duration = Duration::from_millis(5);

/// The knobs, all of them with a low default.
///
/// Discovering that an origin will serve sixty-four concurrent requests is not
/// permission to send sixty-four.
///
/// The fields are public and the struct is exhaustive, matching
/// [`crate::middleware::RetryPolicy`] and [`crate::middleware::RateLimit`]: a
/// caller writes `ConcurrencyConfig { max: 2, ..Default::default() }`. Public
/// fields mean values reach the controller without passing any constructor, so
/// [`ConcurrencyConfig::sanitised`] is the one funnel every configuration goes
/// through — the same arrangement, for the same reason, as `RateLimiter`'s.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConcurrencyConfig {
    /// The floor, and the level a never-seen origin starts at.
    pub min: usize,
    /// The ceiling, whatever an origin turns out to tolerate.
    ///
    /// Six by default, which is the number of connections Chrome opens to one
    /// host over HTTP/1.1 and the number this workspace's pool keeps idle per
    /// key. A browser-shaped default for a library whose purpose is to be
    /// browser-shaped.
    pub max: usize,
    /// Healthy responses per latency verdict.
    pub probe: usize,
    /// Consecutive clean probes before one slot is added.
    pub clean_probes_before_increase: u32,
    /// How far a probe's mean may exceed the baseline before it counts as
    /// degraded.
    pub degradation: f64,
    /// How long after any decrease the limit may not increase.
    pub hold: Duration,
    /// The pause after a refusal that sent no `Retry-After`, doubled for each
    /// consecutive refusal.
    pub cooldown: Duration,
    /// The ceiling on that doubling.
    pub max_cooldown: Duration,
    /// The longest pause a `Retry-After` can buy.
    ///
    /// A server-controlled value is unbounded, and a client that sleeps for the
    /// hundred years one of them asked for is a hang rather than an obedient
    /// client. The requested value is kept verbatim in
    /// [`OriginSnapshot::retry_after_requested`] so a caller who wants to honour
    /// something longer can stop scheduling that origin itself.
    pub max_pause: Duration,
    /// How many origins are remembered. See [`DEFAULT_ORIGIN_CAPACITY`].
    pub capacity: usize,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            min: 1,
            max: 6,
            probe: 5,
            clean_probes_before_increase: 4,
            degradation: 2.0,
            hold: Duration::from_secs(30),
            cooldown: Duration::from_secs(5),
            max_cooldown: Duration::from_secs(300),
            max_pause: Duration::from_secs(3600),
            capacity: DEFAULT_ORIGIN_CAPACITY,
        }
    }
}

impl ConcurrencyConfig {
    /// The configuration with every field forced into a range it can be used
    /// in.
    ///
    /// Clamping rather than panicking, for the reason `RateLimiter` gives: the
    /// fields are public, a misconfigured controller that runs slowly is a bug
    /// the caller can see and fix, and a panic is one that takes their process
    /// with it. A capacity of zero becomes one, because a store that cannot hold
    /// the entry it was just handed is a disabled feature rather than a small
    /// one.
    #[must_use]
    pub fn sanitised(self) -> Self {
        let min = self.min.max(1);
        Self {
            min,
            max: self.max.max(min),
            probe: self.probe.max(1),
            clean_probes_before_increase: self.clean_probes_before_increase.max(1),
            degradation: if self.degradation.is_finite() && self.degradation > 1.0 {
                self.degradation
            } else {
                2.0
            },
            hold: self.hold,
            cooldown: self.cooldown,
            max_cooldown: self.max_cooldown.max(self.cooldown),
            // A day. The field is public, so `Duration::MAX` reaches this, and
            // an unclamped pause of `Duration::MAX` is not a long wait but a
            // dropped one: `Instant::checked_add` returns `None` and the pause
            // vanishes. Clamping here is what keeps `deadline` total by
            // construction rather than by hope.
            max_pause: self.max_pause.min(Duration::from_secs(86_400)),
            capacity: self.capacity.max(1),
        }
    }

    /// How far a purge drops the store below [`ConcurrencyConfig::capacity`].
    ///
    /// A batch rather than one entry, so a store under sustained pressure pays
    /// the eviction scan once per batch instead of once per insert — the same
    /// amortisation, and the same reasoning, as
    /// `chromulate_cookie::JarLimits::purge_batch`.
    fn purge_batch(&self) -> usize {
        (self.capacity / 16).max(1)
    }

    fn purge_target(&self) -> usize {
        self.capacity.saturating_sub(self.purge_batch()).max(1)
    }
}

/// What one completed request told the controller.
///
/// [`Signal::from_response`] is the mapping the engine uses; the variants are
/// public so a caller who knows more than a status code can say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signal {
    /// The origin served the request. The only signal that carries a latency
    /// sample and the only one that can lead to an increase.
    Healthy,
    /// The origin answered, but not with something worth learning a latency
    /// from — a `500` is usually a fast failure, and letting it into the
    /// baseline makes every later real response look degraded.
    ///
    /// Returns the slot and resets the clean-probe run. It is not evidence of
    /// health.
    Neutral,
    /// The origin asked for less: a `429` or a `503`.
    Backpressure {
        /// What `Retry-After` asked for, if it was present and parsed.
        retry_after: Option<Duration>,
    },
    /// The origin refused: a `403`.
    ///
    /// Not a rate signal, and never treated as one.
    Refused,
    /// The request did not produce a status at all.
    ///
    /// Neutral for the limit. A transport failure may be the origin shedding
    /// load or may be this host's network, and the controller cannot tell which,
    /// so it declines to read a verdict into it. It does reset the clean-probe
    /// run, because it is not evidence of health either.
    Failed,
}

impl Signal {
    /// The mapping from a status code, with no headers to read.
    ///
    /// ```
    /// use chromulate_http::adaptive::Signal;
    /// use http::StatusCode;
    ///
    /// assert_eq!(Signal::from_status(StatusCode::OK), Signal::Healthy);
    /// assert_eq!(Signal::from_status(StatusCode::NOT_FOUND), Signal::Healthy);
    /// assert_eq!(Signal::from_status(StatusCode::FORBIDDEN), Signal::Refused);
    /// assert!(matches!(
    ///     Signal::from_status(StatusCode::TOO_MANY_REQUESTS),
    ///     Signal::Backpressure { .. }
    /// ));
    /// ```
    #[must_use]
    pub fn from_status(status: StatusCode) -> Self {
        match status {
            StatusCode::FORBIDDEN => Self::Refused,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                Self::Backpressure { retry_after: None }
            }
            // A `500`, `502` or `504` is an answer, but not one to time. Every
            // other status — including a `404` — is a request the origin served
            // in full, which is exactly what a latency sample should measure.
            other if other.is_server_error() => Self::Neutral,
            _ => Self::Healthy,
        }
    }

    /// The mapping from a whole response, so `Retry-After` is read.
    ///
    /// `now` is the client's wall clock, used only when the `Retry-After` is in
    /// its `HTTP-date` form *and* the response carried no `Date` header of its
    /// own. See [`retry_after_delay`].
    #[must_use]
    pub fn from_response<T>(response: &http::Response<T>, now: SystemTime) -> Self {
        match Self::from_status(response.status()) {
            Self::Backpressure { .. } => Self::Backpressure {
                retry_after: retry_after_delay(response.headers(), now),
            },
            other => other,
        }
    }
}

/// What an origin's entry looks like from outside.
///
/// A snapshot rather than a handle: reading it takes the entry's lock once and
/// copies, so nothing a caller does with it can hold up a request.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct OriginSnapshot {
    /// Slots the controller will currently grant.
    pub limit: usize,
    /// Slots granted and not yet returned.
    pub in_flight: usize,
    /// The most slots this origin may ever be granted again.
    ///
    /// Starts at [`ConcurrencyConfig::max`] and falls on a `429` or `503`. It
    /// rises again only for a caller who asked for that with
    /// [`AdaptiveConcurrency::with_ceiling_recovery`], and then only on a clean
    /// probe, so a snapshot taken while an origin is idle reports the ceiling as
    /// it stood at the last probe rather than as it would be if one ran now.
    pub ceiling: usize,
    /// The latency this origin is measured against, once one probe has
    /// completed.
    pub baseline: Option<Duration>,
    /// Whether this origin has answered `403`.
    ///
    /// The limit is frozen while this is set. Nothing in this module clears it;
    /// [`AdaptiveConcurrency::forget`] is how a caller who has dealt with the
    /// refusal says so.
    pub refused: bool,
    /// How much of an asked-for pause is left.
    pub paused_for: Option<Duration>,
    /// The last `Retry-After` this origin asked for, before
    /// [`ConcurrencyConfig::max_pause`] clamped it.
    pub retry_after_requested: Option<Duration>,
    /// How many refusals this origin has produced.
    pub refusals: u32,
    /// Clean probes since the last increase or decrease.
    pub clean_probes: u32,
}

/// The mutable half of one origin's entry.
#[derive(Debug)]
struct Origin {
    limit: usize,
    in_flight: usize,
    ceiling: usize,
    baseline: Option<Duration>,
    /// Healthy latencies in the probe under way, and how many.
    probe_total: Duration,
    probe_samples: usize,
    clean_probes: u32,
    /// Whether any permit since the last verdict had to queue for a slot.
    saturated: bool,
    refused: bool,
    refusals: u32,
    retry_after_requested: Option<Duration>,
    /// No permit is granted before this.
    resume_at: Option<Instant>,
    /// The limit may not increase before this.
    hold_until: Option<Instant>,
    /// When the ceiling last moved, or `None` while it stands at
    /// [`ConcurrencyConfig::max`] and has nothing to recover from.
    ///
    /// Read only when a caller opted into
    /// [`AdaptiveConcurrency::with_ceiling_recovery`]; without that it is
    /// written by a refusal and never looked at again.
    ceiling_since: Option<Instant>,
}

impl Origin {
    fn new(config: &ConcurrencyConfig) -> Self {
        Self {
            limit: config.min,
            in_flight: 0,
            ceiling: config.max,
            baseline: None,
            probe_total: Duration::ZERO,
            probe_samples: 0,
            clean_probes: 0,
            saturated: false,
            refused: false,
            refusals: 0,
            retry_after_requested: None,
            resume_at: None,
            hold_until: None,
            ceiling_since: None,
        }
    }

    /// Whether this entry has learned something eviction should not throw away.
    fn has_lesson(&self, config: &ConcurrencyConfig) -> bool {
        self.refused || self.ceiling < config.max
    }

    /// Throws away the probe under way and the run of clean probes behind it.
    ///
    /// Anything that is not a healthy response breaks the run: the evidence an
    /// increase rests on is *consecutive* clean probes, and a run with a `500`
    /// in the middle of it is not one.
    fn abandon_probe(&mut self) {
        self.probe_total = Duration::ZERO;
        self.probe_samples = 0;
        self.clean_probes = 0;
    }

    /// Throws away the evidence, saturation included, because the limit moved.
    ///
    /// Saturation survives an abandoned probe but not a change of limit. It
    /// answers "is *this* limit the binding constraint", and the moment the
    /// limit changes that question has not been asked yet.
    fn limit_changed(&mut self) {
        self.abandon_probe();
        self.saturated = false;
    }
}

/// One origin's entry: a lock around its state, and a way to wake whoever is
/// waiting for a slot.
///
/// There is a `Mutex` here and `CLAUDE.md` is right to ask why. The decision a
/// permit makes — compare the count against the limit, then take a slot — is not
/// a decision two callers may interleave, so it is one critical section with no
/// `await` in it, exactly as `RateLimiter::reserve` is. The lock is per origin
/// rather than global, so two origins never contend, and it is taken twice per
/// request against a network round trip.
#[derive(Debug)]
struct OriginState {
    inner: Mutex<Origin>,
    slot: Notify,
    /// Ticks on use, so eviction can rank by recency without a clock.
    ///
    /// A counter rather than an `Instant` for the reason `ValidatorStore` gives:
    /// `Instant + Duration` panics on overflow and this module handles
    /// server-controlled input, while `fetch_add` wraps.
    last_use_seq: AtomicU64,
}

impl OriginState {
    fn new(config: &ConcurrencyConfig, seq: u64) -> Self {
        Self {
            inner: Mutex::new(Origin::new(config)),
            slot: Notify::new(),
            last_use_seq: AtomicU64::new(seq),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Origin> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// How much of an asked-for pause is left at `now`.
    fn pause_remaining(&self, now: Instant) -> Duration {
        self.lock()
            .resume_at
            .map_or(Duration::ZERO, |at| at.saturating_duration_since(now))
    }

    /// Takes a slot, waiting for one if every slot is busy.
    ///
    /// Returns whether it had to wait, which is the evidence an increase needs:
    /// a limit nobody queued behind is not the binding constraint, so adding to
    /// it would be adding capacity nothing asked for.
    async fn take_slot(&self) -> bool {
        let mut waited = false;
        loop {
            if self.try_take_slot(waited) {
                return waited;
            }
            waited = true;

            // Registered before the second check and awaited after it, so a
            // release landing between the two cannot be missed. `notify_waiters`
            // only wakes what is already registered.
            let notified = self.slot.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if self.try_take_slot(waited) {
                return waited;
            }
            notified.await;
        }
    }

    /// Takes a slot if one is free, recording that the limit was binding when
    /// this caller had to queue for it.
    fn try_take_slot(&self, waited: bool) -> bool {
        let mut origin = self.lock();
        if origin.in_flight < origin.limit {
            origin.in_flight += 1;
            if waited {
                origin.saturated = true;
            }
            true
        } else {
            false
        }
    }
}

/// Multiplies a duration by a factor without panicking.
///
/// `Duration::mul_f64` panics on a non-finite factor and on overflow, and both
/// arms are reachable here: the factor comes from a public config field and the
/// duration is measured between two instants a caller's clock produced.
fn scale(duration: Duration, factor: f64) -> Duration {
    Duration::try_from_secs_f64(duration.as_secs_f64() * factor).unwrap_or(Duration::MAX)
}

/// Reads `Retry-After` in both of its forms.
///
/// The delta-seconds form is taken at face value. The `HTTP-date` form is
/// resolved against the response's *own* `Date` header when it sent one, so both
/// ends of the subtraction come from the server's clock and skew between the two
/// machines cannot change the answer; `now` is the fallback for a response that
/// carried no `Date`. A date already in the past yields
/// [`Duration::ZERO`] rather than an error, which is what a server that is
/// already ready to be talked to again is saying.
///
/// [`crate::middleware::retry::parse_retry_after`] deliberately reads only the
/// delta-seconds form, because it has no `Date` header to hand and refuses to
/// trust one clock against another. Having one, this does not have that problem.
///
/// ```
/// use std::time::{Duration, SystemTime};
///
/// use chromulate_http::adaptive::retry_after_delay;
/// use http::HeaderMap;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("retry-after", "120".parse().unwrap());
/// assert_eq!(
///     retry_after_delay(&headers, SystemTime::UNIX_EPOCH),
///     Some(Duration::from_secs(120)),
/// );
///
/// // The date form, resolved against the response's own `Date`.
/// let mut headers = HeaderMap::new();
/// headers.insert("date", "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap());
/// headers.insert("retry-after", "Sun, 06 Nov 1994 08:59:37 GMT".parse().unwrap());
/// assert_eq!(
///     retry_after_delay(&headers, SystemTime::UNIX_EPOCH),
///     Some(Duration::from_secs(600)),
/// );
/// ```
#[must_use]
pub fn retry_after_delay(headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let target = http_date(value)?;
    let from = headers
        .get(DATE)
        .and_then(|date| date.to_str().ok())
        .and_then(http_date)
        .unwrap_or(now);
    // `Err` means the date is in the past, which is not an error here.
    Some(target.duration_since(from).unwrap_or(Duration::ZERO))
}

mod date;
use date::http_date;

/// Takes a permit from a controller the caller may not have installed.
///
/// This and [`complete_from`] are the concrete pair, for a caller driving
/// *this* controller: one line before the request and one after, the same two
/// lines whether or not a controller is configured, and no boxing either side.
/// The engine wires in [`crate::concurrency::acquire_from`] instead, because it
/// holds whatever controller the caller installed rather than this one.
///
/// ```
/// use chromulate_http::adaptive::{self, AdaptiveConcurrency, Ceiling};
/// use url::Url;
///
/// # async fn run() {
/// let installed = Some(AdaptiveConcurrency::new(Ceiling::Unlimited));
/// let url = Url::parse("https://example.com/").unwrap();
///
/// let permit = adaptive::acquire_from(installed.as_ref(), &url).await;
/// assert!(permit.is_some());
///
/// // And with nothing configured, the same line costs nothing.
/// assert!(adaptive::acquire_from(None, &url).await.is_none());
/// # }
/// ```
pub async fn acquire_from(controller: Option<&AdaptiveConcurrency>, url: &Url) -> Option<Permit> {
    match controller {
        Some(controller) => Some(controller.acquire(url).await),
        None => None,
    }
}

/// Reports a response against a permit the caller may not have taken.
///
/// The counterpart to [`acquire_from`], and the same concrete pair rather than
/// the erased one. `Retry-After` is only read when the status is one that
/// carries it, so an ordinary response never pays for the wall-clock read that
/// resolving its `HTTP-date` form needs.
///
/// A request that produced no response at all reports nothing: dropping the
/// `Option<Permit>` returns the slot without teaching the controller a verdict,
/// which is the right answer when a transport failure could equally be this
/// host's network. A caller that knows better can say so with
/// [`Permit::complete`] and [`Signal::Failed`].
pub fn complete_from<T>(permit: Option<Permit>, response: &http::Response<T>) {
    let Some(permit) = permit else {
        return;
    };
    let signal = match Signal::from_status(response.status()) {
        Signal::Backpressure { .. } => Signal::Backpressure {
            retry_after: retry_after_delay(response.headers(), SystemTime::now()),
        },
        other => other,
    };
    permit.complete(signal);
}

/// A slot on an origin, held for the length of one request.
///
/// Dropping one returns the slot without teaching the controller anything.
/// [`Permit::complete`] returns it *and* reports what happened, which is the
/// only way the limit ever moves.
#[derive(Debug)]
pub struct Permit {
    shared: Arc<Shared>,
    state: Arc<OriginState>,
    started: Instant,
    waited: bool,
    reported: bool,
}

impl Permit {
    /// Returns the slot and tells the controller what the origin did.
    pub fn complete(mut self, signal: Signal) {
        let now = self.shared.time.now();
        let latency = now.saturating_duration_since(self.started);
        self.reported = true;
        release(&self.state, &self.shared, now, latency, Some(signal));
    }

    /// Whether this permit had to queue for its slot.
    #[must_use]
    pub fn waited_for_a_slot(&self) -> bool {
        self.waited
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if self.reported {
            return;
        }
        // A permit dropped without a report — a cancelled request, a panic
        // unwinding past it — must still return its slot, or the origin leaks
        // capacity until its entry is evicted. It reports no signal, because
        // nobody observed one.
        let now = self.shared.time.now();
        let latency = now.saturating_duration_since(self.started);
        release(&self.state, &self.shared, now, latency, None);
    }
}

/// Reports an [`Outcome`] from the seam as the [`Signal`] this law speaks.
///
/// The seam deliberately carries no verdict, so this is where one is reached —
/// in the implementation whose opinion it is, rather than in the type every
/// other implementation also has to use. `SystemTime::now` is read only for a
/// status that can carry a `Retry-After`, so an ordinary response never pays for
/// a wall-clock read.
impl Lease for Permit {
    fn complete(self: Box<Self>, outcome: &Outcome<'_>) {
        let signal = match outcome.status() {
            Some(status) => match Signal::from_status(status) {
                Signal::Backpressure { .. } => Signal::Backpressure {
                    retry_after: outcome
                        .headers()
                        .and_then(|headers| retry_after_delay(headers, SystemTime::now())),
                },
                other => other,
            },
            None => Signal::Failed,
        };
        Permit::complete(*self, signal);
    }
}

/// Returns a slot and applies whatever the outcome taught, then wakes a waiter.
fn release(
    state: &OriginState,
    shared: &Shared,
    now: Instant,
    latency: Duration,
    signal: Option<Signal>,
) {
    {
        let mut origin = state.lock();
        origin.in_flight = origin.in_flight.saturating_sub(1);
        if let Some(signal) = signal {
            apply(&mut origin, shared, now, latency, signal);
        }
    }
    // Outside the lock: a woken waiter takes it immediately.
    state.slot.notify_waiters();
}

/// `now + duration`, without the panic `Instant + Duration` carries.
///
/// No input reaches the fallback. Every duration handed to this has already
/// been clamped — a pause by [`ConcurrencyConfig::max_pause`], itself capped at
/// a day by [`ConcurrencyConfig::sanitised`], and a hold by whatever the caller
/// configured — so an `Instant` close enough to the end of the platform's
/// representable range for a day not to fit would have to exist first, and on
/// no supported platform does one. Mutating this line back to `now + duration`
/// turns no test red, and the honest reading of that is "unreachable", not
/// "guarded". It stays because the partial function's failure mode is a panic
/// in a library, and because this repository has fixed exactly that bug in five
/// files already; the sixth would be written by whoever widens the clamp above,
/// which is precisely when nobody will be looking here.
fn deadline(now: Instant, duration: Duration) -> Instant {
    now.checked_add(duration).unwrap_or(now)
}

/// The pause a refusal that named no `Retry-After` earns.
///
/// Multiplicative in the number of refusals, and capped, so an origin that keeps
/// refusing is asked less and less often without the schedule running away.
fn cooldown(config: &ConcurrencyConfig, refusals: u32) -> Duration {
    let doublings = refusals.saturating_sub(1).min(31);
    config
        .cooldown
        .saturating_mul(2u32.saturating_pow(doublings))
        .min(config.max_cooldown)
}

/// The control law. See the [module documentation](self).
fn apply(origin: &mut Origin, shared: &Shared, now: Instant, latency: Duration, signal: Signal) {
    let config = &shared.config;
    match signal {
        Signal::Healthy => healthy(origin, shared, now, latency),
        // A `403` is a refusal, not a rate signal, and the difference is the
        // whole of this arm. Nothing halves, nothing pauses, nothing is retried
        // and nothing about the next request changes; the flag is raised, the
        // limit freezes where it stands, and the caller decides what a refusal
        // means. Backing off into a `403` would be tuning around a control
        // rather than obeying one — see the scope boundary in `CLAUDE.md`.
        Signal::Refused => {
            origin.refused = true;
            origin.abandon_probe();
        }
        Signal::Backpressure { retry_after } => refuse(origin, config, now, retry_after),
        // Answered, but not evidence of health and not worth timing.
        Signal::Neutral | Signal::Failed => origin.abandon_probe(),
    }
}

/// One healthy response, and the probe verdict it may complete.
fn healthy(origin: &mut Origin, shared: &Shared, now: Instant, latency: Duration) {
    let config = &shared.config;
    origin.probe_total = origin.probe_total.saturating_add(latency);
    origin.probe_samples += 1;
    if origin.probe_samples < config.probe {
        return;
    }

    let samples = u32::try_from(origin.probe_samples).unwrap_or(u32::MAX);
    let mean = origin
        .probe_total
        .checked_div(samples)
        .unwrap_or(Duration::ZERO);
    origin.probe_total = Duration::ZERO;
    origin.probe_samples = 0;

    let Some(baseline) = origin.baseline else {
        // Condition 2. The first probe an origin completes is the thing every
        // later probe is measured against, so it cannot itself be a verdict.
        // This is what a never-seen origin does: one probe at `min`, learning.
        origin.baseline = Some(mean);
        return;
    };

    // Condition 3, computed against the baseline as it stands before this probe
    // is folded into it, and against both thresholds: the ratio, and the
    // absolute margin that keeps the ratio meaningful for a fast origin.
    let threshold =
        scale(baseline, config.degradation).max(baseline.saturating_add(DEGRADATION_FLOOR));
    let degraded = mean > threshold;
    // Follows a faster origin at once and a slower one at `BASELINE_DRIFT` per
    // probe. One expression covers both: when `mean` is the smaller it is
    // already what the `min` returns, so the explicit "snap down" branch this
    // started as was dead code, and mutation is what said so.
    origin.baseline = Some(mean.min(scale(baseline, BASELINE_DRIFT)));

    if degraded {
        // The primary signal. An origin answering `200` while its response time
        // doubles is saying something no status code will, and it is saying it
        // long before it decides to refuse anyone.
        origin.limit = (origin.limit / 2).max(config.min);
        origin.hold_until = Some(deadline(now, config.hold));
        origin.limit_changed();
        return;
    }

    // A clean probe is the only evidence this law accepts that an origin is
    // healthy *now*, which is what a recovering ceiling has to rest on. Off
    // unless the caller asked for it; see `relax_ceiling`.
    relax_ceiling(origin, shared, now);

    // Condition 6, checked before the run is credited rather than after, which
    // is the whole of its effect. A probe landing inside a hold does not count
    // towards the next increase at all: banking evidence while the controller
    // has been told to wait, and cashing all of it the instant the hold ends,
    // makes a hold cost time but not patience. Recovery after a decrease
    // therefore needs a run gathered *after* the hold, which is what makes it
    // strictly slower than the decrease that caused it. The decrease already
    // reset the run and nothing credits it while the hold stands, so there is
    // deliberately nothing to clear here.
    if origin.hold_until.is_some_and(|until| now < until) {
        return;
    }
    // Condition 4.
    origin.clean_probes = origin.clean_probes.saturating_add(1);
    if origin.clean_probes < config.clean_probes_before_increase {
        return;
    }
    // Condition 7. An origin that refused is not one to ramp against.
    if origin.refused {
        return;
    }
    // Condition 5. Nobody queued, so the limit is not what is holding anything
    // up and another slot would sit unused. This is also what keeps a caller's
    // rate limit from being climbed past: when the limiter is the binding
    // constraint, permits do not queue for slots, so the evidence an increase
    // needs is never produced.
    if !origin.saturated {
        return;
    }
    // Condition 8.
    let ceiling = origin.ceiling.min(config.max);
    if origin.limit >= ceiling {
        return;
    }

    origin.limit += 1;
    origin.limit_changed();
}

/// Lets a ceiling a refusal lowered climb back, one slot at a time.
///
/// Off unless the caller passed an interval to
/// [`AdaptiveConcurrency::with_ceiling_recovery`], and there is no default
/// interval on purpose: the ratchet was chosen deliberately for a workload that
/// must not earn `429`s, and a caller who opts out of it is saying they know
/// their own quota. With one set, this is the additive half of AIMD — one slot
/// per interval of quiet, with the *limit* still having to earn each of those
/// slots through the increase rule, so a recovered ceiling is permission to try
/// again rather than a jump back to where the refusal happened.
///
/// The three guards are separable and each is reachable:
/// [`AdaptiveConcurrency::ceiling_recovery`] being unset is what keeps today's
/// permanence, the `max` check is what stops a fully recovered ceiling from
/// growing without bound, and the interval check is what makes recovery take
/// time. `ceiling_since` can only be `None` once the `max` check has passed for
/// an origin that never refused, which cannot happen — a refusal is the only
/// thing that lowers a ceiling, and it always records when.
fn relax_ceiling(origin: &mut Origin, shared: &Shared, now: Instant) {
    let Some(interval) = shared.ceiling_recovery else {
        return;
    };
    if origin.ceiling >= shared.config.max {
        return;
    }
    if origin
        .ceiling_since
        .is_none_or(|since| now < deadline(since, interval))
    {
        return;
    }
    // Bounded by the `max` check above rather than by a `min` here: two lines
    // enforcing one rule means neither can be shown to be doing it, and the
    // check has to exist anyway to stop `ceiling_since` being reset for ever.
    origin.ceiling += 1;
    origin.ceiling_since = Some(now);
}

/// A `429` or a `503`: a level this origin has now refused.
///
/// The ceiling only ever falls, unless the caller asked for
/// [`AdaptiveConcurrency::with_ceiling_recovery`]. Halving and then climbing
/// back on this law's own initiative would mean re-probing a level already known
/// to refuse — choosing to be refused on a schedule — which is the one thing
/// this controller exists not to do.
fn refuse(
    origin: &mut Origin,
    config: &ConcurrencyConfig,
    now: Instant,
    retry_after: Option<Duration>,
) {
    origin.refusals = origin.refusals.saturating_add(1);
    origin.retry_after_requested = retry_after;

    let learned = (origin.limit / 2).max(config.min);
    // The `min` cannot bind today and no test reaches it: condition 8 only ever
    // raises the limit while it is below the ceiling, so `limit <= ceiling`
    // holds, and `learned` — half of the limit — is already at or under the
    // ceiling. It stays because it is the line that makes "the ceiling only
    // ever falls" true by construction rather than by a chain of reasoning
    // about a different function, and because the day someone lets the limit
    // exceed the ceiling is the day this quietly starts raising it instead.
    origin.ceiling = origin.ceiling.min(learned);
    origin.limit = origin.limit.min(origin.ceiling);
    // When the ceiling last moved, which is what a recovery interval is measured
    // from. Written whether or not recovery is configured, because the cost is
    // one `Instant` and the alternative is a field that means something
    // different depending on a setting made elsewhere.
    origin.ceiling_since = Some(now);

    // `Retry-After` is obeyed as given, up to the configured ceiling on a
    // pause. What was asked for is kept verbatim in the snapshot, so a caller
    // who wants to honour something longer than this process is willing to
    // sleep for can read it and stop scheduling the origin itself.
    let pause = match retry_after {
        Some(asked) => asked.min(config.max_pause),
        None => cooldown(config, origin.refusals),
    };
    origin.resume_at = Some(deadline(now, pause));
    origin.hold_until = Some(deadline(now, pause.saturating_add(config.hold)));
    // The level changed, so what was normal at the old level is not the
    // measurement to hold the new one against.
    origin.baseline = None;
    origin.limit_changed();
}

/// The parts a [`Permit`] needs after the controller may have been dropped.
struct Shared {
    config: ConcurrencyConfig,
    /// See [`AdaptiveConcurrency::with_ceiling_recovery`]. `None` — the default
    /// — is the permanent ratchet this law has always had.
    ///
    /// Held here rather than in [`ConcurrencyConfig`] because that struct is
    /// exhaustive by design, so a new field there is a source break for every
    /// caller who wrote a literal without `..Default::default()`.
    ceiling_recovery: Option<Duration>,
    time: TimeSource,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("config", &self.config)
            .field("ceiling_recovery", &self.ceiling_recovery)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct Store {
    origins: HashMap<Box<str>, Arc<OriginState>>,
}

impl Store {
    /// Evicts down to `target`, never touching `protect` or an entry with a
    /// request in flight.
    ///
    /// One pass holding no more than the `doomed` worst candidates, so the store
    /// is never flattened into a temporary its own size — the same shape as
    /// `ValidatorStore::evict`. The rank is `(has_lesson, last_use_seq)`, so an
    /// origin that has taught the controller a ceiling or a refusal outlives an
    /// idle one it has learned nothing from. Under enough pressure a lesson can
    /// still be evicted, and it is: a store keyed by server-chosen values gets a
    /// capacity here, not an exception.
    ///
    /// An entry with a slot outstanding is skipped, because evicting it would
    /// drop the in-flight count and let the next lookup grant the origin a fresh
    /// set of slots on top of the ones already out. The store can therefore
    /// exceed its capacity by the number of origins with a request in flight —
    /// a number set by the caller's own concurrency, not by the servers.
    fn evict(&mut self, config: &ConcurrencyConfig, protect: &str) {
        if self.origins.len() <= config.capacity {
            return;
        }
        let doomed = self.origins.len() - config.purge_target();

        let mut worst: BinaryHeap<(bool, u64, &str)> = BinaryHeap::with_capacity(doomed + 1);
        for (key, state) in &self.origins {
            if &**key == protect {
                continue;
            }
            // `try_lock` rather than `lock`: this runs under the store's write
            // lock, and a permit holding an entry's mutex is by definition an
            // entry with a request in flight, which is one this pass skips
            // anyway.
            let Ok(origin) = state.inner.try_lock() else {
                continue;
            };
            if origin.in_flight > 0 {
                continue;
            }
            let candidate = (
                origin.has_lesson(config),
                state.last_use_seq.load(Ordering::Relaxed),
                &**key,
            );
            drop(origin);
            if worst.len() < doomed {
                worst.push(candidate);
            } else if worst.peek().is_some_and(|held| *held > candidate) {
                worst.pop();
                worst.push(candidate);
            }
        }
        let victims: Vec<Box<str>> = worst.into_iter().map(|(_, _, key)| key.into()).collect();
        for key in victims {
            self.origins.remove(&key);
        }
    }
}

/// The authority a controller keys an origin by: `host` or `host:port`.
///
/// The server's address rather than the web origin, because a server's capacity
/// is not per-scheme — `http://example.com` and `https://example.com` are one
/// machine with one budget. Userinfo is excluded, so a URL carrying credentials
/// does not put a password in a map key or in `Debug` output.
///
/// ```
/// use chromulate_http::adaptive::authority_of;
/// use url::Url;
///
/// let url = Url::parse("https://user:secret@example.com/a/b?c=d").unwrap();
/// assert_eq!(authority_of(&url), "example.com");
///
/// let url = Url::parse("https://example.com:8443/").unwrap();
/// assert_eq!(authority_of(&url), "example.com:8443");
/// ```
#[must_use]
pub fn authority_of(url: &Url) -> &str {
    &url[Position::BeforeHost..Position::BeforePath]
}

/// A per-origin concurrency controller.
///
/// # Increase rule
///
/// One slot is added when *every* one of these holds at the end of a probe:
///
/// 1. the probe completed — [`ConcurrencyConfig::probe`] consecutive healthy
///    responses with nothing else in between;
/// 2. a baseline exists, so there is something to compare the probe against. A
///    never-seen origin fails this for its first probe and cannot increase;
/// 3. the probe's mean latency did not exceed the baseline by
///    [`ConcurrencyConfig::degradation`];
/// 4. this makes [`ConcurrencyConfig::clean_probes_before_increase`]
///    consecutive clean probes;
/// 5. at least one permit since the last verdict had to queue for a slot, so
///    the limit is the binding constraint rather than an unused headroom;
/// 6. the hold set by the last decrease has elapsed — a probe that lands inside
///    a hold is discarded rather than banked, so recovery needs a run gathered
///    *after* the hold rather than one saved up during it;
/// 7. the origin has never answered `403`;
/// 8. the result stays at or under the origin's ceiling.
///
/// # Decrease rule
///
/// - The moment a completed probe's mean latency exceeds the baseline by
///   [`ConcurrencyConfig::degradation`], the limit halves — floor
///   [`ConcurrencyConfig::min`] — and no increase may happen for
///   [`ConcurrencyConfig::hold`]. The ceiling is untouched: latency is shared
///   and often transient.
/// - The moment a `429` or `503` arrives, and without waiting for a probe, the
///   origin's **ceiling** falls to half the limit that earned it and the limit
///   falls to the new ceiling. That is permanent for the life of the entry. The
///   controller obeys `Retry-After` when one is present and backs off
///   multiplicatively when one is not.
///
/// A `503` is treated exactly as a `429` here. A client cannot tell which of the
/// two an origin uses to say "slow down", and the costs are not symmetric: being
/// wrong towards caution costs one origin a lower ceiling, being wrong the other
/// way costs the crawl.
///
/// # Example
///
/// ```
/// use chromulate_http::adaptive::{AdaptiveConcurrency, Ceiling, Signal};
/// use url::Url;
///
/// # async fn run() {
/// let controller = AdaptiveConcurrency::new(Ceiling::Unlimited);
/// let url = Url::parse("https://example.com/product/1").unwrap();
///
/// let permit = controller.acquire(&url).await;
/// // ... send the request ...
/// permit.complete(Signal::Healthy);
/// # }
/// ```
pub struct AdaptiveConcurrency {
    shared: Arc<Shared>,
    ceiling: Ceiling,
    store: RwLock<Store>,
    seq: AtomicU64,
}

impl fmt::Debug for AdaptiveConcurrency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdaptiveConcurrency")
            .field("config", &self.shared.config)
            .field("ceiling_recovery", &self.shared.ceiling_recovery)
            .field("ceiling", &self.ceiling)
            .field("origins", &self.len())
            .finish_non_exhaustive()
    }
}

impl AdaptiveConcurrency {
    /// A controller with the default configuration, under `ceiling`.
    #[must_use]
    pub fn new(ceiling: Ceiling) -> Self {
        Self::with_config(ConcurrencyConfig::default(), ceiling)
    }

    /// A controller with a specific configuration, under `ceiling`.
    #[must_use]
    pub fn with_config(config: ConcurrencyConfig, ceiling: Ceiling) -> Self {
        Self {
            shared: Arc::new(Shared {
                config: config.sanitised(),
                ceiling_recovery: None,
                time: TimeSource::system(),
            }),
            ceiling,
            store: RwLock::new(Store::default()),
            seq: AtomicU64::new(0),
        }
    }

    /// Replaces the clock and timer, so a test can drive the law without
    /// waiting for it.
    #[must_use]
    pub fn with_time_source(mut self, time: TimeSource) -> Self {
        self.shared = Arc::new(Shared {
            config: self.shared.config,
            ceiling_recovery: self.shared.ceiling_recovery,
            time,
        });
        self
    }

    /// Lets a ceiling that a `429` or `503` lowered climb back, one slot per
    /// `interval`.
    ///
    /// **Off by default, and the default is the point.** Left alone, a refusal
    /// lowers an origin's ceiling for the life of the entry and the controller
    /// never approaches that level again, which is what a crawl that must not
    /// earn `429`s wants. This turns that ratchet into the additive half of
    /// classic AIMD, for the caller who knows their own quota — one told, for
    /// instance, that their provider allows a hundred requests per second — and
    /// would rather recover from a refusal than treat it as final.
    ///
    /// It is still slow on purpose: a recovered ceiling is only *permission* for
    /// the limit to try that level again, and the limit still has to earn each
    /// slot through the whole run of clean probes. Recovery is evaluated when a
    /// clean probe completes, so an idle origin's ceiling does not move and a
    /// snapshot reports it as of the last probe. An interval of zero means
    /// "recover on every clean probe", which is a coherent choice and a fast one.
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use chromulate_http::adaptive::{AdaptiveConcurrency, Ceiling};
    ///
    /// let controller = AdaptiveConcurrency::new(Ceiling::Unlimited)
    ///     .with_ceiling_recovery(Duration::from_secs(600));
    /// assert_eq!(
    ///     controller.ceiling_recovery(),
    ///     Some(Duration::from_secs(600))
    /// );
    /// assert_eq!(
    ///     AdaptiveConcurrency::new(Ceiling::Unlimited).ceiling_recovery(),
    ///     None,
    ///     "a refusal is final unless the caller says otherwise"
    /// );
    /// ```
    #[must_use]
    pub fn with_ceiling_recovery(mut self, interval: Duration) -> Self {
        self.shared = Arc::new(Shared {
            config: self.shared.config,
            ceiling_recovery: Some(interval),
            time: self.shared.time.clone(),
        });
        self
    }

    /// The configuration in force, after clamping.
    #[must_use]
    pub fn config(&self) -> &ConcurrencyConfig {
        &self.shared.config
    }

    /// How long a lowered ceiling waits before it may regain one slot, or
    /// `None` when a refusal is final.
    #[must_use]
    pub fn ceiling_recovery(&self) -> Option<Duration> {
        self.shared.ceiling_recovery
    }

    /// How many origins are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.read().origins.len()
    }

    /// Whether nothing is remembered yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// What the controller has learned about one authority.
    #[must_use]
    pub fn snapshot(&self, authority: &str) -> Option<OriginSnapshot> {
        let state = Arc::clone(self.read().origins.get(authority)?);
        let now = self.shared.time.now();
        let origin = state.lock();
        Some(OriginSnapshot {
            limit: origin.limit,
            in_flight: origin.in_flight,
            ceiling: origin.ceiling,
            baseline: origin.baseline,
            refused: origin.refused,
            paused_for: origin
                .resume_at
                .map(|at| at.saturating_duration_since(now))
                .filter(|left| !left.is_zero()),
            retry_after_requested: origin.retry_after_requested,
            refusals: origin.refusals,
            clean_probes: origin.clean_probes,
        })
    }

    /// Forgets an authority, ceiling and refusal included.
    ///
    /// The lever behind "surface it and let the caller decide": a caller who has
    /// dealt with whatever produced a `403` says so here. Permits already
    /// outstanding keep working against the forgotten entry and simply teach it
    /// nothing.
    ///
    /// Returns whether anything was remembered.
    pub fn forget(&self, authority: &str) -> bool {
        self.write().origins.remove(authority).is_some()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Store> {
        self.store
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Store> {
        self.store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn state_for(&self, authority: &str) -> Arc<OriginState> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        if let Some(state) = self.read().origins.get(authority) {
            state.last_use_seq.store(seq, Ordering::Relaxed);
            return Arc::clone(state);
        }

        let mut store = self.write();
        // Another writer may have inserted while no lock was held.
        if let Some(state) = store.origins.get(authority) {
            state.last_use_seq.store(seq, Ordering::Relaxed);
            return Arc::clone(state);
        }
        let state = Arc::new(OriginState::new(&self.shared.config, seq));
        store.origins.insert(authority.into(), Arc::clone(&state));
        store.evict(&self.shared.config, authority);
        state
    }

    /// Waits for permission to send one request to `url`.
    ///
    /// In order: any pause the origin asked for, then the caller's
    /// [`Ceiling`], then a slot. The ceiling comes before the slot on purpose —
    /// a permit that has not paid the caller's rate must not exist, and holding
    /// a slot while waiting to pay would report a saturation that was the
    /// limiter's doing.
    pub async fn acquire(&self, url: &Url) -> Permit {
        self.acquire_authority(authority_of(url)).await
    }

    /// [`AdaptiveConcurrency::acquire`], for a caller that already has the
    /// authority.
    pub async fn acquire_authority(&self, authority: &str) -> Permit {
        let state = self.state_for(authority);

        // A pause the origin asked for. Looped rather than slept once, because
        // a second refusal may extend it while this one is waiting.
        loop {
            let left = state.pause_remaining(self.shared.time.now());
            if left.is_zero() {
                break;
            }
            self.shared.time.sleep(left).await;
        }

        // The caller's ceiling. There is no path to a `Permit` that skips this.
        self.ceiling.pay(&self.shared.time).await;

        let waited = state.take_slot().await;
        Permit {
            shared: Arc::clone(&self.shared),
            state,
            started: self.shared.time.now(),
            waited,
            reported: false,
        }
    }
}

/// This law, behind the seam every controller is reached through.
///
/// The boxing is what erasure costs: one allocation for the future and one for
/// the lease, per hop, on top of what the law itself does. A caller who holds an
/// `AdaptiveConcurrency` directly and wants neither can call
/// [`AdaptiveConcurrency::acquire`] and [`Permit::complete`], which are the same
/// two calls without the indirection.
impl ConcurrencyController for AdaptiveConcurrency {
    fn acquire<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Box<dyn Lease>> {
        Box::pin(async move {
            Box::new(AdaptiveConcurrency::acquire(self, url).await) as Box<dyn Lease>
        })
    }
}
