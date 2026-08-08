# Network events: an observer seam, not a replacement for `Outcome`

Status: assessment, no spike. Written 2026-08-08.

The question under assessment: should the concurrency seam's `Outcome` be replaced by a
lower-level stream of network events — `RequestStarted`, `Connected`,
`TlsHandshakeComplete`, `HeadersReceived`, `FirstByteReceived`, `BodyCompleted`,
`ConnectionClosed` — from which `AdaptiveConcurrency` and third-party controllers,
including learned or model-driven ones, derive their own decisions?

The recommendation is: no to *replaced*, yes to the events. Keep the concurrency seam
exactly as it is, and add a separate, additive observer seam that emits the events. A
controller that wants events subscribes to the observer *and* holds its leases; the two
seams compose without either widening.

The conventions of [`02-chromulate-design.md`](02-chromulate-design.md) apply: claims about
code carry a `path:line` citation, and claims that were not observed are labelled with what
would settle them.

---

## 1. What `Outcome` is, and what replacing it would cost

`Outcome` is two observed facts — status code and response headers — and deliberately
nothing concluded from them (`chromulate-http/src/concurrency.rs:157-181`). The seam is two
methods: `acquire` returns a `Lease`, `Lease::complete` reports the outcome
(`concurrency.rs:122-149`). Latency is deliberately absent: a controller measures it
between `acquire` and `complete` against its own clock, which is what keeps a controller
with an injected clock testable without waiting (`concurrency.rs:172-176`).

That minimalism is not an accident to be outgrown; it is the property that makes a
third-party controller a page of code. Replace `Outcome` with an event subscription and
the simplest possible controller — a fixed limit per origin — must now consume a lifecycle
stream to learn the one thing it ever needed: this request is finished. The complexity
lands on every implementation to serve the rare one, which is the shape of seam this
project's own history warns against: a pre-classified verdict was kept out of `Outcome`
for exactly this reason, and a mandatory event stream is the same mistake with more
moving parts.

## 2. The proposed events are not concurrency vocabulary

Read the list again as a description of *where the information lives*:

- `Connected` and `TlsHandshakeComplete` happen in the dialling path
  (`connect.rs:408`). A pooled connection skips both: the engine checks the pool first
  (`engine.rs:847`), and a browser-grade client reuses aggressively, so for most requests
  these events do not occur at all. Any consumer treating them as per-request phases must
  first model their absence.
- `ConnectionClosed` is not a request event. Connections outlive and interleave requests
  (`pool.rs:334`, `pool.rs:369`), and an HTTP/2 connection serves many at once. It is a
  *connection* event with a lifetime of its own.
- `HeadersReceived` versus `FirstByteReceived` is a distinction drawn inside hyper's read
  path, which this crate drives but does not instrument. UNVERIFIED whether it can be
  observed without patching hyper; settled by attempting it.
- `RequestStarted` and `BodyCompleted` are engine-visible today: the send path that
  consults the concurrency seam (`engine.rs:677`, `engine.rs:686`) brackets exactly that
  span.

So the event list describes a **request-lifecycle observability surface spanning four
layers** — engine, pool, dialling, TLS — not an input to the concurrency decision. It is
also, recognisably, a Resource-Timing-shaped phase-timings API, a thing this project has
separately wanted for callers asking where a slow request spent its time. One design
should serve both asks, because they are the same ask: let a consumer see when each phase
of a request happened, without the engine concluding anything on their behalf.

## 3. The shape that serves both

A single observer seam, additive and absent by default:

- A `NetworkObserver` trait with one method receiving a borrowed event; an
  `Option<Arc<dyn NetworkObserver>>` on the engine that is `None` unless installed —
  the same zero-when-absent pattern the concurrency seam measured at no cost on the
  `None` path.
- Events carry observations only: which request, which connection, a monotonic timestamp,
  and the facts of the phase. No event means "slow", "healthy", or "backpressure";
  judgment stays in the consumer, per the seam-vocabulary rule in `CLAUDE.md`.
- Connection-level events carry a connection identity, not a request identity, because
  that is what they are events *about*; a consumer correlating them to requests does so
  in its own state.
- `AdaptiveConcurrency` does not change. It speaks `Outcome` and its own clock today and
  loses nothing. A model-driven controller subscribes to the observer for its features
  and holds leases for its actuation — composition, with each seam staying narrow.

What this costs is plumbing emission points through layers that are currently, and
deliberately, decoupled — the pool and dialler would gain an observer handle they do not
have today. Every emission point is on the hot path; the steady-state figure of 48
allocations per request is published and benchmarked, so the budget is: zero events, zero
cost, and the installed cost is UNMEASURED until a spike measures it against
`chromulate-bench`.

## 4. What would settle the open points

1. Whether hyper exposes enough to distinguish first byte from parsed headers — attempt
   it; if not, ship `HeadersReceived` only and say so.
2. The installed cost per event — the allocation counter, n≥3, before any figure is
   claimed.
3. Whether delivery is a synchronous call or a bounded channel — a spike must show a slow
   observer cannot stall the request path, or the API must document that it can.

Sequenced: engine-level events first (`RequestStarted`, `HeadersReceived`,
`BodyCompleted` — reachable without new plumbing), connection-level events second, and a
Resource-Timing-style per-request summary view last, built on top of the same seam.
