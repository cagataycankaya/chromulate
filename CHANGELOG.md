# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the usual pre-1.0 caveat
that breaking changes may land in a minor release.

## [Unreleased]

## [0.3.0] — 2026-08-08

### Added

- **`chromulate-concurrency`, a new crate holding the two per-origin control laws.**
  `AdaptiveConcurrency`, `FixedConcurrency`, `Ceiling`, `ConcurrencyConfig`, `Signal`,
  `Permit`, `OriginSnapshot`, `retry_after_delay`, `DEFAULT_ORIGIN_CAPACITY` and
  `DEFAULT_FIXED_CAPACITY` all moved here from `chromulate-http` unchanged — same
  behaviour, same defaults, same tests, new paths. The dependency runs one way only:
  this crate depends on `chromulate-http` for the trait, and `chromulate-http` depends
  on it in no form, dev-dependencies included. That is what makes "the engine holds no
  policy" checkable rather than asserted.

- **`chromulate_http::concurrency::Unlimited`**, a controller that grants every lease on
  the first poll and learns nothing from any outcome. Behaviourally identical to
  installing no controller at all — and *not* the cheaper of the two, because an
  installed controller pays the seam's erasure of one boxed future and one boxed lease
  per hop. It exists for a configuration that picks a controller at run time and would
  otherwise thread an `Option` through every layer to say "none", and as the thing a
  delegating third-party controller wraps when its own policy is switched off. A caller
  who simply wants no concurrency control should still install nothing.

### Changed

- **The `adaptive-concurrency` feature is gone from `chromulate-http` (breaking).**
  It gated the `ConcurrencyController` seam *and* the laws behind it with one switch, so
  the trait a third-party controller implements existed only when a feature nobody else
  in the build had turned on. The seam — `ConcurrencyController`, `Lease`, `Outcome`,
  `acquire_from`, `complete_from`, `authority_of`, `Unlimited`, and
  `EngineBuilder::concurrency` — is now always compiled.

  A manifest naming `chromulate-http/adaptive-concurrency` fails to resolve and should
  drop the feature. Code reaching `chromulate_http::adaptive::*` or
  `chromulate_http::concurrency::{Ceiling, FixedConcurrency, FixedLease,
  DEFAULT_FIXED_CAPACITY}` moves to `chromulate_concurrency::*`; everything else in
  `chromulate_http::concurrency` keeps its path.

  Compiling the seam unconditionally is free for a caller who installs nothing.
  Measured with `cargo run --release -p chromulate-bench --bin allocs`, three runs
  before and three after: 48 allocations per pooled request in all six, and 48 was also
  the figure when the module was gated away entirely. The erasure is charged per
  installed controller, not per build.

- **`authority_of` moved from `chromulate_http::adaptive` to
  `chromulate_http::concurrency` (breaking).** It is the key convention the trait offers
  every implementation, so it stayed with the trait rather than leaving with the laws —
  a third-party controller that wants the same key must not have to depend on somebody
  else's policy crate to get it. `chromulate_concurrency::adaptive::authority_of`
  re-exports it, so callers of the old path change only the crate name.

- **`chromulate`'s `adaptive-concurrency` feature now pulls in `chromulate-concurrency`**
  rather than forwarding to `chromulate-http`, and re-exports it as
  `chromulate::concurrency`. What it gates changed: `ClientBuilder::concurrency` and the
  seam types are now available with the feature *off*, so a caller can install a
  controller of their own without enabling anything. The feature buys the two shipped
  laws and nothing else. Enabling it still changes no behaviour on its own — a
  controller has to be installed.

- **The concurrency suite now runs in a default `cargo test --workspace`.** It sat behind
  an off-by-default feature, so the ordinary test command never compiled it; the new
  crate is an unconditional workspace member. Default-feature run: 846 tests before,
  930 after. The `--all-features` total went 1,148 to 1,154, and every one of those six
  is new rather than moved — two doctests on the new crate root and on `Unlimited`, and
  four tests covering `Unlimited` and the no-controller default path.

### Fixed

- **`chromulate` did not compile when `ActiveBackend` named anything but rustls.**
  `ClientBuilder::tls` took the concrete `TlsEngine` where `chromulate-http`'s builder
  takes the alias, so `--cfg chromulate_mock_backend` produced `E0308` in the facade. It
  now takes `ActiveBackend`, which *is* `TlsEngine` in a default build, so no caller's
  source changes. The `backend-seam` CI job ran `-p chromulate-tls -p chromulate-http`
  only, which is why the one crate a user adds to their manifest was the one crate the
  seam's own proof never built; it now includes `-p chromulate`.

  Three documents claimed more than that job checked — `chromulate-tls`'s crate docs said
  "the workspace still compiles and its tests still pass", and the README and
  `docs/fidelity.md` said CI builds and tests against the second backend. Two crates did.
  Each now names the three.

- **The TLS backend seam was unreachable from the facade.** `TlsBackend`,
  `TlsBackendConfig` and `ActiveBackend` were not exported from `chromulate::tls` at all,
  so a caller could not bring the trait into scope without depending on `chromulate-tls`
  directly — and the trait is how a backend is used. All three are now exported.

  Relatedly, call sites reading `engine.tls().fidelity()` were relying on `TlsEngine`'s
  *inherent* methods, which shadow the identically named trait methods and resolve only
  for that one backend. They now read `TlsBackendConfig::fidelity(...)`. Importing the
  trait alone does not fix this: the inherent method still wins and `-D warnings` then
  rejects the import as unused. Both halves are needed, which is why each site says so in
  a comment.

### Documentation

- **Two documents said HTTP/2 regular header order was unreachable. It has been reproduced
  since before 0.1.0.** The premise was right and the conclusion was inverted: h2 does encode
  header fields by iterating the `HeaderMap`, and `http` does decline to document an
  iteration order — but iterating the map is exactly what makes the order controllable. The
  engine rebuilds the outgoing map by appending in the profile's order
  (`crates/chromulate-http/src/engine.rs:1146`) and h2 writes it out that way, which
  `crates/chromulate/tests/live_identity.rs` asserts against the capture on the wire.

  Because that rests on an undocumented property it carries its own guard,
  `a_rebuilt_header_map_iterates_in_the_order_it_was_appended` (`engine.rs:1362`), which
  fails if a future `http` release reorders. `docs/fidelity.md` and the README had it right
  as an exact match throughout; §8.5 of the design document and Phase 6 of the roadmap
  contradicted them, and both are corrected. This one was found in an audit before 0.2.0 was
  tagged and was left out of the fix list by mistake, so it shipped in a released document.

- **Phase 6 of the roadmap now costs its options in counted lines rather than adjectives.**
  It previously weighed two routes as "the first is cheaper and slower; the second is a
  significant amount of protocol code to own", which is not a basis for choosing. Measured:
  an upstream h2 setter is ~90–110 lines, because a config value reaches the send path
  through 13 sites in 5 files (traced via `initial_max_send_streams`). A published fork
  costs the same ~100 lines plus re-owning hyper's HTTP/2 glue, because a library cannot ship
  a `[patch.crates-io]`.

  Of hyper's 2,388 lines of h2 glue about 676 are unreachable here — `ping.rs` is gated on
  `is_enabled()`, false when neither adaptive window nor keep-alive is set, so 248 of its 515
  lines never construct; CONNECT upgrade support is ~83; and 15 of `client/conn/http2.rs`'s 27
  public functions are setters nothing calls. That leaves ~1,712 needed, but it does not lift
  out: `proto/h2/client.rs` reaches into nine internal hyper modules. The empirical check
  agrees — `wreq` took this route and carries a renamed h2 fork plus `wreq-proto`, a fork of
  hyper's whole protocol layer at 10,836 lines whose h2 glue is 2,412 against hyper's 2,388.
  Plan against ~10,800, not ~1,700.

  The recommendation that falls out is to try upstream first: h2 issue #637 asked for a
  `header_table_size` setter for fingerprinting reasons, closed as completed, and this crate
  calls that setter today.

- **Phase 6 of the roadmap gained a third route: depending on the published `http2` fork
  rather than owning one.** The `http2` crate (crates.io, MIT, the renamed `h2` fork `wreq`
  carries) already exposes `headers_pseudo_order`, `headers_stream_dependency` and
  `settings_order`, and its encode path writes the stream dependency — the line stock `h2`
  leaves as a no-op. Checked 2026-08-08, version 0.5.20 had merged upstream h2 0.4.15 in
  full, CONTINUATION-flood protection included. The cost is an adapter — hyper links `h2`,
  not `http2`, so the HTTP/2 path would drive it directly — estimated at 300–700 lines and
  UNMEASURED, the one figure in that table that is not counted, plus trusting a single
  maintainer for security fixes rather than hyperium.

- **A new assessment, `docs/architecture/05-network-events-assessment.md`**, answers
  whether the concurrency seam's `Outcome` should become a stream of lifecycle events
  (`Connected`, `TlsHandshakeComplete`, `FirstByteReceived`, …). The recommendation is no
  to replacing — the two-method seam is what keeps a third-party controller a page of code
  — and yes to the events as a separate, additive observer seam, absent by default, whose
  events carry observations and no judgment. Half the proposed events are not per-request
  facts at all: a pooled connection skips `Connected` and the TLS handshake entirely, and
  `ConnectionClosed` belongs to a connection's lifetime, not a request's.

- **The design document and README now describe the concurrency layer as it is.** Four
  sites in the design document still tied the seam to the removed
  `chromulate-http/adaptive-concurrency` feature and cited engine lines that had moved.
  The README's client-behaviour table gained the concurrency row it never had, the
  workspace tables and dependency diagram gained `chromulate-concurrency`, and "What
  Chromulate does not do" now states the boundary the seam enforces: the engine emits
  signals — observed status and headers — and the caller decides what they mean.

## [0.2.0] — 2026-08-05

### Added

- **`ConcurrencyController` and `Lease`**, which turn per-origin concurrency from a control
  law a caller must accept into a seam they can implement. The engine asks any installed
  controller for permission per hop and reports an `Outcome` carrying the **raw status and
  response headers**, not a pre-classified verdict — because a verdict is one law's reading.
  A `503` is backpressure to the shipped law and an ordinary error to an origin mid-deploy;
  a `403` is a refusal here and an expired token elsewhere. Handing either across the seam
  would make every third-party controller inherit opinions it may not share, which is the
  thing the seam exists to stop. Latency is deliberately absent for the same reason: a
  controller measures it against its own clock, which is what keeps an injected clock
  testable.
- **`FixedConcurrency`**, a second implementation that bounds in-flight requests per origin
  and never adapts. It ignores `Outcome` entirely, which is what shows the trait is not
  shaped around the adaptive law's needs. A caller who knows their own limits should not have
  to configure an adaptive controller into submission to get a fixed one.
- **`AdaptiveConcurrency::with_ceiling_recovery(interval)`**, making one former certainty a
  choice. A `429` still lowers an origin's ceiling permanently by default — that was chosen
  deliberately and is unchanged — but a caller who knows their own limit can now opt into the
  additive half of AIMD and let the ceiling climb back one slot per quiet interval. The `403`
  freeze stays policy and is deliberately not configurable: the knob would be "keep ramping
  against an origin that has refused you", which is the project's scope boundary rather than
  a tuning decision.
- **`ClientBuilder::concurrency`**, so the seam is reachable from the facade. The feature was
  not forwarded at all before this, which meant a caller depending on `chromulate` — which is
  what the README tells them to do — could not install a controller without adding a second
  dependency.

  A controller can only ever make a request wait. It runs below the middleware chain, so a
  `RateLimiter` has already spent its token before a controller is consulted, and the trait
  exposes no way to obtain a limiter or to signal "send now regardless". Proven rather than
  asserted: a third-party controller granting 64 instant permits still takes at least 80 ms
  to send five requests at 50 per second.

  Dynamic dispatch costs two allocations and about 47 ns per hop for a caller who installs a
  controller; a caller holding an `AdaptiveConcurrency` directly pays neither. Steady-state
  allocations are unchanged at 48 per request, because the feature is off by default.

- **Per-origin adaptive concurrency**, behind the off-by-default `adaptive-concurrency`
  feature. A controller that learns how many concurrent requests an origin serves
  comfortably and stays there, because there is no single right number: measured on four
  marketplaces, one HTTP/2 connection carrying eight requests at once cut the per-request
  cost by 5.2x on one origin and 2.9x on another, and the knee fell in a different place on
  each.

  **Latency is the primary signal, not status.** Congestion shows in response time long
  before an origin decides to refuse, so a probe whose mean exceeds its baseline halves the
  limit at once, while adding a slot takes twenty healthy responses and evidence that
  something actually queued for one. Overshooting costs milliseconds; being cautious costs
  almost nothing.

  **A `429` or `503` lowers that origin's ceiling permanently**, to half the level that
  earned it, rather than halving and climbing back. Classic additive-increase
  multiplicative-decrease *finds* a limit by hitting it, which means eating a refusal on a
  schedule forever; re-probing a level known to refuse is choosing to be refused.
  `Retry-After` is obeyed in both its forms, and an exponential cooldown applies when it is
  absent.

  **A `403` is not backpressure.** It freezes the limit, surfaces itself, and does nothing
  else — no halving, no pause, no retry, and nothing varies a profile, a header or an
  identity in response to it. It is the origin saying no rather than saying how much, and
  tuning around it would be the scope boundary rather than a control decision.

  The caller's `RateLimiter` is a structural ceiling rather than a checked one: it is a
  required constructor argument, a token is spent before any permit is granted, and a
  rate-limited caller queues behind the limiter rather than behind slots — so it cannot
  produce the saturation evidence an increase requires. Per-origin state is bounded at 4,096
  authorities with lesson-holding entries outliving idle ones. This cannot promise zero
  `429`s — a threshold can change, is often shared across clients on one IP, and may not be
  concurrency-based at all — but it never chooses to find a limit by hitting it.

- **`multipart/form-data` request bodies**, behind the off-by-default `multipart` feature.
  `RequestBuilder::multipart` takes a `Form` of `Part`s and streams it, so a form built from
  `Part::file` sends the file from disk to the socket without buffering it; only a part of
  unknown length falls back to chunked. The encoding follows a recorded capture of Chrome 151
  rather than RFC 7578 alone — `"`, CR and LF are percent-escaped in field names and
  filenames and nothing else is, filenames are raw UTF-8 with no `filename*`, and a part
  carries a `Content-Type` only when it has a filename. The boundary is verified absent from
  every buffered part before use; a streaming part cannot be searched without consuming it,
  and that limit is pinned by a test rather than left in prose.
- **The HSTS preload list**, behind the off-by-default `hsts-preload` feature: all 94,628
  `force-https` entries from Chromium at revision `7be0edc6`, compiled in as a
  1,749,625-byte sorted table. It protects the first request to an origin this process has
  never visited, which is the one case a store learned from responses cannot cover. Off by
  default because it grows a release binary by 1,750,560 bytes (measured — `__TEXT,__const` +1,748,992 for the table, `__text` +960 for the code); a lookup costs
  269-283 ns and allocates nothing, roughly 33 ns of which is canonicalising the host. Precedence is `dynamic || preload`, matching
  Chromium, so an origin cannot take itself off the list with `max-age=0`. The ancestor walk
  deliberately does not stop at the registrable domain: fifty-seven entries carry Chromium's `public-suffix`
  policy, among them the bare TLDs `app`, `dev`, `bank`, `page` and `google` — 51 names in
  the shipped blob have a single label, every one of them with `includeSubDomains` — and
  clamping would have silently unprotected everything under them.
- **An RFC 9111 HTTP cache**, as the new `chromulate-cache` crate, behind the off-by-default
  `cache` feature. Storability, freshness, the full §4.2.3 age correction,
  `ETag`/`Last-Modified` revalidation with correct `304` field merging, `Vary` selection, the
  `no-cache`/`no-store` distinction, and invalidation on unsafe methods. What it omits —
  stale-while-revalidate, stale-if-error, shared-cache semantics, ranges, `HEAD`,
  persistence — is listed in the crate's own documentation rather than left to be discovered.
  Responses are recorded as the caller streams them, so nothing is buffered ahead of the
  reader. `private` and `Set-Cookie` responses are not stored by default, and neither is any
  response whose `Vary` names a header the engine writes after the cache has seen the
  request. The sharded lock costs 70 ns uncontended, 174 ns/op across eight threads against
  247 ns/op with a single shard.
- **`Response::bytes_until`**, behind the off-by-default `early-stop` feature, which reads only the front of a body — stopping on a byte
  marker (found even when split across chunks), a predicate over the decoded prefix, or a
  byte budget — and reports which. On HTTP/2 stopping early resets the stream and keeps the
  pooled connection, observed as `RST_STREAM(CANCEL)` at a real h2 origin; on HTTP/1.1 it
  still discards the connection, which is required for correctness.

  **The byte saving is large and reproducible; the time saving is neither.** Measured on six
  marketplace product pages whose structured product data sits between 0.3% and 17% into the
  body, across two independent runs: bytes read fall by **82%** in both (4040 KB to 744 KB,
  and 10039 KB to 1762 KB on the four-site subset of the second run). Time is a different
  story — the first run showed a median of 177 ms falling to 114 ms, and the second showed
  120 ms falling to 119 ms, which is nothing. The explanation is that the saving is bounded
  by how much of a request was *transfer* rather than the origin's own think time; on the
  second run the floor was about 110 ms of think time and the full-body read was already
  near it. Treat the byte figure as the claim and the time figure as conditional on the
  network.

  It is off by default and the default read is unaffected either way: `bytes()` has always
  returned the whole body and still does, so nothing truncates unless a caller asks for it.
  What the feature gates is whether the API exists at all, which keeps `Stop`, `Prefix` and
  `StopReason` out of the surface of a build that does not want a truncating read.

  For the same reason this is **not a competitive advantage**. Measured against `reqwest`
  and `wreq` hand-rolling the same early stop over their own byte streams, all three read
  the same 82% less and land within noise of each other (medians 119, 113 and 109 ms with
  interquartile ranges that overlap almost entirely). All three keep their pooled HTTP/2
  connection across an abandoned body — that is hyper's behaviour, not this crate's. What
  `bytes_until` is worth is not speed: it is the chunk-boundary marker search a caller would
  otherwise hand-roll and get wrong, and the distinction between "found it", "ran out of
  budget" and "reached the end", without which a fixed byte budget silently extracted only
  12 of 18 pages in the same measurement.
- **`chromulate-h3`**: RFC 7838 `Alt-Svc` parsing and a per-origin alternative-service cache,
  bounded at 10,000 origins with expiry-first eviction, which is how a client learns an
  origin offers HTTP/3. The bound exists because what fills the cache is chosen by the
  servers a crawl visits rather than by the caller. A QUIC spike behind the
  non-default `quic-spike` feature establishes what the `quinn`/`h3` stack would put on the
  wire. A real HTTP/3 request succeeds, but the handshake omits five extensions the Chrome
  capture carries, emits no GREASE, and its transport-parameter set cannot be changed through
  `quinn`'s public API. QUIC is therefore **not shipped**: this project has no
  Chrome-over-QUIC capture, so its fidelity is not poor but *unmeasurable*, and shipping it
  would mean claiming a protocol surface nobody checked.
  `docs/architecture/04-http3-assessment.md` records the measurements.
- **`ValidatorStore`** in `chromulate-http`, behind the off-by-default `validator-store`
  feature: `ETag` and `Last-Modified` remembered per URL and replayed as
  `If-None-Match`/`If-Modified-Since` on the next visit, regardless of whether the response
  was storable. **This is deliberately not browser behaviour** — Chrome does not revalidate a
  response it was told not to store — and the conditional headers are appended after the
  profile's own, a placement no capture backs. Its reach is narrow and measured: of six
  Turkish marketplace pages probed on 2026-08-04 only one offered a validator at all and none
  offered an `ETag`, though on that one origin a `304` returned in 60 ms with 0 bytes against
  a 1,106,803-byte body. Bodies are not stored; the bound is 4096 URLs at a measured 326
  bytes each.

- **`Client::with_hsts()`** — access to the HSTS store, so a caller can seed origins it
  already knows about or inspect what a run learned. It takes a closure; see *Changed* for
  why it is not the guard-returning `hsts()` this entry originally announced.
- **`RequestBuilder::basic_auth` and `bearer_auth`.** Both mark the header value sensitive,
  so a credential does not reach a log through `HeaderMap`'s `Debug`. `basic_auth` always
  sends the colon: `user:` and `user` are different credentials on the wire.
- **A features table in the README**, saying what ships and what does not, with the
  fidelity rows pointing at the measurements behind them.
- **CI: Miri over `chromulate-core`** (verified locally first — 31 tests pass under it,
  including the `tokio` ones) and **a nightly schedule for the live network tests**, so
  that "a site changed" and "we broke it" stop looking the same.
- **Per-phase request timings — `chromulate::Timings`, read from
  `Response::timings()`.** Resolve, connect, TLS handshake, redirect time and time to
  response head, with `Timings::elapsed()` read after the body for the time to body
  complete. `std::time::Instant` throughout: no metrics crate, no exporter, no new
  dependency. The connection phases are `Option<Duration>`, because a request served from
  the pool performs none of them and `Some(ZERO)` would claim it performed them
  instantly. After a redirect chain the phases describe the final hop and the earlier
  hops are `Timings::redirect()`. Measured at **48 allocations per steady-state request,
  unchanged** (`--bin allocs`, n=3, spread 0.0%).

### Changed

- **A rotating proxy pool no longer presents one session from every exit.** A `Client` built
  with `proxy_pool` of two or more proxies, or with a custom `proxy_provider`, now gives each
  exit address its own cookie jar, its own `Accept-CH` client-hint grant and its own
  `ValidatorStore`. Measured against three real ISP proxies with distinct exit addresses
  before the change: a cookie set through the first exit was presented from all three. That
  did not merely waste the rotation — it told the origin the three addresses were one client,
  which is a stronger signal than not rotating at all, and it happened silently.

  Clients with no proxy, one proxy, a one-member pool, or a jar named through `cookie_jar`
  are unchanged and share one session, so the common cases run today's code path exactly.
  `ClientBuilder::proxy_isolation` states either choice at the call site, and
  `ProxyIsolation::PerProxy { max_routes }` caps how many exits hold state — 32 by default,
  dropping the least recently used past that so a new exit starts fresh rather than borrowing
  another's.

  The default is per-exit because the two failure modes are not symmetric: sharing a session
  the caller wanted split is silent, while splitting one they wanted shared logs them out on
  the first run and is fixed in one line.

  **What is deliberately still shared, and why.** HSTS, because it is a policy about the
  origin rather than the client, and because the upgrade happens before a route is chosen —
  splitting it would send the first request through each new exit in plaintext, a downgrade
  rather than an isolation win. Adaptive concurrency, because it is learned from status codes
  and never sent. An HTTP cache cannot be shared safely here and is refused at build time
  with `Error::Config` rather than quietly shared.

  **A leak this does not close:** TLS session tickets are bound into one `rustls` client
  configuration, so a resumed handshake through one exit can present a ticket the origin
  issued to another, linking them below HTTP before any cookie is sent. This is stated in
  `ProxyIsolation`'s own documentation rather than left to be found.

  The lookup costs 3.4 ns per request on the shared path and 23.5 ns with eight live exits
  (Apple M1 Pro, best of seven over 1M calls, n=3). Allocations per steady-state request are
  unchanged at 48.

- **The TLS backend seam now carries the connection, and its signature changed to do it
  without cost.** `TlsBackend` existed as public API but had zero production callers:
  `chromulate-http` held a concrete `TlsEngine` and called its inherent `connect`, so the
  trait was exercised only by its own unit test. It is now the path every TLS connection
  takes. Two breaking changes to the trait were needed to get there, both of them the point
  rather than incidental:

  - `TlsBackend::Stream` is a new associated type, and `connect` returns
    `(Self::Stream, HandshakeInfo)` instead of a boxed `TlsConnection`. The boxed form put a
    `dyn` behind every `poll_read` and `poll_write` on the request path; an associated type
    keeps the stream concrete and the dispatch static. `TlsConnection` is unchanged and
    still available for callers who want to erase the type — they now opt into that cost
    instead of having it imposed.
  - `connect` returns the `HandshakeInfo` alongside the stream. `chromulate-http` previously
    called `HandshakeInfo::of_stream`, which reads rustls's own connection state, so the
    caller was coupled to the implementation the trait exists to hide. A backend that is not
    rustls could not have answered that question the same way.

  New: `chromulate_tls::ActiveBackend`, a type alias for the backend this build links
  (`TlsEngine` today). Backend choice is deliberately a build-time alias rather than a
  runtime object — naming it concretely is what keeps the associated type concrete, and so
  what keeps the vtable off the hot path. It is the same trade `rustls` makes with its
  crypto providers. `EngineBuilder::tls` and `Engine::tls` now name `ActiveBackend`; since
  it currently aliases `TlsEngine`, no caller has to change.

  The measurable result: `crates/chromulate-http/src/` no longer contains the string
  `rustls` anywhere outside one explanatory comment. `Stream::Secure` derives its type from
  `<ActiveBackend as TlsBackend<TcpStream>>::Stream` rather than naming `TlsStream`
  directly — the unused-import error that change produced is the evidence the decoupling is
  real. Adding a BoringSSL backend is now implementing the trait and pointing two aliases at
  it under a cargo feature, not editing the connection path. Behaviour is unchanged and
  UNMEASURED for performance: the change removes indirection rather than adding it, but no
  before/after benchmark was run, so no speed claim is made.

- **The seam now has a second implementation, and writing it found four defects in the
  first.** A trait with one implementation is a guess about an interface. `mock::MockBackend`
  is that second implementation: it shares no code and no types with rustls, performs no
  handshake, and chooses `IO` as its `Stream` where the rustls backend chooses
  `tokio_rustls::client::TlsStream<IO>`. `chromulate-http` builds and passes its tests
  against it.

  It is selected by `--cfg chromulate_mock_backend`, **not** a cargo feature. Features must
  be additive and `--all-features` would switch it on, which would mean every other CI job
  believing it exercised TLS while linking a backend that encrypts nothing. A new CI job,
  "The TLS seam admits a second backend", builds and tests both crates under that flag.

  What the second implementation exposed, none of which the first had shown:

  - **`from_profile`, `target_identity` and `fidelity` were missing from the trait.**
    `chromulate-http` builds its own backend when a caller supplies none, and the CLI and the
    facade's own documented example call the other two. All three were inherent `TlsEngine`
    methods, so the seam only worked for the one backend that already existed.
  - **The trait was split in two.** `from_profile` does not mention `IO`, so on an
    `IO`-generic trait it could not be called at all — `ActiveBackend::from_profile(&profile)`
    failed to infer the parameter. The `IO`-independent members now live on
    `TlsBackendConfig`, which `TlsBackend<IO>` requires. The rule that fell out: a member
    belongs on `TlsBackend<IO>` only if it actually involves the stream.
  - **A backend that negotiates nothing must not claim a negotiated protocol.** The mock
    first reported ALPN `h2` because the profile offers it first; `chromulate-http` duly
    spoke HTTP/2 to a plaintext HTTP/1 origin and a test failed. It now reports `None`.
  - **One HSTS test proves its point through TLS failing.**
    `a_recorded_hsts_policy_upgrades_a_later_plaintext_request` shows the scheme was rewritten
    by observing that the upgraded request cannot connect, which rests on a handshake against
    a plaintext port failing. Under a no-op backend that evidence evaporates, so the test is
    `ignore`d there with the reason recorded. The behaviour is fine; the evidence for it is
    what depends on real TLS.

- **A third backend, `recording::RecordingBackend`, is the acceptance harness a
  fingerprint-controlling backend has to pass.** The mock proved the seam admits a backend
  that is not rustls; it could not prove the seam admits one that *reproduces a fingerprint*,
  because it consumes nothing — it clones the profile's spec and hands the stream back, so
  cipher order, GREASE placement and the extension set were never exercised.

  This backend performs the step every real backend performs before any bytes move: flatten
  the profile into the vocabulary a TLS library accepts, which is wire code points and flags
  rather than Rust types. `SSL_CTX_set_cipher_list` takes numbers. Whatever a backend cannot
  express as numbers is lost at that boundary, silently, and the ClientHello is wrong.
  `RecordedClientHello` is that intermediate form, and `to_spec()` rebuilds a
  `ClientHelloSpec` from it **alone** — never from the profile it came from, because reaching
  back would make the round trip vacuous.

  Nine tests. The one that matters compares the reconstruction's JA4 with the profile's
  target. A mutation test proves it can fail: dropping an extension, dropping a cipher suite,
  reversing the signature algorithms, or clearing ALPN each move the fingerprint. One case
  deliberately does *not* — transposing two cipher suites, because JA4 sorts before hashing —
  and it is caught by a separate order assertion instead, which is why cipher order is its own
  test rather than folded into the JA4 one. An unrecognised TLS version code point is an error
  rather than a silent drop, and the error names the code point.

  Behind the same `--cfg chromulate_mock_backend` flag as the mock; nothing ships it.

  Still not established, and it is the important half: **configuration fidelity is not wire
  fidelity.** This harness shows a backend *could* be handed everything the profile specifies.
  Whether it *sends* it is what `tests/emitted_client_hello.rs` decodes real bytes for, and
  what rustls fails. Only a real second TLS implementation closes that gap.

- **The minimum supported Rust version is 1.88**, corrected rather than raised.
  `rust-version` said 1.85 while `cargo +1.85.0 check --workspace --all-features` had been
  failing: the engine uses a let-chain, stable only from 1.88 on the 2024 edition, and
  `rcgen` pulls `time@0.3.47`, which declares 1.88 itself. CI reported green throughout
  because its MSRV job never tested 1.85 — `rust-toolchain.toml` pins the channel to stable
  and won over the toolchain the action installed, the same failure the Miri and fuzz jobs
  carry comments about. That job now runs `cargo +1.88.0` explicitly.
- **`Engine::hsts()` and `Client::hsts()` are replaced by `with_hsts()`, which takes a
  closure.** The old methods returned the store's write guard, and a caller who held it
  across an `.await` — which the doc comment asked them not to do — blocked the worker so
  completely that a `tokio::time::timeout` around a later request never fired. A public API
  whose contract is "hold this wrong and your process stops responding" is a defect rather
  than a documented caveat. The closure releases the lock before it returns and the borrow
  cannot escape it. Migration: `client.hsts().record(…)` becomes
  `client.with_hsts(|store| store.record(…))`. No other public method in the workspace
  returns a lock guard; all twelve that do are private.
- **`PoolConfig::max_total` now bounds each connection population separately** rather than
  their sum, so a pool may hold up to twice it. They cannot share a budget: only an idle
  entry can be freed, so one counter lets either protocol starve the other. At its cap the
  multiplexed population **declines** a new origin rather than evicting one, and the reason
  is fidelity rather than capacity — dropping the pool's handle closes nothing, since an
  in-flight request holds its own clone, so eviction would only make the next request open a
  second connection to an origin that already has a healthy one. Two concurrent HTTP/2
  connections and a second SETTINGS preface from one client is a shape no browser produces.

- **A response head now has a thirty-second default bound.** `EngineConfig::new` and
  `ClientBuilder::new` both default `head_timeout` to 30s, matching the existing
  `connect_timeout` default. Before this, a default-configured client had no bound at all on
  a server that accepted a connection and then went quiet — only connection *establishment*
  was bounded. The whole-request `timeout` deliberately stays `None`: a large download, a
  streamed response and an SSE stream all legitimately run long, and no default tells one of
  those from a hang.

  **This breaks long polling** and anything else that withholds the response head until an
  event fires; there the silence is the protocol, not a stall. Those callers want the new
  `ClientBuilder::no_head_timeout()`, or `EngineConfig { head_timeout: None, .. }`.
  `head_timeout(Duration)` can only set `Some`, which is why the opt-out is its own method.

  The default is set in both places on purpose: `ClientBuilder::build` overwrites
  `config.head_timeout` unconditionally, so a default set only on `EngineConfig` would have
  left the facade — the primary public API — unbounded.

- **`chromulate_http::FinalUrl` is now `chromulate_http::ResponseInfo`**, a struct
  carrying the final URL *and* the timings. One extension rather than two:
  `http::Extensions` boxes every value it stores, so a second insert would have been a
  49th allocation on a path whose count is a published figure. `chromulate::Response`
  consumes it as before, so the facade API is unchanged.

### Fixed

- **Shipped output undercounted the GREASE positions by one.** `STRUCTURAL_LIMITS` — printed
  by `chromulate fingerprint` and by the `capabilities` example — said GREASE is missing from
  "the five slots the profile marks", and `docs/fidelity.md` enumerated five: first cipher,
  first extension, first supported group, first key share, last extension. The capture records
  **six** (`client_hello.grease_positions`), and `GreasePlacement::ALL` sets all of them: the
  omitted one is *first supported version*. The confusion is structural rather than careless —
  `GreasePlacement` carries five booleans because its `extensions` flag covers two wire slots
  — so the fix says which number counts what, and the guidance is to count against the capture
  rather than the struct. Corrected in `fidelity.rs`, `chromulate-tls`'s crate documentation,
  `docs/fidelity.md`, the assertion message in `emitted_client_hello.rs`, and `CLAUDE.md`,
  which had inherited the five-item list.

- **The Akamai fingerprint's PRIORITY field was assumed rather than checked.**
  `emitted_http2.rs` decoded SETTINGS, the connection `WINDOW_UPDATE`, the HEADERS flags and
  the pseudo-header order, and its prose claimed all four fields were verified from the wire —
  but its frame loop matched only types `0x4`, `0x8` and `0x1`, so a PRIORITY frame (`0x2`)
  fell through the catch-all arm unseen. Three fields were checked and the fourth was
  asserted by omission. The loop now counts PRIORITY frames and the test compares that count
  against the profile's. Being precise about what this guards: against the Chrome profile both
  sides are zero, so deleting the counting arm would leave the test green — it does not prove
  the counter counts. What it catches is the case that will actually arise: a profile whose
  capture *does* record PRIORITY frames, such as Firefox's `3:0:0:201,…`, against a client
  whose h2 write path for them is `unimplemented!()`. That divergence was previously silent.

Twelve of these came from adversarial audits of the six features above, run after they
landed. Each audit was told to try to break shipped code rather than review a plan, and to
re-verify the implementing agent's claims rather than inherit them.

- **A `304` could smuggle a response past every storability rule, including `Set-Cookie`.**
  The cache re-validated an entry and merged the `304`'s fields into it without re-running
  §3's checks, so an origin answering a revalidation — rather than a request — could attach
  `no-store`, `private` or `Set-Cookie` to a stored entry. The `Set-Cookie` case is the sharp
  one: it was merged into the stored headers and replayed to every later request for that
  URL, handing one identity's state to another, which the crate's own documentation said
  never happens. Storability is re-checked on the merged headers now; a refusal removes the
  entry and still returns what the origin sent.
- **A `304` naming a different `ETag` relabelled the stored body** (RFC 9111 §4.3.4), after
  which every later revalidation confirmed the wrong representation. Validators are compared
  by their opaque part now, past any `W/`.
- **A `304` changing `Vary` left the entry matching requests it was never fetched for.**
- **A body disagreeing with its `Content-Length` was stored with the disagreement frozen in**
  and served that way on every hit; RFC 9110 §6.3 calls such a message malformed.
- **An entry larger than a shard's share of the memory budget flushed that whole shard** —
  inserted, then purged along with every other key in it, keeping nothing. The defaults sit
  in exactly that range: `max_body_bytes` is 8 MiB against a default shard's 2 MiB, so one
  large response could flush a sixteenth of the cache. Refused now, dropping only the copy it
  supersedes.
- **A trailing root label bypassed the HSTS preload list entirely.** `https://gmail.com./`
  arrives with the host `gmail.com.`, which DNS resolves identically, but it matched no entry
  — so a request to a preloaded host went out in plaintext. The dynamic store had the mirror
  defect, keeping two policies for one host.
- **An empty label invented preload matches.** The ancestor walk stepped over the empty label
  in `a..app` and reached the `app` entry, forcing HTTPS on a host that never asked. Chromium
  rejects such names outright. Both are fixed by one canonicalisation in front of `record`,
  `applies_to` and the preload lookup; it costs about 33 ns per request, which is why the
  published lookup figure moved from 235 ns to 275.
- **`Stop::read` read past its budget**, so `Response::bytes_until` could overrun the
  client's `max_response_size` when a marker arrived in a single chunk. Two layers, each
  independently mutation-verified: a match ending past the budget no longer sets a target,
  and the target is clamped to the budget.
- **`Prefix::matched()` reported a match when the budget cut the marker in half**, so a
  caller could parse half a marker believing it whole.
- **`ValidatorStore::remove` took the write lock on an empty store**, and `observe` calls it
  on every `200` carrying no validator — five origins in six on the workload this feature
  documents. A store that had never held anything took an exclusive lock on every response.
- **`ValidatorStore`'s `Debug` printed every stored URL**, with query strings and userinfo;
  observed output included a password and a session token. It prints a count and a capacity
  now, matching what `Response`'s own `Debug` omits and why.
- **A lone CR or LF in a multipart field name was escaped as a filename's would be.** Blink
  normalises line endings in a name and does not in a filename; the capture could not
  distinguish the two rules because it contained exactly one line break and it was a pair,
  which renders identically under both. Corrected against Blink's source, and the capture
  file now records that this rule rests on a source reading rather than an observation —
  a weaker class of evidence, labelled as such.
- **A streamed empty chunk became an empty data frame**, which under chunked encoding is the
  end-of-body marker. hyper drops one before the socket so nothing broke over hyper, but
  `Form::into_body` returns a public `Body` and the two part kinds gave different guarantees.

- **A cookie set by a same-origin redirect was never sent on the next hop.** The engine
  consulted the jar only when the request carried no `Cookie` header, and a same-origin
  redirect kept the header computed for the first hop — so the second lookup was suppressed
  and the redirect's own `Set-Cookie` never reached the wire. A login that redirects after
  authenticating lost its session cookie, and a cookie the redirect *deleted* was replayed.
  The header the engine computes is now removed once the wire order has been built, so only a
  header the **caller** set survives into the next hop; a caller's own `Cookie` still wins on
  every hop, unchanged. The defect was invisible whenever the jar was empty before the first
  hop, which is what every existing redirect test started from.
- **HTTP/2 connections escaped the pool's `max_total` cap, and took HTTP/1.1 pooling with
  them.** Fifty multiplexed origins against a cap of ten pooled all fifty. Worse, both
  protocols shared one counter that only HTTP/1.1 eviction could decrement, so HTTP/2
  pressure evicted HTTP/1.1 sockets to satisfy a cap HTTP/2 never respected: after twenty
  HTTP/2 releases, one of five subsequent HTTP/1.1 connections remained retrievable. Now ten,
  and five of five.

- **The README's Rust examples are now compiled.** The status banner claimed they were, and
  nothing checked: the file was not wired into rustdoc, and one example used three
  variables it never declared. They are doctests now, so a change that breaks one fails
  `cargo test`.
- **A timeout larger than the monotonic clock could represent panicked the process.**
  `ClientBuilder::timeout` and `RequestBuilder::timeout` pass a caller's `Duration` through
  unvalidated, so `Duration::MAX` was one public call from `Instant::now() + total` and
  `overflow when adding duration to instant`. Such a budget now reads as no deadline at all,
  which is the same request: `Instant` has no epoch, so there is no portable far-future
  value to saturate to, and `Deadline` already carries "no limit" as `at: None`.
- **A large DNS cache TTL panicked on the first lookup it cached.** `CachingResolver::new`
  validates nothing, so `Duration::MAX` as a positive or negative TTL reached `now + ttl` in
  `Cache::settle` and panicked the first time a result was stored. Reachable from the
  facade, which re-exports the resolver. Expiries are computed with a checked addition now,
  and a TTL too large to represent caches the entry for the life of the process. TTLs are
  deliberately not clamped at construction: unlike a rate of zero, a TTL of centuries is a
  coherent request, and a ceiling would have made the checked addition unreachable.
- **A caller's rate limit could panic the process.** `RateLimit`'s fields are public, so
  `RateLimit { per_second: 0.0, burst: 1.0 }` reached a limiter without passing the
  assertion in `RateLimit::per_second`. `reserve` then divided the token debt by that rate
  and handed the quotient to `Duration::from_secs_f64`, which panics on infinity and on
  anything past `Duration`'s range. Observed before the fix for both `0.0` and `1e-300`.
  The rate is now clamped where every limit funnels through, to one request per hour rather
  than to an arbitrarily tiny value: a caller who misconfigured a limiter should see a rate
  limit, not a hang. A misconfigured limiter now runs slowly instead of taking the caller's
  process with it.
- **A stalled redirect body could outlive the whole-request deadline.** A redirect body is
  read off the socket before its connection is reused, and `REDIRECT_DRAIN_LIMIT` caps how
  many bytes that read accepts — but nothing capped how long it took. A server answering
  `302` with a `Content-Length` and then no bytes held the request open indefinitely. With
  `timeout` set to 200 ms the request was still running when the test harness cut it off at
  3.001 s; it now ends in 0.21 s. Abandoning the drain does not pool a half-read socket:
  a body that fails takes its connection with it, which is the behaviour `PoolSlot` already
  documented.
- **A test that raced on `tracing`'s callsite interest cache.** It failed on Linux while
  macOS and Windows passed, on the release commit. `with_default` installs a thread-local
  subscriber without rebuilding the global interest cache, so a callsite first evaluated
  with no subscriber installed stays cached as uninteresting and the capturing test sees
  nothing. Not reproducible locally — 25 runs pass either way — so the verification was the
  CI Linux job.

### Documentation

Corrections found by checking claims against the code rather than re-reading them:

- the design document described the connection pool as a **sharded map** and argued against
  the single mutex that is actually implemented;
- its pool defaults table said 8 idle per key and 256 total, against the code's 6 and 100,
  and listed a separate handshake timeout that shares the connect timeout;
- it claimed eviction on `GOAWAY` and on profile unregistration, neither of which exists;
- it described a **staggered RFC 8305 connect race** that `dial()` does not do — and says
  so in a comment at the call site. Corrected in the design document and in the README
  features table, where the same wrong claim had just been written;
- several `UNMEASURED` labels predated the harness, including one stating that no benchmark
  had ever been run;
- `CONTRIBUTING.md` listed three pre-PR commands where CI now runs six, and did not mention
  the shell pitfall that let two failures through this session: a piped `cargo clippy`
  reports the exit status of the pipe's last command.

`CLAUDE.md` gains a **Before every release** section requiring this pass, with these
examples in it, so the next release does not rediscover them.

Four questions the architecture documents did not answer at all now have sections: the
tokio task spawn strategy, the pool's ownership model, what backpressure does and does not
bound, and lock contention with numbers.

## [0.1.0] — 2026-08-04

The first release. Everything below was measured or tested before it was written down;
where something is unverified it says so, and the two documents that carry the numbers are
[`docs/performance.md`](docs/performance.md) and [`docs/fidelity.md`](docs/fidelity.md).

**Read [Honest limitations](README.md#honest-limitations) before depending on this.** The
short version: the HTTP layer reproduces the captured browser closely, the TLS ClientHello
does not match and is distinguishable at a glance, there is no HTTP/3, and one profile
ships.

### Added — initial implementation

The first working version of the engine: twelve crates covering the fingerprint algebra,
browser profiles, header construction, cookies, compression, DNS, proxies, TLS, the HTTP
engine, the public client, and a CLI.

- **Fingerprint model and computation.** JA3, JA4, JA4_r, and the Akamai HTTP/2 fingerprint,
  golden-tested against a live capture of a real Chrome 151 on macOS. A profile models its
  extensions as a *set plus permutation rules* rather than one frozen order, because two
  captures from the same browser minutes apart produced different JA3 hashes
  (`a0442bdf…` and `43b2a31e…`) with an identical cipher list — Chrome permutes its
  ClientHello extension order on every connection, so JA3 is not a stable identifier for a
  browser build and JA4, which sorts before hashing, is.
- **Header engine** reproducing the captured navigation header order exactly, with
  `Sec-Fetch-*` derivation, client-hint escalation via `Accept-CH`, and per-destination
  `Accept` values.
- **Cookie jar** with domain and path matching, the lenient browser date parser, `SameSite`,
  `Secure`, `__Host-`/`__Secure-` prefixes, and bounded eviction.
- **HTTP engine** with an identity-aware connection pool, the redirect loop, streaming
  decompression, and retry and rate-limiting middleware.
- **TLS engine** over rustls, with a `fidelity` module that reports the gap between the
  profile's target ClientHello and what rustls actually emits, as a value a caller can read
  and log rather than a caveat in prose.
- **CLI**: `get`, `fingerprint`, and `profiles`.

### Measured — performance

A benchmark harness (`crates/chromulate-bench`, plus criterion suites) was added and run on
an Apple M1 Pro. See [`benches/README.md`](benches/README.md) to reproduce.

- **Throughput: 0.79–0.88x of `reqwest`**, i.e. 12–21% slower, measured against a loopback
  origin at concurrency 1, 8, 64, and 256, as the median of paired per-round ratios. Four
  independent runs agree on that range; individual rounds under machine load reach 0.77x, so
  treat the range as the quiet-machine figure. A browser-identity engine doing more work per
  request than a plain client is expected; the specific cost is not, see below.
- **127 heap allocations per steady-state request**, against reqwest's 49 — 2.59x. **80 of
  those 127 are `HeaderEngine::apply`**, which costs 4.32 µs per request. The design
  documents' low-allocation claim is **not currently supported by measurement**, and the
  reason is that per-request work re-derives values that are constants of the profile.
  This is the single largest identified optimisation and it has not been applied.
- **Constant-memory streaming confirmed, with a control.** A 256 MiB body streams at a
  1.44 MiB peak; the identical body read through `Response::bytes` peaks at 260.7 MiB. The
  measurement can see buffering, and did not see it in the streaming path.
- Idle client ≈0.55 MiB over a tokio runtime; ≈38.8 KiB per pooled connection at the
  64→512 margin.
- Per-connection fingerprint work is negligible: generating a fresh extension permutation
  is 183 ns, `ja4` 4.2 µs, `ja4_raw` 3.1 µs, the Akamai string 453 ns. None of these runs
  per request.
- Cookie jar lookup is flat, not linear: `cookies_for` ≈1.14 µs and `store` replacing an
  existing cookie ≈530 ns, both unchanged across jars of 10, 1,000, and 10,000 cookies. Those
  figures are measured with the capacity limits raised so nothing is evicted.
- **The exception, and it is the common case for a long-running crawler:** once a jar reaches
  its default 3,000-cookie limit, a `store` that inserts a *new* cookie costs **21.6 µs**,
  against 536 ns for one that replaces an existing cookie in the same jar. The difference is
  eviction — picking the globally least-recently-used cookie means examining all of them.
  That mechanism is measured rather than inferred: a variant where every insert lands on its
  own domain, so per-domain trimming never runs, costs 22.4 µs — *slower*, not faster, which
  rules out per-domain trimming and localises the cost to the global scan alone.
  Linear in the cap, not in the number of requests, and a deliberate limit rather than a
  defect: removing it needs either a purge margin or a global LRU index, and both change what
  `JarLimits::total` means.

### Changed — performance, measured against the baseline above

The optimisation wave the baseline called for. Every figure is the median of runs on the
same machine and harness as the baseline; the baseline numbers are quoted alongside.

- **Throughput is at parity with `reqwest`: paired medians 0.93–1.09x** across concurrency
  1–256 (two independent runs), against the baseline's 0.79–0.88x. The machine was noisier
  than on the baseline day, so treat the claim as "the 12–21% deficit is gone", not
  "faster than reqwest".
- **48 heap allocations per steady-state request, from 127** — now *below* reqwest's 49
  (0.98x, was 2.59x). First request: 156 → 78 (reqwest 76). The design documents'
  low-allocation claim is now supported by measurement. The wave, in order of payoff:
  - `HeaderEngine` precomputes every profile-constant name and value at construction and
    promotes their buffers once: `apply` fell from 80 allocations / 4.38 µs to
    8 allocations / **1.46 µs** per request.
  - The wire header list is moved onto the outgoing request instead of the map being
    rebuilt and then cloned.
  - The parsed `Url` travels with the request (`RequestUrl` extension); the five
    `Url`/`Uri` crossings per request are gone, and `FinalUrl` is taken from the response
    rather than cloned.
  - The pool key's identity hash is computed once at construction instead of SipHashing
    ~200 bytes two to three times per request, and the https fallback key clones
    reference counts instead of re-copying strings.
  - The response body wrappers poll the `Body` directly: one boxed stream and two poll
    layers fewer per response.
- **`Pool::release` no longer walks the whole pool under the global mutex per request**:
  a running count answers the cap check, and the expiry sweep runs at most once per
  quarter of the idle timeout. Mechanism proven by construction and pinned by five new
  pool tests; the multi-origin throughput effect awaits a multi-origin harness.
- **Cookie eviction at the caps is amortised, mirroring Chromium's purge batches** (a
  tenth of the total cap, a sixth of the per-domain cap): storing a new cookie into a
  full default jar fell from **21.9 µs to 1.32 µs** (one domain) and **22.7 µs to
  1.85 µs** (spread domains); replace stays ~560 ns. The caps are now documented as
  ceilings the jar purges below, not levels it sits at, and two new mutations in
  `tools/cookie-mutation-check.py` guard the batching.
- **`Body::collect` pre-sizes from the declared length** (hyper's `Content-Length` size
  hint now travels with the body): collecting 16 MiB fell from 1.62 ms to **492 µs**
  (9.7 → 31.7 GiB/s). Undeclared lengths are unchanged.
- **`PoolConfig::http1_max_buf_size`** bounds hyper's per-connection h1 buffers (default
  unchanged). Measured with 512 pooled connections that had each downloaded a 4 MiB body:
  resident memory fell from a ~381 MiB median to ~217 MiB with a 16 KiB cap — roughly
  45% — while with 1 KiB bodies the buffers never grow and the cap saves nothing. It also
  caps the acceptable response header block, which is why it is a documented knob rather
  than a new default.
- The Accept-CH store's read lock is skipped until a grant has ever been recorded.
- Constant-memory streaming still holds after the body-path changes (256 MiB at a
  +1.39 MiB peak against a +260 MiB buffering control), and the wire header order still
  matches the capture — both re-verified, not assumed.

### Changed — dependency bumps, measured

`md-5` 0.10 → 0.11, `sha2` 0.10 → 0.11, `base64` 0.22 → 0.23, `rand` 0.9 → 0.10, and
`actions/checkout` v4 → v7. Each was merged and verified on its own; `rand` 0.10 moved
`random_range` from `Rng` to a blanket-implemented `RngExt`, which the GREASE draw and the
retry jitter now import.

Measured against the same benches on the same machine, two independent runs agreeing:

| | Before | After |
|---|---:|---:|
| `fingerprint/ja4` | 4.39 µs | **3.52 µs** (−20%) |
| `fingerprint/ja4_raw` | 3.38 µs | **3.19 µs** (−14%) |
| `fingerprint/ja3_hash` | 373 ns | **350 ns** (−6%) |
| `fingerprint/wire_extension_order` | 183 ns | **171 ns** (−6.5%) |
| Allocations per request | 48 | 48 (unchanged) |
| `header/*`, `cookies_for/*`, `body_collect/*` | — | unchanged |

The RustCrypto 0.11 releases are where the JA4 gain comes from. Nothing regressed, and
allocation counts are byte-identical.

The GREASE draw was re-verified rather than assumed to survive the `rand` upgrade: over
2,000 seeds it still yields all sixteen reserved code points and every one satisfies
RFC 8701's `0x?A?A`. The golden Chrome 151 tests and the live network tests stay green.

`dtolnay/rust-toolchain` is now in the Dependabot ignore list: the `msrv` job pins it to
1.85.0 because that is the workspace's declared `rust-version`, not because it is an
action version to keep current, and bumping it would have left the job green while
verifying nothing.

### Added — HSTS, supply-chain checks, and profile verification

- **HTTP Strict Transport Security (RFC 6797).** An origin that has sent
  `Strict-Transport-Security` is never spoken to in plaintext again — the upgrade happens
  before the request is sent, because a redirect would already be too late. A header
  arriving over cleartext is ignored (§8.1), IP-literal hosts take no policy (§8.1.1), and
  `max-age=0` removes one (§6.1.1). The store is bounded.
- **`chromulate verify`** rebuilds every shipped profile from the capture compiled into the
  binary and compares JA4, JA3, the Akamai fingerprint, the header order and the user agent
  against what ships. It enforces the project's strictest rule — no hand-written fingerprint
  constant — from outside the test suite, and runs as its own CI job. Proven by mutation:
  changing one window-update constant produces a diff and exit 1.
- **`cargo deny` in CI**, covering advisories, licences, duplicate versions and source
  registries. It found two real things on its first run: a stack-exhaustion advisory in
  `time` reachable through a dev-dependency added the same day, and `webpki-roots` shipping
  Mozilla's CA data under a licence the policy had not listed.
- **Adversarial sweeps for the expansion guard**, covering four codings against
  incompressible, highly compressible and mixed payloads, plus truncation, trailing garbage,
  bit flips and mismatched codings. Mutation-checked. Not a substitute for coverage-guided
  fuzzing, but it runs in CI on stable, which `cargo fuzz` cannot.

### Fixed — HTTP/2 connections were never pooled

Found by measuring a real HTTPS origin for the first time.

An HTTP/1.1 connection returns to the pool when its response body ends. An HTTP/2
connection multiplexes, so nothing gave it back — and nothing registered the freshly
opened one either, so **every HTTP/2 request opened a new TCP connection and repeated the
TLS handshake**, against every modern origin, for the life of the client. No offline
benchmark here could see it: the loopback origin is plaintext, ALPN never runs, and the
HTTP/2 connection path was unexercised.

`Engine::acquire` now registers a newly opened multiplexed connection with the pool.
Measured on a CDN asset serving all clients identical bytes: a warm request went from
289 ms to **170 ms**, and the paired ratio against `reqwest` from 0.345x — 2.9x slower —
to **0.992x**. Two network-gated tests (`chromulate-http/tests/live_pooling.rs`) pin it,
both watched failing first.

### Added — a live benchmark harness

`cargo run -p chromulate-bench --features live --bin live` measures a real HTTPS origin
with TLS and HTTP/2 in the picture: cold and warm latency against `reqwest`, pool
occupancy, and a body dump for checking that two clients were actually served the same
page. See [`benches/README.md`](benches/README.md); the measured results are in
[`docs/performance.md`](docs/performance.md).

Its first finding beyond the pooling bug is a caveat on every real-page comparison: the
measured origin serves non-browser clients an extra ~90 KB hidden SEO block, so Chromulate
downloads 17% less and cannot be compared like for like on those URLs. Where the bytes are
identical, the two clients are at parity.

### Measured — fidelity

Against a live echo endpoint, the engine reproduces Chrome 151's HTTP/2 preface in 3 of the
Akamai fingerprint's 4 fields and its request header order exactly, where an ordinary `curl`
matches 1 of 4 and none of the order. The one HTTP/2 field that differs is the pseudo-header
order, hard-coded in `h2`, and it is reported by `Http2Fidelity::unsupported` rather than
hidden.

Its TLS JA4 does **not** match Chrome's, and is no closer than `curl`'s. A JA4 either matches
or it does not; "closer" buys nothing for a hash comparison. See
[the design document](docs/architecture/02-chromulate-design.md) §8 for exactly which rustls
limits cause this and what would have to change.

### Fixed — from the first review pass

A review of the initial implementation found and reproduced 24 defects, every one with a
failing test before the fix. The ones worth recording:

- **A hostile server could abort the client process.** An oversized `Content-Encoding`
  response header built an unbounded chain of nested decoders; polling it overflowed the
  stack and aborted with `SIGABRT`, which no supervisor can recover. A ~2.4 KB header
  sufficed in a debug build and ~12 KB in release. The coding list is now bounded and
  decoders are no longer built eagerly.
- **A retried `POST` could silently send an empty body.** `Body::try_clone` reported a
  drained fixed body as replayable, returning `Some` of an empty body, and
  `Error::is_retryable` classified send-phase body errors as retryable. Together a dropped
  connection produced a replay with no payload and `Content-Length: 0`. `try_clone` now
  returns `None` once the bytes have gone, and body errors are never retryable.
- **`Accept-CH` was treated as additive.** RFC 8942 §3.1 specifies that an opt-in *overrides*
  the persisted set, so a site could not narrow the hints it received, and an empty
  `Accept-CH` — the documented way to clear the set — was a no-op. Now replaces.
- **`__Host-` and `__Secure-` cookie name prefixes were not enforced**, on either the parse
  path or the snapshot-import path. Both now share one predicate.
- **A cancelled DNS lookup poisoned its hostname** for the life of the process and leaked the
  cache entry.
- **Two unrelated IP literals computed as `Sec-Fetch-Site: same-site`.**
- **`SameSite=Strict` cookies were never sent**, not even same-origin, because the
  `CookieStore` trait carried no fetch context.
- **A plaintext response could delete a `Secure` cookie** with `Max-Age=0`, though it could
  not overwrite one.
- **`Jar::store` was quadratic.** One response carrying 50,000 `Set-Cookie` headers took
  7,653 ms; it now takes 28 ms (mean of three runs). A crawl over 16,000 distinct sites went
  from 1,857 ms to 238 ms. At the top end this was a denial of service, not just a slow path.
- Plus SOCKS5 credential truncation, a `Jar::import` overflow panic, an expansion-ratio guard
  weakened by nested codings, and several parser leniencies.

### Known gaps

- The emitted ClientHello is not byte-identical to the captured browser's: no GREASE, no
  ALPS, no SCT, 9 of 15 cipher suites, and rustls appends an SCSV Chrome does not send. The
  `fidelity` module enumerates these at runtime.
- HTTP/2 pseudo-header order cannot be set through `h2`.
- Only the Chrome profile ships with captured data. Others need a capture; nothing is
  fabricated.
- The capture covers one navigation request, so per-destination `Accept` and `priority`
  values, the subresource header order, and the `cookie` header's position are modelled
  rather than observed, and are marked as such in the source.

[Unreleased]: https://github.com/cagataycankaya/chromulate/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/cagataycankaya/chromulate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cagataycankaya/chromulate/releases/tag/v0.1.0
