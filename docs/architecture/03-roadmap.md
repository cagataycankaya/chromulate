# Chromulate Roadmap

Revision of 2026-08-04. Companion to
[`02-chromulate-design.md`](02-chromulate-design.md).

This roadmap describes what exists, what is being built right now, what comes next, and
what is speculative. Each phase carries a definition of done that someone could check
without asking the author what they meant. Where a phase depends on something outside the
project's control, that is stated rather than scheduled.

No dates are given. The project has one capture, a core crate, and a workspace; committing
to a calendar on that basis would be a work of fiction. The phases are ordered by
dependency, and each is small enough to finish.

---

## Table of contents

- [Status legend](#status-legend)
- [Phase 0: Workspace and core vocabulary](#phase-0-workspace-and-core-vocabulary)
- [Phase 1: The identity data plane](#phase-1-the-identity-data-plane)
- [Phase 2: Supporting engines](#phase-2-supporting-engines)
- [Phase 3: Transport, HTTP, and a working client](#phase-3-transport-http-and-a-working-client)
- [Phase 4: Emitted-shape verification](#phase-4-emitted-shape-verification)
- [Phase 5: Closing the TLS gap](#phase-5-closing-the-tls-gap)
- [Phase 6: HTTP/2 wire fidelity](#phase-6-http2-wire-fidelity)
- [Phase 7: Performance](#phase-7-performance)
- [Phase 8: Ecosystem and long term](#phase-8-ecosystem-and-long-term)
- [What is deliberately not on this roadmap](#what-is-deliberately-not-on-this-roadmap)

---

## Status legend

**Done** — written and in the repository.
**Landing** — being written in the change that produced this document.
**Next** — specified, not started, no blockers.
**Speculative** — depends on a decision or on work outside this repository.

The relationship between the phases here and the phase lists in `docs/prompts/prompt-1.md:435-462` and
`docs/prompts/prompt-3.md:437-471` is not one to one, and deliberately so. Both prompts order the work
as core, TLS, profiles, HTTP/2, HTTP/3, performance. That order builds the transport before
the thing the transport is supposed to reproduce, which means the TLS work would have no
reference to check itself against. This roadmap inverts the first half: the identity data
plane and its golden tests come before the transport, so that when the TLS crate is written
there is already an authoritative answer to what it is trying to produce.

---

## Phase 0: Workspace and core vocabulary

**Status: Done.**

The Cargo workspace exists with fifteen members (`Cargo.toml:3-19`) — the fourteen published
crates plus `chromulate-bench`, which is `publish = false` — shared dependency versions, and
workspace lints including `unsafe_code = "forbid"` (`Cargo.toml:90-93`).

`chromulate-core` is written: the error hierarchy
(`crates/chromulate-core/src/error.rs`), the streaming body
(`crates/chromulate-core/src/body.rs`), per-request browser fetch context
(`crates/chromulate-core/src/request.rs`), URL and origin helpers
(`crates/chromulate-core/src/uri.rs`), and the extension traits
(`crates/chromulate-core/src/traits.rs`). It contains no I/O by design
(`crates/chromulate-core/src/lib.rs:3-6`).

**Definition of done, and how it was met.** The crate builds, has no I/O dependency, and
carries tests beside the code. Counting the test functions in the six modules gives 38
(`error.rs` 5, `body.rs` 7, `request.rs` 8, `traits.rs` 4, `uri.rs` 7, `timings.rs` 7) plus
two doc examples (`lib.rs:8-16` and `timings.rs:51-61`, the latter on `Timings` itself).
`timings.rs` is the per-phase timings module, added after this document's first count.
`cargo test -p chromulate-core` was run while writing this revision: 38 unit tests and 2 doc
tests, all passing.

---

## Phase 1: The identity data plane

**Status: Done.**

`chromulate-fingerprint` and `chromulate-profile` shipped in 0.1.0 (`CHANGELOG.md:144-161`):
the ClientHello and HTTP/2 models, the JA3, JA4 and Akamai computations, and the Chrome
profile populated from the capture at
`crates/chromulate-fingerprint/tests/data/chrome-151-macos.json`.

This is Phase 1 rather than Phase 3 because it produces the reference every later phase
checks itself against. Writing the TLS crate first would mean writing it against a mental
model of Chrome rather than against a tested one.

**Definition of done.**

- `ja3` reproduces the capture's string for both samples (`chrome-151-macos.json:20`,
  `:31`) and `ja3_hash` reproduces `a0442bdf8e49e27cb5ee80009f29a6a2` and
  `43b2a31e00f7c2151cef4cd21c7c58f7`.
- `ja4` reproduces `t13d1516h2_8daaf6152771_806a8c22fdea` and
  `t13d1517h2_8daaf6152771_a87ad97598a9`; `ja4_raw` reproduces both `ja4_r` fields.
- `akamai_http2` reproduces `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` and its
  MD5 `52d84b11737d980aef856699f885ca86`.
- Extension order is modelled as a set plus a permutation policy: two different seeds
  produce two different wire orders over the same set, GREASE occupies first and last, and
  `pre_shared_key` is last whenever present.
- Shuffling never reorders the cipher list.
- `Profile::chrome_stable()` computes to the captured JA4. This single assertion is what
  connects the profile constants to observed reality.
- A JSON loader accepts a user-supplied capture in the same format the shipped profile uses.
- No fingerprint constant exists that is not traceable to a field of the capture. Firefox
  and Safari profiles are not shipped, because no capture for them exists.
- `cargo clippy -p <crate> --all-targets -- -D warnings` is clean and `cargo test -p <crate>`
  is green, with the output pasted into the crate's report.

---

## Phase 2: Supporting engines

**Status: Done.**

Four leaf crates that depend only on core, plus the header engine that depends on the
profile. All five shipped in 0.1.0 (`CHANGELOG.md:144-161`).

`chromulate-cookie` — a browser-grade jar implementing `CookieStore`
(`crates/chromulate-core/src/traits.rs:71-77`), with the lenient date parser real browsers
use, public-suffix rejection, `SameSite` handling, and per-domain eviction.

`chromulate-compression` — streaming decoders for the codings a browser advertises, with
an expansion guard, and the default `Accept-Encoding` value `gzip, deflate, br, zstd`
matching the capture (`chrome-151-macos.json:152`).

`chromulate-dns` — `Resolve` implementations with fixed-TTL caching, single-flight collapsing of
concurrent lookups for one host, and IP version preference.

`chromulate-proxy` — proxy URL parsing, `no_proxy` rules, HTTP `CONNECT` and SOCKS5
handshakes, and rotation, with credentials redacted from `Debug` and from every error
message.

`chromulate-header` — the profile plus a request context to an ordered header list, with
`Sec-Fetch-*` derived from `RequestOptions` (`crates/chromulate-core/src/request.rs:122-144`)
and `Referer` from `referrer_for` (`crates/chromulate-core/src/uri.rs:89-107`).

**Definition of done.** Per crate: clippy clean, tests green, with output in the crate's
report. Behaviourally, the tests that matter are the ones that are easy to skip. Cookie
expiry tested with an injected clock and never with `sleep`. Single-flight proven with a
counting resolver: N concurrent lookups for one host increment the counter once. Proxy wire
formats asserted byte for byte against a local `TcpListener` playing the proxy role, for
both `CONNECT` and SOCKS5, including the failure paths. Decompression proven streaming
rather than buffered, and the expansion guard proven with a highly compressible payload.
Credentials proven absent from `format!("{:?}", proxy)` and from `to_string()`.

Header order is produced from the profile's explicit order list, not from `HeaderMap`
iteration — `http::HeaderMap` iterates in an arbitrary order the crate declines to guarantee
(http 1.5.0, `src/header/map.rs:914`), so relying on it would produce an order unrelated to
any browser.

---

## Phase 3: Transport, HTTP, and a working client

**Status: Done.** Every item in the definition below is met and covered by a test, with two
worth naming because they are the ones a reader would doubt: two profiles sharing a pool
never share a connection (`pool.rs`, and end to end in `engine_behaviour.rs`), and
`chromulate verify` rebuilds each profile from its capture and fails on drift.

`chromulate-tls` translates a `ClientHelloSpec` into a rustls configuration: cipher order
from a custom `CryptoProvider`, group order, ALPN, certificate compression, resumption.

`chromulate-http` provides the connection pool keyed on origin, proxy and identity, the
HTTP/1.1 and HTTP/2 exchanges, the redirect loop, and the terminal `Exchange`
implementation (`crates/chromulate-core/src/traits.rs:89-92`).

`chromulate` provides `Client`, its builder, and the request API. `chromulate-cli` builds the
`chromulate` binary, with `get`, `fingerprint`, `profiles`, and `verify` subcommands that make
profile maintenance a reviewable process rather than a research project. There is no `profile
diff` subcommand; recomputing a profile from its capture and reporting drift is what `verify`
does.

**Definition of done.**

- `Client::chrome().get(url).send().await` returns a 200 from a real HTTPS origin.
- A second request to the same origin reuses the pooled connection, proven by a test that
  observes one handshake for two requests.
- Two requests with different profiles against the same origin do **not** share a
  connection, proven by a test that observes two handshakes. This is the assertion that
  protects the design's central premise.
- A redirect chain is followed, with cookies applied per hop against that hop's URL, and
  `Authorization` and `Cookie` dropped on a cross-origin hop.
- A streaming download of a body larger than available memory completes at constant
  residency.
- Dropping a response mid-body does not return the connection to the pool as reusable.
- `chromulate-cli fingerprint` prints the target fingerprint the profile describes and the
  configuration actually handed to rustls, side by side.
- `chromulate verify` recomputes every shipped profile against its capture and exits non-zero
  on a mismatch. This runs in CI (`.github/workflows/ci.yml:119`).
- Clippy clean across the workspace; `cargo test` green offline, with network tests behind
  the `network-tests` feature.

---

## Phase 4: Emitted-shape verification

**Status: Mostly done.** The ClientHello is decoded off the wire and compared with the
profile field by field (`chromulate-tls/tests/emitted_client_hello.rs`), and the HTTP/2
preface is recorded from a local TLS origin and compared likewise, including the
pseudo-header order decoded out of the HPACK block
(`chromulate-http/tests/emitted_http2.rs`). The measured deltas are written up in
[`../fidelity.md`](../fidelity.md).

Two items remain: the diffs live as assertions inside the tests rather than as separate
checked-in artifacts, and `Client::identity_report()` does not exist — the CLI's
`fingerprint` subcommand reports the same information, but from the profile and the
provider's capabilities rather than from a measurement.

This is the most valuable phase on the roadmap and the one most likely to be skipped,
because everything appears to work without it.

Every test through Phase 3 checks what Chromulate *computes*. Nothing checks what
Chromulate *emits*. Section 8 of the design document is written from reading rustls and h2
source, which predicts a fingerprint mismatch but does not measure it. This phase replaces
that prediction with a measurement.

**Definition of done.**

- A local TLS listener captures the raw ClientHello, parses it back into a
  `ClientHelloSpec`, and produces a diff against the Chrome profile.
- A local HTTP/2 server records the SETTINGS frame in order, the connection window update,
  and the HPACK-decoded header sequence including pseudo-headers, and diffs those against
  the profile's `Http2Spec`.
- Both diffs are checked into the repository as artifacts and asserted in CI. They are
  expected to be non-empty. The test fails when a diff *changes*, not when it is non-empty,
  so a regression is caught and a known gap is not treated as a failure.
- The design document's section 8.4 is updated to replace "UNMEASURED" with the measured
  JA3 and JA4 that Chromulate actually presents.
- `Client::identity_report()` reports the measured delta rather than a computed one.

After this phase the project can state its fidelity as a number instead of an argument.

---

## Phase 5: Closing the TLS gap

**Status: Partly done.** Four independent options, each with its own definition of done. Two
have landed, one is outstanding and outside this project's control, and one was considered
and rejected. None is a prerequisite for a useful 1.0, and the two that landed did not close
the gap this phase is named for — section 8.4 of the design document still stands.

**Switch the rustls provider to `aws-lc-rs`. Status: Done.** It ships behind the
off-by-default `aws-lc-rs` feature (`crates/chromulate-tls/Cargo.toml`), which selects the
provider at `provider.rs:32-39`. It supplies `X25519MLKEM768`, so on that build the profile's
group list goes from three of four offered to four of four and the key shares become exactly
the pair the capture shows (`chrome-151-macos.json:84-86`), which
`crates/chromulate-tls/src/lib.rs:54-60` records. The stated conditions are both met: the C
build dependency is documented in the feature's own comment and is gated, so a pure-Rust
build with no C toolchain remains the default. Nothing else in the fidelity gap moved — not
GREASE, not ALPS, not the SCT extension, not the six missing cipher suites, not the SCSV.

**Contribute GREASE and ALPS upstream to rustls.** rustls's own documentation lists ALPS as
something it may implement (rustls 0.23.43, `src/manual/features.rs:98`). Done when the
features are released upstream and the Phase 4 diff shrinks accordingly. Outside this
project's control; needs an owner willing to work on someone else's schedule.

**A pluggable TLS backend trait. Status: Done (2026-08-05).** Specified in section 9.8 of
the design document. The rustls implementation now sits behind `TlsBackend` with no
behaviour change: `chromulate-http` holds an `ActiveBackend`, handshakes through the trait,
and derives its stream type from it, so an out-of-tree BoringSSL backend is possible without
the default build acquiring a C dependency. The full battery — `fmt`, `clippy` under
`RUSTFLAGS=-D warnings`, the workspace tests, `cargo +1.88 check`, and `cargo doc` under
`RUSTDOCFLAGS=-D warnings` — was green across the change.

A second implementation followed, because a trait with one is a guess: `mock::MockBackend`
under `--cfg chromulate_mock_backend`, checked by its own CI job. Writing it found three
trait members missing (`from_profile`, `target_identity`, `fidelity`, all of them inherent
`TlsEngine` methods the seam could not reach) and one that could not be called at all,
because `from_profile` does not mention `IO` and so could not be resolved on an
`IO`-generic trait. The trait is now split into `TlsBackendConfig` and `TlsBackend<IO>`.

The mock was undemanding — it consumes nothing — so a third implementation followed:
`recording::RecordingBackend`, which flattens a profile into wire code points the way a TLS
library requires and rebuilds a `ClientHelloSpec` from that alone. Its round-trip test
compares the reconstruction's JA4 with the profile's target, and a mutation test proves the
round trip can fail. This is the acceptance harness a BoringSSL backend is measured against.

What this does *not* establish: configuration fidelity is not wire fidelity. The harness
shows a backend *could* be handed everything the profile specifies; whether it *sends* it is
what `tests/emitted_client_hello.rs` decodes real bytes for, and what rustls fails. Only a
real second TLS implementation closes that.

**A custom ClientHello encoder in front of rustls.** Assessed in the design document as
not recommended: the ClientHello is part of a transcript both sides hash, and splicing a
hand-built one in front of a state machine that believes it built a different one produces
failures that are version-dependent and very hard to debug. Listed here for completeness
and to record that it was considered and rejected rather than overlooked.

The six cipher suites rustls does not implement — CBC and static-RSA
(`chrome-151-macos.json:60-77` versus rustls 0.23.43 `src/crypto/ring/mod.rs:71-89`) — are
not addressed by any of these options and will not be. Their absence is a deliberate
security position of rustls, and asking for them upstream would be asking rustls to be a
different library.

---

## Phase 6: HTTP/2 wire fidelity

**Status: Speculative.**

Three of the four Akamai fingerprint components are reachable with stock h2: the SETTINGS
list, the connection window increment, and the empty priority field. The fourth is not.
h2 emits pseudo-headers as `:method, :scheme, :authority, :path`
(h2 0.4.15, `src/frame/headers.rs:704-731`) where Chrome sends
`:method, :authority, :scheme, :path` (`chrome-151-macos.json:127`).

Regular header order is *not* in the same position, and this document said it was until
2026-08-08. h2 encodes fields by iterating the `HeaderMap`, which is exactly what makes the
order controllable: the engine rebuilds the map in the profile's order and h2 writes it out
that way. Section 8.5 of the design document has the detail and the guard test.

### What the routes cost, measured 2026-08-08

The earlier text weighed two routes qualitatively — "the first is cheaper and slower; the
second is a significant amount of protocol code to own" — which is not a basis for choosing.
These are counted rather than estimated:

| Route | Measured cost |
|---|---|
| Upstream setter in h2 | **~90–110 lines.** A config value reaches the send path through 13 sites in 5 files, measured by tracing `initial_max_send_streams`; pseudo-header order needs that path plus a rewrite of the `Iter::next` chain, and HEADERS priority needs it plus five bytes and a flag in `Headers::encode`. |
| Renamed fork, published | The same ~100 lines, **plus re-owning hyper's HTTP/2 glue**. `[patch.crates-io]` cannot be shipped by a library — verified by experiment — so `chromulate-http` would have to stop using `hyper::client::conn::http2`. |
| Depend on the published `http2` fork | **~300–700 lines, UNMEASURED** — the one figure in this table that is estimated rather than counted. hyper links `h2`, not `http2`, so the HTTP/2 path would drive `http2` directly while HTTP/1.1 stays on hyper; `h2`'s own client example is 52 lines and is the floor. |
| Chromulate-owned HPACK path | Not re-costed. The route above dominates it and no longer needs deciding first. |

**The glue is the expensive half, and it cannot be taken in part.** Of hyper's 2,388 lines of
h2 glue, roughly 676 are unreachable for this crate — `ping.rs`'s BDP and keep-alive
machinery is behind `is_enabled()`, which is false when neither adaptive window nor
keep-alive is set, so 248 of its 515 lines never construct; CONNECT upgrade support is about
83; and 15 of `client/conn/http2.rs`'s 27 public functions are setters nothing here calls.
That leaves ~1,712 genuinely needed. But `proto/h2/client.rs` reaches into nine internal
hyper modules across fourteen imports — `dispatch`, `body`, `common`, `upgrade`, `rt::bounds`
among them — so the reachable part does not lift out cleanly.

The empirical check agrees: `wreq`, a maintained browser-fingerprinting client, took exactly
this route and carries `http2` (a renamed h2 fork, 27,238 lines against h2's 26,161) plus
`wreq-proto`, a fork of hyper's whole protocol layer at 10,836 lines, of which the h2 glue is
2,412 — within a percent of hyper's 2,388. It re-owned the glue nearly line for line and
keeps hyper only as a dev-dependency. **Plan against ~10,800, not ~1,700.**

That figure prices *owning* a fork, and there is a third route that does not: depending on
the fork that is already published. `http2` (crates.io, MIT, the renamed `h2` fork wreq
carries) already exposes `headers_pseudo_order`, `headers_stream_dependency`, and
`settings_order`, and its encode path writes the stream dependency — the exact line stock
`h2` leaves as a no-op. Checked 2026-08-08: version 0.5.20 had merged upstream h2 0.4.15 in
full — its changelog's top entry is h2's, verbatim — including the CONTINUATION-flood
protection. What this route costs is the adapter in the table above, plus a trust decision:
security fixes arrive from a single maintainer rather than from hyperium, so the fork's
currency against upstream is a thing to re-verify at the moment of adoption, not a property
to remember from this paragraph.

**Try upstream first.** h2 has already accepted a fingerprint-motivated knob: issue #637,
asking for a `header_table_size` setter for exactly this purpose, closed as completed, and
this crate calls that setter today. hyper's #3170 closed `not_planned`, but on the
architectural ground that hyper has no TLS rather than any objection to the goal. A rejected
PR costs the ~60 lines it took to write; an unnecessary fork costs the glue forever.

**Definition of done.** The Phase 4 HTTP/2 diff is empty, and `akamai_http2` computed from
the emitted frames equals `52d84b11737d980aef856699f885ca86`.

---

## Phase 7: Performance

**Status: Done.** The harness came first and the wave followed it; both are recorded in
[`../performance.md`](../performance.md), with the pre-wave state in
[`../performance-baseline.md`](../performance-baseline.md). The middleware chain-depth sweep
is the one specified family that does not exist.

The harness was built before any optimisation was merged, and every merged change cites a
before-and-after from it. The design document's section 10, once entirely UNMEASURED, now
carries the measured values.

**Definition of done for the harness, as specified.**

- Three benchmark families: a middleware chain-depth sweep, to price the boxed futures at
  the extension boundaries; a throughput test against a local server with pool reuse on and
  off; and an allocation count per request under a heap profiler. **The chain-depth sweep was
  not built.** `crates/chromulate-bench/src/bin/` holds `allocs.rs`, `e2e.rs`, `live.rs`,
  `memory.rs`, `multiorigin.rs`, `profile.rs`, and `tlsbench.rs` — none of them sweeps
  middleware chain depth. The other two families exist: `e2e.rs` for throughput, `allocs.rs`
  for the allocation count.
- Every benchmark reports n≥3 runs with variance. A single run is not a measurement.
- A documented command that reproduces the numbers on a developer machine (`benches/README.md`).
- Section 10 of the design document is updated with measured values, replacing the targets.

**Definition of done for the optimisation work that follows.** Each merged change cites the
harness output before and after. Changes that do not improve a measured number are not
merged, however plausible the reasoning.

The pool's concurrency model turned out to be a single `Mutex<PoolState>`
(`crates/chromulate-http/src/pool.rs:266`), not a shard map, so there was no shard count for
the harness to settle — §10.3 of the design document found it flat to 100 origins once the
release-path sweep was amortised. What remains open is whether the per-extension-boundary
allocation of the boxed-future design (design document section 3.4) is measurable at all
against the cost of a syscall.

---

## Phase 8: Ecosystem and long term

**Status: read the item, not the phase.** Roughly in priority order. This phase was written as
speculative and is no longer: HSTS and the HTTP cache have landed in full, HTTP/3 has landed
in half, and CI maturity has landed except for one piece. Only the first and fifth items below
are untouched.

**More captured profiles.** Chrome Beta, Chrome Canary, Chrome on Linux and Windows,
Firefox, Safari. Each needs a real capture; none will be written by hand. The blocker is
access to browsers and a capture procedure, not code — the loader already exists from Phase
1. Richer captures also close the gaps in section 5.6 of the design document: per-destination
`Accept` values, subresource header order, non-document `priority` values, and high-entropy
client hints.

**HSTS.** **Done**, preload list included. A store is consulted before the request leaves
and is populated from `Strict-Transport-Security` responses; a header arriving over
cleartext is ignored, IP literals take no policy, and `max-age=0` removes one. The preload
list ships behind the off-by-default `hsts-preload` feature and is the part that protects
the *first* request to an origin this process has never visited — `Client::with_hsts()` remains
the lighter answer, letting a caller seed a
policy it already knows.

**HTTP/3.** Split in two. `Alt-Svc` parsing and the alternative-service cache: **Done**, in
`chromulate-h3`. The QUIC transport: **Speculative**, assessed and recommended against for
now — a real request succeeds, but the handshake cannot be shaped through `quinn`'s public
API and there is no Chrome-over-QUIC capture to measure its fidelity against, so shipping
it would mean claiming a protocol surface nobody checked. See
[`04-http3-assessment.md`](04-http3-assessment.md).

**An HTTP cache.** **Done.** `chromulate-cache`, behind `chromulate-http`'s off-by-default
`cache` feature. The parts of RFC 9111 it does not implement are listed in the crate's own
documentation rather than left to be discovered.

**Documentation.** An architecture book built from these documents, a cookbook of worked
examples, a plugin guide covering the seven seams, and a performance guide that exists only
once Phase 7 has produced numbers to put in it.

**CI maturity.** **Done except for coverage reporting.** The platform matrix runs the tests on
Linux, macOS and Windows (`.github/workflows/ci.yml:47-53`); a separate job checks the 1.88
MSRV with `cargo +1.88.0` pinned explicitly, because `rust-toolchain.toml` would otherwise win
and silently run it on stable (`:62-75`); Miri runs over `chromulate-core` only, for the
tractability reason above (`:88-105`); and the `network-tests` suite runs in its own job with
`continue-on-error`, on a nightly cron rather than per push, so an unrelated upstream outage
does not block a merge (`:8-14`, `:219-229`).

**Coverage reporting is the one item still missing**, and it is the one with the least
obvious payoff: a line-coverage number over a workspace whose hardest properties are checked
by mutation (`tools/cookie-mutation-check.py`) and by emitted-shape decoding would move
without meaning much either way. Worth adding for the diff view on a pull request rather than
for the percentage.

---

## What is deliberately not on this roadmap

A JavaScript engine, a DOM, or any form of rendering. These are permanent exclusions, not
unscheduled work.

Anything whose purpose is to avoid detection. The design document's section 13.4 gives the
engineering argument: fidelity to a capture is testable and undetectability is not, so
building toward the latter produces a codebase where nobody can tell whether a change helped.

Benchmark comparisons against other HTTP clients. They will not appear in any document
until someone has run them, and when they do appear they will name the harness, the
hardware, and the run count.
