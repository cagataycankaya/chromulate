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

The Cargo workspace exists with twelve members (`Cargo.toml:3-16`), shared dependency
versions, and workspace lints including `unsafe_code = "forbid"` (`Cargo.toml:70-77`).

`chromulate-core` is written: the error hierarchy
(`crates/chromulate-core/src/error.rs`), the streaming body
(`crates/chromulate-core/src/body.rs`), per-request browser fetch context
(`crates/chromulate-core/src/request.rs`), URL and origin helpers
(`crates/chromulate-core/src/uri.rs`), and the extension traits
(`crates/chromulate-core/src/traits.rs`). It contains no I/O by design
(`crates/chromulate-core/src/lib.rs:3-6`).

**Definition of done, and how it was met.** The crate builds, has no I/O dependency, and
carries tests beside the code. Counting the test functions in the five modules gives 24
(`error.rs` 4, `body.rs` 6, `request.rs` 4, `traits.rs` 3, `uri.rs` 7) plus the doc example
at `lib.rs:8-16`, which matches the 25 the shared API contract records as green. Those tests
were not run as part of writing this document, so the pass state here is cited, not
observed.

---

## Phase 1: The identity data plane

**Status: Landing.**

`chromulate-fingerprint` and `chromulate-profile`: the ClientHello and HTTP/2 models, the
JA3, JA4 and Akamai computations, and the Chrome profile populated from the capture at
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

**Status: Landing.**

Four leaf crates that depend only on core, plus the header engine that depends on the
profile.

`chromulate-cookie` — a browser-grade jar implementing `CookieStore`
(`crates/chromulate-core/src/traits.rs:71-77`), with the lenient date parser real browsers
use, public-suffix rejection, `SameSite` handling, and per-domain eviction.

`chromulate-compression` — streaming decoders for the codings a browser advertises, with
an expansion guard, and the default `Accept-Encoding` value `gzip, deflate, br, zstd`
matching the capture (`chrome-151-macos.json:152`).

`chromulate-dns` — `Resolve` implementations with TTL caching, single-flight collapsing of
concurrent lookups for one host, and IP version preference.

`chromulate-proxy` — proxy URL parsing, `no_proxy` rules, HTTP `CONNECT` and SOCKS5
handshakes, and rotation, with credentials redacted from `Debug` and from every error
message.

`chromulate-header` — the profile plus a request context to an ordered header list, with
`Sec-Fetch-*` derived from `RequestOptions` (`crates/chromulate-core/src/request.rs:122-139`)
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

**Status: Next.**

`chromulate-tls` translates a `ClientHelloSpec` into a rustls configuration: cipher order
from a custom `CryptoProvider`, group order, ALPN, certificate compression, resumption.

`chromulate-http` provides the connection pool keyed on origin, proxy and identity, the
HTTP/1.1 and HTTP/2 exchanges, the redirect loop, and the terminal `Exchange`
implementation (`crates/chromulate-core/src/traits.rs:81-84`).

`chromulate` provides `Client`, its builder, and the request API. `chromulate-cli` provides
`get`, `fingerprint`, and the profile `diff` and `verify` subcommands that make profile
maintenance a reviewable process rather than a research project.

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
- `chromulate-cli profile verify` recomputes every shipped profile against its capture and
  exits non-zero on a mismatch. This runs in CI.
- Clippy clean across the workspace; `cargo test` green offline, with network tests behind
  the `network-tests` feature.

---

## Phase 4: Emitted-shape verification

**Status: Next, immediately after Phase 3.**

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

**Status: Speculative.** Four independent options, each with its own definition of done.
None is a prerequisite for a useful 1.0.

**Switch the rustls provider to `aws-lc-rs`.** Supplies `X25519MLKEM768`, so the group list
and the two-share key exchange can match the capture (`chrome-151-macos.json:84-86`). Done
when the Phase 4 diff no longer reports a supported-groups mismatch, and when the C build
dependency is documented and gated behind a feature so pure-Rust builds remain possible.

**Contribute GREASE and ALPS upstream to rustls.** rustls's own documentation lists ALPS as
something it may implement (rustls 0.23.43, `src/manual/features.rs:98`). Done when the
features are released upstream and the Phase 4 diff shrinks accordingly. Outside this
project's control; needs an owner willing to work on someone else's schedule.

**A pluggable TLS backend trait.** Specified in section 9.8 of the design document. Done
when the rustls implementation sits behind the trait with no behaviour change, so that an
out-of-tree BoringSSL backend is possible without the default build acquiring a C
dependency.

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
`:method, :authority, :scheme, :path` (`chrome-151-macos.json:127`). Regular header order
is equally out of reach, because h2 encodes fields by iterating the `HeaderMap`.

Two routes: upstream support in h2 for a caller-specified pseudo-header order and a
caller-specified field order, or a Chromulate-owned HPACK encoding path. The first is
cheaper and slower; the second is a significant amount of protocol code to own.

**Definition of done.** The Phase 4 HTTP/2 diff is empty, and `akamai_http2` computed from
the emitted frames equals `52d84b11737d980aef856699f885ca86`.

---

## Phase 7: Performance

**Status: Next after Phase 3, and strictly in this order.**

The harness comes first. No optimisation is merged before it exists, and none is merged
without a before-and-after from it. The design document's section 10 is entirely
UNMEASURED, and it will stay that way until this phase produces numbers.

**Definition of done for the harness.**

- Three benchmark families: a middleware chain-depth sweep, to price the boxed futures at
  the extension boundaries; a throughput test against a local server with pool reuse on and
  off; and an allocation count per request under a heap profiler.
- Every benchmark reports n≥3 runs with variance. A single run is not a measurement.
- A documented command that reproduces the numbers on a developer machine.
- Section 10 of the design document is updated with measured values, replacing the targets.

**Definition of done for the optimisation work that follows.** Each merged change cites the
harness output before and after. Changes that do not improve a measured number are not
merged, however plausible the reasoning.

Two questions the harness is expected to settle: the pool's shard count, currently
unchosen; and whether the per-extension-boundary allocation of the boxed-future design
(design document section 3.4) is measurable at all against the cost of a syscall.

---

## Phase 8: Ecosystem and long term

**Status: Speculative.** Roughly in priority order.

**More captured profiles.** Chrome Beta, Chrome Canary, Chrome on Linux and Windows,
Firefox, Safari. Each needs a real capture; none will be written by hand. The blocker is
access to browsers and a capture procedure, not code — the loader already exists from Phase
1. Richer captures also close the gaps in section 5.6 of the design document: per-destination
`Accept` values, subresource header order, non-document `priority` values, and high-entropy
client hints.

**HSTS.** A store consulted before the request leaves, populated from
`Strict-Transport-Security` responses, with an optional preload list behind a feature flag.
This should land before 1.0, because an engine that makes a plaintext request where a
browser would not has an observable behavioural difference and a real downgrade exposure.

**HTTP/3.** Architecture only until the open questions in section 15 of the design document
are answered — principally whether one pool can sensibly hold both TCP and QUIC connections
for an origin. The transport seam from Phase 5 is the natural place for it.

**An HTTP cache.** Deferred from v1 because the `Middleware` seam already supports it and
most target users do not want one. Revisited when someone needs it enough to maintain
RFC 9111 correctness.

**Documentation.** An architecture book built from these documents, a cookbook of worked
examples, a plugin guide covering the seven seams, and a performance guide that exists only
once Phase 7 has produced numbers to put in it.

**CI maturity.** The platform matrix on stable and on the 1.85 MSRV (`Cargo.toml:21`), Miri
over `chromulate-core` only (it has no I/O and is therefore tractable), coverage reporting,
and a scheduled job running the `network-tests` suite separately from pull-request CI so
that an unrelated upstream outage does not block a merge.

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
