# Performance

The measured performance of Chromulate after the 2026-08-04 optimisation wave, and a
record of what that wave changed, why, and what each change was worth. The numbers this
work started from are preserved unchanged in the
[performance baseline](performance-baseline.md); reproduce either set with the harness
described in [`../benches/README.md`](../benches/README.md).

Everything here is measured — median of at least three runs, or criterion medians — on an
Apple M1 Pro (8P+2E, 16 GiB, macOS 26.5.2), rustc 1.97.1, `opt-level = 3`, `lto = "thin"`,
`codegen-units = 1`, against `reqwest` 0.13 with `default-features = false`. Where a claim
is inferred or unmeasured, it says so.

## Headlines, before → after

| Metric | Baseline | Now | Command |
|---|---:|---:|---|
| Throughput vs reqwest, paired medians, c=1–256 | 0.79–0.88x | **0.93–1.09x** | `--bin e2e` |
| Heap allocations per steady-state request | 127 (2.59x reqwest) | **48 (0.98x)** | `--bin allocs` |
| Allocations, first request (connect) | 156 | **78** | `--bin allocs` |
| Bytes allocated per request | 22,333 | **20,855** | `--bin allocs` |
| `HeaderEngine::apply`, per request | 80 allocs / 4.38 µs | **8 allocs / 1.46 µs** | `cargo bench -p chromulate-header` |
| Cookie `store` into a full default jar | 21.9–22.7 µs | **1.32–1.85 µs** | `cargo bench -p chromulate-cookie` |
| `Body::collect`, 16 MiB, length declared | 1.62 ms | **492 µs (31.7 GiB/s)** | `cargo bench -p chromulate-core` |
| 512 pooled connections after 4 MiB bodies, with the 16 KiB buffer cap | ~381 MiB | **~217 MiB** | `--bin memory -- pool 512` |
| Streaming a 256 MiB body, peak RSS delta | +1.45 MiB | **+1.39 MiB** | `--bin memory -- stream` |

Two honesty notes. The throughput confirmation runs were taken on a noisier machine than
the baseline day; the paired-median design absorbs that, and two independent runs agree,
but the defensible claim is *the 12–21% deficit is gone*, not *Chromulate is faster than
reqwest*. And the buffer-cap row is an **opt-in knob** measured under the workload it
exists for (grown buffers); under 1 KiB bodies it saves nothing.

## What the wave changed, and what each change was worth

Ranked as applied. Every mechanism below was verified by the named benchmark before and
after the change; the test suite (577 tests), `clippy -D warnings`, and
`tools/cookie-mutation-check.py` were green at every commit.

### 1. The header engine precomputes everything the profile fixes

The largest single cost in the workspace. `HeaderEngine::apply` re-derived, on every
request, values that are constants of the profile: the header order was cloned as a fresh
`Vec<String>`, every value was built as a `String` and re-encoded through
`HeaderValue::from_str`, and non-standard header names were re-parsed per request. Worse,
each freshly built name and value was backed by a vec-backed `Bytes` whose *first* clone
pays a promotion allocation — and the request path cloned every one of them.

Names and constant values are now parsed, encoded, and promoted once, when the engine is
built; the order plan is a vector of prepared slots; enum-derived values
(`sec-fetch-*`, `priority`, `upgrade-insecure-requests`, the non-document `accept`
variants) use `HeaderValue::from_static`, which never allocates; and the caller's header
map is taken rather than cloned. Apply-time error semantics for unencodable profile
values are preserved.

**Measured:** `apply` 80 → 8 allocations, 4.38 → 1.46 µs; whole request 127 → 59
allocations. The wire order still matches the Chrome capture — the golden tests and the
live loopback order test are the guard.

### 2–3. One header map and one URL parse per request, instead of three and five

The engine built the ordered header list, rebuilt the request's map from it, then cloned
the whole map onto the outgoing request; the ordered list is now moved onto the wire
request and the rebuild is gone. Separately, one request crossed the `Url`/`Uri` boundary
five times (parse, serialise, re-parse in `send`, re-parse in `Engine::run`, re-derive as
the wire target); the parsed `Url` now travels in a `RequestUrl` extension, the wire
`Uri` is carved out of the request's own `Uri` components, and the facade takes `FinalUrl`
out of the response extensions instead of cloning it.

**Measured:** 59 → 50 allocations per request.

### 4. The pool key stopped re-hashing the identity string

`PoolKey`'s derived `Hash` fed the ~200-byte connection identity (JA4 | Akamai | user
agent) through SipHash two to three times per request, for a value constant for the
engine's lifetime. The identity now carries a content hash computed once; `Hash` writes
that word. The https fallback key is derived from the preferred key by cloning reference
counts instead of copying strings. **Allocations unchanged on the plaintext harness (its
single http origin builds one key); the saving is CPU and applies to https key sets —
folded into the end-to-end figure.**

### 5. `Pool::release` no longer walks the pool under the global mutex

Every release ran a full expiry sweep over every idle and multiplexed entry and then
re-counted the whole pool — inside the one mutex all requests share, O(max_total) per
request in a multi-origin crawl, and invisible in a single-origin benchmark. A running
`held` count answers the cap check in O(1), and the sweep runs at most once per quarter of
the idle timeout; expired entries are still rejected at checkout, and the at-cap path
evicts oldest-first, so cap enforcement is unchanged. Five new pool tests pin the
invariants; all were run green against the old implementation first.

**Mechanism proven by construction; the multi-origin throughput effect is UNMEASURED
until the harness grows a multi-origin mode.**

### 6. The response body wrappers poll the body directly

Each response body was wrapped through `BodyStream` + `filter_map` + `Box::pin` twice —
three wrapper allocations and a six-layer poll chain, four layers dynamic. The pool-return
and deadline wrappers now hold the `Body` and poll its frames directly.

**Measured:** 50 → 48 allocations per request — Chromulate now allocates slightly less
per steady-state request than reqwest (0.98x).

### 7. `Body::collect` pre-sizes from the declared length

`collect` grew a `BytesMut` by doubling, copying a 16 MiB body repeatedly on the way up,
and the engine never propagated hyper's exact size hint, so no response body ever declared
a length. The hint now travels with the body and `collect` sizes its buffer once, clamped
to the collect limit so a lying `Content-Length` cannot become an allocation the peer
never backs with data.

**Measured:** 16 MiB collect 1.62 ms → 492 µs (9.7 → 31.7 GiB/s) when the length is
declared; undeclared lengths unchanged.

### 8. Cookie eviction purges in batches, the way Chromium does

A jar at its 3,000-cookie cap evicted exactly one cookie per store, paying a full-jar
least-recently-used scan every time — the permanent state of a long-running crawler. The
per-domain path had the same shape hidden inside it: every store rescanned the whole
bucket even when nothing was over any cap (measured at 363 entry visits per single-cookie
store). Both caps now purge in batches using Chromium's own ratios — a tenth of the total
(`kPurgeCookies` 300 / `kMaxCookies` 3300), a sixth of the per-domain cap
(`kDomainPurgeCookies` 30 / `kMaxCookiesPerHost` 180). The caps are ceilings the jar
never exceeds at rest; under sustained pressure the level oscillates one batch below.
Limits too small to batch keep the old exact-cap behaviour.

Three new tests were written first and watched fail against the old code; the
mutation-check script gained two mutations that revert each batch independently, and
reports every fix covered.

**Measured:** full-jar insert 21.9 µs → 1.32 µs (one domain, 16.6x) and 22.7 µs → 1.85 µs
(spread domains, 12.3x); replace ~560 ns and lookups unchanged.

### 9. The Accept-CH lock is skipped until a grant exists

`RwLock::read` on every request is an atomic read-modify-write on a shared cache line,
paid even though most deployments never see an `Accept-CH` header. An `AtomicBool` now
gates the lock; until a grant is recorded, an empty store answers identically without it.
Coherence-traffic saving, UNMEASURED at this concurrency.

### 10. Callers can bound hyper's per-connection HTTP/1.1 buffers

Nothing configured hyper's `http1::Builder`, so every pooled connection carried the
defaults: an adaptive read buffer with a 408 KiB ceiling that never shrinks while the
connection idles, plus the write buffer. `PoolConfig::http1_max_buf_size` (default `None`
keeps hyper's behaviour) now bounds them. It is a behavioural knob, not a free
optimisation — the same ceiling caps the response header block hyper will accept, and
values under hyper's 8 KiB floor are raised to it.

**Measured, 512 pooled connections that each downloaded a 4 MiB body first:** default
buffers 370–476 MiB resident (median ~381); capped at 16 KiB, 188–220 MiB (median ~217) —
roughly 45% less, with no overlap between the run sets. With 1 KiB bodies the buffers
never grow and the cap saves nothing; that is the workload to size it against. For HTTP/2
deployments, remember the advertised 15 MiB connection window — part of the Akamai
fingerprint, so not tunable — is the number to plan per-connection memory against.

## Where the CPU actually goes

Measured with a sampling profiler (`sample` on macOS) attached to a dedicated
single-client load — `cargo run --release -p chromulate-bench --bin profile -- 25 64`,
1.7 million requests, 12 s of samples, concurrency 64 against the plaintext loopback
origin. Percentages are of *busy* samples; threads parked in the scheduler are excluded,
because counting them would measure how long the run was rather than what it did.

| Category | % of busy samples |
|---|---:|
| Syscall I/O (`recvfrom`, `sendto`, `writev`) | **46.8%** |
| Allocator and `memmove`/`memset` | 15.2% |
| Unattributed / other | 10.5% |
| Chromulate HTTP engine | 8.2% |
| **Waiting on locks** | **6.8%** |
| hyper / http / h2 | 6.8% |
| Chromulate header engine | **2.8%** |
| tokio runtime | 2.8% |
| Chromulate cookie jar | 0.1% |

Three things this settles.

**The header engine is no longer the story.** This document used to carry an inference —
that `HeaderEngine::apply` was "about half" the original throughput gap — labelled as an
inference because nothing had profiled it. Profiled, after the precompute change, it is
**2.8% of busy CPU**. The inference is retired; the number replaces it.

**On loopback the client is I/O-bound, not CPU-bound.** Nearly half of busy time is in
socket syscalls. That is a property of the benchmark as much as of the client — a real
network moves time from syscalls to waiting — but it means per-request CPU work is not what
limits throughput here, which is worth knowing before optimising any of the smaller rows.

**Lock waiting is now larger than any single Chromulate component.** At 6.8% it is more
than double the header engine. The call graph shows it arising from the pool mutex
(`Pool::checkout` and `Pool::release`), the cookie jar's read lock, and the allocator's own
internal locks — so a second run with the jar disabled attributes it: lock waiting barely
moves (6.8% → 6.5%), which rules the cookie jar out and leaves the pool mutex and the
allocator. That is the honest next target if this profile is ever the binding one, and it
is measured rather than guessed — see §10.3 of the design document for why the single pool
mutex is nonetheless not the bottleneck at 100 origins.

## Dependency bumps, 2026-08-04

`md-5` and `sha2` 0.10 → 0.11, `base64` 0.22 → 0.23, `rand` 0.9 → 0.10, merged one at a
time with the full suite green after each. The RustCrypto releases moved the fingerprint
hashes measurably, and nothing regressed:

| | Before | After |
|---|---:|---:|
| `fingerprint/ja4` | 4.39 µs | **3.52 µs** (−20%) |
| `fingerprint/ja4_raw` | 3.38 µs | **3.19 µs** (−14%) |
| `fingerprint/ja3_hash` | 373 ns | **350 ns** (−6%) |
| `fingerprint/wire_extension_order` | 183 ns | **171 ns** (−6.5%) |
| Allocations per request | 48 | 48 |
| `header`, `cookie`, `body_collect` | — | unchanged |

None of it is on the per-request path — the fingerprint work runs per connection at most,
and `ja4` runs only on demand — so this is a real improvement in a place that was already
too cheap to matter. It is recorded because a dependency bump that moves a number by 20%
in either direction is worth knowing about.

One caveat about method, since it nearly became a wrong claim in this document:
`wire_extension_order` first appeared to have improved by 66%. It had not. The pre-merge
sample for that row was taken on a loaded machine and read 315–463 ns against a true value
of ~183 ns, so the comparison was against noise. A second run settled it at 171 ns. When a
bench row disagrees with its own recorded history by 2.5x, the baseline is the suspect,
not the change.

## Against a real origin

Everything above is loopback, which isolates client overhead and says nothing about the
work that distinguishes this crate: the TLS handshake and the HTTP/2 path. The `live`
harness measures a real HTTPS origin, and the first thing it found was a defect no offline
benchmark in this repository could have found.

**HTTP/2 connections were never pooled.** An HTTP/1.1 connection returns to the pool when
its response body ends; an HTTP/2 connection multiplexes, so nothing gave it back — and
nothing registered the freshly opened one either. Every HTTP/2 request therefore opened a
new TCP connection and repeated the TLS handshake, against every modern origin, for the
life of the client. The loopback origin is plaintext, so ALPN never runs and the HTTP/2
connection path was simply unexercised. Measured against a CDN asset serving all clients
identical bytes:

| Warm request, 620 KB asset | Before | After |
|---|---:|---:|
| Chromulate, total median | 289 ms | **170 ms** |
| Paired ratio vs `reqwest` | 0.345x (2.9x slower) | **0.992x** (parity) |
| Pool occupancy after a request | 0 | 1, and stable |

Two network-gated tests in `chromulate-http/tests/live_pooling.rs` pin it; both were
watched failing first. Run them with
`cargo test -p chromulate-http --features network-tests -- --ignored`.

### What the live numbers say

Two questions, two different answers, and conflating them is how a benchmark misleads.

**Client overhead is at parity.** On a static CDN asset — where all three clients receive
byte-identical responses (620,723 B) — Chromulate is 1.009x cold and 0.992x warm against
`reqwest`. That is the honest client-to-client comparison, because it is the only one where
both sides did the same work.

**End to end on real pages, Chromulate is faster, and mostly not for a reason in the
client.** Against Trendyol product pages (16 URLs, alternating order, paired medians):
1.76x per URL, TTFB 324 ms against 552 ms. But the origin does not serve the two clients
the same page: it sends `reqwest` an extra ~90 KB hidden `dr-webmenu-links` block — a
crawler-oriented SEO menu — that a browser-identified client never receives. Chromulate
downloads 17% less and the origin answers it faster. Product data is identical in both;
that was checked, not assumed.

So: **presenting a browser identity got a faster answer and a smaller page from this
origin, while the client itself is neither faster nor slower than `reqwest`.** Both halves
matter, and only the second is a property of this code.

| Live measurement | Chromulate | `reqwest` | Ratio |
|---|---:|---:|---|
| CDN asset, identical bytes, warm | 170 ms | 166 ms | 0.992x (parity) |
| CDN asset, identical bytes, cold | 457 ms | 463 ms | 1.009x |
| Product page, warm | 320 ms | 453 ms | 1.444x |
| Product page, cold | 537 ms | 722 ms | 1.320x |
| 16-page crawl, per URL median | 353 ms | 628 ms | 1.762x |

Reproduce with `cargo run --release -p chromulate-bench --features live --bin live -- …`;
see [`../benches/README.md`](../benches/README.md) for the modes and the pacing rules.

## Deliberate behaviour changes

- `JarLimits::total` and `per_domain` are ceilings the jar purges one batch below
  (a tenth / a sixth), matching Chromium; documented on the type, guarded by mutation.
- `Pool::len()` can briefly count expired-but-unswept entries between sweeps.
- `PoolConfig` gained a field; construct it with `..PoolConfig::default()`.
- `RequestBuilder::build` attaches a `RequestUrl` extension the engine consumes.

## What this still does not measure

Worth reading before trusting any number here in another setting.

- **Concurrent throughput over HTTPS.** The live harness measures latency one request at a
  time. The requests-per-second figures are all plaintext loopback.
- **CPU attribution by a sampling profiler.** The claim that the header engine was about
  half the original loopback gap was always an inference, and remains one.
- **Multi-origin pool behaviour**, which is what the `Pool::release` change needs before
  its throughput claim can be more than a mechanism.
- **Memory under a soak test.** Every memory figure is a point measurement.
- **Any origin but the two the live runs used.** The 1.76x on real pages is a property of
  that origin's behaviour towards a browser identity as much as of this client; another
  site that serves every client the same bytes should be expected to look like the CDN
  row, which is parity.
