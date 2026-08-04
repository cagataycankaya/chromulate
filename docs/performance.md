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

## Deliberate behaviour changes

- `JarLimits::total` and `per_domain` are ceilings the jar purges one batch below
  (a tenth / a sixth), matching Chromium; documented on the type, guarded by mutation.
- `Pool::len()` can briefly count expired-but-unswept entries between sweeps.
- `PoolConfig` gained a field; construct it with `..PoolConfig::default()`.
- `RequestBuilder::build` attaches a `RequestUrl` extension the engine consumes.

## What this still does not measure

Unchanged from the baseline, and worth reading before trusting any number here in another
setting: throughput against an HTTPS origin and over HTTP/2 (Chromulate's distinguishing
work is in the handshake, and none of it appears in these figures); CPU attribution by a
sampling profiler; multi-origin pool behaviour, which is also what the `Pool::release`
change needs for its throughput claim; real-network behaviour; memory under a soak test;
and an end-to-end workload whose responses actually set cookies.
