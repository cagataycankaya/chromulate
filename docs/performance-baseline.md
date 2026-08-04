# Performance baseline

Measured numbers for Chromulate as of the initial implementation. Reproduce them with the
harness described in [`../benches/README.md`](../benches/README.md); this document records
what it produced, so a reader deciding whether to depend on the crate does not have to run
it first.

Everything here is measured. Where something is inferred rather than measured, it says so.

> **Status (2026-08-04, later the same day):** the optimisation opportunities at the end of
> this document have since been applied and re-measured on the same machine and harness.
> This document is kept as the *before* record; the after numbers, and what each change
> was worth, are in [`performance.md`](performance.md), with the summary in the
> [changelog](../CHANGELOG.md) under "Changed — performance". Headlines: throughput parity
> with reqwest (paired medians 0.93–1.09x, was 0.79–0.88x), 48 allocations per steady-state
> request (was 127; reqwest 49), full-jar cookie insert 1.3–1.9 µs amortised (was ~21–22 µs).

## Machine

| | |
|---|---|
| CPU | Apple M1 Pro, 10 cores (8 performance + 2 efficiency) |
| Memory | 16 GiB |
| OS | macOS 26.5.2, Darwin 25.5.0 |
| Toolchain | rustc 1.97.1, `opt-level = 3`, `lto = "thin"`, `codegen-units = 1` |
| Baseline client | `reqwest` 0.13, `default-features = false` |

## Throughput against reqwest

Loopback hyper origin, 1 KiB body, plaintext HTTP/1.1, keep-alive, connection reuse verified
by counting server-side accepts. Each figure is the median of paired per-round ratios —
paired so that both clients are compared on the same machine state rather than on two means
taken minutes apart.

**Three independent runs, by two operators:**

| Concurrency | run A | run B | run C (quiet machine, n=7) |
|---:|---:|---:|---:|
| 1 | 0.872x | 0.873x | 0.875x |
| 8 | 0.834x | 0.832x | 0.836x |
| 64 | 0.817x | 0.803x | 0.802x |
| 256 | 0.815x | ~0.81x | 0.792x |

**Chromulate sustains 0.79–0.88x of reqwest's throughput — it is 12 to 21% slower.** Maximum
disagreement between runs is 0.023x.

Those are medians. **Individual rounds under CPU contention reach 0.767x**, which is real
behaviour rather than measurement error: if you quote a single round rather than a median,
expect the lower figure.

A browser-identity engine doing more work per request than a plain HTTP client is the
expected result. Chromulate computes an ordered, profile-exact header list on every request;
reqwest writes the handful of headers it was given.

## Allocations per request

Counting global allocator, current-thread runtime, deterministic across repeats.

| | Chromulate | reqwest | Ratio |
|---|---:|---:|---:|
| First request (connect) | 156 | 76 | 2.05x |
| Steady state, per request | **127** | **49** | **2.59x** |
| Steady state, bytes | 22,333 | 16,380 | 1.36x |

Where they go, measured in isolation:

| Component | Allocations | Bytes |
|---|---:|---:|
| **`HeaderEngine::apply`** | **80** | **6,507** |
| `RequestBuilder::build` | 8 | 522 |
| `Url::parse` round-trip inside `send` | 4 | 147 |
| `Url::parse` | 3 | 103 |
| `Jar::cookies_for` (empty jar) | 2 | 13 |

**The low-allocation claim in the design documents is not supported by this measurement.**
Eighty of the 127 allocations are the header engine re-deriving values that are constants of
the profile: `build_order` copies the base order into a fresh `Vec<String>`, every value is
built as a `String` and then re-encoded through `HeaderValue::from_str`, and non-standard
header names are re-parsed and cloned two or three times each.

That the header engine is the largest cost is measured. That it accounts for roughly half
the throughput gap is an **inference** — it assumes both clients are CPU-saturated, which
was not verified with a profiler.

## Memory

| | |
|---|---:|
| Idle client over a tokio runtime | +0.55 MiB |
| Per pooled connection (64→512 margin) | 38.8 KiB |
| 512 pooled connections | ≈21 MiB |

### Streaming, with a control

| | Body | Peak RSS | Delta |
|---|---:|---:|---:|
| `Response::bytes_stream` | 256 MiB | 4.25 MiB | **+1.44 MiB** |
| `Response::bytes` (control) | 256 MiB | 263.55 MiB | +260.72 MiB |

**Constant-memory streaming holds.** The control is what makes that meaningful: the same
body read through the buffering API peaks at 260 MiB, so the measurement can see buffering
when it happens, and did not see it in the streaming path.

## Micro-benchmarks

Per connection, not per request:

| | |
|---|---:|
| `wire_extension_order` (fresh permutation) | 183 ns |
| `ja4` | 4.22 µs |
| `ja4_raw` | 3.14 µs |
| `akamai_http2` | 453 ns |
| `akamai_http2_hash` | 162 ns |

Fingerprint computation is not on the per-request path and is not worth optimising.

### Cookie jar

| | |
|---|---:|
| `cookies_for`, jars of 10 / 1,000 / 10,000 | ≈1.14 µs, flat |
| `store` replacing an existing cookie | ≈530 ns, flat |
| `store` inserting into a jar **at the 3,000 default cap** | **21.4 µs** |

The first two rows are measured with the capacity limits raised so nothing is evicted.
The third is the steady state for a long-running crawler, whose jar reaches the cap and
stays there: **41x the replace path**, because choosing the globally least-recently-used
victim examines every cookie.

The mechanism is measured, not assumed. A variant where every insert lands on its own
domain — so per-domain trimming cannot fire — costs 22.4 µs, *slower* rather than faster.
Per-domain trimming contributes nothing; the cost is the global scan alone. That matters
because both candidate fixes, a purge margin and a global LRU index, target the global scan.

Lookup is linear in the matching bucket, not in the jar.

## What this does not measure

- **TLS.** Every throughput figure is plaintext HTTP/1.1 on loopback, so the handshake —
  Chromulate's distinguishing work — contributes nothing to these numbers.
- **HTTP/2 throughput**, entirely.
- **A real network.** On loopback, reopening a connection is nearly free, which is why the
  default 6-connection pool costs nothing measurable here even while reopening 250
  connections per round at concurrency 256. Over a real network with TLS each of those
  would cost a round trip and a handshake. Do not read "the default pool is free" from this.

## Known optimisation opportunities

Ranked by expected payoff. **All three have since been applied** — see the status note at
the top and the changelog for the measured results. The list is kept as written so the
predictions can be compared against what the changes actually delivered.

1. **Precompute the profile's constant headers in `HeaderEngine::new`.** `HeaderName` and
   `HeaderValue` are both `Bytes`-backed, so cloning is a refcount bump rather than an
   allocation. Most of the 80 allocations per request are recomputing values that never
   change for a given profile.
2. **Avoid the `Url::parse` round-trip inside `send`** — 4 allocations to re-parse a URL the
   caller already parsed.
3. **Give the cookie jar a purge margin or a global LRU index** so a full jar does not scan
   every cookie per insert.
