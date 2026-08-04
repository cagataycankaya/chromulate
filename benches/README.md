# Benchmarks

Everything here answers a question that would otherwise be answered by
guessing. Run the command, read the number; do not quote a number from this file
without re-running it on your own machine, because none of these figures are
properties of Chromulate alone — they are properties of Chromulate on one
machine under one load.

The measured results live in [`docs/performance.md`](../docs/performance.md)
(current, after the 2026-08-04 optimisation wave) and
[`docs/performance-baseline.md`](../docs/performance-baseline.md) (the state that
wave started from), together with the CPU and toolchain they came from.

## What is here

| Command | What it answers |
|---|---|
| `cargo run --release -p chromulate-bench --bin e2e` | How many requests per second, against `reqwest` as a baseline |
| `cargo run --release -p chromulate-bench --bin allocs` | How many heap allocations one request costs, against `reqwest` |
| `cargo run --release -p chromulate-bench --bin memory -- <phase>` | Resident memory: idle, pooled, and while streaming |
| `cargo bench -p chromulate-fingerprint` | Per-connection ClientHello permutation and fingerprint strings |
| `cargo bench -p chromulate-header` | Building the ordered header list for one request |
| `cargo bench -p chromulate-cookie` | Cookie lookup and storage as the jar grows |
| `cargo bench -p chromulate-core` | `Body::collect` over a chunked stream |
| `cargo bench -p chromulate-compression` | Decompression throughput per coding |
| `cargo run --release -p chromulate-bench --bin multiorigin` | Throughput as the number of distinct origins grows — the shape a single-origin run hides |
| `cargo run --release -p chromulate-bench --bin profile -- <secs> <concurrency>` | A steady single-client load for a sampling profiler to attach to |
| `cargo run --release -p chromulate-bench --bin memory -- soak <secs>` | Resident memory sampled over a sustained multi-origin load, so a leak shows as a slope |
| `cargo run --release -p chromulate-bench --features live --bin live -- …` | Latency against a **real HTTPS origin**, with TLS and HTTP/2 in the picture |
| `cargo run --release -p chromulate-bench --features live --bin tlsbench` | Concurrent throughput over TLS and HTTP/2 against a **local** origin |
| `python3 tools/pool-scan-cost.py` | What the amortised pool sweep is worth, by reverting it and re-measuring |

`cargo bench --workspace` runs every criterion suite.

## End-to-end throughput

```
cargo run --release -p chromulate-bench --bin e2e
```

A loopback hyper server on its own tokio runtime serves a fixed 1 KiB body over
plaintext HTTP/1.1 with keep-alive. The client sweeps concurrency 1, 8, 64 and
256, and the identical workload runs through `reqwest`.

Four configurations are measured, because "how fast is Chromulate" has four
different answers depending on what you compare:

- `chromulate (default pool 6)` — `Client::chrome()` untouched. Six idle
  connections per host is what a browser holds for an HTTP/1.1 origin, and it is
  the number a user gets without tuning.
- `chromulate (pool 512)` — the same client with the idle pool raised above the
  concurrency level, which separates per-request cost from connection churn.
- `chromulate (pool 512, no cookies)` — additionally without the cookie jar,
  which is the configuration closest to what reqwest does by default.
- `reqwest` — the baseline.

Two things about the method are worth knowing before trusting the output:

**Rounds are interleaved.** Every configuration is measured once per round
rather than all of one configuration's repeats back to back. A slow patch on the
machine then lands on every client instead of on whichever one happened to be
running.

**The ratio is paired.** It is the mean of per-round ratios, not the ratio of
two means taken minutes apart. On a shared machine the paired figure is stable
where the unpaired one drifts by tens of percent.

The harness also reports how many TCP connections the server accepted **during
the measured window**, which is the only direct evidence that a pool is
reusing connections rather than reopening them. A well-behaved pooled client
opens zero after warmup.

Environment overrides: `BENCH_SECS` (default 2), `BENCH_WARMUP_MS` (500),
`BENCH_REPEATS` (3), `BENCH_SERVER_THREADS` (4), `BENCH_CLIENT_THREADS` (4).

### What this does not measure

Plaintext, so no TLS handshake and no record-layer cost. That is deliberate for
a per-request overhead number — with connections reused, a handshake amortises
to nothing and all it would add is noise from two different TLS stacks — but it
means the figure is not "Chromulate against an HTTPS origin".

Loopback, so no bandwidth-delay product and no packet loss. Client overhead is
the whole of the measurement, which is the point, but it also means the numbers
are an upper bound that no real network will reproduce.

Client and server share one machine. The ratio is fair because both clients face
the same server, but the absolute figures are lower than a dedicated origin
would give.

## Allocations per request

```
cargo run --release -p chromulate-bench --bin allocs
```

Installs a counting global allocator and brackets a request with it. The
counters are thread-local and the client runs on a current-thread runtime, so
the loopback server's allocations — which happen on other threads — are excluded.

Three regimes are reported because they answer different questions: the first
request pays for the connect and the HTTP/1.1 handshake; the second is the first
to run on a pooled connection; the steady state is the mean over a hundred
pooled requests. `reqwest` is measured identically in the same process.

This is the one benchmark whose crate is exempt from the workspace's
`forbid(unsafe_code)`: a `GlobalAlloc` implementation cannot be written without
`unsafe`. `chromulate-bench` is `publish = false` and no shipped binary links
it. Every other file in that crate carries `#![forbid(unsafe_code)]` of its own.

## Memory

```
cargo run --release -p chromulate-bench --bin memory -- idle
cargo run --release -p chromulate-bench --bin memory -- pool 1
cargo run --release -p chromulate-bench --bin memory -- pool 64
cargo run --release -p chromulate-bench --bin memory -- pool 512
cargo run --release -p chromulate-bench --bin memory -- stream
cargo run --release -p chromulate-bench --bin memory -- buffer
```

One phase per process invocation, because resident memory does not come back
down cleanly within a process and a second phase would inherit the first one's
high-water mark.

For the pooled phases the origin server runs in a **child process**. In one
process, 512 pooled client connections would be measured together with the 512
server-side connections holding them open, and the total would belong to
neither side.

`stream` reads a 256 MB body through `Response::bytes_stream`, sampling resident
memory every 8 MB consumed. `buffer` reads the same body through
`Response::bytes`, which is supposed to buffer it whole.

**`buffer` is the control, and it is not optional.** A flat peak in `stream`
only means something if the same measurement can be shown to move when memory
really is being held. Run both or trust neither.

## Many origins, and why one is not enough

```
cargo run --release -p chromulate-bench --bin multiorigin
```

A connection pool is keyed by origin, so anything costing *per pool key* — an eviction
sweep, a capacity count, contention between unrelated hosts — is invisible with one origin
and grows with the number of them. A crawler is the second shape, not the first.

The harness sweeps the origin count with concurrency and everything else fixed
(`BENCH_ORIGINS`, default `1,10,50,100`), and runs `reqwest` through the same sweep as a
control: a bend that appears in both is the machine rather than either client.

`tools/pool-scan-cost.py` is the companion. It reverts the amortised-sweep fix in a working
copy, runs both versions, prints the two curves side by side, and restores the source —
which is how the fix stopped being a mechanism and became a number. It reports a missing
target rather than quietly measuring nothing, in the manner of `cookie-mutation-check.py`.

## Where the CPU goes

```
./target/release/profile 25 64 &
sample $! 12 -file /tmp/chromulate.sample     # macOS; use perf on Linux
```

Every other harness interleaves several clients in one process, which is what makes their
*ratios* trustworthy and their *profiles* useless — a sample taken during an `e2e` run
attributes time to whichever client happened to be running. `profile` drives Chromulate and
nothing else against the loopback origin, so a call tree describes this crate.

Read the result as a share of *busy* samples: threads parked in the scheduler are not work,
and counting them measures how long the run was rather than what it did.

## Soak

```
cargo run --release -p chromulate-bench --bin memory -- soak 540
```

Every other memory phase is a point measurement, and a leak is a slope. This runs a
sustained multi-origin load and samples resident memory every ten seconds, reporting growth
over the second half so that startup allocation is not counted as a leak.

**The origin runs in a child process, and that is not incidental.** The first version ran
the origins in-process and appeared to show memory climbing from 73 MiB to 1.8 GB. That was
the in-process servers holding connection buffers — the same confound the pooled phase
already avoids. Measured with the origin isolated: flat at 9.7 MiB across 56 million
requests.

## Against a real origin

```
cargo run --release -p chromulate-bench --features live --bin live -- single <url>...
cargo run --release -p chromulate-bench --features live --bin live -- crawl <file> [limit]
cargo run --release -p chromulate-bench --features live --bin live -- pool <url>
cargo run --release -p chromulate-bench --features live --bin live -- dump <url> <prefix>
cargo run --release -p chromulate-bench --features live --bin live -- links <category-url>
```

Everything else here is plaintext loopback, which is what isolates client overhead — and
also what hides everything that only happens over TLS. `live` measures a real origin, and
it is the harness that found HTTP/2 connections were never being pooled: on loopback ALPN
never runs, so no offline test in this repository touches that path at all.

`single` reports **cold** (a fresh client per request: DNS, TCP, the TLS handshake, one
request) separately from **warm** (repeated requests on a pooled connection), because a
client can be fine at one and broken at the other — which is exactly what happened. Three
clients are compared: Chromulate, Chromulate with the cookie jar off, and `reqwest`. The
no-cookie variant is not decoration: it is the only way to tell a slow client from an
origin that answers a cookied request differently.

`pool` prints what the connection pool holds after each of several requests. A latency
number cannot distinguish "the client is slow" from "the client re-handshakes every time";
this can.

`dump` writes each client's body to a file. **Check the sizes before trusting a latency
comparison.** Real origins serve different clients different pages — one measured origin
sends non-browser clients an extra 90 KB of hidden SEO markup — and when the bodies differ
the timings are comparing two different downloads. `single` prints a warning when the
sizes differ by more than 5%.

The `live` cargo feature is opt-in because it builds `reqwest` with TLS and the four
content codings, so that both clients do the same work. That is a different `reqwest` from
the one the loopback harnesses were measured against, so **run `e2e`, `allocs` and
`memory` without `--features live`** or their numbers are not comparable with the recorded
ones.

**This talks to somebody else's server.** Requests are paced (`LIVE_PACE_MS`, default
500 ms) and the counts are deliberately small (`LIVE_ROUNDS`, `LIVE_WARM_REQUESTS`).
Raising them turns a measurement of your client into a load test of a stranger's origin.

## Micro-benchmarks

Criterion, fixed sample sizes so runs are comparable. Results land in
`target/criterion/`.

`cargo bench -p <crate> -- <filter>` narrows to matching benchmark ids, and
criterion compares against the previous run of the same id automatically, which
is what makes these useful for checking that a change did what it claimed.

The cookie suite is the one to read carefully, and the one whose fixtures can
lie.

`cookies_for/single_domain` grows with the jar because RFC 6265 §5.4 requires
the `Cookie` header be sorted, so the matching set genuinely has to be walked.
`cookies_for/spread` holds the queried bucket at ten cookies while the *total*
grows, so growth in those rows would mean lookup costs something per cookie in
the whole jar — which for a long-running crawl accumulating cookies across
thousands of sites is the difference between a flat cost and a rising one.

`store/at_default_cap/insert` against `store/at_default_cap/replace` is the pair
to watch. The jar enforces `JarLimits::total` by purging a batch (a tenth of the
cap) of least-recently-used cookies, so the full-jar scan is amortised over the
next batch of stores rather than paid per store. The full-jar insert row is
still the one that describes production, and it should sit within a few times
the replace row — a return to a ~20 µs figure means the batching regressed.

**Two assertions guard fixtures that would otherwise fail silently**, and they
are the reason to trust these rows rather than merely read them:

- The jar enforces its limits by **evicting, not refusing**. A "10,000-cookie"
  fixture under default limits is really 3,000 cookies, or 180 for a single
  domain, and the row would carry a label the jar never held. `fill` asserts the
  held count matches the label.
- A `CookieContext` with `is_top_level_navigation: false` and no initiator makes
  ordinary `SameSite=Lax` cookies ineligible, so `cookies_for` returns `None` in
  a few hundred nanoseconds — a fast, flat, entirely meaningless line.
  `check_lookup` asserts a header with the expected cookie count comes back
  before anything is timed.

If either assertion fires the fixture is wrong and no number from that run means
anything. That is deliberate: a benchmark that quietly measures an early return
is worse than one that crashes.
