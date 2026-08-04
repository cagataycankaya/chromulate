# Benchmarks

Everything here answers a question that would otherwise be answered by
guessing. Run the command, read the number; do not quote a number from this file
without re-running it on your own machine, because none of these figures are
properties of Chromulate alone — they are properties of Chromulate on one
machine under one load.

The measured results from the run that introduced this harness are in
`.superpowers/preflight/2026-08-04-chromulate-agent-P1-report.md`, together with
the CPU and toolchain they came from.

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

## Micro-benchmarks

Criterion, fixed sample sizes so runs are comparable. Results land in
`target/criterion/`.

`cargo bench -p <crate> -- <filter>` narrows to matching benchmark ids, and
criterion compares against the previous run of the same id automatically, which
is what makes these useful for checking that a change did what it claimed.

The cookie suite is the one to read carefully. `cookies_for/single_domain` grows
with the jar because RFC 6265 §5.4 requires the `Cookie` header be sorted, so
the matching set genuinely has to be walked. `cookies_for/spread` holds the
queried bucket at ten cookies while the *total* grows, so growth in those rows
would mean lookup costs something per cookie in the whole jar — which for a
long-running crawl accumulating cookies across thousands of sites is the
difference between a flat cost and a rising one.
