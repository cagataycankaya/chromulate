# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the usual pre-1.0 caveat
that breaking changes may land in a minor release.

## [Unreleased]

### Added

- **`Client::hsts()`** — access to the HSTS store, so a caller can seed a policy for an
  origin it already knows is HTTPS-only. Without it the store was learn-only, and the
  *first* request of a process to such an origin was the one that would have gone out in
  plaintext.
- **`RequestBuilder::basic_auth` and `bearer_auth`.** Both mark the header value sensitive,
  so a credential does not reach a log through `HeaderMap`'s `Debug`. `basic_auth` always
  sends the colon: `user:` and `user` are different credentials on the wire.
- **A features table in the README**, saying what ships and what does not, with the
  fidelity rows pointing at the measurements behind them.
- **CI: Miri over `chromulate-core`** (verified locally first — 31 tests pass under it,
  including the `tokio` ones) and **a nightly schedule for the live network tests**, so
  that "a site changed" and "we broke it" stop looking the same.

### Fixed

- **The README's Rust examples are now compiled.** The status banner claimed they were, and
  nothing checked: the file was not wired into rustdoc, and one example used three
  variables it never declared. They are doctests now, so a change that breaks one fails
  `cargo test`.
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

[Unreleased]: https://github.com/cagataycankaya/chromulate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cagataycankaya/chromulate/releases/tag/v0.1.0
