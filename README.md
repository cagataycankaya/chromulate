# Chromulate

**A browser-grade networking engine for Rust.**

Chromulate sends requests that look, on the wire, like the requests a modern browser
sends — the TLS ClientHello shape, the HTTP/2 settings and frame behaviour, the header set
and its ordering, the cookie semantics, the compression negotiation — while keeping the
memory footprint and throughput of a native Rust HTTP client.

It embeds no browser. There is no Chromium, no Blink, no V8, no DOM, no renderer, and no
JavaScript engine. Chromulate is the networking layer and nothing else.

```text
Hyper + browser networking behaviour        not        a headless browser
```

[![CI](https://github.com/cagataycankaya/chromulate/actions/workflows/ci.yml/badge.svg)](https://github.com/cagataycankaya/chromulate/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

> **Status: 0.1.0, early development.** Everything described below is implemented and
> tested — the examples compile, the CLI issues real requests, and every performance and
> fidelity figure in the documentation was measured rather than estimated. What is early is
> the surface: this is pre-1.0 and breaking changes will land in minor releases. Read
> [Honest limitations](#honest-limitations) before depending on it — in particular, **the
> TLS fingerprint does not match Chrome's** — and [Performance](docs/performance.md) before
> assuming it is fast.

## Why this exists

A crawler, an uptime monitor, or a protocol researcher that uses an ordinary HTTP client
does not behave like a browser, and that difference is visible from the first packet.
The cipher list is in a different order. The extension set is different. The HTTP/2
SETTINGS values differ, and so does the order the headers arrive in. None of this is
hidden — it is simply what the protocols expose.

Most tools address this by driving a real browser, paying hundreds of megabytes of
resident memory and a process per session for a rendering engine they never use.
Chromulate takes the other path: model the observable network behaviour precisely, and
implement only that.

## The design in one idea

A caller picks an identity. Everything else follows.

```rust
# use chromulate::Client;
# fn main() -> Result<(), chromulate::Error> {
let client = Client::chrome()?;
# Ok(())
# }
```

That one call configures the TLS shape, the HTTP/2 settings and window sizes, the header
set and its exact order, the client hint brands, the `Accept` and `Accept-Language` and
`Accept-Encoding` values, and the cookie policy — as one coherent profile.

Coherence is the whole point. A client that sends a Chrome user agent over a non-Chrome
TLS handshake has not emulated a browser; it has produced an identity that exists nowhere
in the world and is more distinctive than either of the things it was mixing. Chromulate
treats the identity as a single object so that the parts cannot drift apart.

## Fingerprint data is captured, not invented

Every shipped profile is derived from an observed capture of a real browser, stored in the
repository with its provenance. The Chrome profile comes from a live Chrome 151 on macOS,
captured over two separate connections.

That second connection turned out to matter. Comparing the two captures shows something a
single sample would have hidden:

| | connection 1 | connection 2 |
|---|---|---|
| JA3 hash | `a0442bdf8e49e27cb5ee80009f29a6a2` | `43b2a31e00f7c2151cef4cd21c7c58f7` |
| JA4 cipher component | `8daaf6152771` | `8daaf6152771` |
| cipher order | identical | identical |
| extension order | shuffled | shuffled differently |

Chrome permutes its ClientHello extension order on every connection. The cipher order is
stable; the extension order is not. So **JA3 is not a stable identifier for a Chrome
build**, and any profile that freezes one extension order is reproducing an artefact of a
single sample rather than the browser's actual behaviour. JA4, which sorts before hashing,
is stable — which is precisely why it was designed that way.

Chromulate therefore models a profile's extensions as a set plus its permutation rules —
GREASE first and last, `pre_shared_key` always last — and generates a fresh order per
connection, as the browser does.

## Installation

```toml
[dependencies]
chromulate = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Usage

A request with a browser identity:

```no_run
use chromulate::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::chrome()?;

    let response = client.get("https://example.com").send().await?;

    println!("{} {:?}", response.status(), response.version());
    println!("{}", response.text().await?);
    Ok(())
}
```

Configured explicitly:

```rust
use chromulate::{Client, Profile};
use std::time::Duration;

# fn main() -> Result<(), chromulate::Error> {
let client = Client::builder()
    .profile(Profile::chrome_stable())
    .cookie_store(true)
    .timeout(Duration::from_secs(30))
    .proxy("socks5h://user:pass@127.0.0.1:1080")?
    .build()?;
# Ok(())
# }
```

Streaming a large response without buffering it:

```rust
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

# async fn example(
#     client: chromulate::Client,
#     url: &str,
#     sink: &mut (impl AsyncWriteExt + Unpin),
# ) -> Result<(), Box<dyn std::error::Error>> {
let mut stream = client.get(url).send().await?.bytes_stream();
while let Some(chunk) = stream.next().await {
    sink.write_all(&chunk?).await?;
}
# Ok(())
# }
```

## Features

What ships today, and what is not here. Every "yes" below is covered by tests in the
repository; the measured claims behind the fidelity rows are in
[docs/fidelity.md](docs/fidelity.md).

### Protocol and transport

| | |
|---|---|
| HTTP/1.1 and HTTP/2 | Yes, chosen by ALPN, with connection pooling for both |
| TLS 1.2 and 1.3 | Yes, over `rustls` with the platform trust store |
| HTTP/3 and QUIC | **No.** Not implemented; Chrome upgrades where an origin offers it and this does not |
| Connection pool keyed by profile identity | Yes — two profiles never share a connection, which is what stops a request being observed with another identity's fingerprint |
| HSTS | Yes. Learned from responses, applied before the request leaves; a header arriving over cleartext is ignored |
| HSTS preload list | Yes, behind the off-by-default `hsts-preload` feature: Chromium's complete list, 94,628 entries, which protects the first request to an origin. Off by default because it grows a release binary by 1,766,656 bytes (measured) |
| Proxies | Yes: HTTP `CONNECT`, SOCKS5 and SOCKS5h, with rotation and `NO_PROXY` |
| DNS | Yes: caching, TTL-aware, with concurrent lookups for one name collapsed into one |
| Happy Eyeballs (RFC 8305) | **No.** Addresses are tried in the resolver's order; a browser races the families. A latency difference, not an observable one |

### Browser identity

| | |
|---|---|
| Header set, values and order | **Exact match** against the capture |
| HTTP/2 SETTINGS and connection window | **Exact match** |
| HTTP/2 pseudo-header order | **No** — `h2` emits `m,s,a,p` where Chrome sends `m,a,s,p` |
| HTTP/2 HEADERS priority | **No** — `h2` exposes no way to set it |
| TLS ClientHello / JA4 | **Does not match.** `rustls` builds its own; ten cipher suites against fifteen, no GREASE |
| GREASE (RFC 8701) | Modelled and tested, but never reaches the wire |
| `Sec-Fetch-*` derivation | Yes, from the request's fetch context |
| Low-entropy client hints (`Sec-CH-UA*`) | Yes |
| High-entropy client hints | Mechanism yes, values no — the capture never exercised an `Accept-CH` round trip |
| Profiles shipped | One: Chrome 151 on macOS. Others need a capture; none will be written by hand |

### Client behaviour

| | |
|---|---|
| Cookie jar | Yes: domain and path matching, `SameSite`, `Secure`, `__Host-`/`__Secure-` prefixes, bounded eviction, JSON export and import |
| Redirects | Yes, with per-hop cookies and credentials dropped when a hop crosses origins |
| Decompression | Yes: `gzip`, `deflate`, `br`, `zstd`, streaming, with a decompression-bomb guard |
| Streaming bodies | Yes, both directions; a 256 MiB response streams at a 1.39 MiB peak |
| Timeouts | Yes: whole-request, response-head, and connect, separately. Connect and response-head default to 30s, so a silent server cannot hold a request open; whole-request has no default, because a large download or an SSE stream legitimately runs long. Long polling wants `no_head_timeout()` |
| Retry with backoff and jitter | Yes, idempotent methods by default |
| Rate limiting | Yes |
| Middleware | Yes — a `Middleware`/`Next` chain, plus six other extension seams |
| `basic_auth` / `bearer_auth` | Yes, marked sensitive so credentials stay out of logs |
| JSON, form and query helpers | Yes |
| Multipart bodies | No. Planned |
| HTTP cache (RFC 9111) | No. Deliberately deferred — the middleware seam supports it when someone needs it |
| WebSockets | No, and not planned here |
| JavaScript, a DOM, rendering | **Never.** Permanent exclusions — use a browser |

### Tooling

| | |
|---|---|
| CLI | `get`, `fingerprint`, `profiles`, `verify` |
| Benchmarks | Throughput against `reqwest`, allocations per request, memory, multi-origin, concurrent TLS, a live-origin harness, and a soak test |
| Fidelity checks | Emitted ClientHello and HTTP/2 preface parsed back off the wire and compared with the profile |
| Supply chain | `cargo deny` in CI: advisories, licences, duplicate versions, source registries; `cargo machete` for dependencies nothing uses |
| Fuzzing | Eight libFuzzer targets over the parsers that read untrusted input — `Set-Cookie`, the cookie date grammar, the jar snapshot importer, the header engine's `Accept-CH` path, both decompression paths, proxy URLs, capture JSON. Built on every push, run on the nightly schedule |
| Memory checking | Miri over `chromulate-core`, the one crate with no I/O and therefore the one Miri can see |

## Workspace layout

| Crate | Responsibility |
|---|---|
| `chromulate` | The facade. `Client`, the builder, and the request API. |
| `chromulate-core` | The shared vocabulary: errors, the streaming body, fetch context, and the extension traits. No I/O. |
| `chromulate-fingerprint` | The fingerprint algebra: ClientHello and HTTP/2 models, and JA3, JA4, and Akamai computation. |
| `chromulate-profile` | Browser identities built from captured data. |
| `chromulate-header` | Header construction and ordering, client hints, and `Sec-Fetch-*`. |
| `chromulate-cookie` | The cookie jar: domain and path matching, `SameSite`, secure contexts, eviction. |
| `chromulate-compression` | Streaming `gzip`, `deflate`, `br`, and `zstd` decoding with an expansion guard. |
| `chromulate-dns` | Resolution, caching, and single-flight collapsing of concurrent lookups. |
| `chromulate-proxy` | HTTP `CONNECT` tunnelling, SOCKS5, and rotation. |
| `chromulate-tls` | TLS configuration derived from a profile. |
| `chromulate-http` | The engine: connection pool, HTTP/1.1 and HTTP/2, and the redirect loop. |
| `chromulate-cli` | A command-line client for inspecting behaviour. |

How the crates depend on each other:

```mermaid
graph TD
    cli["chromulate-cli"] --> facade["chromulate"]
    facade --> http["chromulate-http"]
    http --> tls["chromulate-tls"]
    http --> header["chromulate-header"]
    http --> cookie["chromulate-cookie"]
    http --> compression["chromulate-compression"]
    http --> dns["chromulate-dns"]
    http --> proxy["chromulate-proxy"]
    tls --> profile["chromulate-profile"]
    tls --> fingerprint["chromulate-fingerprint"]
    header --> profile
    profile --> fingerprint
    profile --> core["chromulate-core"]
    cookie --> core
    compression --> core
    dns --> core
    proxy --> core
```

Omitted for legibility: `chromulate-core` is a direct dependency of every crate shown
except `chromulate-cli` and `chromulate-fingerprint`, and the two top crates
(`chromulate`, `chromulate-http`) additionally depend on most of the crates beneath them
directly, for re-exports and plumbing. `chromulate-fingerprint` depends on nothing in the
workspace — the fingerprint algebra is deliberately free-standing.

## Documentation

- [Browser networking reference](docs/architecture/01-browser-networking-reference.md) —
  how a browser actually performs a request, and what an observer can see at each layer.
- [Chromulate design](docs/architecture/02-chromulate-design.md) — the engineering
  specification, with the reasoning and the rejected alternatives.
- [Roadmap](docs/architecture/03-roadmap.md) — what exists, what is next, what is
  speculative.
- [Fidelity](docs/fidelity.md) — what a server actually sees, layer by layer, measured
  against a live capture of the browser being modelled. Read this before assuming the TLS
  fingerprint matches.
- [Performance](docs/performance.md) — the measured current state: throughput at parity
  with `reqwest`, 48 allocations per request, constant-memory streaming — and what each
  change in the optimisation wave was worth, with what the measurements do not cover.
- [Performance baseline](docs/performance-baseline.md) — the measured state the wave
  started from, kept unchanged so the two can be compared.
- [Releasing](RELEASING.md) — versioning, MSRV, and deprecation policy, and the release
  checklist.

## What Chromulate does not do

It does not render, execute JavaScript, or model a DOM. If you need any of those, you need
a browser, and Playwright is excellent.

It also is not a tool for defeating security controls. Chromulate reproduces
standards-compliant browser networking behaviour because that is what
browser-compatible networking means, and because a crawler that misrepresents its
protocol behaviour produces bad data. Contributions aimed at a specific defence are out of
scope; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Honest limitations

**The TLS fingerprint does not match Chrome's.** Measured, not estimated: Chromulate emits
JA4 `t13d1012h2_…` where the captured Chrome sends `t13d1516h2_…` — ten cipher suites
against fifteen, twelve extensions against sixteen, and **no GREASE in any slot**. The
difference is visible without comparing hashes. Chromulate builds on `rustls`, which does
not expose ClientHello ordering, GREASE placement, or the extension set to its users: the
fingerprint crate models and computes the target shape exactly, and the golden tests prove
the model matches a real browser, but the bytes on the wire are `rustls`'s own. Closing
that gap needs a custom ClientHello encoder or a different TLS backend.

Also measured, and also not matching:

- **HTTP/2 pseudo-header order** is `m,s,a,p` where Chrome sends `m,a,s,p`, and the first
  `HEADERS` frame carries no priority fields where Chrome's does. Both are fixed behaviour
  of the `h2` crate. The SETTINGS and connection window *do* match exactly.
- **HTTP/3 and QUIC are not supported at all.** Chrome upgrades to HTTP/3 where an origin
  advertises it; Chromulate stays on HTTP/2.
- **There is one profile**: Chrome 151 on macOS. Presenting as Chrome on Windows or Linux,
  or as Firefox, needs a capture of that browser — the project does not allow a fingerprint
  constant that was not observed, so this cannot be filled in from documentation.
- **High-entropy client hints have no values.** The `Accept-CH` round trip works, but the
  shipped profile carries nothing for `Sec-CH-UA-Arch` and friends, so a server that asks
  gets nothing where Chrome would answer.

What *does* match, exactly: the request header set, their values, and their order; the
HTTP/2 SETTINGS and connection window. See [fidelity](docs/fidelity.md) for the full
layer-by-layer comparison and how to reproduce it in one command.

If your requirement is a matching TLS fingerprint, this crate does not meet it, and no
configuration of it does.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The rule that matters most: profile data is
captured from a real browser, never hand-written.

## License

Dual licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
