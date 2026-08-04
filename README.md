# Chromulate

**A browser-grade networking engine for Rust.**

Chromulate sends requests that look, on the wire, like the requests a modern browser
sends — the TLS ClientHello shape, the HTTP/2 settings and frame behaviour, the header set
and its ordering, the cookie semantics, the compression negotiation — while keeping the
memory footprint and throughput of a native Rust HTTP client.

It embeds no browser. There is no Chromium, no Blink, no V8, no DOM, no renderer, and no
JavaScript engine. Chromulate is the networking layer and nothing else.

```
Hyper + browser networking behaviour        not        a headless browser
```

[![CI](https://github.com/cagataycankaya/chromulate/actions/workflows/ci.yml/badge.svg)](https://github.com/cagataycankaya/chromulate/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

> **Status: early development.** The core, the fingerprint algebra, and the supporting
> engines are implemented and tested. The public client API described below is the design
> target and is landing now. Expect breaking changes before 0.2.

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
let client = Client::chrome()?;
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

```rust
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

let client = Client::builder()
    .profile(Profile::chrome_stable())
    .cookie_store(true)
    .timeout(Duration::from_secs(30))
    .proxy("socks5h://user:pass@127.0.0.1:1080")?
    .build()?;
```

Streaming a large response without buffering it:

```rust
use futures_util::StreamExt;

let mut stream = client.get(url).send().await?.bytes_stream();
while let Some(chunk) = stream.next().await {
    sink.write_all(&chunk?).await?;
}
```

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

## Documentation

- [Browser networking reference](docs/architecture/01-browser-networking-reference.md) —
  how a browser actually performs a request, and what an observer can see at each layer.
- [Chromulate design](docs/architecture/02-chromulate-design.md) — the engineering
  specification, with the reasoning and the rejected alternatives.
- [Roadmap](docs/architecture/03-roadmap.md) — what exists, what is next, what is
  speculative.

## What Chromulate does not do

It does not render, execute JavaScript, or model a DOM. If you need any of those, you need
a browser, and Playwright is excellent.

It also is not a tool for defeating security controls. Chromulate reproduces
standards-compliant browser networking behaviour because that is what
browser-compatible networking means, and because a crawler that misrepresents its
protocol behaviour produces bad data. Contributions aimed at a specific defence are out of
scope; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Honest limitations

Chromulate builds on `rustls`, which does not expose ClientHello extension ordering or
GREASE placement to its users. The fingerprint crate models and computes the target shape
exactly, and the golden tests prove the model matches a real browser — but the bytes
`rustls` puts on the wire are `rustls`'s own. Closing that gap needs either a custom
ClientHello encoder or a different TLS backend, and the design document says so plainly
rather than claiming an emulation fidelity the current stack cannot deliver.

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
