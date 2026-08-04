# Fidelity: what a server actually sees

How closely Chromulate's observable network surface matches the browser it models,
measured rather than claimed. Every figure below comes from one of two places: a live
capture of a real Chrome 151 on macOS
(`crates/chromulate-fingerprint/tests/data/chrome-151-macos.json`, taken 2026-08-04), and
what an echo endpoint reported seeing from Chromulate on the same day.

Reproduce it with:

```
./target/release/chromulate fingerprint                     # what the profile targets, and what this build cannot send
./target/release/chromulate get https://tls.peet.ws/api/all # what a server sees
cargo test -p chromulate --features network-tests -- --ignored
```

**Read the summary before the detail.** Chromulate reproduces the HTTP layer closely and
the TLS layer only partially. If your requirement is "the TLS fingerprint is Chrome's",
this crate does not meet it, and no configuration of it does.

## Summary

| Layer | Verdict |
|---|---|
| HTTP/2 SETTINGS and connection window | **Exact match** |
| HTTP request header set, values, and order | **Exact match** against the capture |
| HTTP/2 pseudo-header order | Does not match (`m,s,a,p` against Chrome's `m,a,s,p`) |
| HTTP/2 HEADERS priority fields | Not sent at all |
| TLS ClientHello / JA4 | **Does not match**, and is distinguishable at a glance |
| GREASE | Not emitted, in any slot |
| HTTP/3 / QUIC | Not supported |
| High-entropy client hints | Mechanism works, profile carries no values |

## TLS ClientHello, JA3 and JA4

| | Real Chrome 151 | Chromulate, as observed |
|---|---|---|
| JA4 | `t13d1516h2_8daaf6152771_806a8c22fdea` | `t13d1012h2_61a7ad8aa9b6_69ed562cf35e` |
| Cipher suites offered | 15 | 10 |
| Extensions offered | 16 | 12 |
| JA3 hash | `a0442bdf…` (varies per connection) | `f23d967d…` |

All three JA4 components differ, and so does the `1516` / `1012` prefix that encodes the
cipher and extension counts — meaning the difference is visible without comparing hashes
at all.

Extensions Chrome sends that Chromulate does not:

- `signed_certificate_timestamp` (0x0012)
- `application_settings` / ALPS (0x44cd)
- `encrypted_client_hello` (0xfe0d)
- `renegotiation_info` (0xff01) — Chromulate signals it with the
  `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` cipher suite instead, which also adds a tenth
  cipher that Chrome's list does not have

**GREASE is never emitted.** The profile models it in five slots (first cipher, first
extension, first supported group, first key share, last extension) and RFC 8701 is
implemented and tested; none of it reaches the wire.

The reason is structural rather than an oversight: rustls builds its own ClientHello and
accepts no instruction on its shape. `chromulate fingerprint` prints the full list of
divergences for the linked provider, so this is checkable from a shell rather than only
from this document.

## HTTP/2

| Field | Chrome | Chromulate | |
|---|---|---|---|
| SETTINGS | `1:65536;2:0;4:6291456;6:262144` | identical | match |
| Connection `WINDOW_UPDATE` | `15663105` | identical | match |
| Priority frames | none | none | match |
| Pseudo-header order | `m,a,s,p` | `m,s,a,p` | **differs** |
| Akamai fingerprint hash | `52d84b11737d980aef856699f885ca86` | `3cca6cd1f3324cc4e05a72aa0cd8b4b7` | differs |

Three of the Akamai fingerprint's four fields match exactly; the fourth does not, so the
hash does not either.

Separately, Chrome's first `HEADERS` frame carries priority information — captured as
weight 256, depends-on 0, exclusive — and **Chromulate sends `HEADERS` with no priority
flag at all**. Both this and the pseudo-header order are fixed behaviour of the `h2`
crate: the order comes from a struct field order in `frame::headers::Pseudo`, and there is
no API for the priority flag. `Http2Fidelity::unsupported` reports both rather than
hiding them.

## Request headers and client hints

The header set, the values, and the order on the wire match the capture exactly — twelve
headers for a navigation:

```
sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests,
user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest,
accept-encoding, accept-language, priority
```

This is the layer Chromulate reproduces best, and it is guarded by golden tests plus a
live order check.

**High-entropy client hints are a gap.** The `Accept-CH` round trip is implemented and
tested — a server can ask, and the store remembers per origin — but the shipped Chrome
profile carries no values for `Sec-CH-UA-Arch`, `-Bitness`, `-Platform-Version`,
`-Full-Version-List` or `-Model`, because the capture never exercised an `Accept-CH`
exchange. So a server that requests them gets nothing, where a real Chrome would answer.
Closing this needs a richer capture, not code.

## HTTP/3 and QUIC

Not supported. There is no QUIC transport and no HTTP/3 client; ALPN offers `h2` and
`http/1.1` only. The single mention of `h3` in the tree is in `capture.rs`, which
recognises it in a *captured* ALPN list so a capture can be labelled as QUIC.

This is itself observable: modern Chrome upgrades to HTTP/3 on origins that advertise it
via `Alt-Svc`, and Chromulate stays on HTTP/2.

## What this crate is for, and is not

Chromulate reproduces standards-compliant browser networking behaviour so that crawlers,
monitors and research tools present the same protocol surface a browser does — which is
what makes them compatible with servers that vary their behaviour by client, and what
stops a crawler collecting data no browser would have received.

It is **not** built to defeat security controls, and this document deliberately contains
no measurement of how it fares against any bot-management product. That is the project's
scope boundary, recorded in `CLAUDE.md`, and the numbers above are the honest answer to
the question that is in scope: how close is the protocol surface, layer by layer.

Anyone whose requirement is a matching TLS fingerprint should read the first table again.
