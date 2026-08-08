# Fidelity: what a server actually sees

How closely Chromulate's observable network surface matches the browser it models,
measured rather than claimed. Every figure below comes from one of three places: a live
capture of a real Chrome 151 on macOS
(`crates/chromulate-fingerprint/tests/data/chrome-151-macos.json`, taken 2026-08-04),
what an echo endpoint reported seeing from Chromulate on the same day, and — for the
BoringSSL paragraph alone — a probe recorded in
`.superpowers/preflight/2026-08-08-boringssl-backend-agent-P1-report.md`. That third source
is the exception worth flagging: the probe's sources are not in this repository, so its
figures are the only ones here that a checkout cannot reproduce.

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
| HTTP/2 standalone PRIORITY frames | Both send none — but see below before reading that as a match |
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

The Chromulate column is the default build — the `ring` provider with `cert-compression`
on. It is not the only one: `crates/chromulate-tls/tests/emitted_client_hello.rs` records
four JA4s, one per (provider, feature) pair, because `--no-default-features` drops the
extension count to 11 and `aws-lc-rs` changes the hash again. `aws-lc-rs` also raises group
coverage from three of four to four of four and makes the key shares the capture's exact
pair, which makes it the one configuration knob in this workspace that narrows the TLS gap
rather than moving it.

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

**GREASE is never emitted.** The profile models it in six wire positions (first cipher,
first extension, last extension, first supported group, first key share, first supported
version) and RFC 8701 is implemented and tested; none of it reaches the wire. The count is
worth stating carefully, because `GreasePlacement` carries five booleans — its `extensions`
flag covers both the first and last slot — and prose that says "five" while enumerating six
is how the supported-version slot went missing from this document until 2026-08-05. Count
against `client_hello.grease_positions` in the capture, not against the struct.

The reason is structural rather than an oversight: rustls builds its own ClientHello and
accepts no instruction on its shape. `chromulate fingerprint` prints the full list of
divergences for the linked provider, so this is checkable from a shell rather than only
from this document.

### What has been built towards closing it, and why none of it moves the numbers above

Because the gap is a property of rustls rather than of how it is configured, closing it
needs a different TLS implementation. The seam that would accept one is in place:
`chromulate-http` opens every TLS connection through the `TlsBackend` trait and derives its
stream type from the linked backend, so the string `rustls` does not appear anywhere in
`crates/chromulate-http/src/` outside three explanatory comments, none of which is a type
reference. Two further implementations
exist behind `--cfg chromulate_mock_backend`, and a CI job builds and tests
`chromulate-tls`, `chromulate-http` and the `chromulate` facade against them. The facade
was added to that job on 2026-08-08 because it had stopped compiling under the flag — the
seam held everywhere the job looked, and the crate it did not look at was the public one.

They answer two different questions, and neither is the question this document asks:

- `mock::MockBackend` shares no code or types with rustls, which is what makes the seam's
  independence a checked claim rather than an assertion.
- `recording::RecordingBackend` flattens a profile into the wire code points a TLS library
  accepts — `SSL_CTX_set_cipher_list` takes numbers — and rebuilds a `ClientHelloSpec` from
  that alone. Its round trip must reproduce the profile's JA4, and a mutation test shows the
  check can fail: dropping an extension, dropping a cipher suite, reversing the signature
  algorithms or clearing ALPN each move the fingerprint. One case deliberately does not —
  transposing two cipher suites, because JA4 sorts — so cipher order carries its own
  assertion.

**None of this changes a single figure in the table above, and it is worth being blunt about
why.** The recording harness measures *configuration* fidelity: whether a backend could be
handed everything the profile specifies without losing any of it at the boundary. This
document measures *wire* fidelity: what a server actually receives. They are different
claims, and a build can pass the first while failing the second — which is exactly what
happens today, because rustls is still the only backend that opens a socket.

**A BoringSSL backend would clear almost all of it, and a measurement from 2026-08-08 says
where it stops.** A probe against both published binding families put a real ClientHello on
a socket and decoded it: 15 of 15 cipher suites in wire order, 16 of 16 extensions, the
groups and key shares including `X25519MLKEM768`, and GREASE in all six positions with the
group and key-share values drawn from one slot, as Chrome's generator requires.

On `boring2` all of that comes from the safe API. On `boring` 5.1.0 — the crate Phase 5
selects — `status_request` and ALPS reach the wire only through three `unsafe` FFI calls,
without which the probe emitted 14 of the 16 extensions; adding them would need a second
`#![forbid(unsafe_code)]` exception recorded in `CLAUDE.md`.

The probe's JA4 was
`t13d1516h2_8daaf6152771_d8a2da3f94cd` against the target's
`t13d1516h2_8daaf6152771_806a8c22fdea` — the first two components byte-identical.

The whole remaining difference was attributed by substituting only the capture's
signature-algorithm list into the decoded hello, which lands on the target exactly. Chrome
sends three code points first — `0x0904`, `0x0905`, `0x0906` — that no BoringSSL will emit:
rejected by name, rejected as raw values, absent from the generated bindings. The capture
records them as `unknown_0x0904`, so what they are is not established here; what matters is
that the wire form cannot be reproduced. **A BoringSSL backend therefore closes GREASE,
ALPS, SCT, ECH, the extension set and the key shares, and leaves JA4's third component
different.** The cipher *order* is closed on `boring2`, whose patches delete BoringSSL's
hardware-dependent TLS 1.3 ordering, but not on `boring` 5.1.0, where the order comes from
`EVP_has_aes_hardware()` and matched the capture on the AES-NI host it was measured on.
Behaviour on a host without AES-NI is UNMEASURED, which is the device-class hazard the
cipher-order note in `CLAUDE.md` describes. That is the ceiling for that route, measured
rather than predicted.

So the harness is a bar for work that has not been done, not evidence about work that has.
A BoringSSL backend would have to clear it, and clearing it would still not be enough on its
own: `tests/emitted_client_hello.rs` decodes the bytes a real connection writes, and that is
the test whose assertions have to turn from "differs" to "matches" one at a time before any
number here changes. Run either with `cargo test -p chromulate-tls`; the recording tests
compile in an ordinary test build, so they run on every platform in CI without the flag.

## HTTP/2

| Field | Chrome | Chromulate | |
|---|---|---|---|
| SETTINGS | `1:65536;2:0;4:6291456;6:262144` | identical | match |
| Connection `WINDOW_UPDATE` | `15663105` | identical | match |
| Priority frames | none | none | match, with two caveats below |
| Pseudo-header order | `m,a,s,p` | `m,s,a,p` | **differs** |
| Akamai fingerprint hash | `52d84b11737d980aef856699f885ca86` | `3cca6cd1f3324cc4e05a72aa0cd8b4b7` | differs |

Three of the Akamai fingerprint's four fields match exactly; the fourth does not, so the
hash does not either.

**All four rows are verified from the wire by a hermetic test**, not only by the live echo
above: `chromulate-http/tests/emitted_http2.rs` stands up a TLS listener that negotiates
`h2`, records the client's opening frames, and decodes the SETTINGS order, the connection
window update, the PRIORITY frame count, the HEADERS flags, and the pseudo-header order out
of the HPACK block. It asserts the two divergences rather than describing them, so a future
`h2` release that closes either one fails the test and this document gets corrected instead
of going stale. The test was mutation-checked: flipping the expected pseudo-header order to
Chrome's turns it red with the wire's actual order in the failure message.

Two caveats on the priority-frame row, because it is the weakest of the four and was until
recently not checked at all — the frame loop ignored frame type `0x2` entirely while this
document claimed all four rows were verified.

It is now counted, but against the Chrome profile both sides are zero, so deleting the
counting arm would leave the test green: the assertion does not prove the counter counts.
What it catches is a profile whose capture *does* record PRIORITY frames — Firefox's
`3:0:0:201,…`, for instance — against a client whose `h2` write path for them is
`unimplemented!()`. That divergence was previously silent.

And "Chrome sends none" is a fact about the captured scenario rather than about Chrome. Its
reprioritisation path is live by default, so a page that reprioritises a resource does emit
PRIORITY frames; the capture is a single navigation with nothing to reprioritise. Read the
row as "none for a bare navigation", and expect a fingerprint captured mid-page-load to
disagree.

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

Not shipped, and measured rather than guessed. No default build speaks HTTP/3: ALPN offers
`h2` and `http/1.1` only.

What does exist is `chromulate-h3` — RFC 7838 `Alt-Svc` parsing and an alternative-service
cache, which is how a client learns an origin offers HTTP/3 — plus a QUIC spike behind the
non-default `quic-spike` feature that completes a real HTTP/3 request. The spike is a
measurement, not a product. The handshake it produces omits six extensions the Chrome
capture carries — `0x0012`, `0x001b`, `0x0023`, `0x44cd`, `0xfe0d`, `0xff01` — emits no
GREASE, and its transport-parameter set cannot be shaped through `quinn`'s public API. The
count difference is five rather than six, because the QUIC hello adds
`quic_transport_parameters` that the TCP capture does not carry; naming the code points
avoids the subtraction. Since this repository holds no Chrome-over-QUIC capture, the fidelity
of an HTTP/3 path is not poor but *unmeasurable*, which is why it is not shipped. See
[`architecture/04-http3-assessment.md`](architecture/04-http3-assessment.md).

`capture.rs` also recognises `h3` in a *captured* ALPN list, so a capture can be labelled as
QUIC.

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
