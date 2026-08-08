# HTTP/3: what was established, and what should ship

Status: assessment with a working spike. Written 2026-08-04.

`README.md:168` says HTTP/3 is assessed but not shipped, and `README.md:360-361` adds that
Chrome upgrades where an origin offers it and Chromulate stays on HTTP/2. Both are still true after
this work, and this document argues
it should stay true for the QUIC half for now. It also explains why the other half —
learning that an origin *offers* HTTP/3 — has shipped.

The recommendation is not "QUIC is hard". It works: [section 3](#3-the-functional-half-works)
records a real HTTP/3 `200` against a real origin, made by code in this repository. The
recommendation rests on something narrower and more specific to this project, in
[section 6](#6-the-recommendation).

Two conventions from [`02-chromulate-design.md`](02-chromulate-design.md) apply here.
Claims about code carry a `path:line` citation checked against the file. Claims that were
not observed are labelled, and the label says what would settle them.

---

## Contents

1. [What was built](#1-what-was-built)
2. [The dependency ground truth](#2-the-dependency-ground-truth)
3. [The functional half works](#3-the-functional-half-works)
4. [The fidelity finding](#4-the-fidelity-finding)
5. [The blocker this project cannot argue its way past](#5-the-blocker-this-project-cannot-argue-its-way-past)
6. [The recommendation](#6-the-recommendation)
7. [What engine integration would require](#7-what-engine-integration-would-require)
8. [Unverified, and what would settle each](#8-unverified-and-what-would-settle-each)

---

## 1. What was built

One new crate, `chromulate-h3`, containing two things at very different stages. Nothing in
`chromulate-http` calls any of it; this wave establishes *whether and how*, not *does*.

**`Alt-Svc`, shipped and on by default.** `AltSvc::parse` implements the RFC 7838 field
grammar and `AltSvcCache` holds per-origin state with expiry
(`crates/chromulate-h3/src/alt_svc.rs`). This is the discovery half of HTTP/3 and it is
useful whether or not QUIC ever lands: an origin answering `Alt-Svc: h3=":443"` is telling
every client that it speaks HTTP/3, and recording that is an observation about the origin.
It is pure protocol work with no transport, no `unsafe`, and no new risk. 50 tests under
`alt_svc::tests`, up from the 29 this document was written with — the adversarial parser
coverage and the cache bound landed after.

**A QUIC spike, behind the non-default `quic-spike` feature.** Enough code to observe what
the `quinn` stack would put on the wire, plus one real request
(`crates/chromulate-h3/src/spike/`). 24 tests, of which one is the live request and is
`#[ignore]`d as well as feature-gated. `cargo test -p chromulate-h3 --all-features` therefore
reports 74 tests, 73 passed and 1 ignored, plus 2 doc-tests. The spike exists to be measured,
not used.

Both halves were written failing-test-first, and the guards were mutation-checked: eight
mutations, each applied alone with the tree restored afterwards, each turning at least one
test red. The run is reproduced in [section 4.5](#45-the-mutation-check).

## 2. The dependency ground truth

Resolved by `cargo add` into a scratch manifest and read out of `cargo metadata`, not from
memory.

| Crate | Version | MSRV | Licence | `unsafe` blocks |
|---|---|---|---|---|
| `quinn` | 0.11.11 | 1.85 | MIT OR Apache-2.0 | 0 in `src/`, 5 in `src/tests.rs` |
| `quinn-proto` | 0.11.16 | 1.85 | MIT OR Apache-2.0 | 4 |
| `quinn-udp` | 0.5.15 | 1.85 | MIT OR Apache-2.0 | **66** |
| `h3` | 0.0.8 | 1.70 | MIT | 0 |
| `h3-quinn` | 0.0.10 | 1.70 | MIT | 0 |

Three observations rather than three worries.

**Licences and advisories pass.** `cargo deny check` exits `0` with the whole QUIC stack in
the graph — `advisories ok, bans ok, licenses ok, sources ok` — and needed no new entry in
`deny.toml`. This was checked first, because a licence problem would have ended the
investigation.

**The MSRV held, at zero margin, for about five hours.** `quinn`'s `rust-version` is `1.85`.
This workspace's was too when this section was first written, checked rather than assumed:
`cargo +1.85.0 check -p chromulate-h3 --all-features` exited `0` with the whole QUIC stack in
the graph. That check also turned up something this work did not cause and does not fix on
its own: `cargo +1.85.0 check --workspace --all-features` failed on the branch this crate was
written from, for two reasons that have nothing to do with HTTP/3 — a `let` chain in
`crates/chromulate-http/src/engine.rs`, stable in 1.88 and not in 1.85, and `rcgen` pulls `time@0.3.47`, which
requires 1.88. Both reach the workspace through crates this change does not touch.

That made the declared MSRV of `1.85` wrong on the day this crate landed, and it is why
the sentence above is past tense: commit `775bafe` ("The declared MSRV was wrong, and CI
could not have caught it"), the same day, raised the workspace's `rust-version` to `1.88`
(`Cargo.toml:29`) — the number the `let` chain and `rcgen` already required — rather than
removing either cause. `quinn`'s `1.85` did not move, so the margin this crate now sits on
is three point-releases, not zero, and `cargo +1.85.0 check -p chromulate-h3 --all-features`
now exits `101` (`chromulate-h3@0.1.0 requires rustc 1.88`), refused on the workspace's
declared minimum before the QUIC-specific code is even reached.
`cargo +1.88.0 check --workspace --all-features` is the check that now matters, and it
passes. The `msrv` CI job (`.github/workflows/ci.yml:62-75`) is what enforces it, pinned to
`dtolnay/rust-toolchain@1.88.0` explicitly for the same reason the Miri and fuzz jobs pin
their own toolchains: `rust-toolchain.toml` pins the ambient channel to stable, and a bare
version input to that action loses to it silently, which is exactly how the `1.85` claim
went unnoticed by CI for as long as it did.

**`unsafe` arrives with the datapath, not the protocol.** `quinn-proto` is a state machine
with four `unsafe` blocks; `quinn-udp` is a portable UDP datapath — `sendmmsg`, `recvmmsg`,
GSO, control-message handling — with 66. None of the three crates carries
`#![forbid(unsafe_code)]` or `#![deny(unsafe_code)]`.

This changes nothing about `chromulate-h3`, which forbids `unsafe` like every other crate
here, and a dependency's `unsafe` is its own business. It is recorded because
`02-chromulate-design.md:62` answers "is there unsafe code?" with "none in any shipped
crate", and a reader entitled to that answer is also entitled to know that one feature flag
links 66 `unsafe` blocks of platform socket code underneath it. That is why `quic-spike` is
off by default: the flag makes the change visible at the point where someone chooses it.

**No second workspace `unsafe` exception is proposed or needed.** `chromulate-h3` carries
`#![forbid(unsafe_code)]` (`crates/chromulate-h3/src/lib.rs:43`) and `[lints] workspace = true`.

## 3. The functional half works

```
cargo test -p chromulate-h3 --features network-tests -- --ignored --nocapture
```

```
HTTP/3 200 OK from 104.18.27.14:443 over ALPN h3, 125959 body bytes
test spike::request::tests::a_real_http3_get_returns_a_response ... ok
```

That is `crates/chromulate-h3/src/spike/request.rs` performing a `GET` against
`https://cloudflare-quic.com/`: QUIC handshake, ALPN `h3` negotiated, HTTP/3 request,
response body read to completion. The negative recommendation below is not "this does not
work". It works, in about 150 lines, and `h3` plus `h3-quinn` are pleasant to use.

What it is not is a transport. There is no pool, no `Alt-Svc` upgrade path, no race against
TCP, no connection migration, no typed error mapping. [Section 7](#7-what-engine-integration-would-require)
prices those.

## 4. The fidelity finding

### 4.1 How it was observed

Not by reading crate names, and not by decrypting packets. `quinn::ClientConfig::new` takes
an `Arc<dyn quinn::crypto::ClientConfig>`, and that trait is public and unsealed. Its one
method receives the connection's `TransportParameters` by reference, and
`TransportParameters::write` is public even though every field of the struct is
`pub(crate)`. Wrapping the returned `Session` gives the same access to the ClientHello,
because `write_handshake` hands the caller the plaintext CRYPTO stream.

So `crates/chromulate-h3/src/spike/probe.rs` plugs a recorder into that seam and reads both.
`quinn_proto::Connection::new` calls `write_crypto()` for the client side while it is still
being constructed (`quinn-proto-0.11.16/src/connection/mod.rs:362-366`), so everything is
recorded synchronously inside `Endpoint::connect`, before a packet leaves. The observation
needs no server, no network and no timing, which is why it runs in the ordinary hermetic
suite.

That asymmetry — `write` public, every field `pub(crate)`, `new` `pub(crate)`,
`TransportParameterId` `pub(crate)` — is itself the headline. A downstream crate can
*observe* exactly what `quinn` will send and cannot *change* it.

### 4.2 What the handshake looks like

Reproduce with
`cargo test -p chromulate-h3 --all-features -- --nocapture the_quic_hello_omits`:

```
quinn + rustls over QUIC : q13d0311h3_55b375c5d22e_387675cfb458
captured Chrome 151 (TCP): t13d1516h2_8daaf6152771_806a8c22fdea  [not the QUIC target]
extensions 11 vs 16; absent from the QUIC hello: [0x0012, 0x001b, 0x0023, 0x44cd, 0xfe0d, 0xff01]
extensions on the wire: [0039, 0033, 0010, 002d, 000d, 0000, 002b, 0017, 0005, 000a, 000b]
```

**The right-hand column is not the target and the test says so.** The shipped capture is
Chrome over TCP. QUIC mandates TLS 1.3 (RFC 9001 §4.2), so a QUIC ClientHello legitimately
offers only the three TLS 1.3 suites, and setting `03` against `15` compares two different
things. Nothing in this repository knows what Chrome's QUIC ClientHello looks like.

What *is* comparable is the extension set, because those six absences are not
transport-specific. `signed_certificate_timestamp` (0x0012), `compress_certificate`
(0x001b), `session_ticket` (0x0023), `application_settings` (0x44cd),
`encrypted_client_hello` (0xfe0d) and `renegotiation_info` (0xff01) are all in the shipped
capture (`crates/chromulate-profile/src/chrome.rs:43-60`) and none of them reaches the wire.
That is the same divergence `docs/fidelity.md:47-54` already records for TCP, reproduced
over QUIC — as it must be, since the same rustls builds both.

**GREASE is absent over QUIC too**, asserted rather than assumed
(`no_grease_reaches_the_wire_over_quic_either`). rustls emits no GREASE cipher, extension,
group or key share; grepping `rustls-0.23.43/src` for GREASE finds only `EchMode::Grease`.

One extension in that list behaves differently from the rest, and finding out why was
accidental but is worth keeping. `compress_certificate` (0x001b) is **absent** when the
spike is built alone and **present** under `cargo test --workspace --all-features`. The
cause is Cargo feature unification: `chromulate-tls` enables `rustls/brotli` through its
default `cert-compression` feature (`crates/chromulate-tls/Cargo.toml:34`), and because
features unify across a workspace build, this crate's rustls gains the extension whenever
`chromulate-tls` is in the same graph.

The emitted ClientHello is therefore a property of the whole dependency graph, not of the
crate that opens the connection. That is worth stating plainly in a project that treats the
handshake as a specified output: a downstream user who depends on one Chromulate crate and
not another can get a different fingerprint from the same code, and nothing today reports
that. The spike's test prints which way it went rather than asserting one, because both
outcomes are correct for the build that produced them.

### 4.3 One assumption this work overturned

It is tempting to assume rustls emits a fixed hello and that ordering is therefore another
gap. It is not. rustls shuffles order-insensitive extensions from a per-connection seed
(`rustls-0.23.43/src/client/common.rs:40`, `src/msgs/handshake.rs:977` and `:1068-1090`),
and `quinn` shuffles its transport parameters per connection and sends exactly one reserved
`31N+27` GREASE parameter with a freshly drawn identifier
(`quinn-proto-0.11.16/src/transport_parameters.rs:177-182`).

Both are observed here, not read off the source:
`rustls_permutes_the_extension_order_between_connections`,
`quinn_randomises_transport_parameter_order_between_connections`, and
`the_reserved_grease_identifier_is_redrawn_per_connection` each demand that at least one of
sixteen fresh connections differs, while asserting the *set* stays stable.

This is what §5.4 of the design document asks for — an identity that is a distribution, not
a constant — arriving by accident from the dependencies. It also means **order is not the
axis on which this fails**: JA4 sorts both the cipher and extension lists before hashing and
ignores GREASE, so neither shuffle changes a JA4 by a character. What fails is membership.

### 4.4 What cannot be shaped, and what can

The precise answer is more interesting than "no".

**The transport parameter *set* cannot be changed through `quinn`.** Demonstrated, not
argued, by `no_transport_config_setting_removes_a_parameter_from_the_set`: every knob
`TransportConfig` offers is moved off its default and the emitted set is unchanged except
for `max_datagram_frame_size` (0x20), which `datagram_receive_buffer_size(None)` does
remove. `min_ack_delay` (0xff04de1b) is set unconditionally from a private constant
(`transport_parameters.rs:174-176`) and survives everything.

**But rustls itself will emit any parameters you hand it.**
`rustls::quic::ClientConnection::new` takes them as `params: Vec<u8>` and treats them as
opaque (`rustls-0.23.43/src/quic.rs:163-167`). `rustls_itself_accepts_arbitrary_transport_parameter_bytes`
feeds it a hand-built block containing identifier `0x3127` — which `quinn` has no name for —
and reads the same bytes back out of extension 0x0039 unaltered.

So the escape hatch is real: a custom `crypto::ClientConfig` can ignore quinn's
`&TransportParameters` and hand rustls anything. The cost is that
`QuicClientConfig::start_session` calls that constructor with quinn's own parameters
(`quinn-proto-0.11.16/src/crypto/rustls.rs:369-374`) and `TlsSession` is private, so taking
the hatch means reimplementing quinn's TLS backend and keeping it in sync — which is exactly
what `quinn-boring` does.

**What no hatch reaches is the Initial packet itself.** `MIN_INITIAL_SIZE` and
`INITIAL_MTU` are private constants wired into `builder.pad_to(...)`, and CRYPTO
fragmentation, PADDING placement, packet-number length and the initial packet number have no
public API. Connection ID lengths *are* reachable, via
`ClientConfig::initial_dst_cid_provider` and `EndpointConfig::cid_generator`.

**And the extension set is not reachable at all.** `rustls`'s `ClientExtensions` is
`pub(crate)` and its field list *is* the extension universe: there is no arbitrary-extension
injection, so `application_settings` and ECH cannot be added by any consumer. This is the
same wall `docs/fidelity.md:64-67` already documents for TCP. It is not a QUIC problem; it
is the existing TLS problem, unchanged.

**HTTP/3 adds a second fingerprint surface below TLS.** `h3` hard-codes its SETTINGS content
and order — GREASE first when enabled, then `MAX_HEADER_LIST_SIZE`,
`ENABLE_CONNECT_PROTOCOL`, `ENABLE_WEBTRANSPORT`, `H3_DATAGRAM`, `WEBTRANSPORT_MAX_SESSIONS`,
all five always emitted (`h3-0.0.8/src/config.rs:72-133`) — and never sends
`QPACK_MAX_TABLE_CAPACITY` (0x1) or `QPACK_MAX_BLOCKED_STREAMS` (0x7), though both
identifiers are defined at `src/proto/frame.rs:445-446`. The public builder offers
`send_settings`, `max_field_section_size`, `send_grease`, `enable_datagram` and
`enable_extended_connect`, and no reordering or omission.

This is the HTTP/2 SETTINGS story again — the one this project reproduces *exactly* today,
per `docs/fidelity.md:29` — except that here the ordering is not reachable. It has been read
from source, not observed on the wire, because observing our own SETTINGS frame needs a
server the spike does not stand up.

### 4.5 The mutation check

Eight guards, each mutated alone with the tree restored afterwards. All eight turn at least
one test red:

```
RED  expiry check always says live            -> 3 tests
RED  insecure-origin guard removed            -> 1
RED  `clear` no longer recognised             -> 1
RED  splitter stops respecting quotes         -> 1
RED  protocol-id no longer percent-decoded    -> 1
RED  a new field appends instead of replacing -> 1
RED  alt-authority split takes first colon    -> 1
RED  probe reorders what it records           -> 9
```

The seventh was **still green** on the first run, and that is the entry worth keeping. The
"last colon wins" rule in `parse_alt_authority` had no test that could reach it: the only
multi-colon case was a bracketed IPv6 literal, where the depth counter skips the inner
colons so the first depth-0 colon *is* the last one. The test
`the_port_separator_is_the_last_colon_not_the_first` was added for it, and the mutation now
turns red.

One thing the run showed that no assertion states: `clear_forgets_the_origins_alternatives`
does *not* fail when `clear` stops being recognised, because an unparseable field also
empties the origin. Only `recognises_clear` distinguishes them. Both are kept, and this
paragraph is here so the next reader does not mistake the first for coverage of the second.

## 5. The blocker this project cannot argue its way past

Everything above measures the gap between this stack and *some* browser. None of it measures
the gap to Chrome, because:

**There is no Chrome-over-QUIC capture in this repository, and this project's first data
rule forbids inventing one.** `CLAUDE.md:36-42` requires every fingerprint constant to trace
to an observed capture with recorded provenance, and the profile loader enforces it by
rejecting a profile without one. `01-browser-networking-reference.md:852-855` already says
the same thing about this exact subject: *the capture contains no HTTP/3 evidence*, and an
implementation targeting HTTP/3 needs its own capture before asserting any constant.

Third-party observations of Chrome's QUIC parameters do exist —
`refraction-networking/uquic` ships a Chrome parrot derived from its own packet capture, and
Chrome's QUICHE source shows the GREASE and Fisher-Yates shuffle strategy directly. Those are
good evidence that the shapes differ in both directions, and they are cited here as such.
They are *not* a capture this project took, so nothing derived from them may become a profile
constant. Adopting someone else's parrot table would be exactly the "hand-written fingerprint
constant that was not observed" the rule exists to prevent, with the added problem that a
reader would have no way to tell.

So the honest position is not "HTTP/3 fidelity here is poor". It is: **HTTP/3 fidelity here
is unmeasured, and cannot be measured until someone captures Chrome speaking QUIC.** Shipping
a transport whose fidelity cannot be assessed would put the project in the position it
criticises in §5.1 of the design document — a client claiming to be something it has not
checked it is.

## 6. The recommendation

**Ship the `Alt-Svc` half. Do not ship QUIC yet.** Three reasons, in the order they should be
weighed.

**One: the thing that decides it is missing, not broken.** No capture, no target, no verdict —
[section 5](#5-the-blocker-this-project-cannot-argue-its-way-past). Every other argument here
is secondary to that one, and every other argument would be answered differently if a capture
existed.

**Two: the fidelity surface would get wider, not narrower.** Today the project's weakest
claim is one layer, TLS, and `docs/fidelity.md` is precise about it. HTTP/3 would add a QUIC
transport parameter set that diverges in both directions and an HTTP/3 SETTINGS frame whose
order is unreachable — while inheriting the *entire* existing TLS gap unchanged, since the
same rustls builds both hellos. A user who reads "HTTP/3 supported" reasonably infers the
protocol surface got closer to a browser. It would not have.

**Three: upstream has considered this and declined.** `quinn` issue #2057 asked for exactly
this control. The GREASE parameter and the shuffle landed (#2058, #2066); the option to
*disable* the GREASE parameter was closed unmerged (#2061). The maintainers' stated position
is that being hard to fingerprint by default is in scope and imitating a specific
implementation is not — and the requester agreed, noting that mimicry belongs in specialised
libraries such as uTLS. That is a reasonable position for a general-purpose QUIC stack and it
means waiting for upstream is not a plan.

What would change the recommendation, in order of cost: a Chrome QUIC capture (unblocks
measurement); an upstream rustls extension-set mechanism (unblocks the TLS half, which
`02-chromulate-design.md` §8.6 already rates as slow and uncertain); a bespoke
`crypto::ClientConfig` over `rustls::quic` (unblocks transport parameters at the price of
maintaining a fork of quinn's TLS backend). The Initial packet framing needs a fork of
`quinn-proto` — the layer `uquic` needed a hard fork of `quic-go` to reach, across 18 patched
files.

`uquic`'s own README is worth quoting as the ceiling on this whole approach: it is "not ready
for production use nor peer-reviewed", such mimicry "MAY NOT be realistically
indistinguishable from real QUIC clients", and misuse "MAY lead to easier fingerprinting
against the mimic". A project that ships an honest fidelity table should take that seriously
before adding a surface it cannot yet check.

## 7. What engine integration would require

Concretely, for whoever picks this up. None of this was done; it is scoped, not estimated.

**The pool is the hard part, and the reason is structural.** `02-chromulate-design.md:58`
records today's model: *HTTP/1.1 is exclusive and returns through the response body; HTTP/2
is shared and is registered when opened. Two protocols, two doors.* An HTTP/3 connection is
neither. It is multiplexed like h2, so it wants the shared door — but the key it hangs on
loses its TCP assumption. Four consequences:

- **The pool key.** Today a key implies a TCP connection to a host and port. QUIC is UDP, and
  the same `(host, port)` may hold both an h2 connection and an h3 one simultaneously —
  which is normal, because the h3 one is reached by upgrade after the h2 one answered. The
  key needs a transport discriminant, and `docs/architecture/02-chromulate-design.md` §15
  already records this as unresolved.
- **Connection migration.** A QUIC connection survives a client address change, so the pool's
  identity for a connection can no longer be the socket. Nothing in the current pool assumes
  otherwise because nothing in it could.
- **The `Exchange` seam.** `chromulate_core::Exchange` is the terminal trait and is protocol
  agnostic, so a third exchange implementation fits without a core change. That part is
  cheap.
- **Error mapping.** `quinn::ConnectionError` and `h3::Error` need mapping onto
  `chromulate_core::Error`, and the `is_retryable` reasoning in `error.rs:208-221` needs
  rethinking for QUIC: a handshake failure over UDP genuinely may be a blocked-UDP network
  rather than a structural mismatch, which is the opposite of the TCP case that variant was
  written for.

**The upgrade path is a policy, not a connection.** `AltSvcCache` now exists, but nothing
consults it. A browser races QUIC against TCP and uses whichever establishes first, because
UDP is blocked on a nontrivial fraction of networks
(`01-browser-networking-reference.md:885-889`). A client that always prefers h3 once
advertised, or never does, is distinguishable from a browser before a request is sent — so
the race is part of the fidelity target, not an optimisation. It also needs the `Alt-Svc`
cache to live on the `Client` and survive across requests.

**Files that would change**, none of which this wave touched: `crates/chromulate-http/src/pool.rs`
(key and ownership model), `connect.rs` (a UDP dial path beside the TCP one), `engine.rs` (
protocol selection and the upgrade decision), `crates/chromulate/src/client.rs` (builder
surface and the cache's home), plus `docs/fidelity.md:36` and `README.md:168,360-361`, which all
state HTTP/3 is unsupported and would become wrong.

**What would not change:** `chromulate-header` (HTTP/3 uses the same pseudo-headers in the
same order), `chromulate-cookie`, `chromulate-compression`, `chromulate-core`'s traits.

## 8. Unverified, and what would settle each

- **Chrome's QUIC transport parameter set, order, and ClientHello.** Not observed by this
  project. The third-party evidence cited above suggests roughly ten shared identifiers with
  about three differing in each direction, but that is someone else's capture and no number
  from it belongs in a profile. *Settled by:* a capture of Chrome against a controlled HTTP/3
  origin, recorded into `crates/chromulate-profile/data/` with provenance, the way the TCP
  capture was.
- **Chrome's JA4 over QUIC.** Unknown, for the same reason. The `q13d`, `03` and `h3` fields
  of `q13d0311h3_…` would very likely match; the `11` and both hashes almost certainly would
  not. *Settled by:* the same capture.
- **What this stack's HTTP/3 SETTINGS frame looks like on the wire.** Read from `h3`'s source,
  not observed. *Settled by:* an emitted-shape harness like
  `chromulate-http/tests/emitted_http2.rs`, standing up an HTTP/3 listener and decoding the
  client's opening frames. That is the right shape of test and it was out of scope here.
- **Whether rustls would accept an extension-set mechanism upstream.** No rustls issue on it
  was found; only `quinn`'s position is documented. *Settled by:* asking.
- **Whether one pool can sensibly hold TCP and QUIC connections for one origin.** Still the
  open question §15 of the design document records. Nothing here answered it, because nothing
  here integrated with the pool.
- **Whether the feature-unification effect on the ClientHello reaches beyond 0x001b.** Only
  `compress_certificate` was observed to move. Other rustls features may do the same.
  *Settled by:* a matrix run of the spike's observation across rustls feature combinations,
  which the spike is already shaped to support.
