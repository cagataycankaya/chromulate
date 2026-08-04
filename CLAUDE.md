# Chromulate — Project Instructions

Chromulate is a browser-grade networking engine written in Rust. It reproduces the
observable network behaviour of a modern browser (TLS ClientHello shape, HTTP/2
settings and header ordering, cookie semantics, compression negotiation) without
embedding a browser engine. No Chromium, no Blink, no V8, no DOM, no JavaScript.

## Language rules

- **All code comments, doc comments, `TODO`/`FIXME`/`NOTE` markers, commit messages,
  identifiers, log messages, error strings, and Markdown documentation MUST be written
  in English.** This holds even when the conversation is in another language. The
  project is open source and English is its working language.
- Conversation with the maintainer may be in Turkish; the repository content may not.
- No mixed-language files. One language per file, and that language is English.

## Engineering rules

### Observe, don't theorise

Nothing is "working", "fixed", "fast", or "compatible" until it has been observed.
Reading code produces a hypothesis, not a verdict.

- Every behavioural claim needs a live test: `cargo test`, `cargo clippy`, a real HTTPS
  request, or a captured fingerprint comparison.
- Performance claims need at least three measured runs, or they are labelled UNMEASURED.
- A bug is "fixed" only when the original failing reproduction turns green.

### Fingerprint data is captured, never invented

Profile values (cipher order, extension set, HTTP/2 settings, header order, user agent)
must come from an observed capture of a real browser. Every profile records its
provenance in `crates/chromulate-profile/data/`: what was captured, from which browser
build, on which platform, and when. Never hand-write a fingerprint constant that was not
observed.

### Correctness constraints that are easy to get wrong

- Chrome randomises ClientHello extension **order** on every connection, so JA3 is not
  stable across connections for a single browser build. Cipher suite order *is* stable.
  Profiles model the extension set plus its permutation rules, not one frozen order.
- GREASE values must be drawn from the reserved `0x?A?A` set and placed where the real
  browser places them (first cipher, first extension, first supported group, first key
  share, last extension).
- `pre_shared_key`, when present, must be the final extension (RFC 8446 §4.2.11).
- HTTP/2 pseudo-header order is part of the fingerprint: `:method`, `:authority`,
  `:scheme`, `:path`.

## Code style

- Rust 2024 edition. `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must be
  clean before any commit.
- `#![forbid(unsafe_code)]` in every crate unless a documented, benchmarked exception is
  approved; `unsafe` requires a `SAFETY:` comment stating the invariant.
- Prefer `bytes::Bytes` over `Vec<u8>` on data paths. Stream by default; buffer only when
  the API contract demands a complete body.
- Avoid `Arc<Mutex<_>>` on hot paths. Reach for ownership, `&mut`, or a sharded structure
  before reaching for a lock.
- Errors are typed. No `Box<dyn Error>` in public signatures, no `unwrap()` outside tests
  and `main`.
- Public items carry doc comments with a runnable example where the item is an entry
  point.

## Scope boundary

Chromulate reproduces standards-compliant browser networking behaviour so that crawlers,
monitors, and research tools observe the same protocol surface a browser would. It is not
built to defeat security controls, and contributions framed around evading detection are
out of scope.

## Two testing rules learned the hard way

**A test that has never failed is not known to guard anything.** Write the failing test
first and watch it fail; if you are adding a test to protect an existing fix, remove the fix
in a working copy and confirm the test goes red, then restore. A green suite tells you the
tests pass, not that they would notice if the behaviour broke.
`tools/cookie-mutation-check.py` is a worked example of doing this
mechanically for a group of properties: run it after any refactor of `chromulate-cookie`. It
snapshots and restores the source itself, so it never leaves the tree modified. If it reports
a target as not found, the code moved and that property has lost its mutation coverage until
the script is updated — which is the point at which someone has to think, rather than the
point at which it quietly stops checking.

Two things this has already caught here: a `Secure`-cookie guard where mutation proved the
deletion and overwrite paths really do share one check rather than carrying two copies; and
a linearity fix where the test only goes red when *both* halves are reverted, so removing
either one alone looks harmless and is not.

**Test the default path, not only the path you changed.** The sharpest bug in this project's
history so far was introduced by a fix whose own tests could not have caught it: all three
new tests set an initiator, so none of them exercised the far more common case of a request
with no `RequestOptions` at all. The fix worked for `SameSite=Strict` and silently dropped
every `Lax` cookie on every ordinary request — logging out every session on every site. It
was caught by pre-existing facade tests, not by the new ones.

When you add tests for a case, ask what those tests structurally cannot reach. If every new
test sets some field, the absent-field path is untested by construction, and that is usually
the path most callers take.

## Testing layout

- Unit tests live beside the code they test.
- Golden tests compare computed fingerprints against captured browser data in
  `crates/chromulate-fingerprint/tests/data/`.
- Integration tests that require the network are behind the `network-tests` feature so
  the default `cargo test` run stays hermetic and offline.
