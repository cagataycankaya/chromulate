# Contributing to Chromulate

Thanks for considering a contribution. This document covers the few things that are
specific to this project; everything else is ordinary Rust practice.

## Ground rules

**English everywhere.** All code, comments, documentation, commit messages, and issue
discussion are in English. Contributors are welcome from anywhere, and a single working
language is what keeps the project readable to all of them.

**Fingerprint data is captured, never invented.** This is the rule that matters most. A
browser profile describes the observable behaviour of a real browser build. If a value in
a profile was not observed in a capture, it is wrong, and a wrong profile is worse than no
profile because it produces an identity that is internally inconsistent. Every profile
records where its data came from. Pull requests that hand-edit a fingerprint constant
without a corresponding capture will be asked for the capture.

**Claims need evidence.** "This is faster" needs at least three measured runs. "This
fixes it" needs the failing test that now passes. Reading the code and reasoning about it
is a hypothesis; running it is a result.

## Before you open a pull request

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

All three must be clean. CI runs the same commands plus a documentation build, an MSRV
check against Rust 1.85, and tests on Linux, macOS, and Windows.

Tests that need the public internet are gated behind the `network-tests` feature and
marked `#[ignore]`, so the default test run stays hermetic and offline. Keep it that way:
a contributor on a plane should be able to run the full default suite.

## Contributing a browser profile

1. Capture a real browser against an endpoint that echoes the TLS ClientHello and the
   HTTP/2 preface. Take **at least two captures on separate connections** so that
   per-connection randomisation is visible rather than baked in as a constant.
2. Save the raw capture under `crates/chromulate-fingerprint/tests/data/` with a
   `_provenance` block recording the browser build, the platform, the endpoint, and the
   date.
3. Add the profile, and add a golden test asserting that the profile's computed JA4 and
   HTTP/2 fingerprint match the capture. A profile without a golden test will not be
   merged.

## Scope

Chromulate reproduces standards-compliant browser networking behaviour so that crawlers,
monitors, availability checkers, and protocol researchers observe the same wire behaviour
a browser would. Work framed around evading a specific security control is out of scope,
and issues framed that way will be closed. The distinction is between building an engine
that behaves like a browser because that is what correct browser-compatible networking
means, and building a tool aimed at a particular defence. The first is the project; the
second is not.

## Commit messages

Present tense, imperative mood, explaining why rather than what:

```
Collapse concurrent lookups for the same host into one query

A crawl that starts 500 tasks against one domain previously issued 500
identical DNS queries. Single-flighting them means one query and 499
waiters, which also removes the thundering herd against the resolver
after a cache expiry.
```

## Getting help

Open a discussion or an issue. Questions about the architecture are best answered against
`docs/architecture/`, which is the reference the implementation follows.
