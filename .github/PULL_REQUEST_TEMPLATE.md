<!-- Explain why rather than what — the diff already says what. -->

## What this changes, and why

## Evidence

<!--
Claims need evidence, in the PR as everywhere else in this project:
- a fix cites the failing test that now passes;
- a performance claim cites at least three measured runs, or is labelled UNMEASURED;
- a behaviour change cites the test that observes it.
-->

## Checklist

- [ ] `cargo fmt --all` — clean
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean
- [ ] `cargo test --workspace --all-features` — green
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` — clean
- [ ] `cargo deny check` — clean
- [ ] `cargo run -p chromulate-cli -- verify` — green
- [ ] If `chromulate-cookie` was touched: `python3 tools/cookie-mutation-check.py` run
- [ ] If profile data was touched: every value comes from a capture with provenance — nothing hand-written
- [ ] English throughout: code, comments, docs, commit messages
