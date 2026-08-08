# Releasing Chromulate

This document is the policy; the mechanics of any one release live in the checklist at
the end. It exists so that version numbers mean something a user can rely on without
reading the diff.

## Versioning

Chromulate follows [Semantic Versioning](https://semver.org).

**Before 1.0** (where the project is now): breaking changes land in **minor** releases
(`0.1` → `0.2`), and patch releases (`0.1.0` → `0.1.1`) contain only fixes — no API
changes, no observable behaviour changes except the corrected one. Every observable
behaviour change gets its own `CHANGELOG.md` line, including the ones that are
corrections rather than features.

**At 1.0**, the version becomes a promise about the API, not about fidelity. The
fingerprint gaps documented in [Honest limitations](README.md#honest-limitations) may
persist into 1.0 — the roadmap's TLS-gap phase states explicitly that none of its options
is a prerequisite for a useful 1.0. What 1.0 commits to is that breaking API changes
require a major release from then on.

## MSRV policy

The minimum supported Rust version is declared once, in `Cargo.toml`'s
`workspace.package.rust-version`, and enforced by the `msrv` job in CI. Raising it:

- is at least a **minor** release, never a patch;
- gets a `CHANGELOG.md` entry stating the old and new version and the reason;
- updates the CI job's pinned toolchain in the same commit, so the declared and the
  tested MSRV cannot drift apart.

There is no fixed support window. The MSRV is raised when a dependency or a language
feature makes holding it more expensive than the value of keeping it, and the changelog
entry says which one it was.

## Deprecation policy

Before 1.0: replaced APIs carry `#[deprecated]` pointing at the replacement for at least
one minor release when that is practical, but pre-1.0 minors may remove APIs outright;
the changelog is the authoritative record either way.

From 1.0: a deprecated item keeps working, with `#[deprecated(note = "...")]` naming its
replacement, for at least one minor release before it is removed — and removal is a major
release.

## Publishing order

The workspace crates depend on each other by path and version, so crates.io publishes
must run leaf-first. The order below is derived from the dependency graph; within one
step the order does not matter.

1. `chromulate-core`, `chromulate-fingerprint` (independent of everything else)
2. `chromulate-profile`
3. `chromulate-header`, `chromulate-tls`, `chromulate-cookie`, `chromulate-compression`,
   `chromulate-dns`, `chromulate-proxy`, `chromulate-cache`, `chromulate-h3`

   `chromulate-cache` must be here rather than later: `chromulate-http` depends on it
   whenever the `cache` feature is on, so publishing the engine first fails. `chromulate-h3`
   has no in-workspace consumer today, so its position is free — it sits here because it
   depends only on `chromulate-core` and `chromulate-fingerprint`.
4. `chromulate-http`
5. `chromulate-concurrency`

   It depends on `chromulate-http` for the `ConcurrencyController` seam, and the
   dependency runs only that way — `chromulate-http` must never depend on it,
   dev-dependencies included, or the trait and its implementations become a
   cycle that cannot be published at all.
6. `chromulate`
7. `chromulate-cli`

`chromulate-bench` is `publish = false` and is never published.

## The release checklist

A release is the moment the documentation stops being notes and starts being a promise,
so it gets a documentation pass of its own — before tagging, not after.

1. **Re-read every document against the code, not from memory**: `README.md`,
   `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/fidelity.md`,
   `docs/performance.md`, `benches/README.md`, and everything under
   `docs/architecture/`. For each claim that can be checked, check it — grep for the
   function, run the command, read the constant. A claim that cannot be checked in under
   a minute is rewritten as what *can* be checked.
2. **Write the changelog from the diff, not from memory.** Every performance claim
   carries its figure or the label UNMEASURED. Every observable behaviour change gets its
   own line.
3. **Check the version-shaped statements**: the README status banner, the feature
   tables, the roadmap's phase statuses, and any "not yet implemented" that has since
   been implemented.
4. **Bump the workspace version**, update `CHANGELOG.md`'s section header and date, and
   bump `html_root_url` in every crate that declares one:

   ```
   rg -n 'html_root_url' crates/ | rg -v "$NEW_VERSION"
   ```

   That grep must come back empty. It is called out separately because the attribute is
   the one version-shaped statement that lives in nine `lib.rs` files rather than in
   `Cargo.toml`, and step 3 missed it for the whole of 0.2.0 — every one of them still
   said `0.1.0` when 0.3.0 was being prepared. Seven crates declare no `html_root_url` at
   all, which is why nothing broke and why nobody noticed; if that inconsistency is ever
   resolved, resolving it by deleting the attribute removes this step, since docs.rs sets
   the value itself for published crates.
5. **Tag only a commit whose CI is green** — all jobs, all platforms. A published tag is
   never moved afterwards; if the tagged commit turns out broken, the fix is a new
   release.
6. **Publish in the order above**, then verify the facade installs cleanly from
   crates.io in an empty project.
