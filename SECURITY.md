# Security Policy

## Supported versions

Chromulate is pre-1.0. Security fixes land on `main` and in the next release; there are
no maintained backport branches yet.

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/cagataycankaya/chromulate/security/advisories/new)
rather than opening a public issue. Please include a reproduction, the affected version or
commit, and what an attacker gains.

Expect an acknowledgement within a few days and an assessment within two weeks.

## What counts as a vulnerability here

This is a networking client, so the interesting threats come from hostile servers and
hostile input rather than from hostile users of the library:

- **Decompression bombs.** A response that expands beyond the configured limit must be
  rejected while streaming, not after buffering. A bypass of that limit is a
  vulnerability.
- **Credential leakage.** Proxy credentials, cookies, and authorization headers must never
  appear in `Debug` output, `Display` output, error messages, or logs. A leak is a
  vulnerability.
- **Certificate validation bypass.** Any path that reaches a completed handshake without
  validating the chain, other than through an explicitly documented opt-out the caller had
  to write, is a vulnerability.
- **Cookie scope violations.** Sending a cookie to an origin that should not receive it —
  a public-suffix domain match, a `Secure` cookie over plaintext, a cross-site `Strict`
  cookie — is a vulnerability.
- **Redirect handling.** Forwarding credentials or authorization headers across an origin
  boundary during a redirect is a vulnerability.
- **HSTS bypass.** A plaintext request to an origin with a live policy — or a policy
  recorded from a response that did not arrive over TLS, which would let anyone able to
  inject into cleartext pin or unpin an origin — is a vulnerability.
- **Resource exhaustion** reachable from a single hostile origin: unbounded memory in the
  connection pool, the cookie jar, or the DNS cache.
- **Memory safety.** The workspace sets `unsafe_code = "forbid"`, so any memory-safety
  issue implies either a dependency bug or a lint escape, and both are worth reporting.
  One crate opts out: `chromulate-bench`, whose purpose is a counting global allocator and
  which cannot be written without `unsafe impl GlobalAlloc`. It is `publish = false` and
  nothing a user links contains it.

## What does not count

- The ability to configure the client to present a browser's network identity. That is the
  documented purpose of the project.
- Reports that a particular website can or cannot distinguish Chromulate from a browser.
  That is a compatibility matter, not a security one — open a normal issue.
