# Capture provenance

Real HTTP response bodies, captured live through the shipped CLI (one
unauthenticated `GET` per site) on 2026-08-08. Each file is the raw response
body, byte for byte as received — nothing added, nothing stripped. Do not
edit these files by hand; re-capture instead. This follows the same
provenance discipline as `crates/chromulate-fingerprint/tests/data/`, which
records the same facts in a `_provenance` block inside the JSON capture
itself — these are HTML, so the record lives here instead.

These captures are what reopened `chromulate-challenge` after its first
acceptance: the header rule the crate shipped with (`cf-mitigated:
challenge`) never fires against either deployment below, so the crate had to
gain body rules against real, captured pages rather than the earlier,
correct-at-the-time decision to ship none. See
`.superpowers/preflight/2026-08-08-challenge-handoff-agent-B2b-brief.md` and
`.superpowers/preflight/2026-08-08-challenge-handoff-agent-B2b-report.md`.

## `cloudflare-js-interstitial-200.html`

- **Source:** `incehesap.com` (Turkish e-commerce), captured 2026-08-08.
- **Response:** `200 OK`.
- **Response headers observed:** `cf-ray`, `server: cloudflare`,
  `cf-cache-status`, `alt-svc`, `set-cookie: cuid=…`, `content-type:
  text/html`. **No `cf-mitigated` header** — this deployment does not send
  it.
- **Body:** Cloudflare's JavaScript interstitial. `<title>Just a
  moment...</title>`, a `<script>` injected at
  `/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1`, and — inside
  that script — `window._cf_chl_opt.cType: 'managed'`. `cType: 'managed'` is
  Cloudflare's own label for a **managed challenge**, which dynamically
  chooses between a non-interactive check and an interactive one depending
  on a risk score computed after this page loads. That is direct evidence,
  not an inference, for why `CloudflareDetector` cannot report a more
  specific `ChallengeKind` than `Unknown` from this page: the page itself
  does not know yet which kind of work it is.

## `cloudflare-waf-block-403.html`

- **Source:** `n11.com` (Turkish e-commerce), captured 2026-08-08.
- **Response:** `403 Forbidden`.
- **Response headers observed:** `cf-ray`, `server: cloudflare`,
  `set-cookie: __cf_bm=…`. **No `cf-mitigated` header.**
- **Body:** Cloudflare's WAF block page. `<title>Attention Required! |
  Cloudflare</title>`, "Sorry, you have been blocked", "This website is
  using a security service to protect itself from online attacks." This is
  **not** a challenge — Cloudflare has already decided to refuse this
  client, and running JavaScript does not change that decision. A
  `BrowserFallback` handed this would spend its budget launching a browser
  for nothing. `CloudflareDetector` must not report
  `Detection::Challenged` for it.
