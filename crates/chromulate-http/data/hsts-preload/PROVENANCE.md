# HSTS preload list — provenance

`preload.bin` is the HSTS preload list that `chromulate-http` compiles in behind the
`hsts-preload` feature. It is captured data, not authored data: no name and no
`includeSubDomains` flag in it was typed by a person. This file records where it came
from and how it got into this shape, so that a later reader can check both rather than
trust them.

## What was fetched

| | |
|---|---|
| File | `net/http/transport_security_state_static.json` |
| Project | `chromium/src`, mirrored on GitHub as `chromium/chromium` |
| URL | `https://raw.githubusercontent.com/chromium/chromium/main/net/http/transport_security_state_static.json` |
| Chromium revision | `7be0edc636b0e7b0143e2700ecf5c8af750d09ec` |
| Revision date | 2026-07-28, *"Add service.gov.scot to HSTS preload list"* |
| Fetched on | 2026-08-04 |
| Source size | 10,521,862 bytes |
| Source SHA-256 | `39b4fd956b63c3f574506639e76a44589e8a6df1748b307fcc9eeffb4d08141f` |

The revision is the newest commit touching that path at the time of the fetch, read from
`https://api.github.com/repos/chromium/chromium/commits?path=net/http/transport_security_state_static.json&per_page=1`.
`main` moves, so the URL alone would not identify what was fetched; the revision and the
SHA-256 do.

## What is committed

| | |
|---|---|
| File | `preload.bin` |
| Size | 1,749,625 bytes |
| SHA-256 | `a63b508c7076f2e919f4edb7102a04dd6f8b4648c191d024b3bdd7982313d522` |
| Entries | 94,628 |
| With `include_subdomains` | 94,378 |
| Without | 250 |

**This is the complete list, not a subset.** All 94,628 entries in the source file carry
`"mode": "force-https"`, and all 94,628 are here. Nothing was sampled, filtered by policy,
or dropped for size. The generator does drop entries whose `mode` is not `force-https` —
there are none in this revision, and a pinning-only entry says nothing about the scheme —
so if that count ever diverges from the source's entry count, that is the reason.

The 1.7 MB is why the feature is off by default. `crates/chromulate-http/Cargo.toml`
records the measured binary growth.

## How it was transformed

```
curl -o transport_security_state_static.json \
  https://raw.githubusercontent.com/chromium/chromium/main/net/http/transport_security_state_static.json
python3 generate.py transport_security_state_static.json preload.bin
```

`generate.py` in this directory is the only thing that has ever written `preload.bin`. It
strips the `//` comments Chromium's JSON dialect allows (refusing to run if it ever finds
a trailing one, which its line-based stripper would corrupt), keeps the `force-https`
entries, lowercases and sorts the names as byte strings, and packs them into the layout
its module docstring describes: a header, one `u32` index word per entry carrying the
`include_subdomains` flag in bit 31 and the name's start offset in the rest, and one
concatenated blob of names.

Sorting is the only reordering, and it exists so the lookup can binary search. It prints
the counts and both digests in the table above; a reader who repeats the two commands
against the same revision should get a byte-identical file.

## Refreshing it

Re-run the two commands, then update: the revision, date, sizes, digests and counts in
this file; `ENTRY_COUNT` and `BLOB.len()` in
`crates/chromulate-http/src/hsts/preload.rs`'s
`the_blob_is_the_captured_list_and_not_a_sample`; and `SOURCE_REVISION` and `FETCHED_AT`
in the same module. The test exists so that a refresh cannot be half-done quietly.

`crates/chromulate-http/tests/hsts_preload.rs` names specific hosts —
`gmail.com` (preloaded without `includeSubDomains`), `app` (a whole TLD, with them),
and several that are absent. Its first test asserts each of those assumptions against the
committed blob, so a refresh that moves any of them fails there with a clear reason rather
than scattering confusing failures across the rest of the file. That guard was earned:
a draft of the unit tests assumed `mail.com` was not on the list. It is.
