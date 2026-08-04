# Fuzzing Chromulate

libFuzzer targets for the parsers that read input Chromulate does not control. A
response header, a compressed body, and a proxy environment variable are all
chosen by somebody else; the rule for every target here is that malformed input
comes back as a typed error, never as a panic, an abort, or an unbounded
allocation.

## Running

`cargo-fuzz` needs a nightly compiler, and `rust-toolchain.toml` pins this
repository to stable. A toolchain file wins over whatever is otherwise selected,
so `+nightly` is required on every command — without it these fail on stable with
a missing-flag error rather than falling back.

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz build                       # all targets
cargo +nightly fuzz run cookie_set_cookie       # until it finds something, or Ctrl-C
cargo +nightly fuzz run proxy_parse -- -max_total_time=60
cargo +nightly fuzz list
```

A run with no time limit runs until interrupted. CI gives each target a short
budget, which is enough to catch a target that no longer builds or that panics on
its own seeds; finding anything deeper takes a long run, and the place for that is
a machine with hours rather than a pull request.

libFuzzer writes every input it finds interesting back into the first corpus
directory it is given, which for the commands above is the committed one — a
twenty-second run leaves a few thousand files in `git status`. Passing a scratch
directory first keeps the seeds in git read-only, and is what CI does:

```sh
cargo +nightly fuzz run cookie_set_cookie "$(mktemp -d)" fuzz/corpus/cookie_set_cookie \
  -- -max_total_time=60
```

If a run does churn the committed corpus, `./make-seeds.py` puts it back.

## Targets

| Target | Crate | Input it models |
| --- | --- | --- |
| `cookie_set_cookie` | `chromulate-cookie` | A `Set-Cookie` header, stored and read back under two `SameSite` contexts, then round-tripped through the jar snapshot |
| `cookie_expires_date` | `chromulate-cookie` | The `Expires` and `Max-Age` attribute values, with the rest of the cookie held fixed |
| `cookie_snapshot_import` | `chromulate-cookie` | A persisted `JarSnapshot` JSON document, restored into a jar and exported back out |
| `header_engine_apply` | `chromulate-header` | An `Accept-CH` value and a block of caller-set headers, applied against the captured order |
| `compression_decode` | `chromulate-compression` | A compressed body, with the first input byte selecting gzip, deflate, brotli, zstd, or identity |
| `compression_content_encoding` | `chromulate-compression` | A `Content-Encoding` header driving the decoder chain, then the body — the path `MAX_CONTENT_CODINGS` bounds |
| `proxy_parse` | `chromulate-proxy` | A proxy URL, a `no_proxy` list, and a candidate host, NUL-separated |
| `fingerprint_capture` | `chromulate-fingerprint` | A capture JSON document, plus the JA3/JA4/Akamai computations downstream of a successful load |

Several of these bound a resource rather than parse a grammar, and each one arms
its limit far below the shipped default so that a short run can actually reach it.
`compression_decode` arms `ExpansionGuard` at 64 KiB and 20x against defaults of
100 MiB and 100x, because no fuzzer will stumble onto a 100 MiB expansion inside a
CI time budget. `cookie_snapshot_import` gives its jar a cap of 8 cookies against a
default of 3000, and `header_engine_apply` gives its `AcceptChStore` room for 4
origins against a default of 10,000, for the same reason: a cap the corpus can
never reach is a branch that is not being fuzzed.

## Corpus

Seeds are committed under `corpus/<target>/`, a handful per target, each well under
a kilobyte except the capture documents. They are starting points, not coverage:
a realistic input so the fuzzer begins from a shape the parser accepts, plus at
least one input on the rejection path.

`make-seeds.py` generates all of them, and exists because most are compressed
binaries. Committed alone those would be blobs nobody could check or extend; the
script is where a reader sees that `corpus/compression_decode/gzip` is one known
HTML fragment gzipped with a coding-selector byte in front. Add seeds there rather
than by hand, so the next person can still tell what each one is.

`corpus/fingerprint_capture/` derives from
`crates/chromulate-fingerprint/tests/data/chrome-151-macos.json` — the real
capture, minified, and a copy with the optional resumed-connection sample removed.
Nothing in it is hand-written, and nothing added here may be: the project's rule
that fingerprint values come from an observed capture applies to fuzz seeds too.
The truncated and empty seeds are malformed blobs, not fingerprint data.

libFuzzer writes its own discoveries into the corpus directory as it runs. Those
are working state, not project data — commit a new seed only when it is a
reproduction of something worth keeping. Crashes land in `artifacts/`, which is
ignored; when one appears, commit the artefact as a seed under `corpus/` so the
case stays covered after the fix, and write the regression test in the crate
itself. A fuzz corpus is not a substitute for a test that names what it is
checking.
