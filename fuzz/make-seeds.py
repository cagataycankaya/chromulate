#!/usr/bin/env python3
"""Regenerates the committed seed corpus under `corpus/<target>/`.

Most of these seeds are compressed binaries. Committed on their own they would be
opaque blobs nobody could check or extend, which is the same problem this project
avoids everywhere else by recording where a constant came from. This script is
that record: every seed is either produced here from readable source text, or
derived from the capture document named below.

Run it from the `fuzz` directory. It removes and rewrites `corpus/`, so anything
libFuzzer discovered and anybody kept is destroyed - promote a discovery into this
script before running it again.

Requires the `gzip` (stdlib), `brotli`, and `zstd` command-line tools.
"""

import gzip
import json
import pathlib
import shutil
import subprocess
import sys
import zlib

ROOT = pathlib.Path(__file__).parent
CORPUS = ROOT / "corpus"

# Compressible enough that gzip and brotli produce a real ratio, short enough that
# every seed stays well under a kilobyte.
SAMPLE = (
    b"<!doctype html><html><head><title>chromulate</title></head>"
    b"<body><p>hello hello hello hello</p></body></html>"
)

CAPTURE = ROOT / ".." / "crates" / "chromulate-fingerprint" / "tests" / "data" / "chrome-151-macos.json"


def write(target: str, name: str, data: bytes) -> None:
    directory = CORPUS / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


def run(argv: list[str], stdin: bytes) -> bytes:
    return subprocess.run(argv, input=stdin, capture_output=True, check=True).stdout


def main() -> int:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)

    # A `Set-Cookie` header per seed, covering the attributes whose handling
    # differs most: the `__Host-` prefix, an explicit `Domain`, and a deletion.
    for name, header in {
        "session-lax": b"session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax",
        "host-prefix": b"__Host-id=9; Path=/; Secure",
        "domain-expires": b"a=b; Domain=example.com; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
        "delete-maxage": b"x=y; Max-Age=0; SameSite=Strict",
    }.items():
        write("cookie_set_cookie", name, header)

    # Attribute values only - the target supplies the cookie around them. The
    # three date shapes are the ones RFC 6265's lenient parser has to accept.
    for name, value in {
        "rfc1123": b"Wed, 21 Oct 2026 07:28:00 GMT",
        "rfc850-dashes": b"Thu, 01-Jan-1970 00:00:00 GMT",
        "asctime": b"Sun Nov  6 08:49:37 1994",
        "seconds": b"3600",
    }.items():
        write("cookie_expires_date", name, value)

    gz = gzip.compress(SAMPLE)
    zl = zlib.compress(SAMPLE)
    br = run(["brotli", "-c", "-q", "5"], SAMPLE)
    zs = run(["zstd", "-c", "-q", "-5"], SAMPLE)

    # First byte selects the coding; see the target for the mapping.
    write("compression_decode", "gzip", bytes([0]) + gz)
    write("compression_decode", "deflate", bytes([1]) + zl)
    write("compression_decode", "brotli", bytes([2]) + br)
    write("compression_decode", "zstd", bytes([3]) + zs)
    write("compression_decode", "identity", bytes([4]) + SAMPLE)

    # `Content-Encoding` value, newline, then the body.
    write("compression_content_encoding", "gzip", b"gzip\n" + gz)
    write(
        "compression_content_encoding",
        "stacked-br-gzip",
        b"gzip, br\n" + run(["brotli", "-c", "-q", "5"], gz),
    )
    write("compression_content_encoding", "identity", b"identity\nplain body")
    # Nine codings against a limit of eight, so the rejection path is seeded
    # rather than left for the fuzzer to rediscover.
    write("compression_content_encoding", "over-the-coding-limit", b", ".join([b"gzip"] * 9) + b"\n" + gz)

    # Proxy URL, `no_proxy` list, candidate host - NUL between each.
    for name, fields in {
        "http-bypass-hit": b"http://proxy.example.com:8080\x00localhost,.internal.example.com\x00service.internal.example.com",
        "socks5-credentials": b"socks5://user:p%40ss@127.0.0.1:1080\x00*\x00example.com",
        "https-no-bypass": b"https://proxy.example.com:3128\x00\x00example.com",
        "socks5h-cidr": b"socks5h://10.0.0.1:1080\x0010.0.0.0/8,192.168.0.0/16\x0010.1.2.3",
    }.items():
        write("proxy_parse", name, fields)

    # Derived from the committed capture, never hand-written: the project's rule
    # that a fingerprint value comes from an observed capture covers seeds too.
    document = json.loads(CAPTURE.read_text())
    compact = json.dumps(document, separators=(",", ":")).encode()
    write("fingerprint_capture", "chrome-151-macos-minified", compact)

    without_resumption = dict(document)
    without_resumption.pop("sample_clean", None)
    write(
        "fingerprint_capture",
        "no-sample-clean",
        json.dumps(without_resumption, separators=(",", ":")).encode(),
    )

    # Malformed blobs, not fingerprint data: a starting point on the reject path.
    write("fingerprint_capture", "truncated", compact[:200])
    write("fingerprint_capture", "empty-object", b"{}")

    for directory in sorted(CORPUS.iterdir()):
        seeds = sorted(directory.iterdir())
        largest = max(seed.stat().st_size for seed in seeds)
        print(f"{directory.name}: {len(seeds)} seeds, largest {largest} B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
