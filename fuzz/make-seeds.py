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


def record(name: str, value: str, **overrides) -> dict:
    """One `CookieRecord`, with every field `Jar::export` writes.

    Serde fills nothing in for a missing field, so a snapshot seed that omits one
    fails to deserialise and the target returns before it reaches `import`.
    """
    fields = {
        "name": name,
        "value": value,
        "domain": "example.com",
        "host_only": True,
        "path": "/",
        "secure": True,
        "http_only": False,
        "same_site": "Lax",
        "partitioned": False,
        "expires": None,
        "creation_seq": 0,
        "last_access_seq": 0,
    }
    return fields | overrides


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

    # Jar snapshots, the shape `Jar::export` produces and `Jar::import` reads back.
    # Written here rather than by hand because this script wipes `corpus/`, so a
    # seed that lives only in that directory survives until somebody next runs it.
    for name, cookies in {
        "empty": [],
        "round-trip": [record("session", "abc123")],
        # `__Host-` forbids a `Domain` scope, requires `Path=/`, and requires
        # `Secure`. This record breaks all three, and `import` must drop it.
        "host-prefix-violation": [
            record("__Host-session", "forged", host_only=False, path="/admin", secure=False)
        ],
        # Nine records against a total cap of eight, so the eviction pass runs
        # rather than being left for the fuzzer to rediscover.
        "over-the-limit": [
            record(f"c{index}", str(index), domain=f"site{index}.example") for index in range(9)
        ],
        # The saturating counters: `u64::MAX + 1` would wrap the jar's sequence
        # back to zero and corrupt RFC 6265 §5.4 ordering for everything after.
        "maximal-sequence": [
            record("session", "abc", creation_seq=2**64 - 1, last_access_seq=2**64 - 1)
        ],
        # A value no `Set-Cookie` could have carried. It would break the joined
        # `Cookie` header, so that record goes and the rest of the snapshot stays.
        "unrepresentable-value": [record("poisoned", "a\r\nb"), record("good", "1")],
    }.items():
        write("cookie_snapshot_import", name, json.dumps({"cookies": cookies}).encode())

    # Two selector bytes, then NUL between each field: the `Accept-CH` value, the
    # caller header block, the target URL, the referrer, the initiator, and a
    # high-entropy hint value. See the target for the selector bit layout.
    for name, fields in {
        # Navigate/document, HTTP/1.1, GET, user-activated: the shape an address
        # bar produces, and the one the captured order was recorded from.
        "navigate-document": (0, 2, "", "", "https://example.com/index.html", "", "", ""),
        # Three hints granted, so a grant reaches the order and the high-entropy
        # slots are inserted rather than skipped.
        "granted-hints": (
            0,
            2,
            "Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version, Sec-CH-UA-Bitness",
            "",
            "https://example.com/index.html",
            "",
            "",
            "15.6.0",
        ),
        # A caller header the profile orders and one it does not, each set twice:
        # every value has to come back together at that name's one slot.
        "caller-overrides": (
            0,
            2,
            "",
            "accept-language: tr-TR\naccept-language: en-US\nx-trace: 1\nx-trace: 2",
            "https://example.com/index.html",
            "",
            "",
            "",
        ),
        # Cross-site POST: `Origin`, `Referer` and a cross-site `Sec-Fetch-Site`
        # all appear, which is three insertions into the captured order at once.
        "cross-site-post": (
            31,
            5,
            "",
            "content-type: application/json",
            "https://api.example.com/v1/items",
            "https://other.test/page",
            "https://other.test/",
            "",
        ),
        # A URL with no host at all, the one case `apply` documents as an error.
        "no-host-url": (22, 1, "", "", "data:text/plain,hello", "", "", ""),
    }.items():
        selectors = bytes(fields[:2])
        payload = b"\x00".join(part.encode() for part in fields[2:])
        write("header_engine_apply", name, selectors + payload)

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
