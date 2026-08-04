#!/usr/bin/env python3
"""Turn Chromium's ``transport_security_state_static.json`` into ``preload.bin``.

This is the whole transform. Nothing about the list is written by hand: every
name and every ``include_subdomains`` flag in the output comes from the source
file, and this script does not filter, sample, or reorder by any rule other than
byte-wise sorting, which the lookup needs in order to binary search.

Usage::

    curl -o transport_security_state_static.json \\
      https://raw.githubusercontent.com/chromium/chromium/main/net/http/transport_security_state_static.json
    python3 generate.py transport_security_state_static.json preload.bin

It prints the numbers that belong in PROVENANCE.md, including the SHA-256 of
both files, so that a later reader can tell whether the committed blob really
came from the source revision the document claims.

Output format, little-endian throughout. It exists to be read directly out of
``include_bytes!`` with no startup parse and no allocation::

    0    magic "CHROMHS1"                   8 bytes
    8    count           u32                number of entries
    12   names_len       u32                total bytes of the name blob
    16   index[count+1]  u32 each           bit 31: include_subdomains
                                            bits 0..=30: start offset into names
    ...  names                              names_len bytes, concatenated

Entry ``i`` spans ``names[index[i] & MASK .. index[i + 1] & MASK]``, so the
trailing sentinel ``index[count]`` is ``names_len`` with its flag bit clear.
Names are ASCII, lowercase, and sorted ascending as byte strings.
"""

import hashlib
import json
import sys

MAGIC = b"CHROMHS1"
FLAG_INCLUDE_SUBDOMAINS = 1 << 31
OFFSET_MASK = FLAG_INCLUDE_SUBDOMAINS - 1


def load_entries(path):
    """Parse Chromium's JSON-with-``//``-comments file into a list of entries."""
    raw = path.read_text(encoding="utf-8")
    # Chromium's own reader strips whole-line `//` comments; there are no
    # trailing ones, and the script asserts that rather than assuming it.
    lines = raw.split("\n")
    for line in lines:
        stripped = line.lstrip()
        if "//" in line and not stripped.startswith("//"):
            raise SystemExit(
                f"trailing // comment, which this stripper would corrupt: {line!r}"
            )
    body = "\n".join(line for line in lines if not line.lstrip().startswith("//"))
    return json.loads(body)["entries"]


def encode(entries):
    """Encode entries into the binary blob described in the module docstring."""
    names = []
    for entry in entries:
        # Only `force-https` entries say anything about the scheme. Anything
        # else in the file would be a pinning-only entry, which this crate does
        # not implement -- so it is dropped rather than silently treated as an
        # upgrade.
        if entry.get("mode") != "force-https":
            continue
        name = entry["name"]
        if not name.isascii():
            # The source file is punycode already; a non-ASCII name would mean
            # the format changed and the lookup's byte comparison is no longer
            # the right one.
            raise SystemExit(f"non-ASCII name, which the byte lookup cannot match: {name!r}")
        names.append((name.lower(), bool(entry.get("include_subdomains"))))

    names.sort(key=lambda pair: pair[0].encode("ascii"))
    for earlier, later in zip(names, names[1:]):
        if earlier[0] == later[0]:
            raise SystemExit(f"duplicate name, which makes the flag ambiguous: {earlier[0]!r}")

    blob = bytearray()
    index = bytearray()
    for name, include_subdomains in names:
        start = len(blob)
        if start > OFFSET_MASK:
            raise SystemExit("name blob outgrew the 31-bit offset field")
        word = start | (FLAG_INCLUDE_SUBDOMAINS if include_subdomains else 0)
        index += word.to_bytes(4, "little")
        blob += name.encode("ascii")
    index += len(blob).to_bytes(4, "little")

    out = bytearray(MAGIC)
    out += len(names).to_bytes(4, "little")
    out += len(blob).to_bytes(4, "little")
    out += index
    out += blob
    return bytes(out), names


def main(argv):
    import pathlib

    if len(argv) != 3:
        raise SystemExit(f"usage: {argv[0]} <source.json> <preload.bin>")
    source = pathlib.Path(argv[1])
    target = pathlib.Path(argv[2])

    entries = load_entries(source)
    out, names = encode(entries)
    target.write_bytes(out)

    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    output_digest = hashlib.sha256(out).hexdigest()
    included = sum(1 for _, flag in names if flag)
    print(f"source entries        : {len(entries)}")
    print(f"force-https entries   : {len(names)}")
    print(f"include_subdomains    : {included} true, {len(names) - included} false")
    print(f"source bytes          : {len(source.read_bytes())}")
    print(f"source sha256         : {source_digest}")
    print(f"output bytes          : {len(out)}")
    print(f"output sha256         : {output_digest}")


if __name__ == "__main__":
    main(sys.argv)
