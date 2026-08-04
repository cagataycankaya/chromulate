#!/usr/bin/env python3
"""Measure what the amortised pool sweep is worth, by taking it away.

`Pool::release` used to run a full expiry sweep over every pooled connection and
then re-count the whole pool, on every single request. That cost is invisible
with one origin — there is almost nothing to walk — so the fix that removed it
shipped with its mechanism proven by reading and its effect unmeasured.

This script closes that gap the way `cookie-mutation-check.py` closes coverage
gaps: it reverts the fix in a working copy, runs the multi-origin harness
against both versions, and prints the two curves side by side. The jar script
asks "would a test notice if this were reverted"; this one asks "would a
benchmark".

It snapshots and restores the source itself, so it never leaves the tree
modified — including when it fails or is interrupted.

    python3 tools/pool-scan-cost.py [--origins 1,10,50,100] [--repeats 3]

If a target is reported as not found, the code moved and this measurement needs
updating, which is the point at which someone has to think rather than the point
at which it quietly measures nothing.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
POOL = ROOT / "crates/chromulate-http/src/pool.rs"

# (description, exact source to find, replacement)
#
# Together these restore the pre-fix behaviour: sweep on every release, and
# answer the capacity question by walking every key instead of reading the
# running count.
MUTATIONS = [
    (
        "expiry sweep runs on every release again",
        """        let now = Instant::now();
        if now.duration_since(state.last_sweep) < self.config.idle_timeout / 4 {
            return;
        }
        state.last_sweep = now;
        Self::evict_expired(state, self.config.idle_timeout);""",
        """        Self::evict_expired(state, self.config.idle_timeout);""",
    ),
    (
        "capacity answered by walking the pool again",
        """        if state.held >= self.config.max_total {""",
        """        let walked: usize = state.idle.values().map(Vec::len).sum::<usize>()
            + state.multiplexed.len();
        if walked >= self.config.max_total {""",
    ),
]


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=ROOT, text=True, check=False, **kwargs)


def measure(label: str, origins: str, repeats: int) -> dict[int, float]:
    """Builds and runs the harness, returning origin count -> median rps."""
    print(f"--- building and measuring: {label}", flush=True)
    build = run(
        ["cargo", "build", "--release", "-p", "chromulate-bench", "--bin", "multiorigin"],
        capture_output=True,
    )
    if build.returncode != 0:
        print(build.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"build failed for {label}")

    env_line = {"BENCH_ORIGINS": origins, "BENCH_REPEATS": str(repeats)}
    import os

    environment = {**os.environ, **env_line}
    result = subprocess.run(
        [str(ROOT / "target/release/multiorigin")],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        print(result.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"harness failed for {label}")

    medians: dict[int, float] = {}
    for line in result.stdout.splitlines():
        match = re.match(r"chromulate\s+origins=(\d+)\s+median\s+([\d.]+) rps", line.strip())
        if match:
            medians[int(match.group(1))] = float(match.group(2))
    if not medians:
        raise SystemExit(f"could not parse any chromulate rows for {label}")
    return medians


def apply_mutations() -> str:
    original = POOL.read_text()
    patched = original
    for description, target, replacement in MUTATIONS:
        if target not in patched:
            raise SystemExit(
                f"SKIPPED: target not found in pool.rs ({description}); the code moved "
                "and this measurement needs updating"
            )
        patched = patched.replace(target, replacement, 1)
    POOL.write_text(patched)
    return original


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origins", default="1,10,50,100")
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()

    fixed = measure("as shipped (amortised sweep, running count)", args.origins, args.repeats)

    original = apply_mutations()
    try:
        reverted = measure("fix reverted (sweep and count per release)", args.origins, args.repeats)
    finally:
        POOL.write_text(original)
        print("--- pool.rs restored", flush=True)

    # Rebuild so the tree is left with a binary matching the restored source.
    run(["cargo", "build", "--release", "-p", "chromulate-bench", "--bin", "multiorigin"],
        capture_output=True)

    print()
    print("# median rps by origin count")
    print(f"{'origins':>8}  {'as shipped':>12}  {'fix reverted':>13}  {'shipped is':>11}")
    for count in sorted(fixed):
        if count not in reverted:
            continue
        gain = fixed[count] / reverted[count]
        print(f"{count:>8}  {fixed[count]:>12.0f}  {reverted[count]:>13.0f}  {gain:>10.2f}x")
    print()
    print(
        "A ratio near 1.00 at one origin and above it as origins grow is the shape the fix\n"
        "predicts: the sweep cost scales with how many connections the pool holds, so it is\n"
        "free to skip when there is nothing to walk and expensive when there is."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
