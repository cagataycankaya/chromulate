#!/usr/bin/env python3
"""Mutation check for the five cookie-jar security properties fixed by agent FX4.

Run it after any refactor that touches `crates/chromulate-cookie/`:

    python3 .superpowers/preflight/fx4-cookie-mutation-check.py

A passing test suite proves the tests still run. It does not prove they still test
anything: a mechanical refactor can leave an assertion in place while quietly making it
vacuous. This breaks each fix in turn and requires the guarding tests to go red. A fix
whose test stays green when the fix is removed is not covered, whatever the suite says.

Self-contained: it snapshots the source files itself, mutates, tests, and restores from
that snapshot. It never leaves the tree modified, including on failure.

If a mutation target is "NOT FOUND", the code moved. That is not a failure — it means
this script needs its find-string updated to match the new code, and until it is, that
property has no mutation coverage.

Findings guarded (from the 2026-08-04 R2 security review):
  F2  __Host- / __Secure- cookie name prefixes (RFC 6265bis 5.7 steps 20-21)
  F3  Jar::store is linear, not quadratic
  F4  "Leave Secure Cookies Alone" on the deletion path as well as the overwrite path
  F6  Jar::import does not overflow on a maximal sequence number
  F10 One unrepresentable imported record does not suppress a whole site's cookies
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "crates" / "chromulate-cookie" / "src"
FILES = ("cookie.rs", "jar.rs", "lib.rs")

# (label, file, find, replace, tests that MUST go red, optional second (find, replace))
MUTATIONS = [
    (
        # Breaking the one shared predicate must turn BOTH doors red: the `store` path
        # through `Cookie::parse` and the `import` path. That is the evidence they share a
        # guard rather than carrying two copies of the rule.
        "F2 __Host- promise no longer checked (both doors)",
        "cookie.rs",
        'return secure && host_only && path == "/";',
        "return true;",
        [
            "a_host_prefixed_cookie_carrying_a_domain_attribute_is_rejected",
            "a_host_prefixed_cookie_with_a_path_other_than_root_is_rejected",
            "a_host_prefixed_cookie_without_secure_is_rejected",
            "a_host_prefixed_name_requires_secure_no_domain_attribute_and_a_root_path",
            "a_host_prefixed_name_is_rejected_when_the_default_path_is_not_the_root",
            "a_host_prefixed_name_on_an_ip_host_still_needs_no_domain_attribute",
            "import_will_not_load_a_record_that_breaks_its_own_name_prefix_promise",
        ],
    ),
    (
        "F2 __Secure- promise no longer checked",
        "cookie.rs",
        """    if starts_with_ignore_ascii_case(name, SECURE_PREFIX) {
        return secure;
    }""",
        """    if starts_with_ignore_ascii_case(name, SECURE_PREFIX) {
        return true;
    }""",
        ["a_secure_prefixed_name_requires_the_secure_attribute_and_a_secure_origin"],
    ),
    (
        "F2 secure-origin requirement removed",
        "cookie.rs",
        """            if !request_is_secure {
                return None;
            }""",
        """            if false {
                return None;
            }""",
        [
            "a_secure_prefixed_cookie_set_over_plaintext_is_rejected",
            "a_prefix_in_a_different_case_is_still_enforced",
        ],
    ),
    (
        "F2 prefix match made case-SENSITIVE",
        "cookie.rs",
        "head.eq_ignore_ascii_case(prefix.as_bytes())",
        "head == prefix.as_bytes()",
        [
            "a_prefix_in_a_different_case_is_still_enforced",
            "a_prefix_written_in_a_different_case_is_still_enforced",
        ],
    ),
    (
        "F4 Leave Secure Cookies Alone guard removed",
        "jar.rs",
        "if is_secure_cookie && !request_is_secure {",
        "if false {",
        [
            # Both must fail. That is the evidence the two paths share one guard rather
            # than carrying two copies of the condition, which is the whole point of F4.
            "a_plaintext_response_may_not_delete_an_existing_secure_cookie",
            "a_plaintext_response_may_not_overwrite_an_existing_secure_cookie",
        ],
    ),
    (
        "F6 saturating_add reverted to +1",
        "jar.rs",
        ".fetch_max(record.creation_seq.saturating_add(1), Ordering::Relaxed);",
        ".fetch_max(record.creation_seq + 1, Ordering::Relaxed);",
        ["import_of_a_record_with_a_maximal_sequence_number_does_not_overflow"],
    ),
    (
        "F10 import validation removed",
        "jar.rs",
        "if !is_representable(&record.name, &record.value) {",
        "if false {",
        ["one_unrepresentable_imported_record_does_not_suppress_the_other_cookies"],
    ),
    (
        "F3 per-store tidy widened back to the whole jar",
        "jar.rs",
        """        for site in &touched {
            let per_domain = self.limits.per_domain;
            let trim_target = self.limits.domain_purge_target();
            store.with_site(site, |bucket| {
                if bucket.len() > per_domain {
                    bucket.remove_expired(now);
                    bucket.trim_to(trim_target);
                }
            });
        }""",
        "        store.tidy_every_site(now, self.limits.per_domain);",
        ["storing_a_cookie_for_each_of_many_sites_stays_linear_in_the_number_of_sites"],
    ),
    (
        "P8 per-domain purge batch reverted to exact-cap trimming",
        "jar.rs",
        """                if bucket.len() > per_domain {
                    bucket.remove_expired(now);
                    bucket.trim_to(trim_target);
                }""",
        """                bucket.remove_expired(now);
                bucket.trim_to(per_domain);""",
        ["per_domain_eviction_cost_amortises_once_a_bucket_is_full"],
    ),
    (
        "P8 global purge batch reverted to exact-cap eviction",
        "jar.rs",
        """    pub const fn purge_batch(&self) -> usize {
        self.total / 10
    }""",
        """    pub const fn purge_batch(&self) -> usize {
        0
    }""",
        ["eviction_cost_amortises_across_inserts_once_the_jar_is_full"],
    ),
    (
        # Both halves have to go. Either one alone leaves the test green - see the note on
        # `Bucket::position_of`.
        "F3 bucket index reverted to a linear scan, in-response trim disabled",
        "jar.rs",
        """        examined(1);
        self.index
            .get(&(name.to_owned(), domain.to_owned(), path.to_owned()))
            .copied()""",
        """        self.entries.iter().position(|entry| {
            examined(1);
            entry.cookie.name == name
                && entry.cookie.domain == domain
                && entry.cookie.path == path
        })""",
        ["storing_one_response_with_many_cookies_stays_linear_in_the_number_of_cookies"],
        ("if bucket.len() > per_domain.saturating_mul(2) {", "if false {"),
    ),
]


def run_test(name):
    """True if the named test passed."""
    result = subprocess.run(
        ["cargo", "test", "-p", "chromulate-cookie", "--lib", "--", "--exact", name],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    out = result.stdout + result.stderr
    if "1 passed" in out and "0 failed" in out:
        return True
    if "1 failed" in out or "0 passed" in out:
        return False
    raise SystemExit(f"could not read a result for {name}:\n{out[-2000:]}")


def main():
    snapshot = Path(tempfile.mkdtemp(prefix="fx4-mutation-snapshot-"))
    for name in FILES:
        shutil.copy(SRC / name, snapshot / name)

    def restore():
        for filename in FILES:
            shutil.copy(snapshot / filename, SRC / filename)

    everything_covered = True
    try:
        for mutation in MUTATIONS:
            label, filename, find, replace, must_fail = mutation[:5]
            extra = mutation[5] if len(mutation) > 5 else None

            path = SRC / filename
            text = path.read_text()
            if find not in text:
                print(f"\n--- {label}\n      SKIPPED: target not found in {filename};"
                      " the code moved and this mutation needs updating")
                everything_covered = False
                continue
            text = text.replace(find, replace, 1)
            if extra:
                if extra[0] not in text:
                    print(f"\n--- {label}\n      SKIPPED: second target not found")
                    everything_covered = False
                    restore()
                    continue
                text = text.replace(extra[0], extra[1], 1)
            path.write_text(text)

            print(f"\n--- {label}")
            for test in must_fail:
                passed = run_test(test)
                if passed:
                    everything_covered = False
                print(
                    f"      {'FAIL' if passed else 'ok  '}  {test}: "
                    f"{'NOT COVERED (still passed)' if passed else 'went red as required'}"
                )
            restore()

        print("\n--- restored; confirming the suite is green again")
        result = subprocess.run(
            ["cargo", "test", "-p", "chromulate-cookie"],
            capture_output=True,
            text=True,
            cwd=REPO,
        )
        for line in (result.stdout + result.stderr).splitlines():
            if "test result:" in line:
                print("      " + line.strip())
    finally:
        restore()
        shutil.rmtree(snapshot, ignore_errors=True)

    print("\nEVERY FIX IS COVERED" if everything_covered else "\nSOME FIX IS NOT COVERED")
    return 0 if everything_covered else 1


if __name__ == "__main__":
    sys.exit(main())
