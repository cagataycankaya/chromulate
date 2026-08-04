//! The HSTS preload list, as Chromium ships it.
//!
//! A store learned from responses cannot protect the *first* request to an
//! origin, because the plaintext request is what teaches it. RFC 6797 §12.3
//! ("HSTS Pre-Loaded List") is the answer browsers use: a list of hosts
//! pre-configured in the user agent "in a manner similar to how root CA
//! certificates are embedded in browsers 'at the factory'", and §7.1 says
//! plainly that establishing a Known HSTS Host by "a client-side pre-loaded
//! Known HSTS Host list MAY also be used".
//!
//! # The list is captured, not written
//!
//! Every name and every `include_subdomains` flag here comes from Chromium's
//! `net/http/transport_security_state_static.json`. Nothing is hand-entered,
//! nothing is sampled: this is the complete set of `mode: "force-https"` entries
//! from one identified revision of that file. See
//! `data/hsts-preload/PROVENANCE.md` for the URL, the revision, the date, the
//! SHA-256 of both the source and the blob, and `data/hsts-preload/generate.py`
//! for the transform, which is the only thing that has ever written the blob.
//!
//! # Matching is on label boundaries, and the public suffix list plays no part
//!
//! An entry covers its own name always, and covers a subdomain only when it
//! carries `include_subdomains`. Because the lookup asks about the host and then
//! about each ancestor formed by dropping a leading label, the boundary falls
//! where the dots are and never inside a label: `notgmail.com` does not reach the
//! `gmail.com` entry, though one string is a suffix of the other.
//!
//! It is tempting to reach for `psl` here, since `chromulate-cookie` uses it to
//! find the registrable domain and stop a cookie escaping to a public suffix.
//! That would be wrong for HSTS, and the list says so itself: 57 entries in the
//! captured revision carry `"policy": "public-suffix"`, and they include the bare
//! TLDs `app`, `dev`, `bank`, `page`, and `google`, each with
//! `include_subdomains`. Stopping the ancestor walk at the registrable domain
//! would mean `anything.example.app` never reaches the `app` entry, and every
//! host under those TLDs would silently lose the protection Chromium gives it.
//! The walk therefore runs to the last label, exactly as Chromium's own
//! `GetStaticSTSState` does.
//!
//! # Shape, and what the shape actually costs
//!
//! The blob is a sorted table of names with a parallel index, read straight out
//! of `include_bytes!`. There is no startup parse, no map to build, and a lookup
//! allocates nothing: it is a binary search whose comparisons borrow from the
//! blob and from the caller's host. See `data/hsts-preload/generate.py` for the
//! layout.
//!
//! The table was chosen over a `HashMap` built once at startup, and the measured
//! numbers do not say what that choice is usually justified with. On macOS arm64,
//! release, five rounds of 200,000 lookups each
//! (`measure_the_table_against_a_hashmap_built_at_startup` below):
//!
//! - this table: 87.1–91.0 ns per exact lookup, 0 ms of startup, 0 bytes of heap;
//! - `HashMap<&[u8], bool>`: 11.8–12.1 ns per lookup, after 4.4 ms spent building
//!   it and roughly five megabytes of heap held for the life of the process.
//!
//! So the map is about seven times faster per lookup and the table wins anyway.
//! What is being bought for 76 ns is 4.4 ms of startup that every process pays
//! whether or not it ever asks, several megabytes that are never released, and a
//! `OnceLock` on the request path to guard the build. The number that decides it
//! is the absolute one: `covers` costs 269–283 ns over the mixed host shapes in
//! `tests/hsts_preload.rs` (two runs of five rounds of 200,000, macOS arm64,
//! release; the top of that range is a first-round outlier), it is consulted once
//! per request, and a request is measured in milliseconds. A quarter of a
//! microsecond is not where this client spends its time.
//!
//! That figure was 234.8–239.6 ns before `super::canonical_name` was added in
//! front of the match, measured the same way on the same machine; canonicalising
//! the host costs about 33 ns of the total. It buys a preload list that a single
//! extra dot in a URL cannot walk around, which is not a trade that needed
//! thinking about.
//!
//! The map is also not quite the same function. Matching a mixed-case host
//! against a byte-keyed map means allocating a lowercased copy per lookup or
//! writing a custom equivalence; the binary search folds case as it reads,
//! because it compares byte by byte anyway.
//!
//! # The name is canonicalised first, in both halves
//!
//! [`covers`] puts the host through `super::canonical_name` before it matches
//! anything — the same function [`super::HstsStore::applies_to`] uses, so the
//! learned half and the preloaded half agree on what a host *is*. Two things
//! come out of that, and each was a real defect before it did:
//!
//! - a host written with the root label present (`example.com.`, which is what
//!   `url` hands over for `http://example.com./`) matches its entry, where
//!   before it silently did not and the request went out in plaintext;
//! - a host with any other empty label (`a..app`) matches nothing, where before
//!   the ancestor walk stepped over the empty label and reached the `app` entry.
//!
//! [`lookup`] does not canonicalise: it is the raw table probe the tests use to
//! read what the blob holds, and canonicalising there would make it unable to
//! say so.

use std::cmp::Ordering;

/// The encoded list. `data/hsts-preload/generate.py` documents the layout.
const BLOB: &[u8] = include_bytes!("../../data/hsts-preload/preload.bin");

/// Bytes before the index: the magic, the entry count, and the name-blob length.
const HEADER_LEN: usize = 16;

/// Bit 31 of an index word carries the entry's `include_subdomains` flag.
const FLAG_INCLUDE_SUBDOMAINS: u32 = 1 << 31;

/// The remaining bits carry the entry's start offset into the name blob.
const OFFSET_MASK: u32 = FLAG_INCLUDE_SUBDOMAINS - 1;

/// Reads the little-endian `u32` at `at`.
///
/// A `const fn` so that the header can be decoded at compile time; it is the
/// same function the lookup calls at run time.
const fn word_at(at: usize) -> u32 {
    u32::from_le_bytes([BLOB[at], BLOB[at + 1], BLOB[at + 2], BLOB[at + 3]])
}

/// How many hosts the compiled-in list holds.
///
/// Read out of the blob rather than written here, so it cannot drift from the
/// data the way a hand-maintained count would.
pub const ENTRY_COUNT: usize = word_at(8) as usize;

/// Total bytes of concatenated names.
///
/// Used only by the compile-time checks below, which is a real use — but Rust
/// 1.88, this crate's minimum, does not count uses inside an anonymous `const`
/// item's initializer and reports the constant as dead. Later toolchains do see
/// it, so the lint fires on the MSRV job alone. The allow is narrower than
/// dropping the assertion it feeds.
#[allow(dead_code)]
const NAMES_LEN: usize = word_at(12) as usize;

/// Where the name blob starts: past the header and the `ENTRY_COUNT + 1` index
/// words, the last of which is the sentinel that gives the final name its end.
const NAMES_START: usize = HEADER_LEN + 4 * (ENTRY_COUNT + 1);

/// The file the list was taken from.
pub const SOURCE_FILE: &str = "chromium/src net/http/transport_security_state_static.json";

/// The Chromium commit the list was taken from.
pub const SOURCE_REVISION: &str = "7be0edc636b0e7b0143e2700ecf5c8af750d09ec";

/// When the list was fetched, as an ISO 8601 date.
pub const FETCHED_AT: &str = "2026-08-04";

// The blob is checked at compile time, because a truncated or mismatched file
// should stop a build rather than produce a lookup that reads whatever is there.
const _: () = {
    assert!(
        BLOB.len() > HEADER_LEN,
        "preload blob is shorter than its header"
    );
    assert!(
        BLOB[0] == b'C'
            && BLOB[1] == b'H'
            && BLOB[2] == b'R'
            && BLOB[3] == b'O'
            && BLOB[4] == b'M'
            && BLOB[5] == b'H'
            && BLOB[6] == b'S'
            && BLOB[7] == b'1',
        "preload blob does not start with the CHROMHS1 magic"
    );
    assert!(ENTRY_COUNT > 0, "preload blob holds no entries");
    assert!(
        NAMES_START + NAMES_LEN == BLOB.len(),
        "preload blob length disagrees with its header"
    );
    assert!(
        word_at(HEADER_LEN + 4 * ENTRY_COUNT) as usize == NAMES_LEN,
        "preload blob's sentinel offset is not the name-blob length"
    );
};

/// The name of entry `index`, as bytes.
fn name_at(index: usize) -> &'static [u8] {
    let start = (word_at(HEADER_LEN + 4 * index) & OFFSET_MASK) as usize;
    let end = (word_at(HEADER_LEN + 4 * (index + 1)) & OFFSET_MASK) as usize;
    &BLOB[NAMES_START + start..NAMES_START + end]
}

/// Whether entry `index` asserts `includeSubDomains`.
fn includes_subdomains(index: usize) -> bool {
    word_at(HEADER_LEN + 4 * index) & FLAG_INCLUDE_SUBDOMAINS != 0
}

/// Orders a table name against a query host, folding the query's ASCII case.
///
/// The table is lowercase and sorted by byte value, so lowercasing the query as
/// it is read gives the same total order the table was sorted under — which is
/// what makes the binary search valid, and what lets the lookup accept a
/// mixed-case host without allocating a lowercased copy of it.
fn compare(table: &[u8], query: &[u8]) -> Ordering {
    let common = if table.len() < query.len() {
        table.len()
    } else {
        query.len()
    };
    for at in 0..common {
        let ordering = table[at].cmp(&query[at].to_ascii_lowercase());
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    table.len().cmp(&query.len())
}

/// Looks `name` up as a whole entry, returning its `includeSubDomains` flag.
///
/// This is an exact match on the full name: it says nothing about subdomains and
/// it does not canonicalise `name`, so a root label makes it miss. [`covers`] is
/// the question a caller usually wants answered, and the one that canonicalises.
///
/// ```
/// use chromulate_http::hsts::preload;
///
/// // Google preloads `gmail.com` without `includeSubDomains`.
/// assert_eq!(preload::lookup("gmail.com"), Some(false));
/// // `.app` is preloaded as a whole TLD, with subdomains.
/// assert_eq!(preload::lookup("app"), Some(true));
/// assert_eq!(preload::lookup("example.com"), None);
/// // The raw table holds no root label, so neither does a query that finds it.
/// assert_eq!(preload::lookup("gmail.com."), None);
/// assert!(preload::covers("gmail.com."));
/// ```
#[must_use]
pub fn lookup(name: &str) -> Option<bool> {
    let query = name.as_bytes();
    let mut low = 0usize;
    let mut high = ENTRY_COUNT;
    while low < high {
        let middle = low + (high - low) / 2;
        match compare(name_at(middle), query) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => return Some(includes_subdomains(middle)),
        }
    }
    None
}

/// Whether the preload list demands HTTPS for `host`.
///
/// True when `host` is itself an entry, or when an ancestor of it is an entry
/// that asserts `includeSubDomains`. `host` may be in any ASCII case and may
/// carry the root label; it must be a name rather than an IP literal, which the
/// caller has already established.
///
/// ```
/// use chromulate_http::hsts::preload;
///
/// assert!(preload::covers("gmail.com"));
/// // `gmail.com` is preloaded without `includeSubDomains`, so this is not covered.
/// assert!(!preload::covers("mail.gmail.com"));
/// // `.app` is preloaded with them, so everything under it is.
/// assert!(preload::covers("anything.example.app"));
/// // A shared string suffix is not a shared label boundary.
/// assert!(!preload::covers("notgmail.com"));
/// // The root label is dropped, as DNS drops it.
/// assert!(preload::covers("anything.example.app."));
/// // An empty label is not a label to walk past.
/// assert!(!preload::covers("anything..app"));
/// ```
#[must_use]
pub fn covers(host: &str) -> bool {
    let Some(host) = super::canonical_name(host) else {
        return false;
    };
    if lookup(host).is_some() {
        return true;
    }

    // An ancestor's entry reaches this host only when that ancestor said
    // `includeSubDomains`. Dropping one leading label at a time is what keeps
    // the comparison on a label boundary; `canonical_name` has already
    // established that no label is empty, so every parent this yields is one.
    let mut rest = host;
    while let Some((_, parent)) = rest.split_once('.') {
        if lookup(parent) == Some(true) {
            return true;
        }
        rest = parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_blob_is_the_captured_list_and_not_a_sample() {
        // Not a round number chosen for tidiness: it is what
        // `data/hsts-preload/generate.py` reported for revision
        // 7be0edc636b0e7b0143e2700ecf5c8af750d09ec, and PROVENANCE.md records the
        // same figure. If the list is regenerated, both move together or this
        // fails and someone has to look at why.
        assert_eq!(ENTRY_COUNT, 94_628);
        assert_eq!(BLOB.len(), 1_749_625);

        // PROVENANCE.md records the flag split too, and nothing was checking it:
        // a blob regenerated from a source that had changed shape could keep both
        // numbers above and still carry a different set of flags. This is the
        // cheapest thing that would notice.
        let with_subdomains = (0..ENTRY_COUNT)
            .filter(|index| includes_subdomains(*index))
            .count();
        assert_eq!(with_subdomains, 94_378);
        assert_eq!(ENTRY_COUNT - with_subdomains, 250);
    }

    #[test]
    fn every_name_is_lowercase_ascii_and_the_table_is_sorted() {
        // The binary search is only correct if the table really is sorted under
        // the order `compare` implements, and `compare` only folds case on the
        // query side because the table is assumed lowercase. Both assumptions
        // are checked against the shipped bytes rather than trusted.
        let mut previous: &[u8] = b"";
        for index in 0..ENTRY_COUNT {
            let name = name_at(index);
            assert!(!name.is_empty(), "entry {index} has an empty name");
            assert!(
                name.iter()
                    .all(|byte| byte.is_ascii() && !byte.is_ascii_uppercase()),
                "entry {index} is not lowercase ASCII: {:?}",
                std::str::from_utf8(name)
            );
            assert!(
                previous < name,
                "entries {} and {index} are out of order: {:?} then {:?}",
                index.saturating_sub(1),
                std::str::from_utf8(previous),
                std::str::from_utf8(name)
            );
            previous = name;
        }
    }

    #[test]
    fn every_entry_is_found_by_the_binary_search() {
        // A sorted table and a search that agrees with it are two claims. This
        // is the one that would catch a `compare` that orders differently from
        // the generator's sort for some name in the middle of the list.
        for index in 0..ENTRY_COUNT {
            let name = std::str::from_utf8(name_at(index)).expect("entry should be UTF-8");
            assert_eq!(
                lookup(name),
                Some(includes_subdomains(index)),
                "entry {index} ({name}) was not found by its own name"
            );
        }
    }

    #[test]
    fn a_name_that_is_a_prefix_or_suffix_of_an_entry_is_not_an_entry() {
        // `compare` falls through to a length comparison, and this is the case
        // that proves it has to: without it a query would match any entry it
        // prefixes, in either direction.
        //
        // The first draft of this test also asserted that `mail.com` is not an
        // entry, on the assumption that it would not be. It is —
        // `"policy": "bulk-18-weeks"`, with `includeSubDomains` — and the test
        // caught the assumption. The names below were read out of the captured
        // file rather than assumed absent.
        assert!(lookup("gmail.com").is_some());
        assert_eq!(lookup("gmail.co"), None);
        assert_eq!(lookup("gmail.comm"), None);
        assert_eq!(lookup("notgmail.com"), None);
    }

    #[test]
    fn the_flag_is_read_per_entry_rather_than_assumed() {
        // 250 of the 94,628 entries have no `include_subdomains`, so a lookup
        // that returned a constant would pass on 99.7% of the list.
        assert_eq!(lookup("gmail.com"), Some(false));
        assert_eq!(lookup("app"), Some(true));
    }

    #[test]
    fn a_mixed_case_host_matches_without_allocating_a_lowercased_copy() {
        assert_eq!(lookup("GMail.CoM"), Some(false));
        assert!(covers("Anything.Example.APP"));
    }

    #[test]
    fn an_entry_without_include_subdomains_does_not_reach_its_subdomains() {
        assert!(covers("gmail.com"));
        assert!(
            !covers("mail.gmail.com"),
            "gmail.com is preloaded without includeSubDomains"
        );
    }

    #[test]
    fn a_public_suffix_entry_reaches_the_hosts_under_it() {
        // The reason `psl` is deliberately not used: clamping the walk at the
        // registrable domain would make every one of these false.
        assert!(covers("app"));
        assert!(covers("example.app"));
        assert!(covers("deep.nested.example.app"));
    }

    #[test]
    fn a_shared_string_suffix_is_not_a_match() {
        assert!(!covers("notgmail.com"));
        assert!(!covers("evilapp"));
        assert!(!covers("example.com"));
    }

    #[test]
    fn a_host_with_no_dots_and_no_entry_terminates() {
        assert!(!covers("localhost"));
        assert!(!covers(""));
    }

    #[test]
    fn the_root_label_is_dropped_before_matching() {
        // `url` keeps the root label, so this is the host `covers` is handed for
        // `http://gmail.com./` — a name that resolves to exactly what
        // `gmail.com` resolves to. Matching it literally missed the entry and
        // sent the request in plaintext.
        assert!(covers("gmail.com."));
        assert!(covers("deep.nested.example.app."));
        assert!(covers("APP."));
        // Dropping it must not widen anything: `gmail.com` still carries no
        // `includeSubDomains`, and a string suffix is still not a label
        // boundary.
        assert!(!covers("mail.gmail.com."));
        assert!(!covers("notgmail.com."));
    }

    #[test]
    fn an_empty_label_is_not_a_label_the_walk_may_step_over() {
        // The false-positive direction. The walk drops one leading label at a
        // time, so before the name was checked it reached `app` through the
        // empty label in each of these and forced HTTPS on a name DNS cannot
        // resolve and Chromium refuses to canonicalise.
        assert!(!covers("a..app"));
        assert!(!covers(".app"));
        assert!(!covers("..app"));
        assert!(!covers("a..gmail.com"));
        assert!(!covers("example.com.."));
        assert!(!covers("."));
        // The well-formed neighbours are untouched.
        assert!(covers("a.example.app"));
        assert!(covers("example.app"));
    }

    /// The comparison the table's shape was chosen on, measured rather than
    /// asserted.
    ///
    /// Ignored because it is a measurement and not a guard. Run it with
    ///
    /// ```text
    /// cargo test -p chromulate-http --features hsts-preload --release \
    ///     --lib hsts::preload::tests::measure -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not a guard; run it deliberately"]
    fn measure_the_table_against_a_hashmap_built_at_startup() {
        use std::collections::HashMap;
        use std::time::Instant;

        let hosts = [
            "localhost",
            "example.com",
            "static.assets.example.org",
            "gmail.com",
            "deep.nested.example.app",
            "notgmail.com",
        ];
        let per_round = 200_000;
        let rounds = 5;

        for round in 0..rounds {
            let started = Instant::now();
            let mut sink = 0u64;
            for index in 0..per_round {
                sink += u64::from(lookup(hosts[index % hosts.len()]).is_some());
            }
            let table = started.elapsed();
            assert!(sink < per_round as u64, "round {round} matched everything");
            println!(
                "round {round}: table {:.1} ns/lookup",
                table.as_secs_f64() * 1e9 / per_round as f64
            );
        }

        let started = Instant::now();
        let mut map: HashMap<&'static [u8], bool> = HashMap::with_capacity(ENTRY_COUNT);
        for index in 0..ENTRY_COUNT {
            map.insert(name_at(index), includes_subdomains(index));
        }
        let build = started.elapsed();
        println!(
            "hashmap build: {:.1} ms once, {ENTRY_COUNT} entries",
            build.as_secs_f64() * 1e3
        );

        for round in 0..rounds {
            let started = Instant::now();
            let mut sink = 0u64;
            for index in 0..per_round {
                sink += u64::from(map.contains_key(hosts[index % hosts.len()].as_bytes()));
            }
            let hashed = started.elapsed();
            assert!(sink < per_round as u64, "round {round} matched everything");
            println!(
                "round {round}: hashmap {:.1} ns/lookup",
                hashed.as_secs_f64() * 1e9 / per_round as f64
            );
        }
    }
}
