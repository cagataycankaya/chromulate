//! `HeaderEngine::apply`, and the `Accept-CH` store a server drives it with.
//!
//! Two of the engine's inputs are chosen by somebody else. The `Accept-CH` value
//! comes from the origin's own response and decides which high-entropy hints join
//! the order; the headers a caller already set have to be woven into the captured
//! order at the profile's slot for each name rather than appended after it. Both
//! meet code that inserts into and indexes a plan built from the profile, so the
//! failures worth hunting here are positional rather than parse failures.
//!
//! The input is a two-byte selector — fetch mode, destination, HTTP version,
//! method, user activation — followed by NUL-separated fields: the `Accept-CH`
//! value, a newline-separated block of `name: value` caller headers, the target
//! URL, the referrer, the initiator, and a high-entropy hint value.
//!
//! Deliberately not covered: the profile, which is captured data rather than
//! untrusted input — `fingerprint_capture` fuzzes the loader that builds one — and
//! `http`'s own header name and value parsers, which reject a caller header here
//! before the engine ever sees it.

#![no_main]
#![forbid(unsafe_code)]

use std::sync::{Arc, OnceLock};

use chromulate_core::{
    Body, FetchDest, FetchMode, Origin, Request, RequestOptions, Result as CoreResult,
};
use chromulate_header::{
    AcceptChLimits, AcceptChStore, HeaderEngine, HighEntropyHints, UserActivatedNavigation,
    parse_accept_ch,
};
use chromulate_profile::Profile;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Version};
use libfuzzer_sys::fuzz_target;
use url::Url;

/// Used whenever the fuzzer's own URL field does not parse, so an input that
/// spends its bytes on headers still reaches `apply` instead of returning early.
const FALLBACK_TARGET: &str = "https://example.com/index.html";

/// Four origins against a shipped default of 10,000, so recording a grant
/// actually evicts one. The origin under test is recorded last and therefore
/// survives, which is what keeps the granted-hint path reachable.
const ACCEPT_CH_LIMITS: AcceptChLimits = AcceptChLimits { origins: 4 };

/// Origins recorded before the one under test, purely to fill the store.
const CROWD: [&str; 4] = [
    "https://a.example",
    "https://b.example",
    "https://c.example",
    "https://d.example",
];

const MODES: [FetchMode; 5] = [
    FetchMode::Navigate,
    FetchMode::Cors,
    FetchMode::NoCors,
    FetchMode::SameOrigin,
    FetchMode::Websocket,
];

const DESTS: [FetchDest; 7] = [
    FetchDest::Document,
    FetchDest::Iframe,
    FetchDest::Script,
    FetchDest::Style,
    FetchDest::Image,
    FetchDest::Font,
    FetchDest::Empty,
];

/// The profile, built once. Every field of it is fixed captured data, so
/// rebuilding it per iteration would only cost executions.
fn profile() -> Arc<Profile> {
    static PROFILE: OnceLock<Arc<Profile>> = OnceLock::new();
    Arc::clone(PROFILE.get_or_init(|| Arc::new(Profile::chrome_stable())))
}

fn field<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> &'a str {
    fields
        .next()
        .and_then(|raw| std::str::from_utf8(raw).ok())
        .unwrap_or("")
}

fn method_for(index: u8) -> Method {
    match index % 6 {
        0 => Method::GET,
        1 => Method::POST,
        2 => Method::PUT,
        3 => Method::DELETE,
        4 => Method::HEAD,
        _ => Method::OPTIONS,
    }
}

fn options_for(
    mode: FetchMode,
    dest: FetchDest,
    referrer: Option<Url>,
    initiator: Option<Origin>,
) -> RequestOptions {
    // `RequestOptions` is `#[non_exhaustive]`, so a struct literal is not
    // available outside its own crate and the fields are set one at a time.
    let mut options = RequestOptions::default();
    options.mode = mode;
    options.dest = dest;
    options.referrer = referrer;
    options.initiator = initiator;
    options
}

/// Parses the caller-header block onto `request`, skipping any line `http` itself
/// would reject. A name that appears twice is appended twice on purpose: that is
/// the multi-value case `apply` has to keep together.
fn set_caller_headers(headers: &mut HeaderMap, block: &str) {
    for line in block.split('\n') {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.trim().as_bytes()),
            HeaderValue::from_str(value.trim()),
        ) else {
            continue;
        };
        headers.append(name, value);
    }
}

/// Each header name occupies one contiguous run of the order, and no more.
///
/// Not "no name appears twice": a caller that sets one name twice gets both values
/// back, and `apply` documents that it emits them together at that name's slot. A
/// name appearing at two *separate* positions is the failure — the captured order
/// this crate exists to reproduce coming apart, which a server reading header
/// order sees and a `HeaderMap` cannot express.
fn every_name_occupies_one_run(order: &[(HeaderName, HeaderValue)]) {
    let mut runs_seen: Vec<&HeaderName> = Vec::with_capacity(order.len());
    for (position, (name, _)) in order.iter().enumerate() {
        if position > 0 && &order[position - 1].0 == name {
            continue;
        }
        assert!(
            !runs_seen.contains(&name),
            "`{name}` is emitted at two separate positions in the order: {:?}",
            order.iter().map(|(name, _)| name).collect::<Vec<_>>()
        );
        runs_seen.push(name);
    }
}

/// The returned `Vec` is the authoritative wire order and the request's own
/// `HeaderMap` is a convenience copy of it. The two disagreeing means a caller who
/// looks a header up by name is told something other than what goes on the wire.
fn map_agrees_with_order(order: &[(HeaderName, HeaderValue)], headers: &HeaderMap) {
    assert_eq!(
        order.len(),
        headers.len(),
        "the order carries {} values and the request's map {}",
        order.len(),
        headers.len()
    );

    for name in headers.keys() {
        let from_order: Vec<&HeaderValue> = order
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .map(|(_, value)| value)
            .collect();
        let from_map: Vec<&HeaderValue> = headers.get_all(name).into_iter().collect();
        assert_eq!(
            from_order, from_map,
            "`{name}` has different values in the order than on the request"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&fetch_selector, rest)) = data.split_first() else {
        return;
    };
    let Some((&request_selector, rest)) = rest.split_first() else {
        return;
    };

    let mut fields = rest.split(|&byte| byte == 0);
    let accept_ch = field(&mut fields);
    let caller_headers = field(&mut fields);
    let target = field(&mut fields);
    let referrer = field(&mut fields);
    let initiator = field(&mut fields);
    let hint_value = field(&mut fields);

    // Exercised on its own as well as through the store, because an `Accept-CH`
    // value that names nothing this crate models never reaches a grant at all.
    let _ = parse_accept_ch(accept_ch);

    let target = Url::parse(target)
        .unwrap_or_else(|_| Url::parse(FALLBACK_TARGET).expect("a literal URL parses"));
    let referrer = Url::parse(referrer).ok();
    let initiator = Url::parse(initiator)
        .ok()
        .and_then(|url| Origin::of(&url).ok());

    let mut accept_ch_store = AcceptChStore::with_limits(ACCEPT_CH_LIMITS);
    for origin in CROWD {
        let url = Url::parse(origin).expect("a literal URL parses");
        let origin = Origin::of(&url).expect("a literal https URL has an origin");
        accept_ch_store.record(origin, accept_ch);
    }
    // Last, so the crowd above is what eviction reaches for and this origin's
    // grant is still there when `apply` asks for it.
    if let Ok(origin) = Origin::of(&target) {
        accept_ch_store.record(origin, accept_ch);
    }
    assert!(
        accept_ch_store.len() <= ACCEPT_CH_LIMITS.origins,
        "the store holds {} origins against a cap of {}",
        accept_ch_store.len(),
        ACCEPT_CH_LIMITS.origins
    );

    let mut request = Request::new(Body::empty());
    *request.method_mut() = method_for(request_selector >> 2);
    *request.version_mut() = if request_selector & 1 == 0 {
        Version::HTTP_11
    } else {
        Version::HTTP_2
    };
    if request_selector & 2 != 0 {
        request.extensions_mut().insert(UserActivatedNavigation);
    }
    set_caller_headers(request.headers_mut(), caller_headers);

    // A fuzzer-chosen hint value reaches the branch that reports a profile value
    // the `http` crate cannot encode, which is an error rather than a panic.
    let hints = HighEntropyHints {
        platform_version: Some(hint_value.to_owned()),
        ..HighEntropyHints::default()
    };
    let engine = HeaderEngine::new(profile()).with_high_entropy_hints(hints);

    let options = options_for(
        MODES[usize::from(fetch_selector) % MODES.len()],
        DESTS[usize::from(fetch_selector / 5) % DESTS.len()],
        referrer,
        initiator,
    );

    let applied: CoreResult<_> = engine.apply(&mut request, &target, &options, &accept_ch_store);
    let Ok(order) = applied else {
        return;
    };

    every_name_occupies_one_run(&order);
    map_agrees_with_order(&order, request.headers());
});
