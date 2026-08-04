//! `Set-Cookie` header bytes in, jar state out.
//!
//! Every byte reaching this parser is chosen by whoever runs the server, so it is
//! the widest untrusted-input surface in the project. The target drives the whole
//! public round trip rather than the parser alone: store, read back under two
//! `SameSite` contexts, and export/import the jar, so whatever the parser accepted
//! also has to survive matching and serialisation.

#![no_main]
#![forbid(unsafe_code)]

use chromulate_cookie::Jar;
use chromulate_core::{CookieContext, CookieStore, Origin};
use http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use url::Url;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = HeaderValue::from_bytes(data) else {
        return;
    };

    let target = Url::parse("https://sub.example.com/a/b").expect("a literal URL parses");
    let jar = Jar::new();

    jar.store(&target, &mut std::iter::once(&value));
    // Storing the same header twice takes the overwrite path, which shares its
    // `Secure`-cookie guard with the deletion path rather than carrying a copy.
    jar.store(&target, &mut std::iter::once(&value));

    // The context a caller passes when it tracks no site relationship, which is
    // what most callers pass. Its `Lax`/`Strict` split is easy to break silently.
    let unknown_site = CookieContext::conservative_default();
    let _ = jar.cookies_for(&target, &unknown_site);

    let same_site = CookieContext {
        initiator: Origin::of(&target).ok(),
        is_top_level_navigation: false,
    };
    let _ = jar.cookies_for(&target, &same_site);

    // A sibling host under the same registrable domain, and the root path:
    // whatever domain and path the parser resolved now has to be matched
    // against something it does not equal.
    let sibling = Url::parse("https://other.example.com/").expect("a literal URL parses");
    let _ = jar.cookies_for(&sibling, &unknown_site);

    let snapshot = jar.export();
    let restored = Jar::new();
    restored.import(&snapshot);
    let _ = restored.cookies_for(&target, &unknown_site);
});
