//! The lenient `Expires` date parser, and the `Max-Age` seconds parser beside it.
//!
//! Neither has a public entry point of its own, so both are reached the way a
//! server reaches them: through a `Set-Cookie` header. Holding everything but the
//! attribute value fixed spends the mutation budget on the date grammar instead of
//! on rediscovering the cookie grammar, which `cookie_set_cookie` already covers.

#![no_main]
#![forbid(unsafe_code)]

use chromulate_cookie::Jar;
use chromulate_core::{CookieContext, CookieStore};
use http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use url::Url;

fn store_and_read(attribute: &[u8], value: &[u8], target: &Url) {
    let mut header = Vec::with_capacity(attribute.len() + value.len() + 16);
    header.extend_from_slice(b"fuzz=1; Path=/; ");
    header.extend_from_slice(attribute);
    header.extend_from_slice(value);

    let Ok(header) = HeaderValue::from_bytes(&header) else {
        return;
    };

    let jar = Jar::new();
    jar.store(target, &mut std::iter::once(&header));
    // Reading back matters: an `Expires` in the past deletes the cookie, and a
    // far-future one is clamped to the 400-day cap. Both decisions happen here,
    // not at store time.
    let _ = jar.cookies_for(target, &CookieContext::conservative_default());
}

fuzz_target!(|data: &[u8]| {
    let target = Url::parse("https://example.com/").expect("a literal URL parses");

    store_and_read(b"Expires=", data, &target);
    store_and_read(b"Max-Age=", data, &target);
});
