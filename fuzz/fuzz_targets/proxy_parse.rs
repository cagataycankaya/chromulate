//! Proxy URL parsing and `no_proxy` rule matching.
//!
//! Both take strings from configuration a user did not necessarily write: the
//! `*_PROXY` environment variables are set by whoever set up the machine, and a
//! `no_proxy` list is copied between shells until nobody remembers its shape. The
//! parse has to fail rather than panic on anything, and `matches` has to answer
//! for any host string at all, including the empty one.
//!
//! The input is three NUL-separated fields — proxy URL, `no_proxy` list, candidate
//! host. NUL appears in none of the three legitimately, so it is a separator the
//! fuzzer finds once and then leaves alone.

#![no_main]
#![forbid(unsafe_code)]

use chromulate_proxy::{NoProxy, Proxy, ProxyUrl};
use libfuzzer_sys::fuzz_target;

fn field<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> Option<&'a str> {
    fields.next().and_then(|raw| std::str::from_utf8(raw).ok())
}

fuzz_target!(|data: &[u8]| {
    let mut fields = data.split(|&b| b == 0);

    let Some(url) = field(&mut fields) else {
        return;
    };
    let no_proxy = field(&mut fields).unwrap_or("");
    let host = field(&mut fields).unwrap_or("");

    // Exercised on its own as well as through `Proxy`, because a `no_proxy` list
    // is usable without a proxy URL that parses.
    if let Ok(rules) = NoProxy::parse(no_proxy) {
        let _ = rules.matches(host);
    }

    let Ok(proxy_url) = ProxyUrl::parse(url) else {
        return;
    };

    // Accessors, not just the parse: percent-decoded credentials and the base64
    // auth header are built after parsing, from whatever the parse accepted.
    let _ = proxy_url.host();
    let _ = proxy_url.username();
    let _ = proxy_url.password();
    let _ = proxy_url.host_port();
    let _ = proxy_url.basic_auth_header_value();

    let mut proxy = Proxy::new(proxy_url);
    if let Ok(rules) = NoProxy::parse(no_proxy) {
        proxy = proxy.with_no_proxy(rules);
    }
    let _ = proxy.bypasses(host);
});
