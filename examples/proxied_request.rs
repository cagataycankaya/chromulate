//! Routing requests through a proxy.
//!
//! ```text
//! cargo run --example proxied_request -- socks5h://127.0.0.1:1080 https://example.com
//! ```
//!
//! Prefer `socks5h` over `socks5`. Both tunnel the connection, but `socks5`
//! resolves the target hostname on this machine before connecting, which hands
//! the name to the local resolver and defeats much of the point; `socks5h`
//! passes the name to the proxy and lets it resolve.

use chromulate::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let proxy = args
        .next()
        .unwrap_or_else(|| "socks5h://127.0.0.1:1080".to_owned());
    let url = args
        .next()
        .unwrap_or_else(|| "https://example.com".to_owned());

    // `proxy` parses the URL, so it returns a `Result` rather than the
    // builder directly.
    let client = Client::builder().proxy(&proxy)?.build()?;

    match client.get(&url).send().await {
        Ok(response) => {
            println!("{} via the proxy", response.status());
            println!(
                "{}",
                response.text().await?.chars().take(300).collect::<String>()
            );
        }
        Err(error) => {
            // Proxy errors redact credentials, so this is safe to print even
            // when the proxy URL carried a username and password.
            eprintln!("request failed: {error}");
            std::process::exit(1);
        }
    }

    // A pool of proxies rotates round-robin, one exit per request. The pool key
    // includes the exit, so a connection opened through one proxy is never
    // reused for a request routed through another.
    //
    // Each exit also keeps its own cookies, because a pool of two or more
    // defaults to `ProxyIsolation::PerProxy`: presenting one session from every
    // exit would tell the origin that the addresses are one client. Add
    // `.proxy_isolation(ProxyIsolation::Shared)` for the other case — rotating
    // exits to spread load on a site you are logged in to.
    let rotating = Client::builder()
        .proxy_pool(["socks5h://127.0.0.1:1080", "socks5h://127.0.0.1:1081"])?
        .build()?;
    println!(
        "rotating client ready: {:?}, isolation {:?}",
        rotating.profile().name,
        rotating.proxy_isolation()
    );

    Ok(())
}
