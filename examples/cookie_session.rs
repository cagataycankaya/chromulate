//! Keeping a session across requests with the cookie jar.
//!
//! ```text
//! cargo run --example cookie_session
//! ```
//!
//! The jar is on by default, so a session usually needs no configuration at
//! all. This example makes it explicit, and shows how to share one jar between
//! two clients — which is how you give two different identities the same
//! logged-in session, or persist a session across a restart.

use std::sync::Arc;

use chromulate::Client;
use chromulate::cookie::Jar;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://httpbin.org".to_owned());

    // One jar, shared. Both clients read and write the same cookies.
    let jar = Arc::new(Jar::new());

    let client = Client::builder().cookie_jar(Arc::clone(&jar)).build()?;

    // The server sets a cookie here.
    let set = client
        .get(format!("{base}/cookies/set?session=abc123"))
        .send()
        .await?;
    println!("set: {}", set.status());
    let _ = set.bytes().await?;

    // The jar replays it without the caller doing anything.
    let echoed = client.get(format!("{base}/cookies")).send().await?;
    println!("echoed: {}", echoed.status());
    println!("{}", echoed.text().await?);

    // A second client on the same jar is already in the session.
    let other = Client::builder().cookie_jar(Arc::clone(&jar)).build()?;
    let shared = other.get(format!("{base}/cookies")).send().await?;
    println!("shared jar: {}", shared.text().await?);

    // The jar can be exported and reloaded, so a session survives a restart.
    let snapshot = jar.export();
    println!("{} cookie(s) held", snapshot.cookies.len());

    let restored = Arc::new(Jar::new());
    restored.import(&snapshot);
    println!("{} cookie(s) restored", restored.export().cookies.len());

    Ok(())
}
