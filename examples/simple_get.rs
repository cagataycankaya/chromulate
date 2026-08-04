//! A GET with a browser identity, and a report of how browser-like it really
//! was.
//!
//! ```text
//! cargo run --example simple_get -- https://example.com
//! ```

use chromulate::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com".to_owned());

    let client = Client::chrome()?;

    let response = client.get(&url).send().await?;

    println!("{} {:?}", response.status(), response.version());
    println!("final url: {}", response.url());
    for (name, value) in response.headers() {
        println!("  {name}: {}", value.to_str().unwrap_or("<binary>"));
    }

    let body = response.text().await?;
    println!("\n{} bytes of body", body.len());
    println!("{}", body.chars().take(500).collect::<String>());

    // What the profile aims at, and where this stack falls short of it. Both
    // are worth printing together: the target alone would overstate what the
    // request actually looked like.
    let engine = client.engine();
    println!("\ntarget identity: {}", engine.tls().target_identity());
    println!("tls fidelity:    {}", engine.tls().fidelity());
    println!("http/2 target:   {}", engine.http2_fidelity().target);
    for gap in &engine.http2_fidelity().unsupported {
        println!("  http/2 gap: {gap}");
    }

    Ok(())
}
