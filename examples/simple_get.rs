//! A GET with a browser identity, and a report of how browser-like it really
//! was.
//!
//! ```text
//! cargo run --example simple_get -- https://example.com
//! ```

use chromulate::Client;
// `target_identity` and `fidelity` are called through the trait rather than as
// inherent methods. The rustls backend happens to have inherent methods of the
// same name, so `engine.tls().fidelity()` compiles in a default build and stops
// compiling the moment `ActiveBackend` names anything else — which is how the
// facade came to be broken under `--cfg chromulate_mock_backend`. Naming the
// trait keeps this example honest about which one it means.
use chromulate::tls::TlsBackendConfig;

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
    println!(
        "\ntarget identity: {}",
        TlsBackendConfig::target_identity(engine.tls())
    );
    println!(
        "tls fidelity:    {}",
        TlsBackendConfig::fidelity(engine.tls())
    );
    println!("http/2 target:   {}", engine.http2_fidelity().target);
    for gap in &engine.http2_fidelity().unsupported {
        println!("  http/2 gap: {gap}");
    }

    Ok(())
}
