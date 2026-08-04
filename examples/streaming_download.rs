//! Downloading without holding the response in memory.
//!
//! ```text
//! cargo run --example streaming_download -- https://example.com/large.bin out.bin
//! ```

use chromulate::Client;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .unwrap_or_else(|| "https://example.com".to_owned());
    let destination = args.next().unwrap_or_else(|| "download.out".to_owned());

    let client = Client::chrome()?;
    let response = client.get(&url).send().await?.error_for_status()?;

    if let Some(length) = response.content_length() {
        println!("downloading {length} bytes to {destination}");
    } else {
        println!("downloading to {destination} (length unknown)");
    }

    let mut file = tokio::fs::File::create(&destination).await?;
    let mut written = 0u64;

    // `bytes_stream` never buffers the whole body, so this stays flat in memory
    // whether the response is a kilobyte or a gigabyte.
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        written += chunk.len() as u64;
        file.write_all(&chunk).await?;
    }
    file.flush().await?;

    println!("wrote {written} bytes");
    Ok(())
}
