//! Writing a middleware.
//!
//! ```text
//! cargo run --example custom_middleware -- https://example.com
//! ```
//!
//! A middleware wraps a whole logical request, so it sees one request even when
//! the engine follows several redirect hops to satisfy it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use chromulate::header::{HeaderName, HeaderValue};
// A middleware sees the raw `http::Response<Body>` that travels through the
// chain, which the facade re-exports as `HttpResponse`. `chromulate::Response`
// is the richer type `send()` hands back to a caller, and is not what the
// chain carries.
use chromulate::{BoxFuture, Client, HttpResponse, Middleware, Next, Request, Result};

/// Times every request and counts how many went through.
///
/// The counter is shared rather than owned, because `ClientBuilder::middleware`
/// takes the middleware by value and the caller still wants to read the total
/// afterwards.
struct Timing {
    requests: Arc<AtomicU64>,
}

impl Middleware for Timing {
    fn name(&self) -> &'static str {
        "timing"
    }

    fn handle<'a>(
        &'a self,
        request: Request,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<HttpResponse>> {
        Box::pin(async move {
            let method = request.method().clone();
            // The host, not the whole URL: a query string routinely carries
            // tokens, and this line gets printed.
            let host = request.uri().host().unwrap_or("unknown").to_owned();

            let started = Instant::now();
            let result = next.run(request).await;
            let elapsed = started.elapsed();

            let count = self.requests.fetch_add(1, Ordering::Relaxed) + 1;
            match &result {
                Ok(response) => println!(
                    "[{count}] {method} {host} -> {} in {elapsed:?}",
                    response.status()
                ),
                Err(error) => {
                    println!("[{count}] {method} {host} -> failed in {elapsed:?}: {error}");
                }
            }
            result
        })
    }
}

/// Adds a header to every outgoing request.
struct AddHeader {
    name: HeaderName,
    value: HeaderValue,
}

impl Middleware for AddHeader {
    fn name(&self) -> &'static str {
        "add-header"
    }

    fn handle<'a>(
        &'a self,
        mut request: Request,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<HttpResponse>> {
        Box::pin(async move {
            request
                .headers_mut()
                .insert(self.name.clone(), self.value.clone());
            next.run(request).await
        })
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com".to_owned());

    let requests = Arc::new(AtomicU64::new(0));

    let client = Client::builder()
        // The chain runs outermost first, so timing wraps the header addition
        // and therefore measures it.
        .middleware(Timing {
            requests: Arc::clone(&requests),
        })
        .middleware(AddHeader {
            name: HeaderName::from_static("x-example"),
            value: HeaderValue::from_static("chromulate"),
        })
        .build()?;

    for _ in 0..2 {
        let response = client.get(&url).send().await?;
        let _ = response.bytes().await?;
    }

    println!("{} request(s) observed", requests.load(Ordering::Relaxed));
    Ok(())
}
