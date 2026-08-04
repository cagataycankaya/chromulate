//! One real HTTP/3 `GET`, to establish that the functional half works.
//!
//! Behind `network-tests`, because it reaches the public internet and the project's
//! default `cargo test` run is hermetic. It exists so that the assessment's negative
//! recommendation cannot be mistaken for "this does not work": it does work, and the
//! reason not to ship it is fidelity, not function.
//!
//! This is deliberately the shortest path that produces a response. There is no pool,
//! no `Alt-Svc` upgrade, no happy-eyeballs race against TCP, no connection migration —
//! all of which a browser does and all of which the assessment counts as outstanding.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use bytes::Buf;

use crate::spike::error::SpikeError;

/// What a spike request returned.
#[derive(Debug, Clone)]
pub struct H3Response {
    /// The response status.
    pub status: http::StatusCode,
    /// The response body, buffered — the spike has no streaming contract to keep.
    pub body: Vec<u8>,
    /// The ALPN protocol the QUIC handshake actually negotiated.
    pub negotiated_alpn: String,
    /// The address that answered.
    pub peer: SocketAddr,
}

/// Performs one HTTP/3 `GET` and buffers the response.
///
/// # Errors
///
/// [`SpikeError::Request`] for every failure mode, with the underlying message
/// attached. The spike does not classify failures the way `chromulate_core::Error`
/// does, because nothing depends on it doing so.
pub async fn get(url: &str) -> Result<H3Response, SpikeError> {
    let uri: http::Uri = url
        .parse()
        .map_err(|error| SpikeError::Request(format!("`{url}` is not a URI: {error}")))?;
    let host = uri
        .host()
        .ok_or_else(|| SpikeError::Request(format!("`{url}` has no host")))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(443);

    let peer = tokio::task::spawn_blocking({
        let host = host.clone();
        move || {
            (host.as_str(), port).to_socket_addrs().map(|mut addrs| {
                addrs
                    .find(SocketAddr::is_ipv4)
                    .or_else(|| (host.as_str(), port).to_socket_addrs().ok()?.next())
            })
        }
    })
    .await
    .map_err(|error| SpikeError::Request(error.to_string()))?
    .map_err(|error| SpikeError::Request(format!("cannot resolve `{host}`: {error}")))?
    .ok_or_else(|| SpikeError::Request(format!("`{host}` resolved to no addresses")))?;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| SpikeError::Request(error.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| SpikeError::Request(error.to_string()))?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_tls));

    let bind: SocketAddr = if peer.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let endpoint = quinn::Endpoint::client(bind)
        .map_err(|error| SpikeError::Request(format!("cannot bind an endpoint: {error}")))?;

    let connection = endpoint
        .connect_with(client_config, peer, &host)
        .map_err(|error| SpikeError::Request(error.to_string()))?
        .await
        .map_err(|error| SpikeError::Request(format!("QUIC handshake failed: {error}")))?;

    let negotiated_alpn = connection
        .handshake_data()
        .and_then(|data| {
            data.downcast::<quinn::crypto::rustls::HandshakeData>()
                .ok()
                .and_then(|data| data.protocol)
        })
        .map(|protocol| String::from_utf8_lossy(&protocol).into_owned())
        .unwrap_or_default();

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|error| SpikeError::Request(format!("HTTP/3 setup failed: {error}")))?;

    // The connection has to be polled for the request to make progress.
    let driving = tokio::spawn(async move { driver.wait_idle().await });

    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(())
        .map_err(|error| SpikeError::Request(error.to_string()))?;

    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|error| SpikeError::Request(error.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|error| SpikeError::Request(error.to_string()))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|error| SpikeError::Request(error.to_string()))?;

    let mut body = Vec::new();
    while let Some(chunk) = stream
        .recv_data()
        .await
        .map_err(|error| SpikeError::Request(error.to_string()))?
    {
        body.extend_from_slice(chunk.chunk());
    }

    drop(send_request);
    let _ = driving.await;
    endpoint.wait_idle().await;

    Ok(H3Response {
        status: response.status(),
        body,
        negotiated_alpn,
        peer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A live HTTP/3 request. `#[ignore]` as well as feature-gated, matching the
    /// project's convention for tests that reach real origins
    /// (`docs/fidelity.md` documents the `-- --ignored` invocation).
    #[tokio::test]
    #[ignore = "reaches the public internet"]
    async fn a_real_http3_get_returns_a_response() {
        let response = get("https://cloudflare-quic.com/")
            .await
            .expect("the origin speaks HTTP/3");
        assert_eq!(response.negotiated_alpn, "h3");
        assert!(response.status.is_success(), "status {}", response.status);
        assert!(!response.body.is_empty());
        println!(
            "HTTP/3 {} from {} over ALPN {}, {} body bytes",
            response.status,
            response.peer,
            response.negotiated_alpn,
            response.body.len()
        );
    }
}
