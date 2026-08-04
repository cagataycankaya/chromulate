//! A loopback **HTTPS** origin, so the protocol stack the crate exists for can
//! be measured.
//!
//! Every plaintext harness here deliberately excludes TLS to isolate
//! per-request cost, and that exclusion is also what leaves the crate's
//! distinguishing work — the handshake, ALPN, and HTTP/2 — unmeasured. Pointing
//! a benchmark at a public origin is not the answer either: a stranger's server
//! is not a fair or a polite load generator, and its latency swamps the client.
//!
//! This is the missing third option. It serves the same routes as
//! [`crate::server`] over rustls with ALPN advertising `h2` and `http/1.1`, on
//! a certificate generated in-process for `localhost`. The certificate is
//! returned alongside the address so a client can trust *exactly* it — no
//! disabled verification anywhere, which matters because a benchmark that turns
//! certificate checking off is no longer measuring the handshake a real client
//! performs.

#![forbid(unsafe_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_rustls::TlsAcceptor;

/// A running HTTPS origin.
#[derive(Debug)]
pub struct TlsOrigin {
    addr: SocketAddr,
    certificate: CertificateDer<'static>,
    accepted: Arc<AtomicU64>,
    _runtime: Runtime,
}

impl TlsOrigin {
    /// The address the origin is listening on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The self-signed certificate this origin presents, DER encoded.
    ///
    /// Hand this to the client under measurement as an extra trust root. A
    /// client that trusts this and nothing else verifies the chain exactly as
    /// it would against the public web, which is the property a benchmark with
    /// verification disabled would quietly lose.
    #[must_use]
    pub fn certificate_der(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    /// How many TCP connections have been accepted.
    #[must_use]
    pub fn accept_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.accepted)
    }

    /// `https://localhost:{port}{path}`.
    ///
    /// The hostname is `localhost` rather than `127.0.0.1` because that is the
    /// name on the certificate, and a client that verifies properly checks it.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.addr.port())
    }
}

/// Starts an HTTPS origin on its own runtime.
///
/// # Errors
///
/// Returns an I/O error when the runtime cannot be built, the listener cannot
/// bind, or the certificate cannot be generated.
pub fn start(worker_threads: usize) -> io::Result<TlsOrigin> {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|error| io::Error::other(format!("certificate generation failed: {error}")))?;
    let certificate = CertificateDer::from(issued.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(issued.signing_key.serialize_der())
        .map_err(|error| io::Error::other(format!("private key is not usable: {error}")))?;

    // reqwest's rustls build pulls in aws-lc-rs while this workspace links
    // ring, so two providers are present and rustls refuses to guess. The
    // server picks ring explicitly, matching what the client under measurement
    // uses; installing it as the process default is idempotent and harmless if
    // something else got there first.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .map_err(|error| io::Error::other(format!("server config rejected: {error}")))?;
    // Order matters: rustls picks the first protocol both sides offer, and a
    // client presenting a browser's ALPN list expects h2 to win.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name("bench-tls-origin")
        .enable_all()
        .build()?;

    let listener = runtime.block_on(async { TcpListener::bind("127.0.0.1:0").await })?;
    let addr = listener.local_addr()?;

    let accepted = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&accepted);

    runtime.spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            counter.fetch_add(1, Ordering::Relaxed);
            let _ = stream.set_nodelay(true);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Which HTTP version to speak is decided by ALPN, exactly as it
                // is against a real origin; serving h1 to a client that
                // negotiated h2 would fail the connection.
                let negotiated_h2 = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .is_some_and(|protocol| protocol == b"h2");
                let io = TokioIo::new(tls);
                if negotiated_h2 {
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service_fn(crate::server::route_public))
                        .await;
                } else {
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, service_fn(crate::server::route_public))
                        .await;
                }
            });
        }
    });

    Ok(TlsOrigin {
        addr,
        certificate,
        accepted,
        _runtime: runtime,
    })
}
