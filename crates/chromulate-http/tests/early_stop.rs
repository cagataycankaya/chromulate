//! What abandoning a response body costs, measured against real origins.
//!
//! [`chromulate_http::Stop`] reads the front of a body and drops the rest. What
//! that costs depends entirely on the protocol, and the difference is not a
//! detail: on one measured page — trendyol.com, 453 KB — reading 91% fewer
//! bytes was still 16 ms *slower* end to end, because the next request paid a
//! fresh handshake.
//!
//! So the two halves are held here separately, against origins that can tell
//! the difference:
//!
//! - HTTP/1.1 runs against the plaintext recording server, which counts
//!   `accept` calls. A connection that does not come back is the correct
//!   behaviour and the test that matters most: a socket with unread bytes on it
//!   handed to the next request is a correctness bug, not an optimisation.
//! - HTTP/2 runs against a real `h2` origin over TLS, because ALPN is the only
//!   way this crate ever produces an HTTP/2 connection. The origin holds its
//!   `SendStream` open and polls it for a reset, so the `RST_STREAM` the client
//!   sends is *observed at the peer* rather than inferred from the client
//!   carrying on.

// Not built under `--cfg chromulate_mock_backend`: this test needs a real TLS origin and a
// `TlsEngine` that trusts its certificate. The mock backend performs no
// handshake, so there is nothing here for it to measure.
#![cfg(not(chromulate_mock_backend))]

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use chromulate_core::{Body, Request, Response};
use chromulate_dns::StaticResolver;
use chromulate_http::{Engine, EngineConfig, Stop, StopReason};
use chromulate_profile::Profile;
use common::{Reply, TestServer};
use http::Method;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// A marker deep enough into the body that finding it proves the scan ran, and
/// far enough from the end that stopping there abandons most of the response.
const MARKER: &str = "application/ld+json";

fn get(url: &str) -> Request {
    http::Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Body::empty())
        .expect("a valid request")
}

/// A response body with the marker near the front and bulk after it.
fn page_with_marker() -> Vec<u8> {
    let mut page = Vec::with_capacity(256 * 1024);
    page.extend_from_slice(b"<html><head>");
    page.extend_from_slice(MARKER.as_bytes());
    page.extend_from_slice(br#"{"price":42}"#);
    page.resize(256 * 1024, b'x');
    page
}

// ------------------------------------------------------------------ HTTP/1.1

fn h1_engine(server: &TestServer, host: &str) -> Engine {
    let resolver = StaticResolver::empty().with_host(host.to_owned(), vec![server.addr()]);
    let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
    config.connect_timeout = Some(Duration::from_secs(5));
    Engine::builder(config)
        .resolver(Arc::new(resolver))
        .build()
        .expect("the engine must build")
}

/// The behaviour this change must not weaken.
///
/// An HTTP/1.1 socket is one byte stream. Once a body has been abandoned there
/// is no way to know how many unread bytes are still arriving, so the
/// connection cannot be reused — and a pool that took it back anyway would
/// serve the next request the tail of this response.
#[tokio::test]
async fn an_abandoned_http1_body_does_not_return_its_connection_to_the_pool() {
    let server = TestServer::always(Reply::ok().with_body(page_with_marker())).await;
    let engine = h1_engine(&server, "example.test");
    let url = server.url_for("example.test", "/product");

    let response = engine
        .send(get(&url))
        .await
        .expect("the request must succeed");
    assert_eq!(response.version(), http::Version::HTTP_11);
    assert_eq!(
        engine.pool().len(),
        0,
        "an HTTP/1.1 connection is on loan for the whole exchange"
    );

    let prefix = Stop::marker(MARKER)
        .plus(12)
        .read(response.into_body())
        .await
        .expect("the prefix must read");

    assert_eq!(prefix.reason(), StopReason::Matched);
    assert!(!prefix.is_complete(), "most of the body was abandoned");
    assert!(
        prefix.bytes().len() < 1024,
        "the read must have stopped near the front, not at the end: {} bytes",
        prefix.bytes().len()
    );

    // The connection is dropped along with the body, and hyper's connection
    // task needs a poll to notice.
    settle().await;
    assert_eq!(
        engine.pool().len(),
        0,
        "a half-read HTTP/1.1 socket must never go back to the pool"
    );

    // And the proof that costs something: the next request has to dial again.
    let second = engine
        .send(get(&url))
        .await
        .expect("the second request must succeed");
    let _ = second.into_body().collect(1024 * 1024).await;
    assert_eq!(
        server.accepts(),
        2,
        "abandoning an HTTP/1.1 body costs the connection, and the next request pays for it"
    );
}

/// Frames `payload` as an HTTP/1.1 chunked body, in chunks small enough that
/// abandoning lands inside one rather than between two.
fn chunked_framing(payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(payload.len() + 1024);
    for piece in payload.chunks(8 * 1024) {
        framed.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        framed.extend_from_slice(piece);
        framed.extend_from_slice(b"\r\n");
    }
    framed.extend_from_slice(b"0\r\n\r\n");
    framed
}

/// The correctness claim, at every place a read can be abandoned and on both
/// HTTP/1.1 framings.
///
/// What each assertion is worth was checked by mutation: releasing the slot
/// from a `Drop` on `ReleasingStream`, so an abandoned body hands its socket
/// back, turns the pool assertion below red at byte 0 and the `accepts`
/// assertion red one byte short of the end.
///
/// The body-equality assertion did **not** go red under that mutation, and the
/// reason is worth recording rather than leaving as a mystery for whoever
/// mutates this next: `Pool::checkout` asks `is_usable()`, which is hyper's own
/// view of a connection whose response body was dropped, so a wrongly pooled
/// socket is refused at checkout instead of serving the next request a tail.
/// It stays as the property that must hold — the pool is this crate's guard and
/// hyper's is not a contract — but no mutation here has shown it failing.
#[tokio::test]
async fn an_abandoned_http1_body_never_leaves_a_socket_the_next_request_can_use() {
    let page = page_with_marker();
    let marker_end = MARKER.len() + "<html><head>".len();

    let framings: [(&str, Reply); 2] = [
        ("content-length", Reply::ok().with_body(page.clone())),
        (
            "chunked",
            Reply::ok()
                .with_header("transfer-encoding", "chunked")
                .with_body(chunked_framing(&page)),
        ),
    ];

    for (framing, reply) in framings {
        // Byte 0, one byte in, mid-marker, mid-chunk, one short of the end, and
        // exactly the last byte.
        for stop_at in [
            0,
            1,
            marker_end as u64,
            9 * 1024,
            page.len() as u64 - 1,
            page.len() as u64,
        ] {
            let server = TestServer::always(reply.clone()).await;
            let engine = h1_engine(&server, "example.test");
            let url = server.url_for("example.test", "/product");

            let response = engine
                .send(get(&url))
                .await
                .expect("the request must succeed");
            let prefix = Stop::after(stop_at)
                .read(response.into_body())
                .await
                .expect("the prefix must read");

            assert_eq!(
                prefix.bytes().len() as u64,
                stop_at,
                "{framing}: a budget of {stop_at} must return exactly that many bytes"
            );
            assert!(
                !prefix.is_complete(),
                "{framing}: stopping at {stop_at} left the stream unfinished, \
                 however few bytes were outstanding"
            );

            settle().await;
            assert_eq!(
                engine.pool().len(),
                0,
                "{framing}: a socket abandoned at byte {stop_at} must not be pooled"
            );

            let second = engine
                .send(get(&url))
                .await
                .expect("the second request must succeed");
            let body = second
                .into_body()
                .collect(1024 * 1024)
                .await
                .expect("the second body must arrive whole");

            assert_eq!(
                body.len(),
                page.len(),
                "{framing}: the second response after abandoning at {stop_at} \
                 was the wrong length"
            );
            assert_eq!(
                &body[..],
                &page[..],
                "{framing}: the second response after abandoning at {stop_at} \
                 was not the page — a half-read socket was reused"
            );
            assert_eq!(
                server.accepts(),
                2,
                "{framing}: abandoning at {stop_at} costs the connection"
            );
        }
    }
}

/// The other half: a body read to its end on a chunked response returns its
/// connection, so the discard above is a consequence of abandoning rather than
/// of the framing.
#[tokio::test]
async fn a_chunked_http1_body_read_to_its_end_still_returns_its_connection() {
    let page = page_with_marker();
    let server = TestServer::always(
        Reply::ok()
            .with_header("transfer-encoding", "chunked")
            .with_body(chunked_framing(&page)),
    )
    .await;
    let engine = h1_engine(&server, "example.test");
    let url = server.url_for("example.test", "/product");

    let response = engine
        .send(get(&url))
        .await
        .expect("the request must succeed");
    let prefix = Stop::marker("not-on-this-page")
        .read(response.into_body())
        .await
        .expect("the prefix must read");

    assert_eq!(prefix.reason(), StopReason::EndOfBody);
    assert!(prefix.is_complete());
    assert_eq!(prefix.bytes().len(), page.len());
    assert_eq!(engine.pool().len(), 1);

    let second = engine
        .send(get(&url))
        .await
        .expect("the second request must succeed");
    let body = second
        .into_body()
        .collect(1024 * 1024)
        .await
        .expect("the second body must arrive whole");
    assert_eq!(&body[..], &page[..]);
    assert_eq!(
        server.accepts(),
        1,
        "the second request must have reused it"
    );
}

#[tokio::test]
async fn an_http1_body_read_to_its_end_still_returns_its_connection() {
    let server = TestServer::always(Reply::ok().with_body(page_with_marker())).await;
    let engine = h1_engine(&server, "example.test");
    let url = server.url_for("example.test", "/product");

    let response = engine
        .send(get(&url))
        .await
        .expect("the request must succeed");

    // A marker that is not on the page, so the read runs to the end.
    let prefix = Stop::marker("not-on-this-page")
        .read(response.into_body())
        .await
        .expect("the prefix must read");

    assert_eq!(prefix.reason(), StopReason::EndOfBody);
    assert!(prefix.is_complete());
    assert_eq!(prefix.bytes().len(), 256 * 1024);
    assert_eq!(
        engine.pool().len(),
        1,
        "a body read to its end leaves a clean socket, which belongs in the pool"
    );

    let second = engine
        .send(get(&url))
        .await
        .expect("the second request must succeed");
    let _ = second.into_body().collect(1024 * 1024).await;
    assert_eq!(
        server.accepts(),
        1,
        "the second request must have reused it"
    );
}

/// The condition is a content condition, so it has to see content. A body that
/// arrives gzipped does not contain the marker at all on the wire.
#[tokio::test]
async fn the_condition_sees_decoded_bytes_and_not_wire_bytes() {
    use std::io::Write as _;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&page_with_marker())
        .expect("writing to an in-memory encoder cannot fail");
    let compressed = encoder.finish().expect("the encoder must finish");
    assert!(
        !contains(&compressed, MARKER.as_bytes()),
        "the fixture is only meaningful if the marker is absent from the wire bytes"
    );

    let server = TestServer::always(
        Reply::ok()
            .with_header("content-encoding", "gzip")
            .with_body(compressed),
    )
    .await;
    let engine = h1_engine(&server, "example.test");

    let response = engine
        .send(get(&server.url_for("example.test", "/product")))
        .await
        .expect("the request must succeed");

    let prefix = Stop::marker(MARKER)
        .plus(12)
        .read(response.into_body())
        .await
        .expect("the prefix must read");

    assert_eq!(prefix.reason(), StopReason::Matched);
    assert_eq!(
        prefix.bytes(),
        &b"<html><head>application/ld+json{\"price\":42}"[..]
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// -------------------------------------------------------------------- HTTP/2

/// An `h2` origin over TLS that reports the resets its peer sent.
struct H2Origin {
    addr: SocketAddr,
    certificate: CertificateDer<'static>,
    accepts: Arc<AtomicUsize>,
    resets: Arc<Mutex<Vec<(String, u32)>>>,
}

impl H2Origin {
    /// How many TCP connections were accepted. One means everything ran over a
    /// single multiplexed connection.
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// `(path, RST_STREAM error code)` for every stream the client reset.
    fn resets(&self) -> Vec<(String, u32)> {
        self.resets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Starts the origin.
///
/// `/streamed` sends the head and one chunk carrying the marker, then holds the
/// stream open and waits to be reset. `/whole` sends its body and ends the
/// stream at once. Nothing about either answer is buffered by a framework: the
/// point is to hold a `SendStream` and ask it whether the client cancelled.
async fn h2_origin() -> io::Result<H2Origin> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|error| io::Error::other(format!("certificate generation failed: {error}")))?;
    let certificate = CertificateDer::from(issued.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(issued.signing_key.serialize_der())
        .map_err(|error| io::Error::other(format!("key unusable: {error}")))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .map_err(|error| io::Error::other(format!("server config rejected: {error}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let accepts = Arc::new(AtomicUsize::new(0));
    let resets = Arc::new(Mutex::new(Vec::new()));

    {
        let accepts = Arc::clone(&accepts);
        let resets = Arc::clone(&resets);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                accepts.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let resets = Arc::clone(&resets);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Ok(mut connection) = h2::server::handshake(tls).await else {
                        return;
                    };
                    while let Some(Ok((request, respond))) = connection.accept().await {
                        let resets = Arc::clone(&resets);
                        tokio::spawn(async move {
                            serve_h2(request, respond, &resets).await;
                        });
                    }
                });
            }
        });
    }

    Ok(H2Origin {
        addr,
        certificate,
        accepts,
        resets,
    })
}

async fn serve_h2(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    resets: &Mutex<Vec<(String, u32)>>,
) {
    let path = request.uri().path().to_owned();
    let page = page_with_marker();
    let head = http::Response::builder()
        .status(200)
        .body(())
        .expect("a valid response head");

    if path == "/whole" {
        if let Ok(mut stream) = respond.send_response(head, false) {
            let _ = stream.send_data(Bytes::from(page), true);
        }
        return;
    }

    let Ok(mut stream) = respond.send_response(head, false) else {
        return;
    };
    // Enough to carry the marker and no more, so the client has something to
    // find and a great deal left to abandon.
    if stream
        .send_data(Bytes::from(page[..4096].to_vec()), false)
        .is_err()
    {
        return;
    }

    // The observation. If the client abandons its body this yields the reason
    // it sent; if it reads on, the timeout expires and the rest is delivered.
    let reset = tokio::time::timeout(
        Duration::from_secs(5),
        std::future::poll_fn(|cx| stream.poll_reset(cx)),
    )
    .await;

    match reset {
        Ok(Ok(reason)) => resets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((path, u32::from(reason))),
        _ => {
            let _ = stream.send_data(Bytes::from(page[4096..].to_vec()), true);
        }
    }
}

/// An engine that trusts the origin's certificate and nothing else, so the
/// handshake stays a real verifying one.
fn h2_engine(origin: &H2Origin) -> Engine {
    let profile = Arc::new(Profile::chrome_stable());
    let tls = chromulate_tls::TlsEngine::builder(&profile)
        .add_root_certificate(origin.certificate.clone())
        .build()
        .expect("the TLS engine must build");
    let resolver = StaticResolver::empty().with_host("localhost".to_owned(), vec![origin.addr]);
    let mut config = EngineConfig::new(profile);
    config.connect_timeout = Some(Duration::from_secs(5));
    Engine::builder(config)
        .tls(tls)
        .resolver(Arc::new(resolver))
        .build()
        .expect("the engine must build")
}

/// `RST_STREAM` with `CANCEL` (RFC 9113 §7).
const CANCEL: u32 = 0x8;

/// The asymmetry this whole feature turns on, observed rather than assumed.
///
/// Dropping the body drops hyper's `Incoming`, which owns h2's `RecvStream`.
/// When its last reference goes, h2 schedules an implicit reset for that stream
/// alone — and the origin below sees exactly that, then answers a second
/// request over the same TCP connection.
#[tokio::test]
async fn an_abandoned_http2_body_leaves_its_connection_pooled_and_reusable() {
    let origin = h2_origin().await.expect("the h2 origin must start");
    let engine = h2_engine(&origin);
    let base = format!("https://localhost:{}", origin.addr.port());

    let response = engine
        .send(get(&format!("{base}/streamed")))
        .await
        .expect("the request must succeed");
    assert_eq!(
        response.version(),
        http::Version::HTTP_2,
        "this test is only about HTTP/2 and ALPN must have chosen it"
    );
    assert_eq!(
        engine.pool().len(),
        1,
        "a multiplexed connection belongs to the pool from the moment it is opened"
    );

    let prefix = Stop::marker(MARKER)
        .plus(12)
        .read(response.into_body())
        .await
        .expect("the prefix must read");

    assert_eq!(prefix.reason(), StopReason::Matched);
    assert!(!prefix.is_complete(), "the rest of the body was abandoned");

    // The RST_STREAM is written by the connection task, so it needs a turn.
    settle().await;

    assert_eq!(
        origin.resets(),
        vec![("/streamed".to_owned(), CANCEL)],
        "dropping an HTTP/2 body must reset that stream, and nothing else"
    );
    assert_eq!(
        engine.pool().len(),
        1,
        "resetting one stream must not cost the connection"
    );

    // Pooled is a claim about a map. Reusable is a claim about the network.
    let second = engine
        .send(get(&format!("{base}/whole")))
        .await
        .expect("the second request must succeed over the same connection");
    let body = second
        .into_body()
        .collect(1024 * 1024)
        .await
        .expect("the second body must arrive whole");

    assert_eq!(body.len(), 256 * 1024);
    assert_eq!(
        origin.accepts(),
        1,
        "the second request must have reused the connection the first one cancelled a stream on"
    );
}

#[tokio::test]
async fn an_http2_body_read_to_its_end_keeps_its_connection_too() {
    let origin = h2_origin().await.expect("the h2 origin must start");
    let engine = h2_engine(&origin);
    let base = format!("https://localhost:{}", origin.addr.port());

    let response = engine
        .send(get(&format!("{base}/whole")))
        .await
        .expect("the request must succeed");
    assert_eq!(response.version(), http::Version::HTTP_2);

    let prefix = Stop::marker("not-on-this-page")
        .read(response.into_body())
        .await
        .expect("the prefix must read");

    assert_eq!(prefix.reason(), StopReason::EndOfBody);
    assert!(prefix.is_complete());
    assert_eq!(prefix.bytes().len(), 256 * 1024);

    settle().await;
    assert!(
        origin.resets().is_empty(),
        "a body read to its end has nothing to cancel"
    );
    assert_eq!(engine.pool().len(), 1);

    let second: Response = engine
        .send(get(&format!("{base}/whole")))
        .await
        .expect("the second request must succeed");
    let _ = second.into_body().collect(1024 * 1024).await;
    assert_eq!(origin.accepts(), 1);
}

/// Lets the connection tasks run the writes and closes that a `drop` only
/// scheduled. Sleeping rather than yielding because the frame has to cross a
/// loopback socket and be parsed by the origin's own task.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}
