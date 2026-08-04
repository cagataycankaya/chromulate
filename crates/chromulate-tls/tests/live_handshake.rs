//! Handshakes against real servers.
//!
//! These are behind the `network-tests` feature and `#[ignore]`, so the default
//! `cargo test` run stays offline and hermetic. Run them with:
//!
//! ```text
//! cargo test -p chromulate-tls --features network-tests -- --ignored --nocapture
//! ```
//!
//! They are the only place several claims in the crate documentation can be
//! checked: that a full handshake against a public site succeeds and negotiates
//! `h2`, that the second connection to the same host resumes, and that
//! certificate verification actually rejects a bad certificate rather than
//! merely being configured to.

#![cfg(feature = "network-tests")]

use std::time::Duration;

use chromulate_core::Error;
use chromulate_profile::Profile;
use chromulate_tls::{Alpn, HandshakeInfo, TlsEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

async fn tcp(host: &str) -> TcpStream {
    timeout(CONNECT_TIMEOUT, TcpStream::connect((host, 443)))
        .await
        .expect("the TCP connection should not time out")
        .unwrap_or_else(|error| panic!("could not reach {host}:443: {error}"))
}

fn chrome() -> TlsEngine {
    TlsEngine::new(&Profile::chrome_stable()).expect("the Chrome engine must build")
}

#[tokio::test]
#[ignore = "opens a real connection to the public internet"]
async fn a_real_handshake_against_a_public_host_negotiates_http2() {
    let engine = chrome();
    let stream = engine
        .connect(tcp("www.google.com").await, "www.google.com")
        .await
        .expect("the handshake against www.google.com should succeed");

    let info = HandshakeInfo::of_stream(&stream);
    println!("www.google.com -> {info:?}");
    println!("target identity: {}", engine.target_identity());
    println!("fidelity: {}", engine.fidelity());

    assert_eq!(
        info.alpn,
        Some(Alpn::Http2),
        "the profile offers h2 first and Google speaks it"
    );
    assert!(info.is_http2());
    assert_eq!(
        info.version,
        Some(chromulate_fingerprint::TlsVersion::Tls13)
    );
    assert!(!info.resumed, "the first connection cannot resume anything");
}

#[tokio::test]
#[ignore = "opens two real connections to the public internet"]
async fn the_second_connection_to_a_host_resumes_the_session() {
    let engine = chrome();
    let host = "www.cloudflare.com";

    let first = engine
        .connect(tcp(host).await, host)
        .await
        .expect("the first handshake should succeed");
    let first_info = HandshakeInfo::of_stream(&first);
    assert!(!first_info.resumed);

    // A TLS 1.3 ticket arrives after the handshake, in the first application
    // data flight, so the connection has to be used before one is stored.
    let mut first = first;
    let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    first
        .write_all(request.as_bytes())
        .await
        .expect("writing a request should succeed");
    let mut sink = Vec::new();
    let _ = timeout(CONNECT_TIMEOUT, first.read_to_end(&mut sink)).await;

    let name = chromulate_tls::server_name(host).expect("the host is usable");
    assert!(
        engine.sessions().has_ticket(&name),
        "the server should have issued a session ticket"
    );

    let second = engine
        .connect(tcp(host).await, host)
        .await
        .expect("the second handshake should succeed");
    let second_info = HandshakeInfo::of_stream(&second);
    println!("first: {first_info:?}\nsecond: {second_info:?}");

    // Whether the handshake *resumes* is the server's decision, not this
    // client's, and asserting it makes the test fail for something outside the
    // repository. `www.cloudflare.com` is anycast: the second connection can
    // reach an edge that does not share ticket keys with the first, and then a
    // full handshake is the correct outcome. This test failed exactly that way
    // on a GitHub runner while passing three times in a row from a developer
    // machine.
    //
    // What this client controls is asserted above: a ticket was issued and
    // stored, so it is offered on the next connection to the same name. The
    // resumption itself is reported rather than required.
    if second_info.resumed {
        println!("the server resumed the session from the stored ticket");
    } else {
        println!(
            "the server declined to resume and performed a full handshake; \
             with an anycast origin this is a normal outcome, not a client fault"
        );
    }

    // A full handshake is still a *successful* one, and the identity it
    // presents must not change between connections — that would be a real
    // regression, and it is the part this test can hold the client to.
    assert_eq!(
        second_info.alpn, first_info.alpn,
        "the second connection negotiated a different protocol"
    );
    assert_eq!(
        second_info.version, first_info.version,
        "the second connection negotiated a different TLS version"
    );
}

#[tokio::test]
#[ignore = "opens a real connection to the public internet"]
async fn a_ticket_stored_for_one_host_is_not_offered_to_another() {
    let engine = chrome();

    let mut stream = engine
        .connect(tcp("www.cloudflare.com").await, "www.cloudflare.com")
        .await
        .expect("the first handshake should succeed");
    stream
        .write_all(b"HEAD / HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("writing a request should succeed");
    let mut sink = Vec::new();
    let _ = timeout(CONNECT_TIMEOUT, stream.read_to_end(&mut sink)).await;

    let stored = chromulate_tls::server_name("www.cloudflare.com").expect("usable host");
    let other = chromulate_tls::server_name("www.google.com").expect("usable host");
    assert!(engine.sessions().has_ticket(&stored));
    assert!(
        !engine.sessions().has_ticket(&other),
        "material from one host must never be offered to another"
    );

    let elsewhere = engine
        .connect(tcp("www.google.com").await, "www.google.com")
        .await
        .expect("the handshake against the other host should succeed");
    assert!(
        !HandshakeInfo::of_stream(&elsewhere).resumed,
        "a different host must get a full handshake"
    );
}

#[tokio::test]
#[ignore = "opens a real connection to the public internet"]
async fn a_certificate_that_does_not_verify_is_rejected_by_the_default_engine() {
    let engine = chrome();
    let host = "self-signed.badssl.com";

    let error = engine
        .connect(tcp(host).await, host)
        .await
        .expect_err("a self-signed certificate must not be accepted");

    println!("{host} -> {error}");
    assert!(
        matches!(error, Error::Tls { .. }),
        "the failure should be reported as a TLS error; got {error:?}"
    );
    assert!(error.is_tls());
}

#[tokio::test]
#[ignore = "opens a real connection to the public internet"]
#[cfg(feature = "dangerous-configuration")]
async fn the_dangerous_engine_accepts_the_certificate_the_default_engine_rejects() {
    let host = "self-signed.badssl.com";
    let engine = TlsEngine::builder(&Profile::chrome_stable())
        .danger_accept_invalid_certs(true)
        .build()
        .expect("the dangerous engine must build");

    let stream = engine
        .connect(tcp(host).await, host)
        .await
        .expect("with verification off, a self-signed certificate is accepted");
    println!("{host} -> {:?}", HandshakeInfo::of_stream(&stream));
}

#[tokio::test]
#[ignore = "opens a real connection to the public internet"]
#[cfg(feature = "platform-roots")]
async fn the_platform_trust_store_verifies_a_public_host_too() {
    let engine = TlsEngine::builder(&Profile::chrome_stable())
        .with_root_source(chromulate_tls::RootSource::Platform)
        .build()
        .expect("the platform trust store must load");
    println!("trust: {}", engine.trust_policy());

    let stream = engine
        .connect(tcp("www.google.com").await, "www.google.com")
        .await
        .expect("the platform roots should verify Google");
    assert_eq!(HandshakeInfo::of_stream(&stream).alpn, Some(Alpn::Http2));
}
