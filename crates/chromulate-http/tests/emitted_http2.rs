//! What this client actually puts on an HTTP/2 connection, read off the wire.
//!
//! The profile states an HTTP/2 shape — SETTINGS in a given order, a connection
//! window update, and a pseudo-header order — and the engine hands the first
//! two to `hyper`. Whether they arrive in that shape is a different question
//! from whether they were configured, and until this test existed only the
//! configuration was checked.
//!
//! So this stands up a TLS listener that negotiates `h2` by ALPN, lets the
//! client connect and send one request, and then parses the raw frames: the
//! connection preface, the SETTINGS frame in order, the WINDOW_UPDATE, and the
//! HEADERS frame's flags and pseudo-header order. Nothing is asserted from
//! reading `h2`'s source.
//!
//! **The pseudo-header order is decoded without a full HPACK implementation**,
//! and deliberately so. Pseudo-headers are sent as static-table references —
//! one byte each for `:method GET`, `:scheme https` and `:path /`, and an
//! indexed name with a literal value for `:authority` — so identifying them
//! needs the static table's first eight entries and the ability to skip a
//! literal by its length prefix. Decoding the Huffman-coded ordinary headers
//! would need the 257-entry HPACK Huffman table for no gain here: their order
//! is already golden-tested in `chromulate-header` and checked on the wire by
//! the live tests.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use chromulate_core::Body;
use chromulate_http::{Engine, EngineConfig};
use chromulate_profile::Profile;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The 24-byte client connection preface (RFC 9113 §3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameHeader {
    length: usize,
    kind: u8,
    flags: u8,
    stream: u32,
}

/// Everything this test reads off the connection.
#[derive(Debug, Default)]
struct Observed {
    /// `(identifier, value)` in the order the SETTINGS frame carried them.
    settings: Vec<(u16, u32)>,
    /// The connection-level WINDOW_UPDATE increment, if one was sent.
    window_update: Option<u32>,
    /// Whether the HEADERS frame set the PRIORITY flag.
    headers_priority_flag: bool,
    /// How many standalone PRIORITY frames arrived before the first HEADERS.
    ///
    /// This is the Akamai fingerprint's third field, which is a count of
    /// PRIORITY *frames* and not of the HEADERS priority flag above. The two
    /// are separate observables and the capture shows Chrome using one without
    /// the other, so they are recorded separately here too.
    priority_frames: usize,
    /// Pseudo-header names in the order the HEADERS block listed them.
    pseudo_order: Vec<&'static str>,
}

/// A TLS origin that records the client's opening frames and then stops.
///
/// It never answers the request. The client will see the connection close and
/// report an error, which is fine and is why the test ignores the request's
/// result: everything under examination is sent before a response would be.
type Recording = (
    SocketAddr,
    CertificateDer<'static>,
    tokio::task::JoinHandle<Observed>,
);

async fn record_opening_frames() -> io::Result<Recording> {
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

    let handle = tokio::spawn(async move {
        let mut observed = Observed::default();
        let Ok((stream, _)) = listener.accept().await else {
            return observed;
        };
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return observed;
        };

        // The server must send its own SETTINGS before the client will send
        // HEADERS, because a client waits for the server's preface.
        let empty_settings = [0, 0, 0, 4, 0, 0, 0, 0, 0];
        if tls.write_all(&empty_settings).await.is_err() {
            return observed;
        }

        let mut preface = [0u8; PREFACE.len()];
        if tls.read_exact(&mut preface).await.is_err() || preface != PREFACE {
            return observed;
        }

        // Read frames until the request's HEADERS arrives, or the client gives
        // up. Everything under test is in the first few frames.
        for _ in 0..16 {
            let Some(header) = read_frame_header(&mut tls).await else {
                break;
            };
            let mut payload = vec![0u8; header.length];
            if tls.read_exact(&mut payload).await.is_err() {
                break;
            }
            match header.kind {
                0x4 if header.flags & 0x1 == 0 => {
                    for entry in payload.chunks_exact(6) {
                        let id = u16::from_be_bytes([entry[0], entry[1]]);
                        let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
                        observed.settings.push((id, value));
                    }
                }
                0x8 if header.stream == 0 && payload.len() == 4 => {
                    let increment =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    observed.window_update = Some(increment & 0x7fff_ffff);
                }
                0x2 => {
                    observed.priority_frames += 1;
                }
                0x1 => {
                    observed.headers_priority_flag = header.flags & 0x20 != 0;
                    // A PRIORITY flag prefixes the block with five bytes.
                    let block = if observed.headers_priority_flag {
                        &payload[5.min(payload.len())..]
                    } else {
                        &payload[..]
                    };
                    observed.pseudo_order = pseudo_header_order(block);
                    return observed;
                }
                _ => {}
            }
        }
        observed
    });

    Ok((addr, certificate, handle))
}

async fn read_frame_header<S>(stream: &mut S) -> Option<FrameHeader>
where
    S: AsyncReadExt + Unpin,
{
    let mut header = [0u8; 9];
    stream.read_exact(&mut header).await.ok()?;
    Some(FrameHeader {
        length: u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize,
        kind: header[3],
        flags: header[4],
        stream: u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff,
    })
}

/// The pseudo-header names in a HPACK block, in order.
///
/// Walks the block's structure without decoding it: every field is either a
/// static-table reference, whose index names it, or a literal whose name and
/// value are length-prefixed and can be stepped over. Fields whose name is a
/// literal are ordinary headers — pseudo-headers are always indexed — so they
/// are skipped rather than decoded.
fn pseudo_header_order(block: &[u8]) -> Vec<&'static str> {
    /// The pseudo-header entries of the HPACK static table (RFC 7541 appendix A).
    fn pseudo_of(index: usize) -> Option<&'static str> {
        match index {
            1 => Some(":authority"),
            2 | 3 => Some(":method"),
            4 | 5 => Some(":path"),
            6 | 7 => Some(":scheme"),
            8..=14 => Some(":status"),
            _ => None,
        }
    }

    let mut found = Vec::new();
    let mut at = 0usize;

    // Reads an HPACK integer with `prefix` significant bits in the first byte.
    fn integer(bytes: &[u8], at: &mut usize, prefix: u8) -> Option<usize> {
        let mask = (1u16 << prefix) - 1;
        let first = *bytes.get(*at)? as u16 & mask;
        *at += 1;
        if first < mask {
            return Some(first as usize);
        }
        let mut value = mask as usize;
        let mut shift = 0;
        loop {
            let byte = *bytes.get(*at)?;
            *at += 1;
            value += ((byte & 0x7f) as usize) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
        }
    }

    // Steps over a length-prefixed string without decoding it; the top bit of
    // the length byte is the Huffman flag, which does not change the length.
    fn skip_string(bytes: &[u8], at: &mut usize) -> Option<()> {
        let length = integer(bytes, at, 7)?;
        *at = at.checked_add(length)?;
        (*at <= bytes.len()).then_some(())
    }

    while at < block.len() {
        let byte = block[at];
        if byte & 0x80 != 0 {
            // Indexed header field: the index names it outright.
            let Some(index) = integer(block, &mut at, 7) else {
                break;
            };
            if let Some(name) = pseudo_of(index) {
                found.push(name);
            }
        } else if byte & 0xc0 == 0x40 || byte & 0xf0 == 0x00 || byte & 0xf0 == 0x10 {
            // Literal, with or without indexing. A zero index means the name is
            // a literal too and has to be stepped over.
            let prefix = if byte & 0xc0 == 0x40 { 6 } else { 4 };
            let Some(index) = integer(block, &mut at, prefix) else {
                break;
            };
            if index == 0 {
                if skip_string(block, &mut at).is_none() {
                    break;
                }
            } else if let Some(name) = pseudo_of(index) {
                found.push(name);
            }
            if skip_string(block, &mut at).is_none() {
                break;
            }
        } else if byte & 0xe0 == 0x20 {
            // Dynamic table size update: an integer and nothing else.
            if integer(block, &mut at, 5).is_none() {
                break;
            }
        } else {
            break;
        }
    }

    found
}

/// An engine that trusts the recording origin's certificate and nothing else.
///
/// Trusting the one certificate rather than disabling verification keeps the
/// handshake a real one: the shape under examination is what a verifying client
/// emits, which is the only shape worth recording.
fn engine_trusting(certificate: CertificateDer<'static>) -> Engine {
    let profile = Arc::new(Profile::chrome_stable());
    let tls = chromulate_tls::TlsEngine::builder(&profile)
        .add_root_certificate(certificate)
        .build()
        .expect("the TLS engine must build");
    Engine::builder(EngineConfig::new(profile))
        .tls(tls)
        .build()
        .expect("the engine must build")
}

#[tokio::test]
async fn the_emitted_http2_preface_matches_the_profile() {
    let (addr, certificate, recorder) = record_opening_frames()
        .await
        .expect("the recording origin must start");

    let engine = engine_trusting(certificate);
    let url = format!("https://localhost:{}/", addr.port());
    let request = http::Request::builder()
        .uri(&url)
        .body(Body::empty())
        .expect("the request must build");

    // The origin never answers, so this errors. Everything under test was sent
    // before a response would have been.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), engine.send(request)).await;

    let observed = tokio::time::timeout(std::time::Duration::from_secs(10), recorder)
        .await
        .expect("the recorder must finish")
        .expect("the recorder must not panic");

    let profile = Profile::chrome_stable();

    // SETTINGS, in order, exactly as the capture recorded them.
    let expected: Vec<(u16, u32)> = profile
        .http2
        .settings
        .iter()
        .map(|setting| (setting.id.get(), setting.value))
        .collect();
    assert_eq!(
        observed.settings, expected,
        "the SETTINGS frame on the wire must carry the profile's settings in the profile's order"
    );

    assert_eq!(
        observed.window_update,
        Some(profile.http2.connection_window_update),
        "the connection window update must match the capture"
    );

    // The Akamai fingerprint's third field. Until this assertion existed the
    // frame loop ignored frame type 0x2 entirely, so "Chromulate sends no
    // PRIORITY frames" was a claim no hermetic test could have falsified —
    // three of the four fields were checked and the fourth was assumed.
    //
    // Be clear about what this does and does not guard. Against the Chrome
    // profile both sides are zero, so deleting the `0x2` arm of the frame loop
    // would leave this green: it does not prove the counter counts. What it
    // does catch is the case that will actually arise — a profile whose
    // capture *does* record PRIORITY frames, such as Firefox's
    // `3:0:0:201,...`, against a client that cannot send any, because h2's
    // write path for them is `unimplemented!()`. Today that divergence would
    // be silent. Proving the counter itself would mean factoring the frame
    // walk out of this async recorder into something a synthetic byte stream
    // can be fed to, which is worth doing when a second profile lands.
    assert_eq!(
        observed.priority_frames,
        profile.http2.priority_frames.len(),
        "the profile records {} PRIORITY frame(s) and the wire carried {}",
        profile.http2.priority_frames.len(),
        observed.priority_frames
    );

    // The two known divergences, asserted rather than described, so that a
    // future `h2` release closing either one fails this test and the fidelity
    // documentation gets corrected instead of quietly going stale.
    assert!(
        !observed.headers_priority_flag,
        "h2 has started sending HEADERS with the PRIORITY flag; docs/fidelity.md says it does \
         not, and the Akamai fingerprint's priority field is affected"
    );
    assert_eq!(
        observed.pseudo_order,
        vec![":method", ":scheme", ":authority", ":path"],
        "the emitted pseudo-header order is fixed by h2's frame::headers::Pseudo. Chrome sends \
         m,a,s,p; if this assertion fails h2 has changed it and docs/fidelity.md must be updated"
    );
    assert_ne!(
        observed.pseudo_order,
        profile
            .http2
            .pseudo_header_order
            .as_slice()
            .iter()
            .map(|header| header.as_str())
            .collect::<Vec<_>>(),
        "if the emitted order ever matches the profile's, the recorded divergence is stale"
    );
}
