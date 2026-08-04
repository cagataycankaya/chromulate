//! A recorder that captures what `quinn` hands to TLS, through public API only.
//!
//! `quinn::ClientConfig::new` takes an `Arc<dyn quinn::crypto::ClientConfig>`, and that
//! trait's one method receives the connection's `TransportParameters` by reference:
//!
//! ```text
//! fn start_session(self: Arc<Self>, version: u32, server_name: &str,
//!                  params: &TransportParameters) -> Result<Box<dyn Session>, ConnectError>
//! ```
//!
//! `TransportParameters::write` is public even though every field of the struct is
//! `pub(crate)`. That asymmetry is the whole story of this module: a downstream crate
//! can *observe* what `quinn` will send and cannot *change* it. Wrapping the returned
//! `Session` gives the same access to the ClientHello, because `write_handshake` hands
//! the caller the plaintext CRYPTO stream.
//!
//! Everything here is recorded synchronously during `Endpoint::connect`, before a
//! packet is sent: `quinn_proto::Connection::new` calls `write_crypto()` for the client
//! side while it is still being constructed
//! (`quinn-proto-0.11.16/src/connection/mod.rs:362-366`). The observation therefore
//! needs no server, no network and no timing.
//!
//! The recorder uses `Arc<Mutex<_>>`, which this project avoids on hot paths. This is
//! not one: it is touched twice per connection, in a spike that never runs in
//! production.

use std::any::Any;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use quinn_proto::crypto::{
    ClientConfig as CryptoClientConfig, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys,
    PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError};

use crate::spike::client_hello::ObservedClientHello;
use crate::spike::error::SpikeError;
use crate::spike::transport_params::{TransportParameter, decode_transport_parameters};

/// What one handshake attempt put on the wire.
#[derive(Debug, Clone, Default)]
pub struct RecordedHandshake {
    /// The encoded `quic_transport_parameters` extension body, in `quinn`'s order.
    pub transport_parameters: Vec<u8>,
    /// The first plaintext handshake flight, which is the ClientHello.
    pub client_hello: Vec<u8>,
    /// The server name the session was started for.
    pub server_name: String,
    /// The QUIC version `quinn` chose.
    pub version: u32,
}

/// A handle onto what a probed `quinn` client emitted.
#[derive(Debug, Clone, Default)]
pub struct HandshakeRecorder {
    state: Arc<Mutex<RecordedHandshake>>,
}

impl HandshakeRecorder {
    /// A recorder that has seen nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of what has been recorded.
    ///
    /// # Panics
    ///
    /// If a previous observation panicked while holding the lock.
    #[must_use]
    pub fn snapshot(&self) -> RecordedHandshake {
        self.state
            .lock()
            .expect("recorder lock is never held across a panic in the spike")
            .clone()
    }

    /// Wraps a crypto configuration so that starting a session is observed.
    #[must_use]
    pub fn wrap(&self, inner: Arc<dyn CryptoClientConfig>) -> Arc<dyn CryptoClientConfig> {
        Arc::new(ProbeClientConfig {
            inner,
            recorder: self.clone(),
        })
    }
}

/// One handshake attempt, decoded into comparable form.
#[derive(Debug, Clone)]
pub struct Observation {
    /// The ClientHello this stack emitted.
    pub client_hello: ObservedClientHello,
    /// The transport parameters, in the order `quinn` serialised them.
    pub transport_parameters: Vec<TransportParameter>,
}

/// Starts one QUIC handshake and records what this stack put on the wire.
///
/// The handshake is abandoned immediately. Nothing needs to be listening at the far
/// end and nothing needs to arrive: `quinn` writes the ClientHello while it is still
/// constructing the connection, so both observations are complete before
/// `connect_with` returns.
///
/// Must be called from inside a Tokio runtime, because `quinn::Endpoint::client`
/// resolves its runtime from the ambient handle.
///
/// # Errors
///
/// [`SpikeError::Request`] when the endpoint cannot be created or the connection
/// cannot be started, [`SpikeError::NothingRecorded`] when the probe saw nothing, and
/// [`SpikeError::Malformed`] when what it saw cannot be decoded.
pub fn observe(server_name: &str, alpn: &[&str]) -> Result<Observation, SpikeError> {
    observe_with(server_name, alpn, quinn::TransportConfig::default())
}

/// Builds the rustls configuration this spike uses everywhere, so that the quinn path
/// and the rustls-only path below are compared like for like.
fn tls_config(alpn: &[&str]) -> Result<rustls::ClientConfig, SpikeError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| SpikeError::Request(error.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
    Ok(tls)
}

/// As [`observe`], with a caller-supplied [`quinn::TransportConfig`].
///
/// The point of exposing this is negative: it is how the spike demonstrates that no
/// setting on `TransportConfig` removes a parameter from the emitted set.
///
/// # Errors
///
/// As [`observe`].
pub fn observe_with(
    server_name: &str,
    alpn: &[&str],
    transport: quinn::TransportConfig,
) -> Result<Observation, SpikeError> {
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config(alpn)?)
        .map_err(|error| SpikeError::Request(error.to_string()))?;

    let recorder = HandshakeRecorder::new();
    let mut client_config = quinn::ClientConfig::new(recorder.wrap(Arc::new(quic_tls)));
    client_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|error| SpikeError::Request(format!("cannot bind a client endpoint: {error}")))?;

    // A port nothing listens on. The handshake never completes and does not need to.
    let unreachable = SocketAddr::from(([127, 0, 0, 1], 1));
    let connecting = endpoint
        .connect_with(client_config, unreachable, server_name)
        .map_err(|error| SpikeError::Request(error.to_string()))?;
    drop(connecting);
    endpoint.close(0u32.into(), b"probe complete");

    let recorded = recorder.snapshot();
    if recorded.client_hello.is_empty() {
        return Err(SpikeError::NothingRecorded("the ClientHello"));
    }
    if recorded.transport_parameters.is_empty() {
        return Err(SpikeError::NothingRecorded("the transport parameters"));
    }

    Ok(Observation {
        client_hello: ObservedClientHello::parse(&recorded.client_hello)?,
        transport_parameters: decode_transport_parameters(&recorded.transport_parameters)?,
    })
}

/// Emits a ClientHello through rustls' QUIC API with transport parameters of the
/// caller's choosing, bypassing `quinn` entirely.
///
/// This is the escape hatch, and it is worth being precise about what it proves.
/// `rustls::quic::ClientConnection::new` takes the transport parameters as
/// `params: Vec<u8>` and treats them as opaque
/// (`rustls-0.23.43/src/quic.rs:163-167`), so *any* set, order or unknown identifier
/// can be placed in extension 0x0039. What it does not prove is that this is reachable
/// from `quinn`: `QuicClientConfig::start_session` calls that constructor with
/// `to_vec(params)` from quinn's own `TransportParameters`
/// (`quinn-proto-0.11.16/src/crypto/rustls.rs:369-374`), and `TlsSession` is private,
/// so using the hatch means reimplementing quinn's TLS backend — which is what
/// `quinn-boring` does.
///
/// # Errors
///
/// [`SpikeError::Request`] when the configuration is rejected, and
/// [`SpikeError::Malformed`] when the emitted handshake cannot be decoded.
pub fn emit_with_transport_parameters(
    server_name: &str,
    alpn: &[&str],
    params: Vec<u8>,
) -> Result<ObservedClientHello, SpikeError> {
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|error| SpikeError::Request(error.to_string()))?;
    let mut connection = rustls::quic::ClientConnection::new(
        Arc::new(tls_config(alpn)?),
        rustls::quic::Version::V1,
        name,
        params,
    )
    .map_err(|error| SpikeError::Request(error.to_string()))?;

    let mut buf = Vec::new();
    connection.write_hs(&mut buf);
    if buf.is_empty() {
        return Err(SpikeError::NothingRecorded("the ClientHello"));
    }
    ObservedClientHello::parse(&buf)
}

struct ProbeClientConfig {
    inner: Arc<dyn CryptoClientConfig>,
    recorder: HandshakeRecorder,
}

impl std::fmt::Debug for ProbeClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeClientConfig").finish_non_exhaustive()
    }
}

impl CryptoClientConfig for ProbeClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let mut encoded = Vec::new();
        params.write(&mut encoded);

        if let Ok(mut state) = self.recorder.state.lock() {
            state.transport_parameters = encoded;
            state.server_name = server_name.to_owned();
            state.version = version;
        }

        let inner = self
            .inner
            .clone()
            .start_session(version, server_name, params)?;
        Ok(Box::new(ProbeSession {
            inner,
            recorder: self.recorder.clone(),
        }))
    }
}

struct ProbeSession {
    inner: Box<dyn Session>,
    recorder: HandshakeRecorder,
}

impl Session for ProbeSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let before = buf.len();
        let keys = self.inner.write_handshake(buf);
        if buf.len() > before
            && let Ok(mut state) = self.recorder.state.lock()
            && state.client_hello.is_empty()
        {
            state.client_hello = buf[before..].to_vec();
        }
        keys
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

#[cfg(test)]
mod tests {
    use chromulate_fingerprint::ja4::ja4;
    use chromulate_profile::Profile;

    use super::*;

    fn observed() -> Observation {
        observe("example.com", &["h3"]).expect("the probe records a handshake")
    }

    fn ids(observation: &Observation) -> Vec<u64> {
        observation
            .transport_parameters
            .iter()
            .map(|parameter| parameter.id)
            .collect()
    }

    #[tokio::test]
    async fn the_probe_records_a_client_hello_and_transport_parameters() {
        let observation = observed();
        assert!(!observation.client_hello.cipher_suites.is_empty());
        assert!(!observation.transport_parameters.is_empty());
        assert_eq!(observation.client_hello.alpn, ["h3"]);
        assert!(observation.client_hello.has_sni());
    }

    #[tokio::test]
    async fn the_client_hello_carries_the_quic_transport_parameters_extension() {
        // RFC 9001 section 8.2: the parameters travel in TLS extension 0x0039. The
        // probe reads the same block twice, once from `TransportParameters::write` and
        // once out of the emitted ClientHello, and the two must agree — otherwise the
        // recorder is observing something other than what is sent.
        let observation = observed();
        let from_extension = observation
            .client_hello
            .quic_transport_parameters
            .as_ref()
            .expect("extension 0x0039 is present");
        let decoded = decode_transport_parameters(from_extension).expect("well formed");
        let from_hello: Vec<u64> = decoded.iter().map(|parameter| parameter.id).collect();
        assert_eq!(from_hello, ids(&observation));
    }

    #[tokio::test]
    async fn no_grease_reaches_the_wire_over_quic_either() {
        // `docs/fidelity.md` records this absence for the TCP handshake. The QUIC
        // ClientHello comes out of the same rustls, so the same absence is expected —
        // and it is asserted rather than assumed, so a rustls release that starts
        // emitting GREASE turns this red instead of quietly making the document wrong.
        let observation = observed();
        assert_eq!(
            observation.client_hello.grease_values(),
            Vec::<u16>::new(),
            "extensions were {:04x?}",
            observation.client_hello.extensions
        );
    }

    #[tokio::test]
    async fn quinn_always_sends_a_reserved_grease_transport_parameter() {
        // `quinn-proto-0.11.16/src/transport_parameters.rs:177` sets
        // `grease_transport_parameter: Some(ReservedTransportParameter::random(rng))`
        // unconditionally, and `TransportConfig` has no knob for it. Whether Chrome
        // does the same is unknown to this project, because no QUIC capture exists —
        // so this asserts what quinn does, not what is correct.
        let observation = observed();
        let reserved: Vec<u64> = observation
            .transport_parameters
            .iter()
            .filter(|parameter| parameter.is_reserved_grease())
            .map(|parameter| parameter.id)
            .collect();
        assert_eq!(reserved.len(), 1, "ids were {:#x?}", ids(&observation));
        assert_eq!(reserved[0] % 31, 27);
    }

    /// The registered parameter ids, sorted, with the reserved GREASE one removed.
    ///
    /// The reserved id is redrawn at random on every connection, so it belongs to the
    /// variability being measured rather than to the stable set.
    fn registered_set(observation: &Observation) -> Vec<u64> {
        let mut out: Vec<u64> = observation
            .transport_parameters
            .iter()
            .filter(|parameter| !parameter.is_reserved_grease())
            .map(|parameter| parameter.id)
            .collect();
        out.sort_unstable();
        out
    }

    #[tokio::test]
    async fn quinn_randomises_transport_parameter_order_between_connections() {
        // The finding that decides the fidelity question, observed rather than read
        // off the source: `write_order` is shuffled per connection
        // (`quinn-proto-0.11.16/src/transport_parameters.rs:178-182`) and no public
        // API sets it.
        //
        // Written so it cannot pass by accident. A fixed order fails all sixteen
        // attempts, and the registered set is asserted stable alongside, so a test
        // that went green because the parameters themselves changed would be caught.
        let first_observation = observed();
        let first = ids(&first_observation);
        let baseline_set = registered_set(&first_observation);

        let mut differed = false;
        for _ in 0..16 {
            let observation = observed();
            assert_eq!(
                registered_set(&observation),
                baseline_set,
                "the registered parameter set is expected to be stable"
            );
            if ids(&observation) != first {
                differed = true;
                break;
            }
        }
        assert!(
            differed,
            "order never changed across 16 connections: {first:#x?}"
        );
    }

    #[tokio::test]
    async fn the_reserved_grease_identifier_is_redrawn_per_connection() {
        // Not only the order varies. `ReservedTransportParameter::random`
        // (`transport_parameters.rs:177`) picks a fresh `31 * N + 27` identifier and a
        // fresh payload for every connection, so even the *set* of identifiers a
        // server sees is different each time.
        fn reserved(observation: &Observation) -> u64 {
            observation
                .transport_parameters
                .iter()
                .find(|parameter| parameter.is_reserved_grease())
                .map(|parameter| parameter.id)
                .expect("quinn always sends one")
        }

        let first = reserved(&observed());
        let differed = (0..16).any(|_| reserved(&observed()) != first);
        assert!(differed, "reserved id was {first:#x} every time");
    }

    #[tokio::test]
    async fn rustls_permutes_the_extension_order_between_connections() {
        // Worth observing because it corrects an easy assumption. `docs/fidelity.md`
        // records that Chromulate's TLS shape does not match Chrome and that GREASE
        // never reaches the wire, which reads as "rustls emits a fixed hello". It does
        // not: extension order is shuffled from a per-connection seed
        // (`rustls-0.23.43/src/client/common.rs:40`,
        // `src/msgs/handshake.rs:977` and `:1068-1090`). So the *ordering* half of
        // section 5.4 of the design document is already satisfied here by accident.
        //
        // It also means order is not the axis on which this fails, which matters:
        // JA4 sorts both the cipher and extension lists before hashing, so neither
        // this shuffle nor quinn's transport-parameter shuffle changes a JA4 at all.
        let first = observed().client_hello.extensions;
        let differed = (0..16).any(|_| observed().client_hello.extensions != first);
        assert!(differed, "extension order was {first:04x?} every time");

        // The set is stable even though the order is not.
        let mut baseline = first.clone();
        baseline.sort_unstable();
        for _ in 0..4 {
            let mut next = observed().client_hello.extensions;
            next.sort_unstable();
            assert_eq!(next, baseline);
        }
    }

    #[tokio::test]
    async fn no_transport_config_setting_removes_a_parameter_from_the_set() {
        // The API limit, demonstrated rather than asserted from the source. Every
        // knob `TransportConfig` offers is moved off its default, and the emitted
        // *set* is unchanged: values move, membership does not.
        //
        // `min_ack_delay` (0xff04de1b) is the sharpest case. It is set unconditionally
        // in `TransportParameters::new`
        // (`quinn-proto-0.11.16/src/transport_parameters.rs:174-176`) from a private
        // constant, and no configuration reaches it.
        let baseline = registered_set(&observed());

        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(17u32.into())
            .max_concurrent_uni_streams(19u32.into())
            .max_idle_timeout(Some(
                std::time::Duration::from_secs(7).try_into().expect("valid"),
            ))
            .receive_window(1_234_567u32.into())
            .stream_receive_window(65_536u32.into())
            .datagram_receive_buffer_size(None)
            .allow_spin(false);

        let tweaked =
            observe_with("example.com", &["h3"], transport).expect("the probe records a handshake");
        let tweaked_set = registered_set(&tweaked);

        // `datagram_receive_buffer_size(None)` does remove 0x20, which is the one
        // membership change reachable at all — so the assertion is about the rest.
        let unreachable: Vec<u64> = baseline.iter().copied().filter(|id| *id != 0x20).collect();
        assert_eq!(unreachable, tweaked_set, "set changed beyond 0x20");
        assert!(
            tweaked_set.contains(&0xff04_de1b),
            "min_ack_delay survived every setting, as expected: {tweaked_set:#x?}"
        );
        assert!(tweaked_set.contains(&0x0e), "active_connection_id_limit");
    }

    #[tokio::test]
    async fn rustls_itself_accepts_arbitrary_transport_parameter_bytes() {
        // The other side of the same coin, and the reason the assessment says the gap
        // is reachable but not from here: rustls treats the parameters as opaque, so a
        // caller that owns the `crypto::Session` can emit any set in any order,
        // including identifiers quinn has no name for.
        let handmade = vec![
            0x01, 0x04, 0x80, 0x00, 0x75, 0x30, // max_idle_timeout = 30000
            0x0f, 0x00, // initial_source_connection_id, empty
            0x80, 0x00, 0x31, 0x27, 0x02, 0x4e, 0x20, // 0x3127, an id quinn lacks
        ];
        let hello = emit_with_transport_parameters("example.com", &["h3"], handmade.clone())
            .expect("rustls emits a hello");
        let body = hello
            .quic_transport_parameters
            .expect("extension 0x0039 is present");
        assert_eq!(body, handmade, "rustls passed the bytes through unaltered");

        let decoded = decode_transport_parameters(&body).expect("well formed");
        let ids: Vec<u64> = decoded.iter().map(|parameter| parameter.id).collect();
        assert_eq!(ids, [0x01, 0x0f, 0x3127]);
    }

    #[tokio::test]
    async fn the_quic_hello_omits_extensions_the_captured_chrome_profile_carries() {
        // What this test may and may not conclude, stated plainly, because the
        // temptation to overclaim here is the whole problem.
        //
        // It MAY conclude that the extensions listed below are absent: they are in the
        // shipped capture (`crates/chromulate-profile/src/chrome.rs:43-60`), they are
        // not transport-specific, and rustls does not emit them. That is the same
        // divergence `docs/fidelity.md` already records for TCP, reproduced over QUIC.
        //
        // It MAY NOT conclude anything from the cipher counts. QUIC mandates TLS 1.3
        // (RFC 9001 section 4.2), so a QUIC ClientHello legitimately offers only the
        // TLS 1.3 suites, and comparing three against the capture's fifteen compares a
        // QUIC handshake with a TCP one. The capture is TCP. There is no Chrome QUIC
        // capture in this repository, so the *target* for this row is unknown, and
        // inventing one would break the project's first data rule.
        let observation = observed();
        let spec = observation
            .client_hello
            .to_spec()
            .expect("the observed hello fits the fingerprint model");
        let chrome = Profile::chrome_stable();

        let missing: Vec<String> = chrome
            .client_hello
            .extensions
            .iter()
            .filter(|id| !observation.client_hello.extensions.contains(&id.get()))
            .map(|id| format!("0x{}", id.hex4()))
            .collect();

        // These five are unreachable from any rustls configuration: no feature adds
        // them and there is no arbitrary-extension API.
        for expected in ["0x0012", "0x0023", "0x44cd", "0xfe0d", "0xff01"] {
            assert!(
                missing.iter().any(|id| id == expected),
                "{expected} was expected to be missing; missing set is {missing:?}"
            );
        }

        // `compress_certificate` (0x001b) is deliberately *not* in that list, and the
        // reason is worth knowing. Whether rustls emits it depends on `rustls/brotli`,
        // which `chromulate-tls` turns on through its default `cert-compression`
        // feature (`crates/chromulate-tls/Cargo.toml:34`). Cargo unifies features
        // across a workspace build, so this crate's rustls gains the extension when
        // `chromulate-tls` is in the same graph and loses it when it is not — the
        // emitted set is a property of the whole build, not of this crate. The two
        // outcomes are both correct, so the test reports rather than asserts.
        println!(
            "compress_certificate (0x001b): {}",
            if observation.client_hello.extensions.contains(&0x001b) {
                "present — rustls/brotli is enabled somewhere in this build"
            } else {
                "absent — rustls/brotli is not enabled in this build"
            }
        );

        let quic_ja4 = ja4(&spec);
        let chrome_tcp_ja4 = ja4(&chrome.client_hello);
        assert!(quic_ja4.starts_with('q'), "JA4 was {quic_ja4}");
        assert!(chrome_tcp_ja4.starts_with('t'), "JA4 was {chrome_tcp_ja4}");

        // Printed so the assessment can quote figures a reader can reproduce with
        // `cargo test -p chromulate-h3 --all-features -- --nocapture`.
        println!("quinn + rustls over QUIC : {quic_ja4}");
        println!("captured Chrome 151 (TCP): {chrome_tcp_ja4}  [not the QUIC target]");
        println!(
            "extensions {} vs {}; absent from the QUIC hello: {missing:?}",
            spec.extensions.len(),
            chrome.client_hello.extensions.len()
        );
        println!(
            "extensions on the wire: {:04x?}",
            observation.client_hello.extensions
        );
        println!("transport parameter ids: {:#x?}", ids(&observation));
    }
}
