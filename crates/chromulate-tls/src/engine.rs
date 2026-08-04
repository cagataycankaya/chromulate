//! The connector: a profile in, a verified TLS stream out.

use std::fmt;
use std::sync::Arc;

use chromulate_core::{Error, Result};
use chromulate_fingerprint::{CipherSuite, ClientHelloSpec, TlsVersion};
use chromulate_profile::Profile;
use rustls::client::Resumption;
use rustls::{ClientConfig, ClientConnection};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::fidelity::{Fidelity, TargetIdentity};
use crate::provider::{PROVIDER_NAME, SelectedProvider};
use crate::resumption::{DEFAULT_CAPACITY, SessionStore};
use crate::server_name::{describe, server_name};
use crate::trust::{RootSource, TrustPolicy, root_store};

/// The protocol ALPN settled on, so the HTTP layer does not have to look inside
/// the connection to find out which one to speak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alpn {
    /// `h2`.
    Http2,
    /// `http/1.1`.
    Http11,
    /// Something else the server chose from the offered list.
    Other(String),
}

impl Alpn {
    /// Reads an ALPN identifier off the wire.
    #[must_use]
    pub fn from_wire(value: &[u8]) -> Self {
        match value {
            b"h2" => Self::Http2,
            b"http/1.1" => Self::Http11,
            other => Self::Other(String::from_utf8_lossy(other).into_owned()),
        }
    }

    /// Returns the identifier as it appears on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Http2 => "h2",
            Self::Http11 => "http/1.1",
            Self::Other(other) => other,
        }
    }
}

impl fmt::Display for Alpn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the handshake settled on.
///
/// Read this instead of re-inspecting the connection: the HTTP layer needs
/// [`HandshakeInfo::alpn`] to pick h1 or h2, and [`HandshakeInfo::resumed`] is
/// how you check that the session store is doing its job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeInfo {
    /// The protocol both ends agreed on, or `None` when the server ignored
    /// ALPN.
    pub alpn: Option<Alpn>,
    /// The negotiated protocol version.
    pub version: Option<TlsVersion>,
    /// The negotiated cipher suite, as the code point a fingerprint uses.
    pub cipher_suite: Option<CipherSuite>,
    /// `true` when the handshake resumed a previous session rather than
    /// running in full. A resumed TLS 1.3 handshake is one that carried
    /// `pre_shared_key`.
    pub resumed: bool,
}

impl HandshakeInfo {
    /// Reads the outcome off a finished connection.
    #[must_use]
    pub fn of(connection: &ClientConnection) -> Self {
        Self {
            alpn: connection.alpn_protocol().map(Alpn::from_wire),
            version: connection
                .protocol_version()
                .and_then(|version| TlsVersion::from_u16(u16::from(version))),
            cipher_suite: connection
                .negotiated_cipher_suite()
                .map(|suite| CipherSuite::new(u16::from(suite.suite()))),
            resumed: connection
                .handshake_kind()
                .is_some_and(|kind| kind == rustls::HandshakeKind::Resumed),
        }
    }

    /// Reads the outcome off a stream returned by [`TlsEngine::connect`].
    #[must_use]
    pub fn of_stream<IO>(stream: &TlsStream<IO>) -> Self {
        Self::of(stream.get_ref().1)
    }

    /// Returns `true` when the connection speaks HTTP/2.
    #[must_use]
    pub fn is_http2(&self) -> bool {
        self.alpn == Some(Alpn::Http2)
    }
}

/// A TLS client built from a browser profile.
///
/// Cheap to clone: everything behind it is shared, including the session store,
/// so clones resume each other's sessions.
///
/// ```no_run
/// use chromulate_profile::Profile;
/// use chromulate_tls::{HandshakeInfo, TlsEngine};
/// use tokio::net::TcpStream;
///
/// # async fn run() -> Result<(), chromulate_core::Error> {
/// let engine = TlsEngine::new(&Profile::chrome_stable())?;
/// let tcp = TcpStream::connect("example.com:443")
///     .await
///     .map_err(|error| chromulate_core::Error::Connect {
///         target: "example.com:443".to_owned(),
///         source: Some(Box::new(error)),
///     })?;
///
/// let stream = engine.connect(tcp, "example.com").await?;
/// let info = HandshakeInfo::of_stream(&stream);
/// println!("negotiated {:?} against target {}", info.alpn, engine.target_identity());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TlsEngine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    connector: TlsConnector,
    config: Arc<ClientConfig>,
    target: ClientHelloSpec,
    identity: TargetIdentity,
    fidelity: Fidelity,
    trust: TrustPolicy,
    sessions: Arc<SessionStore>,
}

impl fmt::Debug for EngineInner {
    /// `tokio_rustls::TlsConnector` is not `Debug`, and it holds nothing the
    /// configuration beside it does not already describe.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsEngine")
            .field("fidelity", &self.fidelity)
            .field("trust", &self.trust)
            .field("sessions", &self.sessions)
            .finish_non_exhaustive()
    }
}

impl TlsEngine {
    /// Builds an engine from a profile with the default trust and session
    /// settings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the profile and the linked provider have
    /// no cipher suite, group or protocol version in common, or when the trust
    /// store cannot be built.
    pub fn new(profile: &Profile) -> Result<Self> {
        Self::builder(profile).build()
    }

    /// Starts a builder for an engine from a profile.
    #[must_use]
    pub fn builder(profile: &Profile) -> TlsEngineBuilder {
        TlsEngineBuilder::new(profile)
    }

    /// Opens a TLS connection over an established stream.
    ///
    /// `host` is the name the connection is addressed to: it is normalised the
    /// way [`crate::server_name()`] describes, and an IP literal suppresses SNI.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Url`] when `host` is not a usable name, and
    /// [`Error::Tls`] when the handshake fails, including when the certificate
    /// does not verify.
    pub async fn connect<IO>(&self, io: IO, host: &str) -> Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_to(io, server_name(host)?).await
    }

    /// Opens a TLS connection to an already parsed name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] when the handshake fails.
    pub async fn connect_to<IO>(&self, io: IO, name: ServerName<'static>) -> Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let target = describe(&name);
        let offered_ticket = self.inner.sessions.has_ticket(&name);

        let stream = self
            .inner
            .connector
            .connect(name, io)
            .await
            .map_err(|error| Error::Tls {
                target: target.clone(),
                source: Some(Box::new(error)),
            })?;

        let info = HandshakeInfo::of_stream(&stream);
        tracing::debug!(
            target = %target,
            alpn = ?info.alpn.as_ref().map(Alpn::as_str),
            version = ?info.version,
            resumed = info.resumed,
            offered_ticket,
            "TLS handshake complete"
        );
        Ok(stream)
    }

    /// Returns the ClientHello the profile asked for.
    ///
    /// This is the target, not what goes on the wire. See the crate-level
    /// "Fidelity limits" section, and [`TlsEngine::fidelity`] for the gap this
    /// particular configuration leaves.
    #[must_use]
    pub fn target_client_hello(&self) -> &ClientHelloSpec {
        &self.inner.target
    }

    /// Returns the JA3 and JA4 the profile is aiming at, for logging beside
    /// what an echo endpoint reports back.
    #[must_use]
    pub fn target_identity(&self) -> &TargetIdentity {
        &self.inner.identity
    }

    /// Returns what this configuration does and does not reproduce.
    #[must_use]
    pub fn fidelity(&self) -> &Fidelity {
        &self.inner.fidelity
    }

    /// Returns how server certificates are treated.
    #[must_use]
    pub fn trust_policy(&self) -> TrustPolicy {
        self.inner.trust
    }

    /// Returns the shared session store, so a caller can inspect, clear, or
    /// share it with another engine.
    #[must_use]
    pub fn sessions(&self) -> &Arc<SessionStore> {
        &self.inner.sessions
    }

    /// Returns the rustls configuration, for a caller that needs to build its
    /// own connector from the same settings.
    #[must_use]
    pub fn client_config(&self) -> &Arc<ClientConfig> {
        &self.inner.config
    }
}

/// Assembles a [`TlsEngine`].
#[derive(Debug)]
pub struct TlsEngineBuilder {
    spec: ClientHelloSpec,
    alpn: Option<Vec<String>>,
    roots: RootSource,
    extra_roots: Vec<CertificateDer<'static>>,
    sessions: Option<Arc<SessionStore>>,
    session_capacity: usize,
    accept_invalid_certs: bool,
}

impl TlsEngineBuilder {
    /// Starts from a profile's ClientHello.
    #[must_use]
    pub fn new(profile: &Profile) -> Self {
        Self {
            spec: profile.client_hello.clone(),
            alpn: None,
            roots: RootSource::default(),
            extra_roots: Vec::new(),
            sessions: None,
            session_capacity: DEFAULT_CAPACITY,
            accept_invalid_certs: false,
        }
    }

    /// Overrides the ALPN list the profile carries.
    ///
    /// Use this to force HTTP/1.1 on a client that would otherwise negotiate
    /// h2. It moves the handshake away from the profile, so it is a deliberate
    /// choice rather than a default.
    #[must_use]
    pub fn with_alpn(mut self, protocols: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.alpn = Some(protocols.into_iter().map(Into::into).collect());
        self
    }

    /// Chooses where root certificates come from.
    #[must_use]
    pub fn with_root_source(mut self, source: RootSource) -> Self {
        self.roots = source;
        self
    }

    /// Adds a DER-encoded root certificate on top of the chosen source.
    #[must_use]
    pub fn add_root_certificate(mut self, certificate: CertificateDer<'static>) -> Self {
        self.extra_roots.push(certificate);
        self
    }

    /// Sets how many hosts the session store keeps.
    #[must_use]
    pub fn with_session_capacity(mut self, capacity: usize) -> Self {
        self.session_capacity = capacity;
        self
    }

    /// Shares an existing session store, so two engines resume each other's
    /// sessions.
    #[must_use]
    pub fn with_session_store(mut self, store: Arc<SessionStore>) -> Self {
        self.sessions = Some(store);
        self
    }

    /// Turns off certificate verification entirely.
    ///
    /// **Anyone on the network path can then read and alter everything the
    /// connection carries, and neither this crate nor the server will notice.**
    ///
    /// It is behind the `dangerous-configuration` feature so that reaching it
    /// takes a deliberate change to a manifest, and it is never enabled by any
    /// default path.
    #[cfg(feature = "dangerous-configuration")]
    #[must_use]
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid_certs = accept;
        self
    }

    /// Builds the engine.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the profile and the linked provider have
    /// nothing in common, when the trust store is empty or unreadable, or when
    /// rustls rejects the version selection.
    pub fn build(self) -> Result<TlsEngine> {
        let selected = SelectedProvider::for_spec(&self.spec)?;
        let alpn = self.alpn.clone().unwrap_or_else(|| self.spec.alpn.clone());

        let builder = ClientConfig::builder_with_provider(Arc::clone(&selected.provider))
            .with_protocol_versions(&selected.versions)
            .map_err(|error| {
                Error::config(format!("rustls rejected the profile's versions: {error}"))
            })?;

        let (mut config, trust) = if self.accept_invalid_certs {
            #[cfg(feature = "dangerous-configuration")]
            {
                let verifier = Arc::new(crate::trust::dangerous::AcceptAnyCertificate::new(
                    Arc::clone(&selected.provider),
                ));
                tracing::warn!(
                    "certificate verification is disabled; this connection is not authenticated"
                );
                (
                    builder
                        .dangerous()
                        .with_custom_certificate_verifier(verifier)
                        .with_no_client_auth(),
                    TrustPolicy::DangerouslyUnverified,
                )
            }
            #[cfg(not(feature = "dangerous-configuration"))]
            {
                return Err(Error::config(
                    "accepting invalid certificates needs the `dangerous-configuration` feature",
                ));
            }
        } else {
            let roots = root_store(self.roots, &self.extra_roots)?;
            let count = roots.len();
            (
                builder.with_root_certificates(roots).with_no_client_auth(),
                TrustPolicy::Verified { roots: count },
            )
        };

        config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();

        let sessions = self
            .sessions
            .unwrap_or_else(|| Arc::new(SessionStore::new(self.session_capacity)));
        config.resumption = Resumption::store(Arc::clone(&sessions) as _);

        let fidelity = Fidelity {
            provider: PROVIDER_NAME,
            offered_cipher_suites: selected.offered_cipher_suites,
            dropped_cipher_suites: selected.dropped_cipher_suites,
            offered_groups: selected.offered_groups,
            dropped_groups: selected.dropped_groups,
            dropped_versions: selected.dropped_versions,
            alpn,
            target: TargetIdentity::of(&self.spec),
        };
        tracing::debug!(fidelity = %fidelity, trust = %trust, "built a TLS engine");

        let config = Arc::new(config);
        Ok(TlsEngine {
            inner: Arc::new(EngineInner {
                connector: TlsConnector::from(Arc::clone(&config)),
                config,
                target: self.spec,
                identity: fidelity.target.clone(),
                fidelity,
                trust,
                sessions,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use chromulate_fingerprint::NamedGroup;

    use super::*;

    fn chrome() -> TlsEngine {
        TlsEngine::new(&Profile::chrome_stable()).expect("the Chrome profile must build an engine")
    }

    #[test]
    fn the_chrome_engine_offers_exactly_the_profiles_alpn_list_in_order() {
        let engine = chrome();
        let wire: Vec<Vec<u8>> = engine.client_config().alpn_protocols.clone();
        assert_eq!(
            wire,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "ALPN is one of the few things rustls reproduces exactly"
        );
        assert_eq!(engine.fidelity().alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn the_enabled_suites_are_the_profiles_suites_the_provider_has_in_the_profiles_order() {
        let engine = chrome();
        let profile = Profile::chrome_stable();

        let enabled: Vec<CipherSuite> = engine
            .client_config()
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|suite| CipherSuite::new(u16::from(suite.suite())))
            .collect();

        assert_eq!(&enabled, &engine.fidelity().offered_cipher_suites);
        let expected: Vec<CipherSuite> = profile
            .client_hello
            .ciphers_without_grease()
            .filter(|suite| enabled.contains(suite))
            .collect();
        assert_eq!(enabled, expected);
        assert!(
            !engine.fidelity().dropped_cipher_suites.is_empty(),
            "rustls has no CBC or static-RSA suites, so some of Chrome's list must be dropped"
        );
    }

    #[test]
    fn certificate_verification_is_on_in_the_default_path() {
        let engine = chrome();
        match engine.trust_policy() {
            TrustPolicy::Verified { roots } => assert!(
                roots > 100,
                "the default engine should carry the whole Mozilla root program; got {roots}"
            ),
            TrustPolicy::DangerouslyUnverified => {
                panic!("the default engine must verify certificates")
            }
        }
    }

    #[test]
    fn an_engine_with_no_usable_root_refuses_to_build() {
        let profile = Profile::chrome_stable();
        let error = TlsEngine::builder(&profile)
            .with_root_source(RootSource::None)
            .build()
            .expect_err("an engine with an empty trust store must not build");
        assert!(matches!(error, Error::Config(_)), "got {error:?}");
    }

    #[test]
    #[cfg(not(feature = "dangerous-configuration"))]
    fn without_the_feature_there_is_no_way_to_switch_verification_off() {
        // `danger_accept_invalid_certs` does not exist in this build, so the
        // only reachable path is the verified one.
        assert!(matches!(
            chrome().trust_policy(),
            TrustPolicy::Verified { .. }
        ));
    }

    #[test]
    #[cfg(feature = "dangerous-configuration")]
    fn the_dangerous_path_is_only_taken_when_it_is_asked_for_by_name() {
        let profile = Profile::chrome_stable();
        assert!(matches!(
            TlsEngine::builder(&profile)
                .danger_accept_invalid_certs(false)
                .build()
                .expect("a builder that declines the danger still verifies")
                .trust_policy(),
            TrustPolicy::Verified { .. }
        ));
        assert_eq!(
            TlsEngine::builder(&profile)
                .danger_accept_invalid_certs(true)
                .build()
                .expect("the dangerous engine builds when the feature is on")
                .trust_policy(),
            TrustPolicy::DangerouslyUnverified
        );
    }

    #[test]
    fn the_target_identity_is_the_profiles_fingerprint_not_a_measured_one() {
        let engine = chrome();
        assert_eq!(
            engine.target_identity().ja4,
            Profile::chrome_stable().ja4(),
            "the engine reports the profile's target, which the wire form does not match"
        );
        assert_eq!(
            engine.target_client_hello(),
            &Profile::chrome_stable().client_hello
        );
    }

    #[test]
    fn the_group_chrome_asks_for_first_is_reported_as_dropped_on_a_ring_build() {
        let engine = chrome();
        let fidelity = engine.fidelity();
        if crate::supports_named_group(NamedGroup::X25519_MLKEM768) {
            assert!(
                fidelity
                    .offered_groups
                    .contains(&NamedGroup::X25519_MLKEM768)
            );
        } else {
            assert!(
                fidelity
                    .dropped_groups
                    .contains(&NamedGroup::X25519_MLKEM768),
                "a group the provider lacks must be reported, never silently skipped"
            );
        }
        assert_eq!(
            fidelity.offered_groups.len() + fidelity.dropped_groups.len(),
            Profile::chrome_stable().client_hello.supported_groups.len()
        );
    }

    #[test]
    fn engines_can_share_one_session_store_and_are_otherwise_independent() {
        let profile = Profile::chrome_stable();
        let shared = Arc::new(SessionStore::new(4));

        let first = TlsEngine::builder(&profile)
            .with_session_store(Arc::clone(&shared))
            .build()
            .expect("an engine with a shared store must build");
        let second = TlsEngine::builder(&profile)
            .with_session_store(Arc::clone(&shared))
            .build()
            .expect("a second engine with the same store must build");
        let separate = TlsEngine::new(&profile).expect("a default engine must build");

        assert!(Arc::ptr_eq(first.sessions(), second.sessions()));
        assert!(!Arc::ptr_eq(first.sessions(), separate.sessions()));
        assert_eq!(first.sessions().capacity(), 4);
    }

    #[test]
    fn a_cloned_engine_shares_the_configuration_rather_than_rebuilding_it() {
        let engine = chrome();
        let clone = engine.clone();
        assert!(Arc::ptr_eq(engine.client_config(), clone.client_config()));
    }

    #[test]
    fn overriding_alpn_replaces_the_profiles_list() {
        let engine = TlsEngine::builder(&Profile::chrome_stable())
            .with_alpn(["http/1.1"])
            .build()
            .expect("an http/1.1 only engine must build");
        assert_eq!(
            engine.client_config().alpn_protocols,
            vec![b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn an_alpn_identifier_round_trips_through_the_wire_form() {
        assert_eq!(Alpn::from_wire(b"h2"), Alpn::Http2);
        assert_eq!(Alpn::from_wire(b"http/1.1"), Alpn::Http11);
        assert_eq!(Alpn::from_wire(b"h3").to_string(), "h3");
        assert_eq!(Alpn::Http2.as_str(), "h2");
    }
}
