//! A second backend, so that [`TlsBackend`] has been
//! implemented twice.
//!
//! A trait with one implementation is a guess about an interface. This module
//! exists to turn that guess into a checked claim: [`MockBackend`] implements
//! the seam without rustls, without a handshake, and without producing rustls's
//! stream type, and `chromulate-http` compiles and runs against it unchanged.
//!
//! Writing it found three things the seam was missing, all of which are now on
//! the trait: `from_profile`, because `chromulate-http` builds its own backend
//! when a caller supplies none; and `target_identity` and `fidelity`, because
//! the CLI and the facade's own documented example call them. Each would have
//! surfaced as a compile error in someone else's build, months later, while
//! writing the BoringSSL backend.
//!
//! **This is not a TLS implementation and performs no encryption.** It hands
//! the plaintext stream straight back. It is behind the off-by-default
//! `--cfg chromulate_mock_backend` build flag, not a cargo feature: features
//! must be additive and `--all-features` would enable this one, which would mean
//! a CI run believing it exercised TLS while linking a backend that encrypts
//! nothing. That is a worse outcome than not checking the seam at all.
//!
//! # Example
//!
//! ```
//! use chromulate_profile::Profile;
//! use chromulate_tls::{TlsBackendConfig, mock::MockBackend};
//!
//! # fn main() -> Result<(), chromulate_core::Error> {
//! let backend = MockBackend::from_profile(&Profile::chrome_stable())?;
//!
//! // It aims at the same target the real backend does, because the target is a
//! // property of the profile rather than of the implementation.
//! assert_eq!(
//!     backend.target_identity().ja4,
//!     "t13d1516h2_8daaf6152771_806a8c22fdea"
//! );
//! # Ok(())
//! # }
//! ```

use chromulate_core::{BoxFuture, Result};
use chromulate_fingerprint::ClientHelloSpec;
use chromulate_profile::Profile;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::backend::{TlsBackend, TlsBackendConfig};
use crate::engine::HandshakeInfo;
use crate::fidelity::{Fidelity, TargetIdentity, target_identity};

/// A backend that performs no handshake and encrypts nothing.
///
/// Its purpose is to be *different* from the rustls backend in every way the
/// seam is supposed to tolerate: a different stream type, a handshake result
/// assembled rather than read out of a TLS library, and no rustls types
/// anywhere in its implementation.
#[derive(Debug, Clone)]
pub struct MockBackend {
    client_hello: ClientHelloSpec,
    identity: TargetIdentity,
    fidelity: Fidelity,
}

impl MockBackend {
    /// Builds a mock backend that reports `profile`'s target as its own.
    ///
    /// # Errors
    ///
    /// Never fails today. It returns [`Result`] because the trait method does,
    /// and a backend that has to open a library or load a certificate store
    /// will.
    pub fn new(profile: &Profile) -> Result<Self> {
        Ok(Self {
            client_hello: profile.client_hello.clone(),
            identity: target_identity(profile),
            fidelity: Fidelity {
                // Not `ring` or `aws-lc-rs`: the field is a backend's own name
                // for what is underneath it, and nothing constrains it to
                // rustls's vocabulary.
                provider: "mock",
                offered_cipher_suites: profile.client_hello.cipher_suites.clone(),
                dropped_cipher_suites: Vec::new(),
                offered_groups: profile.client_hello.supported_groups.clone(),
                dropped_groups: Vec::new(),
                dropped_versions: Vec::new(),
                alpn: profile.client_hello.alpn.clone(),
                target: target_identity(profile),
                // The rustls list would be a lie in both directions here, and
                // this backend's real departure is larger than any of it.
                structural_limits: MOCK_STRUCTURAL_LIMITS,
            },
        })
    }
}

/// What this backend does not reproduce, which is everything.
///
/// Stated rather than left empty: an empty list means "no known departures",
/// which is the claim a byte-exact backend makes, and it is the opposite of
/// what is true of a backend that never writes a ClientHello at all.
const MOCK_STRUCTURAL_LIMITS: &[&str] = &[
    "no ClientHello is emitted and no encryption is performed: this backend exists to prove \
     the seam admits an implementation that is not rustls, and it moves bytes through unchanged",
];

impl<IO> TlsBackend<IO> for MockBackend
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// The caller's own stream, handed back untouched.
    ///
    /// The point of the associated type is that a backend picks this. rustls
    /// picks `tokio_rustls::client::TlsStream<IO>`; this picks `IO`. If the
    /// seam only worked for one of those it would not be a seam.
    type Stream = IO;

    fn connect(
        &self,
        io: IO,
        _name: ServerName<'static>,
    ) -> BoxFuture<'_, Result<(Self::Stream, HandshakeInfo)>> {
        Box::pin(async move {
            // Assembled, not read back out of a TLS library. This is the half
            // of the seam that used to be missing: the caller previously asked
            // rustls for this itself, which no other backend could satisfy.
            //
            // `alpn: None` is not laziness. This backend negotiates nothing, so
            // claiming a negotiated protocol would be a lie the caller acts on:
            // an earlier draft reported `h2` because the profile offers it
            // first, and `chromulate-http` duly spoke HTTP/2 to a plaintext
            // HTTP/1 origin. A backend reports what it settled on, and this one
            // settles nothing.
            let info = HandshakeInfo {
                alpn: None,
                version: None,
                cipher_suite: None,
                resumed: false,
            };
            Ok((io, info))
        })
    }
}

impl TlsBackendConfig for MockBackend {
    fn from_profile(profile: &Profile) -> Result<Self> {
        Self::new(profile)
    }

    fn target_client_hello(&self) -> &ClientHelloSpec {
        &self.client_hello
    }

    fn target_identity(&self) -> &TargetIdentity {
        &self.identity
    }

    fn fidelity(&self) -> &Fidelity {
        &self.fidelity
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::server_name;

    fn backend() -> MockBackend {
        MockBackend::from_profile(&Profile::chrome_stable())
            .expect("the mock backend must build from the Chrome profile")
    }

    #[test]
    fn a_second_backend_can_choose_its_own_stream_type() {
        // The assertion is that this compiles: `MockBackend::Stream` is the
        // caller's stream, where the rustls backend's is a rustls type. A seam
        // that pinned the stream type would not admit both.
        fn assert_stream_is<B, IO>()
        where
            B: TlsBackend<IO, Stream = IO>,
            IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
        }
        assert_stream_is::<MockBackend, DuplexStream>();
    }

    #[tokio::test]
    async fn the_mock_backend_hands_back_a_usable_stream_and_a_handshake_result() {
        let (client, mut server) = tokio::io::duplex(64);
        let (mut stream, info) = TlsBackend::connect(
            &backend(),
            client,
            server_name("example.com").expect("a name"),
        )
        .await
        .expect("the mock handshake must succeed");

        assert_eq!(
            info.alpn, None,
            "a backend that negotiates nothing must not claim a negotiated protocol; \
             reporting h2 here made the HTTP layer speak h2 to an HTTP/1 origin"
        );

        stream.write_all(b"ping").await.expect("write must succeed");
        let mut got = [0u8; 4];
        server
            .read_exact(&mut got)
            .await
            .expect("read must succeed");
        assert_eq!(
            &got, b"ping",
            "the stream the seam returned must carry bytes"
        );
    }

    #[test]
    fn both_backends_report_the_same_target_because_the_target_is_the_profiles() {
        let profile = Profile::chrome_stable();
        let engine = crate::TlsEngine::new(&profile).expect("the rustls engine must build");

        assert_eq!(
            backend().target_identity(),
            engine.target_identity(),
            "the ClientHello being aimed at comes from the profile, so swapping the \
             implementation must not move it"
        );
    }

    #[test]
    fn a_backend_states_its_own_fidelity_rather_than_inheriting_rustlss() {
        let backend = backend();
        let fidelity = backend.fidelity();

        assert_eq!(fidelity.provider, "mock");
        assert!(
            fidelity.all_primitives_available(),
            "a backend that drops nothing must be able to say so; the rustls backend drops \
             six cipher suites and says that instead"
        );
    }
}
