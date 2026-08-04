//! Where the client's trust comes from, and the one way to throw it away.

use std::fmt;

use chromulate_core::{Error, Result};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;

/// The set of root certificates a connection is verified against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RootSource {
    /// The Mozilla root program, compiled into the binary by `webpki-roots`.
    ///
    /// This is the default because it makes a build behave the same on every
    /// machine, which is what a crawler or a monitor wants.
    #[default]
    WebPki,
    /// The trust store of the operating system this process is running on.
    ///
    /// Closer to what the browser being imitated would trust, at the cost of a
    /// result that depends on the host. Requires the `platform-roots` feature.
    Platform,
    /// Only the roots the caller adds explicitly.
    ///
    /// Useful for pinning to a private certificate authority, and for a test
    /// that must not accidentally trust the public web.
    None,
}

/// How server certificates are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPolicy {
    /// Certificates are verified against this many root certificates.
    Verified {
        /// The number of roots in the store.
        roots: usize,
    },
    /// Certificates are not verified at all.
    ///
    /// Only reachable through
    /// `TlsEngineBuilder::danger_accept_invalid_certs`.
    DangerouslyUnverified,
}

impl fmt::Display for TrustPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified { roots } => write!(f, "verified against {roots} roots"),
            Self::DangerouslyUnverified => f.write_str("UNVERIFIED - every certificate accepted"),
        }
    }
}

/// Builds the root store for a source plus any extra roots.
///
/// # Errors
///
/// Returns [`Error::Config`] when the platform store cannot be read, when an
/// added certificate does not parse, or when the resulting store is empty —
/// an empty store cannot verify anything, so failing here beats failing every
/// handshake later with a confusing error.
pub(crate) fn root_store(
    source: RootSource,
    extra: &[CertificateDer<'static>],
) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();

    match source {
        RootSource::WebPki => {
            store
                .roots
                .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        RootSource::Platform => platform_roots(&mut store)?,
        RootSource::None => {}
    }

    for certificate in extra {
        store.add(certificate.clone()).map_err(|error| {
            Error::config(format!("an added root certificate is not usable: {error}"))
        })?;
    }

    if store.is_empty() {
        return Err(Error::config(
            "the trust store is empty, so no certificate could ever be verified",
        ));
    }
    Ok(store)
}

/// Loads the operating system trust store.
#[cfg(feature = "platform-roots")]
fn platform_roots(store: &mut RootCertStore) -> Result<()> {
    let loaded = rustls_native_certs::load_native_certs();
    let (added, ignored) = store.add_parsable_certificates(loaded.certs);

    if added == 0 {
        let reasons = loaded
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Error::config(format!(
            "the platform trust store yielded no usable root certificate \
             ({ignored} unparsable, errors: [{reasons}])"
        )));
    }
    if ignored > 0 {
        tracing::debug!(
            added,
            ignored,
            "some platform root certificates were not parsable"
        );
    }
    Ok(())
}

/// Fails with an explanation rather than silently falling back to the bundled
/// roots, which would leave a caller believing it had the platform's trust.
#[cfg(not(feature = "platform-roots"))]
fn platform_roots(_store: &mut RootCertStore) -> Result<()> {
    Err(Error::config(
        "RootSource::Platform needs the `platform-roots` feature of chromulate-tls",
    ))
}

/// A verifier that accepts every certificate, including forged and expired ones.
///
/// Anything sent over a connection using this verifier can be read and altered
/// by whoever is between you and the server.
#[cfg(feature = "dangerous-configuration")]
pub(crate) mod dangerous {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
    use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    /// Accepts any certificate chain, while still checking that the handshake
    /// signature was made by the key in the certificate that was presented.
    ///
    /// The signature check is kept because dropping it would break connections
    /// against servers this is used to debug, and it costs nothing: the point
    /// of this verifier is skipping the *identity* check, which is the part
    /// that makes the connection unsafe.
    #[derive(Debug)]
    pub(crate) struct AcceptAnyCertificate {
        provider: Arc<CryptoProvider>,
    }

    impl AcceptAnyCertificate {
        pub(crate) fn new(provider: Arc<CryptoProvider>) -> Self {
            Self { provider }
        }
    }

    impl ServerCertVerifier for AcceptAnyCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_root_source_is_the_bundled_mozilla_program() {
        assert_eq!(RootSource::default(), RootSource::WebPki);
        let store = root_store(RootSource::WebPki, &[]).expect("the bundled roots must load");
        assert_eq!(store.len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert!(
            store.len() > 100,
            "the Mozilla root program has more than 100 roots; got {}",
            store.len()
        );
    }

    #[test]
    fn a_store_with_no_roots_at_all_is_rejected_rather_than_built() {
        let error = root_store(RootSource::None, &[])
            .expect_err("an empty trust store must not produce a config");
        assert!(matches!(error, Error::Config(_)), "got {error:?}");
    }

    #[test]
    fn asking_for_platform_roots_without_the_feature_fails_loudly() {
        let result = root_store(RootSource::Platform, &[]);
        #[cfg(feature = "platform-roots")]
        {
            let store = result.expect("this machine has a readable trust store");
            assert!(!store.is_empty(), "the platform store should not be empty");
        }
        #[cfg(not(feature = "platform-roots"))]
        {
            let error = result.expect_err("without the feature there is no platform store");
            assert!(
                error.to_string().contains("platform-roots"),
                "the error should name the feature; got {error}"
            );
        }
    }

    #[test]
    fn a_certificate_that_is_not_a_certificate_is_refused() {
        let junk = CertificateDer::from(vec![0x00, 0x01, 0x02]);
        let error = root_store(RootSource::None, std::slice::from_ref(&junk))
            .expect_err("three arbitrary bytes are not a root certificate");
        assert!(matches!(error, Error::Config(_)), "got {error:?}");
    }

    #[test]
    fn the_trust_policy_says_out_loud_when_nothing_is_verified() {
        assert_eq!(
            TrustPolicy::DangerouslyUnverified.to_string(),
            "UNVERIFIED - every certificate accepted"
        );
        assert_eq!(
            TrustPolicy::Verified { roots: 3 }.to_string(),
            "verified against 3 roots"
        );
    }
}
