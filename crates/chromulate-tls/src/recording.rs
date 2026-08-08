//! A backend that consumes a profile the way a real one has to, and records
//! what it was asked for.
//!
//! [`MockBackend`](crate::mock::MockBackend) proved the seam admits a backend
//! that is not rustls. It did not prove the seam admits a backend that
//! *reproduces a fingerprint*, because it consumes nothing: it clones the
//! profile's spec and hands the stream back. Every question that matters to a
//! BoringSSL backend — does the cipher order survive, does GREASE placement
//! survive, does the extension set survive — was left untouched.
//!
//! This backend closes that gap without implementing TLS. It performs the one
//! step a real backend performs before any bytes move: **translate the profile
//! into the vocabulary a TLS library accepts**, which is wire code points and
//! flags, not Rust types. `SSL_CTX_set_cipher_list` takes numbers.
//! `SSL_CTX_set1_group_ids` takes numbers. Whatever a backend cannot express as
//! numbers is lost at that boundary, silently, and the ClientHello is wrong.
//!
//! So [`RecordedClientHello`] is that intermediate form, and
//! [`RecordedClientHello::to_spec`] reconstructs a
//! [`ClientHelloSpec`] from it alone — never from the profile it came from. The
//! test that matters compares the reconstruction's JA4 with the profile's
//! target. If the translation drops anything JA4 counts, the round trip fails.
//!
//! **This is not a TLS implementation and performs no encryption.** It is a
//! measuring instrument, behind the same `--cfg chromulate_mock_backend` flag
//! as the mock, and nothing ships it.
//!
//! # What a round trip does and does not prove
//!
//! It proves a backend *could* have been handed everything the profile
//! specifies. It does not prove a backend *will send* it — that is what
//! `tests/emitted_client_hello.rs` decodes real bytes for, and what rustls
//! fails. The two are different claims and this module only makes the first.

use chromulate_core::{BoxFuture, Error, Result};
use chromulate_fingerprint::{
    CertificateCompression, CipherSuite, ClientHelloSpec, EcPointFormat, ExtensionId, ExtensionSet,
    GreasePlacement, NamedGroup, PskKeyExchangeMode, SignatureScheme, TlsVersion, Transport,
};
use chromulate_profile::Profile;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::backend::{TlsBackend, TlsBackendConfig};
use crate::engine::HandshakeInfo;
use crate::fidelity::{Fidelity, TargetIdentity, target_identity};

/// One backend's configuration, in the vocabulary a TLS library accepts.
///
/// Every list here is `u16` or `u8` rather than a typed identifier, and that is
/// the point: this is the shape the profile has to survive being flattened
/// into. A field that a backend cannot express here is a field it cannot send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedClientHello {
    /// The transport the handshake runs over.
    ///
    /// Not part of the translation — no TLS library is configured with this,
    /// it is a property of the socket — but [`ClientHelloSpec`] needs it, so a
    /// backend has to carry it rather than invent it.
    pub transport: Transport,
    /// Record-layer version.
    pub record_version: u16,
    /// Handshake-header version.
    pub handshake_version: u16,
    /// `supported_versions`, highest first.
    pub supported_versions: Vec<u16>,
    /// Cipher suites in the order they must be offered.
    pub cipher_suites: Vec<u16>,
    /// The extensions to offer, as code points.
    pub extensions: Vec<u16>,
    /// A fixed extension order, or `None` when the backend was asked to
    /// permute — the flag BoringSSL spells `SSL_set_permute_extensions`.
    pub fixed_extension_order: Option<Vec<u16>>,
    /// `supported_groups`, in order.
    pub supported_groups: Vec<u16>,
    /// The groups to send a key share for.
    pub key_share_groups: Vec<u16>,
    /// `signature_algorithms`, in order.
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocol names, wire-encoded.
    pub alpn: Vec<Vec<u8>>,
    /// ALPS protocol names, wire-encoded.
    pub alps: Vec<Vec<u8>>,
    /// Certificate compression algorithms.
    pub certificate_compression: Vec<u16>,
    /// PSK key exchange modes.
    pub psk_key_exchange_modes: Vec<u8>,
    /// EC point formats.
    pub ec_point_formats: Vec<u8>,
    /// GREASE in the first cipher suite slot.
    pub grease_cipher_suites: bool,
    /// GREASE bracketing the extension list.
    pub grease_extensions: bool,
    /// GREASE in the first supported-group slot.
    pub grease_supported_groups: bool,
    /// GREASE in the first key-share slot.
    pub grease_key_shares: bool,
    /// GREASE in the first supported-version slot.
    pub grease_supported_versions: bool,
}

impl RecordedClientHello {
    /// Flattens a profile's ClientHello into wire vocabulary.
    ///
    /// This is the step a real backend performs when it configures its TLS
    /// library, and the only step this module models.
    #[must_use]
    pub fn of(spec: &ClientHelloSpec) -> Self {
        Self {
            transport: spec.transport,
            record_version: spec.record_version.as_u16(),
            handshake_version: spec.handshake_version.as_u16(),
            supported_versions: spec
                .supported_versions
                .iter()
                .map(|version| version.as_u16())
                .collect(),
            cipher_suites: spec.cipher_suites.iter().map(|suite| suite.get()).collect(),
            extensions: spec.extensions.iter().map(ExtensionId::get).collect(),
            fixed_extension_order: match &spec.extension_order {
                chromulate_fingerprint::ExtensionOrder::Fixed(order) => Some(
                    order
                        .as_slice()
                        .iter()
                        .map(|id| ExtensionId::get(*id))
                        .collect(),
                ),
                chromulate_fingerprint::ExtensionOrder::Shuffled(_) => None,
            },
            supported_groups: spec
                .supported_groups
                .iter()
                .map(|group| group.get())
                .collect(),
            key_share_groups: spec
                .key_share_groups
                .iter()
                .map(|group| group.get())
                .collect(),
            signature_algorithms: spec
                .signature_algorithms
                .iter()
                .map(|scheme| scheme.get())
                .collect(),
            alpn: spec
                .alpn
                .iter()
                .map(|protocol| protocol.as_bytes().to_vec())
                .collect(),
            alps: spec
                .alps
                .iter()
                .map(|protocol| protocol.as_bytes().to_vec())
                .collect(),
            certificate_compression: spec
                .certificate_compression
                .iter()
                .map(|algorithm| algorithm.as_u16())
                .collect(),
            psk_key_exchange_modes: spec
                .psk_key_exchange_modes
                .iter()
                .map(|mode| mode.as_u8())
                .collect(),
            ec_point_formats: spec
                .ec_point_formats
                .iter()
                .map(|format| format.as_u8())
                .collect(),
            grease_cipher_suites: spec.grease.cipher_suites,
            grease_extensions: spec.grease.extensions,
            grease_supported_groups: spec.grease.supported_groups,
            grease_key_shares: spec.grease.key_shares,
            grease_supported_versions: spec.grease.supported_versions,
        }
    }

    /// Rebuilds a specification from the recorded configuration alone.
    ///
    /// Deliberately takes nothing but `self`: reaching back to the profile
    /// would make the round trip vacuous, because the answer would be the
    /// question.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when a recorded version code point is not a
    /// TLS version this crate knows — the one lossy conversion here, and worth
    /// failing loudly rather than silently dropping.
    pub fn to_spec(&self) -> Result<ClientHelloSpec> {
        let version = |value: u16| {
            TlsVersion::from_u16(value).ok_or_else(|| {
                Error::Config(format!(
                    "recorded TLS version {value:#06x} is not a known version"
                ))
            })
        };

        Ok(ClientHelloSpec {
            transport: self.transport,
            record_version: version(self.record_version)?,
            handshake_version: version(self.handshake_version)?,
            supported_versions: self
                .supported_versions
                .iter()
                .map(|value| version(*value))
                .collect::<Result<Vec<_>>>()?,
            cipher_suites: self
                .cipher_suites
                .iter()
                .map(|value| CipherSuite::new(*value))
                .collect(),
            extensions: ExtensionSet::new(self.extensions.iter().map(|id| ExtensionId::new(*id))),
            // A recorded fixed order is not reconstructed here: this module
            // models Chrome, which permutes, and rebuilding a pinned order
            // would need `WireExtensionOrder`'s validating constructor and its
            // own error path. `fixed_extension_order` is still recorded so that
            // a backend for a non-permuting browser is not silently misread as
            // permuting; reconstructing it is the work that profile would need.
            extension_order: chromulate_fingerprint::ExtensionOrder::shuffled(),
            supported_groups: self
                .supported_groups
                .iter()
                .map(|value| NamedGroup::new(*value))
                .collect(),
            key_share_groups: self
                .key_share_groups
                .iter()
                .map(|value| NamedGroup::new(*value))
                .collect(),
            signature_algorithms: self
                .signature_algorithms
                .iter()
                .map(|value| SignatureScheme::new(*value))
                .collect(),
            alpn: self
                .alpn
                .iter()
                .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
                .collect(),
            alps: self
                .alps
                .iter()
                .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
                .collect(),
            certificate_compression: self
                .certificate_compression
                .iter()
                .map(|value| CertificateCompression::from(*value))
                .collect(),
            psk_key_exchange_modes: self
                .psk_key_exchange_modes
                .iter()
                .map(|value| PskKeyExchangeMode::from(*value))
                .collect(),
            ec_point_formats: self
                .ec_point_formats
                .iter()
                .map(|value| EcPointFormat::from(*value))
                .collect(),
            grease: GreasePlacement {
                cipher_suites: self.grease_cipher_suites,
                extensions: self.grease_extensions,
                supported_groups: self.grease_supported_groups,
                key_shares: self.grease_key_shares,
                supported_versions: self.grease_supported_versions,
            },
        })
    }
}

/// A backend that records its configuration instead of using it.
///
/// The acceptance harness a fingerprint-controlling backend is measured
/// against: it is handed a profile, it flattens it the way BoringSSL would
/// require, and [`RecordingBackend::recorded`] hands back exactly what a real
/// backend would have been configured with.
#[derive(Debug, Clone)]
pub struct RecordingBackend {
    client_hello: ClientHelloSpec,
    recorded: RecordedClientHello,
    identity: TargetIdentity,
    fidelity: Fidelity,
}

impl RecordingBackend {
    /// Flattens `profile` and keeps the result.
    ///
    /// # Errors
    ///
    /// Never fails today; the signature matches the trait's, and a backend that
    /// has to open a library will.
    pub fn new(profile: &Profile) -> Result<Self> {
        let recorded = RecordedClientHello::of(&profile.client_hello);
        Ok(Self {
            client_hello: profile.client_hello.clone(),
            identity: target_identity(profile),
            fidelity: Fidelity {
                provider: "recording",
                offered_cipher_suites: profile.client_hello.cipher_suites.clone(),
                dropped_cipher_suites: Vec::new(),
                offered_groups: profile.client_hello.supported_groups.clone(),
                dropped_groups: Vec::new(),
                dropped_versions: Vec::new(),
                alpn: profile.client_hello.alpn.clone(),
                target: target_identity(profile),
                structural_limits: RECORDING_STRUCTURAL_LIMITS,
            },
            recorded,
        })
    }

    /// Returns what a real backend would have been configured with.
    #[must_use]
    pub fn recorded(&self) -> &RecordedClientHello {
        &self.recorded
    }
}

/// What this backend does not reproduce.
///
/// It loses nothing at the configuration boundary — that is the property its
/// round-trip test asserts — and it emits nothing either, so the honest
/// statement is about which of the two questions it answers.
const RECORDING_STRUCTURAL_LIMITS: &[&str] = &[
    "no ClientHello reaches a socket: this backend flattens a profile into the wire code \
     points a TLS library accepts and rebuilds a specification from that alone, which \
     measures configuration fidelity rather than wire fidelity",
];

impl TlsBackendConfig for RecordingBackend {
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

impl<IO> TlsBackend<IO> for RecordingBackend
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = IO;

    fn connect(
        &self,
        io: IO,
        _name: ServerName<'static>,
    ) -> BoxFuture<'_, Result<(Self::Stream, HandshakeInfo)>> {
        Box::pin(async move {
            // Negotiates nothing, so it claims nothing. See `mock` for the bug
            // that taught this.
            Ok((
                io,
                HandshakeInfo {
                    alpn: None,
                    version: None,
                    cipher_suite: None,
                    resumed: false,
                },
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use chromulate_fingerprint::{ja4, ja4_raw};

    use super::*;

    fn profile() -> Profile {
        Profile::chrome_stable()
    }

    fn round_trip() -> ClientHelloSpec {
        RecordedClientHello::of(&profile().client_hello)
            .to_spec()
            .expect("the recorded configuration must rebuild a specification")
    }

    /// The claim this module exists for.
    #[test]
    fn flattening_a_profile_and_rebuilding_it_preserves_the_ja4() {
        assert_eq!(
            ja4(&round_trip()),
            profile().ja4(),
            "a backend handed only wire code points must still be able to produce the \
             profile's fingerprint; if this fails the translation drops something JA4 counts"
        );
    }

    /// JA4 sorts, so it cannot see a transposition. The cipher order is part of
    /// the fingerprint and is checked separately for exactly that reason.
    #[test]
    fn the_cipher_order_survives_the_round_trip() {
        assert_eq!(
            round_trip().cipher_suites,
            profile().client_hello.cipher_suites,
            "cipher order is stable in Chrome and must survive flattening in order"
        );
    }

    /// `ja4_raw` carries the lists rather than hashing them, so this compares
    /// the sorted sets and the signature algorithms element by element.
    #[test]
    fn the_raw_ja4_lists_survive_the_round_trip() {
        assert_eq!(ja4_raw(&round_trip()), profile().ja4_raw());
    }

    #[test]
    fn grease_placement_survives_the_round_trip() {
        let rebuilt = round_trip();
        assert_eq!(rebuilt.grease, profile().client_hello.grease);
        assert!(
            rebuilt.grease.supported_versions,
            "the supported-version slot is the one an earlier version of this project's \
             documentation kept losing; a round trip that dropped it must not pass"
        );
    }

    #[test]
    fn the_key_share_groups_survive_in_order() {
        assert_eq!(
            round_trip().key_share_groups,
            profile().client_hello.key_share_groups,
            "Chrome sends two key shares and their order is observable"
        );
    }

    /// The round trip is only worth something if it can fail. Each mutation
    /// below is a translation defect a real backend could plausibly have, and
    /// each must move the fingerprint.
    #[test]
    fn a_translation_that_drops_something_fails_the_round_trip() {
        let profile = profile();
        let target = profile.ja4();

        let mut without_an_extension = RecordedClientHello::of(&profile.client_hello);
        without_an_extension.extensions.pop();
        assert_ne!(
            ja4(&without_an_extension.to_spec().expect("rebuild")),
            target,
            "dropping an extension must change JA4, or this harness proves nothing"
        );

        let mut without_a_cipher = RecordedClientHello::of(&profile.client_hello);
        without_a_cipher.cipher_suites.pop();
        assert_ne!(
            ja4(&without_a_cipher.to_spec().expect("rebuild")),
            target,
            "dropping a cipher suite must change JA4"
        );

        let mut reordered_signatures = RecordedClientHello::of(&profile.client_hello);
        reordered_signatures.signature_algorithms.reverse();
        assert_ne!(
            ja4(&reordered_signatures.to_spec().expect("rebuild")),
            target,
            "JA4 hashes signature algorithms in their offered order, unsorted, so \
             reversing them must be visible"
        );

        let mut without_alpn = RecordedClientHello::of(&profile.client_hello);
        without_alpn.alpn.clear();
        assert_ne!(
            ja4(&without_alpn.to_spec().expect("rebuild")),
            target,
            "ALPN is in JA4's first component"
        );
    }

    /// A transposition JA4 cannot see, caught by the order assertion instead.
    /// This is why `the_cipher_order_survives_the_round_trip` is a separate
    /// test rather than folded into the JA4 one.
    #[test]
    fn a_cipher_transposition_is_invisible_to_ja4_and_visible_to_the_order_check() {
        let profile = profile();
        let mut swapped = RecordedClientHello::of(&profile.client_hello);
        swapped.cipher_suites.swap(0, 1);
        let rebuilt = swapped.to_spec().expect("rebuild");

        assert_eq!(
            ja4(&rebuilt),
            profile.ja4(),
            "JA4 sorts ciphers, so a transposition does not move it"
        );
        assert_ne!(
            rebuilt.cipher_suites, profile.client_hello.cipher_suites,
            "the order check is what catches it"
        );
    }

    #[test]
    fn an_unknown_version_code_point_is_an_error_rather_than_a_silent_drop() {
        let mut recorded = RecordedClientHello::of(&profile().client_hello);
        recorded.supported_versions.push(0x0f0f);
        let error = recorded
            .to_spec()
            .expect_err("an unrecognised version must not be dropped quietly");
        assert!(
            error.to_string().contains("0x0f0f"),
            "the error must name the offending code point: {error}"
        );
    }

    #[test]
    fn the_recording_backend_reports_what_it_was_configured_with() {
        let backend = RecordingBackend::from_profile(&profile()).expect("the backend must build");
        assert_eq!(
            backend.recorded(),
            &RecordedClientHello::of(&profile().client_hello)
        );
        assert_eq!(backend.target_identity().ja4, profile().ja4());
    }
}
