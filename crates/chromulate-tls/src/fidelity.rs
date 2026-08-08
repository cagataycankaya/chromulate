//! The gap between the ClientHello a profile describes and the one rustls sends.
//!
//! This module exists so the gap is a value a caller can read, log and assert
//! on, rather than a caveat in a paragraph somebody skims. See the crate-level
//! "Fidelity limits" section for the prose version.

use std::fmt;

use chromulate_fingerprint::{CipherSuite, ClientHelloSpec, NamedGroup, TlsVersion, ja3, ja4};
use chromulate_profile::Profile;

/// The fingerprints of the ClientHello a profile *describes*.
///
/// These are the target, not a measurement. Nothing in this crate emits a
/// ClientHello with these fingerprints — see [`Fidelity`] for what is actually
/// sent. They are worth computing anyway: logging the target beside what an
/// echo endpoint reports is how you find out how far off you are, and it is the
/// seam a future custom-encoder backend is measured against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetIdentity {
    /// The JA3 string of the profile's reference extension order.
    pub ja3: String,
    /// The MD5 of [`TargetIdentity::ja3`].
    pub ja3_hash: String,
    /// The JA4 fingerprint, which is stable across the profile's extension
    /// permutations in a way JA3 is not.
    pub ja4: String,
}

impl TargetIdentity {
    /// Computes the identity of a ClientHello specification.
    #[must_use]
    pub fn of(spec: &ClientHelloSpec) -> Self {
        let ja3 = ja3(spec);
        Self {
            ja3_hash: chromulate_fingerprint::ja3_hash(&ja3),
            ja3,
            ja4: ja4(spec),
        }
    }
}

impl fmt::Display for TargetIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ja4={} ja3={}", self.ja4, self.ja3_hash)
    }
}

/// Returns the ClientHello a profile is asking for.
///
/// This is the input to the configuration, and the thing the emitted handshake
/// is compared against.
#[must_use]
pub fn target_client_hello(profile: &Profile) -> &ClientHelloSpec {
    &profile.client_hello
}

/// Computes the JA3 and JA4 a profile is aiming at.
#[must_use]
pub fn target_identity(profile: &Profile) -> TargetIdentity {
    TargetIdentity::of(&profile.client_hello)
}

/// The parts of the target ClientHello that no rustls configuration can
/// reproduce, whatever the profile says.
///
/// These are structural: they are properties of rustls's ClientHello encoder,
/// not of the profile, so they hold for every profile and every host, and
/// neither cargo feature shortens the list. The profile-side model is exact —
/// that is what the fingerprint crate's golden tests establish — so everything
/// here is a gap between an accurate model and what the encoder will emit. A
/// backend that encodes its own ClientHello would close them; rustls cannot.
///
/// Each entry was observed, not inferred from reading rustls: they are the
/// findings of `tests/emitted_client_hello.rs`, which decodes the bytes a real
/// `ClientConnection` writes and compares them to the Chrome 151 profile.
pub const STRUCTURAL_LIMITS: &[&str] = &[
    "GREASE is never emitted, in any of the six positions the profile marks (first cipher, \
     first and last extension, first supported group, first key share, first supported version)",
    "the extension permutation is rustls's own; it randomises per connection as the profile \
     expects, but by a different rule and without the GREASE brackets that frame Chrome's list",
    "extensions with no rustls equivalent are absent: signed_certificate_timestamp, \
     application_settings (ALPS) and encrypted_client_hello",
    "renegotiation_info is signalled by the TLS_EMPTY_RENEGOTIATION_INFO_SCSV cipher suite \
     rather than the extension the profile lists, which adds a tenth cipher suite",
    "signature_algorithms comes from the provider and is neither reordered nor trimmed to the \
     profile's list",
    "the number of key shares is rustls's decision, not the profile's key_share_groups list",
];

/// What a built [`crate::TlsEngine`] will and will not reproduce.
///
/// Every list here is derived from the profile and the linked provider at build
/// time, so it describes this configuration rather than TLS in general.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fidelity {
    /// The provider backing the configuration, `ring` or `aws-lc-rs`.
    pub provider: &'static str,
    /// Cipher suites offered, in the profile's order.
    pub offered_cipher_suites: Vec<CipherSuite>,
    /// Cipher suites the profile lists that the provider does not implement.
    pub dropped_cipher_suites: Vec<CipherSuite>,
    /// Named groups offered, in the profile's order.
    pub offered_groups: Vec<NamedGroup>,
    /// Named groups the profile lists that the provider does not implement.
    pub dropped_groups: Vec<NamedGroup>,
    /// Protocol versions the profile lists that rustls does not implement.
    pub dropped_versions: Vec<TlsVersion>,
    /// ALPN identifiers, which are sent exactly as the profile lists them.
    pub alpn: Vec<String>,
    /// The fingerprints of the ClientHello the profile describes.
    pub target: TargetIdentity,
    /// The ways this backend's encoder departs from the profile, whatever
    /// backend it is.
    ///
    /// [`STRUCTURAL_LIMITS`] is the rustls engine's answer and was, until
    /// 2026-08-08, the only one: it is a module constant, and [`fmt::Display`]
    /// read its length directly. That made the field
    /// [`TlsBackendConfig::fidelity`](crate::TlsBackendConfig::fidelity) exists
    /// to publish unpublishable by any other backend — a BoringSSL
    /// implementation closing every one of the six would still have printed
    /// "6 structural limits", and one with a different limit could not have
    /// named it.
    ///
    /// An empty slice is the honest value for a backend that departs from the
    /// profile in no way at all, and [`Display`](fmt::Display) says so rather
    /// than printing a count of zero.
    pub structural_limits: &'static [&'static str],
}

impl Fidelity {
    /// Returns `true` when every cipher suite, group and version the profile
    /// asks for survived into the configuration.
    ///
    /// Even when this is `true` the emitted ClientHello is not the profile's:
    /// [`STRUCTURAL_LIMITS`] still applies. This answers the narrower question
    /// "did the provider have everything the profile named?".
    #[must_use]
    pub fn all_primitives_available(&self) -> bool {
        self.dropped_cipher_suites.is_empty()
            && self.dropped_groups.is_empty()
            && self.dropped_versions.is_empty()
    }

    /// Returns the share of the profile's cipher suites that are offered, as a
    /// count over a total, for logging.
    #[must_use]
    pub fn cipher_coverage(&self) -> (usize, usize) {
        (
            self.offered_cipher_suites.len(),
            self.offered_cipher_suites.len() + self.dropped_cipher_suites.len(),
        )
    }

    /// Returns the share of the profile's named groups that are offered.
    #[must_use]
    pub fn group_coverage(&self) -> (usize, usize) {
        (
            self.offered_groups.len(),
            self.offered_groups.len() + self.dropped_groups.len(),
        )
    }
}

impl fmt::Display for Fidelity {
    /// Writes the one-line summary that belongs in a startup log: the target
    /// fingerprint, what was dropped, and a reminder that the wire form differs
    /// from the target even when nothing was dropped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (suites, suites_total) = self.cipher_coverage();
        let (groups, groups_total) = self.group_coverage();
        write!(
            f,
            "provider={} suites={suites}/{suites_total} groups={groups}/{groups_total} \
             alpn={} target={} dropped_suites=[{}] dropped_groups=[{}] ",
            self.provider,
            self.alpn.join(","),
            self.target,
            hex_list(&self.dropped_cipher_suites),
            hex_list(&self.dropped_groups),
        )?;
        // Reads the backend's own list rather than `STRUCTURAL_LIMITS`, which
        // describes rustls. A backend that has closed all of them says so.
        if self.structural_limits.is_empty() {
            f.write_str("(the emitted ClientHello has no known structural departures)")
        } else {
            write!(
                f,
                "(the emitted ClientHello is not byte-exact: {} structural limits)",
                self.structural_limits.len(),
            )
        }
    }
}

/// Renders code points as hex, the form the capture file and Wireshark use.
pub(crate) fn hex_list<T: Copy + Into<u16>>(values: &[T]) -> String {
    values
        .iter()
        .map(|value| format!("{:#06x}", (*value).into()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_identity_is_the_profiles_own_fingerprint() {
        let profile = Profile::chrome_stable();
        let identity = target_identity(&profile);
        assert_eq!(identity.ja4, profile.ja4());
        assert_eq!(identity.ja3, profile.ja3());
        assert_eq!(identity.ja3_hash, profile.ja3_hash());
        assert_eq!(identity.ja4, "t13d1516h2_8daaf6152771_806a8c22fdea");
    }

    #[test]
    fn target_client_hello_hands_back_the_profiles_own_spec() {
        let profile = Profile::chrome_stable();
        assert_eq!(target_client_hello(&profile), &profile.client_hello);
    }

    #[test]
    fn code_points_are_rendered_as_hex_so_a_log_line_matches_the_capture() {
        assert_eq!(
            hex_list(&[CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA]),
            "0x002f"
        );
        assert_eq!(hex_list::<CipherSuite>(&[]), "");
    }

    /// Builds a `Fidelity` that differs from the rustls engine's only in the
    /// limits it declares.
    fn fidelity_declaring(limits: &'static [&'static str]) -> Fidelity {
        let profile = Profile::chrome_stable();
        Fidelity {
            provider: "test",
            offered_cipher_suites: profile.client_hello.cipher_suites.clone(),
            dropped_cipher_suites: Vec::new(),
            offered_groups: profile.client_hello.supported_groups.clone(),
            dropped_groups: Vec::new(),
            dropped_versions: Vec::new(),
            alpn: profile.client_hello.alpn.clone(),
            target: target_identity(&profile),
            structural_limits: limits,
        }
    }

    #[test]
    fn a_backend_reports_its_own_structural_limits_rather_than_the_rustls_list() {
        // Until 2026-08-08 `Display` read `STRUCTURAL_LIMITS.len()` directly, so
        // every backend printed six however many it actually had. Two limits
        // here, and six in the constant, so the numbers cannot coincide.
        let fidelity = fidelity_declaring(&["one thing", "another thing"]);
        assert_eq!(STRUCTURAL_LIMITS.len(), 6);
        assert!(
            fidelity.to_string().contains("2 structural limits"),
            "a backend declaring two limits must print two, got: {fidelity}"
        );
    }

    #[test]
    fn a_backend_with_no_structural_limits_says_so_instead_of_counting_zero() {
        // The claim a byte-exact backend gets to make. "0 structural limits"
        // would be arithmetically right and would read as a bug.
        let fidelity = fidelity_declaring(&[]);
        let rendered = fidelity.to_string();
        assert!(
            rendered.contains("no known structural departures"),
            "got: {rendered}"
        );
        assert!(!rendered.contains("0 structural limits"), "got: {rendered}");
    }
}
