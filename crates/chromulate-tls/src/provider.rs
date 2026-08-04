//! What the linked rustls can actually do, and how a profile is mapped onto it.
//!
//! Nothing in this module is a table of what rustls "should" support. Every list
//! is read out of the [`CryptoProvider`] that this build links, so the answer
//! changes when the provider changes and a stale assumption cannot survive a
//! version bump.

use std::sync::Arc;

use chromulate_core::{Error, Result};
use chromulate_fingerprint::{CipherSuite, ClientHelloSpec, NamedGroup, TlsVersion};
use rustls::crypto::CryptoProvider;
use rustls::{SupportedProtocolVersion, version};

/// The name of the cryptographic provider this build links.
///
/// `ring` is the default; `aws-lc-rs` is selected by the cargo feature of the
/// same name.
pub const PROVIDER_NAME: &str = if cfg!(feature = "aws-lc-rs") {
    "aws-lc-rs"
} else {
    "ring"
};

/// Returns the provider this build links, with its full suite and group lists.
///
/// ring is the default because a pure-Rust build that needs no C toolchain is
/// part of what this project is. The `aws-lc-rs` feature trades that for one
/// named group; see [`available_named_groups`] for which and why it matters.
#[must_use]
pub fn base_provider() -> CryptoProvider {
    #[cfg(feature = "aws-lc-rs")]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
    #[cfg(not(feature = "aws-lc-rs"))]
    {
        rustls::crypto::ring::default_provider()
    }
}

/// Returns every cipher suite the linked provider implements, in its own
/// preference order.
///
/// This is read from the provider, not from a list kept in this crate.
#[must_use]
pub fn available_cipher_suites() -> Vec<CipherSuite> {
    base_provider()
        .cipher_suites
        .iter()
        .map(|suite| CipherSuite::new(u16::from(suite.suite())))
        .collect()
}

/// Returns every key exchange group the linked provider implements, in its own
/// preference order.
///
/// The answer is provider-dependent and worth checking rather than assuming:
/// the ring provider implements `x25519`, `secp256r1` and `secp384r1` and
/// nothing else, so a profile asking for `X25519MLKEM768` — as Chrome 151 does
/// — cannot be satisfied unless the `aws-lc-rs` feature switches the build to
/// that provider.
#[must_use]
pub fn available_named_groups() -> Vec<NamedGroup> {
    base_provider()
        .kx_groups
        .iter()
        .map(|group| NamedGroup::new(u16::from(group.name())))
        .collect()
}

/// Returns `true` when the linked provider can offer this group.
#[must_use]
pub fn supports_named_group(group: NamedGroup) -> bool {
    available_named_groups().contains(&group)
}

/// Returns `true` when the linked provider can offer this cipher suite.
#[must_use]
pub fn supports_cipher_suite(suite: CipherSuite) -> bool {
    available_cipher_suites().contains(&suite)
}

/// The provider a profile asked for, alongside what had to be dropped to build
/// it.
#[derive(Debug)]
pub(crate) struct SelectedProvider {
    pub(crate) provider: Arc<CryptoProvider>,
    pub(crate) versions: Vec<&'static SupportedProtocolVersion>,
    pub(crate) offered_cipher_suites: Vec<CipherSuite>,
    pub(crate) dropped_cipher_suites: Vec<CipherSuite>,
    pub(crate) offered_groups: Vec<NamedGroup>,
    pub(crate) dropped_groups: Vec<NamedGroup>,
    pub(crate) dropped_versions: Vec<TlsVersion>,
}

impl SelectedProvider {
    /// Builds a provider that offers the profile's suites and groups, in the
    /// profile's order, skipping the ones rustls does not implement.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the profile and the provider have no
    /// cipher suite, no group, or no protocol version in common, because a
    /// configuration built from an empty intersection would fail every
    /// handshake rather than fail the build.
    pub(crate) fn for_spec(spec: &ClientHelloSpec) -> Result<Self> {
        let base = base_provider();

        let mut offered_cipher_suites = Vec::new();
        let mut dropped_cipher_suites = Vec::new();
        let mut cipher_suites = Vec::new();
        for wanted in spec.ciphers_without_grease() {
            match base
                .cipher_suites
                .iter()
                .find(|suite| u16::from(suite.suite()) == wanted.get())
            {
                Some(suite) => {
                    cipher_suites.push(*suite);
                    offered_cipher_suites.push(wanted);
                }
                None => dropped_cipher_suites.push(wanted),
            }
        }

        let mut offered_groups = Vec::new();
        let mut dropped_groups = Vec::new();
        let mut kx_groups = Vec::new();
        for wanted in spec.groups_without_grease() {
            match base
                .kx_groups
                .iter()
                .find(|group| u16::from(group.name()) == wanted.get())
            {
                Some(group) => {
                    kx_groups.push(*group);
                    offered_groups.push(wanted);
                }
                None => dropped_groups.push(wanted),
            }
        }

        let mut versions = Vec::new();
        let mut dropped_versions = Vec::new();
        for wanted in ordered_versions(spec) {
            match protocol_version(wanted) {
                Some(version) => versions.push(version),
                None => dropped_versions.push(wanted),
            }
        }

        if cipher_suites.is_empty() {
            return Err(Error::config(format!(
                "the {PROVIDER_NAME} provider implements none of the profile's {} cipher suites",
                spec.cipher_suites.len()
            )));
        }
        if kx_groups.is_empty() {
            return Err(Error::config(format!(
                "the {PROVIDER_NAME} provider implements none of the profile's {} named groups",
                spec.supported_groups.len()
            )));
        }
        if versions.is_empty() {
            return Err(Error::config(
                "the profile offers no TLS version this build supports",
            ));
        }

        Ok(Self {
            provider: Arc::new(CryptoProvider {
                cipher_suites,
                kx_groups,
                ..base
            }),
            versions,
            offered_cipher_suites,
            dropped_cipher_suites,
            offered_groups,
            dropped_groups,
            dropped_versions,
        })
    }
}

/// Returns the profile's versions highest first, which is the order rustls
/// wants and the order a ClientHello lists them in.
fn ordered_versions(spec: &ClientHelloSpec) -> Vec<TlsVersion> {
    let mut versions = spec.supported_versions.clone();
    if versions.is_empty() {
        versions.push(spec.handshake_version);
    }
    versions.sort_unstable_by(|left, right| right.cmp(left));
    versions.dedup();
    versions
}

/// Maps a modelled version onto the rustls constant, if this build has one.
///
/// TLS 1.0 and 1.1 are absent from rustls entirely, so a profile that offers
/// them loses them here rather than silently getting something else.
fn protocol_version(version: TlsVersion) -> Option<&'static SupportedProtocolVersion> {
    match version {
        TlsVersion::Tls13 => Some(&version::TLS13),
        TlsVersion::Tls12 => Some(&version::TLS12),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use chromulate_profile::Profile;

    use super::*;

    #[test]
    fn the_linked_provider_reports_its_own_group_list_rather_than_a_hard_coded_one() {
        let groups = available_named_groups();
        assert!(
            !groups.is_empty(),
            "a provider with no key exchange group cannot handshake"
        );
        assert!(
            groups.contains(&NamedGroup::X25519),
            "every rustls provider implements x25519; got {groups:?}"
        );
    }

    #[test]
    #[cfg(not(feature = "aws-lc-rs"))]
    fn the_ring_provider_offers_exactly_three_classical_groups_and_no_post_quantum_one() {
        assert_eq!(PROVIDER_NAME, "ring");
        assert_eq!(
            available_named_groups(),
            vec![
                NamedGroup::X25519,
                NamedGroup::SECP256R1,
                NamedGroup::SECP384R1
            ]
        );
        assert!(
            !supports_named_group(NamedGroup::X25519_MLKEM768),
            "ring has no ML-KEM implementation, so the Chrome profile's first group is unreachable"
        );
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn the_aws_lc_rs_provider_does_implement_the_group_chrome_asks_for_first() {
        assert_eq!(PROVIDER_NAME, "aws-lc-rs");
        assert!(
            supports_named_group(NamedGroup::X25519_MLKEM768),
            "the aws-lc-rs feature exists to make this group available; got {:?}",
            available_named_groups()
        );
    }

    #[test]
    fn the_chrome_profile_keeps_its_cipher_order_through_the_intersection() {
        let profile = Profile::chrome_stable();
        let selected = SelectedProvider::for_spec(&profile.client_hello)
            .expect("Chrome's suites overlap ring");

        let wire: Vec<CipherSuite> = selected
            .provider
            .cipher_suites
            .iter()
            .map(|suite| CipherSuite::new(u16::from(suite.suite())))
            .collect();
        assert_eq!(wire, selected.offered_cipher_suites);

        let profile_order: Vec<CipherSuite> = profile
            .client_hello
            .ciphers_without_grease()
            .filter(|suite| wire.contains(suite))
            .collect();
        assert_eq!(
            wire, profile_order,
            "the offered suites must stay in the order the profile lists them"
        );
    }

    #[test]
    fn a_suite_the_provider_lacks_is_reported_as_dropped_rather_than_ignored() {
        let profile = Profile::chrome_stable();
        let selected = SelectedProvider::for_spec(&profile.client_hello)
            .expect("Chrome's suites overlap the provider");

        let total = selected.offered_cipher_suites.len() + selected.dropped_cipher_suites.len();
        assert_eq!(total, profile.client_hello.cipher_suites.len());
        assert!(
            selected
                .dropped_cipher_suites
                .contains(&CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA),
            "rustls implements no CBC RSA suite, so it must appear as dropped"
        );
    }

    #[test]
    fn a_profile_whose_suites_are_all_unavailable_fails_the_build_loudly() {
        let mut spec = Profile::chrome_stable().client_hello;
        spec.cipher_suites = vec![CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA];
        let error = SelectedProvider::for_spec(&spec)
            .expect_err("a provider with no usable suite must not produce a config");
        assert!(matches!(error, Error::Config(_)), "got {error:?}");
    }

    #[test]
    fn versions_are_offered_highest_first_whatever_order_the_profile_lists_them() {
        let mut spec = Profile::chrome_stable().client_hello;
        spec.supported_versions = vec![TlsVersion::Tls12, TlsVersion::Tls13];
        let selected = SelectedProvider::for_spec(&spec).expect("both versions are supported");
        assert_eq!(selected.versions.len(), 2);
        assert_eq!(
            selected.versions[0].version,
            rustls::ProtocolVersion::TLSv1_3
        );
        assert!(selected.dropped_versions.is_empty());
    }

    #[test]
    fn a_version_rustls_does_not_implement_is_reported_as_dropped() {
        let mut spec = Profile::chrome_stable().client_hello;
        spec.supported_versions = vec![TlsVersion::Tls13, TlsVersion::Tls10];
        let selected = SelectedProvider::for_spec(&spec).expect("TLS 1.3 is still offered");
        assert_eq!(selected.dropped_versions, vec![TlsVersion::Tls10]);
    }
}
