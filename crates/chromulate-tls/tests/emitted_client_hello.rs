//! What rustls actually puts on the wire, parsed back out of the bytes.
//!
//! The crate documentation claims the emitted ClientHello is not the profile's
//! ClientHello. These tests are why that claim can be made: they take the bytes
//! a real `ClientConnection` produces, decode them, and compare the result
//! against the Chrome 151 profile field by field. Nothing here is asserted from
//! reading rustls's source — if a rustls upgrade changes the emitted hello,
//! these tests fail and the documentation gets corrected.

use std::sync::Arc;

use chromulate_fingerprint::{
    CertificateCompression, CipherSuite, ClientHelloSpec, EcPointFormat, ExtensionId,
    ExtensionOrder, ExtensionSet, GreasePlacement, NamedGroup, PskKeyExchangeMode, SignatureScheme,
    TlsVersion, Transport, WireExtensionOrder, ja4,
};
use chromulate_profile::Profile;
use chromulate_tls::TlsEngine;
use rustls::ClientConnection;
use rustls_pki_types::ServerName;

mod common;

use common::{EmittedHello, parse};

/// Produces the ClientHello an engine sends to a given name.
///
/// The one part of this file that cannot be shared with the BoringSSL test:
/// rustls hands its first flight to a `Write` sink, so no socket is needed to
/// see it.
fn emit(engine: &TlsEngine, name: ServerName<'static>) -> EmittedHello {
    let mut connection = ClientConnection::new(Arc::clone(engine.client_config()), name)
        .expect("a configured engine must be able to start a connection");

    let mut wire = Vec::new();
    connection
        .write_tls(&mut wire)
        .expect("writing to a Vec cannot fail");

    parse(&wire)
}

fn chrome_engine() -> TlsEngine {
    TlsEngine::new(&Profile::chrome_stable()).expect("the Chrome profile must build an engine")
}

fn name(host: &str) -> ServerName<'static> {
    chromulate_tls::server_name(host).expect("the test host must be usable")
}

#[test]
fn the_emitted_cipher_suites_are_the_profiles_suites_in_the_profiles_order_with_no_grease() {
    let engine = chrome_engine();
    let hello = emit(&engine, name("example.com"));

    let offered: Vec<u16> = engine
        .fidelity()
        .offered_cipher_suites
        .iter()
        .map(|suite| suite.get())
        .collect();

    assert_eq!(offered.len(), 9, "ring implements 9 of the profile's 15");
    assert_eq!(
        hello.cipher_suites,
        [offered.as_slice(), &[0x00ff]].concat(),
        "the profile's suites in the profile's order, then the renegotiation SCSV"
    );
    assert!(
        !hello
            .cipher_suites
            .iter()
            .any(|suite| suite & 0x0f0f == 0x0a0a),
        "rustls emits no GREASE cipher, so none may appear: {:04x?}",
        hello.cipher_suites
    );
}

#[test]
fn the_renegotiation_scsv_is_what_rustls_sends_instead_of_the_renegotiation_extension() {
    let profile = Profile::chrome_stable();
    let with_tls12 = emit(&chrome_engine(), name("example.com"));

    assert_eq!(
        with_tls12.cipher_suites.last(),
        Some(&0x00ff),
        "the SCSV is appended whenever TLS 1.2 is offered"
    );
    assert!(
        !with_tls12.extensions.contains(&0xff01),
        "rustls signals renegotiation with the SCSV cipher, not the extension"
    );
    assert!(
        profile
            .client_hello
            .extensions
            .contains(chromulate_fingerprint::ExtensionId::RENEGOTIATION_INFO),
        "Chrome signals it the other way round, with extension 0xff01"
    );

    let mut tls13_only = profile.clone();
    tls13_only.client_hello.supported_versions = vec![TlsVersion::Tls13];
    let engine = TlsEngine::new(&tls13_only).expect("a TLS 1.3 only engine must build");
    let hello = emit(&engine, name("example.com"));
    assert!(
        !hello.cipher_suites.contains(&0x00ff),
        "with TLS 1.2 off the SCSV goes away: {:04x?}",
        hello.cipher_suites
    );
}

#[test]
fn the_emitted_alpn_list_is_exactly_the_captured_one() {
    let hello = emit(&chrome_engine(), name("example.com"));
    assert_eq!(hello.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
}

#[test]
fn a_domain_target_sends_sni_and_an_ip_literal_target_does_not() {
    let engine = chrome_engine();

    let domain = emit(&engine, name("example.com"));
    assert_eq!(domain.server_name.as_deref(), Some("example.com"));
    assert!(domain.extensions.contains(&0x0000));

    for literal in ["93.184.215.14", "[::1]"] {
        let address = emit(&engine, name(literal));
        assert_eq!(
            address.server_name, None,
            "{literal} must not appear in SNI"
        );
        assert!(
            !address.extensions.contains(&0x0000),
            "{literal} must not carry a server_name extension at all"
        );
    }
}

#[test]
fn the_emitted_groups_are_the_profiles_groups_the_provider_implements_in_order() {
    let engine = chrome_engine();
    let hello = emit(&engine, name("example.com"));

    let offered: Vec<u16> = engine
        .fidelity()
        .offered_groups
        .iter()
        .map(|group| group.get())
        .collect();
    assert_eq!(hello.supported_groups, offered);

    assert!(
        !hello.supported_groups.contains(&0x11ec)
            || chromulate_tls::supports_named_group(NamedGroup::X25519_MLKEM768),
        "X25519MLKEM768 may only be offered by a provider that implements it"
    );
    assert!(
        !hello
            .supported_groups
            .iter()
            .any(|group| group & 0x0f0f == 0x0a0a),
        "no GREASE group is emitted"
    );
}

#[test]
fn the_emitted_versions_are_tls13_then_tls12_and_carry_no_grease() {
    let hello = emit(&chrome_engine(), name("example.com"));
    assert_eq!(hello.supported_versions, vec![0x0304, 0x0303]);
    assert_eq!(
        hello.handshake_version, 0x0303,
        "the handshake header still says TLS 1.2, as the capture does"
    );
}

#[test]
fn the_number_of_key_shares_depends_on_the_provider_not_on_the_profile() {
    let engine = chrome_engine();
    let hello = emit(&engine, name("example.com"));
    let profile = Profile::chrome_stable();

    let wanted: Vec<u16> = profile
        .client_hello
        .key_share_groups
        .iter()
        .copied()
        .map(NamedGroup::get)
        .collect();
    assert_eq!(
        wanted,
        vec![0x11ec, 0x001d],
        "the capture shows Chrome sending shares for X25519MLKEM768 and X25519"
    );

    if chromulate_tls::supports_named_group(NamedGroup::X25519_MLKEM768) {
        // A hybrid group carries its classical companion, so the aws-lc-rs
        // build happens to send exactly the pair the capture shows.
        assert_eq!(
            hello.key_share_groups, wanted,
            "the aws-lc-rs build should match the capture's key shares"
        );
    } else {
        assert_eq!(
            hello.key_share_groups.len(),
            1,
            "without a hybrid group rustls sends a share for its first group only: {:04x?}",
            hello.key_share_groups
        );
        assert_eq!(
            hello.key_share_groups[0],
            engine.fidelity().offered_groups[0].get()
        );
    }
}

#[test]
fn the_emitted_extension_set_differs_from_the_profiles_in_both_directions() {
    let hello = emit(&chrome_engine(), name("example.com"));
    let profile = Profile::chrome_stable();

    let wanted: Vec<u16> = profile
        .client_hello
        .extensions
        .iter()
        .map(ExtensionId::get)
        .collect();

    let missing: Vec<u16> = wanted
        .iter()
        .copied()
        .filter(|id| !hello.extensions.contains(id))
        .collect();
    let extra: Vec<u16> = hello
        .extensions
        .iter()
        .copied()
        .filter(|id| !wanted.contains(id))
        .collect();

    // signed_certificate_timestamp, application_settings (ALPS) and
    // encrypted_client_hello have no rustls equivalent, and renegotiation_info
    // is replaced by the SCSV cipher suite. compress_certificate joins them
    // when the `cert-compression` feature is off.
    let expected_missing: Vec<u16> = if cfg!(feature = "cert-compression") {
        vec![0x0012, 0x44cd, 0xfe0d, 0xff01]
    } else {
        vec![0x0012, 0x001b, 0x44cd, 0xfe0d, 0xff01]
    };
    assert_eq!(missing, expected_missing);
    assert!(
        extra.is_empty(),
        "rustls sends nothing the profile does not list: {extra:04x?}"
    );
    assert_eq!(
        hello.extensions.len(),
        wanted.len() - expected_missing.len(),
        "every profile extension is either emitted or accounted for as missing"
    );
}

#[test]
fn no_grease_appears_anywhere_in_the_emitted_extension_list() {
    let hello = emit(&chrome_engine(), name("example.com"));
    assert!(
        !hello.extensions.iter().any(|id| id & 0x0f0f == 0x0a0a),
        "the profile marks six GREASE positions; rustls fills none of them: {:04x?}",
        hello.extensions
    );
}

#[test]
fn the_extension_order_is_reshuffled_per_connection_as_the_profile_expects() {
    let engine = chrome_engine();
    let orders: Vec<Vec<u16>> = (0..16)
        .map(|_| emit(&engine, name("example.com")).extensions)
        .collect();

    let distinct: std::collections::BTreeSet<&Vec<u16>> = orders.iter().collect();
    assert!(
        distinct.len() > 1,
        "rustls seeds a fresh extension order per connection; 16 connections gave one order"
    );

    let reference: std::collections::BTreeSet<u16> = orders[0].iter().copied().collect();
    for order in &orders {
        let set: std::collections::BTreeSet<u16> = order.iter().copied().collect();
        assert_eq!(set, reference, "only the order changes, never the set");
    }

    assert!(
        Profile::chrome_stable()
            .client_hello
            .extension_order
            .is_shuffled(),
        "the profile being reproduced also permutes, so this behaviour matches it"
    );
}

#[test]
fn the_signature_algorithms_are_the_providers_list_not_the_profiles() {
    let hello = emit(&chrome_engine(), name("example.com"));
    let profile: Vec<u16> = Profile::chrome_stable()
        .client_hello
        .signature_algorithms
        .iter()
        .copied()
        .map(SignatureScheme::get)
        .collect();

    assert_ne!(
        hello.signature_algorithms, profile,
        "rustls offers what its provider verifies, in its own order"
    );
    assert!(
        !hello.signature_algorithms.is_empty(),
        "some signature algorithms must be offered"
    );
}

#[test]
#[cfg(feature = "cert-compression")]
fn certificate_compression_is_offered_with_brotli_as_the_capture_shows() {
    let hello = emit(&chrome_engine(), name("example.com"));
    assert_eq!(
        hello.certificate_compression,
        vec![0x0002],
        "the capture offers brotli only"
    );
}

#[test]
#[cfg(not(feature = "cert-compression"))]
fn certificate_compression_is_absent_without_the_feature() {
    let hello = emit(&chrome_engine(), name("example.com"));
    assert!(hello.certificate_compression.is_empty());
    assert!(!hello.extensions.contains(&0x001b));
}

#[test]
fn the_fingerprint_of_what_is_sent_is_not_the_fingerprint_of_the_profile() {
    let engine = chrome_engine();
    let emitted: Vec<String> = (0..4)
        .map(|_| ja4(&spec_of(&emit(&engine, name("example.com")))))
        .collect();

    assert!(
        emitted.windows(2).all(|pair| pair[0] == pair[1]),
        "JA4 sorts what rustls shuffles, so it should be stable: {emitted:?}"
    );

    let target = &engine.target_identity().ja4;
    assert_ne!(
        &emitted[0], target,
        "if these ever match, the Fidelity limits section is out of date and should say so"
    );

    // Recorded so a change in either direction shows up in a diff rather than
    // only in a failure message. The two providers offer different signature
    // algorithm lists, which is the component that differs between them.
    assert_eq!(target, "t13d1516h2_8daaf6152771_806a8c22fdea");
    let expected = match (
        chromulate_tls::PROVIDER_NAME,
        cfg!(feature = "cert-compression"),
    ) {
        ("aws-lc-rs", true) => "t13d1012h2_61a7ad8aa9b6_41631feb4e62",
        ("aws-lc-rs", false) => "t13d1011h2_61a7ad8aa9b6_f9531d972513",
        (_, true) => "t13d1012h2_61a7ad8aa9b6_69ed562cf35e",
        (_, false) => "t13d1011h2_61a7ad8aa9b6_3fcd1a44f3e3",
    };
    assert_eq!(emitted[0], expected);
}

/// Rebuilds a fingerprintable specification from the decoded bytes.
///
/// Fields the wire does not carry are filled from what was parsed, never from
/// the profile, so the fingerprint describes the emitted hello alone.
fn spec_of(hello: &EmittedHello) -> ClientHelloSpec {
    ClientHelloSpec {
        transport: Transport::Tcp,
        record_version: TlsVersion::from_u16(hello.record_version)
            .expect("the emitted record version must be a modelled one"),
        handshake_version: TlsVersion::from_u16(hello.handshake_version)
            .expect("the emitted handshake version must be a modelled one"),
        supported_versions: hello
            .supported_versions
            .iter()
            .filter_map(|version| TlsVersion::from_u16(*version))
            .collect(),
        cipher_suites: hello
            .cipher_suites
            .iter()
            .copied()
            .map(CipherSuite::new)
            .collect(),
        extensions: ExtensionSet::new(hello.extensions.iter().copied().map(ExtensionId::new)),
        extension_order: ExtensionOrder::Fixed(
            WireExtensionOrder::new(
                hello
                    .extensions
                    .iter()
                    .copied()
                    .map(ExtensionId::new)
                    .collect(),
            )
            .expect("an emitted order must satisfy the wire invariants"),
        ),
        supported_groups: hello
            .supported_groups
            .iter()
            .copied()
            .map(NamedGroup::new)
            .collect(),
        key_share_groups: hello
            .key_share_groups
            .iter()
            .copied()
            .map(NamedGroup::new)
            .collect(),
        signature_algorithms: hello
            .signature_algorithms
            .iter()
            .copied()
            .map(SignatureScheme::new)
            .collect(),
        alpn: hello.alpn.clone(),
        alps: Vec::new(),
        certificate_compression: hello
            .certificate_compression
            .iter()
            .copied()
            .map(CertificateCompression::from)
            .collect(),
        psk_key_exchange_modes: hello
            .psk_key_exchange_modes
            .iter()
            .copied()
            .map(PskKeyExchangeMode::from)
            .collect(),
        ec_point_formats: hello
            .ec_point_formats
            .iter()
            .copied()
            .map(EcPointFormat::from)
            .collect(),
        grease: GreasePlacement::NONE,
    }
}
