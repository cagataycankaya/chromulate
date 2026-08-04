//! Golden tests against the live Chrome 151 capture.
//!
//! Every expected value here appears twice: once as the field recorded in
//! `data/chrome-151-macos.json`, and once as a literal. The recorded field
//! proves the computation matches the capture; the literal proves the capture
//! itself has not been quietly edited to match a broken computation.

use chromulate_fingerprint::{
    Capture, CipherSuite, ClientHelloSpec, ExtensionId, ExtensionOrder, GreaseValue, NamedGroup,
    SignatureScheme, akamai_http2, akamai_http2_hash, ja3, ja3_hash, ja4, ja4_raw,
};

const CAPTURE_JSON: &str = include_str!("data/chrome-151-macos.json");

fn capture() -> Capture {
    Capture::parse(CAPTURE_JSON).expect("the shipped capture must parse")
}

/// The Chrome spec exactly as captured, with the extension order pinned to the
/// one the navigate sample recorded.
fn navigate_spec(capture: &Capture) -> ClientHelloSpec {
    let mut spec = capture
        .client_hello()
        .expect("the capture must yield a ClientHello spec");
    spec.extension_order = ExtensionOrder::Fixed(
        capture
            .sample_navigate
            .ja3_extension_order()
            .expect("the recorded JA3 must yield an extension order"),
    );
    spec
}

/// The same browser on a resumed connection: the base spec plus
/// `pre_shared_key`, with the order the clean sample recorded.
fn clean_spec(capture: &Capture) -> ClientHelloSpec {
    let clean = capture
        .sample_clean
        .as_ref()
        .expect("the capture must carry a resumed sample");
    let mut spec = navigate_spec(capture).with_pre_shared_key();
    spec.extension_order = ExtensionOrder::Fixed(
        clean
            .ja3_extension_order()
            .expect("the recorded JA3 must yield an extension order"),
    );
    spec
}

#[test]
fn ja3_reproduces_the_captured_string_for_a_fresh_connection() {
    let capture = capture();
    let computed = ja3(&navigate_spec(&capture));

    assert_eq!(computed, capture.sample_navigate.ja3);
    assert_eq!(
        computed,
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
         0-51-45-35-16-5-27-18-23-11-17613-65281-43-13-65037-10,4588-29-23-24,0"
    );
}

#[test]
fn ja3_reproduces_the_captured_string_for_a_resumed_connection() {
    let capture = capture();
    let clean = capture
        .sample_clean
        .as_ref()
        .expect("the capture must carry a resumed sample");
    let computed = ja3(&clean_spec(&capture));

    assert_eq!(computed, clean.ja3);
    assert_eq!(
        computed,
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
         16-35-0-5-27-43-23-10-45-65281-17613-51-13-18-65037-11-41,4588-29-23-24,0"
    );
}

#[test]
fn ja3_hashes_match_the_captured_md5_digests() {
    let capture = capture();
    let clean = capture
        .sample_clean
        .as_ref()
        .expect("the capture must carry a resumed sample");

    let navigate_hash = ja3_hash(&ja3(&navigate_spec(&capture)));
    assert_eq!(navigate_hash, capture.sample_navigate.ja3_hash);
    assert_eq!(navigate_hash, "a0442bdf8e49e27cb5ee80009f29a6a2");

    let clean_hash = ja3_hash(&ja3(&clean_spec(&capture)));
    assert_eq!(clean_hash, clean.ja3_hash);
    assert_eq!(clean_hash, "43b2a31e00f7c2151cef4cd21c7c58f7");

    assert_ne!(
        navigate_hash, clean_hash,
        "the same browser must produce different JA3 hashes on two connections"
    );
}

#[test]
fn ja4_reproduces_the_captured_fingerprint_for_both_connections() {
    let capture = capture();
    let clean = capture
        .sample_clean
        .as_ref()
        .expect("the capture must carry a resumed sample");

    let navigate = ja4(&navigate_spec(&capture));
    assert_eq!(navigate, capture.sample_navigate.ja4);
    assert_eq!(navigate, "t13d1516h2_8daaf6152771_806a8c22fdea");

    let resumed = ja4(&clean_spec(&capture));
    assert_eq!(resumed, clean.ja4);
    assert_eq!(resumed, "t13d1517h2_8daaf6152771_a87ad97598a9");
}

#[test]
fn the_ja4_cipher_component_is_identical_across_connections() {
    let capture = capture();
    let navigate = ja4(&navigate_spec(&capture));
    let resumed = ja4(&clean_spec(&capture));

    let cipher_component = |fingerprint: &str| {
        fingerprint
            .split('_')
            .nth(1)
            .expect("a JA4 fingerprint has three components")
            .to_owned()
    };

    assert_eq!(cipher_component(&navigate), cipher_component(&resumed));
    assert_eq!(cipher_component(&navigate), "8daaf6152771");
}

#[test]
fn ja4_raw_reproduces_the_captured_lists_for_both_connections() {
    let capture = capture();
    let clean = capture
        .sample_clean
        .as_ref()
        .expect("the capture must carry a resumed sample");

    assert_eq!(
        ja4_raw(&navigate_spec(&capture)),
        capture.sample_navigate.ja4_r
    );
    assert_eq!(ja4_raw(&clean_spec(&capture)), clean.ja4_r);
}

#[test]
fn ja4_is_stable_no_matter_how_the_extensions_are_permuted() {
    let capture = capture();
    let shuffling = capture
        .client_hello()
        .expect("the capture must yield a ClientHello spec");
    let pinned = navigate_spec(&capture);

    assert!(
        shuffling.extension_order.is_shuffled(),
        "the capture records a verified finding that Chrome shuffles"
    );
    assert_eq!(ja4(&shuffling), ja4(&pinned));
    assert_eq!(ja4(&shuffling), "t13d1516h2_8daaf6152771_806a8c22fdea");
}

#[test]
fn the_akamai_http2_fingerprint_matches_the_capture() {
    let capture = capture();
    let spec = capture
        .http2()
        .expect("the capture must yield an HTTP/2 spec");
    let fingerprint = akamai_http2(&spec);

    assert_eq!(fingerprint, capture.sample_navigate.akamai_fingerprint);
    assert_eq!(
        fingerprint,
        "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    );

    let hash = akamai_http2_hash(&fingerprint);
    assert_eq!(hash, capture.sample_navigate.akamai_fingerprint_hash);
    assert_eq!(hash, "52d84b11737d980aef856699f885ca86");
}

#[test]
fn the_captured_headers_frame_priority_is_preserved_without_entering_the_fingerprint() {
    let capture = capture();
    let spec = capture
        .http2()
        .expect("the capture must yield an HTTP/2 spec");
    let priority = spec
        .headers_priority
        .expect("the capture records HEADERS frame priority fields");

    assert_eq!(priority.weight, 256);
    assert_eq!(priority.depends_on, 0);
    assert!(priority.exclusive);
    assert!(
        spec.priority_frames.is_empty(),
        "Chrome 151 sends no PRIORITY frames, which is why the third field is 0"
    );
}

#[test]
fn two_connections_permute_the_extensions_but_offer_the_same_set() {
    let capture = capture();
    let spec = capture
        .client_hello()
        .expect("the capture must yield a ClientHello spec");

    let first = spec.wire_extension_order_seeded(11);
    let second = spec.wire_extension_order_seeded(12);
    assert_ne!(first.as_slice(), second.as_slice());

    let mut left: Vec<ExtensionId> = first.without_grease().collect();
    let mut right: Vec<ExtensionId> = second.without_grease().collect();
    left.sort_unstable();
    right.sort_unstable();
    assert_eq!(left, right);
    assert_eq!(left, spec.extensions.sorted());
}

#[test]
fn every_generated_order_is_bracketed_by_grease_with_pre_shared_key_last() {
    let capture = capture();
    let resumed = capture
        .client_hello()
        .expect("the capture must yield a ClientHello spec")
        .with_pre_shared_key();

    for seed in 0..128 {
        let order = resumed.wire_extension_order_seeded(seed);
        let ids = order.as_slice();

        assert!(
            ids[0].is_grease(),
            "seed {seed}: the first slot must be GREASE"
        );
        assert_eq!(
            ids[ids.len() - 1],
            ExtensionId::PRE_SHARED_KEY,
            "seed {seed}: pre_shared_key must be the final extension"
        );
        assert!(
            ids[ids.len() - 2].is_grease(),
            "seed {seed}: the last slot before pre_shared_key must be GREASE"
        );
        assert!(
            GreaseValue::new(ids[0].get()).is_some(),
            "seed {seed}: the leading GREASE must be a reserved value"
        );
        assert_ne!(
            ids[0],
            ids[ids.len() - 2],
            "seed {seed}: RFC 8701 requires the two GREASE values to differ"
        );
    }
}

#[test]
fn the_cipher_order_is_never_shuffled() {
    let capture = capture();
    let spec = capture
        .client_hello()
        .expect("the capture must yield a ClientHello spec");
    let expected: Vec<u16> = spec.ciphers_without_grease().map(|c| c.get()).collect();

    assert_eq!(
        expected,
        vec![
            4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47,
            53
        ]
    );

    for seed in 0..64 {
        let wire = spec.wire_cipher_suites_seeded(seed);
        assert!(
            wire[0].is_grease(),
            "seed {seed}: Chrome offers a GREASE suite first"
        );
        let offered: Vec<u16> = wire[1..].iter().map(|suite| suite.get()).collect();
        assert_eq!(
            offered, expected,
            "seed {seed}: the cipher order must never move"
        );
    }
}

#[test]
fn the_resumed_extension_set_matches_the_captured_resumption_listing() {
    let capture = capture();
    let resumed = capture
        .client_hello()
        .expect("the capture must yield a ClientHello spec")
        .with_pre_shared_key();
    let recorded = capture
        .resumption_extensions()
        .expect("the capture lists the resumption extension set")
        .with(ExtensionId::SERVER_NAME);

    assert_eq!(resumed.extensions, recorded);
    assert!(resumed.extensions.contains(ExtensionId::PRE_SHARED_KEY));
    assert_eq!(resumed.extensions.len(), 17);
}

#[test]
fn every_named_cipher_constant_matches_the_name_the_capture_recorded_for_it() {
    // Driven by the capture's parallel `cipher_suite_names` array: a swapped
    // pair here would still produce the right JA3, because JA3 only sees the
    // numbers, so the names have to be checked against the capture directly.
    let expected: [(CipherSuite, &str); 15] = [
        (
            CipherSuite::TLS_AES_128_GCM_SHA256,
            "TLS_AES_128_GCM_SHA256",
        ),
        (
            CipherSuite::TLS_AES_256_GCM_SHA384,
            "TLS_AES_256_GCM_SHA384",
        ),
        (
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            "TLS_CHACHA20_POLY1305_SHA256",
        ),
        (
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ),
        (
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ),
        (
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        (
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        (
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        ),
        (
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        ),
        (
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
        ),
        (
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            "TLS_RSA_WITH_AES_128_CBC_SHA",
        ),
        (
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            "TLS_RSA_WITH_AES_256_CBC_SHA",
        ),
    ];

    let document: serde_json::Value =
        serde_json::from_str(CAPTURE_JSON).expect("the capture must be JSON");
    let values = document["client_hello"]["cipher_suites_in_wire_order"]
        .as_array()
        .expect("the capture lists cipher suites");
    let names = document["client_hello"]["cipher_suite_names"]
        .as_array()
        .expect("the capture names its cipher suites");
    assert_eq!(values.len(), names.len());

    for (constant, name) in expected {
        let index = names
            .iter()
            .position(|recorded| recorded == name)
            .unwrap_or_else(|| panic!("the capture does not record a suite named {name}"));
        assert_eq!(
            u64::from(constant.get()),
            values[index]
                .as_u64()
                .expect("a named suite has a numeric code point"),
            "the constant for {name} does not match the captured code point"
        );
    }
}

#[test]
fn every_named_group_constant_matches_the_name_the_capture_recorded_for_it() {
    let expected: [(NamedGroup, &str); 4] = [
        (NamedGroup::X25519_MLKEM768, "X25519MLKEM768"),
        (NamedGroup::X25519, "X25519"),
        (NamedGroup::SECP256R1, "secp256r1"),
        (NamedGroup::SECP384R1, "secp384r1"),
    ];

    let document: serde_json::Value =
        serde_json::from_str(CAPTURE_JSON).expect("the capture must be JSON");
    let values = document["client_hello"]["supported_groups"]
        .as_array()
        .expect("the capture lists supported groups");
    let names = document["client_hello"]["supported_group_names"]
        .as_array()
        .expect("the capture names its supported groups");

    for (constant, name) in expected {
        let index = names
            .iter()
            .position(|recorded| recorded == name)
            .unwrap_or_else(|| panic!("the capture does not record a group named {name}"));
        assert_eq!(
            u64::from(constant.get()),
            values[index]
                .as_u64()
                .expect("a named group has a numeric code point")
        );
    }
}

#[test]
fn every_named_signature_scheme_matches_the_name_the_capture_recorded_for_it() {
    let expected: [(SignatureScheme, &str); 8] = [
        (
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            "ecdsa_secp256r1_sha256",
        ),
        (SignatureScheme::RSA_PSS_RSAE_SHA256, "rsa_pss_rsae_sha256"),
        (SignatureScheme::RSA_PKCS1_SHA256, "rsa_pkcs1_sha256"),
        (
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            "ecdsa_secp384r1_sha384",
        ),
        (SignatureScheme::RSA_PSS_RSAE_SHA384, "rsa_pss_rsae_sha384"),
        (SignatureScheme::RSA_PKCS1_SHA384, "rsa_pkcs1_sha384"),
        (SignatureScheme::RSA_PSS_RSAE_SHA512, "rsa_pss_rsae_sha512"),
        (SignatureScheme::RSA_PKCS1_SHA512, "rsa_pkcs1_sha512"),
    ];

    let document: serde_json::Value =
        serde_json::from_str(CAPTURE_JSON).expect("the capture must be JSON");
    let values = document["client_hello"]["signature_algorithms"]
        .as_array()
        .expect("the capture lists signature algorithms");
    let names = document["client_hello"]["signature_algorithm_names"]
        .as_array()
        .expect("the capture names its signature algorithms");

    for (constant, name) in expected {
        let index = names
            .iter()
            .position(|recorded| recorded == name)
            .unwrap_or_else(|| panic!("the capture does not record a scheme named {name}"));
        assert_eq!(
            format!("0x{}", constant.hex4()),
            values[index]
                .as_str()
                .expect("a named scheme is written as a hex literal")
        );
    }
}

#[test]
fn the_capture_records_that_the_extension_order_was_verified_to_be_random() {
    let capture = capture();
    let finding = capture
        .extension_order_finding
        .as_ref()
        .expect("the capture records the shuffling finding");

    assert!(finding.verified);
    assert!(capture.extension_order_is_randomised());
}
