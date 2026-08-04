//! The shipped Chrome profile, as Rust constants.
//!
//! Every value in this module is a transcription of a field in
//! `data/chrome-151-macos.json`; the field it came from is named beside it. The
//! transcription is not taken on trust:
//! `the_hand_written_profile_equals_the_one_loaded_from_the_capture` in
//! `tests/chrome_profile_matches_capture.rs` rebuilds the same profile from the
//! JSON and asserts the two are identical, so a typo here fails the build
//! rather than shipping a browser that does not exist.

use std::collections::BTreeMap;

use chromulate_fingerprint::{
    CertificateCompression, CipherSuite, ClientHelloSpec, EcPointFormat, ExtensionId,
    ExtensionOrder, ExtensionSet, GreasePlacement, HeadersPriority, Http2Spec, NamedGroup,
    Provenance, PseudoHeaderOrder, PskKeyExchangeMode, Setting, SettingId, SignatureScheme,
    TlsVersion, Transport,
};

use crate::profile::{Brand, HeaderOrder, Platform, Profile};

/// `client_hello.cipher_suites_in_wire_order`, GREASE excluded.
const CIPHER_SUITES: [CipherSuite; 15] = [
    CipherSuite::TLS_AES_128_GCM_SHA256,
    CipherSuite::TLS_AES_256_GCM_SHA384,
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
];

/// `client_hello.extension_set_sorted` plus `server_name`, which that listing
/// omits but the recorded JA3 of both samples carries.
const EXTENSIONS: [ExtensionId; 16] = [
    ExtensionId::SERVER_NAME,
    ExtensionId::STATUS_REQUEST,
    ExtensionId::SUPPORTED_GROUPS,
    ExtensionId::EC_POINT_FORMATS,
    ExtensionId::SIGNATURE_ALGORITHMS,
    ExtensionId::ALPN,
    ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP,
    ExtensionId::EXTENDED_MASTER_SECRET,
    ExtensionId::COMPRESS_CERTIFICATE,
    ExtensionId::SESSION_TICKET,
    ExtensionId::SUPPORTED_VERSIONS,
    ExtensionId::PSK_KEY_EXCHANGE_MODES,
    ExtensionId::KEY_SHARE,
    ExtensionId::APPLICATION_SETTINGS,
    ExtensionId::ENCRYPTED_CLIENT_HELLO,
    ExtensionId::RENEGOTIATION_INFO,
];

/// `client_hello.supported_groups`, GREASE excluded.
const SUPPORTED_GROUPS: [NamedGroup; 4] = [
    NamedGroup::X25519_MLKEM768,
    NamedGroup::X25519,
    NamedGroup::SECP256R1,
    NamedGroup::SECP384R1,
];

/// `client_hello.key_share_groups`, GREASE excluded.
const KEY_SHARE_GROUPS: [NamedGroup; 2] = [NamedGroup::X25519_MLKEM768, NamedGroup::X25519];

/// `client_hello.signature_algorithms`, in wire order. JA4 hashes this order.
const SIGNATURE_ALGORITHMS: [SignatureScheme; 11] = [
    SignatureScheme::SCHEME_0X0904,
    SignatureScheme::SCHEME_0X0905,
    SignatureScheme::SCHEME_0X0906,
    SignatureScheme::ECDSA_SECP256R1_SHA256,
    SignatureScheme::RSA_PSS_RSAE_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_SECP384R1_SHA384,
    SignatureScheme::RSA_PSS_RSAE_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_RSAE_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// `client_hello.supported_versions`, GREASE excluded.
const SUPPORTED_VERSIONS: [TlsVersion; 2] = [TlsVersion::Tls13, TlsVersion::Tls12];

/// `http2.settings_in_order`.
const SETTINGS: [(SettingId, u32); 4] = [
    (SettingId::HEADER_TABLE_SIZE, 65_536),
    (SettingId::ENABLE_PUSH, 0),
    (SettingId::INITIAL_WINDOW_SIZE, 6_291_456),
    (SettingId::MAX_HEADER_LIST_SIZE, 262_144),
];

/// `http2.connection_window_update_increment`.
const CONNECTION_WINDOW_UPDATE: u32 = 15_663_105;

/// `http2.navigate_request_header_order`.
const NAVIGATE_HEADER_ORDER: [&str; 12] = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
    "priority",
];

/// `http2.observed_header_values`.
const OBSERVED_HEADERS: [(&str, &str); 11] = [
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\
         */*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    ),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("accept-language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
    (
        "sec-ch-ua",
        "\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"",
    ),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", "\"macOS\""),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "cross-site"),
    ("upgrade-insecure-requests", "1"),
];

/// `_provenance.user_agent`.
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";

/// `observed_header_values["sec-ch-ua"]`, parsed into its entries.
const BRANDS: [(&str, &str); 3] = [
    ("Not=A?Brand", "99"),
    ("Google Chrome", "151"),
    ("Chromium", "151"),
];

/// Builds the Chrome ClientHello spec.
fn client_hello() -> ClientHelloSpec {
    ClientHelloSpec {
        // `client_hello.alpn` offers h2 and http/1.1, so the handshake was
        // carried over TCP rather than QUIC.
        transport: Transport::Tcp,
        record_version: TlsVersion::Tls12,
        handshake_version: TlsVersion::Tls12,
        supported_versions: SUPPORTED_VERSIONS.to_vec(),
        cipher_suites: CIPHER_SUITES.to_vec(),
        extensions: ExtensionSet::new(EXTENSIONS),
        // `_finding_extension_order_is_randomised` was verified during capture:
        // Chrome permutes on every connection and pins nothing but the GREASE
        // brackets and pre_shared_key, which the wire order generator enforces.
        extension_order: ExtensionOrder::shuffled(),
        supported_groups: SUPPORTED_GROUPS.to_vec(),
        key_share_groups: KEY_SHARE_GROUPS.to_vec(),
        signature_algorithms: SIGNATURE_ALGORITHMS.to_vec(),
        alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
        alps: vec!["h2".to_owned()],
        certificate_compression: vec![CertificateCompression::Brotli],
        psk_key_exchange_modes: vec![PskKeyExchangeMode::PskDheKe],
        ec_point_formats: vec![EcPointFormat::Uncompressed],
        // `client_hello.grease_positions` lists all six slots this model knows.
        grease: GreasePlacement::ALL,
    }
}

/// Builds the Chrome HTTP/2 spec.
fn http2() -> Http2Spec {
    Http2Spec {
        settings: SETTINGS
            .iter()
            .map(|(id, value)| Setting::new(*id, *value))
            .collect(),
        connection_window_update: CONNECTION_WINDOW_UPDATE,
        // Chrome 151 sends no PRIORITY frames; it signals priority with the
        // `priority` request header instead.
        priority_frames: Vec::new(),
        headers_priority: Some(HeadersPriority {
            depends_on: 0,
            exclusive: true,
            weight: 256,
        }),
        pseudo_header_order: PseudoHeaderOrder::CHROME,
    }
}

/// Builds the shipped Chrome profile.
pub(crate) fn profile() -> Profile {
    let observed_headers: BTreeMap<String, String> = OBSERVED_HEADERS
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();

    Profile {
        name: "chrome".to_owned(),
        version: "151.0.0.0".to_owned(),
        platform: Platform::MacOs,
        user_agent: USER_AGENT.to_owned(),
        client_hint_brands: BRANDS
            .iter()
            .map(|(brand, version)| Brand::new(*brand, *version))
            .collect(),
        client_hello: client_hello(),
        http2: http2(),
        accept: observed_headers["accept"].clone(),
        accept_language: observed_headers["accept-language"].clone(),
        accept_encoding: observed_headers["accept-encoding"].clone(),
        header_order: HeaderOrder {
            navigate: NAVIGATE_HEADER_ORDER
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            // The capture recorded only a navigation, so there is no observed
            // subresource order to ship. Inventing one would be inventing a
            // fingerprint.
            subresource: None,
        },
        observed_headers,
        provenance: Some(provenance()),
    }
}

/// `_provenance`, verbatim.
fn provenance() -> Provenance {
    Provenance {
        description: "Live capture of Google Chrome's TLS ClientHello and HTTP/2 connection \
                      preface, taken by driving a real Chrome browser to an echo endpoint. These \
                      values are the ground truth for the ChromeStable profile golden tests. Do \
                      not edit by hand - re-capture instead."
            .to_owned(),
        browser: "Google Chrome 151.0.0.0".to_owned(),
        platform: "macOS (arm64 host, Intel UA string as Chrome always reports)".to_owned(),
        endpoint: "https://tls.peet.ws/api/all and https://tls.peet.ws/api/clean".to_owned(),
        captured_at: "2026-08-04".to_owned(),
        capture_method: "browser automation, two separate TLS connections".to_owned(),
        user_agent: USER_AGENT.to_owned(),
    }
}
