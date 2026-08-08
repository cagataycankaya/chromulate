//! What the BoringSSL backend actually puts on the wire.
//!
//! `emitted_client_hello.rs` is the same question asked of rustls, and its
//! answers are a catalogue of deviations. This file asks it of
//! [`chromulate_tls::boring::BoringBackend`], where the answers are supposed to
//! be equalities — so the assertions here are written as equalities against the
//! Chrome 151 profile, and the one place they cannot be is named, explained and
//! pinned rather than omitted.
//!
//! The bytes are real: a `TcpListener` accepts a connection, reads the first
//! record, and hangs up. It is not a TLS server, so the handshake never
//! completes — which is fine, because the first flight is the whole subject.
//! `emitted_client_hello.rs` gets the same bytes out of rustls without a socket
//! at all; BoringSSL will not hand its flight to anything but an `IO`, so this
//! file pays for a loopback socket and shares the decoder.
//!
//! Why the assertions are separate tests rather than one: JA4 is the sum of
//! many settings, and four of the defects this backend is most likely to have —
//! no GREASE, wrong cipher order, one key share instead of two, a truncated
//! group list — do not move it at all. A single test would report "JA4 differs"
//! and name none of them.

#![cfg(feature = "boring")]

use std::collections::BTreeSet;
use std::time::Duration;

use chromulate_fingerprint::{
    CertificateCompression, CipherSuite, ClientHelloSpec, EcPointFormat, ExtensionId,
    ExtensionOrder, ExtensionSet, GreasePlacement, GreaseValue, NamedGroup, PskKeyExchangeMode,
    SignatureScheme, TlsVersion, Transport, WireExtensionOrder, ja4,
};
use chromulate_profile::Profile;
use chromulate_tls::boring::BoringBackend;
use chromulate_tls::{TlsBackend, TlsBackendConfig};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

mod common;

use common::{EmittedHello, parse};

/// The JA4 of the Chrome 151 capture the profile reproduces.
///
/// Pinned here as a literal so a profile change shows up as a diff in this file
/// rather than only as a failure message; `the_target_is_still_the_captured_one`
/// checks the literal against the profile.
const TARGET_JA4: &str = "t13d1516h2_8daaf6152771_806a8c22fdea";

/// How long a capture waits before giving up on the first flight.
///
/// Generous, because it is never reached in the normal case: the listener hangs
/// up as soon as it has the record, which ends the handshake immediately.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(10);

fn chrome_backend() -> BoringBackend {
    BoringBackend::new(&Profile::chrome_stable()).expect("the Chrome profile must build a backend")
}

/// Drives the backend at a loopback listener and decodes the record it writes.
async fn capture_hello(backend: &BoringBackend, host: &str) -> EmittedHello {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("binding a loopback listener must succeed");
    let address = listener
        .local_addr()
        .expect("a bound listener has an address");

    let capture = tokio::spawn(async move {
        let (mut socket, _) = listener
            .accept()
            .await
            .expect("the backend must open the connection");

        let mut header = [0u8; 5];
        socket
            .read_exact(&mut header)
            .await
            .expect("a TLS record header must arrive");
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut body = vec![0u8; length];
        socket
            .read_exact(&mut body)
            .await
            .expect("the record body must arrive whole");

        let mut wire = header.to_vec();
        wire.extend_from_slice(&body);
        wire
        // Dropping the socket here hangs up on the backend, which ends its
        // handshake with an error rather than leaving it waiting for a
        // ServerHello that is never coming.
    });

    let stream = TcpStream::connect(address)
        .await
        .expect("connecting to the loopback listener must succeed");
    let name = chromulate_tls::server_name(host).expect("the test host must be usable");

    // The handshake is expected to fail. Only the bytes it wrote first matter.
    let _ = timeout(CAPTURE_TIMEOUT, backend.connect(stream, name)).await;

    let wire = capture.await.expect("the capture task must not panic");
    parse(&wire)
}

/// The profile's cipher suites as raw code points, in wire order.
fn profile_ciphers() -> Vec<u16> {
    Profile::chrome_stable()
        .client_hello
        .cipher_suites
        .iter()
        .copied()
        .map(CipherSuite::get)
        .collect()
}

/// Drops GREASE from a decoded list, which is the form every profile field is
/// stored in.
fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !GreaseValue::is_grease_value(*value))
        .collect()
}

/// Checks the invariants [`WireExtensionOrder::new`] enforces, before anything
/// constructs one.
///
/// That constructor rejects a repeated extension, a `pre_shared_key` that is not
/// last, and a GREASE value anywhere but the edges — and `spec_of` reaches it
/// through an `expect`. Three real backend defects would therefore surface as a
/// panic inside a helper instead of as a named failure, so they are checked here
/// first and by hand.
fn assert_wire_order_invariants(hello: &EmittedHello) {
    let mut seen = BTreeSet::new();
    for id in &hello.extensions {
        assert!(
            seen.insert(*id),
            "extension {id:#06x} was sent twice: {:04x?}",
            hello.extensions
        );
    }

    let psk = ExtensionId::PRE_SHARED_KEY.get();
    if let Some(index) = hello.extensions.iter().position(|id| *id == psk) {
        assert_eq!(
            index + 1,
            hello.extensions.len(),
            "RFC 8446 4.2.11 requires pre_shared_key to be the final extension, and it sat at \
             index {index} of {}: {:04x?}",
            hello.extensions.len(),
            hello.extensions
        );
    }

    let last_non_psk = hello
        .extensions
        .iter()
        .rposition(|id| *id != psk)
        .expect("a ClientHello carries at least one non-PSK extension");
    for (index, id) in hello.extensions.iter().enumerate() {
        if GreaseValue::is_grease_value(*id) {
            assert!(
                index == 0 || index == last_non_psk,
                "GREASE brackets the extension list; {id:#06x} sat at index {index}: {:04x?}",
                hello.extensions
            );
        }
    }
}

/// Rebuilds a fingerprintable specification from the decoded bytes.
///
/// Every field comes from what was parsed, never from the profile, so the
/// fingerprint describes the emitted hello alone. Call
/// [`assert_wire_order_invariants`] first.
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
        grease: GreasePlacement::ALL,
    }
}

#[tokio::test]
async fn the_target_is_still_the_captured_one() {
    assert_eq!(
        chrome_backend().target_identity().ja4,
        TARGET_JA4,
        "the literal this file compares against is the profile's own target; if the profile \
         moved, every assertion below is aimed at the wrong number"
    );
}

/// A1.
#[tokio::test]
async fn the_emitted_ja4_matches_the_target_in_every_component_but_the_third() {
    let hello = capture_hello(&chrome_backend(), "example.com").await;
    assert_wire_order_invariants(&hello);
    let emitted = ja4(&spec_of(&hello));

    let (emitted_a, rest) = emitted
        .split_once('_')
        .expect("a JA4 has three underscore-separated components");
    let (emitted_b, emitted_c) = rest
        .split_once('_')
        .expect("a JA4 has three underscore-separated components");
    let mut target = TARGET_JA4.splitn(3, '_');
    let target_a = target.next().expect("the target has a first component");
    let target_b = target.next().expect("the target has a second component");
    let target_c = target.next().expect("the target has a third component");

    assert_eq!(
        emitted_a, target_a,
        "the header counts ciphers, extensions, the version and ALPN, and all four are the \
         profile's: emitted {emitted}, target {TARGET_JA4}"
    );
    assert_eq!(
        emitted_b, target_b,
        "the second component is the sorted cipher list, which the backend reproduces exactly: \
         emitted {emitted}, target {TARGET_JA4}"
    );

    // The third component hashes the extension list joined to the signature
    // algorithms, and the signature algorithms are the one thing this backend
    // cannot reproduce: Chrome 151 sends 0x0904, 0x0905 and 0x0906 first, and
    // BoringSSL refuses them by name, refuses them as raw code points, and does
    // not carry them in its bindings. Substituting only those three into an
    // otherwise identical hello yields the capture's JA4 exactly, so this
    // inequality is the whole of the remaining gap.
    //
    // If BoringSSL ever gains those code points, this assertion becomes
    // `assert_eq!(emitted, TARGET_JA4)` and the three tests below it about the
    // gap go away with it.
    assert_ne!(
        emitted_c, target_c,
        "the third component is expected to differ while the signature algorithms differ; if it \
         matches, BoringSSL has gained 0x0904/0x0905/0x0906 and this test, \
         BORING_STRUCTURAL_LIMITS and docs/fidelity.md are all out of date"
    );
}

/// A2.
#[tokio::test]
async fn the_emitted_cipher_suites_are_the_profiles_suites_in_the_profiles_wire_order() {
    let hello = capture_hello(&chrome_backend(), "example.com").await;

    assert_eq!(
        without_grease(&hello.cipher_suites),
        profile_ciphers(),
        "JA4 sorts the cipher list, so order is invisible to it and has to be asserted here: \
         emitted {:04x?}",
        hello.cipher_suites
    );
}

/// A3.
#[tokio::test]
async fn grease_reaches_the_wire_in_all_six_positions_the_profile_marks() {
    let profile = Profile::chrome_stable();
    let grease = profile.client_hello.grease;
    assert_eq!(
        grease,
        GreasePlacement::ALL,
        "this test is written for a profile that marks every position; a profile that marks \
         fewer needs the assertions below made conditional rather than this one relaxed"
    );

    let hello = capture_hello(&chrome_backend(), "example.com").await;

    // Shape, never a value: GREASE is redrawn on every connection, so asserting
    // a specific code point would be asserting a coin flip.
    let is_grease = |value: Option<&u16>, position: &str| {
        let value = value.unwrap_or_else(|| panic!("{position} is empty, so it carries no GREASE"));
        assert!(
            GreaseValue::new(*value).is_some(),
            "{position} must be a reserved 0x?A?A value, and was {value:#06x}"
        );
    };

    is_grease(hello.cipher_suites.first(), "the first cipher suite");
    is_grease(hello.extensions.first(), "the first extension");
    is_grease(hello.extensions.last(), "the last extension");
    is_grease(hello.supported_groups.first(), "the first supported group");
    is_grease(hello.key_share_groups.first(), "the first key share");
    is_grease(
        hello.supported_versions.first(),
        "the first supported version",
    );
}

/// A4.
#[tokio::test]
async fn the_grease_group_and_the_grease_key_share_are_the_same_value() {
    let hello = capture_hello(&chrome_backend(), "example.com").await;

    let group = *hello
        .supported_groups
        .first()
        .expect("supported_groups is not empty");
    let share = *hello
        .key_share_groups
        .first()
        .expect("key_share is not empty");

    // Checked before the equality, and not redundant with A3. Written as the
    // equality alone, this test passed on a backend with GREASE disabled
    // outright: both slots then hold the same real group, 0x11ec, and equal is
    // equal. Requiring the shared value to be GREASE is what stops the
    // strongest form of this defect — no GREASE at all — from satisfying it.
    assert!(
        GreaseValue::new(group).is_some(),
        "the value these two slots share must itself be a reserved 0x?A?A value, and was \
         {group:#06x}"
    );
    assert_eq!(
        group, share,
        "BoringSSL draws the first supported group and the first key share from one \
         ssl_grease_group slot, so Chrome's are necessarily equal on a connection. Two \
         independently drawn values still pass a naive 'is there GREASE here' check and are \
         distinguishable from Chrome: {group:#06x} against {share:#06x}"
    );
}

/// A5.
#[tokio::test]
async fn the_emitted_key_shares_are_the_profiles_key_shares() {
    let profile = Profile::chrome_stable();
    let wanted: Vec<u16> = profile
        .client_hello
        .key_share_groups
        .iter()
        .copied()
        .map(NamedGroup::get)
        .collect();

    let hello = capture_hello(&chrome_backend(), "example.com").await;

    assert_eq!(
        without_grease(&hello.key_share_groups),
        wanted,
        "key shares are not a JA4 input, so sending one where the capture shows two moves \
         nothing this suite would otherwise notice: emitted {:04x?}",
        hello.key_share_groups
    );
}

/// A6.
#[tokio::test]
async fn the_emitted_supported_groups_are_the_profiles_groups() {
    let profile = Profile::chrome_stable();
    let wanted: Vec<u16> = profile
        .client_hello
        .supported_groups
        .iter()
        .copied()
        .map(NamedGroup::get)
        .collect();

    let hello = capture_hello(&chrome_backend(), "example.com").await;

    assert_eq!(
        without_grease(&hello.supported_groups),
        wanted,
        "supported_groups is not a JA4 input either, so a truncated or reordered list is \
         invisible to A1: emitted {:04x?}",
        hello.supported_groups
    );
}

/// A7.
#[tokio::test]
async fn no_grease_appears_in_the_signature_algorithms() {
    let hello = capture_hello(&chrome_backend(), "example.com").await;

    assert!(
        !hello
            .signature_algorithms
            .iter()
            .any(|scheme| GreaseValue::is_grease_value(*scheme)),
        "BoringSSL supports signature-algorithm GREASE behind a flag Chromium never sets, and \
         JA4 filters GREASE out of the signature list, so a backend that set it would look \
         correct to A1: {:04x?}",
        hello.signature_algorithms
    );
}

/// A8.
#[tokio::test]
async fn the_emitted_extension_set_is_the_profiles_extension_set() {
    let profile = Profile::chrome_stable();
    let wanted: Vec<u16> = profile
        .client_hello
        .extensions
        .iter()
        .map(ExtensionId::get)
        .collect();

    let hello = capture_hello(&chrome_backend(), "example.com").await;
    let emitted = without_grease(&hello.extensions);

    let missing: Vec<u16> = wanted
        .iter()
        .copied()
        .filter(|id| !emitted.contains(id))
        .collect();
    let extra: Vec<u16> = emitted
        .iter()
        .copied()
        .filter(|id| !wanted.contains(id))
        .collect();

    assert!(
        missing.is_empty() && extra.is_empty(),
        "the extension set must be the profile's exactly. Missing (the profile lists them, the \
         backend did not send them): {missing:04x?}. Extra (the backend sent them, the profile \
         does not list them): {extra:04x?}. Emitted in wire order: {:04x?}",
        hello.extensions
    );
}

/// A9.
#[tokio::test]
async fn the_ja4_is_stable_across_connections_while_the_extension_order_is_not() {
    const CONNECTIONS: usize = 8;

    let backend = chrome_backend();
    let mut fingerprints = Vec::with_capacity(CONNECTIONS);
    let mut orders = Vec::with_capacity(CONNECTIONS);

    for _ in 0..CONNECTIONS {
        let hello = capture_hello(&backend, "example.com").await;
        assert_wire_order_invariants(&hello);
        fingerprints.push(ja4(&spec_of(&hello)));
        orders.push(hello.extensions);
    }

    let distinct_fingerprints: BTreeSet<&String> = fingerprints.iter().collect();
    assert_eq!(
        distinct_fingerprints.len(),
        1,
        "JA4 sorts what BoringSSL permutes, so it must not move across connections: \
         {fingerprints:?}"
    );

    // GREASE is stripped before the orders are compared, and that is not
    // tidiness. Written against the raw lists, this assertion passed with
    // `set_permute_extensions` removed from the backend: the two GREASE values
    // that bracket the list are redrawn per connection, so the raw order
    // differs every time whether or not anything was permuted. Mutation proved
    // the assertion was decoration; stripping GREASE is what makes it a test of
    // the permutation.
    let distinct_orders: BTreeSet<Vec<u16>> =
        orders.iter().map(|order| without_grease(order)).collect();
    assert!(
        distinct_orders.len() > 1,
        "Chrome permutes its extension order on every connection and the profile records that, \
         so {CONNECTIONS} connections giving one order means the backend froze it: {:04x?}",
        orders[0]
    );

    // The permutation must move the order without moving the set, or the two
    // halves above could both be satisfied by a backend that varies which
    // extensions it sends. GREASE is excluded because its two values are
    // redrawn per connection by design, so the raw sets are expected to differ.
    let reference: BTreeSet<u16> = without_grease(&orders[0]).into_iter().collect();
    for order in &orders {
        let set: BTreeSet<u16> = without_grease(order).into_iter().collect();
        assert_eq!(
            set, reference,
            "only the order may change across connections, never the set: {order:04x?}"
        );
    }
}

/// MEASUREMENT ONLY: prints the emitted fingerprints for the current switches.
#[tokio::test]
async fn print_emitted_fingerprints_for_the_isolation_experiment() {
    let hello = capture_hello(&chrome_backend(), "example.com").await;
    let spec = spec_of(&hello);
    println!(
        "VARIANT ja4={} ja3={} ciphers={} extensions={}",
        ja4(&spec),
        chromulate_fingerprint::ja3_hash(&chromulate_fingerprint::ja3(&spec)),
        hello.cipher_suites.len(),
        hello.extensions.len()
    );
}
