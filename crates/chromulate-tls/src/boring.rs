//! A BoringSSL backend, behind the off-by-default `boring` feature.
//!
//! # What this closes, and what it does not
//!
//! rustls builds its own ClientHello and accepts no instruction on its shape,
//! which is why [`crate::STRUCTURAL_LIMITS`] has six entries. BoringSSL accepts
//! instruction, so this backend closes five of them: GREASE reaches the wire in
//! all six positions the profile marks, the extension permutation is
//! BoringSSL's own GREASE-bracketed one, `signed_certificate_timestamp`, ALPS
//! and `encrypted_client_hello` are sent, `renegotiation_info` is the extension
//! rather than the SCSV, and the key-share count is the profile's.
//!
//! It does not close the sixth. Chrome 151 sends three signature-algorithm code
//! points first — `0x0904`, `0x0905`, `0x0906` — that BoringSSL refuses by name,
//! refuses as raw values, and does not carry in its bindings. Measured
//! 2026-08-08: substituting only those three into an otherwise identical hello
//! produces the capture's JA4 exactly, so they are the whole of the remaining
//! difference, and JA4's third component differs because of them. The gap is
//! published rather than glossed: [`BoringBackend::fidelity`] reports it.
//!
//! "The whole of the remaining difference" is true only because the cipher
//! suites and the signature algorithms are both configured explicitly below.
//! Left to its defaults BoringSSL sends seventeen suites rather than fifteen
//! and adds `rsa_pkcs1_sha1` to the signature list, and the acceptance test
//! caught exactly that in this backend's first draft — a hello that looked
//! configured, was not, and moved two JA4 components rather than one.
//!
//! The cipher *order* is a second caveat. `boring` 5.1.0 orders the TLS 1.3
//! suites on `EVP_has_aes_hardware()`, so this backend reproduces the capture's
//! order on a host with AES-NI and is UNMEASURED on one without.
//!
//! # Selecting it
//!
//! The `boring` feature compiles this module; it does not select it. Pointing
//! [`crate::ActiveBackend`] here additionally needs `--cfg
//! chromulate_boring_backend`. The split is deliberate: a cargo feature is
//! additive across a dependency graph, so a feature that repointed the alias
//! would silently change which TLS implementation every `--all-features` build
//! links — including the tests that assert what rustls emits.

use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod, SslVerifyMode,
    SslVersion,
};
use chromulate_core::{BoxFuture, Error, Result};
use chromulate_fingerprint::{ClientHelloSpec, NamedGroup};
use chromulate_profile::Profile;
use tokio::io::{AsyncRead, AsyncWrite};

use rustls_pki_types::ServerName;

use crate::backend::{TlsBackend, TlsBackendConfig};
use crate::engine::HandshakeInfo;
use crate::fidelity::{Fidelity, TargetIdentity, target_identity};

/// What this backend does not reproduce.
///
/// One entry where rustls has six. It is a `const` per backend rather than a
/// module constant precisely so that this list can be shorter than that one.
pub const BORING_STRUCTURAL_LIMITS: &[&str] = &[
    "three signature algorithms the capture records first — 0x0904, 0x0905 and 0x0906 — are \
     not emitted: BoringSSL refuses them by name and as raw code points, and they are absent \
     from its bindings. With the profile's remaining eight configured explicitly this is the \
     whole of the remaining JA4 difference, and it falls in the third component",
    "the TLS 1.3 cipher suites are ordered by EVP_has_aes_hardware() rather than by the \
     profile, so the capture's order is reproduced on a host with AES-NI and is UNMEASURED \
     on one without",
];

/// A TLS backend built on BoringSSL.
pub struct BoringBackend {
    connector: SslConnector,
    spec: ClientHelloSpec,
    identity: TargetIdentity,
    fidelity: Fidelity,
    alps: Vec<String>,
}

impl std::fmt::Debug for BoringBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoringBackend")
            .field("target", &self.identity.ja4)
            .finish_non_exhaustive()
    }
}

/// Brotli certificate decompression, which Chrome offers and origins use.
///
/// Chrome advertises brotli in `compress_certificate`, and advertising it is
/// what the fingerprint records — but advertising is a promise. An earlier draft
/// of this backend returned an error from `decompress` on the reasoning that
/// offering the extension was the part that mattered for the fingerprint. Every
/// handshake against an origin that takes the offer then failed, which is how it
/// was found: two Cloudflare-fronted sites that rustls fetched fine returned
/// `TLS handshake failed` here and nowhere else.
///
/// Only decompression is implemented. A client compresses nothing during a
/// handshake — the extension asks the *server* to compress its chain — so
/// `CAN_COMPRESS` is false and `compress` is unreachable.
#[derive(Default, Debug)]
struct BrotliCertificates;

impl CertificateCompressor for BrotliCertificates {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: std::io::Write>(&self, _input: &[u8], _output: &mut W) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "a TLS client does not compress certificates; compress_certificate asks the server to",
        ))
    }

    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        // BoringSSL has already checked the decompressed length against the
        // value the server declared, and rejects a chain that does not match,
        // so this does not need its own expansion guard.
        let mut reader = brotli::Decompressor::new(input, 4096);
        std::io::copy(&mut reader, output).map(|_| ())
    }
}

/// Maps a profile's cipher suite to the name BoringSSL knows it by.
///
/// Configured by name for the same reason as the groups: `boring` 5.1.0 takes a
/// colon-separated list, not code points. A suite with no name here is a
/// fidelity failure and is reported rather than dropped — leaving it out would
/// send a shorter list that still looks plausible.
fn suite_name(suite: chromulate_fingerprint::CipherSuite) -> Option<&'static str> {
    Some(match suite.get() {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xc02f => "ECDHE-RSA-AES128-GCM-SHA256",
        0xc02c => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xc030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xcca9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        0xcca8 => "ECDHE-RSA-CHACHA20-POLY1305",
        0xc013 => "ECDHE-RSA-AES128-SHA",
        0xc014 => "ECDHE-RSA-AES256-SHA",
        0x009c => "AES128-GCM-SHA256",
        0x009d => "AES256-GCM-SHA384",
        0x002f => "AES128-SHA",
        0x0035 => "AES256-SHA",
        _ => return None,
    })
}

/// Maps a profile's signature algorithm to the name BoringSSL knows it by.
///
/// Returns `None` for the three code points BoringSSL has no name for —
/// `0x0904`, `0x0905` and `0x0906` — which the caller drops deliberately rather
/// than failing on, because dropping them is the documented, measured limit of
/// this backend. Any other unknown value is a fidelity failure.
fn sigalg_name(scheme: chromulate_fingerprint::SignatureScheme) -> Option<&'static str> {
    Some(match scheme.get() {
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0401 => "rsa_pkcs1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0501 => "rsa_pkcs1_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0601 => "rsa_pkcs1_sha512",
        _ => return None,
    })
}

/// The signature algorithms BoringSSL cannot be asked for.
///
/// Named rather than inferred, so that a profile carrying a genuinely unknown
/// code point is an error while these three stay a documented omission.
const UNSUPPORTED_SIGNATURE_ALGORITHMS: [u16; 3] = [0x0904, 0x0905, 0x0906];

/// Maps a profile's named group to the name BoringSSL knows it by.
///
/// `boring` 5.1.0 configures groups from a colon-separated list of names rather
/// than from code points, so the profile's numbers have to be translated. A
/// group with no name here is a fidelity failure and is reported as one rather
/// than dropped.
fn curve_name(group: NamedGroup) -> Option<&'static str> {
    match group.get() {
        0x001d => Some("X25519"),
        0x0017 => Some("P-256"),
        0x0018 => Some("P-384"),
        0x0019 => Some("P-521"),
        0x11ec => Some("X25519MLKEM768"),
        _ => None,
    }
}

impl BoringBackend {
    /// Builds a backend that aims at `profile`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when BoringSSL rejects a value the profile
    /// asks for — which is a fidelity failure worth surfacing rather than
    /// quietly narrowing the hello.
    pub fn new(profile: &Profile) -> Result<Self> {
        let spec = profile.client_hello.clone();
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| Error::config(format!("BoringSSL context: {e}")))?;

        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| Error::config(format!("minimum TLS version: {e}")))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| Error::config(format!("maximum TLS version: {e}")))?;

        // GREASE and the permuted extension order are one call each here and
        // are the two things rustls cannot be asked for at all.
        builder.set_grease_enabled(true);
        builder.set_permute_extensions(true);
        builder.enable_signed_cert_timestamps();

        let curves: Vec<&str> = spec
            .supported_groups
            .iter()
            .copied()
            .filter_map(curve_name)
            .collect();
        if curves.len() != spec.supported_groups.len() {
            return Err(Error::config(
                "the profile names a supported group BoringSSL does not implement",
            ));
        }
        builder
            .set_curves_list(&curves.join(":"))
            .map_err(|e| Error::config(format!("supported groups: {e}")))?;

        // Without this the library sends its own default list, which for
        // Chrome 151's profile is seventeen suites rather than fifteen — the two
        // extras being ECDHE-ECDSA-AES128-SHA and ECDHE-ECDSA-AES256-SHA. The
        // JA4 cipher count and hash both move, so a backend that skips this
        // looks configured and is not.
        let mut suites = Vec::with_capacity(spec.cipher_suites.len());
        for suite in &spec.cipher_suites {
            match suite_name(*suite) {
                Some(name) => suites.push(name),
                None => {
                    return Err(Error::config(format!(
                        "the profile names cipher suite {:#06x}, which this backend cannot \
                         configure by name",
                        suite.get()
                    )));
                }
            }
        }
        builder
            .set_cipher_list(&suites.join(":"))
            .map_err(|e| Error::config(format!("cipher suites: {e}")))?;

        // Likewise: the default list carries rsa_pkcs1_sha1 (0x0201), which
        // Chrome 151 does not send, and omitting this call leaves it on the
        // wire. The three code points BoringSSL has no name for are dropped
        // here, which is the gap this backend documents.
        let mut sigalgs = Vec::with_capacity(spec.signature_algorithms.len());
        for scheme in &spec.signature_algorithms {
            match sigalg_name(*scheme) {
                Some(name) => sigalgs.push(name),
                None if UNSUPPORTED_SIGNATURE_ALGORITHMS.contains(&scheme.get()) => {}
                None => {
                    return Err(Error::config(format!(
                        "the profile names signature algorithm {:#06x}, which this backend \
                         cannot configure by name",
                        scheme.get()
                    )));
                }
            }
        }
        builder
            .set_sigalgs_list(&sigalgs.join(":"))
            .map_err(|e| Error::config(format!("signature algorithms: {e}")))?;

        builder
            .add_certificate_compression_algorithm(BrotliCertificates)
            .map_err(|e| Error::config(format!("certificate compression: {e}")))?;

        // The two calls `boring` 5.1.0 does not wrap. See
        // `chromulate-boring-ffi` for why they are `unsafe` and why they are
        // not in this crate.
        chromulate_boring_ffi::enable_ocsp_stapling(&mut builder);

        builder.set_verify(SslVerifyMode::PEER);

        let alpn = wire_alpn(&spec.alpn);
        builder
            .set_alpn_protos(&alpn)
            .map_err(|e| Error::config(format!("ALPN: {e}")))?;

        let identity = target_identity(profile);
        let fidelity = Fidelity {
            provider: "boringssl",
            offered_cipher_suites: spec.cipher_suites.clone(),
            dropped_cipher_suites: Vec::new(),
            offered_groups: spec.supported_groups.clone(),
            dropped_groups: Vec::new(),
            dropped_versions: Vec::new(),
            alpn: spec.alpn.clone(),
            target: identity.clone(),
            structural_limits: BORING_STRUCTURAL_LIMITS,
        };

        Ok(Self {
            connector: builder.build(),
            spec,
            identity,
            fidelity,
            alps: spec_alps(profile),
        })
    }
}

/// Encodes ALPN identifiers in the length-prefixed wire form.
fn wire_alpn(alpn: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for protocol in alpn {
        out.push(u8::try_from(protocol.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(protocol.as_bytes());
    }
    out
}

/// The ALPS protocol list the profile records.
fn spec_alps(profile: &Profile) -> Vec<String> {
    profile.client_hello.alps.clone()
}

impl TlsBackendConfig for BoringBackend {
    fn from_profile(profile: &Profile) -> Result<Self> {
        Self::new(profile)
    }

    fn target_client_hello(&self) -> &ClientHelloSpec {
        &self.spec
    }

    fn target_identity(&self) -> &TargetIdentity {
        &self.identity
    }

    fn fidelity(&self) -> &Fidelity {
        &self.fidelity
    }
}

impl<IO> TlsBackend<IO> for BoringBackend
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = tokio_boring::SslStream<IO>;

    fn connect(
        &self,
        io: IO,
        name: ServerName<'static>,
    ) -> BoxFuture<'_, Result<(Self::Stream, HandshakeInfo)>> {
        Box::pin(async move {
            let host = crate::server_name::describe(&name);
            let mut ssl = self
                .connector
                .configure()
                .and_then(|config| config.into_ssl(&host))
                .map_err(|e| Error::Tls {
                    target: host.clone(),
                    source: Some(Box::new(e)),
                })?;

            // ALPS is per-connection in BoringSSL, so it is set here rather
            // than on the context. The capture's codepoint is the new one.
            for protocol in &self.alps {
                if !chromulate_boring_ffi::add_application_settings(&mut ssl, protocol.as_bytes()) {
                    return Err(Error::Tls {
                        target: host.clone(),
                        source: Some(
                            format!("BoringSSL refused the ALPS protocol {protocol:?}").into(),
                        ),
                    });
                }
            }
            if !self.alps.is_empty() {
                chromulate_boring_ffi::use_new_alps_codepoint(&mut ssl);
            }
            ssl.set_enable_ech_grease(true);

            let stream = tokio_boring::SslStreamBuilder::new(ssl, io)
                .connect()
                .await
                .map_err(|e| Error::Tls {
                    target: host.clone(),
                    source: Some(format!("{e}").into()),
                })?;

            let info = handshake_info(&stream);
            Ok((stream, info))
        })
    }
}

/// Reads the handshake outcome off a finished BoringSSL stream.
fn handshake_info<IO>(stream: &tokio_boring::SslStream<IO>) -> HandshakeInfo {
    let ssl = stream.ssl();
    // `SslVersion` and the cipher's code point are both opaque in `boring`
    // 5.1.0: the version wraps a private field and `SslCipherRef::id` returns
    // the session id rather than the suite number. Both are matched by value
    // against the constants instead, which is the only route the safe API
    // offers and is why a suite the profile does not list reads as `None`
    // rather than as a wrong number.
    HandshakeInfo {
        alpn: ssl.selected_alpn_protocol().map(crate::Alpn::from_wire),
        version: ssl.version2().and_then(version_code_point),
        cipher_suite: ssl
            .current_cipher()
            .and_then(|cipher| suite_code_point(cipher.name())),
        resumed: ssl.session_reused(),
    }
}

/// Maps BoringSSL's opaque version to the code point a fingerprint uses.
fn version_code_point(version: SslVersion) -> Option<chromulate_fingerprint::TlsVersion> {
    let code = match version {
        SslVersion::TLS1_3 => 0x0304,
        SslVersion::TLS1_2 => 0x0303,
        SslVersion::TLS1_1 => 0x0302,
        SslVersion::TLS1 => 0x0301,
        _ => return None,
    };
    chromulate_fingerprint::TlsVersion::from_u16(code)
}

/// Maps BoringSSL's suite name to its code point.
///
/// Only the suites the shipped profile lists are mapped; anything else returns
/// `None`, because reporting a suite this build did not offer would be a
/// fabricated observation.
fn suite_code_point(name: &str) -> Option<chromulate_fingerprint::CipherSuite> {
    let code = match name {
        "TLS_AES_128_GCM_SHA256" => 0x1301,
        "TLS_AES_256_GCM_SHA384" => 0x1302,
        "TLS_CHACHA20_POLY1305_SHA256" => 0x1303,
        "ECDHE-ECDSA-AES128-GCM-SHA256" => 0xc02b,
        "ECDHE-RSA-AES128-GCM-SHA256" => 0xc02f,
        "ECDHE-ECDSA-AES256-GCM-SHA384" => 0xc02c,
        "ECDHE-RSA-AES256-GCM-SHA384" => 0xc030,
        "ECDHE-ECDSA-CHACHA20-POLY1305" => 0xcca9,
        "ECDHE-RSA-CHACHA20-POLY1305" => 0xcca8,
        "ECDHE-RSA-AES128-SHA" => 0xc013,
        "ECDHE-RSA-AES256-SHA" => 0xc014,
        "AES128-GCM-SHA256" => 0x009c,
        "AES256-GCM-SHA384" => 0x009d,
        "AES128-SHA" => 0x002f,
        "AES256-SHA" => 0x0035,
        _ => return None,
    };
    Some(chromulate_fingerprint::CipherSuite::new(code))
}
