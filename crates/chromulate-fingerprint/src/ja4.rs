//! JA4, the sorted TLS ClientHello fingerprint.
//!
//! JA4 exists because JA3 is unstable: Chrome permutes its extension order on
//! every connection, so the same browser yields different JA3 hashes minutes
//! apart. JA4 sorts the cipher and extension lists before hashing, which makes
//! it a property of the client build rather than of one handshake.

use sha2::{Digest, Sha256};

use crate::client_hello::ClientHelloSpec;
use crate::ids::ExtensionId;

/// The digest length JA4 truncates each SHA-256 to, in hex characters.
const TRUNCATED_HASH_LEN: usize = 12;

/// The value JA4 prints when a component has nothing to hash.
const EMPTY_COMPONENT: &str = "000000000000";

/// Computes the JA4 fingerprint, `a_b_c`.
///
/// `a` describes the handshake, `b` is the truncated SHA-256 of the sorted
/// cipher list, and `c` is the truncated SHA-256 of the sorted extension list
/// joined to the signature algorithms in their original order.
#[must_use]
pub fn ja4(spec: &ClientHelloSpec) -> String {
    let parts = Ja4Parts::of(spec);
    format!(
        "{}_{}_{}",
        parts.header,
        truncated_sha256(&parts.ciphers),
        truncated_sha256(&parts.extensions_and_signatures()),
    )
}

/// Computes the raw JA4 (`JA4_r`), which carries the lists instead of hashing
/// them: `a_ciphers_extensions_signaturealgorithms`.
///
/// The last two fields are built from the same helper [`ja4`] hashes, so
/// rejoining them always reproduces the string behind the `c` digest. That
/// makes a client with no `signature_algorithms` extension print three fields
/// rather than four with an empty one. The JA4 specification states the
/// no-underscore rule for the hashed form only and says nothing about the raw
/// form, so this is Chromulate's choice for the unspecified case, made so that
/// the two functions cannot disagree — not a rule the specification imposes.
#[must_use]
pub fn ja4_raw(spec: &ClientHelloSpec) -> String {
    let parts = Ja4Parts::of(spec);
    format!(
        "{}_{}_{}",
        parts.header,
        parts.ciphers,
        parts.extensions_and_signatures()
    )
}

struct Ja4Parts {
    header: String,
    ciphers: String,
    extensions: String,
    signature_algorithms: String,
}

impl Ja4Parts {
    fn of(spec: &ClientHelloSpec) -> Self {
        let mut ciphers: Vec<String> = spec
            .ciphers_without_grease()
            .map(super::ids::CipherSuite::hex4)
            .collect();
        let cipher_count = ciphers.len();
        ciphers.sort_unstable();

        // SNI and ALPN are counted in the header but excluded from the hashed
        // list, so that a fingerprint does not change with the site visited.
        let extension_count = spec.extensions.iter().filter(|id| !id.is_grease()).count();
        let mut extensions: Vec<String> = spec
            .extensions
            .iter()
            .filter(|id| {
                !id.is_grease() && *id != ExtensionId::SERVER_NAME && *id != ExtensionId::ALPN
            })
            .map(|id| id.hex4())
            .collect();
        extensions.sort_unstable();

        let signature_algorithms = spec
            .signature_algorithms
            .iter()
            .filter(|scheme| !scheme.is_grease())
            .map(|scheme| scheme.hex4())
            .collect::<Vec<_>>()
            .join(",");

        Self {
            header: header(spec, cipher_count, extension_count),
            ciphers: ciphers.join(","),
            extensions: extensions.join(","),
            signature_algorithms,
        }
    }

    /// The `c` pre-image: the extension list, then the signature algorithms.
    ///
    /// The separator is dropped when there are no signature algorithms, so that
    /// a client that omits the extension does not hash a trailing underscore.
    /// [`ja4`] and [`ja4_raw`] both go through here, which is what stops the
    /// hashed form and the raw form describing different strings.
    fn extensions_and_signatures(&self) -> String {
        if self.signature_algorithms.is_empty() {
            self.extensions.clone()
        } else {
            format!("{}_{}", self.extensions, self.signature_algorithms)
        }
    }
}

fn header(spec: &ClientHelloSpec, cipher_count: usize, extension_count: usize) -> String {
    format!(
        "{}{}{}{}{}{}",
        spec.transport.ja4_char(),
        spec.effective_version().ja4_code(),
        if spec.has_sni() { 'd' } else { 'i' },
        two_digits(cipher_count),
        two_digits(extension_count),
        alpn_code(spec.first_alpn()),
    )
}

/// JA4 counts are two digits wide and saturate rather than overflow.
fn two_digits(count: usize) -> String {
    format!("{:02}", count.min(99))
}

/// The first and last character of the first ALPN protocol.
///
/// A protocol whose first or last byte is not alphanumeric is represented by
/// the first and last character of its hex encoding instead, per the JA4
/// specification. The Chrome capture only exercises the `h2` path.
fn alpn_code(alpn: Option<&str>) -> String {
    let Some(alpn) = alpn.filter(|value| !value.is_empty()) else {
        return "00".to_owned();
    };

    let bytes = alpn.as_bytes();
    let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        format!("{}{}", first as char, last as char)
    } else {
        let encoded = hex::encode(bytes);
        let encoded = encoded.as_bytes();
        format!(
            "{}{}",
            encoded[0] as char,
            encoded[encoded.len() - 1] as char
        )
    }
}

fn truncated_sha256(input: &str) -> String {
    if input.is_empty() {
        return EMPTY_COMPONENT.to_owned();
    }
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..TRUNCATED_HASH_LEN].to_owned()
}

#[cfg(test)]
mod tests {
    use crate::client_hello::{ExtensionOrder, ExtensionSet, GreasePlacement};
    use crate::ids::{CipherSuite, NamedGroup, TlsVersion, Transport};

    use super::*;

    /// A TLS 1.2-era client that offers no `signature_algorithms` extension,
    /// which is the only shape in which the two JA4 forms can disagree.
    fn spec_without_signature_algorithms() -> ClientHelloSpec {
        ClientHelloSpec {
            transport: Transport::Tcp,
            record_version: TlsVersion::Tls12,
            handshake_version: TlsVersion::Tls12,
            supported_versions: vec![TlsVersion::Tls13, TlsVersion::Tls12],
            cipher_suites: vec![
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
            ],
            extensions: ExtensionSet::new([
                ExtensionId::SERVER_NAME,
                ExtensionId::SUPPORTED_GROUPS,
                ExtensionId::SESSION_TICKET,
                ExtensionId::SUPPORTED_VERSIONS,
                ExtensionId::KEY_SHARE,
                ExtensionId::ALPN,
                ExtensionId::EC_POINT_FORMATS,
            ]),
            extension_order: ExtensionOrder::shuffled(),
            supported_groups: vec![NamedGroup::X25519],
            key_share_groups: vec![NamedGroup::X25519],
            signature_algorithms: Vec::new(),
            alpn: vec!["h2".to_owned()],
            alps: Vec::new(),
            certificate_compression: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            ec_point_formats: Vec::new(),
            grease: GreasePlacement::NONE,
        }
    }

    #[test]
    fn the_raw_form_carries_exactly_the_string_the_hashed_form_hashed() {
        let spec = spec_without_signature_algorithms();
        let hashed = ja4(&spec);
        let raw = ja4_raw(&spec);

        let pre_image = raw
            .splitn(3, '_')
            .nth(2)
            .expect("JA4_r starts with a header and a cipher list");
        let digest = hashed
            .rsplit('_')
            .next()
            .expect("JA4 has three underscore separated components");

        assert_eq!(
            truncated_sha256(pre_image),
            digest,
            "rejoining JA4_r's tail must reproduce the string JA4 hashed\n  ja4   = {hashed}\n  ja4_r = {raw}"
        );
    }

    #[test]
    fn the_raw_form_does_not_end_in_a_separator_when_there_are_no_signature_algorithms() {
        let raw = ja4_raw(&spec_without_signature_algorithms());
        assert!(
            !raw.ends_with('_'),
            "JA4_r must not advertise an empty trailing field: {raw}"
        );
    }

    #[test]
    fn a_component_with_nothing_to_hash_is_printed_as_zeroes() {
        assert_eq!(truncated_sha256(""), EMPTY_COMPONENT);
    }

    #[test]
    fn counts_are_two_digits_and_saturate_at_ninety_nine() {
        assert_eq!(two_digits(0), "00");
        assert_eq!(two_digits(7), "07");
        assert_eq!(two_digits(16), "16");
        assert_eq!(two_digits(250), "99");
    }

    #[test]
    fn the_alpn_code_is_the_first_and_last_character_of_the_first_protocol() {
        assert_eq!(alpn_code(Some("h2")), "h2");
        assert_eq!(alpn_code(Some("http/1.1")), "h1");
        assert_eq!(alpn_code(Some("h3")), "h3");
        assert_eq!(alpn_code(None), "00");
        assert_eq!(alpn_code(Some("")), "00");
    }
}
