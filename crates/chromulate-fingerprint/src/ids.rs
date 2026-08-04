//! Newtypes over the 16-bit code points that make up a ClientHello.
//!
//! Every one of these is a `u16` on the wire, and mixing them up produces a
//! fingerprint that is subtly wrong rather than obviously broken, so they are
//! kept apart by the type system. Only the code points present in the shipped
//! Chrome 151 capture are given names; anything else is still representable
//! through `new`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::grease::GreaseValue;

macro_rules! code_point {
    (
        $(#[$attr:meta])*
        $name:ident, $what:literal
    ) => {
        $(#[$attr])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name(u16);

        impl $name {
            #[doc = concat!("Wraps a raw ", $what, " code point.")]
            #[must_use]
            pub const fn new(value: u16) -> Self {
                Self(value)
            }

            #[doc = concat!("Returns the raw ", $what, " code point.")]
            #[must_use]
            pub const fn get(self) -> u16 {
                self.0
            }

            /// Returns `true` when this code point is a reserved GREASE value.
            #[must_use]
            pub const fn is_grease(self) -> bool {
                GreaseValue::is_grease_value(self.0)
            }

            /// Formats the code point as four lowercase hex digits, the form JA4 hashes.
            #[must_use]
            pub fn hex4(self) -> String {
                format!("{:04x}", self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<u16> for $name {
            fn from(value: u16) -> Self {
                Self(value)
            }
        }

        impl From<$name> for u16 {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl From<GreaseValue> for $name {
            fn from(value: GreaseValue) -> Self {
                Self(value.get())
            }
        }
    };
}

code_point! {
    /// A TLS cipher suite code point.
    CipherSuite, "cipher suite"
}

code_point! {
    /// A TLS extension code point.
    ExtensionId, "extension"
}

code_point! {
    /// A TLS supported-group (named curve) code point.
    NamedGroup, "named group"
}

code_point! {
    /// A TLS signature scheme code point.
    SignatureScheme, "signature scheme"
}

impl CipherSuite {
    /// `TLS_RSA_WITH_AES_128_CBC_SHA`.
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: Self = Self(0x002f);
    /// `TLS_RSA_WITH_AES_256_CBC_SHA`.
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: Self = Self(0x0035);
    /// `TLS_RSA_WITH_AES_128_GCM_SHA256`.
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0x009c);
    /// `TLS_RSA_WITH_AES_256_GCM_SHA384`.
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0x009d);
    /// `TLS_AES_128_GCM_SHA256`, a TLS 1.3 suite.
    pub const TLS_AES_128_GCM_SHA256: Self = Self(0x1301);
    /// `TLS_AES_256_GCM_SHA384`, a TLS 1.3 suite.
    pub const TLS_AES_256_GCM_SHA384: Self = Self(0x1302);
    /// `TLS_CHACHA20_POLY1305_SHA256`, a TLS 1.3 suite.
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(0x1303);
    /// `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`.
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Self = Self(0xc013);
    /// `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`.
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Self = Self(0xc014);
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self = Self(0xc02b);
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Self = Self(0xc02c);
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0xc02f);
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0xc030);
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xcca8);
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xcca9);
}

impl ExtensionId {
    /// `server_name` (SNI). JA4 counts it but excludes it from the hashed list.
    pub const SERVER_NAME: Self = Self(0x0000);
    /// `status_request` (OCSP stapling).
    pub const STATUS_REQUEST: Self = Self(0x0005);
    /// `supported_groups`.
    pub const SUPPORTED_GROUPS: Self = Self(0x000a);
    /// `ec_point_formats`.
    pub const EC_POINT_FORMATS: Self = Self(0x000b);
    /// `signature_algorithms`.
    pub const SIGNATURE_ALGORITHMS: Self = Self(0x000d);
    /// `application_layer_protocol_negotiation` (ALPN).
    ///
    /// JA4 counts it but excludes it from the hashed list.
    pub const ALPN: Self = Self(0x0010);
    /// `signed_certificate_timestamp`.
    pub const SIGNED_CERTIFICATE_TIMESTAMP: Self = Self(0x0012);
    /// `extended_master_secret`.
    pub const EXTENDED_MASTER_SECRET: Self = Self(0x0017);
    /// `compress_certificate`.
    pub const COMPRESS_CERTIFICATE: Self = Self(0x001b);
    /// `session_ticket`.
    pub const SESSION_TICKET: Self = Self(0x0023);
    /// `pre_shared_key`, which RFC 8446 section 4.2.11 requires to be the last extension.
    pub const PRE_SHARED_KEY: Self = Self(0x0029);
    /// `supported_versions`.
    pub const SUPPORTED_VERSIONS: Self = Self(0x002b);
    /// `psk_key_exchange_modes`.
    pub const PSK_KEY_EXCHANGE_MODES: Self = Self(0x002d);
    /// `key_share`.
    pub const KEY_SHARE: Self = Self(0x0033);
    /// `application_settings` (ALPS), Chrome's settings-exchange extension.
    pub const APPLICATION_SETTINGS: Self = Self(0x44cd);
    /// `encrypted_client_hello`.
    pub const ENCRYPTED_CLIENT_HELLO: Self = Self(0xfe0d);
    /// `renegotiation_info`.
    pub const RENEGOTIATION_INFO: Self = Self(0xff01);
}

impl NamedGroup {
    /// `secp256r1`.
    pub const SECP256R1: Self = Self(0x0017);
    /// `secp384r1`.
    pub const SECP384R1: Self = Self(0x0018);
    /// `x25519`.
    pub const X25519: Self = Self(0x001d);
    /// `X25519MLKEM768`, the post-quantum hybrid Chrome 151 offers first.
    pub const X25519_MLKEM768: Self = Self(0x11ec);
}

impl SignatureScheme {
    /// `rsa_pkcs1_sha256`.
    pub const RSA_PKCS1_SHA256: Self = Self(0x0401);
    /// `ecdsa_secp256r1_sha256`.
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    /// `rsa_pkcs1_sha384`.
    pub const RSA_PKCS1_SHA384: Self = Self(0x0501);
    /// `ecdsa_secp384r1_sha384`.
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    /// `rsa_pkcs1_sha512`.
    pub const RSA_PKCS1_SHA512: Self = Self(0x0601);
    /// `rsa_pss_rsae_sha256`.
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    /// `rsa_pss_rsae_sha384`.
    pub const RSA_PSS_RSAE_SHA384: Self = Self(0x0805);
    /// `rsa_pss_rsae_sha512`.
    pub const RSA_PSS_RSAE_SHA512: Self = Self(0x0806);
    /// Scheme `0x0904`, recorded by the Chrome 151 capture without a name.
    ///
    /// Named after its code point because the capture reports it as
    /// `unknown_0x0904`; inventing a friendlier name would be inventing data.
    pub const SCHEME_0X0904: Self = Self(0x0904);
    /// Scheme `0x0905`, recorded by the Chrome 151 capture without a name.
    pub const SCHEME_0X0905: Self = Self(0x0905);
    /// Scheme `0x0906`, recorded by the Chrome 151 capture without a name.
    pub const SCHEME_0X0906: Self = Self(0x0906);
}

/// A TLS protocol version, as carried in a version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u16")]
#[non_exhaustive]
pub enum TlsVersion {
    /// TLS 1.0, `0x0301`.
    Tls10,
    /// TLS 1.1, `0x0302`.
    Tls11,
    /// TLS 1.2, `0x0303`.
    Tls12,
    /// TLS 1.3, `0x0304`.
    Tls13,
}

impl TlsVersion {
    /// Returns the code point this version occupies in a version field.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
        }
    }

    /// Parses a version code point, returning `None` for anything unmodelled.
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0301 => Some(Self::Tls10),
            0x0302 => Some(Self::Tls11),
            0x0303 => Some(Self::Tls12),
            0x0304 => Some(Self::Tls13),
            _ => None,
        }
    }

    /// Returns the two-character version code JA4 uses.
    #[must_use]
    pub const fn ja4_code(self) -> &'static str {
        match self {
            Self::Tls10 => "10",
            Self::Tls11 => "11",
            Self::Tls12 => "12",
            Self::Tls13 => "13",
        }
    }
}

impl From<TlsVersion> for u16 {
    fn from(value: TlsVersion) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for TlsVersion {
    type Error = UnknownTlsVersion;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_u16(value).ok_or(UnknownTlsVersion(value))
    }
}

/// A version code point that this crate does not model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0:#06x} is not a TLS version this crate models")]
pub struct UnknownTlsVersion(pub u16);

/// The transport a ClientHello was sent over, which JA4 records as its first character.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// TLS over TCP.
    Tcp,
    /// TLS inside QUIC.
    Quic,
}

impl Transport {
    /// Returns the JA4 protocol character, `t` for TCP and `q` for QUIC.
    #[must_use]
    pub const fn ja4_char(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
        }
    }
}

/// A certificate compression algorithm (RFC 8879).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "u16", from = "u16")]
#[non_exhaustive]
pub enum CertificateCompression {
    /// `zlib`, code point 1.
    Zlib,
    /// `brotli`, code point 2.
    Brotli,
    /// `zstd`, code point 3.
    Zstd,
    /// A code point outside the three registered algorithms.
    Other(u16),
}

impl CertificateCompression {
    /// Returns the registry code point.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Zlib => 1,
            Self::Brotli => 2,
            Self::Zstd => 3,
            Self::Other(value) => value,
        }
    }

    /// Looks the algorithm up by its registry name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "zlib" => Some(Self::Zlib),
            "brotli" => Some(Self::Brotli),
            "zstd" => Some(Self::Zstd),
            _ => None,
        }
    }
}

impl From<u16> for CertificateCompression {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::Zlib,
            2 => Self::Brotli,
            3 => Self::Zstd,
            other => Self::Other(other),
        }
    }
}

impl From<CertificateCompression> for u16 {
    fn from(value: CertificateCompression) -> Self {
        value.as_u16()
    }
}

/// A PSK key exchange mode (RFC 8446 section 4.2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "u8", from = "u8")]
#[non_exhaustive]
pub enum PskKeyExchangeMode {
    /// `psk_ke`, code point 0.
    PskKe,
    /// `psk_dhe_ke`, code point 1.
    PskDheKe,
    /// A code point outside the two registered modes.
    Other(u8),
}

impl PskKeyExchangeMode {
    /// Returns the registry code point.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::PskKe => 0,
            Self::PskDheKe => 1,
            Self::Other(value) => value,
        }
    }

    /// Looks the mode up by its registry name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "psk_ke" => Some(Self::PskKe),
            "psk_dhe_ke" => Some(Self::PskDheKe),
            _ => None,
        }
    }
}

impl From<u8> for PskKeyExchangeMode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::PskKe,
            1 => Self::PskDheKe,
            other => Self::Other(other),
        }
    }
}

impl From<PskKeyExchangeMode> for u8 {
    fn from(value: PskKeyExchangeMode) -> Self {
        value.as_u8()
    }
}

/// An EC point format, the fifth JA3 field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "u8", from = "u8")]
#[non_exhaustive]
pub enum EcPointFormat {
    /// `uncompressed`, code point 0.
    Uncompressed,
    /// `ansiX962_compressed_prime`, code point 1.
    AnsiX962CompressedPrime,
    /// `ansiX962_compressed_char2`, code point 2.
    AnsiX962CompressedChar2,
    /// A code point outside the three registered formats.
    Other(u8),
}

impl EcPointFormat {
    /// Returns the registry code point.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Uncompressed => 0,
            Self::AnsiX962CompressedPrime => 1,
            Self::AnsiX962CompressedChar2 => 2,
            Self::Other(value) => value,
        }
    }

    /// Looks the format up by its registry name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "uncompressed" => Some(Self::Uncompressed),
            "ansiX962_compressed_prime" => Some(Self::AnsiX962CompressedPrime),
            "ansiX962_compressed_char2" => Some(Self::AnsiX962CompressedChar2),
            _ => None,
        }
    }
}

impl From<u8> for EcPointFormat {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Uncompressed,
            1 => Self::AnsiX962CompressedPrime,
            2 => Self::AnsiX962CompressedChar2,
            other => Self::Other(other),
        }
    }
}

impl From<EcPointFormat> for u8 {
    fn from(value: EcPointFormat) -> Self {
        value.as_u8()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_points_render_as_four_hex_digits_for_ja4() {
        assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.hex4(), "1301");
        assert_eq!(ExtensionId::SERVER_NAME.hex4(), "0000");
        assert_eq!(ExtensionId::APPLICATION_SETTINGS.hex4(), "44cd");
        assert_eq!(ExtensionId::RENEGOTIATION_INFO.hex4(), "ff01");
        assert_eq!(NamedGroup::X25519_MLKEM768.hex4(), "11ec");
    }

    #[test]
    fn named_constants_match_the_decimal_values_in_the_capture() {
        assert_eq!(NamedGroup::X25519_MLKEM768.get(), 4588);
        assert_eq!(NamedGroup::X25519.get(), 29);
        assert_eq!(NamedGroup::SECP256R1.get(), 23);
        assert_eq!(NamedGroup::SECP384R1.get(), 24);
        assert_eq!(ExtensionId::APPLICATION_SETTINGS.get(), 17613);
        assert_eq!(ExtensionId::ENCRYPTED_CLIENT_HELLO.get(), 65037);
        assert_eq!(ExtensionId::RENEGOTIATION_INFO.get(), 65281);
        assert_eq!(ExtensionId::PRE_SHARED_KEY.get(), 41);
    }

    #[test]
    fn tls_version_round_trips_through_its_code_point() {
        for version in [
            TlsVersion::Tls10,
            TlsVersion::Tls11,
            TlsVersion::Tls12,
            TlsVersion::Tls13,
        ] {
            assert_eq!(TlsVersion::from_u16(version.as_u16()), Some(version));
        }
        assert_eq!(TlsVersion::Tls13.as_u16(), 772);
        assert_eq!(TlsVersion::Tls12.as_u16(), 771);
    }
}
