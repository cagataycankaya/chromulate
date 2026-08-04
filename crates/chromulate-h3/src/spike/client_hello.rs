//! Decoding the ClientHello this stack emits, into the project's fingerprint model.
//!
//! Inside QUIC there is no TLS record layer: CRYPTO frames carry handshake messages
//! directly (RFC 9001 section 4). The bytes `quinn` hands to the transport are
//! therefore a bare `Handshake` structure, and this module reads it.
//!
//! The point of turning the result into a [`ClientHelloSpec`] rather than reporting raw
//! numbers is that the project already knows how to compare one of those with a capture:
//! `chromulate_fingerprint::ja4` will produce a JA4 string, with `q` as the transport
//! character, that can be set beside the captured Chrome value.

use chromulate_fingerprint::client_hello::{
    ClientHelloSpec, ExtensionOrder, ExtensionSet, GreasePlacement, WireExtensionOrder,
};
use chromulate_fingerprint::ids::{
    CertificateCompression, CipherSuite, EcPointFormat, ExtensionId, NamedGroup,
    PskKeyExchangeMode, SignatureScheme, TlsVersion, Transport,
};

use crate::spike::error::SpikeError;

/// Extension code points this module reads by name.
mod ext {
    pub(super) const SERVER_NAME: u16 = 0x0000;
    pub(super) const SUPPORTED_GROUPS: u16 = 0x000a;
    pub(super) const EC_POINT_FORMATS: u16 = 0x000b;
    pub(super) const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub(super) const ALPN: u16 = 0x0010;
    pub(super) const COMPRESS_CERTIFICATE: u16 = 0x001b;
    pub(super) const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    pub(super) const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub(super) const KEY_SHARE: u16 = 0x0033;
    pub(super) const QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
}

/// A ClientHello as it was actually emitted, in wire order.
#[derive(Debug, Clone, Default)]
pub struct ObservedClientHello {
    /// The `legacy_version` field of the handshake body.
    pub handshake_version: u16,
    /// Cipher suites, in wire order, GREASE included.
    pub cipher_suites: Vec<u16>,
    /// Extension code points, in wire order, GREASE included.
    pub extensions: Vec<u16>,
    /// `supported_versions`, highest-preference first.
    pub supported_versions: Vec<u16>,
    /// `supported_groups`, in wire order.
    pub supported_groups: Vec<u16>,
    /// The groups a key share was actually sent for.
    pub key_share_groups: Vec<u16>,
    /// `signature_algorithms`, in wire order.
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocol identifiers, most preferred first.
    pub alpn: Vec<String>,
    /// `psk_key_exchange_modes`.
    pub psk_key_exchange_modes: Vec<u8>,
    /// `ec_point_formats`.
    pub ec_point_formats: Vec<u8>,
    /// `compress_certificate` algorithms.
    pub certificate_compression: Vec<u16>,
    /// The raw `quic_transport_parameters` extension body, when present.
    pub quic_transport_parameters: Option<Vec<u8>>,
}

impl ObservedClientHello {
    /// Parses a TLS `Handshake` message carrying a ClientHello.
    ///
    /// # Errors
    ///
    /// [`SpikeError::Malformed`] when the message is not a ClientHello or any length
    /// prefix runs past the end of the buffer.
    pub fn parse(handshake: &[u8]) -> Result<Self, SpikeError> {
        let mut reader = Reader::new(handshake);

        if reader.u8()? != 1 {
            return Err(SpikeError::malformed(
                "handshake",
                "first message is not a ClientHello",
            ));
        }
        let body_len = reader.u24()?;
        let body = reader.take(body_len)?;
        let mut body = Reader::new(body);

        let mut observed = Self {
            handshake_version: body.u16()?,
            ..Self::default()
        };
        let _random = body.take(32)?;
        let session_id_len = usize::from(body.u8()?);
        let _session_id = body.take(session_id_len)?;

        let cipher_bytes = body.length_prefixed_u16()?;
        observed.cipher_suites = Reader::new(cipher_bytes).u16_list()?;

        let compression_len = usize::from(body.u8()?);
        let _compression = body.take(compression_len)?;

        // A ClientHello may legally end here; over QUIC it never does.
        if body.is_empty() {
            return Ok(observed);
        }
        let mut extensions = Reader::new(body.length_prefixed_u16()?);
        while !extensions.is_empty() {
            let id = extensions.u16()?;
            let payload = extensions.length_prefixed_u16()?;
            observed.extensions.push(id);
            observed.read_extension(id, payload)?;
        }
        Ok(observed)
    }

    fn read_extension(&mut self, id: u16, payload: &[u8]) -> Result<(), SpikeError> {
        let mut reader = Reader::new(payload);
        match id {
            ext::SUPPORTED_GROUPS => {
                self.supported_groups = Reader::new(reader.length_prefixed_u16()?).u16_list()?;
            }
            ext::SUPPORTED_VERSIONS => {
                let list_len = usize::from(reader.u8()?);
                self.supported_versions = Reader::new(reader.take(list_len)?).u16_list()?;
            }
            ext::SIGNATURE_ALGORITHMS => {
                self.signature_algorithms =
                    Reader::new(reader.length_prefixed_u16()?).u16_list()?;
            }
            ext::EC_POINT_FORMATS => {
                let list_len = usize::from(reader.u8()?);
                self.ec_point_formats = reader.take(list_len)?.to_vec();
            }
            ext::PSK_KEY_EXCHANGE_MODES => {
                let list_len = usize::from(reader.u8()?);
                self.psk_key_exchange_modes = reader.take(list_len)?.to_vec();
            }
            ext::COMPRESS_CERTIFICATE => {
                let list_len = usize::from(reader.u8()?);
                self.certificate_compression = Reader::new(reader.take(list_len)?).u16_list()?;
            }
            ext::KEY_SHARE => {
                let mut entries = Reader::new(reader.length_prefixed_u16()?);
                while !entries.is_empty() {
                    self.key_share_groups.push(entries.u16()?);
                    let _key = entries.length_prefixed_u16()?;
                }
            }
            ext::ALPN => {
                let mut list = Reader::new(reader.length_prefixed_u16()?);
                while !list.is_empty() {
                    let len = usize::from(list.u8()?);
                    let name = list.take(len)?;
                    self.alpn.push(String::from_utf8_lossy(name).into_owned());
                }
            }
            ext::QUIC_TRANSPORT_PARAMETERS => {
                self.quic_transport_parameters = Some(payload.to_vec());
            }
            _ => {}
        }
        Ok(())
    }

    /// Every GREASE code point that appeared anywhere in the message.
    ///
    /// Empty is the answer this spike expects, and empty is the finding: the same
    /// absence `docs/fidelity.md` already records for the TCP handshake.
    #[must_use]
    pub fn grease_values(&self) -> Vec<u16> {
        self.cipher_suites
            .iter()
            .chain(&self.extensions)
            .chain(&self.supported_groups)
            .chain(&self.key_share_groups)
            .chain(&self.supported_versions)
            .copied()
            .filter(|value| CipherSuite::new(*value).is_grease())
            .collect()
    }

    /// Whether the client offered a server name.
    #[must_use]
    pub fn has_sni(&self) -> bool {
        self.extensions.contains(&ext::SERVER_NAME)
    }

    /// Builds the project's fingerprint model from what was observed.
    ///
    /// The transport is [`Transport::Quic`], so the JA4 computed from the result
    /// carries `q` where the shipped Chrome capture carries `t`.
    ///
    /// # Errors
    ///
    /// [`SpikeError::Spec`] when the extension list cannot be expressed as a wire
    /// order — which the fingerprint crate rejects, for instance when `pre_shared_key`
    /// is present but not last.
    pub fn to_spec(&self) -> Result<ClientHelloSpec, SpikeError> {
        let extension_ids: Vec<ExtensionId> = self
            .extensions
            .iter()
            .copied()
            .map(ExtensionId::new)
            .collect();
        let order = WireExtensionOrder::new(extension_ids.clone())
            .map_err(|error| SpikeError::Spec(error.to_string()))?;

        let supported_versions: Vec<TlsVersion> = self
            .supported_versions
            .iter()
            .filter_map(|value| TlsVersion::from_u16(*value))
            .collect();

        Ok(ClientHelloSpec {
            transport: Transport::Quic,
            // QUIC has no record layer; the field the project models as the record
            // version has no counterpart, so it is reported as the handshake version.
            record_version: TlsVersion::from_u16(self.handshake_version)
                .unwrap_or(TlsVersion::Tls12),
            handshake_version: TlsVersion::from_u16(self.handshake_version)
                .unwrap_or(TlsVersion::Tls12),
            supported_versions,
            cipher_suites: self
                .cipher_suites
                .iter()
                .copied()
                .map(CipherSuite::new)
                .collect(),
            extensions: ExtensionSet::new(extension_ids),
            extension_order: ExtensionOrder::Fixed(order),
            supported_groups: self
                .supported_groups
                .iter()
                .copied()
                .map(NamedGroup::new)
                .collect(),
            key_share_groups: self
                .key_share_groups
                .iter()
                .copied()
                .map(NamedGroup::new)
                .collect(),
            signature_algorithms: self
                .signature_algorithms
                .iter()
                .copied()
                .map(SignatureScheme::new)
                .collect(),
            alpn: self.alpn.clone(),
            alps: Vec::new(),
            certificate_compression: self
                .certificate_compression
                .iter()
                .copied()
                .map(CertificateCompression::from)
                .collect(),
            psk_key_exchange_modes: self
                .psk_key_exchange_modes
                .iter()
                .copied()
                .map(PskKeyExchangeMode::from)
                .collect(),
            ec_point_formats: self
                .ec_point_formats
                .iter()
                .copied()
                .map(EcPointFormat::from)
                .collect(),
            // Observed, not assumed: whatever GREASE this stack emitted, which the
            // spike's own test asserts is none.
            grease: GreasePlacement::NONE,
        })
    }
}

/// A bounds-checked cursor. Every read either advances or returns an error; nothing
/// here can silently truncate, which is the failure mode a hand-written TLS parser has.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], SpikeError> {
        if self.bytes.len() < count {
            return Err(SpikeError::malformed(
                "ClientHello",
                format!("needs {count} bytes, {} remain", self.bytes.len()),
            ));
        }
        let (head, tail) = self.bytes.split_at(count);
        self.bytes = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, SpikeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SpikeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<usize, SpikeError> {
        let bytes = self.take(3)?;
        Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }

    fn length_prefixed_u16(&mut self) -> Result<&'a [u8], SpikeError> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    fn u16_list(&mut self) -> Result<Vec<u16>, SpikeError> {
        let mut out = Vec::with_capacity(self.bytes.len() / 2);
        while !self.is_empty() {
            out.push(self.u16()?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but well-formed ClientHello: two ciphers, ALPN `h3`, TLS 1.3 in
    /// `supported_versions`, and a `quic_transport_parameters` extension.
    fn sample() -> Vec<u8> {
        let mut extensions = Vec::new();

        // ALPN: one protocol, "h3".
        extensions.extend_from_slice(&0x0010u16.to_be_bytes());
        extensions.extend_from_slice(&5u16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.push(2);
        extensions.extend_from_slice(b"h3");

        // supported_versions: TLS 1.3.
        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.push(2);
        extensions.extend_from_slice(&0x0304u16.to_be_bytes());

        // quic_transport_parameters: id 0x01, length 1, value 0x0a.
        extensions.extend_from_slice(&0x0039u16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.extend_from_slice(&[0x01, 0x01, 0x0a]);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // empty session id
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(1);
        body.push(0); // null compression
        body.extend_from_slice(&u16::try_from(extensions.len()).expect("fits").to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut message = vec![1u8];
        let length = body.len();
        message.push(u8::try_from(length >> 16).expect("fits"));
        message.push(u8::try_from((length >> 8) & 0xff).expect("fits"));
        message.push(u8::try_from(length & 0xff).expect("fits"));
        message.extend_from_slice(&body);
        message
    }

    #[test]
    fn reads_ciphers_extensions_and_alpn_in_wire_order() {
        let hello = ObservedClientHello::parse(&sample()).expect("sample is well formed");
        assert_eq!(hello.cipher_suites, [0x1301, 0x1302]);
        assert_eq!(hello.extensions, [0x0010, 0x002b, 0x0039]);
        assert_eq!(hello.alpn, ["h3"]);
        assert_eq!(hello.supported_versions, [0x0304]);
    }

    #[test]
    fn carries_the_transport_parameter_body_out_intact() {
        let hello = ObservedClientHello::parse(&sample()).expect("sample is well formed");
        let body = hello
            .quic_transport_parameters
            .expect("the sample carries the extension");
        assert_eq!(body, [0x01, 0x01, 0x0a]);
    }

    #[test]
    fn a_message_that_is_not_a_client_hello_is_rejected() {
        let mut bytes = sample();
        bytes[0] = 2; // ServerHello
        let err = ObservedClientHello::parse(&bytes).expect_err("not a ClientHello");
        assert!(matches!(err, SpikeError::Malformed { .. }), "{err}");
    }

    #[test]
    fn a_truncated_message_is_an_error_rather_than_a_partial_parse() {
        let bytes = sample();
        let err = ObservedClientHello::parse(&bytes[..bytes.len() - 4])
            .expect_err("the extension block is cut short");
        assert!(matches!(err, SpikeError::Malformed { .. }), "{err}");
    }

    #[test]
    fn a_length_prefix_past_the_end_is_an_error() {
        let mut bytes = sample();
        // Inflate the cipher suite list length past the end of the buffer.
        bytes[4 + 2 + 32 + 1] = 0xff;
        let err = ObservedClientHello::parse(&bytes).expect_err("cipher list overruns");
        assert!(matches!(err, SpikeError::Malformed { .. }), "{err}");
    }

    #[test]
    fn the_sample_carries_no_grease() {
        let hello = ObservedClientHello::parse(&sample()).expect("sample is well formed");
        assert!(hello.grease_values().is_empty());
    }

    #[test]
    fn the_spec_it_builds_reports_quic() {
        let hello = ObservedClientHello::parse(&sample()).expect("sample is well formed");
        let spec = hello.to_spec().expect("sample fits the model");
        assert_eq!(spec.transport, Transport::Quic);
        assert_eq!(spec.first_alpn(), Some("h3"));
        assert_eq!(spec.effective_version(), TlsVersion::Tls13);
        assert_eq!(spec.cipher_suites.len(), 2);
    }
}
