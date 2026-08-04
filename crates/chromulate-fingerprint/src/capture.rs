//! The capture document format, and the parser that turns one into specs.
//!
//! A capture is a recording of what a real browser put on the wire. Chromulate
//! never invents fingerprint constants, so this schema is the only supported
//! way to teach the library about a browser it does not ship with: record a
//! handshake, write it down in this shape, and load it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::client_hello::{
    ClientHelloSpec, ExtensionOrder, ExtensionSet, GreasePlacement, WireExtensionOrder,
};
use crate::error::CaptureError;
use crate::http2::{
    HeadersPriority, Http2Spec, PriorityFrame, PseudoHeader, PseudoHeaderOrder, Setting, SettingId,
};
use crate::ids::{
    CertificateCompression, CipherSuite, EcPointFormat, ExtensionId, NamedGroup,
    PskKeyExchangeMode, SignatureScheme, TlsVersion, Transport,
};

/// A recorded browser capture.
#[derive(Debug, Clone, Deserialize)]
pub struct Capture {
    /// Where the recording came from.
    #[serde(rename = "_provenance")]
    pub provenance: Provenance,

    /// The verified finding that this client permutes its extension order.
    ///
    /// When present and verified, the loaded spec shuffles rather than
    /// reproducing the one order that happened to be recorded.
    #[serde(rename = "_finding_extension_order_is_randomised", default)]
    pub extension_order_finding: Option<Finding>,

    /// The fingerprints observed on a fresh connection.
    pub sample_navigate: Sample,

    /// The fingerprints observed on a resumed connection, if one was recorded.
    #[serde(default)]
    pub sample_clean: Option<Sample>,

    /// The recorded ClientHello.
    pub client_hello: ClientHelloCapture,

    /// The recorded HTTP/2 connection.
    pub http2: Http2Capture,
}

/// Where a capture came from, so a fingerprint can always be traced back.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Provenance {
    /// What was recorded and how to read it.
    pub description: String,
    /// The browser name and build.
    pub browser: String,
    /// The platform it ran on.
    pub platform: String,
    /// The endpoint that echoed the handshake back.
    pub endpoint: String,
    /// The capture date.
    pub captured_at: String,
    /// How the capture was driven.
    pub capture_method: String,
    /// The user agent the browser sent.
    pub user_agent: String,
}

/// A recorded, verified claim about the capture.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Finding {
    /// What was claimed.
    pub claim: String,
    /// The observation supporting it.
    pub evidence: String,
    /// Whether the claim was confirmed during capture.
    pub verified: bool,
}

/// The fingerprints observed on one connection.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Sample {
    /// A note describing the connection.
    #[serde(default)]
    pub note: Option<String>,
    /// The observed JA3 string.
    pub ja3: String,
    /// The observed JA3 MD5.
    pub ja3_hash: String,
    /// The observed JA4 fingerprint.
    pub ja4: String,
    /// The observed raw JA4.
    pub ja4_r: String,
    /// The observed Akamai HTTP/2 fingerprint.
    pub akamai_fingerprint: String,
    /// The observed Akamai MD5.
    pub akamai_fingerprint_hash: String,
}

impl Sample {
    /// Returns the extension list recorded in the third JA3 field.
    ///
    /// The JA3 string is the authoritative record of what was on the wire, so
    /// this is what the loader trusts when a document's extension set and its
    /// JA3 disagree.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::MalformedJa3`] when the string does not have
    /// five comma-separated fields of decimal code points.
    pub fn ja3_extensions(&self) -> Result<Vec<ExtensionId>, CaptureError> {
        let fields: Vec<&str> = self.ja3.split(',').collect();
        if fields.len() != 5 {
            return Err(CaptureError::MalformedJa3 {
                reason: format!("expected 5 comma separated fields, found {}", fields.len()),
            });
        }
        parse_dashed(fields[2])
            .map(|values| values.into_iter().map(ExtensionId::new).collect())
            .map_err(|value| CaptureError::MalformedJa3 {
                reason: format!("extension field contains {value:?}, which is not a code point"),
            })
    }

    /// Returns the extension order recorded in the third JA3 field.
    ///
    /// # Errors
    ///
    /// Returns an error when the JA3 string is malformed, or when the recorded
    /// order violates a wire invariant.
    pub fn ja3_extension_order(&self) -> Result<WireExtensionOrder, CaptureError> {
        Ok(WireExtensionOrder::new(self.ja3_extensions()?)?)
    }
}

/// A recorded ClientHello.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientHelloCapture {
    /// The record layer version.
    pub record_version: u16,
    /// The handshake version.
    pub handshake_version: u16,
    /// Cipher suites in wire order, `"GREASE"` marking a GREASE slot.
    pub cipher_suites_in_wire_order: Vec<CodePoint>,
    /// The extensions offered, sorted, excluding GREASE.
    pub extension_set_sorted: Vec<u16>,
    /// The extensions offered when a session ticket is available.
    #[serde(default)]
    pub extension_set_with_resumption_sorted: Option<Vec<u16>>,
    /// The `supported_groups` list.
    pub supported_groups: Vec<CodePoint>,
    /// The groups a key share was sent for.
    pub key_share_groups: Vec<CodePoint>,
    /// The `supported_versions` list.
    pub supported_versions: Vec<CodePoint>,
    /// The `signature_algorithms` list, in wire order.
    pub signature_algorithms: Vec<CodePoint>,
    /// ALPN protocol identifiers.
    pub alpn: Vec<String>,
    /// ALPS protocol identifiers.
    #[serde(default)]
    pub alps: Vec<String>,
    /// Certificate compression algorithm names.
    #[serde(default)]
    pub certificate_compression: Vec<String>,
    /// PSK key exchange mode names.
    #[serde(default)]
    pub psk_key_exchange_modes: Vec<String>,
    /// EC point format names.
    #[serde(default)]
    pub ec_point_formats: Vec<String>,
    /// The positions GREASE was observed in.
    #[serde(default)]
    pub grease_positions: Vec<String>,
}

/// A recorded HTTP/2 connection.
///
/// The header fields here describe the browser rather than the protocol; they
/// live in the same document because they were observed on the same
/// connection, and `chromulate-profile` reads them from here.
#[derive(Debug, Clone, Deserialize)]
pub struct Http2Capture {
    /// The SETTINGS entries in the order they were sent.
    pub settings_in_order: Vec<SettingCapture>,
    /// The connection-level WINDOW_UPDATE increment.
    #[serde(default)]
    pub connection_window_update_increment: u32,
    /// The pseudo-header order.
    pub pseudo_header_order: Vec<String>,
    /// The priority fields on the first HEADERS frame.
    #[serde(default)]
    pub headers_frame_priority: Option<HeadersPriorityCapture>,
    /// PRIORITY frames sent before the first request.
    #[serde(default)]
    pub priority_frames: Vec<PriorityFrameCapture>,
    /// The header order observed on a top level navigation.
    #[serde(default)]
    pub navigate_request_header_order: Vec<String>,
    /// The header order observed on a subresource fetch.
    #[serde(default)]
    pub subresource_request_header_order: Option<Vec<String>>,
    /// The header values observed on the wire.
    #[serde(default)]
    pub observed_header_values: BTreeMap<String, String>,
}

/// A recorded SETTINGS entry.
#[derive(Debug, Clone, Deserialize)]
pub struct SettingCapture {
    /// The setting identifier.
    pub id: u16,
    /// The advertised value.
    pub value: u32,
}

/// Recorded HEADERS frame priority fields.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct HeadersPriorityCapture {
    /// The weight, in the 1..=256 form.
    pub weight: u16,
    /// The stream depended on.
    pub depends_on: u32,
    /// Whether the dependency is exclusive.
    pub exclusive: bool,
}

/// A recorded PRIORITY frame.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct PriorityFrameCapture {
    /// The stream the frame applies to.
    pub stream_id: u32,
    /// Whether the dependency is exclusive.
    pub exclusive: bool,
    /// The stream depended on.
    pub depends_on: u32,
    /// The weight, in the 1..=256 form.
    pub weight: u16,
}

/// A code point as a capture writes it: a number, `"GREASE"`, or `"0x1301"`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CodePoint {
    /// A decimal code point.
    Number(u16),
    /// A textual code point: the marker `GREASE`, or a `0x` hex literal.
    Text(String),
}

impl CodePoint {
    /// Resolves the code point, returning `None` for a GREASE marker.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::UnknownCodePoint`] for text that is neither
    /// `GREASE` nor a `0x` hex literal in range.
    pub fn value(&self, field: &'static str) -> Result<Option<u16>, CaptureError> {
        match self {
            Self::Number(value) => Ok(Some(*value)),
            Self::Text(text) if text.eq_ignore_ascii_case("GREASE") => Ok(None),
            Self::Text(text) => {
                let digits = text
                    .strip_prefix("0x")
                    .or_else(|| text.strip_prefix("0X"))
                    .ok_or_else(|| CaptureError::UnknownCodePoint {
                        field,
                        value: text.clone(),
                    })?;
                u16::from_str_radix(digits, 16).map(Some).map_err(|_| {
                    CaptureError::UnknownCodePoint {
                        field,
                        value: text.clone(),
                    }
                })
            }
        }
    }
}

/// Resolves a list of code points, reporting whether a GREASE marker was seen.
fn resolve(values: &[CodePoint], field: &'static str) -> Result<(Vec<u16>, bool), CaptureError> {
    let mut resolved = Vec::with_capacity(values.len());
    let mut grease = false;
    for value in values {
        match value.value(field)? {
            Some(value) => resolved.push(value),
            None => grease = true,
        }
    }
    Ok((resolved, grease))
}

fn parse_dashed(field: &str) -> Result<Vec<u16>, String> {
    if field.is_empty() {
        return Ok(Vec::new());
    }
    field
        .split('-')
        .map(|value| value.parse::<u16>().map_err(|_| value.to_owned()))
        .collect()
}

fn version(value: u16, field: &'static str) -> Result<TlsVersion, CaptureError> {
    TlsVersion::from_u16(value).ok_or(CaptureError::ValueOutOfRange {
        field,
        value: u64::from(value),
        width: 16,
    })
}

impl Capture {
    /// Parses a capture document.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::Json`] when the document is not valid JSON or
    /// does not match the schema.
    pub fn parse(json: &str) -> Result<Self, CaptureError> {
        serde_json::from_str(json).map_err(|error| CaptureError::Json {
            message: error.to_string(),
        })
    }

    /// Returns `true` when the capture records a verified finding that this
    /// client permutes its extension order.
    #[must_use]
    pub fn extension_order_is_randomised(&self) -> bool {
        self.extension_order_finding
            .as_ref()
            .is_some_and(|finding| finding.verified)
    }

    /// Builds the ClientHello spec the capture describes.
    ///
    /// The extension set is the union of `extension_set_sorted` and the
    /// extensions recorded in the navigate sample's JA3 string. The union is
    /// needed because a capture's convenience listing can omit an extension the
    /// handshake carried — the shipped Chrome 151 capture omits `server_name`
    /// from `extension_set_sorted` while its JA3 records it — and every member
    /// of the union is still observed data.
    ///
    /// The union only covers that one direction. For a client that does not
    /// permute, the recorded order is the whole handshake, so an extension the
    /// set claims and the order omits is a contradiction rather than a gap, and
    /// it is refused rather than papered over.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError`] when a code point, name, or GREASE position is
    /// unrecognised, when the recorded order violates a wire invariant, or when
    /// a non-permuting capture's extension set and recorded order disagree.
    pub fn client_hello(&self) -> Result<ClientHelloSpec, CaptureError> {
        let hello = &self.client_hello;

        let (ciphers, grease_ciphers) = resolve(
            &hello.cipher_suites_in_wire_order,
            "cipher_suites_in_wire_order",
        )?;
        let (groups, grease_groups) = resolve(&hello.supported_groups, "supported_groups")?;
        let (key_shares, grease_key_shares) = resolve(&hello.key_share_groups, "key_share_groups")?;
        let (versions, grease_versions) = resolve(&hello.supported_versions, "supported_versions")?;
        let (signatures, _) = resolve(&hello.signature_algorithms, "signature_algorithms")?;

        let mut extensions = ExtensionSet::new(
            hello
                .extension_set_sorted
                .iter()
                .copied()
                .map(ExtensionId::new),
        );
        for id in self.sample_navigate.ja3_extensions()? {
            extensions.insert(id);
        }

        let mut grease = self.grease_placement()?;
        grease.cipher_suites |= grease_ciphers;
        grease.supported_groups |= grease_groups;
        grease.key_shares |= grease_key_shares;
        grease.supported_versions |= grease_versions;

        let extension_order = if self.extension_order_is_randomised() {
            ExtensionOrder::shuffled()
        } else {
            let order = self.sample_navigate.ja3_extension_order()?;
            // For a client that does not permute, the recorded order is the
            // whole handshake rather than one sample of many, so an extension
            // the set claims and the order omits is not a gap the union can
            // close: the two sides describe different handshakes.
            if let Some(missing) = extensions
                .iter()
                .find(|id| !order.iter().any(|recorded| recorded == *id))
            {
                return Err(CaptureError::InconsistentExtensionSet {
                    value: missing.get(),
                    ja3_order: order.iter().map(ExtensionId::get).collect(),
                });
            }
            ExtensionOrder::Fixed(order)
        };

        let mut supported_versions = Vec::with_capacity(versions.len());
        for value in versions {
            supported_versions.push(version(value, "supported_versions")?);
        }

        Ok(ClientHelloSpec {
            transport: if hello.alpn.iter().any(|protocol| protocol == "h3") {
                Transport::Quic
            } else {
                Transport::Tcp
            },
            record_version: version(hello.record_version, "record_version")?,
            handshake_version: version(hello.handshake_version, "handshake_version")?,
            supported_versions,
            cipher_suites: ciphers.into_iter().map(CipherSuite::new).collect(),
            extensions,
            extension_order,
            supported_groups: groups.into_iter().map(NamedGroup::new).collect(),
            key_share_groups: key_shares.into_iter().map(NamedGroup::new).collect(),
            signature_algorithms: signatures.into_iter().map(SignatureScheme::new).collect(),
            alpn: hello.alpn.clone(),
            alps: hello.alps.clone(),
            certificate_compression: named(
                &hello.certificate_compression,
                "certificate_compression",
                CertificateCompression::from_name,
            )?,
            psk_key_exchange_modes: named(
                &hello.psk_key_exchange_modes,
                "psk_key_exchange_modes",
                PskKeyExchangeMode::from_name,
            )?,
            ec_point_formats: named(
                &hello.ec_point_formats,
                "ec_point_formats",
                EcPointFormat::from_name,
            )?,
            grease,
        })
    }

    /// Builds the HTTP/2 spec the capture describes.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError`] when the pseudo-header order is not the four
    /// request pseudo-headers.
    pub fn http2(&self) -> Result<Http2Spec, CaptureError> {
        let http2 = &self.http2;

        let mut order = Vec::with_capacity(4);
        for name in &http2.pseudo_header_order {
            let header = PseudoHeader::from_name(name).ok_or_else(|| {
                CaptureError::InvalidPseudoHeaderOrder {
                    value: http2.pseudo_header_order.join(","),
                }
            })?;
            order.push(header);
        }
        let order: [PseudoHeader; 4] =
            order
                .try_into()
                .map_err(|_| CaptureError::InvalidPseudoHeaderOrder {
                    value: http2.pseudo_header_order.join(","),
                })?;

        Ok(Http2Spec {
            settings: http2
                .settings_in_order
                .iter()
                .map(|setting| Setting::new(SettingId::new(setting.id), setting.value))
                .collect(),
            connection_window_update: http2.connection_window_update_increment,
            priority_frames: http2
                .priority_frames
                .iter()
                .map(|frame| PriorityFrame {
                    stream_id: frame.stream_id,
                    exclusive: frame.exclusive,
                    depends_on: frame.depends_on,
                    weight: frame.weight,
                })
                .collect(),
            headers_priority: http2
                .headers_frame_priority
                .map(|priority| HeadersPriority {
                    depends_on: priority.depends_on,
                    exclusive: priority.exclusive,
                    weight: priority.weight,
                }),
            pseudo_header_order: PseudoHeaderOrder::new(order)?,
        })
    }

    /// Returns the extension set observed when a session ticket was available,
    /// if the capture recorded one.
    #[must_use]
    pub fn resumption_extensions(&self) -> Option<ExtensionSet> {
        self.client_hello
            .extension_set_with_resumption_sorted
            .as_ref()
            .map(|ids| ExtensionSet::new(ids.iter().copied().map(ExtensionId::new)))
    }

    fn grease_placement(&self) -> Result<GreasePlacement, CaptureError> {
        let mut placement = GreasePlacement::NONE;
        for position in &self.client_hello.grease_positions {
            match position.as_str() {
                "first cipher suite" => placement.cipher_suites = true,
                "first extension" | "last extension" => placement.extensions = true,
                "first supported group" => placement.supported_groups = true,
                "first key share" => placement.key_shares = true,
                "first supported version" => placement.supported_versions = true,
                other => {
                    return Err(CaptureError::UnknownGreasePosition {
                        value: other.to_owned(),
                    });
                }
            }
        }
        Ok(placement)
    }
}

fn named<T>(
    names: &[String],
    field: &'static str,
    lookup: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>, CaptureError> {
    names
        .iter()
        .map(|name| {
            lookup(name).ok_or_else(|| CaptureError::UnknownName {
                field,
                value: name.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grease_marker_resolves_to_no_code_point() {
        let values = vec![
            CodePoint::Text("GREASE".to_owned()),
            CodePoint::Number(4865),
        ];
        let (resolved, grease) = resolve(&values, "test").expect("GREASE and a number resolve");
        assert_eq!(resolved, vec![4865]);
        assert!(grease);
    }

    #[test]
    fn a_hex_code_point_resolves_to_its_numeric_value() {
        let value = CodePoint::Text("0x0904".to_owned());
        assert_eq!(value.value("test").expect("hex resolves"), Some(0x0904));
    }

    #[test]
    fn an_unrecognised_code_point_is_an_error_rather_than_a_silent_skip() {
        let value = CodePoint::Text("probably_x25519".to_owned());
        assert!(matches!(
            value.value("test"),
            Err(CaptureError::UnknownCodePoint { .. })
        ));
    }

    /// A capture with every field empty, for tests that vary one at a time.
    ///
    /// It records no shuffling finding, so it takes the `Fixed` branch: the
    /// shape a Firefox or Safari capture has, and the one `from_capture` exists
    /// to serve.
    fn minimal_fixed_capture() -> Capture {
        Capture {
            provenance: Provenance {
                description: String::new(),
                browser: String::new(),
                platform: String::new(),
                endpoint: String::new(),
                captured_at: String::new(),
                capture_method: String::new(),
                user_agent: String::new(),
            },
            extension_order_finding: None,
            sample_navigate: Sample {
                note: None,
                ja3: String::new(),
                ja3_hash: String::new(),
                ja4: String::new(),
                ja4_r: String::new(),
                akamai_fingerprint: String::new(),
                akamai_fingerprint_hash: String::new(),
            },
            sample_clean: None,
            client_hello: ClientHelloCapture {
                record_version: 771,
                handshake_version: 771,
                cipher_suites_in_wire_order: Vec::new(),
                extension_set_sorted: Vec::new(),
                extension_set_with_resumption_sorted: None,
                supported_groups: Vec::new(),
                key_share_groups: Vec::new(),
                supported_versions: Vec::new(),
                signature_algorithms: Vec::new(),
                alpn: Vec::new(),
                alps: Vec::new(),
                certificate_compression: Vec::new(),
                psk_key_exchange_modes: Vec::new(),
                ec_point_formats: Vec::new(),
                grease_positions: Vec::new(),
            },
            http2: Http2Capture {
                settings_in_order: Vec::new(),
                connection_window_update_increment: 0,
                pseudo_header_order: Vec::new(),
                headers_frame_priority: None,
                priority_frames: Vec::new(),
                navigate_request_header_order: Vec::new(),
                subresource_request_header_order: None,
                observed_header_values: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn an_unrecognised_grease_position_is_an_error() {
        let mut capture = minimal_fixed_capture();
        capture.client_hello.grease_positions = vec!["somewhere in the middle".to_owned()];

        assert!(matches!(
            capture.grease_placement(),
            Err(CaptureError::UnknownGreasePosition { .. })
        ));
    }

    #[test]
    fn a_capture_listing_an_extension_its_recorded_order_does_not_carry_is_rejected() {
        let mut capture = minimal_fixed_capture();
        capture.sample_navigate.ja3 = "771,4865,0-10-11,29,0".to_owned();
        // `padding` is claimed as offered, but the handshake this capture
        // recorded did not carry it.
        capture.client_hello.extension_set_sorted = vec![0, 10, 11, 21];

        let error = capture
            .client_hello()
            .expect_err("a capture that contradicts itself must not become a profile");
        assert_eq!(
            error,
            CaptureError::InconsistentExtensionSet {
                value: 21,
                ja3_order: vec![0, 10, 11],
            }
        );
        let message = error.to_string();
        assert!(
            message.contains("0x0015") && message.contains("[0, 10, 11]"),
            "the error must name both sides of the disagreement: {message}"
        );
    }

    #[test]
    fn a_recorded_order_carrying_an_extension_the_set_omits_still_loads() {
        // The shipped Chrome capture has exactly this gap: `server_name` is in
        // both recorded JA3 strings but not in `extension_set_sorted`. The
        // union covers it, and it cannot produce contradictory counts, because
        // the recorded order is the wider of the two sides.
        let mut capture = minimal_fixed_capture();
        capture.sample_navigate.ja3 = "771,4865,0-10-11,29,0".to_owned();
        capture.client_hello.extension_set_sorted = vec![10, 11];

        let spec = capture
            .client_hello()
            .expect("the documented union still loads");
        assert_eq!(spec.extensions.len(), 3);
    }

    #[test]
    fn a_shuffling_capture_is_not_held_to_one_recorded_order() {
        // Chrome permutes, so its recorded order is one sample rather than the
        // client's whole story, and a set wider than that sample is expected.
        let mut capture = minimal_fixed_capture();
        capture.extension_order_finding = Some(Finding {
            claim: String::new(),
            evidence: String::new(),
            verified: true,
        });
        capture.sample_navigate.ja3 = "771,4865,0-10-11,29,0".to_owned();
        capture.client_hello.extension_set_sorted = vec![0, 10, 11, 21];

        let spec = capture
            .client_hello()
            .expect("a shuffling capture records a permutation, not the only legal order");
        assert!(spec.extension_order.is_shuffled());
        assert_eq!(spec.extensions.len(), 4);
    }
}
