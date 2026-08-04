//! The HTTP/2 connection model the Akamai fingerprint is computed from.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SpecError;

/// An HTTP/2 SETTINGS identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SettingId(u16);

impl SettingId {
    /// `SETTINGS_HEADER_TABLE_SIZE`.
    pub const HEADER_TABLE_SIZE: Self = Self(0x1);
    /// `SETTINGS_ENABLE_PUSH`.
    pub const ENABLE_PUSH: Self = Self(0x2);
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`.
    pub const MAX_CONCURRENT_STREAMS: Self = Self(0x3);
    /// `SETTINGS_INITIAL_WINDOW_SIZE`.
    pub const INITIAL_WINDOW_SIZE: Self = Self(0x4);
    /// `SETTINGS_MAX_FRAME_SIZE`.
    pub const MAX_FRAME_SIZE: Self = Self(0x5);
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`.
    pub const MAX_HEADER_LIST_SIZE: Self = Self(0x6);
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
    pub const ENABLE_CONNECT_PROTOCOL: Self = Self(0x8);
    /// `SETTINGS_NO_RFC7540_PRIORITIES`.
    pub const NO_RFC7540_PRIORITIES: Self = Self(0x9);

    /// Wraps a raw settings identifier.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw settings identifier.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for SettingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One entry of the SETTINGS frame. Order is part of the fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
    /// The setting identifier.
    pub id: SettingId,
    /// The advertised value.
    pub value: u32,
}

impl Setting {
    /// Builds a setting.
    #[must_use]
    pub const fn new(id: SettingId, value: u32) -> Self {
        Self { id, value }
    }
}

/// A PRIORITY frame, as counted by the Akamai fingerprint's third field.
///
/// Chrome 151 sends none of these; it expresses priority with the `priority`
/// request header instead, which is why the captured fingerprint's third field
/// is a bare `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorityFrame {
    /// The stream the frame applies to.
    pub stream_id: u32,
    /// Whether the dependency is exclusive.
    pub exclusive: bool,
    /// The stream depended on.
    pub depends_on: u32,
    /// The weight, in the 1..=256 form the Akamai fingerprint prints.
    pub weight: u16,
}

/// The priority fields carried on the first HEADERS frame.
///
/// This is not part of the Akamai fingerprint string, which only counts
/// PRIORITY frames, but a client has to reproduce it to look right on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersPriority {
    /// The stream depended on.
    pub depends_on: u32,
    /// Whether the dependency is exclusive.
    pub exclusive: bool,
    /// The weight, in the 1..=256 form.
    pub weight: u16,
}

/// An HTTP/2 request pseudo-header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PseudoHeader {
    /// `:method`.
    Method,
    /// `:authority`.
    Authority,
    /// `:scheme`.
    Scheme,
    /// `:path`.
    Path,
}

impl PseudoHeader {
    /// Returns the header name, colon included.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Method => ":method",
            Self::Authority => ":authority",
            Self::Scheme => ":scheme",
            Self::Path => ":path",
        }
    }

    /// Returns the single character the Akamai fingerprint uses.
    #[must_use]
    pub const fn code(self) -> char {
        match self {
            Self::Method => 'm',
            Self::Authority => 'a',
            Self::Scheme => 's',
            Self::Path => 'p',
        }
    }

    /// Parses a pseudo-header name, with or without its leading colon.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.strip_prefix(':').unwrap_or(name) {
            "method" => Some(Self::Method),
            "authority" => Some(Self::Authority),
            "scheme" => Some(Self::Scheme),
            "path" => Some(Self::Path),
            _ => None,
        }
    }
}

/// The order the four request pseudo-headers are emitted in.
///
/// The constructor rejects a list that repeats one, so holding this type means
/// holding a permutation of all four rather than an arbitrary list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "[PseudoHeader; 4]", into = "[PseudoHeader; 4]")]
pub struct PseudoHeaderOrder([PseudoHeader; 4]);

impl PseudoHeaderOrder {
    /// The order Chrome emits, `:method :authority :scheme :path`.
    pub const CHROME: Self = Self([
        PseudoHeader::Method,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
        PseudoHeader::Path,
    ]);

    /// Validates and wraps an order.
    ///
    /// # Errors
    ///
    /// Returns [`SpecError::DuplicatePseudoHeader`] when a pseudo-header
    /// repeats, which also means one is missing.
    pub fn new(order: [PseudoHeader; 4]) -> Result<Self, SpecError> {
        for (index, header) in order.iter().enumerate() {
            if order[..index].contains(header) {
                return Err(SpecError::DuplicatePseudoHeader {
                    name: header.as_str(),
                });
            }
        }
        Ok(Self(order))
    }

    /// Returns the order as a slice.
    #[must_use]
    pub const fn as_slice(&self) -> &[PseudoHeader; 4] {
        &self.0
    }

    /// Renders the order as the Akamai fingerprint's fourth field, `m,a,s,p`.
    #[must_use]
    pub fn code(&self) -> String {
        let mut out = String::with_capacity(7);
        for (index, header) in self.0.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push(header.code());
        }
        out
    }
}

impl TryFrom<[PseudoHeader; 4]> for PseudoHeaderOrder {
    type Error = SpecError;

    fn try_from(order: [PseudoHeader; 4]) -> Result<Self, Self::Error> {
        Self::new(order)
    }
}

impl From<PseudoHeaderOrder> for [PseudoHeader; 4] {
    fn from(order: PseudoHeaderOrder) -> Self {
        order.0
    }
}

/// Everything an observer can derive an HTTP/2 fingerprint from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http2Spec {
    /// The SETTINGS frame entries, in the order they are sent.
    pub settings: Vec<Setting>,
    /// The increment of the connection-level WINDOW_UPDATE, or 0 when none is sent.
    pub connection_window_update: u32,
    /// PRIORITY frames sent before the first request.
    pub priority_frames: Vec<PriorityFrame>,
    /// The priority fields on the first HEADERS frame, if it carries any.
    pub headers_priority: Option<HeadersPriority>,
    /// The pseudo-header order.
    pub pseudo_header_order: PseudoHeaderOrder,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pseudo_header_order_rejects_a_repeated_entry() {
        let error = PseudoHeaderOrder::new([
            PseudoHeader::Method,
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
        ])
        .expect_err("a repeated pseudo-header must be rejected");
        assert_eq!(error, SpecError::DuplicatePseudoHeader { name: ":method" });
    }

    #[test]
    fn the_chrome_pseudo_header_order_renders_as_masp() {
        assert_eq!(PseudoHeaderOrder::CHROME.code(), "m,a,s,p");
    }

    #[test]
    fn pseudo_header_names_parse_with_and_without_the_colon() {
        assert_eq!(
            PseudoHeader::from_name(":authority"),
            Some(PseudoHeader::Authority)
        );
        assert_eq!(
            PseudoHeader::from_name("authority"),
            Some(PseudoHeader::Authority)
        );
        assert_eq!(PseudoHeader::from_name(":status"), None);
    }
}
