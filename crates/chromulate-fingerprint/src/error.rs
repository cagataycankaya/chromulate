//! Errors raised when building a spec or reading a capture document.

use thiserror::Error;

/// A spec was rejected because it violates a wire-format invariant.
///
/// These are not I/O failures: they mean the described ClientHello or HTTP/2
/// connection could not be produced by a conforming client, so refusing it
/// early is cheaper than shipping a fingerprint no real browser emits.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SpecError {
    /// The same extension identifier was listed twice in one ClientHello.
    #[error("extension {value:#06x} appears more than once in the extension order")]
    DuplicateExtension {
        /// The repeated extension identifier.
        value: u16,
    },

    /// `pre_shared_key` was not the final extension.
    ///
    /// RFC 8446 section 4.2.11 requires it to be last so that the binder can be
    /// computed over the truncated ClientHello.
    #[error(
        "pre_shared_key is at index {index} of {len} extensions but RFC 8446 4.2.11 requires it to be last"
    )]
    PreSharedKeyNotLast {
        /// Index at which `pre_shared_key` was found.
        index: usize,
        /// Total number of extensions in the order.
        len: usize,
    },

    /// A GREASE extension appeared somewhere other than the edges of the list.
    #[error(
        "GREASE extension {value:#06x} at index {index} is neither the first nor the last slot"
    )]
    MisplacedGrease {
        /// The GREASE value that was misplaced.
        value: u16,
        /// Index at which it was found.
        index: usize,
    },

    /// A shuffled order tried to pin an extension the wire format places itself.
    ///
    /// `pre_shared_key` has to be the final extension (RFC 8446 section 4.2.11)
    /// and GREASE has to bracket the list, so the generator positions both. A
    /// pin for either could only contradict it.
    #[error("extension {value:#06x} cannot be pinned: {reason}")]
    UnpinnableExtension {
        /// The extension identifier that was pinned.
        value: u16,
        /// Why the wire format does not leave this extension's place open.
        reason: &'static str,
    },

    /// The same pseudo-header was listed twice in an HTTP/2 pseudo-header order.
    #[error("pseudo-header {name} appears more than once in the pseudo-header order")]
    DuplicatePseudoHeader {
        /// The repeated pseudo-header name, including its leading colon.
        name: &'static str,
    },
}

/// A capture document could not be read, or could not be turned into a spec.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// The document is not valid JSON, or does not match the capture schema.
    #[error("capture is not a valid capture document: {message}")]
    Json {
        /// The underlying serde error rendered as text.
        message: String,
    },

    /// A code point was neither a number, `GREASE`, nor a `0x` hex literal.
    #[error("unrecognised code point {value:?} in field {field}")]
    UnknownCodePoint {
        /// The capture field the value came from.
        field: &'static str,
        /// The value as it appeared in the document.
        value: String,
    },

    /// A symbolic name has no known code point in the relevant IANA registry.
    #[error("unrecognised name {value:?} in field {field}")]
    UnknownName {
        /// The capture field the name came from.
        field: &'static str,
        /// The name as it appeared in the document.
        value: String,
    },

    /// A `grease_positions` entry did not name a position this model knows.
    ///
    /// This is an error rather than a silent skip: dropping a GREASE position
    /// would silently change every fingerprint computed from the capture.
    #[error("unrecognised GREASE position {value:?}")]
    UnknownGreasePosition {
        /// The position string as it appeared in the document.
        value: String,
    },

    /// The capture's extension set and its recorded handshake disagree.
    ///
    /// Only raised for a client that does not permute its extension order, where
    /// the recorded JA3 is the authoritative account of one handshake rather than
    /// one sample of many. An extension the set claims but the order does not
    /// carry means the document describes two different handshakes, which would
    /// otherwise load into a profile whose JA3 and JA4 report different extension
    /// counts for the same connection.
    #[error(
        "capture lists extension {value:#06x} in extension_set_sorted, but the recorded JA3 order {ja3_order:?} does not carry it"
    )]
    InconsistentExtensionSet {
        /// The first extension the set claims and the recorded order omits.
        value: u16,
        /// The extension order the recorded JA3 string carries.
        ja3_order: Vec<u16>,
    },

    /// A recorded JA3 string did not have the expected five comma-separated fields.
    #[error("recorded JA3 string is malformed: {reason}")]
    MalformedJa3 {
        /// What was wrong with the string.
        reason: String,
    },

    /// The pseudo-header order was not the four HTTP/2 request pseudo-headers.
    #[error("pseudo-header order {value:?} is not a valid HTTP/2 request pseudo-header list")]
    InvalidPseudoHeaderOrder {
        /// The list as it appeared in the document.
        value: String,
    },

    /// A numeric field did not fit the width the protocol allows.
    #[error("value {value} in field {field} does not fit in {width} bits")]
    ValueOutOfRange {
        /// The capture field the value came from.
        field: &'static str,
        /// The offending value.
        value: u64,
        /// The number of bits the wire format allows.
        width: u32,
    },

    /// The capture describes a ClientHello that violates a wire invariant.
    #[error(transparent)]
    Spec(#[from] SpecError),
}
