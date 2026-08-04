//! Decoding the QUIC transport parameters extension (RFC 9000 section 18).
//!
//! The extension body is a sequence of `(id, length, value)` triples, each of the first
//! two encoded as a QUIC variable-length integer (RFC 9000 section 16). The *order* of
//! the triples is part of what a server observes, which is the reason this decoder
//! keeps them in a `Vec` and never sorts.

use crate::spike::error::SpikeError;

/// One transport parameter, as it appeared on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParameter {
    /// The parameter identifier.
    pub id: u64,
    /// The raw parameter value.
    pub value: Vec<u8>,
}

impl TransportParameter {
    /// Whether the identifier is one of the reserved values a client sends purely to
    /// keep servers tolerant of unknown parameters.
    ///
    /// RFC 9000 section 18.1 reserves the identifiers of the form `31 * N + 27` for
    /// this. Their presence, and the fact that the identifier and payload are random,
    /// is itself observable.
    #[must_use]
    pub const fn is_reserved_grease(&self) -> bool {
        self.id % 31 == 27
    }

    /// The value read as a QUIC variable-length integer, when it is one.
    #[must_use]
    pub fn as_varint(&self) -> Option<u64> {
        let (value, consumed) = read_varint(&self.value).ok()?;
        (consumed == self.value.len()).then_some(value)
    }
}

/// Decodes the body of a `quic_transport_parameters` extension.
///
/// # Errors
///
/// [`SpikeError::Malformed`] when a variable-length integer or a value runs past the
/// end of the buffer.
pub fn decode_transport_parameters(
    mut bytes: &[u8],
) -> Result<Vec<TransportParameter>, SpikeError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (id, consumed) = read_varint(bytes)?;
        bytes = &bytes[consumed..];
        let (length, consumed) = read_varint(bytes)?;
        bytes = &bytes[consumed..];

        let length = usize::try_from(length)
            .map_err(|_| SpikeError::malformed("transport parameters", "length exceeds usize"))?;
        if bytes.len() < length {
            return Err(SpikeError::malformed(
                "transport parameters",
                format!(
                    "parameter {id:#x} claims {length} bytes, {} remain",
                    bytes.len()
                ),
            ));
        }
        out.push(TransportParameter {
            id,
            value: bytes[..length].to_vec(),
        });
        bytes = &bytes[length..];
    }
    Ok(out)
}

/// Reads one QUIC variable-length integer, returning it and the bytes consumed.
fn read_varint(bytes: &[u8]) -> Result<(u64, usize), SpikeError> {
    let first = *bytes
        .first()
        .ok_or_else(|| SpikeError::malformed("varint", "buffer is empty"))?;
    let length = 1usize << (first >> 6);
    if bytes.len() < length {
        return Err(SpikeError::malformed(
            "varint",
            format!("needs {length} bytes, {} remain", bytes.len()),
        ));
    }

    let mut value = u64::from(first & 0b0011_1111);
    for byte in &bytes[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_four_varint_widths() {
        // The worked examples from RFC 9000 section A.1.
        assert_eq!(read_varint(&[0x25]).expect("one byte"), (37, 1));
        assert_eq!(read_varint(&[0x7b, 0xbd]).expect("two bytes"), (15_293, 2));
        assert_eq!(
            read_varint(&[0x9d, 0x7f, 0x3e, 0x7d]).expect("four bytes"),
            (494_878_333, 4)
        );
        assert_eq!(
            read_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]).expect("eight bytes"),
            (151_288_809_941_952_652, 8)
        );
    }

    #[test]
    fn decodes_a_pair_of_parameters_in_order() {
        // id 0x01 (max_idle_timeout) = 30000, then id 0x04 (initial_max_data) = 37.
        // The widths are the point: 30000 does not fit the 14 bits a two-byte varint
        // carries, so it takes four bytes (`0x80 0x00 0x75 0x30`), while 37 fits the
        // six bits of a one-byte varint (`0x25`).
        let bytes = [0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x04, 0x01, 0x25];
        let params = decode_transport_parameters(&bytes).expect("well formed");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].id, 0x01);
        assert_eq!(params[0].as_varint(), Some(30_000));
        assert_eq!(params[1].id, 0x04);
        assert_eq!(params[1].as_varint(), Some(37));
    }

    #[test]
    fn a_truncated_value_is_an_error_rather_than_a_short_read() {
        let bytes = [0x01, 0x08, 0x00];
        let err = decode_transport_parameters(&bytes).expect_err("value is truncated");
        assert!(matches!(err, SpikeError::Malformed { .. }), "{err}");
    }

    #[test]
    fn a_truncated_varint_is_an_error() {
        // 0xc0 announces an eight-byte varint but only two bytes follow.
        let err = read_varint(&[0xc0, 0x00]).expect_err("varint is truncated");
        assert!(matches!(err, SpikeError::Malformed { .. }), "{err}");
    }

    #[test]
    fn reserved_identifiers_are_recognised() {
        // RFC 9000 section 18.1: reserved ids have the form 31 * N + 27.
        let reserved = TransportParameter {
            id: 27,
            value: Vec::new(),
        };
        assert!(reserved.is_reserved_grease());
        let reserved = TransportParameter {
            id: 31 * 1_000 + 27,
            value: Vec::new(),
        };
        assert!(reserved.is_reserved_grease());

        let real = TransportParameter {
            id: 0x0f,
            value: Vec::new(),
        };
        assert!(!real.is_reserved_grease());
    }

    #[test]
    fn an_empty_body_decodes_to_no_parameters() {
        assert!(
            decode_transport_parameters(&[])
                .expect("empty is well formed")
                .is_empty()
        );
    }
}
