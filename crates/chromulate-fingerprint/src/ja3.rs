//! JA3, the original TLS ClientHello fingerprint.

use md5::{Digest, Md5};

use crate::client_hello::{ClientHelloSpec, WireExtensionOrder};

/// Computes the JA3 string for a spec, using its reference extension order.
///
/// For a profile that shuffles its extensions this is one of the many JA3
/// strings the client produces, not a stable identity — see
/// [`ClientHelloSpec::reference_extension_order`]. Use
/// [`ja3_with_extension_order`] to compute the JA3 of a specific connection.
///
/// The format is `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats`,
/// with each list joined by `-` and every GREASE value removed.
#[must_use]
pub fn ja3(spec: &ClientHelloSpec) -> String {
    ja3_with_extension_order(spec, &spec.reference_extension_order())
}

/// Computes the JA3 string for one observed connection's extension order.
#[must_use]
pub fn ja3_with_extension_order(spec: &ClientHelloSpec, order: &WireExtensionOrder) -> String {
    let ciphers = join_dashes(spec.ciphers_without_grease().map(|suite| suite.get()));
    let extensions = join_dashes(order.without_grease().map(|id| id.get()));
    let curves = join_dashes(spec.groups_without_grease().map(|group| group.get()));
    let formats = join_dashes(
        spec.ec_point_formats
            .iter()
            .map(|format| u16::from(format.as_u8())),
    );

    format!(
        "{},{ciphers},{extensions},{curves},{formats}",
        spec.handshake_version.as_u16()
    )
}

/// Hashes a JA3 string with MD5, the digest JA3 is normally exchanged as.
#[must_use]
pub fn ja3_hash(ja3: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(ja3.as_bytes());
    hex::encode(hasher.finalize())
}

fn join_dashes(values: impl Iterator<Item = u16>) -> String {
    values
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_string_hashes_to_the_known_md5_of_nothing() {
        assert_eq!(ja3_hash(""), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
