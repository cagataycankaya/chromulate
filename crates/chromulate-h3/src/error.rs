//! Typed errors for the alternative-service layer.

use thiserror::Error;

/// Why an `Alt-Svc` field was refused.
///
/// Parsing itself does not produce an error: RFC 7838 section 3 tells a client to
/// ignore alternatives it cannot use, so an unparseable `alt-value` is skipped and the
/// rest of the field is kept. What *can* fail is recording a field against an origin
/// that is not allowed to advertise one.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AltSvcError {
    /// The response carrying the field came over a transport that cannot authenticate
    /// the origin, so the alternative cannot be trusted (RFC 7838 section 2.1).
    #[error("origin `{origin}` is not secure, so its Alt-Svc field is ignored")]
    InsecureOrigin {
        /// The origin that sent the field.
        origin: String,
    },
}
