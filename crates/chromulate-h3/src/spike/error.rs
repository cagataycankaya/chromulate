//! Typed errors for the spike.

use thiserror::Error;

/// Why an observation or a spike request failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpikeError {
    /// A length prefix ran past the end of the buffer, or a field was truncated.
    #[error("malformed {structure}: {detail}")]
    Malformed {
        /// What was being decoded.
        structure: &'static str,
        /// What went wrong.
        detail: String,
    },

    /// The handshake produced no bytes for the field being examined.
    #[error("nothing was recorded for {0}; the handshake did not reach that point")]
    NothingRecorded(&'static str),

    /// A `ClientHelloSpec` could not be built from what was observed.
    #[error("observed ClientHello does not fit the fingerprint model: {0}")]
    Spec(String),

    /// The spike could not reach or complete an HTTP/3 exchange.
    #[error("http/3 request failed: {0}")]
    Request(String),
}

impl SpikeError {
    pub(crate) fn malformed(structure: &'static str, detail: impl Into<String>) -> Self {
        Self::Malformed {
            structure,
            detail: detail.into(),
        }
    }
}
