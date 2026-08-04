//! The unified Chromulate error hierarchy.
//!
//! Errors are typed rather than stringly typed so callers can branch on the failure
//! class without parsing messages. Every variant answers three questions that a
//! networking client is repeatedly asked: which phase failed, is it worth retrying,
//! and was it caused by us or by the peer.

use std::fmt;

/// A boxed error from a dependency or a user supplied component.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Convenient result alias used across the workspace.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The stage of the request lifecycle in which a failure occurred.
///
/// Attached to timeouts and connection failures so a caller can tell a slow DNS
/// server apart from a slow origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Phase {
    /// Building or validating the request before any I/O happened.
    Build,
    /// Resolving a hostname to addresses.
    Resolve,
    /// Establishing a TCP connection or a proxy tunnel.
    Connect,
    /// Performing the TLS handshake.
    Handshake,
    /// Writing request headers and body.
    Send,
    /// Waiting for the response head.
    AwaitResponse,
    /// Streaming the response body.
    ReceiveBody,
}

impl Phase {
    /// A short lowercase label, suitable for logs and metric labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::Handshake => "handshake",
            Self::Send => "send",
            Self::AwaitResponse => "await_response",
            Self::ReceiveBody => "receive_body",
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error type returned by every fallible Chromulate operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The request could not be constructed, or was rejected before any I/O.
    #[error("invalid request: {0}")]
    Builder(String),

    /// A URL was malformed or unsupported.
    #[error("invalid url: {0}")]
    Url(String),

    /// The scheme is not one this client can speak.
    #[error("unsupported scheme `{0}`")]
    UnsupportedScheme(String),

    /// Hostname resolution failed.
    #[error("failed to resolve `{host}`")]
    Resolve {
        /// The hostname that could not be resolved.
        host: String,
        /// The underlying resolver error, when the resolver produced one.
        #[source]
        source: Option<BoxError>,
    },

    /// A transport connection could not be established.
    #[error("failed to connect to `{target}`")]
    Connect {
        /// Host and port that were dialled.
        target: String,
        /// The underlying socket error.
        #[source]
        source: Option<BoxError>,
    },

    /// The proxy refused, mis-negotiated, or failed to tunnel the connection.
    #[error("proxy error via `{proxy}`: {message}")]
    Proxy {
        /// The proxy that was in use, with credentials removed.
        proxy: String,
        /// What went wrong.
        message: String,
    },

    /// The TLS handshake failed, including certificate verification failures.
    #[error("TLS handshake failed with `{target}`")]
    Tls {
        /// The peer we were handshaking with.
        target: String,
        /// The underlying TLS error.
        #[source]
        source: Option<BoxError>,
    },

    /// The peer violated the HTTP protocol, at any version.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// An operation exceeded its deadline.
    #[error("timed out during {0}")]
    Timeout(Phase),

    /// The redirect chain exceeded the configured limit.
    #[error("redirect limit of {limit} exceeded")]
    TooManyRedirects {
        /// The configured maximum.
        limit: usize,
    },

    /// A redirect could not be followed, for example because the target scheme is
    /// unsupported or the `Location` header was malformed.
    #[error("cannot follow redirect: {0}")]
    Redirect(String),

    /// Reading or writing a body failed.
    #[error("body error during {phase}")]
    Body {
        /// Where in the lifecycle the body failed.
        phase: Phase,
        /// The underlying cause.
        #[source]
        source: Option<BoxError>,
    },

    /// A response body could not be decompressed or decoded.
    #[error("failed to decode `{encoding}` response body")]
    Decode {
        /// The content coding that failed.
        encoding: String,
        /// The underlying cause.
        #[source]
        source: Option<BoxError>,
    },

    /// The response exceeded a configured size limit.
    #[error("response body exceeded the {limit} byte limit")]
    BodyTooLarge {
        /// The configured maximum in bytes.
        limit: u64,
    },

    /// A middleware or user supplied component failed.
    #[error("middleware `{name}` failed")]
    Middleware {
        /// The name reported by the middleware.
        name: &'static str,
        /// The underlying cause.
        #[source]
        source: BoxError,
    },

    /// The client was shut down, or the connection pool is closed.
    #[error("client has been shut down")]
    Shutdown,

    /// Configuration was rejected while building a client.
    #[error("configuration error: {0}")]
    Config(String),
}

impl Error {
    /// Builds a [`Error::Builder`] from anything displayable.
    pub fn builder(message: impl fmt::Display) -> Self {
        Self::Builder(message.to_string())
    }

    /// Builds a [`Error::Config`] from anything displayable.
    pub fn config(message: impl fmt::Display) -> Self {
        Self::Config(message.to_string())
    }

    /// Builds a [`Error::Protocol`] from anything displayable.
    pub fn protocol(message: impl fmt::Display) -> Self {
        Self::Protocol(message.to_string())
    }

    /// Builds a [`Error::Url`] from anything displayable.
    pub fn url(message: impl fmt::Display) -> Self {
        Self::Url(message.to_string())
    }

    /// Whether retrying the identical request could plausibly succeed.
    ///
    /// This is deliberately conservative: it reports `true` only for failures that
    /// happened before the server could have processed the request, or for transport
    /// faults that are known to be transient. A caller that retries non-idempotent
    /// methods must apply its own additional policy on top of this.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Resolve { .. } | Self::Connect { .. } => true,
            Self::Tls { .. } => false,
            Self::Timeout(phase) => matches!(
                phase,
                Phase::Resolve | Phase::Connect | Phase::Handshake | Phase::AwaitResponse
            ),
            Self::Proxy { .. } => true,
            Self::Protocol(_) => false,
            // Not even for `Phase::Send`. By the time a body error is raised the transport
            // has started writing, so the origin may already hold a complete request. Only
            // the engine knows whether a single byte actually left, and it can report that
            // case as `Connect` instead.
            Self::Body { .. } => false,
            _ => false,
        }
    }

    /// Whether this error was a deadline expiry.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    /// Whether this error came from certificate or handshake validation.
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls { .. })
    }

    /// Whether this error is the caller's fault rather than the network's.
    ///
    /// Useful for deciding whether to surface a stack trace or a user-facing message.
    pub fn is_user_error(&self) -> bool {
        matches!(
            self,
            Self::Builder(_) | Self::Url(_) | Self::UnsupportedScheme(_) | Self::Config(_)
        )
    }

    /// The lifecycle phase this error belongs to, when one can be determined.
    pub fn phase(&self) -> Option<Phase> {
        match self {
            Self::Builder(_) | Self::Url(_) | Self::UnsupportedScheme(_) | Self::Config(_) => {
                Some(Phase::Build)
            }
            Self::Resolve { .. } => Some(Phase::Resolve),
            Self::Connect { .. } | Self::Proxy { .. } => Some(Phase::Connect),
            Self::Tls { .. } => Some(Phase::Handshake),
            Self::Timeout(phase) => Some(*phase),
            Self::Body { phase, .. } => Some(*phase),
            Self::Decode { .. } | Self::BodyTooLarge { .. } => Some(Phase::ReceiveBody),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_failures_are_retryable_but_tls_failures_are_not() {
        let connect = Error::Connect {
            target: "example.com:443".into(),
            source: None,
        };
        let tls = Error::Tls {
            target: "example.com:443".into(),
            source: None,
        };

        assert!(connect.is_retryable());
        assert!(!tls.is_retryable());
        assert!(tls.is_tls());
    }

    #[test]
    fn a_send_phase_body_error_is_not_retryable() {
        // Writing had already begun, so the origin may hold a complete request. Replaying
        // it would duplicate a side effect.
        let err = Error::Body {
            phase: Phase::Send,
            source: None,
        };
        assert!(!err.is_retryable());
        assert_eq!(err.phase(), Some(Phase::Send));
    }

    #[test]
    fn body_receive_timeout_is_not_retryable() {
        // Bytes may already have reached the caller, so replaying is unsafe.
        assert!(!Error::Timeout(Phase::ReceiveBody).is_retryable());
        assert!(Error::Timeout(Phase::Connect).is_retryable());
    }

    #[test]
    fn phase_is_reported_for_transport_errors() {
        let err = Error::Decode {
            encoding: "br".into(),
            source: None,
        };
        assert_eq!(err.phase(), Some(Phase::ReceiveBody));
        assert!(!err.is_user_error());
    }

    #[test]
    fn builder_errors_are_attributed_to_the_caller() {
        let err = Error::builder("method not allowed with a body");
        assert!(err.is_user_error());
        assert_eq!(err.phase(), Some(Phase::Build));
    }
}
