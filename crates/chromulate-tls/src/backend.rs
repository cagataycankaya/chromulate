//! The seam a different TLS implementation would slot into.
//!
//! rustls cannot emit a byte-exact browser ClientHello, and no amount of
//! configuration will change that — the limits listed in
//! [`crate::STRUCTURAL_LIMITS`] are properties of its encoder. A backend that
//! writes its own ClientHello, over BoringSSL or over a hand-rolled encoder,
//! would lift them. This trait is the one thing such a backend has to implement
//! for callers not to notice the change.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use chromulate_core::{BoxFuture, Result};
use chromulate_fingerprint::ClientHelloSpec;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::engine::{HandshakeInfo, TlsEngine};

/// A byte stream a TLS backend can hand back.
pub trait TlsIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> TlsIo for T {}

/// A finished TLS connection, with the handshake outcome attached.
///
/// The stream is boxed so that every backend returns the same type. When the
/// backend is known to be rustls and the extra indirection is not wanted,
/// [`TlsEngine::connect`] hands back `tokio_rustls`'s stream directly.
pub struct TlsConnection {
    io: Box<dyn TlsIo>,
    info: HandshakeInfo,
}

impl TlsConnection {
    /// Wraps a stream and the outcome of the handshake that produced it.
    pub fn new(io: impl TlsIo + 'static, info: HandshakeInfo) -> Self {
        Self {
            io: Box::new(io),
            info,
        }
    }

    /// Returns what the handshake settled on.
    #[must_use]
    pub fn info(&self) -> &HandshakeInfo {
        &self.info
    }
}

impl fmt::Debug for TlsConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnection")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Something that can turn a plaintext stream into a TLS stream on a profile's
/// behalf.
///
/// Implemented here by [`TlsEngine`] over rustls. A caller written against this
/// trait keeps working when the implementation underneath changes.
pub trait TlsBackend<IO>: Send + Sync + 'static
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Performs the handshake over an established stream.
    ///
    /// # Errors
    ///
    /// Returns [`chromulate_core::Error::Tls`] when the handshake fails.
    fn connect(&self, io: IO, name: ServerName<'static>) -> BoxFuture<'_, Result<TlsConnection>>;

    /// Returns the ClientHello this backend is trying to reproduce.
    ///
    /// What it actually emits is a separate question; a caller comparing the
    /// two is the point of exposing this.
    fn target_client_hello(&self) -> &ClientHelloSpec;
}

impl<IO> TlsBackend<IO> for TlsEngine
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn connect(&self, io: IO, name: ServerName<'static>) -> BoxFuture<'_, Result<TlsConnection>> {
        Box::pin(async move {
            let stream = self.connect_to(io, name).await?;
            let info = HandshakeInfo::of_stream(&stream);
            Ok(TlsConnection::new(stream, info))
        })
    }

    fn target_client_hello(&self) -> &ClientHelloSpec {
        TlsEngine::target_client_hello(self)
    }
}

#[cfg(test)]
mod tests {
    use chromulate_profile::Profile;
    use tokio::io::DuplexStream;

    use super::*;

    #[test]
    fn the_engine_is_usable_through_the_backend_trait() {
        let engine =
            TlsEngine::new(&Profile::chrome_stable()).expect("the Chrome engine must build");
        let backend: &dyn TlsBackend<DuplexStream> = &engine;

        assert_eq!(
            backend.target_client_hello(),
            &Profile::chrome_stable().client_hello,
            "a caller behind the trait can still read the target it is aiming at"
        );
    }
}
