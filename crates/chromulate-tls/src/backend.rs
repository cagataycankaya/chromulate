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
use chromulate_profile::Profile;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::engine::{HandshakeInfo, TlsEngine};
use crate::fidelity::{Fidelity, TargetIdentity};

/// A byte stream a TLS backend can hand back.
pub trait TlsIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> TlsIo for T {}

/// A finished TLS connection, with the handshake outcome attached.
///
/// The stream is boxed so that connections from different backends can be held
/// in one collection. This is a convenience for callers who want that, not the
/// shape [`TlsBackend`] imposes: the trait hands back a concrete
/// [`TlsBackend::Stream`], and the request path in `chromulate-http` uses that
/// directly so no byte crosses a vtable.
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

/// What a backend is, independent of the stream type it will be handed.
///
/// Split out of [`TlsBackend`] because none of these depend on `IO`, and while
/// they lived on the `IO`-generic trait none of them could be called without
/// naming a stream type that had nothing to do with the question. Writing a
/// second backend turned that from a wart into a compile error:
/// `ActiveBackend::from_profile(&profile)` could not infer `IO`, because
/// nothing in the signature mentions it.
///
/// So the rule this encodes: a member belongs on `TlsBackend<IO>` only if it
/// actually involves the stream.
pub trait TlsBackendConfig {
    /// Builds a backend configured from a profile.
    ///
    /// On the trait because `chromulate-http` constructs its own backend when a
    /// caller does not supply one; without it, a seam still forces the caller to
    /// name a concrete type in order to get one.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile cannot be turned into a working
    /// configuration.
    fn from_profile(profile: &Profile) -> Result<Self>
    where
        Self: Sized;

    /// Returns the ClientHello this backend is trying to reproduce.
    ///
    /// What it actually emits is a separate question; a caller comparing the
    /// two is the point of exposing this.
    fn target_client_hello(&self) -> &ClientHelloSpec;

    /// Returns the fingerprints of the ClientHello this backend aims at.
    fn target_identity(&self) -> &TargetIdentity;

    /// Reports what this backend will and will not reproduce.
    ///
    /// Every backend has to answer this, including one that reproduces
    /// everything. A backend that could decline to state its gap would make the
    /// gap invisible, and this project's whole claim is that the gap is
    /// published rather than glossed.
    fn fidelity(&self) -> &Fidelity;
}

/// Something that can turn a plaintext stream into a TLS stream on a profile's
/// behalf.
///
/// Implemented here by [`TlsEngine`] over rustls, and by
/// `crate::mock::MockBackend` under `--cfg chromulate_mock_backend`. A caller written
/// against this trait keeps working when the implementation underneath changes.
pub trait TlsBackend<IO>: TlsBackendConfig + Send + Sync + 'static
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// The stream this backend hands back.
    ///
    /// An associated type rather than a boxed trait object, so that the request
    /// path costs no virtual dispatch: a caller naming a concrete backend gets
    /// a concrete stream and every `poll_read` is a direct call. [`TlsConnection`]
    /// exists for callers that would rather erase the type, and it is their
    /// choice to pay for it rather than this trait's to impose.
    type Stream: TlsIo;

    /// Performs the handshake over an established stream.
    ///
    /// Returns what the handshake settled on alongside the stream, because
    /// reading that back out afterwards is backend-specific — rustls answers it
    /// from its own connection state, and a BoringSSL backend would not — so a
    /// caller that had to ask separately would be coupled to the implementation
    /// it is supposed to be insulated from.
    ///
    /// The future is boxed. That is one allocation per handshake, not per byte,
    /// and it keeps the trait object-safe for anyone who wants runtime selection.
    ///
    /// # Errors
    ///
    /// Returns [`chromulate_core::Error::Tls`] when the handshake fails.
    fn connect(
        &self,
        io: IO,
        name: ServerName<'static>,
    ) -> BoxFuture<'_, Result<(Self::Stream, HandshakeInfo)>>;
}

impl TlsBackendConfig for TlsEngine {
    fn from_profile(profile: &Profile) -> Result<Self> {
        TlsEngine::new(profile)
    }

    fn target_client_hello(&self) -> &ClientHelloSpec {
        TlsEngine::target_client_hello(self)
    }

    fn target_identity(&self) -> &TargetIdentity {
        TlsEngine::target_identity(self)
    }

    fn fidelity(&self) -> &Fidelity {
        TlsEngine::fidelity(self)
    }
}

impl<IO> TlsBackend<IO> for TlsEngine
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = crate::TlsStream<IO>;

    fn connect(
        &self,
        io: IO,
        name: ServerName<'static>,
    ) -> BoxFuture<'_, Result<(Self::Stream, HandshakeInfo)>> {
        Box::pin(async move {
            let stream = self.connect_to(io, name).await?;
            let info = HandshakeInfo::of_stream(&stream);
            Ok((stream, info))
        })
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
        let backend: &dyn TlsBackend<DuplexStream, Stream = crate::TlsStream<DuplexStream>> =
            &engine;

        assert_eq!(
            backend.target_client_hello(),
            &Profile::chrome_stable().client_hello,
            "a caller behind the trait can still read the target it is aiming at"
        );
    }

    /// The trait stays object-safe, which is not free once it has an associated
    /// type and is therefore worth pinning: naming `dyn TlsBackend` above only
    /// compiles while the associated type can be written out at the use site.
    /// Runtime backend selection is not something this workspace does today,
    /// but foreclosing it should be a decision rather than an accident.
    #[test]
    fn a_backend_can_be_used_as_a_trait_object() {
        let engine =
            TlsEngine::new(&Profile::chrome_stable()).expect("the Chrome engine must build");
        let boxed: Box<dyn TlsBackend<DuplexStream, Stream = crate::TlsStream<DuplexStream>>> =
            Box::new(engine);

        assert_eq!(
            boxed.target_client_hello().alpn,
            vec!["h2".to_owned(), "http/1.1".to_owned()],
            "the boxed backend still reports the profile's ALPN"
        );
    }
}
