//! Opening a connection: resolve, dial, handshake, and hand hyper the result.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use chromulate_core::{Body, Error, HostPort, Origin, Phase, Resolve, Result, Timings};
use chromulate_profile::Profile;
use chromulate_proxy::{Proxy, ProxyProvider};
use chromulate_tls::{ActiveBackend, Alpn, TlsBackend, server_name};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::deadline::Deadline;
use crate::http2::{Http2Fidelity, configure};
use crate::pool::{Connection, ConnectionIdentity, PoolKey, Protocol};

/// The TLS stream the linked backend produces over a TCP socket.
///
/// Derived from [`ActiveBackend`] rather than named directly, so that pointing
/// that alias at a different backend does not leave a rustls type sitting in
/// the middle of the connection path. It resolves to a concrete type, so
/// reading and writing through [`Stream`] is a static call in both variants.
type BackendStream = <ActiveBackend as TlsBackend<TcpStream>>::Stream;

/// A plaintext or TLS byte stream.
///
/// Both variants are `Unpin`, so the enum is projected with `get_mut` rather
/// than a projection macro — the workspace forbids `unsafe`, which rules out
/// `pin-project-lite`.
enum Stream {
    Plain(TcpStream),
    Secure(Box<BackendStream>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(io) => Pin::new(io).poll_read(cx, buf),
            Self::Secure(io) => Pin::new(io.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(io) => Pin::new(io).poll_write(cx, buf),
            Self::Secure(io) => Pin::new(io.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(io) => Pin::new(io).poll_flush(cx),
            Self::Secure(io) => Pin::new(io.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(io) => Pin::new(io).poll_shutdown(cx),
            Self::Secure(io) => Pin::new(io.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Where one request is going and how it gets there.
///
/// The proxy is chosen once and carried, because a rotating
/// [`ProxyProvider`] advances on every call: asking it again to label the pool
/// key would both skip an entry and label the connection with an exit it was
/// not opened through.
#[derive(Debug, Clone)]
pub(crate) struct Route {
    origin: Origin,
    proxy: Option<Arc<Proxy>>,
    label: Option<Arc<str>>,
}

impl Route {
    /// The proxy this route goes through, credentials redacted, or `None` for a
    /// direct connection.
    ///
    /// The same value [`PoolKey::proxy`] carries, so a route's session state is
    /// keyed by exactly what its connections are keyed by — see
    /// [`crate::session`].
    pub(crate) fn proxy_label(&self) -> Option<&Arc<str>> {
        self.label.as_ref()
    }
}

/// Everything needed to open connections on a profile's behalf.
pub(crate) struct Connector {
    resolver: Arc<dyn Resolve>,
    tls: ActiveBackend,
    proxies: Option<Arc<dyn ProxyProvider>>,
    profile: Arc<Profile>,
    identity: ConnectionIdentity,
    connect_timeout: Option<Duration>,
    /// See [`crate::PoolConfig::http1_max_buf_size`].
    http1_max_buf_size: Option<usize>,
    http2_fidelity: Http2Fidelity,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("identity", &self.identity)
            .field("connect_timeout", &self.connect_timeout)
            .field("proxied", &self.proxies.is_some())
            .finish_non_exhaustive()
    }
}

impl Connector {
    pub(crate) fn new(
        profile: Arc<Profile>,
        tls: ActiveBackend,
        resolver: Arc<dyn Resolve>,
        proxies: Option<Arc<dyn ProxyProvider>>,
        connect_timeout: Option<Duration>,
        http1_max_buf_size: Option<usize>,
    ) -> Self {
        // Configuring a throwaway builder is the only way to learn what hyper
        // will refuse without opening a connection first.
        let mut scratch = http2::Builder::new(TokioExecutor::new());
        let http2_fidelity = configure(&mut scratch, &profile.http2);

        Self {
            identity: ConnectionIdentity::of(&profile),
            resolver,
            tls,
            proxies,
            profile,
            connect_timeout,
            http1_max_buf_size,
            http2_fidelity,
        }
    }

    pub(crate) fn identity(&self) -> &ConnectionIdentity {
        &self.identity
    }

    pub(crate) fn http2_fidelity(&self) -> &Http2Fidelity {
        &self.http2_fidelity
    }

    pub(crate) fn tls(&self) -> &ActiveBackend {
        &self.tls
    }

    /// Chooses the proxy, if any, that this request will use.
    pub(crate) async fn route(&self, origin: Origin) -> Route {
        let proxy = match &self.proxies {
            Some(provider) => provider
                .next()
                .await
                .filter(|proxy| !proxy.bypasses(origin.host())),
            None => None,
        };
        // `ProxyUrl`'s Display redacts credentials, so the label is safe to put
        // in a pool key, a log line, or a `Debug` dump.
        let label = proxy
            .as_ref()
            .map(|proxy| Arc::from(proxy.url().to_string()));
        Route {
            origin,
            proxy,
            label,
        }
    }

    /// The pool keys a request on this route may be served from, most preferred
    /// first.
    ///
    /// HTTP/2 comes first because a browser holding an h2 connection to an
    /// origin reuses it rather than opening a second one.
    pub(crate) fn candidate_keys(&self, route: &Route) -> Vec<PoolKey> {
        let preferred = PoolKey {
            scheme: route.origin.scheme().into(),
            host: route.origin.host().into(),
            port: route.origin.port(),
            proxy: route.label.clone(),
            identity: self.identity.clone(),
            protocol: if route.origin.is_secure() {
                Protocol::Http2
            } else {
                Protocol::Http11
            },
        };
        if route.origin.is_secure() {
            // Every field but the protocol is shared, so the fallback key
            // clones reference counts rather than copying the strings again.
            let fallback = PoolKey {
                protocol: Protocol::Http11,
                ..preferred.clone()
            };
            vec![preferred, fallback]
        } else {
            vec![preferred]
        }
    }

    /// Opens a new connection along `route`, timing each phase into `timings`.
    ///
    /// Only the phases this call actually performs are recorded, so a caller
    /// that was served from the pool never reaches here and its `timings` keep
    /// reporting `None` — which is the distinction between "no handshake" and
    /// "an instant handshake".
    pub(crate) async fn connect(
        &self,
        route: &Route,
        deadline: &Deadline,
        timings: &mut Timings,
    ) -> Result<(PoolKey, Connection)> {
        let origin = &route.origin;
        let target = HostPort::new(origin.host().to_owned(), origin.port());

        let span = tracing::debug_span!(
            "connect",
            target = %target,
            proxy = route.label.as_deref().unwrap_or("none"),
        );
        let _guard = span.enter();

        let stream = match &route.proxy {
            Some(proxy) => {
                let budget = [self.connect_timeout, deadline.remaining()]
                    .into_iter()
                    .flatten()
                    .min()
                    .unwrap_or(DEFAULT_PROXY_BUDGET);
                let started = Instant::now();
                let stream = deadline
                    .run(
                        Phase::Connect,
                        self.connect_timeout,
                        proxy.connect(&target, budget),
                    )
                    .await?;
                // No resolve phase is recorded: the proxy resolves the target
                // name, and whatever it cost is inside the tunnel setup.
                timings.record_connect(started.elapsed());
                stream
            }
            None => {
                let started = Instant::now();
                let addresses = deadline
                    .run(
                        Phase::Resolve,
                        self.connect_timeout,
                        self.resolver.resolve(target.clone()),
                    )
                    .await?;
                let resolved = Instant::now();
                timings.record_resolve(resolved.saturating_duration_since(started));

                let stream = deadline
                    .run(
                        Phase::Connect,
                        self.connect_timeout,
                        dial(&addresses, &target),
                    )
                    .await?;
                timings.record_connect(resolved.elapsed());
                stream
            }
        };

        let (stream, alpn) = if origin.is_secure() {
            let started = Instant::now();
            // Through `TlsBackend`, not through `TlsEngine`'s inherent method.
            // The seam only proves it is the right shape while a real caller
            // stands on it; a trait nothing calls is a guess about an API.
            // Dispatch stays static because `ActiveBackend` is a concrete type.
            let (tls, info) = deadline
                .run(
                    Phase::Handshake,
                    self.connect_timeout,
                    TlsBackend::connect(&self.tls, stream, server_name(origin.host())?),
                )
                .await?;
            timings.record_handshake(started.elapsed());
            tracing::debug!(
                alpn = info.alpn.as_ref().map(Alpn::as_str),
                resumed = info.resumed,
                "tls handshake complete"
            );
            let alpn = info.alpn.unwrap_or(Alpn::Http11);
            (Stream::Secure(Box::new(tls)), alpn)
        } else {
            // No ALPN without TLS. Chromulate does not attempt h2c: a browser
            // does not either, and an `Upgrade` dance would itself be a
            // distinguishing behaviour.
            (Stream::Plain(stream), Alpn::Http11)
        };

        let protocol = if alpn == Alpn::Http2 {
            Protocol::Http2
        } else {
            Protocol::Http11
        };

        let key = PoolKey {
            scheme: origin.scheme().into(),
            host: origin.host().into(),
            port: origin.port(),
            proxy: route.label.clone(),
            identity: self.identity.clone(),
            protocol,
        };

        // Shares `Phase::Handshake` with the TLS handshake for timeout
        // attribution but is deliberately not added to the recorded handshake
        // time: a caller reading "handshake" against a captured trace means the
        // TLS one, and folding hyper's preface into it would make the two
        // numbers incomparable.
        let connection = deadline
            .run(
                Phase::Handshake,
                self.connect_timeout,
                self.protocol_handshake(stream, protocol, origin),
            )
            .await?;

        tracing::debug!(key = %key, "connection established");
        Ok((key, connection))
    }

    async fn protocol_handshake(
        &self,
        stream: Stream,
        protocol: Protocol,
        origin: &Origin,
    ) -> Result<Connection> {
        let io = TokioIo::new(stream);
        let target = origin.ascii_serialization();

        match protocol {
            Protocol::Http2 => {
                let mut builder = http2::Builder::new(TokioExecutor::new());
                configure(&mut builder, &self.profile.http2);
                let (sender, driver) =
                    builder
                        .handshake::<_, Body>(io)
                        .await
                        .map_err(|error| Error::Connect {
                            target: target.clone(),
                            source: Some(Box::new(error)),
                        })?;
                tokio::spawn(async move {
                    if let Err(error) = driver.await {
                        tracing::debug!(%error, "http/2 connection closed");
                    }
                });
                Ok(Connection::Http2(sender))
            }
            Protocol::Http11 => {
                let mut builder = http1::Builder::new();
                if let Some(max) = self.http1_max_buf_size {
                    // hyper panics below its 8 KiB floor rather than clamping,
                    // so the floor is applied here; see the field's docs.
                    builder.max_buf_size(max.max(8_192));
                }
                let (sender, driver) =
                    builder
                        .handshake::<_, Body>(io)
                        .await
                        .map_err(|error| Error::Connect {
                            target: target.clone(),
                            source: Some(Box::new(error)),
                        })?;
                tokio::spawn(async move {
                    if let Err(error) = driver.await {
                        tracing::debug!(%error, "http/1.1 connection closed");
                    }
                });
                Ok(Connection::Http1(sender))
            }
        }
    }
}

/// The budget handed to a proxy handshake when neither a connect timeout nor a
/// request deadline bounds it.
const DEFAULT_PROXY_BUDGET: Duration = Duration::from_secs(30);

/// Tries each address in turn, keeping the last failure to report.
///
/// The resolver decides the order; a browser races the address families
/// instead ("happy eyeballs"), which is a latency optimisation rather than an
/// observable difference, and it is not implemented here.
async fn dial(addresses: &[SocketAddr], target: &HostPort) -> Result<TcpStream> {
    let mut last: Option<io::Error> = None;

    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => {
                // Browsers disable Nagle's algorithm; a small request waiting
                // for a full segment is a visible latency difference.
                let _ = stream.set_nodelay(true);
                tracing::trace!(%address, "connected");
                return Ok(stream);
            }
            Err(error) => {
                tracing::trace!(%address, %error, "address unreachable");
                last = Some(error);
            }
        }
    }

    Err(Error::Connect {
        target: target.to_string(),
        source: last.map(|error| Box::new(error) as chromulate_core::BoxError),
    })
}

#[cfg(test)]
mod tests {
    use chromulate_dns::StaticResolver;
    use chromulate_proxy::{ProxyUrl, RoundRobin};
    use chromulate_tls::TlsBackendConfig;
    use url::Url;

    use super::*;

    fn connector_with(proxies: Option<Arc<dyn ProxyProvider>>) -> Connector {
        let profile = Arc::new(Profile::chrome_stable());
        let tls =
            ActiveBackend::from_profile(&profile).expect("the profile must build a TLS engine");
        Connector::new(
            Arc::clone(&profile),
            tls,
            Arc::new(StaticResolver::empty()),
            proxies,
            Some(Duration::from_secs(5)),
            None,
        )
    }

    fn origin(url: &str) -> Origin {
        Origin::of(&Url::parse(url).expect("a valid url")).expect("a valid origin")
    }

    #[tokio::test]
    async fn a_secure_origin_may_be_served_by_either_protocol_with_http2_preferred() {
        let connector = connector_with(None);
        let route = connector.route(origin("https://example.com/")).await;

        let protocols: Vec<Protocol> = connector
            .candidate_keys(&route)
            .iter()
            .map(|key| key.protocol)
            .collect();
        assert_eq!(protocols, vec![Protocol::Http2, Protocol::Http11]);
    }

    #[tokio::test]
    async fn a_plaintext_origin_is_only_ever_http1_because_there_is_no_alpn() {
        let connector = connector_with(None);
        let route = connector.route(origin("http://example.com/")).await;

        let protocols: Vec<Protocol> = connector
            .candidate_keys(&route)
            .iter()
            .map(|key| key.protocol)
            .collect();
        assert_eq!(protocols, vec![Protocol::Http11]);
    }

    #[tokio::test]
    async fn choosing_a_route_advances_a_rotating_proxy_pool_exactly_once() {
        let pool = vec![
            Proxy::new(ProxyUrl::parse("http://a.proxy.test:8080").expect("a valid proxy url")),
            Proxy::new(ProxyUrl::parse("http://b.proxy.test:8080").expect("a valid proxy url")),
        ];
        let connector = connector_with(Some(Arc::new(RoundRobin::new(pool))));

        let first = connector.route(origin("https://example.com/")).await;
        let second = connector.route(origin("https://example.com/")).await;

        // Labelling the key must not consume a second entry, so two requests
        // see the two pool members in order rather than skipping one each.
        assert_eq!(first.label.as_deref(), Some("http://a.proxy.test:8080"));
        assert_eq!(second.label.as_deref(), Some("http://b.proxy.test:8080"));
    }

    #[tokio::test]
    async fn the_proxy_appears_in_every_candidate_key_so_exits_are_never_shared() {
        let pool = vec![Proxy::new(
            ProxyUrl::parse("socks5h://user:secret@exit.test:1080").expect("a valid proxy url"),
        )];
        let connector = connector_with(Some(Arc::new(RoundRobin::new(pool))));
        let route = connector.route(origin("https://example.com/")).await;

        for key in connector.candidate_keys(&route) {
            let label = key.proxy.as_deref().expect("the key must record the exit");
            assert!(label.contains("exit.test:1080"), "{label}");
            assert!(
                !label.contains("secret"),
                "a pool key ends up in logs; credentials must be redacted: {label}"
            );
        }
    }

    #[tokio::test]
    async fn dialling_no_addresses_reports_the_target_rather_than_hanging() {
        let target = HostPort::new("nowhere.invalid", 443);
        let error = dial(&[], &target)
            .await
            .expect_err("an empty address list cannot connect");
        assert!(
            matches!(&error, Error::Connect { target, .. } if target == "nowhere.invalid:443"),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_connector_reports_the_http2_gap_without_opening_a_connection() {
        let connector = connector_with(None);
        assert!(
            !connector.http2_fidelity().is_exact(),
            "h2's fixed pseudo-header order is always a gap"
        );
        assert_eq!(
            connector.http2_fidelity().target,
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        );
    }
}
