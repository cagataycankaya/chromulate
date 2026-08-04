//! A loopback HTTP/1.1 origin server for the benchmarks.
//!
//! Two routes:
//!
//! - `/` returns a fixed body of [`SMALL_BODY_LEN`] bytes with a
//!   `Content-Length`, which is the shape a client-overhead measurement wants:
//!   enough body to exercise the read path, small enough that copying it is not
//!   what the benchmark measures.
//! - `/big/{bytes}` streams `{bytes}` bytes in [`CHUNK_LEN`] chunks. It is used
//!   to check that a streaming response body really is constant-memory.

#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use futures_util::stream;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

/// Length of the body served from `/`.
pub const SMALL_BODY_LEN: usize = 1024;

/// Chunk size the `/big/{bytes}` route streams with.
pub const CHUNK_LEN: usize = 64 * 1024;

type ServerBody = BoxBody<Bytes, io::Error>;

/// A running loopback server.
///
/// The server keeps running until this handle is dropped; dropping it drops the
/// runtime it lives on, which shuts the accept loop down.
#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
    accepted: Arc<AtomicU64>,
    // The runtime must outlive the accept task. Kept as a field for that
    // reason, and dropped last.
    _runtime: Runtime,
}

impl Server {
    /// The address the server is listening on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// How many TCP connections the server has accepted since it started.
    ///
    /// This is the only honest way to tell whether a client's connection pool
    /// is doing its job: a keep-alive client that reuses connections shows a
    /// count close to its concurrency level, and one that churns shows a count
    /// close to its request count.
    #[must_use]
    pub fn connections_accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// The accept counter itself, so a measurement running on another runtime
    /// can bracket just its own window.
    #[must_use]
    pub fn accept_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.accepted)
    }

    /// `http://127.0.0.1:{port}{path}` for this server.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

/// Starts the server on its own multi-threaded runtime with `worker_threads`
/// workers.
///
/// The server gets a runtime of its own so that the client under measurement
/// does not share a scheduler with it. They still share the machine — see
/// `benches/README.md` for what that does and does not let you conclude.
///
/// # Errors
///
/// Returns the underlying I/O error when the runtime cannot be built or the
/// listener cannot bind.
pub fn start(worker_threads: usize) -> io::Result<Server> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name("bench-server")
        .enable_all()
        .build()?;

    let listener = runtime.block_on(async { TcpListener::bind("127.0.0.1:0").await })?;
    let addr = listener.local_addr()?;

    let accepted = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&accepted);

    runtime.spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            counter.fetch_add(1, Ordering::Relaxed);
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(stream), service_fn(route))
                    .await;
            });
        }
    });

    Ok(Server {
        addr,
        accepted,
        _runtime: runtime,
    })
}

/// Several origins on one runtime, so a client sees many distinct pool keys.
///
/// A connection pool is keyed by origin, so measuring anything that scales with
/// the *number of keys* — eviction sweeps, capacity accounting, lock contention
/// between unrelated hosts — needs more than one origin. Every listener here
/// binds its own port on `127.0.0.1`, which is what makes each one a separate
/// key, and they share a runtime so that starting a hundred of them costs a
/// hundred sockets rather than a hundred schedulers.
#[derive(Debug)]
pub struct Origins {
    addrs: Vec<SocketAddr>,
    accepted: Arc<AtomicU64>,
    _runtime: Runtime,
}

impl Origins {
    /// One URL per origin, all for the same `path`.
    #[must_use]
    pub fn urls(&self, path: &str) -> Vec<String> {
        self.addrs
            .iter()
            .map(|addr| format!("http://{addr}{path}"))
            .collect()
    }

    /// How many origins are listening.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    /// Whether no origin is listening.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// The shared accept counter across every origin.
    #[must_use]
    pub fn accept_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.accepted)
    }
}

/// Starts `count` origins on one runtime with `worker_threads` workers.
///
/// # Errors
///
/// Returns the underlying I/O error when the runtime cannot be built or a
/// listener cannot bind.
pub fn start_many(count: usize, worker_threads: usize) -> io::Result<Origins> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name("bench-origins")
        .enable_all()
        .build()?;

    let accepted = Arc::new(AtomicU64::new(0));
    let mut addrs = Vec::with_capacity(count);

    for _ in 0..count {
        let listener = runtime.block_on(async { TcpListener::bind("127.0.0.1:0").await })?;
        addrs.push(listener.local_addr()?);
        let counter = Arc::clone(&accepted);
        runtime.spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = stream.set_nodelay(true);
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(TokioIo::new(stream), service_fn(route))
                        .await;
                });
            }
        });
    }

    Ok(Origins {
        addrs,
        accepted,
        _runtime: runtime,
    })
}

/// The same routes, reachable from the HTTPS origin in [`crate::tls_server`].
///
/// Sharing one route table is what makes the plaintext and TLS figures
/// comparable: any difference between them is the protocol stack, not two
/// servers doing different work.
pub(crate) async fn route_public(
    request: Request<Incoming>,
) -> Result<Response<ServerBody>, Infallible> {
    route(request).await
}

async fn route(request: Request<Incoming>) -> Result<Response<ServerBody>, Infallible> {
    let path = request.uri().path().to_owned();

    // The request body is not read by any benchmark route, but hyper needs it
    // consumed before the connection can be reused.
    let mut body = request.into_body();
    while body.frame().await.transpose().ok().flatten().is_some() {}

    if let Some(rest) = path.strip_prefix("/big/") {
        return Ok(match rest.parse::<u64>() {
            Ok(total) => big(total),
            Err(_) => status(StatusCode::BAD_REQUEST),
        });
    }

    Ok(match path.as_str() {
        "/" => small(),
        _ => status(StatusCode::NOT_FOUND),
    })
}

fn small() -> Response<ServerBody> {
    // Rebuilt per request on purpose: `Bytes::from_static` would make the
    // server's cost unrepresentatively low, and a `Full` over a static slice
    // costs the same either way.
    let payload = Bytes::from_static(&[b'x'; SMALL_BODY_LEN]);
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(http::header::CONTENT_LENGTH, payload.len())
        .body(Full::new(payload).map_err(io::Error::other).boxed())
        .unwrap_or_else(|_| status(StatusCode::INTERNAL_SERVER_ERROR))
}

fn big(total: u64) -> Response<ServerBody> {
    let chunk = Bytes::from_static(&[b'y'; CHUNK_LEN]);
    let mut remaining = total;
    let frames = stream::iter(std::iter::from_fn(move || {
        if remaining == 0 {
            return None;
        }
        let take = remaining.min(CHUNK_LEN as u64) as usize;
        remaining -= take as u64;
        Some(Ok(Frame::data(chunk.slice(..take))))
    }));

    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(http::header::CONTENT_LENGTH, total)
        .body(StreamBody::new(frames).boxed())
        .unwrap_or_else(|_| status(StatusCode::INTERNAL_SERVER_ERROR))
}

fn status(code: StatusCode) -> Response<ServerBody> {
    let mut response = Response::new(Empty::<Bytes>::new().map_err(io::Error::other).boxed());
    *response.status_mut() = code;
    response
}
