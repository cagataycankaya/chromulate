//! A hand-rolled HTTP/1.1 server for the engine's integration tests.
//!
//! Hand-rolled rather than hyper-based on purpose: these tests assert on the
//! exact bytes the engine puts on the wire — the header order, whether a body
//! was re-sent, whether a second request arrived on the same TCP connection —
//! and a server framework would normalise some of that away before a test could
//! see it. Counting `accept` calls is also the only honest way to prove
//! connection reuse.
//!
//! # This is a copy
//!
//! The original is `crates/chromulate-http/tests/common/mod.rs`, and it is
//! copied rather than shared because `chromulate-http` must not depend on this
//! crate in any form — a dev-dependency back the other way would make the seam
//! and its implementation a cycle. Only `adaptive_through_the_engine.rs` uses
//! it, and only for `TestServer` and `Reply`. If the original grows a capability
//! that file needs, copy that too rather than reaching across.

// A shared test module is compiled into each integration test binary, so items
// only some of them use look dead, and `pub` on them looks unreachable.
#![allow(dead_code, unreachable_pub)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One request as the server received it.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub target: String,
    /// Header names in the order they arrived, lowercased.
    pub header_order: Vec<String>,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Vec<u8>,
    /// Which TCP connection this arrived on, counting from zero.
    pub connection: usize,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// What the server should send back.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Close the connection after replying instead of keeping it alive.
    pub close: bool,
    /// Wait this long before sending anything.
    pub delay: Option<Duration>,
    /// Send the head, then stall without ever sending the body.
    pub stall_after_head: bool,
}

impl Reply {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            close: false,
            delay: None,
            stall_after_head: false,
        }
    }

    pub fn ok() -> Self {
        Self::new(200)
    }

    pub fn text(body: &str) -> Self {
        Self::new(200).with_body(body.as_bytes().to_vec())
    }

    pub fn redirect(status: u16, location: &str) -> Self {
        Self::new(status).with_header("location", location)
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn closing(mut self) -> Self {
        self.close = true;
        self
    }

    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    pub fn stalling_after_head(mut self) -> Self {
        self.stall_after_head = true;
        self
    }
}

type Handler = Arc<dyn Fn(&Recorded) -> Reply + Send + Sync>;

/// A local HTTP/1.1 server that records what it received.
pub struct TestServer {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<Recorded>>>,
}

impl TestServer {
    /// Starts a server that answers every request with `handler`.
    pub async fn start<F>(handler: F) -> Self
    where
        F: Fn(&Recorded) -> Reply + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("the test server must bind a loopback port");
        let addr = listener
            .local_addr()
            .expect("a bound listener has a local address");

        let accepts = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler: Handler = Arc::new(handler);

        {
            let accepts = Arc::clone(&accepts);
            let received = Arc::clone(&received);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let index = accepts.fetch_add(1, Ordering::SeqCst);
                    let handler = Arc::clone(&handler);
                    let received = Arc::clone(&received);
                    tokio::spawn(async move {
                        serve(stream, index, handler, received).await;
                    });
                }
            });
        }

        Self {
            addr,
            accepts,
            received,
        }
    }

    /// A server that always answers the same way.
    pub async fn always(reply: Reply) -> Self {
        Self::start(move |_| reply.clone()).await
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// How many TCP connections were accepted. This is the connection-reuse
    /// measurement: two requests over one connection accept once.
    pub fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Every request received, in order.
    pub fn received(&self) -> Vec<Recorded> {
        self.received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn request_count(&self) -> usize {
        self.received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// A URL for `host`, pointing at this server's port.
    pub fn url_for(&self, host: &str, path: &str) -> String {
        format!("http://{host}:{}{path}", self.addr.port())
    }
}

async fn serve(
    mut stream: TcpStream,
    connection: usize,
    handler: Handler,
    received: Arc<Mutex<Vec<Recorded>>>,
) {
    let mut buffered: Vec<u8> = Vec::new();

    loop {
        let Some(request) = read_request(&mut stream, &mut buffered, connection).await else {
            return;
        };

        let reply = handler(&request);
        received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request);

        if let Some(delay) = reply.delay {
            tokio::time::sleep(delay).await;
        }

        let mut head = format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status));
        let mut has_length = false;
        for (name, value) in &reply.headers {
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
            {
                has_length = true;
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if !has_length {
            head.push_str(&format!("content-length: {}\r\n", reply.body.len()));
        }
        if reply.close {
            head.push_str("connection: close\r\n");
        }
        head.push_str("\r\n");

        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        if reply.stall_after_head {
            let _ = stream.flush().await;
            // Hold the connection open, sending nothing, until the client
            // gives up. The test's deadline is what ends this.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            return;
        }
        if stream.write_all(&reply.body).await.is_err() {
            return;
        }
        let _ = stream.flush().await;

        if reply.close {
            let _ = stream.shutdown().await;
            return;
        }
    }
}

/// Reads one request, leaving anything after it in `buffered` for the next.
async fn read_request(
    stream: &mut TcpStream,
    buffered: &mut Vec<u8>,
    connection: usize,
) -> Option<Recorded> {
    let head_end = loop {
        if let Some(position) = find_double_crlf(buffered) {
            break position;
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffered.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8_lossy(&buffered[..head_end]).into_owned();
    let mut rest = buffered.split_off(head_end + 4);
    std::mem::swap(buffered, &mut rest);

    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();

    let mut header_order = Vec::new();
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        header_order.push(name.clone());
        headers.entry(name).or_default().push(value);
    }

    let length: usize = headers
        .get("content-length")
        .and_then(|values| values.first())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);

    let chunked = headers
        .get("transfer-encoding")
        .and_then(|values| values.first())
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"));

    let body = if chunked {
        read_chunked(stream, buffered).await?
    } else {
        while buffered.len() < length {
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                break;
            }
            buffered.extend_from_slice(&chunk[..read]);
        }
        let take = length.min(buffered.len());
        let body: Vec<u8> = buffered.drain(..take).collect();
        body
    };

    Some(Recorded {
        method,
        target,
        header_order,
        headers,
        body,
        connection,
    })
}

async fn read_chunked(stream: &mut TcpStream, buffered: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = loop {
            if let Some(position) = find_crlf(buffered) {
                break position;
            }
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return Some(body);
            }
            buffered.extend_from_slice(&chunk[..read]);
        };

        let size_line = String::from_utf8_lossy(&buffered[..line_end]).into_owned();
        buffered.drain(..line_end + 2);
        let size = usize::from_str_radix(size_line.trim().split(';').next()?.trim(), 16).ok()?;

        while buffered.len() < size + 2 {
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return Some(body);
            }
            buffered.extend_from_slice(&chunk[..read]);
        }

        if size == 0 {
            buffered.drain(..2.min(buffered.len()));
            return Some(body);
        }
        body.extend_from_slice(&buffered[..size]);
        buffered.drain(..size + 2);
    }
}

fn find_double_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// A local HTTP `CONNECT` proxy that tunnels every request to one fixed
/// address, whatever authority the `CONNECT` line named.
///
/// It stands in for one exit address. The target is ignored on purpose, and
/// that is what lets a test address the origin by a real hostname: a proxied
/// route hands the name to the proxy rather than resolving it, so the engine
/// needs no resolver entry and the bytes still arrive at the loopback listener
/// the test started.
///
/// Two of these in front of one [`TestServer`] are the local reproduction of
/// "one origin, reached through two different exits" — which is the measurement
/// this file exists to make runnable without anybody's paid proxies.
pub struct TestProxy {
    addr: SocketAddr,
    tunnels: Arc<AtomicUsize>,
}

impl TestProxy {
    /// Starts a proxy that tunnels everything to `origin`.
    pub async fn start(origin: SocketAddr) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("the test proxy must bind a loopback port");
        let addr = listener
            .local_addr()
            .expect("a bound listener has a local address");
        let tunnels = Arc::new(AtomicUsize::new(0));

        {
            let tunnels = Arc::clone(&tunnels);
            tokio::spawn(async move {
                loop {
                    let Ok((client, _)) = listener.accept().await else {
                        return;
                    };
                    tunnels.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        tunnel(client, origin).await;
                    });
                }
            });
        }

        Self { addr, tunnels }
    }

    /// The `http://` URL to hand to `proxy` or `proxy_pool`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// How many tunnels this exit was asked to open.
    pub fn tunnels(&self) -> usize {
        self.tunnels.load(Ordering::SeqCst)
    }
}

async fn tunnel(mut client: TcpStream, origin: SocketAddr) {
    // Read the `CONNECT` head and nothing past it: the byte after the blank
    // line already belongs to the tunnel, and a `TcpStream` cannot be unread.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match client.read(&mut byte).await {
            Ok(0) | Err(_) => return,
            Ok(_) => head.push(byte[0]),
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 16 * 1024 {
            return;
        }
    }
    if !head.starts_with(b"CONNECT ") {
        return;
    }

    let Ok(mut upstream) = TcpStream::connect(origin).await else {
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}
