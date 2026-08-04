//! HTTP `CONNECT` tunnelling, used by the `http://` and `https://` proxy schemes.

use chromulate_core::{Error, HostPort, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::dial::dial;
use crate::url::ProxyUrl;

/// The largest response head this crate will buffer while looking for the terminating
/// blank line, guarding against a misbehaving or malicious proxy that never sends one.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Dials `proxy` and tunnels to `target` with an HTTP `CONNECT` request.
///
/// On success, the returned stream is positioned exactly at the first byte the target
/// sent (or is ready to send the first byte the caller writes); no tunnel bytes are
/// consumed while reading the response head.
pub(crate) async fn connect(proxy: &ProxyUrl, target: &HostPort) -> Result<TcpStream> {
    let mut stream = dial(proxy).await?;
    tunnel(&mut stream, proxy, target).await?;
    Ok(stream)
}

async fn tunnel(stream: &mut TcpStream, proxy: &ProxyUrl, target: &HostPort) -> Result<()> {
    let authority = target.to_string();
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = proxy.basic_auth_header_value() {
        request.push_str("Proxy-Authorization: ");
        request.push_str(&auth);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|err| proxy_error(proxy, format!("failed to write CONNECT request: {err}")))?;

    let head = read_head(stream)
        .await
        .map_err(|err| proxy_error(proxy, format!("failed to read CONNECT response: {err}")))?;

    let (status, reason) = parse_status_line(&head)
        .ok_or_else(|| proxy_error(proxy, "malformed CONNECT response status line"))?;

    if !(200..300).contains(&status) {
        return Err(proxy_error(
            proxy,
            format!(
                "CONNECT rejected with status {status} {}",
                sanitize_reason(&reason)
            ),
        ));
    }
    Ok(())
}

/// The longest reason phrase this crate will repeat back in an error message.
const MAX_REASON_CHARS: usize = 80;

/// Renders a proxy-supplied reason phrase safely for an error message.
///
/// The phrase is fully attacker-controlled and lands in an error a caller is very likely
/// to print to a terminal. `\r` and `\n` cannot reach here — the status line is cut at
/// the first `\n` and a trailing `\r` is trimmed — but every other C0 control does,
/// including the ANSI escape sequences that let a hostile proxy rewrite what the
/// operator sees. Anything outside printable ASCII is escaped rather than passed
/// through, and the result is truncated: the numeric status carries the information, the
/// phrase is only a hint.
fn sanitize_reason(reason: &str) -> String {
    let mut out = String::with_capacity(reason.len());
    for c in reason.chars().take(MAX_REASON_CHARS) {
        if c == ' ' || c.is_ascii_graphic() {
            out.push(c);
        } else {
            out.extend(c.escape_debug());
        }
    }
    if reason.chars().nth(MAX_REASON_CHARS).is_some() {
        out.push_str("...");
    }
    out
}

/// Reads exactly the response head (through the terminating `\r\n\r\n`), one byte at a
/// time.
///
/// Reading byte-by-byte, rather than into a larger buffer, guarantees the socket read
/// never crosses past the header boundary into tunnel data: once the tunnel is
/// established the proxy stops speaking HTTP, and any byte read past the blank line
/// would belong to the target and be unrecoverable, since a `TcpStream` cannot be
/// "unread" from.
async fn read_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "proxy closed the connection before completing the CONNECT response",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > MAX_HEAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CONNECT response head exceeded the size limit",
            ));
        }
    }
}

/// Parses `HTTP/1.1 200 Connection established` into `(200, "Connection established")`.
///
/// The version token must start with `HTTP/` and the status must be exactly three ASCII
/// digits. Both checks matter because `str::parse::<u16>` accepts Rust's integer syntax,
/// which is broader than the HTTP grammar: without them `HTTP/1.1 +200 ok`,
/// `HTTP/1.1 000200 ok` and `not-http 299 x` all open a tunnel that no HTTP parser
/// downstream would have accepted.
fn parse_status_line(head: &[u8]) -> Option<(u16, String)> {
    let line_end = head.iter().position(|&b| b == b'\n')?;
    let line = std::str::from_utf8(&head[..line_end])
        .ok()?
        .trim_end_matches('\r');
    let mut parts = line.splitn(3, ' ');

    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }

    let status = parts.next()?;
    if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let status = status.parse::<u16>().ok()?;

    let reason = parts.next().unwrap_or("").to_string();
    Some((status, reason))
}

fn proxy_error(proxy: &ProxyUrl, message: impl Into<String>) -> Error {
    Error::Proxy {
        proxy: proxy.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn sends_the_exact_connect_request_bytes_without_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!("http://{}:{}", addr.ip(), addr.port()))
            .expect("valid proxy URL");
        let target = HostPort::new("example.com", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 1024];
            let n = read_until_double_crlf(&mut socket, &mut buf).await;
            socket
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .expect("write response");
            buf.truncate(n);
            buf
        });

        let stream = connect(&proxy, &target).await.expect("tunnel established");
        drop(stream);

        let request = server.await.expect("server task");
        assert_eq!(
            request,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn sends_proxy_authorization_header_when_credentials_are_set() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!(
            "http://aladdin:opensesame@{}:{}",
            addr.ip(),
            addr.port()
        ))
        .expect("valid proxy URL");
        let target = HostPort::new("example.com", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 1024];
            let n = read_until_double_crlf(&mut socket, &mut buf).await;
            socket
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .expect("write response");
            buf.truncate(n);
            buf
        });

        let stream = connect(&proxy, &target).await.expect("tunnel established");
        drop(stream);

        let request = server.await.expect("server task");
        assert_eq!(
            request,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l\r\n\r\n".to_vec()
        );
    }

    #[tokio::test]
    async fn bracket_ipv6_targets_in_the_request_line_and_host_header() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!("http://{}:{}", addr.ip(), addr.port()))
            .expect("valid proxy URL");
        let target = HostPort::new("::1", 8443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 1024];
            let n = read_until_double_crlf(&mut socket, &mut buf).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                .await
                .expect("write response");
            buf.truncate(n);
            buf
        });

        connect(&proxy, &target).await.expect("tunnel established");
        let request = server.await.expect("server task");
        assert_eq!(
            request,
            b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn a_non_2xx_status_becomes_a_redacted_proxy_error() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!(
            "http://alice:hunter2@{}:{}",
            addr.ip(),
            addr.port()
        ))
        .expect("valid proxy URL");
        let target = HostPort::new("example.com", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 1024];
            let _ = read_until_double_crlf(&mut socket, &mut buf).await;
            socket
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")
                .await
                .expect("write response");
        });

        let err = connect(&proxy, &target).await.unwrap_err();
        server.await.expect("server task");

        match err {
            Error::Proxy {
                proxy: redacted,
                message,
            } => {
                assert!(!redacted.contains("alice"));
                assert!(!redacted.contains("hunter2"));
                assert!(message.contains("407"));
            }
            other => panic!("expected Error::Proxy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_tunnel_stays_open_for_data_sent_immediately_after_the_response_head() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!("http://{}:{}", addr.ip(), addr.port()))
            .expect("valid proxy URL");
        let target = HostPort::new("example.com", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 1024];
            let _ = read_until_double_crlf(&mut socket, &mut buf).await;
            // Write the response head and the first tunnel byte in a single write, the
            // way a real proxy's TCP stack might coalesce them.
            socket
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\ntunnel-byte")
                .await
                .expect("write response and payload");
        });

        let mut stream = connect(&proxy, &target).await.expect("tunnel established");
        let mut received = [0u8; b"tunnel-byte".len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("read tunnel payload");
        server.await.expect("server task");

        assert_eq!(&received, b"tunnel-byte");
    }

    /// Runs a CONNECT against a proxy that answers with `response`, returning the error.
    async fn connect_error_for_response(response: &'static [u8]) -> Error {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!("http://{}:{}", addr.ip(), addr.port()))
            .expect("valid proxy URL");
        let target = HostPort::new("example.com", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 1024];
            let _ = read_until_double_crlf(&mut socket, &mut buf).await;
            socket.write_all(response).await.expect("write response");
        });

        let err = connect(&proxy, &target).await.unwrap_err();
        server.await.expect("server task");
        err
    }

    #[tokio::test]
    async fn a_hostile_connect_reason_phrase_reaches_the_error_message_escaped() {
        // The reason phrase is fully attacker-controlled and lands in an error a caller
        // is very likely to print to a terminal. This payload erases the current line,
        // switches the colour, and rings the bell.
        let err = connect_error_for_response(
            b"HTTP/1.1 403 \x1b[2K\x1b[31mFATAL: credentials leaked\x07\r\n\r\n",
        )
        .await;

        match err {
            Error::Proxy { message, .. } => {
                assert!(
                    message.contains("403"),
                    "the numeric status is the part that carries information: {message}"
                );
                assert!(
                    !message.chars().any(char::is_control),
                    "the error message carries control characters: {message:?}"
                );
            }
            other => panic!("expected Error::Proxy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_overlong_connect_reason_phrase_is_truncated_in_the_error_message() {
        // Nothing bounds the reason phrase but the 16 KB head limit, so without a
        // truncation of its own the error message inherits that whole budget.
        let err = connect_error_for_response(
            b"HTTP/1.1 502 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
        )
        .await;

        match err {
            Error::Proxy { message, .. } => {
                assert!(
                    message.len() < 160,
                    "the reason phrase should be truncated, got {} bytes: {message}",
                    message.len()
                );
                assert!(message.contains("502"));
            }
            other => panic!("expected Error::Proxy, got {other:?}"),
        }
    }

    #[test]
    fn the_status_line_parser_requires_an_http_version_and_a_three_digit_status() {
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Some((200, "Connection established".to_string()))
        );
        assert_eq!(
            parse_status_line(b"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n"),
            Some((407, "Proxy Authentication Required".to_string()))
        );
        // A missing reason phrase is common enough in the wild to keep accepting.
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200\r\n\r\n"),
            Some((200, String::new()))
        );

        // Rust's integer syntax is broader than the three-digit status code the HTTP
        // grammar allows, and the version token was previously discarded unread. A
        // response no HTTP parser downstream would accept must not open a tunnel here.
        for rejected in [
            &b"HTTP/1.1 +200 ok\r\n\r\n"[..],
            b"HTTP/1.1 000200 ok\r\n\r\n",
            b"HTTP/1.1 0200 x\r\n\r\n",
            b"not-http 299 x\r\n\r\n",
            b"\x00 200 x\r\n\r\n",
            b"HTTP/1.1 20 x\r\n\r\n",
        ] {
            assert_eq!(
                parse_status_line(rejected),
                None,
                "{:?} must not parse as a status line",
                String::from_utf8_lossy(rejected)
            );
        }
    }

    async fn read_until_double_crlf(socket: &mut TcpStream, buf: &mut [u8]) -> usize {
        let mut total = 0;
        loop {
            let n = socket
                .read(&mut buf[total..])
                .await
                .expect("read from client");
            total += n;
            if buf[..total].ends_with(b"\r\n\r\n") || n == 0 {
                return total;
            }
        }
    }
}
