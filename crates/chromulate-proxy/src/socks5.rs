//! SOCKS5 tunnelling per RFC 1928 (protocol) and RFC 1929 (username/password
//! sub-negotiation), used by the `socks5://` and `socks5h://` proxy schemes.
//!
//! Implemented by hand against the RFCs rather than pulling in a SOCKS crate, per the
//! crate's dependency policy.

use std::net::IpAddr;

use chromulate_core::{Error, HostPort, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::dial::dial;
use crate::url::{ProxyScheme, ProxyUrl};

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const AUTH_SUBNEGOTIATION_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;

/// Dials `proxy` and establishes a SOCKS5 tunnel to `target`.
pub(crate) async fn connect(proxy: &ProxyUrl, target: &HostPort) -> Result<TcpStream> {
    let mut stream = dial(proxy).await?;
    handshake(&mut stream, proxy).await?;
    request_connect(&mut stream, proxy, target).await?;
    Ok(stream)
}

async fn handshake(stream: &mut TcpStream, proxy: &ProxyUrl) -> Result<()> {
    let methods: &[u8] = if proxy.has_credentials() {
        &[METHOD_USERNAME_PASSWORD, METHOD_NO_AUTH]
    } else {
        &[METHOD_NO_AUTH]
    };

    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(VERSION);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    write_all(stream, &greeting, proxy).await?;

    let mut selection = [0u8; 2];
    read_exact(stream, &mut selection, proxy).await?;
    if selection[0] != VERSION {
        return Err(proxy_error(
            proxy,
            format!(
                "proxy replied with unsupported SOCKS version {:#04x}",
                selection[0]
            ),
        ));
    }

    let selected = selection[1];
    if selected == METHOD_NO_ACCEPTABLE {
        return Err(proxy_error(
            proxy,
            "proxy rejected all offered authentication methods",
        ));
    }
    // RFC 1928 requires the client to close the connection when the proxy selects a
    // method it did not offer. Checked before the dispatch below, so a proxy answering
    // `0x02` to a greeting that only offered `0x00` cannot draw the client into an
    // RFC 1929 sub-negotiation it never asked for.
    if !methods.contains(&selected) {
        return Err(proxy_error(
            proxy,
            format!(
                "proxy selected authentication method {selected:#04x}, which the client did not offer"
            ),
        ));
    }

    match selected {
        METHOD_NO_AUTH => Ok(()),
        METHOD_USERNAME_PASSWORD => authenticate(stream, proxy).await,
        // `methods` only ever holds the two above, so the check just made has already
        // rejected everything else.
        other => Err(proxy_error(
            proxy,
            format!("proxy selected an unsupported authentication method {other:#04x}"),
        )),
    }
}

async fn authenticate(stream: &mut TcpStream, proxy: &ProxyUrl) -> Result<()> {
    let username = proxy.username().unwrap_or("");
    let password = proxy.password().unwrap_or("");
    check_credential_length("username", username)?;
    check_credential_length("password", password)?;

    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(AUTH_SUBNEGOTIATION_VERSION);
    request.push(username.len() as u8);
    request.extend_from_slice(username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    write_all(stream, &request, proxy).await?;

    let mut response = [0u8; 2];
    read_exact(stream, &mut response, proxy).await?;
    if response[0] != AUTH_SUBNEGOTIATION_VERSION {
        return Err(proxy_error(
            proxy,
            "proxy replied with an unsupported username/password sub-negotiation version",
        ));
    }
    if response[1] != AUTH_SUCCESS {
        return Err(proxy_error(
            proxy,
            "SOCKS5 username/password authentication failed",
        ));
    }
    Ok(())
}

/// Rejects a credential too long for RFC 1929's one-byte length prefix.
///
/// Truncating instead would desynchronise the whole exchange: the proxy would read
/// `len as u8` bytes as the field, the next byte as the following field's length, and
/// the remainder as the start of another SOCKS5 message — while the client believed it
/// had authenticated. Length is counted in bytes, so around 64 non-ASCII characters is
/// enough to reach the limit.
///
/// The message names the field and the limit but never the value, since an error string
/// is the one place a credential must not appear.
fn check_credential_length(field: &str, value: &str) -> Result<()> {
    if value.len() > u8::MAX as usize {
        return Err(Error::builder(format!(
            "SOCKS5 {field} is {} bytes, longer than the 255 bytes RFC 1929 allows",
            value.len()
        )));
    }
    Ok(())
}

async fn request_connect(
    stream: &mut TcpStream,
    proxy: &ProxyUrl,
    target: &HostPort,
) -> Result<()> {
    let mut request = vec![VERSION, CMD_CONNECT, 0x00];
    encode_address(&mut request, proxy, target).await?;
    write_all(stream, &request, proxy).await?;

    let mut head = [0u8; 4];
    read_exact(stream, &mut head, proxy).await?;
    if head[0] != VERSION {
        return Err(proxy_error(
            proxy,
            format!(
                "proxy replied with unsupported SOCKS version {:#04x}",
                head[0]
            ),
        ));
    }
    let reply = head[1];
    let address_type = head[3];

    // The proxy's own reason for failing is reported first. A proxy that refuses the
    // connection and also sends a malformed bound address has already told us the
    // useful half, and complaining about the address type would throw it away.
    reply_to_result(reply, proxy)?;

    // The bound address is not needed by the caller, but it must still be consumed so
    // the stream is left positioned at the first byte of tunnel data.
    match address_type {
        ATYP_V4 => discard(stream, proxy, 4 + 2).await?,
        ATYP_V6 => discard(stream, proxy, 16 + 2).await?,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len, proxy).await?;
            discard(stream, proxy, len[0] as usize + 2).await?;
        }
        other => {
            return Err(proxy_error(
                proxy,
                format!("proxy reply used an unsupported address type {other:#04x}"),
            ));
        }
    }

    Ok(())
}

async fn discard(stream: &mut TcpStream, proxy: &ProxyUrl, len: usize) -> Result<()> {
    let mut buf = vec![0u8; len];
    read_exact(stream, &mut buf, proxy).await
}

fn reply_to_result(reply: u8, proxy: &ProxyUrl) -> Result<()> {
    let message = match reply {
        0x00 => return Ok(()),
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        other => {
            return Err(proxy_error(
                proxy,
                format!("unknown SOCKS5 reply code {other:#04x}"),
            ));
        }
    };
    Err(proxy_error(proxy, message))
}

/// Encodes the destination address for the SOCKS5 `CONNECT` request.
///
/// A literal IP in `target` is always sent as an IPv4 or IPv6 address, regardless of
/// scheme; there is nothing to resolve. For a hostname, [`ProxyScheme::Socks5h`]
/// sends the domain name address type so the *proxy* resolves it, while
/// [`ProxyScheme::Socks5`] resolves locally first: sending a hostname to the proxy
/// under the plain `socks5://` scheme would silently change which resolver answers
/// for it, which is exactly the DNS-leak distinction the two schemes exist to make
/// explicit.
async fn encode_address(buf: &mut Vec<u8>, proxy: &ProxyUrl, target: &HostPort) -> Result<()> {
    if let Ok(ip) = target.host().parse::<IpAddr>() {
        push_ip_address(buf, ip, target.port());
        return Ok(());
    }

    if proxy.scheme() == ProxyScheme::Socks5h {
        return push_domain_address(buf, target.host(), target.port());
    }

    debug_assert!(proxy.scheme().client_resolves_target());
    let mut addresses = tokio::net::lookup_host((target.host(), target.port()))
        .await
        .map_err(|err| Error::Resolve {
            host: target.host().to_string(),
            source: Some(Box::new(err)),
        })?;
    let resolved = addresses.next().ok_or_else(|| Error::Resolve {
        host: target.host().to_string(),
        source: None,
    })?;
    push_ip_address(buf, resolved.ip(), target.port());
    Ok(())
}

fn push_ip_address(buf: &mut Vec<u8>, ip: IpAddr, port: u16) {
    match ip {
        IpAddr::V4(v4) => {
            buf.push(ATYP_V4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_V6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&port.to_be_bytes());
}

fn push_domain_address(buf: &mut Vec<u8>, host: &str, port: u16) -> Result<()> {
    if host.len() > u8::MAX as usize {
        return Err(Error::builder(format!(
            "SOCKS5 domain name `{host}` is longer than 255 bytes"
        )));
    }
    buf.push(ATYP_DOMAIN);
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

async fn write_all(stream: &mut TcpStream, buf: &[u8], proxy: &ProxyUrl) -> Result<()> {
    stream
        .write_all(buf)
        .await
        .map_err(|err| proxy_error(proxy, format!("write failed: {err}")))
}

async fn read_exact(stream: &mut TcpStream, buf: &mut [u8], proxy: &ProxyUrl) -> Result<()> {
    stream
        .read_exact(buf)
        .await
        .map(|_| ())
        .map_err(|err| proxy_error(proxy, format!("read failed: {err}")))
}

fn proxy_error(proxy: &ProxyUrl, message: impl Into<String>) -> Error {
    Error::Proxy {
        proxy: proxy.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    async fn fake_proxy() -> (TcpListener, ProxyUrl) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!("socks5://{}:{}", addr.ip(), addr.port()))
            .expect("valid proxy URL");
        (listener, proxy)
    }

    #[tokio::test]
    async fn greeting_offers_no_auth_only_without_credentials() {
        let (listener, proxy) = fake_proxy().await;
        let target = HostPort::new("93.184.216.34", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            socket
                .read_exact(&mut greeting)
                .await
                .expect("read greeting header");
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.expect("read methods");
            socket
                .write_all(&[VERSION, METHOD_NO_AUTH])
                .await
                .expect("write selection");

            let mut request = [0u8; 4];
            socket
                .read_exact(&mut request)
                .await
                .expect("read connect request head");
            let mut addr = [0u8; 4 + 2];
            socket
                .read_exact(&mut addr)
                .await
                .expect("read ipv4 address");
            socket
                .write_all(&[VERSION, 0x00, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .expect("write reply");

            (greeting, methods, request, addr)
        });

        connect(&proxy, &target).await.expect("connected");
        let (greeting, methods, _request, _addr) = server.await.expect("server task");
        assert_eq!(greeting, [VERSION, 1]);
        assert_eq!(methods, vec![METHOD_NO_AUTH]);
    }

    #[tokio::test]
    async fn greeting_offers_username_password_first_when_credentials_are_set() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!(
            "socks5://alice:hunter2@{}:{}",
            addr.ip(),
            addr.port()
        ))
        .expect("valid proxy URL");
        let target = HostPort::new("93.184.216.34", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            socket
                .read_exact(&mut greeting)
                .await
                .expect("read greeting header");
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.expect("read methods");
            socket
                .write_all(&[VERSION, METHOD_USERNAME_PASSWORD])
                .await
                .expect("write selection");

            let mut auth_header = [0u8; 2];
            socket
                .read_exact(&mut auth_header)
                .await
                .expect("read auth version and ulen");
            let mut username = vec![0u8; auth_header[1] as usize];
            socket
                .read_exact(&mut username)
                .await
                .expect("read username");
            let mut plen = [0u8; 1];
            socket.read_exact(&mut plen).await.expect("read plen");
            let mut password = vec![0u8; plen[0] as usize];
            socket
                .read_exact(&mut password)
                .await
                .expect("read password");
            socket
                .write_all(&[AUTH_SUBNEGOTIATION_VERSION, AUTH_SUCCESS])
                .await
                .expect("write auth result");

            let mut request = [0u8; 4];
            socket
                .read_exact(&mut request)
                .await
                .expect("read connect request head");
            let mut addr_bytes = [0u8; 4 + 2];
            socket
                .read_exact(&mut addr_bytes)
                .await
                .expect("read ipv4 address");
            socket
                .write_all(&[VERSION, 0x00, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .expect("write reply");

            (methods, auth_header, username, password)
        });

        connect(&proxy, &target).await.expect("connected");
        let (methods, auth_header, username, password) = server.await.expect("server task");
        assert_eq!(methods, vec![METHOD_USERNAME_PASSWORD, METHOD_NO_AUTH]);
        assert_eq!(auth_header, [AUTH_SUBNEGOTIATION_VERSION, 5]);
        assert_eq!(username, b"alice");
        assert_eq!(password, b"hunter2");
    }

    #[tokio::test]
    async fn connect_request_uses_ipv4_address_type_for_a_literal_ipv4_target() {
        let (listener, proxy) = fake_proxy().await;
        let target = HostPort::new("93.184.216.34", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            socket
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.expect("read methods");
            socket
                .write_all(&[VERSION, METHOD_NO_AUTH])
                .await
                .expect("write selection");

            let mut request = vec![0u8; 4];
            socket
                .read_exact(&mut request)
                .await
                .expect("read request head");
            let mut rest = vec![0u8; 4 + 2];
            socket
                .read_exact(&mut rest)
                .await
                .expect("read ipv4 address and port");
            request.extend_from_slice(&rest);
            socket
                .write_all(&[VERSION, 0x00, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .expect("write reply");
            request
        });

        connect(&proxy, &target).await.expect("connected");
        let request = server.await.expect("server task");
        assert_eq!(
            request,
            vec![
                VERSION,
                CMD_CONNECT,
                0x00,
                ATYP_V4,
                93,
                184,
                216,
                34,
                0x01,
                0xBB
            ]
        );
    }

    #[tokio::test]
    async fn connect_request_uses_ipv6_address_type_for_a_literal_ipv6_target() {
        let (listener, proxy) = fake_proxy().await;
        let target = HostPort::new("2001:db8::1", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            socket
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.expect("read methods");
            socket
                .write_all(&[VERSION, METHOD_NO_AUTH])
                .await
                .expect("write selection");

            let mut request = vec![0u8; 4];
            socket
                .read_exact(&mut request)
                .await
                .expect("read request head");
            let mut rest = vec![0u8; 16 + 2];
            socket
                .read_exact(&mut rest)
                .await
                .expect("read ipv6 address and port");
            request.extend_from_slice(&rest);
            socket
                .write_all(&[VERSION, 0x00, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .expect("write reply");
            request
        });

        connect(&proxy, &target).await.expect("connected");
        let request = server.await.expect("server task");
        let expected_ip = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let mut expected = vec![VERSION, CMD_CONNECT, 0x00, ATYP_V6];
        expected.extend_from_slice(&expected_ip.octets());
        expected.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(request, expected);
    }

    #[tokio::test]
    async fn socks5h_sends_domain_address_type_for_a_hostname_target() {
        let (listener, proxy) = fake_proxy_with_scheme("socks5h").await;
        let target = HostPort::new("example.com", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            socket
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.expect("read methods");
            socket
                .write_all(&[VERSION, METHOD_NO_AUTH])
                .await
                .expect("write selection");

            let mut head = vec![0u8; 5];
            socket
                .read_exact(&mut head)
                .await
                .expect("read request head and domain length");
            let domain_len = head[4] as usize;
            let mut rest = vec![0u8; domain_len + 2];
            socket
                .read_exact(&mut rest)
                .await
                .expect("read domain and port");
            head.extend_from_slice(&rest);
            socket
                .write_all(&[VERSION, 0x00, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .expect("write reply");
            head
        });

        connect(&proxy, &target).await.expect("connected");
        let request = server.await.expect("server task");

        let mut expected = vec![
            VERSION,
            CMD_CONNECT,
            0x00,
            ATYP_DOMAIN,
            b"example.com".len() as u8,
        ];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(request, expected);
    }

    #[tokio::test]
    async fn plain_socks5_resolves_a_hostname_locally_instead_of_sending_it() {
        let (listener, proxy) = fake_proxy_with_scheme("socks5").await;
        let target = HostPort::new("localhost", 443);

        // Resolve the same way the client under test will, so the assertion does not
        // depend on which of 127.0.0.1 / ::1 the local resolver prefers.
        let mut expected_addrs = tokio::net::lookup_host(("localhost", 443))
            .await
            .expect("resolve localhost for the test itself");
        let expected_ip = expected_addrs
            .next()
            .expect("at least one address for localhost")
            .ip();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            socket
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.expect("read methods");
            socket
                .write_all(&[VERSION, METHOD_NO_AUTH])
                .await
                .expect("write selection");

            let mut head = vec![0u8; 4];
            socket
                .read_exact(&mut head)
                .await
                .expect("read request head");
            let address_type = head[3];
            let address_len = match address_type {
                ATYP_V4 => 4,
                ATYP_V6 => 16,
                other => panic!("expected an IP address type for plain socks5, got {other:#04x}"),
            };
            let mut rest = vec![0u8; address_len + 2];
            socket
                .read_exact(&mut rest)
                .await
                .expect("read address and port");
            head.extend_from_slice(&rest);
            socket
                .write_all(&[VERSION, 0x00, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .expect("write reply");
            head
        });

        connect(&proxy, &target).await.expect("connected");
        let request = server.await.expect("server task");

        assert_ne!(
            request[3], ATYP_DOMAIN,
            "plain socks5:// must not send a domain name to the proxy"
        );
        let sent_ip: IpAddr = match request[3] {
            ATYP_V4 => IpAddr::V4(std::net::Ipv4Addr::new(
                request[4], request[5], request[6], request[7],
            )),
            ATYP_V6 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&request[4..20]);
                IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            other => panic!("unexpected address type {other:#04x}"),
        };
        assert_eq!(sent_ip, expected_ip);
    }

    #[tokio::test]
    async fn each_socks5_reply_code_maps_to_a_distinct_message() {
        let cases: &[(u8, &str)] = &[
            (0x01, "general SOCKS server failure"),
            (0x02, "connection not allowed by ruleset"),
            (0x03, "network unreachable"),
            (0x04, "host unreachable"),
            (0x05, "connection refused"),
            (0x06, "TTL expired"),
            (0x07, "command not supported"),
            (0x08, "address type not supported"),
        ];

        let mut messages = std::collections::HashSet::new();
        for &(code, expected_message) in cases {
            let (listener, proxy) = fake_proxy().await;
            let target = HostPort::new("93.184.216.34", 443);

            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let mut greeting = [0u8; 2];
                socket
                    .read_exact(&mut greeting)
                    .await
                    .expect("read greeting");
                let mut methods = vec![0u8; greeting[1] as usize];
                socket.read_exact(&mut methods).await.expect("read methods");
                socket
                    .write_all(&[VERSION, METHOD_NO_AUTH])
                    .await
                    .expect("write selection");

                let mut request = vec![0u8; 4];
                socket
                    .read_exact(&mut request)
                    .await
                    .expect("read request head");
                let mut rest = vec![0u8; 4 + 2];
                socket
                    .read_exact(&mut rest)
                    .await
                    .expect("read ipv4 address and port");
                socket
                    .write_all(&[VERSION, code, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("write reply");
            });

            let err = connect(&proxy, &target).await.unwrap_err();
            server.await.expect("server task");

            match err {
                Error::Proxy { message, .. } => {
                    assert_eq!(message, expected_message);
                    messages.insert(message);
                }
                other => panic!("expected Error::Proxy for code {code:#04x}, got {other:?}"),
            }
        }
        assert_eq!(
            messages.len(),
            cases.len(),
            "every reply code must map to a distinct message"
        );
    }

    #[tokio::test]
    async fn method_no_acceptable_is_a_redacted_proxy_error() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!(
            "socks5://alice:hunter2@{}:{}",
            addr.ip(),
            addr.port()
        ))
        .expect("valid proxy URL");
        let target = HostPort::new("93.184.216.34", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            socket
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.expect("read methods");
            socket
                .write_all(&[VERSION, METHOD_NO_ACCEPTABLE])
                .await
                .expect("write selection");
        });

        let err = connect(&proxy, &target).await.unwrap_err();
        server.await.expect("server task");

        match err {
            Error::Proxy {
                proxy: redacted, ..
            } => {
                assert!(!redacted.contains("alice"));
                assert!(!redacted.contains("hunter2"));
            }
            other => panic!("expected Error::Proxy, got {other:?}"),
        }
    }

    /// Reads whatever the client sends next, returning empty if it closes or stays
    /// silent. Bounded by a deadline so a client that is waiting for a reply cannot
    /// deadlock the test against a server that is waiting for a request.
    async fn read_next_message(socket: &mut TcpStream) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        let read =
            tokio::time::timeout(std::time::Duration::from_millis(250), socket.read(&mut buf))
                .await
                .unwrap_or(Ok(0))
                .unwrap_or(0);
        buf.truncate(read);
        buf
    }

    /// Completes the greeting and answers with `selected_method`.
    async fn greet(socket: &mut TcpStream, selected_method: u8) -> Vec<u8> {
        let mut greeting = [0u8; 2];
        socket
            .read_exact(&mut greeting)
            .await
            .expect("read greeting header");
        let mut methods = vec![0u8; greeting[1] as usize];
        socket.read_exact(&mut methods).await.expect("read methods");
        socket
            .write_all(&[VERSION, selected_method])
            .await
            .expect("write selection");
        methods
    }

    #[tokio::test]
    async fn a_socks5_credential_longer_than_255_bytes_is_rejected_rather_than_truncated() {
        // RFC 1929 encodes each length in one byte. Truncating a 300-byte username to
        // `300 as u8 == 44` desynchronises the exchange: the proxy reads 44 bytes as the
        // username, the 45th as the password length, and further username bytes as the
        // password, while the remainder stays in the stream to be read as the next
        // SOCKS5 message. The client would believe it had authenticated.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let username = "A".repeat(300);
        let proxy = ProxyUrl::parse(&format!(
            "socks5://{username}:secret@{}:{}",
            addr.ip(),
            addr.port()
        ))
        .expect("valid proxy URL");
        let target = HostPort::new("93.184.216.34", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            greet(&mut socket, METHOD_USERNAME_PASSWORD).await;
            read_next_message(&mut socket).await
        });

        let err = connect(&proxy, &target).await.unwrap_err();
        let after_selection = server.await.expect("server task");

        assert!(
            after_selection.is_empty(),
            "the client sent a truncated credential instead of refusing: {after_selection:?}"
        );
        match err {
            Error::Builder(message) => {
                assert!(
                    message.contains("255"),
                    "the error should name the RFC 1929 limit: {message}"
                );
                assert!(
                    !message.contains(&username),
                    "the error must not echo the credential: {message}"
                );
            }
            other => panic!("expected Error::Builder, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_authentication_method_the_client_never_offered_is_rejected() {
        // With no credentials configured the client offers only `[0x00]`. RFC 1928
        // requires it to close the connection when the proxy selects anything else,
        // rather than opening a sub-negotiation it never asked for.
        let (listener, proxy) = fake_proxy().await;
        let target = HostPort::new("93.184.216.34", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let methods = greet(&mut socket, METHOD_USERNAME_PASSWORD).await;
            (methods, read_next_message(&mut socket).await)
        });

        let err = connect(&proxy, &target).await.unwrap_err();
        let (methods, after_selection) = server.await.expect("server task");

        assert_eq!(methods, vec![METHOD_NO_AUTH]);
        assert!(
            after_selection.is_empty(),
            "the client began an auth sub-negotiation for a method it never offered: \
             {after_selection:?}"
        );
        match err {
            Error::Proxy { message, .. } => assert!(
                message.contains("did not offer"),
                "the error should say the method was never offered: {message}"
            ),
            other => panic!("expected Error::Proxy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_refused_connection_reports_the_reply_code_not_the_bound_address_type() {
        // A proxy that both refuses the connection and sends a malformed bound address
        // has already told us the useful half; reporting the address type instead throws
        // the actual failure reason away.
        let (listener, proxy) = fake_proxy().await;
        let target = HostPort::new("93.184.216.34", 443);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            greet(&mut socket, METHOD_NO_AUTH).await;

            let mut request = vec![0u8; 4 + 4 + 2];
            socket
                .read_exact(&mut request)
                .await
                .expect("read connect request");
            // Reply code 0x02 (not allowed by ruleset) with an address type no SOCKS5
            // reply may carry.
            socket
                .write_all(&[VERSION, 0x02, 0x00, 0x09])
                .await
                .expect("write reply");
        });

        let err = connect(&proxy, &target).await.unwrap_err();
        server.await.expect("server task");

        match err {
            Error::Proxy { message, .. } => {
                assert_eq!(message, "connection not allowed by ruleset");
            }
            other => panic!("expected Error::Proxy, got {other:?}"),
        }
    }

    async fn fake_proxy_with_scheme(scheme: &str) -> (TcpListener, ProxyUrl) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("local addr");
        let proxy = ProxyUrl::parse(&format!("{scheme}://{}:{}", addr.ip(), addr.port()))
            .expect("valid proxy URL");
        (listener, proxy)
    }
}
