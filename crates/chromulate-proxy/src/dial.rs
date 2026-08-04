//! Dialing the proxy's own TCP endpoint, shared by the HTTP `CONNECT` and SOCKS5
//! tunnel implementations.

use chromulate_core::{Error, Result};
use tokio::net::TcpStream;

use crate::url::ProxyUrl;

/// Opens a plain TCP connection to the proxy itself.
///
/// This resolves and connects to `proxy`'s own host and port; it has nothing to do
/// with how the *target* hostname is resolved, which is governed by [`ProxyScheme`]
/// and handled separately in the HTTP `CONNECT` and SOCKS5 modules.
///
/// [`ProxyScheme`]: crate::ProxyScheme
pub(crate) async fn dial(proxy: &ProxyUrl) -> Result<TcpStream> {
    TcpStream::connect((proxy.host(), proxy.port()))
        .await
        .map_err(|err| Error::Connect {
            target: proxy.to_string(),
            source: Some(Box::new(err)),
        })
}
