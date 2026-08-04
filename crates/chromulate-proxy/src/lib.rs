//! Proxy configuration, connection establishment, and rotation for Chromulate.
//!
//! A browser reaching the network through a corporate or residential proxy is
//! observably different from one connecting directly: it speaks HTTP `CONNECT` or
//! SOCKS5 before any application traffic, it may resolve hostnames itself or defer to
//! the proxy, and it honours a `no_proxy` bypass list. This crate reproduces that
//! surface: parsing proxy URLs (including the scheme distinction that decides who
//! resolves a hostname), reading the standard `*_PROXY` environment variables,
//! tunnelling with HTTP `CONNECT` or hand-rolled SOCKS5, and rotating across a pool of
//! proxies.
//!
//! It deliberately stops at a connected, tunnelled [`tokio::net::TcpStream`]: TLS to
//! the target (when the target is `https://`) is the caller's responsibility, kept out
//! of this crate to avoid a dependency from transport-selection code onto the TLS
//! stack.
//!
//! ```
//! use chromulate_proxy::{NoProxy, Proxy, ProxyUrl};
//!
//! let proxy = Proxy::new(ProxyUrl::parse("http://proxy.example.com:8080").unwrap())
//!     .with_no_proxy(NoProxy::parse("localhost,.internal.example.com").unwrap());
//!
//! assert!(proxy.bypasses("service.internal.example.com"));
//! assert!(!proxy.bypasses("example.com"));
//! ```

#![warn(missing_docs)]

mod dial;
mod http_connect;
mod no_proxy;
mod provider;
mod proxy;
mod socks5;
mod url;

pub use no_proxy::NoProxy;
pub use provider::{ProxyProvider, Random, RoundRobin, Single};
pub use proxy::{Proxy, ProxyEnvironment};
pub use url::{ProxyScheme, ProxyUrl};
