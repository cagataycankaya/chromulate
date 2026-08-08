//! The resolver layer behind [`chromulate_core::Resolve`].
//!
//! [`SystemResolver`] resolves hostnames through the operating system, the way a
//! browser does by default. [`StaticResolver`] pins hosts to fixed addresses, for
//! tests and for crawlers that need to bypass DNS entirely. [`CachingResolver`] wraps
//! either one (or any other [`chromulate_core::Resolve`] implementation) with a TTL cache and
//! single-flight lookup collapsing, which is the reason this crate exists: without
//! it, a crawler that starts many concurrent requests to one host issues one DNS
//! query per request instead of one query total.
//!
//! ## DNS-over-HTTPS
//!
//! This crate does not implement DNS-over-HTTPS. `Resolve` is a plain trait with a
//! single method, so a DoH resolver is a separate implementation of it, not a change
//! to anything here. It plugs in the same way `SystemResolver` and `StaticResolver`
//! do, and can itself be wrapped in [`CachingResolver`].
//!
//! ```
//! use std::net::SocketAddr;
//!
//! use chromulate_core::{HostPort, Resolve};
//! use chromulate_dns::{CachingResolver, StaticResolver};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let pinned: SocketAddr = "93.184.216.34:443".parse()?;
//! let resolver = CachingResolver::with_default_ttls(
//!     StaticResolver::empty().with_host("example.com", vec![pinned]),
//! );
//!
//! let addrs = resolver.resolve(HostPort::new("example.com", 443)).await?;
//! assert_eq!(addrs, vec![pinned]);
//! # Ok(())
//! # }
//! ```

#![doc(html_root_url = "https://docs.rs/chromulate-dns/0.3.0")]
#![warn(missing_docs)]

mod caching;
mod ip_preference;
mod static_resolver;
mod system;

pub use caching::{CachingResolver, Clock, DEFAULT_NEGATIVE_TTL, DEFAULT_POSITIVE_TTL};
pub use ip_preference::IpVersionPreference;
pub use static_resolver::StaticResolver;
pub use system::SystemResolver;
