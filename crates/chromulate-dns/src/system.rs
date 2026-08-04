//! Resolution via the operating system's asynchronous DNS resolver.

use std::net::SocketAddr;

use chromulate_core::{BoxFuture, Error, HostPort, Resolve, Result};
use tokio::net::lookup_host;

use crate::ip_preference::IpVersionPreference;

/// Resolves hostnames using [`tokio::net::lookup_host`], the standard non-blocking
/// wrapper around the platform's own resolver (`getaddrinfo` and friends).
///
/// This is the resolver a `Client` uses unless told otherwise. It carries no cache and
/// no single-flight coordination of its own; wrap it in [`crate::CachingResolver`] for
/// both.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver {
    preference: IpVersionPreference,
}

impl SystemResolver {
    /// Creates a resolver using the browser-default address family preference
    /// ([`IpVersionPreference::PreferIpv6`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a resolver with an explicit address family preference.
    pub const fn with_preference(preference: IpVersionPreference) -> Self {
        Self { preference }
    }
}

impl Resolve for SystemResolver {
    fn resolve(&self, target: HostPort) -> BoxFuture<'_, Result<Vec<SocketAddr>>> {
        let preference = self.preference;
        Box::pin(async move {
            let host = target.host().to_string();
            let port = target.port();
            let resolved =
                lookup_host((host.as_str(), port))
                    .await
                    .map_err(|source| Error::Resolve {
                        host: host.clone(),
                        source: Some(Box::new(source)),
                    })?;

            let addrs: Vec<SocketAddr> = resolved.collect();
            if addrs.is_empty() {
                return Err(Error::Resolve { host, source: None });
            }
            Ok(preference.reorder(addrs))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_resolver_prefers_ipv6_like_a_browser() {
        assert_eq!(
            SystemResolver::new().preference,
            IpVersionPreference::PreferIpv6
        );
    }

    #[test]
    fn a_specific_preference_is_kept_as_given() {
        let resolver = SystemResolver::with_preference(IpVersionPreference::Ipv4Only);
        assert_eq!(resolver.preference, IpVersionPreference::Ipv4Only);
    }
}
