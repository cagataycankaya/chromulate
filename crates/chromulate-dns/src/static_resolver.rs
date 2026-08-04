//! A resolver backed by a fixed, in-memory host-to-address map.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use chromulate_core::{BoxFuture, Error, HostPort, Resolve, Result};

/// Resolves only the hosts it was given, failing every other lookup.
///
/// Useful in tests, where a live resolver would be non-deterministic and require
/// network access, and for pinning a crawler to specific addresses regardless of what
/// DNS would otherwise return.
///
/// Cloning is cheap: the address map is reference-counted and shared, not copied.
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    entries: Arc<HashMap<String, Vec<SocketAddr>>>,
}

impl StaticResolver {
    /// A resolver with no pinned hosts; every lookup fails.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a resolver from a fixed host-to-addresses map.
    ///
    /// The map key is the bare hostname, without a port, matching
    /// [`HostPort::host`]. Only the IP address of each configured
    /// [`SocketAddr`] is used: a resolver turns names into addresses, and the
    /// port belongs to the URL being requested, so one pin covers every port
    /// the caller might ask that host for.
    pub fn new(entries: HashMap<String, Vec<SocketAddr>>) -> Self {
        Self {
            entries: Arc::new(entries),
        }
    }

    /// Returns a resolver with one additional host pinned, leaving `self` unchanged.
    ///
    /// As with [`StaticResolver::new`], the ports in `addrs` are not part of
    /// the pin; the port of each resolved address comes from the lookup.
    pub fn with_host(&self, host: impl Into<String>, addrs: Vec<SocketAddr>) -> Self {
        let mut entries = (*self.entries).clone();
        entries.insert(host.into(), addrs);
        Self {
            entries: Arc::new(entries),
        }
    }
}

impl Resolve for StaticResolver {
    fn resolve(&self, target: HostPort) -> BoxFuture<'_, Result<Vec<SocketAddr>>> {
        let port = target.port();
        let found = self.entries.get(target.host()).map(|addrs| {
            addrs
                .iter()
                .map(|addr| SocketAddr::new(addr.ip(), port))
                .collect()
        });
        let host = target.host().to_string();
        Box::pin(async move { found.ok_or(Error::Resolve { host, source: None }) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        SocketAddr::from(([93, 184, 216, 34], 443))
    }

    #[tokio::test]
    async fn a_pinned_host_resolves_to_its_configured_addresses() {
        let resolver = StaticResolver::empty().with_host("example.com", vec![addr()]);
        let resolved = resolver
            .resolve(HostPort::new("example.com", 443))
            .await
            .expect("pinned host should resolve");
        assert_eq!(resolved, vec![addr()]);
    }

    #[tokio::test]
    async fn an_unpinned_host_fails_to_resolve() {
        let resolver = StaticResolver::empty();
        let err = resolver
            .resolve(HostPort::new("unknown.example", 443))
            .await
            .expect_err("an unpinned host should not resolve");
        assert!(matches!(err, Error::Resolve { host, .. } if host == "unknown.example"));
    }

    #[tokio::test]
    async fn the_port_comes_from_the_lookup_and_not_from_the_pin() {
        let resolver = StaticResolver::empty().with_host("example.com", vec![addr()]);
        let resolved = resolver
            .resolve(HostPort::new("example.com", 8080))
            .await
            .expect("pinned host should resolve");

        assert_eq!(
            resolved,
            vec![SocketAddr::from(([93, 184, 216, 34], 8080))],
            "one pin covers every port, so the requested port must survive the lookup"
        );
    }

    #[test]
    fn with_host_does_not_mutate_the_original_resolver() {
        let base = StaticResolver::empty();
        let _extended = base.with_host("example.com", vec![addr()]);
        assert!(base.entries.is_empty());
    }
}
