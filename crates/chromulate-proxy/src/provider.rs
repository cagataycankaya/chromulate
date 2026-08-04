//! Proxy pools and rotation strategies.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use chromulate_core::BoxFuture;

use crate::proxy::Proxy;

/// Selects a proxy for the next connection attempt from a pool.
///
/// Mirrors the boxed-future style of [`chromulate_core::Resolve`]: an object-safe
/// trait returning a boxed future, so heterogeneous providers (a fixed pool today, a
/// provider backed by a remote proxy list tomorrow) can be stored behind one
/// `Arc<dyn ProxyProvider>` and swapped at runtime.
pub trait ProxyProvider: Send + Sync + 'static {
    /// Selects the next proxy to try, or `None` if the pool is exhausted (every
    /// member has been reported as failed).
    fn next(&self) -> BoxFuture<'_, Option<Arc<Proxy>>>;

    /// Reports that `proxy` failed, so a rotating provider can temporarily skip it on
    /// subsequent selections.
    fn report_failure(&self, proxy: &Proxy);
}

/// A provider with exactly one proxy.
///
/// Once reported as failed it stays parked: there is nothing else in the pool to fall
/// back to.
pub struct Single {
    proxy: Arc<Proxy>,
    failed: AtomicBool,
}

impl Single {
    /// Wraps a single proxy.
    pub fn new(proxy: Proxy) -> Self {
        Self {
            proxy: Arc::new(proxy),
            failed: AtomicBool::new(false),
        }
    }
}

impl std::fmt::Debug for Single {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Single")
            .field("proxy", &self.proxy)
            .field("failed", &self.failed.load(Ordering::Relaxed))
            .finish()
    }
}

impl ProxyProvider for Single {
    fn next(&self) -> BoxFuture<'_, Option<Arc<Proxy>>> {
        Box::pin(async move {
            if self.failed.load(Ordering::Relaxed) {
                None
            } else {
                Some(Arc::clone(&self.proxy))
            }
        })
    }

    fn report_failure(&self, _proxy: &Proxy) {
        self.failed.store(true, Ordering::Relaxed);
    }
}

/// Cycles through a pool of proxies in order, skipping any reported as failed.
///
/// Selection is lock-free: an atomic cursor and a per-member failed flag, rather than
/// a mutex around the pool, since selection happens on the connect hot path.
pub struct RoundRobin {
    pool: Vec<Arc<Proxy>>,
    failed: Vec<AtomicBool>,
    cursor: AtomicUsize,
}

impl RoundRobin {
    /// Builds a round-robin provider over `pool`, tried in the given order.
    pub fn new(pool: Vec<Proxy>) -> Self {
        let failed = pool.iter().map(|_| AtomicBool::new(false)).collect();
        Self {
            pool: pool.into_iter().map(Arc::new).collect(),
            failed,
            cursor: AtomicUsize::new(0),
        }
    }

    fn index_of(&self, proxy: &Proxy) -> Option<usize> {
        self.pool
            .iter()
            .position(|candidate| candidate.as_ref() == proxy)
    }
}

impl std::fmt::Debug for RoundRobin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoundRobin")
            .field("pool_size", &self.pool.len())
            .field("cursor", &self.cursor.load(Ordering::Relaxed))
            .finish()
    }
}

impl ProxyProvider for RoundRobin {
    fn next(&self) -> BoxFuture<'_, Option<Arc<Proxy>>> {
        Box::pin(async move {
            let len = self.pool.len();
            if len == 0 {
                return None;
            }
            for _ in 0..len {
                let index = self.cursor.fetch_add(1, Ordering::Relaxed) % len;
                if !self.failed[index].load(Ordering::Relaxed) {
                    return Some(Arc::clone(&self.pool[index]));
                }
            }
            None
        })
    }

    fn report_failure(&self, proxy: &Proxy) {
        if let Some(index) = self.index_of(proxy) {
            self.failed[index].store(true, Ordering::Relaxed);
        }
    }
}

/// Picks a uniformly random proxy from the pool on every call, skipping any reported
/// as failed.
pub struct Random {
    pool: Vec<Arc<Proxy>>,
    failed: Vec<AtomicBool>,
}

impl Random {
    /// Builds a random-selection provider over `pool`.
    pub fn new(pool: Vec<Proxy>) -> Self {
        let failed = pool.iter().map(|_| AtomicBool::new(false)).collect();
        Self {
            pool: pool.into_iter().map(Arc::new).collect(),
            failed,
        }
    }

    fn index_of(&self, proxy: &Proxy) -> Option<usize> {
        self.pool
            .iter()
            .position(|candidate| candidate.as_ref() == proxy)
    }
}

impl std::fmt::Debug for Random {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Random")
            .field("pool_size", &self.pool.len())
            .finish()
    }
}

impl ProxyProvider for Random {
    fn next(&self) -> BoxFuture<'_, Option<Arc<Proxy>>> {
        Box::pin(async move {
            let available: Vec<usize> = (0..self.pool.len())
                .filter(|&index| !self.failed[index].load(Ordering::Relaxed))
                .collect();
            if available.is_empty() {
                return None;
            }
            let pick = rand::random_range(0..available.len());
            Some(Arc::clone(&self.pool[available[pick]]))
        })
    }

    fn report_failure(&self, proxy: &Proxy) {
        if let Some(index) = self.index_of(proxy) {
            self.failed[index].store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::ProxyUrl;

    fn proxy(host: &str) -> Proxy {
        Proxy::new(ProxyUrl::parse(&format!("http://{host}:8080")).expect("valid proxy URL"))
    }

    #[tokio::test]
    async fn single_returns_the_same_proxy_until_reported_failed() {
        let provider = Single::new(proxy("a"));
        assert_eq!(provider.next().await.expect("proxy").url().host(), "a");
        provider.report_failure(&proxy("a"));
        assert!(provider.next().await.is_none());
    }

    #[tokio::test]
    async fn round_robin_cycles_through_the_pool_in_order() {
        let provider = RoundRobin::new(vec![proxy("a"), proxy("b"), proxy("c")]);
        let order: Vec<String> = futures_next_n(&provider, 6).await;
        assert_eq!(order, vec!["a", "b", "c", "a", "b", "c"]);
    }

    #[tokio::test]
    async fn round_robin_skips_a_proxy_reported_as_failed() {
        let provider = RoundRobin::new(vec![proxy("a"), proxy("b"), proxy("c")]);
        provider.report_failure(&proxy("b"));
        let order: Vec<String> = futures_next_n(&provider, 4).await;
        assert_eq!(order, vec!["a", "c", "a", "c"]);
    }

    #[tokio::test]
    async fn round_robin_returns_none_once_every_proxy_has_failed() {
        let provider = RoundRobin::new(vec![proxy("a"), proxy("b")]);
        provider.report_failure(&proxy("a"));
        provider.report_failure(&proxy("b"));
        assert!(provider.next().await.is_none());
    }

    #[tokio::test]
    async fn random_never_selects_a_failed_proxy() {
        let provider = Random::new(vec![proxy("a"), proxy("b"), proxy("c")]);
        provider.report_failure(&proxy("b"));
        for _ in 0..50 {
            let selected = provider.next().await.expect("a proxy is still available");
            assert_ne!(selected.url().host(), "b");
        }
    }

    #[tokio::test]
    async fn random_returns_none_once_every_proxy_has_failed() {
        let provider = Random::new(vec![proxy("a")]);
        provider.report_failure(&proxy("a"));
        assert!(provider.next().await.is_none());
    }

    async fn futures_next_n(provider: &dyn ProxyProvider, n: usize) -> Vec<String> {
        let mut hosts = Vec::with_capacity(n);
        for _ in 0..n {
            let proxy = provider.next().await.expect("proxy available");
            hosts.push(proxy.url().host().to_string());
        }
        hosts
    }
}
