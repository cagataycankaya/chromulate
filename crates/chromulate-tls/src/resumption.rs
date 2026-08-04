//! A bounded, per-host store of resumption material.
//!
//! Resumption is not an optimisation here. The Chrome 151 capture's second
//! connection carries `pre_shared_key`, so a client that always performs a full
//! handshake is visibly not a browser. The store is what makes the second
//! connection to a host look like the browser's second connection.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use rustls::NamedGroup;
use rustls::client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls_pki_types::ServerName;

/// The number of hosts a store keeps by default.
///
/// A browser profile holds far more than this, but a crawler pointed at one
/// site needs one entry and a crawler pointed at thousands should not grow an
/// unbounded map, so the default is small and the cap is a constructor
/// argument.
pub const DEFAULT_CAPACITY: usize = 256;

/// The number of TLS 1.3 tickets kept per host.
///
/// A server may issue several; RFC 8446 makes each single-use, so keeping a few
/// lets consecutive connections each present a fresh one. Beyond a handful they
/// are just memory.
const TICKETS_PER_HOST: usize = 8;

/// A bounded store of session tickets and key exchange hints, keyed by server
/// name.
///
/// Entries are evicted least-recently-used once `capacity` hosts are held.
/// Material stored for one host is never offered to another: the map is keyed
/// by the [`ServerName`] the connection was made to, which is the same
/// partitioning a browser applies.
///
/// The store is shared by cloning the [`std::sync::Arc`] the engine holds, so
/// two engines built from one store resume each other's sessions and two
/// engines built with separate stores do not.
#[derive(Debug)]
pub struct SessionStore {
    capacity: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    hosts: HashMap<ServerName<'static>, HostSessions>,
    /// Least recently used first.
    recency: VecDeque<ServerName<'static>>,
}

#[derive(Debug, Default)]
struct HostSessions {
    kx_hint: Option<NamedGroup>,
    tls12: Option<Tls12ClientSessionValue>,
    tls13: VecDeque<Tls13ClientSessionValue>,
}

impl SessionStore {
    /// Builds a store holding at most `capacity` hosts.
    ///
    /// A capacity of zero is raised to one, because a store that cannot hold
    /// anything would silently turn resumption off.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            state: Mutex::new(State::default()),
        }
    }

    /// Returns the number of hosts currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().hosts.len()
    }

    /// Returns `true` when nothing is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of hosts the store will hold before evicting.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Drops everything stored for one host, so the next connection to it
    /// performs a full handshake.
    pub fn forget(&self, server_name: &ServerName<'_>) {
        let mut state = self.lock();
        if state.hosts.remove(&server_name.to_owned()).is_some() {
            state.recency.retain(|held| held != server_name);
        }
    }

    /// Drops everything, so every next connection performs a full handshake.
    pub fn clear(&self) {
        let mut state = self.lock();
        state.hosts.clear();
        state.recency.clear();
    }

    /// Returns `true` when a TLS 1.3 ticket is available for this host.
    ///
    /// Exposed so a caller can tell "the second connection will offer
    /// `pre_shared_key`" from "the server never issued a ticket" without
    /// opening a connection to find out.
    #[must_use]
    pub fn has_ticket(&self, server_name: &ServerName<'_>) -> bool {
        self.lock()
            .hosts
            .get(&server_name.to_owned())
            .is_some_and(|host| !host.tls13.is_empty() || host.tls12.is_some())
    }

    /// A poisoned lock means another thread panicked while holding it. The data
    /// behind it is a cache of resumption material, so the worst outcome of
    /// carrying on is a full handshake; refusing to hand it back would take
    /// every later connection down with the panic.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("the TLS session store lock was poisoned; continuing with its contents");
            poisoned.into_inner()
        })
    }

    /// Runs `edit` against the entry for `server_name`, creating it and evicting
    /// the least recently used host if that takes the store over capacity.
    fn with_host<R>(
        &self,
        server_name: ServerName<'static>,
        edit: impl FnOnce(&mut HostSessions) -> R,
    ) -> R {
        let mut state = self.lock();
        state.touch(&server_name);
        let result = edit(state.hosts.entry(server_name).or_default());
        state.evict_to(self.capacity);
        result
    }

    /// Runs `read` against the entry for `server_name` without creating one.
    fn read_host<R>(
        &self,
        server_name: &ServerName<'_>,
        read: impl FnOnce(&mut HostSessions) -> R,
    ) -> Option<R> {
        let key = server_name.to_owned();
        let mut state = self.lock();
        let result = read(state.hosts.get_mut(&key)?);
        state.touch(server_name);
        Some(result)
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl State {
    /// Moves a host to the most-recently-used end of the queue.
    fn touch(&mut self, server_name: &ServerName<'_>) {
        self.recency.retain(|held| held != server_name);
        self.recency.push_back(server_name.to_owned());
    }

    /// Drops least recently used hosts until the map fits.
    fn evict_to(&mut self, capacity: usize) {
        while self.hosts.len() > capacity {
            match self.recency.pop_front() {
                Some(oldest) => {
                    self.hosts.remove(&oldest);
                }
                None => {
                    self.hosts.clear();
                    break;
                }
            }
        }
    }
}

impl ClientSessionStore for SessionStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.with_host(server_name, |host| host.kx_hint = Some(group));
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.read_host(server_name, |host| host.kx_hint)?
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.with_host(server_name, |host| host.tls12 = Some(value));
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.read_host(server_name, |host| host.tls12.clone())?
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.read_host(server_name, |host| host.tls12 = None);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        self.with_host(server_name, |host| {
            if host.tls13.len() == TICKETS_PER_HOST {
                host.tls13.pop_front();
            }
            host.tls13.push_back(value);
        });
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        self.read_host(server_name, |host| host.tls13.pop_back())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(host: &str) -> ServerName<'static> {
        ServerName::try_from(host)
            .expect("the test host should be a valid name")
            .to_owned()
    }

    #[test]
    fn material_stored_for_one_host_is_not_offered_to_another() {
        let store = SessionStore::new(8);
        store.set_kx_hint(name("example.com"), NamedGroup::X25519);

        assert_eq!(
            store.kx_hint(&name("example.com")),
            Some(NamedGroup::X25519)
        );
        assert_eq!(store.kx_hint(&name("other.example")), None);
        assert_eq!(
            store.kx_hint(&name("sub.example.com")),
            None,
            "a subdomain is a different host, not the same one"
        );
    }

    #[test]
    fn forgetting_a_host_leaves_the_others_alone() {
        let store = SessionStore::new(8);
        store.set_kx_hint(name("a.example"), NamedGroup::X25519);
        store.set_kx_hint(name("b.example"), NamedGroup::secp256r1);

        store.forget(&name("a.example"));

        assert_eq!(store.kx_hint(&name("a.example")), None);
        assert_eq!(
            store.kx_hint(&name("b.example")),
            Some(NamedGroup::secp256r1)
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn the_store_never_grows_past_its_capacity() {
        let store = SessionStore::new(4);
        for index in 0..64 {
            store.set_kx_hint(name(&format!("host{index}.example")), NamedGroup::X25519);
            assert!(
                store.len() <= 4,
                "the store held {} hosts with a capacity of 4",
                store.len()
            );
        }
        assert_eq!(store.len(), 4);
    }

    #[test]
    fn the_least_recently_used_host_is_the_one_evicted() {
        let store = SessionStore::new(2);
        store.set_kx_hint(name("first.example"), NamedGroup::X25519);
        store.set_kx_hint(name("second.example"), NamedGroup::X25519);

        assert_eq!(
            store.kx_hint(&name("first.example")),
            Some(NamedGroup::X25519)
        );
        store.set_kx_hint(name("third.example"), NamedGroup::X25519);

        assert_eq!(
            store.kx_hint(&name("second.example")),
            None,
            "second.example was the least recently used entry"
        );
        assert_eq!(
            store.kx_hint(&name("first.example")),
            Some(NamedGroup::X25519)
        );
        assert_eq!(
            store.kx_hint(&name("third.example")),
            Some(NamedGroup::X25519)
        );
    }

    #[test]
    fn a_zero_capacity_store_still_holds_one_host_rather_than_disabling_resumption() {
        let store = SessionStore::new(0);
        assert_eq!(store.capacity(), 1);
        store.set_kx_hint(name("example.com"), NamedGroup::X25519);
        assert_eq!(
            store.kx_hint(&name("example.com")),
            Some(NamedGroup::X25519)
        );
    }

    #[test]
    fn clearing_the_store_forces_the_next_handshake_to_be_a_full_one() {
        let store = SessionStore::new(8);
        store.set_kx_hint(name("example.com"), NamedGroup::X25519);
        assert!(!store.is_empty());

        store.clear();

        assert!(store.is_empty());
        assert_eq!(store.kx_hint(&name("example.com")), None);
    }

    #[test]
    fn a_host_with_no_stored_ticket_reports_that_it_has_none() {
        let store = SessionStore::new(8);
        store.set_kx_hint(name("example.com"), NamedGroup::X25519);
        assert!(
            !store.has_ticket(&name("example.com")),
            "a key exchange hint is not a ticket"
        );
        assert!(store.take_tls13_ticket(&name("example.com")).is_none());
    }
}
