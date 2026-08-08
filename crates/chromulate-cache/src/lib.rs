//! An RFC 9111 HTTP cache for the Chromulate engine.
//!
//! A wrong cache is worse than no cache: it serves one user's private page to
//! another, or keeps a copy the origin said nobody may keep. This crate is
//! therefore a deliberately small subset of RFC 9111, implemented exactly, with
//! the gaps written down rather than glossed. [What this cache does not
//! do](#what-this-cache-does-not-do) is not an appendix — read it before
//! deciding this is the cache you want.
//!
//! # Using it
//!
//! ```
//! use std::sync::Arc;
//!
//! use chromulate_cache::{CacheConfig, HttpCache, MemoryLimits, MemoryStore};
//!
//! let cache = HttpCache::builder()
//!     .storage(Arc::new(MemoryStore::with_limits(MemoryLimits {
//!         max_bytes: 8 * 1024 * 1024,
//!         shards: 8,
//!     })))
//!     .config(CacheConfig {
//!         // This engine belongs to one identity, so `private` responses may
//!         // be kept. See `CacheConfig::store_private` before copying this.
//!         store_private: true,
//!         ..CacheConfig::default()
//!     })
//!     .build();
//!
//! assert_eq!(cache.config().store_private, true);
//! ```
//!
//! `chromulate-http` wires this in behind its off-by-default `cache` feature;
//! with the feature off, no part of this crate is compiled into the engine.
//!
//! # What this cache does
//!
//! - **Storability** (§3): `GET` only; the heuristically cacheable status set
//!   from RFC 9110 §15.1 minus `206`, plus `302` and `307` when the origin
//!   states a lifetime; `no-store` on either message; `private` under
//!   [`CacheConfig::store_private`]; `Authorization` under §3.5's three
//!   allowances.
//! - **Freshness** (§4.2): `max-age`, `Expires` (including the RFC 9111 §5.3
//!   rule that an invalid `Expires` is a time in the past), and the
//!   `Last-Modified` heuristic capped at
//!   [`CacheConfig::heuristic_cap`]. `s-maxage` is parsed and deliberately not
//!   used for freshness — see below.
//! - **Age** (§4.2.3): the full correction, not just the `Age` field. The
//!   round trip the origin could not know about, and the time the entry has
//!   since spent in this cache, are both added.
//! - **Revalidation** (§4.3): `ETag` becomes `If-None-Match`, `Last-Modified`
//!   becomes `If-Modified-Since`, and a `304` updates the stored fields — never
//!   the stored `Content-Length` — and restarts the entry's age. A `304` is put
//!   back through the storability rules after the merge, because it can carry
//!   `no-store`, `Set-Cookie` or `private` that the stored response did not;
//!   one that fails them is served to the caller and dropped from the store
//!   rather than kept. A `304` naming an `ETag` other than the stored one, or a
//!   `Vary` other than the stored one, updates nothing: §4.3.4 says a validator
//!   this cache does not hold identifies a representation it does not hold.
//! - **`Vary`** (§4.1): a stored response only matches a request whose
//!   selecting fields agree, absence included. `Vary: *` is never stored.
//! - **`no-cache` versus `no-store`** (§5.2.2): a `no-cache` response is
//!   stored and revalidated on every use; a `no-store` response is not stored
//!   at all, and drops whatever was.
//! - **Invalidation** (§4.4): a successful unsafe method drops the stored
//!   response for its target, and for the same-origin targets its `Location`
//!   and `Content-Location` name.
//!
//! # What this cache does not do
//!
//! Each of these is absent on purpose. None of them is partially implemented.
//!
//! - **`stale-while-revalidate` and `stale-if-error`** (RFC 5861). This cache
//!   never serves a stale response. A stale entry is either revalidated or
//!   bypassed, so `must-revalidate` and `proxy-revalidate` are satisfied by
//!   construction and a `5xx` during revalidation is returned to the caller
//!   rather than papered over.
//! - **Shared-cache semantics.** This is a private cache. `s-maxage` does not
//!   contribute to freshness, `public` grants nothing beyond §3.5's
//!   `Authorization` allowance, and there is no `proxy-revalidate` handling.
//!   Do not put this in front of more than one identity without setting
//!   [`CacheConfig::store_private`] to `false` and reading what that costs.
//! - **Range requests.** No `Range`, no `206`, no `Content-Range`, no partial
//!   or combined stored responses. A request that carries `Range` bypasses the
//!   cache entirely.
//! - **`HEAD`.** Neither stored, nor used to update a stored `GET` (§4.3.5).
//! - **Request directives `only-if-cached`, `min-fresh`, and `max-stale`.**
//!   Parsed as unknown and ignored, which is what §5.2 requires of a cache that
//!   does not implement them. `no-cache`, `no-store` and `max-age=0` on a
//!   request *are* honoured.
//! - **Argued `no-cache` and `private`.** `no-cache="set-cookie"` is treated as
//!   bare `no-cache`, and `private="x"` as bare `private`. Stricter than the
//!   specification allows, never less safe.
//! - **`must-understand` and `immutable`.** Parsed, not acted on. `immutable`
//!   would only suppress a revalidation this cache does not perform.
//! - **Trailers.** Dropped, as they are everywhere else in this workspace.
//! - **Persistence.** [`MemoryStore`] is in-process and unshared. A disk or
//!   network backend is an implementation of [`CacheStorage`], not a change
//!   here.
//! - **`Set-Cookie` responses.** Never stored. This is not an RFC rule; it is
//!   this crate's, because replaying a stored `Set-Cookie` re-applies one
//!   identity's state to another request, and dropping it silently loses state
//!   the origin sent.
//! - **`Vary` on fields the engine writes per request.** A response that
//!   selects on `Cookie`, `Accept`, `Referer`, `Origin`, `Priority`,
//!   `Upgrade-Insecure-Requests`, a `Sec-Fetch-*` field, or a high-entropy
//!   client hint is **not stored at all**. The cache sees a request before
//!   `chromulate_header::HeaderEngine` and the cookie jar have written it, so
//!   it cannot prove two such requests equivalent — and `Vary: Cookie` is
//!   precisely how a cache serves one user's page to another. Fields the
//!   profile writes identically on every request (`User-Agent`,
//!   `Accept-Encoding`, `Accept-Language`, the low-entropy hints) are matched
//!   normally, because "absent from both snapshots" and "the same constant on
//!   both requests" are the same statement for those.
//!
//! # Memory
//!
//! A stored body is held whole, as [`bytes::Bytes`]. There is no way to store a
//! stream and no way to replay one, so the choice is between buffering and not
//! caching. What this crate does *not* do is buffer ahead of the caller: a
//! recordable response is handed over still streaming, and the entry is
//! committed only when the caller has read the last chunk. A body that exceeds
//! [`CacheConfig::max_body_bytes`] — eight megabytes by default, and checked
//! against `Content-Length` before a single byte is buffered — is streamed and
//! not stored.
//!
//! The peak cost is therefore one buffered copy per in-flight recordable
//! response, bounded by `max_body_bytes` each, plus [`MemoryLimits::max_bytes`]
//! for the store itself.
//!
//! A body that arrives shorter or longer than its own `Content-Length` is not
//! stored. RFC 9110 §6.3 calls such a message malformed, and storing one would
//! freeze the disagreement: the body becomes [`bytes::Bytes`] and the header
//! stays a claim about it that nothing downstream re-derives.
//!
//! # Locking
//!
//! [`MemoryStore`] is sharded: sixteen independent `Mutex`es by default, chosen
//! by the hash of the key. This project pays for one global lock already, in
//! the connection pool, and a second one in front of every request is what the
//! sharding exists to avoid.

#![doc(html_root_url = "https://docs.rs/chromulate-cache/0.3.0")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cache;
mod clock;
mod date;
mod directive;
mod entry;
mod policy;
mod storage;

pub use cache::{CacheStatus, HttpCache, HttpCacheBuilder, Pending};
pub use clock::{ManualClock, SystemWallClock, WallClock};
pub use directive::CacheControl;
pub use entry::{CacheEntry, CacheKey, Selector, is_hop_by_hop, vary_names};
pub use policy::CacheConfig;
pub use storage::{
    CacheError, CacheStorage, MemoryLimits, MemoryStats, MemoryStore, Variants, merge_variants,
};
