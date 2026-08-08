//! Alternative-service discovery, and an evidence spike for HTTP/3.
//!
//! Two things live here, and they are at very different stages.
//!
//! **`Alt-Svc` is implemented.** [`AltSvc`] parses the field (RFC 7838) and
//! [`AltSvcCache`] remembers what each origin advertised, with expiry. This is the
//! half of HTTP/3 discovery that is pure protocol work: it is how a browser learns
//! an origin speaks HTTP/3 in the first place, it is testable without a socket, and
//! it is useful on its own — knowing that an origin advertises `h3` is an observation
//! about the origin whether or not this crate can take the upgrade.
//!
//! **QUIC is a spike, not a transport.** Behind the non-default `quic-spike` feature
//! there is enough code to observe what the `quinn` stack puts on the wire, and a
//! single real HTTP/3 `GET` behind `network-tests`. Nothing in `chromulate-http` calls
//! any of it. The reasoning, the measurements, and the recommendation are in
//! `docs/architecture/04-http3-assessment.md`; the short version is that this stack
//! can make an HTTP/3 request but cannot make one that looks like Chrome, and that
//! shipping it would move the project's weakest fidelity claim from one layer to two.
//!
//! ```
//! use std::time::{Duration, SystemTime};
//!
//! use chromulate_core::Origin;
//! use chromulate_h3::AltSvcCache;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let origin = Origin::of(&"https://example.com/".parse()?)?;
//! let now = SystemTime::UNIX_EPOCH;
//!
//! let mut cache = AltSvcCache::new();
//! cache.record(&origin, r#"h3=":443"; ma=3600"#, now)?;
//!
//! let alt = cache.h3_alternative(&origin, now).expect("just recorded");
//! assert_eq!(alt.authority_for(&origin), "example.com:443");
//!
//! // And it stops applying when the origin said it would.
//! assert!(cache.h3_alternative(&origin, now + Duration::from_secs(3601)).is_none());
//! # Ok(())
//! # }
//! ```

#![doc(html_root_url = "https://docs.rs/chromulate-h3/0.3.0")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod alt_svc;
pub mod error;

#[cfg(feature = "quic-spike")]
pub mod spike;

pub use alt_svc::{AltSvc, AltSvcCache, Alternative, CachedAlternative, DEFAULT_MAX_AGE, H3_ALPN};
pub use error::AltSvcError;
