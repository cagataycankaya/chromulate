//! The `SameSite` cookie attribute.

use serde::{Deserialize, Serialize};

/// The `SameSite` attribute, restricting when a cookie rides along with a request whose
/// initiator is on a different site than the cookie's own domain.
///
/// Eligibility also depends on request context beyond the target URL (see
/// [`crate::CookieContext`]); this type only names the three attribute values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SameSite {
    /// Sent only on same-site requests, including same-site top-level navigations.
    /// Withheld from every cross-site request, including a top-level navigation such as
    /// following a link from another site.
    Strict,
    /// Sent on same-site requests, and on cross-site top-level navigations, but withheld
    /// from cross-site subresource requests (images, scripts, iframes, XHR/fetch). The
    /// default when the attribute is absent, matching the "`SameSite=Lax` by default"
    /// behaviour every major browser shipped from 2020 onward.
    Lax,
    /// Sent on every request, including cross-site subresource requests. Requires the
    /// `Secure` attribute; a `SameSite=None` cookie without `Secure` is rejected outright.
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_site_values_round_trip_through_json() {
        let json = serde_json::to_string(&SameSite::Lax).expect("should serialize");
        let back: SameSite = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(back, SameSite::Lax);
    }
}
