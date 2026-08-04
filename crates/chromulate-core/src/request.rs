//! Per-request metadata that travels alongside the `http::Request`.
//!
//! Browsers derive a surprising number of headers from information the caller never
//! states explicitly: whether the request is a navigation, what kind of resource is
//! being fetched, and which document initiated it. Chromulate models that context as an
//! explicit value instead of guessing, then hands it to the header engine.

use std::time::Duration;

use url::Url;

use crate::body::Body;
use crate::uri::Origin;

/// A request with a Chromulate body.
pub type Request = http::Request<Body>;

/// A response with a Chromulate body.
pub type Response = http::Response<Body>;

/// The `Sec-Fetch-Mode` of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FetchMode {
    /// A top level document load.
    Navigate,
    /// A subresource fetch subject to CORS.
    #[default]
    Cors,
    /// A fetch that does not use CORS, such as an image or a stylesheet.
    NoCors,
    /// A same-origin only fetch.
    SameOrigin,
    /// A WebSocket handshake.
    Websocket,
}

impl FetchMode {
    /// The wire value for the `Sec-Fetch-Mode` header.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Navigate => "navigate",
            Self::Cors => "cors",
            Self::NoCors => "no-cors",
            Self::SameOrigin => "same-origin",
            Self::Websocket => "websocket",
        }
    }
}

/// The `Sec-Fetch-Dest` of a request: what the response will be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FetchDest {
    /// A top level document.
    Document,
    /// A nested document, such as an iframe.
    Iframe,
    /// A script.
    Script,
    /// A stylesheet.
    Style,
    /// An image.
    Image,
    /// A font.
    Font,
    /// A programmatic fetch with no specific destination.
    #[default]
    Empty,
}

impl FetchDest {
    /// The wire value for the `Sec-Fetch-Dest` header.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Iframe => "iframe",
            Self::Script => "script",
            Self::Style => "style",
            Self::Image => "image",
            Self::Font => "font",
            Self::Empty => "empty",
        }
    }
}

/// How the client should treat 3xx responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedirectPolicy {
    /// Follow up to `limit` redirects, then fail.
    Follow {
        /// The maximum number of hops.
        limit: usize,
    },
    /// Return the 3xx response to the caller untouched.
    None,
}

impl RedirectPolicy {
    /// The browser default of twenty hops.
    ///
    /// Twenty matches the limit browsers and the Fetch specification converged on; it is
    /// high enough for real redirect chains and low enough to stop a loop quickly.
    pub const DEFAULT_LIMIT: usize = 20;
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::Follow {
            limit: Self::DEFAULT_LIMIT,
        }
    }
}

/// Per-request settings and browser fetch context.
///
/// Attach one to a request through `http::Extensions`; the engine reads it back out
/// when building headers and when deciding how to handle the response.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RequestOptions {
    /// Deadline for the whole request, including redirects.
    pub timeout: Option<Duration>,
    /// Deadline for producing the response head.
    ///
    /// `None` means "whatever the engine is configured with", not "no bound":
    /// the engine's own default is thirty seconds, so opting one request out of
    /// it is not something this field can express. Build the client or engine
    /// without a head timeout instead.
    pub head_timeout: Option<Duration>,
    /// What to do with 3xx responses.
    pub redirect: RedirectPolicy,
    /// The `Sec-Fetch-Mode` to advertise.
    pub mode: FetchMode,
    /// The `Sec-Fetch-Dest` to advertise.
    pub dest: FetchDest,
    /// The document that initiated this request, if any.
    pub initiator: Option<Origin>,
    /// The document URL used to derive the `Referer` header.
    pub referrer: Option<Url>,
    /// Whether the caller has already set headers that the engine must not overwrite.
    pub preserve_caller_headers: bool,
}

impl RequestOptions {
    /// Options describing a top level navigation, the shape a browser address bar
    /// produces.
    pub fn navigation() -> Self {
        Self {
            mode: FetchMode::Navigate,
            dest: FetchDest::Document,
            ..Self::default()
        }
    }

    /// Options describing a programmatic `fetch()` style subresource request.
    pub fn api() -> Self {
        Self {
            mode: FetchMode::Cors,
            dest: FetchDest::Empty,
            ..Self::default()
        }
    }

    /// The cookie context these options describe.
    ///
    /// With an initiator, a request is a top-level navigation exactly when its mode is
    /// [`FetchMode::Navigate`], and the initiator carries through for the store to
    /// compare against the target.
    ///
    /// Without one there is nothing to compare the target *to*, so the mode says nothing
    /// about the site relationship and [`CookieContext::conservative_default`] applies
    /// instead. Reading a bare [`FetchMode::Cors`] as "cross-site subresource" would
    /// withhold `Lax` — every ordinary session cookie — from every caller that simply
    /// never named an initiator, which is most of them.
    pub fn cookie_context(&self) -> CookieContext {
        match &self.initiator {
            // Do not collapse this arm into the one below by mapping the mode
            // unconditionally. The mode is only meaningful relative to an initiator, and
            // the default `RequestOptions` pairs `FetchMode::Cors` with no initiator — so
            // an unconditional mapping reads "nobody said who is asking" as "cross-site
            // subresource fetch" and drops every `Lax` cookie the client holds. That is a
            // wider breakage than any `SameSite=Strict` bug: it logs out every session on
            // every site. It has happened once already. The guards are
            // `options_with_no_initiator_fall_back_to_the_conservative_context` below and
            // `an_unattributed_request_still_carries_its_lax_cookie` in
            // `chromulate-http`'s `engine_behaviour` suite.
            None => CookieContext::conservative_default(),
            Some(initiator) => CookieContext {
                initiator: Some(initiator.clone()),
                is_top_level_navigation: self.mode == FetchMode::Navigate,
            },
        }
    }
}

/// The site relationship an outgoing request has with the document that asked for it.
///
/// A target [`Url`] alone is enough for a cookie store to apply domain, path, and
/// `Secure` scoping, but not `SameSite`: `Strict` eligibility turns on whether the
/// request is same-site with its initiator, and `Lax` additionally on whether it is a
/// top-level navigation. [`CookieStore::cookies_for`](crate::CookieStore::cookies_for)
/// takes one of these so the store has both facts to decide with.
///
/// This type deliberately carries facts rather than a verdict. Answering "are these two
/// hosts the same site?" needs the public suffix list, which lives in the cookie crate;
/// core states who asked and what kind of fetch it is, and leaves the comparison to the
/// store. That is also why there is no `Default`: neither field has a value that is safe
/// to assume, so a caller holding no site information says so explicitly with
/// [`CookieContext::conservative_default`].
///
/// [`RequestOptions::cookie_context`] builds one from the fetch metadata a request is
/// already carrying.
#[derive(Debug, Clone)]
pub struct CookieContext {
    /// The origin of the page or script that initiated this request, when known.
    ///
    /// `None` means the initiator is unknown or there isn't one (a direct,
    /// address-bar-style navigation has no initiator either). Either way, this is never
    /// treated as proof of a *cross*-site request: see
    /// [`CookieContext::conservative_default`].
    pub initiator: Option<Origin>,
    /// Whether this request is a top-level navigation (address bar entry, link click,
    /// form submission) rather than a subresource fetch (script, image, iframe, XHR).
    pub is_top_level_navigation: bool,
}

impl CookieContext {
    /// The context to pass when the caller has no site information at all.
    ///
    /// This treats the request the way a browser treats a cross-site top-level
    /// navigation with no `Referer` - a bookmark, a typed URL, a link followed from
    /// another site: `SameSite=Lax` (the attribute's default, and so the overwhelming
    /// majority of real-world cookies) is sent, but `SameSite=Strict` is still withheld,
    /// since nothing here proves the request is same-site.
    ///
    /// That split, rather than sending everything or withholding everything, was
    /// deliberate. Assuming same-site outright would risk attaching a `Strict` cookie -
    /// one a site owner deliberately opted into the strictest protection for - to a
    /// request that turns out to be cross-site, which is exactly what `SameSite=Strict`
    /// exists to prevent. But withholding `Lax` too, the way the attribute's own default
    /// suggests browsers expect it to behave almost everywhere, would make this fallback
    /// silently drop the majority of ordinary session cookies for callers who never
    /// bothered to track navigation context - a functionality bug serious enough to
    /// undermine the point of having a jar. Callers that do track real navigation
    /// context should build the context from it instead, through
    /// [`RequestOptions::cookie_context`] or by naming both fields.
    pub fn conservative_default() -> Self {
        Self {
            initiator: None,
            is_top_level_navigation: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_options_describe_a_document_load() {
        let options = RequestOptions::navigation();
        assert_eq!(options.mode.as_str(), "navigate");
        assert_eq!(options.dest.as_str(), "document");
    }

    #[test]
    fn api_options_describe_a_cors_fetch() {
        let options = RequestOptions::api();
        assert_eq!(options.mode.as_str(), "cors");
        assert_eq!(options.dest.as_str(), "empty");
    }

    #[test]
    fn the_default_redirect_policy_follows_a_bounded_chain() {
        assert_eq!(
            RedirectPolicy::default(),
            RedirectPolicy::Follow { limit: 20 }
        );
    }

    #[test]
    fn options_travel_in_request_extensions() {
        let mut request = http::Request::new(Body::empty());
        request
            .extensions_mut()
            .insert(RequestOptions::navigation());

        let stored = request
            .extensions()
            .get::<RequestOptions>()
            .expect("options should round-trip through extensions");
        assert_eq!(stored.mode, FetchMode::Navigate);
    }

    #[test]
    fn the_conservative_cookie_context_has_no_initiator_and_is_a_navigation() {
        let context = CookieContext::conservative_default();
        assert!(context.initiator.is_none());
        assert!(context.is_top_level_navigation);
    }

    /// Options with an initiator, which is what makes the fetch mode meaningful.
    fn initiated(options: RequestOptions) -> RequestOptions {
        let url = Url::parse("https://app.example/dashboard").unwrap();
        RequestOptions {
            initiator: Some(Origin::of(&url).unwrap()),
            ..options
        }
    }

    #[test]
    fn an_initiated_request_is_a_top_level_navigation_only_when_it_navigates() {
        assert!(
            initiated(RequestOptions::navigation())
                .cookie_context()
                .is_top_level_navigation
        );
        assert!(
            !initiated(RequestOptions::api())
                .cookie_context()
                .is_top_level_navigation
        );
    }

    #[test]
    fn the_cookie_context_carries_the_initiator_the_options_were_given() {
        let options = initiated(RequestOptions::api());
        let initiator = options.initiator.clone();

        assert_eq!(options.cookie_context().initiator, initiator);
        assert!(initiator.is_some(), "the fixture must name an initiator");
    }

    #[test]
    fn options_with_no_initiator_fall_back_to_the_conservative_context() {
        // Guards the `None` arm of `cookie_context`. A subresource fetch nobody
        // attributed says nothing about the site relationship, so it must not be read as
        // a cross-site one: that withholds `Lax`, which is every ordinary session cookie.
        // `is_top_level_navigation` is the assertion that matters here - `false` would be
        // the regression, and it would be silent everywhere but a logged-out user.
        let context = RequestOptions::api().cookie_context();
        assert!(context.initiator.is_none());
        assert!(context.is_top_level_navigation);
    }
}
