//! Cookie `Path` matching and default-path derivation, per RFC 6265 §5.1.4 and §5.4.

/// Derives the default cookie path from a request URI's path, per RFC 6265 §5.1.4.
///
/// A `Set-Cookie` response with no `Path` attribute (or an invalid one) scopes the
/// cookie to this directory rather than the exact request path, so that setting a
/// cookie from `/accounts/login` also covers `/accounts/logout`.
pub(crate) fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_owned();
    }
    match request_path.rfind('/') {
        // Exactly one `/` (e.g. "/" or "/login"): the whole path collapses to root.
        Some(0) | None => "/".to_owned(),
        Some(last_slash) => request_path[..last_slash].to_owned(),
    }
}

/// Whether `cookie_path` scopes a cookie into `request_path`, per RFC 6265 §5.1.4.
///
/// `cookie_path` must be a prefix of `request_path`, and that prefix must end exactly on
/// a path segment boundary: either `cookie_path` already ends in `/`, or the next
/// character in `request_path` is `/`. This stops `/foo` from matching `/foobar`.
pub(crate) fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_of_a_single_segment_is_the_root() {
        assert_eq!(default_path("/login"), "/");
        assert_eq!(default_path("/"), "/");
    }

    #[test]
    fn default_path_of_a_nested_request_drops_the_last_segment() {
        assert_eq!(default_path("/accounts/login"), "/accounts");
        assert_eq!(default_path("/a/b/c"), "/a/b");
    }

    #[test]
    fn default_path_falls_back_to_root_for_a_path_without_a_leading_slash() {
        assert_eq!(default_path(""), "/");
    }

    #[test]
    fn exact_path_matches() {
        assert!(path_matches("/accounts", "/accounts"));
    }

    #[test]
    fn a_directory_prefix_matches_its_children() {
        assert!(path_matches("/accounts/login", "/accounts"));
        assert!(path_matches("/accounts/", "/accounts"));
    }

    #[test]
    fn a_same_prefix_sibling_segment_does_not_match() {
        assert!(!path_matches("/accountsuffix", "/accounts"));
    }

    #[test]
    fn a_shorter_request_path_never_matches_a_longer_cookie_path() {
        assert!(!path_matches("/a", "/a/b"));
    }
}
