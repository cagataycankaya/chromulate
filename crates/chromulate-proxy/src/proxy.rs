//! A configured proxy, and deriving proxy configuration from the environment.

use std::fmt;
use std::time::Duration;

use chromulate_core::{Error, HostPort, Phase, Result};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::no_proxy::NoProxy;
use crate::url::{ProxyScheme, ProxyUrl};
use crate::{http_connect, socks5};

/// A proxy to route connections through, plus the bypass rules that exempt some hosts
/// from it.
///
/// `Debug` delegates to [`ProxyUrl`]'s redacted `Debug` impl, so a `Proxy` is safe to
/// log directly.
#[derive(Clone, PartialEq, Eq)]
pub struct Proxy {
    url: ProxyUrl,
    no_proxy: NoProxy,
}

impl Proxy {
    /// Wraps a proxy URL with an empty bypass list.
    pub const fn new(url: ProxyUrl) -> Self {
        Self {
            url,
            no_proxy: NoProxy::none(),
        }
    }

    /// Attaches a bypass rule set, replacing any existing one.
    #[must_use]
    pub fn with_no_proxy(mut self, no_proxy: NoProxy) -> Self {
        self.no_proxy = no_proxy;
        self
    }

    /// The proxy's URL.
    pub const fn url(&self) -> &ProxyUrl {
        &self.url
    }

    /// The bypass rule set attached to this proxy.
    pub const fn no_proxy(&self) -> &NoProxy {
        &self.no_proxy
    }

    /// Whether `host` should bypass this proxy entirely, per [`NoProxy::matches`].
    pub fn bypasses(&self, host: &str) -> bool {
        self.no_proxy.matches(host)
    }

    /// Reads proxy configuration from the standard `*_PROXY` environment variables.
    ///
    /// See [`ProxyEnvironment::from_env`] for the variables read and their precedence;
    /// this is a convenience alias reachable without naming `ProxyEnvironment`
    /// directly. A single target request needs a scheme-specific proxy (an HTTP
    /// target and an HTTPS target may go through different proxies), which is why this
    /// returns the richer [`ProxyEnvironment`] rather than one [`Proxy`]; call
    /// [`ProxyEnvironment::for_scheme`] to select the one that applies.
    pub fn from_env() -> ProxyEnvironment {
        ProxyEnvironment::from_env()
    }

    /// Establishes a connection to `target` tunnelled through this proxy.
    ///
    /// Dispatches to HTTP `CONNECT` or SOCKS5 based on [`ProxyUrl::scheme`]. The
    /// returned stream is connected all the way to `target`; for a `https://` target
    /// the caller still needs to perform the TLS handshake over it, since this crate
    /// deliberately does not depend on the TLS crate.
    ///
    /// `connect_timeout` bounds the entire operation: dialing the proxy and completing
    /// the tunnelling handshake.
    pub async fn connect(&self, target: &HostPort, connect_timeout: Duration) -> Result<TcpStream> {
        let attempt = async {
            match self.url.scheme() {
                ProxyScheme::Http | ProxyScheme::Https => {
                    http_connect::connect(&self.url, target).await
                }
                ProxyScheme::Socks5 | ProxyScheme::Socks5h => {
                    socks5::connect(&self.url, target).await
                }
            }
        };
        timeout(connect_timeout, attempt)
            .await
            .unwrap_or(Err(Error::Timeout(Phase::Connect)))
    }
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("url", &self.url)
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

/// Proxy configuration assembled from the standard `HTTP_PROXY` / `HTTPS_PROXY` /
/// `ALL_PROXY` / `NO_PROXY` environment variables (and their lowercase forms).
///
/// A single environment can specify different proxies for HTTP and HTTPS targets, so
/// this holds both rather than collapsing them into one [`Proxy`]. Call
/// [`ProxyEnvironment::for_scheme`] to get the [`Proxy`] that applies to a given
/// target scheme.
#[derive(Debug, Clone, Default)]
pub struct ProxyEnvironment {
    http: Option<ProxyUrl>,
    https: Option<ProxyUrl>,
    no_proxy: NoProxy,
}

impl ProxyEnvironment {
    /// Reads `http_proxy`/`HTTP_PROXY`, `https_proxy`/`HTTPS_PROXY`,
    /// `all_proxy`/`ALL_PROXY`, and `no_proxy`/`NO_PROXY`.
    ///
    /// For each variable, the lowercase name takes precedence over the uppercase one
    /// when both are set, following the de-facto convention used by curl and most HTTP
    /// clients. `ALL_PROXY` is used as the fallback for either scheme when a
    /// scheme-specific variable is absent. A variable that fails to parse as a valid
    /// proxy URL, or a `NO_PROXY` value with a malformed CIDR entry, is ignored rather
    /// than causing this function to fail: environment misconfiguration should not be
    /// able to crash a process at construction time. Each such value is reported at
    /// `WARN` through `tracing`, naming the variable but never its contents, because the
    /// resulting fallback — a direct connection, or a bypass list that no longer
    /// bypasses anything — is otherwise invisible.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The parsing logic behind [`ProxyEnvironment::from_env`], parameterized over an
    /// environment lookup function.
    ///
    /// Split out so tests can supply an in-memory lookup instead of mutating the real
    /// process environment: as of this toolchain, `std::env::set_var` and
    /// `std::env::remove_var` are `unsafe fn` (confirmed with `rustc 1.97.1`, error
    /// `E0133`), and this workspace forbids `unsafe_code` outright, so tests cannot use
    /// them. A fake lookup closure also sidesteps the cross-test races that mutating a
    /// process-global would otherwise require a mutex to avoid.
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        // The variable name travels with the value so a parse failure can name the
        // variable the operator actually has to fix.
        let read_pair =
            |lower: &'static str, upper: &'static str| -> Option<(&'static str, String)> {
                lookup(lower)
                    .filter(|v| !v.is_empty())
                    .map(|value| (lower, value))
                    .or_else(|| {
                        lookup(upper)
                            .filter(|v| !v.is_empty())
                            .map(|value| (upper, value))
                    })
            };

        let all = read_pair("all_proxy", "ALL_PROXY");
        let http_raw = read_pair("http_proxy", "HTTP_PROXY").or_else(|| all.clone());
        let https_raw = read_pair("https_proxy", "HTTPS_PROXY").or(all);
        let no_proxy_raw = read_pair("no_proxy", "NO_PROXY");

        Self {
            http: http_raw.and_then(|(variable, raw)| parse_env_proxy(variable, &raw)),
            https: https_raw.and_then(|(variable, raw)| parse_env_proxy(variable, &raw)),
            no_proxy: no_proxy_raw
                .and_then(|(variable, raw)| parse_env_no_proxy(variable, &raw))
                .unwrap_or_default(),
        }
    }

    /// The proxy that applies to a target with the given URL scheme (`"http"` or
    /// `"https"`), falling back to the other scheme's proxy if only that one is set.
    /// Returns `None` if neither is configured.
    pub fn for_scheme(&self, scheme: &str) -> Option<Proxy> {
        let url = if scheme.eq_ignore_ascii_case("https") {
            self.https.as_ref().or(self.http.as_ref())
        } else {
            self.http.as_ref().or(self.https.as_ref())
        }?;
        Some(Proxy::new(url.clone()).with_no_proxy(self.no_proxy.clone()))
    }

    /// The bypass rule set parsed from `NO_PROXY` / `no_proxy`.
    pub const fn no_proxy(&self) -> &NoProxy {
        &self.no_proxy
    }
}

/// Parses a proxy URL read from the environment, warning and ignoring it if malformed.
///
/// Failing open keeps environment misconfiguration from crashing a process at
/// construction time, which is the right default for a constructor. But for someone
/// using a proxy as a network boundary, a fallback to a direct connection is the one
/// outcome they most need to hear about, so it is no longer silent.
///
/// The warning names the variable and the parse failure, never the value: a proxy URL
/// routinely carries credentials.
fn parse_env_proxy(variable: &str, raw: &str) -> Option<ProxyUrl> {
    match ProxyUrl::parse(raw) {
        Ok(url) => Some(url),
        Err(err) => {
            tracing::warn!(
                variable,
                error = %err,
                "ignoring a malformed proxy URL from the environment; requests it would have \
                 covered will connect directly"
            );
            None
        }
    }
}

/// Parses a `no_proxy` value read from the environment, warning and ignoring it if
/// malformed.
///
/// One bad entry discards the whole list, which sends hosts that should have bypassed
/// the proxy through it instead — quieter than an unexpected direct connection, and just
/// as invisible without this.
fn parse_env_no_proxy(variable: &str, raw: &str) -> Option<NoProxy> {
    match NoProxy::parse(raw) {
        Ok(no_proxy) => Some(no_proxy),
        Err(err) => {
            tracing::warn!(
                variable,
                error = %err,
                "ignoring a malformed bypass list from the environment; no host will bypass \
                 the proxy"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Builds a lookup closure over an in-memory map, standing in for
    /// `std::env::var` without touching the real process environment.
    fn lookup(vars: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<&'static str, &'static str> = vars.iter().copied().collect();
        move |key| map.get(key).map(|v| v.to_string())
    }

    #[test]
    fn reads_scheme_specific_proxies_from_uppercase_variables() {
        let env = env_from(&[
            ("HTTP_PROXY", "http://http-proxy.example.com:8080"),
            ("HTTPS_PROXY", "http://https-proxy.example.com:8443"),
        ]);
        assert_eq!(
            env.for_scheme("http").expect("http proxy").url().host(),
            "http-proxy.example.com"
        );
        assert_eq!(
            env.for_scheme("https").expect("https proxy").url().host(),
            "https-proxy.example.com"
        );
    }

    #[test]
    fn lowercase_variable_takes_precedence_over_uppercase() {
        let env = env_from(&[
            ("HTTP_PROXY", "http://uppercase.example.com:8080"),
            ("http_proxy", "http://lowercase.example.com:8080"),
        ]);
        assert_eq!(
            env.for_scheme("http").expect("http proxy").url().host(),
            "lowercase.example.com"
        );
    }

    #[test]
    fn all_proxy_is_the_fallback_for_both_schemes() {
        let env = env_from(&[("ALL_PROXY", "socks5://proxy.example.com:1080")]);
        assert_eq!(
            env.for_scheme("http").expect("http proxy").url().host(),
            "proxy.example.com"
        );
        assert_eq!(
            env.for_scheme("https").expect("https proxy").url().host(),
            "proxy.example.com"
        );
    }

    #[test]
    fn scheme_specific_variable_overrides_all_proxy() {
        let env = env_from(&[
            ("ALL_PROXY", "socks5://fallback.example.com:1080"),
            ("HTTPS_PROXY", "http://https-only.example.com:8443"),
        ]);
        assert_eq!(
            env.for_scheme("https").expect("https proxy").url().host(),
            "https-only.example.com"
        );
        assert_eq!(
            env.for_scheme("http").expect("http proxy").url().host(),
            "fallback.example.com"
        );
    }

    #[test]
    fn no_proxy_variable_is_attached_to_selected_proxies() {
        let env = env_from(&[
            ("ALL_PROXY", "http://proxy.example.com:8080"),
            ("NO_PROXY", "internal.example.com"),
        ]);
        let proxy = env.for_scheme("http").expect("http proxy");
        assert!(proxy.bypasses("internal.example.com"));
        assert!(!proxy.bypasses("external.example.com"));
    }

    #[test]
    fn empty_variable_value_is_treated_as_unset() {
        let env = env_from(&[
            ("http_proxy", ""),
            ("HTTP_PROXY", "http://fallback.example.com:8080"),
        ]);
        assert_eq!(
            env.for_scheme("http").expect("http proxy").url().host(),
            "fallback.example.com"
        );
    }

    #[test]
    fn missing_variables_yield_no_proxy() {
        let env = env_from(&[]);
        assert!(env.for_scheme("http").is_none());
        assert!(env.for_scheme("https").is_none());
    }

    #[test]
    fn malformed_proxy_url_is_ignored_rather_than_panicking() {
        let env = env_from(&[("ALL_PROXY", "not a url")]);
        assert!(env.for_scheme("http").is_none());
    }

    /// A `tracing` writer that keeps everything written to it, so a test can assert on
    /// what was logged.
    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("log mutex")).into_owned()
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log mutex").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Serialises every test that touches a `tracing` callsite in this module.
    ///
    /// `tracing` caches per-callsite interest **globally**. Rust's test harness
    /// runs tests in one process in parallel, so a test that hits a warning's
    /// callsite while no subscriber is installed can have that callsite cached
    /// as uninteresting — after which the capturing test sees nothing, however
    /// correct the code is. It fails on whichever platform happens to schedule
    /// the two tests in that order, which is how this was found: green on macOS
    /// and Windows, red on Linux, on the same commit.
    ///
    /// Holding this lock across both the log-capturing tests and the ones that
    /// merely parse an environment removes the race by removing the
    /// interleaving.
    static TRACING_CALLSITES: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Takes the callsite lock, recovering it if a previous test panicked while
    /// holding it — a poisoned lock here would turn one failure into every
    /// later test failing for an unrelated reason.
    fn callsite_guard() -> std::sync::MutexGuard<'static, ()> {
        TRACING_CALLSITES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Runs `body` with a subscriber that captures everything it logs.
    fn capture_logs(body: impl FnOnce()) -> String {
        let _guard = callsite_guard();
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();

        // `with_default` installs a *thread-local* dispatcher and does not
        // rebuild the global callsite interest cache — only
        // `set_global_default` does. So a callsite first evaluated while no
        // subscriber was installed stays cached as uninteresting, and this
        // capture would see nothing however correct the code is. Rebuilding
        // makes the cache reflect the subscriber that is about to run, which
        // the lock above then keeps true for the duration.
        tracing::callsite::rebuild_interest_cache();

        tracing::subscriber::with_default(subscriber, body);
        logs.contents()
    }

    /// Builds an environment under the callsite lock, so a test that does not
    /// capture logs cannot poison a callsite for one that does.
    fn env_from(pairs: &[(&'static str, &'static str)]) -> ProxyEnvironment {
        let _guard = callsite_guard();
        ProxyEnvironment::from_lookup(lookup(pairs))
    }

    #[test]
    fn a_malformed_proxy_url_in_the_environment_is_reported_before_connecting_directly() {
        // Failing open is the right default for a constructor, but for someone using a
        // proxy as a network boundary a silent direct connection is the one outcome they
        // most need to hear about.
        let logs = capture_logs(|| {
            let env =
                ProxyEnvironment::from_lookup(lookup(&[("HTTPS_PROXY", "http://alice:hunter2@")]));
            assert!(env.for_scheme("https").is_none());
        });

        assert!(
            logs.contains("HTTPS_PROXY"),
            "the warning should name the variable that failed to parse: {logs}"
        );
        assert!(
            !logs.contains("hunter2"),
            "the warning must not leak the credentials it failed to parse: {logs}"
        );
    }

    #[test]
    fn a_malformed_no_proxy_value_is_reported_before_the_bypass_list_is_dropped() {
        let logs = capture_logs(|| {
            let env = ProxyEnvironment::from_lookup(lookup(&[
                ("ALL_PROXY", "http://proxy.example.com:8080"),
                ("NO_PROXY", "internal.example.com,10.0.0.0/99"),
            ]));
            // The whole bypass list is discarded, so a host that should have gone
            // direct is now routed through the proxy instead.
            let proxy = env.for_scheme("http").expect("http proxy");
            assert!(!proxy.bypasses("internal.example.com"));
        });

        assert!(
            logs.contains("NO_PROXY"),
            "the warning should name the variable that failed to parse: {logs}"
        );
    }

    /// Real-environment end-to-end check for `ProxyEnvironment::from_env`.
    ///
    /// Spawns this same test binary as a child process with a controlled environment
    /// (via `Command::env`, which is safe — it configures the *child's* environment at
    /// spawn time and never touches this process's own). Each invocation gets an
    /// isolated environment from the OS, so unlike a shared-process mutation approach
    /// this cannot race with other tests and needs no lock.
    #[test]
    fn from_env_reads_the_real_process_environment() {
        const SENTINEL: &str = "CHROMULATE_PROXY_FROM_ENV_CHILD";

        if std::env::var(SENTINEL).is_ok() {
            let env = ProxyEnvironment::from_env();
            let host = env
                .for_scheme("http")
                .map(|p| p.url().host().to_string())
                .unwrap_or_default();
            println!("CHILD_HTTP_HOST={host}");
            return;
        }

        let exe = std::env::current_exe().expect("test binary has a path");
        let output = std::process::Command::new(exe)
            .arg("from_env_reads_the_real_process_environment")
            .arg("--nocapture")
            .env_clear()
            .env(SENTINEL, "1")
            .env("HTTP_PROXY", "http://from-real-env.example.invalid:8080")
            .output()
            .expect("spawn child test process");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("CHILD_HTTP_HOST=from-real-env.example.invalid"),
            "child stdout was: {stdout}"
        );
    }
}
