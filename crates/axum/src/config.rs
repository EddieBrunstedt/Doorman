//! Cookie configuration.
//!
//! Drives the session cookie written by login/register endpoints, cleared
//! by logout, and read by the session-loading layer.

use std::time::Duration;

use cookie::SameSite;

/// Defaults aimed at first-party browser clients served over HTTPS.
///
/// `secure = true` will cause browsers to drop the cookie when serving over
/// plain HTTP, including `http://localhost` for some browsers. Tests and
/// local-dev hosts that serve unencrypted should override this.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// Name of the session cookie set by login endpoints and read by the
    /// session layer. Defaults to `"doorman_session"`.
    pub session_cookie_name: String,
    /// `Domain` attribute. `None` means the cookie is scoped to the exact
    /// host that served the response (no subdomains).
    pub domain: Option<String>,
    /// `Path` attribute. Defaults to `/`.
    pub path: String,
    /// `Secure` attribute. Defaults to `true`.
    pub secure: bool,
    /// `SameSite` attribute. Defaults to [`SameSite::Lax`], which is the
    /// usual choice for first-party login cookies — sent on top-level
    /// navigations but not on cross-site sub-requests.
    pub same_site: SameSite,
    /// `Max-Age` for the session cookie. Should typically match the
    /// configured [`SessionConfig::absolute_lifetime`](doorman_core::session::SessionConfig)
    /// (or, when sliding renewal is on, the
    /// [`idle_timeout`](doorman_core::session::SessionConfig::idle_timeout)).
    /// Defaults to the
    /// [`SessionConfig`](doorman_core::session::SessionConfig) default lifetime
    /// (30 days) — the figure is named once in
    /// [`DEFAULT_SESSION_LIFETIME`](doorman_core::session::DEFAULT_SESSION_LIFETIME)
    /// and derived here so the cookie and session defaults cannot drift apart.
    pub session_max_age: Duration,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            session_cookie_name: "doorman_session".to_string(),
            domain: None,
            path: "/".to_string(),
            secure: true,
            same_site: SameSite::Lax,
            session_max_age: doorman_core::session::DEFAULT_SESSION_LIFETIME,
        }
    }
}
