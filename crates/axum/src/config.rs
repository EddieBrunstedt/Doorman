//! Cookie configuration.
//!
//! Drives both the session cookie (written by login/register/passkey/oauth
//! endpoints, cleared by logout, and read by the session-loading layer) and
//! the OAuth state cookie (written by `/start`, read and cleared by
//! `/callback`). The OAuth state cookie reuses the session cookie's
//! transport flags (domain, path, secure, samesite) but is given its own
//! name and a short, fixed max-age — its lifetime is bounded by the OAuth
//! handshake, not the session.

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
    /// session layer. Defaults to `"bauth_session"`.
    pub session_cookie_name: String,
    /// Name of the OAuth state cookie. Defaults to `"bauth_oauth_state"`.
    pub oauth_state_cookie_name: String,
    /// `Domain` attribute. `None` means the cookie is scoped to the exact
    /// host that served the response (no subdomains).
    pub domain: Option<String>,
    /// `Path` attribute. Defaults to `/`.
    pub path: String,
    /// `Secure` attribute. Defaults to `true`.
    pub secure: bool,
    /// `SameSite` attribute. Defaults to [`SameSite::Lax`], which is the
    /// usual choice for first-party login cookies — sent on top-level
    /// navigations (so OAuth callbacks work) but not on cross-site sub-
    /// requests.
    pub same_site: SameSite,
    /// `Max-Age` for the session cookie. Should typically match the
    /// configured [`SessionConfig::lifetime`](bauth_core::session::SessionConfig).
    /// Defaults to 30 days.
    pub session_max_age: Duration,
    /// `Max-Age` for the OAuth state cookie. Defaults to 10 minutes,
    /// matching the OAuth state lifetime in
    /// [`OAuthConfig`](bauth_core::oauth::OAuthConfig).
    pub oauth_state_max_age: Duration,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            session_cookie_name: "bauth_session".to_string(),
            oauth_state_cookie_name: "bauth_oauth_state".to_string(),
            domain: None,
            path: "/".to_string(),
            secure: true,
            same_site: SameSite::Lax,
            session_max_age: Duration::from_secs(60 * 60 * 24 * 30),
            oauth_state_max_age: Duration::from_secs(60 * 10),
        }
    }
}
