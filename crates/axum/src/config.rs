use std::time::Duration;

use cookie::SameSite;

#[derive(Debug, Clone)]
pub struct CookieConfig {
    pub session_cookie_name: String,
    pub domain: Option<String>,
    pub path: String,
    pub secure: bool,
    pub same_site: SameSite,
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
