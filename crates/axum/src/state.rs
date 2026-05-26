//! Cloneable router state.
//!
//! Axum requires the state passed to `Router::with_state` to be cheaply
//! cloneable (it is handed to each handler on every request). All the
//! managers in [`bauth_core`] hold their dependencies behind `Arc`, so
//! cloning [`BauthState`] is the cost of cloning a handful of `Arc`s.

use std::sync::Arc;

use bauth_core::session::SessionManager;
use bauth_core::storage::UserStore;
#[cfg(feature = "oauth")]
use url::Url;

use crate::config::CookieConfig;

#[cfg(feature = "magic_link")]
use bauth_core::magic_link::MagicLinkManager;
#[cfg(feature = "oauth")]
use bauth_core::oauth::OAuthManager;
#[cfg(feature = "passkey")]
use bauth_core::passkey::PasskeyManager;
#[cfg(feature = "password")]
use bauth_core::password_auth::PasswordAuthManager;

#[derive(Clone)]
pub struct BauthState {
    pub(crate) session_manager: SessionManager,
    pub(crate) user_store: Arc<dyn UserStore>,
    pub(crate) cookie_config: Arc<CookieConfig>,
    /// Absolute origin (scheme + host [+ port] [+ path prefix]) that
    /// external clients see when calling these routes. Required when the
    /// `oauth` feature is in use — provider redirect URIs must be
    /// absolute — and unused otherwise.
    #[cfg(feature = "oauth")]
    pub(crate) external_origin: Option<Url>,

    #[cfg(feature = "password")]
    pub(crate) password: Option<PasswordAuthManager>,
    #[cfg(feature = "passkey")]
    pub(crate) passkey: Option<PasskeyManager>,
    #[cfg(feature = "oauth")]
    pub(crate) oauth: Option<OAuthManager>,
    #[cfg(feature = "magic_link")]
    pub(crate) magic_link: Option<MagicLinkManager>,
}

impl BauthState {
    pub fn cookie_config(&self) -> &CookieConfig {
        &self.cookie_config
    }

    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    pub fn user_store(&self) -> &Arc<dyn UserStore> {
        &self.user_store
    }
}
