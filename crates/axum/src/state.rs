//! Cloneable router state.
//!
//! Axum requires the state passed to `Router::with_state` to be cheaply
//! cloneable (it is handed to each handler on every request). All the
//! managers in [`bauth_core`] hold their dependencies behind `Arc`, so
//! cloning [`BauthState`] is the cost of cloning a handful of `Arc`s.

use std::sync::Arc;

use bauth_core::session::SessionManager;
use bauth_core::storage::UserStore;

use crate::config::CookieConfig;

#[cfg(feature = "passkey")]
use bauth_core::passkey::PasskeyManager;
#[cfg(feature = "passkey")]
use bauth_core::signup::SignupManager;

/// Shared Axum router state holding configured auth managers and settings.
#[derive(Clone)]
pub struct BauthState {
    pub(crate) session_manager: SessionManager,
    pub(crate) user_store: Arc<dyn UserStore>,
    pub(crate) cookie_config: Arc<CookieConfig>,
    #[cfg(feature = "passkey")]
    pub(crate) passkey: Option<PasskeyManager>,
    #[cfg(feature = "passkey")]
    pub(crate) signup: Option<SignupManager>,
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
