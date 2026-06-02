//! Cloneable router state.
//!
//! Axum requires the state passed to `Router::with_state` to be cheaply
//! cloneable (it is handed to each handler on every request). All the
//! managers in [`bauth_core`] hold their dependencies behind `Arc`, so
//! cloning [`BauthState`] is the cost of cloning a handful of `Arc`s.

use std::sync::Arc;

use bauth_core::session::SessionManager;
use bauth_core::storage::UserStore;

use bauth_core::account::AccountManager;
use bauth_core::passkey::PasskeyManager;
use bauth_core::recovery::RecoveryManager;
use bauth_core::signup::SignupManager;

use crate::config::CookieConfig;

/// Shared Axum router state holding configured auth managers and settings.
///
/// Session-revocation security notices originate inside [`SessionManager`]
/// (which holds the configured notifier), so the state carries no separate
/// notifier handle — the routes drive the manager and the notice follows.
#[derive(Clone)]
pub struct BauthState {
    pub(crate) session_manager: SessionManager,
    pub(crate) user_store: Arc<dyn UserStore>,
    pub(crate) cookie_config: Arc<CookieConfig>,
    pub(crate) passkey: PasskeyManager,
    pub(crate) signup: SignupManager,
    pub(crate) recovery: RecoveryManager,
    pub(crate) account: AccountManager,
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

    /// Borrow the passkey manager the bundled routes drive, so host code
    /// can run the same registration / authentication / listing logic
    /// (e.g. a custom `/api/me` that lists credentials) against the
    /// managers the router already uses.
    pub fn passkey(&self) -> &PasskeyManager {
        &self.passkey
    }

    /// Borrow the signup manager the bundled signup routes drive.
    pub fn signup(&self) -> &SignupManager {
        &self.signup
    }

    /// Borrow the recovery manager the bundled recovery routes drive.
    pub fn recovery(&self) -> &RecoveryManager {
        &self.recovery
    }

    /// Borrow the account manager the bundled account routes drive (verified
    /// email change and account deletion).
    pub fn account(&self) -> &AccountManager {
        &self.account
    }
}
