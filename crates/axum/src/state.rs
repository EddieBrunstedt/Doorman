//! Cloneable router state.
//!
//! Axum requires the state passed to `Router::with_state` to be cheaply
//! cloneable (it is handed to each handler on every request). All the
//! managers in [`doorman_core`] hold their dependencies behind `Arc`, so
//! cloning [`AuthState`] is the cost of cloning a handful of `Arc`s.

use std::sync::Arc;

use doorman_core::session::SessionManager;
use doorman_core::storage::UserStore;

use doorman_core::account::AccountManager;
use doorman_core::operator::OperatorManager;
use doorman_core::passkey::PasskeyManager;
use doorman_core::reauth::ReauthManager;
use doorman_core::recovery::RecoveryManager;
use doorman_core::signup::SignupManager;

use crate::config::CookieConfig;

/// Shared Axum router state holding configured auth managers and settings.
///
/// Session-revocation security notices originate inside [`SessionManager`]
/// (which holds the configured notifier), so the state carries no separate
/// notifier handle — the routes drive the manager and the notice follows.
#[derive(Clone)]
pub struct AuthState {
    pub(crate) session_manager: SessionManager,
    pub(crate) user_store: Arc<dyn UserStore>,
    pub(crate) cookie_config: Arc<CookieConfig>,
    pub(crate) passkey: PasskeyManager,
    pub(crate) signup: SignupManager,
    pub(crate) recovery: RecoveryManager,
    pub(crate) account: AccountManager,
    pub(crate) reauth: ReauthManager,
    pub(crate) operator: OperatorManager,
}

impl AuthState {
    /// The session cookie configuration backing the routes.
    pub fn cookie_config(&self) -> &CookieConfig {
        &self.cookie_config
    }

    /// The session manager the routes mint and resolve sessions through.
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// The user store backing the routes.
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

    /// Borrow the re-authentication manager backing the bundled
    /// `reauth/start` route and the destructive-action gate.
    pub fn reauth(&self) -> &ReauthManager {
        &self.reauth
    }

    /// Borrow the operator manager for host-driven flows that act on a user
    /// _other_ than the acting one (delete another user's account, etc.).
    ///
    /// Reached through this deliberate accessor — and never wired to a bundled
    /// route — precisely so a handler must hold it explicitly to invoke an
    /// operator flow. Doorman performs **no authorization** here: the host must
    /// put its own authorization check in front of every call.
    pub fn operator(&self) -> &OperatorManager {
        &self.operator
    }
}
