use std::sync::Arc;

use doorman_core::assembly::AuthCore;
use doorman_core::destructive::DestructiveActions;
use doorman_core::operator::OperatorManager;
use doorman_core::passkey::PasskeyManager;
use doorman_core::reauth::ReauthManager;
use doorman_core::recovery::RecoveryManager;
use doorman_core::session::SessionManager;
use doorman_core::signup::SignupManager;
use doorman_core::user::UserManager;

use crate::config::CookieConfig;

#[derive(Clone)]
pub struct AuthState {
    pub(crate) core: Arc<AuthCore>,
    pub(crate) cookie_config: Arc<CookieConfig>,
}

impl AuthState {
    pub fn cookie_config(&self) -> &CookieConfig {
        &self.cookie_config
    }

    pub fn sessions(&self) -> &SessionManager {
        &self.core.sessions
    }

    pub fn passkey(&self) -> &PasskeyManager {
        &self.core.passkey
    }

    pub fn signup(&self) -> &SignupManager {
        &self.core.signup
    }

    pub fn recovery(&self) -> &RecoveryManager {
        &self.core.recovery
    }

    pub fn user(&self) -> &UserManager {
        &self.core.user
    }

    pub fn reauth(&self) -> &ReauthManager {
        &self.core.reauth
    }

    pub fn operator(&self) -> &OperatorManager {
        &self.core.operator
    }

    pub fn destructive_actions(&self) -> &DestructiveActions {
        &self.core.destructive_actions
    }
}
