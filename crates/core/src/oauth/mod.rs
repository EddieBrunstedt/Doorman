//! High-level OAuth 2.0 / OIDC authorization flows.
//!
//! The [`OAuthManager`] composes a set of [`OAuthProvider`] implementations
//! with the user, identity, and state stores into the two-step
//! `start_authorization` / `finish_authorization` API a host serves to its
//! frontend. Account linking falls out for free: the same `user_id` can own
//! a password credential, a passkey, and one or more OAuth identities.

mod finish;
pub mod github;
pub mod google;
mod http;
pub mod provider;
mod start;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use url::Url;

use crate::audit::{AuditEvent, AuditEventKind, AuditSink, AuthMethod, CredentialKind};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::session::{IssuedSession, SessionContext, SessionManager};
use crate::storage::{
    OAuthIdentity, OAuthIdentityStore, OAuthStateId, OAuthStateStore, User, UserId, UserStore,
};

pub use provider::{
    AuthorizationRequest, ExchangeRequest, OAuthProvider, ProviderError, ProviderUser,
};

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// How long a `start_authorization` record stays valid waiting for the
    /// callback. The W3C-recommended upper bound for interactive consent
    /// is around 10 minutes; default keeps a small margin.
    pub state_lifetime: Duration,
    /// When `true`, an OAuth login whose provider-reported email is
    /// **verified** and matches an existing user's email is linked to
    /// that user. When `false`, the same situation returns
    /// [`Error::OAuthEmailTaken`] and forces the user to sign in through
    /// their existing method to link explicitly.
    ///
    /// Defaults to `false` because trust in third-party email
    /// verification varies; enabling it accepts that risk.
    pub allow_email_linking: bool,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            state_lifetime: Duration::from_secs(60 * 10),
            allow_email_linking: false,
        }
    }
}

/// Result of [`OAuthManager::start_authorization`]. The host returns the
/// `state` to its frontend (typically as a `Secure; HttpOnly; SameSite=Lax`
/// cookie) and redirects the browser to `authorize_url`.
#[derive(Debug, Clone)]
pub struct StartedAuthorization {
    pub state: OAuthStateId,
    pub authorize_url: Url,
}

/// What `finish_authorization` returns. The caller can inspect
/// `is_new_user` / `link_was_added` to drive a "welcome" or "account
/// linked" UI moment.
#[derive(Debug, Clone)]
pub struct OAuthOutcome {
    pub user: User,
    pub identity: OAuthIdentity,
    pub session: IssuedSession,
    /// `true` when the manager provisioned a brand-new user for this
    /// identity; `false` when it logged into an existing user (either
    /// because the identity was already linked, or because it was linked
    /// just now).
    pub is_new_user: bool,
    /// `true` when this call created the identity row; `false` when an
    /// identity for `(provider, subject)` was already on file.
    pub link_was_added: bool,
}

#[derive(Clone)]
pub struct OAuthManager {
    pub(super) providers: Arc<HashMap<String, Arc<dyn OAuthProvider>>>,
    pub(super) users: Arc<dyn UserStore>,
    pub(super) identities: Arc<dyn OAuthIdentityStore>,
    pub(super) states: Arc<dyn OAuthStateStore>,
    pub(super) sessions: SessionManager,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) audit: Arc<dyn AuditSink>,
    pub(super) config: OAuthConfig,
}

impl OAuthManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        providers: Vec<Arc<dyn OAuthProvider>>,
        users: Arc<dyn UserStore>,
        identities: Arc<dyn OAuthIdentityStore>,
        states: Arc<dyn OAuthStateStore>,
        sessions: SessionManager,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        config: OAuthConfig,
    ) -> Self {
        let mut map: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
        for p in providers {
            let name = p.name().to_string();
            assert!(
                map.insert(name.clone(), p).is_none(),
                "duplicate oauth provider name: {name}"
            );
        }
        Self {
            providers: Arc::new(map),
            users,
            identities,
            states,
            sessions,
            clock,
            audit,
            config,
        }
    }

    pub async fn list_identities(&self, user_id: UserId) -> Result<Vec<OAuthIdentity>> {
        Ok(self.identities.list_for_user(user_id).await?)
    }

    /// Detach an OAuth identity from a user. The `user_id` argument is
    /// enforced server-side so a session for user A cannot delete user
    /// B's identity by guessing a `(provider, subject)` pair.
    pub async fn unlink(
        &self,
        user_id: UserId,
        provider: &str,
        subject: &str,
        context: SessionContext,
    ) -> Result<()> {
        let Some(identity) = self
            .identities
            .find_by_provider_subject(provider, subject)
            .await?
        else {
            return Ok(());
        };
        if identity.user_id != user_id {
            return Err(Error::OAuthIdentityAlreadyLinked);
        }
        self.identities.unlink(provider, subject).await?;
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::CredentialRemoved {
                    user_id,
                    credential_kind: CredentialKind::OAuth,
                },
            })
            .await;
        Ok(())
    }

    pub(super) fn provider(&self, name: &str) -> Result<Arc<dyn OAuthProvider>> {
        self.providers
            .get(name)
            .cloned()
            .ok_or_else(|| Error::OAuthProviderNotConfigured(name.to_owned()))
    }

    pub(super) async fn emit_login(&self, user_id: UserId, context: &SessionContext) {
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::LoginSucceeded {
                    user_id,
                    method: AuthMethod::OAuth,
                },
            })
            .await;
    }
}
