//! High-level OAuth 2.0 / OIDC authorization flows.
//!
//! The [`OAuthManager`] composes a set of [`OAuthProvider`] implementations
//! with the user, identity, and state stores into the two-step
//! `start_authorization` / `finish_authorization` API a host serves to its
//! frontend. Account linking falls out for free: the same `user_id` can own
//! a password credential, a passkey, and one or more OAuth identities.

pub mod github;
pub mod google;
mod http;
pub mod provider;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use url::Url;

use crate::audit::{AuditEvent, AuditEventKind, AuditSink, AuthMethod, CredentialKind};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::session::{IssuedSession, SessionContext, SessionManager};
use crate::storage::{
    OAuthIdentity, OAuthIdentityStore, OAuthStateId, OAuthStateStore, PendingOAuthAuthorization,
    User, UserId, UserStore,
};

pub use provider::{
    AuthorizationRequest, ExchangeRequest, OAuthProvider, ProviderError, ProviderUser,
};

/// Random bytes for PKCE verifier and CSRF state. 32 bytes → 43-character
/// URL-safe base64 string, which sits inside the W3C-recommended 43..=128
/// PKCE verifier length window.
const RANDOM_BYTES: usize = 32;

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
    providers: Arc<HashMap<String, Arc<dyn OAuthProvider>>>,
    users: Arc<dyn UserStore>,
    identities: Arc<dyn OAuthIdentityStore>,
    states: Arc<dyn OAuthStateStore>,
    sessions: SessionManager,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    config: OAuthConfig,
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

    /// Begin an OAuth authorization. Generates PKCE + CSRF state, stores
    /// the per-flow record, and returns the URL to send the browser to.
    ///
    /// `link_user_id` is `Some` when an already-logged-in user wants to
    /// attach a federated identity to their existing account.
    pub async fn start_authorization(
        &self,
        provider_name: &str,
        redirect_uri: &str,
        link_user_id: Option<UserId>,
    ) -> Result<StartedAuthorization> {
        let provider = self.provider(provider_name)?;

        let state = OAuthStateId(random_base64url());
        let pkce_verifier = random_base64url();
        let pkce_challenge = pkce_s256(&pkce_verifier);

        let url = provider.authorization_url(AuthorizationRequest {
            state: &state.0,
            pkce_challenge: &pkce_challenge,
            redirect_uri,
        });

        let now = self.clock.now();
        let lifetime = chrono::Duration::from_std(self.config.state_lifetime)
            .expect("oauth state lifetime overflows chrono::Duration; configure a smaller value");
        self.states
            .put(PendingOAuthAuthorization {
                state_id: state.clone(),
                provider: provider_name.to_owned(),
                pkce_verifier,
                redirect_uri: redirect_uri.to_owned(),
                link_user_id,
                created_at: now,
                expires_at: now + lifetime,
            })
            .await?;

        Ok(StartedAuthorization {
            state,
            authorize_url: url,
        })
    }

    /// Complete an OAuth authorization. The host calls this with the
    /// state value it stored at `start_authorization` (after confirming
    /// the value echoed back in the callback URL matches) and the `code`
    /// the provider returned.
    pub async fn finish_authorization(
        &self,
        state: &OAuthStateId,
        code: &str,
        context: SessionContext,
    ) -> Result<OAuthOutcome> {
        let now = self.clock.now();
        let Some(pending) = self.states.take(state).await? else {
            return Err(Error::InvalidOAuthState);
        };
        if pending.expires_at <= now {
            return Err(Error::InvalidOAuthState);
        }
        let provider = self.provider(&pending.provider)?;

        let provider_user = provider
            .exchange(ExchangeRequest {
                code,
                pkce_verifier: &pending.pkce_verifier,
                redirect_uri: &pending.redirect_uri,
            })
            .await
            .map_err(|e| Error::OAuthProvider(e.to_string()))?;

        // Look up an existing link first; the simplest case is a returning
        // user who has already gone through this provider before.
        if let Some(existing) = self
            .identities
            .find_by_provider_subject(&pending.provider, &provider_user.subject)
            .await?
        {
            // If the caller was attempting to link to a specific user but
            // the identity is already attached elsewhere, reject rather
            // than silently re-attribute.
            if let Some(target) = pending.link_user_id
                && existing.user_id != target
            {
                return Err(Error::OAuthIdentityAlreadyLinked);
            }
            let user = self
                .users
                .find_user_by_id(existing.user_id)
                .await?
                .ok_or(Error::UserNotFound)?;
            let session = self.sessions.create(user.id, context.clone()).await?;
            self.emit_login(user.id, &context).await;
            return Ok(OAuthOutcome {
                user,
                identity: existing,
                session,
                is_new_user: false,
                link_was_added: false,
            });
        }

        let email = provider_user
            .email
            .as_deref()
            .map(normalize_email)
            .filter(|s| !s.is_empty());

        let (target_user, is_new_user) = if let Some(uid) = pending.link_user_id {
            let user = self
                .users
                .find_user_by_id(uid)
                .await?
                .ok_or(Error::UserNotFound)?;
            (user, false)
        } else if let Some(email_norm) = email.as_deref()
            && let Some(existing) = self.users.find_user_by_email(email_norm).await?
        {
            if !(self.config.allow_email_linking && provider_user.email_verified) {
                return Err(Error::OAuthEmailTaken);
            }
            (existing, false)
        } else {
            let new_user = User {
                id: UserId::new(),
                email: email.clone(),
                email_verified_at: provider_user.email_verified.then_some(now),
                created_at: now,
                updated_at: now,
            };
            self.users.create_user(new_user.clone()).await?;
            (new_user, true)
        };

        let identity = OAuthIdentity {
            provider: pending.provider.clone(),
            subject: provider_user.subject.clone(),
            user_id: target_user.id,
            email: email.clone(),
            created_at: now,
            updated_at: now,
        };
        self.identities.link(identity.clone()).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::CredentialAdded {
                    user_id: target_user.id,
                    credential_kind: CredentialKind::OAuth,
                },
            })
            .await;

        let session = self
            .sessions
            .create(target_user.id, context.clone())
            .await?;
        self.emit_login(target_user.id, &context).await;

        Ok(OAuthOutcome {
            user: target_user,
            identity,
            session,
            is_new_user,
            link_was_added: true,
        })
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

    fn provider(&self, name: &str) -> Result<Arc<dyn OAuthProvider>> {
        self.providers
            .get(name)
            .cloned()
            .ok_or_else(|| Error::OAuthProviderNotConfigured(name.to_owned()))
    }

    async fn emit_login(&self, user_id: UserId, context: &SessionContext) {
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

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn random_base64url() -> String {
    let mut bytes = [0u8; RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_base64url_sha256() {
        // RFC 7636 §4.2 worked example: verifier
        // `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` → challenge
        // `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`.
        let challenge = pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn random_state_unique() {
        let a = random_base64url();
        let b = random_base64url();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
    }
}
