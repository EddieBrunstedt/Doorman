//! Complete an OAuth authorization: consume the pending state, exchange
//! the authorization code, link or provision the user, and issue a session.

use crate::audit::{AuditEvent, AuditEventKind, CredentialKind};
use crate::error::{Error, Result};
use crate::session::SessionContext;
use crate::storage::{OAuthIdentity, OAuthStateId, User, UserId};

use super::{OAuthManager, OAuthOutcome, provider::ExchangeRequest};

impl OAuthManager {
    /// Complete an OAuth authorization. The host calls this with the
    /// state value it stored at `start_authorization` (after confirming
    /// the value echoed back in the callback URL matches) and the `code`
    /// the provider returned.
    #[tracing::instrument(
        skip(self, state, code, context),
        fields(method = "oauth", provider = tracing::field::Empty, user_id = tracing::field::Empty),
    )]
    pub async fn finish_authorization(
        &self,
        state: &OAuthStateId,
        code: &str,
        context: SessionContext,
    ) -> Result<OAuthOutcome> {
        let now = self.clock.now();
        let Some(pending) = self.states.take(state).await? else {
            tracing::warn!(outcome = "invalid_state", "oauth finish failed");
            return Err(Error::InvalidOAuthState);
        };
        if pending.expires_at <= now {
            tracing::warn!(outcome = "expired_state", "oauth finish failed");
            return Err(Error::InvalidOAuthState);
        }
        tracing::Span::current().record("provider", tracing::field::display(&pending.provider));
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
                tracing::warn!(outcome = "already_linked", "oauth finish failed");
                return Err(Error::OAuthIdentityAlreadyLinked);
            }
            let user = self
                .users
                .find_user_by_id(existing.user_id)
                .await?
                .ok_or(Error::UserNotFound)?;
            tracing::Span::current().record("user_id", tracing::field::display(user.id));
            let session = self.sessions.create(user.id, context.clone()).await?;
            self.emit_login(user.id, &context).await;
            tracing::info!(
                outcome = "succeeded",
                is_new_user = false,
                "oauth login succeeded"
            );
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
                tracing::warn!(outcome = "email_taken", "oauth finish failed");
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
        tracing::Span::current().record("user_id", tracing::field::display(target_user.id));

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

        tracing::info!(outcome = "succeeded", is_new_user, "oauth login succeeded");
        Ok(OAuthOutcome {
            user: target_user,
            identity,
            session,
            is_new_user,
            link_was_added: true,
        })
    }
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}
