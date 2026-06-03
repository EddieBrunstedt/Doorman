//! Account-lifecycle operations: verified email change and account deletion.
//!
//! [`AccountManager`] owns the two account-management flows that sit outside
//! the signup / recovery / passkey ceremonies:
//!
//! - [`request_email_change`](AccountManager::request_email_change) /
//!   [`confirm_email_change`](AccountManager::confirm_email_change) — a
//!   verified email-change. A single-use confirmation token is mailed to the
//!   *new* address (proving the user controls it) while the *old* address is
//!   notified that a change was initiated. The account's email only moves once
//!   the token is redeemed, so neither a typo nor a hijacked session can
//!   silently repoint the address.
//! - [`delete_account`](AccountManager::delete_account) — irreversibly removes
//!   the user and every row that hangs off it (sessions, credentials,
//!   verification tokens, pending registration ceremonies), evicting any
//!   framework-side session cache as it revokes.
//!
//! The flow reuses the verification-token machinery in
//! [`crate::verification`] so the email-change link behaves exactly like the
//! signup / recovery links (single-use, hashed at rest, purpose-bound).

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::audit::{AuditEvent, AuditEventKind, AuditSink};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::email::{Email, EmailSender, EmailTemplates, default_emails};
use crate::error::{Error, Result};
use crate::session::{SessionContext, SessionManager};
use crate::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, User, UserStore, VerificationPurpose,
    VerificationTokenStore,
};
use crate::token::hash_token;
use crate::verification::{self, TOKEN_PLACEHOLDER};

/// Every verification-token purpose, so account deletion can sweep tokens of
/// all kinds for a user. Kept here (rather than iterating an open match) so a
/// new purpose forces a compile error pointing back at the deletion cascade.
const ALL_TOKEN_PURPOSES: [VerificationPurpose; 3] = [
    VerificationPurpose::Signup,
    VerificationPurpose::Recovery,
    VerificationPurpose::EmailChange,
];

/// Configuration for the verified email-change flow.
#[derive(Clone)]
pub struct AccountConfig {
    /// Lifetime of an email-change confirmation token. Short by design — the
    /// link, once clicked, repoints the account's address.
    pub token_lifetime: Duration,
    /// URL template used in the confirmation email. The literal substring
    /// `{token}` is replaced with the generated token at send time.
    pub url_template: String,
    /// Renderer for the email-change emails. `None` falls back to the renderer
    /// the composition root threads in (see `AuthServiceBuilder::emails`), and to
    /// [`DefaultEmailTemplates`](crate::email::DefaultEmailTemplates) if none was set.
    pub emails: Option<Arc<dyn EmailTemplates>>,
}

impl AccountConfig {
    /// Default email-change confirmation-token lifetime: 15 minutes. Short by
    /// design — see [`AccountConfig::token_lifetime`].
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
}

impl Default for AccountConfig {
    /// Default: a 15-minute token lifetime ([`DEFAULT_TOKEN_LIFETIME`]), a
    /// placeholder `example.invalid` URL template (the host must override
    /// this), and no flow-specific email renderer.
    ///
    /// [`DEFAULT_TOKEN_LIFETIME`]: AccountConfig::DEFAULT_TOKEN_LIFETIME
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            url_template: format!("https://example.invalid/email-change?token={TOKEN_PLACEHOLDER}"),
            emails: None,
        }
    }
}

/// Manager for verified email change and account deletion.
#[derive(Clone)]
pub struct AccountManager {
    users: Arc<dyn UserStore>,
    tokens: Arc<dyn VerificationTokenStore>,
    credentials: Arc<dyn PasskeyCredentialStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    sessions: SessionManager,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    email: Arc<dyn EmailSender>,
    emails: Arc<dyn EmailTemplates>,
    config: AccountConfig,
}

impl AccountManager {
    /// Build an `AccountManager` from the shared [`CoreDeps`] context and the
    /// [`AccountConfig`]. The collaborators (stores, clock, audit, email
    /// transport, session manager) are read from `deps` so they are named once
    /// at the composition root.
    pub fn new(deps: &CoreDeps, config: AccountConfig) -> Self {
        let emails = config.emails.clone().unwrap_or_else(default_emails);
        Self {
            users: deps.users.clone(),
            tokens: deps.verification_tokens.clone(),
            credentials: deps.passkey_credentials.clone(),
            challenges: deps.passkey_challenges.clone(),
            sessions: deps.sessions.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
            email: deps.email.clone(),
            emails,
            config,
        }
    }

    fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    async fn emit(&self, context: &SessionContext, kind: AuditEventKind) {
        self.audit
            .emit(AuditEvent {
                timestamp: self.now(),
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind,
            })
            .await;
    }

    /// Send an email best-effort: a transport failure is logged but never
    /// propagated. Used for the old-address notification, which must not fail
    /// the request after the confirmation link has already been issued.
    async fn send_best_effort(&self, email: Email, description: &str) {
        if let Err(err) = self.email.send(email).await {
            tracing::warn!(error = %err, description, "email send failed (best-effort)");
        }
    }

    /// Request a verified change of `user`'s email to `new_email`.
    ///
    /// Validates and normalizes the target address, rejects an address already
    /// registered (to this or any other account) with [`Error::EmailAlreadyInUse`],
    /// issues a single-use confirmation token to the new address, and notifies
    /// the old address. The account's email is **not** changed here — that
    /// happens in [`confirm_email_change`](Self::confirm_email_change) once the
    /// link is clicked.
    #[tracing::instrument(skip(self, new_email, context), fields(user_id = %user.id))]
    pub async fn request_email_change(
        &self,
        user: &User,
        new_email: &str,
        context: SessionContext,
    ) -> Result<()> {
        let normalized = verification::normalize_email(new_email);
        verification::validate_email(&normalized)?;

        // Reject an address that is already taken — including the user's own
        // current address (nothing to change). Email-change is authenticated,
        // so surfacing "already in use" is acceptable; it is not the
        // enumeration surface the signup / recovery endpoints guard.
        if self.users.find_user_by_email(&normalized).await?.is_some() {
            tracing::warn!(outcome = "email_in_use", "email change rejected");
            return Err(Error::EmailAlreadyInUse);
        }

        let now = self.now();
        let url = verification::issue_link(
            self.tokens.as_ref(),
            user.id,
            VerificationPurpose::EmailChange,
            Some(normalized.clone()),
            self.config.token_lifetime,
            &self.config.url_template,
            now,
        )
        .await?;

        // The confirmation link is the whole flow, so its delivery is a hard
        // failure (unlike the enumeration-sensitive signup / recovery sends).
        let confirmation = self
            .emails
            .email_change_confirmation_email(user, &normalized, &url);
        self.email.send(confirmation).await?;

        // The old-address notice is advisory and must not fail the request.
        let notice = self
            .emails
            .email_change_requested_notification_email(user, &normalized);
        self.send_best_effort(notice, "email change requested notification")
            .await;

        self.emit(
            &context,
            AuditEventKind::EmailChangeRequested { user_id: user.id },
        )
        .await;
        tracing::info!(outcome = "requested", "email change requested");
        Ok(())
    }

    /// Redeem an email-change confirmation token, moving the account's email to
    /// the address the token was issued for. Returns the updated [`User`].
    #[tracing::instrument(skip(self, token, context), fields(user_id = tracing::field::Empty))]
    pub async fn confirm_email_change(&self, token: &str, context: SessionContext) -> Result<User> {
        let hash = hash_token(token);
        let now = self.now();
        let Some(record) = self
            .tokens
            .consume_token(&hash, VerificationPurpose::EmailChange)
            .await?
        else {
            tracing::warn!(outcome = "invalid_token", "email change confirm failed");
            return Err(Error::InvalidVerificationToken);
        };
        // Defense in depth: a store that ignores the purpose filter must not
        // let another flow's token redeem here.
        if record.purpose != VerificationPurpose::EmailChange || record.expires_at <= now {
            tracing::warn!(outcome = "invalid_token", "email change confirm failed");
            return Err(Error::InvalidVerificationToken);
        }
        let Some(new_email) = record.new_email else {
            // An email-change token must carry its target address.
            tracing::warn!(outcome = "missing_new_email", "email change confirm failed");
            return Err(Error::InvalidVerificationToken);
        };

        let Some(mut user) = self.users.find_user_by_id(record.user_id).await? else {
            tracing::warn!(outcome = "user_not_found", "email change confirm failed");
            return Err(Error::UserNotFound);
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        // Re-check the address is still free: another account may have claimed
        // it between request and confirm.
        if let Some(existing) = self.users.find_user_by_email(&new_email).await?
            && existing.id != user.id
        {
            tracing::warn!(outcome = "email_in_use", "email change confirm failed");
            return Err(Error::EmailAlreadyInUse);
        }

        // Clicking a link sent to the new address proves ownership of it.
        user.email = Some(new_email);
        user.email_verified_at = Some(now);
        user.updated_at = now;
        self.users.update_user(user.clone()).await?;

        self.emit(
            &context,
            AuditEventKind::EmailChangeCompleted { user_id: user.id },
        )
        .await;
        tracing::info!(outcome = "completed", "email change completed");
        Ok(user)
    }

    /// Irreversibly delete `user` and everything that hangs off it. Revokes
    /// every session first (evicting any framework-side session cache through
    /// the [`SessionManager`]'s invalidation hook), then removes the user's
    /// passkey credentials, verification tokens, pending registration
    /// ceremonies, and finally the user row itself, leaving no orphaned rows.
    #[tracing::instrument(skip(self, context), fields(user_id = %user.id))]
    pub async fn delete_account(&self, user: &User, context: SessionContext) -> Result<()> {
        let user_id = user.id;

        // Revoke through the session manager so the cache invalidation hook
        // fires (a raw `delete_sessions_for_user` would leave the cache warm).
        self.sessions.revoke_all_for_user(user_id).await?;

        // Remove every credential. The summary projection avoids deserialising
        // any credential blob just to enumerate the ids.
        let credentials = self
            .credentials
            .list_passkey_summaries_for_user(user_id)
            .await?;
        for credential in credentials {
            self.credentials
                .delete_passkey(&credential.credential_id)
                .await?;
        }

        // Drop tokens of every purpose and any pending registration ceremony.
        for purpose in ALL_TOKEN_PURPOSES {
            self.tokens.delete_tokens_for_user(user_id, purpose).await?;
        }
        self.challenges
            .delete_registrations_for_user(user_id)
            .await?;

        // The user row last, so a failure midway never orphans the parent.
        self.users.delete_user(user_id).await?;

        self.emit(&context, AuditEventKind::AccountDeleted { user_id })
            .await;
        tracing::info!(outcome = "deleted", "account deleted");
        Ok(())
    }
}
