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

use crate::audit::{Actor, AuditDispatch, AuditEvent, AuditEventKind};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::email::{Email, EmailSender, EmailTemplates};
use crate::error::{Error, Result};
use crate::reauth::{ReauthAction, ReauthManager, ReauthProof};
use crate::session::{SessionContext, SessionManager};
use crate::storage::{Session, User, VerificationPurpose, VerificationTokenStore};
use crate::token::hash_token;
use crate::user::UserRecords;
use crate::verification::{self, TOKEN_PLACEHOLDER};

/// Configuration for the verified email-change flow.
#[derive(Clone)]
pub struct AccountConfig {
    /// Lifetime of an email-change confirmation token. Short by design — the
    /// link, once clicked, repoints the account's address.
    pub token_lifetime: Duration,
    /// URL template used in the confirmation email. The literal substring
    /// `{token}` is replaced with the generated token at send time.
    pub url_template: String,
}

impl AccountConfig {
    /// Default email-change confirmation-token lifetime: 15 minutes. Short by
    /// design — see [`AccountConfig::token_lifetime`].
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
}

impl Default for AccountConfig {
    /// Default: a 15-minute token lifetime ([`DEFAULT_TOKEN_LIFETIME`]) and a
    /// placeholder `example.invalid` URL template (the host must override
    /// this).
    ///
    /// [`DEFAULT_TOKEN_LIFETIME`]: AccountConfig::DEFAULT_TOKEN_LIFETIME
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            url_template: format!("https://example.invalid/email-change?token={TOKEN_PLACEHOLDER}"),
        }
    }
}

/// Manager for verified email change and account deletion.
#[derive(Clone)]
pub struct AccountManager {
    records: UserRecords,
    tokens: Arc<dyn VerificationTokenStore>,
    sessions: SessionManager,
    reauth: ReauthManager,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
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
        Self {
            records: UserRecords::new(deps),
            tokens: deps.verification_tokens.clone(),
            sessions: deps.sessions.clone(),
            reauth: deps.reauth.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
            email: deps.email.clone(),
            emails: deps.emails.clone(),
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
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
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
    ///
    /// Refused with [`Error::RecoveryCooldownActive`] while the acting
    /// `session` is inside its post-recovery cool-down window: a phished
    /// recovery session must not be able to repoint the account's address out
    /// from under the legitimate owner before they can react. Pass a `session`
    /// resolved from storage for this request; the cool-down (and revocation)
    /// check trusts the supplied snapshot.
    ///
    /// When the host's [`ReauthPolicy`](crate::reauth::ReauthPolicy) gates
    /// [`RequestEmailChange`](ReauthAction::RequestEmailChange), `reauth` must
    /// carry a fresh [`ReauthProof`]; an absent one is rejected with
    /// [`Error::ReauthRequired`]. The cool-down is checked **first** — it is a
    /// hard block re-auth cannot satisfy.
    #[tracing::instrument(skip(self, session, new_email, reauth, context), fields(user_id = %user.id))]
    pub async fn request_email_change(
        &self,
        user: &User,
        session: &Session,
        new_email: &str,
        reauth: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<()> {
        self.sessions.ensure_not_in_recovery_cooldown(session)?;
        self.reauth
            .ensure(
                ReauthAction::RequestEmailChange,
                session,
                reauth.as_ref(),
                &context,
            )
            .await?;
        let normalized = verification::normalize_email(new_email);
        verification::validate_email(&normalized)?;

        // Reject an address that is already taken — including the user's own
        // current address (nothing to change). Email-change is authenticated,
        // so surfacing "already in use" is acceptable; it is not the
        // enumeration surface the signup / recovery endpoints guard.
        if self.records.find_by_email(&normalized).await?.is_some() {
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
        Ok(())
    }

    /// Redeem an email-change confirmation token, moving the account's email to
    /// the address the token was issued for. Returns the updated [`User`].
    ///
    /// The token is consumed even when the change is refused. A disabled
    /// account is refused with [`Error::AccountDisabled`], so a link requested
    /// before an operator disable cannot repoint the frozen account's address;
    /// an address another account claimed since the request is refused with
    /// [`Error::EmailAlreadyInUse`].
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

        let user_id = record.user_id;
        tracing::Span::current().record("user_id", tracing::field::display(user_id));
        if let Err(error) = self.records.find_active(user_id).await {
            tracing::warn!(%error, "email change confirm failed");
            return Err(error);
        }

        // Clicking a link sent to the new address proves ownership of it. The
        // address is re-checked: another account may have claimed it between
        // request and confirm.
        let user = match self.records.change_email(user_id, &new_email).await {
            Ok(user) => user,
            Err(error) => {
                tracing::warn!(%error, "email change confirm failed");
                return Err(error);
            }
        };

        self.emit(&context, AuditEventKind::EmailChangeCompleted { user_id })
            .await;
        Ok(user)
    }

    /// Irreversibly delete the account behind the acting `session` and
    /// everything that hangs off it. Revokes every session first (evicting any
    /// framework-side session cache through the [`SessionManager`]'s
    /// invalidation hook), then removes the user's passkey credentials,
    /// verification tokens, pending registration ceremonies, and finally the
    /// user row itself, leaving no orphaned rows.
    ///
    /// Refused with [`Error::RecoveryCooldownActive`] while `session` is
    /// inside its post-recovery cool-down window: a phished recovery session
    /// must not be able to delete the account before the legitimate owner can
    /// react. Pass a `session` resolved from storage for this request; the
    /// cool-down (and revocation) check trusts the supplied snapshot.
    ///
    /// When the host's [`ReauthPolicy`](crate::reauth::ReauthPolicy) gates
    /// [`DeleteAccount`](ReauthAction::DeleteAccount), `reauth` must carry a
    /// fresh [`ReauthProof`]; an absent one is rejected with
    /// [`Error::ReauthRequired`]. The cool-down is checked **first**.
    #[tracing::instrument(skip(self, reauth, context), fields(user_id = %session.user_id))]
    pub async fn delete_account(
        &self,
        session: &Session,
        reauth: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<()> {
        self.sessions.ensure_not_in_recovery_cooldown(session)?;
        self.reauth
            .ensure(
                ReauthAction::DeleteAccount,
                session,
                reauth.as_ref(),
                &context,
            )
            .await?;
        self.records
            .delete(
                session.user_id,
                Actor::Subject {
                    ip: context.ip,
                    user_agent: context.user_agent,
                },
            )
            .await
    }
}
