//! Account self-service: verified email change, account deletion, and
//! signing out the user's other sessions.
//!
//! [`AccountManager`] owns the account-management flows that sit outside the
//! signup / recovery / passkey ceremonies:
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
//! - [`revoke_other_sessions`](AccountManager::revoke_other_sessions) /
//!   [`revoke_session`](AccountManager::revoke_session) — "sign out everywhere
//!   else" and revoking one of the user's sessions by id.
//!
//! Every session-authenticated method here passes through
//! [`ReauthManager::ensure`] first, so the post-recovery cool-down and the
//! host's re-auth policy are enforced for any transport driving core.
//!
//! The email-change link is an emailed link like the signup and recovery
//! ones (single-use, hashed at rest, purpose-bound), carrying the normalized
//! new address as its payload.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::assembly::AssemblyError;
use crate::audit::{Actor, AuditDispatch, AuditEvent, AuditEventKind};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::email::{EmailSender, EmailTemplates, SecurityEmailNotifier};
use crate::error::{Error, Result};
use crate::link::{EmailChange, EmailedLink};
use crate::reauth::{ReauthAction, ReauthManager, ReauthProof};
use crate::redeem::Redeemer;
use crate::session::{SessionContext, SessionManager};
use crate::storage::{Session, SessionId, User};
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

/// Manager for verified email change, account deletion, and revoking the
/// user's other sessions.
#[derive(Clone)]
pub struct AccountManager {
    records: UserRecords,
    sessions: SessionManager,
    link: EmailedLink<EmailChange>,
    reauth: ReauthManager,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    email: Arc<dyn EmailSender>,
    emails: Arc<dyn EmailTemplates>,
    notifier: SecurityEmailNotifier,
}

impl AccountManager {
    /// Build an `AccountManager` from the shared [`CoreDeps`] context and the
    /// [`AccountConfig`]. The collaborators (stores, session manager, clock,
    /// audit, email transport, re-auth manager) are read from `deps` so they
    /// are named once at the composition root.
    ///
    /// Returns [`AssemblyError::InvalidUrlTemplate`] or
    /// [`AssemblyError::PlaceholderUrlTemplate`] for an unusable
    /// [`url_template`](AccountConfig::url_template), and
    /// [`AssemblyError::InvalidLifetime`] for an out-of-bounds
    /// [`token_lifetime`](AccountConfig::token_lifetime).
    pub(crate) fn new(
        deps: &CoreDeps,
        config: AccountConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        let link = EmailedLink::new(
            deps.verification_tokens.clone(),
            Redeemer::from_deps(deps),
            deps.clock.clone(),
            &config.url_template,
            config.token_lifetime,
        )?;
        Ok(Self {
            records: UserRecords::new(deps),
            sessions: deps.sessions.clone(),
            link,
            reauth: deps.reauth.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
            email: deps.email.clone(),
            emails: deps.emails.clone(),
            notifier: deps.notifier.clone(),
        })
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

        let url = self.link.issue(user.id, normalized.clone()).await?;

        // The confirmation link is the whole flow, so its delivery is a hard
        // failure (unlike the enumeration-sensitive signup / recovery sends).
        let confirmation = self
            .emails
            .email_change_confirmation_email(user, &normalized, &url);
        self.email.send(confirmation).await?;

        // The old-address notice is advisory and must not fail the request.
        self.notifier
            .email_change_requested(user, &normalized)
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
    /// The token is consumed even when the change is refused. A refused link
    /// is [`Error::InvalidVerificationToken`] and is audited as
    /// [`RedemptionFailed`](AuditEventKind::RedemptionFailed). A disabled
    /// account is refused with [`Error::AccountDisabled`], so a link requested
    /// before an operator disable cannot repoint the frozen account's address;
    /// an address another account claimed since the request is refused with
    /// [`Error::EmailAlreadyInUse`].
    #[tracing::instrument(skip(self, token, context), fields(user_id = tracing::field::Empty))]
    pub async fn confirm_email_change(&self, token: &str, context: SessionContext) -> Result<User> {
        let (user, new_email) = self.link.redeem(token, &context).await?;
        let user_id = user.id;

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

    /// Revoke every session belonging to `user` except the acting `session`:
    /// "sign out everywhere else". Returns the number revoked. When anything
    /// was revoked, evicts any framework-side session cache through the
    /// [`SessionManager`]'s invalidation hook and sends the best-effort "other
    /// sessions revoked" security notice.
    ///
    /// Refused with [`Error::RecoveryCooldownActive`] while `session` is
    /// inside its post-recovery cool-down window: a phished recovery session
    /// must not be able to kick the legitimate owner off their devices. Pass a
    /// `session` resolved from storage for this request; the check trusts the
    /// supplied snapshot.
    ///
    /// When the host's [`ReauthPolicy`](crate::reauth::ReauthPolicy) gates
    /// [`RevokeOtherSessions`](ReauthAction::RevokeOtherSessions), `reauth`
    /// must carry a fresh [`ReauthProof`]; an absent one is rejected with
    /// [`Error::ReauthRequired`]. The cool-down is checked **first**.
    #[tracing::instrument(skip(self, user, session, reauth, context), fields(user_id = %user.id, session_id = %session.id))]
    pub async fn revoke_other_sessions(
        &self,
        user: &User,
        session: &Session,
        reauth: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<u64> {
        self.reauth
            .ensure(
                ReauthAction::RevokeOtherSessions,
                session,
                reauth.as_ref(),
                &context,
            )
            .await?;
        let count = self.sessions.revoke_others(user.id, session.id).await?;
        if count > 0 {
            self.notifier.other_sessions_revoked(user).await;
        }
        Ok(count)
    }

    /// Revoke one of `user`'s sessions, identified by `target`.
    ///
    /// Reads the target once and rejects a missing session, or one owned by a
    /// different user, with [`Error::SessionNotFound`], so a probe cannot
    /// learn whether another user's session id exists. When `target` is not
    /// the acting `session`, the best-effort "session revoked" security notice
    /// is sent; self-revocation stays silent.
    ///
    /// Revoking the acting `session` itself is never gated, so the owner can
    /// always sign it out. Revoking *another* session goes through
    /// [`ReauthManager::ensure`] as
    /// [`RevokeSession`](ReauthAction::RevokeSession): refused with
    /// [`Error::RecoveryCooldownActive`] while `session` is inside its
    /// post-recovery cool-down (a phished recovery session must not strand the
    /// owner's other devices), and requiring a fresh [`ReauthProof`] when the
    /// host's policy lists the action. Pass a `session` resolved from storage
    /// for this request; the check trusts the supplied snapshot.
    #[tracing::instrument(skip(self, user, session, reauth, context), fields(user_id = %user.id, session_id = %target))]
    pub async fn revoke_session(
        &self,
        user: &User,
        session: &Session,
        target: SessionId,
        reauth: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<()> {
        let is_current = target == session.id;
        if !is_current {
            self.reauth
                .ensure(
                    ReauthAction::RevokeSession,
                    session,
                    reauth.as_ref(),
                    &context,
                )
                .await?;
        }
        self.sessions
            .revoke_session_for_target(
                user.id,
                target,
                Actor::Subject {
                    ip: session.ip.clone(),
                    user_agent: session.user_agent.clone(),
                },
            )
            .await?;
        if !is_current {
            self.notifier.other_session_revoked(user).await;
        }
        Ok(())
    }
}
