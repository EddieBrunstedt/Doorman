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
use crate::session::{SessionContext, SessionManager};
use crate::storage::{Session, SessionId, User};
use crate::user::UserRecords;
use crate::verification::{self, TOKEN_PLACEHOLDER};

#[derive(Clone)]
pub struct AccountConfig {
    pub token_lifetime: Duration,
    pub url_template: String,
}

impl AccountConfig {
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            url_template: format!("https://example.invalid/email-change?token={TOKEN_PLACEHOLDER}"),
        }
    }
}

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
    pub(crate) fn new(
        deps: &CoreDeps,
        config: AccountConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        let link = EmailedLink::new(deps, &config.url_template, config.token_lifetime)?;
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

    #[tracing::instrument(skip(self, session, new_email, reauth, context), fields(user_id = %session.user_id))]
    pub async fn request_email_change(
        &self,
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

        if self.records.find_by_email(&normalized).await?.is_some() {
            tracing::warn!(outcome = "email_in_use", "email change rejected");
            return Err(Error::EmailAlreadyInUse);
        }

        let user = self.records.find(session.user_id).await?;
        let url = self.link.issue(user.id, normalized.clone()).await?;

        let confirmation = self
            .emails
            .email_change_confirmation_email(&user, &normalized, &url);
        self.email.send(confirmation).await?;

        self.notifier
            .email_change_requested(&user, &normalized)
            .await;

        self.emit(
            &context,
            AuditEventKind::EmailChangeRequested { user_id: user.id },
        )
        .await;
        Ok(())
    }

    #[tracing::instrument(skip(self, token, context), fields(user_id = tracing::field::Empty))]
    pub async fn confirm_email_change(&self, token: &str, context: SessionContext) -> Result<User> {
        let (user, new_email) = self.link.redeem(token, &context).await?;
        let user_id = user.id;

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

    #[tracing::instrument(skip(self, session, reauth, context), fields(user_id = %session.user_id, session_id = %session.id))]
    pub async fn revoke_other_sessions(
        &self,
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
        let count = self
            .sessions
            .revoke_others(session.user_id, session.id)
            .await?;
        if count > 0
            && let Some(user) = self
                .records
                .find_for_notification(session.user_id, "other-sessions revoked")
                .await
        {
            self.notifier.other_sessions_revoked(&user).await;
        }
        Ok(count)
    }

    #[tracing::instrument(skip(self, session, reauth, context), fields(user_id = %session.user_id, session_id = %target))]
    pub async fn revoke_session(
        &self,
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
                session.user_id,
                target,
                Actor::Subject {
                    ip: session.ip.clone(),
                    user_agent: session.user_agent.clone(),
                },
            )
            .await?;
        if !is_current
            && let Some(user) = self
                .records
                .find_for_notification(session.user_id, "other-session revoked")
                .await
        {
            self.notifier.other_session_revoked(&user).await;
        }
        Ok(())
    }
}
