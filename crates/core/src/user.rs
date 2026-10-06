use std::sync::Arc;
use std::time::Duration;

use crate::assembly::AssemblyError;
use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::context::CoreDeps;
use crate::email::{self, EmailSender, EmailTemplates, SecurityNotices};
use crate::email_link::{EmailChange, EmailLinks, TOKEN_PLACEHOLDER};
use crate::error::{Error, Result};
use crate::reauth::{ReauthAction, ReauthManager, ReauthProof};
use crate::session::{SessionContext, SessionManager};
use crate::storage::{Session, SessionId, User};
use crate::user_records::UserRecords;

#[derive(Clone)]
pub struct UserConfig {
    pub token_lifetime: Duration,
    pub url_template: String,
}

impl UserConfig {
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            url_template: format!("https://example.invalid/email-change?token={TOKEN_PLACEHOLDER}"),
        }
    }
}

#[derive(Clone)]
pub struct UserManager {
    records: UserRecords,
    sessions: SessionManager,
    link: EmailLinks<EmailChange>,
    reauth: ReauthManager,
    audit: AuditDispatch,
    email: Arc<dyn EmailSender>,
    emails: Arc<dyn EmailTemplates>,
    notices: SecurityNotices,
}

impl UserManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        config: UserConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        let link = EmailLinks::new(deps, &config.url_template, config.token_lifetime)?;
        Ok(Self {
            records: UserRecords::new(deps),
            sessions: deps.sessions.clone(),
            link,
            reauth: deps.reauth.clone(),
            audit: deps.audit.clone(),
            email: deps.email.clone(),
            emails: deps.emails.clone(),
            notices: deps.notices.clone(),
        })
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
        let normalized = email::normalize_email(new_email);
        email::validate_email(&normalized)?;

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

        self.notices
            .email_change_requested(&user, &normalized)
            .await;

        self.audit
            .emit(
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

        self.audit
            .emit(&context, AuditEventKind::EmailChangeCompleted { user_id })
            .await;
        Ok(user)
    }

    #[tracing::instrument(skip(self, reauth, context), fields(user_id = %session.user_id))]
    pub async fn delete_user(
        &self,
        session: &Session,
        reauth: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<()> {
        self.reauth
            .ensure(ReauthAction::DeleteUser, session, reauth.as_ref(), &context)
            .await?;
        self.records
            .delete(session.user_id, Actor::from(&context))
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
                .find_for_notice(session.user_id, "other-sessions revoked")
                .await
        {
            self.notices.other_sessions_revoked(&user).await;
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
            .revoke_session_for_target(session.user_id, target, Actor::of_session(session))
            .await?;
        if !is_current
            && let Some(user) = self
                .records
                .find_for_notice(session.user_id, "other-session revoked")
                .await
        {
            self.notices.other_session_revoked(&user).await;
        }
        Ok(())
    }
}
