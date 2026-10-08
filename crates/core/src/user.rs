use std::time::Duration;

use crate::assembly::AssemblyError;
use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::context::CoreDeps;
use crate::destructive::Cleared;
use crate::email::{self, Mailer};
use crate::email_link::{EmailChange, EmailLinks, TOKEN_PLACEHOLDER};
use crate::error::{Error, Result};
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::SessionContext;
use crate::storage::User;
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
    link: EmailLinks<EmailChange>,
    audit: AuditDispatch,
    mailer: Mailer,
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
            link,
            audit: deps.audit.clone(),
            mailer: deps.mailer.clone(),
            notices: deps.notices.clone(),
        })
    }

    pub(crate) async fn request_email_change(
        &self,
        cleared: Cleared,
        new_email: &str,
        context: SessionContext,
    ) -> Result<()> {
        let session = cleared.session();
        let normalized = email::normalize_email(new_email);
        email::validate_email(&normalized)?;

        if self.records.find_by_email(&normalized).await?.is_some() {
            tracing::warn!(outcome = "email_in_use", "email change rejected");
            return Err(Error::EmailAlreadyInUse);
        }

        let user = self.records.find(session.user_id).await?;
        let url = self.link.issue(user.id, normalized.clone()).await?;

        self.mailer
            .send(&normalized, |templates| {
                templates.email_change_confirmation_email(&user, &normalized, &url)
            })
            .await?;

        self.notices
            .send(
                &user,
                SecurityNotice::EmailChangeRequested {
                    new_email: &normalized,
                },
            )
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

    pub(crate) async fn delete_user(
        &self,
        cleared: Cleared,
        context: SessionContext,
    ) -> Result<()> {
        self.records
            .delete(cleared.session().user_id, Actor::from(&context))
            .await
    }
}
