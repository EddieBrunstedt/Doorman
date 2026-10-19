use std::time::Duration;

use crate::assembly::AssemblyError;
use crate::audit::{AuditDispatch, AuditEventKind};
use crate::context::CoreDeps;
use crate::destructive::Cleared;
use crate::email::{EmailAddress, Mailer};
use crate::email_link::{EmailLinks, TOKEN_PLACEHOLDER};
use crate::error::{Error, Result};
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::SessionContext;
use crate::storage::{EmailLinkPurpose, User};
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

#[derive(Debug, Clone)]
pub struct EmailChangeOutcome {
    pub user: User,
    pub passkey_count: u64,
}

#[derive(Clone)]
pub struct UserManager {
    records: UserRecords,
    link: EmailLinks,
    audit: AuditDispatch,
    mailer: Mailer,
    notices: SecurityNotices,
}

impl UserManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        config: UserConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        let link = EmailLinks::new(
            deps,
            EmailLinkPurpose::EmailChange,
            &config.url_template,
            config.token_lifetime,
        )?;
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
    ) -> Result<()> {
        let session = cleared.session();
        let address = EmailAddress::parse(new_email)?;

        if self.records.find_by_email(&address).await?.is_some() {
            tracing::warn!(outcome = "email_in_use", "email change rejected");
            return Err(Error::EmailAlreadyInUse);
        }

        let user = self.records.find(session.user_id).await?;
        let url = self.link.issue(&user, Some(&address)).await?;

        // Whoever holds the session may own the new address, and its mail server
        // can take the link yet fail the send. So the old address hears of the
        // change, and the audit records it, before the link leaves.
        self.notices
            .send(
                &user,
                SecurityNotice::EmailChangeRequested {
                    new_email: address.as_str(),
                },
            )
            .await;

        self.audit
            .emit(
                cleared.actor(),
                AuditEventKind::EmailChangeRequested { user_id: user.id },
            )
            .await;

        // The link is the whole flow, so a failed send fails the request. Unlike
        // in signup and recovery, that reveals nothing: the request needs a
        // session, and no user has the new address.
        self.mailer
            .send(address.as_str(), |templates| {
                templates.email_change_confirmation_email(&user, address.as_str(), &url)
            })
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self, token, context), fields(user_id = tracing::field::Empty))]
    pub async fn confirm_email_change(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<EmailChangeOutcome> {
        let (user, new_email) = self.link.redeem(token, &context).await?;
        let new_email = new_email
            .ok_or_else(|| Error::Internal("email-change link carries no new email".to_string()))?;
        let user_id = user.id;

        let user = match self.records.change_email(user_id, &new_email).await {
            Ok(user) => user,
            Err(error) => {
                tracing::warn!(%error, "email change confirm failed");
                return Err(error);
            }
        };

        let passkey_count = self.records.count_passkeys(user_id).await?;
        self.audit
            .emit(&context, AuditEventKind::EmailChangeCompleted { user_id })
            .await;
        Ok(EmailChangeOutcome {
            user,
            passkey_count,
        })
    }

    pub(crate) async fn delete_user(&self, cleared: Cleared) -> Result<()> {
        self.records
            .delete(cleared.session().user_id, cleared.actor())
            .await
    }
}
