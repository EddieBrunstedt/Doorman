use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::assembly::AssemblyError;
use crate::audit::{AuditDispatch, AuditEventKind};
use crate::context::CoreDeps;
use crate::email_link::EmailLinks;
use crate::error::Result;
use crate::passkey::{RegistrationOutcome, StartedRegistration};
use crate::passkey_registration::{
    PasskeyRegistrations, RegisteredPasskey, RegistrationFinish, RegistrationSource,
};
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::SessionContext;
use crate::storage::{EmailLinkPurpose, PasskeyChallengeId, PasskeySummary, User, UserId};
use crate::user_records::UserRecords;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistrationLink {
    Signup,
    Recovery,
}

impl RegistrationLink {
    const fn link_purpose(self) -> EmailLinkPurpose {
        match self {
            Self::Signup => EmailLinkPurpose::Signup,
            Self::Recovery => EmailLinkPurpose::Recovery,
        }
    }

    const fn finish(self) -> RegistrationFinish<'static> {
        match self {
            Self::Signup => RegistrationFinish::SignupLink,
            Self::Recovery => RegistrationFinish::RecoveryLink,
        }
    }

    const fn source(self, owner: &User) -> RegistrationSource<'_> {
        match self {
            Self::Signup => RegistrationSource::SignupLink(owner),
            Self::Recovery => RegistrationSource::RecoveryLink(owner),
        }
    }

    const fn redeemed(self, user_id: UserId) -> AuditEventKind {
        match self {
            Self::Signup => AuditEventKind::SignupLinkRedeemed { user_id },
            Self::Recovery => AuditEventKind::RecoveryLinkRedeemed { user_id },
        }
    }
}

#[derive(Clone)]
pub(crate) struct EmailLinkRegistration {
    link: RegistrationLink,
    links: EmailLinks,
    registrations: PasskeyRegistrations,
    records: UserRecords,
    notices: SecurityNotices,
    audit: AuditDispatch,
}

impl EmailLinkRegistration {
    pub(crate) fn new(
        deps: &CoreDeps,
        registrations: PasskeyRegistrations,
        link: RegistrationLink,
        url_template: &str,
        link_lifetime: Duration,
    ) -> std::result::Result<Self, AssemblyError> {
        Ok(Self {
            link,
            links: EmailLinks::new(deps, link.link_purpose(), url_template, link_lifetime)?,
            registrations,
            records: UserRecords::new(deps),
            notices: deps.notices.clone(),
            audit: deps.audit.clone(),
        })
    }

    pub(crate) async fn issue_link(&self, user_id: UserId) -> Result<String> {
        self.links.issue(user_id, None).await
    }

    pub(crate) async fn redeem(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<StartedRegistration> {
        let (user, _) = self.links.redeem(token, &context).await?;
        self.registrations.invalidate_pending(user.id).await?;
        let started = self.registrations.start(self.link.source(&user)).await?;

        self.audit.emit(&context, self.link.redeemed(user.id)).await;
        tracing::info!(outcome = "redeemed", "email link redeemed");
        Ok(started)
    }

    pub(crate) async fn finish(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<RegistrationOutcome> {
        let RegisteredPasskey {
            user,
            passkey,
            passkey_count,
        } = self
            .registrations
            .finish(challenge_id, response, name, &context, self.link.finish())
            .await?;
        // A registration started since the link was redeemed may belong to whoever holds a lost
        // passkey or a stolen session, so it must not outlive the one the link started.
        self.registrations.invalidate_pending(user.id).await?;
        let session = self
            .records
            .issue_session(&passkey, context.clone())
            .await?;
        self.audit
            .emit(
                &context,
                AuditEventKind::LoginSucceeded { user_id: user.id },
            )
            .await;
        match self.link {
            // The new user registered their first passkey a moment ago, so a security notice
            // would only repeat what they just did.
            RegistrationLink::Signup => {}
            // The recovery-completed notice already says a new passkey was registered.
            RegistrationLink::Recovery => {
                self.notices
                    .send(&user, SecurityNotice::RecoveryCompleted)
                    .await;
            }
        }

        tracing::info!(outcome = "succeeded", "email-link registration finished");
        Ok(RegistrationOutcome {
            user,
            passkey_count,
            session,
            passkey: PasskeySummary::from(passkey),
        })
    }
}
