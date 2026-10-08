use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::assembly::AssemblyError;
use crate::audit::{AuditDispatch, AuditEventKind, SecretKind};
use crate::context::CoreDeps;
use crate::email_link::{EmailLinks, LinkPurpose};
use crate::error::Result;
use crate::passkey::{RegistrationOutcome, StartedRegistration};
use crate::passkey_registration::{
    FinishRules, PasskeyCap, PasskeyRegistrations, RegisteredPasskey, RegistrationSource,
};
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::SessionContext;
use crate::storage::{EmailLink, EmailLinkPurpose, PasskeyChallengeId, User, UserId};
use crate::user_records::UserRecords;

pub(crate) trait RegistrationLink: LinkPurpose<Payload = ()> + Sync {
    const SOURCE: RegistrationSource<'static>;
    const PASSKEY_CAP: PasskeyCap;
    fn redeemed(user_id: UserId) -> AuditEventKind;
    async fn on_redeem(&self, records: &UserRecords, user: &User) -> Result<()>;
    async fn on_finish(&self, notices: &SecurityNotices, user: &User);
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Signup;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Recovery;

impl LinkPurpose for Signup {
    type Payload = ();
    const PURPOSE: EmailLinkPurpose = EmailLinkPurpose::Signup;
    const SECRET: SecretKind = SecretKind::SignupLink;
    const FLOW: &'static str = "signup";
    const LIFETIME_FIELD: &'static str = "signup token_lifetime";

    fn store((): ()) -> Option<String> {
        None
    }

    fn load(_: &EmailLink) -> Option<()> {
        Some(())
    }
}

impl RegistrationLink for Signup {
    const SOURCE: RegistrationSource<'static> = RegistrationSource::SignupLink;
    const PASSKEY_CAP: PasskeyCap = PasskeyCap::Enforced;

    fn redeemed(user_id: UserId) -> AuditEventKind {
        AuditEventKind::SignupLinkRedeemed { user_id }
    }

    async fn on_redeem(&self, records: &UserRecords, user: &User) -> Result<()> {
        records.mark_email_verified(user).await
    }

    // The new user registered their first passkey a moment ago, so a security notice would only
    // repeat what they just did.
    async fn on_finish(&self, _: &SecurityNotices, _: &User) {}
}

impl LinkPurpose for Recovery {
    type Payload = ();
    const PURPOSE: EmailLinkPurpose = EmailLinkPurpose::Recovery;
    const SECRET: SecretKind = SecretKind::RecoveryLink;
    const FLOW: &'static str = "recovery";
    const LIFETIME_FIELD: &'static str = "recovery token_lifetime";

    fn store((): ()) -> Option<String> {
        None
    }

    fn load(_: &EmailLink) -> Option<()> {
        Some(())
    }
}

impl RegistrationLink for Recovery {
    const SOURCE: RegistrationSource<'static> = RegistrationSource::RecoveryLink;
    // A user who has lost their passkeys may still sit at the cap, and recovery is their way back.
    const PASSKEY_CAP: PasskeyCap = PasskeyCap::Exempt;

    fn redeemed(user_id: UserId) -> AuditEventKind {
        AuditEventKind::RecoveryLinkRedeemed { user_id }
    }

    async fn on_redeem(&self, _: &UserRecords, _: &User) -> Result<()> {
        Ok(())
    }

    // The recovery-completed notice already says a new passkey was registered.
    async fn on_finish(&self, notices: &SecurityNotices, user: &User) {
        notices.send(user, SecurityNotice::RecoveryCompleted).await;
    }
}

#[derive(Clone)]
pub(crate) struct EmailLinkRegistration<P> {
    purpose: P,
    links: EmailLinks<P>,
    registrations: PasskeyRegistrations,
    records: UserRecords,
    notices: SecurityNotices,
    audit: AuditDispatch,
}

impl<P: RegistrationLink> EmailLinkRegistration<P> {
    pub(crate) fn new(
        deps: &CoreDeps,
        registrations: PasskeyRegistrations,
        purpose: P,
        url_template: &str,
        link_lifetime: Duration,
    ) -> std::result::Result<Self, AssemblyError> {
        Ok(Self {
            purpose,
            links: EmailLinks::new(deps, url_template, link_lifetime)?,
            registrations,
            records: UserRecords::new(deps),
            notices: deps.notices.clone(),
            audit: deps.audit.clone(),
        })
    }

    pub(crate) async fn issue_link(&self, user_id: UserId) -> Result<String> {
        self.links.issue(user_id, ()).await
    }

    pub(crate) async fn redeem(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<StartedRegistration> {
        let (user, ()) = self.links.redeem(token, &context).await?;
        self.purpose.on_redeem(&self.records, &user).await?;
        self.registrations.invalidate_pending(user.id).await?;
        let started = self.registrations.start(user.id, P::SOURCE).await?;

        self.audit.emit(&context, P::redeemed(user.id)).await;
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
        let rules = FinishRules {
            purpose: P::SOURCE.purpose(),
            passkey_cap: P::PASSKEY_CAP,
        };
        let RegisteredPasskey { user, passkey } = self
            .registrations
            .finish(challenge_id, response, name, &context, rules)
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
        self.purpose.on_finish(&self.notices, &user).await;

        tracing::info!(outcome = "succeeded", "email-link registration finished");
        Ok(RegistrationOutcome {
            user,
            session,
            passkey,
        })
    }
}
