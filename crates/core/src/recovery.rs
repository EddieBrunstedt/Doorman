use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::audit::{AuditDispatch, AuditEventKind, RecoveryFailureReason};
use crate::context::CoreDeps;
use crate::email::{EmailAddress, Mailer};
use crate::email_link::{Issued, LinkTemplate};
use crate::email_link_registration::{EmailLinkRegistration, RegistrationLink};
use crate::error::Result;
use crate::lifetime::Lifetime;
use crate::passkey::{RegistrationOutcome, StartedRegistration};
use crate::passkey_registration::PasskeyRegistrations;
use crate::rate_limit::{Attempt, RateLimitEnforcer};
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::{RequestTransport, SessionContext};
use crate::storage::PasskeyChallengeId;
use crate::user_records::{OwnerRefusal, UserRecords};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a recovery cool-down ({0:?}) must last at least {min:?}", min = CoolDownLength::MIN)]
pub struct CoolDownTooShort(pub Duration);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoolDownLength(Lifetime);

impl CoolDownLength {
    pub const DEFAULT: Self = Self(Lifetime::from_secs(60 * 60 * 24));
    pub const MIN: Duration = Duration::from_secs(60 * 60);

    pub fn new(length: Lifetime) -> std::result::Result<Self, CoolDownTooShort> {
        if length.get() < Self::MIN {
            return Err(CoolDownTooShort(length.get()));
        }
        Ok(Self(length))
    }

    // A cool-down this short barely slows down whoever took over a user through recovery, so a host
    // has to name the danger to get one.
    pub const fn danger_below_floor(length: Lifetime) -> Self {
        Self(length)
    }

    pub fn get(self) -> Lifetime {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    pub token_lifetime: Lifetime,
    pub cool_down: CoolDownLength,
}

impl RecoveryConfig {
    pub const DEFAULT_TOKEN_LIFETIME: Lifetime = Lifetime::from_secs(60 * 15);
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            cool_down: CoolDownLength::DEFAULT,
        }
    }
}

#[derive(Clone)]
pub struct RecoveryManager {
    records: UserRecords,
    registration: EmailLinkRegistration,
    mailer: Mailer,
    notices: SecurityNotices,
    rate_limits: RateLimitEnforcer,
    audit: AuditDispatch,
}

impl RecoveryManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        registrations: PasskeyRegistrations,
        template: LinkTemplate,
        config: &RecoveryConfig,
    ) -> Self {
        Self {
            records: UserRecords::new(deps),
            registration: EmailLinkRegistration::new(
                deps,
                registrations,
                RegistrationLink::Recovery,
                template,
                config.token_lifetime,
            ),
            mailer: deps.mailer.clone(),
            notices: deps.notices.clone(),
            rate_limits: deps.rate_limits.clone(),
            audit: deps.audit.clone(),
        }
    }

    #[tracing::instrument(
        skip(self, email, context),
        fields(method = "recovery", user_id = tracing::field::Empty),
    )]
    pub async fn request_recovery(&self, email: &str, context: SessionContext) -> Result<()> {
        let address = EmailAddress::parse(email)?;

        self.rate_limits
            .enforce(&context, Attempt::RecoveryRequest { email: &address })
            .await?;

        let Some(user) = self.records.find_by_email(&address).await? else {
            self.audit
                .emit(
                    &context,
                    AuditEventKind::RecoveryRequested { user_id: None },
                )
                .await;
            self.audit
                .emit(
                    &context,
                    AuditEventKind::RecoveryFailed {
                        user_id: None,
                        reason: RecoveryFailureReason::UnknownEmail,
                    },
                )
                .await;
            return Ok(());
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        let url = match self.registration.issue_link(&user).await? {
            Issued::Link(url) => url,
            Issued::Refused(refusal) => {
                let reason = match refusal {
                    // Delete disables a user before removing them, so one gone by now is
                    // refused as disabled.
                    OwnerRefusal::UserDisabled | OwnerRefusal::UserNotFound => {
                        RecoveryFailureReason::UserDisabled
                    }
                    // There is no access to regain until signup has finished; a signup link
                    // finishes it.
                    OwnerRefusal::WrongSignupStage => RecoveryFailureReason::SignupUnfinished,
                };
                self.audit
                    .emit(
                        &context,
                        AuditEventKind::RecoveryFailed {
                            user_id: Some(user.id),
                            reason,
                        },
                    )
                    .await;
                return Ok(());
            }
        };
        self.mailer
            .send_best_effort(&user, "recovery link", |templates| {
                templates.recovery_email(&user, &url)
            })
            .await;
        self.notices
            .send(&user, SecurityNotice::RecoveryRequested)
            .await;

        self.audit
            .emit(
                &context,
                AuditEventKind::RecoveryRequested {
                    user_id: Some(user.id),
                },
            )
            .await;
        Ok(())
    }

    #[tracing::instrument(
        skip(self, token, context),
        fields(method = "recovery", user_id = tracing::field::Empty),
    )]
    pub async fn redeem_recovery_link(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<StartedRegistration> {
        self.registration.redeem(token, context).await
    }

    #[tracing::instrument(
        skip(self, response, name, context),
        fields(method = "recovery", user_id = tracing::field::Empty),
    )]
    pub async fn finish_recovery(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        transport: RequestTransport,
        context: SessionContext,
    ) -> Result<RegistrationOutcome> {
        self.registration
            .finish(challenge_id, response, name, transport, context)
            .await
    }
}
