use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::assembly::{AssemblyError, MAX_LIFETIME};
use crate::audit::{AuditDispatch, AuditEventKind, RecoveryFailureReason};
use crate::context::CoreDeps;
use crate::email::{EmailAddress, Mailer};
use crate::email_link::{Issued, LinkTemplate};
use crate::email_link_registration::{EmailLinkRegistration, RegistrationLink};
use crate::error::Result;
use crate::passkey::{RegistrationOutcome, StartedRegistration};
use crate::passkey_registration::PasskeyRegistrations;
use crate::rate_limit::{Attempt, RateLimitEnforcer};
use crate::redeem::OwnerRefusal;
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::SessionContext;
use crate::storage::{PasskeyChallengeId, SessionTransport};
use crate::user_records::UserRecords;

#[derive(Clone)]
pub struct RecoveryConfig {
    pub token_lifetime: Duration,
    pub cool_down: Duration,
    pub danger_allow_cool_down_below_floor: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryConfigError {
    #[error("recovery cool-down ({configured:?}) is below the floor of {minimum:?}")]
    CoolDownTooShort {
        configured: Duration,
        minimum: Duration,
    },
    #[error("recovery cool-down ({configured:?}) is above the ceiling of {maximum:?}")]
    CoolDownTooLong {
        configured: Duration,
        maximum: Duration,
    },
}

impl RecoveryConfig {
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
    pub const DEFAULT_COOL_DOWN: Duration = Duration::from_secs(60 * 60 * 24);
    pub const MIN_COOL_DOWN: Duration = Duration::from_secs(60 * 60);
    pub const MAX_COOL_DOWN: Duration = MAX_LIFETIME;

    pub(crate) fn validated_cool_down(
        &self,
    ) -> std::result::Result<chrono::Duration, RecoveryConfigError> {
        let too_long = RecoveryConfigError::CoolDownTooLong {
            configured: self.cool_down,
            maximum: Self::MAX_COOL_DOWN,
        };
        if self.cool_down > Self::MAX_COOL_DOWN {
            return Err(too_long);
        }
        if self.cool_down < Self::MIN_COOL_DOWN && !self.danger_allow_cool_down_below_floor {
            return Err(RecoveryConfigError::CoolDownTooShort {
                configured: self.cool_down,
                minimum: Self::MIN_COOL_DOWN,
            });
        }
        chrono::Duration::from_std(self.cool_down).map_err(|_| too_long)
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            cool_down: Self::DEFAULT_COOL_DOWN,
            danger_allow_cool_down_below_floor: false,
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
    ) -> std::result::Result<Self, AssemblyError> {
        Ok(Self {
            records: UserRecords::new(deps),
            registration: EmailLinkRegistration::new(
                deps,
                registrations,
                RegistrationLink::Recovery,
                template,
                config.token_lifetime,
            )?,
            mailer: deps.mailer.clone(),
            notices: deps.notices.clone(),
            rate_limits: deps.rate_limits.clone(),
            audit: deps.audit.clone(),
        })
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
                    OwnerRefusal::UserDisabled => RecoveryFailureReason::UserDisabled,
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
        transport: SessionTransport,
        context: SessionContext,
    ) -> Result<RegistrationOutcome> {
        self.registration
            .finish(challenge_id, response, name, transport, context)
            .await
    }
}
