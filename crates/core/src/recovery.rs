use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::assembly::{AssemblyError, MAX_LIFETIME};
use crate::audit::{AuditEventKind, RecoveryFailureReason};
use crate::error::Result;
use crate::link::{self, EmailedLink};
use crate::passkey::{CredentialCap, EnrollmentPolicy};
use crate::rate_limit::{self, RateLimitPolicy};
use crate::session::SessionContext;
use crate::storage::PasskeyChallengeId;
use crate::user;
use crate::verification::{
    self, EnrollmentFlow, EnrollmentOutcome, TOKEN_PLACEHOLDER, VerificationConsumeOutcome,
};

#[derive(Clone)]
pub struct RecoveryConfig {
    pub token_lifetime: Duration,
    pub url_template: String,
    pub rate_limits: RecoveryRateLimits,
    pub cooldown: Duration,
    pub danger_allow_cooldown_below_floor: bool,
}

pub const MIN_COOLDOWN: Duration = Duration::from_secs(60 * 60);

pub const MAX_COOLDOWN: Duration = MAX_LIFETIME;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryConfigError {
    #[error("recovery cooldown ({configured:?}) is below the floor of {minimum:?}")]
    CooldownTooShort {
        configured: Duration,
        minimum: Duration,
    },
    #[error("recovery cooldown ({configured:?}) is above the ceiling of {maximum:?}")]
    CooldownTooLong {
        configured: Duration,
        maximum: Duration,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct RecoveryRateLimits {
    pub request_per_ip: Option<RateLimitPolicy>,
    pub request_per_identifier: Option<RateLimitPolicy>,
    pub request_per_identifier_daily: Option<RateLimitPolicy>,
    pub request_global: Option<RateLimitPolicy>,
}

impl RecoveryRateLimits {
    pub const DEFAULT_PER_IP: RateLimitPolicy =
        RateLimitPolicy::new(20, Duration::from_secs(60 * 60));
    pub const DEFAULT_PER_IDENTIFIER: RateLimitPolicy =
        RateLimitPolicy::new(5, Duration::from_secs(60 * 60));
    pub const DEFAULT_PER_IDENTIFIER_DAILY: RateLimitPolicy =
        RateLimitPolicy::new(10, Duration::from_secs(60 * 60 * 24));

    pub const fn disabled() -> Self {
        Self {
            request_per_ip: None,
            request_per_identifier: None,
            request_per_identifier_daily: None,
            request_global: None,
        }
    }
}

impl Default for RecoveryRateLimits {
    fn default() -> Self {
        Self {
            request_per_ip: Some(Self::DEFAULT_PER_IP),
            request_per_identifier: Some(Self::DEFAULT_PER_IDENTIFIER),
            request_per_identifier_daily: Some(Self::DEFAULT_PER_IDENTIFIER_DAILY),
            request_global: None,
        }
    }
}

impl RecoveryConfig {
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
    pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60 * 60 * 24);
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            url_template: format!("https://example.invalid/recovery?token={TOKEN_PLACEHOLDER}"),
            rate_limits: RecoveryRateLimits::default(),
            cooldown: Self::DEFAULT_COOLDOWN,
            danger_allow_cooldown_below_floor: false,
        }
    }
}

#[derive(Clone)]
pub struct RecoveryManager {
    flow: EnrollmentFlow,
    link: EmailedLink<link::Recovery>,
    config: RecoveryConfig,
    policy: EnrollmentPolicy,
}

impl RecoveryManager {
    pub(crate) fn new(
        flow: EnrollmentFlow,
        config: RecoveryConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        let too_long = RecoveryConfigError::CooldownTooLong {
            configured: config.cooldown,
            maximum: MAX_COOLDOWN,
        };
        if config.cooldown > MAX_COOLDOWN {
            return Err(too_long.into());
        }
        if config.cooldown < MIN_COOLDOWN && !config.danger_allow_cooldown_below_floor {
            return Err(RecoveryConfigError::CooldownTooShort {
                configured: config.cooldown,
                minimum: MIN_COOLDOWN,
            }
            .into());
        }
        let cooldown = chrono::Duration::from_std(config.cooldown).map_err(|_| too_long)?;
        let link = flow.emailed_link(&config.url_template, config.token_lifetime)?;
        Ok(Self {
            flow,
            link,
            config,
            policy: EnrollmentPolicy {
                cooldown: Some(cooldown),
                credential_cap: CredentialCap::Exempt,
            },
        })
    }

    #[tracing::instrument(
        skip(self, email, context),
        fields(method = "recovery", user_id = tracing::field::Empty),
    )]
    pub async fn request_recovery(&self, email: &str, context: SessionContext) -> Result<()> {
        let email_normalized = verification::normalize_email(email);
        verification::validate_email(&email_normalized)?;

        let rate_limits = &self.config.rate_limits;
        rate_limit::enforce_all(
            self.flow.rate_limiter().as_ref(),
            &[
                (
                    rate_limits.request_per_ip,
                    "recovery/request",
                    "ip",
                    context.ip.as_deref(),
                ),
                (
                    rate_limits.request_per_identifier,
                    "recovery/request",
                    "email",
                    Some(email_normalized.as_str()),
                ),
                (
                    rate_limits.request_per_identifier_daily,
                    "recovery/request",
                    "email_daily",
                    Some(email_normalized.as_str()),
                ),
                (
                    rate_limits.request_global,
                    "recovery/request",
                    "global",
                    Some("all"),
                ),
            ],
            || async {
                self.flow
                    .audit_recovery_failed(None, RecoveryFailureReason::RateLimited, &context)
                    .await;
            },
        )
        .await?;

        let Some(user) = self.flow.records().find_by_email(&email_normalized).await? else {
            self.flow
                .emit(
                    &context,
                    AuditEventKind::RecoveryRequested { user_id: None },
                )
                .await;
            self.flow
                .audit_recovery_failed(None, RecoveryFailureReason::UnknownEmail, &context)
                .await;
            return Ok(());
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        if user::ensure_active(&user).is_err() {
            self.flow
                .audit_recovery_failed(
                    Some(user.id),
                    RecoveryFailureReason::AccountDisabled,
                    &context,
                )
                .await;
            return Ok(());
        }

        let url = self.link.issue(user.id, ()).await?;
        let notifier = self.flow.notifier();
        notifier
            .send_best_effort(&user, "recovery link", |emails| {
                emails.recovery_email(&user, &url)
            })
            .await;
        notifier.recovery_requested(&user).await;

        self.flow
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
    pub async fn consume_recovery(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<VerificationConsumeOutcome> {
        let (user, ()) = self.link.redeem(token, &context).await?;
        let outcome = self.flow.start_enrollment(user.id, self.policy).await?;

        self.flow
            .emit(
                &context,
                AuditEventKind::RecoveryConsumed { user_id: user.id },
            )
            .await;
        tracing::info!(outcome = "consumed", "recovery token consumed");
        Ok(outcome)
    }

    pub async fn finish_recovery(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<EnrollmentOutcome> {
        let outcome = self
            .flow
            .enroll(challenge_id, response, name, context, self.policy)
            .await?;

        self.flow.notifier().recovery_completed(&outcome.user).await;

        tracing::info!(outcome = "succeeded", "recovery finished");
        Ok(outcome)
    }
}
