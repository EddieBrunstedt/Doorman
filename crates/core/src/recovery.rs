use std::sync::Arc;
use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::assembly::{AssemblyError, MAX_LIFETIME};
use crate::audit::{AuditDispatch, AuditEventKind, RecoveryFailureReason};
use crate::context::CoreDeps;
use crate::email::SecurityEmailNotifier;
use crate::error::Result;
use crate::link::{self, EmailedLink};
use crate::passkey::{EmailLinkRegistration, PasskeyManager, RegistrationOutcome};
use crate::rate_limit::{self, RateLimitPolicy, RateLimiter};
use crate::session::SessionContext;
use crate::storage::PasskeyChallengeId;
use crate::user::{self, UserRecords};
use crate::verification::{self, TOKEN_PLACEHOLDER, VerificationConsumeOutcome};

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
    passkeys: PasskeyManager,
    records: UserRecords,
    link: EmailedLink<link::Recovery>,
    notifier: SecurityEmailNotifier,
    rate_limiter: Arc<dyn RateLimiter>,
    audit: AuditDispatch,
    config: RecoveryConfig,
    registration: EmailLinkRegistration,
}

impl RecoveryManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        passkeys: PasskeyManager,
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
        Ok(Self {
            passkeys,
            records: UserRecords::new(deps),
            link: EmailedLink::new(deps, &config.url_template, config.token_lifetime)?,
            notifier: deps.notifier.clone(),
            rate_limiter: deps.rate_limiter.clone(),
            audit: deps.audit.clone(),
            config,
            registration: EmailLinkRegistration::Recovery { cooldown },
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
            self.rate_limiter.as_ref(),
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
                self.audit
                    .emit(
                        &context,
                        AuditEventKind::RecoveryFailed {
                            user_id: None,
                            reason: RecoveryFailureReason::RateLimited,
                        },
                    )
                    .await;
            },
        )
        .await?;

        let Some(user) = self.records.find_by_email(&email_normalized).await? else {
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

        if user::ensure_active(&user).is_err() {
            self.audit
                .emit(
                    &context,
                    AuditEventKind::RecoveryFailed {
                        user_id: Some(user.id),
                        reason: RecoveryFailureReason::AccountDisabled,
                    },
                )
                .await;
            return Ok(());
        }

        let url = self.link.issue(user.id, ()).await?;
        self.notifier
            .send_best_effort(&user, "recovery link", |emails| {
                emails.recovery_email(&user, &url)
            })
            .await;
        self.notifier.recovery_requested(&user).await;

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
    pub async fn consume_recovery(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<VerificationConsumeOutcome> {
        let (user, ()) = self.link.redeem(token, &context).await?;
        let (challenge_id, options) = self
            .passkeys
            .start_email_link_registration(user.id, self.registration)
            .await?;

        self.audit
            .emit(
                &context,
                AuditEventKind::RecoveryConsumed { user_id: user.id },
            )
            .await;
        tracing::info!(outcome = "consumed", "recovery token consumed");
        Ok(VerificationConsumeOutcome {
            challenge_id,
            options,
        })
    }

    pub async fn finish_recovery(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<RegistrationOutcome> {
        let outcome = self
            .passkeys
            .finish_email_link_registration(
                challenge_id,
                response,
                name,
                context,
                self.registration,
            )
            .await?;

        self.notifier.recovery_completed(&outcome.user).await;

        tracing::info!(outcome = "succeeded", "recovery finished");
        Ok(outcome)
    }
}
