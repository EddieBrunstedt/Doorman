use std::sync::Arc;
use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::assembly::{AssemblyError, MAX_LIFETIME};
use crate::audit::{AuditDispatch, AuditEventKind, RecoveryFailureReason};
use crate::context::CoreDeps;
use crate::email::{self, Mailer};
use crate::email_link::TOKEN_PLACEHOLDER;
use crate::email_link_registration::{EmailLinkRegistration, Recovery};
use crate::error::Result;
use crate::passkey::{RegistrationOutcome, StartedRegistration};
use crate::passkey_registration::PasskeyRegistrations;
use crate::rate_limit::{self, RateLimitPolicy, RateLimiter};
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::SessionContext;
use crate::storage::PasskeyChallengeId;
use crate::user_records::UserRecords;

#[derive(Clone)]
pub struct RecoveryConfig {
    pub token_lifetime: Duration,
    pub url_template: String,
    pub rate_limits: RecoveryRateLimits,
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
    pub const DEFAULT_COOL_DOWN: Duration = Duration::from_secs(60 * 60 * 24);
    pub const MIN_COOL_DOWN: Duration = Duration::from_secs(60 * 60);
    pub const MAX_COOL_DOWN: Duration = MAX_LIFETIME;
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            url_template: format!("https://example.invalid/recovery?token={TOKEN_PLACEHOLDER}"),
            rate_limits: RecoveryRateLimits::default(),
            cool_down: Self::DEFAULT_COOL_DOWN,
            danger_allow_cool_down_below_floor: false,
        }
    }
}

#[derive(Clone)]
pub struct RecoveryManager {
    records: UserRecords,
    registration: EmailLinkRegistration<Recovery>,
    mailer: Mailer,
    notices: SecurityNotices,
    rate_limiter: Arc<dyn RateLimiter>,
    audit: AuditDispatch,
    config: RecoveryConfig,
}

impl RecoveryManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        registrations: PasskeyRegistrations,
        config: RecoveryConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        let too_long = RecoveryConfigError::CoolDownTooLong {
            configured: config.cool_down,
            maximum: RecoveryConfig::MAX_COOL_DOWN,
        };
        if config.cool_down > RecoveryConfig::MAX_COOL_DOWN {
            return Err(too_long.into());
        }
        if config.cool_down < RecoveryConfig::MIN_COOL_DOWN
            && !config.danger_allow_cool_down_below_floor
        {
            return Err(RecoveryConfigError::CoolDownTooShort {
                configured: config.cool_down,
                minimum: RecoveryConfig::MIN_COOL_DOWN,
            }
            .into());
        }
        let cool_down = chrono::Duration::from_std(config.cool_down).map_err(|_| too_long)?;
        Ok(Self {
            records: UserRecords::new(deps),
            registration: EmailLinkRegistration::new(
                deps,
                registrations,
                Recovery { cool_down },
                &config.url_template,
                config.token_lifetime,
            )?,
            mailer: deps.mailer.clone(),
            notices: deps.notices.clone(),
            rate_limiter: deps.rate_limiter.clone(),
            audit: deps.audit.clone(),
            config,
        })
    }

    #[tracing::instrument(
        skip(self, email, context),
        fields(method = "recovery", user_id = tracing::field::Empty),
    )]
    pub async fn request_recovery(&self, email: &str, context: SessionContext) -> Result<()> {
        let email_normalized = email::normalize_email(email);
        email::validate_email(&email_normalized)?;

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

        if !user.status.is_active() {
            self.audit
                .emit(
                    &context,
                    AuditEventKind::RecoveryFailed {
                        user_id: Some(user.id),
                        reason: RecoveryFailureReason::UserDisabled,
                    },
                )
                .await;
            return Ok(());
        }

        let url = self.registration.issue_link(user.id).await?;
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
        context: SessionContext,
    ) -> Result<RegistrationOutcome> {
        self.registration
            .finish(challenge_id, response, name, context)
            .await
    }
}
