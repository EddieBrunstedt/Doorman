use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::assembly::AssemblyError;
use crate::audit::AuditEventKind;
use crate::error::{Error, Result};
use crate::link::{self, EmailedLink};
use crate::passkey::{CredentialCap, EnrollmentPolicy};
use crate::rate_limit::{self, RateLimitPolicy};
use crate::session::SessionContext;
use crate::storage::{PasskeyChallengeId, User};
use crate::verification::{
    self, EnrollmentFlow, EnrollmentOutcome, TOKEN_PLACEHOLDER, VerificationConsumeOutcome,
};

#[derive(Debug, Clone)]
pub enum SignupDecision {
    Allow,
    DenySilently,
    Deny { reason: Option<String> },
}

#[async_trait]
pub trait SignupPolicy: Send + Sync {
    async fn evaluate(
        &self,
        email: &str,
        invite_token: Option<&str>,
        context: &SessionContext,
    ) -> Result<SignupDecision>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OpenSignupPolicy;

#[async_trait]
impl SignupPolicy for OpenSignupPolicy {
    async fn evaluate(
        &self,
        _email: &str,
        _invite_token: Option<&str>,
        _context: &SessionContext,
    ) -> Result<SignupDecision> {
        Ok(SignupDecision::Allow)
    }
}

#[derive(Clone)]
pub struct SignupConfig {
    pub token_lifetime: Duration,
    pub url_template: String,
    pub rate_limits: SignupRateLimits,
    pub policy: Arc<dyn SignupPolicy>,
}

#[derive(Debug, Clone, Copy)]
pub struct SignupRateLimits {
    pub request_per_ip: Option<RateLimitPolicy>,
    pub request_per_identifier: Option<RateLimitPolicy>,
}

impl SignupRateLimits {
    pub const DEFAULT_PER_IP: RateLimitPolicy =
        RateLimitPolicy::new(5, Duration::from_secs(60 * 60));
    pub const DEFAULT_PER_IDENTIFIER: RateLimitPolicy =
        RateLimitPolicy::new(3, Duration::from_secs(60 * 60));

    pub const fn disabled() -> Self {
        Self {
            request_per_ip: None,
            request_per_identifier: None,
        }
    }
}

impl Default for SignupRateLimits {
    fn default() -> Self {
        Self {
            request_per_ip: Some(Self::DEFAULT_PER_IP),
            request_per_identifier: Some(Self::DEFAULT_PER_IDENTIFIER),
        }
    }
}

impl SignupConfig {
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
}

impl Default for SignupConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            url_template: format!("https://example.invalid/signup?token={TOKEN_PLACEHOLDER}"),
            rate_limits: SignupRateLimits::default(),
            policy: Arc::new(OpenSignupPolicy),
        }
    }
}

const SIGNUP_POLICY: EnrollmentPolicy = EnrollmentPolicy {
    cooldown: None,
    credential_cap: CredentialCap::Enforce,
};

#[derive(Clone)]
pub struct SignupManager {
    flow: EnrollmentFlow,
    link: EmailedLink<link::Signup>,
    config: SignupConfig,
}

impl SignupManager {
    pub(crate) fn new(
        flow: EnrollmentFlow,
        config: SignupConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        let link = flow.emailed_link(&config.url_template, config.token_lifetime)?;
        Ok(Self { flow, link, config })
    }

    #[tracing::instrument(
        skip(self, email, invite_token, context),
        fields(method = "signup", user_id = tracing::field::Empty),
    )]
    pub async fn request_signup(
        &self,
        email: &str,
        invite_token: Option<&str>,
        context: SessionContext,
    ) -> Result<()> {
        let email_normalized = verification::normalize_email(email);
        verification::validate_email(&email_normalized)?;

        rate_limit::enforce_all(
            self.flow.rate_limiter().as_ref(),
            &[
                (
                    self.config.rate_limits.request_per_ip,
                    "signup/request",
                    "ip",
                    context.ip.as_deref(),
                ),
                (
                    self.config.rate_limits.request_per_identifier,
                    "signup/request",
                    "email",
                    Some(email_normalized.as_str()),
                ),
            ],
            || async {},
        )
        .await?;

        match self
            .config
            .policy
            .evaluate(&email_normalized, invite_token, &context)
            .await?
        {
            SignupDecision::Allow => {}
            SignupDecision::DenySilently => {
                self.flow.emit(&context, AuditEventKind::SignupDenied).await;
                tracing::info!(outcome = "denied_silent", "signup request denied");
                return Ok(());
            }
            SignupDecision::Deny { reason } => {
                self.flow.emit(&context, AuditEventKind::SignupDenied).await;
                tracing::info!(outcome = "denied", reason = ?reason, "signup request denied");
                return Err(Error::SignupNotAllowed);
            }
        }

        let records = self.flow.records();
        if let Some(existing) = records.find_by_email(&email_normalized).await? {
            return self.request_for_existing(&existing, &context).await;
        }
        let Some(user) = records.create_unverified(&email_normalized).await? else {
            return match records.find_by_email(&email_normalized).await? {
                Some(existing) => self.request_for_existing(&existing, &context).await,
                None => Ok(()),
            };
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        self.send_link(&user, &context).await?;
        tracing::info!(outcome = "sent", "signup email sent");
        Ok(())
    }

    async fn request_for_existing(&self, existing: &User, context: &SessionContext) -> Result<()> {
        tracing::Span::current().record("user_id", tracing::field::display(existing.id));

        if !self.flow.has_passkey(existing.id).await? {
            self.send_link(existing, context).await?;
            tracing::info!(
                outcome = "reissued",
                "signup email re-sent to passkey-less user"
            );
            return Ok(());
        }

        self.flow
            .emit(
                context,
                AuditEventKind::SignupRequested {
                    user_id: existing.id,
                },
            )
            .await;
        tracing::info!(outcome = "already_registered", "signup request (silent)");
        Ok(())
    }

    async fn send_link(&self, user: &User, context: &SessionContext) -> Result<()> {
        let url = self.link.issue(user.id, ()).await?;
        self.flow
            .notifier()
            .send_best_effort(user, "signup link", |emails| {
                emails.signup_email(user, &url)
            })
            .await;
        self.flow
            .emit(
                context,
                AuditEventKind::SignupRequested { user_id: user.id },
            )
            .await;
        Ok(())
    }

    #[tracing::instrument(
        skip(self, token, context),
        fields(method = "signup", user_id = tracing::field::Empty),
    )]
    pub async fn consume_signup(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<VerificationConsumeOutcome> {
        let (user, ()) = self.link.redeem(token, &context).await?;
        self.flow.records().mark_email_verified(&user).await?;
        let outcome = self.flow.start_enrollment(user.id, SIGNUP_POLICY).await?;

        self.flow
            .emit(
                &context,
                AuditEventKind::SignupConsumed { user_id: user.id },
            )
            .await;
        tracing::info!(outcome = "consumed", "signup token consumed");
        Ok(outcome)
    }

    pub async fn finish_signup(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<EnrollmentOutcome> {
        let outcome = self
            .flow
            .enroll(challenge_id, response, name, context, SIGNUP_POLICY)
            .await?;
        tracing::info!(outcome = "succeeded", "signup finished");
        Ok(outcome)
    }
}
