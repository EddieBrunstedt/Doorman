use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::assembly::AssemblyError;
use crate::audit::{AuditDispatch, AuditEventKind};
use crate::context::CoreDeps;
use crate::email::{self, Mailer};
use crate::email_link::TOKEN_PLACEHOLDER;
use crate::email_link_registration::{EmailLinkRegistration, RegistrationLink};
use crate::error::{Error, Result};
use crate::passkey::{RegistrationOutcome, StartedRegistration};
use crate::passkey_registration::PasskeyRegistrations;
use crate::rate_limit::{self, RateLimitPolicy, RateLimiter};
use crate::session::SessionContext;
use crate::storage::{PasskeyChallengeId, PasskeyStore, User};
use crate::user_records::UserRecords;

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

#[derive(Clone)]
pub struct SignupManager {
    passkeys: Arc<dyn PasskeyStore>,
    records: UserRecords,
    registration: EmailLinkRegistration,
    mailer: Mailer,
    rate_limiter: Arc<dyn RateLimiter>,
    audit: AuditDispatch,
    config: SignupConfig,
}

impl SignupManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        registrations: PasskeyRegistrations,
        config: SignupConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        Ok(Self {
            passkeys: deps.passkeys.clone(),
            records: UserRecords::new(deps),
            registration: EmailLinkRegistration::new(
                deps,
                registrations,
                RegistrationLink::Signup,
                &config.url_template,
                config.token_lifetime,
            )?,
            mailer: deps.mailer.clone(),
            rate_limiter: deps.rate_limiter.clone(),
            audit: deps.audit.clone(),
            config,
        })
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
        let email_normalized = email::normalize_email(email);
        email::validate_email(&email_normalized)?;

        rate_limit::enforce_all(
            self.rate_limiter.as_ref(),
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
                self.audit
                    .emit(&context, AuditEventKind::SignupDenied)
                    .await;
                tracing::info!(outcome = "denied_silent", "signup request denied");
                return Ok(());
            }
            SignupDecision::Deny { reason } => {
                self.audit
                    .emit(&context, AuditEventKind::SignupDenied)
                    .await;
                tracing::info!(outcome = "denied", reason = ?reason, "signup request denied");
                return Err(Error::SignupNotAllowed);
            }
        }

        let records = &self.records;
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

        if self
            .passkeys
            .list_passkeys_for_user(existing.id)
            .await?
            .is_empty()
        {
            self.send_link(existing, context).await?;
            tracing::info!(
                outcome = "reissued",
                "signup email re-sent to passkey-less user"
            );
            return Ok(());
        }

        self.audit
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
        let url = self.registration.issue_link(user.id).await?;
        self.mailer
            .send_best_effort(user, "signup link", |templates| {
                templates.signup_email(user, &url)
            })
            .await;
        self.audit
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
    pub async fn redeem_signup_link(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<StartedRegistration> {
        self.registration.redeem(token, context).await
    }

    #[tracing::instrument(
        skip(self, response, name, context),
        fields(method = "signup", user_id = tracing::field::Empty),
    )]
    pub async fn finish_signup(
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
