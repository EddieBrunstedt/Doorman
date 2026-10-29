use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::assembly::AssemblyError;
use crate::audit::{AuditDispatch, AuditEventKind, SignupFailureReason};
use crate::context::CoreDeps;
use crate::email::{EmailAddress, Mailer};
use crate::email_link::{Issued, LinkTemplate};
use crate::email_link_registration::{EmailLinkRegistration, RegistrationLink};
use crate::error::{Error, Result};
use crate::passkey::{RegistrationOutcome, StartedRegistration};
use crate::passkey_registration::PasskeyRegistrations;
use crate::rate_limit::{Attempt, RateLimitEnforcer};
use crate::session::{RequestTransport, SessionContext};
use crate::storage::{PasskeyChallengeId, User};
use crate::user_records::{OwnerRefusal, UserRecords};

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
    pub policy: Arc<dyn SignupPolicy>,
}

impl SignupConfig {
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
}

impl Default for SignupConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            policy: Arc::new(OpenSignupPolicy),
        }
    }
}

#[derive(Clone)]
pub struct SignupManager {
    records: UserRecords,
    registration: EmailLinkRegistration,
    mailer: Mailer,
    rate_limits: RateLimitEnforcer,
    audit: AuditDispatch,
    config: SignupConfig,
}

impl SignupManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        registrations: PasskeyRegistrations,
        template: LinkTemplate,
        config: SignupConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        Ok(Self {
            records: UserRecords::new(deps),
            registration: EmailLinkRegistration::new(
                deps,
                registrations,
                RegistrationLink::Signup,
                template,
                config.token_lifetime,
            )?,
            mailer: deps.mailer.clone(),
            rate_limits: deps.rate_limits.clone(),
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
        let address = EmailAddress::parse(email)?;

        self.rate_limits
            .enforce(&context, Attempt::SignupRequest { email: &address })
            .await?;

        match self
            .config
            .policy
            .evaluate(address.as_str(), invite_token, &context)
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

        let Some(user) = self.find_or_create(&address).await? else {
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
                        SignupFailureReason::UserDisabled
                    }
                    OwnerRefusal::WrongSignupStage => SignupFailureReason::SignupFinished,
                };
                self.audit
                    .emit(
                        &context,
                        AuditEventKind::SignupFailed {
                            user_id: user.id,
                            reason,
                        },
                    )
                    .await;
                tracing::info!(outcome = "refused", reason = ?reason, "signup request (silent)");
                return Ok(());
            }
        };
        self.send_link(&user, &url, &context).await;
        tracing::info!(outcome = "sent", "signup email sent");
        Ok(())
    }

    // `None` when a concurrent request created the user and it was gone again by the time this one
    // looked.
    async fn find_or_create(&self, address: &EmailAddress) -> Result<Option<User>> {
        let records = &self.records;
        if let Some(existing) = records.find_by_email(address).await? {
            return Ok(Some(existing));
        }
        match records.create(address).await? {
            Some(user) => Ok(Some(user)),
            None => records.find_by_email(address).await,
        }
    }

    async fn send_link(&self, user: &User, url: &str, context: &SessionContext) {
        self.mailer
            .send_best_effort(user, "signup link", |templates| {
                templates.signup_email(user, url)
            })
            .await;
        self.audit
            .emit(
                context,
                AuditEventKind::SignupRequested { user_id: user.id },
            )
            .await;
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
        transport: RequestTransport,
        context: SessionContext,
    ) -> Result<RegistrationOutcome> {
        self.registration
            .finish(challenge_id, response, name, transport, context)
            .await
    }
}
