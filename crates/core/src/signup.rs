//! Signup flow: email-the-link, click to register a passkey.
//!
//! The [`SignupManager`] drives the three-step path a new user takes to
//! land their first session:
//!
//! 1. [`request_signup`](SignupManager::request_signup) — the user submits
//!    an email. The manager issues a single-use, time-limited token, embeds
//!    it in a URL via the configured template, and hands the rendered email
//!    to the configured [`EmailSender`]. The response is identical whether
//!    or not the email is already registered, so the endpoint is not an
//!    enumeration oracle.
//! 2. [`consume_signup`](SignupManager::consume_signup) — clicking the link
//!    redeems the token atomically, marks the user's email verified, and
//!    starts a passkey registration ceremony bound to the user. The
//!    returned challenge is what the browser hands to
//!    `navigator.credentials.create`.
//! 3. [`finish_signup`](SignupManager::finish_signup) — finalises the
//!    passkey registration and issues a session.
//!
//! No session is issued from the email click alone. A passkey is always
//! interposed, so the steady-state login path stays phishing-resistant.
//!
//! Recovery uses a sibling primitive; the two flows deliberately use
//! distinct token purposes so a leaked link of one kind cannot be redeemed
//! as the other.

use std::sync::Arc;
use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::audit::{AuditEvent, AuditEventKind, AuditSink};
use crate::clock::Clock;
use crate::email::{BauthEmails, EmailSender, default_emails};
use crate::error::{Error, Result};
use crate::passkey::PasskeyManager;
use crate::rate_limit::{RateLimitPolicy, RateLimiter};
use crate::session::{SessionContext, SessionManager, hash_token};
use crate::storage::{
    PasskeyChallengeId, User, UserId, UserStore, VerificationPurpose, VerificationTokenStore,
};
use crate::verification::{self, EnrollmentOutcome, TOKEN_PLACEHOLDER, VerificationConsumeOutcome};

/// Configuration for issuing and consuming signup tokens.
#[derive(Clone)]
pub struct SignupConfig {
    /// Token lifetime. Short by design — the link, once clicked, is the
    /// only thing standing between the visitor and registering a passkey
    /// against the email address. A stale link sitting in an inbox is a
    /// takeover vector.
    pub token_lifetime: Duration,
    /// URL template used in signup emails. The literal substring `{token}`
    /// is replaced with the generated token at send time.
    pub url_template: String,
    /// Rate-limit policies applied to the request endpoint. Both the
    /// per-IP and per-identifier policies are checked; both must clear
    /// for the request to proceed.
    pub rate_limits: SignupRateLimits,
    /// Renderer for the signup email. Defaults to
    /// [`DefaultBauthEmails`](crate::email::DefaultBauthEmails); hosts that
    /// want branded copy override this with an [`Arc<dyn BauthEmails>`].
    pub emails: Arc<dyn BauthEmails>,
}

/// Rate-limit policies for the signup request endpoint.
#[derive(Debug, Clone, Copy)]
pub struct SignupRateLimits {
    pub request_per_ip: Option<RateLimitPolicy>,
    pub request_per_identifier: Option<RateLimitPolicy>,
}

impl SignupRateLimits {
    /// Turn off every policy. Equivalent to wiring a
    /// [`NoopRateLimiter`](crate::rate_limit::NoopRateLimiter) but keeps
    /// the limiter free of fan-out on hot paths.
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
            request_per_ip: Some(RateLimitPolicy::new(5, Duration::from_secs(60 * 60))),
            request_per_identifier: Some(RateLimitPolicy::new(3, Duration::from_secs(60 * 60))),
        }
    }
}

impl Default for SignupConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Duration::from_secs(60 * 15),
            url_template: format!("https://example.invalid/signup?token={TOKEN_PLACEHOLDER}"),
            rate_limits: SignupRateLimits::default(),
            emails: default_emails(),
        }
    }
}

/// Manager for the three-step signup flow.
#[derive(Clone)]
pub struct SignupManager {
    users: Arc<dyn UserStore>,
    tokens: Arc<dyn VerificationTokenStore>,
    passkey: PasskeyManager,
    sessions: SessionManager,
    email: Arc<dyn EmailSender>,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    rate_limiter: Arc<dyn RateLimiter>,
    config: SignupConfig,
}

impl SignupManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserStore>,
        tokens: Arc<dyn VerificationTokenStore>,
        passkey: PasskeyManager,
        sessions: SessionManager,
        email: Arc<dyn EmailSender>,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        rate_limiter: Arc<dyn RateLimiter>,
        config: SignupConfig,
    ) -> Self {
        Self {
            users,
            tokens,
            passkey,
            sessions,
            email,
            clock,
            audit,
            rate_limiter,
            config,
        }
    }

    /// Diagnostic accessor used by the axum builder's startup warnings
    /// to detect dev-only email transports without exposing the
    /// underlying `Arc<dyn EmailSender>`.
    #[doc(hidden)]
    pub fn email_kind(&self) -> crate::email::EmailSenderKind {
        self.email.diagnostic_kind()
    }

    /// Issue a signup link to `email`. Returns `Ok(())` regardless of
    /// whether the email is already registered, so the endpoint cannot be
    /// used to enumerate accounts. When the email is registered we audit
    /// the attempt and silently no-op; when it is not, we provision a new
    /// (unverified) user, store a single-use token, and email the link.
    #[tracing::instrument(
        skip(self, email, context),
        fields(method = "signup", user_id = tracing::field::Empty),
    )]
    pub async fn request_signup(&self, email: &str, context: SessionContext) -> Result<()> {
        let email_normalized = verification::normalize_email(email);
        verification::validate_email(&email_normalized)?;

        verification::enforce_rate_limit(
            self.rate_limiter.as_ref(),
            self.config.rate_limits.request_per_ip,
            "signup/request/ip",
            context.ip.as_deref(),
        )
        .await?;
        verification::enforce_rate_limit(
            self.rate_limiter.as_ref(),
            self.config.rate_limits.request_per_identifier,
            "signup/request/email",
            Some(email_normalized.as_str()),
        )
        .await?;

        let now = self.clock.now();
        if let Some(existing) = self.users.find_user_by_email(&email_normalized).await? {
            // Existing account: silent success preserves enumeration
            // resistance. The legitimate user falls back to passkey
            // sign-in or uses the recovery flow to enrol a new passkey.
            tracing::Span::current().record("user_id", tracing::field::display(existing.id));
            self.audit
                .emit(AuditEvent {
                    timestamp: now,
                    ip: context.ip,
                    user_agent: context.user_agent,
                    kind: AuditEventKind::SignupRequested {
                        user_id: existing.id,
                    },
                })
                .await;
            tracing::info!(outcome = "already_registered", "signup request (silent)");
            return Ok(());
        }

        let user = User {
            id: UserId::new(),
            email: Some(email_normalized.clone()),
            email_verified_at: None,
            created_at: now,
            updated_at: now,
        };
        self.users.create_user(user.clone()).await?;
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        // Invalidate any prior signup tokens for the user, store a fresh
        // single-use token, and render the link URL.
        let url = verification::issue_link(
            self.tokens.as_ref(),
            user.id,
            VerificationPurpose::Signup,
            self.config.token_lifetime,
            &self.config.url_template,
            now,
        )
        .await?;
        let email = self.config.emails.signup_email(&user, &url);
        self.email.send(email).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::SignupRequested { user_id: user.id },
            })
            .await;
        tracing::info!(outcome = "sent", "signup email sent");
        Ok(())
    }

    /// Redeem a signup token and start a passkey registration ceremony.
    /// The token is atomically consumed (so the same link cannot be
    /// replayed); the user's email is marked verified by the click; and
    /// the returned [`VerificationConsumeOutcome`] carries the registration
    /// challenge for the browser.
    #[tracing::instrument(
        skip(self, token, context),
        fields(method = "signup", user_id = tracing::field::Empty),
    )]
    pub async fn consume_signup(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<VerificationConsumeOutcome> {
        let hash = hash_token(token);
        let now = self.clock.now();
        let Some(record) = self
            .tokens
            .consume_token(&hash, VerificationPurpose::Signup)
            .await?
        else {
            tracing::warn!(outcome = "invalid_token", "signup consume failed");
            return Err(Error::InvalidVerificationToken);
        };
        if record.expires_at <= now {
            tracing::warn!(outcome = "expired_token", "signup consume failed");
            return Err(Error::InvalidVerificationToken);
        }
        let Some(mut user) = self.users.find_user_by_id(record.user_id).await? else {
            tracing::warn!(outcome = "user_not_found", "signup consume failed");
            return Err(Error::UserNotFound);
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        if user.email_verified_at.is_none() {
            // Clicking a link sent to the address proves ownership.
            user.email_verified_at = Some(now);
            user.updated_at = now;
            self.users.update_user(user.clone()).await?;
        }

        let (challenge_id, options) = self.passkey.start_registration(user.id).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::SignupConsumed { user_id: user.id },
            })
            .await;
        tracing::info!(outcome = "consumed", "signup token consumed");
        Ok(VerificationConsumeOutcome {
            challenge_id,
            options,
        })
    }

    /// Complete a signup-time passkey registration ceremony and issue a
    /// session. The passkey is bound to the user identified by the
    /// challenge state, so the wire shape does not need to carry a user id.
    pub async fn finish_signup(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<EnrollmentOutcome> {
        let passkey = self
            .passkey
            .finish_registration(challenge_id, response, name, context.clone())
            .await?;
        let Some(user) = self.users.find_user_by_id(passkey.user_id).await? else {
            return Err(Error::UserNotFound);
        };
        let session = self.sessions.create(user.id, context.clone()).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::LoginSucceeded { user_id: user.id },
            })
            .await;
        tracing::info!(outcome = "succeeded", "signup finished");
        Ok(EnrollmentOutcome {
            user,
            session,
            passkey,
        })
    }
}
