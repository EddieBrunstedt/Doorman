//! Signup flow: email-the-link, click to register a passkey.
//!
//! The [`SignupManager`] drives the three-step path a new user takes to
//! land their first session:
//!
//! 1. [`request_signup`](SignupManager::request_signup) — the user submits
//!    an email. The manager issues a single-use, time-limited token, embeds
//!    it in a URL via the configured template, and hands the rendered email
//!    to the configured [`EmailSender`](crate::email::EmailSender). The
//!    response is identical whether or not the email is already registered,
//!    so the endpoint is not an
//!    enumeration oracle.
//! 2. [`consume_signup`](SignupManager::consume_signup) — clicking the link
//!    redeems the token atomically, marks the user's email verified, and
//!    starts a passkey registration ceremony bound to the user. The
//!    returned challenge is what the browser hands to
//!    `navigator.credentials.create`.
//! 3. [`finish_signup`](SignupManager::finish_signup) — finalises the
//!    passkey registration, sends the passkey-registered security notice,
//!    and issues a session.
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

use crate::audit::AuditEventKind;
use crate::email::{EmailTemplates, default_emails};
use crate::error::Result;
use crate::rate_limit::RateLimitPolicy;
use crate::session::SessionContext;
use crate::storage::{PasskeyChallengeId, User, UserId, VerificationPurpose};
use crate::verification::{
    self, EnrollmentFlow, EnrollmentOutcome, FlowKind, TOKEN_PLACEHOLDER,
    VerificationConsumeOutcome,
};

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
    /// Renderer for the signup email. `None` falls back to the renderer the
    /// composition root threads in (see [`AuthServiceBuilder::emails`]), and to
    /// [`DefaultEmailTemplates`](crate::email::DefaultEmailTemplates) if none was
    /// set. Set `Some(..)` to brand this flow specifically, overriding the
    /// shared renderer.
    ///
    /// [`AuthServiceBuilder::emails`]: https://docs.rs/doorman-axum
    pub emails: Option<Arc<dyn EmailTemplates>>,
}

/// Rate-limit policies for the signup request endpoint.
#[derive(Debug, Clone, Copy)]
pub struct SignupRateLimits {
    /// Limit on signup requests per client IP, or `None` to disable.
    pub request_per_ip: Option<RateLimitPolicy>,
    /// Limit on signup requests per email identifier, or `None` to disable.
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
            emails: None,
        }
    }
}

/// Manager for the three-step signup flow.
///
/// A thin wrapper over the shared [`EnrollmentFlow`]: `consume_signup` and
/// `finish_signup` delegate to it directly, and `request_signup` is the one
/// genuinely signup-specific body (provision-on-unknown-email is the
/// inverse of recovery's silent no-op).
#[derive(Clone)]
pub struct SignupManager {
    flow: EnrollmentFlow,
    config: SignupConfig,
    /// Renderer resolved from [`SignupConfig::emails`], falling back to
    /// [`DefaultEmailTemplates`](crate::email::DefaultEmailTemplates) when unset.
    emails: Arc<dyn EmailTemplates>,
}

impl SignupManager {
    /// Build the signup manager from an enrollment flow and its config.
    pub fn new(flow: EnrollmentFlow, config: SignupConfig) -> Self {
        let emails = config.emails.clone().unwrap_or_else(default_emails);
        Self {
            flow,
            config,
            emails,
        }
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

        verification::enforce_all(
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

        let now = self.flow.now();
        if let Some(existing) = self
            .flow
            .users()
            .find_user_by_email(&email_normalized)
            .await?
        {
            // Existing account: silent success preserves enumeration
            // resistance. The legitimate user falls back to passkey
            // sign-in or uses the recovery flow to enrol a new passkey.
            tracing::Span::current().record("user_id", tracing::field::display(existing.id));
            self.flow
                .emit(
                    &context,
                    AuditEventKind::SignupRequested {
                        user_id: existing.id,
                    },
                )
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
        self.flow.users().create_user(user.clone()).await?;
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        // Invalidate any prior signup tokens for the user, store a fresh
        // single-use token, and render the link URL.
        let url = verification::issue_link(
            self.flow.tokens().as_ref(),
            user.id,
            VerificationPurpose::Signup,
            None,
            self.config.token_lifetime,
            &self.config.url_template,
            now,
        )
        .await?;
        // Best-effort: a transport failure here must not become an error
        // response. The already-registered branch above returns `Ok(())` with
        // no send, so propagating a send error from this new-user branch would
        // make a bounce distinguish a fresh address from a registered one.
        let email = self.emails.signup_email(&user, &url);
        self.flow.send_best_effort(email, "signup link").await;

        self.flow
            .emit(
                &context,
                AuditEventKind::SignupRequested { user_id: user.id },
            )
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
        self.flow.consume(FlowKind::Signup, token, context).await
    }

    /// Complete a signup-time passkey registration ceremony, send the
    /// passkey-registered security notice, and issue a session. The passkey
    /// is bound to the user identified by the challenge state, so the wire
    /// shape does not need to carry a user id.
    pub async fn finish_signup(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<EnrollmentOutcome> {
        self.flow
            .finish(
                FlowKind::Signup,
                challenge_id,
                response,
                name,
                context,
                None,
                None,
            )
            .await
    }
}
