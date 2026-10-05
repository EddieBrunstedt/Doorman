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
//!    so the endpoint is not an enumeration oracle.
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

use async_trait::async_trait;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::audit::AuditEventKind;
use crate::error::{Error, Result};
use crate::rate_limit::RateLimitPolicy;
use crate::session::SessionContext;
use crate::storage::{PasskeyChallengeId, VerificationPurpose};
use crate::verification::{
    self, EnrollmentFlow, EnrollmentOutcome, FlowKind, TOKEN_PLACEHOLDER,
    VerificationConsumeOutcome,
};

/// Outcome of a [`SignupPolicy`] evaluation. The host chooses how a rejected
/// signup behaves on the wire.
#[derive(Debug, Clone)]
pub enum SignupDecision {
    /// Proceed with the signup request.
    Allow,
    /// Reject, but return the same success the endpoint returns for an allowed
    /// request (HTTP 204 / `Ok(())`). No link is sent and no user is created.
    /// Preserves enumeration resistance at the cost of inviteless-UX feedback.
    DenySilently,
    /// Reject with a typed error ([`Error::SignupNotAllowed`] → HTTP 403). The
    /// `reason` is recorded for the host's logs/audit and is *not* exposed on
    /// the wire.
    Deny {
        /// Host-supplied rationale recorded at the denial site (logs/audit).
        /// Never carried onto the wire, so it is safe to put account-specific
        /// detail here.
        reason: Option<String>,
    },
}

/// Host hook deciding whether a signup attempt may proceed.
///
/// doorman supplies the normalized email, the opaque host-defined invite token
/// (if any — doorman never interprets it), and the request [`SessionContext`].
/// The host owns any allowlist / invite store. Returning `Err` (e.g. a store
/// failure) aborts the request and surfaces as a server error.
///
/// The gate runs **after** rate limiting and **before** any user is
/// provisioned: a denied attempt still spends rate-limit budget (so a host
/// invite-store lookup cannot be hammered unthrottled) but never creates a
/// [`User`](crate::storage::User) row.
#[async_trait]
pub trait SignupPolicy: Send + Sync {
    /// Decide whether the signup attempt described by `email` / `invite_token`
    /// / `context` may proceed.
    async fn evaluate(
        &self,
        email: &str,
        invite_token: Option<&str>,
        context: &SessionContext,
    ) -> Result<SignupDecision>;
}

/// Default policy: every signup is allowed. Wired unless the host overrides it,
/// so out of the box signup stays open exactly as before.
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
    /// Host gate deciding whether a signup may proceed. Defaults to
    /// [`OpenSignupPolicy`] (open signup); override it to wire an allowlist /
    /// invite store.
    pub policy: Arc<dyn SignupPolicy>,
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
    /// Default per-IP policy: 5 signup requests per IP per hour.
    pub const DEFAULT_PER_IP: RateLimitPolicy =
        RateLimitPolicy::new(5, Duration::from_secs(60 * 60));
    /// Default per-identifier policy: 3 signup requests per email per hour.
    pub const DEFAULT_PER_IDENTIFIER: RateLimitPolicy =
        RateLimitPolicy::new(3, Duration::from_secs(60 * 60));

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
    /// Default: 5 requests per IP per hour ([`DEFAULT_PER_IP`]) and 3 per
    /// email per hour ([`DEFAULT_PER_IDENTIFIER`]). The host overrides either
    /// field via struct-update syntax; pass [`disabled`] to turn both off.
    ///
    /// [`DEFAULT_PER_IP`]: SignupRateLimits::DEFAULT_PER_IP
    /// [`DEFAULT_PER_IDENTIFIER`]: SignupRateLimits::DEFAULT_PER_IDENTIFIER
    /// [`disabled`]: SignupRateLimits::disabled
    fn default() -> Self {
        Self {
            request_per_ip: Some(Self::DEFAULT_PER_IP),
            request_per_identifier: Some(Self::DEFAULT_PER_IDENTIFIER),
        }
    }
}

impl SignupConfig {
    /// Default signup-token lifetime: 15 minutes. Short by design — see
    /// [`SignupConfig::token_lifetime`].
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
}

impl Default for SignupConfig {
    /// Default: a 15-minute token lifetime ([`DEFAULT_TOKEN_LIFETIME`]), the
    /// default [`SignupRateLimits`], a placeholder `example.invalid` URL
    /// template (the host must override this), and the open
    /// [`OpenSignupPolicy`] (every signup allowed).
    ///
    /// [`DEFAULT_TOKEN_LIFETIME`]: SignupConfig::DEFAULT_TOKEN_LIFETIME
    fn default() -> Self {
        Self {
            token_lifetime: Self::DEFAULT_TOKEN_LIFETIME,
            url_template: format!("https://example.invalid/signup?token={TOKEN_PLACEHOLDER}"),
            rate_limits: SignupRateLimits::default(),
            policy: Arc::new(OpenSignupPolicy),
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
}

impl SignupManager {
    /// Build the signup manager from an enrollment flow and its config. The
    /// email renderer comes from the [`EnrollmentFlow`] (and thus the shared
    /// [`CoreDeps`](crate::context::CoreDeps)).
    pub fn new(flow: EnrollmentFlow, config: SignupConfig) -> Self {
        Self { flow, config }
    }

    /// Issue a signup link to `email`. Returns `Ok(())` regardless of
    /// whether the email is already registered, so the endpoint cannot be
    /// used to enumerate accounts. When the email is unregistered we
    /// provision a new (unverified) user, store a single-use token, and
    /// email the link. When it is registered but the account holds zero
    /// credentials — a botched or abandoned first enrollment — we re-issue a
    /// fresh signup link rather than forcing the user into recovery. Only a
    /// registered account with at least one credential audits the attempt
    /// and silently no-ops.
    ///
    /// `invite_token` is an optional, opaque, host-defined value handed
    /// verbatim to the configured [`SignupPolicy`]. doorman never parses,
    /// validates, stores, or consumes it, and treats it as a secret in
    /// transit (it is redacted from tracing).
    ///
    /// The configured [`SignupPolicy`] gate runs after rate limiting and
    /// before any user lookup or provisioning:
    /// [`SignupDecision::DenySilently`] returns the same `Ok(())` an allowed
    /// request returns (no link, no user); [`SignupDecision::Deny`] returns
    /// [`Error::SignupNotAllowed`]; a policy `Err` propagates unchanged.
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

        // Host signup gate. Runs after rate limiting (a denied attempt still
        // spends budget, so a host invite-store lookup cannot be hammered) and
        // before any user lookup or provisioning (a denied email never creates
        // a row). The invite token is passed verbatim and never interpreted.
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

        let now = self.flow.now();
        if let Some(existing) = self.flow.records().find_by_email(&email_normalized).await? {
            tracing::Span::current().record("user_id", tracing::field::display(existing.id));

            // A user row with zero credentials never finished its first
            // enrollment (a botched first passkey, or a user who deleted their
            // last one). Forcing them into recovery — and its cooldown — for
            // what is still a first enrollment is wrong, so re-issue a fresh
            // signup link instead of silently no-opping. The response shape is
            // unchanged (`Ok(())` + best-effort send), so sending to a
            // zero-credential existing address stays observationally identical
            // to a brand-new signup and adds no enumeration oracle.
            let credential_count = self
                .flow
                .credentials()
                .list_passkey_summaries_for_user(existing.id)
                .await?
                .len();
            if credential_count == 0 {
                // Same invalidate-prior / store-fresh / send path the
                // new-user branch below takes. The signup-request rate limit
                // enforced above already covers this send, so it cannot be
                // used to email-bomb the address.
                let url = verification::issue_link(
                    self.flow.tokens().as_ref(),
                    existing.id,
                    VerificationPurpose::Signup,
                    None,
                    self.config.token_lifetime,
                    &self.config.url_template,
                    now,
                )
                .await?;
                let email = self.flow.emails().signup_email(&existing, &url);
                self.flow.send_best_effort(email, "signup link").await;
                self.flow
                    .emit(
                        &context,
                        AuditEventKind::SignupRequested {
                            user_id: existing.id,
                        },
                    )
                    .await;
                tracing::info!(
                    outcome = "reissued",
                    "signup email re-sent to passkey-less user"
                );
                return Ok(());
            }

            // Existing account with at least one credential: silent success
            // preserves enumeration resistance. The legitimate user falls back
            // to passkey sign-in or uses the recovery flow to enrol a new
            // passkey.
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

        let user = self
            .flow
            .records()
            .create_unverified(&email_normalized)
            .await?;
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
        let email = self.flow.emails().signup_email(&user, &url);
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
            )
            .await
    }
}
