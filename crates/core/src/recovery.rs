//! Recovery flow: email-the-link, click to enrol a new passkey.
//!
//! The [`RecoveryManager`] drives the three-step path a user takes when
//! they have lost access to every registered passkey:
//!
//! 1. [`request_recovery`](RecoveryManager::request_recovery) — the user
//!    submits an email. The response is identical whether or not the
//!    email resolves to a registered account, so the endpoint cannot be
//!    used to enumerate users. When the email **is** registered we send
//!    the recovery link _and_ a separate requested-recovery notification
//!    so the legitimate inbox owner sees that recovery was just initiated.
//! 2. [`consume_recovery`](RecoveryManager::consume_recovery) — clicking
//!    the link atomically redeems the single-use token and starts a
//!    passkey registration ceremony bound to the user. The browser hands
//!    the returned challenge to `navigator.credentials.create`.
//! 3. [`finish_recovery`](RecoveryManager::finish_recovery) — finalises
//!    the passkey registration and issues a session. On success the user
//!    gets the passkey-registered security notice plus a completed-recovery
//!    notification so they see that recovery completed and a new passkey
//!    was enrolled.
//!
//! No session is issued from the email click alone. A passkey is always
//! interposed; an attacker who phishes the link still has to leave a
//! visible credential on the user's authenticator list. The resulting
//! session carries a post-recovery cool-down (24h by default) that blocks
//! destructive auth actions while the legitimate user has time to react.

use std::sync::Arc;
use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::audit::{AuditEventKind, RecoveryFailureReason};
use crate::email::{BauthEmails, default_emails};
use crate::error::Result;
use crate::rate_limit::RateLimitPolicy;
use crate::session::SessionContext;
use crate::storage::{PasskeyChallengeId, VerificationPurpose};
use crate::verification::{
    self, EnrollmentFlow, EnrollmentOutcome, FlowKind, TOKEN_PLACEHOLDER,
    VerificationConsumeOutcome,
};

/// Configuration for issuing and consuming recovery tokens.
#[derive(Clone)]
pub struct RecoveryConfig {
    /// Token lifetime. Short by design — the link, once clicked, is the
    /// only thing standing between the visitor and registering a passkey
    /// on the account. A stale link sitting in an inbox is a takeover
    /// vector.
    pub token_lifetime: Duration,
    /// URL template used in recovery emails. The literal substring
    /// `{token}` is replaced with the generated token at send time.
    pub url_template: String,
    /// Rate-limit policies applied to the recovery request endpoint.
    /// The per-IP and per-identifier policies are independent and any
    /// non-`None` policy is enforced. Aggressive defaults are applied; see
    /// [`RecoveryRateLimits::default`].
    pub rate_limits: RecoveryRateLimits,
    /// Renderer for the recovery emails. Defaults to
    /// [`DefaultBauthEmails`](crate::email::DefaultBauthEmails); hosts
    /// override this for branded copy.
    pub emails: Arc<dyn BauthEmails>,
    /// Length of the post-recovery cool-down applied to the session
    /// issued by `finish_recovery`. While the cool-down is active the
    /// host's destructive surfaces (delete passkey, revoke other sessions
    /// — see [`crate::error::Error::RecoveryCooldownActive`]) refuse to
    /// run from that session. Floor of one hour enforced by
    /// [`RecoveryManager::new`].
    pub cooldown: Duration,
}

/// Minimum permitted [`RecoveryConfig::cooldown`]. Set well below the 24h
/// default so hosts have room to shorten the window in tests and local
/// development, but high enough that a real deployment cannot accidentally
/// disable the property.
pub const MIN_COOLDOWN: Duration = Duration::from_secs(60 * 60);

/// Rate-limit policies for the recovery request endpoint. The consume
/// endpoint is gated by single-use token possession and is
/// self-limiting, so it does not appear here.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryRateLimits {
    /// Per source IP. Default 20 / hour.
    pub request_per_ip: Option<RateLimitPolicy>,
    /// Per target email (the recovery identifier). Default 5 / hour.
    pub request_per_identifier: Option<RateLimitPolicy>,
    /// Per target email over a longer window. Default 10 / day.
    pub request_per_identifier_daily: Option<RateLimitPolicy>,
    /// Optional global ceiling across every recovery attempt. Off by
    /// default — hosts that want a cap configure one explicitly.
    pub request_global: Option<RateLimitPolicy>,
}

impl RecoveryRateLimits {
    /// Turn off every policy.
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
            request_per_ip: Some(RateLimitPolicy::new(20, Duration::from_secs(60 * 60))),
            request_per_identifier: Some(RateLimitPolicy::new(5, Duration::from_secs(60 * 60))),
            request_per_identifier_daily: Some(RateLimitPolicy::new(
                10,
                Duration::from_secs(60 * 60 * 24),
            )),
            request_global: None,
        }
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Duration::from_secs(60 * 15),
            url_template: format!("https://example.invalid/recovery?token={TOKEN_PLACEHOLDER}"),
            rate_limits: RecoveryRateLimits::default(),
            emails: default_emails(),
            cooldown: Duration::from_secs(60 * 60 * 24),
        }
    }
}

/// Manager for the three-step recovery flow.
///
/// A thin wrapper over the shared [`EnrollmentFlow`]: `consume_recovery`
/// delegates directly and `finish_recovery` delegates with the cool-down
/// and success-notification knobs set. `request_recovery` stays here — its
/// silent-no-op-on-unknown-email behaviour and extra rate-limit policies
/// are what make it distinct from signup's request path.
#[derive(Clone)]
pub struct RecoveryManager {
    flow: EnrollmentFlow,
    config: RecoveryConfig,
}

impl RecoveryManager {
    /// Construct a `RecoveryManager`.
    ///
    /// Panics if `config.cooldown` is below [`MIN_COOLDOWN`] (one hour).
    /// The floor exists because the cool-down is the only thing protecting
    /// a freshly-recovered account from an attacker who phished the link
    /// before the legitimate owner reacted; setting it shorter than that
    /// would defeat the post-recovery cool-down protection.
    pub fn new(flow: EnrollmentFlow, config: RecoveryConfig) -> Self {
        assert!(
            config.cooldown >= MIN_COOLDOWN,
            "RecoveryConfig.cooldown ({:?}) is below the documented floor of {:?}",
            config.cooldown,
            MIN_COOLDOWN,
        );
        Self { flow, config }
    }

    /// Diagnostic accessor used by the axum builder's startup warnings
    /// to detect dev-only email transports without exposing the
    /// underlying `Arc<dyn EmailSender>`.
    #[doc(hidden)]
    pub fn email_kind(&self) -> crate::email::EmailSenderKind {
        self.flow.email_kind()
    }

    /// Issue a recovery link to `email`. Returns `Ok(())` regardless of
    /// whether the email resolves to a registered user, so the endpoint
    /// cannot be used to enumerate accounts. When the email **is**
    /// registered we send the recovery link and the recovery-requested
    /// notification email and audit the attempt; when it is **not**, we
    /// audit the attempt and silently no-op.
    #[tracing::instrument(
        skip(self, email, context),
        fields(method = "recovery", user_id = tracing::field::Empty),
    )]
    pub async fn request_recovery(&self, email: &str, context: SessionContext) -> Result<()> {
        let email_normalized = verification::normalize_email(email);
        verification::validate_email(&email_normalized)?;

        let rate_limits = &self.config.rate_limits;
        verification::enforce_all(
            self.flow.rate_limiter().as_ref(),
            &[
                (
                    rate_limits.request_per_ip,
                    "recovery/request/ip",
                    context.ip.as_deref(),
                ),
                (
                    rate_limits.request_per_identifier,
                    "recovery/request/email",
                    Some(email_normalized.as_str()),
                ),
                (
                    rate_limits.request_per_identifier_daily,
                    "recovery/request/email/daily",
                    Some(email_normalized.as_str()),
                ),
                (
                    rate_limits.request_global,
                    "recovery/request/global",
                    Some("global"),
                ),
            ],
            || async {
                self.flow
                    .audit_recovery_failed(None, RecoveryFailureReason::RateLimited, &context)
                    .await;
            },
        )
        .await?;

        let now = self.flow.now();
        let Some(user) = self
            .flow
            .users()
            .find_user_by_email(&email_normalized)
            .await?
        else {
            // Unknown email: audit the attempt and silently no-op so the
            // endpoint cannot tell the caller whether or not the address
            // is on file. No notification email is sent — doing so would
            // re-introduce the enumeration oracle by side-channel.
            self.flow
                .emit(
                    &context,
                    AuditEventKind::RecoveryRequested { user_id: None },
                )
                .await;
            self.flow
                .audit_recovery_failed(None, RecoveryFailureReason::UnknownEmail, &context)
                .await;
            tracing::info!(outcome = "unknown_email", "recovery request (silent)");
            return Ok(());
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        // Invalidate any prior recovery tokens for the user, store a fresh
        // single-use token, and render the link URL.
        let url = verification::issue_link(
            self.flow.tokens().as_ref(),
            user.id,
            VerificationPurpose::Recovery,
            self.config.token_lifetime,
            &self.config.url_template,
            now,
        )
        .await?;
        let link_email = self.config.emails.recovery_email(&user, &url);
        self.flow.email_sender().send(link_email).await?;
        let notification = self
            .config
            .emails
            .recovery_requested_notification_email(&user);
        self.flow.email_sender().send(notification).await?;

        self.flow
            .emit(
                &context,
                AuditEventKind::RecoveryRequested {
                    user_id: Some(user.id),
                },
            )
            .await;
        tracing::info!(outcome = "sent", "recovery email sent");
        Ok(())
    }

    /// Redeem a recovery token and start a passkey registration ceremony.
    /// The token is atomically consumed so the same link cannot be
    /// replayed; the returned [`VerificationConsumeOutcome`] carries the
    /// registration challenge.
    #[tracing::instrument(
        skip(self, token, context),
        fields(method = "recovery", user_id = tracing::field::Empty),
    )]
    pub async fn consume_recovery(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<VerificationConsumeOutcome> {
        self.flow.consume(FlowKind::Recovery, token, context).await
    }

    /// Complete the recovery-time passkey registration ceremony and issue
    /// a session. The session carries a post-recovery cool-down, and the
    /// user receives the passkey-registered security notice plus a
    /// recovery-completed notification email.
    pub async fn finish_recovery(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<EnrollmentOutcome> {
        self.flow
            .finish(
                FlowKind::Recovery,
                challenge_id,
                response,
                name,
                context,
                Some(self.config.cooldown),
                Some(&|user| {
                    self.config
                        .emails
                        .recovery_completed_notification_email(user)
                }),
            )
            .await
    }
}
