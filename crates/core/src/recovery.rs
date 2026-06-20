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
//! session and recovery-created passkey carry the same post-recovery
//! cool-down (24h by default), and passkeys added from a restricted
//! session inherit the active deadline.

use std::time::Duration;

use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::audit::{AuditEventKind, RecoveryFailureReason};
use crate::error::Result;
use crate::rate_limit::RateLimitPolicy;
use crate::session::SessionContext;
use crate::storage::{PasskeyChallengeId, VerificationPurpose};
use crate::verification::{
    self, EnrollmentFlow, EnrollmentOutcome, FlowKind, RecoveryFinish, TOKEN_PLACEHOLDER,
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
    /// Length of the post-recovery cool-down applied to the session and
    /// passkey created by `finish_recovery`. Sessions created from that
    /// passkey, or from passkeys added by a restricted session, stay
    /// restricted until this deadline; destructive surfaces (delete passkey,
    /// revoke other sessions — see
    /// [`crate::error::Error::RecoveryCooldownActive`]) refuse requests from
    /// restricted sessions. Floor of one hour enforced by
    /// [`RecoveryManager::new`] unless [`danger_allow_cooldown_below_floor`]
    /// is set.
    ///
    /// [`danger_allow_cooldown_below_floor`]: RecoveryConfig::danger_allow_cooldown_below_floor
    pub cooldown: Duration,
    /// Escape hatch: when `true`, [`RecoveryManager::new`] accepts a
    /// [`cooldown`] below [`MIN_COOLDOWN`] instead of rejecting it.
    ///
    /// The floor exists because the cool-down is the only thing protecting a
    /// freshly-recovered account from an attacker who phished the recovery
    /// link before the legitimate owner reacted; dropping below it weakens
    /// that property. doorman does **not** prevent a host that has weighed
    /// the trade-off from going lower — but it must say so explicitly here, so
    /// a small [`cooldown`] can never silently disable the protection by
    /// accident. Leave this `false` unless you have a deliberate reason.
    ///
    /// [`cooldown`]: RecoveryConfig::cooldown
    pub danger_allow_cooldown_below_floor: bool,
}

/// Minimum permitted [`RecoveryConfig::cooldown`] on the normal path. Set
/// well below the 24h default so hosts have room to shorten the window in
/// tests and local development, but high enough that a real deployment cannot
/// accidentally disable the property. A host that has deliberately decided it
/// wants a shorter (or zero) cool-down opts out of the floor with
/// [`RecoveryConfig::danger_allow_cooldown_below_floor`].
pub const MIN_COOLDOWN: Duration = Duration::from_secs(60 * 60);

/// Rejection returned by [`RecoveryManager::new`] when the supplied
/// [`RecoveryConfig`] is invalid. Construction is fallible rather than a
/// panic so the misconfiguration is threaded back to the host through the
/// builder (the axum builder maps this onto its `BuilderError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryConfigError {
    /// `cooldown` is below the documented [`MIN_COOLDOWN`] floor and
    /// [`RecoveryConfig::danger_allow_cooldown_below_floor`] was not set. The
    /// cool-down is the only thing protecting a freshly-recovered account
    /// from an attacker who phished the link before the legitimate owner
    /// reacted, so a sub-floor value is rejected by default rather than
    /// silently weakening the property. A host that wants a shorter window
    /// sets the escape hatch.
    #[error("recovery cooldown ({configured:?}) is below the floor of {minimum:?}")]
    CooldownTooShort {
        /// The cool-down the host configured.
        configured: Duration,
        /// The minimum cool-down doorman enforces.
        minimum: Duration,
    },
}

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
    /// Default per-IP policy: 20 recovery requests per IP per hour.
    pub const DEFAULT_PER_IP: RateLimitPolicy =
        RateLimitPolicy::new(20, Duration::from_secs(60 * 60));
    /// Default per-identifier policy: 5 recovery requests per email per hour.
    pub const DEFAULT_PER_IDENTIFIER: RateLimitPolicy =
        RateLimitPolicy::new(5, Duration::from_secs(60 * 60));
    /// Default per-identifier daily policy: 10 recovery requests per email
    /// per day, bounding sustained pressure that stays under the hourly cap.
    pub const DEFAULT_PER_IDENTIFIER_DAILY: RateLimitPolicy =
        RateLimitPolicy::new(10, Duration::from_secs(60 * 60 * 24));

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
    /// Default: 20 / IP / hour ([`DEFAULT_PER_IP`]), 5 / email / hour
    /// ([`DEFAULT_PER_IDENTIFIER`]), and 10 / email / day
    /// ([`DEFAULT_PER_IDENTIFIER_DAILY`]). The global ceiling is off by
    /// default; the host opts in. Override any field via struct-update
    /// syntax, or pass [`disabled`] to turn every policy off.
    ///
    /// [`DEFAULT_PER_IP`]: RecoveryRateLimits::DEFAULT_PER_IP
    /// [`DEFAULT_PER_IDENTIFIER`]: RecoveryRateLimits::DEFAULT_PER_IDENTIFIER
    /// [`DEFAULT_PER_IDENTIFIER_DAILY`]: RecoveryRateLimits::DEFAULT_PER_IDENTIFIER_DAILY
    /// [`disabled`]: RecoveryRateLimits::disabled
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
    /// Default recovery-token lifetime: 15 minutes. Short by design — see
    /// [`RecoveryConfig::token_lifetime`].
    pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 15);
    /// Default post-recovery cool-down: 24 hours. Must stay at or above
    /// [`MIN_COOLDOWN`]; see [`RecoveryConfig::cooldown`].
    pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60 * 60 * 24);
}

impl Default for RecoveryConfig {
    /// Default: a 15-minute token lifetime ([`DEFAULT_TOKEN_LIFETIME`]), the
    /// default [`RecoveryRateLimits`], a 24-hour post-recovery cool-down
    /// ([`DEFAULT_COOLDOWN`]), and a placeholder `example.invalid` URL template
    /// (the host must override this).
    ///
    /// [`DEFAULT_TOKEN_LIFETIME`]: RecoveryConfig::DEFAULT_TOKEN_LIFETIME
    /// [`DEFAULT_COOLDOWN`]: RecoveryConfig::DEFAULT_COOLDOWN
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
    /// Returns [`RecoveryConfigError::CooldownTooShort`] if `config.cooldown`
    /// is below [`MIN_COOLDOWN`] (one hour) and
    /// [`config.danger_allow_cooldown_below_floor`] is `false`. The floor
    /// exists because the cool-down is the only thing protecting a
    /// freshly-recovered account from an attacker who phished the link before
    /// the legitimate owner reacted; setting it shorter than that would defeat
    /// the post-recovery cool-down protection. A host that has deliberately
    /// accepted that trade-off sets the escape hatch to opt out of the floor.
    ///
    /// [`config.danger_allow_cooldown_below_floor`]: RecoveryConfig::danger_allow_cooldown_below_floor
    pub fn new(
        flow: EnrollmentFlow,
        config: RecoveryConfig,
    ) -> std::result::Result<Self, RecoveryConfigError> {
        if config.cooldown < MIN_COOLDOWN && !config.danger_allow_cooldown_below_floor {
            return Err(RecoveryConfigError::CooldownTooShort {
                configured: config.cooldown,
                minimum: MIN_COOLDOWN,
            });
        }
        Ok(Self { flow, config })
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

        if !user.status.is_active() {
            // The account is disabled. Refuse to issue a recovery link — a
            // disabled account must not be able to recover its way back in. The
            // external response is kept identical to the unknown-email and
            // registered-active paths (`Ok(())`, no token, no distinguishing
            // signal) so disable never becomes an account-state oracle: we
            // simply issue no token and send no email, auditing the refusal
            // internally. This mirrors the silent-on-unknown-email posture
            // above. The shared predicate is the same one auth gates on.
            self.flow
                .audit_recovery_failed(
                    Some(user.id),
                    RecoveryFailureReason::AccountDisabled,
                    &context,
                )
                .await;
            tracing::info!(
                outcome = "account_disabled",
                "recovery request refused (silent)"
            );
            return Ok(());
        }

        // Invalidate any prior recovery tokens for the user, store a fresh
        // single-use token, and render the link URL.
        let url = verification::issue_link(
            self.flow.tokens().as_ref(),
            user.id,
            VerificationPurpose::Recovery,
            None,
            self.config.token_lifetime,
            &self.config.url_template,
            now,
        )
        .await?;
        // Best-effort: an unknown address sends nothing and returns `Ok(())`,
        // so a transport failure on either of these sends must not surface as a
        // distinct error response — that would let an attacker who can force
        // bounces (or simply measure two synchronous sends vs none) tell a
        // registered address from an unknown one, defeating the property this
        // endpoint exists to protect.
        let link_email = self.flow.emails().recovery_email(&user, &url);
        self.flow
            .send_best_effort(link_email, "recovery link")
            .await;
        let notification = self
            .flow
            .emails()
            .recovery_requested_notification_email(&user);
        self.flow
            .send_best_effort(notification, "recovery requested notification")
            .await;

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
    /// a session. The session and newly registered passkey carry the same
    /// post-recovery cool-down, and the user receives the passkey-registered
    /// security notice plus a recovery-completed notification email.
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
                Some(RecoveryFinish {
                    cooldown: self.config.cooldown,
                    notification: &|user| {
                        self.flow
                            .emails()
                            .recovery_completed_notification_email(user)
                    },
                }),
            )
            .await
    }
}
