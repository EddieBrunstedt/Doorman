//! Recovery flow: email-the-link, click to enrol a new passkey.
//!
//! The [`RecoveryManager`] drives the three-step path a user takes when
//! they have lost access to every registered passkey:
//!
//! 1. [`request_recovery`](RecoveryManager::request_recovery) — the user
//!    submits an email. The response is identical whether or not the
//!    email resolves to a registered account, so the endpoint cannot be
//!    used to enumerate users. When the email **is** registered we send
//!    the recovery link _and_ a separate notification so the legitimate
//!    inbox owner sees that a recovery was just initiated.
//! 2. [`consume_recovery`](RecoveryManager::consume_recovery) — clicking
//!    the link atomically redeems the single-use token and starts a
//!    passkey registration ceremony bound to the user. The browser hands
//!    the returned challenge to `navigator.credentials.create`.
//! 3. [`finish_recovery`](RecoveryManager::finish_recovery) — finalises
//!    the passkey registration and issues a session. On success a
//!    second notification email goes out so the user sees that the
//!    recovery completed and a new passkey was enrolled.
//!
//! No session is issued from the email click alone. A passkey is always
//! interposed; an attacker who phishes the link still has to leave a
//! visible credential on the user's authenticator list. Phase 7 layers
//! a 24h cool-down on the resulting session — until that lands the
//! recovery session is unrestricted, but the rest of the design is
//! already in place.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

use crate::audit::{AuditEvent, AuditEventKind, AuditSink, AuthMethod, RecoveryFailureReason};
use crate::clock::Clock;
use crate::email::{BauthEmails, EmailSender, default_emails};
use crate::error::{Error, Result};
use crate::passkey::PasskeyManager;
use crate::rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
use crate::session::{IssuedSession, SessionContext, SessionManager, hash_token};
use crate::storage::{
    PasskeyChallengeId, StoredPasskey, TokenHash, User, UserId, UserStore, VerificationPurpose,
    VerificationToken, VerificationTokenStore,
};

const RECOVERY_TOKEN_BYTES: usize = 32;

/// Placeholder substituted with the generated token in URL templates.
pub const TOKEN_PLACEHOLDER: &str = "{token}";

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
    /// non-`None` policy is enforced. Aggressive defaults match the
    /// numbers in `PASSKEY_PIVOT.md` decision 4.
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
    /// [`RecoveryConfig::validated`].
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

/// Result of a successful [`RecoveryManager::consume_recovery`] call: the
/// caller hands `options` to `navigator.credentials.create` and echoes
/// `challenge_id` back at finish time.
#[derive(Debug)]
pub struct RecoveryConsumeOutcome {
    pub challenge_id: PasskeyChallengeId,
    pub options: CreationChallengeResponse,
}

/// Result of a successful [`RecoveryManager::finish_recovery`] call.
#[derive(Debug, Clone)]
pub struct RecoveryOutcome {
    pub user: User,
    pub session: IssuedSession,
    pub passkey: StoredPasskey,
}

/// Manager for the three-step recovery flow.
#[derive(Clone)]
pub struct RecoveryManager {
    users: Arc<dyn UserStore>,
    tokens: Arc<dyn VerificationTokenStore>,
    passkey: PasskeyManager,
    sessions: SessionManager,
    email: Arc<dyn EmailSender>,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    rate_limiter: Arc<dyn RateLimiter>,
    config: RecoveryConfig,
}

impl RecoveryManager {
    /// Construct a `RecoveryManager`.
    ///
    /// Panics if `config.cooldown` is below [`MIN_COOLDOWN`] (one hour).
    /// The floor exists because the cool-down is the only thing protecting
    /// a freshly-recovered account from an attacker who phished the link
    /// before the legitimate owner reacted; setting it shorter than that
    /// would defeat the property documented in `PASSKEY_PIVOT.md`
    /// decision 3.
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
        config: RecoveryConfig,
    ) -> Self {
        assert!(
            config.cooldown >= MIN_COOLDOWN,
            "RecoveryConfig.cooldown ({:?}) is below the documented floor of {:?}",
            config.cooldown,
            MIN_COOLDOWN,
        );
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

    /// Issue a recovery link to `email`. Returns `Ok(())` regardless of
    /// whether the email resolves to a registered user, so the endpoint
    /// cannot be used to enumerate accounts. When the email **is**
    /// registered we send the recovery link and the recovery-notification
    /// email and audit the attempt; when it is **not**, we audit the
    /// attempt and silently no-op.
    #[tracing::instrument(
        skip(self, email, context),
        fields(method = "recovery", user_id = tracing::field::Empty),
    )]
    pub async fn request_recovery(&self, email: &str, context: SessionContext) -> Result<()> {
        let email_normalized = normalize_email(email);
        validate_email(&email_normalized)?;

        if let Err(err) = self
            .enforce_rate_limit(
                self.config.rate_limits.request_per_ip,
                "recovery/request/ip",
                context.ip.as_deref(),
            )
            .await
        {
            self.audit_failed(None, RecoveryFailureReason::RateLimited, &context)
                .await;
            return Err(err);
        }
        if let Err(err) = self
            .enforce_rate_limit(
                self.config.rate_limits.request_per_identifier,
                "recovery/request/email",
                Some(email_normalized.as_str()),
            )
            .await
        {
            self.audit_failed(None, RecoveryFailureReason::RateLimited, &context)
                .await;
            return Err(err);
        }
        if let Err(err) = self
            .enforce_rate_limit(
                self.config.rate_limits.request_per_identifier_daily,
                "recovery/request/email/daily",
                Some(email_normalized.as_str()),
            )
            .await
        {
            self.audit_failed(None, RecoveryFailureReason::RateLimited, &context)
                .await;
            return Err(err);
        }
        if let Err(err) = self
            .enforce_rate_limit(
                self.config.rate_limits.request_global,
                "recovery/request/global",
                Some("global"),
            )
            .await
        {
            self.audit_failed(None, RecoveryFailureReason::RateLimited, &context)
                .await;
            return Err(err);
        }

        let now = self.clock.now();
        let Some(user) = self.users.find_user_by_email(&email_normalized).await? else {
            // Unknown email: audit the attempt and silently no-op so the
            // endpoint cannot tell the caller whether or not the address
            // is on file. No notification email is sent — doing so would
            // re-introduce the enumeration oracle by side-channel.
            self.audit
                .emit(AuditEvent {
                    timestamp: now,
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                    kind: AuditEventKind::RecoveryRequested { user_id: None },
                })
                .await;
            self.audit_failed(None, RecoveryFailureReason::UnknownEmail, &context)
                .await;
            tracing::info!(outcome = "unknown_email", "recovery request (silent)");
            return Ok(());
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        // Invalidate any prior recovery tokens for the user so a stale
        // link cannot still be redeemed after a fresh request.
        self.tokens
            .delete_tokens_for_user(user.id, VerificationPurpose::Recovery)
            .await?;

        let lifetime = chrono::Duration::from_std(self.config.token_lifetime)
            .expect("recovery lifetime overflows chrono::Duration; configure a smaller value");
        let (token, token_hash) = generate_token();
        self.tokens
            .create_token(VerificationToken {
                token_hash,
                user_id: user.id,
                purpose: VerificationPurpose::Recovery,
                created_at: now,
                expires_at: now + lifetime,
            })
            .await?;

        let url = build_url(&self.config.url_template, &token);
        let link_email = self.config.emails.recovery_email(&user, &url);
        self.email.send(link_email).await?;
        let notification = self.config.emails.recovery_notification_email(&user);
        self.email.send(notification).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::RecoveryRequested {
                    user_id: Some(user.id),
                },
            })
            .await;
        tracing::info!(outcome = "sent", "recovery email sent");
        Ok(())
    }

    /// Redeem a recovery token and start a passkey registration ceremony.
    /// The token is atomically consumed so the same link cannot be
    /// replayed; the returned [`RecoveryConsumeOutcome`] carries the
    /// registration challenge.
    #[tracing::instrument(
        skip(self, token, context),
        fields(method = "recovery", user_id = tracing::field::Empty),
    )]
    pub async fn consume_recovery(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<RecoveryConsumeOutcome> {
        let hash = hash_token(token);
        let now = self.clock.now();
        let Some(record) = self
            .tokens
            .consume_token(&hash, VerificationPurpose::Recovery)
            .await?
        else {
            self.audit_failed(None, RecoveryFailureReason::InvalidToken, &context)
                .await;
            tracing::warn!(outcome = "invalid_token", "recovery consume failed");
            return Err(Error::InvalidVerificationToken);
        };
        if record.expires_at <= now {
            // Expired tokens are audited but the user is *not* notified:
            // an expired link grants nothing, and emailing on every stale
            // click would train users to ignore the real alerts.
            self.audit_failed(
                Some(record.user_id),
                RecoveryFailureReason::ExpiredToken,
                &context,
            )
            .await;
            tracing::warn!(outcome = "expired_token", "recovery consume failed");
            return Err(Error::InvalidVerificationToken);
        }
        let Some(user) = self.users.find_user_by_id(record.user_id).await? else {
            // The user vanished between request and consume. Treat the
            // token as invalid to keep the response consistent with the
            // "no such user" path.
            self.audit_failed(
                Some(record.user_id),
                RecoveryFailureReason::InvalidToken,
                &context,
            )
            .await;
            tracing::warn!(outcome = "user_not_found", "recovery consume failed");
            return Err(Error::UserNotFound);
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        let (challenge_id, options) = self.passkey.start_registration(user.id).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::RecoveryConsumed { user_id: user.id },
            })
            .await;
        tracing::info!(outcome = "consumed", "recovery token consumed");
        Ok(RecoveryConsumeOutcome {
            challenge_id,
            options,
        })
    }

    /// Complete the recovery-time passkey registration ceremony and issue
    /// a session. Sends a second notification email so the user sees that
    /// the recovery completed and a new passkey was enrolled.
    pub async fn finish_recovery(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<RecoveryOutcome> {
        let passkey = self
            .passkey
            .finish_registration(challenge_id, response, name, context.clone())
            .await?;
        let Some(user) = self.users.find_user_by_id(passkey.user_id).await? else {
            return Err(Error::UserNotFound);
        };
        let cooldown = chrono::Duration::from_std(self.config.cooldown)
            .expect("recovery cooldown overflows chrono::Duration; configure a smaller value");
        let cooldown_until = self.clock.now() + cooldown;
        let session = self
            .sessions
            .create_restricted(user.id, context.clone(), cooldown_until)
            .await?;

        // Notify the registered user that recovery completed. Best-effort
        // — a notification-send failure is logged but does not roll back
        // the recovery (the passkey is already enrolled).
        let notification = self.config.emails.recovery_notification_email(&user);
        if let Err(err) = self.email.send(notification).await {
            tracing::warn!(error = %err, "recovery success notification failed");
        }

        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::LoginSucceeded {
                    user_id: user.id,
                    method: AuthMethod::Passkey,
                },
            })
            .await;
        tracing::info!(outcome = "succeeded", "recovery finished");
        Ok(RecoveryOutcome {
            user,
            session,
            passkey,
        })
    }

    async fn enforce_rate_limit(
        &self,
        policy: Option<RateLimitPolicy>,
        prefix: &str,
        scope: Option<&str>,
    ) -> Result<()> {
        let (Some(policy), Some(scope)) = (policy, scope) else {
            return Ok(());
        };
        let key = format!("{prefix}:{scope}");
        match self.rate_limiter.check(&key, policy).await? {
            RateLimitDecision::Allowed => Ok(()),
            RateLimitDecision::Limited { retry_after } => Err(Error::RateLimited { retry_after }),
        }
    }

    async fn audit_failed(
        &self,
        user_id: Option<UserId>,
        reason: RecoveryFailureReason,
        context: &SessionContext,
    ) {
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::RecoveryFailed { user_id, reason },
            })
            .await;
    }
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() || !email.contains('@') {
        return Err(Error::InvalidEmail);
    }
    Ok(())
}

fn build_url(template: &str, token: &str) -> String {
    template.replace(TOKEN_PLACEHOLDER, token)
}

fn generate_token() -> (String, TokenHash) {
    let mut bytes = [0u8; RECOVERY_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&token);
    (token, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_substitutes_placeholder() {
        let url = build_url("https://x.test/r?token={token}", "abc");
        assert_eq!(url, "https://x.test/r?token=abc");
    }

    #[test]
    fn tokens_are_unique() {
        let (a, ha) = generate_token();
        let (b, hb) = generate_token();
        assert_ne!(a, b);
        assert_ne!(ha, hb);
    }
}
