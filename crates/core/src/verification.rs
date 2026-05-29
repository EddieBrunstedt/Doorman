//! Shared "verification link" primitive behind signup and recovery.
//!
//! Both flows are the same shape: email a single-use, hashed-token link →
//! consume it to start a passkey registration ceremony → finish the
//! ceremony and issue a session. This module owns the pieces that are
//! genuinely identical between them — email normalization/validation, URL
//! templating, token generation, rate-limit enforcement, token issuance,
//! and the two result types — so [`signup`](crate::signup) and
//! [`recovery`](crate::recovery) read as thin specializations rather than
//! parallel copies.
//!
//! The flows still differ where it matters, and those differences stay in
//! the managers: signup provisions a new unverified user on an unknown
//! email while recovery silently no-ops (enumeration resistance differs by
//! design); recovery additionally sends a notification email, issues a
//! cool-down session, and emits a richer audit trail.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

use crate::audit::{AuditEvent, AuditEventKind, AuditSink, RecoveryFailureReason};
use crate::clock::Clock;
use crate::email::{Email, EmailSender, EmailSenderKind};
use crate::error::{Error, Result};
use crate::passkey::PasskeyManager;
use crate::rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
use crate::session::{IssuedSession, SessionContext, SessionManager, generate_token, hash_token};
use crate::storage::{
    PasskeyChallengeId, StoredPasskey, User, UserId, UserStore, VerificationPurpose,
    VerificationToken, VerificationTokenStore,
};

/// Placeholder substituted with the generated token in URL templates. The
/// literal substring `{token}` is replaced with the generated token at
/// send time.
pub const TOKEN_PLACEHOLDER: &str = "{token}";

/// Result of a successful `consume` call on either flow: the caller hands
/// `options` to `navigator.credentials.create` and echoes `challenge_id`
/// back at finish time.
#[derive(Debug)]
pub struct VerificationConsumeOutcome {
    pub challenge_id: PasskeyChallengeId,
    pub options: CreationChallengeResponse,
}

/// Result of a successful `finish` call on either flow: a passkey is
/// enrolled and a session is issued for the user.
#[derive(Debug, Clone)]
pub struct EnrollmentOutcome {
    pub user: User,
    pub session: IssuedSession,
    pub passkey: StoredPasskey,
}

/// Normalize an email for storage and lookup: trim surrounding whitespace
/// and lowercase. Keeps the "find by email" path case-insensitive.
pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Cheap structural validation. Not an RFC-compliant parser; just enough
/// to reject obviously malformed input before it reaches storage.
pub(crate) fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() || !email.contains('@') {
        return Err(Error::InvalidEmail);
    }
    Ok(())
}

/// Substitute [`TOKEN_PLACEHOLDER`] in a configured URL template with the
/// generated token.
pub(crate) fn build_url(template: &str, token: &str) -> String {
    template.replace(TOKEN_PLACEHOLDER, token)
}

/// Enforce one rate-limit policy for a `prefix:scope` key. A `None` policy
/// or `None` scope is a no-op (the policy is disabled or there is no value
/// to key on).
pub(crate) async fn enforce_rate_limit(
    rate_limiter: &dyn RateLimiter,
    policy: Option<RateLimitPolicy>,
    prefix: &str,
    scope: Option<&str>,
) -> Result<()> {
    let (Some(policy), Some(scope)) = (policy, scope) else {
        return Ok(());
    };
    let key = format!("{prefix}:{scope}");
    match rate_limiter.check(&key, policy).await? {
        RateLimitDecision::Allowed => Ok(()),
        RateLimitDecision::Limited { retry_after } => Err(Error::RateLimited { retry_after }),
    }
}

/// Enforce a list of rate-limit policies in order, short-circuiting on the
/// first rejection. Each entry is `(policy, prefix, scope)` with the same
/// semantics as [`enforce_rate_limit`]. `on_reject` runs once, just before
/// the rejecting error is returned — recovery uses it to emit a
/// `RateLimited` audit event; signup passes a no-op.
pub(crate) async fn enforce_all<F, Fut>(
    rate_limiter: &dyn RateLimiter,
    policies: &[(Option<RateLimitPolicy>, &str, Option<&str>)],
    on_reject: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for &(policy, prefix, scope) in policies {
        if let Err(err) = enforce_rate_limit(rate_limiter, policy, prefix, scope).await {
            on_reject().await;
            return Err(err);
        }
    }
    Ok(())
}

/// Issue a single-use verification link for `user_id`: drop any prior
/// tokens of the same `purpose` (so a stale link cannot be redeemed after
/// a fresh request), store a freshly-hashed token, and return the rendered
/// URL for the caller to drop into an email. Only the cleartext token
/// leaves this function, embedded in the returned URL.
pub(crate) async fn issue_link(
    tokens: &dyn VerificationTokenStore,
    user_id: UserId,
    purpose: VerificationPurpose,
    token_lifetime: std::time::Duration,
    url_template: &str,
    now: DateTime<Utc>,
) -> Result<String> {
    tokens.delete_tokens_for_user(user_id, purpose).await?;

    let lifetime = chrono::Duration::from_std(token_lifetime).expect(
        "verification token lifetime overflows chrono::Duration; configure a smaller value",
    );
    let (token, token_hash) = generate_token();
    tokens
        .create_token(VerificationToken {
            token_hash,
            user_id,
            purpose,
            created_at: now,
            expires_at: now + lifetime,
        })
        .await?;

    Ok(build_url(url_template, &token))
}

/// Which verification flow an [`EnrollmentFlow`] operation is running for.
/// The signup and recovery managers share the consume/finish skeleton; this
/// names the handful of per-flow differences in that skeleton (token
/// purpose, which audit events fire, whether consuming marks the email
/// verified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowKind {
    Signup,
    Recovery,
}

impl FlowKind {
    fn purpose(self) -> VerificationPurpose {
        match self {
            FlowKind::Signup => VerificationPurpose::Signup,
            FlowKind::Recovery => VerificationPurpose::Recovery,
        }
    }

    /// Lower-case flow name used in the log lines the skeleton emits.
    fn label(self) -> &'static str {
        match self {
            FlowKind::Signup => "signup",
            FlowKind::Recovery => "recovery",
        }
    }

    fn consumed_event(self, user_id: UserId) -> AuditEventKind {
        match self {
            FlowKind::Signup => AuditEventKind::SignupConsumed { user_id },
            FlowKind::Recovery => AuditEventKind::RecoveryConsumed { user_id },
        }
    }

    /// Whether consuming the token also marks the user's email verified.
    /// Signup treats clicking a link sent to the address as proof of
    /// ownership; recovery runs against an already-verified address, so it
    /// leaves the flag untouched.
    fn marks_email_verified(self) -> bool {
        matches!(self, FlowKind::Signup)
    }

    /// Whether a consume failure is recorded in the audit log. Only recovery
    /// emits `RecoveryFailed`; signup warn-logs and moves on.
    fn audits_consume_failures(self) -> bool {
        matches!(self, FlowKind::Recovery)
    }
}

/// Shared dependencies and consume/finish skeleton behind the signup and
/// recovery managers. Both managers hold one of these and delegate to it,
/// passing a [`FlowKind`] plus the per-flow knobs (post-recovery cool-down,
/// finish-time notification) that distinguish the two flows. This is what
/// keeps the two managers from being near-identical copies.
#[derive(Clone)]
pub struct EnrollmentFlow {
    users: Arc<dyn UserStore>,
    tokens: Arc<dyn VerificationTokenStore>,
    passkey: PasskeyManager,
    sessions: SessionManager,
    email: Arc<dyn EmailSender>,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    rate_limiter: Arc<dyn RateLimiter>,
}

impl EnrollmentFlow {
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
        }
    }

    pub(crate) fn users(&self) -> &Arc<dyn UserStore> {
        &self.users
    }

    pub(crate) fn tokens(&self) -> &Arc<dyn VerificationTokenStore> {
        &self.tokens
    }

    pub(crate) fn email_sender(&self) -> &Arc<dyn EmailSender> {
        &self.email
    }

    pub(crate) fn rate_limiter(&self) -> &Arc<dyn RateLimiter> {
        &self.rate_limiter
    }

    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    /// Diagnostic accessor used by the axum builder's startup warnings to
    /// detect dev-only email transports.
    pub(crate) fn email_kind(&self) -> EmailSenderKind {
        self.email.diagnostic_kind()
    }

    /// Emit one audit event stamped with the current clock and the request
    /// context's IP / user-agent.
    pub(crate) async fn emit(&self, context: &SessionContext, kind: AuditEventKind) {
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind,
            })
            .await;
    }

    /// Record a recovery failure. No-op for signup, which does not audit
    /// failures.
    pub(crate) async fn audit_recovery_failed(
        &self,
        user_id: Option<UserId>,
        reason: RecoveryFailureReason,
        context: &SessionContext,
    ) {
        self.emit(context, AuditEventKind::RecoveryFailed { user_id, reason })
            .await;
    }

    /// Redeem a verification token and start a passkey registration ceremony.
    /// The token is consumed atomically (so a link cannot be replayed); on
    /// signup the click also marks the email verified. Failure paths warn-log
    /// for both flows and additionally emit `RecoveryFailed` for recovery.
    pub(crate) async fn consume(
        &self,
        kind: FlowKind,
        token: &str,
        context: SessionContext,
    ) -> Result<VerificationConsumeOutcome> {
        let hash = hash_token(token);
        let now = self.clock.now();
        let Some(record) = self.tokens.consume_token(&hash, kind.purpose()).await? else {
            if kind.audits_consume_failures() {
                self.audit_recovery_failed(None, RecoveryFailureReason::InvalidToken, &context)
                    .await;
            }
            tracing::warn!(outcome = "invalid_token", "{} consume failed", kind.label());
            return Err(Error::InvalidVerificationToken);
        };
        if record.expires_at <= now {
            // Expired tokens are audited (recovery only) but the user is not
            // notified: an expired link grants nothing, and emailing on every
            // stale click would train users to ignore the real alerts.
            if kind.audits_consume_failures() {
                self.audit_recovery_failed(
                    Some(record.user_id),
                    RecoveryFailureReason::ExpiredToken,
                    &context,
                )
                .await;
            }
            tracing::warn!(outcome = "expired_token", "{} consume failed", kind.label());
            return Err(Error::InvalidVerificationToken);
        }
        let Some(mut user) = self.users.find_user_by_id(record.user_id).await? else {
            // The user vanished between request and consume. Treat the token
            // as invalid to keep the response consistent with the "no such
            // user" path.
            if kind.audits_consume_failures() {
                self.audit_recovery_failed(
                    Some(record.user_id),
                    RecoveryFailureReason::InvalidToken,
                    &context,
                )
                .await;
            }
            tracing::warn!(
                outcome = "user_not_found",
                "{} consume failed",
                kind.label()
            );
            return Err(Error::UserNotFound);
        };
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        if kind.marks_email_verified() && user.email_verified_at.is_none() {
            // Clicking a link sent to the address proves ownership.
            user.email_verified_at = Some(now);
            user.updated_at = now;
            self.users.update_user(user.clone()).await?;
        }

        let (challenge_id, options) = self.passkey.start_registration(user.id).await?;

        self.emit(&context, kind.consumed_event(user.id)).await;
        tracing::info!(outcome = "consumed", "{} token consumed", kind.label());
        Ok(VerificationConsumeOutcome {
            challenge_id,
            options,
        })
    }

    /// Finish a passkey registration ceremony and issue a session. When
    /// `cooldown` is set the session is restricted by a post-recovery
    /// cool-down; when `notification` is set the rendered email is sent
    /// best-effort once the new passkey is enrolled. Both flows audit
    /// `LoginSucceeded`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finish(
        &self,
        kind: FlowKind,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
        cooldown: Option<std::time::Duration>,
        notification: Option<&(dyn Fn(&User) -> Email + Send + Sync)>,
    ) -> Result<EnrollmentOutcome> {
        let passkey = self
            .passkey
            .finish_registration(challenge_id, response, name, context.clone())
            .await?;
        let Some(user) = self.users.find_user_by_id(passkey.user_id).await? else {
            return Err(Error::UserNotFound);
        };

        let session = match cooldown {
            Some(cooldown) => {
                let cooldown = chrono::Duration::from_std(cooldown).expect(
                    "recovery cooldown overflows chrono::Duration; configure a smaller value",
                );
                let cooldown_until = self.clock.now() + cooldown;
                self.sessions
                    .create_restricted(user.id, context.clone(), cooldown_until)
                    .await?
            }
            None => self.sessions.create(user.id, context.clone()).await?,
        };

        if let Some(render) = notification {
            // Best-effort — a notification-send failure is logged but does
            // not roll back the enrollment (the passkey is already stored).
            if let Err(err) = self.email.send(render(&user)).await {
                tracing::warn!(error = %err, "{} success notification failed", kind.label());
            }
        }

        self.emit(
            &context,
            AuditEventKind::LoginSucceeded { user_id: user.id },
        )
        .await;
        tracing::info!(outcome = "succeeded", "{} finished", kind.label());
        Ok(EnrollmentOutcome {
            user,
            session,
            passkey,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_substitutes_placeholder() {
        let url = build_url("https://x.test/s?token={token}", "abc");
        assert_eq!(url, "https://x.test/s?token=abc");
    }

    #[test]
    fn tokens_are_unique() {
        let (a, ha) = generate_token();
        let (b, hb) = generate_token();
        assert_ne!(a, b);
        assert_ne!(ha, hb);
    }

    #[test]
    fn normalize_email_trims_and_lowercases() {
        assert_eq!(normalize_email("  USER@Example.COM "), "user@example.com");
    }

    #[test]
    fn validate_email_rejects_malformed() {
        assert!(validate_email("nope").is_err());
        assert!(validate_email("").is_err());
        assert!(validate_email("a@b").is_ok());
    }
}
