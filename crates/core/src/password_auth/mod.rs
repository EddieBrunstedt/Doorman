//! High-level password authentication flows: register, login, logout,
//! change password, request and complete email verification, and request
//! and complete password reset.
//!
//! The manager owns the storage traits and the [`SessionManager`] and
//! composes them into the user-visible flows. Audit events are emitted
//! at every meaningful step so a host can build a complete security
//! timeline by subscribing to the [`AuditSink`].

mod change_password;
mod login;
mod password_reset;
mod register;
mod verify_email;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::audit::{AuditEvent, AuditEventKind, AuditSink, LoginFailureReason};
use crate::clock::Clock;
use crate::email::EmailSender;
use crate::error::{Error, Result};
use crate::password::PasswordPolicy;
use crate::rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
use crate::session::{SessionContext, SessionManager, hash_token};
use crate::storage::{PasswordCredentialStore, TokenHash, UserStore, VerificationTokenStore};

pub use register::RegisterOutcome;

const VERIFICATION_TOKEN_BYTES: usize = 32;

/// Placeholder substituted with the generated token in URL templates.
pub const TOKEN_PLACEHOLDER: &str = "{token}";

#[derive(Debug, Clone)]
pub struct PasswordAuthConfig {
    pub password_policy: PasswordPolicy,
    pub email_verification_lifetime: Duration,
    pub password_reset_lifetime: Duration,
    /// URL template used in verification emails. The literal substring
    /// `{token}` is replaced with the generated token at send time.
    pub verification_url_template: String,
    /// URL template used in password-reset emails. Same `{token}` rule.
    pub password_reset_url_template: String,
    /// When `true`, [`PasswordAuthManager::login`] rejects users whose
    /// email is not yet verified with [`Error::EmailNotVerified`], and
    /// [`PasswordAuthManager::register`] does not auto-issue a session.
    pub require_email_verification: bool,
    /// When `true`, [`PasswordAuthManager::reset_password`] revokes every
    /// existing session for the affected user as part of the reset.
    /// Defaults to `true` because reset implies a credential compromise.
    pub revoke_sessions_on_password_reset: bool,
    /// Rate-limit policies applied to login and unauthenticated email
    /// flows (password reset request, verification email re-issue).
    /// Defaults to a conservative posture; set to [`PasswordRateLimits::disabled`]
    /// to turn enforcement off.
    pub rate_limits: PasswordRateLimits,
}

/// Rate-limit policies applied to the password-auth flows. Each protected
/// operation is checked against an IP-keyed bucket and an identifier-keyed
/// bucket: the IP bucket caps the rate at which a single client can probe,
/// while the identifier bucket caps the rate at which one email or account
/// can be targeted regardless of source IP. Both must clear for the
/// operation to proceed.
#[derive(Debug, Clone, Copy)]
pub struct PasswordRateLimits {
    pub login_per_ip: Option<RateLimitPolicy>,
    pub login_per_identifier: Option<RateLimitPolicy>,
    pub password_reset_per_ip: Option<RateLimitPolicy>,
    pub password_reset_per_identifier: Option<RateLimitPolicy>,
    pub verification_email_per_user: Option<RateLimitPolicy>,
}

impl PasswordRateLimits {
    /// Turn off every policy. Equivalent to wiring a
    /// [`NoopRateLimiter`](crate::rate_limit::NoopRateLimiter) but keeps
    /// the limiter free of fan-out on hot paths.
    pub const fn disabled() -> Self {
        Self {
            login_per_ip: None,
            login_per_identifier: None,
            password_reset_per_ip: None,
            password_reset_per_identifier: None,
            verification_email_per_user: None,
        }
    }
}

impl Default for PasswordRateLimits {
    fn default() -> Self {
        Self {
            // Defaults balance UX with abuse resistance: a legitimate user
            // typing a password wrong a handful of times in a minute is
            // fine; a credential-stuffing bot is not.
            login_per_ip: Some(RateLimitPolicy::new(20, Duration::from_secs(60))),
            login_per_identifier: Some(RateLimitPolicy::new(10, Duration::from_secs(60 * 15))),
            password_reset_per_ip: Some(RateLimitPolicy::new(5, Duration::from_secs(60 * 60))),
            password_reset_per_identifier: Some(RateLimitPolicy::new(
                3,
                Duration::from_secs(60 * 60),
            )),
            verification_email_per_user: Some(RateLimitPolicy::new(
                5,
                Duration::from_secs(60 * 60),
            )),
        }
    }
}

impl Default for PasswordAuthConfig {
    fn default() -> Self {
        Self {
            password_policy: PasswordPolicy::default(),
            email_verification_lifetime: Duration::from_secs(60 * 60 * 24),
            password_reset_lifetime: Duration::from_secs(60 * 60),
            verification_url_template: format!(
                "https://example.invalid/verify-email?token={TOKEN_PLACEHOLDER}"
            ),
            password_reset_url_template: format!(
                "https://example.invalid/reset-password?token={TOKEN_PLACEHOLDER}"
            ),
            require_email_verification: false,
            revoke_sessions_on_password_reset: true,
            rate_limits: PasswordRateLimits::default(),
        }
    }
}

#[derive(Clone)]
pub struct PasswordAuthManager {
    pub(super) users: Arc<dyn UserStore>,
    pub(super) passwords: Arc<dyn PasswordCredentialStore>,
    pub(super) tokens: Arc<dyn VerificationTokenStore>,
    pub(super) sessions: SessionManager,
    pub(super) email: Arc<dyn EmailSender>,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) audit: Arc<dyn AuditSink>,
    pub(super) rate_limiter: Arc<dyn RateLimiter>,
    pub(super) config: PasswordAuthConfig,
}

impl PasswordAuthManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserStore>,
        passwords: Arc<dyn PasswordCredentialStore>,
        tokens: Arc<dyn VerificationTokenStore>,
        sessions: SessionManager,
        email: Arc<dyn EmailSender>,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        rate_limiter: Arc<dyn RateLimiter>,
        config: PasswordAuthConfig,
    ) -> Self {
        Self {
            users,
            passwords,
            tokens,
            sessions,
            email,
            clock,
            audit,
            rate_limiter,
            config,
        }
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        self.sessions.revoke(token).await
    }

    pub(super) async fn enforce_rate_limit(
        &self,
        policy: Option<RateLimitPolicy>,
        prefix: &str,
        scope: Option<&str>,
    ) -> Result<()> {
        // Skip cleanly when either the policy is disabled or the caller
        // didn't supply the keying scope (e.g. an IP-keyed policy on a
        // request that arrived without an IP).
        let (Some(policy), Some(scope)) = (policy, scope) else {
            return Ok(());
        };
        let key = format!("{prefix}:{scope}");
        match self.rate_limiter.check(&key, policy).await? {
            RateLimitDecision::Allowed => Ok(()),
            RateLimitDecision::Limited { retry_after } => Err(Error::RateLimited { retry_after }),
        }
    }

    pub(super) async fn emit_login_failed(
        &self,
        identifier: &str,
        reason: LoginFailureReason,
        context: &SessionContext,
    ) {
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::LoginFailed {
                    identifier: identifier.to_owned(),
                    reason,
                },
            })
            .await;
    }
}

pub(super) fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

pub(super) fn validate_email(email: &str) -> Result<()> {
    // Minimal sanity check only. Real address validation is delegated to
    // the host (and ultimately to the email provider that will accept or
    // bounce the message).
    if email.is_empty() || !email.contains('@') {
        return Err(Error::InvalidEmail);
    }
    Ok(())
}

pub(super) fn build_url(template: &str, token: &str) -> String {
    template.replace(TOKEN_PLACEHOLDER, token)
}

pub(super) fn generate_verification_token() -> (String, TokenHash) {
    let mut bytes = [0u8; VERIFICATION_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&token);
    (token, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lowercases_and_trims() {
        assert_eq!(
            normalize_email("  Alice@Example.com  "),
            "alice@example.com"
        );
    }

    #[test]
    fn build_url_substitutes_placeholder() {
        let url = build_url("https://x.test/v?token={token}", "abc");
        assert_eq!(url, "https://x.test/v?token=abc");
    }

    #[test]
    fn validate_email_rejects_missing_at() {
        assert!(matches!(validate_email("alice"), Err(Error::InvalidEmail)));
        assert!(matches!(validate_email(""), Err(Error::InvalidEmail)));
        assert!(validate_email("a@b").is_ok());
    }

    #[test]
    fn tokens_are_unique() {
        let (a, ha) = generate_verification_token();
        let (b, hb) = generate_verification_token();
        assert_ne!(a, b);
        assert_ne!(ha, hb);
    }
}
