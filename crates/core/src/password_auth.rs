//! High-level password authentication flows: register, login, logout,
//! change password, request and complete email verification, and request
//! and complete password reset.
//!
//! The manager owns the storage traits and the [`SessionManager`] and
//! composes them into the user-visible flows. Audit events are emitted
//! at every meaningful step so a host can build a complete security
//! timeline by subscribing to the [`AuditSink`].

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::audit::{
    AuditEvent, AuditEventKind, AuditSink, AuthMethod, CredentialKind, LoginFailureReason,
};
use crate::clock::Clock;
use crate::email::{Email, EmailSender};
use crate::error::{Error, Result};
use crate::password::{PasswordPolicy, hash_password_async, verify_password_async};
use crate::rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
use crate::session::{IssuedSession, SessionContext, SessionManager, hash_token};
use crate::storage::{
    PasswordCredential, PasswordCredentialStore, TokenHash, User, UserId, UserStore,
    VerificationPurpose, VerificationToken, VerificationTokenStore,
};

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

/// Result of a successful [`PasswordAuthManager::register`] call. The
/// session is `None` when [`PasswordAuthConfig::require_email_verification`]
/// is enabled, because an unverified user should not yet be logged in.
#[derive(Debug, Clone)]
pub struct RegisterOutcome {
    pub user: User,
    pub session: Option<IssuedSession>,
}

#[derive(Clone)]
pub struct PasswordAuthManager {
    users: Arc<dyn UserStore>,
    passwords: Arc<dyn PasswordCredentialStore>,
    tokens: Arc<dyn VerificationTokenStore>,
    sessions: SessionManager,
    email: Arc<dyn EmailSender>,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    rate_limiter: Arc<dyn RateLimiter>,
    config: PasswordAuthConfig,
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

    pub async fn register(
        &self,
        email: &str,
        password: &str,
        context: SessionContext,
    ) -> Result<RegisterOutcome> {
        let email_normalized = normalize_email(email);
        validate_email(&email_normalized)?;
        self.config.password_policy.validate(password)?;

        if self
            .users
            .find_user_by_email(&email_normalized)
            .await?
            .is_some()
        {
            return Err(Error::EmailAlreadyTaken);
        }

        let now = self.clock.now();
        let user = User {
            id: UserId::new(),
            email: Some(email_normalized),
            email_verified_at: None,
            created_at: now,
            updated_at: now,
        };
        self.users.create_user(user.clone()).await?;

        let password_hash = hash_password_async(password.to_owned()).await?;
        self.passwords
            .set_password(PasswordCredential {
                user_id: user.id,
                hash: password_hash,
                updated_at: now,
            })
            .await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::CredentialAdded {
                    user_id: user.id,
                    credential_kind: CredentialKind::Password,
                },
            })
            .await;

        self.send_verification_email_to(&user).await?;

        let session = if self.config.require_email_verification {
            None
        } else {
            Some(self.sessions.create(user.id, context).await?)
        };

        Ok(RegisterOutcome { user, session })
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
        context: SessionContext,
    ) -> Result<IssuedSession> {
        let email_normalized = normalize_email(email);
        let now = self.clock.now();

        self.enforce_rate_limit(
            self.config.rate_limits.login_per_ip,
            "password/login/ip",
            context.ip.as_deref(),
        )
        .await?;
        self.enforce_rate_limit(
            self.config.rate_limits.login_per_identifier,
            "password/login/email",
            Some(email_normalized.as_str()),
        )
        .await?;

        let Some(user) = self.users.find_user_by_email(&email_normalized).await? else {
            self.emit_login_failed(
                &email_normalized,
                LoginFailureReason::UserNotFound,
                &context,
            )
            .await;
            return Err(Error::InvalidCredentials);
        };

        let Some(credential) = self.passwords.get_password(user.id).await? else {
            self.emit_login_failed(
                &email_normalized,
                LoginFailureReason::InvalidCredential,
                &context,
            )
            .await;
            return Err(Error::InvalidCredentials);
        };

        if !verify_password_async(password.to_owned(), credential.hash.clone()).await? {
            self.emit_login_failed(
                &email_normalized,
                LoginFailureReason::InvalidCredential,
                &context,
            )
            .await;
            return Err(Error::InvalidCredentials);
        }

        if self.config.require_email_verification && user.email_verified_at.is_none() {
            self.emit_login_failed(
                &email_normalized,
                LoginFailureReason::EmailNotVerified,
                &context,
            )
            .await;
            return Err(Error::EmailNotVerified);
        }

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::LoginSucceeded {
                    user_id: user.id,
                    method: AuthMethod::Password,
                },
            })
            .await;

        self.sessions.create(user.id, context).await
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        self.sessions.revoke(token).await
    }

    pub async fn change_password(
        &self,
        user_id: UserId,
        current_password: &str,
        new_password: &str,
        context: SessionContext,
    ) -> Result<()> {
        self.config.password_policy.validate(new_password)?;
        let Some(credential) = self.passwords.get_password(user_id).await? else {
            return Err(Error::InvalidCredentials);
        };
        if !verify_password_async(current_password.to_owned(), credential.hash.clone()).await? {
            return Err(Error::InvalidCredentials);
        }
        let new_hash = hash_password_async(new_password.to_owned()).await?;
        let now = self.clock.now();
        self.passwords
            .set_password(PasswordCredential {
                user_id,
                hash: new_hash,
                updated_at: now,
            })
            .await?;
        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::PasswordChanged { user_id },
            })
            .await;
        Ok(())
    }

    pub async fn request_email_verification(&self, user_id: UserId) -> Result<()> {
        self.enforce_rate_limit(
            self.config.rate_limits.verification_email_per_user,
            "password/verify/user",
            Some(user_id.to_string().as_str()),
        )
        .await?;

        let Some(user) = self.users.find_user_by_id(user_id).await? else {
            return Err(Error::UserNotFound);
        };
        if user.email.is_none() {
            return Err(Error::UserHasNoEmail);
        }
        if user.email_verified_at.is_some() {
            return Err(Error::EmailAlreadyVerified);
        }
        self.send_verification_email_to(&user).await?;
        Ok(())
    }

    pub async fn verify_email(&self, token: &str, context: SessionContext) -> Result<()> {
        let hash = hash_token(token);
        let now = self.clock.now();
        let Some(record) = self
            .tokens
            .consume_token(&hash, VerificationPurpose::EmailVerification)
            .await?
        else {
            return Err(Error::InvalidVerificationToken);
        };
        if record.expires_at <= now {
            return Err(Error::InvalidVerificationToken);
        }
        let Some(mut user) = self.users.find_user_by_id(record.user_id).await? else {
            return Err(Error::UserNotFound);
        };
        user.email_verified_at = Some(now);
        user.updated_at = now;
        self.users.update_user(user.clone()).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::EmailVerified { user_id: user.id },
            })
            .await;
        Ok(())
    }

    pub async fn request_password_reset(&self, email: &str, context: SessionContext) -> Result<()> {
        let email_normalized = normalize_email(email);

        self.enforce_rate_limit(
            self.config.rate_limits.password_reset_per_ip,
            "password/reset/ip",
            context.ip.as_deref(),
        )
        .await?;
        self.enforce_rate_limit(
            self.config.rate_limits.password_reset_per_identifier,
            "password/reset/email",
            Some(email_normalized.as_str()),
        )
        .await?;

        // Silent success for unknown addresses keeps the endpoint from
        // doubling as an account-enumeration oracle.
        let Some(user) = self.users.find_user_by_email(&email_normalized).await? else {
            return Ok(());
        };

        // Invalidate prior outstanding reset tokens so an attacker who
        // grabbed a stale email link can't reuse it after a fresh
        // request.
        self.tokens
            .delete_tokens_for_user(user.id, VerificationPurpose::PasswordReset)
            .await?;

        let now = self.clock.now();
        let lifetime = chrono::Duration::from_std(self.config.password_reset_lifetime).expect(
            "password reset lifetime overflows chrono::Duration; configure a smaller value",
        );
        let (token, token_hash) = generate_verification_token();
        self.tokens
            .create_token(VerificationToken {
                token_hash,
                user_id: user.id,
                purpose: VerificationPurpose::PasswordReset,
                created_at: now,
                expires_at: now + lifetime,
            })
            .await?;

        if let Some(to) = user.email.clone() {
            let url = build_url(&self.config.password_reset_url_template, &token);
            self.email
                .send(build_password_reset_email(to, &url))
                .await?;
        }

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::PasswordResetRequested { user_id: user.id },
            })
            .await;
        Ok(())
    }

    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
        context: SessionContext,
    ) -> Result<()> {
        self.config.password_policy.validate(new_password)?;
        let hash = hash_token(token);
        let now = self.clock.now();
        let Some(record) = self
            .tokens
            .consume_token(&hash, VerificationPurpose::PasswordReset)
            .await?
        else {
            return Err(Error::InvalidVerificationToken);
        };
        if record.expires_at <= now {
            return Err(Error::InvalidVerificationToken);
        }
        let new_hash = hash_password_async(new_password.to_owned()).await?;
        self.passwords
            .set_password(PasswordCredential {
                user_id: record.user_id,
                hash: new_hash,
                updated_at: now,
            })
            .await?;

        if self.config.revoke_sessions_on_password_reset {
            self.sessions.revoke_all_for_user(record.user_id).await?;
        }

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::PasswordChanged {
                    user_id: record.user_id,
                },
            })
            .await;
        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::PasswordResetCompleted {
                    user_id: record.user_id,
                },
            })
            .await;
        Ok(())
    }

    async fn send_verification_email_to(&self, user: &User) -> Result<()> {
        let Some(to) = user.email.clone() else {
            return Ok(());
        };

        // Drop any prior verification tokens so an old email link can't
        // be reused after the user requests a new one.
        self.tokens
            .delete_tokens_for_user(user.id, VerificationPurpose::EmailVerification)
            .await?;

        let now = self.clock.now();
        let lifetime = chrono::Duration::from_std(self.config.email_verification_lifetime).expect(
            "email verification lifetime overflows chrono::Duration; configure a smaller value",
        );
        let (token, token_hash) = generate_verification_token();
        self.tokens
            .create_token(VerificationToken {
                token_hash,
                user_id: user.id,
                purpose: VerificationPurpose::EmailVerification,
                created_at: now,
                expires_at: now + lifetime,
            })
            .await?;

        let url = build_url(&self.config.verification_url_template, &token);
        self.email.send(build_verification_email(to, &url)).await?;
        Ok(())
    }

    async fn enforce_rate_limit(
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

    async fn emit_login_failed(
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

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn validate_email(email: &str) -> Result<()> {
    // Minimal sanity check only. Real address validation is delegated to
    // the host (and ultimately to the email provider that will accept or
    // bounce the message).
    if email.is_empty() || !email.contains('@') {
        return Err(Error::InvalidEmail);
    }
    Ok(())
}

fn build_url(template: &str, token: &str) -> String {
    template.replace(TOKEN_PLACEHOLDER, token)
}

fn build_verification_email(to: String, url: &str) -> Email {
    Email {
        to,
        subject: "Verify your email address".to_string(),
        body_text: format!(
            "Hello,\n\n\
             Please confirm your email address by visiting the link below:\n\n\
             {url}\n\n\
             If you did not request this, you can ignore this message.\n"
        ),
        body_html: None,
    }
}

fn build_password_reset_email(to: String, url: &str) -> Email {
    Email {
        to,
        subject: "Reset your password".to_string(),
        body_text: format!(
            "Hello,\n\n\
             A password reset was requested for your account. To choose a new password, visit:\n\n\
             {url}\n\n\
             If you did not request this you can safely ignore this message — your password will not change.\n"
        ),
        body_html: None,
    }
}

fn generate_verification_token() -> (String, TokenHash) {
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
