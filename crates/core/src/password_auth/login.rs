//! Password login: rate-limit, look up the user, verify the password,
//! enforce email-verification policy, and issue a session.

use crate::audit::{AuditEvent, AuditEventKind, AuthMethod, LoginFailureReason};
use crate::error::{Error, Result};
use crate::password::verify_password_async;
use crate::session::{IssuedSession, SessionContext};

use super::{PasswordAuthManager, normalize_email};

impl PasswordAuthManager {
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
}
