//! Password reset: issue a single-use reset token, deliver it via email,
//! and consume it to set a new password (optionally revoking other
//! sessions).

use crate::audit::{AuditEvent, AuditEventKind};
use crate::email::Email;
use crate::error::{Error, Result};
use crate::password::hash_password_async;
use crate::session::{SessionContext, hash_token};
use crate::storage::{PasswordCredential, VerificationPurpose, VerificationToken};

use super::{PasswordAuthManager, build_url, generate_verification_token, normalize_email};

impl PasswordAuthManager {
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
