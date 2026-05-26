//! Email verification: issue tokens, send the verification email, and
//! consume a token to mark a user verified.

use crate::audit::{AuditEvent, AuditEventKind};
use crate::error::{Error, Result};
use crate::session::{SessionContext, hash_token};
use crate::storage::{User, VerificationPurpose, VerificationToken};

use super::{PasswordAuthManager, build_url, generate_verification_token};

impl PasswordAuthManager {
    pub async fn request_email_verification(&self, user_id: crate::storage::UserId) -> Result<()> {
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

    pub(super) async fn send_verification_email_to(&self, user: &User) -> Result<()> {
        if user.email.is_none() {
            return Ok(());
        }

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
        let email = self.config.emails.verification_email(user, &url);
        self.email.send(email).await?;
        Ok(())
    }
}
