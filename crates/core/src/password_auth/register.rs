//! User registration: create a user, hash and store the password,
//! send a verification email, and optionally auto-issue a session.

use crate::audit::{AuditEvent, AuditEventKind, CredentialKind};
use crate::error::{Error, Result};
use crate::password::hash_password_async;
use crate::session::{IssuedSession, SessionContext};
use crate::storage::{PasswordCredential, User, UserId};

use super::{PasswordAuthManager, normalize_email, validate_email};

/// Result of a successful [`PasswordAuthManager::register`] call. The
/// session is `None` when [`PasswordAuthConfig::require_email_verification`]
/// is enabled, because an unverified user should not yet be logged in.
///
/// [`PasswordAuthConfig::require_email_verification`]: super::PasswordAuthConfig::require_email_verification
#[derive(Debug, Clone)]
pub struct RegisterOutcome {
    pub user: User,
    pub session: Option<IssuedSession>,
}

impl PasswordAuthManager {
    #[tracing::instrument(skip(self, email, password, context), fields(method = "password", user_id = tracing::field::Empty))]
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
            tracing::warn!(outcome = "email_taken", "register failed");
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
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

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

        tracing::info!(outcome = "registered", "user registered");
        Ok(RegisterOutcome { user, session })
    }
}
