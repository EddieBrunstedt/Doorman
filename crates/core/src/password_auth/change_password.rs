//! Authenticated password change: verify the current password, hash the
//! new one, and emit an audit event.

use crate::audit::{AuditEvent, AuditEventKind};
use crate::error::{Error, Result};
use crate::password::{hash_password_async, verify_password_async};
use crate::session::SessionContext;
use crate::storage::{PasswordCredential, UserId};

use super::PasswordAuthManager;

impl PasswordAuthManager {
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
}
