use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result, StorageErrorKind};
use crate::session::SessionManager;
use crate::storage::{
    AccountStatus, PasskeyChallengeStore, PasskeyCredentialStore, User, UserId, UserStore,
    VerificationPurpose, VerificationTokenStore,
};

const ALL_TOKEN_PURPOSES: [VerificationPurpose; 3] = [
    VerificationPurpose::Signup,
    VerificationPurpose::Recovery,
    VerificationPurpose::EmailChange,
];

pub(crate) fn ensure_active(user: &User) -> Result<()> {
    if user.status.is_active() {
        Ok(())
    } else {
        Err(Error::AccountDisabled)
    }
}

pub(crate) async fn find_active_user(users: &dyn UserStore, user_id: UserId) -> Result<User> {
    let user = users
        .find_user_by_id(user_id)
        .await?
        .ok_or(Error::UserNotFound)?;
    ensure_active(&user)?;
    Ok(user)
}

#[derive(Clone)]
pub(crate) struct UserRecords {
    users: Arc<dyn UserStore>,
    sessions: SessionManager,
    credentials: Arc<dyn PasskeyCredentialStore>,
    tokens: Arc<dyn VerificationTokenStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
}

impl UserRecords {
    pub(crate) fn new(deps: &CoreDeps) -> Self {
        Self {
            users: deps.users.clone(),
            sessions: deps.sessions.clone(),
            credentials: deps.passkey_credentials.clone(),
            tokens: deps.verification_tokens.clone(),
            challenges: deps.passkey_challenges.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
        }
    }

    fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    pub(crate) async fn find(&self, user_id: UserId) -> Result<User> {
        self.users
            .find_user_by_id(user_id)
            .await?
            .ok_or(Error::UserNotFound)
    }

    pub(crate) async fn find_for_notification(
        &self,
        user_id: UserId,
        what: &'static str,
    ) -> Option<User> {
        match self.find(user_id).await {
            Ok(user) => Some(user),
            Err(Error::UserNotFound) => {
                tracing::warn!(
                    %user_id,
                    "{what} notification skipped because user was not found"
                );
                None
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    %user_id,
                    "{what} notification skipped because user lookup failed"
                );
                None
            }
        }
    }

    pub(crate) async fn find_active(&self, user_id: UserId) -> Result<User> {
        find_active_user(self.users.as_ref(), user_id).await
    }

    pub(crate) async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        Ok(self.users.find_user_by_email(email).await?)
    }

    pub(crate) async fn create_unverified(&self, email: &str) -> Result<Option<User>> {
        let now = self.now();
        let user = User {
            id: UserId::new(),
            email: Some(email.to_owned()),
            email_verified_at: None,
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
        };
        match self.users.create_user(user.clone()).await {
            Ok(()) => Ok(Some(user)),
            Err(e) if e.kind() == StorageErrorKind::Conflict => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) async fn mark_email_verified(&self, user: &User) -> Result<()> {
        if user.email_verified_at.is_none() {
            self.users.mark_email_verified(user.id, self.now()).await?;
        }
        Ok(())
    }

    pub(crate) async fn change_email(&self, user_id: UserId, email: &str) -> Result<User> {
        match self.users.set_user_email(user_id, email, self.now()).await {
            Ok(()) => self.find(user_id).await,
            Err(e) => Err(match e.kind() {
                StorageErrorKind::Conflict => Error::EmailAlreadyInUse,
                StorageErrorKind::NotFound => Error::UserNotFound,
                _ => e.into(),
            }),
        }
    }

    pub(crate) async fn disable(&self, user_id: UserId) -> Result<u64> {
        let now = self.now();
        // The status goes before the sessions; `SessionManager::issue` relies on that order.
        self.users
            .set_user_status(user_id, AccountStatus::Disabled { at: now }, now)
            .await?;
        self.sessions.revoke_all_for_user(user_id).await
    }

    pub(crate) async fn enable(&self, user_id: UserId) -> Result<()> {
        self.users
            .set_user_status(user_id, AccountStatus::Active, self.now())
            .await?;
        Ok(())
    }

    pub(crate) async fn delete(&self, user_id: UserId, actor: Actor) -> Result<()> {
        self.find(user_id).await?;

        // Disabling first makes a racing login refuse its own session (see `SessionManager::issue`),
        // and leaves a delete that fails partway with a user who cannot log in.
        self.disable(user_id).await?;
        self.credentials.delete_passkeys_for_user(user_id).await?;
        for purpose in ALL_TOKEN_PURPOSES {
            self.tokens.delete_tokens_for_user(user_id, purpose).await?;
        }
        self.challenges
            .delete_registrations_for_user(user_id)
            .await?;
        self.users.delete_user(user_id).await?;

        self.audit
            .emit(actor, AuditEventKind::AccountDeleted { user_id })
            .await;
        Ok(())
    }
}
