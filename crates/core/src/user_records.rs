use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result, StorageErrorKind};
use crate::session::{IssuedSession, SessionContext};
use crate::session_records::SessionRecords;
use crate::storage::{
    EmailLinkStore, PasskeyChallengeStore, PasskeyStore, StoredPasskey, User, UserId, UserStatus,
    UserStore,
};

#[derive(Clone)]
pub(crate) struct UserRecords {
    users: Arc<dyn UserStore>,
    sessions: SessionRecords,
    passkeys: Arc<dyn PasskeyStore>,
    links: Arc<dyn EmailLinkStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
}

impl UserRecords {
    pub(crate) fn new(deps: &CoreDeps) -> Self {
        Self {
            users: deps.users.clone(),
            sessions: deps.sessions.clone(),
            passkeys: deps.passkeys.clone(),
            links: deps.email_links.clone(),
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

    pub(crate) async fn find_active(&self, user_id: UserId) -> Result<User> {
        let user = self.find(user_id).await?;
        if user.status.is_active() {
            Ok(user)
        } else {
            Err(Error::UserDisabled)
        }
    }

    pub(crate) async fn count_passkeys(&self, user_id: UserId) -> Result<u64> {
        let passkeys = self.passkeys.list_passkeys_for_user(user_id).await?;
        Ok(passkeys.len() as u64)
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
            status: UserStatus::Active,
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
        // The email-change link proved control of the new address.
        let verified_at = self.now();
        match self.users.set_user_email(user_id, email, verified_at).await {
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
        // The status goes before the sessions; `issue_session` relies on that order.
        self.users
            .set_user_status(user_id, UserStatus::Disabled { at: now }, now)
            .await?;
        self.sessions.revoke_all_for_user(user_id).await
    }

    pub(crate) async fn issue_session(
        &self,
        passkey: &StoredPasskey,
        context: SessionContext,
    ) -> Result<IssuedSession> {
        let user_id = passkey.user_id;
        let issued = self.sessions.create(passkey, &context).await?;
        // Disable and delete change the user before deleting their sessions, so if that delete
        // missed this session, this read sees the change. The token is handed out only after it.
        if let Err(error) = self.find_active(user_id).await {
            self.sessions.discard(&issued.session).await;
            return Err(error);
        }

        self.audit
            .emit(
                &context,
                AuditEventKind::SessionCreated {
                    user_id,
                    session_id: issued.session.id,
                },
            )
            .await;

        Ok(issued)
    }

    pub(crate) async fn enable(&self, user_id: UserId) -> Result<()> {
        self.users
            .set_user_status(user_id, UserStatus::Active, self.now())
            .await?;
        Ok(())
    }

    pub(crate) async fn delete(&self, user_id: UserId, actor: Actor) -> Result<()> {
        self.find(user_id).await?;

        // Disabling first makes a racing login refuse its own session (see `issue_session`),
        // and leaves a delete that fails partway with a user who cannot log in.
        self.disable(user_id).await?;
        self.passkeys.delete_passkeys_for_user(user_id).await?;
        self.links.delete_links_for_user(user_id).await?;
        self.challenges
            .delete_registrations_for_user(user_id)
            .await?;
        self.users.delete_user(user_id).await?;

        self.audit
            .emit(actor, AuditEventKind::UserDeleted { user_id })
            .await;
        Ok(())
    }
}
