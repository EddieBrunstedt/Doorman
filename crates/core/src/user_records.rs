use std::future::Future;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::email::EmailAddress;
use crate::error::{Error, Result, StorageErrorKind};
use crate::session::{IssuedSession, SessionContext};
use crate::session_records::SessionRecords;
use crate::storage::{
    EmailLinkStore, PasskeyChallengeStore, PasskeyStore, SessionTransport, StoredPasskey, User,
    UserId, UserStatus, UserStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignupStage {
    Unfinished,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerRefusal {
    UserNotFound,
    UserDisabled,
    WrongSignupStage,
}

impl OwnerRefusal {
    // For an owner who holds a session, and so has finished signup.
    pub(crate) fn into_error(self) -> Error {
        match self {
            Self::UserNotFound => Error::UserNotFound,
            Self::UserDisabled => Error::UserDisabled,
            Self::WrongSignupStage => Error::Internal(
                "a session is held by a user who has not finished signup".to_string(),
            ),
        }
    }
}

// A secret belongs to its owner only while they are active and at the point in signup its purpose
// needs: a signup secret only until signup has finished, since from then on only recovery brings
// the user back, with its cool-down; every other secret only once it has.
pub(crate) fn owner_refusal(owner: &User, stage: SignupStage) -> Option<OwnerRefusal> {
    if !owner.status.is_active() {
        Some(OwnerRefusal::UserDisabled)
    } else if owner.has_finished_signup() != (stage == SignupStage::Finished) {
        Some(OwnerRefusal::WrongSignupStage)
    } else {
        None
    }
}

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

    pub(crate) async fn check_owner(
        &self,
        owner: UserId,
        stage: SignupStage,
    ) -> Result<std::result::Result<User, OwnerRefusal>> {
        Ok(match self.find_owner(owner).await? {
            Ok(user) => owner_refusal(&user, stage).map_or(Ok(user), Err),
            refused => refused,
        })
    }

    // Disable and delete change the user before deleting the sessions, email links and passkey
    // registrations the user owns, so a row written meanwhile can miss that delete. Its writer
    // calls this once the row is written, and hands out the row's secret only if the owner is
    // still there and active; otherwise the row is discarded.
    pub(crate) async fn confirm_written(
        &self,
        owner: UserId,
        discard: impl Future<Output = ()>,
    ) -> Result<std::result::Result<User, OwnerRefusal>> {
        let checked = match self.find_owner(owner).await {
            Ok(Ok(user)) if !user.status.is_active() => Ok(Err(OwnerRefusal::UserDisabled)),
            found => found,
        };
        if !matches!(checked, Ok(Ok(_))) {
            discard.await;
        }
        checked
    }

    async fn find_owner(&self, owner: UserId) -> Result<std::result::Result<User, OwnerRefusal>> {
        match self.find(owner).await {
            Ok(user) => Ok(Ok(user)),
            Err(Error::UserNotFound) => Ok(Err(OwnerRefusal::UserNotFound)),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn count_passkeys(&self, user_id: UserId) -> Result<u64> {
        let passkeys = self.passkeys.list_passkeys_for_user(user_id).await?;
        Ok(passkeys.len() as u64)
    }

    pub(crate) async fn find_by_email(&self, email: &EmailAddress) -> Result<Option<User>> {
        Ok(self.users.find_user_by_email(email.as_str()).await?)
    }

    pub(crate) async fn create(&self, email: &EmailAddress) -> Result<Option<User>> {
        let now = self.now();
        let user = User {
            id: UserId::new(),
            email: Some(email.as_str().to_owned()),
            signed_up_at: None,
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

    pub(crate) async fn mark_signed_up(&self, user: User) -> Result<User> {
        let now = self.now();
        self.users.mark_signed_up(user.id, now).await?;
        Ok(User {
            signed_up_at: Some(now),
            updated_at: now,
            ..user
        })
    }

    pub(crate) async fn change_email(&self, user_id: UserId, email: &EmailAddress) -> Result<User> {
        match self
            .users
            .set_user_email(user_id, email.as_str(), self.now())
            .await
        {
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
        // The status goes before the rows the user owns; `confirm_written` relies on that order.
        self.users
            .set_user_status(user_id, UserStatus::Disabled { at: now }, now)
            .await?;
        let revoked_count = self.sessions.revoke_all_for_user(user_id).await?;
        // Redemption refuses these while the user is disabled; deleting them keeps an enable from
        // bringing them back.
        self.links.delete_links_for_user(user_id).await?;
        self.challenges
            .delete_registrations_for_user(user_id)
            .await?;
        Ok(revoked_count)
    }

    pub(crate) fn check_session_allowed(&self, transport: SessionTransport) -> Result<()> {
        self.sessions.check_allowed(transport)
    }

    pub(crate) async fn issue_session(
        &self,
        passkey: &StoredPasskey,
        transport: SessionTransport,
        context: SessionContext,
    ) -> Result<IssuedSession> {
        let user_id = passkey.user_id;
        let issued = self.sessions.create(passkey, transport, &context).await?;
        if let Err(refusal) = self
            .confirm_written(user_id, self.sessions.discard(&issued.session))
            .await?
        {
            return Err(refusal.into_error());
        }

        self.audit
            .emit(
                &context,
                AuditEventKind::SessionCreated {
                    user_id,
                    session_id: issued.session.id,
                    transport,
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

        // Disabling first makes a racing write refuse its own row (see `confirm_written`), and
        // leaves a delete that fails partway with a user who cannot log in.
        self.disable(user_id).await?;
        self.passkeys.delete_passkeys_for_user(user_id).await?;
        self.users.delete_user(user_id).await?;

        self.audit
            .emit(actor, AuditEventKind::UserDeleted { user_id })
            .await;
        Ok(())
    }
}
