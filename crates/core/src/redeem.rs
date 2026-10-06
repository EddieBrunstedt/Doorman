use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::audit::RedemptionFailureReason::{
    Expired, Malformed, Unknown, UserDisabled, UserNotFound, WrongPurpose,
};
use crate::audit::{AuditDispatch, AuditEventKind, RedemptionFailureReason, SecretKind};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::session::SessionContext;
use crate::storage::{User, UserId, UserStore};
use crate::user_records::find_active_user;

pub(crate) struct Candidate<T> {
    pub owner: Option<UserId>,
    pub purpose_matches: bool,
    pub expires_at: DateTime<Utc>,
    pub payload: Result<T>,
}

#[derive(Clone)]
pub(crate) struct Redeemer {
    users: Arc<dyn UserStore>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
}

impl Redeemer {
    pub(crate) fn new(
        users: Arc<dyn UserStore>,
        clock: Arc<dyn Clock>,
        audit: AuditDispatch,
    ) -> Self {
        Self {
            users,
            clock,
            audit,
        }
    }

    pub(crate) fn from_deps(deps: &CoreDeps) -> Self {
        Self::new(deps.users.clone(), deps.clock.clone(), deps.audit.clone())
    }

    pub(crate) async fn check<T>(
        &self,
        secret: SecretKind,
        unknown_owner: Option<UserId>,
        candidate: Option<Candidate<T>>,
        context: &SessionContext,
    ) -> Result<T> {
        let Some(candidate) = candidate else {
            return Err(self.refuse(secret, unknown_owner, Unknown, context).await);
        };
        let reason = if !candidate.purpose_matches {
            WrongPurpose
        } else if candidate.expires_at <= self.clock.now() {
            Expired
        } else {
            match candidate.payload {
                Ok(value) => return Ok(value),
                Err(error) => {
                    tracing::warn!(%error, "single-use secret payload did not decode");
                    Malformed
                }
            }
        };
        Err(self.refuse(secret, candidate.owner, reason, context).await)
    }

    pub(crate) async fn active_owner(
        &self,
        secret: SecretKind,
        user_id: UserId,
        context: &SessionContext,
    ) -> Result<User> {
        match find_active_user(self.users.as_ref(), user_id).await {
            Ok(user) => Ok(user),
            Err(Error::UserNotFound) => Err(self
                .refuse(secret, Some(user_id), UserNotFound, context)
                .await),
            Err(Error::UserDisabled) => Err(self
                .refuse(secret, Some(user_id), UserDisabled, context)
                .await),
            Err(error) => Err(error),
        }
    }

    async fn refuse(
        &self,
        secret: SecretKind,
        user_id: Option<UserId>,
        reason: RedemptionFailureReason,
        context: &SessionContext,
    ) -> Error {
        self.audit
            .emit(
                context,
                AuditEventKind::RedemptionFailed {
                    user_id,
                    secret,
                    reason,
                },
            )
            .await;
        refusal_error(secret, reason)
    }
}

fn refusal_error(secret: SecretKind, reason: RedemptionFailureReason) -> Error {
    if reason == UserDisabled {
        return Error::UserDisabled;
    }
    match secret {
        SecretKind::RegistrationChallenge | SecretKind::LoginChallenge => {
            Error::InvalidPasskeyChallenge
        }
        SecretKind::ReauthChallenge => Error::ReauthRequired,
        SecretKind::SignupLink | SecretKind::RecoveryLink | SecretKind::EmailChangeLink => {
            Error::InvalidEmailLink
        }
    }
}
