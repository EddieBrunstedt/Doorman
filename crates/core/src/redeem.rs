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
use crate::storage::{User, UserId};
use crate::user_records::UserRecords;

pub(crate) struct Candidate<T> {
    pub owner: Option<UserId>,
    pub purpose_matches: bool,
    pub expires_at: DateTime<Utc>,
    pub payload: Result<T>,
}

#[derive(Clone)]
pub(crate) struct Redeemer {
    records: UserRecords,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
}

impl Redeemer {
    pub(crate) fn from_deps(deps: &CoreDeps) -> Self {
        Self {
            records: UserRecords::new(deps),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
        }
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
        match self.records.find_active(user_id).await {
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

    pub(crate) async fn refuse(
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
