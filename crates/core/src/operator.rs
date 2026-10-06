use crate::audit::{AuditDispatch, AuditEventKind, OperatorActor};
use crate::context::CoreDeps;
use crate::email::SecurityEmailNotifier;
use crate::error::{Error, Result};
use crate::passkey::{PasskeyManager, PasskeyRemovalNotice};
use crate::session::SessionManager;
use crate::storage::{PasskeySummary, SessionId, SessionSummary, User, UserId};
use crate::user::UserRecords;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorNotice {
    Send,
    Suppress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationPolicy {
    pub passkey_removed: OperatorNotice,
    pub sessions_revoked: OperatorNotice,
    pub account_disabled: OperatorNotice,
}

impl Default for NotificationPolicy {
    fn default() -> Self {
        Self {
            passkey_removed: OperatorNotice::Send,
            sessions_revoked: OperatorNotice::Suppress,
            account_disabled: OperatorNotice::Suppress,
        }
    }
}

#[derive(Clone)]
pub struct OperatorManager {
    records: UserRecords,
    sessions: SessionManager,
    passkey: PasskeyManager,
    notifier: SecurityEmailNotifier,
    audit: AuditDispatch,
    notifications: NotificationPolicy,
}

impl OperatorManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        passkey: PasskeyManager,
        notifications: NotificationPolicy,
    ) -> Self {
        Self {
            records: UserRecords::new(deps),
            sessions: deps.sessions.clone(),
            passkey,
            notifier: deps.notifier.clone(),
            audit: deps.audit.clone(),
            notifications,
        }
    }

    pub fn notification_policy(&self) -> &NotificationPolicy {
        &self.notifications
    }

    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn delete_account(&self, target_user_id: UserId, actor: OperatorActor) -> Result<()> {
        self.records
            .delete(target_user_id, actor.into())
            .await
            .inspect_err(|error| tracing::warn!(%error, "operator delete failed"))
    }

    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn disable(&self, target_user_id: UserId, actor: OperatorActor) -> Result<()> {
        let user = self.resolve_subject(target_user_id).await?;

        let revoked_count = self.records.disable(target_user_id).await?;
        self.audit
            .emit(
                actor.clone(),
                AuditEventKind::OperatorRevokedAllSessions {
                    user_id: target_user_id,
                    revoked_count,
                },
            )
            .await;

        self.audit
            .emit(
                actor,
                AuditEventKind::OperatorDisabledAccount {
                    user_id: target_user_id,
                },
            )
            .await;

        if self.notifications.account_disabled == OperatorNotice::Send {
            self.notifier.operator_account_disabled(&user).await;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn enable(&self, target_user_id: UserId, actor: OperatorActor) -> Result<()> {
        self.resolve_subject(target_user_id).await?;

        self.records.enable(target_user_id).await?;

        self.audit
            .emit(
                actor,
                AuditEventKind::OperatorEnabledAccount {
                    user_id: target_user_id,
                },
            )
            .await;

        Ok(())
    }

    async fn resolve_subject(&self, target_user_id: UserId) -> Result<User> {
        self.records
            .find(target_user_id)
            .await
            .inspect_err(|error| {
                if matches!(error, Error::UserNotFound) {
                    tracing::warn!(outcome = "user_not_found", "operator flow failed");
                }
            })
    }

    #[tracing::instrument(skip(self, credential_id, actor), fields(target_user_id = %target_user_id))]
    pub async fn remove_passkey(
        &self,
        target_user_id: UserId,
        credential_id: &[u8],
        actor: OperatorActor,
    ) -> Result<()> {
        self.resolve_subject(target_user_id).await?;

        let notice = match self.notifications.passkey_removed {
            OperatorNotice::Send => PasskeyRemovalNotice::Operator,
            OperatorNotice::Suppress => PasskeyRemovalNotice::Suppressed,
        };

        self.passkey
            .remove_passkey_for(target_user_id, credential_id, actor.into(), notice)
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn revoke_all_sessions(
        &self,
        target_user_id: UserId,
        actor: OperatorActor,
    ) -> Result<u64> {
        let user = self.resolve_subject(target_user_id).await?;

        let count = self.sessions.revoke_all_for_user(target_user_id).await?;

        self.audit
            .emit(
                actor,
                AuditEventKind::OperatorRevokedAllSessions {
                    user_id: target_user_id,
                    revoked_count: count,
                },
            )
            .await;

        if count > 0 && self.notifications.sessions_revoked == OperatorNotice::Send {
            self.notifier.operator_sessions_revoked(&user).await;
        }

        Ok(count)
    }

    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id, session_id = %session_id))]
    pub async fn revoke_session(
        &self,
        target_user_id: UserId,
        session_id: SessionId,
        actor: OperatorActor,
    ) -> Result<()> {
        self.resolve_subject(target_user_id).await?;

        self.sessions
            .revoke_session_for_target(target_user_id, session_id, actor.into())
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn list_passkeys(
        &self,
        target_user_id: UserId,
        actor: OperatorActor,
    ) -> Result<Vec<PasskeySummary>> {
        self.resolve_subject(target_user_id).await?;

        let summaries = self.passkey.list_passkey_summaries(target_user_id).await?;

        self.audit
            .emit(
                actor,
                AuditEventKind::OperatorListedPasskeys {
                    user_id: target_user_id,
                },
            )
            .await;

        tracing::info!(
            count = summaries.len(),
            outcome = "listed",
            "operator list passkeys"
        );
        Ok(summaries)
    }

    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn list_sessions(
        &self,
        target_user_id: UserId,
        actor: OperatorActor,
    ) -> Result<Vec<SessionSummary>> {
        self.resolve_subject(target_user_id).await?;

        let summaries = self
            .sessions
            .list_summaries_for_user(target_user_id)
            .await?;

        self.audit
            .emit(
                actor,
                AuditEventKind::OperatorListedSessions {
                    user_id: target_user_id,
                },
            )
            .await;

        tracing::info!(
            count = summaries.len(),
            outcome = "listed",
            "operator list sessions"
        );
        Ok(summaries)
    }
}
