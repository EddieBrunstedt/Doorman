use crate::audit::{AuditDispatch, AuditEventKind, OperatorActor};
use crate::context::CoreDeps;
use crate::email::SecurityNotices;
use crate::error::{Error, Result};
use crate::passkey::{PasskeyManager, PasskeyRemovalNotice};
use crate::session::SessionManager;
use crate::storage::{PasskeySummary, SessionId, SessionSummary, User, UserId};
use crate::user_records::UserRecords;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorNotice {
    Send,
    Suppress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoticePolicy {
    pub passkey_removed: OperatorNotice,
    pub sessions_revoked: OperatorNotice,
    pub user_disabled: OperatorNotice,
}

impl Default for NoticePolicy {
    fn default() -> Self {
        Self {
            passkey_removed: OperatorNotice::Send,
            sessions_revoked: OperatorNotice::Suppress,
            user_disabled: OperatorNotice::Suppress,
        }
    }
}

#[derive(Clone)]
pub struct OperatorManager {
    records: UserRecords,
    sessions: SessionManager,
    passkey: PasskeyManager,
    notices: SecurityNotices,
    audit: AuditDispatch,
    notice_policy: NoticePolicy,
}

impl OperatorManager {
    pub(crate) fn new(
        deps: &CoreDeps,
        passkey: PasskeyManager,
        notice_policy: NoticePolicy,
    ) -> Self {
        Self {
            records: UserRecords::new(deps),
            sessions: deps.sessions.clone(),
            passkey,
            notices: deps.notices.clone(),
            audit: deps.audit.clone(),
            notice_policy,
        }
    }

    pub fn notice_policy(&self) -> &NoticePolicy {
        &self.notice_policy
    }

    #[tracing::instrument(skip(self, actor), fields(target_user_id = %target_user_id))]
    pub async fn delete_user(&self, target_user_id: UserId, actor: OperatorActor) -> Result<()> {
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
                AuditEventKind::OperatorDisabledUser {
                    user_id: target_user_id,
                },
            )
            .await;

        if self.notice_policy.user_disabled == OperatorNotice::Send {
            self.notices.operator_user_disabled(&user).await;
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
                AuditEventKind::OperatorEnabledUser {
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

        let notice = match self.notice_policy.passkey_removed {
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

        if count > 0 && self.notice_policy.sessions_revoked == OperatorNotice::Send {
            self.notices.operator_sessions_revoked(&user).await;
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
