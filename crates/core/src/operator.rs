use crate::audit::{AuditDispatch, AuditEventKind, OperatorActor};
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::passkey::PasskeyManager;
use crate::security_notice::{NoticePolicy, SecurityNotice, SecurityNotices};
use crate::session_records::SessionRecords;
use crate::storage::{PasskeySummary, SessionId, SessionSummary, User, UserId};
use crate::user_records::UserRecords;

#[derive(Clone)]
pub struct OperatorManager {
    records: UserRecords,
    sessions: SessionRecords,
    passkey: PasskeyManager,
    notices: SecurityNotices,
    audit: AuditDispatch,
}

impl OperatorManager {
    pub(crate) fn new(deps: &CoreDeps, passkey: PasskeyManager) -> Self {
        Self {
            records: UserRecords::new(deps),
            sessions: deps.sessions.clone(),
            passkey,
            notices: deps.notices.clone(),
            audit: deps.audit.clone(),
        }
    }

    pub fn notice_policy(&self) -> &NoticePolicy {
        self.notices.policy()
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

        self.notices
            .send(&user, SecurityNotice::OperatorDisabledUser)
            .await;

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

        self.passkey
            .remove_passkey_for(target_user_id, credential_id, actor.into())
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

        if count > 0 {
            self.notices
                .send(&user, SecurityNotice::OperatorRevokedSessions)
                .await;
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
            .revoke_owned(target_user_id, session_id, actor.into())
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
