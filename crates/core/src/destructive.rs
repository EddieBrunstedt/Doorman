use crate::audit::Actor;
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::passkey::PasskeyManager;
use crate::reauth::{ReauthAction, ReauthManager, ReauthPolicy, ReauthProof};
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::{ResolvedSession, SessionContext};
use crate::session_records::SessionRecords;
use crate::storage::SessionId;
use crate::user::UserManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestructiveAction {
    DeleteUser,
    RequestEmailChange { new_email: String },
    RemovePasskey { credential_id: Vec<u8> },
    RevokeSession { id: SessionId },
    RevokeOtherSessions,
    LogOutEverywhere,
}

impl DestructiveAction {
    pub fn reauth_action(&self) -> ReauthAction {
        match self {
            Self::DeleteUser => ReauthAction::DeleteUser,
            Self::RequestEmailChange { .. } => ReauthAction::RequestEmailChange,
            Self::RemovePasskey { .. } => ReauthAction::RemovePasskey,
            Self::RevokeSession { .. } => ReauthAction::RevokeSession,
            Self::RevokeOtherSessions | Self::LogOutEverywhere => ReauthAction::RevokeOtherSessions,
        }
    }
}

// Only the gate builds one, and every destructive action's implementation takes one, so none of
// them can run without passing it.
pub(crate) struct Cleared {
    session: ResolvedSession,
}

impl Cleared {
    pub(crate) fn session(&self) -> &ResolvedSession {
        &self.session
    }
}

#[derive(Clone)]
pub(crate) struct DestructiveActions {
    records: SessionRecords,
    reauth: ReauthManager,
    policy: ReauthPolicy,
    notices: SecurityNotices,
    passkey: PasskeyManager,
    user: UserManager,
}

impl DestructiveActions {
    pub(crate) fn new(
        deps: &CoreDeps,
        reauth: ReauthManager,
        policy: ReauthPolicy,
        passkey: PasskeyManager,
        user: UserManager,
    ) -> Self {
        Self {
            records: deps.sessions.clone(),
            reauth,
            policy,
            notices: deps.notices.clone(),
            passkey,
            user,
        }
    }

    #[tracing::instrument(
        skip_all,
        fields(user_id = %session.user_id, session_id = %session.id, action = ?action.reauth_action()),
    )]
    pub(crate) async fn perform(
        &self,
        session: &ResolvedSession,
        action: DestructiveAction,
        proof: Option<ReauthProof>,
        context: SessionContext,
    ) -> Result<()> {
        let cleared = self
            .clear(action.reauth_action(), session, proof.as_ref(), &context)
            .await?;
        match action {
            DestructiveAction::DeleteUser => self.user.delete_user(cleared, context).await,
            DestructiveAction::RequestEmailChange { new_email } => {
                self.user
                    .request_email_change(cleared, &new_email, context)
                    .await
            }
            DestructiveAction::RemovePasskey { credential_id } => {
                self.passkey
                    .remove_passkey(cleared, &credential_id, context)
                    .await
            }
            DestructiveAction::RevokeSession { id } => self.revoke(cleared, id).await,
            DestructiveAction::RevokeOtherSessions => self.revoke_others(&cleared).await,
            DestructiveAction::LogOutEverywhere => self.log_out_everywhere(cleared).await,
        }
    }

    async fn clear(
        &self,
        action: ReauthAction,
        session: &ResolvedSession,
        proof: Option<&ReauthProof>,
        context: &SessionContext,
    ) -> Result<Cleared> {
        let session = self.records.reread(session).await?;
        RecoveryCoolDown::refuse_destructive_action(&session)?;
        if self.policy.requires(action) {
            let Some(proof) = proof else {
                tracing::info!(outcome = "proof_required", "reauth required");
                return Err(Error::ReauthRequired);
            };
            self.reauth.verify(&session, proof, context).await?;
        }
        Ok(Cleared { session })
    }

    async fn log_out_everywhere(&self, cleared: Cleared) -> Result<()> {
        self.revoke_others(&cleared).await?;
        let session = cleared.session();
        self.records
            .revoke_owned(session.user_id, session.id, Actor::of_session(session))
            .await
    }

    async fn revoke(&self, cleared: Cleared, target: SessionId) -> Result<()> {
        let session = cleared.session();
        self.records
            .revoke_owned(session.user_id, target, Actor::of_session(session))
            .await?;
        // Revoking the current session is logging out, so there is no other session to tell of.
        if target != session.id {
            self.notices
                .send_to(session.user_id, SecurityNotice::OtherSessionRevoked)
                .await;
        }
        Ok(())
    }

    async fn revoke_others(&self, cleared: &Cleared) -> Result<()> {
        let session = cleared.session();
        let count = self
            .records
            .revoke_others(session, Actor::of_session(session))
            .await?;
        if count > 0 {
            self.notices
                .send_to(session.user_id, SecurityNotice::OtherSessionsRevoked)
                .await;
        }
        Ok(())
    }
}
