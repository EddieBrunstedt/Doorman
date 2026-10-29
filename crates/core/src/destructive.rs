use crate::audit::Actor;
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::passkey::PasskeyManager;
use crate::reauth::{ReauthAction, ReauthManager, ReauthPolicy, ReauthProof};
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::security_notice::{SecurityNotice, SecurityNotices};
use crate::session::{ResolvedSession, SessionContext};
use crate::session_records::{LiveSession, SessionRecords};
use crate::storage::SessionId;
use crate::user::UserManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestructiveAction {
    DeleteUser,
    RequestEmailChange { new_email: String },
    RemovePasskey { credential_id: Vec<u8> },
    RevokeAnotherSession { id: SessionId },
    RevokeOtherSessions,
    LogOutEverywhere,
}

impl DestructiveAction {
    pub fn reauth_action(&self) -> ReauthAction {
        match self {
            Self::DeleteUser => ReauthAction::DeleteUser,
            Self::RequestEmailChange { .. } => ReauthAction::RequestEmailChange,
            Self::RemovePasskey { .. } => ReauthAction::RemovePasskey,
            Self::RevokeAnotherSession { .. } => ReauthAction::RevokeAnotherSession,
            Self::RevokeOtherSessions | Self::LogOutEverywhere => ReauthAction::RevokeOtherSessions,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentSession {
    Kept,
    Ended,
}

// Only the gate builds one, and every destructive action's implementation takes one, so none of
// them can run without passing it.
pub(crate) struct Cleared {
    session: LiveSession,
}

impl Cleared {
    pub(crate) fn session(&self) -> &LiveSession {
        &self.session
    }

    pub(crate) fn actor(&self) -> Actor {
        self.session.actor()
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
    ) -> Result<CurrentSession> {
        // Ending the acting session is logging out, which passes no gate, so it can't be asked for
        // as a destructive action. Refused before the gate, so no proof is used up.
        if action == (DestructiveAction::RevokeAnotherSession { id: session.id }) {
            tracing::info!(outcome = "acting_session", "session revoke refused");
            return Err(Error::ActingSessionNotRevocable);
        }
        let cleared = self
            .clear(action.reauth_action(), session, proof.as_ref(), context)
            .await?;
        match action {
            DestructiveAction::DeleteUser => {
                self.user.delete_user(cleared).await?;
                Ok(CurrentSession::Ended)
            }
            DestructiveAction::RequestEmailChange { new_email } => {
                self.user.request_email_change(cleared, &new_email).await?;
                Ok(CurrentSession::Kept)
            }
            DestructiveAction::RemovePasskey { credential_id } => {
                self.passkey.remove_passkey(cleared, &credential_id).await?;
                Ok(CurrentSession::Kept)
            }
            DestructiveAction::RevokeAnotherSession { id } => {
                self.revoke_another(cleared, id).await?;
                Ok(CurrentSession::Kept)
            }
            DestructiveAction::RevokeOtherSessions => {
                self.revoke_others(&cleared).await?;
                Ok(CurrentSession::Kept)
            }
            DestructiveAction::LogOutEverywhere => {
                self.log_out_everywhere(cleared).await?;
                Ok(CurrentSession::Ended)
            }
        }
    }

    async fn clear(
        &self,
        action: ReauthAction,
        session: &ResolvedSession,
        proof: Option<&ReauthProof>,
        context: SessionContext,
    ) -> Result<Cleared> {
        let session = self.records.reread(session, context).await?;
        RecoveryCoolDown::refuse_destructive_action(&session)?;
        if self.policy.requires(action) {
            let Some(proof) = proof else {
                tracing::info!(outcome = "proof_required", "reauth required");
                return Err(Error::ReauthRequired);
            };
            self.reauth.verify(&session, proof).await?;
        }
        Ok(Cleared { session })
    }

    async fn log_out_everywhere(&self, cleared: Cleared) -> Result<()> {
        self.revoke_others(&cleared).await?;
        self.records
            .log_out(cleared.session(), cleared.actor())
            .await
    }

    async fn revoke_another(&self, cleared: Cleared, target: SessionId) -> Result<()> {
        let session = cleared.session();
        self.records
            .revoke_owned(session.user_id, target, cleared.actor())
            .await?;
        self.notices
            .send_to(session.user_id, SecurityNotice::OtherSessionRevoked)
            .await;
        Ok(())
    }

    async fn revoke_others(&self, cleared: &Cleared) -> Result<()> {
        let session = cleared.session();
        let count = self.records.revoke_others(session, cleared.actor()).await?;
        if count > 0 {
            self.notices
                .send_to(session.user_id, SecurityNotice::OtherSessionsRevoked)
                .await;
        }
        Ok(())
    }
}
