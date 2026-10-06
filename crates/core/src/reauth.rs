use std::sync::Arc;

use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse, Webauthn};

use crate::assertion::AssertionVerifier;
use crate::audit::{AuditDispatch, AuditEventKind};
use crate::challenge::{PasskeyChallenge, Reauth};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::passkey::PasskeyConfig;
use crate::recovery_cooldown::RecoveryCooldown;
use crate::redeem::Redeemer;
use crate::session::SessionContext;
use crate::storage::{PasskeyChallengeId, Session, Storage, UserId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReauthAction {
    DeleteAccount,
    RequestEmailChange,
    RemovePasskey,
    RevokeOtherSessions,
    RevokeSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReauthPolicy {
    delete_account: bool,
    request_email_change: bool,
    remove_passkey: bool,
    revoke_other_sessions: bool,
    revoke_session: bool,
}

impl ReauthPolicy {
    pub fn required_for(actions: impl IntoIterator<Item = ReauthAction>) -> Self {
        let mut policy = Self::disabled();
        for action in actions {
            match action {
                ReauthAction::DeleteAccount => policy.delete_account = true,
                ReauthAction::RequestEmailChange => policy.request_email_change = true,
                ReauthAction::RemovePasskey => policy.remove_passkey = true,
                ReauthAction::RevokeOtherSessions => policy.revoke_other_sessions = true,
                ReauthAction::RevokeSession => policy.revoke_session = true,
            }
        }
        policy
    }

    pub const fn disabled() -> Self {
        Self {
            delete_account: false,
            request_email_change: false,
            remove_passkey: false,
            revoke_other_sessions: false,
            revoke_session: false,
        }
    }

    pub const fn requires(&self, action: ReauthAction) -> bool {
        match action {
            ReauthAction::DeleteAccount => self.delete_account,
            ReauthAction::RequestEmailChange => self.request_email_change,
            ReauthAction::RemovePasskey => self.remove_passkey,
            ReauthAction::RevokeOtherSessions => self.revoke_other_sessions,
            ReauthAction::RevokeSession => self.revoke_session,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReauthProof {
    pub challenge_id: PasskeyChallengeId,
    pub assertion: PublicKeyCredential,
}

#[derive(Clone)]
pub struct ReauthManager {
    challenges: PasskeyChallenge<Reauth>,
    assertions: AssertionVerifier,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    policy: ReauthPolicy,
}

impl ReauthManager {
    pub(crate) fn new(
        config: &PasskeyConfig,
        storage: &Storage,
        clock: Arc<dyn Clock>,
        audit: AuditDispatch,
        policy: ReauthPolicy,
        webauthn: Arc<Webauthn>,
    ) -> Self {
        Self {
            challenges: PasskeyChallenge::new(
                config,
                webauthn.clone(),
                storage.passkey_challenges.clone(),
                storage.passkey_credentials.clone(),
                Redeemer::new(storage.users.clone(), clock.clone(), audit.clone()),
                clock.clone(),
            ),
            assertions: AssertionVerifier::new(
                webauthn,
                storage.users.clone(),
                storage.passkey_credentials.clone(),
                clock.clone(),
            ),
            clock,
            audit,
            policy,
        }
    }

    pub fn policy(&self) -> ReauthPolicy {
        self.policy
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn start(
        &self,
        user_id: UserId,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let (id, rcr) = self.challenges.issue(user_id).await?;
        tracing::info!(outcome = "started", "reauth started");
        Ok((id, rcr))
    }

    #[tracing::instrument(skip(self, session, proof, context), fields(user_id = %session.user_id))]
    pub async fn ensure(
        &self,
        action: ReauthAction,
        session: &Session,
        proof: Option<&ReauthProof>,
        context: &SessionContext,
    ) -> Result<()> {
        RecoveryCooldown::refuse_destructive_action(session, self.clock.now())?;
        if !self.policy.requires(action) {
            return Ok(());
        }
        let user_id = session.user_id;
        let Some(proof) = proof else {
            tracing::info!(outcome = "proof_required", "reauth required");
            return Err(Error::ReauthRequired);
        };

        let pending = self
            .challenges
            .redeem(proof.challenge_id, user_id, context)
            .await?;
        if let Err(refusal) = self.assertions.verify(pending, &proof.assertion).await? {
            self.audit
                .emit(
                    context,
                    AuditEventKind::ReauthFailed {
                        user_id,
                        reason: refusal.reason,
                    },
                )
                .await;
            return Err(refusal.error);
        }

        self.audit
            .emit(context, AuditEventKind::ReauthSucceeded { user_id })
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_for_gates_only_listed_actions() {
        let policy =
            ReauthPolicy::required_for([ReauthAction::DeleteAccount, ReauthAction::RemovePasskey]);
        assert!(policy.requires(ReauthAction::DeleteAccount));
        assert!(policy.requires(ReauthAction::RemovePasskey));
        assert!(!policy.requires(ReauthAction::RequestEmailChange));
    }

    #[test]
    fn disabled_gates_nothing() {
        let policy = ReauthPolicy::disabled();
        assert!(!policy.requires(ReauthAction::DeleteAccount));
        assert!(!policy.requires(ReauthAction::RequestEmailChange));
        assert!(!policy.requires(ReauthAction::RemovePasskey));
    }
}
