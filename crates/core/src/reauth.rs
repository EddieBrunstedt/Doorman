use std::collections::BTreeSet;
use std::sync::Arc;

use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse, Webauthn};

use crate::assertion::AssertionVerifier;
use crate::audit::{AuditDispatch, AuditEventKind};
use crate::challenge::{PasskeyChallenge, Reauth};
use crate::context::CoreDeps;
use crate::error::Result;
use crate::passkey::PasskeyConfig;
use crate::session::{ResolvedSession, SessionContext};
use crate::storage::{PasskeyChallengeId, Session};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReauthAction {
    DeleteUser,
    RequestEmailChange,
    RemovePasskey,
    RevokeOtherSessions,
    RevokeSession,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReauthPolicy {
    required: BTreeSet<ReauthAction>,
}

impl ReauthPolicy {
    pub fn required_for(actions: impl IntoIterator<Item = ReauthAction>) -> Self {
        Self {
            required: actions.into_iter().collect(),
        }
    }

    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn requires(&self, action: ReauthAction) -> bool {
        self.required.contains(&action)
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
    audit: AuditDispatch,
}

impl ReauthManager {
    pub(crate) fn new(deps: &CoreDeps, config: &PasskeyConfig, webauthn: Arc<Webauthn>) -> Self {
        Self {
            challenges: PasskeyChallenge::from_deps(deps, config, webauthn.clone()),
            assertions: AssertionVerifier::from_deps(deps, webauthn),
            audit: deps.audit.clone(),
        }
    }

    #[tracing::instrument(skip_all, fields(user_id = %session.user_id))]
    pub async fn start(
        &self,
        session: &ResolvedSession,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let (id, rcr) = self.challenges.issue(session).await?;
        tracing::info!(outcome = "started", "reauth started");
        Ok((id, rcr))
    }

    pub(crate) async fn verify(
        &self,
        session: &Session,
        proof: &ReauthProof,
        context: &SessionContext,
    ) -> Result<()> {
        let user_id = session.user_id;
        let pending = self
            .challenges
            .redeem(proof.challenge_id, session, context)
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
            ReauthPolicy::required_for([ReauthAction::DeleteUser, ReauthAction::RemovePasskey]);
        assert!(policy.requires(ReauthAction::DeleteUser));
        assert!(policy.requires(ReauthAction::RemovePasskey));
        assert!(!policy.requires(ReauthAction::RequestEmailChange));
    }

    #[test]
    fn disabled_gates_nothing() {
        let policy = ReauthPolicy::disabled();
        assert!(!policy.requires(ReauthAction::DeleteUser));
        assert!(!policy.requires(ReauthAction::RequestEmailChange));
        assert!(!policy.requires(ReauthAction::RemovePasskey));
    }
}
