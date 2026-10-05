use std::sync::Arc;

use chrono::{DateTime, Utc};
use webauthn_rs::prelude::{
    Passkey, PublicKeyCredential, RequestChallengeResponse, Webauthn, WebauthnError,
};

use crate::audit::{
    Actor, AuditDispatch, AuditEvent, AuditEventKind, AuditSink, ReauthFailureReason,
};
use crate::clock::{Clock, expiry};
use crate::error::{Error, Result};
use crate::passkey::{
    PasskeyConfig, build_webauthn, decode_credential, encode_passkey_authentication_state,
    find_owned_passkey,
};
use crate::redeem::Redeemer;
use crate::session::SessionContext;
use crate::storage::{
    AuthenticationPurpose, PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore,
    Session, Storage, StoredPasskeyAuthentication, UserId,
};

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
    webauthn: Arc<Webauthn>,
    credentials: Arc<dyn PasskeyCredentialStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    redeemer: Redeemer,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    challenge_lifetime: std::time::Duration,
    policy: ReauthPolicy,
}

impl ReauthManager {
    pub(crate) fn new(
        config: &PasskeyConfig,
        storage: &Storage,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        policy: ReauthPolicy,
    ) -> Result<Self> {
        let audit = AuditDispatch::new(audit);
        Ok(Self {
            webauthn: Arc::new(build_webauthn(config)?),
            credentials: storage.passkey_credentials.clone(),
            challenges: storage.passkey_challenges.clone(),
            redeemer: Redeemer::new(storage, clock.clone(), audit.clone()),
            clock,
            audit,
            challenge_lifetime: config.challenge_lifetime,
            policy,
        })
    }

    pub fn policy(&self) -> ReauthPolicy {
        self.policy
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn start(
        &self,
        user_id: UserId,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let stored = self.credentials.list_passkeys_for_user(user_id).await?;
        if stored.is_empty() {
            tracing::warn!(outcome = "no_credentials", "reauth start refused");
            return Err(Error::PasskeyNotFound);
        }
        let passkeys = stored
            .iter()
            .map(|c| decode_credential(&c.passkey))
            .collect::<Result<Vec<Passkey>>>()?;

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        self.challenges
            .put_authentication(StoredPasskeyAuthentication {
                id,
                purpose: AuthenticationPurpose::Reauth,
                state: encode_passkey_authentication_state(&auth_state)?,
                created_at: now,
                expires_at: expiry(now, self.challenge_lifetime)?,
            })
            .await?;
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
        if session.is_in_recovery_cooldown(self.clock.now()) {
            return Err(Error::RecoveryCooldownActive);
        }
        if !self.policy.requires(action) {
            return Ok(());
        }
        let user_id = session.user_id;
        let Some(proof) = proof else {
            tracing::info!(outcome = "proof_required", "reauth required");
            return Err(Error::ReauthRequired);
        };

        let auth_state = self
            .redeemer
            .reauth(proof.challenge_id, user_id, context)
            .await?;
        let now = self.clock.now();
        let result = match self
            .webauthn
            .finish_passkey_authentication(&proof.assertion, &auth_state)
        {
            Ok(result) => result,
            Err(WebauthnError::CredentialPossibleCompromise) => {
                self.emit_failed(
                    now,
                    context,
                    user_id,
                    ReauthFailureReason::CounterRegression,
                )
                .await;
                return Err(Error::PasskeyPossibleCompromise);
            }
            Err(e) => {
                self.emit_failed(now, context, user_id, ReauthFailureReason::BadAssertion)
                    .await;
                return Err(Error::Webauthn(e.to_string()));
            }
        };

        if !result.user_verified() {
            self.emit_failed(
                now,
                context,
                user_id,
                ReauthFailureReason::UserVerificationMissing,
            )
            .await;
            return Err(Error::UserVerificationRequired);
        }

        let cred_id: &[u8] = result.cred_id().as_ref();
        match find_owned_passkey(self.credentials.as_ref(), user_id, cred_id).await {
            Ok(_) => {}
            Err(Error::PasskeyNotFound | Error::PasskeyOwnershipMismatch) => {
                self.emit_failed(
                    now,
                    context,
                    user_id,
                    ReauthFailureReason::OwnershipMismatch,
                )
                .await;
                return Err(Error::PasskeyOwnershipMismatch);
            }
            Err(error) => return Err(error),
        }

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
                kind: AuditEventKind::ReauthSucceeded { user_id },
            })
            .await;
        Ok(())
    }

    async fn emit_failed(
        &self,
        now: DateTime<Utc>,
        context: &SessionContext,
        user_id: UserId,
        reason: ReauthFailureReason,
    ) {
        self.audit
            .emit(AuditEvent {
                timestamp: now,
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
                kind: AuditEventKind::ReauthFailed { user_id, reason },
            })
            .await;
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
