use std::sync::Arc;

use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyAuthentication, PublicKeyCredential, Webauthn, WebauthnError,
};

use crate::audit::AuthFailureReason;
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::error::{Error, Result};
use crate::passkey::PasskeyMetadata;
use crate::passkey_format;
use crate::storage::{PasskeyStore, PasskeyUse, StoredPasskey, User, UserId};
use crate::user_records::UserRecords;

pub(crate) enum PendingAssertion {
    Login(DiscoverableAuthentication),
    Reauth {
        user_id: UserId,
        state: PasskeyAuthentication,
    },
}

pub(crate) struct VerifiedAssertion {
    pub user: User,
    pub passkey: StoredPasskey,
}

pub(crate) struct AssertionRefusal {
    pub user_id: Option<UserId>,
    pub reason: AuthFailureReason,
    pub error: Error,
}

#[derive(Clone)]
pub(crate) struct AssertionVerifier {
    webauthn: Arc<Webauthn>,
    records: UserRecords,
    passkeys: Arc<dyn PasskeyStore>,
    clock: Arc<dyn Clock>,
}

impl AssertionVerifier {
    pub(crate) fn from_deps(deps: &CoreDeps, webauthn: Arc<Webauthn>) -> Self {
        Self {
            webauthn,
            records: UserRecords::new(deps),
            passkeys: deps.passkeys.clone(),
            clock: deps.clock.clone(),
        }
    }

    pub(crate) async fn verify(
        &self,
        pending: PendingAssertion,
        response: &PublicKeyCredential,
    ) -> Result<std::result::Result<VerifiedAssertion, AssertionRefusal>> {
        let expected_user = match &pending {
            PendingAssertion::Login(_) => None,
            PendingAssertion::Reauth { user_id, .. } => Some(*user_id),
        };
        let stored = self
            .passkeys
            .find_passkey_by_credential_id(response.raw_id.as_ref())
            .await?;
        let stored = match (stored, expected_user) {
            (Some(stored), None) if user_id_from_handle(response) == Some(stored.user_id) => stored,
            (Some(stored), Some(expected)) if stored.user_id == expected => stored,
            (Some(stored), None) => {
                return Ok(Err(refuse(
                    Some(stored.user_id),
                    AuthFailureReason::UserHandleMismatch,
                    Error::PasskeyOwnershipMismatch,
                )));
            }
            (None, None) => {
                return Ok(Err(refuse(
                    None,
                    AuthFailureReason::UnknownPasskey,
                    Error::PasskeyNotFound,
                )));
            }
            (_, Some(expected)) => {
                return Ok(Err(refuse(
                    Some(expected),
                    AuthFailureReason::OwnershipMismatch,
                    Error::PasskeyOwnershipMismatch,
                )));
            }
        };
        let user_id = stored.user_id;

        let mut passkey = passkey_format::decode(&stored.passkey)?;
        let result = match self.finish(pending, response, &passkey) {
            Ok(result) => result,
            Err(WebauthnError::CredentialPossibleCompromise) => {
                return Ok(Err(refuse(
                    Some(user_id),
                    AuthFailureReason::CounterRegression,
                    Error::PasskeyPossibleCompromise,
                )));
            }
            Err(e) => {
                return Ok(Err(refuse(
                    Some(user_id),
                    AuthFailureReason::BadAssertion,
                    Error::Webauthn(e.to_string()),
                )));
            }
        };
        if !result.user_verified() {
            return Ok(Err(refuse(
                Some(user_id),
                AuthFailureReason::UserVerificationMissing,
                Error::UserVerificationRequired,
            )));
        }

        let user = match self.records.find_active(user_id).await {
            Ok(user) => user,
            Err(error) => {
                let reason = match error {
                    Error::UserNotFound => AuthFailureReason::UnknownPasskey,
                    Error::UserDisabled => AuthFailureReason::UserDisabled,
                    _ => return Err(error),
                };
                return Ok(Err(refuse(Some(user_id), reason, error)));
            }
        };

        passkey.update_credential(&result);
        let refreshed = PasskeyMetadata::from_passkey(&passkey);
        self.passkeys
            .record_passkey_use(
                &stored.credential_id,
                PasskeyUse {
                    passkey: passkey_format::encode(&passkey)?,
                    backup_eligible: refreshed.backup_eligible,
                    backup_state: refreshed.backup_state,
                    used_at: self.clock.now(),
                },
            )
            .await?;

        Ok(Ok(VerifiedAssertion {
            user,
            passkey: stored,
        }))
    }

    fn finish(
        &self,
        pending: PendingAssertion,
        response: &PublicKeyCredential,
        passkey: &Passkey,
    ) -> std::result::Result<AuthenticationResult, WebauthnError> {
        match pending {
            PendingAssertion::Login(state) => self.webauthn.finish_discoverable_authentication(
                response,
                state,
                &[DiscoverableKey::from(passkey)],
            ),
            PendingAssertion::Reauth { state, .. } => self
                .webauthn
                .finish_passkey_authentication(response, &state),
        }
    }
}

fn refuse(user_id: Option<UserId>, reason: AuthFailureReason, error: Error) -> AssertionRefusal {
    AssertionRefusal {
        user_id,
        reason,
        error,
    }
}

fn user_id_from_handle(response: &PublicKeyCredential) -> Option<UserId> {
    let handle = response.response.user_handle.as_ref()?;
    Uuid::from_slice(handle.as_ref()).ok().map(UserId)
}
