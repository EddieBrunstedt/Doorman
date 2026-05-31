//! Passkey (WebAuthn) registration and authentication ceremonies.
//!
//! The manager wraps a `webauthn-rs` [`Webauthn`] instance and composes
//! it with the user store, the passkey credential store, and a separate
//! challenge store that holds the per-ceremony server-side state between
//! the `start_*` and `finish_*` calls. Audit events are emitted at every
//! meaningful step, and successful passkey lifecycle changes send
//! best-effort security notifications after the credential store changes.
//!
//! Account linking falls out of the design for free: register a passkey
//! against any existing user id and that user now has a passkey credential.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::ResidentKeyRequirement;

use crate::audit::{AuditEvent, AuditEventKind, AuditSink};
use crate::clock::Clock;
use crate::email::{BauthEmails, EmailSender, SecurityEmailNotifier, default_emails};
use crate::error::{Error, Result};
use crate::session::{IssuedSession, SessionContext, SessionManager};
use crate::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore, PasskeySummary,
    StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration, User, UserId, UserStore,
};

/// WebAuthn relying-party configuration for passkey flows.
#[derive(Clone)]
pub struct PasskeyConfig {
    /// Relying party identifier, typically the registrable suffix of
    /// the site origin (e.g. `"example.com"` for `https://app.example.com`).
    pub rp_id: String,
    /// The full origin the browser will see when calling `navigator
    /// .credentials.create` / `.get` (e.g. `https://app.example.com`).
    pub rp_origin: Url,
    /// Display name shown to users in the platform's passkey UI.
    pub rp_name: String,
    /// How long an unfinished ceremony stays valid. Defaults to 5 minutes,
    /// matching the W3C recommended authenticator timeout.
    pub challenge_lifetime: Duration,
    /// Renderer for passkey lifecycle security notifications. Defaults to
    /// [`DefaultBauthEmails`](crate::email::DefaultBauthEmails); hosts that
    /// want branded copy can replace this with their own [`BauthEmails`]
    /// implementation.
    pub emails: Arc<dyn BauthEmails>,
}

impl std::fmt::Debug for PasskeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyConfig")
            .field("rp_id", &self.rp_id)
            .field("rp_origin", &self.rp_origin)
            .field("rp_name", &self.rp_name)
            .field("challenge_lifetime", &self.challenge_lifetime)
            .finish()
    }
}

impl PasskeyConfig {
    pub fn new(rp_id: impl Into<String>, rp_origin: Url, rp_name: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            rp_origin,
            rp_name: rp_name.into(),
            challenge_lifetime: Duration::from_secs(300),
            emails: default_emails(),
        }
    }
}

/// Manager for passkey registration, authentication, listing, and removal.
#[derive(Clone)]
pub struct PasskeyManager {
    users: Arc<dyn UserStore>,
    credentials: Arc<dyn PasskeyCredentialStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    sessions: SessionManager,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    notifier: SecurityEmailNotifier,
    webauthn: Arc<Webauthn>,
    config: PasskeyConfig,
}

impl PasskeyManager {
    pub fn new(
        users: Arc<dyn UserStore>,
        credentials: Arc<dyn PasskeyCredentialStore>,
        challenges: Arc<dyn PasskeyChallengeStore>,
        sessions: SessionManager,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        email: Arc<dyn EmailSender>,
        config: PasskeyConfig,
    ) -> Result<Self> {
        let notifier = SecurityEmailNotifier::new(email, config.emails.clone());
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
            .map_err(|e| Error::InvalidRelyingParty(e.to_string()))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| Error::InvalidRelyingParty(e.to_string()))?;

        Ok(Self {
            users,
            credentials,
            challenges,
            sessions,
            clock,
            audit,
            notifier,
            webauthn: Arc::new(webauthn),
            config,
        })
    }

    /// Diagnostic accessor used by the axum builder's startup warnings to
    /// detect dev-only email transports.
    #[doc(hidden)]
    pub fn notification_email_kind(&self) -> crate::email::EmailSenderKind {
        self.notifier.sender_kind()
    }

    /// Clone the security-notification helper used by this manager.
    /// Axum uses it for session-management notifications so the same
    /// configured sender and template renderer cover every bundled
    /// security notice.
    #[doc(hidden)]
    pub fn security_email_notifier(&self) -> SecurityEmailNotifier {
        self.notifier.clone()
    }

    /// Begin registering a new passkey for `user_id`. The returned
    /// [`CreationChallengeResponse`] is the JSON payload to hand to
    /// `navigator.credentials.create` on the client; the
    /// [`PasskeyChallengeId`] is what the client must echo back to
    /// [`PasskeyManager::finish_registration`].
    #[tracing::instrument(skip(self), fields(method = "passkey", user_id = %user_id))]
    pub async fn start_registration(
        &self,
        user_id: UserId,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        self.start_registration_inner(user_id, None).await
    }

    /// Begin registering a new passkey and associate optional recovery
    /// cool-down metadata with the in-progress ceremony. If the registration
    /// later finishes through [`PasskeyManager::finish_registration`], the
    /// stored credential receives the same timestamp. Callers deriving this
    /// value from an authenticated session should pass
    /// [`crate::storage::Session::active_recovery_cooldown_until`] rather
    /// than the raw session field so expired cool-downs are not propagated.
    #[tracing::instrument(skip(self), fields(method = "passkey", user_id = %user_id))]
    pub async fn start_registration_with_recovery_cooldown(
        &self,
        user_id: UserId,
        recovery_cooldown_until: Option<DateTime<Utc>>,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        self.start_registration_inner(user_id, recovery_cooldown_until)
            .await
    }

    async fn start_registration_inner(
        &self,
        user_id: UserId,
        recovery_cooldown_until: Option<DateTime<Utc>>,
    ) -> Result<(PasskeyChallengeId, CreationChallengeResponse)> {
        let user = self
            .users
            .find_user_by_id(user_id)
            .await?
            .ok_or(Error::UserNotFound)?;

        let (user_name, user_display_name) = display_names_for(&user);

        let existing = self.credentials.list_passkeys_for_user(user_id).await?;
        let exclude = if existing.is_empty() {
            None
        } else {
            // The top-level credential id is enough to exclude already-registered
            // authenticators; no need to deserialise each opaque passkey blob.
            Some(
                existing
                    .iter()
                    .map(|c| CredentialID::from(c.credential_id.clone()))
                    .collect(),
            )
        };

        let (mut ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_id.0, &user_name, &user_display_name, exclude)
            .map_err(|e| Error::Webauthn(e.to_string()))?;
        require_discoverable_credential(&mut ccr);

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        let stored = StoredPasskeyRegistration {
            id,
            user_id,
            state: encode_registration_state(&reg_state)?,
            created_at: now,
            expires_at: now + challenge_lifetime(self.config.challenge_lifetime),
            recovery_cooldown_until,
        };
        self.challenges.put_registration(stored).await?;
        tracing::info!(outcome = "started", "passkey registration started");
        Ok((id, ccr))
    }

    /// Complete a registration ceremony. On success the passkey is
    /// persisted and a [`CredentialAdded`](AuditEventKind::CredentialAdded)
    /// event is emitted. If the registration challenge was started with
    /// recovery cool-down metadata, the stored passkey receives that same
    /// timestamp.
    #[tracing::instrument(
        skip(self, response, name, context),
        fields(method = "passkey", user_id = tracing::field::Empty),
    )]
    pub async fn finish_registration(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<StoredPasskey> {
        self.finish_registration_inner(challenge_id, response, name, context, None)
            .await
    }

    /// Complete a registration ceremony while overriding any cool-down stored
    /// on the challenge. Recovery flows use this to bind the exact deadline
    /// they also apply to the newly issued session.
    #[tracing::instrument(
        skip(self, response, name, context),
        fields(method = "passkey", user_id = tracing::field::Empty),
    )]
    pub async fn finish_registration_with_recovery_cooldown(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
        recovery_cooldown_until: DateTime<Utc>,
    ) -> Result<StoredPasskey> {
        self.finish_registration_inner(
            challenge_id,
            response,
            name,
            context,
            Some(recovery_cooldown_until),
        )
        .await
    }

    async fn finish_registration_inner(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
        recovery_cooldown_override: Option<DateTime<Utc>>,
    ) -> Result<StoredPasskey> {
        let now = self.clock.now();
        let Some(stored) = self.challenges.take_registration(challenge_id).await? else {
            tracing::warn!(outcome = "invalid_challenge", "passkey registration failed");
            return Err(Error::InvalidPasskeyChallenge);
        };
        if stored.expires_at <= now {
            tracing::warn!(outcome = "expired_challenge", "passkey registration failed");
            return Err(Error::InvalidPasskeyChallenge);
        }
        let user_id = stored.user_id;
        let challenge_recovery_cooldown_until = stored.recovery_cooldown_until;
        tracing::Span::current().record("user_id", tracing::field::display(user_id));

        let reg_state = decode_registration_state(&stored.state)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &reg_state)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let credential = StoredPasskey {
            credential_id: passkey.cred_id().to_vec(),
            user_id,
            passkey: encode_credential(&passkey)?,
            name,
            created_at: now,
            last_used_at: None,
            recovery_cooldown_until: recovery_cooldown_override
                .or(challenge_recovery_cooldown_until),
        };
        self.credentials.add_passkey(credential.clone()).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::CredentialAdded { user_id },
            })
            .await;
        self.notify_passkey_registered(user_id, credential.name.as_deref())
            .await;
        tracing::info!(outcome = "registered", "passkey registered");
        Ok(credential)
    }

    async fn notify_passkey_registered(&self, user_id: UserId, passkey_name: Option<&str>) {
        match self.users.find_user_by_id(user_id).await {
            Ok(Some(user)) => self.notifier.passkey_registered(&user, passkey_name).await,
            Ok(None) => {
                tracing::warn!(
                    %user_id,
                    "passkey registered notification skipped because user was not found"
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    %user_id,
                    "passkey registered notification skipped because user lookup failed"
                );
            }
        }
    }

    async fn notify_passkey_removed(&self, user_id: UserId, passkey_name: Option<&str>) {
        match self.users.find_user_by_id(user_id).await {
            Ok(Some(user)) => self.notifier.passkey_removed(&user, passkey_name).await,
            Ok(None) => {
                tracing::warn!(
                    %user_id,
                    "passkey removed notification skipped because user was not found"
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    %user_id,
                    "passkey removed notification skipped because user lookup failed"
                );
            }
        }
    }

    /// Begin a discoverable passkey authentication ceremony. Returns the
    /// [`RequestChallengeResponse`] for `navigator.credentials.get` and a
    /// [`PasskeyChallengeId`] the client must echo back. No user input is
    /// accepted, so every caller receives the same challenge shape and the
    /// user is identified only at finish-time from the authenticator response.
    #[tracing::instrument(skip(self), fields(method = "passkey"))]
    pub async fn start_authentication(
        &self,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let (rcr, auth_state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        let stored = StoredPasskeyAuthentication {
            id,
            state: encode_authentication_state(&auth_state)?,
            created_at: now,
            expires_at: now + challenge_lifetime(self.config.challenge_lifetime),
        };
        self.challenges.put_authentication(stored).await?;
        tracing::info!(outcome = "started", "passkey authentication started");
        Ok((id, rcr))
    }

    /// Complete an authentication ceremony, issuing a session on success.
    /// If the authenticated passkey still carries an active recovery
    /// cool-down deadline, the issued session inherits that restriction.
    #[tracing::instrument(
        skip(self, response, context),
        fields(method = "passkey", user_id = tracing::field::Empty),
    )]
    pub async fn finish_authentication(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &PublicKeyCredential,
        context: SessionContext,
    ) -> Result<IssuedSession> {
        let now = self.clock.now();
        let Some(stored) = self.challenges.take_authentication(challenge_id).await? else {
            tracing::warn!(outcome = "invalid_challenge", "passkey login failed");
            return Err(Error::InvalidPasskeyChallenge);
        };
        if stored.expires_at <= now {
            tracing::warn!(outcome = "expired_challenge", "passkey login failed");
            return Err(Error::InvalidPasskeyChallenge);
        }

        let cred_id_bytes: &[u8] = response.raw_id.as_ref();
        let Some(mut credential) = self
            .credentials
            .find_passkey_by_credential_id(cred_id_bytes)
            .await?
        else {
            tracing::warn!(outcome = "credential_not_found", "passkey login failed");
            return Err(Error::PasskeyNotFound);
        };

        if let Some(asserted_user) = user_id_from_handle(response)?
            && asserted_user != credential.user_id
        {
            tracing::warn!(outcome = "ownership_mismatch", "passkey login failed");
            return Err(Error::PasskeyOwnershipMismatch);
        }
        tracing::Span::current().record("user_id", tracing::field::display(credential.user_id));

        let mut passkey = decode_credential(&credential.passkey)?;
        let discoverable = [DiscoverableKey::from(&passkey)];
        let auth_state = decode_authentication_state(&stored.state)?;
        let auth_result = self
            .webauthn
            .finish_discoverable_authentication(response, auth_state, &discoverable)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let user_id = credential.user_id;
        let active_recovery_cooldown_until = credential
            .recovery_cooldown_until
            .as_ref()
            .filter(|until| now < **until)
            .cloned();

        // Counter / backup-state updates are advisory per webauthn-rs;
        // last_used_at always advances, so we persist on every success. The
        // mutated passkey is re-serialised into the opaque blob; `credential`
        // is then moved into the store rather than cloned — nothing below
        // reads it, only the `user_id` captured above.
        passkey.update_credential(&auth_result);
        credential.passkey = encode_credential(&passkey)?;
        credential.last_used_at = Some(now);
        self.credentials.update_passkey(credential).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::LoginSucceeded { user_id },
            })
            .await;

        tracing::info!(outcome = "succeeded", "passkey login succeeded");
        match active_recovery_cooldown_until {
            Some(cooldown_until) => {
                self.sessions
                    .create_restricted(user_id, context, cooldown_until)
                    .await
            }
            None => self.sessions.create(user_id, context).await,
        }
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_passkeys(&self, user_id: UserId) -> Result<Vec<StoredPasskey>> {
        Ok(self.credentials.list_passkeys_for_user(user_id).await?)
    }

    /// List the user's passkeys as metadata-only [`PasskeySummary`] values.
    /// Backs the management listing and count paths without deserialising
    /// the credential blob.
    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list_passkey_summaries(&self, user_id: UserId) -> Result<Vec<PasskeySummary>> {
        Ok(self
            .credentials
            .list_passkey_summaries_for_user(user_id)
            .await?)
    }

    /// Remove a passkey. The `user_id` argument is enforced server-side
    /// so a session for user A cannot delete user B's credential by
    /// guessing a credential id.
    #[tracing::instrument(skip(self, credential_id, context), fields(user_id = %user_id))]
    pub async fn remove_passkey(
        &self,
        user_id: UserId,
        credential_id: &[u8],
        context: SessionContext,
    ) -> Result<()> {
        let Some(credential) = self
            .credentials
            .find_passkey_by_credential_id(credential_id)
            .await?
        else {
            tracing::warn!(outcome = "credential_not_found", "passkey remove failed");
            return Err(Error::PasskeyNotFound);
        };
        if credential.user_id != user_id {
            tracing::warn!(outcome = "ownership_mismatch", "passkey remove failed");
            return Err(Error::PasskeyOwnershipMismatch);
        }
        self.credentials.delete_passkey(credential_id).await?;
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::CredentialRemoved { user_id },
            })
            .await;
        self.notify_passkey_removed(user_id, credential.name.as_deref())
            .await;
        tracing::info!(outcome = "removed", "passkey removed");
        Ok(())
    }
}

fn display_names_for(user: &User) -> (String, String) {
    let id_str = user.id.to_string();
    let name = user.email.clone().unwrap_or_else(|| id_str.clone());
    (name.clone(), name)
}

fn require_discoverable_credential(ccr: &mut CreationChallengeResponse) {
    let selection = ccr
        .public_key
        .authenticator_selection
        .as_mut()
        .expect("webauthn-rs passkey registration includes authenticator selection");
    selection.require_resident_key = true;
    selection.resident_key = Some(ResidentKeyRequirement::Required);
}

fn user_id_from_handle(response: &PublicKeyCredential) -> Result<Option<UserId>> {
    response
        .response
        .user_handle
        .as_ref()
        .map(|handle| {
            Uuid::from_slice(handle.as_ref())
                .map(UserId)
                .map_err(|_| Error::PasskeyNotFound)
        })
        .transpose()
}

// Opaque-blob (de)serialisation. The storage traits deal in `Vec<u8>` so a
// host's store needs no `webauthn-rs` dependency; `bauth-core` is the only
// layer that knows the blob is JSON-serialised `webauthn-rs` state.

fn encode_credential(passkey: &Passkey) -> Result<Vec<u8>> {
    serde_json::to_vec(passkey).map_err(|e| Error::Webauthn(format!("serialise credential: {e}")))
}

fn decode_credential(bytes: &[u8]) -> Result<Passkey> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Webauthn(format!("deserialise credential: {e}")))
}

fn encode_registration_state(state: &PasskeyRegistration) -> Result<Vec<u8>> {
    serde_json::to_vec(state)
        .map_err(|e| Error::Webauthn(format!("serialise registration state: {e}")))
}

fn decode_registration_state(bytes: &[u8]) -> Result<PasskeyRegistration> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Webauthn(format!("deserialise registration state: {e}")))
}

fn encode_authentication_state(state: &DiscoverableAuthentication) -> Result<Vec<u8>> {
    serde_json::to_vec(state)
        .map_err(|e| Error::Webauthn(format!("serialise authentication state: {e}")))
}

fn decode_authentication_state(bytes: &[u8]) -> Result<DiscoverableAuthentication> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Webauthn(format!("deserialise authentication state: {e}")))
}

fn challenge_lifetime(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d)
        .expect("passkey challenge lifetime overflows chrono::Duration; configure a smaller value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn config_constructor_sets_default_lifetime() {
        let c = PasskeyConfig::new(
            "example.com",
            Url::parse("https://example.com").expect("valid url"),
            "Example",
        );
        assert_eq!(c.challenge_lifetime, Duration::from_secs(300));
        assert_eq!(c.rp_id, "example.com");
        assert_eq!(c.rp_name, "Example");
    }
}
