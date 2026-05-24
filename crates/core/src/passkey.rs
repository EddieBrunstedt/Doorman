//! Passkey (WebAuthn) registration and authentication ceremonies.
//!
//! The manager wraps a `webauthn-rs` [`Webauthn`] instance and composes
//! it with the user store, the passkey credential store, and a separate
//! challenge store that holds the per-ceremony server-side state between
//! the `start_*` and `finish_*` calls. Audit events are emitted at every
//! meaningful step so the host can build a complete security timeline.
//!
//! Account linking falls out of the design for free: register a passkey
//! against any existing user id, including one created via the password
//! flow, and that user now has both credentials.

use std::sync::Arc;
use std::time::Duration;

use url::Url;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

use crate::audit::{AuditEvent, AuditEventKind, AuditSink, AuthMethod, CredentialKind};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::session::{IssuedSession, SessionContext, SessionManager};
use crate::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore, StoredPasskey,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, User, UserId, UserStore,
};

#[derive(Debug, Clone)]
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
}

impl PasskeyConfig {
    pub fn new(rp_id: impl Into<String>, rp_origin: Url, rp_name: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            rp_origin,
            rp_name: rp_name.into(),
            challenge_lifetime: Duration::from_secs(300),
        }
    }
}

#[derive(Clone)]
pub struct PasskeyManager {
    users: Arc<dyn UserStore>,
    credentials: Arc<dyn PasskeyCredentialStore>,
    challenges: Arc<dyn PasskeyChallengeStore>,
    sessions: SessionManager,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
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
        config: PasskeyConfig,
    ) -> Result<Self> {
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
            webauthn: Arc::new(webauthn),
            config,
        })
    }

    /// Begin registering a new passkey for `user_id`. The returned
    /// [`CreationChallengeResponse`] is the JSON payload to hand to
    /// `navigator.credentials.create` on the client; the
    /// [`PasskeyChallengeId`] is what the client must echo back to
    /// [`PasskeyManager::finish_registration`].
    pub async fn start_registration(
        &self,
        user_id: UserId,
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
            Some(
                existing
                    .iter()
                    .map(|c| c.passkey.cred_id().clone())
                    .collect(),
            )
        };

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_id.0, &user_name, &user_display_name, exclude)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        let stored = StoredPasskeyRegistration {
            id,
            user_id,
            state: reg_state,
            created_at: now,
            expires_at: now + challenge_lifetime(self.config.challenge_lifetime),
        };
        self.challenges.put_registration(stored).await?;
        Ok((id, ccr))
    }

    /// Complete a registration ceremony. On success the passkey is
    /// persisted and a [`CredentialAdded`](AuditEventKind::CredentialAdded)
    /// event is emitted.
    pub async fn finish_registration(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
    ) -> Result<StoredPasskey> {
        let now = self.clock.now();
        let Some(stored) = self.challenges.take_registration(challenge_id).await? else {
            return Err(Error::InvalidPasskeyChallenge);
        };
        if stored.expires_at <= now {
            return Err(Error::InvalidPasskeyChallenge);
        }

        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &stored.state)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let credential = StoredPasskey {
            credential_id: passkey.cred_id().to_vec(),
            user_id: stored.user_id,
            passkey,
            name,
            created_at: now,
            last_used_at: None,
        };
        self.credentials.add_passkey(credential.clone()).await?;

        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::CredentialAdded {
                    user_id: stored.user_id,
                    credential_kind: CredentialKind::Passkey,
                },
            })
            .await;
        Ok(credential)
    }

    /// Begin authenticating an existing user by email. Returns the
    /// [`RequestChallengeResponse`] for `navigator.credentials.get` and a
    /// [`PasskeyChallengeId`] the client must echo back. Unknown emails
    /// are silently accepted (with no credentials) so the endpoint does
    /// not double as an account-enumeration oracle.
    pub async fn start_authentication(
        &self,
        email: &str,
    ) -> Result<(PasskeyChallengeId, RequestChallengeResponse)> {
        let email_normalized = normalize_email(email);
        let user = self.users.find_user_by_email(&email_normalized).await?;

        let (user_id, passkeys): (Option<UserId>, Vec<Passkey>) = match user {
            Some(u) => {
                let creds = self.credentials.list_passkeys_for_user(u.id).await?;
                let pks = creds.into_iter().map(|c| c.passkey).collect();
                (Some(u.id), pks)
            }
            None => (None, Vec::new()),
        };

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        let now = self.clock.now();
        let id = PasskeyChallengeId::new();
        let stored = StoredPasskeyAuthentication {
            id,
            user_id,
            state: auth_state,
            created_at: now,
            expires_at: now + challenge_lifetime(self.config.challenge_lifetime),
        };
        self.challenges.put_authentication(stored).await?;
        Ok((id, rcr))
    }

    /// Complete an authentication ceremony, issuing a session on success.
    pub async fn finish_authentication(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &PublicKeyCredential,
        context: SessionContext,
    ) -> Result<IssuedSession> {
        let now = self.clock.now();
        let Some(stored) = self.challenges.take_authentication(challenge_id).await? else {
            return Err(Error::InvalidPasskeyChallenge);
        };
        if stored.expires_at <= now {
            return Err(Error::InvalidPasskeyChallenge);
        }

        let cred_id_bytes: &[u8] = response.raw_id.as_ref();
        let Some(mut credential) = self
            .credentials
            .find_passkey_by_credential_id(cred_id_bytes)
            .await?
        else {
            return Err(Error::PasskeyNotFound);
        };

        // If start_authentication recorded the intended user, enforce
        // that the asserted credential actually belongs to them. This
        // closes off "use any registered passkey to log in as anyone"
        // when the host uses email-first UX.
        if let Some(expected_user) = stored.user_id
            && credential.user_id != expected_user
        {
            return Err(Error::PasskeyOwnershipMismatch);
        }

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(response, &stored.state)
            .map_err(|e| Error::Webauthn(e.to_string()))?;

        // Counter / backup-state updates are advisory per webauthn-rs;
        // last_used_at always advances, so we persist on every success.
        credential.passkey.update_credential(&auth_result);
        credential.last_used_at = Some(now);
        self.credentials.update_passkey(credential.clone()).await?;

        let user_id = credential.user_id;
        self.audit
            .emit(AuditEvent {
                timestamp: now,
                ip: context.ip.clone(),
                user_agent: context.user_agent.clone(),
                kind: AuditEventKind::LoginSucceeded {
                    user_id,
                    method: AuthMethod::Passkey,
                },
            })
            .await;

        self.sessions.create(user_id, context).await
    }

    pub async fn list_passkeys(&self, user_id: UserId) -> Result<Vec<StoredPasskey>> {
        Ok(self.credentials.list_passkeys_for_user(user_id).await?)
    }

    /// Remove a passkey. The `user_id` argument is enforced server-side
    /// so a session for user A cannot delete user B's credential by
    /// guessing a credential id.
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
            return Err(Error::PasskeyNotFound);
        };
        if credential.user_id != user_id {
            return Err(Error::PasskeyOwnershipMismatch);
        }
        self.credentials.delete_passkey(credential_id).await?;
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                ip: context.ip,
                user_agent: context.user_agent,
                kind: AuditEventKind::CredentialRemoved {
                    user_id,
                    credential_kind: CredentialKind::Passkey,
                },
            })
            .await;
        Ok(())
    }
}

fn display_names_for(user: &User) -> (String, String) {
    let id_str = user.id.to_string();
    let name = user.email.clone().unwrap_or_else(|| id_str.clone());
    (name.clone(), name)
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
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
            Url::parse("https://example.com").unwrap(),
            "Example",
        );
        assert_eq!(c.challenge_lifetime, Duration::from_secs(300));
        assert_eq!(c.rp_id, "example.com");
        assert_eq!(c.rp_name, "Example");
    }

    #[test]
    fn email_normalisation_matches_password_module() {
        assert_eq!(normalize_email("  Bob@Example.COM "), "bob@example.com");
    }
}
