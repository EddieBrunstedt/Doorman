//! Postgres adapter backed by `sqlx::PgPool`.

use std::sync::Arc;

use async_trait::async_trait;
use bauth_core::error::{StorageError, StorageResult};
use bauth_core::storage::{
    OAuthIdentity, OAuthIdentityStore, OAuthStateId, OAuthStateStore, PasskeyChallengeId,
    PasskeyChallengeStore, PasskeyCredentialStore, PasswordCredential, PasswordCredentialStore,
    PendingOAuthAuthorization, Session, SessionId, SessionStore, Storage, StoredPasskey,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, User, UserId, UserStore,
    VerificationPurpose, VerificationToken, VerificationTokenStore,
};
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};

use crate::common::{
    purpose_from_str, purpose_to_str, storage, token_hash_bytes, token_hash_from_bytes,
    uuid_from_row, uuid_to_bytes,
};

/// Postgres storage adapter. Construct once at startup and hand
/// `storage()` to the quickstart builder, or pull individual stores via
/// the helpers below when wiring managers by hand.
#[derive(Clone)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    /// Open a pool against `url`, e.g. `"postgres://user:pass@host/db"`.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new().max_connections(8).connect(url).await?;
        Ok(Self { pool })
    }

    /// Construct directly from an already-built pool. Useful when the
    /// host wants custom pool tuning.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run the embedded migrations. Idempotent — safe to call on every
    /// boot.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations/postgres")
            .run(&self.pool)
            .await
    }

    /// Build a [`Storage`] populated with every per-concern store backed
    /// by this pool.
    pub fn storage(&self) -> Storage {
        Storage {
            users: self.user_store(),
            sessions: self.session_store(),
            passwords: self.password_credential_store(),
            verification_tokens: self.verification_token_store(),
            passkey_credentials: self.passkey_credential_store(),
            passkey_challenges: self.passkey_challenge_store(),
            oauth_identities: self.oauth_identity_store(),
            oauth_states: self.oauth_state_store(),
        }
    }

    pub fn user_store(&self) -> Arc<dyn UserStore> {
        Arc::new(PgUserStore {
            pool: self.pool.clone(),
        })
    }

    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(PgSessionStore {
            pool: self.pool.clone(),
        })
    }

    pub fn password_credential_store(&self) -> Arc<dyn PasswordCredentialStore> {
        Arc::new(PgPasswordCredentialStore {
            pool: self.pool.clone(),
        })
    }

    pub fn verification_token_store(&self) -> Arc<dyn VerificationTokenStore> {
        Arc::new(PgVerificationTokenStore {
            pool: self.pool.clone(),
        })
    }

    pub fn passkey_credential_store(&self) -> Arc<dyn PasskeyCredentialStore> {
        Arc::new(PgPasskeyCredentialStore {
            pool: self.pool.clone(),
        })
    }

    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(PgPasskeyChallengeStore {
            pool: self.pool.clone(),
        })
    }

    pub fn oauth_identity_store(&self) -> Arc<dyn OAuthIdentityStore> {
        Arc::new(PgOAuthIdentityStore {
            pool: self.pool.clone(),
        })
    }

    pub fn oauth_state_store(&self) -> Arc<dyn OAuthStateStore> {
        Arc::new(PgOAuthStateStore {
            pool: self.pool.clone(),
        })
    }
}

// -----------------------------------------------------------------------------
// users
// -----------------------------------------------------------------------------

struct PgUserStore {
    pool: PgPool,
}

#[async_trait]
impl UserStore for PgUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO users (id, email, email_verified_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(uuid_to_bytes(user.id.0))
        .bind(&user.email)
        .bind(user.email_verified_at)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, email_verified_at, created_at, updated_at
             FROM users WHERE id = $1",
        )
        .bind(uuid_to_bytes(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_user).transpose()
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, email_verified_at, created_at, updated_at
             FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_user).transpose()
    }

    async fn update_user(&self, user: User) -> StorageResult<()> {
        let result = sqlx::query(
            "UPDATE users
             SET email = $1, email_verified_at = $2, updated_at = $3
             WHERE id = $4",
        )
        .bind(&user.email)
        .bind(user.email_verified_at)
        .bind(user.updated_at)
        .bind(uuid_to_bytes(user.id.0))
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::msg("user not found"));
        }
        Ok(())
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(uuid_to_bytes(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }
}

fn row_to_user(row: PgRow) -> StorageResult<User> {
    let id_bytes: Vec<u8> = row.try_get("id").map_err(storage)?;
    Ok(User {
        id: UserId(uuid_from_row(id_bytes)?),
        email: row.try_get("email").map_err(storage)?,
        email_verified_at: row.try_get("email_verified_at").map_err(storage)?,
        created_at: row.try_get("created_at").map_err(storage)?,
        updated_at: row.try_get("updated_at").map_err(storage)?,
    })
}

// -----------------------------------------------------------------------------
// sessions
// -----------------------------------------------------------------------------

struct PgSessionStore {
    pool: PgPool,
}

#[async_trait]
impl SessionStore for PgSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, ip, user_agent)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(uuid_to_bytes(session.id.0))
        .bind(uuid_to_bytes(session.user_id.0))
        .bind(token_hash_bytes(&session.token_hash))
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(&session.ip)
        .bind(&session.user_agent)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let row = sqlx::query(
            "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent
             FROM sessions WHERE token_hash = $1",
        )
        .bind(token_hash_bytes(hash))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_session).transpose()
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        let row = sqlx::query(
            "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent
             FROM sessions WHERE id = $1",
        )
        .bind(uuid_to_bytes(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_session).transpose()
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(uuid_to_bytes(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(uuid_to_bytes(user_id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected())
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected())
    }
}

fn row_to_session(row: PgRow) -> StorageResult<Session> {
    let id_bytes: Vec<u8> = row.try_get("id").map_err(storage)?;
    let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err(storage)?;
    let hash_bytes: Vec<u8> = row.try_get("token_hash").map_err(storage)?;
    Ok(Session {
        id: SessionId(uuid_from_row(id_bytes)?),
        user_id: UserId(uuid_from_row(user_id_bytes)?),
        token_hash: token_hash_from_bytes(&hash_bytes)?,
        created_at: row.try_get("created_at").map_err(storage)?,
        expires_at: row.try_get("expires_at").map_err(storage)?,
        ip: row.try_get("ip").map_err(storage)?,
        user_agent: row.try_get("user_agent").map_err(storage)?,
    })
}

// -----------------------------------------------------------------------------
// password credentials
// -----------------------------------------------------------------------------

struct PgPasswordCredentialStore {
    pool: PgPool,
}

#[async_trait]
impl PasswordCredentialStore for PgPasswordCredentialStore {
    async fn set_password(&self, credential: PasswordCredential) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO password_credentials (user_id, hash, updated_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash, updated_at = EXCLUDED.updated_at",
        )
        .bind(uuid_to_bytes(credential.user_id.0))
        .bind(&credential.hash)
        .bind(credential.updated_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn get_password(&self, user_id: UserId) -> StorageResult<Option<PasswordCredential>> {
        let row = sqlx::query(
            "SELECT user_id, hash, updated_at FROM password_credentials WHERE user_id = $1",
        )
        .bind(uuid_to_bytes(user_id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        let Some(row) = row else { return Ok(None) };
        let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err(storage)?;
        Ok(Some(PasswordCredential {
            user_id: UserId(uuid_from_row(user_id_bytes)?),
            hash: row.try_get("hash").map_err(storage)?,
            updated_at: row.try_get("updated_at").map_err(storage)?,
        }))
    }

    async fn delete_password(&self, user_id: UserId) -> StorageResult<()> {
        sqlx::query("DELETE FROM password_credentials WHERE user_id = $1")
            .bind(uuid_to_bytes(user_id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// verification tokens
// -----------------------------------------------------------------------------

struct PgVerificationTokenStore {
    pool: PgPool,
}

#[async_trait]
impl VerificationTokenStore for PgVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO verification_tokens (token_hash, purpose, user_id, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(token_hash_bytes(&token.token_hash))
        .bind(purpose_to_str(token.purpose))
        .bind(uuid_to_bytes(token.user_id.0))
        .bind(token.created_at)
        .bind(token.expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        let row = sqlx::query(
            "DELETE FROM verification_tokens
             WHERE token_hash = $1 AND purpose = $2
             RETURNING token_hash, purpose, user_id, created_at, expires_at",
        )
        .bind(token_hash_bytes(hash))
        .bind(purpose_to_str(purpose))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_verification_token).transpose()
    }

    async fn find_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        let row = sqlx::query(
            "SELECT token_hash, purpose, user_id, created_at, expires_at
             FROM verification_tokens WHERE token_hash = $1 AND purpose = $2",
        )
        .bind(token_hash_bytes(hash))
        .bind(purpose_to_str(purpose))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_verification_token).transpose()
    }

    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        let result =
            sqlx::query("DELETE FROM verification_tokens WHERE user_id = $1 AND purpose = $2")
                .bind(uuid_to_bytes(user_id.0))
                .bind(purpose_to_str(purpose))
                .execute(&self.pool)
                .await
                .map_err(storage)?;
        Ok(result.rows_affected())
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let result = sqlx::query("DELETE FROM verification_tokens WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected())
    }
}

fn row_to_verification_token(row: PgRow) -> StorageResult<VerificationToken> {
    let hash_bytes: Vec<u8> = row.try_get("token_hash").map_err(storage)?;
    let purpose_str: String = row.try_get("purpose").map_err(storage)?;
    let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err(storage)?;
    Ok(VerificationToken {
        token_hash: token_hash_from_bytes(&hash_bytes)?,
        purpose: purpose_from_str(&purpose_str)?,
        user_id: UserId(uuid_from_row(user_id_bytes)?),
        created_at: row.try_get("created_at").map_err(storage)?,
        expires_at: row.try_get("expires_at").map_err(storage)?,
    })
}

// -----------------------------------------------------------------------------
// passkey credentials
// -----------------------------------------------------------------------------

struct PgPasskeyCredentialStore {
    pool: PgPool,
}

#[async_trait]
impl PasskeyCredentialStore for PgPasskeyCredentialStore {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let serialized = serde_json::to_string(&credential.passkey).map_err(storage)?;
        sqlx::query(
            "INSERT INTO passkey_credentials
             (credential_id, user_id, passkey, name, created_at, last_used_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&credential.credential_id)
        .bind(uuid_to_bytes(credential.user_id.0))
        .bind(serialized)
        .bind(&credential.name)
        .bind(credential.created_at)
        .bind(credential.last_used_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let serialized = serde_json::to_string(&credential.passkey).map_err(storage)?;
        let result = sqlx::query(
            "UPDATE passkey_credentials
             SET user_id = $1, passkey = $2, name = $3, created_at = $4, last_used_at = $5
             WHERE credential_id = $6",
        )
        .bind(uuid_to_bytes(credential.user_id.0))
        .bind(serialized)
        .bind(&credential.name)
        .bind(credential.created_at)
        .bind(credential.last_used_at)
        .bind(&credential.credential_id)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::msg("passkey credential not found"));
        }
        Ok(())
    }

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>> {
        let rows = sqlx::query(
            "SELECT credential_id, user_id, passkey, name, created_at, last_used_at
             FROM passkey_credentials WHERE user_id = $1",
        )
        .bind(uuid_to_bytes(user_id.0))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter().map(row_to_passkey).collect()
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        let row = sqlx::query(
            "SELECT credential_id, user_id, passkey, name, created_at, last_used_at
             FROM passkey_credentials WHERE credential_id = $1",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_passkey).transpose()
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        sqlx::query("DELETE FROM passkey_credentials WHERE credential_id = $1")
            .bind(credential_id)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }
}

fn row_to_passkey(row: PgRow) -> StorageResult<StoredPasskey> {
    let credential_id: Vec<u8> = row.try_get("credential_id").map_err(storage)?;
    let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err(storage)?;
    let passkey_json: String = row.try_get("passkey").map_err(storage)?;
    let passkey: Passkey = serde_json::from_str(&passkey_json).map_err(storage)?;
    Ok(StoredPasskey {
        credential_id,
        user_id: UserId(uuid_from_row(user_id_bytes)?),
        passkey,
        name: row.try_get("name").map_err(storage)?,
        created_at: row.try_get("created_at").map_err(storage)?,
        last_used_at: row.try_get("last_used_at").map_err(storage)?,
    })
}

// -----------------------------------------------------------------------------
// passkey challenges (registrations + authentications)
// -----------------------------------------------------------------------------

struct PgPasskeyChallengeStore {
    pool: PgPool,
}

#[async_trait]
impl PasskeyChallengeStore for PgPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        let serialized = serde_json::to_string(&value.state).map_err(storage)?;
        sqlx::query(
            "INSERT INTO passkey_registrations (id, user_id, state, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(uuid_to_bytes(value.id.0))
        .bind(uuid_to_bytes(value.user_id.0))
        .bind(serialized)
        .bind(value.created_at)
        .bind(value.expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        let row = sqlx::query(
            "DELETE FROM passkey_registrations WHERE id = $1
             RETURNING id, user_id, state, created_at, expires_at",
        )
        .bind(uuid_to_bytes(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        let Some(row) = row else { return Ok(None) };
        let id_bytes: Vec<u8> = row.try_get("id").map_err(storage)?;
        let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err(storage)?;
        let state_json: String = row.try_get("state").map_err(storage)?;
        let state: PasskeyRegistration = serde_json::from_str(&state_json).map_err(storage)?;
        Ok(Some(StoredPasskeyRegistration {
            id: PasskeyChallengeId(uuid_from_row(id_bytes)?),
            user_id: UserId(uuid_from_row(user_id_bytes)?),
            state,
            created_at: row.try_get("created_at").map_err(storage)?,
            expires_at: row.try_get("expires_at").map_err(storage)?,
        }))
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        let serialized = serde_json::to_string(&value.state).map_err(storage)?;
        sqlx::query(
            "INSERT INTO passkey_authentications (id, user_id, state, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(uuid_to_bytes(value.id.0))
        .bind(value.user_id.map(|u| uuid_to_bytes(u.0)))
        .bind(serialized)
        .bind(value.created_at)
        .bind(value.expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        let row = sqlx::query(
            "DELETE FROM passkey_authentications WHERE id = $1
             RETURNING id, user_id, state, created_at, expires_at",
        )
        .bind(uuid_to_bytes(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        let Some(row) = row else { return Ok(None) };
        let id_bytes: Vec<u8> = row.try_get("id").map_err(storage)?;
        let user_id_bytes: Option<Vec<u8>> = row.try_get("user_id").map_err(storage)?;
        let state_json: String = row.try_get("state").map_err(storage)?;
        let state: PasskeyAuthentication = serde_json::from_str(&state_json).map_err(storage)?;
        let user_id = user_id_bytes
            .map(|b| uuid_from_row(b).map(UserId))
            .transpose()?;
        Ok(Some(StoredPasskeyAuthentication {
            id: PasskeyChallengeId(uuid_from_row(id_bytes)?),
            user_id,
            state,
            created_at: row.try_get("created_at").map_err(storage)?,
            expires_at: row.try_get("expires_at").map_err(storage)?,
        }))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let reg = sqlx::query("DELETE FROM passkey_registrations WHERE expires_at <= $1")
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        let auth = sqlx::query("DELETE FROM passkey_authentications WHERE expires_at <= $1")
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        tx.commit().await.map_err(storage)?;
        Ok(reg.rows_affected() + auth.rows_affected())
    }
}

// -----------------------------------------------------------------------------
// oauth identities
// -----------------------------------------------------------------------------

struct PgOAuthIdentityStore {
    pool: PgPool,
}

#[async_trait]
impl OAuthIdentityStore for PgOAuthIdentityStore {
    async fn link(&self, identity: OAuthIdentity) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO oauth_identities
             (provider, subject, user_id, email, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&identity.provider)
        .bind(&identity.subject)
        .bind(uuid_to_bytes(identity.user_id.0))
        .bind(&identity.email)
        .bind(identity.created_at)
        .bind(identity.updated_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn find_by_provider_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> StorageResult<Option<OAuthIdentity>> {
        let row = sqlx::query(
            "SELECT provider, subject, user_id, email, created_at, updated_at
             FROM oauth_identities WHERE provider = $1 AND subject = $2",
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_oauth_identity).transpose()
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<OAuthIdentity>> {
        let rows = sqlx::query(
            "SELECT provider, subject, user_id, email, created_at, updated_at
             FROM oauth_identities WHERE user_id = $1",
        )
        .bind(uuid_to_bytes(user_id.0))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter().map(row_to_oauth_identity).collect()
    }

    async fn unlink(&self, provider: &str, subject: &str) -> StorageResult<()> {
        sqlx::query("DELETE FROM oauth_identities WHERE provider = $1 AND subject = $2")
            .bind(provider)
            .bind(subject)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }
}

fn row_to_oauth_identity(row: PgRow) -> StorageResult<OAuthIdentity> {
    let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err(storage)?;
    Ok(OAuthIdentity {
        provider: row.try_get("provider").map_err(storage)?,
        subject: row.try_get("subject").map_err(storage)?,
        user_id: UserId(uuid_from_row(user_id_bytes)?),
        email: row.try_get("email").map_err(storage)?,
        created_at: row.try_get("created_at").map_err(storage)?,
        updated_at: row.try_get("updated_at").map_err(storage)?,
    })
}

// -----------------------------------------------------------------------------
// oauth states
// -----------------------------------------------------------------------------

struct PgOAuthStateStore {
    pool: PgPool,
}

#[async_trait]
impl OAuthStateStore for PgOAuthStateStore {
    async fn put(&self, value: PendingOAuthAuthorization) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO oauth_states
             (state_id, provider, pkce_verifier, redirect_uri, link_user_id, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&value.state_id.0)
        .bind(&value.provider)
        .bind(&value.pkce_verifier)
        .bind(&value.redirect_uri)
        .bind(value.link_user_id.map(|u| uuid_to_bytes(u.0)))
        .bind(value.created_at)
        .bind(value.expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn take(
        &self,
        state_id: &OAuthStateId,
    ) -> StorageResult<Option<PendingOAuthAuthorization>> {
        let row = sqlx::query(
            "DELETE FROM oauth_states WHERE state_id = $1
             RETURNING state_id, provider, pkce_verifier, redirect_uri, link_user_id, created_at, expires_at",
        )
        .bind(&state_id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        let Some(row) = row else { return Ok(None) };
        let state_id: String = row.try_get("state_id").map_err(storage)?;
        let link_user_id_bytes: Option<Vec<u8>> = row.try_get("link_user_id").map_err(storage)?;
        let link_user_id = link_user_id_bytes
            .map(|b| uuid_from_row(b).map(UserId))
            .transpose()?;
        Ok(Some(PendingOAuthAuthorization {
            state_id: OAuthStateId(state_id),
            provider: row.try_get("provider").map_err(storage)?,
            pkce_verifier: row.try_get("pkce_verifier").map_err(storage)?,
            redirect_uri: row.try_get("redirect_uri").map_err(storage)?,
            link_user_id,
            created_at: row.try_get("created_at").map_err(storage)?,
            expires_at: row.try_get("expires_at").map_err(storage)?,
        }))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let result = sqlx::query("DELETE FROM oauth_states WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected())
    }
}
