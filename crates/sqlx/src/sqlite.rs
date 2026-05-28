//! SQLite adapter backed by `sqlx::SqlitePool`.

use std::sync::Arc;

use async_trait::async_trait;
use bauth_core::error::{StorageError, StorageResult};
use bauth_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore, Session, SessionId,
    SessionStore, Storage, StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration,
    TokenHash, User, UserId, UserStore, VerificationPurpose, VerificationToken,
    VerificationTokenStore,
};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use webauthn_rs::prelude::{DiscoverableAuthentication, Passkey, PasskeyRegistration};

use crate::common::{
    purpose_from_str, purpose_to_str, storage, token_hash_bytes, token_hash_from_bytes,
    uuid_from_row, uuid_to_bytes,
};

/// SQLite storage adapter. Construct once at startup and hand `storage()`
/// to the quickstart builder, or pull individual stores via the helpers
/// below when wiring managers by hand.
#[derive(Clone)]
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    /// Open a pool against `url`. For an ephemeral in-memory DB use
    /// `"sqlite::memory:"`; for a file-backed DB use
    /// `"sqlite:///absolute/path/to/db.sqlite?mode=rwc"`.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let opts: SqliteConnectOptions = url.parse()?;
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts.foreign_keys(true).create_if_missing(true))
            .await?;
        Ok(Self { pool })
    }

    /// Construct directly from an already-built pool. Useful when the
    /// host wants custom pool tuning.
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run the embedded migrations. Idempotent — safe to call on every
    /// boot.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations/sqlite").run(&self.pool).await
    }

    /// Build a [`Storage`] populated with every per-concern store backed
    /// by this pool.
    pub fn storage(&self) -> Storage {
        Storage {
            users: self.user_store(),
            sessions: self.session_store(),
            verification_tokens: self.verification_token_store(),
            passkey_credentials: self.passkey_credential_store(),
            passkey_challenges: self.passkey_challenge_store(),
        }
    }

    pub fn user_store(&self) -> Arc<dyn UserStore> {
        Arc::new(SqliteUserStore {
            pool: self.pool.clone(),
        })
    }

    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(SqliteSessionStore {
            pool: self.pool.clone(),
        })
    }

    pub fn verification_token_store(&self) -> Arc<dyn VerificationTokenStore> {
        Arc::new(SqliteVerificationTokenStore {
            pool: self.pool.clone(),
        })
    }

    pub fn passkey_credential_store(&self) -> Arc<dyn PasskeyCredentialStore> {
        Arc::new(SqlitePasskeyCredentialStore {
            pool: self.pool.clone(),
        })
    }

    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(SqlitePasskeyChallengeStore {
            pool: self.pool.clone(),
        })
    }
}

// -----------------------------------------------------------------------------
// users
// -----------------------------------------------------------------------------

struct SqliteUserStore {
    pool: SqlitePool,
}

#[async_trait]
impl UserStore for SqliteUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO users (id, email, email_verified_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)",
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
             FROM users WHERE id = ?",
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
             FROM users WHERE email = ?",
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
             SET email = ?, email_verified_at = ?, updated_at = ?
             WHERE id = ?",
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
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(uuid_to_bytes(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }
}

fn row_to_user(row: sqlx::sqlite::SqliteRow) -> StorageResult<User> {
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

struct SqliteSessionStore {
    pool: SqlitePool,
}

#[async_trait]
impl SessionStore for SqliteSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid_to_bytes(session.id.0))
        .bind(uuid_to_bytes(session.user_id.0))
        .bind(token_hash_bytes(&session.token_hash))
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(&session.ip)
        .bind(&session.user_agent)
        .bind(session.recovery_cooldown_until)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let row = sqlx::query(
            "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until
             FROM sessions WHERE token_hash = ?",
        )
        .bind(token_hash_bytes(hash))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_session).transpose()
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        let row = sqlx::query(
            "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until
             FROM sessions WHERE id = ?",
        )
        .bind(uuid_to_bytes(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_session).transpose()
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        let rows = sqlx::query(
            "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until
             FROM sessions WHERE user_id = ?",
        )
        .bind(uuid_to_bytes(user_id.0))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter().map(row_to_session).collect()
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(uuid_to_bytes(id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(uuid_to_bytes(user_id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected())
    }

    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = ? AND id != ?")
            .bind(uuid_to_bytes(user_id.0))
            .bind(uuid_to_bytes(except.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected())
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected())
    }
}

fn row_to_session(row: sqlx::sqlite::SqliteRow) -> StorageResult<Session> {
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
        recovery_cooldown_until: row.try_get("recovery_cooldown_until").map_err(storage)?,
    })
}

// -----------------------------------------------------------------------------
// verification tokens
// -----------------------------------------------------------------------------

struct SqliteVerificationTokenStore {
    pool: SqlitePool,
}

#[async_trait]
impl VerificationTokenStore for SqliteVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO verification_tokens (token_hash, purpose, user_id, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?)",
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
             WHERE token_hash = ? AND purpose = ?
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
             FROM verification_tokens WHERE token_hash = ? AND purpose = ?",
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
            sqlx::query("DELETE FROM verification_tokens WHERE user_id = ? AND purpose = ?")
                .bind(uuid_to_bytes(user_id.0))
                .bind(purpose_to_str(purpose))
                .execute(&self.pool)
                .await
                .map_err(storage)?;
        Ok(result.rows_affected())
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let result = sqlx::query("DELETE FROM verification_tokens WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected())
    }
}

fn row_to_verification_token(row: sqlx::sqlite::SqliteRow) -> StorageResult<VerificationToken> {
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

struct SqlitePasskeyCredentialStore {
    pool: SqlitePool,
}

#[async_trait]
impl PasskeyCredentialStore for SqlitePasskeyCredentialStore {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let serialized = serde_json::to_string(&credential.passkey).map_err(storage)?;
        sqlx::query(
            "INSERT INTO passkey_credentials
             (credential_id, user_id, passkey, name, created_at, last_used_at)
             VALUES (?, ?, ?, ?, ?, ?)",
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
             SET user_id = ?, passkey = ?, name = ?, created_at = ?, last_used_at = ?
             WHERE credential_id = ?",
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
             FROM passkey_credentials WHERE user_id = ?",
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
             FROM passkey_credentials WHERE credential_id = ?",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_passkey).transpose()
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        sqlx::query("DELETE FROM passkey_credentials WHERE credential_id = ?")
            .bind(credential_id)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }
}

fn row_to_passkey(row: sqlx::sqlite::SqliteRow) -> StorageResult<StoredPasskey> {
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

struct SqlitePasskeyChallengeStore {
    pool: SqlitePool,
}

#[async_trait]
impl PasskeyChallengeStore for SqlitePasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        let serialized = serde_json::to_string(&value.state).map_err(storage)?;
        sqlx::query(
            "INSERT INTO passkey_registrations (id, user_id, state, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?)",
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
            "DELETE FROM passkey_registrations WHERE id = ?
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
            "INSERT INTO passkey_authentications (id, state, created_at, expires_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(uuid_to_bytes(value.id.0))
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
            "DELETE FROM passkey_authentications WHERE id = ?
             RETURNING id, state, created_at, expires_at",
        )
        .bind(uuid_to_bytes(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        let Some(row) = row else { return Ok(None) };
        let id_bytes: Vec<u8> = row.try_get("id").map_err(storage)?;
        let state_json: String = row.try_get("state").map_err(storage)?;
        let state: DiscoverableAuthentication =
            serde_json::from_str(&state_json).map_err(storage)?;
        Ok(Some(StoredPasskeyAuthentication {
            id: PasskeyChallengeId(uuid_from_row(id_bytes)?),
            state,
            created_at: row.try_get("created_at").map_err(storage)?,
            expires_at: row.try_get("expires_at").map_err(storage)?,
        }))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let reg = sqlx::query("DELETE FROM passkey_registrations WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        let auth = sqlx::query("DELETE FROM passkey_authentications WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        tx.commit().await.map_err(storage)?;
        Ok(reg.rows_affected() + auth.rows_affected())
    }
}
