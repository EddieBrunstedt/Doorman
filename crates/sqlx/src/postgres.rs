//! Postgres adapter backed by `sqlx::PgPool`.
//!
//! Keep this adapter a mirror of `sqlite.rs`: the two bodies differ only
//! in placeholder syntax, row/pool types, and dialect quirks. The shared
//! storage-conformance suite (`tests/conformance`) runs the same
//! assertions against both, so any silent divergence fails a test.

use std::sync::Arc;

use async_trait::async_trait;
use bauth_core::error::{StorageError, StorageResult};
use bauth_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore, PasskeySummary, Session,
    SessionId, SessionStore, Storage, StoredPasskey, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, TokenHash, User, UserId, UserStore, VerificationPurpose,
    VerificationToken, VerificationTokenStore,
};
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};

use crate::common::{
    purpose_from_str, purpose_to_str, storage, token_hash_bytes, token_hash_from_bytes,
    uuid_from_row, uuid_to_bytes,
};

/// Postgres storage adapter. Construct once at startup and hand
/// `storage()` to `BauthAxum::builder`, or pull individual stores via
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
            verification_tokens: self.verification_token_store(),
            passkey_credentials: self.passkey_credential_store(),
            passkey_challenges: self.passkey_challenge_store(),
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
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
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
            "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until
             FROM sessions WHERE id = $1",
        )
        .bind(uuid_to_bytes(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(row_to_session).transpose()
    }

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        let rows = sqlx::query(
            "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until
             FROM sessions WHERE user_id = $1 AND expires_at > $2",
        )
        .bind(uuid_to_bytes(user_id.0))
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter().map(row_to_session).collect()
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

    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id != $2")
            .bind(uuid_to_bytes(user_id.0))
            .bind(uuid_to_bytes(except.0))
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
        recovery_cooldown_until: row.try_get("recovery_cooldown_until").map_err(storage)?,
    })
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
        sqlx::query(
            "INSERT INTO passkey_credentials
             (credential_id, user_id, passkey, name, created_at, last_used_at, recovery_cooldown_until)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&credential.credential_id)
        .bind(uuid_to_bytes(credential.user_id.0))
        .bind(&credential.passkey)
        .bind(&credential.name)
        .bind(credential.created_at)
        .bind(credential.last_used_at)
        .bind(credential.recovery_cooldown_until)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let result = sqlx::query(
            "UPDATE passkey_credentials
             SET user_id = $1, passkey = $2, name = $3, created_at = $4, last_used_at = $5, recovery_cooldown_until = $6
             WHERE credential_id = $7",
        )
        .bind(uuid_to_bytes(credential.user_id.0))
        .bind(&credential.passkey)
        .bind(&credential.name)
        .bind(credential.created_at)
        .bind(credential.last_used_at)
        .bind(credential.recovery_cooldown_until)
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
            "SELECT credential_id, user_id, passkey, name, created_at, last_used_at, recovery_cooldown_until
             FROM passkey_credentials WHERE user_id = $1",
        )
        .bind(uuid_to_bytes(user_id.0))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter().map(row_to_passkey).collect()
    }

    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>> {
        // Deliberately omits the `passkey` blob column: the listing path
        // never deserialises it.
        let rows = sqlx::query(
            "SELECT credential_id, user_id, name, created_at, last_used_at, recovery_cooldown_until
             FROM passkey_credentials WHERE user_id = $1",
        )
        .bind(uuid_to_bytes(user_id.0))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter().map(row_to_passkey_summary).collect()
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        let row = sqlx::query(
            "SELECT credential_id, user_id, passkey, name, created_at, last_used_at, recovery_cooldown_until
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
    let passkey: Vec<u8> = row.try_get("passkey").map_err(storage)?;
    Ok(StoredPasskey {
        credential_id,
        user_id: UserId(uuid_from_row(user_id_bytes)?),
        passkey,
        name: row.try_get("name").map_err(storage)?,
        created_at: row.try_get("created_at").map_err(storage)?,
        last_used_at: row.try_get("last_used_at").map_err(storage)?,
        recovery_cooldown_until: row.try_get("recovery_cooldown_until").map_err(storage)?,
    })
}

fn row_to_passkey_summary(row: PgRow) -> StorageResult<PasskeySummary> {
    let credential_id: Vec<u8> = row.try_get("credential_id").map_err(storage)?;
    let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err(storage)?;
    Ok(PasskeySummary {
        credential_id,
        user_id: UserId(uuid_from_row(user_id_bytes)?),
        name: row.try_get("name").map_err(storage)?,
        created_at: row.try_get("created_at").map_err(storage)?,
        last_used_at: row.try_get("last_used_at").map_err(storage)?,
        recovery_cooldown_until: row.try_get("recovery_cooldown_until").map_err(storage)?,
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
        sqlx::query(
            "INSERT INTO passkey_registrations (id, user_id, state, created_at, expires_at, recovery_cooldown_until)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(uuid_to_bytes(value.id.0))
        .bind(uuid_to_bytes(value.user_id.0))
        .bind(&value.state)
        .bind(value.created_at)
        .bind(value.expires_at)
        .bind(value.recovery_cooldown_until)
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
             RETURNING id, user_id, state, created_at, expires_at, recovery_cooldown_until",
        )
        .bind(uuid_to_bytes(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        let Some(row) = row else { return Ok(None) };
        let id_bytes: Vec<u8> = row.try_get("id").map_err(storage)?;
        let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err(storage)?;
        let state: Vec<u8> = row.try_get("state").map_err(storage)?;
        Ok(Some(StoredPasskeyRegistration {
            id: PasskeyChallengeId(uuid_from_row(id_bytes)?),
            user_id: UserId(uuid_from_row(user_id_bytes)?),
            state,
            created_at: row.try_get("created_at").map_err(storage)?,
            expires_at: row.try_get("expires_at").map_err(storage)?,
            recovery_cooldown_until: row.try_get("recovery_cooldown_until").map_err(storage)?,
        }))
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let res = sqlx::query("DELETE FROM passkey_registrations WHERE user_id = $1")
            .bind(uuid_to_bytes(user_id.0))
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(res.rows_affected())
    }

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM passkey_registrations WHERE user_id = $1")
                .bind(uuid_to_bytes(user_id.0))
                .fetch_one(&self.pool)
                .await
                .map_err(storage)?;
        Ok(count.max(0) as u64)
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO passkey_authentications (id, state, created_at, expires_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(uuid_to_bytes(value.id.0))
        .bind(&value.state)
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
             RETURNING id, state, created_at, expires_at",
        )
        .bind(uuid_to_bytes(id.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        let Some(row) = row else { return Ok(None) };
        let id_bytes: Vec<u8> = row.try_get("id").map_err(storage)?;
        let state: Vec<u8> = row.try_get("state").map_err(storage)?;
        Ok(Some(StoredPasskeyAuthentication {
            id: PasskeyChallengeId(uuid_from_row(id_bytes)?),
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
