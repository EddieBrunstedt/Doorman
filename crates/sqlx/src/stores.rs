//! The single source of truth for the SQLx store logic.
//!
//! [`sqlx_stores`] expands into the five `*Store` implementations, their row
//! mappers, and the store-accessor methods on a dialect's storage wrapper.
//! Each dialect adapter (`sqlite.rs`, `postgres.rs`, `mysql.rs`) keeps only
//! its genuinely dialect-specific surface — connection setup, the pool/row
//! types, the migration path, and the placeholder syntax — and invokes this
//! macro to generate everything else, so the ~600-line body exists once.
//!
//! Placeholders are written once as `?`; the `$placeholders` rewriter passed
//! by each dialect turns them into the syntax that dialect wants (`?` stays
//! for SQLite and MySQL, `$1`/`$2`/… for Postgres). The shared conformance
//! suite runs the same assertions against every expansion.
//!
//! The one place the dialects genuinely diverge is the atomic delete-and-return
//! used by `consume_token` / `take_registration` / `take_authentication`.
//! Postgres and SQLite express it as a single `DELETE … RETURNING`; MySQL has
//! no `RETURNING`, so it runs `SELECT … FOR UPDATE` then `DELETE` inside a
//! transaction. Each dialect selects its strategy via the `take` parameter,
//! which dispatches to [`sqlx_take`]; everything else is shared.

/// Generate the per-concern store implementations and accessors for a SQLx
/// dialect.
///
/// Parameters:
/// - `storage`: the dialect's public storage wrapper type (e.g. `SqliteStorage`).
/// - `pool`: the dialect's pool type (`SqlitePool` / `PgPool` / `MySqlPool`).
/// - `row`: the dialect's row type (`SqliteRow` / `PgRow` / `MySqlRow`).
/// - `placeholders`: a `fn(&str) -> Cow<str>` rewriting `?` placeholders.
/// - `timestamp`: a `fn` every timestamp bind is routed through before binding.
///   Identity (`common::ts_passthrough`) for SQLite and Postgres, which store
///   `DateTime<Utc>` directly; `common::ts_mysql` for MySQL/MariaDB, which must
///   bind the naive UTC datetime so the parameter is typed `DATETIME` rather
///   than the 2038-capped `TIMESTAMP`. See those helpers for the full rationale.
/// - `take`: the atomic delete-and-return strategy, `returning` (Postgres,
///   SQLite) or `txn` (MySQL). See [`sqlx_take`].
macro_rules! sqlx_stores {
    (
        storage: $storage:ident,
        pool: $pool:ty,
        row: $row:ty,
        placeholders: $ph:path,
        timestamp: $ts:path,
        take: $take:tt $(,)?
    ) => {
        impl $storage {
            /// Build a [`Storage`](doorman_core::storage::Storage) populated with
            /// every per-concern store backed by this pool.
            ///
            /// The single-backend shortcut: when every store uses this pool,
            /// this is the struct literal of the five per-store accessors. Mix
            /// backends by writing the `Storage` literal directly instead.
            pub fn all_stores(&self) -> $crate::stores::__reexport::Storage {
                $crate::stores::__reexport::Storage {
                    users: self.user_store(),
                    sessions: self.session_store(),
                    verification_tokens: self.verification_token_store(),
                    passkey_credentials: self.passkey_credential_store(),
                    passkey_challenges: self.passkey_challenge_store(),
                }
            }

            /// The user store backed by this pool.
            pub fn user_store(
                &self,
            ) -> ::std::sync::Arc<dyn $crate::stores::__reexport::UserStore> {
                ::std::sync::Arc::new(UserStoreImpl {
                    pool: self.pool.clone(),
                })
            }

            /// The session store backed by this pool.
            pub fn session_store(
                &self,
            ) -> ::std::sync::Arc<dyn $crate::stores::__reexport::SessionStore> {
                ::std::sync::Arc::new(SessionStoreImpl {
                    pool: self.pool.clone(),
                })
            }

            /// The verification-token store backed by this pool.
            pub fn verification_token_store(
                &self,
            ) -> ::std::sync::Arc<dyn $crate::stores::__reexport::VerificationTokenStore> {
                ::std::sync::Arc::new(VerificationTokenStoreImpl {
                    pool: self.pool.clone(),
                })
            }

            /// The passkey-credential store backed by this pool.
            pub fn passkey_credential_store(
                &self,
            ) -> ::std::sync::Arc<dyn $crate::stores::__reexport::PasskeyCredentialStore> {
                ::std::sync::Arc::new(PasskeyCredentialStoreImpl {
                    pool: self.pool.clone(),
                })
            }

            /// The passkey-challenge store backed by this pool.
            pub fn passkey_challenge_store(
                &self,
            ) -> ::std::sync::Arc<dyn $crate::stores::__reexport::PasskeyChallengeStore> {
                ::std::sync::Arc::new(PasskeyChallengeStoreImpl {
                    pool: self.pool.clone(),
                })
            }
        }

        // ---------------------------------------------------------------------
        // users
        // ---------------------------------------------------------------------

        struct UserStoreImpl {
            pool: $pool,
        }

        #[::async_trait::async_trait]
        impl $crate::stores::__reexport::UserStore for UserStoreImpl {
            async fn create_user(
                &self,
                user: $crate::stores::__reexport::User,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "INSERT INTO users (id, email, email_verified_at, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user.id.0))
                    .bind(&user.email)
                    .bind($ts(user.email_verified_at))
                    .bind($ts(user.created_at))
                    .bind($ts(user.updated_at))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(())
            }

            async fn find_user_by_id(
                &self,
                id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::User>,
            > {
                let sql = $ph(
                    "SELECT id, email, email_verified_at, created_at, updated_at
                     FROM users WHERE id = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                row.map(row_to_user).transpose()
            }

            async fn find_user_by_email(
                &self,
                email: &str,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::User>,
            > {
                let sql = $ph(
                    "SELECT id, email, email_verified_at, created_at, updated_at
                     FROM users WHERE email = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                row.map(row_to_user).transpose()
            }

            async fn update_user(
                &self,
                user: $crate::stores::__reexport::User,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "UPDATE users
                     SET email = ?, email_verified_at = ?, updated_at = ?
                     WHERE id = ?",
                );
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(&user.email)
                    .bind($ts(user.email_verified_at))
                    .bind($ts(user.updated_at))
                    .bind($crate::common::uuid_to_bytes(user.id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                if result.rows_affected() == 0 {
                    return Err($crate::stores::__reexport::StorageError::msg("user not found"));
                }
                Ok(())
            }

            async fn delete_user(
                &self,
                id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph("DELETE FROM users WHERE id = ?");
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(())
            }
        }

        fn row_to_user(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<$crate::stores::__reexport::User> {
            use ::sqlx::Row as _;
            let id_bytes: Vec<u8> = row.try_get("id").map_err($crate::common::storage)?;
            Ok($crate::stores::__reexport::User {
                id: $crate::stores::__reexport::UserId($crate::common::uuid_from_row(id_bytes)?),
                email: row.try_get("email").map_err($crate::common::storage)?,
                email_verified_at: row
                    .try_get("email_verified_at")
                    .map_err($crate::common::storage)?,
                created_at: row.try_get("created_at").map_err($crate::common::storage)?,
                updated_at: row.try_get("updated_at").map_err($crate::common::storage)?,
            })
        }

        // ---------------------------------------------------------------------
        // sessions
        // ---------------------------------------------------------------------

        struct SessionStoreImpl {
            pool: $pool,
        }

        #[::async_trait::async_trait]
        impl $crate::stores::__reexport::SessionStore for SessionStoreImpl {
            async fn create_session(
                &self,
                session: $crate::stores::__reexport::Session,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(session.id.0))
                    .bind($crate::common::uuid_to_bytes(session.user_id.0))
                    .bind($crate::common::token_hash_bytes(&session.token_hash))
                    .bind($ts(session.created_at))
                    .bind($ts(session.expires_at))
                    .bind(&session.ip)
                    .bind(&session.user_agent)
                    .bind($ts(session.recovery_cooldown_until))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(())
            }

            async fn find_session_by_token_hash(
                &self,
                hash: &$crate::stores::__reexport::TokenHash,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::Session>,
            > {
                let sql = $ph(
                    "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until
                     FROM sessions WHERE token_hash = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::token_hash_bytes(hash))
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                row.map(row_to_session).transpose()
            }

            async fn find_session_by_id(
                &self,
                id: $crate::stores::__reexport::SessionId,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::Session>,
            > {
                let sql = $ph(
                    "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until
                     FROM sessions WHERE id = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                row.map(row_to_session).transpose()
            }

            async fn list_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
                now: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<
                Vec<$crate::stores::__reexport::Session>,
            > {
                let sql = $ph(
                    "SELECT id, user_id, token_hash, created_at, expires_at, ip, user_agent, recovery_cooldown_until
                     FROM sessions WHERE user_id = ? AND expires_at > ?",
                );
                let rows = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .bind($ts(now))
                    .fetch_all(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                rows.into_iter().map(row_to_session).collect()
            }

            async fn delete_session(
                &self,
                id: $crate::stores::__reexport::SessionId,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph("DELETE FROM sessions WHERE id = ?");
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(())
            }

            async fn delete_sessions_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql = $ph("DELETE FROM sessions WHERE user_id = ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(result.rows_affected())
            }

            async fn delete_other_sessions_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
                except: $crate::stores::__reexport::SessionId,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql = $ph("DELETE FROM sessions WHERE user_id = ? AND id != ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .bind($crate::common::uuid_to_bytes(except.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(result.rows_affected())
            }

            async fn purge_expired(
                &self,
                now: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql = $ph("DELETE FROM sessions WHERE expires_at <= ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($ts(now))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(result.rows_affected())
            }
        }

        fn row_to_session(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<$crate::stores::__reexport::Session> {
            use ::sqlx::Row as _;
            let id_bytes: Vec<u8> = row.try_get("id").map_err($crate::common::storage)?;
            let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err($crate::common::storage)?;
            let hash_bytes: Vec<u8> = row.try_get("token_hash").map_err($crate::common::storage)?;
            Ok($crate::stores::__reexport::Session {
                id: $crate::stores::__reexport::SessionId(
                    $crate::common::uuid_from_row(id_bytes)?,
                ),
                user_id: $crate::stores::__reexport::UserId(
                    $crate::common::uuid_from_row(user_id_bytes)?,
                ),
                token_hash: $crate::common::token_hash_from_bytes(&hash_bytes)?,
                created_at: row.try_get("created_at").map_err($crate::common::storage)?,
                expires_at: row.try_get("expires_at").map_err($crate::common::storage)?,
                ip: row.try_get("ip").map_err($crate::common::storage)?,
                user_agent: row.try_get("user_agent").map_err($crate::common::storage)?,
                recovery_cooldown_until: row
                    .try_get("recovery_cooldown_until")
                    .map_err($crate::common::storage)?,
            })
        }

        // ---------------------------------------------------------------------
        // verification tokens
        // ---------------------------------------------------------------------

        struct VerificationTokenStoreImpl {
            pool: $pool,
        }

        #[::async_trait::async_trait]
        impl $crate::stores::__reexport::VerificationTokenStore for VerificationTokenStoreImpl {
            async fn create_token(
                &self,
                token: $crate::stores::__reexport::VerificationToken,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "INSERT INTO verification_tokens (token_hash, purpose, user_id, new_email, created_at, expires_at)
                     VALUES (?, ?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::token_hash_bytes(&token.token_hash))
                    .bind($crate::common::purpose_to_str(token.purpose))
                    .bind($crate::common::uuid_to_bytes(token.user_id.0))
                    .bind(&token.new_email)
                    .bind($ts(token.created_at))
                    .bind($ts(token.expires_at))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(())
            }

            async fn consume_token(
                &self,
                hash: &$crate::stores::__reexport::TokenHash,
                purpose: $crate::stores::__reexport::VerificationPurpose,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::VerificationToken>,
            > {
                $crate::stores::sqlx_take! {
                    $take,
                    pool: self.pool,
                    ph: $ph,
                    table: "verification_tokens",
                    cols: "token_hash, purpose, user_id, new_email, created_at, expires_at",
                    filter: "token_hash = ? AND purpose = ?",
                    binds: [
                        $crate::common::token_hash_bytes(hash),
                        $crate::common::purpose_to_str(purpose),
                    ],
                    map: row_to_verification_token,
                }
            }

            async fn delete_tokens_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
                purpose: $crate::stores::__reexport::VerificationPurpose,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql =
                    $ph("DELETE FROM verification_tokens WHERE user_id = ? AND purpose = ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .bind($crate::common::purpose_to_str(purpose))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(result.rows_affected())
            }

            async fn purge_expired(
                &self,
                now: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql = $ph("DELETE FROM verification_tokens WHERE expires_at <= ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($ts(now))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(result.rows_affected())
            }
        }

        fn row_to_verification_token(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<
            $crate::stores::__reexport::VerificationToken,
        > {
            use ::sqlx::Row as _;
            let hash_bytes: Vec<u8> = row.try_get("token_hash").map_err($crate::common::storage)?;
            let purpose_str: String = row.try_get("purpose").map_err($crate::common::storage)?;
            let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err($crate::common::storage)?;
            Ok($crate::stores::__reexport::VerificationToken {
                token_hash: $crate::common::token_hash_from_bytes(&hash_bytes)?,
                purpose: $crate::common::purpose_from_str(&purpose_str)?,
                user_id: $crate::stores::__reexport::UserId(
                    $crate::common::uuid_from_row(user_id_bytes)?,
                ),
                new_email: row.try_get("new_email").map_err($crate::common::storage)?,
                created_at: row.try_get("created_at").map_err($crate::common::storage)?,
                expires_at: row.try_get("expires_at").map_err($crate::common::storage)?,
            })
        }

        // ---------------------------------------------------------------------
        // passkey credentials
        // ---------------------------------------------------------------------

        struct PasskeyCredentialStoreImpl {
            pool: $pool,
        }

        #[::async_trait::async_trait]
        impl $crate::stores::__reexport::PasskeyCredentialStore for PasskeyCredentialStoreImpl {
            async fn add_passkey(
                &self,
                credential: $crate::stores::__reexport::StoredPasskey,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "INSERT INTO passkey_credentials
                     (credential_id, user_id, passkey, name, created_at, last_used_at,
                      aaguid, transports, backup_eligible, backup_state, recovery_cooldown_until)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(&credential.credential_id)
                    .bind($crate::common::uuid_to_bytes(credential.user_id.0))
                    .bind(&credential.passkey)
                    .bind(&credential.name)
                    .bind($ts(credential.created_at))
                    .bind($ts(credential.last_used_at))
                    .bind($crate::common::aaguid_to_str(credential.aaguid))
                    .bind($crate::common::transports_to_str(&credential.transports))
                    .bind(credential.backup_eligible)
                    .bind(credential.backup_state)
                    .bind($ts(credential.recovery_cooldown_until))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(())
            }

            async fn update_passkey(
                &self,
                credential: $crate::stores::__reexport::StoredPasskey,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "UPDATE passkey_credentials
                     SET user_id = ?, passkey = ?, name = ?, created_at = ?, last_used_at = ?,
                         aaguid = ?, transports = ?, backup_eligible = ?, backup_state = ?,
                         recovery_cooldown_until = ?
                     WHERE credential_id = ?",
                );
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(credential.user_id.0))
                    .bind(&credential.passkey)
                    .bind(&credential.name)
                    .bind($ts(credential.created_at))
                    .bind($ts(credential.last_used_at))
                    .bind($crate::common::aaguid_to_str(credential.aaguid))
                    .bind($crate::common::transports_to_str(&credential.transports))
                    .bind(credential.backup_eligible)
                    .bind(credential.backup_state)
                    .bind($ts(credential.recovery_cooldown_until))
                    .bind(&credential.credential_id)
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                if result.rows_affected() == 0 {
                    return Err($crate::stores::__reexport::StorageError::msg(
                        "passkey credential not found",
                    ));
                }
                Ok(())
            }

            async fn list_passkeys_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<
                Vec<$crate::stores::__reexport::StoredPasskey>,
            > {
                let sql = $ph(
                    "SELECT credential_id, user_id, passkey, name, created_at, last_used_at,
                            aaguid, transports, backup_eligible, backup_state, recovery_cooldown_until
                     FROM passkey_credentials WHERE user_id = ?",
                );
                let rows = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .fetch_all(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                rows.into_iter().map(row_to_passkey).collect()
            }

            async fn list_passkey_summaries_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<
                Vec<$crate::stores::__reexport::PasskeySummary>,
            > {
                // Deliberately omits the `passkey` blob column: the listing path
                // never deserialises it.
                let sql = $ph(
                    "SELECT credential_id, user_id, name, created_at, last_used_at,
                            aaguid, transports, backup_eligible, backup_state, recovery_cooldown_until
                     FROM passkey_credentials WHERE user_id = ?",
                );
                let rows = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .fetch_all(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                rows.into_iter().map(row_to_passkey_summary).collect()
            }

            async fn find_passkey_by_credential_id(
                &self,
                credential_id: &[u8],
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::StoredPasskey>,
            > {
                let sql = $ph(
                    "SELECT credential_id, user_id, passkey, name, created_at, last_used_at,
                            aaguid, transports, backup_eligible, backup_state, recovery_cooldown_until
                     FROM passkey_credentials WHERE credential_id = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(credential_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                row.map(row_to_passkey).transpose()
            }

            async fn delete_passkey(
                &self,
                credential_id: &[u8],
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph("DELETE FROM passkey_credentials WHERE credential_id = ?");
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(credential_id)
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(())
            }

            async fn delete_passkeys_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql = $ph("DELETE FROM passkey_credentials WHERE user_id = ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(result.rows_affected())
            }
        }

        // Read every passkey metadata column — everything except the `passkey`
        // blob — into a `PasskeySummary`. Both decoders share this single field
        // assembly: the summary path returns it directly and the full decoder
        // adds the blob, so neither re-lists the metadata columns.
        fn row_to_passkey_summary(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<
            $crate::stores::__reexport::PasskeySummary,
        > {
            use ::sqlx::Row as _;
            let credential_id: Vec<u8> =
                row.try_get("credential_id").map_err($crate::common::storage)?;
            let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err($crate::common::storage)?;
            let aaguid: Option<String> = row.try_get("aaguid").map_err($crate::common::storage)?;
            let transports: String = row.try_get("transports").map_err($crate::common::storage)?;
            Ok($crate::stores::__reexport::PasskeySummary {
                credential_id,
                user_id: $crate::stores::__reexport::UserId(
                    $crate::common::uuid_from_row(user_id_bytes)?,
                ),
                name: row.try_get("name").map_err($crate::common::storage)?,
                created_at: row.try_get("created_at").map_err($crate::common::storage)?,
                last_used_at: row.try_get("last_used_at").map_err($crate::common::storage)?,
                aaguid: $crate::common::aaguid_from_str(aaguid)?,
                transports: $crate::common::transports_from_str(&transports),
                backup_eligible: row
                    .try_get("backup_eligible")
                    .map_err($crate::common::storage)?,
                backup_state: row.try_get("backup_state").map_err($crate::common::storage)?,
                recovery_cooldown_until: row
                    .try_get("recovery_cooldown_until")
                    .map_err($crate::common::storage)?,
            })
        }

        fn row_to_passkey(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<$crate::stores::__reexport::StoredPasskey> {
            use ::sqlx::Row as _;
            let passkey: Vec<u8> = row.try_get("passkey").map_err($crate::common::storage)?;
            let meta = row_to_passkey_summary(row)?;
            Ok($crate::stores::__reexport::StoredPasskey {
                credential_id: meta.credential_id,
                user_id: meta.user_id,
                passkey,
                name: meta.name,
                created_at: meta.created_at,
                last_used_at: meta.last_used_at,
                aaguid: meta.aaguid,
                transports: meta.transports,
                backup_eligible: meta.backup_eligible,
                backup_state: meta.backup_state,
                recovery_cooldown_until: meta.recovery_cooldown_until,
            })
        }

        // ---------------------------------------------------------------------
        // passkey challenges (registrations + authentications)
        // ---------------------------------------------------------------------

        struct PasskeyChallengeStoreImpl {
            pool: $pool,
        }

        #[::async_trait::async_trait]
        impl $crate::stores::__reexport::PasskeyChallengeStore for PasskeyChallengeStoreImpl {
            async fn put_registration(
                &self,
                value: $crate::stores::__reexport::StoredPasskeyRegistration,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "INSERT INTO passkey_registrations (id, user_id, state, created_at, expires_at, recovery_cooldown_until)
                     VALUES (?, ?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(value.id.0))
                    .bind($crate::common::uuid_to_bytes(value.user_id.0))
                    .bind(&value.state)
                    .bind($ts(value.created_at))
                    .bind($ts(value.expires_at))
                    .bind($ts(value.recovery_cooldown_until))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(())
            }

            async fn take_registration(
                &self,
                id: $crate::stores::__reexport::PasskeyChallengeId,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::StoredPasskeyRegistration>,
            > {
                $crate::stores::sqlx_take! {
                    $take,
                    pool: self.pool,
                    ph: $ph,
                    table: "passkey_registrations",
                    cols: "id, user_id, state, created_at, expires_at, recovery_cooldown_until",
                    filter: "id = ?",
                    binds: [$crate::common::uuid_to_bytes(id.0)],
                    map: row_to_registration,
                }
            }

            async fn delete_registrations_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql = $ph("DELETE FROM passkey_registrations WHERE user_id = ?");
                let res = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(res.rows_affected())
            }

            async fn count_registrations_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql =
                    $ph("SELECT COUNT(*) FROM passkey_registrations WHERE user_id = ?");
                let count: i64 = ::sqlx::query_scalar(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .fetch_one(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(count.max(0) as u64)
            }

            async fn put_authentication(
                &self,
                value: $crate::stores::__reexport::StoredPasskeyAuthentication,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "INSERT INTO passkey_authentications (id, state, created_at, expires_at)
                     VALUES (?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(value.id.0))
                    .bind(&value.state)
                    .bind($ts(value.created_at))
                    .bind($ts(value.expires_at))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage)?;
                Ok(())
            }

            async fn take_authentication(
                &self,
                id: $crate::stores::__reexport::PasskeyChallengeId,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::StoredPasskeyAuthentication>,
            > {
                $crate::stores::sqlx_take! {
                    $take,
                    pool: self.pool,
                    ph: $ph,
                    table: "passkey_authentications",
                    cols: "id, state, created_at, expires_at",
                    filter: "id = ?",
                    binds: [$crate::common::uuid_to_bytes(id.0)],
                    map: row_to_authentication,
                }
            }

            async fn purge_expired(
                &self,
                now: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let mut tx = self.pool.begin().await.map_err($crate::common::storage)?;
                let reg_sql = $ph("DELETE FROM passkey_registrations WHERE expires_at <= ?");
                let reg = ::sqlx::query(::sqlx::AssertSqlSafe(reg_sql))
                    .bind($ts(now))
                    .execute(&mut *tx)
                    .await
                    .map_err($crate::common::storage)?;
                let auth_sql = $ph("DELETE FROM passkey_authentications WHERE expires_at <= ?");
                let auth = ::sqlx::query(::sqlx::AssertSqlSafe(auth_sql))
                    .bind($ts(now))
                    .execute(&mut *tx)
                    .await
                    .map_err($crate::common::storage)?;
                tx.commit().await.map_err($crate::common::storage)?;
                Ok(reg.rows_affected() + auth.rows_affected())
            }
        }

        fn row_to_registration(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<
            $crate::stores::__reexport::StoredPasskeyRegistration,
        > {
            use ::sqlx::Row as _;
            let id_bytes: Vec<u8> = row.try_get("id").map_err($crate::common::storage)?;
            let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err($crate::common::storage)?;
            let state: Vec<u8> = row.try_get("state").map_err($crate::common::storage)?;
            Ok($crate::stores::__reexport::StoredPasskeyRegistration {
                id: $crate::stores::__reexport::PasskeyChallengeId(
                    $crate::common::uuid_from_row(id_bytes)?,
                ),
                user_id: $crate::stores::__reexport::UserId(
                    $crate::common::uuid_from_row(user_id_bytes)?,
                ),
                state,
                created_at: row.try_get("created_at").map_err($crate::common::storage)?,
                expires_at: row.try_get("expires_at").map_err($crate::common::storage)?,
                recovery_cooldown_until: row
                    .try_get("recovery_cooldown_until")
                    .map_err($crate::common::storage)?,
            })
        }

        fn row_to_authentication(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<
            $crate::stores::__reexport::StoredPasskeyAuthentication,
        > {
            use ::sqlx::Row as _;
            let id_bytes: Vec<u8> = row.try_get("id").map_err($crate::common::storage)?;
            let state: Vec<u8> = row.try_get("state").map_err($crate::common::storage)?;
            Ok($crate::stores::__reexport::StoredPasskeyAuthentication {
                id: $crate::stores::__reexport::PasskeyChallengeId(
                    $crate::common::uuid_from_row(id_bytes)?,
                ),
                state,
                created_at: row.try_get("created_at").map_err($crate::common::storage)?,
                expires_at: row.try_get("expires_at").map_err($crate::common::storage)?,
            })
        }
    };
}

pub(crate) use sqlx_stores;

/// The atomic delete-and-return behind `consume_token`, `take_registration`,
/// and `take_authentication`, in the two shapes the dialects need.
///
/// Both arms take the same named inputs and evaluate to
/// `StorageResult<Option<T>>`, so a store method body is just the macro call:
/// - `pool`: an expression for the dialect pool (`self.pool`).
/// - `ph`: the dialect placeholder rewriter.
/// - `table`/`cols`/`filter`: the table, the projected columns, and the `WHERE`
///   predicate (with `?` placeholders).
/// - `binds`: the values bound to the predicate, in order. The `txn` arm binds
///   them twice (the `SELECT` and the `DELETE`), so each must be a cheap,
///   side-effect-free expression.
/// - `map`: the `fn($row) -> StorageResult<T>` row mapper.
///
/// `returning` (Postgres, SQLite) issues a single `DELETE … RETURNING`. `txn`
/// (MySQL, which has no `RETURNING`) opens a transaction, locks the row with
/// `SELECT … FOR UPDATE`, deletes it, and commits — so two racing takers
/// serialize on the lock and exactly one observes the row.
macro_rules! sqlx_take {
    (
        returning,
        pool: $pool:expr,
        ph: $ph:path,
        table: $table:literal,
        cols: $cols:literal,
        filter: $filter:literal,
        binds: [$($bind:expr),* $(,)?],
        map: $map:path $(,)?
    ) => {{
        let sql = $ph(concat!(
            "DELETE FROM ", $table, " WHERE ", $filter, " RETURNING ", $cols,
        ));
        let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
            $(.bind($bind))*
            .fetch_optional(&$pool)
            .await
            .map_err($crate::common::storage)?;
        row.map($map).transpose()
    }};
    (
        txn,
        pool: $pool:expr,
        ph: $ph:path,
        table: $table:literal,
        cols: $cols:literal,
        filter: $filter:literal,
        binds: [$($bind:expr),* $(,)?],
        map: $map:path $(,)?
    ) => {{
        let mut tx = $pool.begin().await.map_err($crate::common::storage)?;
        let select_sql = $ph(concat!(
            "SELECT ", $cols, " FROM ", $table, " WHERE ", $filter, " FOR UPDATE",
        ));
        let row = ::sqlx::query(::sqlx::AssertSqlSafe(select_sql))
            $(.bind($bind))*
            .fetch_optional(&mut *tx)
            .await
            .map_err($crate::common::storage)?;
        let Some(row) = row else {
            tx.rollback().await.map_err($crate::common::storage)?;
            return Ok(None);
        };
        let parsed = $map(row)?;
        let delete_sql = $ph(concat!("DELETE FROM ", $table, " WHERE ", $filter));
        ::sqlx::query(::sqlx::AssertSqlSafe(delete_sql))
            $(.bind($bind))*
            .execute(&mut *tx)
            .await
            .map_err($crate::common::storage)?;
        tx.commit().await.map_err($crate::common::storage)?;
        Ok(Some(parsed))
    }};
}

pub(crate) use sqlx_take;

/// Items the generated store bodies reference, re-exported under one path so
/// the macro can name them without each dialect module importing them.
pub(crate) mod __reexport {
    pub use chrono::{DateTime, Utc};
    pub use doorman_core::error::{StorageError, StorageResult};
    pub use doorman_core::storage::{
        PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore, PasskeySummary, Session,
        SessionId, SessionStore, Storage, StoredPasskey, StoredPasskeyAuthentication,
        StoredPasskeyRegistration, TokenHash, User, UserId, UserStore, VerificationPurpose,
        VerificationToken, VerificationTokenStore,
    };
}
