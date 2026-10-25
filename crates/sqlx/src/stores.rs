macro_rules! sqlx_stores {
    (
        storage: $storage:ident,
        pool: $pool:ty,
        row: $row:ty,
        placeholders: $ph:path,
        timestamp: $ts:path,
        take: $take:tt,
        replace_link: $replace_link:tt $(,)?
    ) => {
        impl $storage {
            pub fn all_stores(&self) -> $crate::stores::__reexport::Storage {
                $crate::stores::__reexport::Storage {
                    records: self.records(),
                    expiring: self.expiring(),
                }
            }

            pub fn records(&self) -> $crate::stores::__reexport::RecordStores {
                $crate::stores::__reexport::RecordStores {
                    users: ::std::sync::Arc::new(UserStoreImpl {
                        pool: self.pool.clone(),
                    }),
                    passkeys: ::std::sync::Arc::new(PasskeyStoreImpl {
                        pool: self.pool.clone(),
                    }),
                }
            }

            pub fn expiring(&self) -> $crate::stores::__reexport::ExpiringStores {
                $crate::stores::__reexport::ExpiringStores {
                    sessions: ::std::sync::Arc::new(SessionStoreImpl {
                        pool: self.pool.clone(),
                    }),
                    email_links: ::std::sync::Arc::new(EmailLinkStoreImpl {
                        pool: self.pool.clone(),
                    }),
                    passkey_challenges: ::std::sync::Arc::new(PasskeyChallengeStoreImpl {
                        pool: self.pool.clone(),
                    }),
                }
            }
        }

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
                    "INSERT INTO users (id, email, signed_up_at, status, disabled_at, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user.id.0))
                    .bind(&user.email)
                    .bind($ts(user.signed_up_at))
                    .bind($crate::stores::__reexport::user_status_to_str(&user.status))
                    .bind($ts(user.status.disabled_at()))
                    .bind($ts(user.created_at))
                    .bind($ts(user.updated_at))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                Ok(())
            }

            async fn find_user_by_id(
                &self,
                id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::User>,
            > {
                let sql = $ph(
                    "SELECT id, email, signed_up_at, status, disabled_at, created_at, updated_at
                     FROM users WHERE id = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                row.map(row_to_user).transpose()
            }

            async fn find_user_by_email(
                &self,
                email: &str,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::User>,
            > {
                let sql = $ph(
                    "SELECT id, email, signed_up_at, status, disabled_at, created_at, updated_at
                     FROM users WHERE email = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                row.map(row_to_user).transpose()
            }

            async fn set_user_status(
                &self,
                id: $crate::stores::__reexport::UserId,
                status: $crate::stores::__reexport::UserStatus,
                at: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "UPDATE users SET status = ?, disabled_at = ?, updated_at = ? WHERE id = ?",
                );
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::stores::__reexport::user_status_to_str(&status))
                    .bind($ts(status.disabled_at()))
                    .bind($ts(at))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                if result.rows_affected() == 0 {
                    return Err($crate::stores::__reexport::StorageError::not_found("user not found"));
                }
                Ok(())
            }

            async fn set_user_email(
                &self,
                id: $crate::stores::__reexport::UserId,
                email: &str,
                at: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph("UPDATE users SET email = ?, updated_at = ? WHERE id = ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .bind($ts(at))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                if result.rows_affected() == 0 {
                    return Err($crate::stores::__reexport::StorageError::not_found("user not found"));
                }
                Ok(())
            }

            async fn mark_signed_up(
                &self,
                id: $crate::stores::__reexport::UserId,
                at: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph("UPDATE users SET signed_up_at = ?, updated_at = ? WHERE id = ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($ts(at))
                    .bind($ts(at))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                if result.rows_affected() == 0 {
                    return Err($crate::stores::__reexport::StorageError::not_found("user not found"));
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
                    .map_err($crate::common::storage_err)?;
                Ok(())
            }
        }

        fn row_to_user(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<$crate::stores::__reexport::User> {
            use ::sqlx::Row as _;
            let id_bytes: Vec<u8> = row.try_get("id").map_err($crate::common::storage_err)?;
            let status_str: String = row.try_get("status").map_err($crate::common::storage_err)?;
            let disabled_at: ::core::option::Option<
                $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            > = row.try_get("disabled_at").map_err($crate::common::storage_err)?;
            Ok($crate::stores::__reexport::User {
                id: $crate::stores::__reexport::UserId($crate::common::uuid_from_row(id_bytes)?),
                email: row.try_get("email").map_err($crate::common::storage_err)?,
                signed_up_at: row
                    .try_get("signed_up_at")
                    .map_err($crate::common::storage_err)?,
                status: $crate::stores::__reexport::user_status_from_parts(
                    &status_str,
                    disabled_at,
                )?,
                created_at: row.try_get("created_at").map_err($crate::common::storage_err)?,
                updated_at: row.try_get("updated_at").map_err($crate::common::storage_err)?,
            })
        }

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
                    "INSERT INTO sessions (id, user_id, token_hash, transport, created_at, last_used_at, expires_at, ip, user_agent, recovery_cool_down_until)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(session.id.0))
                    .bind($crate::common::uuid_to_bytes(session.user_id.0))
                    .bind($crate::common::token_hash_bytes(&session.token_hash))
                    .bind($crate::common::session_transport_to_str(session.transport))
                    .bind($ts(session.created_at))
                    .bind($ts(session.last_used_at))
                    .bind($ts(session.expires_at))
                    .bind(session.ip.to_string())
                    .bind(&session.user_agent)
                    .bind($ts(session.recovery_cool_down_until))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                Ok(())
            }

            async fn touch_session(
                &self,
                id: $crate::stores::__reexport::SessionId,
                last_used_at: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
                expires_at: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "UPDATE sessions SET last_used_at = ?, expires_at = ? WHERE id = ?",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($ts(last_used_at))
                    .bind($ts(expires_at))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                Ok(())
            }

            async fn find_session_by_token_hash(
                &self,
                hash: &$crate::stores::__reexport::TokenHash,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::Session>,
            > {
                let sql = $ph(
                    "SELECT id, user_id, token_hash, transport, created_at, last_used_at, expires_at, ip, user_agent, recovery_cool_down_until
                     FROM sessions WHERE token_hash = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::token_hash_bytes(hash))
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                row.map(row_to_session).transpose()
            }

            async fn find_session_by_id(
                &self,
                id: $crate::stores::__reexport::SessionId,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::Session>,
            > {
                let sql = $ph(
                    "SELECT id, user_id, token_hash, transport, created_at, last_used_at, expires_at, ip, user_agent, recovery_cool_down_until
                     FROM sessions WHERE id = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(id.0))
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                row.map(row_to_session).transpose()
            }

            async fn list_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<
                Vec<$crate::stores::__reexport::Session>,
            > {
                let sql = $ph(
                    "SELECT id, user_id, token_hash, transport, created_at, last_used_at, expires_at, ip, user_agent, recovery_cool_down_until
                     FROM sessions WHERE user_id = ?",
                );
                let rows = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .fetch_all(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
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
                    .map_err($crate::common::storage_err)?;
                Ok(())
            }

            async fn delete_sessions_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
                except: Option<$crate::stores::__reexport::SessionId>,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let user = $crate::common::uuid_to_bytes(user_id.0);
                let result = match except {
                    None => {
                        let sql = $ph("DELETE FROM sessions WHERE user_id = ?");
                        ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                            .bind(user)
                            .execute(&self.pool)
                            .await
                    }
                    Some(except) => {
                        let sql = $ph("DELETE FROM sessions WHERE user_id = ? AND id != ?");
                        ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                            .bind(user)
                            .bind($crate::common::uuid_to_bytes(except.0))
                            .execute(&self.pool)
                            .await
                    }
                }
                .map_err($crate::common::storage_err)?;
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
                    .map_err($crate::common::storage_err)?;
                Ok(result.rows_affected())
            }
        }

        fn row_to_session(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<$crate::stores::__reexport::Session> {
            use ::sqlx::Row as _;
            let id_bytes: Vec<u8> = row.try_get("id").map_err($crate::common::storage_err)?;
            let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err($crate::common::storage_err)?;
            let hash_bytes: Vec<u8> = row.try_get("token_hash").map_err($crate::common::storage_err)?;
            let transport: String = row.try_get("transport").map_err($crate::common::storage_err)?;
            let ip: String = row.try_get("ip").map_err($crate::common::storage_err)?;
            Ok($crate::stores::__reexport::Session {
                id: $crate::stores::__reexport::SessionId(
                    $crate::common::uuid_from_row(id_bytes)?,
                ),
                user_id: $crate::stores::__reexport::UserId(
                    $crate::common::uuid_from_row(user_id_bytes)?,
                ),
                token_hash: $crate::common::token_hash_from_bytes(&hash_bytes)?,
                transport: $crate::common::session_transport_from_str(&transport)?,
                created_at: row.try_get("created_at").map_err($crate::common::storage_err)?,
                last_used_at: row.try_get("last_used_at").map_err($crate::common::storage_err)?,
                expires_at: row.try_get("expires_at").map_err($crate::common::storage_err)?,
                ip: $crate::common::client_ip_from_str(&ip)?,
                user_agent: row.try_get("user_agent").map_err($crate::common::storage_err)?,
                recovery_cool_down_until: row
                    .try_get("recovery_cool_down_until")
                    .map_err($crate::common::storage_err)?,
            })
        }

        struct EmailLinkStoreImpl {
            pool: $pool,
        }

        #[::async_trait::async_trait]
        impl $crate::stores::__reexport::EmailLinkStore for EmailLinkStoreImpl {
            async fn replace_link(
                &self,
                link: $crate::stores::__reexport::EmailLink,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                $crate::stores::sqlx_replace_link! {
                    $replace_link,
                    pool: self.pool,
                    ph: $ph,
                    timestamp: $ts,
                    link: link,
                }
            }

            async fn redeem_link(
                &self,
                hash: &$crate::stores::__reexport::TokenHash,
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::EmailLink>,
            > {
                $crate::stores::sqlx_take! {
                    $take,
                    pool: self.pool,
                    ph: $ph,
                    table: "email_links",
                    cols: "token_hash, purpose, user_id, owner_email, new_email, created_at, expires_at",
                    filter: "token_hash = ?",
                    binds: [$crate::common::token_hash_bytes(hash)],
                    map: row_to_email_link,
                }
            }

            async fn delete_links_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql = $ph("DELETE FROM email_links WHERE user_id = ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                Ok(result.rows_affected())
            }

            async fn purge_expired(
                &self,
                now: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql = $ph("DELETE FROM email_links WHERE expires_at <= ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($ts(now))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                Ok(result.rows_affected())
            }
        }

        fn row_to_email_link(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<
            $crate::stores::__reexport::EmailLink,
        > {
            use ::sqlx::Row as _;
            let hash_bytes: Vec<u8> = row.try_get("token_hash").map_err($crate::common::storage_err)?;
            let purpose_str: String = row.try_get("purpose").map_err($crate::common::storage_err)?;
            let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err($crate::common::storage_err)?;
            Ok($crate::stores::__reexport::EmailLink {
                token_hash: $crate::common::token_hash_from_bytes(&hash_bytes)?,
                purpose: $crate::common::purpose_from_str(&purpose_str)?,
                user_id: $crate::stores::__reexport::UserId(
                    $crate::common::uuid_from_row(user_id_bytes)?,
                ),
                owner_email: row.try_get("owner_email").map_err($crate::common::storage_err)?,
                new_email: row.try_get("new_email").map_err($crate::common::storage_err)?,
                created_at: row.try_get("created_at").map_err($crate::common::storage_err)?,
                expires_at: row.try_get("expires_at").map_err($crate::common::storage_err)?,
            })
        }

        struct PasskeyStoreImpl {
            pool: $pool,
        }

        #[::async_trait::async_trait]
        impl $crate::stores::__reexport::PasskeyStore for PasskeyStoreImpl {
            async fn add_passkey(
                &self,
                passkey: $crate::stores::__reexport::StoredPasskey,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "INSERT INTO passkeys
                     (credential_id, user_id, passkey, name, created_at, last_used_at,
                      aaguid, transports, backup_eligible, backup_state, recovery_cool_down_until)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(&passkey.credential_id)
                    .bind($crate::common::uuid_to_bytes(passkey.user_id.0))
                    .bind(&passkey.passkey)
                    .bind(&passkey.name)
                    .bind($ts(passkey.created_at))
                    .bind($ts(passkey.last_used_at))
                    .bind($crate::common::aaguid_to_str(passkey.aaguid))
                    .bind($crate::common::transports_to_str(&passkey.transports))
                    .bind(passkey.backup_eligible)
                    .bind(passkey.backup_state)
                    .bind($ts(passkey.recovery_cool_down_until))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                Ok(())
            }

            async fn record_passkey_use(
                &self,
                credential_id: &[u8],
                used: $crate::stores::__reexport::PasskeyUse,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "UPDATE passkeys
                     SET passkey = ?, backup_eligible = ?, backup_state = ?, last_used_at = ?
                     WHERE credential_id = ?",
                );
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(used.passkey)
                    .bind(used.backup_eligible)
                    .bind(used.backup_state)
                    .bind($ts(used.used_at))
                    .bind(credential_id)
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                if result.rows_affected() == 0 {
                    return Err($crate::stores::__reexport::StorageError::not_found(
                        "passkey not found",
                    ));
                }
                Ok(())
            }

            async fn set_passkey_name(
                &self,
                credential_id: &[u8],
                name: Option<&str>,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph("UPDATE passkeys SET name = ? WHERE credential_id = ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .bind(credential_id)
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                if result.rows_affected() == 0 {
                    return Err($crate::stores::__reexport::StorageError::not_found(
                        "passkey not found",
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
                            aaguid, transports, backup_eligible, backup_state, recovery_cool_down_until
                     FROM passkeys WHERE user_id = ?",
                );
                let rows = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .fetch_all(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                rows.into_iter().map(row_to_passkey).collect()
            }

            async fn find_passkey_by_credential_id(
                &self,
                credential_id: &[u8],
            ) -> $crate::stores::__reexport::StorageResult<
                Option<$crate::stores::__reexport::StoredPasskey>,
            > {
                let sql = $ph(
                    "SELECT credential_id, user_id, passkey, name, created_at, last_used_at,
                            aaguid, transports, backup_eligible, backup_state, recovery_cool_down_until
                     FROM passkeys WHERE credential_id = ?",
                );
                let row = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(credential_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                row.map(row_to_passkey).transpose()
            }

            async fn delete_passkey(
                &self,
                credential_id: &[u8],
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph("DELETE FROM passkeys WHERE credential_id = ?");
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind(credential_id)
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                Ok(())
            }

            async fn delete_passkeys_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let sql = $ph("DELETE FROM passkeys WHERE user_id = ?");
                let result = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                Ok(result.rows_affected())
            }
        }

        fn row_to_passkey(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<$crate::stores::__reexport::StoredPasskey> {
            use ::sqlx::Row as _;
            let passkey: Vec<u8> = row.try_get("passkey").map_err($crate::common::storage_err)?;
            let credential_id: Vec<u8> =
                row.try_get("credential_id").map_err($crate::common::storage_err)?;
            let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err($crate::common::storage_err)?;
            let aaguid: Option<String> = row.try_get("aaguid").map_err($crate::common::storage_err)?;
            let transports: String = row.try_get("transports").map_err($crate::common::storage_err)?;
            Ok($crate::stores::__reexport::StoredPasskey {
                credential_id,
                user_id: $crate::stores::__reexport::UserId(
                    $crate::common::uuid_from_row(user_id_bytes)?,
                ),
                passkey,
                name: row.try_get("name").map_err($crate::common::storage_err)?,
                created_at: row.try_get("created_at").map_err($crate::common::storage_err)?,
                last_used_at: row.try_get("last_used_at").map_err($crate::common::storage_err)?,
                aaguid: $crate::common::aaguid_from_str(aaguid)?,
                transports: $crate::common::transports_from_str(&transports),
                backup_eligible: row
                    .try_get("backup_eligible")
                    .map_err($crate::common::storage_err)?,
                backup_state: row.try_get("backup_state").map_err($crate::common::storage_err)?,
                recovery_cool_down_until: row
                    .try_get("recovery_cool_down_until")
                    .map_err($crate::common::storage_err)?,
            })
        }

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
                    "INSERT INTO passkey_registrations (id, purpose, user_id, state, owner_email, created_at, expires_at, recovery_cool_down_until)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(value.id.0))
                    .bind($crate::common::registration_purpose_to_str(value.purpose))
                    .bind($crate::common::uuid_to_bytes(value.user_id.0))
                    .bind(&value.state)
                    .bind(&value.owner_email)
                    .bind($ts(value.created_at))
                    .bind($ts(value.expires_at))
                    .bind($ts(value.recovery_cool_down_until))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
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
                    cols: "id, purpose, user_id, state, owner_email, created_at, expires_at, recovery_cool_down_until",
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
                    .map_err($crate::common::storage_err)?;
                Ok(res.rows_affected())
            }

            async fn list_registrations_for_user(
                &self,
                user_id: $crate::stores::__reexport::UserId,
            ) -> $crate::stores::__reexport::StorageResult<
                Vec<$crate::stores::__reexport::StoredPasskeyRegistration>,
            > {
                let sql = $ph(
                    "SELECT id, purpose, user_id, state, owner_email, created_at, expires_at, recovery_cool_down_until
                     FROM passkey_registrations WHERE user_id = ?",
                );
                let rows = ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(user_id.0))
                    .fetch_all(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
                rows.into_iter().map(row_to_registration).collect()
            }

            async fn put_authentication(
                &self,
                value: $crate::stores::__reexport::StoredPasskeyAuthentication,
            ) -> $crate::stores::__reexport::StorageResult<()> {
                let sql = $ph(
                    "INSERT INTO passkey_authentications (id, purpose, state, created_at, expires_at)
                     VALUES (?, ?, ?, ?, ?)",
                );
                ::sqlx::query(::sqlx::AssertSqlSafe(sql))
                    .bind($crate::common::uuid_to_bytes(value.id.0))
                    .bind($crate::common::authentication_purpose_to_str(value.purpose))
                    .bind(&value.state)
                    .bind($ts(value.created_at))
                    .bind($ts(value.expires_at))
                    .execute(&self.pool)
                    .await
                    .map_err($crate::common::storage_err)?;
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
                    cols: "id, purpose, state, created_at, expires_at",
                    filter: "id = ?",
                    binds: [$crate::common::uuid_to_bytes(id.0)],
                    map: row_to_authentication,
                }
            }

            async fn purge_expired(
                &self,
                now: $crate::stores::__reexport::DateTime<$crate::stores::__reexport::Utc>,
            ) -> $crate::stores::__reexport::StorageResult<u64> {
                let mut tx = self.pool.begin().await.map_err($crate::common::storage_err)?;
                let reg_sql = $ph("DELETE FROM passkey_registrations WHERE expires_at <= ?");
                let reg = ::sqlx::query(::sqlx::AssertSqlSafe(reg_sql))
                    .bind($ts(now))
                    .execute(&mut *tx)
                    .await
                    .map_err($crate::common::storage_err)?;
                let auth_sql = $ph("DELETE FROM passkey_authentications WHERE expires_at <= ?");
                let auth = ::sqlx::query(::sqlx::AssertSqlSafe(auth_sql))
                    .bind($ts(now))
                    .execute(&mut *tx)
                    .await
                    .map_err($crate::common::storage_err)?;
                tx.commit().await.map_err($crate::common::storage_err)?;
                Ok(reg.rows_affected() + auth.rows_affected())
            }
        }

        fn row_to_registration(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<
            $crate::stores::__reexport::StoredPasskeyRegistration,
        > {
            use ::sqlx::Row as _;
            let id_bytes: Vec<u8> = row.try_get("id").map_err($crate::common::storage_err)?;
            let purpose: String = row.try_get("purpose").map_err($crate::common::storage_err)?;
            let user_id_bytes: Vec<u8> = row.try_get("user_id").map_err($crate::common::storage_err)?;
            let state: Vec<u8> = row.try_get("state").map_err($crate::common::storage_err)?;
            Ok($crate::stores::__reexport::StoredPasskeyRegistration {
                id: $crate::stores::__reexport::PasskeyChallengeId(
                    $crate::common::uuid_from_row(id_bytes)?,
                ),
                purpose: $crate::common::registration_purpose_from_str(&purpose)?,
                user_id: $crate::stores::__reexport::UserId(
                    $crate::common::uuid_from_row(user_id_bytes)?,
                ),
                state,
                owner_email: row.try_get("owner_email").map_err($crate::common::storage_err)?,
                created_at: row.try_get("created_at").map_err($crate::common::storage_err)?,
                expires_at: row.try_get("expires_at").map_err($crate::common::storage_err)?,
                recovery_cool_down_until: row
                    .try_get("recovery_cool_down_until")
                    .map_err($crate::common::storage_err)?,
            })
        }

        fn row_to_authentication(
            row: $row,
        ) -> $crate::stores::__reexport::StorageResult<
            $crate::stores::__reexport::StoredPasskeyAuthentication,
        > {
            use ::sqlx::Row as _;
            let id_bytes: Vec<u8> = row.try_get("id").map_err($crate::common::storage_err)?;
            let purpose: String = row.try_get("purpose").map_err($crate::common::storage_err)?;
            let state: Vec<u8> = row.try_get("state").map_err($crate::common::storage_err)?;
            Ok($crate::stores::__reexport::StoredPasskeyAuthentication {
                id: $crate::stores::__reexport::PasskeyChallengeId(
                    $crate::common::uuid_from_row(id_bytes)?,
                ),
                purpose: $crate::common::authentication_purpose_from_str(&purpose)?,
                state,
                created_at: row.try_get("created_at").map_err($crate::common::storage_err)?,
                expires_at: row.try_get("expires_at").map_err($crate::common::storage_err)?,
            })
        }
    };
}

pub(crate) use sqlx_stores;

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
            .map_err($crate::common::storage_err)?;
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
        let mut tx = $pool.begin().await.map_err($crate::common::storage_err)?;
        let select_sql = $ph(concat!(
            "SELECT ", $cols, " FROM ", $table, " WHERE ", $filter, " FOR UPDATE",
        ));
        let row = ::sqlx::query(::sqlx::AssertSqlSafe(select_sql))
            $(.bind($bind))*
            .fetch_optional(&mut *tx)
            .await
            .map_err($crate::common::storage_err)?;
        let Some(row) = row else {
            tx.rollback().await.map_err($crate::common::storage_err)?;
            return Ok(None);
        };
        let parsed = $map(row)?;
        let delete_sql = $ph(concat!("DELETE FROM ", $table, " WHERE ", $filter));
        ::sqlx::query(::sqlx::AssertSqlSafe(delete_sql))
            $(.bind($bind))*
            .execute(&mut *tx)
            .await
            .map_err($crate::common::storage_err)?;
        tx.commit().await.map_err($crate::common::storage_err)?;
        Ok(Some(parsed))
    }};
}

pub(crate) use sqlx_take;

macro_rules! sqlx_replace_link {
    (
        upsert,
        pool: $pool:expr,
        ph: $ph:path,
        timestamp: $ts:path,
        link: $link:expr $(,)?
    ) => {{
        let link = $link;
        let sql = $ph(
            "INSERT INTO email_links (token_hash, purpose, user_id, owner_email, new_email, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (user_id, purpose) DO UPDATE SET
                 token_hash = excluded.token_hash,
                 owner_email = excluded.owner_email,
                 new_email = excluded.new_email,
                 created_at = excluded.created_at,
                 expires_at = excluded.expires_at",
        );
        ::sqlx::query(::sqlx::AssertSqlSafe(sql))
            .bind($crate::common::token_hash_bytes(&link.token_hash))
            .bind($crate::common::purpose_to_str(link.purpose))
            .bind($crate::common::uuid_to_bytes(link.user_id.0))
            .bind(&link.owner_email)
            .bind(&link.new_email)
            .bind($ts(link.created_at))
            .bind($ts(link.expires_at))
            .execute(&$pool)
            .await
            .map_err($crate::common::storage_err)?;
        Ok(())
    }};
    (
        update_or_insert,
        pool: $pool:expr,
        ph: $ph:path,
        timestamp: $ts:path,
        link: $link:expr $(,)?
    ) => {{
        let link = $link;
        // MySQL's upsert fires on any unique key, so a colliding token hash would overwrite
        // another user's link instead of being refused. Deleting, then inserting, in one
        // transaction deadlocks: the delete of an absent row locks the index gap that every
        // concurrent replace's insert then waits on, even another user's.
        let user_id = $crate::common::uuid_to_bytes(link.user_id.0);
        let purpose = $crate::common::purpose_to_str(link.purpose);
        let update_sql = $ph(
            "UPDATE email_links SET token_hash = ?, owner_email = ?, new_email = ?, created_at = ?, expires_at = ?
             WHERE user_id = ? AND purpose = ?",
        );
        let insert_sql = $ph(
            "INSERT INTO email_links (token_hash, purpose, user_id, owner_email, new_email, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        );
        let mut attempts = 0;
        loop {
            attempts += 1;
            let updated = ::sqlx::query(::sqlx::AssertSqlSafe(update_sql.clone()))
                .bind($crate::common::token_hash_bytes(&link.token_hash))
                .bind(&link.owner_email)
                .bind(&link.new_email)
                .bind($ts(link.created_at))
                .bind($ts(link.expires_at))
                .bind(&user_id)
                .bind(purpose)
                .execute(&$pool)
                .await
                .map_err($crate::common::storage_err)?;
            // sqlx connects with CLIENT_FOUND_ROWS, so this counts the rows matched, even
            // when an identical link left them unchanged.
            if updated.rows_affected() > 0 {
                break Ok(());
            }
            let inserted = ::sqlx::query(::sqlx::AssertSqlSafe(insert_sql.clone()))
                .bind($crate::common::token_hash_bytes(&link.token_hash))
                .bind(purpose)
                .bind(&user_id)
                .bind(&link.owner_email)
                .bind(&link.new_email)
                .bind($ts(link.created_at))
                .bind($ts(link.expires_at))
                .execute(&$pool)
                .await;
            match inserted {
                Ok(_) => break Ok(()),
                // A concurrent replace inserted the owner's row first, so update that row
                // instead. A colliding token hash keeps failing and is refused once the
                // attempts run out.
                Err(e)
                    if attempts < 3
                        && e.as_database_error().is_some_and(|db| db.is_unique_violation()) =>
                {
                    continue;
                }
                Err(e) => break Err($crate::common::storage_err(e)),
            }
        }
    }};
}

pub(crate) use sqlx_replace_link;

pub(crate) mod __reexport {
    pub use chrono::{DateTime, Utc};
    pub use doorman_core::encoding::{user_status_from_parts, user_status_to_str};
    pub use doorman_core::error::{StorageError, StorageResult};
    pub use doorman_core::storage::{
        EmailLink, EmailLinkStore, ExpiringStores, PasskeyChallengeId, PasskeyChallengeStore,
        PasskeyStore, PasskeyUse, RecordStores, Session, SessionId, SessionStore, Storage,
        StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, User,
        UserId, UserStatus, UserStore,
    };
}
