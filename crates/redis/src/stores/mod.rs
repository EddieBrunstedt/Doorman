pub(crate) mod passkey_chal;
pub(crate) mod session;
pub(crate) mod verification;

use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{Session, StoredPasskeyRegistration, VerificationToken};
use redis::aio::ConnectionManager;
use serde::de::DeserializeOwned;

use crate::client;
use crate::keys::KeySchema;

pub(crate) trait IndexedRow: DeserializeOwned {
    fn expires_at(&self) -> DateTime<Utc>;

    fn companion_key(&self, _keys: &KeySchema) -> Option<String> {
        None
    }
}

impl IndexedRow for Session {
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn companion_key(&self, keys: &KeySchema) -> Option<String> {
        Some(keys.session_hash_index(&self.token_hash))
    }
}

impl IndexedRow for VerificationToken {
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl IndexedRow for StoredPasskeyRegistration {
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

pub(crate) async fn purge_index_sets<T: IndexedRow>(
    conn: &mut ConnectionManager,
    keys: &KeySchema,
    pattern: &str,
    row_key: impl Fn(&str) -> String,
    now: DateTime<Utc>,
) -> StorageResult<u64> {
    let set_keys = client::scan_all(conn, pattern).await?;
    let mut removed = 0u64;
    for set_key in set_keys {
        let members = client::smembers(conn, &set_key).await?;
        if members.is_empty() {
            continue;
        }
        let row_keys: Vec<String> = members.iter().map(|m| row_key(m)).collect();
        let rows: Vec<Option<T>> = client::mget_json(conn, &row_keys).await?;

        let mut del_keys = Vec::new();
        let mut srem_members = Vec::new();
        for ((member, key), row) in members.into_iter().zip(row_keys).zip(rows) {
            match row {
                Some(row) if row.expires_at() <= now => {
                    del_keys.extend(row.companion_key(keys));
                    del_keys.push(key);
                    srem_members.push(member);
                }
                Some(_) => {}
                None => srem_members.push(member),
            }
        }
        client::del(conn, &del_keys).await?;
        removed += client::srem(conn, &set_key, &srem_members).await?;
    }
    Ok(removed)
}
