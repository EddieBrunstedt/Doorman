pub(crate) mod email_link;
pub(crate) mod passkey_chal;
pub(crate) mod session;

use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{Session, StoredPasskeyRegistration};
use redis::aio::ConnectionManager;
use serde::de::DeserializeOwned;

use crate::client;
use crate::keys::KeySchema;
use crate::scripts;

static INSERT_ABSENT: LazyLock<redis::Script> =
    LazyLock::new(|| redis::Script::new(scripts::INSERT_ABSENT));

pub(crate) struct OwnerIndex<'a> {
    pub(crate) set: &'a str,
    pub(crate) member: &'a str,
}

pub(crate) async fn insert_absent(
    conn: &mut ConnectionManager,
    rows: &[(&str, &str)],
    expires_at: DateTime<Utc>,
    index: Option<OwnerIndex<'_>>,
    what: &str,
) -> StorageResult<()> {
    let mut invocation = INSERT_ABSENT.prepare_invoke();
    for (key, _) in rows {
        invocation.key(*key);
    }
    if let Some(index) = &index {
        invocation.key(index.set);
    }
    invocation
        .arg(rows.len())
        .arg(expires_at.timestamp_millis());
    for (_, value) in rows {
        invocation.arg(*value);
    }
    if let Some(index) = &index {
        invocation.arg(index.member);
    }
    let inserted: i64 = invocation
        .invoke_async(conn)
        .await
        .map_err(StorageError::new)?;
    if inserted == 0 {
        return Err(StorageError::conflict(format!("{what} already exists")));
    }
    Ok(())
}

pub(crate) async fn list_indexed<T: IndexedRow>(
    conn: &mut ConnectionManager,
    set_key: &str,
    row_key: impl Fn(&str) -> String,
) -> StorageResult<Vec<T>> {
    let members = client::smembers(conn, set_key).await?;
    if members.is_empty() {
        return Ok(Vec::new());
    }
    let row_keys: Vec<String> = members.iter().map(|m| row_key(m)).collect();
    let rows: Vec<Option<T>> = client::mget_json(conn, &row_keys).await?;

    let mut out = Vec::new();
    let mut dangling = Vec::new();
    for (member, row) in members.into_iter().zip(rows) {
        match row {
            Some(row) => out.push(row),
            None => dangling.push(member),
        }
    }
    let _ = client::srem(conn, set_key, &dangling).await;
    Ok(out)
}

pub(crate) async fn delete_indexed<T: IndexedRow>(
    conn: &mut ConnectionManager,
    keys: &KeySchema,
    set_key: &str,
    row_key: impl Fn(&str) -> String,
    except: Option<&str>,
) -> StorageResult<u64> {
    let mut members = client::smembers(conn, set_key).await?;
    members.retain(|m| Some(m.as_str()) != except);
    if members.is_empty() {
        return Ok(0);
    }
    let row_keys: Vec<String> = members.iter().map(|m| row_key(m)).collect();
    let rows: Vec<Option<T>> = client::mget_json(conn, &row_keys).await?;
    let companions: Vec<String> = rows
        .iter()
        .flatten()
        .filter_map(|row| row.companion_key(keys))
        .collect();

    let mut pipe = redis::pipe();
    pipe.atomic();
    pipe.cmd("DEL").arg(&row_keys);
    if !companions.is_empty() {
        pipe.cmd("DEL").arg(&companions).ignore();
    }
    // Only the members read above leave the set: a row inserted since keeps
    // its member, so a later delete or list still finds it.
    pipe.cmd("SREM").arg(set_key).arg(&members).ignore();
    let (removed,): (u64,) = pipe.query_async(conn).await.map_err(StorageError::new)?;
    Ok(removed)
}

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
