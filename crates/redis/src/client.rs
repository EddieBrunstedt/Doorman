use doorman_core::error::{StorageError, StorageResult};
use redis::aio::ConnectionManager;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::keys::KeySchema;

#[derive(Clone)]
pub(crate) struct RedisClient {
    conn: ConnectionManager,
    keys: KeySchema,
}

impl RedisClient {
    pub(crate) fn new(conn: ConnectionManager, prefix: String) -> Self {
        Self {
            conn,
            keys: KeySchema::new(prefix),
        }
    }

    pub(crate) fn conn(&self) -> ConnectionManager {
        self.conn.clone()
    }

    pub(crate) fn keys(&self) -> &KeySchema {
        &self.keys
    }

    pub(crate) fn with_prefix(mut self, prefix: String) -> Self {
        self.keys = KeySchema::new(prefix);
        self
    }

    pub(crate) async fn ping(&self) -> StorageResult<()> {
        let mut conn = self.conn.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map(|_| ())
            .map_err(StorageError::new)
    }
}

pub(crate) fn to_json<T: Serialize>(value: &T) -> StorageResult<String> {
    serde_json::to_string(value).map_err(StorageError::new)
}

pub(crate) fn from_json<T: DeserializeOwned>(raw: &str) -> StorageResult<T> {
    serde_json::from_str(raw).map_err(StorageError::new)
}

pub(crate) async fn get_string(
    conn: &mut ConnectionManager,
    key: &str,
) -> StorageResult<Option<String>> {
    redis::cmd("GET")
        .arg(key)
        .query_async(conn)
        .await
        .map_err(StorageError::new)
}

pub(crate) async fn get_json<T: DeserializeOwned>(
    conn: &mut ConnectionManager,
    key: &str,
) -> StorageResult<Option<T>> {
    match get_string(conn, key).await? {
        Some(raw) => Ok(Some(from_json(&raw)?)),
        None => Ok(None),
    }
}

pub(crate) async fn getdel_json<T: DeserializeOwned>(
    conn: &mut ConnectionManager,
    key: &str,
) -> StorageResult<Option<T>> {
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(key)
        .query_async(conn)
        .await
        .map_err(StorageError::new)?;
    match raw {
        Some(raw) => Ok(Some(from_json(&raw)?)),
        None => Ok(None),
    }
}

pub(crate) async fn mget_json<T: DeserializeOwned>(
    conn: &mut ConnectionManager,
    keys: &[String],
) -> StorageResult<Vec<Option<T>>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let raws: Vec<Option<String>> = redis::cmd("MGET")
        .arg(keys)
        .query_async(conn)
        .await
        .map_err(StorageError::new)?;
    raws.into_iter()
        .map(|raw| raw.map(|raw| from_json(&raw)).transpose())
        .collect()
}

pub(crate) async fn smembers(
    conn: &mut ConnectionManager,
    key: &str,
) -> StorageResult<Vec<String>> {
    redis::cmd("SMEMBERS")
        .arg(key)
        .query_async(conn)
        .await
        .map_err(StorageError::new)
}

pub(crate) async fn srem(
    conn: &mut ConnectionManager,
    key: &str,
    members: &[String],
) -> StorageResult<u64> {
    if members.is_empty() {
        return Ok(0);
    }
    redis::cmd("SREM")
        .arg(key)
        .arg(members)
        .query_async(conn)
        .await
        .map_err(StorageError::new)
}

pub(crate) async fn del(conn: &mut ConnectionManager, keys: &[String]) -> StorageResult<u64> {
    if keys.is_empty() {
        return Ok(0);
    }
    redis::cmd("DEL")
        .arg(keys)
        .query_async(conn)
        .await
        .map_err(StorageError::new)
}

pub(crate) async fn scan_all(
    conn: &mut ConnectionManager,
    pattern: &str,
) -> StorageResult<Vec<String>> {
    let mut cursor: u64 = 0;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(256)
            .query_async(conn)
            .await
            .map_err(StorageError::new)?;
        for key in batch {
            if seen.insert(key.clone()) {
                out.push(key);
            }
        }
        if next == 0 {
            break;
        }
        cursor = next;
    }
    Ok(out)
}
