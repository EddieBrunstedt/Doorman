use doorman_core::error::{StorageError, StorageResult};
use redis::aio::ConnectionManager;
use redis::cluster_async::ClusterConnection;
use redis::{Cmd, FromRedisValue, RedisResult, Script, Value};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::keys::{Key, Keys, Namespace};

#[derive(Clone)]
pub(crate) enum Connection {
    Standalone(ConnectionManager),
    Cluster(ClusterConnection),
}

#[derive(Clone)]
pub(crate) struct RedisClient {
    conn: Connection,
    keys: Keys,
}

impl RedisClient {
    pub(crate) fn new(conn: Connection, namespace: &Namespace) -> Self {
        Self {
            conn,
            keys: Keys::new(namespace),
        }
    }

    pub(crate) fn keys(&self) -> &Keys {
        &self.keys
    }

    pub(crate) fn with_namespace(mut self, namespace: &Namespace) -> Self {
        self.keys = Keys::new(namespace);
        self
    }

    async fn query<T: FromRedisValue>(&self, cmd: &Cmd) -> StorageResult<T> {
        self.query_redis(cmd).await.map_err(StorageError::new)
    }

    async fn query_redis<T: FromRedisValue>(&self, cmd: &Cmd) -> RedisResult<T> {
        match &self.conn {
            Connection::Standalone(conn) => cmd.query_async(&mut conn.clone()).await,
            Connection::Cluster(conn) => cmd.query_async(&mut conn.clone()).await,
        }
    }

    pub(crate) async fn eval<T: FromRedisValue>(
        &self,
        script: &Script,
        keys: &[&Key],
        args: &[String],
    ) -> StorageResult<T> {
        let mut invocation = script.prepare_invoke();
        for key in keys {
            invocation.key(*key);
        }
        for arg in args {
            invocation.arg(arg);
        }
        let result = match &self.conn {
            Connection::Standalone(conn) => invocation.invoke_async(&mut conn.clone()).await,
            Connection::Cluster(conn) => invocation.invoke_async(&mut conn.clone()).await,
        };
        result.map_err(StorageError::new)
    }

    // A cluster sends `INFO` to every primary and answers with a map of their replies.
    pub(crate) async fn memory_info(&self) -> RedisResult<Value> {
        self.query_redis(redis::cmd("INFO").arg("memory")).await
    }

    pub(crate) async fn get(&self, key: &Key) -> StorageResult<Option<String>> {
        self.query(redis::cmd("GET").arg(key)).await
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        key: &Key,
    ) -> StorageResult<Option<T>> {
        self.get(key).await?.as_deref().map(from_json).transpose()
    }

    pub(crate) async fn mget_json<T: DeserializeOwned>(
        &self,
        keys: &[Key],
    ) -> StorageResult<Vec<Option<T>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let raws: Vec<Option<String>> = self.query(redis::cmd("MGET").arg(keys)).await?;
        raws.iter()
            .map(|raw| raw.as_deref().map(from_json).transpose())
            .collect()
    }

    pub(crate) async fn del(&self, key: &Key) -> StorageResult<()> {
        self.query::<u64>(redis::cmd("DEL").arg(key))
            .await
            .map(|_| ())
    }

    pub(crate) async fn zmembers(&self, key: &Key) -> StorageResult<Vec<String>> {
        self.query(redis::cmd("ZRANGE").arg(key).arg(0).arg(-1))
            .await
    }

    pub(crate) async fn zmembers_due(
        &self,
        key: &Key,
        cutoff_ms: i64,
        limit: usize,
    ) -> StorageResult<Vec<String>> {
        self.query(
            redis::cmd("ZRANGE")
                .arg(key)
                .arg("-inf")
                .arg(cutoff_ms)
                .arg("BYSCORE")
                .arg("LIMIT")
                .arg(0)
                .arg(limit),
        )
        .await
    }

    pub(crate) async fn hget(&self, key: &Key, field: &str) -> StorageResult<Option<String>> {
        self.query(redis::cmd("HGET").arg(key).arg(field)).await
    }

    pub(crate) async fn hgetall(&self, key: &Key) -> StorageResult<Vec<(String, String)>> {
        self.query(redis::cmd("HGETALL").arg(key)).await
    }
}

pub(crate) fn to_json<T: Serialize>(value: &T) -> StorageResult<String> {
    serde_json::to_string(value).map_err(StorageError::new)
}

pub(crate) fn from_json<T: DeserializeOwned>(raw: &str) -> StorageResult<T> {
    serde_json::from_str(raw).map_err(StorageError::new)
}
