use std::marker::PhantomData;
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::UserId;
use redis::Script;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::client::{self, RedisClient};
use crate::keys::{Family, Key, Keys, Ownership};
use crate::scripts;

static INSERT: LazyLock<Script> = LazyLock::new(|| scripts::script(scripts::INSERT));
static REPLACE: LazyLock<Script> = LazyLock::new(|| scripts::script(scripts::REPLACE));
static UPDATE: LazyLock<Script> = LazyLock::new(|| scripts::script(scripts::UPDATE));
static TAKE: LazyLock<Script> = LazyLock::new(|| scripts::script(scripts::TAKE));
static DELETE: LazyLock<Script> = LazyLock::new(|| scripts::removing_script(scripts::DELETE));

const PURGE_BATCH: usize = 256;

pub(crate) trait Row: Serialize + DeserializeOwned + Send + Sync {
    const FAMILY: Family;

    fn id(&self) -> String;

    fn deadline(&self) -> DateTime<Utc>;

    fn owner(&self) -> Option<UserId> {
        None
    }

    fn owner_field(&self) -> &'static str {
        ""
    }

    // Keys that name this row by another unique value; each holds the row's id.
    fn lookups(&self, _keys: &Keys) -> Vec<Key> {
        Vec::new()
    }
}

struct Found<R> {
    id: String,
    field: String,
    row: Option<R>,
}

// One batch the deadline index named as due at the cutoff, read apart from its delete.
struct Due<R> {
    cutoff_ms: i64,
    rows: Vec<Found<R>>,
}

pub(crate) enum Insert {
    Done,
    Conflict,
}

pub(crate) struct Table<R> {
    client: RedisClient,
    row: PhantomData<fn() -> R>,
}

impl<R: Row> Table<R> {
    pub(crate) fn new(client: RedisClient) -> Self {
        Self {
            client,
            row: PhantomData,
        }
    }

    fn keys(&self) -> &Keys {
        self.client.keys()
    }

    fn row_key(&self, id: &str) -> Key {
        self.keys().row(R::FAMILY, id)
    }

    fn deadlines(&self) -> Key {
        self.keys().deadlines(R::FAMILY)
    }

    fn owned(&self, owner: UserId) -> Key {
        self.keys().owned(R::FAMILY, owner)
    }

    fn owner_index(&self, row: &R) -> Option<Key> {
        match R::FAMILY.ownership {
            Ownership::None => None,
            Ownership::Set | Ownership::Field => row.owner().map(|owner| self.owned(owner)),
        }
    }

    pub(crate) async fn insert(&self, row: &R) -> StorageResult<Insert> {
        if matches!(R::FAMILY.ownership, Ownership::Field) {
            return Err(StorageError::msg(
                "a row owned by field is written with replace",
            ));
        }
        let id = row.id();
        let row_key = self.row_key(&id);
        let lookups = row.lookups(self.keys());
        let deadlines = self.deadlines();
        let owner = self.owner_index(row);

        let mut keys: Vec<&Key> = vec![&row_key];
        keys.extend(&lookups);
        keys.push(&deadlines);
        keys.extend(&owner);
        let mut args = vec![
            (lookups.len() + 1).to_string(),
            row.deadline().timestamp_millis().to_string(),
            ownership::<R>(owner.as_ref()).to_owned(),
            id.clone(),
            client::to_json(row)?,
        ];
        args.extend(lookups.iter().map(|_| id.clone()));

        let inserted: i64 = self.client.eval(&INSERT, &keys, &args).await?;
        Ok(if inserted == 1 {
            Insert::Done
        } else {
            Insert::Conflict
        })
    }

    // Inserts the row as the one its owner's field names; the row named before can't be taken.
    pub(crate) async fn replace(&self, row: &R) -> StorageResult<Insert> {
        let Some(owner) = row
            .owner()
            .filter(|_| matches!(R::FAMILY.ownership, Ownership::Field))
        else {
            return Err(StorageError::msg("only a row owned by field is replaced"));
        };
        let id = row.id();
        let row_key = self.row_key(&id);
        let deadlines = self.deadlines();
        let owned = self.owned(owner);
        let json = client::to_json(row)?;
        let field = row.owner_field();

        let current = self.client.hget(&owned, field).await?.unwrap_or_default();
        let current_key = (!current.is_empty()).then(|| self.row_key(&current));
        let mut keys: Vec<&Key> = vec![&row_key, &deadlines, &owned];
        keys.extend(&current_key);
        let args = [
            json,
            row.deadline().timestamp_millis().to_string(),
            id,
            field.to_owned(),
            current,
        ];
        let inserted: i64 = self.client.eval(&REPLACE, &keys, &args).await?;
        Ok(if inserted == 1 {
            Insert::Done
        } else {
            Insert::Conflict
        })
    }

    pub(crate) async fn get(&self, id: &str) -> StorageResult<Option<R>> {
        self.client.get_json(&self.row_key(id)).await
    }

    pub(crate) async fn get_by(&self, lookup: &Key) -> StorageResult<Option<R>> {
        let Some(id) = self.client.get(lookup).await? else {
            return Ok(None);
        };
        let row = self.get(&id).await?;
        if row.is_none() {
            // The row never comes back under the same id, so the lookup can go.
            self.client.del(lookup).await?;
        }
        Ok(row)
    }

    pub(crate) async fn take(&self, id: &str) -> StorageResult<Option<R>> {
        // The owner's index key comes from the row, so read it first; the script takes the row
        // only if it is still there.
        let Some(row) = self.get(id).await? else {
            return Ok(None);
        };
        let row_key = self.row_key(id);
        let deadlines = self.deadlines();
        let owner = self.owner_index(&row);
        let mut keys: Vec<&Key> = vec![&row_key, &deadlines];
        keys.extend(&owner);
        let args = [
            id.to_owned(),
            ownership::<R>(owner.as_ref()).to_owned(),
            row.owner_field().to_owned(),
        ];
        let taken: Option<String> = self.client.eval(&TAKE, &keys, &args).await?;
        taken.as_deref().map(client::from_json).transpose()
    }

    // Rewrites a row that still exists, at its new deadline; a row deleted meanwhile stays gone.
    pub(crate) async fn update(&self, row: &R) -> StorageResult<()> {
        let id = row.id();
        let row_key = self.row_key(&id);
        let deadlines = self.deadlines();
        let lookups = row.lookups(self.keys());
        let owner = self.owner_index(row);
        let mut keys: Vec<&Key> = vec![&row_key, &deadlines];
        keys.extend(&lookups);
        keys.extend(&owner);
        let args = [
            client::to_json(row)?,
            row.deadline().timestamp_millis().to_string(),
            id,
            lookups.len().to_string(),
            ownership::<R>(owner.as_ref()).to_owned(),
        ];
        self.client.eval::<i64>(&UPDATE, &keys, &args).await?;
        Ok(())
    }

    pub(crate) async fn delete(&self, id: &str) -> StorageResult<u64> {
        let Some(row) = self.get(id).await? else {
            return Ok(0);
        };
        let found = Found {
            id: id.to_owned(),
            field: row.owner_field().to_owned(),
            row: Some(row),
        };
        self.delete_rows(&[found], None, None).await
    }

    pub(crate) async fn list_owned(&self, owner: UserId) -> StorageResult<Vec<R>> {
        let entries = self.owned_entries(owner).await?;
        let found = self.find(entries).await?;
        Ok(found.into_iter().filter_map(|found| found.row).collect())
    }

    pub(crate) async fn delete_owned(
        &self,
        owner: UserId,
        except: Option<&str>,
    ) -> StorageResult<u64> {
        let mut entries = self.owned_entries(owner).await?;
        entries.retain(|(_, id)| Some(id.as_str()) != except);
        let found = self.find(entries).await?;
        // Only the ids read above go: a row inserted since keeps its entry, so a later delete or
        // list still finds it.
        self.delete_rows(&found, Some(owner), None).await
    }

    pub(crate) async fn purge(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let cutoff_ms = now.timestamp_millis();
        let mut removed = 0;
        loop {
            let due = self.read_due(cutoff_ms).await?;
            // Every entry read leaves the index or slides past the cutoff, so the next batch
            // starts past this one.
            removed += self.purge_due(&due).await?;
            if due.rows.len() < PURGE_BATCH {
                return Ok(removed);
            }
        }
    }

    async fn read_due(&self, cutoff_ms: i64) -> StorageResult<Due<R>> {
        let ids = self
            .client
            .zmembers_due(&self.deadlines(), cutoff_ms, PURGE_BATCH)
            .await?;
        let entries = ids.into_iter().map(|id| (String::new(), id)).collect();
        Ok(Due {
            cutoff_ms,
            rows: self.find(entries).await?,
        })
    }

    // Another caller may touch or delete a row between the read and this delete, so the script
    // checks each row is still due at the cutoff it was read at.
    async fn purge_due(&self, due: &Due<R>) -> StorageResult<u64> {
        self.delete_rows(&due.rows, None, Some(due.cutoff_ms)).await
    }

    // Each entry is a field in the owner's index (empty for a set) and the row id it names.
    async fn owned_entries(&self, owner: UserId) -> StorageResult<Vec<(String, String)>> {
        let owned = self.owned(owner);
        match R::FAMILY.ownership {
            Ownership::None => Ok(Vec::new()),
            Ownership::Set => Ok(self
                .client
                .zmembers(&owned)
                .await?
                .into_iter()
                .map(|id| (String::new(), id))
                .collect()),
            Ownership::Field => self.client.hgetall(&owned).await,
        }
    }

    async fn find(&self, entries: Vec<(String, String)>) -> StorageResult<Vec<Found<R>>> {
        let keys: Vec<Key> = entries.iter().map(|(_, id)| self.row_key(id)).collect();
        let rows = self.client.mget_json(&keys).await?;
        Ok(entries
            .into_iter()
            .zip(rows)
            .map(|((field, id), row): ((String, String), Option<R>)| Found {
                field: row
                    .as_ref()
                    .map_or(field, |row| row.owner_field().to_owned()),
                id,
                row,
            })
            .collect())
    }

    // A row already gone still leaves its indexes; its lookups expired with it.
    async fn delete_rows(
        &self,
        found: &[Found<R>],
        owner: Option<UserId>,
        cutoff_ms: Option<i64>,
    ) -> StorageResult<u64> {
        if found.is_empty() {
            return Ok(0);
        }
        let deadlines = self.deadlines();
        let mut row_keys: Vec<Vec<Key>> = Vec::with_capacity(found.len());
        let mut args = vec![cutoff_ms.map_or_else(|| "+inf".to_owned(), |ms| ms.to_string())];
        for Found { id, field, row } in found {
            let lookups = row
                .as_ref()
                .map(|row| row.lookups(self.keys()))
                .unwrap_or_default();
            let owner_index = match (R::FAMILY.ownership, row, owner) {
                (Ownership::None, _, _) => None,
                (_, Some(row), _) => self.owner_index(row),
                (_, None, owner) => owner.map(|owner| self.owned(owner)),
            };
            args.extend([
                id.clone(),
                lookups.len().to_string(),
                ownership::<R>(owner_index.as_ref()).to_owned(),
                field.clone(),
            ]);
            let mut declared = vec![self.row_key(id)];
            declared.extend(lookups);
            declared.extend(owner_index);
            row_keys.push(declared);
        }
        let mut keys: Vec<&Key> = vec![&deadlines];
        keys.extend(row_keys.iter().flatten());
        self.client.eval(&DELETE, &keys, &args).await
    }
}

fn ownership<R: Row>(owner_index: Option<&Key>) -> &'static str {
    match (R::FAMILY.ownership, owner_index) {
        (_, None) | (Ownership::None, _) => "none",
        (Ownership::Set, Some(_)) => "set",
        (Ownership::Field, Some(_)) => "field",
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use doorman_core::session::hash_token;
    use doorman_core::storage::{Session, SessionId, SessionTransport};
    use testcontainers_modules::redis::Redis;
    use testcontainers_modules::testcontainers::ImageExt;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    use testcontainers_modules::valkey::Valkey;

    use super::*;
    use crate::RedisStorage;

    #[derive(Clone, Copy)]
    enum Backend {
        Redis,
        Valkey,
    }

    // Only held so the container lives as long as the test.
    type ContainerGuard = Box<dyn std::any::Any + Send>;

    async fn start(backend: Backend) -> (ContainerGuard, RedisStorage) {
        let (node, host, port): (ContainerGuard, _, _) = match backend {
            Backend::Redis => {
                let node = Redis::default()
                    .with_tag("7-alpine")
                    .start()
                    .await
                    .expect("start redis container");
                let host = node.get_host().await.expect("container host");
                let port = node.get_host_port_ipv4(6379).await.expect("container port");
                (Box::new(node), host, port)
            }
            Backend::Valkey => {
                let node = Valkey::default()
                    .start()
                    .await
                    .expect("start valkey container");
                let host = node.get_host().await.expect("container host");
                let port = node.get_host_port_ipv4(6379).await.expect("container port");
                (Box::new(node), host, port)
            }
        };
        let storage = RedisStorage::connect(&format!("redis://{host}:{port}"))
            .await
            .expect("connect");
        (node, storage)
    }

    fn session(user_id: UserId, token: &str, expires_at: DateTime<Utc>) -> Session {
        Session {
            id: SessionId::new(),
            user_id,
            token_hash: hash_token(token),
            transport: SessionTransport::Cookie,
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            expires_at,
            ip: "192.0.2.1".parse().expect("client IP"),
            user_agent: None,
            recovery_cool_down_until: None,
        }
    }

    fn ids(sessions: Vec<Session>) -> Vec<SessionId> {
        sessions.into_iter().map(|session| session.id).collect()
    }

    // The store interface can't act between a purge's read and its delete, so this steps through
    // them itself.
    async fn run_a_purge_deletes_only_rows_still_due_when_it_deletes(backend: Backend) {
        let (_node, storage) = start(backend).await;
        let sessions = storage.expiring().sessions;
        let table = Table::<Session>::new(storage.client.clone());
        let now = Utc::now();
        let user = UserId::new();
        let touched = session(user, "touched", now + Duration::hours(1));
        let deleted = session(user, "deleted", now + Duration::hours(1));
        for s in [&touched, &deleted] {
            sessions
                .create_session(s.clone())
                .await
                .expect("create session");
        }

        let cutoff = now + Duration::hours(2);
        let due = table
            .read_due(cutoff.timestamp_millis())
            .await
            .expect("read the due rows");
        assert_eq!(due.rows.len(), 2, "both sessions were due at the cutoff");
        let slid = now + Duration::hours(3);
        sessions
            .touch_session(touched.id, now, slid)
            .await
            .expect("touch a session");
        sessions
            .delete_session(deleted.id)
            .await
            .expect("delete a session");

        assert_eq!(
            table.purge_due(&due).await.expect("purge the due rows"),
            0,
            "neither session was still due when the purge deleted",
        );
        assert_eq!(
            sessions
                .find_session_by_token_hash(&touched.token_hash)
                .await
                .expect("find by token hash")
                .map(|s| s.id),
            Some(touched.id),
            "the touched session kept its row and its lookup",
        );
        assert_eq!(
            ids(sessions.list_for_user(user).await.expect("list")),
            [touched.id],
            "the touched session kept its owner's index entry",
        );
        assert_eq!(
            sessions.purge_expired(cutoff).await.expect("purge"),
            0,
            "the touched session's deadline index entry slid past the cutoff",
        );
        assert_eq!(
            sessions
                .purge_expired(slid + Duration::seconds(1))
                .await
                .expect("purge"),
            1,
            "the touched session is purged once its slid deadline passes",
        );
    }

    #[tokio::test]
    async fn redis_a_purge_deletes_only_rows_still_due_when_it_deletes() {
        run_a_purge_deletes_only_rows_still_due_when_it_deletes(Backend::Redis).await;
    }

    #[tokio::test]
    async fn valkey_a_purge_deletes_only_rows_still_due_when_it_deletes() {
        run_a_purge_deletes_only_rows_still_due_when_it_deletes(Backend::Valkey).await;
    }
}
