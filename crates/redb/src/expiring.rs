use std::marker::PhantomData;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::db::{self, err};
use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::UserId;
use redb::{
    ReadOnlyTable, ReadTransaction, ReadableTable, Table, TableDefinition, TableError,
    WriteTransaction,
};

// Sorted by deadline first, so purge reads only the entries that are due.
type DeadlineKey = (i64, u32, &'static str);
// The owner-index entry and the lookup the row holds, so purge can remove them without reading the
// row.
type DeadlineValue = (Option<&'static str>, Option<&'static str>);

type RowsTable = TableDefinition<'static, &'static str, &'static [u8]>;
type DeadlinesTable = TableDefinition<'static, DeadlineKey, DeadlineValue>;
type OwnersTable = TableDefinition<'static, &'static str, ()>;
type LookupsTable = TableDefinition<'static, &'static str, &'static str>;

pub(crate) struct Family {
    pub(crate) rows: RowsTable,
    pub(crate) deadlines: DeadlinesTable,
    pub(crate) owners: Option<OwnersTable>,
    pub(crate) lookups: Option<LookupsTable>,
}

impl Family {
    pub(crate) fn create_tables(&self, wtxn: &WriteTransaction) -> Result<(), TableError> {
        wtxn.open_table(self.rows)?;
        wtxn.open_table(self.deadlines)?;
        if let Some(owners) = self.owners {
            wtxn.open_table(owners)?;
        }
        if let Some(lookups) = self.lookups {
            wtxn.open_table(lookups)?;
        }
        Ok(())
    }
}

pub(crate) trait Row: Serialize + DeserializeOwned {
    const FAMILY: Family;

    fn key(&self) -> String;

    fn deadline(&self) -> DateTime<Utc>;

    fn owner(&self) -> Option<UserId> {
        None
    }

    // Another unique value that names the row.
    fn lookup(&self) -> Option<String> {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Deadline {
    secs: i64,
    nanos: u32,
}

impl Deadline {
    const LEN: usize = 12;

    fn at(at: DateTime<Utc>) -> Self {
        Self {
            secs: at.timestamp(),
            nanos: at.timestamp_subsec_nanos(),
        }
    }

    fn entry(self, key: &str) -> (i64, u32, &str) {
        (self.secs, self.nanos, key)
    }
}

// The row's deadline goes ahead of core's JSON in a layout this adapter owns, so purging or removing
// a row never decodes core's type, and a row that no longer decodes still expires.
fn pack(deadline: Deadline, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(Deadline::LEN + body.len());
    bytes.extend_from_slice(&deadline.secs.to_be_bytes());
    bytes.extend_from_slice(&deadline.nanos.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn unpack(bytes: &[u8]) -> StorageResult<(Deadline, &[u8])> {
    let corrupt = || StorageError::msg("an expiring row is shorter than its deadline");
    let (secs, rest) = bytes.split_first_chunk::<8>().ok_or_else(corrupt)?;
    let (nanos, body) = rest.split_first_chunk::<4>().ok_or_else(corrupt)?;
    let deadline = Deadline {
        secs: i64::from_be_bytes(*secs),
        nanos: u32::from_be_bytes(*nanos),
    };
    Ok((deadline, body))
}

fn read<R: Row>(
    rows: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> StorageResult<Option<R>> {
    match rows.get(key).map_err(err)? {
        Some(bytes) => Ok(Some(db::decode(unpack(bytes.value())?.1)?)),
        None => Ok(None),
    }
}

fn no_owners() -> StorageError {
    StorageError::msg("this kind of row has no owner")
}

fn no_lookups() -> StorageError {
    StorageError::msg("this kind of row has no lookup")
}

// One kind of expiring row inside a write transaction. Every write keeps the row, its deadline entry,
// its owner-index entry and its lookup in step.
pub(crate) struct Writer<'txn, R> {
    rows: Table<'txn, &'static str, &'static [u8]>,
    deadlines: Table<'txn, DeadlineKey, DeadlineValue>,
    owners: Option<Table<'txn, &'static str, ()>>,
    lookups: Option<Table<'txn, &'static str, &'static str>>,
    row: PhantomData<fn() -> R>,
}

impl<'txn, R: Row> Writer<'txn, R> {
    pub(crate) fn open(wtxn: &'txn WriteTransaction) -> StorageResult<Self> {
        let family = R::FAMILY;
        Ok(Self {
            rows: wtxn.open_table(family.rows).map_err(err)?,
            deadlines: wtxn.open_table(family.deadlines).map_err(err)?,
            owners: family
                .owners
                .map(|owners| wtxn.open_table(owners))
                .transpose()
                .map_err(err)?,
            lookups: family
                .lookups
                .map(|lookups| wtxn.open_table(lookups))
                .transpose()
                .map_err(err)?,
            row: PhantomData,
        })
    }

    // False, writing nothing, when the row's key or lookup is already taken.
    pub(crate) fn insert(&mut self, row: &R) -> StorageResult<bool> {
        let key = row.key();
        let lookup = row.lookup().filter(|_| self.lookups.is_some());
        if self.rows.get(key.as_str()).map_err(err)?.is_some() {
            return Ok(false);
        }
        if let (Some(lookups), Some(lookup)) = (&self.lookups, &lookup)
            && lookups.get(lookup.as_str()).map_err(err)?.is_some()
        {
            return Ok(false);
        }

        let deadline = Deadline::at(row.deadline());
        let body = db::encode(row)?;
        self.rows
            .insert(key.as_str(), pack(deadline, &body).as_slice())
            .map_err(err)?;
        let owner = match (&mut self.owners, row.owner()) {
            (Some(owners), Some(owner)) => {
                let entry = db::owner_key(owner, &key);
                owners.insert(entry.as_str(), ()).map_err(err)?;
                Some(entry)
            }
            _ => None,
        };
        if let (Some(lookups), Some(lookup)) = (&mut self.lookups, &lookup) {
            lookups.insert(lookup.as_str(), key.as_str()).map_err(err)?;
        }
        self.deadlines
            .insert(deadline.entry(&key), (owner.as_deref(), lookup.as_deref()))
            .map_err(err)?;
        Ok(true)
    }

    pub(crate) fn get(&self, key: &str) -> StorageResult<Option<R>> {
        read(&self.rows, key)
    }

    // Removes the row and returns it; a row that doesn't decode stays, as the error aborts the
    // transaction.
    pub(crate) fn take(&mut self, key: &str) -> StorageResult<Option<R>> {
        let (deadline, row) = match self.rows.remove(key).map_err(err)? {
            Some(bytes) => {
                let (deadline, body) = unpack(bytes.value())?;
                (deadline, db::decode(body)?)
            }
            None => return Ok(None),
        };
        self.remove_indexes(deadline, key)?;
        Ok(Some(row))
    }

    // Removes the row without decoding it, so a row that no longer decodes can still be removed.
    pub(crate) fn remove(&mut self, key: &str) -> StorageResult<bool> {
        let deadline = match self.rows.remove(key).map_err(err)? {
            Some(bytes) => unpack(bytes.value())?.0,
            None => return Ok(false),
        };
        self.remove_indexes(deadline, key)?;
        Ok(true)
    }

    pub(crate) fn owned_keys(&self, owner: UserId) -> StorageResult<Vec<String>> {
        db::owned_members(self.owners.as_ref().ok_or_else(no_owners)?, owner)
    }

    pub(crate) fn remove_owned(
        &mut self,
        owner: UserId,
        except: Option<&str>,
    ) -> StorageResult<u64> {
        let mut removed = 0;
        for key in self.owned_keys(owner)? {
            if Some(key.as_str()) != except && self.remove(&key)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    // Reads only the deadline index, never a row, so it costs the number of rows due rather than
    // the size of the table.
    pub(crate) fn purge(&mut self, now: DateTime<Utc>) -> StorageResult<u64> {
        let now = Deadline::at(now);
        let mut due = Vec::new();
        for entry in self.deadlines.iter().map_err(err)? {
            let (entry_key, indexes) = entry.map_err(err)?;
            let (secs, nanos, key) = entry_key.value();
            let deadline = Deadline { secs, nanos };
            if deadline > now {
                break;
            }
            let (owner, lookup) = indexes.value();
            due.push((
                deadline,
                key.to_owned(),
                owner.map(str::to_owned),
                lookup.map(str::to_owned),
            ));
        }

        let mut removed = 0;
        for (deadline, key, owner, lookup) in due {
            self.deadlines.remove(deadline.entry(&key)).map_err(err)?;
            if self.rows.remove(key.as_str()).map_err(err)?.is_some() {
                removed += 1;
            }
            self.remove_index_entries(owner.as_deref(), lookup.as_deref())?;
        }
        Ok(removed)
    }

    fn remove_indexes(&mut self, deadline: Deadline, key: &str) -> StorageResult<()> {
        let (owner, lookup) = match self.deadlines.remove(deadline.entry(key)).map_err(err)? {
            Some(indexes) => {
                let (owner, lookup) = indexes.value();
                (owner.map(str::to_owned), lookup.map(str::to_owned))
            }
            None => return Err(StorageError::msg("an expiring row has no deadline entry")),
        };
        self.remove_index_entries(owner.as_deref(), lookup.as_deref())
    }

    fn remove_index_entries(
        &mut self,
        owner: Option<&str>,
        lookup: Option<&str>,
    ) -> StorageResult<()> {
        if let (Some(owners), Some(owner)) = (&mut self.owners, owner) {
            owners.remove(owner).map_err(err)?;
        }
        if let (Some(lookups), Some(lookup)) = (&mut self.lookups, lookup) {
            lookups.remove(lookup).map_err(err)?;
        }
        Ok(())
    }
}

pub(crate) struct Reader<R> {
    rows: ReadOnlyTable<&'static str, &'static [u8]>,
    owners: Option<ReadOnlyTable<&'static str, ()>>,
    lookups: Option<ReadOnlyTable<&'static str, &'static str>>,
    row: PhantomData<fn() -> R>,
}

impl<R: Row> Reader<R> {
    pub(crate) fn open(rtxn: &ReadTransaction) -> StorageResult<Self> {
        let family = R::FAMILY;
        Ok(Self {
            rows: rtxn.open_table(family.rows).map_err(err)?,
            owners: family
                .owners
                .map(|owners| rtxn.open_table(owners))
                .transpose()
                .map_err(err)?,
            lookups: family
                .lookups
                .map(|lookups| rtxn.open_table(lookups))
                .transpose()
                .map_err(err)?,
            row: PhantomData,
        })
    }

    pub(crate) fn get(&self, key: &str) -> StorageResult<Option<R>> {
        read(&self.rows, key)
    }

    pub(crate) fn get_by(&self, lookup: &str) -> StorageResult<Option<R>> {
        let lookups = self.lookups.as_ref().ok_or_else(no_lookups)?;
        let Some(key) = lookups.get(lookup).map_err(err)? else {
            return Ok(None);
        };
        self.get(key.value())
    }

    pub(crate) fn list_owned(&self, owner: UserId) -> StorageResult<Vec<R>> {
        let owners = self.owners.as_ref().ok_or_else(no_owners)?;
        let mut rows = Vec::new();
        for key in db::owned_members(owners, owner)? {
            rows.extend(self.get(&key)?);
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use doorman_core::session::hash_token;
    use doorman_core::storage::{Session, SessionId, SessionTransport};
    use redb::backends::InMemoryBackend;
    use redb::{Database, ReadableDatabase as _, ReadableTableMetadata as _};

    use super::*;

    fn database() -> Database {
        let db = Database::builder()
            .create_with_backend(InMemoryBackend::new())
            .expect("in-memory database");
        crate::db::ensure_tables(&db).expect("tables");
        db
    }

    fn session(user_id: UserId, expires_at: DateTime<Utc>) -> Session {
        Session {
            id: SessionId::new(),
            user_id,
            token_hash: hash_token(&SessionId::new().to_string()),
            transport: SessionTransport::Cookie,
            created_at: expires_at - Duration::hours(1),
            last_used_at: expires_at - Duration::hours(1),
            expires_at,
            ip: "192.0.2.1".parse().expect("client IP"),
            user_agent: None,
            recovery_cool_down_until: None,
        }
    }

    fn table_lens(db: &Database) -> [u64; 4] {
        let rtxn = db.begin_read().expect("read");
        let family = Session::FAMILY;
        let owners = family.owners.expect("sessions have owners");
        let lookups = family.lookups.expect("sessions have a lookup");
        [
            rtxn.open_table(family.rows)
                .expect("rows")
                .len()
                .expect("len"),
            rtxn.open_table(family.deadlines)
                .expect("deadlines")
                .len()
                .expect("len"),
            rtxn.open_table(owners).expect("owners").len().expect("len"),
            rtxn.open_table(lookups)
                .expect("lookups")
                .len()
                .expect("len"),
        ]
    }

    #[test]
    fn removing_an_owners_rows_does_not_decode_them() {
        let db = database();
        let user_id = UserId::new();
        let now = Utc::now();
        let stale = session(user_id, now + Duration::hours(1));

        let wtxn = db.begin_write().expect("write");
        {
            let mut sessions = Writer::<Session>::open(&wtxn).expect("open");
            assert!(sessions.insert(&stale).expect("insert"));
            assert!(
                sessions
                    .insert(&session(user_id, now + Duration::hours(2)))
                    .expect("insert")
            );
            // Stands in for a row written by an older shape of core's type.
            let rows = &mut sessions.rows;
            let key = stale.id.to_string();
            let reshaped = pack(Deadline::at(stale.expires_at), b"{\"old\":true}");
            rows.insert(key.as_str(), reshaped.as_slice())
                .expect("reshape");
            assert!(
                sessions.get(&key).is_err(),
                "the reshaped row no longer decodes"
            );

            assert_eq!(sessions.remove_owned(user_id, None).expect("remove"), 2);
        }
        wtxn.commit().expect("commit");

        assert_eq!(table_lens(&db), [0; 4], "no row or index entry is left");
    }
}
