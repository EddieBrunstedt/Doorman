use std::fmt::Display;
use std::sync::Arc;

use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::TokenHash;
use redb::{
    Database, ReadTransaction, ReadableDatabase as _, ReadableTable, TableDefinition,
    WriteTransaction,
};

use crate::expiring::Family;

pub(crate) const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
pub(crate) const EMAIL_GUARD: TableDefinition<&str, &str> = TableDefinition::new("email_guard");
pub(crate) const PASSKEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("passkeys");
pub(crate) const USER_PASSKEYS_IDX: TableDefinition<&str, ()> =
    TableDefinition::new("user_passkeys_idx");

pub(crate) const SESSIONS: Family = Family {
    rows: TableDefinition::new("sessions"),
    deadlines: TableDefinition::new("session_deadlines"),
    owners: Some(TableDefinition::new("user_sessions_idx")),
    lookups: Some(TableDefinition::new("session_hash_idx")),
};
pub(crate) const EMAIL_LINKS: Family = Family {
    rows: TableDefinition::new("email_links"),
    deadlines: TableDefinition::new("email_link_deadlines"),
    owners: Some(TableDefinition::new("user_email_links_idx")),
    lookups: None,
};
pub(crate) const PASSKEY_REGISTRATIONS: Family = Family {
    rows: TableDefinition::new("pkregs"),
    deadlines: TableDefinition::new("pkreg_deadlines"),
    owners: Some(TableDefinition::new("user_pkregs_idx")),
    lookups: None,
};
pub(crate) const PASSKEY_AUTHENTICATIONS: Family = Family {
    rows: TableDefinition::new("pkauths"),
    deadlines: TableDefinition::new("pkauth_deadlines"),
    owners: None,
    lookups: None,
};
pub(crate) const DPOP_PROOFS: Family = Family {
    rows: TableDefinition::new("dpop_proofs"),
    deadlines: TableDefinition::new("dpop_proof_deadlines"),
    owners: None,
    lookups: None,
};

const SEP: char = '\x00';

pub(crate) fn token_hash_hex(hash: &TokenHash) -> String {
    hex_bytes(&hash.0)
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    doorman_core::encoding::hex(bytes)
}

pub(crate) fn owner_key(owner: impl Display, member: impl Display) -> String {
    format!("{owner}{SEP}{member}")
}

pub(crate) fn owned_members(
    index: &impl ReadableTable<&'static str, ()>,
    owner: impl Display,
) -> StorageResult<Vec<String>> {
    let prefix = format!("{owner}{SEP}");
    // `\x01` is the character right after SEP, so the range holds exactly this owner's keys.
    let end = format!("{owner}\x01");
    index
        .range(prefix.as_str()..end.as_str())
        .map_err(err)?
        .map(|entry| {
            entry
                .map(|(key, _)| key.value()[prefix.len()..].to_owned())
                .map_err(err)
        })
        .collect()
}

#[derive(Clone)]
pub(crate) struct RedbHandle {
    db: Arc<Database>,
}

impl RedbHandle {
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub(crate) fn db(&self) -> Arc<Database> {
        self.db.clone()
    }

    pub(crate) async fn read<T, F>(&self, f: F) -> StorageResult<T>
    where
        F: FnOnce(&ReadTransaction) -> StorageResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let rtxn = db.begin_read().map_err(err)?;
            f(&rtxn)
        })
        .await
        .map_err(err)?
    }

    pub(crate) async fn write<T, F>(&self, f: F) -> StorageResult<T>
    where
        F: FnOnce(&WriteTransaction) -> StorageResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let wtxn = db.begin_write().map_err(err)?;
            let out = f(&wtxn)?;
            wtxn.commit().map_err(err)?;
            Ok(out)
        })
        .await
        .map_err(err)?
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn ensure_tables(db: &Database) -> Result<(), redb::Error> {
    let wtxn = db.begin_write()?;
    wtxn.open_table(USERS)?;
    wtxn.open_table(EMAIL_GUARD)?;
    wtxn.open_table(PASSKEYS)?;
    wtxn.open_table(USER_PASSKEYS_IDX)?;
    for family in [
        SESSIONS,
        EMAIL_LINKS,
        PASSKEY_REGISTRATIONS,
        PASSKEY_AUTHENTICATIONS,
        DPOP_PROOFS,
    ] {
        family.create_tables(&wtxn)?;
    }
    wtxn.commit()?;
    Ok(())
}

pub(crate) fn err<E>(e: E) -> StorageError
where
    E: std::error::Error + Send + Sync + 'static,
{
    StorageError::new(e)
}
