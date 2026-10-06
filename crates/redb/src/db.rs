use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    EmailLinkPurpose, PasskeySummary, Session, StoredPasskey, TokenHash, UserId,
};
use redb::{Database, ReadTransaction, ReadableDatabase as _, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
pub(crate) const EMAIL_GUARD: TableDefinition<&str, &str> = TableDefinition::new("email_guard");
pub(crate) const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("sessions");
pub(crate) const SESSION_HASH_IDX: TableDefinition<&str, &str> =
    TableDefinition::new("session_hash_idx");
pub(crate) const USER_SESSIONS_IDX: TableDefinition<&str, ()> =
    TableDefinition::new("user_sessions_idx");
pub(crate) const EMAIL_LINKS: TableDefinition<&str, &[u8]> = TableDefinition::new("email_links");
pub(crate) const USER_EMAIL_LINKS_IDX: TableDefinition<&str, ()> =
    TableDefinition::new("user_email_links_idx");
pub(crate) const PASSKEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("passkeys");
pub(crate) const USER_PASSKEYS_IDX: TableDefinition<&str, ()> =
    TableDefinition::new("user_passkeys_idx");
pub(crate) const PKREGS: TableDefinition<&str, &[u8]> = TableDefinition::new("pkregs");
pub(crate) const USER_PKREGS_IDX: TableDefinition<&str, ()> =
    TableDefinition::new("user_pkregs_idx");
pub(crate) const PKAUTHS: TableDefinition<&str, &[u8]> = TableDefinition::new("pkauths");

pub(crate) const SEP: char = '\x00';

pub(crate) fn token_hash_hex(hash: &TokenHash) -> String {
    hex_bytes(&hash.0)
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    doorman_core::encoding::hex(bytes)
}

pub(crate) fn email_link_key(purpose: EmailLinkPurpose, hash: &TokenHash) -> String {
    format!("{}{SEP}{}", purpose_str(purpose), token_hash_hex(hash))
}

pub(crate) fn email_link_key_raw(purpose: EmailLinkPurpose, hash_hex: &str) -> String {
    format!("{}{SEP}{}", purpose_str(purpose), hash_hex)
}

pub(crate) fn user_sessions_idx_key(
    user_id: UserId,
    session_id: doorman_core::storage::SessionId,
) -> String {
    format!("{}{SEP}{}", user_id.0, session_id.0)
}

pub(crate) fn user_sessions_prefix(user_id: UserId) -> String {
    format!("{}{SEP}", user_id.0)
}

pub(crate) fn user_email_links_idx_key(
    user_id: UserId,
    purpose: EmailLinkPurpose,
    hash: &TokenHash,
) -> String {
    format!(
        "{}{SEP}{}{SEP}{}",
        user_id.0,
        purpose_str(purpose),
        token_hash_hex(hash)
    )
}

pub(crate) fn user_email_links_prefix(user_id: UserId, purpose: EmailLinkPurpose) -> String {
    format!("{}{SEP}{}{SEP}", user_id.0, purpose_str(purpose))
}

pub(crate) fn user_passkeys_idx_key(user_id: UserId, credential_id: &[u8]) -> String {
    format!("{}{SEP}{}", user_id.0, hex_bytes(credential_id))
}

pub(crate) fn user_creds_prefix(user_id: UserId) -> String {
    format!("{}{SEP}", user_id.0)
}

pub(crate) fn user_pkregs_idx_key(
    user_id: UserId,
    challenge_id: doorman_core::storage::PasskeyChallengeId,
) -> String {
    format!("{}{SEP}{}", user_id.0, challenge_id.0)
}

pub(crate) fn user_pkregs_prefix(user_id: UserId) -> String {
    format!("{}{SEP}", user_id.0)
}

pub(crate) fn prefix_end(prefix: &str) -> String {
    debug_assert!(prefix.ends_with(SEP));
    let stem = &prefix[..prefix.len() - SEP.len_utf8()];
    format!("{stem}\x01")
}

pub(crate) use doorman_core::encoding::purpose_to_str as purpose_str;

pub(crate) fn fmt_ts(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

pub(crate) fn parse_ts(s: &str) -> StorageResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(err)
}

pub(crate) fn encode<T: Serialize>(value: &T) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(err)
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StorageResult<T> {
    serde_json::from_slice(bytes).map_err(err)
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PasskeyRow {
    pub credential_id_hex: String,
    pub user_id: String,
    pub passkey: Vec<u8>,
    pub name: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub aaguid: Option<String>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub recovery_cool_down_until: Option<String>,
}

pub(crate) fn encode_passkey(passkey: &StoredPasskey) -> StorageResult<Vec<u8>> {
    let row = PasskeyRow {
        credential_id_hex: hex_bytes(&passkey.credential_id),
        user_id: passkey.user_id.0.to_string(),
        passkey: passkey.passkey.clone(),
        name: passkey.name.clone(),
        created_at: fmt_ts(passkey.created_at),
        last_used_at: passkey.last_used_at.map(fmt_ts),
        aaguid: passkey.aaguid.map(|u| u.to_string()),
        transports: passkey.transports.clone(),
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
        recovery_cool_down_until: passkey.recovery_cool_down_until.map(fmt_ts),
    };
    serde_json::to_vec(&row).map_err(err)
}

fn row_to_passkey(row: PasskeyRow) -> StorageResult<StoredPasskey> {
    Ok(StoredPasskey {
        credential_id: decode_hex(&row.credential_id_hex)?,
        user_id: UserId(Uuid::parse_str(&row.user_id).map_err(err)?),
        passkey: row.passkey,
        name: row.name,
        created_at: parse_ts(&row.created_at)?,
        last_used_at: row.last_used_at.as_deref().map(parse_ts).transpose()?,
        aaguid: row
            .aaguid
            .as_deref()
            .map(|s| Uuid::parse_str(s).map_err(err))
            .transpose()?,
        transports: row.transports,
        backup_eligible: row.backup_eligible,
        backup_state: row.backup_state,
        recovery_cool_down_until: row
            .recovery_cool_down_until
            .as_deref()
            .map(parse_ts)
            .transpose()?,
    })
}

pub(crate) fn decode_passkey(bytes: &[u8]) -> StorageResult<StoredPasskey> {
    let row: PasskeyRow = serde_json::from_slice(bytes).map_err(err)?;
    row_to_passkey(row)
}

pub(crate) fn decode_passkey_summary(bytes: &[u8]) -> StorageResult<PasskeySummary> {
    let row: PasskeyRow = serde_json::from_slice(bytes).map_err(err)?;
    Ok(PasskeySummary::from(&row_to_passkey(row)?))
}

fn decode_hex(s: &str) -> StorageResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(StorageError::msg("odd-length hex string in stored record"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| StorageError::msg("invalid hex"))?;
        out.push(byte);
    }
    Ok(out)
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

pub(crate) fn write_session(wtxn: &WriteTransaction, session: &Session) -> StorageResult<()> {
    let session_key = session.id.0.to_string();
    let hash_key = token_hash_hex(&session.token_hash);
    let user_idx_key = user_sessions_idx_key(session.user_id, session.id);
    let encoded = encode(session)?;

    let mut sessions = wtxn.open_table(SESSIONS).map_err(err)?;
    let mut hash_idx = wtxn.open_table(SESSION_HASH_IDX).map_err(err)?;
    let mut user_idx = wtxn.open_table(USER_SESSIONS_IDX).map_err(err)?;

    sessions
        .insert(session_key.as_str(), encoded.as_slice())
        .map_err(err)?;
    hash_idx
        .insert(hash_key.as_str(), session_key.as_str())
        .map_err(err)?;
    user_idx.insert(user_idx_key.as_str(), ()).map_err(err)?;
    Ok(())
}

#[allow(clippy::result_large_err)]
pub(crate) fn ensure_tables(db: &Database) -> Result<(), redb::Error> {
    let wtxn = db.begin_write()?;
    wtxn.open_table(USERS)?;
    wtxn.open_table(EMAIL_GUARD)?;
    wtxn.open_table(SESSIONS)?;
    wtxn.open_table(SESSION_HASH_IDX)?;
    wtxn.open_table(USER_SESSIONS_IDX)?;
    wtxn.open_table(EMAIL_LINKS)?;
    wtxn.open_table(USER_EMAIL_LINKS_IDX)?;
    wtxn.open_table(PASSKEYS)?;
    wtxn.open_table(USER_PASSKEYS_IDX)?;
    wtxn.open_table(PKREGS)?;
    wtxn.open_table(USER_PKREGS_IDX)?;
    wtxn.open_table(PKAUTHS)?;
    wtxn.commit()?;
    Ok(())
}

pub(crate) fn err<E>(e: E) -> StorageError
where
    E: std::error::Error + Send + Sync + 'static,
{
    StorageError::new(e)
}
