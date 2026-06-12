//! Table definitions, key builders, value encoding, and the shared database
//! handle the store implementations build on.
//!
//! ## Table layout
//!
//! Every record type occupies a dedicated redb table. Secondary lookups and
//! per-user collections use separate index tables with compound string keys,
//! kept consistent with the primary table inside every write transaction that
//! touches them.
//!
//! | Table                | Key                                     | Value          |
//! | -------------------- | --------------------------------------- | -------------- |
//! | `users`              | user UUID                               | JSON           |
//! | `email_guard`        | email address                           | user UUID str  |
//! | `sessions`           | session UUID                            | JSON           |
//! | `session_hash_idx`   | token hash hex                          | session UUID   |
//! | `user_sessions_idx`  | `{user_id}\x00{session_id}`             | ()             |
//! | `vtokens`            | `{purpose}\x00{hash_hex}`               | JSON           |
//! | `user_vtokens_idx`   | `{user_id}\x00{purpose}\x00{hash_hex}`  | ()             |
//! | `passkey_creds`      | credential id hex                       | JSON           |
//! | `user_creds_idx`     | `{user_id}\x00{cred_id_hex}`            | ()             |
//! | `pkregs`             | challenge UUID                          | JSON           |
//! | `user_pkregs_idx`    | `{user_id}\x00{challenge_id}`           | ()             |
//! | `pkauths`            | challenge UUID                          | JSON           |
//!
//! ## Compound-key prefix scans
//!
//! The separator `\x00` (NUL byte, `SEP`) never appears in UUIDs, hex strings,
//! or purpose names (all printable ASCII). A prefix scan for all entries under
//! `"{user_id}\x00"` uses the half-open range `[prefix, prefix_end(prefix))`
//! where `prefix_end` replaces the trailing `\x00` with `\x01`.

use std::fmt::Write as _;
use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeySummary, StoredPasskey, TokenHash, UserId, VerificationPurpose,
};
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Table definitions
// ---------------------------------------------------------------------------

pub(crate) const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
pub(crate) const EMAIL_GUARD: TableDefinition<&str, &str> = TableDefinition::new("email_guard");
pub(crate) const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("sessions");
pub(crate) const SESSION_HASH_IDX: TableDefinition<&str, &str> =
    TableDefinition::new("session_hash_idx");
pub(crate) const USER_SESSIONS_IDX: TableDefinition<&str, ()> =
    TableDefinition::new("user_sessions_idx");
pub(crate) const VTOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("vtokens");
pub(crate) const USER_VTOKENS_IDX: TableDefinition<&str, ()> =
    TableDefinition::new("user_vtokens_idx");
pub(crate) const PASSKEY_CREDS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("passkey_creds");
pub(crate) const USER_CREDS_IDX: TableDefinition<&str, ()> = TableDefinition::new("user_creds_idx");
pub(crate) const PKREGS: TableDefinition<&str, &[u8]> = TableDefinition::new("pkregs");
pub(crate) const USER_PKREGS_IDX: TableDefinition<&str, ()> =
    TableDefinition::new("user_pkregs_idx");
pub(crate) const PKAUTHS: TableDefinition<&str, &[u8]> = TableDefinition::new("pkauths");

// ---------------------------------------------------------------------------
// Separator
// ---------------------------------------------------------------------------

/// The byte used to join components of a compound key. NUL (`\x00`) never
/// appears in UUIDs, lowercase hex strings, or purpose names, so it is
/// unambiguous and lets prefix scans use `\x01` as an exclusive upper bound.
pub(crate) const SEP: char = '\x00';

// ---------------------------------------------------------------------------
// Key builders
// ---------------------------------------------------------------------------

pub(crate) fn token_hash_hex(hash: &TokenHash) -> String {
    hex_bytes(&hash.0)
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(crate) fn vtoken_key(purpose: VerificationPurpose, hash: &TokenHash) -> String {
    format!("{}{SEP}{}", purpose_str(purpose), token_hash_hex(hash))
}

/// Reconstruct a `vtokens` primary key from the purpose and the already-hex
/// hash component (avoids decoding hex back to bytes just to re-encode it).
pub(crate) fn vtoken_key_raw(purpose: VerificationPurpose, hash_hex: &str) -> String {
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

pub(crate) fn user_vtokens_idx_key(
    user_id: UserId,
    purpose: VerificationPurpose,
    hash: &TokenHash,
) -> String {
    format!(
        "{}{SEP}{}{SEP}{}",
        user_id.0,
        purpose_str(purpose),
        token_hash_hex(hash)
    )
}

pub(crate) fn user_vtokens_prefix(user_id: UserId, purpose: VerificationPurpose) -> String {
    format!("{}{SEP}{}{SEP}", user_id.0, purpose_str(purpose))
}

pub(crate) fn user_creds_idx_key(user_id: UserId, credential_id: &[u8]) -> String {
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

/// Return the exclusive upper bound for a prefix scan.
///
/// Every prefix ends with `SEP` (`\x00`); the end replaces that with `\x01`
/// so the range `[prefix, prefix_end(prefix))` exactly covers every key that
/// starts with the prefix. The sub-key components (UUIDs, hex, purpose names)
/// only contain printable ASCII (`>= ' '`), so no key starting with the
/// prefix can equal or exceed `prefix_end`.
pub(crate) fn prefix_end(prefix: &str) -> String {
    debug_assert!(prefix.ends_with(SEP));
    // Replace the trailing \x00 (1 byte in UTF-8) with \x01.
    let stem = &prefix[..prefix.len() - SEP.len_utf8()];
    format!("{stem}\x01")
}

pub(crate) fn purpose_str(purpose: VerificationPurpose) -> &'static str {
    match purpose {
        VerificationPurpose::Signup => "signup",
        VerificationPurpose::Recovery => "recovery",
        VerificationPurpose::EmailChange => "email_change",
    }
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

pub(crate) fn fmt_ts(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

pub(crate) fn parse_ts(s: &str) -> StorageResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(err)
}

// ---------------------------------------------------------------------------
// Generic encode / decode (for types that already have Serialize + Deserialize)
// ---------------------------------------------------------------------------

pub(crate) fn encode<T: Serialize>(value: &T) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(err)
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StorageResult<T> {
    serde_json::from_slice(bytes).map_err(err)
}

// ---------------------------------------------------------------------------
// StoredPasskey encoding
//
// `StoredPasskey` does not implement `Serialize`/`Deserialize` (it lives in
// doorman-core and carries no serde dep). We bridge the gap with a private
// record type that mirrors every field verbatim.
// ---------------------------------------------------------------------------

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
    pub recovery_cooldown_until: Option<String>,
}

pub(crate) fn encode_passkey(cred: &StoredPasskey) -> StorageResult<Vec<u8>> {
    let row = PasskeyRow {
        credential_id_hex: hex_bytes(&cred.credential_id),
        user_id: cred.user_id.0.to_string(),
        passkey: cred.passkey.clone(),
        name: cred.name.clone(),
        created_at: fmt_ts(cred.created_at),
        last_used_at: cred.last_used_at.map(fmt_ts),
        aaguid: cred.aaguid.map(|u| u.to_string()),
        transports: cred.transports.clone(),
        backup_eligible: cred.backup_eligible,
        backup_state: cred.backup_state,
        recovery_cooldown_until: cred.recovery_cooldown_until.map(fmt_ts),
    };
    serde_json::to_vec(&row).map_err(err)
}

pub(crate) fn decode_passkey(bytes: &[u8]) -> StorageResult<StoredPasskey> {
    let row: PasskeyRow = serde_json::from_slice(bytes).map_err(err)?;
    let credential_id = decode_hex(&row.credential_id_hex)?;
    Ok(StoredPasskey {
        credential_id,
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
        recovery_cooldown_until: row
            .recovery_cooldown_until
            .as_deref()
            .map(parse_ts)
            .transpose()?,
    })
}

pub(crate) fn decode_passkey_summary(bytes: &[u8]) -> StorageResult<PasskeySummary> {
    let row: PasskeyRow = serde_json::from_slice(bytes).map_err(err)?;
    let credential_id = decode_hex(&row.credential_id_hex)?;
    Ok(PasskeySummary {
        credential_id,
        user_id: UserId(Uuid::parse_str(&row.user_id).map_err(err)?),
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
        recovery_cooldown_until: row
            .recovery_cooldown_until
            .as_deref()
            .map(parse_ts)
            .transpose()?,
    })
}

fn decode_hex(s: &str) -> StorageResult<Vec<u8>> {
    if s.len() % 2 != 0 {
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

// ---------------------------------------------------------------------------
// RedbHandle
// ---------------------------------------------------------------------------

/// Shared handle over the [`Database`], cheaply cloned across store instances.
///
/// Each clone shares the same underlying `Arc<Database>` so all five stores
/// in an `all_stores()` composite share one database file.
#[derive(Clone)]
pub(crate) struct RedbHandle {
    db: Arc<Database>,
}

impl RedbHandle {
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Clone the inner `Arc<Database>`, suitable for moving into a
    /// `spawn_blocking` closure.
    pub(crate) fn db(&self) -> Arc<Database> {
        self.db.clone()
    }
}

// ---------------------------------------------------------------------------
// Table provisioning
// ---------------------------------------------------------------------------

/// Ensure every table exists by opening (thus creating) each one in a single
/// write transaction. Safe to call on every boot — already-existing tables are
/// a no-op.
pub(crate) fn ensure_tables(db: &Database) -> Result<(), redb::Error> {
    let wtxn = db.begin_write()?;
    wtxn.open_table(USERS)?;
    wtxn.open_table(EMAIL_GUARD)?;
    wtxn.open_table(SESSIONS)?;
    wtxn.open_table(SESSION_HASH_IDX)?;
    wtxn.open_table(USER_SESSIONS_IDX)?;
    wtxn.open_table(VTOKENS)?;
    wtxn.open_table(USER_VTOKENS_IDX)?;
    wtxn.open_table(PASSKEY_CREDS)?;
    wtxn.open_table(USER_CREDS_IDX)?;
    wtxn.open_table(PKREGS)?;
    wtxn.open_table(USER_PKREGS_IDX)?;
    wtxn.open_table(PKAUTHS)?;
    wtxn.commit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

/// Wrap any concrete backend error as an opaque [`StorageError`].
pub(crate) fn err<E>(e: E) -> StorageError
where
    E: std::error::Error + Send + Sync + 'static,
{
    StorageError::new(e)
}
