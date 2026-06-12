//! Partition handles, key builders, value encoding, and the shared database
//! handle the store implementations build on.
//!
//! ## Partition layout
//!
//! Every record type occupies a dedicated fjall keyspace (partition). Secondary
//! lookups and per-user collections use separate index partitions with compound
//! string keys, kept consistent with the primary partition inside every write
//! transaction that touches them.
//!
//! | Partition            | Key                                     | Value          |
//! | -------------------- | --------------------------------------- | -------------- |
//! | `users`              | user UUID                               | JSON           |
//! | `email_guard`        | email address                           | user UUID str  |
//! | `sessions`           | session UUID                            | JSON           |
//! | `session_hash_idx`   | token hash hex                          | session UUID   |
//! | `user_sessions_idx`  | `{user_id}\x00{session_id}`             | (empty)        |
//! | `vtokens`            | `{purpose}\x00{hash_hex}`               | JSON           |
//! | `user_vtokens_idx`   | `{user_id}\x00{purpose}\x00{hash_hex}`  | (empty)        |
//! | `passkey_creds`      | credential id hex                       | JSON           |
//! | `user_creds_idx`     | `{user_id}\x00{cred_id_hex}`            | (empty)        |
//! | `pkregs`             | challenge UUID                          | JSON           |
//! | `user_pkregs_idx`    | `{user_id}\x00{challenge_id}`           | (empty)        |
//! | `pkauths`            | challenge UUID                          | JSON           |
//!
//! ## Compound-key prefix scans
//!
//! The separator `\x00` (NUL byte, `SEP`) never appears in UUIDs, hex strings,
//! or purpose names (all printable ASCII). A prefix scan for all entries under
//! `"{user_id}\x00"` uses a half-open byte range
//! `[prefix_bytes, prefix_end_bytes(prefix))` where `prefix_end` replaces the
//! trailing `\x00` with `\x01`.

use std::fmt::Write as _;

use chrono::{DateTime, SecondsFormat, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeySummary, StoredPasskey, TokenHash, UserId, VerificationPurpose,
};
use fjall::{KeyspaceCreateOptions, SingleWriterTxDatabase, SingleWriterTxKeyspace};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
/// so the byte range `[prefix, prefix_end(prefix))` exactly covers every key
/// that starts with the prefix. The sub-key components (UUIDs, hex, purpose
/// names) only contain printable ASCII (`>= ' '`), so no key starting with
/// the prefix can equal or exceed `prefix_end`.
pub(crate) fn prefix_end(prefix: &str) -> String {
    debug_assert!(prefix.ends_with(SEP));
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

// ---------------------------------------------------------------------------
// FjallHandle
// ---------------------------------------------------------------------------

/// All partition handles for the fjall backend, cheaply cloned across stores.
///
/// `SingleWriterTxDatabase` and `SingleWriterTxKeyspace` are both `Clone` and
/// `Arc`-backed internally, so cloning this struct is cheap and all clones
/// share the same on-disk database.
#[derive(Clone)]
pub(crate) struct FjallHandle {
    pub db: SingleWriterTxDatabase,
    pub users: SingleWriterTxKeyspace,
    pub email_guard: SingleWriterTxKeyspace,
    pub sessions: SingleWriterTxKeyspace,
    pub session_hash_idx: SingleWriterTxKeyspace,
    pub user_sessions_idx: SingleWriterTxKeyspace,
    pub vtokens: SingleWriterTxKeyspace,
    pub user_vtokens_idx: SingleWriterTxKeyspace,
    pub passkey_creds: SingleWriterTxKeyspace,
    pub user_creds_idx: SingleWriterTxKeyspace,
    pub pkregs: SingleWriterTxKeyspace,
    pub user_pkregs_idx: SingleWriterTxKeyspace,
    pub pkauths: SingleWriterTxKeyspace,
}

// ---------------------------------------------------------------------------
// Partition provisioning
// ---------------------------------------------------------------------------

/// Open or create all required partitions in one call. Safe to call on every
/// boot — already-existing partitions are a no-op.
pub(crate) fn open_partitions(db: &SingleWriterTxDatabase) -> Result<FjallHandle, fjall::Error> {
    let opts = KeyspaceCreateOptions::default;
    Ok(FjallHandle {
        db: db.clone(),
        users: db.keyspace("users", opts)?,
        email_guard: db.keyspace("email_guard", opts)?,
        sessions: db.keyspace("sessions", opts)?,
        session_hash_idx: db.keyspace("session_hash_idx", opts)?,
        user_sessions_idx: db.keyspace("user_sessions_idx", opts)?,
        vtokens: db.keyspace("vtokens", opts)?,
        user_vtokens_idx: db.keyspace("user_vtokens_idx", opts)?,
        passkey_creds: db.keyspace("passkey_creds", opts)?,
        user_creds_idx: db.keyspace("user_creds_idx", opts)?,
        pkregs: db.keyspace("pkregs", opts)?,
        user_pkregs_idx: db.keyspace("user_pkregs_idx", opts)?,
        pkauths: db.keyspace("pkauths", opts)?,
    })
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
