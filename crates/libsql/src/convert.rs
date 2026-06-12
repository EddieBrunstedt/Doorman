//! Value conversions between doorman's domain types and libSQL's column values.
//!
//! Two directions: `bind_*` helpers turn a domain value into a [`libsql::Value`]
//! for a query parameter, and `col_*` helpers read a typed column back out of a
//! [`libsql::Row`] by position. Timestamps cross the boundary as fixed-width
//! RFC3339 TEXT (see [`bind_ts`]); UUIDs and token hashes as BLOB; the
//! verification purpose and passkey transport list as TEXT, matching the
//! doorman-sqlx SQLite encoding.

use chrono::{DateTime, SecondsFormat, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{TokenHash, VerificationPurpose};
use libsql::Value;
use uuid::Uuid;

/// Map any displayable driver/error into a [`StorageError`].
pub(crate) fn err<E: std::fmt::Display>(e: E) -> StorageError {
    StorageError::msg(e.to_string())
}

// ---------------------------------------------------------------------------
// bind: domain value -> libsql::Value (query parameter)
// ---------------------------------------------------------------------------

/// Bind a UUID as a 16-byte BLOB.
pub(crate) fn bind_uuid(u: Uuid) -> Value {
    Value::Blob(u.as_bytes().to_vec())
}

/// Bind a token hash as a 32-byte BLOB.
pub(crate) fn bind_hash(h: &TokenHash) -> Value {
    Value::Blob(h.0.to_vec())
}

/// Bind an owned byte string as a BLOB.
pub(crate) fn bind_blob(b: Vec<u8>) -> Value {
    Value::Blob(b)
}

/// Bind a byte slice as a BLOB.
pub(crate) fn bind_bytes(b: &[u8]) -> Value {
    Value::Blob(b.to_vec())
}

/// Bind a string as TEXT.
pub(crate) fn bind_text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// Bind an optional string as TEXT or NULL.
pub(crate) fn bind_opt_text(s: Option<String>) -> Value {
    match s {
        Some(s) => Value::Text(s),
        None => Value::Null,
    }
}

/// Bind a boolean as INTEGER `0`/`1`.
pub(crate) fn bind_bool(b: bool) -> Value {
    Value::Integer(b as i64)
}

/// Render a timestamp for its TEXT column.
///
/// Fixed-width RFC3339 in UTC with a `Z` suffix and nanosecond precision
/// (`2026-01-01T00:00:00.000000000Z`). The fixed layout is deliberate: SQLite
/// compares TEXT lexicographically, and this format orders lexicographically
/// exactly as it orders in time, so the `expires_at` range scans are correct
/// without a numeric column.
pub(crate) fn bind_ts(t: DateTime<Utc>) -> Value {
    Value::Text(t.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

/// Bind an optional timestamp as TEXT or NULL.
pub(crate) fn bind_opt_ts(t: Option<DateTime<Utc>>) -> Value {
    match t {
        Some(t) => bind_ts(t),
        None => Value::Null,
    }
}

/// Encode a verification purpose as its stored TEXT token.
pub(crate) fn purpose_to_str(p: VerificationPurpose) -> &'static str {
    match p {
        VerificationPurpose::Signup => "signup",
        VerificationPurpose::Recovery => "recovery",
        VerificationPurpose::EmailChange => "email_change",
    }
}

/// Decode a stored verification-purpose TEXT token.
pub(crate) fn purpose_from_str(s: &str) -> StorageResult<VerificationPurpose> {
    match s {
        "signup" => Ok(VerificationPurpose::Signup),
        "recovery" => Ok(VerificationPurpose::Recovery),
        "email_change" => Ok(VerificationPurpose::EmailChange),
        other => Err(StorageError::msg(format!(
            "unknown verification purpose `{other}` in database"
        ))),
    }
}

/// Flatten the passkey transport hints into one comma-separated TEXT value.
/// Transport tokens never contain commas, so the join is unambiguous; an empty
/// slice stores `""`.
pub(crate) fn transports_to_str(transports: &[String]) -> String {
    transports.join(",")
}

/// Split a comma-separated transports column back into the list, dropping empty
/// segments so a stored `""` round-trips to an empty `Vec`.
pub(crate) fn transports_from_str(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|seg| !seg.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Render an optional AAGUID for its (nullable) TEXT column.
pub(crate) fn bind_aaguid(aaguid: Option<Uuid>) -> Value {
    match aaguid {
        Some(u) => Value::Text(u.to_string()),
        None => Value::Null,
    }
}

// ---------------------------------------------------------------------------
// col: libsql::Row -> typed value (by column position)
// ---------------------------------------------------------------------------

/// Read a BLOB column.
pub(crate) fn col_blob(row: &libsql::Row, idx: i32) -> StorageResult<Vec<u8>> {
    match row.get_value(idx).map_err(err)? {
        Value::Blob(b) => Ok(b),
        other => Err(StorageError::msg(format!(
            "expected BLOB at column {idx}, found {other:?}"
        ))),
    }
}

/// Read a non-null TEXT column.
pub(crate) fn col_text(row: &libsql::Row, idx: i32) -> StorageResult<String> {
    match row.get_value(idx).map_err(err)? {
        Value::Text(s) => Ok(s),
        other => Err(StorageError::msg(format!(
            "expected TEXT at column {idx}, found {other:?}"
        ))),
    }
}

/// Read a nullable TEXT column.
pub(crate) fn col_opt_text(row: &libsql::Row, idx: i32) -> StorageResult<Option<String>> {
    match row.get_value(idx).map_err(err)? {
        Value::Text(s) => Ok(Some(s)),
        Value::Null => Ok(None),
        other => Err(StorageError::msg(format!(
            "expected TEXT or NULL at column {idx}, found {other:?}"
        ))),
    }
}

/// Read an INTEGER column.
pub(crate) fn col_int(row: &libsql::Row, idx: i32) -> StorageResult<i64> {
    match row.get_value(idx).map_err(err)? {
        Value::Integer(i) => Ok(i),
        other => Err(StorageError::msg(format!(
            "expected INTEGER at column {idx}, found {other:?}"
        ))),
    }
}

/// Read a boolean stored as INTEGER (`0` is false, anything else true).
pub(crate) fn col_bool(row: &libsql::Row, idx: i32) -> StorageResult<bool> {
    Ok(col_int(row, idx)? != 0)
}

/// Read a UUID from a 16-byte BLOB column.
pub(crate) fn col_uuid(row: &libsql::Row, idx: i32) -> StorageResult<Uuid> {
    Uuid::from_slice(&col_blob(row, idx)?).map_err(err)
}

/// Read a token hash from a 32-byte BLOB column.
pub(crate) fn col_hash(row: &libsql::Row, idx: i32) -> StorageResult<TokenHash> {
    let bytes = col_blob(row, idx)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| StorageError::msg("token_hash column was not 32 bytes"))?;
    Ok(TokenHash(arr))
}

/// Read a non-null timestamp from its RFC3339 TEXT column.
pub(crate) fn col_ts(row: &libsql::Row, idx: i32) -> StorageResult<DateTime<Utc>> {
    ts_from_str(&col_text(row, idx)?)
}

/// Read a nullable timestamp from its RFC3339 TEXT column.
pub(crate) fn col_opt_ts(row: &libsql::Row, idx: i32) -> StorageResult<Option<DateTime<Utc>>> {
    match col_opt_text(row, idx)? {
        Some(s) => Ok(Some(ts_from_str(&s)?)),
        None => Ok(None),
    }
}

/// Read an optional AAGUID from its nullable TEXT column.
pub(crate) fn col_aaguid(row: &libsql::Row, idx: i32) -> StorageResult<Option<Uuid>> {
    match col_opt_text(row, idx)? {
        Some(s) => Ok(Some(Uuid::parse_str(&s).map_err(err)?)),
        None => Ok(None),
    }
}

fn ts_from_str(s: &str) -> StorageResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(err)
}
