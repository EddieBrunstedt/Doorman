//! Helpers shared between the SQLite and Postgres adapters: type
//! conversions for stored values and a uniform error mapper.

use std::borrow::Cow;

use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{TokenHash, VerificationPurpose};
use uuid::Uuid;

pub(crate) fn storage<E: std::fmt::Display>(e: E) -> StorageError {
    StorageError::msg(e.to_string())
}

/// Placeholder rewriter for the SQLite dialect: a no-op. The shared store
/// bodies in [`crate::stores`] write every placeholder as `?`, which is
/// SQLite's native syntax. The bodies only ever pass `&'static` string
/// literals, so the borrowed result threads straight into sqlx's
/// `SqlSafeStr` (`'static`-bound) path without a copy.
#[cfg(feature = "sqlite")]
pub(crate) fn ph_sqlite(sql: &'static str) -> Cow<'static, str> {
    Cow::Borrowed(sql)
}

/// Placeholder rewriter for the MySQL/MariaDB dialect: a no-op, like
/// [`ph_sqlite`]. MySQL's positional placeholder is `?`, which is exactly what
/// the shared store bodies in [`crate::stores`] already write, so the borrowed
/// `&'static str` threads straight through without a copy.
#[cfg(feature = "mysql")]
pub(crate) fn ph_mysql(sql: &'static str) -> Cow<'static, str> {
    Cow::Borrowed(sql)
}

/// Placeholder rewriter for the Postgres dialect: rewrites each positional
/// `?` into the `$1`, `$2`, … form Postgres expects, in order. No SQL the
/// shared store bodies emit contains a literal `?` outside a placeholder, so
/// the substitution is unambiguous.
#[cfg(feature = "postgres")]
pub(crate) fn ph_postgres(sql: &'static str) -> Cow<'static, str> {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n: u32 = 0;
    for ch in sql.chars() {
        if ch == '?' {
            n += 1;
            out.push('$');
            out.push_str(&n.to_string());
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}

pub(crate) fn token_hash_bytes(h: &TokenHash) -> &[u8] {
    &h.0
}

pub(crate) fn token_hash_from_bytes(b: &[u8]) -> StorageResult<TokenHash> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| StorageError::msg("token_hash row was not 32 bytes"))?;
    Ok(TokenHash(arr))
}

pub(crate) fn uuid_to_bytes(u: Uuid) -> Vec<u8> {
    u.as_bytes().to_vec()
}

pub(crate) fn uuid_from_row(b: Vec<u8>) -> StorageResult<Uuid> {
    Uuid::from_slice(&b).map_err(storage)
}

pub(crate) fn purpose_to_str(p: VerificationPurpose) -> &'static str {
    match p {
        VerificationPurpose::Signup => "signup",
        VerificationPurpose::Recovery => "recovery",
        VerificationPurpose::EmailChange => "email_change",
    }
}

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

/// Flatten the passkey transport hints into a single comma-separated column
/// value. Transport tokens (`usb`, `nfc`, `ble`, `internal`, `hybrid`) never
/// contain commas, so the join is unambiguous; an empty slice stores `""`.
pub(crate) fn transports_to_str(transports: &[String]) -> String {
    transports.join(",")
}

/// Split a comma-separated transports column back into the list. Empty
/// segments are dropped so a stored `""` round-trips to an empty `Vec`.
pub(crate) fn transports_from_str(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|seg| !seg.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Render an optional AAGUID for its (nullable) TEXT column.
pub(crate) fn aaguid_to_str(aaguid: Option<Uuid>) -> Option<String> {
    aaguid.map(|u| u.to_string())
}

/// Parse a nullable AAGUID TEXT column back into a [`Uuid`].
pub(crate) fn aaguid_from_str(s: Option<String>) -> StorageResult<Option<Uuid>> {
    s.map(|raw| Uuid::parse_str(&raw).map_err(storage))
        .transpose()
}
