//! Helpers shared between the SQLite, Postgres, and MySQL/MariaDB adapters:
//! placeholder rewriting, timestamp bind adapters, type conversions for stored
//! values, and a uniform error mapper.

use std::borrow::Cow;

use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::TokenHash;
use uuid::Uuid;

/// Map a driver error to a [`StorageError`], reporting a unique-constraint
/// violation as [`StorageErrorKind::Conflict`](doorman_core::error::StorageErrorKind::Conflict)
/// in every dialect.
pub(crate) fn storage_err(e: sqlx::Error) -> StorageError {
    match e.as_database_error() {
        Some(db) if db.is_unique_violation() => StorageError::conflict(e.to_string()),
        _ => StorageError::msg(e.to_string()),
    }
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

/// Timestamp bind adapter for the SQLite and Postgres dialects: identity.
/// Both store `DateTime<Utc>` directly — SQLite as a text/`TIMESTAMP` column,
/// Postgres as `TIMESTAMPTZ` — so the value binds unchanged. The MySQL adapter
/// uses [`ts_mysql`] instead; the shared store bodies route every timestamp
/// bind through whichever adapter their dialect supplies.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn ts_passthrough<T>(t: T) -> T {
    t
}

/// Timestamp bind adapter for the MySQL/MariaDB dialect: bind the naive UTC
/// datetime rather than the `DateTime<Utc>`.
///
/// sqlx tags `DateTime<Utc>` as MySQL `TIMESTAMP`. MariaDB then applies
/// `TIMESTAMP` range semantics to the incoming parameter — even when the target
/// column is `DATETIME` — and silently turns any value past the 2038-01-19
/// epoch ceiling into NULL, which a `NOT NULL` column then rejects (error
/// 1048). The conformance suite's year-2099 expiries trip exactly this; MySQL 8
/// happens to tolerate it, MariaDB does not. Binding the naive datetime instead
/// tags the parameter as `DATETIME`, so the full `DATETIME` range stores
/// faithfully. The session runs at UTC, so the naive wall-clock is correct.
#[cfg(feature = "mysql")]
pub(crate) fn ts_mysql<T: MysqlDatetime>(t: T) -> T::Bind {
    t.into_datetime()
}

/// Maps the timestamp types the stores bind (`DateTime<Utc>` and its `Option`)
/// to the naive-UTC counterparts [`ts_mysql`] hands to the driver.
#[cfg(feature = "mysql")]
pub(crate) trait MysqlDatetime {
    type Bind;
    fn into_datetime(self) -> Self::Bind;
}

#[cfg(feature = "mysql")]
impl MysqlDatetime for chrono::DateTime<chrono::Utc> {
    type Bind = chrono::NaiveDateTime;
    fn into_datetime(self) -> Self::Bind {
        self.naive_utc()
    }
}

#[cfg(feature = "mysql")]
impl MysqlDatetime for Option<chrono::DateTime<chrono::Utc>> {
    type Bind = Option<chrono::NaiveDateTime>;
    fn into_datetime(self) -> Self::Bind {
        self.map(|d| d.naive_utc())
    }
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
    Uuid::from_slice(&b).map_err(|e| StorageError::msg(e.to_string()))
}

pub(crate) use doorman_core::encoding::{
    aaguid_from_str, aaguid_to_str, authentication_purpose_from_str, authentication_purpose_to_str,
    purpose_from_str, purpose_to_str, transports_from_str, transports_to_str,
};
