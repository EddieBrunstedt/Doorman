use std::borrow::Cow;

use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::TokenHash;
use uuid::Uuid;

pub(crate) fn storage_err(e: sqlx::Error) -> StorageError {
    match e.as_database_error() {
        Some(db) if db.is_unique_violation() => StorageError::conflict(e.to_string()),
        _ => StorageError::msg(e.to_string()),
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn ph_sqlite(sql: &'static str) -> Cow<'static, str> {
    Cow::Borrowed(sql)
}

#[cfg(feature = "mysql")]
pub(crate) fn ph_mysql(sql: &'static str) -> Cow<'static, str> {
    Cow::Borrowed(sql)
}

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

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn ts_passthrough<T>(t: T) -> T {
    t
}

#[cfg(feature = "mysql")]
pub(crate) fn ts_mysql<T: MysqlDatetime>(t: T) -> T::Bind {
    t.into_datetime()
}

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
