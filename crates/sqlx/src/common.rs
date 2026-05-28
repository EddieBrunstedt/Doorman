//! Helpers shared between the SQLite and Postgres adapters: type
//! conversions for stored values and a uniform error mapper.

use bauth_core::error::{StorageError, StorageResult};
use bauth_core::storage::{TokenHash, VerificationPurpose};
use uuid::Uuid;

pub(crate) fn storage<E: std::fmt::Display>(e: E) -> StorageError {
    StorageError::msg(e.to_string())
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
    }
}

pub(crate) fn purpose_from_str(s: &str) -> StorageResult<VerificationPurpose> {
    match s {
        "signup" => Ok(VerificationPurpose::Signup),
        "recovery" => Ok(VerificationPurpose::Recovery),
        other => Err(StorageError::msg(format!(
            "unknown verification purpose `{other}` in database"
        ))),
    }
}
