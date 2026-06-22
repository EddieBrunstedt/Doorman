//! Encode/decode between doorman's domain types and MongoDB BSON documents.
//!
//! ## Document layout
//!
//! Every collection uses a string `_id` built from the record's natural key:
//!
//! | Collection              | `_id` value                     |
//! | ----------------------- | ------------------------------- |
//! | `users`                 | UUID string (`user.id`)         |
//! | `sessions`              | UUID string (`session.id`)      |
//! | `verification_tokens`   | `{purpose}#{token_hash hex}`    |
//! | `passkey_credentials`   | credential-id hex               |
//! | `passkey_registrations` | UUID string (challenge id)      |
//! | `passkey_authentications` | UUID string (challenge id)    |
//!
//! Timestamps are stored as BSON `Date` (millisecond precision). A separate
//! `ttl` field mirrors `expires_at` but is **only written when `expires_at` is
//! in the wall-clock future**: this gates the TTL index so that past-dated test
//! fixtures are not swept by the ~60 s TTL monitor during conformance runs.
//!
//! Binary fields (token hashes, credential ids, passkey blobs, ceremony state)
//! are stored as BSON `BinData` with subtype `Generic`.

use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    PasskeyChallengeId, PasskeySummary, Session, SessionId, StoredPasskey,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, User, UserId,
    VerificationPurpose, VerificationToken,
};
use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::{Binary, Bson, DateTime as BsonDateTime, Document, doc};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

fn missing(key: &str) -> StorageError {
    StorageError::msg(format!("document is missing field `{key}`"))
}

fn wrong_type(key: &str, want: &str) -> StorageError {
    StorageError::msg(format!("field `{key}` is not a {want}"))
}

/// Convert a `chrono::DateTime<Utc>` to a BSON `Date` (millisecond precision).
pub(crate) fn to_bson_dt(dt: DateTime<Utc>) -> BsonDateTime {
    BsonDateTime::from_millis(dt.timestamp_millis())
}

/// Convert a BSON `Date` back to `chrono::DateTime<Utc>`.
pub(crate) fn from_bson_dt(dt: BsonDateTime) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(dt.timestamp_millis())
        .expect("bson DateTime millis always fit in chrono")
}

/// The TTL field value: `Some(date)` when `expires_at` is in the future,
/// `None` otherwise. Only future-dated records receive a TTL index entry,
/// so past-dated conformance fixtures are not swept before the test asserts on them.
pub(crate) fn ttl_bson(expires_at: DateTime<Utc>) -> Option<BsonDateTime> {
    (expires_at > Utc::now()).then(|| to_bson_dt(expires_at))
}

fn to_binary(bytes: Vec<u8>) -> Binary {
    Binary {
        subtype: BinarySubtype::Generic,
        bytes,
    }
}

pub(crate) use doorman_core::encoding::{
    account_status_from_parts, account_status_to_str, hex, purpose_from_str,
    purpose_to_str as purpose_str,
};

// ---------------------------------------------------------------------------
// Document extractors
// ---------------------------------------------------------------------------

pub(crate) fn get_str(doc: &Document, key: &str) -> StorageResult<String> {
    match doc.get(key) {
        Some(Bson::String(s)) => Ok(s.clone()),
        Some(_) => Err(wrong_type(key, "string")),
        None => Err(missing(key)),
    }
}

pub(crate) fn get_opt_str(doc: &Document, key: &str) -> StorageResult<Option<String>> {
    match doc.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(wrong_type(key, "string")),
    }
}

pub(crate) fn get_dt(doc: &Document, key: &str) -> StorageResult<DateTime<Utc>> {
    match doc.get(key) {
        Some(Bson::DateTime(dt)) => Ok(from_bson_dt(*dt)),
        Some(_) => Err(wrong_type(key, "DateTime")),
        None => Err(missing(key)),
    }
}

pub(crate) fn get_opt_dt(doc: &Document, key: &str) -> StorageResult<Option<DateTime<Utc>>> {
    match doc.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::DateTime(dt)) => Ok(Some(from_bson_dt(*dt))),
        Some(_) => Err(wrong_type(key, "DateTime")),
    }
}

pub(crate) fn get_bytes(doc: &Document, key: &str) -> StorageResult<Vec<u8>> {
    match doc.get(key) {
        Some(Bson::Binary(b)) => Ok(b.bytes.clone()),
        Some(_) => Err(wrong_type(key, "Binary")),
        None => Err(missing(key)),
    }
}

pub(crate) fn get_uuid(doc: &Document, key: &str) -> StorageResult<Uuid> {
    Uuid::parse_str(&get_str(doc, key)?)
        .map_err(|e| StorageError::msg(format!("invalid UUID in field `{key}`: {e}")))
}

pub(crate) fn get_opt_uuid(doc: &Document, key: &str) -> StorageResult<Option<Uuid>> {
    match get_opt_str(doc, key)? {
        Some(s) => Uuid::parse_str(&s)
            .map(Some)
            .map_err(|e| StorageError::msg(format!("invalid UUID in field `{key}`: {e}"))),
        None => Ok(None),
    }
}

pub(crate) fn get_token_hash(doc: &Document, key: &str) -> StorageResult<TokenHash> {
    let bytes = get_bytes(doc, key)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StorageError::msg(format!("field `{key}` is not a 32-byte token hash")))?;
    Ok(TokenHash(arr))
}

pub(crate) fn get_str_array(doc: &Document, key: &str) -> StorageResult<Vec<String>> {
    match doc.get(key) {
        None => Ok(Vec::new()),
        Some(Bson::Array(arr)) => arr
            .iter()
            .map(|v| match v {
                Bson::String(s) => Ok(s.clone()),
                _ => Err(wrong_type(key, "array of strings")),
            })
            .collect(),
        Some(_) => Err(wrong_type(key, "array")),
    }
}

pub(crate) fn get_bool(doc: &Document, key: &str) -> StorageResult<bool> {
    match doc.get(key) {
        Some(Bson::Boolean(b)) => Ok(*b),
        Some(_) => Err(wrong_type(key, "bool")),
        None => Err(missing(key)),
    }
}

// ---------------------------------------------------------------------------
// Document ID builders
// ---------------------------------------------------------------------------

pub(crate) fn user_id_str(id: UserId) -> String {
    id.0.to_string()
}

pub(crate) fn session_id_str(id: SessionId) -> String {
    id.0.to_string()
}

/// Compound document id for a verification token, scoped by purpose so a hash
/// can never be redeemed under the wrong flow.
pub(crate) fn vtoken_id(purpose: VerificationPurpose, hash: &TokenHash) -> String {
    format!("{}#{}", purpose_str(purpose), hex(&hash.0))
}

pub(crate) fn passkey_id(credential_id: &[u8]) -> String {
    hex(credential_id)
}

pub(crate) fn challenge_id_str(id: PasskeyChallengeId) -> String {
    id.0.to_string()
}

// ---------------------------------------------------------------------------
// Document builders
// ---------------------------------------------------------------------------

pub(crate) fn user_to_doc(user: &User) -> Document {
    let mut doc = doc! {
        "_id": user_id_str(user.id),
        "created_at": to_bson_dt(user.created_at),
        "updated_at": to_bson_dt(user.updated_at),
    };
    if let Some(email) = &user.email {
        doc.insert("email", email.clone());
    }
    if let Some(ts) = user.email_verified_at {
        doc.insert("email_verified_at", to_bson_dt(ts));
    }
    doc.insert("status", account_status_to_str(&user.status));
    if let Some(ts) = user.status.disabled_at() {
        doc.insert("disabled_at", to_bson_dt(ts));
    }
    doc
}

pub(crate) fn user_from_doc(doc: &Document) -> StorageResult<User> {
    let status =
        account_status_from_parts(&get_str(doc, "status")?, get_opt_dt(doc, "disabled_at")?)?;
    Ok(User {
        id: UserId(get_uuid(doc, "_id")?),
        email: get_opt_str(doc, "email")?,
        email_verified_at: get_opt_dt(doc, "email_verified_at")?,
        status,
        created_at: get_dt(doc, "created_at")?,
        updated_at: get_dt(doc, "updated_at")?,
    })
}

pub(crate) fn session_to_doc(session: &Session) -> Document {
    let token_hash_bin = to_binary(session.token_hash.0.to_vec());
    let mut doc = doc! {
        "_id": session_id_str(session.id),
        "user_id": session.user_id.0.to_string(),
        "token_hash": token_hash_bin,
        "created_at": to_bson_dt(session.created_at),
        "last_used_at": to_bson_dt(session.last_used_at),
        "expires_at": to_bson_dt(session.expires_at),
    };
    if let Some(ip) = &session.ip {
        doc.insert("ip", ip.clone());
    }
    if let Some(ua) = &session.user_agent {
        doc.insert("user_agent", ua.clone());
    }
    if let Some(ts) = session.recovery_cooldown_until {
        doc.insert("recovery_cooldown_until", to_bson_dt(ts));
    }
    if let Some(ttl) = ttl_bson(session.expires_at) {
        doc.insert("ttl", ttl);
    }
    doc
}

pub(crate) fn session_from_doc(doc: &Document) -> StorageResult<Session> {
    Ok(Session {
        id: SessionId(get_uuid(doc, "_id")?),
        user_id: UserId(get_uuid(doc, "user_id")?),
        token_hash: get_token_hash(doc, "token_hash")?,
        created_at: get_dt(doc, "created_at")?,
        last_used_at: get_dt(doc, "last_used_at")?,
        expires_at: get_dt(doc, "expires_at")?,
        ip: get_opt_str(doc, "ip")?,
        user_agent: get_opt_str(doc, "user_agent")?,
        recovery_cooldown_until: get_opt_dt(doc, "recovery_cooldown_until")?,
    })
}

pub(crate) fn vtoken_to_doc(token: &VerificationToken) -> Document {
    let token_hash_bin = to_binary(token.token_hash.0.to_vec());
    let mut doc = doc! {
        "_id": vtoken_id(token.purpose, &token.token_hash),
        "token_hash": token_hash_bin,
        "purpose": purpose_str(token.purpose),
        "user_id": token.user_id.0.to_string(),
        "created_at": to_bson_dt(token.created_at),
        "expires_at": to_bson_dt(token.expires_at),
    };
    if let Some(email) = &token.new_email {
        doc.insert("new_email", email.clone());
    }
    if let Some(ttl) = ttl_bson(token.expires_at) {
        doc.insert("ttl", ttl);
    }
    doc
}

pub(crate) fn vtoken_from_doc(doc: &Document) -> StorageResult<VerificationToken> {
    Ok(VerificationToken {
        token_hash: get_token_hash(doc, "token_hash")?,
        user_id: UserId(get_uuid(doc, "user_id")?),
        purpose: purpose_from_str(&get_str(doc, "purpose")?)?,
        new_email: get_opt_str(doc, "new_email")?,
        created_at: get_dt(doc, "created_at")?,
        expires_at: get_dt(doc, "expires_at")?,
    })
}

pub(crate) fn passkey_to_doc(cred: &StoredPasskey) -> Document {
    let passkey_bin = to_binary(cred.passkey.clone());
    let credential_id_bin = to_binary(cred.credential_id.clone());
    let transports: Vec<Bson> = cred
        .transports
        .iter()
        .map(|t| Bson::String(t.clone()))
        .collect();
    let mut doc = doc! {
        "_id": passkey_id(&cred.credential_id),
        "credential_id": credential_id_bin,
        "user_id": cred.user_id.0.to_string(),
        "passkey": passkey_bin,
        "transports": transports,
        "backup_eligible": cred.backup_eligible,
        "backup_state": cred.backup_state,
        "created_at": to_bson_dt(cred.created_at),
    };
    if let Some(name) = &cred.name {
        doc.insert("name", name.clone());
    }
    if let Some(ts) = cred.last_used_at {
        doc.insert("last_used_at", to_bson_dt(ts));
    }
    if let Some(aaguid) = cred.aaguid {
        doc.insert("aaguid", aaguid.to_string());
    }
    if let Some(ts) = cred.recovery_cooldown_until {
        doc.insert("recovery_cooldown_until", to_bson_dt(ts));
    }
    doc
}

/// Read every passkey metadata field — everything except the opaque `passkey`
/// blob — into a [`PasskeySummary`]. Both decoders share this single field
/// assembly; the summary path returns it directly and the full decoder adds the
/// blob, so neither re-lists the metadata fields.
fn passkey_meta_from_doc(doc: &Document) -> StorageResult<PasskeySummary> {
    Ok(PasskeySummary {
        credential_id: get_bytes(doc, "credential_id")?,
        user_id: UserId(get_uuid(doc, "user_id")?),
        name: get_opt_str(doc, "name")?,
        created_at: get_dt(doc, "created_at")?,
        last_used_at: get_opt_dt(doc, "last_used_at")?,
        aaguid: get_opt_uuid(doc, "aaguid")?,
        transports: get_str_array(doc, "transports")?,
        backup_eligible: get_bool(doc, "backup_eligible")?,
        backup_state: get_bool(doc, "backup_state")?,
        recovery_cooldown_until: get_opt_dt(doc, "recovery_cooldown_until")?,
    })
}

pub(crate) fn passkey_from_doc(doc: &Document) -> StorageResult<StoredPasskey> {
    let meta = passkey_meta_from_doc(doc)?;
    Ok(StoredPasskey {
        credential_id: meta.credential_id,
        user_id: meta.user_id,
        passkey: get_bytes(doc, "passkey")?,
        name: meta.name,
        created_at: meta.created_at,
        last_used_at: meta.last_used_at,
        aaguid: meta.aaguid,
        transports: meta.transports,
        backup_eligible: meta.backup_eligible,
        backup_state: meta.backup_state,
        recovery_cooldown_until: meta.recovery_cooldown_until,
    })
}

/// Project a passkey document to its metadata-only summary without reading the
/// `passkey` blob. The `passkey` field is intentionally not accessed here.
pub(crate) fn passkey_summary_from_doc(doc: &Document) -> StorageResult<PasskeySummary> {
    passkey_meta_from_doc(doc)
}

pub(crate) fn pkreg_to_doc(value: &StoredPasskeyRegistration) -> Document {
    let state_bin = to_binary(value.state.clone());
    let mut doc = doc! {
        "_id": challenge_id_str(value.id),
        "user_id": value.user_id.0.to_string(),
        "state": state_bin,
        "created_at": to_bson_dt(value.created_at),
        "expires_at": to_bson_dt(value.expires_at),
    };
    if let Some(ts) = value.recovery_cooldown_until {
        doc.insert("recovery_cooldown_until", to_bson_dt(ts));
    }
    if let Some(ttl) = ttl_bson(value.expires_at) {
        doc.insert("ttl", ttl);
    }
    doc
}

pub(crate) fn pkreg_from_doc(doc: &Document) -> StorageResult<StoredPasskeyRegistration> {
    Ok(StoredPasskeyRegistration {
        id: PasskeyChallengeId(get_uuid(doc, "_id")?),
        user_id: UserId(get_uuid(doc, "user_id")?),
        state: get_bytes(doc, "state")?,
        created_at: get_dt(doc, "created_at")?,
        expires_at: get_dt(doc, "expires_at")?,
        recovery_cooldown_until: get_opt_dt(doc, "recovery_cooldown_until")?,
    })
}

pub(crate) fn pkauth_to_doc(value: &StoredPasskeyAuthentication) -> Document {
    let state_bin = to_binary(value.state.clone());
    let mut doc = doc! {
        "_id": challenge_id_str(value.id),
        "state": state_bin,
        "created_at": to_bson_dt(value.created_at),
        "expires_at": to_bson_dt(value.expires_at),
    };
    if let Some(ttl) = ttl_bson(value.expires_at) {
        doc.insert("ttl", ttl);
    }
    doc
}

pub(crate) fn pkauth_from_doc(doc: &Document) -> StorageResult<StoredPasskeyAuthentication> {
    Ok(StoredPasskeyAuthentication {
        id: PasskeyChallengeId(get_uuid(doc, "_id")?),
        state: get_bytes(doc, "state")?,
        created_at: get_dt(doc, "created_at")?,
        expires_at: get_dt(doc, "expires_at")?,
    })
}
