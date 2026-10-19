use chrono::{DateTime, Utc};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::storage::{
    EmailLink, PasskeyChallengeId, Session, SessionId, StoredPasskey, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, TokenHash, User, UserId,
};
use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::{Binary, Bson, DateTime as BsonDateTime, Document, doc};
use uuid::Uuid;

fn missing(key: &str) -> StorageError {
    StorageError::msg(format!("document is missing field `{key}`"))
}

fn wrong_type(key: &str, want: &str) -> StorageError {
    StorageError::msg(format!("field `{key}` is not a {want}"))
}

pub(crate) fn to_bson_dt(dt: DateTime<Utc>) -> BsonDateTime {
    BsonDateTime::from_millis(dt.timestamp_millis())
}

fn from_bson_dt(key: &str, dt: BsonDateTime) -> StorageResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(dt.timestamp_millis())
        .ok_or_else(|| StorageError::msg(format!("field `{key}` is out of chrono's date range")))
}

fn to_binary(bytes: Vec<u8>) -> Binary {
    Binary {
        subtype: BinarySubtype::Generic,
        bytes,
    }
}

pub(crate) use doorman_core::encoding::{
    authentication_purpose_from_str, authentication_purpose_to_str, hex, purpose_from_str,
    purpose_to_str as purpose_str, registration_purpose_from_str, registration_purpose_to_str,
    user_status_from_parts, user_status_to_str,
};

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
        Some(Bson::DateTime(dt)) => from_bson_dt(key, *dt),
        Some(_) => Err(wrong_type(key, "DateTime")),
        None => Err(missing(key)),
    }
}

pub(crate) fn get_opt_dt(doc: &Document, key: &str) -> StorageResult<Option<DateTime<Utc>>> {
    match doc.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::DateTime(dt)) => from_bson_dt(key, *dt).map(Some),
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

pub(crate) fn user_id_str(id: UserId) -> String {
    id.0.to_string()
}

pub(crate) fn session_id_str(id: SessionId) -> String {
    id.0.to_string()
}

// Keyed by owner, so storing a link replaces the user's previous link for that purpose.
pub(crate) fn email_link_id(link: &EmailLink) -> String {
    format!("{}:{}", link.user_id.0, purpose_str(link.purpose))
}

pub(crate) fn token_hash_bson(hash: &TokenHash) -> Binary {
    to_binary(hash.0.to_vec())
}

pub(crate) fn passkey_id(credential_id: &[u8]) -> String {
    hex(credential_id)
}

pub(crate) fn challenge_id_str(id: PasskeyChallengeId) -> String {
    id.0.to_string()
}

pub(crate) fn user_to_doc(user: &User) -> Document {
    let mut doc = doc! {
        "_id": user_id_str(user.id),
        "created_at": to_bson_dt(user.created_at),
        "updated_at": to_bson_dt(user.updated_at),
    };
    if let Some(email) = &user.email {
        doc.insert("email", email.clone());
    }
    if let Some(ts) = user.signed_up_at {
        doc.insert("signed_up_at", to_bson_dt(ts));
    }
    doc.insert("status", user_status_to_str(&user.status));
    if let Some(ts) = user.status.disabled_at() {
        doc.insert("disabled_at", to_bson_dt(ts));
    }
    doc
}

pub(crate) fn user_from_doc(doc: &Document) -> StorageResult<User> {
    let status = user_status_from_parts(&get_str(doc, "status")?, get_opt_dt(doc, "disabled_at")?)?;
    Ok(User {
        id: UserId(get_uuid(doc, "_id")?),
        email: get_opt_str(doc, "email")?,
        signed_up_at: get_opt_dt(doc, "signed_up_at")?,
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
    if let Some(ts) = session.recovery_cool_down_until {
        doc.insert("recovery_cool_down_until", to_bson_dt(ts));
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
        recovery_cool_down_until: get_opt_dt(doc, "recovery_cool_down_until")?,
    })
}

pub(crate) fn email_link_to_doc(token: &EmailLink) -> Document {
    let mut doc = doc! {
        "_id": email_link_id(token),
        "token_hash": token_hash_bson(&token.token_hash),
        "purpose": purpose_str(token.purpose),
        "user_id": token.user_id.0.to_string(),
        "created_at": to_bson_dt(token.created_at),
        "expires_at": to_bson_dt(token.expires_at),
    };
    if let Some(email) = &token.owner_email {
        doc.insert("owner_email", email.clone());
    }
    if let Some(email) = &token.new_email {
        doc.insert("new_email", email.clone());
    }
    doc
}

pub(crate) fn email_link_from_doc(doc: &Document) -> StorageResult<EmailLink> {
    Ok(EmailLink {
        token_hash: get_token_hash(doc, "token_hash")?,
        user_id: UserId(get_uuid(doc, "user_id")?),
        purpose: purpose_from_str(&get_str(doc, "purpose")?)?,
        owner_email: get_opt_str(doc, "owner_email")?,
        new_email: get_opt_str(doc, "new_email")?,
        created_at: get_dt(doc, "created_at")?,
        expires_at: get_dt(doc, "expires_at")?,
    })
}

pub(crate) fn passkey_to_doc(passkey: &StoredPasskey) -> Document {
    let passkey_bin = to_binary(passkey.passkey.clone());
    let credential_id_bin = to_binary(passkey.credential_id.clone());
    let transports: Vec<Bson> = passkey
        .transports
        .iter()
        .map(|t| Bson::String(t.clone()))
        .collect();
    let mut doc = doc! {
        "_id": passkey_id(&passkey.credential_id),
        "credential_id": credential_id_bin,
        "user_id": passkey.user_id.0.to_string(),
        "passkey": passkey_bin,
        "transports": transports,
        "backup_eligible": passkey.backup_eligible,
        "backup_state": passkey.backup_state,
        "created_at": to_bson_dt(passkey.created_at),
    };
    if let Some(name) = &passkey.name {
        doc.insert("name", name.clone());
    }
    if let Some(ts) = passkey.last_used_at {
        doc.insert("last_used_at", to_bson_dt(ts));
    }
    if let Some(aaguid) = passkey.aaguid {
        doc.insert("aaguid", aaguid.to_string());
    }
    if let Some(ts) = passkey.recovery_cool_down_until {
        doc.insert("recovery_cool_down_until", to_bson_dt(ts));
    }
    doc
}

pub(crate) fn passkey_from_doc(doc: &Document) -> StorageResult<StoredPasskey> {
    Ok(StoredPasskey {
        credential_id: get_bytes(doc, "credential_id")?,
        user_id: UserId(get_uuid(doc, "user_id")?),
        passkey: get_bytes(doc, "passkey")?,
        name: get_opt_str(doc, "name")?,
        created_at: get_dt(doc, "created_at")?,
        last_used_at: get_opt_dt(doc, "last_used_at")?,
        aaguid: get_opt_uuid(doc, "aaguid")?,
        transports: get_str_array(doc, "transports")?,
        backup_eligible: get_bool(doc, "backup_eligible")?,
        backup_state: get_bool(doc, "backup_state")?,
        recovery_cool_down_until: get_opt_dt(doc, "recovery_cool_down_until")?,
    })
}

pub(crate) fn pkreg_to_doc(value: &StoredPasskeyRegistration) -> Document {
    let state_bin = to_binary(value.state.clone());
    let mut doc = doc! {
        "_id": challenge_id_str(value.id),
        "purpose": registration_purpose_to_str(value.purpose),
        "user_id": value.user_id.0.to_string(),
        "state": state_bin,
        "created_at": to_bson_dt(value.created_at),
        "expires_at": to_bson_dt(value.expires_at),
    };
    if let Some(email) = &value.owner_email {
        doc.insert("owner_email", email.clone());
    }
    if let Some(ts) = value.recovery_cool_down_until {
        doc.insert("recovery_cool_down_until", to_bson_dt(ts));
    }
    doc
}

pub(crate) fn pkreg_from_doc(doc: &Document) -> StorageResult<StoredPasskeyRegistration> {
    Ok(StoredPasskeyRegistration {
        id: PasskeyChallengeId(get_uuid(doc, "_id")?),
        purpose: registration_purpose_from_str(&get_str(doc, "purpose")?)?,
        user_id: UserId(get_uuid(doc, "user_id")?),
        state: get_bytes(doc, "state")?,
        owner_email: get_opt_str(doc, "owner_email")?,
        created_at: get_dt(doc, "created_at")?,
        expires_at: get_dt(doc, "expires_at")?,
        recovery_cool_down_until: get_opt_dt(doc, "recovery_cool_down_until")?,
    })
}

pub(crate) fn pkauth_to_doc(value: &StoredPasskeyAuthentication) -> Document {
    let state_bin = to_binary(value.state.clone());
    doc! {
        "_id": challenge_id_str(value.id),
        "purpose": authentication_purpose_to_str(value.purpose),
        "state": state_bin,
        "created_at": to_bson_dt(value.created_at),
        "expires_at": to_bson_dt(value.expires_at),
    }
}

pub(crate) fn pkauth_from_doc(doc: &Document) -> StorageResult<StoredPasskeyAuthentication> {
    Ok(StoredPasskeyAuthentication {
        id: PasskeyChallengeId(get_uuid(doc, "_id")?),
        purpose: authentication_purpose_from_str(&get_str(doc, "purpose")?)?,
        state: get_bytes(doc, "state")?,
        created_at: get_dt(doc, "created_at")?,
        expires_at: get_dt(doc, "expires_at")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_outside_chronos_range_is_an_error() {
        let doc = doc! { "at": BsonDateTime::MAX };
        assert!(get_dt(&doc, "at").is_err());
        assert!(get_opt_dt(&doc, "at").is_err());
    }
}
