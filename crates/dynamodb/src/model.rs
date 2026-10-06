use chrono::{DateTime, Utc};
use doorman_core::encoding::{
    account_status_from_parts, account_status_to_str, authentication_purpose_from_str,
    authentication_purpose_to_str, hex, purpose_from_str, purpose_to_str as purpose_str,
    registration_purpose_from_str, registration_purpose_to_str,
};
use doorman_core::error::StorageResult;
use doorman_core::storage::{
    PasskeyChallengeId, PasskeySummary, Session, SessionId, StoredPasskey,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, User, UserId,
    VerificationPurpose, VerificationToken,
};
use uuid::Uuid;

use crate::client::{self, GSI1PK, GSI2PK, Item};

pub(crate) const ENTITY_USER: &str = "user";
pub(crate) const ENTITY_EMAIL: &str = "email";
pub(crate) const ENTITY_SESSION: &str = "session";
pub(crate) const ENTITY_SESSION_INDEX: &str = "usess";
pub(crate) const ENTITY_VTOKEN: &str = "vtoken";
pub(crate) const ENTITY_PASSKEY: &str = "passkey";
pub(crate) const ENTITY_PKREG: &str = "pkreg";
pub(crate) const ENTITY_PKAUTH: &str = "pkauth";

pub(crate) fn user_pk(id: UserId) -> String {
    format!("user#{}", id.0)
}

pub(crate) fn email_pk(email: &str) -> String {
    format!("email#{email}")
}

pub(crate) fn session_pk(id: SessionId) -> String {
    session_pk_for(&id.0.to_string())
}

pub(crate) fn session_pk_for(id: &str) -> String {
    format!("session#{id}")
}

pub(crate) fn session_hash_key(hash: &TokenHash) -> String {
    format!("shash#{}", hex(&hash.0))
}

pub(crate) fn session_index_pk(user_id: UserId) -> String {
    format!("usess#{}", user_id.0)
}

pub(crate) const SESSION_IDS: &str = "session_ids";

pub(crate) fn vtoken_pk(purpose: VerificationPurpose, hash: &TokenHash) -> String {
    format!("vtoken#{}#{}", purpose_str(purpose), hex(&hash.0))
}

pub(crate) fn user_vtokens_key(user_id: UserId, purpose: VerificationPurpose) -> String {
    format!("uvtok#{}#{}", user_id.0, purpose_str(purpose))
}

pub(crate) fn passkey_pk(credential_id: &[u8]) -> String {
    format!("passkey#{}", hex(credential_id))
}

pub(crate) fn user_passkeys_key(user_id: UserId) -> String {
    format!("upk#{}", user_id.0)
}

pub(crate) fn pkreg_pk(id: PasskeyChallengeId) -> String {
    format!("pkreg#{}", id.0)
}

pub(crate) fn user_pkregs_key(user_id: UserId) -> String {
    format!("upkreg#{}", user_id.0)
}

pub(crate) fn pkauth_pk(id: PasskeyChallengeId) -> String {
    format!("pkauth#{}", id.0)
}

fn base(entity: &str, pk: String) -> Item {
    let mut item = Item::new();
    item.insert(client::PK.to_string(), client::s(pk));
    item.insert(client::ENTITY.to_string(), client::s(entity));
    item
}

fn put_ts(item: &mut Item, key: &str, value: DateTime<Utc>) {
    item.insert(key.to_string(), client::s(client::fmt_ts(value)));
}

fn put_opt_ts(item: &mut Item, key: &str, value: Option<DateTime<Utc>>) {
    if let Some(value) = value {
        put_ts(item, key, value);
    }
}

fn put_opt_s(item: &mut Item, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        item.insert(key.to_string(), client::s(value));
    }
}

fn put_ttl(item: &mut Item, expires_at: DateTime<Utc>) {
    if let Some(value) = client::ttl_attr(expires_at) {
        item.insert(client::TTL.to_string(), value);
    }
}

pub(crate) fn user_item(user: &User) -> Item {
    let mut item = base(ENTITY_USER, user_pk(user.id));
    item.insert("id".to_string(), client::s(user.id.0.to_string()));
    put_opt_s(&mut item, "email", user.email.as_deref());
    put_opt_ts(&mut item, "email_verified_at", user.email_verified_at);
    item.insert(
        "status".to_string(),
        client::s(account_status_to_str(&user.status)),
    );
    put_opt_ts(&mut item, "disabled_at", user.status.disabled_at());
    put_ts(&mut item, "created_at", user.created_at);
    put_ts(&mut item, "updated_at", user.updated_at);
    item
}

pub(crate) fn user_from_item(item: &Item) -> StorageResult<User> {
    let status = account_status_from_parts(
        &client::get_s(item, "status")?,
        client::get_opt_ts(item, "disabled_at")?,
    )?;
    Ok(User {
        id: UserId(client::get_uuid(item, "id")?),
        email: client::get_opt_s(item, "email")?,
        email_verified_at: client::get_opt_ts(item, "email_verified_at")?,
        status,
        created_at: client::get_ts(item, "created_at")?,
        updated_at: client::get_ts(item, "updated_at")?,
    })
}

pub(crate) fn email_item(email: &str, user_id: UserId) -> Item {
    let mut item = base(ENTITY_EMAIL, email_pk(email));
    item.insert("user_id".to_string(), client::s(user_id.0.to_string()));
    item.insert("email".to_string(), client::s(email));
    item
}

pub(crate) fn email_item_user_id(item: &Item) -> StorageResult<UserId> {
    Ok(UserId(client::get_uuid(item, "user_id")?))
}

pub(crate) fn session_item(session: &Session) -> Item {
    let mut item = base(ENTITY_SESSION, session_pk(session.id));
    item.insert("id".to_string(), client::s(session.id.0.to_string()));
    item.insert(
        "user_id".to_string(),
        client::s(session.user_id.0.to_string()),
    );
    item.insert(
        "token_hash".to_string(),
        client::b(session.token_hash.0.to_vec()),
    );
    put_ts(&mut item, "created_at", session.created_at);
    put_ts(&mut item, "last_used_at", session.last_used_at);
    put_ts(&mut item, client::EXPIRES_AT, session.expires_at);
    put_opt_s(&mut item, "ip", session.ip.as_deref());
    put_opt_s(&mut item, "user_agent", session.user_agent.as_deref());
    put_opt_ts(
        &mut item,
        "recovery_cooldown_until",
        session.recovery_cooldown_until,
    );
    item.insert(
        GSI1PK.to_string(),
        client::s(session_hash_key(&session.token_hash)),
    );
    put_ttl(&mut item, session.expires_at);
    item
}

pub(crate) fn session_from_item(item: &Item) -> StorageResult<Session> {
    Ok(Session {
        id: SessionId(client::get_uuid(item, "id")?),
        user_id: UserId(client::get_uuid(item, "user_id")?),
        token_hash: client::get_token_hash(item, "token_hash")?,
        created_at: client::get_ts(item, "created_at")?,
        last_used_at: client::get_ts(item, "last_used_at")?,
        expires_at: client::get_ts(item, client::EXPIRES_AT)?,
        ip: client::get_opt_s(item, "ip")?,
        user_agent: client::get_opt_s(item, "user_agent")?,
        recovery_cooldown_until: client::get_opt_ts(item, "recovery_cooldown_until")?,
    })
}

pub(crate) fn vtoken_item(token: &VerificationToken) -> Item {
    let mut item = base(ENTITY_VTOKEN, vtoken_pk(token.purpose, &token.token_hash));
    item.insert(
        "token_hash".to_string(),
        client::b(token.token_hash.0.to_vec()),
    );
    item.insert("purpose".to_string(), client::s(purpose_str(token.purpose)));
    item.insert(
        "user_id".to_string(),
        client::s(token.user_id.0.to_string()),
    );
    put_opt_s(&mut item, "new_email", token.new_email.as_deref());
    put_ts(&mut item, "created_at", token.created_at);
    put_ts(&mut item, client::EXPIRES_AT, token.expires_at);
    item.insert(
        GSI2PK.to_string(),
        client::s(user_vtokens_key(token.user_id, token.purpose)),
    );
    put_ttl(&mut item, token.expires_at);
    item
}

pub(crate) fn vtoken_from_item(item: &Item) -> StorageResult<VerificationToken> {
    Ok(VerificationToken {
        token_hash: client::get_token_hash(item, "token_hash")?,
        user_id: UserId(client::get_uuid(item, "user_id")?),
        purpose: purpose_from_str(&client::get_s(item, "purpose")?)?,
        new_email: client::get_opt_s(item, "new_email")?,
        created_at: client::get_ts(item, "created_at")?,
        expires_at: client::get_ts(item, client::EXPIRES_AT)?,
    })
}

pub(crate) fn passkey_item(credential: &StoredPasskey) -> Item {
    let mut item = base(ENTITY_PASSKEY, passkey_pk(&credential.credential_id));
    item.insert(
        "credential_id".to_string(),
        client::b(credential.credential_id.clone()),
    );
    item.insert(
        "user_id".to_string(),
        client::s(credential.user_id.0.to_string()),
    );
    item.insert("passkey".to_string(), client::b(credential.passkey.clone()));
    put_opt_s(&mut item, "name", credential.name.as_deref());
    put_ts(&mut item, "created_at", credential.created_at);
    put_opt_ts(&mut item, "last_used_at", credential.last_used_at);
    let aaguid = credential.aaguid.map(|u| u.to_string());
    put_opt_s(&mut item, "aaguid", aaguid.as_deref());
    item.insert(
        "transports".to_string(),
        client::list_s(credential.transports.iter().cloned()),
    );
    item.insert(
        "backup_eligible".to_string(),
        client::boolean(credential.backup_eligible),
    );
    item.insert(
        "backup_state".to_string(),
        client::boolean(credential.backup_state),
    );
    put_opt_ts(
        &mut item,
        "recovery_cooldown_until",
        credential.recovery_cooldown_until,
    );
    item.insert(
        GSI2PK.to_string(),
        client::s(user_passkeys_key(credential.user_id)),
    );
    item
}

fn passkey_meta_from_item(item: &Item) -> StorageResult<PasskeySummary> {
    Ok(PasskeySummary {
        credential_id: client::get_b(item, "credential_id")?,
        user_id: UserId(client::get_uuid(item, "user_id")?),
        name: client::get_opt_s(item, "name")?,
        created_at: client::get_ts(item, "created_at")?,
        last_used_at: client::get_opt_ts(item, "last_used_at")?,
        aaguid: aaguid_from_item(item)?,
        transports: client::get_list_s(item, "transports")?,
        backup_eligible: client::get_bool(item, "backup_eligible")?,
        backup_state: client::get_bool(item, "backup_state")?,
        recovery_cooldown_until: client::get_opt_ts(item, "recovery_cooldown_until")?,
    })
}

pub(crate) fn passkey_from_item(item: &Item) -> StorageResult<StoredPasskey> {
    let meta = passkey_meta_from_item(item)?;
    Ok(StoredPasskey {
        credential_id: meta.credential_id,
        user_id: meta.user_id,
        passkey: client::get_b(item, "passkey")?,
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

pub(crate) fn passkey_summary_from_item(item: &Item) -> StorageResult<PasskeySummary> {
    passkey_meta_from_item(item)
}

fn aaguid_from_item(item: &Item) -> StorageResult<Option<Uuid>> {
    match client::get_opt_s(item, "aaguid")? {
        Some(raw) => Ok(Some(Uuid::parse_str(&raw).map_err(client::err)?)),
        None => Ok(None),
    }
}

pub(crate) fn pkreg_item(value: &StoredPasskeyRegistration) -> Item {
    let mut item = base(ENTITY_PKREG, pkreg_pk(value.id));
    item.insert("id".to_string(), client::s(value.id.0.to_string()));
    item.insert(
        "purpose".to_string(),
        client::s(registration_purpose_to_str(value.purpose)),
    );
    item.insert(
        "user_id".to_string(),
        client::s(value.user_id.0.to_string()),
    );
    item.insert("state".to_string(), client::b(value.state.clone()));
    put_ts(&mut item, "created_at", value.created_at);
    put_ts(&mut item, client::EXPIRES_AT, value.expires_at);
    put_opt_ts(
        &mut item,
        "recovery_cooldown_until",
        value.recovery_cooldown_until,
    );
    item.insert(
        GSI2PK.to_string(),
        client::s(user_pkregs_key(value.user_id)),
    );
    put_ttl(&mut item, value.expires_at);
    item
}

pub(crate) fn pkreg_from_item(item: &Item) -> StorageResult<StoredPasskeyRegistration> {
    Ok(StoredPasskeyRegistration {
        id: PasskeyChallengeId(client::get_uuid(item, "id")?),
        purpose: registration_purpose_from_str(&client::get_s(item, "purpose")?)?,
        user_id: UserId(client::get_uuid(item, "user_id")?),
        state: client::get_b(item, "state")?,
        created_at: client::get_ts(item, "created_at")?,
        expires_at: client::get_ts(item, client::EXPIRES_AT)?,
        recovery_cooldown_until: client::get_opt_ts(item, "recovery_cooldown_until")?,
    })
}

pub(crate) fn pkauth_item(value: &StoredPasskeyAuthentication) -> Item {
    let mut item = base(ENTITY_PKAUTH, pkauth_pk(value.id));
    item.insert("id".to_string(), client::s(value.id.0.to_string()));
    item.insert(
        "purpose".to_string(),
        client::s(authentication_purpose_to_str(value.purpose)),
    );
    item.insert("state".to_string(), client::b(value.state.clone()));
    put_ts(&mut item, "created_at", value.created_at);
    put_ts(&mut item, client::EXPIRES_AT, value.expires_at);
    put_ttl(&mut item, value.expires_at);
    item
}

pub(crate) fn pkauth_from_item(item: &Item) -> StorageResult<StoredPasskeyAuthentication> {
    Ok(StoredPasskeyAuthentication {
        id: PasskeyChallengeId(client::get_uuid(item, "id")?),
        purpose: authentication_purpose_from_str(&client::get_s(item, "purpose")?)?,
        state: client::get_b(item, "state")?,
        created_at: client::get_ts(item, "created_at")?,
        expires_at: client::get_ts(item, client::EXPIRES_AT)?,
    })
}
