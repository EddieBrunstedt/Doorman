use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::client_ip::ClientIp;
pub use crate::dpop::JwkThumbprint;
#[cfg(doc)]
use crate::error::StorageErrorKind;
use crate::error::StorageResult;
pub use crate::token::TokenHash;

#[derive(Clone)]
pub struct Storage {
    pub records: RecordStores,
    pub expiring: ExpiringStores,
}

#[derive(Clone)]
pub struct RecordStores {
    pub users: Arc<dyn UserStore>,
    pub passkeys: Arc<dyn PasskeyStore>,
}

#[derive(Clone)]
pub struct ExpiringStores {
    pub sessions: Arc<dyn SessionStore>,
    pub email_links: Arc<dyn EmailLinkStore>,
    pub passkey_challenges: Arc<dyn PasskeyChallengeStore>,
    pub dpop_proofs: Arc<dyn DpopProofStore>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserStatus {
    #[default]
    Active,
    Disabled {
        at: DateTime<Utc>,
    },
}

impl UserStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, UserStatus::Active)
    }

    pub fn disabled_at(&self) -> Option<DateTime<Utc>> {
        match self {
            UserStatus::Disabled { at } => Some(*at),
            UserStatus::Active => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: Option<String>,
    pub signed_up_at: Option<DateTime<Utc>>,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn has_finished_signup(&self) -> bool {
        self.signed_up_at.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionTransport {
    Cookie,
    Dpop { jkt: JwkThumbprint },
}

impl SessionTransport {
    pub fn dpop_jkt(&self) -> Option<JwkThumbprint> {
        match self {
            SessionTransport::Dpop { jkt } => Some(*jkt),
            SessionTransport::Cookie => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub token_hash: TokenHash,
    pub transport: SessionTransport,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip: ClientIp,
    pub user_agent: Option<String>,
    pub recovery_cool_down_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: SessionId,
    pub user_id: UserId,
    pub transport: SessionTransport,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip: ClientIp,
    pub user_agent: Option<String>,
    pub recovery_cool_down_until: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, user: User) -> StorageResult<()>;

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>>;

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>>;

    async fn set_user_status(
        &self,
        id: UserId,
        status: UserStatus,
        at: DateTime<Utc>,
    ) -> StorageResult<()>;

    async fn set_user_email(&self, id: UserId, email: &str, at: DateTime<Utc>)
    -> StorageResult<()>;

    async fn mark_signed_up(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()>;

    async fn delete_user(&self, id: UserId) -> StorageResult<()>;
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(&self, session: Session) -> StorageResult<()>;

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()>;

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>>;

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>>;

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>>;

    async fn delete_session(&self, id: SessionId) -> StorageResult<()>;

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64>;

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PasskeyChallengeId(pub Uuid);

impl PasskeyChallengeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PasskeyChallengeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PasskeyChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub credential_id: Vec<u8>,
    pub user_id: UserId,
    pub passkey: Vec<u8>,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub aaguid: Option<Uuid>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub recovery_cool_down_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    pub credential_id: Vec<u8>,
    pub user_id: UserId,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub aaguid: Option<Uuid>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub recovery_cool_down_until: Option<DateTime<Utc>>,
}

impl From<StoredPasskey> for PasskeySummary {
    fn from(value: StoredPasskey) -> Self {
        Self {
            credential_id: value.credential_id,
            user_id: value.user_id,
            name: value.name,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            aaguid: value.aaguid,
            transports: value.transports,
            backup_eligible: value.backup_eligible,
            backup_state: value.backup_state,
            recovery_cool_down_until: value.recovery_cool_down_until,
        }
    }
}

impl From<&StoredPasskey> for PasskeySummary {
    fn from(value: &StoredPasskey) -> Self {
        Self {
            credential_id: value.credential_id.clone(),
            user_id: value.user_id,
            name: value.name.clone(),
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            aaguid: value.aaguid,
            transports: value.transports.clone(),
            backup_eligible: value.backup_eligible,
            backup_state: value.backup_state,
            recovery_cool_down_until: value.recovery_cool_down_until,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationPurpose {
    Signup,
    Recovery,
    AddPasskey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskeyRegistration {
    pub id: PasskeyChallengeId,
    pub purpose: RegistrationPurpose,
    pub user_id: UserId,
    pub state: Vec<u8>,
    pub owner_email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub recovery_cool_down_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationPurpose {
    Login,
    Reauth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskeyAuthentication {
    pub id: PasskeyChallengeId,
    pub purpose: AuthenticationPurpose,
    pub state: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyUse {
    pub passkey: Vec<u8>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub used_at: DateTime<Utc>,
}

#[async_trait]
pub trait PasskeyStore: Send + Sync {
    async fn add_passkey(&self, passkey: StoredPasskey) -> StorageResult<()>;

    async fn record_passkey_use(&self, credential_id: &[u8], used: PasskeyUse)
    -> StorageResult<()>;

    async fn set_passkey_name(&self, credential_id: &[u8], name: Option<&str>)
    -> StorageResult<()>;

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>>;

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>>;

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()>;

    async fn delete_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64>;
}

#[async_trait]
pub trait PasskeyChallengeStore: Send + Sync {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()>;

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>>;

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64>;

    async fn list_registrations_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<StoredPasskeyRegistration>>;

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()>;

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>>;

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailLinkPurpose {
    Signup,
    Recovery,
    EmailChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailLink {
    pub token_hash: TokenHash,
    pub user_id: UserId,
    pub purpose: EmailLinkPurpose,
    pub owner_email: Option<String>,
    pub new_email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait EmailLinkStore: Send + Sync {
    async fn replace_link(&self, link: EmailLink) -> StorageResult<()>;

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>>;

    async fn delete_links_for_user(&self, user_id: UserId) -> StorageResult<u64>;

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DpopProofId(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsedDpopProof {
    pub id: DpopProofId,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait DpopProofStore: Send + Sync {
    // Core never offers a proof at or past its deadline, so a row that has expired may refuse it
    // or not.
    async fn use_proof(&self, proof: UsedDpopProof) -> StorageResult<bool>;

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::hash_token;
    use chrono::TimeZone;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0)
            .single()
            .expect("valid timestamp")
    }

    #[test]
    fn session_json_round_trips() {
        let session = Session {
            id: SessionId::new(),
            user_id: UserId::new(),
            token_hash: hash_token("a-session-token"),
            transport: SessionTransport::Dpop {
                jkt: JwkThumbprint([9u8; 32]),
            },
            created_at: ts(1_000),
            last_used_at: ts(1_000),
            expires_at: ts(2_000),
            ip: "203.0.113.7".parse().expect("ip"),
            user_agent: Some("doorman-test/1.0".to_string()),
            recovery_cool_down_until: Some(ts(1_500)),
        };
        let json = serde_json::to_string(&session).expect("serialize session");
        let back: Session = serde_json::from_str(&json).expect("deserialize session");
        assert_eq!(session, back);
    }

    #[test]
    fn email_link_json_round_trips() {
        let token = EmailLink {
            token_hash: hash_token("an-email-link-token"),
            user_id: UserId::new(),
            purpose: EmailLinkPurpose::EmailChange,
            owner_email: Some("old@example.com".to_string()),
            new_email: Some("new@example.com".to_string()),
            created_at: ts(1_000),
            expires_at: ts(2_000),
        };
        let json = serde_json::to_string(&token).expect("serialize token");
        let back: EmailLink = serde_json::from_str(&json).expect("deserialize token");
        assert_eq!(token, back);
    }

    #[test]
    fn stored_passkey_registration_json_round_trips() {
        let reg = StoredPasskeyRegistration {
            id: PasskeyChallengeId::new(),
            purpose: RegistrationPurpose::Recovery,
            user_id: UserId::new(),
            state: vec![0x00, 0x01, 0xfe, 0xff],
            owner_email: Some("user@example.com".to_string()),
            created_at: ts(1_000),
            expires_at: ts(2_000),
            recovery_cool_down_until: None,
        };
        let json = serde_json::to_string(&reg).expect("serialize registration");
        let back: StoredPasskeyRegistration =
            serde_json::from_str(&json).expect("deserialize registration");
        assert_eq!(reg.id, back.id);
        assert_eq!(reg.purpose, back.purpose);
        assert_eq!(reg.user_id, back.user_id);
        assert_eq!(reg.state, back.state);
        assert_eq!(reg.owner_email, back.owner_email);
        assert_eq!(reg.created_at, back.created_at);
        assert_eq!(reg.expires_at, back.expires_at);
        assert_eq!(reg.recovery_cool_down_until, back.recovery_cool_down_until);
    }

    #[test]
    fn stored_passkey_authentication_json_round_trips() {
        let auth = StoredPasskeyAuthentication {
            id: PasskeyChallengeId::new(),
            purpose: AuthenticationPurpose::Reauth,
            state: vec![0xde, 0xad, 0xbe, 0xef],
            created_at: ts(1_000),
            expires_at: ts(2_000),
        };
        let json = serde_json::to_string(&auth).expect("serialize authentication");
        let back: StoredPasskeyAuthentication =
            serde_json::from_str(&json).expect("deserialize authentication");
        assert_eq!(auth.id, back.id);
        assert_eq!(auth.purpose, back.purpose);
        assert_eq!(auth.state, back.state);
        assert_eq!(auth.created_at, back.created_at);
        assert_eq!(auth.expires_at, back.expires_at);
    }
}
