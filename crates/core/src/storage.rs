use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(doc)]
use crate::error::StorageErrorKind;
use crate::error::StorageResult;
pub use crate::token::TokenHash;

#[derive(Clone)]
pub struct Storage {
    pub users: Arc<dyn UserStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub verification_tokens: Arc<dyn VerificationTokenStore>,
    pub passkey_credentials: Arc<dyn PasskeyCredentialStore>,
    pub passkey_challenges: Arc<dyn PasskeyChallengeStore>,
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
pub enum AccountStatus {
    #[default]
    Active,
    Disabled {
        at: DateTime<Utc>,
    },
}

impl AccountStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, AccountStatus::Active)
    }

    pub fn disabled_at(&self) -> Option<DateTime<Utc>> {
        match self {
            AccountStatus::Disabled { at } => Some(*at),
            AccountStatus::Active => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub status: AccountStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub token_hash: TokenHash,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: SessionId,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, user: User) -> StorageResult<()>;

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>>;

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>>;

    async fn set_user_status(
        &self,
        id: UserId,
        status: AccountStatus,
        at: DateTime<Utc>,
    ) -> StorageResult<()>;

    async fn set_user_email(&self, id: UserId, email: &str, at: DateTime<Utc>)
    -> StorageResult<()>;

    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()>;

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

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>>;

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
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
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
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
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
            recovery_cooldown_until: value.recovery_cooldown_until,
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
            recovery_cooldown_until: value.recovery_cooldown_until,
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
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub recovery_cooldown_until: Option<DateTime<Utc>>,
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
pub trait PasskeyCredentialStore: Send + Sync {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()>;

    async fn record_passkey_use(&self, credential_id: &[u8], used: PasskeyUse)
    -> StorageResult<()>;

    async fn set_passkey_name(&self, credential_id: &[u8], name: Option<&str>)
    -> StorageResult<()>;

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>>;

    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>>;

    async fn count_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64>;

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

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64>;

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()>;

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>>;

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPurpose {
    Signup,
    Recovery,
    EmailChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationToken {
    pub token_hash: TokenHash,
    pub user_id: UserId,
    pub purpose: VerificationPurpose,
    pub new_email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait VerificationTokenStore: Send + Sync {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()>;

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>>;

    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64>;

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
            created_at: ts(1_000),
            last_used_at: ts(1_000),
            expires_at: ts(2_000),
            ip: Some("203.0.113.7".to_string()),
            user_agent: Some("doorman-test/1.0".to_string()),
            recovery_cooldown_until: Some(ts(1_500)),
        };
        let json = serde_json::to_string(&session).expect("serialize session");
        let back: Session = serde_json::from_str(&json).expect("deserialize session");
        assert_eq!(session, back);
    }

    #[test]
    fn verification_token_json_round_trips() {
        let token = VerificationToken {
            token_hash: hash_token("a-verification-token"),
            user_id: UserId::new(),
            purpose: VerificationPurpose::EmailChange,
            new_email: Some("new@example.com".to_string()),
            created_at: ts(1_000),
            expires_at: ts(2_000),
        };
        let json = serde_json::to_string(&token).expect("serialize token");
        let back: VerificationToken = serde_json::from_str(&json).expect("deserialize token");
        assert_eq!(token, back);
    }

    #[test]
    fn stored_passkey_registration_json_round_trips() {
        let reg = StoredPasskeyRegistration {
            id: PasskeyChallengeId::new(),
            purpose: RegistrationPurpose::Recovery,
            user_id: UserId::new(),
            state: vec![0x00, 0x01, 0xfe, 0xff],
            created_at: ts(1_000),
            expires_at: ts(2_000),
            recovery_cooldown_until: None,
        };
        let json = serde_json::to_string(&reg).expect("serialize registration");
        let back: StoredPasskeyRegistration =
            serde_json::from_str(&json).expect("deserialize registration");
        assert_eq!(reg.id, back.id);
        assert_eq!(reg.purpose, back.purpose);
        assert_eq!(reg.user_id, back.user_id);
        assert_eq!(reg.state, back.state);
        assert_eq!(reg.created_at, back.created_at);
        assert_eq!(reg.expires_at, back.expires_at);
        assert_eq!(reg.recovery_cooldown_until, back.recovery_cooldown_until);
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
