use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::clock::Clock;
use crate::error::{StorageError, StorageResult};
use crate::rate_limit::{RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use crate::storage::{
    EmailLink, EmailLinkStore, ExpiringStores, PasskeyChallengeId, PasskeyChallengeStore,
    PasskeyStore, PasskeyUse, RecordStores, Session, SessionId, SessionStore, Storage,
    StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, User, UserId,
    UserStatus, UserStore,
};
use crate::sync;

#[derive(Clone)]
pub struct InMemoryStorage {
    users: Arc<InMemoryUserStore>,
    sessions: Arc<InMemorySessionStore>,
    email_links: Arc<InMemoryEmailLinkStore>,
    passkeys: Arc<InMemoryPasskeyStore>,
    passkey_challenges: Arc<InMemoryPasskeyChallengeStore>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            users: Arc::new(InMemoryUserStore::new()),
            sessions: Arc::new(InMemorySessionStore::new()),
            email_links: Arc::new(InMemoryEmailLinkStore::new()),
            passkeys: Arc::new(InMemoryPasskeyStore::new()),
            passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
        }
    }

    pub fn all_stores(&self) -> Storage {
        Storage {
            records: self.records(),
            expiring: self.expiring(),
        }
    }

    pub fn records(&self) -> RecordStores {
        RecordStores {
            users: self.users.clone(),
            passkeys: self.passkeys.clone(),
        }
    }

    pub fn expiring(&self) -> ExpiringStores {
        ExpiringStores {
            sessions: self.sessions.clone(),
            email_links: self.email_links.clone(),
            passkey_challenges: self.passkey_challenges.clone(),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct InMemoryUserStore {
    inner: RwLock<UserStoreState>,
}

#[derive(Debug, Default)]
struct UserStoreState {
    by_id: HashMap<UserId, User>,
    email_to_id: HashMap<String, UserId>,
}

impl InMemoryUserStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, UserStoreState> {
        sync::read(&self.inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, UserStoreState> {
        sync::write(&self.inner)
    }
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        let mut state = self.write();
        if state.by_id.contains_key(&user.id) {
            return Err(StorageError::conflict("user with that id already exists"));
        }
        if let Some(email) = user.email.as_deref()
            && state.email_to_id.contains_key(email)
        {
            return Err(StorageError::conflict(
                "user with that email already exists",
            ));
        }
        if let Some(email) = user.email.clone() {
            state.email_to_id.insert(email, user.id);
        }
        state.by_id.insert(user.id, user);
        Ok(())
    }

    async fn find_user_by_id(&self, id: UserId) -> StorageResult<Option<User>> {
        Ok(self.read().by_id.get(&id).cloned())
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let state = self.read();
        Ok(state
            .email_to_id
            .get(email)
            .and_then(|id| state.by_id.get(id).cloned()))
    }

    async fn set_user_status(
        &self,
        id: UserId,
        status: UserStatus,
        at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let mut state = self.write();
        let Some(user) = state.by_id.get_mut(&id) else {
            return Err(StorageError::not_found("user not found"));
        };
        user.status = status;
        user.updated_at = at;
        Ok(())
    }

    async fn set_user_email(
        &self,
        id: UserId,
        email: &str,
        verified_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let mut state = self.write();
        let UserStoreState { by_id, email_to_id } = &mut *state;
        let Some(user) = by_id.get_mut(&id) else {
            return Err(StorageError::not_found("user not found"));
        };
        if let Some(other) = email_to_id.get(email)
            && *other != id
        {
            return Err(StorageError::conflict(
                "another user already uses that email",
            ));
        }
        if let Some(old) = user.email.as_deref() {
            email_to_id.remove(old);
        }
        email_to_id.insert(email.to_owned(), id);
        user.email = Some(email.to_owned());
        user.email_verified_at = Some(verified_at);
        user.updated_at = verified_at;
        Ok(())
    }

    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> StorageResult<()> {
        let mut state = self.write();
        let Some(user) = state.by_id.get_mut(&id) else {
            return Err(StorageError::not_found("user not found"));
        };
        user.email_verified_at = Some(at);
        user.updated_at = at;
        Ok(())
    }

    async fn delete_user(&self, id: UserId) -> StorageResult<()> {
        let mut state = self.write();
        if let Some(user) = state.by_id.remove(&id)
            && let Some(email) = user.email
        {
            state.email_to_id.remove(&email);
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct InMemorySessionStore {
    inner: RwLock<SessionStoreState>,
}

#[derive(Debug, Default)]
struct SessionStoreState {
    by_id: HashMap<SessionId, Session>,
    hash_to_id: HashMap<TokenHash, SessionId>,
}

impl SessionStoreState {
    fn remove_where(&mut self, predicate: impl Fn(&SessionId, &Session) -> bool) -> u64 {
        let ids: Vec<SessionId> = self
            .by_id
            .iter()
            .filter_map(|(id, s)| predicate(id, s).then_some(*id))
            .collect();
        let count = ids.len() as u64;
        for id in ids {
            if let Some(session) = self.by_id.remove(&id) {
                self.hash_to_id.remove(&session.token_hash);
            }
        }
        count
    }
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, SessionStoreState> {
        sync::read(&self.inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, SessionStoreState> {
        sync::write(&self.inner)
    }

    pub fn len(&self) -> usize {
        self.read().by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let mut state = self.write();
        if state.by_id.contains_key(&session.id) {
            return Err(StorageError::conflict("session id collision"));
        }
        if state.hash_to_id.contains_key(&session.token_hash) {
            return Err(StorageError::conflict("session token hash collision"));
        }
        state.hash_to_id.insert(session.token_hash, session.id);
        state.by_id.insert(session.id, session);
        Ok(())
    }

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let mut state = self.write();
        if let Some(existing) = state.by_id.get_mut(&id) {
            existing.last_used_at = last_used_at;
            existing.expires_at = expires_at;
        }
        Ok(())
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let state = self.read();
        Ok(state
            .hash_to_id
            .get(hash)
            .and_then(|id| state.by_id.get(id).cloned()))
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        Ok(self.read().by_id.get(&id).cloned())
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<Session>> {
        Ok(self
            .read()
            .by_id
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        let mut state = self.write();
        if let Some(session) = state.by_id.remove(&id) {
            state.hash_to_id.remove(&session.token_hash);
        }
        Ok(())
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64> {
        Ok(self
            .write()
            .remove_where(|id, s| s.user_id == user_id && Some(*id) != except))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        Ok(self.write().remove_where(|_, s| s.expires_at <= now))
    }
}

#[derive(Debug, Default)]
pub struct InMemoryEmailLinkStore {
    inner: Mutex<Vec<EmailLink>>,
}

impl InMemoryEmailLinkStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<EmailLink>> {
        sync::lock(&self.inner)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl EmailLinkStore for InMemoryEmailLinkStore {
    async fn replace_link(&self, link: EmailLink) -> StorageResult<()> {
        let mut state = self.lock();
        if state.iter().any(|t| t.token_hash == link.token_hash) {
            return Err(StorageError::conflict("email link token hash collision"));
        }
        state.retain(|t| !(t.user_id == link.user_id && t.purpose == link.purpose));
        state.push(link);
        Ok(())
    }

    async fn redeem_link(&self, hash: &TokenHash) -> StorageResult<Option<EmailLink>> {
        let mut state = self.lock();
        let pos = state.iter().position(|t| t.token_hash == *hash);
        Ok(pos.map(|i| state.remove(i)))
    }

    async fn delete_links_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let mut state = self.lock();
        let before = state.len();
        state.retain(|t| t.user_id != user_id);
        Ok((before - state.len()) as u64)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let mut state = self.lock();
        let before = state.len();
        state.retain(|t| t.expires_at > now);
        Ok((before - state.len()) as u64)
    }
}

#[derive(Debug, Default)]
pub struct InMemoryPasskeyStore {
    inner: Mutex<Vec<StoredPasskey>>,
}

impl InMemoryPasskeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<StoredPasskey>> {
        sync::lock(&self.inner)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl PasskeyStore for InMemoryPasskeyStore {
    async fn add_passkey(&self, stored: StoredPasskey) -> StorageResult<()> {
        let mut state = self.lock();
        if state
            .iter()
            .any(|c| c.credential_id == stored.credential_id)
        {
            return Err(StorageError::conflict("credential ID already registered"));
        }
        state.push(stored);
        Ok(())
    }

    async fn record_passkey_use(
        &self,
        credential_id: &[u8],
        used: PasskeyUse,
    ) -> StorageResult<()> {
        let mut state = self.lock();
        let Some(stored) = state.iter_mut().find(|c| c.credential_id == credential_id) else {
            return Err(StorageError::not_found("passkey not found"));
        };
        stored.passkey = used.passkey;
        stored.backup_eligible = used.backup_eligible;
        stored.backup_state = used.backup_state;
        stored.last_used_at = Some(used.used_at);
        Ok(())
    }

    async fn set_passkey_name(
        &self,
        credential_id: &[u8],
        name: Option<&str>,
    ) -> StorageResult<()> {
        let mut state = self.lock();
        let Some(stored) = state.iter_mut().find(|c| c.credential_id == credential_id) else {
            return Err(StorageError::not_found("passkey not found"));
        };
        stored.name = name.map(str::to_owned);
        Ok(())
    }

    async fn list_passkeys_for_user(&self, user_id: UserId) -> StorageResult<Vec<StoredPasskey>> {
        Ok(self
            .lock()
            .iter()
            .filter(|c| c.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> StorageResult<Option<StoredPasskey>> {
        Ok(self
            .lock()
            .iter()
            .find(|c| c.credential_id == credential_id)
            .cloned())
    }

    async fn delete_passkey(&self, credential_id: &[u8]) -> StorageResult<()> {
        let mut state = self.lock();
        state.retain(|c| c.credential_id != credential_id);
        Ok(())
    }

    async fn delete_passkeys_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let mut state = self.lock();
        let before = state.len();
        state.retain(|c| c.user_id != user_id);
        Ok((before - state.len()) as u64)
    }
}

#[derive(Debug, Default)]
pub struct InMemoryPasskeyChallengeStore {
    inner: Mutex<PasskeyChallengeState>,
}

#[derive(Debug, Default)]
struct PasskeyChallengeState {
    registrations: HashMap<PasskeyChallengeId, StoredPasskeyRegistration>,
    authentications: HashMap<PasskeyChallengeId, StoredPasskeyAuthentication>,
}

impl InMemoryPasskeyChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PasskeyChallengeState> {
        sync::lock(&self.inner)
    }

    pub fn len(&self) -> usize {
        let s = self.lock();
        s.registrations.len() + s.authentications.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl PasskeyChallengeStore for InMemoryPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        let mut state = self.lock();
        if state.registrations.contains_key(&value.id) {
            return Err(StorageError::conflict(
                "passkey registration challenge collision",
            ));
        }
        state.registrations.insert(value.id, value);
        Ok(())
    }

    async fn take_registration(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyRegistration>> {
        Ok(self.lock().registrations.remove(&id))
    }

    async fn delete_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let mut state = self.lock();
        let before = state.registrations.len();
        state.registrations.retain(|_, v| v.user_id != user_id);
        Ok((before - state.registrations.len()) as u64)
    }

    async fn list_registrations_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<StoredPasskeyRegistration>> {
        Ok(self
            .lock()
            .registrations
            .values()
            .filter(|v| v.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        let mut state = self.lock();
        if state.authentications.contains_key(&value.id) {
            return Err(StorageError::conflict(
                "passkey authentication challenge collision",
            ));
        }
        state.authentications.insert(value.id, value);
        Ok(())
    }

    async fn take_authentication(
        &self,
        id: PasskeyChallengeId,
    ) -> StorageResult<Option<StoredPasskeyAuthentication>> {
        Ok(self.lock().authentications.remove(&id))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let mut state = self.lock();
        let before = state.registrations.len() + state.authentications.len();
        state.registrations.retain(|_, v| v.expires_at > now);
        state.authentications.retain(|_, v| v.expires_at > now);
        let after = state.registrations.len() + state.authentications.len();
        Ok((before - after) as u64)
    }
}

pub struct InMemoryRateLimiter {
    clock: Arc<dyn Clock>,
    inner: Mutex<HashMap<BucketKey, Vec<DateTime<Utc>>>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct BucketKey {
    key: String,
    window_ms: u128,
}

impl InMemoryRateLimiter {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BucketKey, Vec<DateTime<Utc>>>> {
        sync::lock(&self.inner)
    }
}

#[async_trait]
impl RateLimiter for InMemoryRateLimiter {
    async fn check_and_charge(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision> {
        let now = self.clock.now();
        let out_of_range = || StorageError::msg("rate limit window is out of range");
        let window = chrono::Duration::from_std(policy.window).map_err(|_| out_of_range())?;
        let cutoff = now.checked_sub_signed(window).ok_or_else(out_of_range)?;
        let bucket = BucketKey {
            key: key.canonical(),
            window_ms: policy.window.as_millis(),
        };

        let mut state = self.lock();
        let entries = state.entry(bucket).or_default();
        entries.retain(|t| *t > cutoff);

        if entries.len() as u32 >= policy.max_attempts {
            let oldest = entries.first().copied().unwrap_or(now);
            let retry_at = oldest.checked_add_signed(window).ok_or_else(out_of_range)?;
            let retry_after = (retry_at - now)
                .to_std()
                .unwrap_or(std::time::Duration::from_millis(1))
                .max(std::time::Duration::from_millis(1));
            return Ok(RateLimitDecision::Limited { retry_after });
        }

        entries.push(now);
        Ok(RateLimitDecision::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::UserStatus;

    #[tokio::test]
    async fn in_memory_composite_wires_every_store() {
        let storage = InMemoryStorage::new().all_stores();
        let now = chrono::Utc::now();

        let user = User {
            id: UserId::new(),
            email: Some("composite@example.com".into()),
            email_verified_at: None,
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
        };
        storage
            .records
            .users
            .create_user(user.clone())
            .await
            .expect("user store wired");
        assert_eq!(
            storage
                .records
                .users
                .find_user_by_id(user.id)
                .await
                .expect("find user"),
            Some(user.clone()),
        );

        assert!(
            storage
                .expiring
                .sessions
                .list_for_user(user.id)
                .await
                .expect("session store wired")
                .is_empty()
        );
        assert!(
            storage
                .expiring
                .email_links
                .redeem_link(&TokenHash([0u8; 32]))
                .await
                .expect("email link store wired")
                .is_none()
        );
        assert!(
            storage
                .records
                .passkeys
                .list_passkeys_for_user(user.id)
                .await
                .expect("passkey store wired")
                .is_empty()
        );
        assert!(
            storage
                .expiring
                .passkey_challenges
                .take_registration(PasskeyChallengeId::new())
                .await
                .expect("passkey challenge store wired")
                .is_none()
        );
    }

    #[tokio::test]
    async fn repeated_accessor_calls_share_state() {
        let storage = InMemoryStorage::new();
        let now = chrono::Utc::now();
        let user = User {
            id: UserId::new(),
            email: Some("shared@example.com".into()),
            email_verified_at: None,
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
        };

        storage
            .records()
            .users
            .create_user(user.clone())
            .await
            .expect("create via first handle");

        assert_eq!(
            storage
                .records()
                .users
                .find_user_by_id(user.id)
                .await
                .expect("find via second handle"),
            Some(user),
        );
    }

    #[tokio::test]
    async fn rate_limiter_refuses_a_window_past_the_calendar() {
        let limiter = InMemoryRateLimiter::new(Arc::new(crate::clock::SystemClock));
        let policy = RateLimitPolicy::new(1, std::time::Duration::from_millis(i64::MAX as u64));
        let result = limiter
            .check_and_charge(&RateLimitKey::new("test"), policy)
            .await;
        assert!(result.is_err(), "expected an error, got {result:?}");
    }
}
