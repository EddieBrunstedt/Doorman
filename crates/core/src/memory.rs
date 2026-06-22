//! In-memory implementations of every storage trait, intended for tests and
//! local experiments. Not suitable for production: data lives only as long as
//! the process and every operation takes a process-local lock (an `RwLock` on
//! the read-heavy user/session stores, a `Mutex` elsewhere).
//!
//! The stores and [`InMemoryRateLimiter`] are always available: the limiter is
//! the high-level builder default and the stores back local experiments. The pure
//! test doubles (mock clock, in-memory audit sink, capturing email sender)
//! live in `doorman-test-support` so they never compile into a production build.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::clock::Clock;
use crate::error::{StorageError, StorageResult};
use crate::rate_limit::{RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use crate::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore, PasskeySummary, Session,
    SessionId, SessionStore, Storage, StoredPasskey, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, TokenHash, User, UserId, UserStore, VerificationPurpose,
    VerificationToken, VerificationTokenStore,
};

/// A backend handle owning one shared instance of each in-memory store.
///
/// Mirrors the SQLx adapter handles (`SqliteStorage`, `PostgresStorage`): the
/// per-store accessors (`user_store()`, `session_store()`, …) return clones of
/// the *same* underlying `Arc`, so repeated calls share state — exactly as
/// `pg.user_store()` shares one pool. [`all_stores()`](Self::all_stores) is the
/// single-backend shortcut that assembles the full [`Storage`] composite.
///
/// In-memory storage is process-local and lost on restart; use it for tests
/// and local experiments, not production.
///
/// This is a supported testing adapter: it is held to the same conformance and
/// semver guarantees as the shipped database adapters, so host integration
/// tests can build on `InMemoryStorage::new().all_stores()`.
#[derive(Clone)]
pub struct InMemoryStorage {
    users: Arc<InMemoryUserStore>,
    sessions: Arc<InMemorySessionStore>,
    verification_tokens: Arc<InMemoryVerificationTokenStore>,
    passkey_credentials: Arc<InMemoryPasskeyCredentialStore>,
    passkey_challenges: Arc<InMemoryPasskeyChallengeStore>,
}

impl InMemoryStorage {
    /// Create a fresh handle with one empty instance of each store.
    pub fn new() -> Self {
        Self {
            users: Arc::new(InMemoryUserStore::new()),
            sessions: Arc::new(InMemorySessionStore::new()),
            verification_tokens: Arc::new(InMemoryVerificationTokenStore::new()),
            passkey_credentials: Arc::new(InMemoryPasskeyCredentialStore::new()),
            passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
        }
    }

    /// The user store backed by this handle.
    pub fn user_store(&self) -> Arc<dyn UserStore> {
        self.users.clone()
    }

    /// The session store backed by this handle.
    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        self.sessions.clone()
    }

    /// The verification-token store backed by this handle.
    pub fn verification_token_store(&self) -> Arc<dyn VerificationTokenStore> {
        self.verification_tokens.clone()
    }

    /// The passkey-credential store backed by this handle.
    pub fn passkey_credential_store(&self) -> Arc<dyn PasskeyCredentialStore> {
        self.passkey_credentials.clone()
    }

    /// The passkey-challenge store backed by this handle.
    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        self.passkey_challenges.clone()
    }

    /// Build a [`Storage`] composite from this handle's five shared stores.
    ///
    /// The single-backend shortcut, mirroring the SQLx adapters'
    /// `all_stores()`, so framework-agnostic hosts, quickstarts, and benches
    /// get a one-call composite instead of hand-assembling the five fields.
    pub fn all_stores(&self) -> Storage {
        Storage {
            users: self.user_store(),
            sessions: self.session_store(),
            verification_tokens: self.verification_token_store(),
            passkey_credentials: self.passkey_credential_store(),
            passkey_challenges: self.passkey_challenge_store(),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory [`UserStore`] backed by `RwLock`-protected hash maps. The lock
/// is a read-write lock rather than a `Mutex` so the read-heavy resolution
/// path (`find_user_by_id`) does not serialize concurrent lookups.
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
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, UserStoreState> {
        self.inner.read().expect("user store rwlock poisoned")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, UserStoreState> {
        self.inner.write().expect("user store rwlock poisoned")
    }
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        let mut state = self.write();
        if state.by_id.contains_key(&user.id) {
            return Err(StorageError::msg("user with that id already exists"));
        }
        if let Some(email) = user.email.as_deref()
            && state.email_to_id.contains_key(email)
        {
            return Err(StorageError::msg("user with that email already exists"));
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

    async fn update_user(&self, user: User) -> StorageResult<()> {
        let mut state = self.write();
        let Some(existing) = state.by_id.get(&user.id).cloned() else {
            return Err(StorageError::msg("user not found"));
        };
        if existing.email != user.email {
            if let Some(old) = existing.email.as_deref() {
                state.email_to_id.remove(old);
            }
            if let Some(new) = user.email.as_deref() {
                if let Some(other) = state.email_to_id.get(new)
                    && *other != user.id
                {
                    return Err(StorageError::msg("another user already uses that email"));
                }
                state.email_to_id.insert(new.to_owned(), user.id);
            }
        }
        state.by_id.insert(user.id, user);
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

/// In-memory [`SessionStore`] backed by `RwLock`-protected hash maps. As with
/// [`InMemoryUserStore`] the lock is a read-write lock so concurrent
/// `find_session_by_token_hash` lookups on the resolution path proceed in
/// parallel.
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
    /// Remove every session matching `predicate` (and its token-hash index
    /// entry), returning the number removed.
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
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, SessionStoreState> {
        self.inner.read().expect("session store rwlock poisoned")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, SessionStoreState> {
        self.inner.write().expect("session store rwlock poisoned")
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.read().by_id.len()
    }

    /// Whether the store currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let mut state = self.write();
        if state.by_id.contains_key(&session.id) {
            return Err(StorageError::msg("session id collision"));
        }
        if state.hash_to_id.contains_key(&session.token_hash) {
            return Err(StorageError::msg("session token hash collision"));
        }
        state.hash_to_id.insert(session.token_hash, session.id);
        state.by_id.insert(session.id, session);
        Ok(())
    }

    async fn touch_session(&self, session: &Session) -> StorageResult<()> {
        // Conditional write: mutate only if the id is still present. A session
        // deleted between resolution and touch must not be resurrected, so an
        // absent id is a no-op (never an insert). The in-memory store has no
        // auto-eviction, so only the two timestamps are rewritten.
        let mut state = self.write();
        if let Some(existing) = state.by_id.get_mut(&session.id) {
            existing.last_used_at = session.last_used_at;
            existing.expires_at = session.expires_at;
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

    async fn list_for_user(
        &self,
        user_id: UserId,
        _now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        // The reference store returns every session for the user, expired
        // rows included; `SessionManager::list_for_user` applies the
        // `expires_at > now` filter. SQL adapters instead push the predicate
        // into the query (see the `SessionStore::list_for_user` contract).
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

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        Ok(self.write().remove_where(|_, s| s.user_id == user_id))
    }

    async fn delete_other_sessions_for_user(
        &self,
        user_id: UserId,
        except: SessionId,
    ) -> StorageResult<u64> {
        Ok(self
            .write()
            .remove_where(|id, s| s.user_id == user_id && *id != except))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        Ok(self.write().remove_where(|_, s| s.expires_at <= now))
    }
}

/// In-memory [`VerificationTokenStore`] preserving single-use semantics.
#[derive(Debug, Default)]
pub struct InMemoryVerificationTokenStore {
    inner: Mutex<Vec<VerificationToken>>,
}

impl InMemoryVerificationTokenStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<VerificationToken>> {
        self.inner
            .lock()
            .expect("verification token store mutex poisoned")
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl VerificationTokenStore for InMemoryVerificationTokenStore {
    async fn create_token(&self, token: VerificationToken) -> StorageResult<()> {
        let mut state = self.lock();
        if state
            .iter()
            .any(|t| t.token_hash == token.token_hash && t.purpose == token.purpose)
        {
            return Err(StorageError::msg("verification token hash collision"));
        }
        state.push(token);
        Ok(())
    }

    async fn consume_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        let mut state = self.lock();
        let pos = state
            .iter()
            .position(|t| t.token_hash == *hash && t.purpose == purpose);
        Ok(pos.map(|i| state.remove(i)))
    }

    async fn delete_tokens_for_user(
        &self,
        user_id: UserId,
        purpose: VerificationPurpose,
    ) -> StorageResult<u64> {
        let mut state = self.lock();
        let before = state.len();
        state.retain(|t| !(t.user_id == user_id && t.purpose == purpose));
        Ok((before - state.len()) as u64)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let mut state = self.lock();
        let before = state.len();
        state.retain(|t| t.expires_at > now);
        Ok((before - state.len()) as u64)
    }
}

/// In-memory [`PasskeyCredentialStore`].
#[derive(Debug, Default)]
pub struct InMemoryPasskeyCredentialStore {
    inner: Mutex<Vec<StoredPasskey>>,
}

impl InMemoryPasskeyCredentialStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<StoredPasskey>> {
        self.inner
            .lock()
            .expect("passkey credential store mutex poisoned")
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl PasskeyCredentialStore for InMemoryPasskeyCredentialStore {
    async fn add_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let mut state = self.lock();
        if state
            .iter()
            .any(|c| c.credential_id == credential.credential_id)
        {
            return Err(StorageError::msg(
                "passkey credential id already registered",
            ));
        }
        state.push(credential);
        Ok(())
    }

    async fn update_passkey(&self, credential: StoredPasskey) -> StorageResult<()> {
        let mut state = self.lock();
        let Some(slot) = state
            .iter_mut()
            .find(|c| c.credential_id == credential.credential_id)
        else {
            return Err(StorageError::msg("passkey credential not found"));
        };
        *slot = credential;
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

    async fn list_passkey_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> StorageResult<Vec<PasskeySummary>> {
        // The borrowed projection clones metadata only, so the (otherwise
        // large) credential blob is never cloned on the listing path.
        Ok(self
            .lock()
            .iter()
            .filter(|c| c.user_id == user_id)
            .map(PasskeySummary::from)
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

/// In-memory [`PasskeyChallengeStore`] with atomic take semantics.
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
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PasskeyChallengeState> {
        self.inner
            .lock()
            .expect("passkey challenge store mutex poisoned")
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        let s = self.lock();
        s.registrations.len() + s.authentications.len()
    }

    /// Whether the store currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl PasskeyChallengeStore for InMemoryPasskeyChallengeStore {
    async fn put_registration(&self, value: StoredPasskeyRegistration) -> StorageResult<()> {
        let mut state = self.lock();
        if state.registrations.contains_key(&value.id) {
            return Err(StorageError::msg(
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

    async fn count_registrations_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        Ok(self
            .lock()
            .registrations
            .values()
            .filter(|v| v.user_id == user_id)
            .count() as u64)
    }

    async fn put_authentication(&self, value: StoredPasskeyAuthentication) -> StorageResult<()> {
        let mut state = self.lock();
        if state.authentications.contains_key(&value.id) {
            return Err(StorageError::msg(
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

/// In-memory sliding-window-log rate limiter.
///
/// Each `(key, policy.window)` bucket keeps the timestamps of recent
/// attempts and evicts ones older than `policy.window` on every check.
/// Suitable for single-process deployments and tests; a multi-replica
/// deployment should swap in a shared backend.
///
/// Known limitation: the bucket map does not proactively remove empty
/// buckets, so sustained churn across many unique keys can grow memory
/// until process restart. Use a shared or evicting production limiter for
/// hostile or high-cardinality traffic patterns.
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
    /// Create a per-process rate limiter driven by `clock`. Correct only
    /// within one process; multi-node deployments need a shared backend.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BucketKey, Vec<DateTime<Utc>>>> {
        self.inner.lock().expect("rate limiter mutex poisoned")
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
        let window = chrono::Duration::from_std(policy.window)
            .map_err(|_| StorageError::msg("rate limit window overflows chrono::Duration"))?;
        let cutoff = now - window;
        let bucket = BucketKey {
            key: key.canonical(),
            window_ms: policy.window.as_millis(),
        };

        let mut state = self.lock();
        let entries = state.entry(bucket).or_default();
        entries.retain(|t| *t > cutoff);

        if entries.len() as u32 >= policy.max_attempts {
            // `retain` above keeps only entries `> cutoff = now - window`, so the
            // bucket is non-empty and the oldest retained timestamp gives
            // `retry_at = oldest + window > now`. Floor the advisory hint to one
            // millisecond at the window boundary so it is always positive.
            let oldest = entries.first().copied().unwrap_or(now);
            let retry_at = oldest + window;
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
    use crate::storage::AccountStatus;

    #[tokio::test]
    async fn in_memory_composite_wires_every_store() {
        // The composite must hand back working, independent stores; exercise
        // one method per store to prove each field is populated and live.
        let storage = InMemoryStorage::new().all_stores();
        let now = chrono::Utc::now();

        let user = User {
            id: UserId::new(),
            email: Some("composite@example.com".into()),
            email_verified_at: None,
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
        };
        storage
            .users
            .create_user(user.clone())
            .await
            .expect("user store wired");
        assert_eq!(
            storage
                .users
                .find_user_by_id(user.id)
                .await
                .expect("find user"),
            Some(user.clone()),
        );

        assert!(
            storage
                .sessions
                .list_for_user(user.id, now)
                .await
                .expect("session store wired")
                .is_empty()
        );
        assert!(
            storage
                .verification_tokens
                .consume_token(&TokenHash([0u8; 32]), VerificationPurpose::Signup)
                .await
                .expect("verification token store wired")
                .is_none()
        );
        assert!(
            storage
                .passkey_credentials
                .list_passkey_summaries_for_user(user.id)
                .await
                .expect("passkey credential store wired")
                .is_empty()
        );
        assert!(
            storage
                .passkey_challenges
                .take_registration(PasskeyChallengeId::new())
                .await
                .expect("passkey challenge store wired")
                .is_none()
        );
    }

    #[tokio::test]
    async fn repeated_accessor_calls_share_state() {
        // The handle's accessors return clones of the *same* underlying store,
        // so a row written through one accessor handle is visible through
        // another — matching how a pooled SQL adapter shares one pool.
        let storage = InMemoryStorage::new();
        let now = chrono::Utc::now();
        let user = User {
            id: UserId::new(),
            email: Some("shared@example.com".into()),
            email_verified_at: None,
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
        };

        storage
            .user_store()
            .create_user(user.clone())
            .await
            .expect("create via first handle");

        assert_eq!(
            storage
                .user_store()
                .find_user_by_id(user.id)
                .await
                .expect("find via second handle"),
            Some(user),
        );
    }
}
