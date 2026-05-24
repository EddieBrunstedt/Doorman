//! In-memory implementations of every storage trait, intended for tests and
//! local experiments. Not suitable for production: data lives only as long as
//! the process and lookups hold a `std::sync::Mutex` for their duration.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::audit::{AuditEvent, AuditSink};
use crate::clock::Clock;
use crate::email::{Email, EmailSender};
use crate::error::{EmailResult, StorageError, StorageResult};
use crate::rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
use crate::storage::{
    OAuthIdentity, OAuthIdentityStore, OAuthStateId, OAuthStateStore, PasskeyChallengeId,
    PasskeyChallengeStore, PasskeyCredentialStore, PasswordCredential, PasswordCredentialStore,
    PendingOAuthAuthorization, Session, SessionId, SessionStore, StoredPasskey,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, User, UserId, UserStore,
    VerificationPurpose, VerificationToken, VerificationTokenStore,
};

#[derive(Debug, Default)]
pub struct InMemoryUserStore {
    inner: Mutex<UserStoreState>,
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

    fn lock(&self) -> std::sync::MutexGuard<'_, UserStoreState> {
        self.inner.lock().expect("user store mutex poisoned")
    }
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn create_user(&self, user: User) -> StorageResult<()> {
        let mut state = self.lock();
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
        Ok(self.lock().by_id.get(&id).cloned())
    }

    async fn find_user_by_email(&self, email: &str) -> StorageResult<Option<User>> {
        let state = self.lock();
        Ok(state
            .email_to_id
            .get(email)
            .and_then(|id| state.by_id.get(id).cloned()))
    }

    async fn update_user(&self, user: User) -> StorageResult<()> {
        let mut state = self.lock();
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
        let mut state = self.lock();
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
    inner: Mutex<SessionStoreState>,
}

#[derive(Debug, Default)]
struct SessionStoreState {
    by_id: HashMap<SessionId, Session>,
    hash_to_id: HashMap<TokenHash, SessionId>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SessionStoreState> {
        self.inner.lock().expect("session store mutex poisoned")
    }

    pub fn len(&self) -> usize {
        self.lock().by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        let mut state = self.lock();
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

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let state = self.lock();
        Ok(state
            .hash_to_id
            .get(hash)
            .and_then(|id| state.by_id.get(id).cloned()))
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        Ok(self.lock().by_id.get(&id).cloned())
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        let mut state = self.lock();
        if let Some(session) = state.by_id.remove(&id) {
            state.hash_to_id.remove(&session.token_hash);
        }
        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: UserId) -> StorageResult<u64> {
        let mut state = self.lock();
        let ids: Vec<SessionId> = state
            .by_id
            .iter()
            .filter_map(|(id, s)| (s.user_id == user_id).then_some(*id))
            .collect();
        let count = ids.len() as u64;
        for id in ids {
            if let Some(session) = state.by_id.remove(&id) {
                state.hash_to_id.remove(&session.token_hash);
            }
        }
        Ok(count)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let mut state = self.lock();
        let ids: Vec<SessionId> = state
            .by_id
            .iter()
            .filter_map(|(id, s)| (s.expires_at <= now).then_some(*id))
            .collect();
        let count = ids.len() as u64;
        for id in ids {
            if let Some(session) = state.by_id.remove(&id) {
                state.hash_to_id.remove(&session.token_hash);
            }
        }
        Ok(count)
    }
}

#[derive(Debug, Default)]
pub struct InMemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .expect("audit sink mutex poisoned")
            .clone()
    }

    pub fn len(&self) -> usize {
        self.events.lock().expect("audit sink mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl AuditSink for InMemoryAuditSink {
    async fn emit(&self, event: AuditEvent) {
        self.events
            .lock()
            .expect("audit sink mutex poisoned")
            .push(event);
    }
}

#[derive(Debug, Default)]
pub struct InMemoryEmailSender {
    sent: Mutex<Vec<Email>>,
}

impl InMemoryEmailSender {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sent(&self) -> Vec<Email> {
        self.sent
            .lock()
            .expect("email sender mutex poisoned")
            .clone()
    }
}

#[async_trait]
impl EmailSender for InMemoryEmailSender {
    async fn send(&self, email: Email) -> EmailResult<()> {
        self.sent
            .lock()
            .expect("email sender mutex poisoned")
            .push(email);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct InMemoryPasswordCredentialStore {
    inner: Mutex<HashMap<UserId, PasswordCredential>>,
}

impl InMemoryPasswordCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<UserId, PasswordCredential>> {
        self.inner
            .lock()
            .expect("password credential store mutex poisoned")
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl PasswordCredentialStore for InMemoryPasswordCredentialStore {
    async fn set_password(&self, credential: PasswordCredential) -> StorageResult<()> {
        self.lock().insert(credential.user_id, credential);
        Ok(())
    }

    async fn get_password(&self, user_id: UserId) -> StorageResult<Option<PasswordCredential>> {
        Ok(self.lock().get(&user_id).cloned())
    }

    async fn delete_password(&self, user_id: UserId) -> StorageResult<()> {
        self.lock().remove(&user_id);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct InMemoryVerificationTokenStore {
    inner: Mutex<Vec<VerificationToken>>,
}

impl InMemoryVerificationTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<VerificationToken>> {
        self.inner
            .lock()
            .expect("verification token store mutex poisoned")
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

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

    async fn find_token(
        &self,
        hash: &TokenHash,
        purpose: VerificationPurpose,
    ) -> StorageResult<Option<VerificationToken>> {
        let state = self.lock();
        Ok(state
            .iter()
            .find(|t| t.token_hash == *hash && t.purpose == purpose)
            .cloned())
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

#[derive(Debug, Default)]
pub struct InMemoryPasskeyCredentialStore {
    inner: Mutex<Vec<StoredPasskey>>,
}

impl InMemoryPasskeyCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<StoredPasskey>> {
        self.inner
            .lock()
            .expect("passkey credential store mutex poisoned")
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

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
        self.inner
            .lock()
            .expect("passkey challenge store mutex poisoned")
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

#[derive(Debug, Default)]
pub struct InMemoryOAuthIdentityStore {
    inner: Mutex<Vec<OAuthIdentity>>,
}

impl InMemoryOAuthIdentityStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<OAuthIdentity>> {
        self.inner
            .lock()
            .expect("oauth identity store mutex poisoned")
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl OAuthIdentityStore for InMemoryOAuthIdentityStore {
    async fn link(&self, identity: OAuthIdentity) -> StorageResult<()> {
        let mut state = self.lock();
        if state
            .iter()
            .any(|i| i.provider == identity.provider && i.subject == identity.subject)
        {
            return Err(StorageError::msg("oauth identity already linked to a user"));
        }
        state.push(identity);
        Ok(())
    }

    async fn find_by_provider_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> StorageResult<Option<OAuthIdentity>> {
        Ok(self
            .lock()
            .iter()
            .find(|i| i.provider == provider && i.subject == subject)
            .cloned())
    }

    async fn list_for_user(&self, user_id: UserId) -> StorageResult<Vec<OAuthIdentity>> {
        Ok(self
            .lock()
            .iter()
            .filter(|i| i.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn unlink(&self, provider: &str, subject: &str) -> StorageResult<()> {
        let mut state = self.lock();
        state.retain(|i| !(i.provider == provider && i.subject == subject));
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct InMemoryOAuthStateStore {
    inner: Mutex<HashMap<OAuthStateId, PendingOAuthAuthorization>>,
}

impl InMemoryOAuthStateStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<OAuthStateId, PendingOAuthAuthorization>> {
        self.inner.lock().expect("oauth state store mutex poisoned")
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl OAuthStateStore for InMemoryOAuthStateStore {
    async fn put(&self, value: PendingOAuthAuthorization) -> StorageResult<()> {
        let mut state = self.lock();
        if state.contains_key(&value.state_id) {
            return Err(StorageError::msg("oauth state id collision"));
        }
        state.insert(value.state_id.clone(), value);
        Ok(())
    }

    async fn take(
        &self,
        state_id: &OAuthStateId,
    ) -> StorageResult<Option<PendingOAuthAuthorization>> {
        Ok(self.lock().remove(state_id))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let mut state = self.lock();
        let before = state.len();
        state.retain(|_, v| v.expires_at > now);
        Ok((before - state.len()) as u64)
    }
}

/// In-memory sliding-window-log rate limiter.
///
/// Each `(key, policy.window)` bucket keeps the timestamps of recent
/// attempts and evicts ones older than `policy.window` on every check.
/// Suitable for single-process deployments and tests; a multi-replica
/// deployment should swap in a shared backend.
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
        self.inner.lock().expect("rate limiter mutex poisoned")
    }
}

#[async_trait]
impl RateLimiter for InMemoryRateLimiter {
    async fn check(&self, key: &str, policy: RateLimitPolicy) -> StorageResult<RateLimitDecision> {
        let now = self.clock.now();
        let window = chrono::Duration::from_std(policy.window)
            .map_err(|_| StorageError::msg("rate limit window overflows chrono::Duration"))?;
        let cutoff = now - window;
        let bucket = BucketKey {
            key: key.to_owned(),
            window_ms: policy.window.as_millis(),
        };

        let mut state = self.lock();
        let entries = state.entry(bucket).or_default();
        entries.retain(|t| *t > cutoff);

        if entries.len() as u32 >= policy.max_attempts {
            let oldest = *entries.first().unwrap_or(&now);
            let retry_at = oldest + window;
            let retry_after = (retry_at - now).to_std().unwrap_or(policy.window);
            return Ok(RateLimitDecision::Limited { retry_after });
        }

        entries.push(now);
        Ok(RateLimitDecision::Allowed)
    }
}
