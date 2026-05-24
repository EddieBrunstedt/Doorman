//! In-memory implementations of every storage trait, intended for tests and
//! local experiments. Not suitable for production: data lives only as long as
//! the process and lookups hold a `std::sync::Mutex` for their duration.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::audit::{AuditEvent, AuditSink};
use crate::email::{Email, EmailSender};
use crate::error::{EmailResult, StorageError, StorageResult};
use crate::storage::{Session, SessionId, SessionStore, TokenHash, User, UserId, UserStore};

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
