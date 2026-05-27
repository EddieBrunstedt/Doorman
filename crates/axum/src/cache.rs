//! Process-local cache for session-resolution results.
//!
//! The [`SessionLayer`](crate::session::SessionLayer) runs once per request
//! that carries a session token, and without this cache it would do a
//! `SessionStore::find_session_by_token_hash` and a
//! `UserStore::find_user_by_id` on every hit — even for endpoints that
//! never actually look at `AuthUser`. Both reads typically hit the host's
//! database, so the per-request cost adds up under load.
//!
//! The cache lives entirely in `bauth-axum` because it's HTTP-shaped: the
//! TTL choice is tied to how long a request handler can tolerate staleness
//! before noticing a logout, and the trigger is "session layer just ran".
//! `bauth-core` knows nothing about it; it learns about revocations through
//! the framework-agnostic [`SessionInvalidationHook`] trait and we plug a
//! cache-flushing implementation in at builder time.
//!
//! ## Invalidation
//!
//! - On [`SessionManager::revoke`] / [`revoke_by_id`] → the cache
//!   invalidator drops the matching entry.
//! - On [`SessionManager::revoke_all_for_user`] → the cache invalidator
//!   drops every entry belonging to that user.
//! - Time-based: every entry carries an `inserted_at` and is treated as
//!   stale once the configured TTL has elapsed. TTL must be kept well below
//!   `SessionConfig::lifetime` so that a session that is revoked through a
//!   path the hook doesn't cover (e.g. someone calling
//!   `SessionStore::delete_session` directly) still expires in bounded time.
//!
//! [`SessionManager::revoke`]: bauth_core::session::SessionManager::revoke
//! [`revoke_by_id`]: bauth_core::session::SessionManager::revoke_by_id
//! [`SessionManager::revoke_all_for_user`]: bauth_core::session::SessionManager::revoke_all_for_user
//! [`SessionInvalidationHook`]: bauth_core::session::SessionInvalidationHook

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bauth_core::session::SessionInvalidationHook;
use bauth_core::storage::{Session, SessionId, TokenHash, User, UserId};
use lru::LruCache;

/// Default number of entries the cache will keep before LRU-evicting.
pub const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// Default freshness window for a cached entry. Picked to be well below
/// the typical `SessionConfig::lifetime` (30 days by default) so that a
/// revocation made through an unhooked path still self-heals quickly.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);

/// Capacity and freshness configuration for [`SessionCache`].
#[derive(Debug, Clone, Copy)]
pub struct SessionCacheConfig {
    pub capacity: NonZeroUsize,
    pub ttl: Duration,
}

impl Default for SessionCacheConfig {
    fn default() -> Self {
        Self {
            capacity: NonZeroUsize::new(DEFAULT_CACHE_CAPACITY)
                .expect("DEFAULT_CACHE_CAPACITY is non-zero"),
            ttl: DEFAULT_CACHE_TTL,
        }
    }
}

/// Pair returned from a [`SessionCache`] lookup.
#[derive(Clone)]
pub struct CachedAuth {
    pub session: Session,
    pub user: User,
}

struct Entry {
    cached: CachedAuth,
    inserted_at: Instant,
}

/// Process-local session-resolution cache. Exposed so advanced hosts and
/// benches can poke at it directly; the canonical wiring is via the
/// builder, which constructs one and installs an invalidator on the
/// `SessionManager`. Cheaply cloneable because all state lives behind
/// `Arc<Mutex<_>>`.
#[derive(Clone)]
pub struct SessionCache {
    inner: Arc<Mutex<LruCache<TokenHash, Entry>>>,
    ttl: Duration,
}

impl SessionCache {
    pub fn new(config: SessionCacheConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(config.capacity))),
            ttl: config.ttl,
        }
    }

    /// Look up a token. Returns the cached `(Session, User)` pair if one
    /// exists and is still within the TTL; otherwise returns `None` and
    /// drops any stale entry on the way out.
    pub fn get(&self, token_hash: &TokenHash) -> Option<CachedAuth> {
        let mut guard = self.inner.lock().expect("session cache lock poisoned");
        match guard.get(token_hash) {
            Some(entry) if entry.inserted_at.elapsed() <= self.ttl => Some(entry.cached.clone()),
            Some(_) => {
                guard.pop(token_hash);
                None
            }
            None => None,
        }
    }

    pub fn insert(&self, token_hash: TokenHash, session: Session, user: User) {
        let entry = Entry {
            cached: CachedAuth { session, user },
            inserted_at: Instant::now(),
        };
        self.inner
            .lock()
            .expect("session cache lock poisoned")
            .put(token_hash, entry);
    }

    /// Drop the single entry that maps to `session_id`, if any. Linear in
    /// the cache size; at capacity ~1k this is comfortably faster than the
    /// storage round-trip the cache is replacing.
    pub fn invalidate_session(&self, session_id: SessionId) {
        let mut guard = self.inner.lock().expect("session cache lock poisoned");
        let victim = guard
            .iter()
            .find(|(_, entry)| entry.cached.session.id == session_id)
            .map(|(k, _)| *k);
        if let Some(k) = victim {
            guard.pop(&k);
        }
    }

    /// Drop every entry belonging to `user_id`. Used when a user is logged
    /// out everywhere (e.g. after a password reset).
    pub fn invalidate_user(&self, user_id: UserId) {
        let mut guard = self.inner.lock().expect("session cache lock poisoned");
        let victims: Vec<TokenHash> = guard
            .iter()
            .filter(|(_, entry)| entry.cached.session.user_id == user_id)
            .map(|(k, _)| *k)
            .collect();
        for k in victims {
            guard.pop(&k);
        }
    }

    /// `SessionInvalidationHook` handle that flushes matching entries from
    /// this cache. Wire it onto the [`SessionManager`] via
    /// [`SessionManager::with_invalidation_hook`] _before_ constructing the
    /// dependent managers (password / passkey / oauth) so every clone of
    /// the session manager evicts the cache when it invalidates a session.
    ///
    /// [`SessionManager`]: bauth_core::session::SessionManager
    /// [`SessionManager::with_invalidation_hook`]: bauth_core::session::SessionManager::with_invalidation_hook
    pub fn invalidator(&self) -> Arc<dyn SessionInvalidationHook> {
        Arc::new(CacheInvalidator::new(self.clone()))
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("session cache lock poisoned")
            .len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .expect("session cache lock poisoned")
            .is_empty()
    }
}

/// `SessionInvalidationHook` implementation that flushes the matching
/// entries from a [`SessionCache`]. Construct via
/// [`SessionCache::invalidator`].
struct CacheInvalidator {
    cache: SessionCache,
}

impl CacheInvalidator {
    fn new(cache: SessionCache) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl SessionInvalidationHook for CacheInvalidator {
    async fn on_session_invalidated(&self, session_id: SessionId) {
        self.cache.invalidate_session(session_id);
    }

    async fn on_user_sessions_invalidated(&self, user_id: UserId) {
        self.cache.invalidate_user(user_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bauth_core::storage::{SessionId, TokenHash, UserId};
    use chrono::{TimeZone, Utc};

    fn token_hash(byte: u8) -> TokenHash {
        TokenHash([byte; 32])
    }

    fn make_session(user_id: UserId) -> Session {
        Session {
            id: SessionId::new(),
            user_id,
            token_hash: token_hash(0),
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            expires_at: Utc.with_ymd_and_hms(2026, 12, 31, 0, 0, 0).unwrap(),
            ip: None,
            user_agent: None,
        }
    }

    fn make_user(id: UserId) -> User {
        User {
            id,
            email: Some("u@example.com".into()),
            email_verified_at: None,
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        }
    }

    #[test]
    fn round_trip_hit() {
        let cache = SessionCache::new(SessionCacheConfig::default());
        let uid = UserId::new();
        let session = make_session(uid);
        let user = make_user(uid);
        let key = token_hash(1);
        cache.insert(key, session.clone(), user.clone());
        let hit = cache.get(&key).expect("cache hit");
        assert_eq!(hit.session, session);
        assert_eq!(hit.user, user);
    }

    #[test]
    fn miss_returns_none() {
        let cache = SessionCache::new(SessionCacheConfig::default());
        assert!(cache.get(&token_hash(7)).is_none());
    }

    #[test]
    fn ttl_zero_evicts_on_get() {
        let cache = SessionCache::new(SessionCacheConfig {
            capacity: NonZeroUsize::new(8).unwrap(),
            ttl: Duration::from_nanos(0),
        });
        let uid = UserId::new();
        let key = token_hash(2);
        cache.insert(key, make_session(uid), make_user(uid));
        // Spin for at least one nanosecond.
        std::thread::sleep(Duration::from_millis(1));
        assert!(cache.get(&key).is_none(), "ttl expired");
        assert_eq!(cache.len(), 0, "stale entry dropped on miss");
    }

    #[test]
    fn invalidate_session_drops_only_target() {
        let cache = SessionCache::new(SessionCacheConfig::default());
        let uid = UserId::new();
        let s1 = make_session(uid);
        let s2 = make_session(uid);
        cache.insert(token_hash(3), s1.clone(), make_user(uid));
        cache.insert(token_hash(4), s2.clone(), make_user(uid));
        cache.invalidate_session(s1.id);
        assert!(cache.get(&token_hash(3)).is_none());
        assert!(cache.get(&token_hash(4)).is_some());
    }

    #[test]
    fn invalidate_user_drops_all_entries_for_user() {
        let cache = SessionCache::new(SessionCacheConfig::default());
        let alice = UserId::new();
        let bob = UserId::new();
        cache.insert(token_hash(5), make_session(alice), make_user(alice));
        cache.insert(token_hash(6), make_session(alice), make_user(alice));
        cache.insert(token_hash(7), make_session(bob), make_user(bob));
        cache.invalidate_user(alice);
        assert!(cache.get(&token_hash(5)).is_none());
        assert!(cache.get(&token_hash(6)).is_none());
        assert!(cache.get(&token_hash(7)).is_some());
    }

    #[test]
    fn lru_eviction_under_capacity_pressure() {
        let cache = SessionCache::new(SessionCacheConfig {
            capacity: NonZeroUsize::new(2).unwrap(),
            ttl: DEFAULT_CACHE_TTL,
        });
        let uid = UserId::new();
        cache.insert(token_hash(10), make_session(uid), make_user(uid));
        cache.insert(token_hash(11), make_session(uid), make_user(uid));
        // Touch 10 so it becomes MRU; inserting a third entry should evict 11.
        let _ = cache.get(&token_hash(10));
        cache.insert(token_hash(12), make_session(uid), make_user(uid));
        assert!(cache.get(&token_hash(10)).is_some());
        assert!(cache.get(&token_hash(11)).is_none());
        assert!(cache.get(&token_hash(12)).is_some());
    }
}
