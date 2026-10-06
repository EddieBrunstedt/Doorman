use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use lru::LruCache;

use crate::clock::Clock;
use crate::storage::{Session, SessionId, TokenHash, User, UserId};
use crate::sync;

pub(crate) const SHARD_COUNT: usize = 16;

pub const DEFAULT_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);

// The ttl is how long another process may keep serving a revoked session, so
// it stays short.
pub const MAX_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy)]
pub struct SessionCacheConfig {
    pub capacity: NonZeroUsize,
    pub ttl: Duration,
}

impl Default for SessionCacheConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CACHE_CAPACITY,
            ttl: DEFAULT_CACHE_TTL,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionCachePolicy {
    config: Option<SessionCacheConfig>,
}

impl SessionCachePolicy {
    pub const fn disabled() -> Self {
        Self { config: None }
    }

    pub const fn per_process(config: SessionCacheConfig) -> Self {
        Self {
            config: Some(config),
        }
    }

    pub(crate) fn config(self) -> Option<SessionCacheConfig> {
        self.config
    }
}

pub struct CachedAuth {
    pub session: Arc<Session>,
    pub user: Arc<User>,
}

struct Entry {
    cached: Arc<CachedAuth>,
    inserted_at: DateTime<Utc>,
}

struct Shard {
    inner: Mutex<LruCache<TokenHash, Entry>>,
}

#[derive(Clone)]
pub struct SessionCache {
    shards: Arc<[Shard; SHARD_COUNT]>,
    ttl: Duration,
    clock: Arc<dyn Clock>,
}

impl SessionCache {
    pub(crate) fn new(config: SessionCacheConfig, clock: Arc<dyn Clock>) -> Self {
        let per_shard = NonZeroUsize::new(config.capacity.get().div_ceil(SHARD_COUNT))
            .unwrap_or(NonZeroUsize::MIN);
        let shards = std::array::from_fn(|_| Shard {
            inner: Mutex::new(LruCache::new(per_shard)),
        });
        Self {
            shards: Arc::new(shards),
            ttl: config.ttl,
            clock,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    fn is_fresh(&self, inserted_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        (now - inserted_at)
            .to_std()
            .is_ok_and(|elapsed| elapsed < self.ttl)
    }

    fn shard(&self, token_hash: &TokenHash) -> &Shard {
        let idx = (token_hash.0[0] as usize) & (SHARD_COUNT - 1);
        &self.shards[idx]
    }

    pub fn get(&self, token_hash: &TokenHash) -> Option<Arc<CachedAuth>> {
        let mut guard = sync::lock(&self.shard(token_hash).inner);
        let now = self.clock.now();
        match guard.get(token_hash) {
            Some(entry) if self.is_fresh(entry.inserted_at, now) => Some(entry.cached.clone()),
            Some(_) => {
                guard.pop(token_hash);
                None
            }
            None => None,
        }
    }

    pub(crate) fn insert(&self, token_hash: TokenHash, session: Arc<Session>, user: Arc<User>) {
        let entry = Entry {
            cached: Arc::new(CachedAuth { session, user }),
            inserted_at: self.clock.now(),
        };
        sync::lock(&self.shard(&token_hash).inner).put(token_hash, entry);
    }

    pub fn invalidate_session(&self, session_id: SessionId) {
        for shard in self.shards.iter() {
            let mut guard = sync::lock(&shard.inner);
            let victim = guard
                .iter()
                .find(|(_, entry)| entry.cached.session.id == session_id)
                .map(|(k, _)| *k);
            if let Some(k) = victim {
                guard.pop(&k);
                return;
            }
        }
    }

    pub fn invalidate_user(&self, user_id: UserId) {
        for shard in self.shards.iter() {
            let mut guard = sync::lock(&shard.inner);
            let victims: Vec<TokenHash> = guard
                .iter()
                .filter(|(_, entry)| entry.cached.session.user_id == user_id)
                .map(|(k, _)| *k)
                .collect();
            for k in victims {
                guard.pop(&k);
            }
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| sync::lock(&shard.inner).len())
            .sum()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{AccountStatus, SessionId, TokenHash, UserId};
    use chrono::TimeZone;

    struct TestClock(Mutex<DateTime<Utc>>);

    impl TestClock {
        fn advance(&self, by: Duration) {
            let mut now = self.0.lock().expect("test clock lock");
            *now += chrono::Duration::from_std(by).expect("test advance fits chrono");
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().expect("test clock lock")
        }
    }

    fn test_clock() -> Arc<TestClock> {
        Arc::new(TestClock(Mutex::new(
            Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
        )))
    }

    fn cache_with(config: SessionCacheConfig) -> SessionCache {
        SessionCache::new(config, test_clock())
    }

    fn token_hash(byte: u8) -> TokenHash {
        TokenHash([byte; 32])
    }

    fn keyed(shard_byte: u8, salt: u8) -> TokenHash {
        let mut bytes = [0u8; 32];
        bytes[0] = shard_byte;
        bytes[1] = salt;
        TokenHash(bytes)
    }

    fn make_session(user_id: UserId) -> Session {
        Session {
            id: SessionId::new(),
            user_id,
            token_hash: token_hash(0),
            created_at: Utc
                .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            last_used_at: Utc
                .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            expires_at: Utc
                .with_ymd_and_hms(2026, 12, 31, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            ip: None,
            user_agent: None,
            recovery_cooldown_until: None,
        }
    }

    fn make_user(id: UserId) -> User {
        User {
            id,
            email: Some("u@example.com".into()),
            email_verified_at: None,
            status: AccountStatus::Active,
            created_at: Utc
                .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            updated_at: Utc
                .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
        }
    }

    #[test]
    fn round_trip_hit() {
        let cache = cache_with(SessionCacheConfig::default());
        let uid = UserId::new();
        let session = make_session(uid);
        let user = make_user(uid);
        let key = token_hash(1);
        cache.insert(key, Arc::new(session.clone()), Arc::new(user.clone()));
        let hit = cache.get(&key).expect("cache hit");
        assert_eq!(*hit.session, session);
        assert_eq!(*hit.user, user);
    }

    #[test]
    fn miss_returns_none() {
        let cache = cache_with(SessionCacheConfig::default());
        assert!(cache.get(&token_hash(7)).is_none());
    }

    #[test]
    fn stale_entry_evicts_on_get() {
        let clock = test_clock();
        let cache = SessionCache::new(
            SessionCacheConfig {
                capacity: NonZeroUsize::new(8).expect("non-zero capacity"),
                ttl: Duration::from_secs(60),
            },
            clock.clone(),
        );
        let uid = UserId::new();
        let key = token_hash(2);
        cache.insert(key, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        clock.advance(Duration::from_secs(59));
        assert!(cache.get(&key).is_some(), "still fresh inside the ttl");
        clock.advance(Duration::from_secs(1));
        assert!(cache.get(&key).is_none(), "ttl expired");
        assert_eq!(cache.len(), 0, "stale entry dropped on miss");
    }

    #[test]
    fn zero_ttl_disables_caching() {
        let cache = cache_with(SessionCacheConfig {
            ttl: Duration::ZERO,
            ..SessionCacheConfig::default()
        });
        let uid = UserId::new();
        let key = token_hash(8);
        cache.insert(key, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        assert!(cache.get(&key).is_none(), "a zero ttl never serves a hit");
    }

    #[test]
    fn clock_stepping_backwards_makes_entries_stale() {
        let clock = test_clock();
        let cache = SessionCache::new(SessionCacheConfig::default(), clock.clone());
        let uid = UserId::new();
        let key = token_hash(9);
        clock.advance(Duration::from_secs(3600));
        cache.insert(key, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        *clock.0.lock().expect("test clock lock") -= chrono::Duration::seconds(1);
        assert!(
            cache.get(&key).is_none(),
            "an entry stamped in the future is not served",
        );
    }

    #[test]
    fn invalidate_session_drops_only_target() {
        let cache = cache_with(SessionCacheConfig::default());
        let uid = UserId::new();
        let s1 = make_session(uid);
        let s2 = make_session(uid);
        cache.insert(
            token_hash(3),
            Arc::new(s1.clone()),
            Arc::new(make_user(uid)),
        );
        cache.insert(
            token_hash(4),
            Arc::new(s2.clone()),
            Arc::new(make_user(uid)),
        );
        cache.invalidate_session(s1.id);
        assert!(cache.get(&token_hash(3)).is_none());
        assert!(cache.get(&token_hash(4)).is_some());
    }

    #[test]
    fn invalidate_user_drops_all_entries_for_user() {
        let cache = cache_with(SessionCacheConfig::default());
        let alice = UserId::new();
        let bob = UserId::new();
        cache.insert(
            token_hash(5),
            Arc::new(make_session(alice)),
            Arc::new(make_user(alice)),
        );
        cache.insert(
            token_hash(6),
            Arc::new(make_session(alice)),
            Arc::new(make_user(alice)),
        );
        cache.insert(
            token_hash(7),
            Arc::new(make_session(bob)),
            Arc::new(make_user(bob)),
        );
        cache.invalidate_user(alice);
        assert!(cache.get(&token_hash(5)).is_none());
        assert!(cache.get(&token_hash(6)).is_none());
        assert!(cache.get(&token_hash(7)).is_some());
    }

    #[test]
    fn lru_eviction_under_capacity_pressure() {
        let cache = cache_with(SessionCacheConfig {
            capacity: NonZeroUsize::new(SHARD_COUNT * 2).expect("non-zero capacity"),
            ttl: DEFAULT_CACHE_TTL,
        });
        let uid = UserId::new();
        let (a, b, c) = (keyed(0, 1), keyed(0, 2), keyed(0, 3));
        cache.insert(a, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        cache.insert(b, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        let _ = cache.get(&a);
        cache.insert(c, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        assert!(cache.get(&a).is_some());
        assert!(cache.get(&b).is_none());
        assert!(cache.get(&c).is_some());
    }

    #[test]
    fn keys_spread_across_shards_do_not_share_capacity() {
        let cache = cache_with(SessionCacheConfig {
            capacity: NonZeroUsize::new(SHARD_COUNT).expect("non-zero capacity"),
            ttl: DEFAULT_CACHE_TTL,
        });
        let uid = UserId::new();
        let (k0, k1) = (keyed(0, 0), keyed(1, 0));
        cache.insert(k0, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        cache.insert(k1, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        assert!(cache.get(&k0).is_some());
        assert!(cache.get(&k1).is_some());
    }
}
