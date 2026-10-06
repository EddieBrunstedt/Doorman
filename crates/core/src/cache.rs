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

// The ttl is how long another process may keep serving a revoked session or a
// changed user, so it stays short.
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
    config: SessionCacheConfig,
    sessions: bool,
}

impl SessionCachePolicy {
    pub const fn users_only(config: SessionCacheConfig) -> Self {
        Self {
            config,
            sessions: false,
        }
    }

    pub const fn full(config: SessionCacheConfig) -> Self {
        Self {
            config,
            sessions: true,
        }
    }

    pub(crate) fn config(&self) -> SessionCacheConfig {
        self.config
    }
}

pub struct CachedAuth {
    pub session: Arc<Session>,
    pub user: Arc<User>,
}

trait ShardKey: std::hash::Hash + Eq + Copy {
    fn shard(&self) -> usize;
}

impl ShardKey for TokenHash {
    fn shard(&self) -> usize {
        (self.0[0] as usize) & (SHARD_COUNT - 1)
    }
}

impl ShardKey for UserId {
    fn shard(&self) -> usize {
        (self.0.as_bytes()[15] as usize) & (SHARD_COUNT - 1)
    }
}

struct Entry<V> {
    value: V,
    inserted_at: DateTime<Utc>,
}

struct Shards<K, V> {
    shards: [Mutex<LruCache<K, Entry<V>>>; SHARD_COUNT],
}

impl<K: ShardKey, V: Clone> Shards<K, V> {
    fn new(capacity: NonZeroUsize) -> Self {
        let per_shard =
            NonZeroUsize::new(capacity.get().div_ceil(SHARD_COUNT)).unwrap_or(NonZeroUsize::MIN);
        Self {
            shards: std::array::from_fn(|_| Mutex::new(LruCache::new(per_shard))),
        }
    }

    fn get(&self, key: &K, is_fresh: impl Fn(DateTime<Utc>) -> bool) -> Option<V> {
        let mut guard = sync::lock(&self.shards[key.shard()]);
        match guard.get(key) {
            Some(entry) if is_fresh(entry.inserted_at) => Some(entry.value.clone()),
            Some(_) => {
                guard.pop(key);
                None
            }
            None => None,
        }
    }

    fn insert(&self, key: K, value: V, inserted_at: DateTime<Utc>) {
        sync::lock(&self.shards[key.shard()]).put(key, Entry { value, inserted_at });
    }

    fn remove(&self, key: &K) {
        sync::lock(&self.shards[key.shard()]).pop(key);
    }

    fn remove_where(&self, doomed: impl Fn(&V) -> bool) {
        for shard in &self.shards {
            let mut guard = sync::lock(shard);
            let victims: Vec<K> = guard
                .iter()
                .filter(|(_, entry)| doomed(&entry.value))
                .map(|(k, _)| *k)
                .collect();
            for k in victims {
                guard.pop(&k);
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| sync::lock(shard).len())
            .sum()
    }
}

#[derive(Clone)]
pub struct SessionCache {
    users: Arc<Shards<UserId, Arc<User>>>,
    sessions: Option<Arc<Shards<TokenHash, Arc<Session>>>>,
    ttl: Duration,
    clock: Arc<dyn Clock>,
}

impl SessionCache {
    pub(crate) fn new(policy: SessionCachePolicy, clock: Arc<dyn Clock>) -> Self {
        let config = policy.config();
        Self {
            users: Arc::new(Shards::new(config.capacity)),
            sessions: policy
                .sessions
                .then(|| Arc::new(Shards::new(config.capacity))),
            ttl: config.ttl,
            clock,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub(crate) fn caches_sessions(&self) -> bool {
        self.sessions.is_some()
    }

    fn is_fresh(&self, inserted_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        (now - inserted_at)
            .to_std()
            .is_ok_and(|elapsed| elapsed < self.ttl)
    }

    pub fn get(&self, token_hash: &TokenHash) -> Option<CachedAuth> {
        let session = self.session(token_hash)?;
        let user = self.user(session.user_id)?;
        Some(CachedAuth { session, user })
    }

    pub(crate) fn session(&self, token_hash: &TokenHash) -> Option<Arc<Session>> {
        let now = self.clock.now();
        self.sessions
            .as_ref()?
            .get(token_hash, |inserted_at| self.is_fresh(inserted_at, now))
    }

    pub(crate) fn user(&self, user_id: UserId) -> Option<Arc<User>> {
        let now = self.clock.now();
        self.users
            .get(&user_id, |inserted_at| self.is_fresh(inserted_at, now))
    }

    pub(crate) fn insert_session(&self, token_hash: TokenHash, session: Arc<Session>) {
        if let Some(sessions) = &self.sessions {
            sessions.insert(token_hash, session, self.clock.now());
        }
    }

    pub(crate) fn insert_user(&self, user: Arc<User>) {
        self.users.insert(user.id, user, self.clock.now());
    }

    pub fn invalidate_session(&self, session_id: SessionId) {
        if let Some(sessions) = &self.sessions {
            sessions.remove_where(|session| session.id == session_id);
        }
    }

    pub fn invalidate_user(&self, user_id: UserId) {
        self.users.remove(&user_id);
        if let Some(sessions) = &self.sessions {
            sessions.remove_where(|session| session.user_id == user_id);
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.users.len() + self.sessions.as_ref().map_or(0, |sessions| sessions.len())
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
        SessionCache::new(SessionCachePolicy::full(config), test_clock())
    }

    fn put(cache: &SessionCache, key: TokenHash, session: Session, user: User) {
        cache.insert_user(Arc::new(user));
        cache.insert_session(key, Arc::new(session));
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
        put(&cache, key, session.clone(), user.clone());
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
            SessionCachePolicy::full(SessionCacheConfig {
                capacity: NonZeroUsize::new(8).expect("non-zero capacity"),
                ttl: Duration::from_secs(60),
            }),
            clock.clone(),
        );
        let uid = UserId::new();
        let key = token_hash(2);
        put(&cache, key, make_session(uid), make_user(uid));
        clock.advance(Duration::from_secs(59));
        assert!(cache.get(&key).is_some(), "still fresh inside the ttl");
        clock.advance(Duration::from_secs(1));
        assert!(cache.get(&key).is_none(), "ttl expired");
        assert!(cache.user(uid).is_none(), "the user entry expires too");
        assert_eq!(cache.len(), 0, "stale entries dropped on miss");
    }

    #[test]
    fn zero_ttl_disables_caching() {
        let cache = cache_with(SessionCacheConfig {
            ttl: Duration::ZERO,
            ..SessionCacheConfig::default()
        });
        let uid = UserId::new();
        let key = token_hash(8);
        put(&cache, key, make_session(uid), make_user(uid));
        assert!(cache.get(&key).is_none(), "a zero ttl never serves a hit");
    }

    #[test]
    fn clock_stepping_backwards_makes_entries_stale() {
        let clock = test_clock();
        let cache = SessionCache::new(
            SessionCachePolicy::full(SessionCacheConfig::default()),
            clock.clone(),
        );
        let uid = UserId::new();
        let key = token_hash(9);
        clock.advance(Duration::from_secs(3600));
        put(&cache, key, make_session(uid), make_user(uid));
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
        put(&cache, token_hash(3), s1.clone(), make_user(uid));
        put(&cache, token_hash(4), s2.clone(), make_user(uid));
        cache.invalidate_session(s1.id);
        assert!(cache.get(&token_hash(3)).is_none());
        assert!(cache.get(&token_hash(4)).is_some());
    }

    #[test]
    fn invalidate_user_drops_all_entries_for_user() {
        let cache = cache_with(SessionCacheConfig::default());
        let alice = UserId::new();
        let bob = UserId::new();
        put(&cache, token_hash(5), make_session(alice), make_user(alice));
        put(&cache, token_hash(6), make_session(alice), make_user(alice));
        put(&cache, token_hash(7), make_session(bob), make_user(bob));
        cache.invalidate_user(alice);
        assert!(cache.get(&token_hash(5)).is_none());
        assert!(cache.get(&token_hash(6)).is_none());
        assert!(cache.get(&token_hash(7)).is_some());
    }

    #[test]
    fn users_only_never_serves_a_session() {
        let cache = SessionCache::new(
            SessionCachePolicy::users_only(SessionCacheConfig::default()),
            test_clock(),
        );
        let uid = UserId::new();
        let key = token_hash(10);
        put(&cache, key, make_session(uid), make_user(uid));
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.user(uid).as_deref(), Some(&make_user(uid)));
    }

    #[test]
    fn lru_eviction_under_capacity_pressure() {
        let cache = cache_with(SessionCacheConfig {
            capacity: NonZeroUsize::new(SHARD_COUNT * 2).expect("non-zero capacity"),
            ttl: DEFAULT_CACHE_TTL,
        });
        let uid = UserId::new();
        let (a, b, c) = (keyed(0, 1), keyed(0, 2), keyed(0, 3));
        put(&cache, a, make_session(uid), make_user(uid));
        put(&cache, b, make_session(uid), make_user(uid));
        let _ = cache.get(&a);
        put(&cache, c, make_session(uid), make_user(uid));
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
        put(&cache, k0, make_session(uid), make_user(uid));
        put(&cache, k1, make_session(uid), make_user(uid));
        assert!(cache.get(&k0).is_some());
        assert!(cache.get(&k1).is_some());
    }
}
