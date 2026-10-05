//! Process-local cache for session-resolution results.
//!
//! Resolving a session token to its `Session` + `User` pair means a
//! `SessionStore::find_session_by_token_hash` followed by a
//! `UserStore::find_user_by_id`. A front end that runs that resolution on
//! every request carrying a token — even for endpoints that never look at the
//! resolved user — pays both reads each time, and both typically hit the
//! host's database. This cache short-circuits that hot path with an
//! in-process LRU keyed by token hash.
//!
//! The cache is owned by the [`SessionResolver`], which constructs one,
//! installs its invalidator on the [`SessionManager`], and is the only code
//! that reads or seeds entries on the request path. Core learns about
//! revocations through the session manager's invalidation hook, which the
//! resolver points at this cache.
//!
//! ## Invalidation
//!
//! - On [`SessionManager::revoke`] / [`revoke_by_id`] → the cache
//!   invalidator drops the matching entry.
//! - On [`SessionManager::revoke_all_for_user`] → the cache invalidator
//!   drops every entry belonging to that user.
//! - On a change to a user's record (a new or newly verified email) → the
//!   cache invalidator drops every entry belonging to that user without
//!   revoking anything, so the next request re-reads the user.
//! - Time-based: every entry carries an `inserted_at` read from the domain
//!   [`Clock`] and is treated as stale once the configured TTL has elapsed.
//!   TTL must be kept well below [`SessionConfig::absolute_lifetime`] so that
//!   a session that is revoked through a path the hook doesn't cover (e.g.
//!   someone calling `SessionStore::delete_session` directly) still expires
//!   in bounded time. How the TTL relates to the idle timeout is documented
//!   on [`SessionResolver`].
//!
//! ## Sharding
//!
//! The cache is split into `SHARD_COUNT` independent `Mutex<LruCache>`
//! shards, selected by the top byte of the (uniformly distributed) token
//! hash. Lookups on distinct tokens almost always land in different shards,
//! so they take different locks and do not serialize against one another —
//! only collisions within a single shard contend. The configured capacity
//! is divided evenly across the shards.
//!
//! [`Clock`]: crate::clock::Clock
//! [`SessionResolver`]: crate::resolve::SessionResolver
//! [`SessionManager`]: crate::session::SessionManager
//! [`SessionManager::revoke`]: crate::session::SessionManager::revoke
//! [`revoke_by_id`]: crate::session::SessionManager::revoke_by_id
//! [`SessionManager::revoke_all_for_user`]: crate::session::SessionManager::revoke_all_for_user
//! [`SessionConfig::absolute_lifetime`]: crate::session::SessionConfig::absolute_lifetime

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lru::LruCache;

use crate::clock::Clock;
use crate::session::SessionInvalidationHook;
use crate::storage::{Session, SessionId, TokenHash, User, UserId};
use crate::sync;

/// Number of independent lock-striped shards the cache is split across.
/// A power of two so the shard index is a cheap mask of the token-hash
/// prefix byte.
pub(crate) const SHARD_COUNT: usize = 16;

/// Default number of entries the cache will keep before LRU-evicting.
// The `unwrap` runs in const evaluation: a zero here fails the build, never
// a running host.
pub const DEFAULT_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

/// Default freshness window for a cached entry. Picked to be well below
/// the typical `SessionConfig::absolute_lifetime` (30 days by default) so that a
/// revocation made through an unhooked path still self-heals quickly.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);

/// Capacity and freshness configuration for [`SessionCache`].
#[derive(Debug, Clone, Copy)]
pub struct SessionCacheConfig {
    /// Maximum number of resolved sessions to keep cached (across all shards).
    pub capacity: NonZeroUsize,
    /// How long a cached entry stays fresh before it is re-resolved. A zero
    /// TTL disables caching: every lookup misses.
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

/// Resolved authentication pair returned from a [`SessionCache`] lookup.
///
/// The [`Session`] and [`User`] are each held behind an [`Arc`] so a cache
/// hit hands back a refcount bump rather than a deep clone — the whole
/// `CachedAuth` is itself shared as an `Arc` and threaded straight into the
/// front end's per-request context.
pub struct CachedAuth {
    /// The resolved session.
    pub session: Arc<Session>,
    /// The resolved user.
    pub user: Arc<User>,
}

struct Entry {
    cached: Arc<CachedAuth>,
    inserted_at: DateTime<Utc>,
}

/// One lock-striped shard of the cache.
struct Shard {
    inner: Mutex<LruCache<TokenHash, Entry>>,
}

/// Process-local session-resolution cache. Owned by the
/// [`SessionResolver`](crate::resolve::SessionResolver), which constructs one
/// and installs its invalidator on the `SessionManager`; reach it through
/// [`SessionResolver::cache`](crate::resolve::SessionResolver::cache) to
/// inspect or flush it. Cheaply cloneable because all state lives behind
/// `Arc`.
#[derive(Clone)]
pub struct SessionCache {
    shards: Arc<[Shard; SHARD_COUNT]>,
    ttl: Duration,
    clock: Arc<dyn Clock>,
}

impl SessionCache {
    /// Build a sharded session cache from the given capacity/TTL config.
    /// Entry freshness is measured on `clock`, the same domain clock the
    /// session manager judges expiry by.
    pub(crate) fn new(config: SessionCacheConfig, clock: Arc<dyn Clock>) -> Self {
        // Divide the configured capacity across the shards, keeping at least
        // one slot per shard so a tiny configured capacity still functions.
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

    /// The configured freshness window.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Whether an entry inserted at `inserted_at` is still fresh at `now`.
    /// An insert stamped in the future (the clock stepped backwards) counts
    /// as stale, so a clock step can never extend an entry's life.
    fn is_fresh(&self, inserted_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        (now - inserted_at)
            .to_std()
            .is_ok_and(|elapsed| elapsed < self.ttl)
    }

    /// Pick the shard a token hash belongs to from its leading byte. The
    /// hash is a SHA-256 digest, so the prefix is uniformly distributed and
    /// spreads keys evenly across shards.
    fn shard(&self, token_hash: &TokenHash) -> &Shard {
        let idx = (token_hash.0[0] as usize) & (SHARD_COUNT - 1);
        &self.shards[idx]
    }

    /// Look up a token. Returns the cached pair if one exists and is still
    /// within the TTL; otherwise returns `None` and drops any stale entry on
    /// the way out. The returned `Arc<CachedAuth>` is a refcount bump, not a
    /// deep copy of the session/user.
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

    /// Cache a freshly-resolved session/user pair under its token hash.
    pub(crate) fn insert(&self, token_hash: TokenHash, session: Arc<Session>, user: Arc<User>) {
        let entry = Entry {
            cached: Arc::new(CachedAuth { session, user }),
            inserted_at: self.clock.now(),
        };
        sync::lock(&self.shard(&token_hash).inner).put(token_hash, entry);
    }

    /// Drop the single entry that maps to `session_id`, if any. Scans every
    /// shard since the lookup is by session id, not token hash; linear in
    /// the cache size, which at the default capacity is comfortably faster
    /// than the storage round-trip the cache is replacing.
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

    /// Drop every entry belonging to `user_id`. Used when a user is logged
    /// out everywhere or their record changes. Scans every shard.
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

    /// `SessionInvalidationHook` handle that flushes matching entries from
    /// this cache. Install it on the [`SessionManager`] via
    /// [`set_invalidation_hook`]; because the manager shares its hook across
    /// every clone, the order of installation relative to constructing the
    /// dependent managers (passkey / signup) does not matter — every clone
    /// evicts the cache when it invalidates a session.
    ///
    /// [`SessionManager`]: crate::session::SessionManager
    /// [`set_invalidation_hook`]: crate::session::SessionManager::set_invalidation_hook
    pub(crate) fn invalidator(&self) -> Arc<dyn SessionInvalidationHook> {
        Arc::new(CacheInvalidator::new(self.clone()))
    }

    /// Total number of cached entries across all shards. Test-only.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| sync::lock(&shard.inner).len())
            .sum()
    }

    /// Whether the cache holds no entries. Test-only.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    async fn on_user_invalidated(&self, user_id: UserId) {
        self.cache.invalidate_user(user_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{AccountStatus, SessionId, TokenHash, UserId};
    use chrono::TimeZone;

    /// Settable clock, so a test drives TTL expiry without sleeping.
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

    /// Build a token hash whose shard is fixed by `shard_byte` (the leading
    /// byte) but is otherwise distinct via `salt`. Lets a test place several
    /// keys in the *same* shard to exercise per-shard LRU eviction.
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
        // capacity 32 over SHARD_COUNT (16) shards => 2 slots per shard. All
        // three keys share shard 0 (same leading byte) so they contend for
        // the same two slots and exercise per-shard LRU eviction.
        let cache = cache_with(SessionCacheConfig {
            capacity: NonZeroUsize::new(SHARD_COUNT * 2).expect("non-zero capacity"),
            ttl: DEFAULT_CACHE_TTL,
        });
        let uid = UserId::new();
        let (a, b, c) = (keyed(0, 1), keyed(0, 2), keyed(0, 3));
        cache.insert(a, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        cache.insert(b, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        // Touch `a` so it becomes MRU; inserting a third entry should evict `b`.
        let _ = cache.get(&a);
        cache.insert(c, Arc::new(make_session(uid)), Arc::new(make_user(uid)));
        assert!(cache.get(&a).is_some());
        assert!(cache.get(&b).is_none());
        assert!(cache.get(&c).is_some());
    }

    #[test]
    fn keys_spread_across_shards_do_not_share_capacity() {
        // Two keys in different shards both survive even when the per-shard
        // capacity is 1 — independent shards mean no cross-shard eviction.
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
