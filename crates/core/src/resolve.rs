//! Request-time session resolution: turn a session token into the live
//! `(user, session)` pair, or a typed refusal.
//!
//! [`SessionResolver::resolve`] is the one operation a front end runs per
//! request. Behind it sit the process-local [`SessionCache`], the
//! effective-expiry re-check on a cache hit, the session and user lookups on
//! a miss, the account-status gate login also uses, and the idle-deadline
//! slide. The front end only reads the token off the request, calls
//! `resolve`, and — when [`ResolvedSession::slid`] is set — refreshes
//! whatever client-side expiry it mirrors (a cookie `Max-Age`, say).
//!
//! # Cache TTL and the idle timeout
//!
//! A cache hit serves the request without reading storage, so it cannot
//! slide the idle deadline: sliding happens only on a miss, and a
//! continuously active session misses once per cache TTL. Two rules follow,
//! and this module is the one place they are enforced:
//!
//! - **The TTL must be strictly below the idle timeout.** Otherwise an active
//!   user's session could idle out in storage while every request is served
//!   from a warm entry — a silent logout. [`SessionResolver::new`] rejects
//!   such a configuration with [`AssemblyError::IdleTimeoutInvalid`]; a
//!   comfortable margin such as `ttl <= idle_timeout / 2` is recommended.
//! - **The touch throttle is the TTL.** A miss writes the slid deadline only
//!   when the session was last touched at least one TTL ago, so an active
//!   session writes at most once per TTL window.
//!
//! A warm entry is still never served past its session's deadline: a hit
//! whose cached `expires_at` has passed is treated as a miss.

use std::sync::Arc;

use crate::assembly::AssemblyError;
use crate::cache::{SessionCache, SessionCacheConfig};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::metrics::{MetricEvent, MetricSink, NoopMetricSink};
use crate::session::{SessionManager, hash_token};
use crate::storage::{Session, User, UserId, UserStore};

/// A request's resolved authentication state.
///
/// The user and session are shared with the cache, so a hit hands back
/// refcount bumps rather than deep clones.
#[derive(Clone)]
pub struct ResolvedSession {
    /// The session's owner, checked active when it was read from storage.
    pub user: Arc<User>,
    /// The live session.
    pub session: Arc<Session>,
    /// Whether this resolution slid the idle deadline forward. A front end
    /// that mirrors the deadline client-side (a cookie `Max-Age`) refreshes
    /// it when this is set; nothing else changed when it is not.
    pub slid: bool,
}

/// Resolves session tokens for a front end's request path.
///
/// Built once at the composition root —
/// [`AuthCore::builder`](crate::assembly::AuthCore::builder) does it for you.
/// Cheap to clone: every field is `Arc`-backed.
#[derive(Clone)]
pub struct SessionResolver {
    sessions: SessionManager,
    users: Arc<dyn UserStore>,
    cache: SessionCache,
    metrics: Arc<dyn MetricSink>,
}

impl SessionResolver {
    /// Build a resolver over `sessions` and `users`, with a cache configured
    /// by `cache`.
    ///
    /// Installs the cache's invalidator on `sessions`, replacing any hook
    /// already there. The hook cell is shared by every clone of the manager,
    /// so revocations through any clone — logout, revoke-all, operator
    /// disable — evict the cache.
    ///
    /// Returns [`AssemblyError::IdleTimeoutInvalid`] when an idle timeout is
    /// configured and the cache TTL is not strictly below it (see the
    /// [module docs](self)).
    pub fn new(
        sessions: SessionManager,
        users: Arc<dyn UserStore>,
        cache: SessionCacheConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        if let Some(idle_timeout) = sessions.idle_timeout()
            && cache.ttl >= idle_timeout
        {
            return Err(AssemblyError::IdleTimeoutInvalid {
                idle_timeout,
                reason: "must be strictly greater than the cache ttl so a cache-miss touch can slide the session before it idles out",
            });
        }
        let cache = SessionCache::new(cache, sessions.clock().clone());
        sessions.set_invalidation_hook(cache.invalidator());
        Ok(Self {
            sessions,
            users,
            cache,
            metrics: Arc::new(NoopMetricSink),
        })
    }

    /// Report cache hits and misses to `metrics` and return `self`. Defaults
    /// to [`NoopMetricSink`].
    pub fn with_metrics(mut self, metrics: Arc<dyn MetricSink>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Resolve a plaintext session token.
    ///
    /// A fresh cache entry whose session is still within its deadline is
    /// served as-is. Otherwise the session and its owner are read from
    /// storage, the owner's account status is checked, the idle deadline is
    /// slid when due, and the pair is cached.
    ///
    /// # Errors
    ///
    /// - [`Error::SessionNotFound`] — no session has this token (never
    ///   issued, revoked, or purged).
    /// - [`Error::SessionExpired`] — the session is past its deadline.
    /// - [`Error::UserNotFound`] — the session's owner no longer exists.
    /// - [`Error::AccountDisabled`] — the owner's account is disabled. A
    ///   front end should surface this distinctly from "not signed in".
    /// - [`Error::Storage`] — a store failed.
    ///
    /// A refused session is never cached.
    #[tracing::instrument(
        skip_all,
        fields(session_id = tracing::field::Empty, user_id = tracing::field::Empty),
    )]
    pub async fn resolve(&self, token: &str) -> Result<ResolvedSession> {
        let token_hash = hash_token(token);
        let now = self.sessions.clock().now();
        let span = tracing::Span::current();

        // An entry whose session deadline has passed is a miss even while the
        // entry itself is fresh, so an expired session is never served warm.
        if let Some(cached) = self
            .cache
            .get(&token_hash)
            .filter(|cached| cached.session.expires_at > now)
        {
            self.metrics.record(MetricEvent::CacheHit);
            span.record("session_id", tracing::field::display(cached.session.id));
            span.record("user_id", tracing::field::display(cached.user.id));
            return Ok(ResolvedSession {
                user: cached.user.clone(),
                session: cached.session.clone(),
                slid: false,
            });
        }
        self.metrics.record(MetricEvent::CacheMiss);

        let session = self.sessions.validate_by_hash(&token_hash).await?;
        span.record("session_id", tracing::field::display(session.id));
        span.record("user_id", tracing::field::display(session.user_id));
        let user = find_active_user(self.users.as_ref(), session.user_id).await?;
        let (session, slid) = self.sessions.slide(session, now, self.cache.ttl()).await;

        let session = Arc::new(session);
        let user = Arc::new(user);
        self.cache.insert(token_hash, session.clone(), user.clone());
        Ok(ResolvedSession {
            user,
            session,
            slid,
        })
    }

    /// The clock the resolver judges expiry by — the session manager's.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        self.sessions.clock()
    }

    /// The resolver's cache, for observability and benches. Request handling
    /// never needs to reach into it.
    pub fn cache(&self) -> &SessionCache {
        &self.cache
    }
}

/// Load `user_id` and require its account to be active: the account-status
/// gate shared by login
/// ([`PasskeyManager::finish_authentication`](crate::passkey::PasskeyManager::finish_authentication))
/// and [`SessionResolver::resolve`].
///
/// Returns [`Error::UserNotFound`] for a missing user and
/// [`Error::AccountDisabled`] for one that is not
/// [`active`](crate::storage::AccountStatus::is_active).
pub(crate) async fn find_active_user(users: &dyn UserStore, user_id: UserId) -> Result<User> {
    let Some(user) = users.find_user_by_id(user_id).await? else {
        return Err(Error::UserNotFound);
    };
    if !user.status.is_active() {
        return Err(Error::AccountDisabled);
    }
    Ok(user)
}
