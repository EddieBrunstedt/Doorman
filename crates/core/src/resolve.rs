use std::sync::Arc;

use crate::assembly::AssemblyError;
use crate::cache::{SessionCache, SessionCacheConfig};
use crate::clock::Clock;
use crate::error::Result;
use crate::metrics::{MetricEvent, MetricSink, NoopMetricSink};
use crate::session::{SessionManager, hash_token};
use crate::storage::{Session, User, UserStore};
use crate::user::find_active_user;

#[derive(Clone)]
pub struct ResolvedSession {
    pub user: Arc<User>,
    pub session: Arc<Session>,
    pub slid: bool,
}

#[derive(Clone)]
pub struct SessionResolver {
    sessions: SessionManager,
    users: Arc<dyn UserStore>,
    cache: SessionCache,
    metrics: Arc<dyn MetricSink>,
}

impl SessionResolver {
    pub(crate) fn new(
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

    pub(crate) fn with_metrics(mut self, metrics: Arc<dyn MetricSink>) -> Self {
        self.metrics = metrics;
        self
    }

    #[tracing::instrument(
        skip_all,
        fields(session_id = tracing::field::Empty, user_id = tracing::field::Empty),
    )]
    pub async fn resolve(&self, token: &str) -> Result<ResolvedSession> {
        let token_hash = hash_token(token);
        let now = self.sessions.clock().now();
        let span = tracing::Span::current();

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

    pub fn clock(&self) -> &Arc<dyn Clock> {
        self.sessions.clock()
    }

    pub fn cache(&self) -> &SessionCache {
        &self.cache
    }
}
