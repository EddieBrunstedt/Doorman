use std::sync::Arc;

use crate::audit::AuditDispatch;
use crate::clock::Clock;
use crate::email::Mailer;
use crate::metrics::{MetricSink, NoopMetricSink};
use crate::rate_limit::RateLimiter;
use crate::security_notice::SecurityNotices;
use crate::session_records::SessionRecords;
use crate::storage::{EmailLinkStore, PasskeyChallengeStore, PasskeyStore, Storage, UserStore};

#[derive(Clone)]
pub(crate) struct CoreDeps {
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) audit: AuditDispatch,
    pub(crate) mailer: Mailer,
    pub(crate) notices: SecurityNotices,
    pub(crate) rate_limiter: Arc<dyn RateLimiter>,
    pub(crate) metrics: Arc<dyn MetricSink>,
    pub(crate) sessions: SessionRecords,
    pub(crate) users: Arc<dyn UserStore>,
    pub(crate) email_links: Arc<dyn EmailLinkStore>,
    pub(crate) passkeys: Arc<dyn PasskeyStore>,
    pub(crate) passkey_challenges: Arc<dyn PasskeyChallengeStore>,
}

impl CoreDeps {
    #[allow(
        clippy::too_many_arguments,
        reason = "a dependency bundle is inherently wide; a second builder layered over it would add indirection"
    )]
    pub(crate) fn new(
        clock: Arc<dyn Clock>,
        audit: AuditDispatch,
        mailer: Mailer,
        notices: SecurityNotices,
        rate_limiter: Arc<dyn RateLimiter>,
        sessions: SessionRecords,
        storage: Storage,
    ) -> Self {
        Self {
            clock,
            audit,
            mailer,
            notices,
            rate_limiter,
            metrics: Arc::new(NoopMetricSink),
            sessions,
            users: storage.users,
            email_links: storage.email_links,
            passkeys: storage.passkeys,
            passkey_challenges: storage.passkey_challenges,
        }
    }

    pub(crate) fn with_metrics(mut self, metrics: Arc<dyn MetricSink>) -> Self {
        self.metrics = metrics;
        self
    }
}
