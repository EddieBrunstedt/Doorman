use std::sync::Arc;

use crate::audit::AuditDispatch;
use crate::clock::Clock;
use crate::email::{EmailSender, EmailTemplates, SecurityEmailNotifier};
use crate::metrics::{MetricSink, NoopMetricSink};
use crate::rate_limit::RateLimiter;
use crate::reauth::ReauthManager;
use crate::session::SessionManager;
use crate::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, Storage, UserStore, VerificationTokenStore,
};

#[derive(Clone)]
pub(crate) struct CoreDeps {
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) audit: AuditDispatch,
    pub(crate) email: Arc<dyn EmailSender>,
    pub(crate) emails: Arc<dyn EmailTemplates>,
    pub(crate) notifier: SecurityEmailNotifier,
    pub(crate) rate_limiter: Arc<dyn RateLimiter>,
    pub(crate) metrics: Arc<dyn MetricSink>,
    pub(crate) sessions: SessionManager,
    pub(crate) reauth: ReauthManager,
    pub(crate) users: Arc<dyn UserStore>,
    pub(crate) verification_tokens: Arc<dyn VerificationTokenStore>,
    pub(crate) passkey_credentials: Arc<dyn PasskeyCredentialStore>,
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
        email: Arc<dyn EmailSender>,
        emails: Arc<dyn EmailTemplates>,
        notifier: SecurityEmailNotifier,
        rate_limiter: Arc<dyn RateLimiter>,
        sessions: SessionManager,
        reauth: ReauthManager,
        storage: Storage,
    ) -> Self {
        Self {
            clock,
            audit,
            email,
            emails,
            notifier,
            rate_limiter,
            metrics: Arc::new(NoopMetricSink),
            sessions,
            reauth,
            users: storage.users,
            verification_tokens: storage.verification_tokens,
            passkey_credentials: storage.passkey_credentials,
            passkey_challenges: storage.passkey_challenges,
        }
    }

    pub(crate) fn with_metrics(mut self, metrics: Arc<dyn MetricSink>) -> Self {
        self.metrics = metrics;
        self
    }
}
