//! Shared dependency context threaded into the core managers.
//!
//! [`CoreDeps`] bundles the collaborators every manager needs — the clock,
//! audit sink, email transport, rate limiter, the already-constructed
//! [`SessionManager`], and the persistence stores — so the composition root
//! (the place that wires everything together at startup) names them once
//! instead of re-listing each one in every manager constructor.
//! [`PasskeyManager::new`] and [`EnrollmentFlow::new`] take this bundle plus
//! their own config rather than a long positional argument list.
//!
//! [`PasskeyManager::new`]: crate::passkey::PasskeyManager::new
//! [`EnrollmentFlow::new`]: crate::verification::EnrollmentFlow::new

use std::sync::Arc;

use crate::audit::{AuditDispatch, AuditSink};
use crate::clock::Clock;
use crate::email::{EmailSender, EmailTemplates, SecurityEmailNotifier};
use crate::metrics::{MetricSink, NoopMetricSink};
use crate::rate_limit::RateLimiter;
use crate::reauth::ReauthManager;
use crate::session::SessionManager;
use crate::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, Storage, UserStore, VerificationTokenStore,
};

/// Shared collaborators handed to the core managers at construction.
///
/// Built once at the composition root (the high-level builder, or a host
/// wiring managers by hand) and passed by reference to each manager
/// constructor. Cheap to clone — every field is an `Arc` or an `Arc`-backed
/// manager — so a host that needs per-flow variation (e.g. a distinct rate
/// limiter for signup versus recovery) can clone the base and override the
/// one field with struct-update syntax.
///
/// The [`SessionManager`] is held rather than the bare session store
/// because the passkey and enrollment flows issue sessions through it (and
/// must observe the same invalidation hook the session layer installs).
/// Build the `SessionManager` first, wire any invalidation hook onto it,
/// then assemble `CoreDeps`.
#[derive(Clone)]
pub struct CoreDeps {
    /// Clock used for every timestamp and expiry comparison.
    pub clock: Arc<dyn Clock>,
    /// Dispatch that traces every audit event on the `doorman::audit` target
    /// and forwards it to the host's sink. The raw [`AuditSink`] is wrapped
    /// here (at [`new`](Self::new)) and never exposed, so a manager cannot emit
    /// to the sink without the matching tracing line.
    pub audit: AuditDispatch,
    /// Transport for signup / recovery links and best-effort security
    /// notifications.
    pub email: Arc<dyn EmailSender>,
    /// The single [`EmailTemplates`] renderer
    /// that brands every transactional email: the signup / recovery / email-change
    /// links and the security notices. Threaded through the enrollment and
    /// account managers (for the link copy) and used to build
    /// [`notifier`](Self::notifier) (for the notices) so one renderer covers
    /// every flow. Defaults to
    /// [`DefaultEmailTemplates`](crate::email::DefaultEmailTemplates).
    pub emails: Arc<dyn EmailTemplates>,
    /// Notifier for best-effort security notices (passkey lifecycle,
    /// session revocation). Built once at the composition root from
    /// [`email`](Self::email) and the chosen [`EmailTemplates`]
    /// renderer, then shared by the passkey and session managers so every
    /// bundled notice originates from one configured helper.
    pub notifier: SecurityEmailNotifier,
    /// Limiter enforced by the enrollment (signup / recovery) request
    /// endpoints. Unused by the passkey and session managers.
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Optional metrics sink for the auth hot-path counters (login success,
    /// auth failure, auth latency). Defaults to
    /// [`NoopMetricSink`]; set a host backend with
    /// [`with_metrics`](Self::with_metrics).
    pub metrics: Arc<dyn MetricSink>,
    /// Session manager the passkey and enrollment flows mint sessions
    /// through.
    pub sessions: SessionManager,
    /// Re-authentication manager the destructive flows (account deletion,
    /// email-change request, passkey removal) gate through. Carries the
    /// host's [`ReauthPolicy`](crate::reauth::ReauthPolicy), so it is built
    /// before the bundle and shared the same way [`sessions`](Self::sessions)
    /// is.
    pub reauth: ReauthManager,
    /// User store.
    pub users: Arc<dyn UserStore>,
    /// Verification-token store backing the signup / recovery links.
    pub verification_tokens: Arc<dyn VerificationTokenStore>,
    /// Passkey credential store.
    pub passkey_credentials: Arc<dyn PasskeyCredentialStore>,
    /// Per-ceremony passkey challenge store.
    pub passkey_challenges: Arc<dyn PasskeyChallengeStore>,
}

impl CoreDeps {
    /// Assemble a context from the individual collaborators and a
    /// [`Storage`] composite. The [`SessionManager`], the
    /// [`SecurityEmailNotifier`], and the [`ReauthManager`] are passed in
    /// rather than derived here: each needs its own configuration (the
    /// invalidation hook, the email renderer, the [`ReauthPolicy`]) wired up
    /// before the dependent managers clone them.
    ///
    /// [`ReauthPolicy`]: crate::reauth::ReauthPolicy
    // A dependency bundle is inherently wide; the alternative (a second
    // builder layered over this one) would be more indirection, not less.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
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
            audit: AuditDispatch::new(audit),
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

    /// Attach a metrics sink for the auth hot-path counters. Returns the
    /// updated context so it can be chained after [`new`](Self::new); the
    /// default is [`NoopMetricSink`].
    pub fn with_metrics(mut self, metrics: Arc<dyn MetricSink>) -> Self {
        self.metrics = metrics;
        self
    }
}
