//! Shared dependency context threaded into the core managers.
//!
//! [`CoreDeps`] bundles the orthogonal collaborators every manager needs —
//! the clock, audit sink, email transport, rate limiter, the
//! already-constructed [`SessionManager`], and the persistence stores — so
//! the composition root names them once instead of re-listing each one in
//! every manager `new`. It is what lets [`PasskeyManager::new`] and
//! [`EnrollmentFlow::new`] take a `(deps, …)` shape rather than the
//! eight-positional-argument constructors they replaced.
//!
//! [`PasskeyManager::new`]: crate::passkey::PasskeyManager::new
//! [`EnrollmentFlow::new`]: crate::verification::EnrollmentFlow::new

use std::sync::Arc;

use crate::audit::AuditSink;
use crate::clock::Clock;
use crate::email::{EmailSender, SecurityEmailNotifier};
use crate::rate_limit::RateLimiter;
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
    /// Sink that receives security audit events.
    pub audit: Arc<dyn AuditSink>,
    /// Transport for signup / recovery links and best-effort security
    /// notifications.
    pub email: Arc<dyn EmailSender>,
    /// Notifier for best-effort security notices (passkey lifecycle,
    /// session revocation). Built once at the composition root from
    /// [`email`](Self::email) and the chosen [`BauthEmails`](crate::email::BauthEmails)
    /// renderer, then shared by the passkey and session managers so every
    /// bundled notice originates from one configured helper.
    pub notifier: SecurityEmailNotifier,
    /// Limiter enforced by the enrollment (signup / recovery) request
    /// endpoints. Unused by the passkey and session managers.
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Session manager the passkey and enrollment flows mint sessions
    /// through.
    pub sessions: SessionManager,
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
    /// Assemble a context from the orthogonal collaborators and a
    /// [`Storage`] composite. The session manager and the security
    /// [`SecurityEmailNotifier`] are built separately — the manager needs its
    /// config and any invalidation hook (plus the notifier) wired before
    /// dependent managers clone it — so both are passed in rather than
    /// derived here.
    pub fn new(
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        email: Arc<dyn EmailSender>,
        notifier: SecurityEmailNotifier,
        rate_limiter: Arc<dyn RateLimiter>,
        sessions: SessionManager,
        storage: Storage,
    ) -> Self {
        Self {
            clock,
            audit,
            email,
            notifier,
            rate_limiter,
            sessions,
            users: storage.users,
            verification_tokens: storage.verification_tokens,
            passkey_credentials: storage.passkey_credentials,
            passkey_challenges: storage.passkey_challenges,
        }
    }
}
