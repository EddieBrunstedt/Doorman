//! High-level [`BauthBuilder`] entry point, reached via
//! [`BauthAxum::builder`].
//!
//! Most hosts want one wired-up auth surface, not a tour of every manager
//! they need to construct. [`BauthAxum::builder`] takes the composite
//! [`bauth_core::storage::Storage`] (typically obtained in one call from a
//! storage adapter such as `bauth-sqlx`) plus the passkey config,
//! constructs the `SessionManager`/`PasskeyManager`/`SignupManager`/
//! `RecoveryManager` internally with sensible defaults, and returns a
//! fully built [`BauthAxum`].
//!
//! Defaults applied when the host does not override them:
//! - [`Clock`] → [`SystemClock`]
//! - [`AuditSink`] → [`NoopAuditSink`]
//! - [`RateLimiter`] → [`InMemoryRateLimiter`]
//!
//! The [`EmailSender`] and [`PasskeyConfig`] have **no defaults**. Hosts
//! must wire them explicitly via [`BauthBuilder::email`] and
//! [`BauthBuilder::passkey`]; otherwise [`build`](BauthBuilder::build)
//! returns [`BuilderError::MissingEmailSender`] or
//! [`BuilderError::MissingPasskeyConfig`]. First-party email transports:
//! [`TerminalEmailSender`] (stdout) and [`FileEmailSender`] (`.eml`
//! files on disk); both are intended for local development and trip
//! a startup warning. Production hosts plug in their real transport
//! (lettre, resend, SES, …) through the [`EmailSender`] trait. The same
//! sender is also used for best-effort security notifications such as
//! passkey-registration notices. We keep build-time errors rather than
//! typestate because the required inputs are
//! few and the simpler builder is easier to read.
//!
//! These defaults are fine for development but not for production.
//! [`build`](BauthBuilder::build) surfaces the mismatch via the
//! [`warnings`](crate::warnings) module — hosts who have made an informed
//! choice silence them with [`BauthBuilder::silence_warnings`]. The
//! host's responsibility is to wire real implementations through
//! [`BauthBuilder::clock`], [`audit`], etc.
//!
//! [`Clock`]: bauth_core::clock::Clock
//! [`SystemClock`]: bauth_core::clock::SystemClock
//! [`AuditSink`]: bauth_core::audit::AuditSink
//! [`NoopAuditSink`]: bauth_core::audit::NoopAuditSink
//! [`RateLimiter`]: bauth_core::rate_limit::RateLimiter
//! [`InMemoryRateLimiter`]: bauth_core::memory::InMemoryRateLimiter
//! [`EmailSender`]: bauth_core::email::EmailSender
//! [`PasskeyConfig`]: bauth_core::passkey::PasskeyConfig
//! [`TerminalEmailSender`]: bauth_core::email::TerminalEmailSender
//! [`FileEmailSender`]: bauth_core::email::FileEmailSender
//! [`audit`]: BauthBuilder::audit

use std::sync::Arc;

use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::context::CoreDeps;
use bauth_core::email::{BauthEmails, DefaultBauthEmails, EmailSender, SecurityEmailNotifier};
use bauth_core::memory::InMemoryRateLimiter;
use bauth_core::passkey::{PasskeyConfig, PasskeyManager};
use bauth_core::rate_limit::RateLimiter;
use bauth_core::recovery::{RecoveryConfig, RecoveryManager};
use bauth_core::session::{SessionConfig, SessionManager};
use bauth_core::signup::{SignupConfig, SignupManager};
use bauth_core::storage::Storage;
use bauth_core::verification::EnrollmentFlow;

use url::Url;

use crate::BauthAxum;
use crate::cache::{SessionCache, SessionCacheConfig};
use crate::config::CookieConfig;
use crate::csrf::CsrfConfig;
use crate::manager_builder::{BuilderError, ManagerBuilder};
use crate::warnings::{
    RateLimiterFlavor, Warnings, is_dev_email_transport, is_noop_audit, rate_limiter_flavor,
};

/// High-level builder returned from [`BauthAxum::builder`].
///
/// This is the headline path: hand it a composite [`Storage`] (typically
/// from a storage adapter such as `bauth-sqlx`) plus the passkey config
/// and email transport, and it constructs the core managers for you. Hosts
/// that have already built the managers themselves want the lower-level
/// [`ManagerBuilder`] via [`BauthAxum::from_managers`] instead.
///
/// See the module-level docs for the full picture. Typical use:
///
/// ```ignore
/// use bauth_axum::prelude::*;
/// use bauth_core::verification::TOKEN_PLACEHOLDER;
///
/// let base = origin.as_str().trim_end_matches('/');
/// let auth = BauthAxum::builder(storage)
///     .email(Arc::new(TerminalEmailSender))
///     .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
///     .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
///     .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
///     .external_origin(origin)
///     .cookie(CookieConfig::default())
///     .build()?;
/// ```
///
/// Collects the storage, the orthogonal collaborators (clock / audit /
/// email / rate limiter), the session config, the cookie config, and the
/// passkey config. The signup flow is part of the only login UX and is
/// configured implicitly; hosts that want to override its defaults call
/// [`signup`](Self::signup). Construction of the core managers happens in
/// [`build`](Self::build).
pub struct BauthBuilder {
    storage: Storage,
    clock: Option<Arc<dyn Clock>>,
    audit: Option<Arc<dyn AuditSink>>,
    email: Option<Arc<dyn EmailSender>>,
    emails: Option<Arc<dyn BauthEmails>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    session_config: Option<SessionConfig>,
    cookie_config: Option<CookieConfig>,
    cache_config: Option<SessionCacheConfig>,
    csrf_config: Option<CsrfConfig>,
    silence_warnings: bool,

    external_origin: Option<Url>,

    passkey: Option<PasskeyConfig>,
    signup: Option<SignupConfig>,
    recovery: Option<RecoveryConfig>,
}

impl BauthBuilder {
    pub(crate) fn new(storage: Storage) -> Self {
        Self {
            storage,
            clock: None,
            audit: None,
            email: None,
            emails: None,
            rate_limiter: None,
            session_config: None,
            cookie_config: None,
            cache_config: None,
            csrf_config: None,
            silence_warnings: false,
            external_origin: None,
            passkey: None,
            signup: None,
            recovery: None,
        }
    }

    /// Suppress the build-time configuration warnings. Use after you have
    /// reviewed the warnings and made an informed choice — e.g. you are
    /// intentionally running with the in-memory rate limiter in a
    /// single-process deployment.
    pub fn silence_warnings(mut self) -> Self {
        self.silence_warnings = true;
        self
    }

    /// Override the default [`SystemClock`].
    ///
    /// [`SystemClock`]: bauth_core::clock::SystemClock
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Override the default [`NoopAuditSink`]. Wire a real sink in
    /// production so security events are not silently dropped.
    ///
    /// [`NoopAuditSink`]: bauth_core::audit::NoopAuditSink
    pub fn audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Wire the [`EmailSender`] used by signup / recovery link delivery and
    /// best-effort security notifications. Required — [`build`](Self::build) returns
    /// [`BuilderError::MissingEmailSender`] when not set.
    ///
    /// [`EmailSender`]: bauth_core::email::EmailSender
    pub fn email(mut self, email: Arc<dyn EmailSender>) -> Self {
        self.email = Some(email);
        self
    }

    /// Wire one [`BauthEmails`] renderer for every flow at once: the signup
    /// link, the recovery link and notices, and the best-effort security
    /// notices (passkey lifecycle, session revocation). This is the single
    /// place to brand all transactional copy.
    ///
    /// A renderer set directly on a [`SignupConfig`](bauth_core::signup::SignupConfig)
    /// or [`RecoveryConfig`](bauth_core::recovery::RecoveryConfig) still wins
    /// for that flow. Branding only some flows without calling this — leaving
    /// the rest on the stock copy — trips a startup warning so partial wiring
    /// is never silent.
    ///
    /// [`BauthEmails`]: bauth_core::email::BauthEmails
    pub fn emails(mut self, emails: Arc<dyn BauthEmails>) -> Self {
        self.emails = Some(emails);
        self
    }

    /// Override the default [`InMemoryRateLimiter`]. The in-memory limiter
    /// is per-process; a multi-replica deployment should swap in a shared
    /// backend.
    ///
    /// [`InMemoryRateLimiter`]: bauth_core::memory::InMemoryRateLimiter
    pub fn limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Override the default [`SessionConfig`] (30-day lifetime).
    pub fn session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = Some(config);
        self
    }

    /// Override the default [`CookieConfig`].
    pub fn cookie(mut self, config: CookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }

    /// Override the session-resolution cache parameters.
    pub fn cache_config(mut self, config: SessionCacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Override the CSRF origin-check behaviour. By default, CSRF checks
    /// are enabled when [`external_origin`](Self::external_origin) is set
    /// and disabled otherwise.
    pub fn csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    /// Configure the WebAuthn relying party for the always-on passkey
    /// flows. Required — [`build`](Self::build) returns
    /// [`BuilderError::MissingPasskeyConfig`] when not set.
    pub fn passkey(mut self, config: PasskeyConfig) -> Self {
        self.passkey = Some(config);
        self
    }

    /// Override the default [`SignupConfig`] (15-minute token lifetime,
    /// default rate limits). Pair with [`email`](Self::email) so the
    /// rendered links actually leave the process; the signup flow is on
    /// implicitly.
    pub fn signup(mut self, config: SignupConfig) -> Self {
        self.signup = Some(config);
        self
    }

    /// Override the default [`RecoveryConfig`] (15-minute token lifetime,
    /// aggressive default rate limits). Like signup, the recovery flow is
    /// always on.
    pub fn recovery(mut self, config: RecoveryConfig) -> Self {
        self.recovery = Some(config);
        self
    }

    /// Absolute public origin clients use to reach the auth routes.
    /// Supplying an origin enables CSRF origin checks by default.
    pub fn external_origin(mut self, origin: Url) -> Self {
        self.external_origin = Some(origin);
        self
    }

    /// Construct the managers and return a wired-up [`BauthAxum`].
    pub fn build(self) -> Result<BauthAxum, BuilderError> {
        let clock: Arc<dyn Clock> = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let audit: Arc<dyn AuditSink> = self.audit.unwrap_or_else(|| Arc::new(NoopAuditSink));
        let email: Arc<dyn EmailSender> = self.email.ok_or(BuilderError::MissingEmailSender)?;
        let passkey_config = self.passkey.ok_or(BuilderError::MissingPasskeyConfig)?;
        let limiter: Arc<dyn RateLimiter> = self
            .rate_limiter
            .unwrap_or_else(|| Arc::new(InMemoryRateLimiter::new(clock.clone())));
        let session_config = self.session_config.unwrap_or_default();

        // The collaborator traits no longer expose diagnostic methods; the
        // bundled dev/noop defaults are recognised here by downcasting the
        // raw `Arc<dyn …>` the host supplied (see `crate::warnings`).
        let mut warnings = Warnings::default();
        if is_noop_audit(audit.as_ref()) {
            warnings.noop_audit = true;
        }
        match rate_limiter_flavor(limiter.as_ref()) {
            RateLimiterFlavor::Noop => warnings.noop_rate_limiter = true,
            RateLimiterFlavor::InMemory => warnings.in_memory_rate_limiter = true,
            RateLimiterFlavor::Custom => {}
        }
        if is_dev_email_transport(email.as_ref()) {
            warnings.dev_email_transport = true;
        }

        // Resolve the one renderer that brands every flow. A renderer set on
        // a specific config still wins for that flow; the shared `.emails(..)`
        // value fills the rest. Branding only some flows without the shared
        // renderer leaves the security notices on the stock copy — flag that
        // so partial wiring is never silent.
        let mut signup_config = self.signup.unwrap_or_default();
        let mut recovery_config = self.recovery.unwrap_or_default();
        if self.emails.is_none()
            && (signup_config.emails.is_some() || recovery_config.emails.is_some())
        {
            warnings.partial_email_branding = true;
        }
        if let Some(shared) = &self.emails {
            signup_config.emails.get_or_insert_with(|| shared.clone());
            recovery_config.emails.get_or_insert_with(|| shared.clone());
        }
        let notifier_renderer: Arc<dyn BauthEmails> = self
            .emails
            .clone()
            .unwrap_or_else(|| Arc::new(DefaultBauthEmails));
        let notifier = SecurityEmailNotifier::new(email.clone(), notifier_renderer);

        // Build the cache up-front so its invalidator can be attached to
        // the `SessionManager` before any dependent manager clones it.
        // Every clone captures the same invalidation hook, so revocations
        // routed through manager logout / revoke paths evict the cache for
        // free. The security notifier is installed the same way — before the
        // manager is cloned into `CoreDeps` — so every clone carries it.
        let cache = SessionCache::new(self.cache_config.unwrap_or_default());

        let session_manager = SessionManager::new(
            self.storage.sessions.clone(),
            clock.clone(),
            audit.clone(),
            session_config,
        )
        .with_invalidation_hook(cache.invalidator())
        .with_security_notifier(notifier.clone());

        // Bundle the shared collaborators once. Every manager below reads
        // what it needs from this context instead of re-threading each
        // store / clock / sink through its own positional constructor.
        let deps = CoreDeps::new(
            clock,
            audit,
            email,
            notifier,
            limiter,
            session_manager.clone(),
            self.storage.clone(),
        );

        let mut builder = ManagerBuilder::default()
            .session_manager(session_manager)
            .user_store(deps.users.clone())
            .session_cache(cache);
        builder.inherited_warnings = warnings;
        if self.silence_warnings {
            builder.silence_warnings = true;
        }

        if let Some(cookie_config) = self.cookie_config {
            builder = builder.cookie_config(cookie_config);
        }

        if let Some(csrf_config) = self.csrf_config {
            builder = builder.csrf(csrf_config);
        }

        let passkey_manager =
            PasskeyManager::new(&deps, passkey_config).map_err(BuilderError::Passkey)?;

        // Signup and recovery share the same dependencies and consume/finish
        // skeleton; build one EnrollmentFlow and hand a clone to each manager.
        let enrollment_flow = EnrollmentFlow::new(&deps, passkey_manager.clone());

        // Signup is part of the only login UX — wire it implicitly so the
        // host doesn't have to opt in. Hosts that need to tune the rate
        // limits or token lifetime call `.signup(...)`.
        let signup_manager = SignupManager::new(enrollment_flow.clone(), signup_config);

        // Recovery rides on the same primitives as signup and is similarly
        // always-on. Hosts override the defaults via `.recovery(...)` to
        // tune the aggressive rate limits.
        let recovery_manager = RecoveryManager::new(enrollment_flow, recovery_config);

        builder = builder
            .passkey_manager(passkey_manager)
            .signup_manager(signup_manager)
            .recovery_manager(recovery_manager);

        if let Some(origin) = self.external_origin {
            builder = builder.external_origin(origin);
        }

        builder.build()
    }
}
