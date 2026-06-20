//! High-level [`AuthServiceBuilder`] entry point, reached via
//! [`AuthService::builder`].
//!
//! Most hosts want one wired-up auth surface, not a tour of every manager
//! they need to construct. [`AuthService::builder`] takes the composite
//! [`doorman_core::storage::Storage`] (typically obtained in one call from a
//! storage adapter such as `doorman-sqlx`) plus the passkey config,
//! constructs the `SessionManager`/`PasskeyManager`/`SignupManager`/
//! `RecoveryManager` internally with sensible defaults, and returns a
//! fully built [`AuthService`].
//!
//! The portable half of that work — resolving the collaborator defaults,
//! validating the URL templates and lifetimes, wiring the security notifier
//! and cache invalidator, and constructing the managers in dependency order —
//! lives in [`doorman_core::assembly`]. This builder delegates to
//! [`AuthCore::builder`](doorman_core::assembly::AuthCore::builder) for that
//! part and then layers on the HTTP-specific decisions (cookie config and its
//! `__Host-`/`__Secure-` prefix rules, the CSRF posture, and the router /
//! session layer).
//!
//! The builder is strict by default: the only collaborator with a silent
//! default is the [`Clock`] → [`SystemClock`]. Everything whose wrong choice
//! is a security or delivery footgun must be wired explicitly, so the unsafe
//! option is always a visible, greppable call rather than an implicit default
//! the host has to be warned about. [`build`](AuthServiceBuilder::build)
//! returns a [`BuilderError`] when a required input is missing:
//!
//! - [`EmailSender`] → [`BuilderError::MissingEmailSender`]
//! - [`PasskeyConfig`] → [`BuilderError::MissingPasskeyConfig`]
//! - [`AuditSink`] → [`BuilderError::MissingAuditSink`] (pass
//!   [`NoopAuditSink`] explicitly to discard events)
//! - [`RateLimiter`] → [`BuilderError::MissingRateLimiter`] (pass
//!   [`InMemoryRateLimiter`], a shared backend, or `NoopRateLimiter`)
//! - a CSRF decision → [`BuilderError::CsrfDecisionRequired`] unless
//!   [`external_origin`](AuthServiceBuilder::external_origin) is set or CSRF
//!   is explicitly configured
//! - a real signup / recovery / account `url_template` → the stock
//!   `example.invalid` placeholder is rejected with
//!   [`BuilderError::PlaceholderUrlTemplate`]
//!
//! First-party email transports [`TerminalEmailSender`] (stdout) and
//! [`FileEmailSender`] (`.eml` files on disk) are intended for local
//! development; production hosts plug in their real transport (lettre,
//! resend, SES, …) through the [`EmailSender`] trait. The same sender is also
//! used for best-effort security notifications such as passkey-registration
//! notices. We keep build-time errors rather than typestate because the
//! required inputs are few and the simpler builder is easier to read.
//!
//! [`Clock`]: doorman_core::clock::Clock
//! [`SystemClock`]: doorman_core::clock::SystemClock
//! [`AuditSink`]: doorman_core::audit::AuditSink
//! [`NoopAuditSink`]: doorman_core::audit::NoopAuditSink
//! [`RateLimiter`]: doorman_core::rate_limit::RateLimiter
//! [`InMemoryRateLimiter`]: doorman_core::memory::InMemoryRateLimiter
//! [`EmailSender`]: doorman_core::email::EmailSender
//! [`PasskeyConfig`]: doorman_core::passkey::PasskeyConfig
//! [`TerminalEmailSender`]: doorman_core::email::TerminalEmailSender
//! [`FileEmailSender`]: doorman_core::email::FileEmailSender

use std::sync::Arc;

use doorman_core::account::AccountConfig;
use doorman_core::assembly::AuthCore;
use doorman_core::audit::AuditSink;
use doorman_core::clock::Clock;
use doorman_core::email::{EmailSender, EmailTemplates};
use doorman_core::metrics::Metrics;
use doorman_core::passkey::PasskeyConfig;
use doorman_core::rate_limit::RateLimiter;
use doorman_core::recovery::RecoveryConfig;
use doorman_core::session::SessionConfig;
use doorman_core::signup::SignupConfig;
use doorman_core::storage::Storage;

use url::Url;

use crate::AuthService;
use crate::cache::SessionCacheConfig;
use crate::config::CookieConfig;
use crate::csrf::CsrfConfig;
use crate::manager_builder::{BuilderError, ManagerBuilder};

/// High-level builder returned from [`AuthService::builder`].
///
/// This is the headline path: hand it a composite [`Storage`] (typically
/// from a storage adapter such as `doorman-sqlx`) plus the passkey config
/// and email transport, and it constructs the core managers for you. Hosts
/// that have already built the managers themselves want the lower-level
/// [`ManagerBuilder`] via [`AuthService::from_managers`] instead.
///
/// See the module-level docs for the full picture. Typical use:
///
/// ```ignore
/// use doorman_axum::prelude::*;
/// use doorman_core::verification::TOKEN_PLACEHOLDER;
///
/// let base = origin.as_str().trim_end_matches('/');
/// let auth = AuthService::builder(storage)
///     .email(Arc::new(TerminalEmailSender))
///     .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
///     .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
///     .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
///     .external_origin(origin)
///     .cookie(CookieConfig::default())
///     .build()?;
/// ```
///
/// Collects the storage, the collaborators (clock / audit / email / rate
/// limiter), the session config, the cookie config, and the
/// passkey config. The signup flow is part of the only login UX and is
/// configured implicitly; hosts that want to override its defaults call
/// [`signup`](Self::signup). The portable assembly is delegated to
/// [`AuthCore::builder`] in [`build`](Self::build); this builder adds the
/// cookie / CSRF decisions on top.
pub struct AuthServiceBuilder {
    storage: Storage,
    clock: Option<Arc<dyn Clock>>,
    audit: Option<Arc<dyn AuditSink>>,
    email: Option<Arc<dyn EmailSender>>,
    emails: Option<Arc<dyn EmailTemplates>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    metrics: Option<Arc<dyn Metrics>>,
    session_config: Option<SessionConfig>,
    cookie_config: Option<CookieConfig>,
    cache_config: Option<SessionCacheConfig>,
    csrf_config: Option<CsrfConfig>,

    external_origin: Option<Url>,

    passkey: Option<PasskeyConfig>,
    signup: Option<SignupConfig>,
    recovery: Option<RecoveryConfig>,
    account: Option<AccountConfig>,
}

impl AuthServiceBuilder {
    pub(crate) fn new(storage: Storage) -> Self {
        Self {
            storage,
            clock: None,
            audit: None,
            email: None,
            emails: None,
            rate_limiter: None,
            metrics: None,
            session_config: None,
            cookie_config: None,
            cache_config: None,
            csrf_config: None,
            external_origin: None,
            passkey: None,
            signup: None,
            recovery: None,
            account: None,
        }
    }

    /// Override the default [`SystemClock`].
    ///
    /// [`SystemClock`]: doorman_core::clock::SystemClock
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Wire the [`AuditSink`] security events are written to. Required —
    /// [`build`](Self::build) returns [`BuilderError::MissingAuditSink`] when
    /// not set. To discard events deliberately, pass
    /// `Arc::new(NoopAuditSink)` explicitly.
    ///
    /// [`AuditSink`]: doorman_core::audit::AuditSink
    pub fn audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Wire the [`EmailSender`] used by signup / recovery link delivery and
    /// best-effort security notifications. Required — [`build`](Self::build) returns
    /// [`BuilderError::MissingEmailSender`] when not set.
    ///
    /// [`EmailSender`]: doorman_core::email::EmailSender
    pub fn email(mut self, email: Arc<dyn EmailSender>) -> Self {
        self.email = Some(email);
        self
    }

    /// Wire the one [`EmailTemplates`] renderer for every transactional email
    /// the app sends: the signup link, the recovery link and notices, the
    /// email-change confirmation, and the best-effort security notices (passkey
    /// lifecycle, session revocation). This is the single place to brand all
    /// transactional copy.
    ///
    /// Defaults to [`DefaultEmailTemplates`](doorman_core::email::DefaultEmailTemplates),
    /// whose trait methods each have a stock body — implement [`EmailTemplates`]
    /// and override only the messages you want to change, inheriting the rest.
    ///
    /// [`EmailTemplates`]: doorman_core::email::EmailTemplates
    pub fn emails(mut self, emails: Arc<dyn EmailTemplates>) -> Self {
        self.emails = Some(emails);
        self
    }

    /// Wire the [`RateLimiter`] enforcing per-flow budgets. Required —
    /// [`build`](Self::build) returns [`BuilderError::MissingRateLimiter`]
    /// when not set. The bundled [`InMemoryRateLimiter`] is per-process (fine
    /// single-process; a multi-replica deployment should swap in a shared
    /// backend); pass `NoopRateLimiter` to disable enforcement deliberately.
    ///
    /// [`RateLimiter`]: doorman_core::rate_limit::RateLimiter
    /// [`InMemoryRateLimiter`]: doorman_core::memory::InMemoryRateLimiter
    pub fn limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Wire a [`Metrics`] sink for production telemetry. The auth managers
    /// report login success, authentication failure, and per-ceremony
    /// latency through it, and the session layer reports cache hit / miss.
    /// Defaults to [`NoopMetrics`], which discards every observation.
    ///
    /// [`Metrics`]: doorman_core::metrics::Metrics
    /// [`NoopMetrics`]: doorman_core::metrics::NoopMetrics
    pub fn metrics(mut self, metrics: Arc<dyn Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Override the default [`SessionConfig`] (30-day lifetime).
    pub fn session(mut self, config: SessionConfig) -> Self {
        self.session_config = Some(config);
        self
    }

    /// Override the default [`CookieConfig`].
    pub fn cookie(mut self, config: CookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }

    /// Override the session-resolution cache parameters.
    pub fn cache(mut self, config: SessionCacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Set the CSRF origin-check behaviour explicitly. Setting
    /// [`external_origin`](Self::external_origin) already enables checks; call
    /// this with [`CsrfConfig::disabled`](crate::csrf::CsrfConfig::disabled)
    /// to opt out deliberately. With neither an origin nor an explicit config,
    /// [`build`](Self::build) returns [`BuilderError::CsrfDecisionRequired`]
    /// rather than silently leaving the check off.
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

    /// Override the default [`AccountConfig`] backing the verified
    /// email-change flow (15-minute confirmation-token lifetime). Set the
    /// `url_template` to a route in your app that posts the token back to
    /// `/auth/account/email/confirm`; like signup / recovery, the template
    /// must contain the `{token}` placeholder.
    pub fn account(mut self, config: AccountConfig) -> Self {
        self.account = Some(config);
        self
    }

    /// Absolute public origin clients use to reach the auth routes.
    /// Supplying an origin enables CSRF origin checks and satisfies the
    /// required CSRF decision (see [`csrf`](Self::csrf)).
    pub fn external_origin(mut self, origin: Url) -> Self {
        self.external_origin = Some(origin);
        self
    }

    /// Construct the managers and return a wired-up [`AuthService`].
    ///
    /// The portable assembly (collaborator defaults, URL / lifetime
    /// validation, notifier + cache wiring, manager construction) is
    /// delegated to [`AuthCore::builder`]; any [`AssemblyError`] it returns is
    /// mapped onto the matching [`BuilderError`] variant. This method then
    /// adds the HTTP decisions — the cookie `Max-Age` vs session-lifetime
    /// check here, the `__Host-`/`__Secure-` prefix rules and the CSRF posture
    /// in [`ManagerBuilder::build`].
    ///
    /// [`AssemblyError`]: doorman_core::assembly::AssemblyError
    pub fn build(self) -> Result<AuthService, BuilderError> {
        let session_config = self.session_config.unwrap_or_default();
        let session_lifetime = session_config.lifetime;
        let cookie_config = self.cookie_config.unwrap_or_default();

        // Keep a handle to the composite storage before it is consumed by the
        // core assembly below, so the built service can sweep expired rows via
        // `AuthService::purge_expired`. `Storage` is a bundle of `Arc` stores,
        // so the clone is cheap and shares the same underlying data.
        let storage = self.storage.clone();

        // Delegate the portable half. Each input is threaded through only when
        // the host set it, so the core builder applies the same defaults this
        // builder used to. The required-input and validation errors come back
        // as `AssemblyError` and map onto the matching `BuilderError` variant.
        let mut core_builder = AuthCore::builder(self.storage).session(session_config);
        if let Some(clock) = self.clock {
            core_builder = core_builder.clock(clock);
        }
        if let Some(audit) = self.audit {
            core_builder = core_builder.audit(audit);
        }
        if let Some(email) = self.email {
            core_builder = core_builder.email(email);
        }
        if let Some(emails) = self.emails {
            core_builder = core_builder.emails(emails);
        }
        if let Some(limiter) = self.rate_limiter {
            core_builder = core_builder.limiter(limiter);
        }
        if let Some(metrics) = self.metrics {
            core_builder = core_builder.metrics(metrics);
        }
        if let Some(cache_config) = self.cache_config {
            core_builder = core_builder.cache(cache_config);
        }
        if let Some(passkey) = self.passkey {
            core_builder = core_builder.passkey(passkey);
        }
        if let Some(signup) = self.signup {
            core_builder = core_builder.signup(signup);
        }
        if let Some(recovery) = self.recovery {
            core_builder = core_builder.recovery(recovery);
        }
        if let Some(account) = self.account {
            core_builder = core_builder.account(account);
        }

        let core = core_builder.build()?;

        // The cookie Max-Age vs session-lifetime check is HTTP-specific: it
        // compares a cookie attribute against the session lifetime. Run it
        // after the portable assembly so a misconfigured lifetime (validated
        // in core) is reported as the lifetime error, not masked by a cookie
        // that now "exceeds" a rejected lifetime.
        if cookie_config.session_max_age > session_lifetime {
            return Err(BuilderError::CookieMaxAgeExceedsSessionLifetime {
                cookie_max_age: cookie_config.session_max_age,
                session_lifetime,
            });
        }

        let mut builder = ManagerBuilder::default()
            .session_manager(core.session_manager.clone())
            .user_store(core.user_store.clone())
            .session_cache(core.cache.clone())
            .metrics(core.metrics.clone())
            .cookie(cookie_config)
            .passkey_manager(core.passkey)
            .signup_manager(core.signup)
            .recovery_manager(core.recovery)
            .account_manager(core.account)
            .operator_manager(core.operator);

        if let Some(csrf_config) = self.csrf_config {
            builder = builder.csrf(csrf_config);
        }

        if let Some(origin) = self.external_origin {
            builder = builder.external_origin(origin);
        }

        let mut service = builder.build()?;
        service.storage = Some(storage);
        Ok(service)
    }
}
