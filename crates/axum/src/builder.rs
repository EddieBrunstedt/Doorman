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
use std::time::Duration;

use doorman_core::account::{AccountConfig, AccountManager};
use doorman_core::audit::AuditSink;
use doorman_core::clock::{Clock, SystemClock};
use doorman_core::context::CoreDeps;
use doorman_core::email::{
    DefaultEmailTemplates, EmailSender, EmailTemplates, SecurityEmailNotifier,
};
use doorman_core::metrics::{Metrics, NoopMetrics};
use doorman_core::passkey::{PasskeyConfig, PasskeyManager};
use doorman_core::rate_limit::RateLimiter;
use doorman_core::recovery::{RecoveryConfig, RecoveryManager};
use doorman_core::session::{SessionConfig, SessionManager};
use doorman_core::signup::{SignupConfig, SignupManager};
use doorman_core::storage::Storage;
use doorman_core::verification::{EnrollmentFlow, TOKEN_PLACEHOLDER};

use url::Url;

/// Upper bound on any host-supplied lifetime (session / token). Ten years —
/// well below the point where converting to a `chrono::Duration` overflows,
/// and far past any sane session or verification-link validity. A value
/// above this is almost certainly a units mistake, so the build rejects it.
const MAX_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 10);

/// Host (DNS suffix) reserved for documentation/examples. A `url_template`
/// still pointing here is the stock default the host never replaced.
const PLACEHOLDER_URL_HOST: &str = "example.invalid";

/// Reject a zero or implausibly large lifetime before it reaches a manager
/// (where converting to a `chrono::Duration` would otherwise panic).
fn validate_lifetime(field: &'static str, value: Duration) -> Result<(), BuilderError> {
    if value.is_zero() || value > MAX_LIFETIME {
        return Err(BuilderError::InvalidLifetime {
            field,
            value,
            max: MAX_LIFETIME,
        });
    }
    Ok(())
}

/// Reject a `url_template` that would render a link without the verification
/// token. The link is the entire signup / recovery flow, so a template
/// missing the placeholder is a hard error rather than a warning.
fn validate_url_template(flow: &'static str, template: &str) -> Result<(), BuilderError> {
    if template.contains(TOKEN_PLACEHOLDER) {
        Ok(())
    } else {
        Err(BuilderError::InvalidUrlTemplate {
            flow,
            placeholder: TOKEN_PLACEHOLDER,
        })
    }
}

/// Reject a `url_template` still pointing at the reserved `example.invalid`
/// host — the stock default the host never replaced. The link would carry a
/// valid token but resolve nowhere, so the build fails closed rather than
/// emailing a dead link.
fn reject_placeholder_url(flow: &'static str, template: &str) -> Result<(), BuilderError> {
    if template.contains(PLACEHOLDER_URL_HOST) {
        Err(BuilderError::PlaceholderUrlTemplate {
            flow,
            placeholder_host: PLACEHOLDER_URL_HOST,
        })
    } else {
        Ok(())
    }
}

use crate::AuthService;
use crate::cache::{SessionCache, SessionCacheConfig};
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
/// [`signup`](Self::signup). Construction of the core managers happens in
/// [`build`](Self::build).
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
    pub fn build(self) -> Result<AuthService, BuilderError> {
        let clock: Arc<dyn Clock> = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let email: Arc<dyn EmailSender> = self.email.ok_or(BuilderError::MissingEmailSender)?;
        let passkey_config = self.passkey.ok_or(BuilderError::MissingPasskeyConfig)?;
        let audit: Arc<dyn AuditSink> = self.audit.ok_or(BuilderError::MissingAuditSink)?;
        let limiter: Arc<dyn RateLimiter> =
            self.rate_limiter.ok_or(BuilderError::MissingRateLimiter)?;
        let metrics: Arc<dyn Metrics> = self
            .metrics
            .unwrap_or_else(|| Arc::new(NoopMetrics) as Arc<dyn Metrics>);
        let session_config = self.session_config.unwrap_or_default();

        // One renderer brands every flow and every notice. The host wires it
        // with `.emails(..)`; left unset it falls back to the stock copy.
        // There is no per-flow override, so partial branding (and the warning
        // it used to need) is structurally impossible.
        let emails: Arc<dyn EmailTemplates> = self
            .emails
            .unwrap_or_else(|| Arc::new(DefaultEmailTemplates));
        let signup_config = self.signup.unwrap_or_default();
        let recovery_config = self.recovery.unwrap_or_default();
        let account_config = self.account.unwrap_or_default();

        // Fail closed on every misconfigured value before constructing any
        // manager: a template that drops the token, a template still pointing
        // at the stock example.invalid host (a valid link to a domain the host
        // does not own — effectively dead), a zero/absurd lifetime (which would
        // otherwise panic when converted to chrono), or a cookie that outlives
        // its session.
        validate_url_template("signup", &signup_config.url_template)?;
        validate_url_template("recovery", &recovery_config.url_template)?;
        validate_url_template("account email change", &account_config.url_template)?;
        reject_placeholder_url("signup", &signup_config.url_template)?;
        reject_placeholder_url("recovery", &recovery_config.url_template)?;
        reject_placeholder_url("account email change", &account_config.url_template)?;
        validate_lifetime("session lifetime", session_config.lifetime)?;
        validate_lifetime("signup token_lifetime", signup_config.token_lifetime)?;
        validate_lifetime("recovery token_lifetime", recovery_config.token_lifetime)?;
        validate_lifetime("account token_lifetime", account_config.token_lifetime)?;

        let cookie_config = self.cookie_config.unwrap_or_default();
        if cookie_config.session_max_age > session_config.lifetime {
            return Err(BuilderError::CookieMaxAgeExceedsSessionLifetime {
                cookie_max_age: cookie_config.session_max_age,
                session_lifetime: session_config.lifetime,
            });
        }
        let notifier = SecurityEmailNotifier::new(email.clone(), emails.clone());

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
            emails,
            notifier,
            limiter,
            session_manager.clone(),
            self.storage.clone(),
        )
        .with_metrics(metrics.clone());

        let mut builder = ManagerBuilder::default()
            .session_manager(session_manager)
            .user_store(deps.users.clone())
            .session_cache(cache)
            .metrics(metrics);

        builder = builder.cookie(cookie_config);

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
        let recovery_manager = RecoveryManager::new(enrollment_flow, recovery_config)?;

        // The account manager reads its collaborators (stores, clock, audit,
        // email transport, session manager) from the same shared context.
        let account_manager = AccountManager::new(&deps, account_config);

        builder = builder
            .passkey_manager(passkey_manager)
            .signup_manager(signup_manager)
            .recovery_manager(recovery_manager)
            .account_manager(account_manager);

        if let Some(origin) = self.external_origin {
            builder = builder.external_origin(origin);
        }

        builder.build()
    }
}
