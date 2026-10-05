//! Framework-agnostic assembly seam: wire a [`Storage`] composite and the
//! auth collaborators into a ready-to-serve [`AuthCore`].
//!
//! [`AuthCore::builder`] is the composition root for the auth engine. It
//! takes the composite [`Storage`] (typically obtained in one call from a
//! storage adapter such as `doorman-sqlx`) plus the passkey config and email
//! transport, resolves the silent defaults, validates everything whose wrong
//! choice is a security or delivery footgun, and constructs the managers in
//! the order their shared collaborators require. A front end — `doorman-axum`
//! is the first-party one — consumes the resulting [`AuthCore`] and bolts on
//! its HTTP presentation (cookies, CSRF, the router and session layer).
//!
//! The builder is strict by default: the only collaborator with a silent
//! default is the [`Clock`] → [`SystemClock`]. Everything whose wrong choice
//! is a security or delivery footgun must be wired explicitly, so the unsafe
//! option is always a visible, greppable call rather than an implicit default.
//! [`build`](AuthCoreBuilder::build) returns an [`AssemblyError`] when a
//! required input is missing or a configured value is invalid:
//!
//! - [`EmailSender`] → [`AssemblyError::MissingEmailSender`]
//! - [`PasskeyConfig`] → [`AssemblyError::MissingPasskeyConfig`]
//! - [`AuditSink`] → [`AssemblyError::MissingAuditSink`] (pass
//!   [`NoopAuditSink`](crate::audit::NoopAuditSink) explicitly to discard
//!   events)
//! - [`RateLimiter`] → [`AssemblyError::MissingRateLimiter`] (pass
//!   [`InMemoryRateLimiter`](crate::memory::InMemoryRateLimiter), a shared
//!   backend, or [`NoopRateLimiter`](crate::rate_limit::NoopRateLimiter))
//! - a real signup / recovery / account `url_template` → the stock
//!   `example.invalid` placeholder is rejected with
//!   [`AssemblyError::PlaceholderUrlTemplate`]
//!
//! [`Clock`]: crate::clock::Clock
//! [`SystemClock`]: crate::clock::SystemClock
//! [`AuditSink`]: crate::audit::AuditSink
//! [`RateLimiter`]: crate::rate_limit::RateLimiter
//! [`EmailSender`]: crate::email::EmailSender
//! [`PasskeyConfig`]: crate::passkey::PasskeyConfig

use std::sync::Arc;
use std::time::Duration;

use crate::account::{AccountConfig, AccountManager};
use crate::audit::AuditSink;
use crate::cache::SessionCacheConfig;
use crate::clock::{Clock, SystemClock};
use crate::context::CoreDeps;
use crate::email::{DefaultEmailTemplates, EmailSender, EmailTemplates, SecurityEmailNotifier};
use crate::metrics::{MetricSink, NoopMetricSink};
use crate::operator::{NotificationPolicy, OperatorManager};
use crate::passkey::{PasskeyConfig, PasskeyManager};
use crate::rate_limit::RateLimiter;
use crate::reauth::{ReauthManager, ReauthPolicy};
use crate::recovery::{RecoveryConfig, RecoveryConfigError, RecoveryManager};
use crate::resolve::SessionResolver;
use crate::session::{SessionConfig, SessionManager};
use crate::signup::{SignupConfig, SignupManager};
use crate::storage::{Storage, UserStore};
use crate::verification::{EnrollmentFlow, TOKEN_PLACEHOLDER};

/// Upper bound on any host-supplied lifetime (session / token). Ten years —
/// well below the point where converting to a `chrono::Duration` overflows,
/// and far past any sane session or verification-link validity. A value
/// above this is almost certainly a units mistake, so the build rejects it.
pub(crate) const MAX_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 10);

/// Host (DNS suffix) reserved for documentation/examples. A `url_template`
/// still pointing here is the stock default the host never replaced.
pub(crate) const PLACEHOLDER_URL_HOST: &str = "example.invalid";

/// Errors returned when the framework-agnostic auth engine is incompletely
/// or invalidly configured through [`AuthCore::builder`].
///
/// A front end wrapping this builder (such as `doorman-axum`) typically
/// embeds these variants in its own builder error so a host sees one error
/// type covering both the portable assembly and the HTTP presentation.
#[derive(Debug, thiserror::Error)]
pub enum AssemblyError {
    /// No [`EmailSender`] was supplied. There is no
    /// silent default; pick a real transport (lettre, resend, …) for
    /// production, or use
    /// [`TerminalEmailSender`](crate::email::TerminalEmailSender) /
    /// `FileEmailSender` for local development.
    #[error("email_sender is required")]
    MissingEmailSender,
    /// No [`AuditSink`] was supplied. There is no
    /// silent default: a real deployment wires a sink that persists security
    /// events, and a host that genuinely wants events discarded says so
    /// explicitly with [`NoopAuditSink`](crate::audit::NoopAuditSink).
    #[error("audit sink is required (pass NoopAuditSink explicitly to discard events)")]
    MissingAuditSink,
    /// No [`RateLimiter`] was supplied. There
    /// is no silent default: a host picks the per-process
    /// [`InMemoryRateLimiter`](crate::memory::InMemoryRateLimiter), a shared
    /// backend, or — to opt out of enforcement entirely —
    /// [`NoopRateLimiter`](crate::rate_limit::NoopRateLimiter), but the choice
    /// is always explicit.
    #[error(
        "rate limiter is required (pass InMemoryRateLimiter, a shared backend, or NoopRateLimiter explicitly)"
    )]
    MissingRateLimiter,
    /// No WebAuthn relying-party [`PasskeyConfig`]
    /// was supplied, so the passkey manager cannot be constructed.
    #[error("passkey config is required")]
    MissingPasskeyConfig,
    /// No re-authentication decision was made: the builder was given neither a
    /// [`ReauthPolicy`] (listing the destructive actions to gate) nor an
    /// explicit [`ReauthPolicy::disabled`] opt-out. Like the CSRF decision,
    /// the build refuses to guess whether destructive actions should require a
    /// fresh passkey assertion, so it fails closed until the host decides.
    #[error(
        "a re-authentication decision is required: pass ReauthPolicy::required_for([..]) to gate destructive actions, or ReauthPolicy::disabled() to opt out"
    )]
    ReauthDecisionRequired,
    /// Constructing the [`PasskeyManager`]
    /// from the supplied relying-party configuration failed.
    #[error("passkey manager construction failed: {0}")]
    Passkey(crate::error::Error),
    /// A flow's `url_template` does not contain the
    /// [`TOKEN_PLACEHOLDER`]
    /// substring, so the rendered link would not carry the verification
    /// token. The build fails closed rather than emailing a dead link.
    #[error(
        "{flow} url_template must contain the `{placeholder}` placeholder so the link carries the token"
    )]
    InvalidUrlTemplate {
        /// The flow whose template is invalid (`"signup"`, `"recovery"`,
        /// `"account email change"`).
        flow: &'static str,
        /// The placeholder substring that was expected but missing.
        placeholder: &'static str,
    },
    /// A flow's `url_template` is still the stock `example.invalid`
    /// placeholder the host never replaced. The link would carry a valid
    /// token but point at a domain the host does not own, so the email is
    /// effectively dead. The build fails closed rather than mailing it.
    #[error(
        "{flow} url_template is still the stock `{placeholder_host}` placeholder; set a real template via the matching builder method"
    )]
    PlaceholderUrlTemplate {
        /// The flow whose template was left at the placeholder (`"signup"`,
        /// `"recovery"`, `"account email change"`).
        flow: &'static str,
        /// The reserved placeholder host that was detected.
        placeholder_host: &'static str,
    },
    /// The recovery cool-down is below the documented floor. Surfaced from
    /// [`RecoveryManager::new`].
    #[error("recovery cooldown is misconfigured: {0}")]
    RecoveryCooldownTooShort(#[from] RecoveryConfigError),
    /// A configured lifetime (session, signup token, recovery token, or
    /// account token) is zero or implausibly large. Rejected at build time
    /// rather than panicking later when converted to a `chrono::Duration`.
    #[error("{field} ({value:?}) must be greater than zero and at most {max:?}")]
    InvalidLifetime {
        /// Which lifetime field is out of bounds.
        field: &'static str,
        /// The rejected value.
        value: Duration,
        /// The maximum permitted value.
        max: Duration,
    },
    /// The configured session idle timeout is invalid relative to the absolute
    /// lifetime or the session-resolution cache TTL. The `idle_timeout` must
    /// be greater than zero, at most the ten-year lifetime ceiling, at most the
    /// session's `absolute_lifetime`, and strictly greater than the cache
    /// `ttl` — the last rule is explained in [`crate::resolve`].
    #[error("session idle_timeout ({idle_timeout:?}) is invalid: {reason}")]
    IdleTimeoutInvalid {
        /// The rejected idle timeout.
        idle_timeout: Duration,
        /// Why it was rejected.
        reason: &'static str,
    },
}

/// Reject a zero or implausibly large lifetime before it reaches a manager
/// (where converting to a `chrono::Duration` would otherwise panic).
fn validate_lifetime(field: &'static str, value: Duration) -> Result<(), AssemblyError> {
    if value.is_zero() || value > MAX_LIFETIME {
        return Err(AssemblyError::InvalidLifetime {
            field,
            value,
            max: MAX_LIFETIME,
        });
    }
    Ok(())
}

/// Reject a session idle timeout outside the lifetime bounds: the same
/// zero/`MAX_LIFETIME` bound the absolute lifetime gets, and
/// `idle_timeout <= absolute_lifetime`. Its relation to the cache TTL is
/// checked by [`SessionResolver::new`].
fn validate_idle_timeout(
    idle_timeout: Duration,
    absolute_lifetime: Duration,
) -> Result<(), AssemblyError> {
    if idle_timeout.is_zero() || idle_timeout > MAX_LIFETIME {
        return Err(AssemblyError::IdleTimeoutInvalid {
            idle_timeout,
            reason: "must be greater than zero and at most MAX_LIFETIME",
        });
    }
    if idle_timeout > absolute_lifetime {
        return Err(AssemblyError::IdleTimeoutInvalid {
            idle_timeout,
            reason: "must not exceed the session absolute_lifetime",
        });
    }
    Ok(())
}

/// Reject a `url_template` that would render a link without the verification
/// token. The link is the entire signup / recovery flow, so a template
/// missing the placeholder is a hard error rather than a warning.
fn validate_url_template(flow: &'static str, template: &str) -> Result<(), AssemblyError> {
    if template.contains(TOKEN_PLACEHOLDER) {
        Ok(())
    } else {
        Err(AssemblyError::InvalidUrlTemplate {
            flow,
            placeholder: TOKEN_PLACEHOLDER,
        })
    }
}

/// Reject a `url_template` still pointing at the reserved `example.invalid`
/// host — the stock default the host never replaced. The link would carry a
/// valid token but resolve nowhere, so the build fails closed rather than
/// emailing a dead link.
fn reject_placeholder_url(flow: &'static str, template: &str) -> Result<(), AssemblyError> {
    if template.contains(PLACEHOLDER_URL_HOST) {
        Err(AssemblyError::PlaceholderUrlTemplate {
            flow,
            placeholder_host: PLACEHOLDER_URL_HOST,
        })
    } else {
        Ok(())
    }
}

/// The assembled, framework-agnostic auth engine.
///
/// Holds the wired-up managers — each already sharing one [`CoreDeps`] bundle
/// — plus the [`SessionResolver`] a front end runs on every request. A front
/// end consumes these to mount its routes and resolve sessions;
/// `doorman-axum` hands `resolver` to its session layer and threads the
/// managers into its router state.
///
/// Cheap to move and clone — every field is `Arc`-backed.
pub struct AuthCore {
    /// Session manager (carrying the invalidation hook and security notifier).
    pub session_manager: SessionManager,
    /// Request-time session resolution: cache, expiry, account status and
    /// idle sliding behind one call. Its cache invalidator is installed on
    /// [`session_manager`](Self::session_manager).
    pub resolver: SessionResolver,
    /// User store, surfaced for front-end handlers that read user records.
    pub user_store: Arc<dyn UserStore>,
    /// Passkey registration / authentication manager.
    pub passkey: PasskeyManager,
    /// Signup (email-the-link, enrol a passkey) manager.
    pub signup: SignupManager,
    /// Recovery manager (lost-all-passkeys re-enrolment).
    pub recovery: RecoveryManager,
    /// Account manager (verified email change, account deletion).
    pub account: AccountManager,
    /// Re-authentication manager backing the `reauth/start` ceremony and the
    /// destructive-action gate.
    pub reauth: ReauthManager,
    /// Operator manager (host-driven flows acting on another user). Reached
    /// through its own deliberate accessor so a handler must hold it
    /// explicitly to invoke an operator flow.
    pub operator: OperatorManager,
}

impl AuthCore {
    /// Start the framework-agnostic assembly builder from a composite
    /// [`Storage`]. Wire the collaborators and configs, then
    /// [`build`](AuthCoreBuilder::build) to get a ready [`AuthCore`].
    pub fn builder(storage: Storage) -> AuthCoreBuilder {
        AuthCoreBuilder::new(storage)
    }
}

/// Builder for [`AuthCore`]. Carries the portable collaborators, the per-flow
/// configs, and the session-cache config; runs the portable validation; wires
/// the security notifier and session resolver; and constructs the managers in
/// the order their shared collaborators require.
pub struct AuthCoreBuilder {
    storage: Storage,
    clock: Option<Arc<dyn Clock>>,
    audit: Option<Arc<dyn AuditSink>>,
    email: Option<Arc<dyn EmailSender>>,
    emails: Option<Arc<dyn EmailTemplates>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    metrics: Option<Arc<dyn MetricSink>>,
    session_config: Option<SessionConfig>,
    cache_config: Option<SessionCacheConfig>,
    passkey: Option<PasskeyConfig>,
    signup: Option<SignupConfig>,
    recovery: Option<RecoveryConfig>,
    account: Option<AccountConfig>,
    reauth: Option<ReauthPolicy>,
    notification_policy: Option<NotificationPolicy>,
}

impl AuthCoreBuilder {
    fn new(storage: Storage) -> Self {
        Self {
            storage,
            clock: None,
            audit: None,
            email: None,
            emails: None,
            rate_limiter: None,
            metrics: None,
            session_config: None,
            cache_config: None,
            passkey: None,
            signup: None,
            recovery: None,
            account: None,
            reauth: None,
            notification_policy: None,
        }
    }

    /// Override the default [`SystemClock`].
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Wire the [`AuditSink`] security events are
    /// written to. Required.
    pub fn audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Wire the [`EmailSender`] used by signup /
    /// recovery link delivery and best-effort security notifications.
    /// Required.
    pub fn email(mut self, email: Arc<dyn EmailSender>) -> Self {
        self.email = Some(email);
        self
    }

    /// Wire the one [`EmailTemplates`] renderer
    /// for every transactional email. Defaults to
    /// [`DefaultEmailTemplates`].
    pub fn emails(mut self, emails: Arc<dyn EmailTemplates>) -> Self {
        self.emails = Some(emails);
        self
    }

    /// Wire the [`RateLimiter`] enforcing
    /// per-flow budgets. Required.
    pub fn limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Wire a [`MetricSink`] sink for the auth hot-path
    /// counters. Defaults to [`NoopMetricSink`].
    pub fn metrics(mut self, metrics: Arc<dyn MetricSink>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Override the default [`SessionConfig`] (30-day lifetime).
    pub fn session(mut self, config: SessionConfig) -> Self {
        self.session_config = Some(config);
        self
    }

    /// Override the session-resolution cache parameters.
    pub fn cache(mut self, config: SessionCacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Configure the WebAuthn relying party for the always-on passkey flows.
    /// Required.
    pub fn passkey(mut self, config: PasskeyConfig) -> Self {
        self.passkey = Some(config);
        self
    }

    /// Override the default [`SignupConfig`].
    pub fn signup(mut self, config: SignupConfig) -> Self {
        self.signup = Some(config);
        self
    }

    /// Override the default [`RecoveryConfig`].
    pub fn recovery(mut self, config: RecoveryConfig) -> Self {
        self.recovery = Some(config);
        self
    }

    /// Override the default [`AccountConfig`] backing the verified
    /// email-change flow.
    pub fn account(mut self, config: AccountConfig) -> Self {
        self.account = Some(config);
        self
    }

    /// Decide which destructive actions require a fresh passkey
    /// re-authentication. **Required** — there is no default, so
    /// [`build`](Self::build) returns [`AssemblyError::ReauthDecisionRequired`]
    /// until this is called (with [`ReauthPolicy::required_for`] to gate
    /// actions, or [`ReauthPolicy::disabled`] to opt out deliberately).
    pub fn reauthentication(mut self, policy: ReauthPolicy) -> Self {
        self.reauth = Some(policy);
        self
    }

    /// Set the [`NotificationPolicy`] governing whether operator flows notify
    /// the subject. Left unset, the asymmetric default applies (passkey-removed
    /// notices send, session-revoked notices suppress).
    pub fn notification_policy(mut self, policy: NotificationPolicy) -> Self {
        self.notification_policy = Some(policy);
        self
    }

    /// Resolve defaults, validate the portable configuration, wire the
    /// notifier and session resolver, and construct the managers in the
    /// order their shared collaborators require.
    pub fn build(self) -> Result<AuthCore, AssemblyError> {
        let clock: Arc<dyn Clock> = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let email: Arc<dyn EmailSender> = self.email.ok_or(AssemblyError::MissingEmailSender)?;
        let passkey_config = self.passkey.ok_or(AssemblyError::MissingPasskeyConfig)?;
        let audit: Arc<dyn AuditSink> = self.audit.ok_or(AssemblyError::MissingAuditSink)?;
        let limiter: Arc<dyn RateLimiter> =
            self.rate_limiter.ok_or(AssemblyError::MissingRateLimiter)?;
        let metrics: Arc<dyn MetricSink> = self
            .metrics
            .unwrap_or_else(|| Arc::new(NoopMetricSink) as Arc<dyn MetricSink>);
        let session_config = self.session_config.unwrap_or_default();

        // One renderer brands every flow and every notice. The host wires it
        // with `.emails(..)`; left unset it falls back to the stock copy.
        // There is no per-flow override, so partial branding is structurally
        // impossible.
        let emails: Arc<dyn EmailTemplates> = self
            .emails
            .unwrap_or_else(|| Arc::new(DefaultEmailTemplates));
        let signup_config = self.signup.unwrap_or_default();
        let recovery_config = self.recovery.unwrap_or_default();
        let account_config = self.account.unwrap_or_default();

        // Fail closed on every misconfigured value before constructing any
        // manager: a template that drops the token, a template still pointing
        // at the stock example.invalid host (a valid link to a domain the host
        // does not own — effectively dead), or a zero/absurd lifetime (which
        // would otherwise panic when converted to chrono).
        validate_url_template("signup", &signup_config.url_template)?;
        validate_url_template("recovery", &recovery_config.url_template)?;
        validate_url_template("account email change", &account_config.url_template)?;
        reject_placeholder_url("signup", &signup_config.url_template)?;
        reject_placeholder_url("recovery", &recovery_config.url_template)?;
        reject_placeholder_url("account email change", &account_config.url_template)?;
        validate_lifetime(
            "session absolute_lifetime",
            session_config.absolute_lifetime,
        )?;
        validate_lifetime("signup token_lifetime", signup_config.token_lifetime)?;
        validate_lifetime("recovery token_lifetime", recovery_config.token_lifetime)?;
        validate_lifetime("account token_lifetime", account_config.token_lifetime)?;

        if let Some(idle_timeout) = session_config.idle_timeout {
            validate_idle_timeout(idle_timeout, session_config.absolute_lifetime)?;
        }

        let notifier = SecurityEmailNotifier::new(email.clone(), emails.clone());

        // The security notifier is installed before the manager is cloned into
        // `CoreDeps`, so every clone carries it. The resolver installs its
        // cache invalidator in the hook cell every clone shares, so
        // revocations routed through any manager evict the cache.
        let session_manager = SessionManager::new(
            self.storage.sessions.clone(),
            clock.clone(),
            audit.clone(),
            session_config,
        )
        .with_security_notifier(notifier.clone());
        let resolver = SessionResolver::new(
            session_manager.clone(),
            self.storage.users.clone(),
            self.cache_config.unwrap_or_default(),
        )?
        .with_metrics(metrics.clone());

        // No re-auth default: the host must decide whether destructive actions
        // require a fresh passkey assertion. Mirrors the CSRF decision — fail
        // closed rather than silently leaving the gate off. Resolved here,
        // after the other collaborator and URL/lifetime validation, so a build
        // missing several inputs still surfaces the most specific error first.
        let reauth_policy = self.reauth.ok_or(AssemblyError::ReauthDecisionRequired)?;

        // Build the re-auth manager before the bundle so it can be shared the
        // same way the session manager is. It carries its own `Webauthn` handle
        // built from the same relying-party config as the passkey manager —
        // the handle is stateless across ceremonies, so a second one is
        // equivalent to sharing one and keeps the bundle free of a webauthn
        // field.
        let reauth = ReauthManager::new(
            &passkey_config,
            self.storage.passkey_credentials.clone(),
            self.storage.passkey_challenges.clone(),
            clock.clone(),
            audit.clone(),
            reauth_policy,
        )
        .map_err(AssemblyError::Passkey)?;

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
            reauth.clone(),
            self.storage.clone(),
        )
        .with_metrics(metrics);

        let user_store = deps.users.clone();

        let passkey = PasskeyManager::new(&deps, passkey_config).map_err(AssemblyError::Passkey)?;

        // Signup and recovery share the same dependencies and consume/finish
        // skeleton; build one EnrollmentFlow and hand a clone to each manager.
        let enrollment_flow = EnrollmentFlow::new(&deps, passkey.clone());

        // Signup is part of the only login UX — always on. Hosts that need to
        // tune the rate limits or token lifetime call `.signup(...)`.
        let signup = SignupManager::new(enrollment_flow.clone(), signup_config);

        // Recovery rides on the same primitives as signup and is similarly
        // always-on. The sub-floor cool-down check is enforced here.
        let recovery = RecoveryManager::new(enrollment_flow, recovery_config)?;

        // The account manager reads its collaborators (stores, clock, audit,
        // email transport, session manager) from the same shared context.
        let account = AccountManager::new(&deps, account_config);

        // The operator manager reuses the account cascade and reads its own
        // collaborators from the same context. Its notification policy is
        // chosen here at the composition root; left unset the asymmetric
        // default applies.
        let operator = OperatorManager::new(
            &deps,
            passkey.clone(),
            self.notification_policy.unwrap_or_default(),
        );

        Ok(AuthCore {
            session_manager,
            resolver,
            user_store,
            passkey,
            signup,
            recovery,
            account,
            reauth,
            operator,
        })
    }
}
