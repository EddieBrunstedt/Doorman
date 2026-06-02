//! Low-level [`ManagerBuilder`] for [`BauthAxum`].
//!
//! The host wires the framework-agnostic managers from [`bauth_core`]
//! (each constructed against its storage traits, clock, email sender,
//! etc.) into the builder, then calls [`ManagerBuilder::build`] to get
//! back a value that exposes a mountable [`axum::Router`] plus the
//! [`SessionLayer`] needed for the extractors.
//!
//! Reach this builder via [`BauthAxum::from_managers`]. Most hosts want
//! the higher-level storage-in path instead — see
//! [`BauthAxum::builder`](crate::BauthAxum::builder) and
//! [`BauthBuilder`](crate::BauthBuilder).

use std::sync::Arc;

use bauth_core::metrics::{Metrics, NoopMetrics};
use bauth_core::session::SessionManager;
use bauth_core::storage::UserStore;
use url::Url;

use crate::BauthAxum;
use crate::cache::{SessionCache, SessionCacheConfig};
use crate::config::CookieConfig;
use crate::csrf::CsrfConfig;
use crate::session::{SessionLayer, SessionLayerState};
use crate::state::BauthState;
use crate::warnings::{self, Warnings};

use bauth_core::account::AccountManager;
use bauth_core::passkey::PasskeyManager;
use bauth_core::recovery::RecoveryManager;
use bauth_core::signup::SignupManager;

/// Errors returned when the Axum auth surface is incompletely configured.
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("session_manager is required")]
    MissingSessionManager,
    #[error("user_store is required")]
    MissingUserStore,
    /// The [`BauthBuilder`](crate::BauthBuilder) high-level builder, which
    /// constructs the signup / recovery managers itself, was not given an
    /// [`EmailSender`]. There is no silent default; pick a real transport
    /// (lettre, resend, …) for production, or use [`TerminalEmailSender`] /
    /// [`FileEmailSender`] for local development. The low-level
    /// [`ManagerBuilder`] takes pre-built managers that already own their
    /// sender, so it never returns this error.
    ///
    /// [`EmailSender`]: bauth_core::email::EmailSender
    /// [`TerminalEmailSender`]: bauth_core::email::TerminalEmailSender
    /// [`FileEmailSender`]: bauth_core::email::FileEmailSender
    #[error("email_sender is required")]
    MissingEmailSender,
    /// The high-level builder cannot construct the passkey manager until
    /// the host supplies the WebAuthn relying-party configuration via
    /// [`BauthBuilder::passkey`](crate::BauthBuilder::passkey).
    #[error("passkey config is required")]
    MissingPasskeyConfig,
    #[error("passkey_manager is required")]
    MissingPasskeyManager,
    #[error("signup_manager is required")]
    MissingSignupManager,
    #[error("recovery_manager is required")]
    MissingRecoveryManager,
    #[error("account_manager is required")]
    MissingAccountManager,
    /// Returned through [`BauthBuilder`](crate::BauthBuilder), which has to
    /// construct the passkey manager itself. The direct `ManagerBuilder`
    /// path takes a pre-built [`PasskeyManager`] and surfaces the same
    /// error to the host at construction time.
    ///
    /// [`PasskeyManager`]: bauth_core::passkey::PasskeyManager
    #[error("passkey manager construction failed: {0}")]
    Passkey(bauth_core::error::Error),
    /// A flow's `url_template` does not contain the
    /// [`TOKEN_PLACEHOLDER`](bauth_core::verification::TOKEN_PLACEHOLDER)
    /// substring, so the rendered link would not carry the verification
    /// token. The build fails closed rather than emailing a dead link.
    #[error(
        "{flow} url_template must contain the `{placeholder}` placeholder so the link carries the token"
    )]
    InvalidUrlTemplate {
        flow: &'static str,
        placeholder: &'static str,
    },
    /// The recovery cool-down is below the documented floor. Surfaced from
    /// [`RecoveryManager::new`](bauth_core::recovery::RecoveryManager::new).
    #[error("recovery cooldown is misconfigured: {0}")]
    RecoveryCooldownTooShort(#[from] bauth_core::recovery::RecoveryConfigError),
    /// The session cookie name carries a `__Host-` or `__Secure-` prefix but
    /// the cookie attributes do not satisfy what that prefix requires (per
    /// the cookie-prefix spec). A browser would silently reject the cookie,
    /// so the build fails closed instead.
    #[error("cookie name `{name}` carries a {prefix} prefix but {requirement}")]
    InvalidCookiePrefix {
        name: String,
        prefix: &'static str,
        requirement: &'static str,
    },
    /// A configured lifetime (session, signup token, or recovery token) is
    /// zero or implausibly large. Rejected at build time rather than
    /// panicking later when converted to a `chrono::Duration`.
    #[error("{field} ({value:?}) must be greater than zero and at most {max:?}")]
    InvalidLifetime {
        field: &'static str,
        value: std::time::Duration,
        max: std::time::Duration,
    },
    /// The session cookie `Max-Age` outlives the session lifetime, so the
    /// browser would keep sending a cookie whose session is already dead.
    #[error(
        "cookie Max-Age ({cookie_max_age:?}) exceeds the session lifetime ({session_lifetime:?})"
    )]
    CookieMaxAgeExceedsSessionLifetime {
        cookie_max_age: std::time::Duration,
        session_lifetime: std::time::Duration,
    },
}

/// Low-level builder for hosts that construct the core managers
/// themselves.
///
/// Use this when you build the [`SessionManager`], [`PasskeyManager`],
/// [`SignupManager`], and [`RecoveryManager`] yourself (wiring your own
/// clock, audit sink, rate limiter, email transport, etc.) and just need
/// the HTTP presentation layer bolted on. Each manager already owns its
/// [`EmailSender`](bauth_core::email::EmailSender), so this builder does not
/// take a separate sender. The dev-transport startup warning is emitted only
/// on the high-level [`BauthBuilder`](crate::BauthBuilder) path, which holds
/// the raw transport and can inspect it.
///
/// If you would rather hand over a [`Storage`](bauth_core::storage::Storage)
/// plus passkey / email config and let the managers be constructed for you,
/// use [`BauthAxum::builder`](crate::BauthAxum::builder) instead.
#[derive(Default)]
pub struct ManagerBuilder {
    session_manager: Option<SessionManager>,
    user_store: Option<Arc<dyn UserStore>>,
    cookie_config: Option<CookieConfig>,
    cache_config: Option<SessionCacheConfig>,
    session_cache: Option<SessionCache>,
    /// Pre-computed warning conditions from a parent builder (the
    /// high-level [`BauthBuilder`](crate::BauthBuilder) entry point) that
    /// already inspected audit / rate-limiter / linking state the low-level
    /// builder does not see. Merged with the builder's own cookie-config
    /// check at [`Self::build`] time. Set through
    /// [`inherited_warnings`](Self::inherited_warnings) rather than poked
    /// directly so the high-level builder doesn't reach into private state.
    inherited_warnings: Warnings,
    silence_warnings: bool,
    external_origin: Option<Url>,
    csrf_config: Option<CsrfConfig>,
    metrics: Option<Arc<dyn Metrics>>,

    passkey: Option<PasskeyManager>,
    signup: Option<SignupManager>,
    recovery: Option<RecoveryManager>,
    account: Option<AccountManager>,
}

impl ManagerBuilder {
    pub fn session_manager(mut self, manager: SessionManager) -> Self {
        self.session_manager = Some(manager);
        self
    }

    pub fn user_store(mut self, store: Arc<dyn UserStore>) -> Self {
        self.user_store = Some(store);
        self
    }

    pub fn cookie(mut self, config: CookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }

    /// Override the default session-resolution cache parameters. The
    /// session layer runs an in-process LRU keyed by token hash so the
    /// hot path (handlers that don't read `AuthUser`, plus high-RPS
    /// authenticated endpoints) doesn't hit the session and user stores
    /// on every request.
    ///
    /// Ignored if [`session_cache`](Self::session_cache) is supplied.
    pub fn cache(mut self, config: SessionCacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Hand the builder a pre-constructed [`SessionCache`]. Use this when
    /// the host wires the cache invalidator onto the [`SessionManager`] (via
    /// [`SessionManager::with_invalidation_hook`]): passing the same cache
    /// here ensures the layer reads from the cache the host has hooked into.
    /// Because the manager shares its hook across every clone, the order of
    /// installing the invalidator relative to constructing the dependent
    /// managers does not matter.
    ///
    /// If the host neither supplies a cache nor wires an invalidator,
    /// revocations will only be cleared by the cache TTL. The
    /// [`BauthAxum::builder`](crate::BauthAxum::builder) entry point handles
    /// all of this automatically.
    ///
    /// [`SessionManager`]: bauth_core::session::SessionManager
    /// [`SessionManager::with_invalidation_hook`]: bauth_core::session::SessionManager::with_invalidation_hook
    pub fn session_cache(mut self, cache: SessionCache) -> Self {
        self.session_cache = Some(cache);
        self
    }

    /// Absolute public origin (scheme + host [+ port] [+ path prefix])
    /// that external clients use to reach the auth routes. Supplying an
    /// origin enables the CSRF origin-check layer by default; disable it
    /// explicitly with [`csrf`](Self::csrf) when you have a
    /// known non-browser deployment.
    pub fn external_origin(mut self, origin: Url) -> Self {
        self.external_origin = Some(origin);
        self
    }

    /// Override the CSRF origin-check behaviour. By default, CSRF checks
    /// are enabled when [`external_origin`](Self::external_origin) is set
    /// and disabled otherwise.
    pub fn csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    /// Wire a [`Metrics`] sink for the session-layer cache hit / miss
    /// counters. The core managers report their own counters (login success,
    /// auth failure, latency) through the metrics sink they were built with;
    /// this setter covers the axum layer's cache observations. Defaults to
    /// [`NoopMetrics`].
    pub fn metrics(mut self, metrics: Arc<dyn Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn passkey_manager(mut self, manager: PasskeyManager) -> Self {
        self.passkey = Some(manager);
        self
    }

    pub fn signup_manager(mut self, manager: SignupManager) -> Self {
        self.signup = Some(manager);
        self
    }

    pub fn recovery_manager(mut self, manager: RecoveryManager) -> Self {
        self.recovery = Some(manager);
        self
    }

    pub fn account_manager(mut self, manager: AccountManager) -> Self {
        self.account = Some(manager);
        self
    }

    /// Suppress the build-time configuration warnings. Use after you have
    /// reviewed the warnings and made an informed choice — e.g. you are
    /// intentionally running with an in-memory rate limiter in a
    /// single-process deployment.
    pub fn silence_warnings(mut self) -> Self {
        self.silence_warnings = true;
        self
    }

    /// Seed the warning conditions a parent builder has already computed
    /// (audit / rate-limiter / email-transport / partial-branding state the
    /// low-level builder cannot see). Crate-internal: only the high-level
    /// [`BauthBuilder`](crate::BauthBuilder) supplies these.
    pub(crate) fn inherited_warnings(mut self, warnings: Warnings) -> Self {
        self.inherited_warnings = warnings;
        self
    }

    pub fn build(self) -> Result<BauthAxum, BuilderError> {
        let session_manager = self
            .session_manager
            .ok_or(BuilderError::MissingSessionManager)?;
        let user_store = self.user_store.ok_or(BuilderError::MissingUserStore)?;
        let passkey = self.passkey.ok_or(BuilderError::MissingPasskeyManager)?;
        let signup = self.signup.ok_or(BuilderError::MissingSignupManager)?;
        let recovery = self.recovery.ok_or(BuilderError::MissingRecoveryManager)?;
        let account = self.account.ok_or(BuilderError::MissingAccountManager)?;
        let cookie_config = self.cookie_config.unwrap_or_default();
        validate_cookie_prefix(&cookie_config)?;
        let cookie_config = Arc::new(cookie_config);

        if !self.silence_warnings {
            let mut warnings = self.inherited_warnings.clone();
            warnings.cookie_insecure_in_production = warnings::check_cookie(&cookie_config);
            // Email-transport and audit/limiter diagnostics are decided by the
            // high-level `BauthBuilder` (which holds the raw collaborators) and
            // arrive via `inherited_warnings`. The low-level path takes pre-built
            // managers that already own their transport, so it adds only the
            // cookie check here.
            warnings.emit();
        }

        let default_csrf_origin = self.external_origin.clone();
        let csrf_config = self
            .csrf_config
            .unwrap_or_else(|| {
                default_csrf_origin
                    .as_ref()
                    .map(|origin| CsrfConfig::new(origin.clone()))
                    .unwrap_or_else(CsrfConfig::disabled)
            })
            .enabled_config();

        // Use the host-supplied cache when present so the layer reads from
        // whatever cache the host has already wired an invalidator into;
        // otherwise construct a fresh one. Wiring the invalidator onto the
        // session manager is the host's responsibility on this path
        // because the `SessionManager` is immutable after construction —
        // see [`session_cache`](Self::session_cache) and
        // [`BauthAxum::builder`](crate::BauthAxum::builder).
        let cache = self
            .session_cache
            .unwrap_or_else(|| SessionCache::new(self.cache_config.unwrap_or_default()));

        let metrics = self
            .metrics
            .unwrap_or_else(|| Arc::new(NoopMetrics) as Arc<dyn Metrics>);

        let layer_state = Arc::new(SessionLayerState {
            session_manager: session_manager.clone(),
            user_store: user_store.clone(),
            cookie_name: cookie_config.session_cookie_name.clone(),
            cache: cache.clone(),
            csrf: csrf_config,
            metrics,
        });

        let state = BauthState {
            session_manager,
            user_store,
            cookie_config,
            passkey,
            signup,
            recovery,
            account,
        };

        Ok(BauthAxum {
            state,
            session_layer: SessionLayer::new(layer_state),
            cache,
        })
    }
}

/// Enforce the cookie-prefix rules from the cookie-name spec so a
/// misconfigured cookie fails the build instead of being silently dropped
/// by the browser at runtime.
///
/// - `__Host-` requires `Secure`, `Path=/`, and **no** `Domain` attribute.
/// - `__Secure-` requires `Secure`.
pub(crate) fn validate_cookie_prefix(config: &CookieConfig) -> Result<(), BuilderError> {
    let name = config.session_cookie_name.as_str();
    let invalid = |prefix, requirement| BuilderError::InvalidCookiePrefix {
        name: name.to_string(),
        prefix,
        requirement,
    };
    if name.starts_with("__Host-") {
        if !config.secure {
            return Err(invalid("__Host-", "requires secure = true"));
        }
        if config.path != "/" {
            return Err(invalid("__Host-", "requires path = \"/\""));
        }
        if config.domain.is_some() {
            return Err(invalid("__Host-", "must not set a Domain attribute"));
        }
    } else if name.starts_with("__Secure-") && !config.secure {
        return Err(invalid("__Secure-", "requires secure = true"));
    }
    Ok(())
}
