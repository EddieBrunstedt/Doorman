//! High-level [`quickstart`] entry point.
//!
//! Most hosts want one wired-up auth surface, not a tour of every manager
//! they need to construct. [`quickstart`] takes the composite
//! [`bauth_core::storage::Storage`] (typically obtained in one call from a
//! storage adapter such as `bauth-sqlx`) plus opt-in per-method configs,
//! constructs the `SessionManager`/`PasswordAuthManager`/`PasskeyManager`/
//! `OAuthManager`/`MagicLinkManager` internally with sensible defaults, and
//! returns a fully built [`BauthAxum`].
//!
//! Defaults applied when the host does not override them:
//! - [`Clock`] → [`SystemClock`]
//! - [`AuditSink`] → [`NoopAuditSink`]
//! - [`RateLimiter`] → [`InMemoryRateLimiter`]
//! - [`EmailSender`] → [`NoopEmailSender`]
//!
//! These defaults are fine for development but not for production.
//! [`build`](QuickstartBuilder::build) surfaces the mismatch via the
//! [`warnings`](crate::warnings) module — hosts who have made an informed
//! choice silence them with [`QuickstartBuilder::silence_warnings`]. The
//! host's responsibility is to wire real implementations through
//! [`QuickstartBuilder::clock`], [`audit`], etc.
//!
//! [`Clock`]: bauth_core::clock::Clock
//! [`SystemClock`]: bauth_core::clock::SystemClock
//! [`AuditSink`]: bauth_core::audit::AuditSink
//! [`NoopAuditSink`]: bauth_core::audit::NoopAuditSink
//! [`RateLimiter`]: bauth_core::rate_limit::RateLimiter
//! [`InMemoryRateLimiter`]: bauth_core::memory::InMemoryRateLimiter
//! [`EmailSender`]: bauth_core::email::EmailSender
//! [`NoopEmailSender`]: bauth_core::email::NoopEmailSender
//! [`audit`]: QuickstartBuilder::audit

use std::sync::Arc;

use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::{EmailSender, NoopEmailSender};
use bauth_core::memory::InMemoryRateLimiter;
use bauth_core::rate_limit::RateLimiter;
use bauth_core::session::{SessionConfig, SessionManager};
use bauth_core::storage::Storage;

#[cfg(feature = "magic_link")]
use bauth_core::magic_link::{MagicLinkConfig, MagicLinkManager};
#[cfg(feature = "oauth")]
use bauth_core::oauth::{OAuthConfig, OAuthManager, OAuthProvider};
#[cfg(feature = "passkey")]
use bauth_core::passkey::{PasskeyConfig, PasskeyManager};
#[cfg(feature = "password")]
use bauth_core::password_auth::{PasswordAuthConfig, PasswordAuthManager};

use url::Url;

use crate::BauthAxum;
use crate::builder::{BauthAxumBuilder, BuilderError};
use crate::cache::{SessionCache, SessionCacheConfig};
use crate::config::CookieConfig;
use crate::csrf::CsrfConfig;
use crate::warnings::Warnings;

/// Begin building a [`BauthAxum`] from a composite [`Storage`].
///
/// See the [module-level docs](self) for the full picture. Typical use:
///
/// ```ignore
/// use bauth_axum::prelude::*;
///
/// let auth = bauth_axum::quickstart(storage)
///     .password(PasswordAuthConfig::default())
///     .cookie(CookieConfig::default())
///     .build()?;
/// ```
pub fn quickstart(storage: Storage) -> QuickstartBuilder {
    QuickstartBuilder::new(storage)
}

/// Builder returned from [`quickstart`].
///
/// Collects the storage, the orthogonal collaborators (clock / audit /
/// email / rate limiter), the session config, the cookie config, and the
/// opt-in per-method configs (password / passkey / oauth / magic-link).
/// Construction of the core managers happens in [`build`](Self::build).
pub struct QuickstartBuilder {
    storage: Storage,
    clock: Option<Arc<dyn Clock>>,
    audit: Option<Arc<dyn AuditSink>>,
    email: Option<Arc<dyn EmailSender>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    session_config: Option<SessionConfig>,
    cookie_config: Option<CookieConfig>,
    cache_config: Option<SessionCacheConfig>,
    csrf_config: Option<CsrfConfig>,
    silence_warnings: bool,

    external_origin: Option<Url>,

    #[cfg(feature = "password")]
    password: Option<PasswordAuthConfig>,
    #[cfg(feature = "passkey")]
    passkey: Option<PasskeyConfig>,
    #[cfg(feature = "oauth")]
    oauth: Option<OAuthSetup>,
    #[cfg(feature = "magic_link")]
    magic_link: Option<MagicLinkConfig>,
}

#[cfg(feature = "oauth")]
struct OAuthSetup {
    providers: Vec<Arc<dyn OAuthProvider>>,
    config: OAuthConfig,
}

impl QuickstartBuilder {
    fn new(storage: Storage) -> Self {
        Self {
            storage,
            clock: None,
            audit: None,
            email: None,
            rate_limiter: None,
            session_config: None,
            cookie_config: None,
            cache_config: None,
            csrf_config: None,
            silence_warnings: false,
            external_origin: None,
            #[cfg(feature = "password")]
            password: None,
            #[cfg(feature = "passkey")]
            passkey: None,
            #[cfg(feature = "oauth")]
            oauth: None,
            #[cfg(feature = "magic_link")]
            magic_link: None,
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

    /// Override the default [`NoopEmailSender`]. Required for the
    /// verification, password-reset, and magic-link flows to actually
    /// deliver mail.
    ///
    /// [`NoopEmailSender`]: bauth_core::email::NoopEmailSender
    pub fn email(mut self, email: Arc<dyn EmailSender>) -> Self {
        self.email = Some(email);
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
    pub fn with_csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    /// Enable password flows with the supplied config.
    #[cfg(feature = "password")]
    pub fn password(mut self, config: PasswordAuthConfig) -> Self {
        self.password = Some(config);
        self
    }

    /// Enable passkey flows with the supplied config.
    #[cfg(feature = "passkey")]
    pub fn passkey(mut self, config: PasskeyConfig) -> Self {
        self.passkey = Some(config);
        self
    }

    /// Enable magic-link flows with the supplied config. Requires a real
    /// [`EmailSender`] (set via [`email`](Self::email)) to actually
    /// deliver links; the default [`NoopEmailSender`] silently drops them.
    ///
    /// [`EmailSender`]: bauth_core::email::EmailSender
    /// [`NoopEmailSender`]: bauth_core::email::NoopEmailSender
    #[cfg(feature = "magic_link")]
    pub fn magic_link(mut self, config: MagicLinkConfig) -> Self {
        self.magic_link = Some(config);
        self
    }

    /// Enable OAuth with the supplied providers and the default
    /// [`OAuthConfig`]. Requires [`external_origin`](Self::external_origin)
    /// to be set.
    #[cfg(feature = "oauth")]
    pub fn oauth<I>(mut self, providers: I) -> Self
    where
        I: IntoIterator<Item = Arc<dyn OAuthProvider>>,
    {
        self.oauth = Some(OAuthSetup {
            providers: providers.into_iter().collect(),
            config: OAuthConfig::default(),
        });
        self
    }

    /// Enable OAuth with the supplied providers and a custom
    /// [`OAuthConfig`].
    #[cfg(feature = "oauth")]
    pub fn oauth_with<I>(mut self, providers: I, config: OAuthConfig) -> Self
    where
        I: IntoIterator<Item = Arc<dyn OAuthProvider>>,
    {
        self.oauth = Some(OAuthSetup {
            providers: providers.into_iter().collect(),
            config,
        });
        self
    }

    /// Absolute public origin clients use to reach the auth routes.
    /// Required when OAuth is in use. Supplying an origin also enables
    /// CSRF origin checks by default.
    pub fn external_origin(mut self, origin: Url) -> Self {
        self.external_origin = Some(origin);
        self
    }

    /// Construct the managers and return a wired-up [`BauthAxum`].
    pub fn build(self) -> Result<BauthAxum, BuilderError> {
        let clock: Arc<dyn Clock> = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let audit: Arc<dyn AuditSink> = self.audit.unwrap_or_else(|| Arc::new(NoopAuditSink));
        let email: Arc<dyn EmailSender> = self.email.unwrap_or_else(|| Arc::new(NoopEmailSender));
        let limiter: Arc<dyn RateLimiter> = self
            .rate_limiter
            .unwrap_or_else(|| Arc::new(InMemoryRateLimiter::new(clock.clone())));
        let session_config = self.session_config.unwrap_or_default();

        let mut warnings = Warnings::default();
        if audit.is_noop_sink() {
            warnings.noop_audit = true;
        }
        match limiter.diagnostic_kind() {
            bauth_core::rate_limit::RateLimiterKind::Noop => {
                warnings.noop_rate_limiter = true;
            }
            bauth_core::rate_limit::RateLimiterKind::InMemory => {
                warnings.in_memory_rate_limiter = true;
            }
            bauth_core::rate_limit::RateLimiterKind::Custom => {}
        }
        #[cfg(all(feature = "password", feature = "oauth"))]
        if let (Some(password_cfg), Some(oauth_setup)) =
            (self.password.as_ref(), self.oauth.as_ref())
            && oauth_setup.config.allow_email_linking
            && !password_cfg.require_email_verification
        {
            warnings.unsafe_oauth_email_linking = true;
        }

        // Build the cache up-front so its invalidator can be attached to
        // the `SessionManager` before any dependent manager clones it.
        // Every clone captures the same invalidation hook, so revocations
        // routed through `PasswordAuthManager::logout`,
        // `reset_password`, etc. evict the cache for free.
        let cache = SessionCache::new(self.cache_config.unwrap_or_default());

        let session_manager = SessionManager::new(
            self.storage.sessions.clone(),
            clock.clone(),
            audit.clone(),
            session_config,
        )
        .with_invalidation_hook(cache.invalidator());

        let mut builder = BauthAxumBuilder::default()
            .session_manager(session_manager.clone())
            .user_store(self.storage.users.clone())
            .session_cache(cache);
        builder.inherited_warnings = warnings;
        if self.silence_warnings {
            builder.silence_warnings = true;
        }

        if let Some(cookie_config) = self.cookie_config {
            builder = builder.cookie_config(cookie_config);
        }

        if let Some(csrf_config) = self.csrf_config {
            builder = builder.with_csrf(csrf_config);
        }

        #[cfg(feature = "password")]
        if let Some(config) = self.password {
            let manager = PasswordAuthManager::new(
                self.storage.users.clone(),
                self.storage.passwords.clone(),
                self.storage.verification_tokens.clone(),
                session_manager.clone(),
                email.clone(),
                clock.clone(),
                audit.clone(),
                limiter.clone(),
                config,
            );
            builder = builder.password_manager(manager);
        }

        #[cfg(feature = "passkey")]
        if let Some(config) = self.passkey {
            let manager = PasskeyManager::new(
                self.storage.users.clone(),
                self.storage.passkey_credentials.clone(),
                self.storage.passkey_challenges.clone(),
                session_manager.clone(),
                clock.clone(),
                audit.clone(),
                config,
            )
            .map_err(BuilderError::Passkey)?;
            builder = builder.passkey_manager(manager);
        }

        #[cfg(feature = "oauth")]
        if let Some(setup) = self.oauth {
            let manager = OAuthManager::new(
                setup.providers,
                self.storage.users.clone(),
                self.storage.oauth_identities.clone(),
                self.storage.oauth_states.clone(),
                session_manager.clone(),
                clock.clone(),
                audit.clone(),
                setup.config,
            );
            builder = builder.oauth_manager(manager);
        }

        if let Some(origin) = self.external_origin {
            builder = builder.external_origin(origin);
        }

        #[cfg(feature = "magic_link")]
        if let Some(config) = self.magic_link {
            let manager = MagicLinkManager::new(
                self.storage.users.clone(),
                self.storage.verification_tokens.clone(),
                session_manager.clone(),
                email.clone(),
                clock.clone(),
                audit.clone(),
                limiter.clone(),
                config,
            );
            builder = builder.magic_link_manager(manager);
        }

        // Touch otherwise-unused values when no method features are active
        // so the unused-binding lint doesn't fire on a host that compiles
        // with `default-features = false`.
        let _ = (&email, &limiter);

        builder.build()
    }
}
