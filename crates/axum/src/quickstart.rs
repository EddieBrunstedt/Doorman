//! High-level [`quickstart`] entry point.
//!
//! Most hosts want one wired-up auth surface, not a tour of every manager
//! they need to construct. [`quickstart`] takes the composite
//! [`bauth_core::storage::Storage`] (typically obtained in one call from a
//! storage adapter such as `bauth-sqlx`) plus opt-in per-method configs,
//! constructs the `SessionManager`/`PasswordAuthManager`/`PasskeyManager`/
//! `OAuthManager` internally with sensible defaults, and returns a fully
//! built [`BauthAxum`].
//!
//! Defaults applied when the host does not override them:
//! - [`Clock`] → [`SystemClock`]
//! - [`AuditSink`] → [`NoopAuditSink`]
//! - [`RateLimiter`] → [`InMemoryRateLimiter`]
//! - [`EmailSender`] → [`NoopEmailSender`]
//!
//! These defaults are fine for development but not for production. The
//! later "startup sanity checks" phase will surface that mismatch with
//! warnings at build time; today the host's responsibility is to wire real
//! implementations through [`QuickstartBuilder::clock`], [`audit`], etc.
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

#[cfg(feature = "oauth")]
use bauth_core::oauth::{OAuthConfig, OAuthManager, OAuthProvider};
#[cfg(feature = "passkey")]
use bauth_core::passkey::{PasskeyConfig, PasskeyManager};
#[cfg(feature = "password")]
use bauth_core::password_auth::{PasswordAuthConfig, PasswordAuthManager};

#[cfg(feature = "oauth")]
use url::Url;

use crate::BauthAxum;
use crate::builder::{BauthAxumBuilder, BuilderError};
use crate::cache::{SessionCache, SessionCacheConfig};
use crate::config::CookieConfig;

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
/// opt-in per-method configs (password / passkey / oauth). Construction of
/// the core managers happens in [`build`](Self::build).
pub struct QuickstartBuilder {
    storage: Storage,
    clock: Option<Arc<dyn Clock>>,
    audit: Option<Arc<dyn AuditSink>>,
    email: Option<Arc<dyn EmailSender>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    session_config: Option<SessionConfig>,
    cookie_config: Option<CookieConfig>,
    cache_config: Option<SessionCacheConfig>,

    #[cfg(feature = "oauth")]
    external_origin: Option<Url>,

    #[cfg(feature = "password")]
    password: Option<PasswordAuthConfig>,
    #[cfg(feature = "passkey")]
    passkey: Option<PasskeyConfig>,
    #[cfg(feature = "oauth")]
    oauth: Option<OAuthSetup>,
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
            #[cfg(feature = "oauth")]
            external_origin: None,
            #[cfg(feature = "password")]
            password: None,
            #[cfg(feature = "passkey")]
            passkey: None,
            #[cfg(feature = "oauth")]
            oauth: None,
        }
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
    /// verification, password-reset, and (later) magic-link flows to
    /// actually deliver mail.
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
    /// Required when [`oauth`](Self::oauth) is in use.
    #[cfg(feature = "oauth")]
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

        if let Some(cookie_config) = self.cookie_config {
            builder = builder.cookie_config(cookie_config);
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

        #[cfg(feature = "oauth")]
        if let Some(origin) = self.external_origin {
            builder = builder.external_origin(origin);
        }

        // Touch otherwise-unused values when no method features are active
        // so the unused-binding lint doesn't fire on a host that compiles
        // with `default-features = false`.
        let _ = (&email, &limiter);

        builder.build()
    }
}
