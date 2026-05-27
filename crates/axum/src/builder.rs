//! Builder for [`BauthAxum`].
//!
//! The host wires the framework-agnostic managers from [`bauth_core`]
//! (each constructed against its storage traits, clock, email sender,
//! etc.) into the builder, then calls [`BauthAxumBuilder::build`] to get
//! back a value that exposes a mountable [`axum::Router`] plus the
//! [`SessionLayer`] needed for the extractors.

use std::sync::Arc;

use bauth_core::email::{EmailSender, EmailSenderKind};
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

#[cfg(feature = "magic_link")]
use bauth_core::magic_link::MagicLinkManager;
#[cfg(feature = "passkey")]
use bauth_core::passkey::PasskeyManager;

/// Errors returned when the Axum auth surface is incompletely configured.
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("session_manager is required")]
    MissingSessionManager,
    #[error("user_store is required")]
    MissingUserStore,
    /// The host did not wire an [`EmailSender`]. There is no silent
    /// default; pick a real transport (lettre, resend, …) for
    /// production, or use [`TerminalEmailSender`] /
    /// [`FileEmailSender`] for local development.
    ///
    /// [`EmailSender`]: bauth_core::email::EmailSender
    /// [`TerminalEmailSender`]: bauth_core::email::TerminalEmailSender
    /// [`FileEmailSender`]: bauth_core::email::FileEmailSender
    #[error("email_sender is required")]
    MissingEmailSender,
    /// Only returned through [`quickstart`](crate::quickstart), which has
    /// to construct the passkey manager itself. The direct
    /// `BauthAxumBuilder` path takes a pre-built [`PasskeyManager`] and
    /// surfaces the same error to the host at construction time.
    ///
    /// [`PasskeyManager`]: bauth_core::passkey::PasskeyManager
    #[cfg(feature = "passkey")]
    #[error("passkey manager construction failed: {0}")]
    Passkey(bauth_core::error::Error),
}

/// Low-level builder for hosts that construct core managers themselves.
#[derive(Default)]
pub struct BauthAxumBuilder {
    session_manager: Option<SessionManager>,
    user_store: Option<Arc<dyn UserStore>>,
    email_sender: Option<Arc<dyn EmailSender>>,
    cookie_config: Option<CookieConfig>,
    cache_config: Option<SessionCacheConfig>,
    session_cache: Option<SessionCache>,
    /// Pre-computed warning conditions from a parent builder (the
    /// quickstart entry point) that already inspected audit / rate-limiter
    /// / linking state the low-level builder does not see. Merged with the
    /// builder's own cookie-config check at [`Self::build`] time.
    pub(crate) inherited_warnings: Warnings,
    pub(crate) silence_warnings: bool,
    external_origin: Option<Url>,
    csrf_config: Option<CsrfConfig>,

    #[cfg(feature = "passkey")]
    passkey: Option<PasskeyManager>,
    #[cfg(feature = "magic_link")]
    magic_link: Option<MagicLinkManager>,
}

impl BauthAxumBuilder {
    pub fn session_manager(mut self, manager: SessionManager) -> Self {
        self.session_manager = Some(manager);
        self
    }

    pub fn user_store(mut self, store: Arc<dyn UserStore>) -> Self {
        self.user_store = Some(store);
        self
    }

    /// Wire the [`EmailSender`] used by the signup / recovery flows.
    /// Required — [`build`](Self::build) returns
    /// [`BuilderError::MissingEmailSender`] when not set. The same
    /// transport must be the one passed into the
    /// [`MagicLinkManager`](bauth_core::magic_link::MagicLinkManager)
    /// the host constructs; the builder keeps a reference so it can
    /// detect dev transports for the startup warnings.
    ///
    /// [`EmailSender`]: bauth_core::email::EmailSender
    pub fn email_sender(mut self, sender: Arc<dyn EmailSender>) -> Self {
        self.email_sender = Some(sender);
        self
    }

    pub fn cookie_config(mut self, config: CookieConfig) -> Self {
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
    pub fn cache_config(mut self, config: SessionCacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Hand the builder a pre-constructed [`SessionCache`]. Use this when
    /// the host needs to wire the cache invalidator onto the
    /// [`SessionManager`] (via [`SessionManager::with_invalidation_hook`])
    /// _before_ constructing the dependent managers — passing the same
    /// cache here ensures the layer reads from the cache the host has
    /// hooked into.
    ///
    /// If the host neither supplies a cache nor wires an invalidator,
    /// revocations made through cloned `SessionManager`s held by the
    /// passkey / magic-link managers will not evict cached entries;
    /// they will only be cleared by the cache TTL. The
    /// [`quickstart`](crate::quickstart) entry point handles all of this
    /// automatically.
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
    /// explicitly with [`with_csrf`](Self::with_csrf) when you have a
    /// known non-browser deployment.
    pub fn external_origin(mut self, origin: Url) -> Self {
        self.external_origin = Some(origin);
        self
    }

    /// Override the CSRF origin-check behaviour. By default, CSRF checks
    /// are enabled when [`external_origin`](Self::external_origin) is set
    /// and disabled otherwise.
    pub fn with_csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    #[cfg(feature = "passkey")]
    pub fn passkey_manager(mut self, manager: PasskeyManager) -> Self {
        self.passkey = Some(manager);
        self
    }

    #[cfg(feature = "magic_link")]
    pub fn magic_link_manager(mut self, manager: MagicLinkManager) -> Self {
        self.magic_link = Some(manager);
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

    pub fn build(self) -> Result<BauthAxum, BuilderError> {
        let session_manager = self
            .session_manager
            .ok_or(BuilderError::MissingSessionManager)?;
        let user_store = self.user_store.ok_or(BuilderError::MissingUserStore)?;
        let email_sender = self.email_sender.ok_or(BuilderError::MissingEmailSender)?;
        let cookie_config = Arc::new(self.cookie_config.unwrap_or_default());

        if !self.silence_warnings {
            let mut warnings = self.inherited_warnings.clone();
            warnings.cookie_insecure_in_production = warnings::check_cookie(&cookie_config);
            if matches!(
                email_sender.diagnostic_kind(),
                EmailSenderKind::Terminal | EmailSenderKind::File
            ) {
                warnings.dev_email_transport = true;
            }
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
        // [`quickstart`](crate::quickstart).
        let cache = self
            .session_cache
            .unwrap_or_else(|| SessionCache::new(self.cache_config.unwrap_or_default()));

        let layer_state = Arc::new(SessionLayerState {
            session_manager: session_manager.clone(),
            user_store: user_store.clone(),
            cookie_name: cookie_config.session_cookie_name.clone(),
            cache: cache.clone(),
            csrf: csrf_config,
        });

        let state = BauthState {
            session_manager,
            user_store,
            cookie_config,
            #[cfg(feature = "passkey")]
            passkey: self.passkey,
            #[cfg(feature = "magic_link")]
            magic_link: self.magic_link,
        };

        Ok(BauthAxum {
            state,
            session_layer: SessionLayer::new(layer_state),
            cache,
        })
    }
}
