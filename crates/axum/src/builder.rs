//! Builder for [`BauthAxum`].
//!
//! The host wires the framework-agnostic managers from [`bauth_core`]
//! (each constructed against its storage traits, clock, email sender,
//! etc.) into the builder, then calls [`BauthAxumBuilder::build`] to get
//! back a value that exposes a mountable [`axum::Router`] plus the
//! [`SessionLayer`] needed for the extractors.

use std::sync::Arc;

use bauth_core::session::{SessionInvalidationHook, SessionManager};
use bauth_core::storage::UserStore;
#[cfg(feature = "oauth")]
use url::Url;

use crate::BauthAxum;
use crate::cache::{CacheInvalidator, SessionCache, SessionCacheConfig};
use crate::config::CookieConfig;
use crate::session::{SessionLayer, SessionLayerState};
use crate::state::BauthState;

#[cfg(feature = "oauth")]
use bauth_core::oauth::OAuthManager;
#[cfg(feature = "passkey")]
use bauth_core::passkey::PasskeyManager;
#[cfg(feature = "password")]
use bauth_core::password_auth::PasswordAuthManager;

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("session_manager is required")]
    MissingSessionManager,
    #[error("user_store is required")]
    MissingUserStore,
    #[cfg(feature = "oauth")]
    #[error("external_origin must be set when the oauth manager is configured")]
    MissingExternalOrigin,
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

#[derive(Default)]
pub struct BauthAxumBuilder {
    session_manager: Option<SessionManager>,
    user_store: Option<Arc<dyn UserStore>>,
    cookie_config: Option<CookieConfig>,
    cache_config: Option<SessionCacheConfig>,
    #[cfg(feature = "oauth")]
    external_origin: Option<Url>,

    #[cfg(feature = "password")]
    password: Option<PasswordAuthManager>,
    #[cfg(feature = "passkey")]
    passkey: Option<PasskeyManager>,
    #[cfg(feature = "oauth")]
    oauth: Option<OAuthManager>,
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

    pub fn cookie_config(mut self, config: CookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }

    /// Override the default session-resolution cache parameters. The
    /// session layer runs an in-process LRU keyed by token hash so the
    /// hot path (handlers that don't read `AuthUser`, plus high-RPS
    /// authenticated endpoints) doesn't hit the session and user stores
    /// on every request.
    pub fn cache_config(mut self, config: SessionCacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Absolute public origin (scheme + host [+ port] [+ path prefix])
    /// that external clients use to reach the auth routes. Required when
    /// the `oauth` feature is in use, because providers must be handed an
    /// absolute callback URL at authorization time.
    #[cfg(feature = "oauth")]
    pub fn external_origin(mut self, origin: Url) -> Self {
        self.external_origin = Some(origin);
        self
    }

    #[cfg(feature = "password")]
    pub fn password_manager(mut self, manager: PasswordAuthManager) -> Self {
        self.password = Some(manager);
        self
    }

    #[cfg(feature = "passkey")]
    pub fn passkey_manager(mut self, manager: PasskeyManager) -> Self {
        self.passkey = Some(manager);
        self
    }

    #[cfg(feature = "oauth")]
    pub fn oauth_manager(mut self, manager: OAuthManager) -> Self {
        self.oauth = Some(manager);
        self
    }

    pub fn build(self) -> Result<BauthAxum, BuilderError> {
        let session_manager = self
            .session_manager
            .ok_or(BuilderError::MissingSessionManager)?;
        let user_store = self.user_store.ok_or(BuilderError::MissingUserStore)?;
        let cookie_config = Arc::new(self.cookie_config.unwrap_or_default());

        #[cfg(feature = "oauth")]
        if self.oauth.is_some() && self.external_origin.is_none() {
            return Err(BuilderError::MissingExternalOrigin);
        }

        let cache = SessionCache::new(self.cache_config.unwrap_or_default());
        // Register the cache as an invalidation hook so revokes routed
        // through SessionManager — including those triggered by the
        // password/oauth managers that hold their own clones — evict the
        // matching entries without the host having to know the cache
        // exists. The hook is shared across every clone of the manager
        // because it lives behind an `Arc<RwLock<_>>`.
        session_manager.set_invalidation_hook(
            Arc::new(CacheInvalidator::new(cache.clone())) as Arc<dyn SessionInvalidationHook>
        );

        let layer_state = Arc::new(SessionLayerState {
            session_manager: session_manager.clone(),
            user_store: user_store.clone(),
            cookie_name: cookie_config.session_cookie_name.clone(),
            cache: cache.clone(),
        });

        let state = BauthState {
            session_manager,
            user_store,
            cookie_config,
            #[cfg(feature = "oauth")]
            external_origin: self.external_origin,

            #[cfg(feature = "password")]
            password: self.password,
            #[cfg(feature = "passkey")]
            passkey: self.passkey,
            #[cfg(feature = "oauth")]
            oauth: self.oauth,
        };

        Ok(BauthAxum {
            state,
            session_layer: SessionLayer::new(layer_state),
            cache,
        })
    }
}
