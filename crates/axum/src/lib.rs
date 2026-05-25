//! Axum HTTP integration for the [`bauth_core`] authentication library.
//!
//! ```ignore
//! use std::sync::Arc;
//! use bauth_axum::{BauthAxum, CookieConfig};
//!
//! let auth = BauthAxum::builder()
//!     .session_manager(session_manager)
//!     .user_store(user_store)
//!     .password_manager(password_manager)
//!     .passkey_manager(passkey_manager)
//!     .oauth_manager(oauth_manager)
//!     .external_origin("https://app.example.com".parse().unwrap())
//!     .cookie_config(CookieConfig::default())
//!     .build()
//!     .expect("auth configured");
//!
//! let app = axum::Router::new()
//!     .merge(auth.router())
//!     .route("/api/me", axum::routing::get(me))
//!     .layer(auth.session_layer());
//! ```
//!
//! The split between the framework-agnostic [`bauth_core`] crate and this
//! crate is intentional: nothing axum-shaped leaks into `bauth_core`, so
//! a sibling integration for another framework remains a future option
//! without disturbing the core auth logic.

pub mod cache;
pub mod config;
mod cookies;
pub mod dto;
pub mod error;
pub mod extractors;
pub mod prelude;
mod quickstart;
mod routes;
pub mod session;
mod state;

mod builder;

pub use bauth_core as core;

pub use builder::{BauthAxumBuilder, BuilderError};
pub use cache::{DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, SessionCache, SessionCacheConfig};
pub use config::CookieConfig;
pub use error::{ErrorBody, ErrorPayload, ErrorResponse};
pub use extractors::{AuthSession, AuthUser, OptionalAuthUser, RequestContext};
pub use quickstart::{QuickstartBuilder, quickstart};
pub use session::{AuthContext, SessionLayer};
pub use state::BauthState;

use axum::Router;

/// Wired-up authentication HTTP layer. Construct via
/// [`BauthAxum::builder`], then mount the [`router()`](BauthAxum::router)
/// into your application and apply the [`session_layer()`](BauthAxum::session_layer)
/// so the extractors see the per-request `AuthContext`.
pub struct BauthAxum {
    state: BauthState,
    session_layer: SessionLayer,
    cache: SessionCache,
}

impl BauthAxum {
    pub fn builder() -> BauthAxumBuilder {
        BauthAxumBuilder::default()
    }

    /// A `Router` carrying every enabled auth endpoint, scoped under the
    /// `/auth` prefix. Merge it into the application router. The router
    /// is returned with its state already applied (`Router<()>`), so the
    /// host can `.merge` or `.nest` freely.
    pub fn router(&self) -> Router {
        Router::new().nest("/auth", routes::router(self.state.clone()))
    }

    /// The session-loading middleware. Apply it (via [`Router::layer`])
    /// to whatever subtree of the application should be able to resolve
    /// [`AuthUser`] / [`OptionalAuthUser`] — typically the whole app.
    pub fn session_layer(&self) -> SessionLayer {
        self.session_layer.clone()
    }

    pub fn state(&self) -> &BauthState {
        &self.state
    }

    /// Handle to the session-resolution cache. Surfaced primarily for
    /// tests and observability — application code should not need to
    /// reach into the cache directly.
    pub fn cache(&self) -> &SessionCache {
        &self.cache
    }
}
