//! Axum-first HTTP integration for bauth.
//!
//! Most hosts start with [`quickstart`], hand it a
//! [`bauth_core::storage::Storage`] value from a storage adapter such as
//! `bauth-sqlx`, enable the auth methods they want, and mount the returned
//! [`BauthAxum`] on their application router.
//!
//! ```ignore
//! use bauth_axum::prelude::*;
//! use bauth_sqlx::SqliteStorage;
//!
//! let storage = SqliteStorage::connect("sqlite:///var/lib/app/auth.db?mode=rwc").await?;
//! storage.migrate().await?;
//!
//! let auth = bauth_axum::quickstart(storage.storage())
//!     .password(PasswordAuthConfig::default())
//!     .external_origin("https://app.example.com".parse()?)
//!     .cookie(CookieConfig::default())
//!     .build()?;
//!
//! let app = axum::Router::new()
//!     .merge(auth.router())
//!     .route("/api/me", axum::routing::get(me))
//!     .layer(auth.session_layer());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`BauthAxum::builder`] remains available for hosts that want to
//! construct the core managers by hand.

pub mod cache;
pub mod config;
mod cookies;
pub mod csrf;
pub mod dto;
pub mod error;
pub mod extractors;
pub mod prelude;
mod quickstart;
mod routes;
pub mod session;
mod state;
pub mod warnings;

mod builder;

pub use bauth_core as core;

pub use builder::{BauthAxumBuilder, BuilderError};
pub use cache::{DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, SessionCache, SessionCacheConfig};
pub use config::CookieConfig;
pub use csrf::{CsrfConfig, CsrfLayer};
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
    /// Start the low-level builder that accepts pre-constructed managers.
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

    /// Access the router state backing the auth routes.
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
