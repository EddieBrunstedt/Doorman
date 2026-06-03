//! Axum-first HTTP integration for bauth.
//!
//! Most hosts start with [`BauthAxum::builder`], hand it a
//! [`bauth_core::storage::Storage`] value from a storage adapter such as
//! `bauth-sqlx`, configure the passkey relying party and email transport,
//! and mount the returned [`BauthAxum`] on their application router.
//!
//! ```ignore
//! use std::sync::Arc;
//!
//! use bauth_axum::prelude::*;
//! use bauth_core::verification::TOKEN_PLACEHOLDER;
//! use bauth_sqlx::SqliteStorage;
//!
//! let storage = SqliteStorage::connect("sqlite:///var/lib/app/auth.db?mode=rwc").await?;
//! storage.migrate().await?;
//!
//! let origin = "https://app.example.com".parse()?;
//! let base = origin.as_str().trim_end_matches('/');
//! let auth = BauthAxum::builder(storage.storage())
//!     .email(Arc::new(TerminalEmailSender))
//!     .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
//!     .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
//!     .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
//!     .external_origin(origin)
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
//! [`BauthAxum::from_managers`] remains available for hosts that want to
//! construct the core managers by hand.

// TODO(Phase 23): flip to `#![deny(missing_docs)]` once every public item is
// documented. Scoped to this library's public API on purpose — kept out of the
// workspace lints so the requirement never fires on test/bench helpers.
#![allow(missing_docs)]

pub mod cache;
pub mod config;
mod cookies;
pub mod csrf;
pub mod dto;
pub mod error;
pub mod extractors;
pub mod prelude;
mod routes;
pub mod session;
mod state;
pub mod warnings;

mod builder;
mod manager_builder;

pub use bauth_core as core;

pub use builder::BauthBuilder;
pub use cache::{DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, SessionCache, SessionCacheConfig};
pub use config::CookieConfig;
pub use csrf::{CsrfConfig, CsrfLayer};
pub use error::{ErrorBody, ErrorPayload, ErrorResponse};
pub use extractors::{AuthSession, AuthUser, OptionalAuthUser, RequestContext};
pub use manager_builder::{BuilderError, ManagerBuilder};
pub use session::{AuthContext, SessionLayer};
pub use state::BauthState;

use axum::Router;

use bauth_core::storage::Storage;

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
    /// Start the high-level builder from a composite [`Storage`]. This is
    /// the path most hosts want: it constructs the core managers for you
    /// from sensible defaults. See [`BauthBuilder`].
    pub fn builder(storage: Storage) -> BauthBuilder {
        BauthBuilder::new(storage)
    }

    /// Start the low-level builder that accepts pre-constructed managers.
    /// Use this when you have built the [`SessionManager`], [`PasskeyManager`],
    /// [`SignupManager`], and [`RecoveryManager`] yourself. See
    /// [`ManagerBuilder`].
    ///
    /// [`SessionManager`]: bauth_core::session::SessionManager
    /// [`PasskeyManager`]: bauth_core::passkey::PasskeyManager
    /// [`SignupManager`]: bauth_core::signup::SignupManager
    /// [`RecoveryManager`]: bauth_core::recovery::RecoveryManager
    pub fn from_managers() -> ManagerBuilder {
        ManagerBuilder::default()
    }

    /// A `Router` carrying every auth endpoint, scoped under the
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
