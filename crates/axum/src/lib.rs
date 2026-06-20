//! Axum-first HTTP integration for doorman.
//!
//! Most hosts start with [`AuthService::builder`], hand it a
//! [`doorman_core::storage::Storage`] value from a storage adapter such as
//! `doorman-sqlx`, configure the passkey relying party and email transport,
//! and mount the returned [`AuthService`] on their application router.
//!
//! The builder is strict by default: the audit sink, rate limiter, and a
//! CSRF decision are all required, so the unsafe option is always explicit.
//! This single-process example wires a no-op audit sink and the per-process
//! in-memory limiter on purpose.
//!
//! ```ignore
//! use std::sync::Arc;
//!
//! use doorman_axum::prelude::*;
//! use doorman_core::verification::TOKEN_PLACEHOLDER;
//! use doorman_sqlx::SqliteStorage;
//!
//! let storage = SqliteStorage::connect("sqlite:///var/lib/app/auth.db?mode=rwc").await?;
//! storage.migrate().await?;
//!
//! let origin = "https://app.example.com".parse()?;
//! let base = origin.as_str().trim_end_matches('/');
//! let auth = AuthService::builder(storage.all_stores())
//!     .email(Arc::new(TerminalEmailSender))
//!     .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
//!     .audit(Arc::new(NoopAuditSink))
//!     .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
//!     .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
//!     .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
//!     .account(AccountConfig { url_template: format!("{base}/account/email?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
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
//! [`AuthService::from_managers`] remains available for hosts that want to
//! construct the core managers by hand.

// Every public item in this library carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test/bench helpers.
#![deny(missing_docs)]

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

mod builder;
mod manager_builder;

pub use doorman_core as core;

pub use builder::AuthServiceBuilder;
pub use cache::{DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, SessionCache, SessionCacheConfig};
pub use config::CookieConfig;
pub use csrf::{CsrfConfig, CsrfLayer};
pub use error::{ErrorBody, ErrorPayload, ErrorResponse};
pub use extractors::{AuthSession, AuthUser, OptionalAuthUser, RequestContext};
pub use manager_builder::{BuilderError, ManagerBuilder};
pub use session::{AuthContext, SessionLayer};
pub use state::AuthState;

use axum::Router;
use chrono::{DateTime, Utc};

use doorman_core::error::{StorageError, StorageResult};
use doorman_core::purge::PurgeSummary;
use doorman_core::storage::Storage;

/// Wired-up authentication HTTP layer. Construct via
/// [`AuthService::builder`], then mount the [`router()`](AuthService::router)
/// into your application and apply the [`session_layer()`](AuthService::session_layer)
/// so the extractors see the per-request `AuthContext`.
pub struct AuthService {
    state: AuthState,
    session_layer: SessionLayer,
    cache: SessionCache,
    /// The composite storage the service was built from, kept so an
    /// in-process job or test can sweep expired rows through
    /// [`purge_expired`](AuthService::purge_expired). Present only on the
    /// [`builder`](AuthService::builder) path, which owns the `Storage`;
    /// `None` on the [`from_managers`](AuthService::from_managers) path, whose
    /// pre-built managers carry no composite handle.
    storage: Option<Storage>,
}

impl AuthService {
    /// Start the high-level builder from a composite [`Storage`]. This is
    /// the path most hosts want: it constructs the core managers for you
    /// from sensible defaults. See [`AuthServiceBuilder`].
    pub fn builder(storage: Storage) -> AuthServiceBuilder {
        AuthServiceBuilder::new(storage)
    }

    /// Start the low-level builder that accepts pre-constructed managers.
    /// Use this when you have built the [`SessionManager`], [`PasskeyManager`],
    /// [`SignupManager`], and [`RecoveryManager`] yourself. See
    /// [`ManagerBuilder`].
    ///
    /// [`SessionManager`]: doorman_core::session::SessionManager
    /// [`PasskeyManager`]: doorman_core::passkey::PasskeyManager
    /// [`SignupManager`]: doorman_core::signup::SignupManager
    /// [`RecoveryManager`]: doorman_core::recovery::RecoveryManager
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
    pub fn state(&self) -> &AuthState {
        &self.state
    }

    /// Handle to the session-resolution cache. Surfaced primarily for
    /// tests and observability — application code should not need to
    /// reach into the cache directly.
    pub fn cache(&self) -> &SessionCache {
        &self.cache
    }

    /// Sweep every store of rows whose expiry is at or before `now`, returning
    /// the per-store [`PurgeSummary`]. A thin delegate to
    /// [`Storage::purge_all_expired`] that makes the sweep reachable from the
    /// built service — handy for an in-process job or a test that already holds
    /// the `AuthService` rather than the raw `Storage`.
    ///
    /// Available on a service built via [`builder`](AuthService::builder),
    /// which owns the composite [`Storage`]. The lower-level
    /// [`from_managers`](AuthService::from_managers) path takes pre-built
    /// managers and has no composite handle, so it returns a [`StorageError`];
    /// those hosts call [`Storage::purge_all_expired`] on the storage they
    /// constructed the managers from.
    pub async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<PurgeSummary> {
        match &self.storage {
            Some(storage) => storage.purge_all_expired(now).await,
            None => Err(StorageError::msg(
                "purge_expired is only available on a service built via AuthService::builder; \
                 the from_managers path has no composite Storage handle — call \
                 Storage::purge_all_expired on the storage you built the managers from",
            )),
        }
    }
}
