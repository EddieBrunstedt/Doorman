//! Axum-first HTTP integration for doorman.
//!
//! A host assembles the auth engine with [`AuthCore::builder`] — handing it a
//! [`doorman_core::storage::Storage`] value from a storage adapter such as
//! `doorman-sqlx` and configuring the passkey relying party, email transport
//! and every other portable option — then passes the built [`AuthCore`] to
//! [`AuthService::builder`] for the cookie and CSRF settings, and mounts the
//! returned [`AuthService`] on its application router.
//!
//! Both builders are strict by default: the audit sink, rate limiter,
//! re-auth decision, and CSRF decision are all required, so the unsafe option
//! is always explicit. This single-process example wires a no-op audit sink
//! and the per-process in-memory limiter on purpose.
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
//! let core = AuthCore::builder(storage.all_stores())
//!     .email(Arc::new(TerminalEmailSender))
//!     .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
//!     .audit(Arc::new(NoopAuditSink))
//!     .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
//!     .reauthentication(ReauthPolicy::disabled())
//!     .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
//!     .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
//!     .account(AccountConfig { url_template: format!("{base}/account/email?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
//!     .build()?;
//! let auth = AuthService::builder(core)
//!     .external_origin(origin)
//!     .cookie(CookieConfig::default())
//!     .build()?;
//!
//! let app = axum::Router::new()
//!     .merge(auth.router())
//!     .route("/api/me", axum::routing::get(me))
//!     .layer(auth.session_layer());
//!
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//! axum::serve(
//!     listener,
//!     app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
//! ).await?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// Every public item in this library carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test/bench helpers.
#![deny(missing_docs)]
// Lock in rustdoc quality alongside the coverage above: broken intra-doc links,
// malformed code blocks, bare URLs, and the rest of the rustdoc lint group warn
// here and become hard errors under the `-D warnings` doc gate.
#![warn(rustdoc::all)]

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

pub use doorman_core as core;

pub use builder::{AuthServiceBuilder, BuilderError};
pub use cache::{DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, SessionCache, SessionCacheConfig};
pub use config::CookieConfig;
pub use csrf::CsrfConfig;
pub use error::{ErrorBody, ErrorPayload, ErrorResponse};
pub use extractors::{AuthSession, AuthUser, ClientIp, OptionalAuthUser, RequestContext};
pub use session::{AuthContext, SessionLayer};
pub use state::AuthState;

use axum::Router;
use chrono::{DateTime, Utc};

use doorman_core::assembly::AuthCore;
use doorman_core::error::StorageResult;
use doorman_core::purge::PurgeSummary;
use doorman_core::storage::Storage;

/// Wired-up authentication HTTP layer. Construct via
/// [`AuthService::builder`] from an assembled [`AuthCore`], then mount the
/// [`router()`](AuthService::router) into your application and apply the
/// [`session_layer()`](AuthService::session_layer) so the extractors see the
/// per-request `AuthContext`.
pub struct AuthService {
    state: AuthState,
    session_layer: SessionLayer,
    cache: SessionCache,
    /// The composite storage the core was built over, kept so an in-process
    /// job or test can sweep expired rows through
    /// [`purge_expired`](AuthService::purge_expired).
    storage: Storage,
}

impl AuthService {
    /// Start the builder from an assembled [`AuthCore`]. The core carries
    /// every portable option; this builder adds the cookie and CSRF
    /// settings. See [`AuthServiceBuilder`].
    pub fn builder(core: AuthCore) -> AuthServiceBuilder {
        AuthServiceBuilder::new(core)
    }

    /// A `Router` carrying every auth endpoint, scoped under the
    /// `/auth` prefix. Merge it into the application router. The router
    /// is returned with its state already applied (`Router<()>`), so the
    /// host can `.merge` or `.nest` freely. Routes using [`RequestContext`]
    /// require [`ClientIp`] or `ConnectInfo<SocketAddr>` in request extensions;
    /// serve with [`Router::into_make_service_with_connect_info`] to supply the
    /// socket address. Missing identity is a `500 internal_error`.
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
    pub async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<PurgeSummary> {
        self.storage.purge_all_expired(now).await
    }
}
