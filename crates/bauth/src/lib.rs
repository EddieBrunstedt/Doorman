//! `bauth` — the front door to the bauth authentication library.
//!
//! bauth is an opinionated, passkey-only authentication stack. The
//! implementation is split across three crates:
//!
//! - [`bauth_core`] — framework-agnostic primitives: storage traits,
//!   managers, clock/email/audit/rate-limiter collaborators.
//! - `bauth_axum` — the supported HTTP integration for Axum.
//! - `bauth_sqlx` — SQLx storage adapters (SQLite and Postgres).
//!
//! This crate is the front door: depend on it once and pull the pieces you
//! need in behind features instead of tracking three separate dependencies
//! and keeping their versions in lock-step.
//!
//! ```toml
//! [dependencies]
//! bauth = { version = "0.1", features = ["axum", "sqlite"] }
//! ```
//!
//! ## Features
//!
//! - `axum` — re-export `bauth-axum` at `bauth::axum`.
//! - `sqlite` — re-export `bauth-sqlx` (SQLite adapter) at `bauth::sqlx`.
//! - `postgres` — re-export `bauth-sqlx` (Postgres adapter) at `bauth::sqlx`.
//!
//! [`bauth::core`](core) is always available. The [`prelude`] re-exports the
//! richest available prelude (axum's when the `axum` feature is on, core's
//! otherwise) plus the storage adapters when a sqlx feature is enabled.
//!
//! ## Example
//!
//! ```ignore
//! use std::sync::Arc;
//!
//! use bauth::prelude::*;
//! use bauth::core::verification::TOKEN_PLACEHOLDER;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = SqliteStorage::connect("sqlite::memory:").await?;
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
//! # let _ = auth;
//! # Ok(()) }
//! ```

/// Framework-agnostic authentication primitives. Always available.
pub use bauth_core as core;

/// Axum HTTP integration. Requires the `axum` feature.
#[cfg(feature = "axum")]
pub use bauth_axum as axum;

/// SQLx storage adapters. Requires the `sqlite` or `postgres` feature.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub use bauth_sqlx as sqlx;

/// One-line import for hosts wiring bauth into their app.
///
/// Re-exports the most complete prelude available — `bauth_axum::prelude`
/// when the `axum` feature is enabled (it already folds in the core
/// prelude), or [`bauth_core::prelude`] otherwise — plus the SQLx storage
/// adapters when a sqlx feature is on.
pub mod prelude {
    #[cfg(feature = "axum")]
    pub use bauth_axum::prelude::*;

    #[cfg(not(feature = "axum"))]
    pub use bauth_core::prelude::*;

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub use bauth_sqlx::*;
}
