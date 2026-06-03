//! `doorman` — the front door to the doorman authentication library.
//!
//! doorman is an opinionated, passkey-only authentication stack. The
//! implementation is split across three crates:
//!
//! - [`doorman_core`] — framework-agnostic primitives: storage traits,
//!   managers, clock/email/audit/rate-limiter collaborators.
//! - `doorman_axum` — the supported HTTP integration for Axum.
//! - `doorman_sqlx` — SQLx storage adapters (SQLite and Postgres).
//!
//! This crate is the front door: depend on it once and pull the pieces you
//! need in behind features instead of tracking three separate dependencies
//! and keeping their versions in lock-step.
//!
//! ```toml
//! [dependencies]
//! doorman = { version = "0.1", features = ["axum", "sqlite"] }
//! ```
//!
//! ## Features
//!
//! - `axum` — re-export `doorman-axum` at `doorman::axum`.
//! - `sqlite` — re-export `doorman-sqlx` (SQLite adapter) at `doorman::sqlx`.
//! - `postgres` — re-export `doorman-sqlx` (Postgres adapter) at `doorman::sqlx`.
//! - `file-email` — bundled `.eml` file email transport for local development.
//!
//! [`doorman::core`](core) is always available. The [`prelude`] re-exports the
//! richest available prelude (axum's when the `axum` feature is on, core's
//! otherwise) plus the storage adapters when a sqlx feature is enabled.
//!
//! ## Example
//!
//! ```ignore
//! use std::sync::Arc;
//!
//! use doorman::prelude::*;
//! use doorman::core::verification::TOKEN_PLACEHOLDER;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = SqliteStorage::connect("sqlite::memory:").await?;
//! storage.migrate().await?;
//!
//! let origin = "https://app.example.com".parse()?;
//! let base = origin.as_str().trim_end_matches('/');
//! let auth = DoormanAxum::builder(storage.storage())
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

// Every public item in this crate carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test/bench helpers.
#![deny(missing_docs)]

/// Framework-agnostic authentication primitives. Always available.
pub use doorman_core as core;

/// Axum HTTP integration. Requires the `axum` feature.
#[cfg(feature = "axum")]
pub use doorman_axum as axum;

/// SQLx storage adapters. Requires the `sqlite` or `postgres` feature.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub use doorman_sqlx as sqlx;

/// One-line import for hosts wiring doorman into their app.
///
/// Re-exports the most complete prelude available — `doorman_axum::prelude`
/// when the `axum` feature is enabled (it already folds in the core
/// prelude), or [`doorman_core::prelude`] otherwise — plus the SQLx storage
/// adapters when a sqlx feature is on.
pub mod prelude {
    #[cfg(feature = "axum")]
    pub use doorman_axum::prelude::*;

    #[cfg(not(feature = "axum"))]
    pub use doorman_core::prelude::*;

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub use doorman_sqlx::*;
}
