//! SQLx-backed storage adapter for `bauth-core`.
//!
//! Two adapters ship behind cargo features:
//!
//! - `sqlite` — `SqliteStorage` for SQLite databases.
//! - `postgres` — `PostgresStorage` for Postgres databases.
//!
//! Both expose `connect`, `from_pool`, `pool`, `migrate`, and `storage`.
//! `storage()` returns a [`bauth_core::storage::Storage`] populated with
//! every store implementation, ready to hand to `BauthAxum::builder` in
//! `bauth-axum`.
//!
//! ```ignore
//! use bauth_sqlx::SqliteStorage;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = SqliteStorage::connect("sqlite::memory:").await?;
//! storage.migrate().await?;
//! let composite = storage.storage();
//! # let _ = composite;
//! # Ok(()) }
//! ```

// TODO(Phase 23): flip to `#![deny(missing_docs)]` once every public item is
// documented. Scoped to this library's public API on purpose — kept out of the
// workspace lints so the requirement never fires on test/bench helpers.
#![allow(missing_docs)]

#[cfg(any(feature = "sqlite", feature = "postgres"))]
mod common;

#[cfg(any(feature = "sqlite", feature = "postgres"))]
mod stores;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStorage;

#[cfg(feature = "postgres")]
pub use postgres::PostgresStorage;
