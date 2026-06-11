//! SQLx-backed storage adapter for `doorman-core`.
//!
//! Three adapters ship behind cargo features:
//!
//! - `sqlite` — `SqliteStorage` for SQLite databases.
//! - `postgres` — `PostgresStorage` for Postgres databases.
//! - `mysql` — `MySqlStorage` for MySQL and MariaDB databases.
//!
//! All expose `connect`, `from_pool`, `pool`, `migrate`, and `all_stores`.
//! `all_stores()` returns a [`doorman_core::storage::Storage`] populated with
//! every store implementation, ready to hand to `AuthService::builder` in
//! `doorman-axum`.
//!
//! ```ignore
//! use doorman_sqlx::SqliteStorage;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = SqliteStorage::connect("sqlite::memory:").await?;
//! storage.migrate().await?;
//! let composite = storage.all_stores();
//! # let _ = composite;
//! # Ok(()) }
//! ```

// Every public item in this library carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test/bench helpers.
#![deny(missing_docs)]

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
mod common;

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
mod stores;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "mysql")]
pub mod mysql;

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStorage;

#[cfg(feature = "postgres")]
pub use postgres::PostgresStorage;

#[cfg(feature = "mysql")]
pub use mysql::MySqlStorage;
