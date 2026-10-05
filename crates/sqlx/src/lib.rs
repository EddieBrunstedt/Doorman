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
