// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

pub use doorman_core as core;

pub mod ops;

#[cfg(feature = "axum")]
pub use doorman_axum as axum;

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub use doorman_sqlx as sqlx;

#[cfg(feature = "redis")]
pub use doorman_redis as redis;

#[cfg(feature = "mongodb")]
pub use doorman_mongodb as mongodb;

#[cfg(feature = "redb")]
pub use doorman_redb as redb;

pub mod prelude {
    #[cfg(feature = "axum")]
    pub use doorman_axum::prelude::*;

    #[cfg(not(feature = "axum"))]
    pub use doorman_core::prelude::*;

    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    pub use doorman_sqlx::*;

    #[cfg(feature = "redis")]
    pub use doorman_redis::*;

    #[cfg(feature = "mongodb")]
    pub use doorman_mongodb::*;

    #[cfg(feature = "redb")]
    pub use doorman_redb::*;
}
