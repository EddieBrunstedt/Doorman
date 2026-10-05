pub use doorman_core as core;

#[cfg(feature = "purge-runner")]
pub mod ops;

#[cfg(feature = "axum")]
pub use doorman_axum as axum;

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub use doorman_sqlx as sqlx;

#[cfg(feature = "redis")]
pub use doorman_redis as redis;

#[cfg(feature = "dynamodb")]
pub use doorman_dynamodb as dynamodb;

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

    #[cfg(feature = "dynamodb")]
    pub use doorman_dynamodb::*;

    #[cfg(feature = "mongodb")]
    pub use doorman_mongodb::*;

    #[cfg(feature = "redb")]
    pub use doorman_redb::*;
}
