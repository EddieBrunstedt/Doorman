//! Shared application library for the purge example.
//!
//! The whole point of this example is [`build_storage`]: the **single source of
//! truth** for how this deployment constructs its storage. Both binaries in the
//! crate — the application server (`src/bin/server.rs`) and the one-shot purge
//! job (`src/bin/purge.rs`) — call it, so the two processes read the same
//! database from the same environment and their configuration cannot drift.
//!
//! That single-source-of-truth property is what makes the host-owned purge
//! binary safe: a misconfiguration (wrong table, wrong namespace, wrong URL)
//! would have to be made in *one* place that both processes share, rather than
//! re-entered on every purge invocation where it could silently sweep the wrong
//! data and report a clean zero.
//!
//! A real serverless / scale-to-zero host (the kind that cannot rely on the
//! in-process background sweeper) keeps this exact shape and only swaps the body
//! of `build_storage` for its own backend — the rest of the example, and the
//! `doorman::ops::run_purge` runner the purge binary calls, stay identical.

use std::env;

use doorman::core::storage::Storage;
use doorman::sqlx::SqliteStorage;

/// Connect to the configured database, run migrations, and return the composite
/// [`Storage`] both binaries drive.
///
/// This example targets SQLite so it runs with no external services — the point
/// it teaches is the shared-builder *pattern*, not the backend. Panicking on a
/// failed connection or migration is fine for an example binary; a production
/// host returns the error and lets the caller decide.
pub async fn build_storage() -> Storage {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://doorman-purge-example.db?mode=rwc".to_owned());

    let storage = SqliteStorage::connect(&database_url)
        .await
        .expect("connect to the configured database");
    storage.migrate().await.expect("run storage migrations");
    storage.all_stores()
}
