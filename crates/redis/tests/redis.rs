//! Runs the shared storage-conformance suite against the Redis adapter.
//!
//! Skipped unless `REDIS_URL` points at a disposable server (e.g.
//! `REDIS_URL=redis://127.0.0.1:6379`); `just up` provides one locally and CI
//! supplies a containerised Redis. The suite uses a unique key prefix per run,
//! so it does not disturb unrelated keys.

mod common;

#[tokio::test]
async fn redis_storage_conformance() {
    let Some(storage) = common::storage("REDIS_URL").await else {
        return;
    };
    doorman_conformance::run(&storage).await;
    // The Redis adapter pushes the `expires_at > now` predicate into
    // `list_for_user`, so it satisfies the database-backed assertions too.
    doorman_conformance::run_db_backed(&storage).await;
}
