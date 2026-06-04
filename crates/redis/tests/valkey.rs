//! Runs the shared storage-conformance suite against Valkey.
//!
//! Valkey shares the RESP protocol and the command set this adapter uses, so
//! the identical suite runs unchanged; only the target server differs. Skipped
//! unless `VALKEY_URL` points at a disposable server (e.g.
//! `VALKEY_URL=redis://127.0.0.1:6380`); `just up` provides one locally and CI
//! supplies a containerised Valkey. Running both this and the Redis suite is
//! what catches any Redis/Valkey drift mechanically (§3).

mod common;

#[tokio::test]
async fn valkey_storage_conformance() {
    let Some(storage) = common::storage("VALKEY_URL").await else {
        return;
    };
    doorman_conformance::run(&storage).await;
    doorman_conformance::run_db_backed(&storage).await;
}
