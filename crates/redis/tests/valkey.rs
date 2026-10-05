//! Runs the shared storage-conformance suite against Valkey.
//!
//! Valkey shares the RESP protocol and the command set this adapter uses, so
//! the identical suite runs unchanged; only the target server differs. Running
//! both this and the Redis suite is what catches any Redis/Valkey drift
//! mechanically.
//!
//! Self-contained: it starts a throwaway Valkey container via `testcontainers`,
//! so it needs a running Docker daemon and nothing else. There is no
//! environment-variable branch and no external server. A running Docker daemon
//! is therefore a prerequisite for the workspace test run.

mod common;

use common::Backend;

#[tokio::test]
async fn valkey_storage_conformance() {
    // `_node` keeps the container alive until the end of the test.
    let (_node, storage) = common::storage(Backend::Valkey).await;
    doorman_conformance::run(&storage).await;
}
