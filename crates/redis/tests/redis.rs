//! Runs the shared storage-conformance suite against the Redis adapter.
//!
//! Self-contained: it starts a throwaway Redis container via `testcontainers`,
//! so it needs a running Docker daemon and nothing else. There is no
//! environment-variable branch and no external server — every run gets a fresh,
//! empty server that is removed when the test ends. The suite uses a unique key
//! prefix per run. A running Docker daemon is therefore a prerequisite for the
//! workspace test run.

mod common;

use common::Backend;

#[tokio::test]
async fn redis_storage_conformance() {
    // `_node` keeps the container alive until the end of the test.
    let (_node, storage) = common::storage(Backend::Redis).await;
    doorman_conformance::run(&storage).await;
}
