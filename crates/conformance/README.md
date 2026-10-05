# doorman-conformance

Backend-agnostic storage-conformance suite for [doorman](https://codeberg.org/EddieBrunstedt/Doorman) storage adapters.

Every check takes a `doorman_core::storage::Storage` and asserts the contract the `doorman-core` managers rely on, independent of how the rows are stored. Use it to validate any adapter — first-party (`doorman-sqlx`, `doorman-redis`) or your own — against the exact same assertions.

## Usage

Add it under `[dev-dependencies]` and call it from a test that stands up your adapter and hands the suite a populated `Storage`:

```rust
#[tokio::test]
async fn my_adapter_conformance() {
    let storage = MyStorage::connect(url).await.expect("connect");
    doorman_conformance::run(&storage.all_stores()).await;
}
```

`run` is the backend-agnostic suite every adapter must pass, the in-memory reference stores included. It must be awaited inside a Tokio runtime: the concurrency checks spawn tasks to race one single-use row. `#[tokio::test]` is enough; a multi-thread runtime also runs the racing callers in parallel.

The checks share one `Storage` instance and isolate themselves with freshly minted ids and token hashes, so the suite is safe to run against a shared database; flush or use a disposable database for repeatable runs.
