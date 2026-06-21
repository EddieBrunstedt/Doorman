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
    // Adapters that push the expiry predicate into their query layer also run:
    doorman_conformance::run_db_backed(&storage.all_stores()).await;
}
```

`run` is the backend-agnostic suite every adapter must pass. `run_db_backed` adds assertions that only hold for adapters which filter expired rows in their query layer (the in-memory reference store deliberately returns them and the manager filters instead), so call it only from those harnesses.

The checks share one `Storage` instance and isolate themselves with freshly minted ids and token hashes, so the suite is safe to run against a shared database; flush or use a disposable database for repeatable runs.
