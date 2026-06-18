# doorman-redb

redb embedded storage adapter for the [doorman](https://codeberg.org/EddieBrunstedt/Doorman) authentication library.

`doorman-redb` fills **all five** storage traits against a single [redb](https://crates.io/crates/redb) database file — a pure-Rust, ACID-transactional, copy-on-write B-tree. No server and no network are required, which suits single-binary self-hosted deployments that want a lighter footprint than SQLite. It pulls no `libsqlite3-sys` C build dependency the way the SQLite adapter does.

## Usage

```toml
[dependencies]
doorman-redb = "0.1"
```

```rust,ignore
use doorman_redb::RedbStorage;

let storage = RedbStorage::open("doorman.redb")?;

let auth = AuthService::builder(storage.all_stores())
    // ... rest of the builder
    .build()?;
```

Through the umbrella crate, enable the `redb` feature and reach the adapter at `doorman::redb`:

```toml
doorman = { version = "0.1", features = ["axum", "redb"] }
```

`RedbStorage::open` creates the file if it is missing and opens it in place otherwise; an exclusive OS-level lock prevents two processes from opening the same file at once.

## Expiry

redb has no native per-record TTL. Expiry is emulated: every listing path filters on `expires_at > now`, and an authoritative `purge_expired` sweep physically removes expired rows. Register `purge_expired` with a background task or a periodic maintenance job in production.

## Testing

`cargo test -p doorman-redb` runs the shared storage-conformance suite against a temporary file. It needs no Docker — the suite is self-contained and runs against a local file.

```sh
cargo test -p doorman-redb
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
