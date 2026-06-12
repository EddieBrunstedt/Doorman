# doorman-libsql

libSQL / [Turso](https://turso.tech) storage adapter for the [doorman](https://codeberg.org/EddieBrunstedt/bauth) authentication library.

`doorman-libsql` fills **all five** storage traits against a remote [Turso](https://turso.tech) / libSQL database over the Hrana protocol, built on the official [`libsql`](https://crates.io/crates/libsql) client. libSQL speaks SQLite's SQL dialect, so the schema and queries mirror the SQLite adapter in `doorman-sqlx`; what this crate adds is the remote, edge-friendly connection model a Turso deployment uses.

## Usage

```toml
[dependencies]
doorman-libsql = "0.1"
```

```rust,ignore
use doorman_libsql::LibsqlStorage;

let storage = LibsqlStorage::connect_remote(
    "libsql://my-db.turso.io".to_string(),
    std::env::var("TURSO_AUTH_TOKEN")?,
).await?;
storage.migrate().await?; // idempotent; safe on every boot

let auth = AuthService::builder(storage.all_stores())
    // ... rest of the builder
    .build()?;
```

Through the umbrella crate, enable the `libsql` feature and reach the adapter at `doorman::libsql`:

```toml
doorman = { version = "0.1", features = ["axum", "libsql"] }
```

## Choosing a constructor

| Constructor                  | Backing                                                        |
| ---------------------------- | -------------------------------------------------------------- |
| `connect_remote(url, token)` | A remote Turso database over Hrana. Nothing is stored locally. |
| `from_database(db)`          | A caller-built `libsql::Database` for any other configuration. |

## Why remote-only — and how to get a local file or embedded replica

libSQL's embedded engine (local files, in-memory, embedded replicas) statically links its own SQLite C library, which **collides at link time** with `doorman-sqlx`'s SQLite adapter (also a bundled `sqlite3.c`). A single binary can't carry both, and pulling the engine in here would break the workspace's `--all-features` build, so this adapter bundles no SQLite engine and connects only to a remote server.

A local file is already covered by `doorman-sqlx`'s SQLite adapter. A host that specifically wants a libSQL _local file_ or an _embedded replica_ enables those `libsql` features in its own manifest, builds the `libsql::Database`, and hands it to `from_database` — and must then not also link `doorman-sqlx`'s SQLite adapter:

```toml
# in the host's Cargo.toml
libsql = { version = "0.9", features = ["core", "replication"] }
```

```rust,ignore
// embedded replica: local reads, writes forwarded to the primary
let db = libsql::Builder::new_remote_replica(
    "replica.db",
    "libsql://my-db.turso.io".to_string(),
    std::env::var("TURSO_AUTH_TOKEN")?,
).build().await?;
db.sync().await?; // pull the latest frames; call periodically

let storage = LibsqlStorage::from_database(db).await?;
storage.migrate().await?;
// storage.database().sync().await? to refresh later
```

## How it maps onto libSQL

libSQL is SQLite-compatible, so the schema is the `doorman-sqlx` SQLite schema in its final shape: UUIDs and 32-byte token hashes are stored as `BLOB`, timestamps as fixed-width RFC3339 `TEXT` (UTC, nanosecond precision) so a lexicographic comparison matches chronological order for the `expires_at` range scans. The notable points:

- **One consolidated, idempotent schema.** `migrate()` runs `schema.sql` — every statement is `CREATE TABLE/INDEX IF NOT EXISTS` — so it is safe to call on every boot.
- **Atomic single-use.** `consume_token`, `take_registration`, and `take_authentication` are a single `DELETE ... RETURNING`, which libSQL supports — the row is removed and its old contents returned in one statement, so single-use tokens and challenges stay single-use even under concurrency. No transaction is needed.
- **Expiry pushed into the query.** `list_for_user` filters `expires_at > now` in SQL, so expired rows never leave the store, and `purge_expired` is the authoritative reclamation pass.

## Connection model

The adapter holds a single libSQL connection, shared cheaply (by reference) across all five stores: one connection multiplexes requests to the server over Hrana, so this is the natural shape. Foreign-key enforcement (`PRAGMA foreign_keys = ON`, with the schema's `ON DELETE CASCADE`) is set on that connection. A host that wants several independent connections can build several `LibsqlStorage` values over the same `libsql::Database` via `from_database`.

## TLS / crypto stack

The `libsql` dependency enables only `remote` and `tls` (deliberately not the bundled-SQLite `core`/`replication` engine). Its TLS rides hyper-rustls' ring provider, so this adapter keeps doorman off `aws-lc` — a single ring crypto stack across the workspace.

## Testing

`cargo test -p doorman-libsql` runs the shared storage-conformance suite against a real server: it starts a throwaway [libsql-server (sqld)](https://github.com/tursodatabase/libsql/tree/main/libsql-server) container via [testcontainers](https://docs.rs/testcontainers) and runs the suite over the Hrana/remote client — the path a Turso deployment uses. A running Docker daemon is therefore a prerequisite:

```sh
cargo test -p doorman-libsql
```

`just test-libsql` wraps this command.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
