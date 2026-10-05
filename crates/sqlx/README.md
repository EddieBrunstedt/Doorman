# doorman-sqlx

SQLx-backed storage adapter for [`doorman-core`](../core). Three backends ship behind cargo features:

- `sqlite` — `SqliteStorage` for SQLite databases.
- `postgres` — `PostgresStorage` for Postgres databases.
- `mysql` — `MySqlStorage` for MySQL and MariaDB databases (one driver serves both).

All implement every storage trait the library defines: `UserStore`, `SessionStore`, `VerificationTokenStore`, `PasskeyCredentialStore`, `PasskeyChallengeStore`.

## Usage

```toml
[dependencies]
doorman-sqlx = { version = "0.1", features = ["sqlite"] }
```

```rust
use doorman_sqlx::SqliteStorage;

let storage = SqliteStorage::connect("sqlite:///var/lib/myapp/auth.db?mode=rwc").await?;
storage.migrate().await?;

let composite = storage.all_stores();   // doorman_core::storage::Storage — hand to AuthCore::builder
```

For an ephemeral in-memory database (handy in tests), use `"sqlite::memory:"` as the URL.

For Postgres, swap the feature and the type:

```toml
[dependencies]
doorman-sqlx = { version = "0.1", features = ["postgres"] }
```

```rust
use doorman_sqlx::PostgresStorage;

let storage = PostgresStorage::connect("postgres://user:pass@host/db").await?;
storage.migrate().await?;
let composite = storage.all_stores();
```

For MySQL or MariaDB, use the `mysql` feature and `MySqlStorage`:

```toml
[dependencies]
doorman-sqlx = { version = "0.1", features = ["mysql"] }
```

```rust
use doorman_sqlx::MySqlStorage;

let storage = MySqlStorage::connect("mysql://user:pass@host:3306/db").await?;
storage.migrate().await?;
let composite = storage.all_stores();
```

## Schemas and migrations

The migrations live under `migrations/sqlite/`, `migrations/postgres/`, and `migrations/mysql/`. They are embedded into the binary at compile time via `sqlx::migrate!` and applied by `migrate()`. The schemas are the same shape; only dialect details differ — column types (`BLOB`/`BINARY` vs `BYTEA`, `TEXT`/`DATETIME(6)` vs `TIMESTAMPTZ`) and, on MySQL, the absence of `DELETE … RETURNING` (the atomic single-use take runs as `SELECT … FOR UPDATE` + `DELETE` in a transaction instead). MySQL timestamps use `DATETIME(6)` rather than `TIMESTAMP` to keep sub-second TTL precision and span years outside `TIMESTAMP`'s 1970–2038 range.

## Connection pool tuning

`connect(url)` opens an 8-connection pool with sensible defaults. For production tuning, build your own pool and use `from_pool`:

```rust
use sqlx::sqlite::SqlitePoolOptions;
use doorman_sqlx::SqliteStorage;

let pool = SqlitePoolOptions::new()
    .max_connections(32)
    .connect("sqlite:///var/lib/myapp/auth.db?mode=rwc")
    .await?;
let storage = SqliteStorage::from_pool(pool);
```

`pool()` returns the underlying `SqlitePool` / `PgPool` / `MySqlPool` if you want to share it with the rest of your app.

## Testing

`cargo test -p doorman-sqlx --features sqlite` runs the SQLite suite in memory; no external services needed.

The Postgres and MySQL/MariaDB suites are self-contained: each starts its own throwaway database container via [testcontainers](https://docs.rs/testcontainers), so they need only a running Docker daemon — no external server or connection-string env var. Every run gets a fresh, empty database that is removed when the test ends. A running Docker daemon is therefore a prerequisite:

```sh
cargo test -p doorman-sqlx --features postgres
cargo test -p doorman-sqlx --features mysql   # MySQL + MariaDB
```

Running both the MySQL and MariaDB suites is what catches MySQL/MariaDB drift mechanically.
