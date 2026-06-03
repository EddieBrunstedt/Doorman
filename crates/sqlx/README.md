# doorman-sqlx

SQLx-backed storage adapter for [`doorman-core`](../core). Two backends ship behind cargo features:

- `sqlite` — `SqliteStorage` for SQLite databases.
- `postgres` — `PostgresStorage` for Postgres databases.

Both implement every storage trait the library defines: `UserStore`, `SessionStore`, `VerificationTokenStore`, `PasskeyCredentialStore`, `PasskeyChallengeStore`.

## Usage

```toml
[dependencies]
doorman-sqlx = { version = "0.1", features = ["sqlite"] }
```

```rust
use doorman_sqlx::SqliteStorage;

let storage = SqliteStorage::connect("sqlite:///var/lib/myapp/auth.db?mode=rwc").await?;
storage.migrate().await?;

let composite = storage.all_stores();   // doorman_core::storage::Storage — hand to AuthService::builder
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

## Schemas and migrations

One migration file per backend lives under `migrations/sqlite/` and `migrations/postgres/`. They are embedded into the binary at compile time via `sqlx::migrate!` and applied by `migrate()`. The schemas are the same shape; only column-type names differ (`BLOB` vs `BYTEA`, `TEXT` vs `TIMESTAMPTZ` for timestamps).

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

`pool()` returns the underlying `SqlitePool` / `PgPool` if you want to share it with the rest of your app.

## Testing

`cargo test -p doorman-sqlx --features sqlite` runs the SQLite suite in memory; no external services needed.

`cargo test -p doorman-sqlx --features postgres` runs the Postgres suite **if** `PG_URL` is set, e.g. `PG_URL=postgres://postgres:postgres@localhost/doorman_test`. The test wipes the `public` schema of the target database before running, so point it at a disposable test DB only.
