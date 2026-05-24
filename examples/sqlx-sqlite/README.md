# bauth-sqlx-sqlite

Reference storage adapter for `bauth-core` using SQLx against SQLite.

Implements every storage trait the library defines: `UserStore`,
`SessionStore`, `PasswordCredentialStore`, `VerificationTokenStore`,
`PasskeyCredentialStore`, `PasskeyChallengeStore`, `OAuthIdentityStore`,
`OAuthStateStore`.

## Usage

```rust
use std::sync::Arc;
use bauth_sqlx_sqlite::SqliteStorage;

let storage = SqliteStorage::connect("sqlite:///var/lib/myapp/auth.db?mode=rwc").await?;
storage.migrate().await?;

let users = storage.user_store();
let sessions = storage.session_store();
// ... wire up the rest into the bauth managers.
```

For an in-memory DB used in tests, pass `"sqlite::memory:"` as the URL.

## Schema

See [`migrations/0001_initial.sql`](migrations/0001_initial.sql) — one
table per logical store, plus indexes on the columns the storage trait
methods hit. Migrations are embedded into the binary at compile time via
`sqlx::migrate!` and applied by `SqliteStorage::migrate()`.

## Porting to Postgres

The SQL is plain enough to copy across with two tweaks:

- Replace `BLOB` with `BYTEA` (or `UUID` for the UUID columns).
- The `DELETE … RETURNING` queries used for atomic consume already work
  on Postgres unchanged.

The Rust code itself moves over by swapping `SqlitePool` for `PgPool` and
the `sqlx::sqlite::SqliteRow` mapping helpers for the Postgres
equivalents.

## What this crate intentionally does not do

- It is not published to crates.io. Copy the file into your host app, or
  depend on this example as a path/git dependency until a polished
  `bauth-sqlx` crate ships.
- It does not bundle a connection-pool strategy beyond a sensible
  default (`max_connections(8)`). Configure your own pool and pass it
  to `SqliteStorage::from_pool`.
