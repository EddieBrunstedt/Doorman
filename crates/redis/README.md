# doorman-redis

Redis/Valkey-backed ephemeral storage and rate limiter for the [doorman](https://codeberg.org/EddieBrunstedt/Doorman) authentication library.

`doorman-redis` moves the ephemeral, TTL-bearing auth state — sessions, verification tokens, and passkey ceremony challenges — plus the rate limiter onto Redis or Valkey, so a multi-replica deployment shares them (instant cross-process revoke, one rate-limit budget) instead of keeping per-process copies. A single adapter built on [`redis-rs`](https://crates.io/crates/redis) connects to either server.

It deliberately does **not** implement `UserStore` or `PasskeyCredentialStore`: those hold the system-of-record (accounts and the actual passkey material), which never expires and wants relational guarantees, so it belongs in a SQL backend (`doorman-sqlx`). `RedisStorage` therefore has no `all_stores()`; it is always assembled into a `Storage` literal alongside a SQL adapter, which makes the SQL/Redis split explicit at the call site.

## Usage

```toml
[dependencies]
doorman-redis = "0.1"
doorman-sqlx = { version = "0.1", features = ["postgres"] }
```

```rust
use doorman_core::storage::Storage;
use doorman_redis::RedisStorage;
use doorman_sqlx::PostgresStorage;

let pg = PostgresStorage::connect("postgres://localhost/app").await?;
pg.migrate().await?;
let redis = RedisStorage::connect("redis://localhost:6379").await?;

let storage = Storage {
    users:               pg.user_store(),
    passkey_credentials: pg.passkey_credential_store(),
    sessions:            redis.session_store(),
    verification_tokens: redis.verification_token_store(),
    passkey_challenges:  redis.passkey_challenge_store(),
};

let auth = AuthService::builder(storage)
    .limiter(redis.rate_limiter())
    // ... rest of the builder
    .build()?;
```

Through the umbrella crate, enable a SQL feature plus `redis` (or `valkey`) and reach the adapter at `doorman::redis`:

```toml
doorman = { version = "0.1", features = ["axum", "postgres", "redis"] }
```

## The rate limiter

The rate limiter is not a store, so it is wired separately from the `Storage` literal — pass it to the builder with `.limiter(redis.rate_limiter())`. It is a sliding-window log driven by a single Lua script, so check-and-charge is atomic across replicas, matching the in-memory limiter's semantics. `rate_limiter()` sources `now` from a `SystemClock`; `rate_limiter_with_clock(clock)` injects a different one (e.g. a mock clock in tests) so the limiter's window agrees with the managers' notion of time.

## Connection management

`connect(url)` opens a multiplexed, auto-reconnecting `ConnectionManager` — the right default for the short, single-round-trip operations these stores issue, with no pool to size. Hosts who want to bring their own connection (TLS, auth, timeouts, or a custom pool) have two seams:

```rust
// Configure the client yourself, then let the adapter open the manager.
let client = redis::Client::open("rediss://user:pass@host:6379")?;
let redis = RedisStorage::from_client(client).await?;

// Or hand in an already-established ConnectionManager.
let redis = RedisStorage::from_connection_manager(manager);
```

All keys are namespaced under a prefix (default `doorman:`); override it with `.with_prefix("app:")`. There is no `migrate()` — Redis is schemaless — but `ping()` is a health check. `connection_manager()` returns a clone of the underlying connection to share with the rest of the app.

## Connection string forms

The `redis://` scheme addresses both Redis and Valkey; only the target server differs.

| Form                              | Meaning                       |
| --------------------------------- | ----------------------------- |
| `redis://host:6379`               | plain TCP                     |
| `redis://host:6379/2`             | select logical database 2     |
| `redis://:password@host:6379`     | password auth (`requirepass`) |
| `redis://user:password@host:6379` | ACL username + password       |
| `rediss://host:6379`              | TLS (note the double `s`)     |
| `unix:///run/redis.sock`          | Unix domain socket            |

## Redis vs Valkey

Valkey is a fork of Redis (from 7.2.4) under the Linux Foundation. They share the RESP wire protocol and every command this adapter uses (`GET`/`SET`/`GETDEL`, sorted sets, Lua `EVAL`/`EVALSHA`, `SCAN`, `PEXPIREAT`), so one codebase serves both. The CI conformance suite runs against a live Redis **and** a live Valkey so any drift is caught mechanically.

**Minimum server version: Redis 6.2 / Valkey 7.2** (for the atomic `GETDEL` that backs single-use token consumption; sorted sets and Lua are available far earlier).

## Operational notes

**Single node, not Cluster.** The adapter targets a single logical Redis/Valkey (optionally replicated), not Redis Cluster. Several operations span multiple keys in one round trip — the `MULTI/EXEC` writes, the `MGET` batch reads, and the multi-key `DEL` — and assume those keys share a node. On a clustered deployment whose keys hash to different slots, these raise `CROSSSLOT` errors at runtime rather than failing cleanly at startup, so point the adapter at a non-clustered endpoint.

**Purge scans the keyspace.** `purge_expired` walks the server with `SCAN`, so its cost scales with the _total_ number of keys present, not just doorman's. On a server shared with unrelated data, give doorman its own logical database (`redis://host:6379/<n>`) or instance, or run the purge on a cadence that accounts for the wider keyspace.

## Testing

`cargo test -p doorman-redis` runs the shared storage-conformance suite plus the rate-limiter and single-use concurrency tests. They are self-contained: each starts its own throwaway Redis or Valkey container via [testcontainers](https://docs.rs/testcontainers), so they need only a running Docker daemon — no external server or `*_URL` env var. Running both the Redis and Valkey suites is what catches Redis/Valkey drift mechanically.

A running Docker daemon is therefore a prerequisite:

```sh
cargo test -p doorman-redis
```

`just test-redis` wraps this command. Each test gets its own fresh container, so there is no shared state and no destructive `FLUSHDB`.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
