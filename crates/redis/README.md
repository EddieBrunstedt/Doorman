# doorman-redis

Redis/Valkey-backed ephemeral storage for the [doorman](https://codeberg.org/EddieBrunstedt/bauth) authentication library.

`doorman-redis` moves the ephemeral, TTL-bearing auth state — sessions, verification tokens, and passkey ceremony challenges — plus the rate limiter onto Redis or Valkey, so a multi-replica deployment shares them instead of keeping per-process copies. A single adapter built on `redis-rs` connects to either server.

It deliberately does not implement `UserStore` or `PasskeyCredentialStore`: those hold the system-of-record and belong in a SQL backend (`doorman-sqlx`). `RedisStorage` is always assembled into a `Storage` literal alongside a SQL adapter.

```rust,ignore
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
```

Minimum server version: Redis 6.2 / Valkey 7.2.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
