# doorman-mongodb

MongoDB storage adapter for the [doorman](https://codeberg.org/EddieBrunstedt/Doorman) authentication library.

`doorman-mongodb` fills **all five** storage traits against a MongoDB database, using one collection per record kind. It suits any deployment where MongoDB is already the path of least resistance — including serverless, edge, and managed-database environments. It is built on the official [`mongodb`](https://crates.io/crates/mongodb) Rust driver.

The adapter takes a caller-built `mongodb::Database`, so the host owns connection pool, credentials, TLS configuration, and read/write concern; doorman issues operations through it unchanged.

## Usage

```toml
[dependencies]
doorman-mongodb = "0.1"
mongodb = "3"
```

```rust
use doorman_mongodb::MongoDbStorage;

let client = mongodb::Client::with_uri_str("mongodb://localhost:27017").await?;
let database = client.database("my_app");

let storage = MongoDbStorage::new(database);
storage.ensure_indexes().await?; // idempotent; safe on every boot

let core = AuthCore::builder(storage.all_stores())
    // ... rest of the builder
    .build()?;
```

Through the umbrella crate, enable the `mongodb` feature and reach the adapter at `doorman::mongodb`:

```toml
doorman = { version = "0.1", features = ["axum", "mongodb"] }
```

## Collections

| Collection                | `_id` scheme           | Notable indexes                        |
| ------------------------- | ---------------------- | -------------------------------------- |
| `users`                   | UUID string            | Partial unique on `email`              |
| `sessions`                | UUID string            | Unique on `token_hash`; `user_id`; TTL |
| `verification_tokens`     | `{purpose}#{hash hex}` | `(user_id, purpose)`; TTL              |
| `passkey_credentials`     | credential-id hex      | `user_id`                              |
| `passkey_registrations`   | UUID string            | `user_id`; TTL                         |
| `passkey_authentications` | UUID string            | TTL                                    |

## Design highlights

- **Atomic single-use.** `consume_token`, `take_registration`, and `take_authentication` are a `findOneAndDelete` call. MongoDB serializes writes per document, so exactly one concurrent caller observes the old image — the single-use guarantee tokens and ceremonies rely on.
- **Email uniqueness.** A partial unique index on `email` (covering only documents where the field is a string) enforces email uniqueness while allowing multiple email-less users to coexist without conflict. No companion guard document or transaction is needed; a standalone MongoDB node (no replica set) suffices.
- **Expiry.** MongoDB's TTL monitor runs roughly every 60 seconds and is a production memory-reclamation backstop only. A separate `ttl` field is written only for future-dated expiries (so past-dated test fixtures are not swept). Listing paths push `expires_at > now` into the query, and `purge_expired` performs authoritative, immediate reclamation via `deleteMany`.
- **Timestamps.** Stored as BSON `Date` (millisecond precision) so they sort correctly and drive the TTL monitor directly.

## Provisioning indexes

`ensure_indexes()` creates all collection indexes idempotently. It is safe to call on every boot — MongoDB's `createIndex` is a no-op when the index already exists with the same definition. A host that manages its own infrastructure can create the indexes out of band and skip this call (see the `ensure_indexes` doc comment for the full list).

## TLS / crypto stack

The driver's ring-backed `rustls-tls` feature is enabled and `rustls-tls-aws-lc` left off, keeping the workspace on its single ring crypto stack (no `aws-lc`).

## Testing

`cargo test -p doorman-mongodb` runs the shared storage-conformance suite. It is self-contained: it starts a throwaway MongoDB container via [testcontainers](https://docs.rs/testcontainers), creates indexes, and removes the container when the test ends — no external URI or environment variable needed. A running Docker daemon is therefore a prerequisite:

```sh
cargo test -p doorman-mongodb
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
