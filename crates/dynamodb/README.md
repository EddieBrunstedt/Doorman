# doorman-dynamodb

Amazon DynamoDB storage adapter for the [doorman](https://codeberg.org/EddieBrunstedt/Doorman) authentication library.

`doorman-dynamodb` fills **all five** storage traits against a single DynamoDB table, so an AWS-native or Lambda/serverless deployment can run doorman with neither a SQL server nor a Redis instance — exactly the environments where a managed, pay-per-request key-value store is already the path of least resistance. It is built on the official [`aws-sdk-dynamodb`](https://crates.io/crates/aws-sdk-dynamodb).

The adapter takes a caller-built `aws_sdk_dynamodb::Client`, so the host owns region, credentials, retry, and endpoint configuration; doorman issues operations through it unchanged.

## Usage

```toml
[dependencies]
doorman-dynamodb = "0.1"
aws-config = "1"
aws-sdk-dynamodb = "1"
```

```rust,ignore
use doorman_dynamodb::DynamoDbStorage;

let config = aws_config::load_from_env().await;
let client = aws_sdk_dynamodb::Client::new(&config);

let storage = DynamoDbStorage::new(client, "doorman");
storage.create_table().await?; // idempotent; safe on every boot

let auth = AuthService::builder(storage.all_stores())
    // ... rest of the builder
    .build()?;
```

Through the umbrella crate, enable the `dynamodb` feature and reach the adapter at `doorman::dynamodb`:

```toml
doorman = { version = "0.1", features = ["axum", "dynamodb"] }
```

## How it maps onto DynamoDB

Everything lives in **one table** addressed by a single string partition key (`pk`), with two global secondary indexes for the secondary access patterns and DynamoDB's native per-item TTL for the ephemeral records.

| Record                 | `pk`                      | `lookup-index` (`gsi1pk`) | `owner-index` (`gsi2pk`) |
| ---------------------- | ------------------------- | ------------------------- | ------------------------ |
| User                   | `user#<id>`               | —                         | —                        |
| Email guard            | `email#<email>`           | —                         | —                        |
| Session                | `session#<id>`            | `shash#<hash>`            | `usess#<uid>`            |
| Verification token     | `vtoken#<purpose>#<hash>` | —                         | `uvtok#<uid>#<purpose>`  |
| Passkey credential     | `passkey#<credential id>` | —                         | `upk#<uid>`              |
| Passkey registration   | `pkreg#<id>`              | —                         | `upkreg#<uid>`           |
| Passkey authentication | `pkauth#<id>`             | —                         | —                        |

The notable design points:

- **Atomic single-use.** `consume_token`, `take_registration`, and `take_authentication` are a `DeleteItem` with `ReturnValues=ALL_OLD`. DynamoDB serializes writes per item, so under concurrency exactly one caller observes the value — the single-use guarantee single-use tokens and challenges rely on.
- **Email uniqueness.** A GSI can enforce no constraints and is only eventually consistent, so a user's email is guarded by a strongly-consistent companion item written in the same `TransactWriteItems` as the user (each guarded by `attribute_not_exists`). The guard doubles as the email → user lookup. Every other secondary lookup uses a GSI, which DynamoDB maintains automatically — deleting or TTL-evicting a row drops its index entries for free, so there is no dangling-index bookkeeping.
- **Expiry.** Native TTL deletion lags by up to ~48h and is a _memory_ backstop only. The stores filter `expires_at > now` on read, and `purge_expired` performs the authoritative, immediate reclamation (a consistent table scan filtered to the relevant record kind).

## Eventual consistency

Reads of the system-of-record (users, passkey credentials) are strongly-consistent, so a record is visible the instant it is written. The per-user collection listings and the token-hash session lookup read a GSI, which is eventually consistent: a row is normally visible within milliseconds of its write but not guaranteed to be on the very next read. The managers re-resolve and re-filter, so this never yields an incorrect result — only, rarely, a momentarily stale one.

## Provisioning the table

`create_table()` creates the table with on-demand (`PAY_PER_REQUEST`) billing, both GSIs (all-projection), and TTL enabled on the `ttl` attribute. It is idempotent — an already-existing table is a no-op — so it is safe to call on every boot.

A host that manages its own infrastructure (Terraform, CloudFormation, CDK) can skip it and create the table out of band. The requirements are: a single string partition key `pk`; a `lookup-index` GSI with string partition key `gsi1pk`; an `owner-index` GSI with string partition key `gsi2pk`; both GSIs projecting `ALL`; and TTL enabled on the `ttl` attribute.

## TLS / crypto stack

The adapter does not bundle an HTTP client or a TLS stack of its own — the host's `aws_sdk_dynamodb::Client` brings the connector. This keeps doorman off `aws-lc` (a second crypto stack the workspace otherwise avoids) when you wire the client with a ring-backed rustls connector, matching the rest of doorman.

## Testing

`cargo test -p doorman-dynamodb` runs the shared storage-conformance suite. It is self-contained: it starts a throwaway [DynamoDB Local](https://hub.docker.com/r/amazon/dynamodb-local) container via [testcontainers](https://docs.rs/testcontainers), provisions a fresh table, and removes the container when the test ends — no external table or `*_URL` env var. A running Docker daemon is therefore a prerequisite:

```sh
cargo test -p doorman-dynamodb
```

`just test-dynamodb` wraps this command.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
