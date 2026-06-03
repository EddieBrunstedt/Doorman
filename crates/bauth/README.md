# bauth

Umbrella crate for [bauth](../../README.md), the opinionated passkey-only Axum
auth library. One dependency and one version to bump: it re-exports
[`bauth-core`](../core), [`bauth-axum`](../axum), and [`bauth-sqlx`](../sqlx)
behind features as `bauth::core`, `bauth::axum`, and `bauth::sqlx`.

```toml
[dependencies]
bauth = { version = "0.1", features = ["axum", "sqlite"] }
```

Hosts that want only a subset can depend on the individual crates directly. The
quickstart, documentation index, and production checklist live in the
[workspace README](../../README.md) and [`docs/`](../../docs).

API reference: `cargo doc -p bauth --open`.
