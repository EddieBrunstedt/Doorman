# doorman

Umbrella crate for [doorman](../../README.md), the opinionated passkey-only Axum auth library. One dependency and one version to bump: it re-exports [`doorman-core`](../core), [`doorman-axum`](../axum), and [`doorman-sqlx`](../sqlx) behind features as `doorman::core`, `doorman::axum`, and `doorman::sqlx`.

```toml
[dependencies]
doorman = { version = "0.1", features = ["axum", "sqlite"] }
```

Hosts that want only a subset can depend on the individual crates directly. The quickstart, documentation index, and production checklist live in the [workspace README](../../README.md) and [`docs/`](../../docs).

API reference: `cargo doc -p doorman --open`.
