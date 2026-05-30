# Benchmarks

bauth ships [criterion](https://github.com/bheisler/criterion.rs) benches covering the hot auth paths at three layers: the framework-agnostic managers (`bauth-core`), the HTTP request path (`bauth-axum`), and the storage adapters (`bauth-sqlx`).

Absolute numbers are machine-specific and not meaningful on their own. The value is in **relative** comparison: cached vs uncached, allowed vs limited, in-memory vs SQLite, with vs without crypto. Run a baseline, change something, and compare — criterion reports the delta automatically.

## Running

```sh
# Everything in a crate
cargo bench -p bauth-core
cargo bench -p bauth-axum
cargo bench -p bauth-sqlx --features sqlite

# A single bench target
cargo bench -p bauth-core --bench passkey_auth
cargo bench -p bauth-axum --bench session_cache

# A single function within a target (substring filter)
cargo bench -p bauth-core --bench session -- token_hash

# Quick smoke run (rough numbers, much faster)
cargo bench -p bauth-core --bench session -- \
    --warm-up-time 0.2 --measurement-time 0.3 --sample-size 10
```

Criterion writes detailed reports (including HTML if `gnuplot` is present) under `target/criterion/`.

## What is measured

### `bauth-core` — manager level, no HTTP

| Bench (`--bench`) | Function               | Path measured                                                                                                                                                     |
| ----------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `session`         | `session_create`       | `SessionManager::create` against the in-memory store (token gen + hash + insert + audit emit).                                                                    |
| `session`         | `session_validate`     | Manager-level `validate` against the in-memory store (no cache in front — `bauth-axum` measures cache behavior separately).                                       |
| `session`         | `token_hash`           | `hash_token` throughput. Runs on every authenticated request.                                                                                                     |
| `rate_limit`      | `rate_limit_allowed`   | `InMemoryRateLimiter::check` on a within-budget attempt.                                                                                                          |
| `rate_limit`      | `rate_limit_limited`   | `check` on a saturated bucket (the hot path under an active attack).                                                                                              |
| `enrollment`      | `signup_request`       | `SignupManager::request_signup` — normalize/validate, rate-limit, user provisioning, token issuance, link render, captured email send.                            |
| `passkey_auth`    | `passkey_authenticate` | Full discoverable auth ceremony: `start_authentication` → `SoftPasskey` signs → `finish_authentication` + session issue. The only crypto-heavy steady-state path. |

### `bauth-axum` — HTTP path via `tower::ServiceExt::oneshot`

| Bench           | Function              | Path measured                                                                                                                                                              |
| --------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `session_cache` | `cache_hit`           | Raw `SessionCache::get` hit with a precomputed token hash. This isolates the real process-local cache, not the full session layer.                                         |
| `session_cache` | `cache_miss_populate` | Cold-cache populate sequence after token extraction: hash token, observe cache miss, manager validate, user lookup, cache insert. Cache clearing happens in untimed setup. |
| `request_path`  | `me_cached`           | `GET /me` with a valid bearer token, cache warm — the realistic per-request auth overhead added to every endpoint.                                                         |
| `request_path`  | `me_uncached`         | The same request with the cache cleared in untimed setup each iteration (cold-cache store round-trip through the full router).                                             |
| `request_path`  | `layer_no_auth`       | An unauthenticated request through the layer — its fixed cost on traffic carrying no session.                                                                              |

### `bauth-sqlx` — storage adapters (requires `--features sqlite`)

| Bench     | Function                    | Path measured                                                |
| --------- | --------------------------- | ------------------------------------------------------------ |
| `storage` | `sqlite_session_create`     | Insert a session row.                                        |
| `storage` | `sqlite_find_by_token_hash` | The per-request hot path: look up a session by hashed token. |
| `storage` | `sqlite_find_by_id`         | Indexed primary-key lookup.                                  |

Runs against an ephemeral `sqlite::memory:` database. Compare these against the `bauth-core` `session` numbers (in-memory reference) to see the adapter cost. A Postgres counterpart can be added behind a `DATABASE_URL`-gated bench if a server is available.

## Reading the results

- **Cached vs uncached** (`session_cache`, `request_path`) shows what the session-resolution cache buys. Use `request_path` for full router / middleware costs; `session_cache` is a lower-level cache/store microbench.
- **Allowed vs limited** (`rate_limit`) shows the limiter's cost in both regimes.
- **With vs without crypto**: `passkey_authenticate` dwarfs the other core paths — WebAuthn signature verification dominates login latency.
- **In-memory vs SQLite**: compare `bauth-sqlx` `storage` against the `bauth-core` `session` baseline for adapter overhead.
