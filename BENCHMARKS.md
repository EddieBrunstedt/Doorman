# Benchmarks

doorman ships [criterion](https://github.com/bheisler/criterion.rs) benches covering the hot auth paths at three layers: the framework-agnostic managers (`doorman-core`), the HTTP request path (`doorman-axum`), and the storage adapters (`doorman-sqlx`).

Absolute numbers are machine-specific and not meaningful on their own. The value is in **relative** comparison: cached vs uncached, allowed vs limited, in-memory vs SQLite vs Postgres, with vs without crypto, and one table size vs another. Run a baseline, change something, and compare — criterion reports the delta automatically.

## Running

```sh
# Everything in a crate
cargo bench -p doorman-core
cargo bench -p doorman-axum
cargo bench -p doorman-sqlx --features sqlite

# Storage benches with the optional Postgres path (needs a running Docker daemon; see below)
cargo bench -p doorman-sqlx --features "sqlite postgres" --bench storage

# A single bench target
cargo bench -p doorman-core --bench passkey_auth
cargo bench -p doorman-axum --bench concurrency

# A single function within a target (substring filter)
cargo bench -p doorman-core --bench session -- token_hash
cargo bench -p doorman-sqlx --features sqlite --bench storage -- list_for_user

# Quick smoke run (rough numbers, much faster)
cargo bench -p doorman-core --bench session -- \
    --warm-up-time 0.2 --measurement-time 0.3 --sample-size 10
```

Criterion writes detailed reports (including HTML if `gnuplot` is present) under `target/criterion/`.

## Reproducible protocol

Benchmarks are only comparable when the build and the machine are held fixed. The workspace pins a dedicated `[profile.bench]` (in the root `Cargo.toml`) so the binary is built the same way every time:

```toml
[profile.bench]
opt-level = 3
lto = "fat"
codegen-units = 1
debug = false
```

`codegen-units = 1` plus fat LTO removes the run-to-run variance that incremental codegen-unit partitioning otherwise introduces. The first build under this profile is slow; subsequent runs reuse it.

To get stable, comparable numbers:

1. **Record the environment** (fill the table below for any numbers you publish): exact `rustc -Vv`, CPU model, core count, RAM, OS/kernel, and the CPU frequency governor.
2. **Pin the CPU.** On Linux set the governor to `performance` and disable turbo/boost so clocks don't drift mid-run:
   ```sh
   sudo cpupower frequency-set -g performance
   # AMD: echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost
   # Intel: echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
   ```
3. **Quiesce the machine.** Close other workloads; run on AC power; let the machine reach thermal steady state.
4. **Use a real measurement window.** Run the full criterion defaults (no `--measurement-time` shortcuts) for any number you intend to compare or publish. The smoke-run flags above are for "did it move a lot?", not for the record.
5. **Compare with saved baselines** (below) rather than eyeballing two separate runs.

### Environment template

Fill this in alongside any published numbers:

| Field       | Value                               |
| ----------- | ----------------------------------- |
| `rustc`     | _e.g._ `1.85.0 (stable)`            |
| CPU         | _e.g._ `AMD Ryzen 9 7950X, 16C/32T` |
| RAM         | _e.g._ `64 GiB`                     |
| OS/kernel   | _e.g._ `Arch Linux, 7.0.10`         |
| Governor    | _e.g._ `performance, boost off`     |
| doorman rev | _e.g._ `git rev-parse --short HEAD` |

## Saved baselines and regression comparison

Criterion can persist a named baseline and compare a later run against it — this is what CI uses to flag regressions (wired up in the release-hygiene phase).

```sh
# Record a baseline named "main"
cargo bench -p doorman-core --bench session -- --save-baseline main

# Later, compare the working tree against it (does not overwrite "main")
cargo bench -p doorman-core --bench session -- --baseline main
```

A typical local flow: `--save-baseline before`, make a change, `--baseline before`. Criterion prints the percentage change and whether it considers the difference significant. Baselines live under `target/criterion/` and are keyed by benchmark id, so renaming a bench function starts a fresh baseline.

## What is measured

### `doorman-core` — manager level, no HTTP

| Bench (`--bench`) | Function               | Path measured                                                                                                                                                   |
| ----------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `session`         | `session_create`       | `SessionManager::create` against the in-memory store (token gen + hash + insert + audit emit).                                                                  |
| `session`         | `session_validate`     | Manager-level `validate` against the in-memory store (no cache in front — `doorman-axum` measures cache behavior separately).                                   |
| `session`         | `token_hash`           | `hash_token` throughput. Runs on every authenticated request; the end-to-end request benches (`doorman-axum` `request_path`) fold this cost into the full path. |
| `rate_limit`      | `rate_limit_allowed`   | `InMemoryRateLimiter::check_and_charge` on a within-budget attempt.                                                                                             |
| `rate_limit`      | `rate_limit_limited`   | `check_and_charge` on a saturated bucket (the hot path under an active attack).                                                                                 |
| `enrollment`      | `signup_request`       | `SignupManager::request_signup` — normalize/validate, rate-limit, user provisioning, token issuance, link render, captured email send.                          |
| `passkey_auth`    | `passkey_authenticate` | Full discoverable auth ceremony: `start_authentication` → `SoftPasskey` signs → `finish_authentication` + session issue. The headline login-throughput number.  |
| `passkey_auth`    | `passkey_finish`       | Just `finish_authentication` (assertion verify, counter check, user-handle binding, session issue); the start + signing happen in untimed `iter_custom` setup.  |

### `doorman-axum` — HTTP path via `tower::ServiceExt::oneshot`

| Bench           | Function                   | Path measured                                                                                                                                                              |
| --------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `session_cache` | `cache_hit`                | Raw `SessionCache::get` hit with a precomputed token hash. This isolates the real process-local cache, not the full session layer.                                         |
| `session_cache` | `cache_miss_populate`      | `SessionResolver::resolve` on a cold cache: hash token, cache miss, session validate, user lookup and status check, cache insert. Cache clearing happens in untimed setup. |
| `request_path`  | `me_cached`                | `GET /me` with a valid bearer token, cache warm — the realistic per-request auth overhead (including token hashing) added to every endpoint.                               |
| `request_path`  | `me_uncached`              | The same request with the cache cleared in untimed setup each iteration (cold-cache store round-trip through the full router).                                             |
| `request_path`  | `layer_no_auth`            | An unauthenticated request through the layer — its fixed cost on traffic carrying no session.                                                                              |
| `concurrency`   | `cache_hit`                | 32 concurrent `SessionCache::get` hits across distinct keys on a fixed 4-worker runtime — characterizes the sharded cache lock under fan-out.                              |
| `concurrency`   | `validate`                 | 32 concurrent `SessionManager::validate_by_hash` calls against the in-memory store with no cache — characterizes the reference store's read lock under fan-out.            |
| `parsing`       | `csrf/same_origin_allow`   | `CsrfLayer` decision on a same-origin cookie POST: parse `Cookie` + `Origin`, then call the inner service.                                                                 |
| `parsing`       | `csrf/cross_origin_reject` | The CSRF decision on a cross-origin cookie POST: parse and short-circuit with a rejection.                                                                                 |
| `parsing`       | `csrf/bearer_bypass`       | The CSRF decision when an `Authorization: Bearer` header is present: the bearer parse skips the origin check.                                                              |

### `doorman-sqlx` — storage adapters

All storage benches are registered under a per-dialect group, so ids read `sqlite/...` and (with the Postgres path enabled) `postgres/...`.

| Bench (group/id)                             | Path measured                                                                                                                                  |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `{dialect}/session_create`                   | Insert a session row into a table pre-seeded to a representative size.                                                                         |
| `{dialect}/find_by_token_hash`               | The per-request hot path: look up a session by hashed token.                                                                                   |
| `{dialect}/find_by_id`                       | Indexed primary-key lookup.                                                                                                                    |
| `{dialect}/find_by_token_hash/{1,100,10000}` | The hashed-token lookup at three table sizes, showing index scaling.                                                                           |
| `{dialect}/list_for_user/{1,100,10000}`      | Listing a user's active sessions as the per-user row count grows (throughput reported per row).                                                |
| `{dialect}/purge_expired`                    | The indexed `DELETE ... WHERE expires_at <= ?` over a table of expired rows, re-seeded before each pass (throughput reported per row removed). |

SQLite runs against an ephemeral `sqlite::memory:` database and is always enabled. The Postgres path is optional: compile with the `postgres` feature and have a Docker daemon running. It starts a throwaway Postgres container via [testcontainers](https://docs.rs/testcontainers) — no external server or connection string — and resets the `public` schema for a clean migration state, exactly like the conformance suite. A pinned container image also makes the numbers reproducible across machines. Compare the `sqlite/...` and `postgres/...` groups against the `doorman-core` `session` numbers (the in-memory reference) to see adapter overhead.

## Reading the results

- **Cached vs uncached** (`session_cache`, `request_path`) shows what the session-resolution cache buys. Use `request_path` for full router / middleware costs; `session_cache` is a lower-level cache/store microbench.
- **Contention** (`concurrency`) shows how cache and store locking hold up under concurrent fan-out; compare its per-element throughput against the single-threaded `session_cache`/`session` latencies.
- **Allowed vs limited** (`rate_limit`) shows the limiter's cost in both regimes.
- **With vs without crypto**: `passkey_authenticate`/`passkey_finish` dwarf the other core paths — WebAuthn signature verification dominates login latency. `passkey_finish` isolates the server-side verify from the ceremony setup.
- **In-memory vs SQLite vs Postgres**: compare the `doorman-sqlx` dialect groups against the `doorman-core` `session` baseline for adapter overhead, and read the scaling ids to see how lookups and listing grow with table size.
- **Parsing overhead** (`parsing`) shows the fixed per-request cookie/header parsing cost the CSRF layer adds to state-changing requests.
