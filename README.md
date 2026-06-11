# doorman

doorman is an opinionated passkey-only Axum auth library, with email magic links for recovery only.

It gives an Axum app one steady-state login method — discoverable passkeys/WebAuthn — plus email-gated signup and recovery flows that force a passkey registration before any session is issued. There are no passwords, OAuth providers, TOTP codes, or general-purpose email login links.

This crate is pre-1.0; breaking changes can still land before the public surface is declared stable.

## Quickstart

```toml
[dependencies]
axum = "0.8"
doorman = { version = "0.1", features = ["axum", "sqlite"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

`doorman` is the umbrella crate: one dependency, one version to bump. It re-exports `doorman-core`, `doorman-axum`, `doorman-sqlx`, and `doorman-redis` behind features as `doorman::core`, `doorman::axum`, `doorman::sqlx`, and `doorman::redis`. Hosts that want only a subset can still depend on the individual crates directly.

```rust
use std::sync::Arc;
use axum::{routing::get, Router};
use doorman::prelude::*;
use doorman::core::verification::TOKEN_PLACEHOLDER;

let storage = SqliteStorage::connect("sqlite:///var/lib/app/auth.db?mode=rwc").await?;
storage.migrate().await?;
let origin = "https://app.example.com".parse()?;
let base = origin.as_str().trim_end_matches('/');
let auth = AuthService::builder(storage.all_stores())
    .email(Arc::new(TerminalEmailSender))
    .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
    .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .external_origin(origin)
    .cookie(CookieConfig::default())
    .build()?;
let app = Router::new().merge(auth.router()).route("/api/me", get(me)).layer(auth.session_layer());
```

`auth.router()` mounts the passkey, signup, recovery, and session-management routes under `/auth`. `auth.session_layer()` resolves the session cookie or bearer token so your handlers can use `AuthUser`, `OptionalAuthUser`, and `AuthSession`.

`TerminalEmailSender` is for local development. In production, implement `EmailSender` with your transactional email provider and keep `CookieConfig::secure = true`.

## User flows

- **Sign up:** `POST /auth/signup/request` sends an email link. Consuming that link starts passkey registration; `/auth/signup/finish` registers the first passkey, sends a passkey-registered security notification, and only then issues the session.
- **Sign in:** `POST /auth/passkey/authenticate/start` takes no email or username. The browser shows the user's discoverable passkeys, and the server identifies the user from the WebAuthn response.
- **Recover:** `POST /auth/recovery/request` sends a recovery link and a recovery-requested notification for a registered account; unknown addresses still receive no email. The link only starts a new passkey registration. `/auth/recovery/finish` registers that passkey, sends passkey-registered and recovery-completed notifications, and issues a session restricted by the default 24h post-recovery cool-down. The recovery-created passkey carries the same cool-down deadline: signing in with it before the deadline creates another restricted session, while pre-existing passkeys stay unrestricted.
- **Manage access:** authenticated users can list/add/delete passkeys and list/revoke sessions. During an active recovery cool-down, destructive lockout actions are blocked: deleting passkeys, revoking other sessions, and "sign out everywhere else". Adding passkeys and revoking/logging out of the current session remain allowed; passkeys added from a restricted session inherit the active cool-down. Passkey add/remove and high-risk session revocations send best-effort security notifications.
- **Sign out:** `POST /auth/logout` revokes the caller's current session and returns `204` with a `Set-Cookie` that clears the session cookie. Signing out of your own session is allowed even during the post-recovery cool-down.

Encourage every user to register at least two passkeys: for example a platform passkey plus a password-manager or hardware-key backup. The `UserDto.passkey_count` field exists so hosts can render that nudge.

## Run the minimal app

```sh
cargo run -p doorman-minimal-app
```

Open <http://localhost:3000>. Signup and recovery emails are printed to the terminal, so copy the link from stdout and complete the flow in the browser. The example uses SQLite, Axum, the bundled router, and a static HTML page with no frontend build step.

## What ships

- Passkey/WebAuthn registration and discoverable authentication via [`webauthn-rs`](https://crates.io/crates/webauthn-rs).
- Email-gated signup and recovery with single-use hashed tokens.
- Server-side opaque sessions with instant revocation.
- Passkey-bound post-recovery cool-down for destructive auth actions.
- Security notification emails for recovery, passkey lifecycle, and high-risk session revocation events.
- Cookie and bearer-token session presentation.
- CSRF origin checks for cookie-authenticated state-changing requests.
- Audit and rate-limiter traits, with development defaults.
- First-party SQLx storage for SQLite, Postgres, and MySQL/MariaDB.
- First-party Redis/Valkey adapter for the ephemeral stores (sessions, verification tokens, passkey challenges) and a shared cross-replica rate limiter, paired with a SQL backend for the system-of-record stores.
- Development email transports: terminal output, and `.eml` file output behind the `file-email` feature.

## Production checklist

Review the startup warnings emitted by `AuthService::builder().build()` or `AuthService::from_managers().build()` and make explicit choices before silencing them.

- Replace `TerminalEmailSender` / `FileEmailSender` with a real `EmailSender` for signup/recovery links and security notifications.
- Wire a durable `AuditSink`; `NoopAuditSink` discards security events.
- Wire a shared production `RateLimiter`; `InMemoryRateLimiter` is per-process.
- Set `external_origin` to the exact public origin and keep the default CSRF layer enabled for browser cookie flows.
- Keep secure, HttpOnly, SameSite session cookies outside local HTTP development.
- Run storage migrations and periodically purge expired sessions, verification tokens, and passkey challenges.
- Monitor recovery requests/completions, passkey add/remove events, high-risk session revocations, and failed WebAuthn ceremonies.
- Prompt users with `passkey_count < 2` to add a backup passkey.

## Workspace layout

```text
crates/core/        framework-agnostic managers, storage traits, email/audit/rate-limit traits
crates/axum/        Axum router, extractors, session layer, CSRF layer
crates/sqlx/        SQLite/Postgres storage adapter
crates/redis/       Redis/Valkey ephemeral stores + shared rate limiter
crates/conformance/ shared storage-adapter conformance suite
examples/minimal-app/  runnable Axum + SQLite app
examples/web-client/   browser-side WebAuthn helper reference
```

## Development

The repo ships a [`justfile`](justfile) and a [`compose.yaml`](compose.yaml) so the inner loop needs no manual setup. Install [`just`](https://github.com/casey/just) and Docker, then:

```sh
just up        # start local Redis (:6379) + Valkey (:6380), wait for health
just test      # run the whole workspace suite against them
just verify    # the full local gate: fmt-check, clippy, doc, test (mirrors CI)
just down      # stop the containers when you are done
```

`just` exports `REDIS_URL` / `VALKEY_URL` into every recipe, so the `doorman-redis` conformance suite finds the servers automatically. Run `just` with no arguments to list every recipe.

### Running the tests by hand

Most of the suite needs no services. The database- and Redis-backed conformance suites are gated on environment variables and **skip with a message** when those are unset, so a bare `cargo test` still passes:

```sh
cargo test --workspace                     # everything that needs no server
PG_URL=postgres://postgres:postgres@localhost/doorman_test \
  cargo test -p doorman-sqlx --features postgres
REDIS_URL=redis://127.0.0.1:6379 VALKEY_URL=redis://127.0.0.1:6380 \
  cargo test -p doorman-redis
```

The Redis/Valkey suites flush their database at the start of each run, so point `REDIS_URL` / `VALKEY_URL` only at disposable servers.

## Benchmarks

Criterion benches cover the hot auth paths at the manager, HTTP, and storage layers. See [`BENCHMARKS.md`](BENCHMARKS.md) for what is measured and how to read the numbers. Quick start:

```sh
cargo bench -p doorman-core
cargo bench -p doorman-axum
cargo bench -p doorman-sqlx --features sqlite
```

## Custom storage or HTTP surface

The quickest path is `doorman-sqlx` plus `AuthService::builder(...)`. Hosts on another database stack implement the `doorman-core` storage traits: `UserStore`, `SessionStore`, `VerificationTokenStore`, `PasskeyCredentialStore`, and `PasskeyChallengeStore`. Backends are chosen per trait via the `Storage` struct literal, so you can mix them — for example a SQL backend for the system-of-record stores with `doorman-redis` for the ephemeral stores and a shared rate limiter (`features = ["postgres", "redis"]`). See [`crates/redis/README.md`](crates/redis/README.md). The published `doorman-conformance` crate holds the contract tests every adapter is verified against.

If you want a custom HTTP API, call the core managers directly: `SessionManager`, `PasskeyManager`, `SignupManager`, and `RecoveryManager`.

## Documentation

- [`docs/concepts.md`](docs/concepts.md) — the auth model, passkey-only rationale, sessions, opaque tokens, recovery cool-down.
- [`docs/flows.md`](docs/flows.md) — signup, login, recovery, and account management with sequence diagrams.
- [`docs/security.md`](docs/security.md) — threat model, implemented guarantees, defaults, and vulnerability disclosure.
- [`docs/integration.md`](docs/integration.md) — wiring into Axum, custom stores, custom email/branding.
- [`docs/operations.md`](docs/operations.md) — purging, config, rate limiting, observability, single-tenant assumption.

API reference: `cargo doc --open`.

## Security

See [`docs/security.md`](docs/security.md) for the threat model, implemented guarantees, defaults, and host hardening requirements, and [`SECURITY.md`](SECURITY.md) for the vulnerability-disclosure policy.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
