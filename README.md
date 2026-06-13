# doorman

**Passkey-only authentication for Rust web apps.** doorman gives an [Axum](https://github.com/tokio-rs/axum) application a single, modern way to log in — discoverable passkeys (WebAuthn) — backed by email links that exist only to onboard and recover accounts.

There are no passwords, no OAuth providers, no TOTP codes, and no general-purpose "email me a login link". Every account is anchored to one or more passkeys; email is used only to prove control of an address during signup, account recovery, and email changes.

> doorman is pre-1.0. The public API is in good shape but breaking changes can still land before 1.0.

## Why passkey-only?

Passwords are the root of most account-security problems: reuse, phishing, leaks, and the endless reset machinery built to paper over them. Passkeys are phishing-resistant by construction (the credential is bound to your site's origin) and need no shared secret on the server.

doorman commits to that model fully instead of bolting passkeys onto a password system:

- **One way in.** Returning users authenticate with a discoverable passkey — no username, no password, no second factor to juggle.
- **Email is a recovery channel, not a login.** A signup or recovery link only ever _starts a passkey registration_; it never issues a session by itself. A leaked email link cannot, on its own, log anyone in.
- **Lost-device recovery without a help desk.** Users recover through a verified email link that enrolls a fresh passkey, gated by a cool-down that disables destructive actions while a recovery is fresh.

## How it works

doorman ships the server half of three WebAuthn ceremonies plus account management, wired into ready-to-mount Axum routes:

| Flow        | What the user does                                                                  | What doorman does                                                                                                                   |
| ----------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Sign up** | Enters an email, clicks the emailed link, registers a passkey                       | Mails a single-use link → the link starts passkey registration → on finish, registers the first passkey and _then_ issues a session |
| **Sign in** | Picks a passkey in the browser prompt                                               | Identifies the user from the WebAuthn response — no email or username needed (discoverable credentials)                             |
| **Recover** | Enters an email, clicks the link, registers a new passkey                           | Mails a recovery link → the link enrolls a fresh passkey → issues a session restricted by a post-recovery cool-down                 |
| **Manage**  | Lists/adds/removes passkeys, lists/revokes sessions, changes email, deletes account | Enforces the cool-down on destructive actions and sends security-notification emails                                                |

Sessions are **server-side and opaque**: the cookie (or bearer token) is a random handle to a row doorman owns, so revocation is instant and there is no token to forge or decode.

## Quickstart

```toml
[dependencies]
doorman = { git = "https://codeberg.org/EddieBrunstedt/Doorman", features = ["axum", "sqlite"] }
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

`doorman` is an **umbrella crate**: one dependency, one version to bump. It re-exports the framework-agnostic core, the Axum integration, and the storage adapters behind features (`doorman::core`, `doorman::axum`, `doorman::sqlx`, `doorman::redis`, …). The `prelude` pulls in everything a typical host needs in one line.

```rust
use std::sync::Arc;

use axum::{routing::get, Router};
use doorman::prelude::*;
use doorman::core::verification::TOKEN_PLACEHOLDER;

// 1. Open storage and run migrations.
let storage = SqliteStorage::connect("sqlite:///var/lib/app/auth.db?mode=rwc").await?;
storage.migrate().await?;

// 2. Build the auth service.
let origin = "https://app.example.com".parse()?;
let base = origin.as_str().trim_end_matches('/');
let auth = AuthService::builder(storage.all_stores())
    .email(Arc::new(TerminalEmailSender))                       // dev transport; swap for production
    .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
    .signup(SignupConfig {
        url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"),
        ..Default::default()
    })
    .recovery(RecoveryConfig {
        url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"),
        ..Default::default()
    })
    .external_origin(origin)
    .cookie(CookieConfig::default())
    .build()?;

// 3. Mount the routes and the session middleware.
let app = Router::new()
    .merge(auth.router())               // all /auth/* endpoints
    .route("/api/me", get(me))          // your own handlers
    .layer(auth.session_layer());       // resolves the session for extractors
```

`auth.router()` mounts every endpoint under `/auth`. `auth.session_layer()` resolves the session cookie or bearer token on each request so your handlers can use the extractors:

```rust
use doorman::prelude::*;

// Requires a valid session — returns 401 otherwise.
async fn me(user: AuthUser) -> String {
    format!("hello, {}", user.id)
}

// Present whether or not the request is authenticated.
async fn maybe(user: OptionalAuthUser) { /* ... */ }

// The full session context (user + session + recovery cool-down state).
async fn whoami(auth: AuthSession) { /* ... */ }
```

`TerminalEmailSender` prints emails to stdout for local development. In production, implement `EmailSender` for your transactional email provider and keep `CookieConfig { secure: true, .. }`.

### Run the example app

```sh
cargo run -p doorman-minimal-app
```

Open <http://localhost:3000>. Signup and recovery emails are printed to the terminal — copy the link from stdout and finish the flow in the browser. The example uses SQLite, the bundled router, and a single static HTML page with no frontend build step.

## HTTP endpoints

Every route is mounted under `/auth` by `auth.router()`:

| Group        | Endpoints                                                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **Sign up**  | `POST /auth/signup/request` · `POST /auth/signup/consume` · `POST /auth/signup/finish`                                                    |
| **Sign in**  | `POST /auth/passkey/authenticate/start` · `POST /auth/passkey/authenticate/finish`                                                        |
| **Recovery** | `POST /auth/recovery/request` · `POST /auth/recovery/consume` · `POST /auth/recovery/finish`                                              |
| **Passkeys** | `POST /auth/passkey/register/start` · `POST /auth/passkey/register/finish` · `GET /auth/passkey` · `DELETE /auth/passkey/{credential_id}` |
| **Sessions** | `POST /auth/logout` · `POST /auth/logout-all` · `GET /auth/sessions` · `DELETE /auth/sessions` (others) · `DELETE /auth/sessions/{id}`    |
| **Account**  | `POST /auth/account/email` · `POST /auth/account/email/confirm` · `DELETE /auth/account`                                                  |

The `request → consume → finish` shape is shared by signup and recovery: `request` emails a link, `consume` redeems that link and starts a passkey ceremony, and `finish` completes the ceremony and issues a session.

## The recovery cool-down

Recovery is the one place a passkey can be added without proving possession of an existing one, so doorman treats freshly recovered sessions as lower-trust. After recovery, the new session — and the passkey it created — carry a **post-recovery cool-down** (24 hours by default). While it is active, doorman blocks the actions an attacker would use to lock out the real owner:

- deleting passkeys
- revoking _other_ sessions, and "sign out everywhere else"
- changing the account email or deleting the account

Adding passkeys and signing out of _your own_ current session stay allowed throughout. A passkey added during the cool-down inherits the same deadline; pre-existing passkeys are never restricted, so the legitimate owner simply signs in with one of theirs and waits the window out (or the attacker is shut out the moment the owner revokes the recovery session).

Encourage every user to register at least two passkeys — for example a platform passkey plus a hardware key or password-manager backup. The `UserDto.passkey_count` field is there so hosts can render that nudge.

## What's in the box

- **Passkey/WebAuthn** registration and discoverable authentication via [`webauthn-rs`](https://crates.io/crates/webauthn-rs).
- **Email-gated signup, recovery, and email change** with single-use, hashed-at-rest, purpose-bound tokens.
- **Server-side opaque sessions** with instant revocation, presented as cookies or bearer tokens.
- **Passkey-bound post-recovery cool-down** for destructive account actions.
- **Security-notification emails** for recovery, passkey add/remove, email change, and high-risk session revocations.
- **CSRF origin checks** for cookie-authenticated state-changing requests.
- **Pluggable collaborators** — audit sink, rate limiter, metrics, clock, and email renderer — each with a sensible development default and a startup warning when a placeholder is left in place.
- **A session-resolution cache** so the hot authenticated-request path doesn't hit storage every time.

## Storage backends

doorman's persistence is defined by five small traits in `doorman-core`: `UserStore`, `SessionStore`, `VerificationTokenStore`, `PasskeyCredentialStore`, and `PasskeyChallengeStore`. First-party adapters implement them:

| Feature                         | Backend                               | Notes                                                                                   |
| ------------------------------- | ------------------------------------- | --------------------------------------------------------------------------------------- |
| `sqlite` / `postgres` / `mysql` | SQLite, Postgres, MySQL/MariaDB       | First-party SQLx adapter; covers all five stores                                        |
| `dynamodb`                      | Amazon DynamoDB                       | All five stores from one table — AWS-native / serverless                                |
| `mongodb`                       | MongoDB                               | All five stores from one database                                                       |
| `redb`                          | [redb](https://crates.io/crates/redb) | Embedded, single-file, pure-Rust adapter                                                |
| `redis` / `valkey`              | Redis or Valkey                       | _Ephemeral_ stores (sessions, tokens, challenges) + a shared cross-replica rate limiter |

Because a backend is chosen **per trait** via the `Storage` struct, you can mix them. The intended mixed deployment is a SQL backend for the system-of-record stores (users and passkey credentials) paired with `doorman-redis` for the ephemeral, TTL-bearing stores and a shared rate limiter:

```rust
let storage = Storage {
    users:               pg.user_store(),
    passkey_credentials: pg.passkey_credential_store(),
    sessions:            redis.session_store(),
    verification_tokens: redis.verification_token_store(),
    passkey_challenges:  redis.passkey_challenge_store(),
};
```

Redis intentionally does **not** implement `UserStore` or `PasskeyCredentialStore` — that data never expires and wants relational guarantees — so `RedisStorage` is always assembled alongside a SQL adapter. See [`crates/redis/README.md`](crates/redis/README.md).

To support a database doorman doesn't ship, implement the five traits yourself. The published `doorman-conformance` crate holds the contract tests every adapter is verified against, so a custom store can be checked the same way the first-party ones are.

## Going to production

`AuthService::builder().build()` emits startup warnings whenever a development placeholder is still wired in. Review them and make each choice explicitly:

- **Email** — replace `TerminalEmailSender` / `FileEmailSender` with a real `EmailSender`. doorman uses it for both the link emails and the security notifications.
- **Audit** — wire a durable `AuditSink`; the default `NoopAuditSink` discards security events.
- **Rate limiting** — wire a shared `RateLimiter` (e.g. the Redis one); `InMemoryRateLimiter` is per-process and `NoopRateLimiter` disables enforcement.
- **Origin & CSRF** — set `external_origin` to the exact public origin and keep the default CSRF layer enabled for browser cookie flows.
- **Cookies** — keep `secure`, `HttpOnly`, `SameSite` session cookies anywhere but local HTTP development.
- **Maintenance** — run storage migrations and periodically purge expired sessions, verification tokens, and passkey challenges.
- **Monitoring** — watch recovery requests/completions, passkey add/remove events, high-risk session revocations, and failed WebAuthn ceremonies. Optionally wire a `Metrics` implementation.
- **Backup passkeys** — prompt users with `passkey_count < 2` to add one.

## Building a custom HTTP surface

The Axum integration is the supported front end, but it is a thin shell over framework-agnostic managers in `doorman-core`: `SessionManager`, `PasskeyManager`, `SignupManager`, `RecoveryManager`, and `AccountManager`. Call them directly via `AuthService::from_managers()` to put doorman behind a different framework or a bespoke API.

## Workspace layout

```text
crates/doorman/      umbrella crate re-exporting the others behind features
crates/core/         framework-agnostic managers, storage traits, email/audit/rate-limit/metrics traits
crates/axum/         Axum router, extractors, session layer, CSRF layer
crates/sqlx/         SQLite / Postgres / MySQL / MariaDB storage adapter
crates/redis/        Redis/Valkey ephemeral stores + shared rate limiter
crates/dynamodb/     Amazon DynamoDB storage adapter
crates/mongodb/      MongoDB storage adapter
crates/redb/         redb embedded key-value storage adapter
crates/conformance/  shared storage-adapter conformance suite
crates/test-support/ test-only collaborators (mock clock, capturing sinks)
examples/minimal-app/  runnable Axum + SQLite app
examples/web-client/   browser-side WebAuthn helper reference
```

## Development

The repo ships a [`justfile`](justfile) so the inner loop needs no manual setup. Install [`just`](https://github.com/casey/just) and Docker, then:

```sh
just test      # run the whole workspace suite
just verify    # the full local gate: fmt-check, clippy, doc, test (mirrors CI)
```

Run `just` with no arguments to list every recipe.

### Running tests by hand

**A running Docker daemon is required for the full suite.** The storage-conformance suites are self-contained: each starts its own throwaway database container via [testcontainers](https://docs.rs/testcontainers) — no external server or connection string to configure — and tears it down when the test ends.

```sh
cargo test --workspace --all-features             # everything, incl. all storage backends
cargo test -p doorman-sqlx --features postgres    # just Postgres
cargo test -p doorman-sqlx --features mysql       # just MySQL + MariaDB
cargo test -p doorman-redis                       # just Redis + Valkey
cargo test -p doorman-dynamodb                    # just DynamoDB (local container)
cargo test -p doorman-mongodb                     # just MongoDB
cargo test -p doorman-redb                        # just redb (no Docker needed)
```

Only SQLite (`--features sqlite`) and redb need no Docker — they run in memory / against a local file. The `just test-<backend>` recipes wrap the per-backend commands.

### Benchmarks

Criterion benches cover the hot auth paths at the manager, HTTP, and storage layers. See [`BENCHMARKS.md`](BENCHMARKS.md) for what is measured and how to read the numbers.

```sh
cargo bench -p doorman-core
cargo bench -p doorman-axum
cargo bench -p doorman-sqlx --features sqlite
```

## Documentation

- [`docs/concepts.md`](docs/concepts.md) — the auth model, passkey-only rationale, sessions, opaque tokens, recovery cool-down.
- [`docs/flows.md`](docs/flows.md) — signup, login, recovery, and account management with sequence diagrams.
- [`docs/security.md`](docs/security.md) — threat model, implemented guarantees, defaults, and disclosure policy.
- [`docs/integration.md`](docs/integration.md) — wiring into Axum, custom stores, custom email/branding.
- [`docs/operations.md`](docs/operations.md) — purging, configuration, rate limiting, observability, the single-tenant assumption.

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
