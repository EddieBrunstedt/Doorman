# doorman

<!-- cargo-rdme start -->

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
use doorman::core::memory::InMemoryRateLimiter;
use doorman::core::verification::TOKEN_PLACEHOLDER;
use url::Url;

// 1. Open storage and run migrations.
let storage = SqliteStorage::connect("sqlite:///var/lib/app/auth.db?mode=rwc").await?;
storage.migrate().await?; // applies pending embedded migrations; idempotent, safe on every boot

// 2. Build the auth service.
let origin: Url = "https://app.example.com".parse()?;
let base = origin.as_str().trim_end_matches('/');
let auth = AuthService::builder(storage.all_stores())
    .email(Arc::new(TerminalEmailSender)) // dev transport; swap for production
    .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
    .audit(Arc::new(NoopAuditSink)) // discards events; wire a durable sink in prod
    .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock)))) // per-process; share a backend across replicas
    .signup(SignupConfig {
        url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"),
        ..Default::default()
    })
    .recovery(RecoveryConfig {
        url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"),
        ..Default::default()
    })
    .account(AccountConfig {
        url_template: format!("{base}/account/email?token={TOKEN_PLACEHOLDER}"),
        ..Default::default()
    })
    .reauthentication(ReauthPolicy::required_for([ // required decision; or ReauthPolicy::disabled()
        ReauthAction::DeleteAccount,
        ReauthAction::RemovePasskey,
    ]))
    .external_origin(origin) // enables CSRF origin checks; required CSRF decision
    .cookie(CookieConfig::default())
    .build()?;

// 3. Mount the routes and the session middleware.
let app = Router::new()
    .merge(auth.router()) // all /auth/* endpoints
    .route("/api/me", get(me)) // your own handlers
    .layer(auth.session_layer()); // resolves the session for extractors

// 4. Supply socket identity for rate limits and session/audit metadata.
let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
axum::serve(
    listener,
    app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
).await?;
```

`auth.router()` mounts every endpoint under `/auth`. `auth.session_layer()` resolves the session cookie or bearer token on each request so your handlers can use the extractors:

```rust
use doorman::prelude::*;

// Requires a valid session — returns 401 otherwise.
async fn me(user: AuthUser) -> String {
    format!("hello, {}", user.0.id)
}

// Present whether or not the request is authenticated.
async fn maybe(user: OptionalAuthUser) { /* ... */ }

// The full session context (user + session + recovery cool-down state).
async fn whoami(auth: AuthSession) { /* ... */ }
```

Forwarding headers are ignored. Behind a proxy, use trusted host middleware to insert `ClientIp`; see [client identity](https://codeberg.org/EddieBrunstedt/Doorman/src/branch/main/docs/integration.md#client-identity-and-proxies). Requests requiring identity return `500 internal_error` when neither `ClientIp` nor socket metadata is present.

`TerminalEmailSender` prints emails to stdout for local development. In production, implement `EmailSender` for your transactional email provider and keep `CookieConfig { secure: true, .. }`.

### Run the example app

```sh
cargo run -p doorman-minimal-app
```

Open <http://localhost:3000>. Signup and recovery emails are printed to the terminal — copy the link from stdout and finish the flow in the browser. The example uses SQLite, the bundled router, and a single static HTML page with no frontend build step.

## Cargo features

`doorman` bundles every crate behind a feature flag; enable only what you wire up.

- `axum` — the Axum HTTP integration (the supported user-facing surface), exposed at `doorman::axum`.
- **Storage adapters** — `sqlite`, `postgres`, `mysql`, `redis` (with its `valkey` alias), `dynamodb`, `mongodb`, `redb`; choose one per store, and mix backends if you like.
- `file-email` — bundled `.eml` file email transport for local development.
- `purge-runner` — the generic one-shot purge runner (`doorman::ops::run_purge`) for hosts that sweep expired rows from an external scheduler.

<!-- cargo-rdme end -->

## HTTP endpoints

Every route is mounted under `/auth` by `auth.router()`:

| Group        | Endpoints                                                                                                                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Sign up**  | `POST /auth/signup/request` · `POST /auth/signup/consume` · `POST /auth/signup/finish`                                                                                                     |
| **Sign in**  | `POST /auth/passkey/authenticate/start` · `POST /auth/passkey/authenticate/finish`                                                                                                         |
| **Recovery** | `POST /auth/recovery/request` · `POST /auth/recovery/consume` · `POST /auth/recovery/finish`                                                                                               |
| **Passkeys** | `POST /auth/passkey/register/start` · `POST /auth/passkey/register/finish` · `GET /auth/passkey` · `PATCH /auth/passkey/{credential_id}` (rename) · `DELETE /auth/passkey/{credential_id}` |
| **Sessions** | `POST /auth/logout` · `POST /auth/logout-all` · `GET /auth/sessions` · `DELETE /auth/sessions` (others) · `DELETE /auth/sessions/{id}`                                                     |
| **Account**  | `POST /auth/account/email` · `POST /auth/account/email/confirm` · `DELETE /auth/account`                                                                                                   |

The `request → consume → finish` shape is shared by signup and recovery: `request` emails a link, `consume` redeems that link and starts a passkey ceremony, and `finish` completes the ceremony and issues a session.

## Operator actions

`OperatorManager` is the user-management API: manage accounts by calling it, not by mutating doorman's tables directly — it keeps the storage invariants and the audit trail intact. Support and admin flows that act on _another_ user — disable or enable an account, delete it, revoke one or all of its sessions, remove a passkey, list its passkeys or sessions — all live here, reached through `auth.state().operator()`.

These flows are deliberately **not** mounted by `auth.router()`, and doorman performs no authorization of its own: an operator action is unauthenticated as far as the library is concerned, so you write the handler and put your own admin check in front of it. Every flow records an operator-attributed audit trail ([`docs/operators.md`](docs/operators.md)).

```rust
use axum::extract::{Path, State};
use axum::http::StatusCode;
use doorman::prelude::{AuthState, OperatorActor, UserId};

async fn disable_user(
    State(state): State<AuthState>,
    admin: AdminUser,
    Path(target): Path<UserId>,
) -> Result<StatusCode, AppError> {
    let actor = OperatorActor::new(admin.id, None, None, None)?;
    state.operator().disable(target, actor).await?;
    Ok(StatusCode::NO_CONTENT)
}
```

`AdminUser` and `AppError` are your own extractor and error type. Authorization runs while `AdminUser` is extracted, so an unauthorized request is rejected before the handler body executes. Mount the route on a sub-router carrying the auth state, then merge it alongside `auth.router()`:

```rust
use axum::routing::post;
use axum::Router;

let admin_routes = Router::new()
    .route("/admin/users/{id}/disable", post(disable_user))
    .with_state(auth.state().clone());
```

## The recovery cool-down

Recovery is always available and cannot be disabled — `AuthCore` always builds the recovery manager and `auth.router()` always mounts the recovery routes. It is the escape hatch for a user who has lost every passkey, so it is the one flow allowed to enroll a passkey without proving possession of an existing one (it also bypasses the per-user passkey cap for that reason).

Because recovery can add a passkey without proving possession of an existing one, doorman treats freshly recovered sessions as lower-trust. After recovery, the new session — and the passkey it created — carry a **post-recovery cool-down** (24 hours by default). The cool-down is stamped **only** by recovery; an ordinary passkey sign-in carries none. While it is active, doorman blocks the actions an attacker would use to lock out the real owner, and leaves the rest alone:

| Action                                          | During cool-down |
| ----------------------------------------------- | ---------------- |
| Remove a passkey                                | 🚫 blocked       |
| Revoke _other_ sessions / "sign out everywhere" | 🚫 blocked       |
| Change account email                            | 🚫 blocked       |
| Delete account                                  | 🚫 blocked       |
| Add a passkey                                   | ✅ allowed       |
| Sign out of _your own_ current session          | ✅ allowed       |

A passkey added during the cool-down inherits the same deadline; pre-existing passkeys are never restricted, so the legitimate owner simply signs in with one of theirs and waits the window out (or the attacker is shut out the moment the owner revokes the recovery session).

Encourage every user to register at least two passkeys — for example a platform passkey plus a hardware key or password-manager backup. The `UserDto.passkey_count` field is there so hosts can render that nudge.

## Adding another device

Registering a passkey on a new device is the ordinary authenticated flow, **not** recovery: an already–signed-in user calls `POST /auth/passkey/register/start` then `POST /auth/passkey/register/finish` (with `GET /auth/passkey` to list and `DELETE /auth/passkey/{credential_id}` to remove). No email link is involved and no cool-down applies — recovery exists only for the user who has lost _every_ passkey.

Enrolling a credential that lives on a _different_ device — registering from your laptop using the passkey on your phone, say — is driven by the browser and platform, not by doorman: WebAuthn's hybrid transport (the QR-code / Bluetooth caBLE hand-off) and platform passkey sync (iCloud Keychain, Google Password Manager) move credentials across devices below the application layer. doorman only ever sees the finished registration, so cross-device enrollment is outside its scope.

## What's in the box

- **Passkey/WebAuthn** registration and discoverable authentication via [`webauthn-rs`](https://crates.io/crates/webauthn-rs).
- **Email-gated signup, recovery, and email change** with single-use, hashed-at-rest, purpose-bound tokens.
- **Server-side opaque sessions** with instant revocation, presented as cookies or bearer tokens.
- **Passkey-bound post-recovery cool-down** for destructive account actions.
- **Operator actions** for support/admin tooling — disable/enable, delete, session revocation, passkey removal — core-only with a two-record audit trail; you own the route and its authorization.
- **Security-notification emails** for recovery, passkey add/remove, email change, and high-risk session revocations.
- **CSRF origin checks** for cookie-authenticated state-changing requests.
- **Pluggable collaborators** — audit sink, rate limiter, metrics, clock, and email renderer — wired explicitly at build time, so each is visible in the code.
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
| _(built into `doorman-core`)_   | `InMemoryStorage`                     | Process-local store for tests and ephemeral deployments; fills all five stores          |

Because a backend is chosen **per trait** via the `Storage` struct, you can mix them. A single-node app needs only one persistent backend — `doorman-sqlx`, `doorman-redb`, `doorman-mongodb`, or `doorman-dynamodb` — to fill all five stores; no Redis is required. Redis only enters for a multi-node deployment: pair a persistent backend for the system-of-record stores (users and passkey credentials) with `doorman-redis` for the ephemeral, TTL-bearing stores (sessions, tokens, challenges) and a shared cross-replica rate limiter:

```rust
let storage = Storage {
    users:               pg.user_store(),
    passkey_credentials: pg.passkey_credential_store(),
    sessions:            redis.session_store(),
    verification_tokens: redis.verification_token_store(),
    passkey_challenges:  redis.passkey_challenge_store(),
};
```

Redis intentionally does **not** implement `UserStore` or `PasskeyCredentialStore` — that data never expires and must be durable — so `RedisStorage` is always assembled alongside one of the persistent backends. See [`crates/redis/README.md`](crates/redis/README.md).

To support a database doorman doesn't ship, implement the five traits yourself. The published `doorman-conformance` crate holds the contract tests every adapter is verified against, so a custom store can be checked the same way the first-party ones are.

## Going to production

`AuthService::builder().build()` is strict by default: there is no silent insecure default, so every footgun is a choice you make explicitly at the call site rather than a warning you have to remember to act on. The build fails closed (returns a `BuilderError`) until each of these is wired:

- **Email** — required. Use `TerminalEmailSender` / `FileEmailSender` for local development, or a real `EmailSender` in production (used for both the link emails and the security notifications).
- **Audit** — required. Wire a durable `AuditSink`, or pass `NoopAuditSink` explicitly. Every audit event is also written to the `doorman::audit` `tracing` target, so even `NoopAuditSink` still leaves a structured log trail — it only discards the _durable_ sink record.
- **Rate limiting** — required. Wire a shared `RateLimiter` (e.g. the Redis one) for multi-replica deployments, the per-process `InMemoryRateLimiter` for a single process, or `NoopRateLimiter` to disable enforcement deliberately.
- **Origin & CSRF** — required decision. Set `external_origin` to the exact public origin (which enables the CSRF origin checks for browser cookie flows), or opt out explicitly with `CsrfConfig::disabled()`.
- **Re-authentication** — required decision. Pass `ReauthPolicy::required_for([..])` to require a fresh passkey assertion before the destructive actions (delete account, email-change request, passkey removal), or `ReauthPolicy::disabled()` to opt out explicitly.
- **URL templates** — required. The stock `example.invalid` signup / recovery / account templates are rejected; set real ones that carry the `{token}` placeholder.
- **Cookies** — session cookies are always `HttpOnly`; `Secure` (default on) and `SameSite` (default `Lax`) are the configurable knobs. The only setting to relax for local HTTP development is `secure = false` — a `Secure` cookie is dropped over plain `http://`.
- **Maintenance** — run storage migrations on boot, then sweep expired sessions, verification tokens, and passkey challenges. Either call `Storage::purge_all_expired(now)` from your own scheduler, or enable the `background-purge` feature on `doorman-core` and let `spawn_purge_task` run the sweep on an interval for you. See [`docs/operations.md`](docs/operations.md) for both, including the external-scheduler (`purge-runner`) variant for serverless hosts.
- **Monitoring** — doorman _emits_ signals; the watching and alerting are yours — the library never stores or evaluates them. Security events flow to the `AuditSink` (recovery requests/completions, passkey add/remove, high-risk session revocations, failed WebAuthn ceremonies); operational metrics flow to an optional `MetricSink` — login successes, auth failures, ceremony latency, and the axum session-cache hit/miss. Wire either into your own observability stack.
- **Backup passkeys** — prompt users with `passkey_count < 2` to add one.

## Layering

doorman is batteries-included and Axum-first. The auth engine and its assembly live in `doorman-core`: `AuthCore::builder(storage)` resolves the collaborator defaults, validates the URL templates and lifetimes, wires the security notifier and session-resolution cache, and constructs the managers (`SessionManager`, `PasskeyManager`, `SignupManager`, `RecoveryManager`, `AccountManager`) in dependency order. `doorman-axum` is the first-party HTTP integration: `AuthService::builder(storage)` delegates that portable assembly to `doorman-core` and adds the HTTP layer (cookies, CSRF, the router and session layer). Hosts that have already constructed the managers themselves can hand them to `AuthService::from_managers()`.

## Workspace layout

```text
crates/doorman/         umbrella crate re-exporting the others behind features
crates/core/            framework-agnostic managers, storage traits, email/audit/rate-limit/metrics traits
crates/axum/            Axum router, extractors, session layer, CSRF layer
crates/sqlx/            SQLite / Postgres / MySQL / MariaDB storage adapter
crates/redis/           Redis/Valkey ephemeral stores + shared rate limiter
crates/dynamodb/        Amazon DynamoDB storage adapter
crates/mongodb/         MongoDB storage adapter
crates/redb/            redb embedded key-value storage adapter
crates/conformance/     shared storage-adapter conformance suite
crates/test-support/    test-only collaborators (mock clock, capturing sinks)
examples/minimal-app/   runnable Axum + SQLite app
examples/web-client/    browser-side WebAuthn helper reference
```

## Versioning and MSRV

doorman follows [Semantic Versioning](https://semver.org/). Every published crate (`doorman`, `doorman-core`, `doorman-axum`, and the storage adapters) shares one workspace version and is released in lockstep, so a given `doorman` release pins matching adapter versions. Notable changes are recorded in [`CHANGELOG.md`](CHANGELOG.md) (Keep a Changelog format).

**Pre-1.0:** while the version is `0.x`, the public API is not yet stable. Per Cargo's semver rules a minor bump (`0.x` → `0.(x+1)`) may contain breaking changes, and this project uses minor bumps for exactly that — breaking changes land freely as the surface is refined toward `1.0`. Patch releases (`0.x.y` → `0.x.(y+1)`) stay backwards compatible. Pin a minor version if you need stability between upgrades.

**MSRV:** the minimum supported Rust version is **1.94**, driven by the dependency tree (sqlx 0.9 requires 1.94). CI and `just msrv` enforce it against the pinned `1.94.1` toolchain. An MSRV bump is treated as a routine change, not a breaking one, and may occur in a minor (pre-1.0) release; it will be noted in the changelog.

## Development

The repo ships a [`justfile`](justfile) so the inner loop needs no manual setup. Install [`just`](https://github.com/casey/just) and Docker, then:

```sh
just test      # run the whole workspace suite
just verify    # the full local gate, mirroring CI end to end
just msrv      # MSRV check alone (needs the pinned 1.94.1 toolchain)
```

`just verify` runs every gate CI does: `fmt-check`, `dprint-check`, `clippy`, `doc`, the isolated feature builds (`check-features`), `msrv`, and `test`. The full gate needs a running Docker daemon (for `test`) and the pinned `1.94.1` toolchain installed via rustup (for `msrv`); CI is the canonical `--locked` gate, but the compile-heavy recipes pass `--locked` locally too so lockfile drift surfaces before CI.

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
- [`docs/operators.md`](docs/operators.md) — operator flows, host authorization, the two-record audit pattern, and the operator threat model.

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
