# Integration

How to wire doorman into an Axum application, swap in your own stores, and brand the emails. Read [concepts.md](concepts.md) for the trait seams first. For a runnable reference, see `examples/minimal-app`.

## The five-minute path

The shortest route is `doorman-sqlx` for storage plus the high-level `AuthService::builder`. This is the quickstart from the [top-level README](../README.md):

```rust,ignore
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
    .passkey(PasskeyConfig::from_origin(origin.clone(), "Example")?)
    .audit(Arc::new(NoopAuditSink))
    .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
    .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .account(AccountConfig { url_template: format!("{base}/account/email?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .external_origin(origin)
    .cookie(CookieConfig::default())
    .build()?;

let app = Router::new()
    .merge(auth.router())
    .route("/api/me", get(me))
    .layer(auth.session_layer());
```

- `auth.router()` mounts the passkey, signup, recovery, session, and account routes under `/auth`.
- `auth.session_layer()` resolves the session cookie or bearer token so your handlers can extract `AuthUser`, `OptionalAuthUser`, and `AuthSession`.

`PasskeyConfig::from_origin(origin, rp_name)` derives the relying-party id from the origin host. Use `PasskeyConfig::new(rp_id, origin, rp_name)` when the relying-party id is a registrable suffix that differs from the origin host.

## The builder setters

Every collaborator and config has a bare-noun setter on `AuthServiceBuilder` (and the same names on the low-level `ManagerBuilder`):

| Setter                                                                                                   | Purpose                                                 |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `.email(Arc<dyn EmailSender>)`                                                                           | Transport for links and notices. Required.              |
| `.emails(Arc<dyn EmailTemplates>)`                                                                       | One renderer branding every email (see below).          |
| `.audit(Arc<dyn AuditSink>)`                                                                             | Sink for security events. Required.                     |
| `.limiter(Arc<dyn RateLimiter>)`                                                                         | Rate-limit backend. Required.                           |
| `.metrics(Arc<dyn Metrics>)`                                                                             | Observability hook.                                     |
| `.clock(Arc<dyn Clock>)`                                                                                 | Time source (mock in tests). Defaults to `SystemClock`. |
| `.passkey(PasskeyConfig)`                                                                                | Relying party + ceremony config. Required.              |
| `.signup(SignupConfig)` / `.recovery(RecoveryConfig)` / `.account(AccountConfig)`                        | Flow configs (URL templates, lifetimes, cool-down).     |
| `.session(SessionConfig)` / `.cookie(CookieConfig)` / `.cache(SessionCacheConfig)` / `.csrf(CsrfConfig)` | Session presentation + caching + CSRF.                  |
| `.external_origin(Url)`                                                                                  | Public origin, enables CSRF origin checks.              |

The builder is strict by default — there is no silent insecure default, so every footgun is an explicit call rather than a warning. `build()` returns a `BuilderError` until each required input is wired: the email transport (`MissingEmailSender`), passkey config (`MissingPasskeyConfig`), audit sink (`MissingAuditSink` — pass `NoopAuditSink` to discard events), rate limiter (`MissingRateLimiter` — pass `InMemoryRateLimiter`, a shared backend, or `NoopRateLimiter`), and a CSRF decision (`CsrfDecisionRequired` — set `external_origin` or `CsrfConfig::disabled()`). It also fails closed on a stock `example.invalid` URL template (`PlaceholderUrlTemplate`), a URL template missing `{token}` (`TOKEN_PLACEHOLDER`), a sub-floor recovery cool-down, a `__Host-`/`__Secure-` cookie name without the matching attributes, an out-of-bounds TTL, or a cookie max-age exceeding the session lifetime. No public config value panics the build.

## Choosing or implementing a store

For a single backend, depend on one of the first-party adapters — `doorman-sqlx` (SQLite/Postgres/MySQL), `doorman-dynamodb`, `doorman-mongodb`, or `doorman-redb` — and call `storage.all_stores()` to get the composite `Storage` value. For an in-memory store (tests, ephemeral deployments) use `InMemoryStorage::new().all_stores()`.

`Storage` is a struct of per-trait `Arc<dyn>` fields, so backends can be mixed by naming each one in the literal. The common production split is SQL for the system-of-record stores plus `doorman-redis` for the ephemeral stores and a shared rate limiter — the latter being the only way a multi-replica deployment gets instant cross-process session revoke and one rate-limit budget:

```rust,ignore
let pg = PostgresStorage::connect(pg_url).await?;
pg.migrate().await?;
let redis = RedisStorage::connect("redis://localhost:6379").await?;

let storage = Storage {
    users:               pg.user_store(),
    passkey_credentials: pg.passkey_credential_store(),
    sessions:            redis.session_store(),
    verification_tokens: redis.verification_token_store(),
    passkey_challenges:  redis.passkey_challenge_store(),
};
let auth = AuthService::builder(storage).limiter(redis.rate_limiter()) /* … */ ;
```

Redis cannot hold the system-of-record stores, so it has no `all_stores()` and is always paired with a SQL backend like this. See [`crates/redis/README.md`](../crates/redis/README.md).

To back doorman with another database, implement the five storage traits from `doorman_core::storage`:

- `UserStore`
- `SessionStore`
- `VerificationTokenStore`
- `PasskeyCredentialStore`
- `PasskeyChallengeStore`

The traits deal in **opaque bytes and primitives** — they have no `webauthn-rs` dependency. doorman-core serializes the WebAuthn ceremony and credential blobs before they cross the store boundary, and keeps the `credential_id` as a top-level `Vec<u8>` for indexing. Each trait's rustdoc documents its invariants: error semantics, idempotency, and the meaning of "expired rows may still be returned" (the manager re-filters by `now`). The published `doorman-conformance` crate is the executable contract; add it under `[dev-dependencies]` and run `doorman_conformance::run(&storage)` against a new adapter. Key-value adapters have three extra expectations (atomic take, best-effort secondary indexes, a real `purge_expired`) spelled out in the `doorman_core::storage` module docs.

Assemble the five into a `Storage`:

```rust,ignore
let storage = Storage {
    users: Arc::new(my_user_store),
    sessions: Arc::new(my_session_store),
    verification_tokens: Arc::new(my_token_store),
    passkey_credentials: Arc::new(my_credential_store),
    passkey_challenges: Arc::new(my_challenge_store),
};
```

## Testing your integration with `InMemoryStorage`

`InMemoryStorage` is a supported testing adapter that lives in `doorman-core` and is held to the same conformance and semver guarantees as the shipped database adapters. It fills all five stores from one process-local handle, so a host's integration test can stand up a real `AuthService` with no database, container, or migration step — `InMemoryStorage::new().all_stores()` drops straight into the same builder the quickstart uses:

```rust,ignore
use std::sync::Arc;
use axum::{routing::get, Router};
use doorman::prelude::*;
use doorman::core::memory::{InMemoryRateLimiter, InMemoryStorage};
use doorman::core::verification::TOKEN_PLACEHOLDER;

#[tokio::test]
async fn signup_route_is_mounted() -> Result<(), Box<dyn std::error::Error>> {
    let origin: url::Url = "http://localhost:3000".parse()?;
    let base = origin.as_str().trim_end_matches('/');

    let auth = AuthService::builder(InMemoryStorage::new().all_stores())
        .email(Arc::new(TerminalEmailSender))
        .passkey(PasskeyConfig::new("localhost", origin.clone(), "Example"))
        .audit(Arc::new(NoopAuditSink))
        .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
        .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
        .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
        .account(AccountConfig { url_template: format!("{base}/account/email?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
        .external_origin(origin)
        .cookie(CookieConfig::default())
        .build()?;

    let app = Router::new()
        .merge(auth.router())
        .route("/api/me", get(|_: AuthSession| async { "ok" }))
        .layer(auth.session_layer());

    // Drive `app` with `tower::ServiceExt::oneshot` or bind it to an ephemeral
    // port and hit it over HTTP — every flow runs against the in-memory store.
    let _ = app;
    Ok(())
}
```

The handle starts empty and is lost when the test process exits; for a shared production-grade store, reach for one of the database adapters above. To brand or capture the emails the flows send, swap `TerminalEmailSender` for `CapturingEmailSender` from `doorman-test-support`.

## Custom email and branding

`.email(...)` sets the **transport**; `.emails(...)` sets the **renderer**. Implement `EmailSender` to deliver mail through your provider (lettre, Resend, SES, …):

```rust,ignore
use async_trait::async_trait;
use doorman::core::email::{Email, EmailSender};
use doorman::core::error::EmailResult;

struct MyTransport { /* provider client */ }

#[async_trait]
impl EmailSender for MyTransport {
    async fn send(&self, email: Email) -> EmailResult<()> {
        // hand email.to / subject / body_text / body_html to your provider
        Ok(())
    }
}
```

Implement `EmailTemplates` to customise the copy. Every method has a default body, so override only what you want to brand and inherit the rest. One `.emails(Arc<dyn EmailTemplates>)` call is the single place to brand every transactional email — the signup, recovery, and email-change links **and** the security notices (passkey lifecycle, session revocation). Left unset, the stock `DefaultEmailTemplates` copy is used.

User-facing copy is the host's responsibility on the **client** too: doorman returns machine error codes (see `crates/axum/src/error.rs`), and the example client maps those codes to human guidance. See [operations.md](operations.md#customizing-user-facing-messages).

## Driving the managers directly

For a custom HTTP surface (not Axum, or a bespoke API shape), skip the router and call the core managers: `SessionManager`, `PasskeyManager`, `SignupManager`, `RecoveryManager`, `AccountManager`. The high-level builder exposes the same managers the routes use via `AuthState::session_manager()`, `passkey()`, `signup()`, and `recovery()` accessors, so host code can drive them alongside the bundled routes. The low-level `AuthService::from_managers()` path accepts managers you constructed yourself.

## Extractors

With the session layer applied, handlers can extract:

- `AuthUser` — a newtype around `Arc<User>`; rejects with `401` if there is no valid session.
- `OptionalAuthUser` — `Some`/`None`, never rejects.
- `AuthSession` — the resolved session plus helpers (e.g. `is_in_recovery_cooldown`, answered through the configured clock).
- `RequestContext` — IP / user-agent captured from request headers.

```rust,ignore
use axum::Json;
use doorman::prelude::*;

async fn me(user: AuthUser) -> Json<UserDto> {
    // AuthUser is AuthUser(pub Arc<User>); passkey_count comes from your store.
    Json(UserDto::from_user(&user.0, 0))
}
```
