# Integration

How to wire doorman into an Axum application, swap in your own stores, and brand the emails. Read [concepts.md](concepts.md) for the trait seams first. For a runnable reference, see `examples/minimal-app`.

## The five-minute path

The shortest route is `doorman-sqlx` for storage plus the high-level `AuthService::builder`. This is the quickstart from the [top-level README](../README.md):

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
    .passkey(PasskeyConfig::from_origin(origin.clone(), "Example")?)
    .audit(Arc::new(NoopAuditSink))
    .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
    .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .account(AccountConfig { url_template: format!("{base}/account/email?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .reauthentication(ReauthPolicy::required_for([ReauthAction::DeleteAccount, ReauthAction::RemovePasskey]))
    .external_origin(origin)
    .cookie(CookieConfig::default())
    .build()?;

let app = Router::new()
    .merge(auth.router())
    .route("/api/me", get(me))
    .layer(auth.session_layer());

let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
axum::serve(
    listener,
    app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
).await?;
```

- `auth.router()` mounts the passkey, signup, recovery, session, and account routes under `/auth`.
- `auth.session_layer()` resolves the session cookie or bearer token so your handlers can extract `AuthUser`, `OptionalAuthUser`, and `AuthSession`.

`PasskeyConfig::from_origin(origin, rp_name)` derives the relying-party id from the origin host. Use `PasskeyConfig::new(rp_id, origin, rp_name)` when the relying-party id is a registrable suffix that differs from the origin host.

## The builder setters

Every collaborator and config has a bare-noun setter on `AuthServiceBuilder` (and the same names on the low-level `ManagerBuilder`):

| Setter                                                                                                   | Purpose                                                     |
| -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `.email(Arc<dyn EmailSender>)`                                                                           | Transport for links and notices. Required.                  |
| `.emails(Arc<dyn EmailTemplates>)`                                                                       | One renderer branding every email (see below).              |
| `.audit(Arc<dyn AuditSink>)`                                                                             | Sink for security events. Required.                         |
| `.limiter(Arc<dyn RateLimiter>)`                                                                         | Rate-limit backend. Required.                               |
| `.metrics(Arc<dyn MetricSink>)`                                                                          | Observability hook.                                         |
| `.clock(Arc<dyn Clock>)`                                                                                 | Time source (mock in tests). Defaults to `SystemClock`.     |
| `.passkey(PasskeyConfig)`                                                                                | Relying party + ceremony config. Required.                  |
| `.signup(SignupConfig)` / `.recovery(RecoveryConfig)` / `.account(AccountConfig)`                        | Flow configs (URL templates, lifetimes, cool-down).         |
| `.reauthentication(ReauthPolicy)`                                                                        | Which destructive actions need a fresh assertion. Required. |
| `.session(SessionConfig)` / `.cookie(CookieConfig)` / `.cache(SessionCacheConfig)` / `.csrf(CsrfConfig)` | Session presentation + caching + CSRF.                      |
| `.external_origin(Url)`                                                                                  | Public origin, enables CSRF origin checks.                  |

The builder is strict by default — there is no silent insecure default, so every footgun is an explicit call rather than a warning. `build()` returns a `BuilderError` until each required input is wired: the email transport (`MissingEmailSender`), passkey config (`MissingPasskeyConfig`), audit sink (`MissingAuditSink` — pass `NoopAuditSink` to discard events), rate limiter (`MissingRateLimiter` — pass `InMemoryRateLimiter`, a shared backend, or `NoopRateLimiter`), a CSRF decision (`CsrfDecisionRequired` — set `external_origin` or `CsrfConfig::disabled()`), and a re-authentication decision (`ReauthDecisionRequired` — pass `ReauthPolicy::required_for([..])` or `ReauthPolicy::disabled()`). It also fails closed on a stock `example.invalid` URL template (`PlaceholderUrlTemplate`), a URL template missing `{token}` (`TOKEN_PLACEHOLDER`), a sub-floor recovery cool-down, a `__Host-`/`__Secure-` cookie name without the matching attributes, an out-of-bounds TTL, or a cookie max-age exceeding the session lifetime. No public config value panics the build.

## Choosing or implementing a store

For a single backend, depend on one of the first-party adapters — `doorman-sqlx` (SQLite/Postgres/MySQL), `doorman-dynamodb`, `doorman-mongodb`, or `doorman-redb` — and call `storage.all_stores()` to get the composite `Storage` value. For an in-memory store (tests, ephemeral deployments) use `InMemoryStorage::new().all_stores()`.

`Storage` is a struct of per-trait `Arc<dyn>` fields, so backends can be mixed by naming each one in the literal. The common production split is SQL for the system-of-record stores plus `doorman-redis` for the ephemeral stores and a shared rate limiter — the latter being the only way a multi-replica deployment gets instant cross-process session revoke and one rate-limit budget:

```rust
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

```rust
let storage = Storage {
    users: Arc::new(my_user_store),
    sessions: Arc::new(my_session_store),
    verification_tokens: Arc::new(my_token_store),
    passkey_credentials: Arc::new(my_credential_store),
    passkey_challenges: Arc::new(my_challenge_store),
};
```

## Storing your own data against a doorman user

Key your tables on the doorman `UserId` and reference `users(id) ON DELETE CASCADE` — provided your tables live in the **same SQL database** as doorman's `users` store. Then **delete through doorman**: `AccountManager::delete_account` (self-service) or the operator delete ends in a single `DELETE FROM users`, which the database cascades to both doorman's rows and yours, atomically, while preserving doorman's session-cache invalidation and the `AccountDeleted` audit event. Do not invert it — a host-issued `DELETE FROM users` reaches around doorman, skipping the cache hook (stale sessions resolve until their TTL) and the audit event. For data in a separate database or a non-SQL backend there is no shared transaction (the storage traits are per-concern and engine-agnostic — see [operators.md](operators.md#non-atomicity--deleted-is-not-atomically-or-instantaneously-global)): order deletes so doorman goes last, or soft-delete and reconcile on a sweep.

## Testing your integration with `InMemoryStorage`

`InMemoryStorage` is a supported testing adapter that lives in `doorman-core` and is held to the same conformance and semver guarantees as the shipped database adapters. It fills all five stores from one process-local handle, so a host's integration test can stand up a real `AuthService` with no database, container, or migration step — `InMemoryStorage::new().all_stores()` drops straight into the same builder the quickstart uses:

```rust
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

```rust
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

## Layering: core assembly and the Axum front end

doorman is batteries-included and Axum-first. The auth engine and its assembly live in `doorman-core`. `AuthCore::builder(storage)` is the composition root: it resolves the collaborator defaults, validates the signup/recovery/account URL templates and the configured lifetimes, wires the security notifier and the session-resolution cache (installing the cache invalidator on the `SessionManager`), and constructs the five managers — `SessionManager`, `PasskeyManager`, `SignupManager`, `RecoveryManager`, `AccountManager` — in the order their shared collaborators require. Its `AssemblyError` carries those portable failure modes.

`doorman-axum` is the first-party HTTP integration. `AuthService::builder(storage)` delegates that portable assembly to `doorman-core` and then adds the HTTP layer: the cookie config and its `__Host-`/`__Secure-` prefix rules, the CSRF posture, and the mountable router plus session layer. Its `BuilderError` embeds the core `AssemblyError` variants so a host sees one error type.

The high-level builder still exposes the assembled managers the routes drive via the `AuthState::session_manager()`, `passkey()`, `signup()`, `recovery()`, and `account()` accessors, so host code can run the same logic alongside the bundled routes. Hosts that construct the managers themselves hand them to the low-level `AuthService::from_managers()` path.

## Extractors

With the session layer applied, handlers can extract:

- `AuthUser` — a newtype around `Arc<User>`; rejects with `401` if there is no valid session.
- `OptionalAuthUser` — `Some`/`None`, never rejects.
- `AuthSession` — the resolved session plus helpers (e.g. `is_in_recovery_cooldown`, answered through the configured clock).
- `RequestContext` — client IP from trusted request extensions, plus the untrusted `User-Agent` header. Requires `ClientIp` or `ConnectInfo<SocketAddr>`; see below.

```rust
use axum::Json;
use doorman::prelude::*;

async fn me(user: AuthUser) -> Json<UserDto> {
    // AuthUser is AuthUser(pub Arc<User>); passkey_count comes from your store.
    Json(UserDto::from_user(&user.0, 0))
}
```

## Client identity and proxies

Every route using `RequestContext` resolves one client IP for rate-limit keys, session records, and audit events. Resolution has this precedence:

1. `doorman::axum::ClientIp(IpAddr)` in request extensions, supplied by trusted host middleware.
2. Axum's `ConnectInfo<std::net::SocketAddr>` in request extensions, supplied by `into_make_service_with_connect_info::<SocketAddr>()` when serving the router.
3. If neither is present, reject with **500** and code **`internal_error`**, log the missing-metadata diagnostic, and do not run the handler.

Identity is required even if the route's rate-limit policies are disabled. Disabling a policy with `None` still disables that limit; it does not opt out of the HTTP identity contract. Core managers remain transport-independent: direct callers may supply `SessionContext { ip: None, .. }`, which skips per-IP checks. Direct callers must establish provenance and validate/canonicalize any IP they do supply.

Only the IP enters the bucket, never the source port. IPv6 addresses use their canonical textual form, and IPv4-mapped IPv6 addresses normalize to IPv4. `ClientIp` wraps `std::net::IpAddr`, so textual input must parse successfully before insertion. `User-Agent` remains ordinary untrusted metadata.

### Direct connections

Use the server setup in the quickstart above. Doorman ignores `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, and other forwarding headers, regardless of whether they are single, repeated, conflicting, malformed, or contain multiple hops. Headers cannot supply missing identity or override socket identity.

### Behind a proxy or a custom transport

Doorman delegates proxy resolution to the host. Without host middleware, requests are attributed to the immediate socket peer, so clients behind the same proxy share its rate-limit bucket. Insert a `ClientIp` extension **per request**, before doorman's handlers run, when the host has resolved a trustworthy end-client address. It overrides socket metadata and also works for transports without a socket address.

```rust
use std::net::IpAddr;
use axum::extract::Request;
use doorman::axum::ClientIp;

// Call from trusted host middleware after validating the peer and resolving
// the deployment's forwarding chain. The IP is already parsed, not a header.
fn attach_resolved_client_ip(request: &mut Request, resolved_ip: IpAddr) {
    request.extensions_mut().insert(ClientIp(resolved_ip));
}
```

The host resolver must verify the immediate peer against its configured trusted proxies before accepting forwarding information. It must define the accepted header and resolve the chain from the trusted end (typically right to left, stopping at the first untrusted hop), so attacker-supplied prefixes cannot select the identity. It must also define how malformed, duplicate, and conflicting headers are rejected. Do not insert an unchecked leftmost forwarding value. If trusted resolution fails, reject the request in that middleware; do not fall back to an attacker-controlled value. An ordinary HTTP client cannot set a Rust request extension, but host middleware can undermine this boundary if it blindly copies a header into it.

### Migration and tests

Hosts must serve with `into_make_service_with_connect_info::<SocketAddr>()` or supply the trusted extension. Replace any reliance on doorman parsing forwarding headers with host middleware that follows the trust contract above. Proxy deployments also need the resolver configured for their actual topology.

Tests using `tower::ServiceExt::oneshot` must insert server metadata into the request, for example `request.extensions_mut().insert(axum::extract::ConnectInfo(peer_socket_addr))`, or a trusted `ClientIp`. These are request extensions, not HTTP headers. Test the server's `into_make_service_with_connect_info` setup over a real socket as well.
