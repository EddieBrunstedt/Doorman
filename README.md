# bauth

A Rust authentication library for Axum (and, in principle, any HTTP
framework). Composes correct primitives — Argon2id, WebAuthn,
PKCE OAuth, server-side opaque sessions — behind a small set of storage
traits the host implements.

The goal is to fill the gap [better-auth](https://github.com/better-auth/better-auth)
fills in the JS ecosystem: drop-in, modern auth without dictating your
storage, ORM, or frontend.

Status: pre-1.0. Public surface is stable enough to build against, but
expect breaking changes between minor versions until 1.0.

## Workspace layout

```
crates/
  core/    # bauth-core — framework-agnostic primitives, traits, managers
  axum/    # bauth-axum — HTTP layer (router, extractors, middleware)
  sqlx/    # bauth-sqlx — SQLx storage adapter (SQLite and Postgres, feature-gated)
examples/
  web-client/   # browser-side TypeScript for the passkey ceremonies
```

## What's in v1

- Password auth (Argon2id) with email verification and password reset
- Passkeys / WebAuthn via [`webauthn-rs`](https://crates.io/crates/webauthn-rs)
- OAuth social login with PKCE (Google + GitHub, plus a provider trait)
- Server-side opaque session tokens with instant revocation
- Rate limiting on sensitive endpoints (login, password reset, verification re-issue)
- Audit log emission for every meaningful auth event
- Account linking — one user can hold password + passkeys + multiple OAuth identities

See [`PLAN.md`](PLAN.md) for design rationale and the full roadmap.

## Design in one paragraph

`bauth-core` defines storage traits — `UserStore`, `SessionStore`,
`PasswordCredentialStore`, `PasskeyCredentialStore`,
`PasskeyChallengeStore`, `OAuthIdentityStore`, `OAuthStateStore`,
`VerificationTokenStore`, plus `EmailSender`, `AuditSink`, `Clock`, and
`RateLimiter`. The host implements them (or uses an example adapter),
constructs the managers (`SessionManager`, `PasswordAuthManager`,
`PasskeyManager`, `OAuthManager`), and either mounts the routes from
`bauth-axum` or drives the managers directly.

## Worked example: mounting on Axum

The intended entry point for an Axum host. Wire your stores into the
managers from `bauth-core`, hand them to `BauthAxum::builder()`, and
merge the returned router into your app.

```rust
use std::sync::Arc;
use std::time::Duration;

use axum::{Router, routing::get, Json};
use bauth_axum::{AuthUser, BauthAxum, CookieConfig};
use bauth_axum::dto::UserDto;
use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::{EmailSender, NoopEmailSender};
use bauth_core::memory::{
    InMemoryPasswordCredentialStore, InMemoryRateLimiter, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::password_auth::{PasswordAuthConfig, PasswordAuthManager};
use bauth_core::rate_limit::RateLimiter;
use bauth_core::session::{SessionConfig, SessionManager};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let email: Arc<dyn EmailSender> = Arc::new(NoopEmailSender);
    let limiter: Arc<dyn RateLimiter> = Arc::new(InMemoryRateLimiter::new(clock.clone()));

    let users = Arc::new(InMemoryUserStore::new());
    let sessions = Arc::new(InMemorySessionStore::new());
    let passwords = Arc::new(InMemoryPasswordCredentialStore::new());
    let tokens = Arc::new(InMemoryVerificationTokenStore::new());

    let session_manager = SessionManager::new(
        sessions,
        clock.clone(),
        audit.clone(),
        SessionConfig { lifetime: Duration::from_secs(60 * 60 * 24 * 30) },
    );
    let password_manager = PasswordAuthManager::new(
        users.clone(),
        passwords,
        tokens,
        session_manager.clone(),
        email,
        clock,
        audit,
        limiter,
        PasswordAuthConfig::default(),
    );

    let auth = BauthAxum::builder()
        .session_manager(session_manager)
        .user_store(users)
        .password_manager(password_manager)
        .cookie_config(CookieConfig::default())
        .build()?;

    let app = Router::new()
        .merge(auth.router())                  // mounts /auth/*
        .route("/api/me", get(me))
        .layer(auth.session_layer());          // populates AuthUser

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn me(AuthUser(user): AuthUser) -> Json<UserDto> {
    Json(user.into())
}
```

`auth.router()` mounts every endpoint whose backing manager you supplied
to the builder. Add `.passkey_manager(...)`, `.oauth_manager(...)`, and
(for OAuth) `.external_origin("https://app.example.com".parse()?)` to
turn on the other auth methods.

For a production-shaped storage layer, use
[`bauth-sqlx`](crates/sqlx) — `SqliteStorage` and `PostgresStorage`
implement every storage trait against a SQLx pool, with embedded
migrations. Enable the `sqlite` or `postgres` feature for the backend
you need.

### Driving the managers directly

If you're not on Axum or want full control of the HTTP surface, skip
`bauth-axum` and call the managers from `bauth-core` yourself — they
own all the auth logic and return framework-agnostic outcomes
(`IssuedSession`, `RegisterOutcome`, `OAuthOutcome`, …). The Axum crate
is a thin translation layer on top.

## Configuration knobs you usually want to think about

- `SessionConfig::lifetime` — defaults to 30 days
- `PasswordAuthConfig::require_email_verification` — gate login on verified email
- `PasswordAuthConfig::revoke_sessions_on_password_reset` — defaults to `true`
- `PasswordAuthConfig::rate_limits` — per-IP and per-identifier policies for
  login, password reset, and verification re-issue
- `PasskeyConfig::{rp_id, rp_origin, rp_name}` — relying-party identity
- `OAuthConfig::allow_email_linking` — auto-link OAuth identity to an
  existing email-matching account when the provider asserts the email is
  verified. Off by default.
- `CookieConfig` (from `bauth-axum`) — session and OAuth state cookie
  attributes: `session_cookie_name`, `oauth_state_cookie_name`, `domain`,
  `path`, `secure` (defaults to `true` — disable for plain-HTTP local
  dev), `same_site` (defaults to `Lax`), `session_max_age` (match
  `SessionConfig::lifetime`), `oauth_state_max_age`.
- `BauthAxumBuilder::external_origin` — required when an OAuth manager
  is supplied. The absolute origin external clients see (e.g.
  `https://app.example.com`); used to build the absolute callback URL
  handed to providers. Build will fail without it.

### Feature flags on `bauth-axum`

`password`, `passkey`, `oauth` (all on by default). Disable the ones
you don't use to shrink compile time and dependency surface:

```toml
bauth-axum = { version = "0.1", default-features = false, features = ["password"] }
```

## Security

See [`SECURITY.md`](SECURITY.md) for the threat model, hardening
checklist for hosts (cookie flags, CSRF, key rotation, etc.), and the
vulnerability disclosure address.

## License

MIT OR Apache-2.0 at your option.
