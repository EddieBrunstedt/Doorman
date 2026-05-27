# bauth

bauth is an Axum-first authentication library for Rust applications. It
ships correct auth primitives — Argon2id passwords, passkeys/WebAuthn,
PKCE OAuth, magic links, server-side opaque sessions, CSRF origin checks,
rate limiting, and audit events — behind storage traits you can back with
SQLx or your own database layer.

The user-facing crate is `bauth-axum`. `bauth-core` stays
framework-agnostic so the auth logic is testable without a router, but
Axum is the supported integration today.

Status: pre-1.0. The surface is usable, but breaking changes can land
between minor versions until 1.0.

## Quickstart: mount bauth on Axum

```toml
[dependencies]
axum = "0.8"
bauth-axum = "0.1"
bauth-core = "0.1"
bauth-sqlx = { version = "0.1", features = ["sqlite"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use std::sync::Arc;

use axum::{Json, Router, routing::get};
use bauth_axum::dto::{MeResponse, SessionDto};
use bauth_axum::prelude::*;
use bauth_core::oauth::google::GoogleProvider;
use bauth_sqlx::SqliteStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = SqliteStorage::connect("sqlite:///var/lib/myapp/auth.db?mode=rwc").await?;
    storage.migrate().await?;

    let origin = "https://app.example.com".parse()?;
    let google: Arc<dyn OAuthProvider> = Arc::new(GoogleProvider::new(
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
    ));

    let auth = bauth_axum::quickstart(storage.storage())
        .password(PasswordAuthConfig::default())
        .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
        .oauth([google])
        .external_origin(origin)
        .cookie(CookieConfig::default())
        .build()?;

    let app = Router::new()
        .merge(auth.router())
        .route("/api/me", get(me))
        .layer(auth.session_layer());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn me(auth: AuthSession) -> Json<MeResponse> {
    Json(MeResponse {
        user: auth.user.into(),
        session: SessionDto::from_session(auth.session, true),
    })
}
```

`auth.router()` mounts `/auth/*` routes for every method you enabled.
`auth.session_layer()` reads the session cookie or bearer token and makes
`AuthUser`, `OptionalAuthUser`, and `AuthSession` work in your handlers.

For local plain-HTTP development, set `CookieConfig { secure: false, .. }`;
leave `secure = true` in production.

## Run the minimal app

A complete runnable app lives in [`examples/minimal-app`](examples/minimal-app):
SQLite via `bauth-sqlx`, password auth, passkeys, optional Google OAuth,
`/api/me`, and a static HTML page with no frontend build step.

```sh
cargo run -p bauth-minimal-app
```

Open <http://localhost:3000>. To enable Google OAuth, set
`GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` and register
`http://localhost:3000/auth/oauth/google/callback` as the callback URL.

## What ships

- Password auth with Argon2id, email verification, and password reset.
- Passkeys / WebAuthn via [`webauthn-rs`](https://crates.io/crates/webauthn-rs).
- OAuth social login with PKCE; Google and GitHub providers are included,
  and custom providers implement `OAuthProvider`.
- Magic-link sign-in using single-use, hashed email tokens.
- Server-side opaque sessions with instant revocation and a signed-in
  devices endpoint.
- CSRF origin checks for cookie-backed state-changing requests.
- Rate limiting and audit events for sensitive auth operations.
- First-party SQLx storage adapter for SQLite and Postgres.

## Workspace layout

```text
crates/
  core/    # bauth-core: managers, storage traits, auth primitives
  axum/    # bauth-axum: router, extractors, session layer, CSRF layer
  sqlx/    # bauth-sqlx: SQLite/Postgres storage adapter
examples/
  minimal-app/  # runnable Axum + SQLite app
  web-client/   # browser-side passkey helper reference
```

## Production checklist

These mirror the startup warnings emitted by `quickstart().build()` and
`BauthAxum::builder().build()`.

- Keep `CookieConfig::secure = true` outside local HTTP development.
- Set `external_origin("https://app.example.com".parse()?)`; this also
  enables the default CSRF origin-check layer.
- Do not disable CSRF unless authenticated browser cookies are not in
  scope and every client uses bearer tokens.
- Wire a real `AuditSink`; `NoopAuditSink` discards security events.
- Wire a production `RateLimiter`. The built-in `InMemoryRateLimiter` is
  per-process, so multi-replica deployments need a shared backend.
- Wire a real `EmailSender` before relying on email verification,
  password reset, or magic links.
- If you enable `OAuthConfig::allow_email_linking`, also set
  `PasswordAuthConfig::require_email_verification = true` unless you
  intentionally trust every provider's `email_verified` claim.
- Run storage migrations at startup and periodically purge expired
  sessions, verification tokens, passkey challenges, and OAuth states.

Use `.silence_warnings()` only after you have reviewed the warning and
made an explicit operational choice.

## Configuration knobs

- `SessionConfig::lifetime` — session lifetime; defaults to 30 days.
- `PasswordAuthConfig` — password policy, verification/reset lifetimes,
  URL templates, `require_email_verification`, reset-time session
  revocation, rate limits, and email renderer.
- `PasskeyConfig` — WebAuthn relying-party id, origin, display name, and
  challenge lifetime.
- `OAuthConfig::allow_email_linking` — auto-link provider identities to
  an existing verified email. Defaults to `false`.
- `MagicLinkConfig` — token lifetime, URL template, signup policy, rate
  limits, and email renderer.
- `CookieConfig` — session/state cookie names, domain/path, `secure`,
  `SameSite`, and max ages.
- `CsrfConfig` — override or disable the origin-check layer.

Feature flags on `bauth-axum`: `password`, `passkey`, `oauth`, and
`magic_link` (all enabled by default).

```toml
bauth-axum = { version = "0.1", default-features = false, features = ["password"] }
```

## Custom storage and direct manager use

The happy path is `bauth-sqlx` plus `bauth_axum::quickstart(...)`. Hosts
on another database stack implement the storage traits in `bauth-core`:
`UserStore`, `SessionStore`, `PasswordCredentialStore`,
`VerificationTokenStore`, `PasskeyCredentialStore`,
`PasskeyChallengeStore`, `OAuthIdentityStore`, and `OAuthStateStore`.

If you want full control of the HTTP surface, skip `bauth-axum` routes and
call the core managers directly (`SessionManager`, `PasswordAuthManager`,
`PasskeyManager`, `OAuthManager`, `MagicLinkManager`). They return
framework-agnostic outcomes such as `IssuedSession`, `RegisterOutcome`,
and `OAuthOutcome`.

## Security

See [`SECURITY.md`](SECURITY.md) for the threat model, host hardening
requirements, cookie and CSRF guidance, operational cleanup, and the
vulnerability disclosure address.

## License

MIT OR Apache-2.0 at your option.
