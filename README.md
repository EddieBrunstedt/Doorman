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
examples/
  sqlx-sqlite/  # reference storage adapter using SQLx + SQLite
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

## Worked example (in-memory, for tests and local play)

```rust
use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::{EmailSender, NoopEmailSender};
use bauth_core::memory::{
    InMemoryPasswordCredentialStore, InMemoryRateLimiter, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::password_auth::{PasswordAuthConfig, PasswordAuthManager};
use bauth_core::rate_limit::RateLimiter;
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::storage::{
    PasswordCredentialStore, SessionStore, UserStore, VerificationTokenStore,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let email: Arc<dyn EmailSender> = Arc::new(NoopEmailSender);

    let users: Arc<dyn UserStore> = Arc::new(InMemoryUserStore::new());
    let sessions: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    let passwords: Arc<dyn PasswordCredentialStore> =
        Arc::new(InMemoryPasswordCredentialStore::new());
    let tokens: Arc<dyn VerificationTokenStore> =
        Arc::new(InMemoryVerificationTokenStore::new());
    let limiter: Arc<dyn RateLimiter> = Arc::new(InMemoryRateLimiter::new(clock.clone()));

    let session_manager = SessionManager::new(
        sessions.clone(),
        clock.clone(),
        audit.clone(),
        SessionConfig { lifetime: Duration::from_secs(60 * 60 * 24 * 30) },
    );
    let manager = PasswordAuthManager::new(
        users,
        passwords,
        tokens,
        session_manager,
        email,
        clock,
        audit,
        limiter,
        PasswordAuthConfig::default(),
    );

    let outcome = manager
        .register("alice@example.com", "correct horse battery staple", SessionContext::default())
        .await?;
    println!("registered {:?}", outcome.user.id);
    Ok(())
}
```

For a production-shaped storage layer, see
[`examples/sqlx-sqlite`](examples/sqlx-sqlite) — every trait wired to a
single SQLite database via SQLx, with migrations and tests.

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

## Security

See [`SECURITY.md`](SECURITY.md) for the threat model, hardening
checklist for hosts (cookie flags, CSRF, key rotation, etc.), and the
vulnerability disclosure address.

## License

MIT OR Apache-2.0 at your option.
