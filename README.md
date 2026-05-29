# bauth

bauth is an opinionated passkey-only Axum auth library, with email magic
links for recovery only.

It gives an Axum app one steady-state login method — discoverable
passkeys/WebAuthn — plus email-gated signup and recovery flows that force
a passkey registration before any session is issued. There are no
passwords, OAuth providers, TOTP codes, or general-purpose email login
links.

This crate is pre-1.0; breaking changes can still land before the public
surface is declared stable.

## Quickstart

```toml
[dependencies]
axum = "0.8"
bauth = { version = "0.1", features = ["axum", "sqlite"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

`bauth` is the umbrella crate: one dependency, one version to bump. It
re-exports `bauth-core`, `bauth-axum`, and `bauth-sqlx` behind features as
`bauth::core`, `bauth::axum`, and `bauth::sqlx`. Hosts that want only a
subset can still depend on the individual crates directly.

```rust
use std::sync::Arc;
use axum::{routing::get, Router};
use bauth::prelude::*;
use bauth::core::verification::TOKEN_PLACEHOLDER;

let storage = SqliteStorage::connect("sqlite:///var/lib/app/auth.db?mode=rwc").await?;
storage.migrate().await?;
let origin = "https://app.example.com".parse()?;
let base = origin.as_str().trim_end_matches('/');
let auth = BauthAxum::builder(storage.storage())
    .email(Arc::new(TerminalEmailSender))
    .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
    .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
    .external_origin(origin)
    .cookie(CookieConfig::default())
    .build()?;
let app = Router::new().merge(auth.router()).route("/api/me", get(me)).layer(auth.session_layer());
```

`auth.router()` mounts the passkey, signup, recovery, and session-management
routes under `/auth`. `auth.session_layer()` resolves the session cookie or
bearer token so your handlers can use `AuthUser`, `OptionalAuthUser`, and
`AuthSession`.

`TerminalEmailSender` is for local development. In production, implement
`EmailSender` with your transactional email provider and keep
`CookieConfig::secure = true`.

## User flows

- **Sign up:** `POST /auth/signup/request` sends an email link. Consuming
  that link starts passkey registration; `/auth/signup/finish` registers
  the first passkey and issues the session.
- **Sign in:** `POST /auth/passkey/authenticate/start` takes no email or
  username. The browser shows the user's discoverable passkeys, and the
  server identifies the user from the WebAuthn response.
- **Recover:** `POST /auth/recovery/request` sends a recovery email for a
  registered account. The link can only start a new passkey registration.
  `/auth/recovery/finish` issues a session restricted by the default 24h
  post-recovery cool-down.
- **Manage access:** authenticated users can list/add/delete passkeys and
  list/revoke sessions. Cool-down sessions cannot delete passkeys or revoke
  other sessions.
- **Sign out:** `POST /auth/logout` revokes the caller's current session
  and returns `204` with a `Set-Cookie` that clears the session cookie.
  Signing out of your own session is allowed even during the post-recovery
  cool-down.

Encourage every user to register at least two passkeys: for example a
platform passkey plus a password-manager or hardware-key backup. The
`UserDto.passkey_count` field exists so hosts can render that nudge.

## Run the minimal app

```sh
cargo run -p bauth-minimal-app
```

Open <http://localhost:3000>. Signup and recovery emails are printed to
the terminal, so copy the link from stdout and complete the flow in the
browser. The example uses SQLite, Axum, the bundled router, and a static
HTML page with no frontend build step.

## What ships

- Passkey/WebAuthn registration and discoverable authentication via
  [`webauthn-rs`](https://crates.io/crates/webauthn-rs).
- Email-gated signup and recovery with single-use hashed tokens.
- Server-side opaque sessions with instant revocation.
- Post-recovery session cool-down for destructive auth actions.
- Cookie and bearer-token session presentation.
- CSRF origin checks for cookie-authenticated state-changing requests.
- Audit and rate-limiter traits, with development defaults.
- First-party SQLx storage for SQLite and Postgres.
- Development email transports: terminal and `.eml` file output.

## Production checklist

Review the startup warnings emitted by `BauthAxum::builder().build()` or
`BauthAxum::from_managers().build()` and make explicit choices before
silencing them.

- Replace `TerminalEmailSender` / `FileEmailSender` with a real
  `EmailSender`.
- Wire a durable `AuditSink`; `NoopAuditSink` discards security events.
- Wire a shared production `RateLimiter`; `InMemoryRateLimiter` is
  per-process.
- Set `external_origin` to the exact public origin and keep the default
  CSRF layer enabled for browser cookie flows.
- Keep secure, HttpOnly, SameSite session cookies outside local HTTP
  development.
- Run storage migrations and periodically purge expired sessions,
  verification tokens, and passkey challenges.
- Monitor recovery requests and failed WebAuthn ceremonies.
- Prompt users with `passkey_count < 2` to add a backup passkey.

## Workspace layout

```text
crates/core/   framework-agnostic managers, storage traits, email/audit/rate-limit traits
crates/axum/   Axum router, extractors, session layer, CSRF layer
crates/sqlx/   SQLite/Postgres storage adapter
examples/minimal-app/  runnable Axum + SQLite app
examples/web-client/   browser-side WebAuthn helper reference
```

## Custom storage or HTTP surface

The quickest path is `bauth-sqlx` plus `BauthAxum::builder(...)`.
Hosts on another database stack implement the `bauth-core` storage traits:
`UserStore`, `SessionStore`, `VerificationTokenStore`,
`PasskeyCredentialStore`, and `PasskeyChallengeStore`.

If you want a custom HTTP API, call the core managers directly:
`SessionManager`, `PasskeyManager`, `SignupManager`, and
`RecoveryManager`.

## Security

See [`SECURITY.md`](SECURITY.md) for the threat model, recovery design,
defaults, and host hardening requirements.

## License

MIT OR Apache-2.0 at your option.
