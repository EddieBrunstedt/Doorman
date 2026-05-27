# bauth minimal app

Runnable Axum app showing the `bauth_axum::quickstart` path with:

- SQLite storage via `bauth-sqlx`
- passkey registration/login
- magic-link signup/login with email bodies printed to the server terminal
- optional Google OAuth
- `/api/me`
- one static HTML page, no frontend build step

## Run

```sh
cargo run -p bauth-minimal-app
```

Open <http://localhost:3000>.

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite://bauth-minimal-app.db?mode=rwc` | SQLite database URL. |
| `EXTERNAL_ORIGIN` | `http://localhost:3000` | Public origin used for CSRF, passkeys, and OAuth callbacks. |
| `BIND_ADDR` | `127.0.0.1:3000` | Socket address to bind. |
| `PASSKEY_RP_ID` | host from `EXTERNAL_ORIGIN` | WebAuthn relying-party id. |
| `PASSKEY_RP_NAME` | `bauth minimal app` | WebAuthn display name. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | unset | Enables Google OAuth when both are present. |

For Google OAuth, register this callback URL with Google:

```text
http://localhost:3000/auth/oauth/google/callback
```

This example uses a terminal-printing email sender and the development
rate-limiter default. It is a quickstart reference, not a production
deployment template.
