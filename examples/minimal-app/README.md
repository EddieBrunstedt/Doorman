# bauth minimal app

Runnable Axum app showing the `bauth_axum::quickstart` path with:

- SQLite storage via `bauth-sqlx`
- passkey-based sign-in
- email-link signup that finishes with a passkey registration; email bodies are printed to the server terminal for local development
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
| `EXTERNAL_ORIGIN` | `http://localhost:3000` | Public origin used for CSRF and passkeys. |
| `BIND_ADDR` | `127.0.0.1:3000` | Socket address to bind. |
| `PASSKEY_RP_ID` | host from `EXTERNAL_ORIGIN` | WebAuthn relying-party id. |
| `PASSKEY_RP_NAME` | `bauth minimal app` | WebAuthn display name. |
This example uses a terminal-printing email sender and the development
rate-limiter default. It is a quickstart reference, not a production
deployment template.
