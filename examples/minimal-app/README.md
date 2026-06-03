# bauth minimal app

Runnable Axum + SQLite app for the final passkey-only bauth surface.

It demonstrates:

- email-first signup that finishes by registering the user's first passkey;
- discoverable passkey sign-in with no email prompt;
- recovery by email link followed by forced new-passkey registration before
  any session is issued;
- the passkey-bound post-recovery cool-down UX (`409 recovery_cooldown_active`
  on blocked actions);
- passkey listing, adding, and deletion;
- session listing, current-session logout, and "sign out everywhere else";
- a `/api/me` host route that includes `passkey_count` and recovery cool-down state.

## Run

```sh
cargo run -p bauth-minimal-app
```

Open <http://localhost:3000>. The app uses `TerminalEmailSender`, so signup,
recovery, and security-notification emails are printed to the process
stdout. Copy the printed URL into the browser to consume the token and
register a passkey.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite://bauth-minimal-app.db?mode=rwc` | SQLite database URL. |
| `EXTERNAL_ORIGIN` | `http://localhost:3000` | Public origin used for passkeys, CSRF, and email links. |
| `BIND_ADDR` | `127.0.0.1:3000` | Socket address to bind. |
| `PASSKEY_RP_ID` | host from `EXTERNAL_ORIGIN` | WebAuthn relying-party id. |
| `PASSKEY_RP_NAME` | `bauth minimal app` | WebAuthn display name. |

## User-facing messages

bauth returns stable machine error codes (e.g. `recovery_cooldown_active`),
not end-user prose. The static page maps them to guidance in its
`ERROR_GUIDANCE` table and shows the friendly text in an `role="alert"` region
while keeping the raw code in the activity log. Edit that table to rebrand or
localise the copy; the full code set is in `crates/axum/src/error.rs`. The page
also includes basic accessibility (form labels, focus management after a flow
completes, and ARIA live regions for status and errors).

## Caveats

This is a development reference, not a production template. It silences
startup warnings because it intentionally uses terminal email and the
in-memory rate-limiter default. Production hosts need a real `EmailSender`
for both link delivery and security notifications.
