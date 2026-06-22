# doorman minimal app

A runnable Axum + SQLite app exercising the full passkey-only doorman surface:

- email-first signup that finishes by registering the user's first passkey;
- discoverable passkey sign-in with no email prompt;
- recovery by email link, which forces a new passkey before any session is issued;
- the post-recovery cooldown that blocks destructive actions (`409 recovery_cooldown_active`);
- passkey listing (synced vs device-bound), adding, renaming, and deletion;
- session listing and signing out of this device, of other devices, or everywhere;
- step-up re-authentication: deletion, email change, and passkey removal retry transparently after a fresh passkey assertion when the server returns `401 reauth_required`;
- verified email change (confirmation link consumed from the `email_change_token` query param);
- a `/api/me` host route — this app's own, not a doorman endpoint — returning the user, `passkey_count`, and cooldown state.

## Run

```sh
cargo run -p doorman-minimal-app
```

Open <http://localhost:3000>. Email transport prints each message to the server terminal, so signup, recovery, and email-change links land there — copy the printed URL into the browser to consume the token and register a passkey.

## Layout

A dark, two-column page: controls on the left, a **trace** on the right.

- Every action opens a labelled flow. The steps it triggers — each request and each browser passkey ceremony — nest under it as expandable rows, so the whole dance (e.g. `consume` → `navigator.credentials.create()` → `finish`) reads top to bottom.
- The page wraps `window.fetch`, so the trace shows **every** request the page makes — including the background state re-reads that repaint the left panel after an action. Nothing is hidden, and the `✓` outcome line marks where one action's dance ends.
- Each row is tagged `doorman` (a `/auth` route) or `app` (this app's `/api/me`) and carries a one-line note on what doorman is doing; the request and response payloads are one click down.

doorman returns stable machine error codes, not end-user prose. The page maps them to guidance in its `ERROR_GUIDANCE` table and shows the friendly text in a `role="alert"` region while the raw code stays in the trace. Edit that table to rebrand or localise; the full code set is in `crates/axum/src/error.rs`. The WebAuthn glue (base64url ↔ `ArrayBuffer`, `create()`/`get()`) is also available, typed, in [`examples/web-client`](../web-client).

## Environment

| Variable          | Default                                    | Purpose                                                 |
| ----------------- | ------------------------------------------ | ------------------------------------------------------- |
| `DATABASE_URL`    | `sqlite://doorman-minimal-app.db?mode=rwc` | SQLite database URL.                                    |
| `EXTERNAL_ORIGIN` | `http://localhost:3000`                    | Public origin used for passkeys, CSRF, and email links. |
| `BIND_ADDR`       | `127.0.0.1:3000`                           | Socket address to bind.                                 |
| `PASSKEY_RP_ID`   | host from `EXTERNAL_ORIGIN`                | WebAuthn relying-party id.                              |
| `PASSKEY_RP_NAME` | `doorman minimal app`                      | WebAuthn display name.                                  |

## Caveats

A development reference, not a production template. It uses terminal email and the in-memory rate-limiter default; a real deployment wires a transactional `EmailSender` (for links _and_ security notices), a persistent audit sink, and a shared rate-limiter backend.
