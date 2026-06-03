# doorman web-client reference

Small TypeScript reference for browser code that talks to the `doorman-axum`
HTTP routes. This is not an npm package; copy the pieces you want into your
frontend.

`passkey.ts` does the only awkward part of WebAuthn integration: converting
between the base64url strings returned by `webauthn-rs` JSON and the
`ArrayBuffer` fields required by `navigator.credentials.create()` and
`navigator.credentials.get()`.

## Running this reference

This is a TypeScript reference, not a ready-to-serve page: `index.html` imports
`./passkey.ts` directly, so you need a TypeScript-aware dev server or bundler
(Vite, esbuild, `tsx`, …) and a running `doorman-axum` backend to talk to (the
WebAuthn origin must match the backend's `external_origin`). For a no-build,
runnable demo against a live Axum + SQLite server, use
[`examples/minimal-app`](../minimal-app) instead — it ships a plain static
page with the same flows.

## Mapping error codes to user copy

doorman returns a stable machine error code, never end-user prose — the HTTP error
body is `{ "error": { "code", "message" } }`. The client decides what the user
reads. `passkey.ts` shows the pattern: failed requests throw a `DoormanError`
carrying `.code`, `.status`, and a `.guidance` string resolved from the
exported `ERROR_GUIDANCE` table (e.g. `recovery_cooldown_active` →
"This action is blocked during the 24-hour recovery cool-down…").

Customise it by editing `ERROR_GUIDANCE` (wording, tone, localisation) or by
reading `err.code` yourself and routing to your own UI. Codes worth handling:
`recovery_cooldown_active`, `csrf_origin_mismatch`, `session_not_found` /
`session_expired`, `email_already_in_use`, `invalid_verification_token`,
`rate_limited`, and `passkey_possible_compromise`. The full set is in
`crates/axum/src/error.rs`.

## Helpers

- `requestSignup(email)` → `POST /auth/signup/request`
- `finishSignup(token, passkeyName?)` → consume signup token, register the
  first passkey, receive `AuthResponse`; the server sends a best-effort
  passkey-registered notification
- `authenticatePasskey()` → discoverable passkey sign-in, receive
  `AuthResponse`
- `requestRecovery(email)` → `POST /auth/recovery/request`
- `finishRecovery(token, passkeyName?)` → consume recovery token, register a
  new cool-down-bound passkey, receive a recovery cool-down session; the
  server sends passkey-registered and recovery-completed notifications
- `registerPasskey(name?)` → add a passkey for the current session. If the
  current session is in recovery cool-down, the new passkey inherits that
  deadline
- `listPasskeys()` / `deletePasskey(id)`
- `listSessions()` / `revokeSession(id)` / `revokeOtherSessions()`

## Endpoint shape

| Method | Path | Body | Response |
| --- | --- | --- | --- |
| POST | `/auth/signup/request` | `{ email }` | `204` |
| POST | `/auth/signup/consume` | `{ token }` | `{ challenge_id, options }` |
| POST | `/auth/signup/finish` | `{ challenge_id, response, name? }` | `AuthResponse` |
| POST | `/auth/passkey/authenticate/start` | empty | `{ challenge_id, options }` |
| POST | `/auth/passkey/authenticate/finish` | `{ challenge_id, response }` | `AuthResponse` |
| POST | `/auth/recovery/request` | `{ email }` | `204` |
| POST | `/auth/recovery/consume` | `{ token }` | `{ challenge_id, options }` |
| POST | `/auth/recovery/finish` | `{ challenge_id, response, name? }` | `AuthResponse` |
| POST | `/auth/passkey/register/start` | empty, authenticated | `{ challenge_id, options }` |
| POST | `/auth/passkey/register/finish` | `{ challenge_id, response, name? }` | `PasskeyDto` |
| GET | `/auth/passkey` | authenticated | `PasskeyDto[]` |
| DELETE | `/auth/passkey/{credential_id}` | authenticated | `204` or `409 recovery_cooldown_active` |
| GET | `/auth/sessions` | authenticated | `SessionDto[]` |
| DELETE | `/auth/sessions/{id}` | authenticated | `204` or `409 recovery_cooldown_active` for other sessions |
| DELETE | `/auth/sessions` | authenticated | `204` or `409 recovery_cooldown_active` |

Recovery links only start passkey registration; no session is issued until
`/auth/recovery/finish` succeeds. During recovery cool-down, deleting
passkeys, revoking other sessions, and `DELETE /auth/sessions` are blocked;
adding passkeys and revoking/logging out of the current session remain
allowed. Signing in with a recovery-created or inherited passkey before its
cool-down deadline returns another restricted `AuthResponse`.

`index.html` wires the helpers to a minimal page. The bundled
`examples/minimal-app` contains a fuller no-build static client that shows
signup, sign-in, recovery, passkeys, and sessions against a live Axum app.
