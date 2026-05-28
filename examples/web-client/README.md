# bauth web-client reference

Small TypeScript reference for browser code that talks to the `bauth-axum`
HTTP routes. This is not an npm package; copy the pieces you want into your
frontend.

`passkey.ts` does the only awkward part of WebAuthn integration: converting
between the base64url strings returned by `webauthn-rs` JSON and the
`ArrayBuffer` fields required by `navigator.credentials.create()` and
`navigator.credentials.get()`.

## Helpers

- `requestSignup(email)` → `POST /auth/signup/request`
- `finishSignup(token, passkeyName?)` → consume signup token, register the
  first passkey, receive `AuthResponse`
- `authenticatePasskey()` → discoverable passkey sign-in, receive
  `AuthResponse`
- `requestRecovery(email)` → `POST /auth/recovery/request`
- `finishRecovery(token, passkeyName?)` → consume recovery token, register a
  new passkey, receive a recovery cool-down session
- `registerPasskey(name?)` → add a passkey for the current session
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

`index.html` wires the helpers to a minimal page. The bundled
`examples/minimal-app` contains a fuller no-build static client that shows
signup, sign-in, recovery, passkeys, and sessions against a live Axum app.
