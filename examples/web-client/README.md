# bauth web-client (passkey example)

Worked TypeScript example for the passkey ceremonies exposed by
`bauth-core`. There is no `npm` package — this directory is intended to be
read alongside the README and copied into a host frontend.

The browser side of WebAuthn requires a small amount of base64url
encoding/decoding because `navigator.credentials.create` / `.get` expect
`ArrayBuffer` for `challenge`, `user.id`, and `allowCredentials[].id`,
while `bauth-core` (via `webauthn-rs`) returns and accepts base64url
strings. The helpers in `passkey.ts` handle that translation.

## Endpoints assumed

| Method | Path | Body | Response |
| ------ | ---- | ---- | -------- |
| POST | `/auth/passkey/register/start` | empty (user is identified by session) | `{ challenge_id, options }` |
| POST | `/auth/passkey/register/finish` | `{ challenge_id, response, name? }` | passkey dto |
| POST | `/auth/passkey/authenticate/start` | `{ email }` | `{ challenge_id, options }` |
| POST | `/auth/passkey/authenticate/finish` | `{ challenge_id, response }` | auth response (session cookie set) |

`options` is the JSON `webauthn-rs` produces for
`CreationChallengeResponse` / `RequestChallengeResponse` and `response`
is the result returned by the authenticator, serialised back to JSON.

## Files

- `passkey.ts` — `registerPasskey()` and `authenticatePasskey()`
- `index.html` — minimal page wiring the two functions to buttons
