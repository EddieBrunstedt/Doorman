# Flows

The three first-class flows are **signup**, **login**, and **recovery**, plus the account-management operations. Each diagram shows the browser, the doorman router, and the email transport. Route paths are relative to the `/auth` prefix the router mounts under.

Read [concepts.md](concepts.md) first for the vocabulary (discoverable passkeys, opaque tokens, recovery cool-down).

## Signup

A new account is bootstrapped by proving control of an email address and then registering the first passkey. The session is issued only after the passkey is registered — the email link alone never logs anyone in.

```
Browser                         doorman router                    Email
   |                                 |                             |
   |  POST /auth/signup/request      |                             |
   |  { email }                      |                             |
   |-------------------------------->|                             |
   |                                 |  store single-use token     |
   |                                 |  (purpose = Signup)         |
   |                                 |--- send signup link ------->|
   |   204 (same response whether    |                             |
   |<-- address is new or known) ----|                             |
   |                                 |                             |
   |  user opens link, posts token   |                             |
   |  POST /auth/signup/consume      |                             |
   |  { token }                      |                             |
   |-------------------------------->|                             |
   |                                 |  mark email verified,       |
   |                                 |  start passkey registration |
   |<-- registration challenge ------|                             |
   |                                 |                             |
   |  POST /auth/signup/finish       |                             |
   |  { registration response }      |                             |
   |-------------------------------->|                             |
   |                                 |  register first passkey,    |
   |                                 |  send "passkey registered"  |
   |                                 |  notice, mint session       |
   |<-- 200 + Set-Cookie session ----|                             |
```

`/auth/signup/request` returns the **same** response for a new and an already-registered address (an already-registered address simply gets no email), so the endpoint does not reveal who has an account.

## Login

Steady-state login is a single discoverable-passkey ceremony with no email and no username.

```
Browser                         doorman router
   |                                 |
   |  POST /auth/passkey/             |
   |       authenticate/start         |
   |  (no email, no username)        |
   |-------------------------------->|
   |                                 |  rate-limit by IP,
   |                                 |  mint discoverable challenge
   |<-- challenge -------------------|
   |                                 |
   |  browser prompts user to pick   |
   |  a passkey and signs            |
   |                                 |
   |  POST /auth/passkey/             |
   |       authenticate/finish        |
   |  { assertion }                  |
   |-------------------------------->|
   |                                 |  verify signature + origin,
   |                                 |  check user-handle binding,
   |                                 |  check signature counter,
   |                                 |  mint session
   |<-- 200 + Set-Cookie session ----|
```

The server identifies the user from the authenticator-asserted **user handle** and verifies it matches the credential's stored owner before minting a session. The WebAuthn signature counter is checked for regression (cloned-authenticator detection). Every failure path emits an audit event. See [security.md](security.md#passkeys).

If the credential or session is still inside a recovery cool-down, the minted session is **restricted** (see below).

## Recovery

Recovery is for a user who lost every passkey. It deliberately requires enrolling a _new, visible_ passkey before any session is issued, and the resulting session is restricted by the cool-down.

```
Browser                         doorman router                    Email
   |                                 |                             |
   |  POST /auth/recovery/request    |                             |
   |  { email }                      |                             |
   |-------------------------------->|                             |
   |                                 |  if registered: store token |
   |                                 |  (purpose = Recovery),      |
   |                                 |  send recovery link +       |
   |                                 |  "recovery requested" notice|
   |                                 |--- (registered only) ------>|
   |   204 (same response whether    |                             |
   |<-- address is known or not) ----|                             |
   |                                 |                             |
   |  POST /auth/recovery/consume    |                             |
   |  { token }                      |                             |
   |-------------------------------->|                             |
   |                                 |  start passkey registration |
   |<-- registration challenge ------|                             |
   |                                 |                             |
   |  POST /auth/recovery/finish     |                             |
   |  { registration response }      |                             |
   |-------------------------------->|                             |
   |                                 |  register new passkey,      |
   |                                 |  stamp recovery_cooldown_   |
   |                                 |  until on passkey+session,  |
   |                                 |  send "passkey registered"  |
   |                                 |  + "recovery completed",    |
   |                                 |  mint RESTRICTED session    |
   |<-- 200 + Set-Cookie session ----|                             |
```

Unknown addresses receive **no email** — sending one would be an enumeration oracle. The recovery-created passkey stores the same `recovery_cooldown_until` deadline as the session: signing in with it before the deadline mints another restricted session, and a passkey added from a restricted session inherits the deadline. Pre-existing passkeys and sessions stay unrestricted throughout.

## Restricted (cool-down) sessions

While a session is inside its recovery cool-down, the destructive lockout actions are blocked and everything else proceeds normally:

| Action                                                | During cool-down                 |
| ----------------------------------------------------- | -------------------------------- |
| Add a passkey                                         | Allowed (inherits the cool-down) |
| Log out current session (`POST /auth/logout`)         | Allowed                          |
| Log out everywhere (`POST /auth/logout-all`)          | Allowed (own sessions only)      |
| Delete a passkey (`DELETE /auth/passkey/{id}`)        | **Blocked**                      |
| Revoke another session (`DELETE /auth/sessions/{id}`) | **Blocked**                      |
| Sign out everywhere _else_ (`DELETE /auth/sessions`)  | **Blocked**                      |

After the deadline passes, the checks treat the cool-down as inactive automatically; there is no cleanup job.

## Account management

Authenticated routes for an established account:

| Operation                | Route                                                      | Notes                                                              |
| ------------------------ | ---------------------------------------------------------- | ------------------------------------------------------------------ |
| List passkeys            | `GET /auth/passkey`                                        | Returns metadata (AAGUID, transports, backup state, device label). |
| Add passkey              | `POST /auth/passkey/register/start` → `/finish`            | Allowed during cool-down.                                          |
| Delete passkey           | `DELETE /auth/passkey/{credential_id}`                     | Ownership-checked; blocked during cool-down.                       |
| List sessions            | `GET /auth/sessions`                                       | Carries IP / user-agent / device label.                            |
| Revoke one session       | `DELETE /auth/sessions/{id}`                               | Ownership-checked; blocked during cool-down for _other_ sessions.  |
| Sign out everywhere else | `DELETE /auth/sessions`                                    | Blocked during cool-down.                                          |
| Log out                  | `POST /auth/logout`                                        | Clears the cookie.                                                 |
| Log out everywhere       | `POST /auth/logout-all`                                    | Revokes all of the caller's sessions.                              |
| Change email             | `POST /auth/account/email` → `/auth/account/email/confirm` | Confirmation link to the new address; notice to the old one.       |
| Delete account           | `DELETE /auth/account`                                     | Cascades across all stores; blocked during cool-down.              |

Email change reuses the verification-token machinery: a single-use confirmation link goes to the **new** address and a security notice goes to the **old** one, and the change only lands when the new address confirms.

## Security notifications

doorman sends best-effort security-notice emails (after the protected action has already succeeded) for: a registered-address recovery request, a completed recovery, every successful passkey registration, a passkey removal, an email-change request, revoking another session, and "sign out everywhere else". It does **not** send mail for unknown-address recovery, already-registered signup, or ordinary self-logout.
