# Security policy

This document describes bauth's security model after the passkey-only
pivot, what the library enforces, and what the host application must still
operate correctly.

## Supported surface

bauth has one steady-state login method: passkeys/WebAuthn using the
discoverable-credential ceremony. Email is used only to start signup or
recovery, and an email link never creates a session by itself.

Out of scope by design: password authentication, OAuth, TOTP, recovery
codes, admin impersonation, roles/permissions, and general-purpose email
login.

## Threat model

bauth is designed to defend against:

- phishing of steady-state logins by relying on origin-bound WebAuthn
  signatures;
- user enumeration in signup, recovery, and passkey authentication;
- immediate account lockout after email recovery by binding the
  post-recovery cool-down to recovery-created passkeys and sessions;
- replay of session tokens, verification tokens, and passkey ceremony
  state from normal HTTP flows;
- database reads yielding usable bearer tokens, because tokens are stored
  as hashes;
- CSRF against cookie-authenticated state-changing endpoints.

bauth cannot defend against:

- a compromised host process;
- a database attacker with both read and write access;
- a compromised user email inbox exercising the recovery flow (the
  cool-down limits immediate lockout but cannot prove ownership);
- social engineering that convinces a user to approve recovery;
- users with no passkey-capable authenticator or no recoverable email
  address.

## Passkeys

- Authentication starts with no email or username. Every caller receives
  the same discoverable challenge shape, and the server learns the user at
  finish time from the WebAuthn response.
- Registration forces resident/discoverable credentials so the
  username-less ceremony works for every passkey bauth creates.
- Ceremony state is persisted server-side and atomically removed on
  finish. A challenge cannot be replayed after a successful or failed
  consume path.
- WebAuthn verification is performed by `webauthn-rs`; signatures are
  bound to the configured relying-party ID and origin.
- Passkeys registered by recovery, or from a session still in recovery
  cool-down, store the active `recovery_cooldown_until` deadline.
- Authenticating with a cool-down-bound passkey before that deadline issues
  a restricted session; after the deadline, the same passkey is treated as
  unrestricted without any cleanup job. Pre-existing passkeys remain
  unrestricted.
- Passkey credential IDs are checked against the authenticated user before
  deletion, so one account cannot remove another account's credential by
  guessing an ID.

## Signup

`/auth/signup/request` returns the same response whether the address is new
or already registered. For a new address, bauth stores a single-use token
hash and sends a signup email. Consuming the token marks the email verified
and starts passkey registration. The session is issued only after
`/auth/signup/finish` successfully registers that passkey.

A leaked signup link cannot be redeemed as a recovery link because token
purposes are distinct.

## Recovery

Recovery exists for users who lost every passkey. It deliberately requires
the visitor to enrol a new visible passkey before any session is issued.

- `/auth/recovery/request` is enumeration-resistant. Registered addresses
  receive a recovery link and a separate recovery-requested notification
  email. Unknown addresses receive no email, because sending one would
  create an enumeration side channel.
- Recovery request rate limits default to 5/hour and 10/day per email,
  20/hour per IP, and no global ceiling unless the host configures one.
- Recovery tokens are single-use, short-lived, hashed at rest, and scoped
  only to starting a passkey registration ceremony.
- Expired-token clicks are audited but do not send another notification.
- `/auth/recovery/finish` registers the new passkey, sends
  passkey-registered and recovery-completed notifications, and issues a
  session with a default 24h cool-down.
- The recovery-created passkey stores the same cool-down deadline as the
  recovery-issued session. Authenticating with that passkey before the
  deadline creates another restricted session. Passkeys added from a
  restricted session inherit the active deadline. Pre-existing passkeys and
  pre-existing sessions remain unrestricted.

During the cool-down, bauth blocks actions that could lock out the
legitimate user: deleting passkeys, revoking other sessions, and
"sign out everywhere else". The session may still add another passkey and
may revoke or log out itself. Once the deadline has passed, checks treat
that cool-down as inactive; no cleanup job is required.

## Sessions

- Session tokens are 256 bits of OS-CSPRNG output, URL-safe base64
  encoded.
- Only SHA-256 token hashes are persisted.
- In-process token-hash equality is constant-time.
- Expiry is enforced server-side.
- Revocation is immediate because sessions are opaque server-side rows,
  not self-contained bearer claims.
- The Axum layer accepts either the HttpOnly cookie or an
  `Authorization: Bearer` token.

## CSRF and cookies

For browser cookie flows, keep the default CSRF layer enabled. When
`external_origin` is configured, mutating requests that carry the session
cookie must present a matching `Origin` header or, if `Origin` is absent, a
matching `Referer` origin.

Set session cookies with `HttpOnly`, `Secure` outside local HTTP
development, `SameSite=Lax`, and `Path=/` unless you intentionally scope
them tighter. Avoid a `Domain` attribute unless cross-subdomain sessions
are required.

Bearer-token clients are not in CSRF scope, but they must protect the raw
token as a credential.

## Audit and rate limiting

Security-significant events are emitted to `AuditSink`: signup request and
consume, recovery request/consume/failure, login success/failure,
credential add/remove, and session create/revoke/expire. Production hosts
should ship these events to durable, queryable storage.

Managers consult `RateLimiter` before sensitive request endpoints. The
built-in in-memory limiter is correct only inside one process; multi-node
deployments need a shared backend.

## Email transport

`TerminalEmailSender` and `FileEmailSender` are development transports.
They expose signup/recovery links and security notices locally and do not
deliver mail to users. Production hosts must implement `EmailSender` using
their email provider and operate SPF, DKIM, DMARC, bounce handling, and
provider-side abuse controls.

Link-delivery emails are hard failures: if bauth cannot send a signup or
recovery link for a valid request, the request fails. Security
notifications are best-effort after the protected action has already
succeeded; send failures are logged and do not roll back passkey or session
changes.

bauth sends security notifications for registered-user recovery requests,
completed recoveries, every successful passkey registration, passkey
removal, revoking another session, and "sign out everywhere else". It does
not send recovery mail for unknown addresses, signup mail for already
registered addresses, or security mail for ordinary self-logout.

## Operational hygiene

- Run SQL migrations before serving traffic.
- Periodically purge expired sessions, verification tokens, and passkey
  challenges.
- Index token-hash and user lookup columns in custom storage adapters.
- Monitor recovery volume, rate-limit hits, WebAuthn failures, and
  passkey deletions.
- Prompt users to register at least two passkeys.
- Treat email compromise as account compromise and make recovery activity
  visible in product UI and support workflows.

## Defaults

| Knob                       | Default                                            | Notes                                                                                                      |
| -------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Session lifetime           | 30 days                                            | Server-side revocable                                                                                      |
| Passkey challenge lifetime | 5 minutes                                          | Applies to registration and authentication ceremonies                                                      |
| Signup token lifetime      | 15 minutes                                         | Email link can only start first-passkey registration                                                       |
| Signup request limits      | 5/hour per IP, 3/hour per email                    | Enumeration-resistant response                                                                             |
| Recovery token lifetime    | 15 minutes                                         | Email link can only start recovery passkey registration                                                    |
| Recovery request limits    | 20/hour per IP, 5/hour per email, 10/day per email | Global ceiling off by default                                                                              |
| Recovery cool-down         | 24 hours                                           | Configurable, minimum 1 hour; bound to recovery-created/inherited passkeys and sessions until the deadline |
| Cookie `secure`            | `true`                                             | Disable only for local plain-HTTP development                                                              |

## Reporting vulnerabilities

Use the repository's private security-advisory workflow if available. If
not, contact the maintainers out of band before opening a public issue.
