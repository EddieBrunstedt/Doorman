# Security policy

This document covers the threat model `bauth` targets, the hardening
guarantees the library makes, and the additional steps a host
application is expected to take. It is intentionally specific — vague
"follow best practices" advice is not security policy.

## Threat model

`bauth` is designed to defend against:

- **Online credential guessing** — bots iterating common passwords
  against one or many accounts.
- **Account enumeration via timing or distinct error responses** — an
  attacker probing which emails are registered.
- **Token theft from database breach** — an attacker who reads the
  sessions or verification-token tables.
- **CSRF on cookie-authenticated state-changing endpoints** — once a
  host serves auth routes from a browser cookie.
- **Session fixation** — an attacker convincing a user to authenticate
  with a session id the attacker already knows.
- **Replay of in-flight ceremony state** — passkey or OAuth `state`
  values being submitted twice.

It is **not** designed to defend against:

- A host process that is itself compromised.
- A database that is read **and** writable by the attacker (they can
  just insert sessions).
- Offline brute-force of a stolen hash by an actor with unlimited
  compute — Argon2id raises the cost but does not eliminate it.
- Social engineering — phishing, account-recovery support escalation, etc.

## What the library guarantees

### Sessions

- Session tokens are 256 bits of OS-CSPRNG output, URL-safe base64
  encoded.
- Only the SHA-256 **hash** of the token is persisted. A database
  read does not yield usable tokens.
- `TokenHash` equality is constant-time
  (`subtle::ConstantTimeEq`), so any in-process comparison that
  short-circuits across bytes cannot leak the matched prefix length.
- Session expiry is enforced server-side. `validate()` returns
  `SessionExpired` and emits an audit event without producing a session.
- `revoke()` is immediate — no replication lag, no JWT clock skew —
  because sessions are looked up in the host's database every request.

### Passwords

- Hashing is Argon2id via the `argon2` crate's default parameters,
  targeting ~100ms on commodity hardware.
- Stored hashes are PHC strings so parameters can be upgraded later
  without breaking existing users.
- Verification returns a uniform `InvalidCredentials` whether the user
  is missing, has no password credential, or supplied a wrong password.
- `PasswordPolicy::validate` enforces a minimum length. Hosts that
  need entropy classes, dictionary checks, or breach-list lookups
  should layer those on top in their own registration handler.

### Email verification & password reset

- Verification tokens are 256 bits of CSPRNG output; only the hash is
  stored.
- Tokens are single-use — `consume_token` atomically deletes the row
  before returning it.
- Tokens are namespaced by `VerificationPurpose`, so a leaked
  password-reset link cannot be redeemed as an email-verification link
  or vice versa.
- Issuing a fresh token revokes earlier outstanding tokens of the same
  purpose for that user.
- `request_password_reset` returns success regardless of whether the
  email is registered, removing the obvious enumeration vector.

### Passkeys / WebAuthn

- Server-side ceremony state lives in `PasskeyChallengeStore` and is
  removed atomically on completion (`take_*` returns and deletes), so
  the same challenge cannot be replayed.
- Authentication enforces that the asserted credential's `user_id`
  matches the user who started the ceremony when the start was
  username-first — closing "use any registered passkey to log in as
  anyone" when the UX collects an email up front.

### OAuth

- Authorization uses PKCE (S256). The verifier never leaves the
  server.
- The `state` value is 256 bits of CSPRNG output and doubles as the
  CSRF token round-tripped through the provider.
- Pending authorizations are removed atomically when consumed.
- `OAuthConfig::allow_email_linking` defaults to `false`. With it off,
  a provider returning an email that matches an existing account is
  rejected with `OAuthEmailTaken` — the user must sign in via the
  existing method to link explicitly.

### Rate limiting

- `PasswordAuthManager` consults a `RateLimiter` before login, password
  reset request, and verification-email re-issue. Defaults cap a
  single IP and a single account independently.
- The built-in `InMemoryRateLimiter` is sliding-window-log per
  `(key, window)` and accurate for single-process deployments. For
  multi-replica deployments, swap in a shared backend (Redis-backed
  implementations are out of scope for v1 but the trait is stable).
- Exceeding a policy returns `Error::RateLimited { retry_after }`.

### Audit log

- Every meaningful auth event is emitted to `AuditSink`: session
  create/revoke/expire, login success/failure (with reason),
  credential add/remove, password change, password reset request and
  completion, email verification, magic link request/consume.
- Login failure events include the **submitted identifier** (raw
  email) for forensics. If your logging pipeline is sensitive to PII,
  filter on the `AuditSink` side.

## What the host must do

### Cookie flags (when serving sessions via cookie)

Set every authentication cookie with:

- `HttpOnly` — JavaScript cannot read it
- `Secure` — never sent over plaintext HTTP
- `SameSite=Lax` for the session cookie (works with normal navigations
  and OAuth redirects)
- `SameSite=Strict` for short-lived state cookies you control
  end-to-end (e.g. an OAuth state cookie if you stash one)
- `Path=/` (or scoped tighter if you split the app)
- `Domain` only if you actually need cross-subdomain sessions; otherwise
  leave it unset
- A real cookie name prefix (`__Host-`) when domain isn't set

### CSRF on cookie-based endpoints

Browsers will attach a `SameSite=Lax` cookie to top-level navigations,
which is enough to protect most password and passkey flows. State-
changing endpoints that accept JSON from the same origin should still
verify either:

- A custom request header (e.g. `X-CSRF-Token`) that scripts must
  read from a non-HttpOnly cookie or page-embedded token, **or**
- The `Origin`/`Referer` matches your application origin.

`SameSite=Lax` is **not** enough by itself against GET-triggered side
effects — keep state changes to POST/PATCH/DELETE.

### Storage-layer timing

The library's in-memory adapters look sessions and verification tokens
up by hash. Production adapters should do the same — index the token
hash column and look up by equality. The library cannot enforce
constant-time comparison inside your DB, but a SHA-256 hash of a 256-bit
random token is uniformly distributed, so byte-by-byte equality at the
DB layer is not a practical timing leak.

### Email deliverability

`bauth` hands off to `EmailSender` and doesn't track bounces or
complaints. If you rely on email for password reset or verification,
make sure your provider:

- Authenticates outgoing mail (SPF, DKIM, DMARC)
- Surfaces hard bounces so you can disable affected accounts
- Rate-limits delivery so a compromised account cannot be used to
  bombard a third party (the `verification_email_per_user` policy
  already caps this from inside the library)

### Key rotation

The library has no symmetric key to rotate — sessions are random tokens,
not JWTs. If a future version adds a JWT-based session store, this
section will grow.

### Operational hygiene

- Run `SessionManager::purge_expired`, `VerificationTokenStore::
  purge_expired`, `PasskeyChallengeStore::purge_expired`, and
  `OAuthStateStore::purge_expired` on a regular cadence (e.g. once a
  minute). Expired rows are still rejected if read, but pruning keeps
  the tables small.
- Treat the `AuditSink` as a security log. Ship it somewhere durable
  and queryable.
- Monitor login-failure rates per source and per account. The library
  enforces per-policy caps, but anomaly detection above that is on you.

## Defaults we deliberately picked

| Knob | Default | Reason |
| ---- | ------- | ------ |
| Session lifetime | 30 days | Common UX expectation; revocable instantly |
| Password minimum length | 12 chars | OWASP minimum |
| Password reset link lifetime | 1 hour | Short enough to limit forwarded-link abuse |
| Email verification link lifetime | 24 hours | Long enough for slow inboxes |
| `require_email_verification` | `false` | Some apps want frictionless signup; opt in when ready |
| `revoke_sessions_on_password_reset` | `true` | Reset implies credential compromise |
| `allow_email_linking` (OAuth) | `false` | Don't trust third-party "email verified" by default |
| `login_per_ip` | 20 / 60s | Allows a human typo; defeats a single-IP bot |
| `login_per_identifier` | 10 / 15m | Defeats credential stuffing against one account |
| `password_reset_per_identifier` | 3 / 1h | Limits inbox-spam abuse |

Anything in this table can be overridden via the relevant `*Config`
struct.
