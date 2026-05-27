# Security policy

This document covers the threat model `bauth` targets, the guarantees the
library makes, and the operational steps a host application must take.

## Threat model

`bauth` is designed to defend against:

- Account enumeration via timing or distinct error responses.
- Token theft from a database read: session and verification tokens are
  stored only as hashes.
- CSRF on cookie-authenticated state-changing endpoints.
- Session fixation.
- Replay of in-flight passkey, OAuth, or magic-link state.

It is not designed to defend against:

- A host process that is itself compromised.
- A database that is both readable and writable by the attacker.
- Social engineering or compromise of a user's email inbox.

## What the library guarantees

### Sessions

- Session tokens are 256 bits of OS-CSPRNG output, URL-safe base64
  encoded.
- Only the SHA-256 hash of the token is persisted.
- `TokenHash` equality is constant-time in process.
- Session expiry is enforced server-side.
- `revoke()` is immediate because sessions are server-side opaque rows,
  not self-contained bearer claims.

### Magic links

- Magic-link tokens are 256 bits of CSPRNG output; only the hash is
  stored.
- Tokens are single-use: `consume_token` atomically deletes the row
  before returning it.
- Tokens are namespaced by `VerificationPurpose`.
- Issuing a fresh magic link revokes earlier outstanding magic-link
  tokens for that user.
- `request_magic_link` returns success even when signup is disabled and
  the email is unknown, so the endpoint does not reveal which addresses
  are registered.
- A magic link is a bearer credential delivered to the user's inbox. If
  the inbox is compromised, the account can be taken over.

### Passkeys / WebAuthn

- Server-side ceremony state lives in `PasskeyChallengeStore` and is
  removed atomically on completion (`take_*` returns and deletes), so
  the same challenge cannot be replayed.
- Authentication enforces that the asserted credential belongs to the
  user bound to the ceremony.

### OAuth

- Authorization uses PKCE (S256). The verifier never leaves the server.
- The `state` value is 256 bits of CSPRNG output and doubles as the
  CSRF token round-tripped through the provider.
- Pending authorizations are removed atomically when consumed.
- `OAuthConfig::allow_email_linking` defaults to `false`. Enable it only
  when you intentionally trust the provider's `email_verified` claim.

### Rate limiting

- Managers consult a `RateLimiter` before sensitive request endpoints.
- The built-in `InMemoryRateLimiter` is accurate only for single-process
  deployments. Multi-replica deployments need a shared backend.
- Exceeding a policy returns `Error::RateLimited { retry_after }`.

### Audit log

- Security-significant events are emitted to `AuditSink`: session
  create/revoke/expire, login success/failure, credential add/remove,
  magic-link request/consume, and OAuth link/unlink.
- Login failure events include the submitted identifier for forensics.
  If your logging pipeline is sensitive to PII, filter in your sink.

## What the host must do

### Cookie flags

Set authentication cookies with:

- `HttpOnly`
- `Secure` outside local HTTP development
- `SameSite=Lax` for the session cookie
- `Path=/` unless you intentionally scope tighter
- no `Domain` unless cross-subdomain sessions are required

### CSRF on cookie-based endpoints

`bauth-axum` enables its `CsrfLayer` by default when
`external_origin` is configured. For any non-GET/HEAD/OPTIONS request
that carries the configured session cookie, the layer requires either an
`Origin` header matching the application origin or, when `Origin` is
absent, a matching `Referer` origin.

Requests authenticated with `Authorization: Bearer ...` are not in CSRF
scope. Disable the layer only for tests or known non-browser deployments.

### Storage-layer timing

Production adapters should index token-hash columns and look up by hash
equality. The library cannot enforce constant-time comparison inside a
DB, but a SHA-256 hash of a 256-bit random token is uniformly
distributed, so DB equality is not a practical timing leak.

### Email deliverability

`bauth` hands off to `EmailSender` and does not track bounces or
complaints. If you rely on email links, make sure your provider
authenticates outgoing mail (SPF, DKIM, DMARC), surfaces hard bounces,
and rate-limits delivery abuse.

### Operational hygiene

- Run `SessionManager::purge_expired`,
  `VerificationTokenStore::purge_expired`,
  `PasskeyChallengeStore::purge_expired`, and
  `OAuthStateStore::purge_expired` on a regular cadence.
- Treat the `AuditSink` as a security log. Ship it somewhere durable and
  queryable.
- Monitor auth-failure rates per source and per account. The library
  enforces per-policy caps, but anomaly detection above that is on you.

## Defaults we deliberately picked

| Knob | Default | Reason |
| ---- | ------- | ------ |
| Session lifetime | 30 days | Common UX expectation; revocable instantly |
| Magic-link lifetime | 15 minutes | The link itself is the credential |
| `allow_email_linking` (OAuth) | `false` | Do not trust third-party email claims by default |
| Magic-link requests per IP | 5 / 1h | Limits inbox-spam abuse |
| Magic-link requests per identifier | 3 / 1h | Limits targeted inbox-spam abuse |

Anything in this table can be overridden via the relevant `*Config`
struct.
