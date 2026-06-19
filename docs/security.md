# Security

This page is doorman's security model and threat model. It describes the guarantees the library **actually implements** today — there are no aspirational claims here. If a paragraph says doorman does something, the code does it and a test guards it. Read [concepts.md](concepts.md) for the vocabulary.

For coordinated vulnerability disclosure and supported-version policy, see [`SECURITY.md`](../SECURITY.md).

## Supported surface

doorman has one steady-state login method: passkeys/WebAuthn using the discoverable-credential ceremony. Email is used only to start signup or recovery, and an email link never creates a session by itself.

Out of scope by design: password authentication, OAuth, TOTP, recovery codes, admin impersonation, roles/permissions, multi-tenancy, and general-purpose email login.

doorman does ship **operator flows** — library-level operations a host invokes to act on a user other than the acting one (delete an account, remove a passkey, revoke sessions, list a user's inventory). They perform **no authorization**: the host's authorization is the single load-bearing control in front of them, and the operator actor is recorded verbatim, never verified. See [operators.md](operators.md) for the host authorization patterns, the two-record audit pattern, and the operator threat model.

## Threat model

doorman is designed to defend against:

- **Phishing of steady-state logins**, by relying on origin-bound WebAuthn signatures — a credential only signs for its registered relying-party origin.
- **User enumeration** in signup, recovery, and passkey authentication: the response shape is identical for known and unknown addresses, including when the email transport fails. For signup and recovery a residual work-asymmetry remains (an unknown address provisions a user, stores a token, and triggers a send; a registered one silently no-ops), bounded by the request rate limits and addressable host-side — see [Email transport](#email-transport).
- **Immediate account lockout after email recovery**, by binding the post-recovery cool-down to recovery-created passkeys and sessions.
- **Replay** of session tokens, verification tokens, and passkey ceremony state from normal HTTP flows — ceremony state is single-use and removed on consume.
- **Database reads yielding usable bearer tokens**, because tokens are stored only as SHA-256 hashes.
- **CSRF** against cookie-authenticated state-changing endpoints.
- **Cloned authenticators**, by checking the WebAuthn signature counter for regression on each assertion.

doorman cannot defend against:

- a compromised host process;
- a database attacker with both read and write access;
- a compromised user email inbox exercising the recovery flow (the cool-down limits immediate lockout but cannot prove ownership);
- social engineering that convinces a user to approve recovery;
- users with no passkey-capable authenticator or no recoverable email address.

## Passkeys

- Authentication starts with no email or username. Every caller receives the same discoverable challenge shape, and the server learns the user at finish time from the WebAuthn response.
- Registration forces resident/discoverable credentials so the username-less ceremony works for every passkey doorman creates.
- Ceremony state is persisted server-side and atomically removed on finish. A challenge cannot be replayed after a successful or failed consume path.
- WebAuthn verification is performed by [`webauthn-rs`](https://crates.io/crates/webauthn-rs); signatures are bound to the configured relying-party ID and origin.
- **User-handle binding:** on discoverable authentication, doorman requires the authenticator to assert a user handle that parses to a known user and equals the credential's stored owner. A missing, malformed, or mismatched handle is rejected and no session is minted.
- **Counter regression:** the asserted signature counter is compared against the stored credential (regression detection inside `webauthn-rs`). A non-advancing counter is treated as a possible clone — the assertion is rejected with a security audit event. Authenticators that always report 0 are exempted, per the WebAuthn spec.
- **Failure auditing:** every authentication rejection emits an `AuthenticationFailed` audit event tagged with a reason (invalid/expired challenge, unknown credential, user-handle mismatch, counter regression, bad assertion). No secrets are included.
- Passkeys registered by recovery, or from a session still in recovery cool-down, store the active `recovery_cooldown_until` deadline.
- Authenticating with a cool-down-bound passkey before that deadline issues a restricted session; after the deadline the same passkey is treated as unrestricted with no cleanup job. Pre-existing passkeys remain unrestricted.
- Passkey credential IDs are checked against the authenticated user before deletion, so one account cannot remove another account's credential by guessing an ID.
- Outside a recovery cool-down, self-service removal may delete a user's **last** passkey. This is intentional: account recovery is the designed backstop for the "lost every passkey" case, so doorman does not block removing the final credential.

## Signup

`/auth/signup/request` returns the same response whether the address is new or already registered. For a new address, doorman stores a single-use token hash and sends a signup email. Consuming the token marks the email verified and starts passkey registration. The session is issued only after `/auth/signup/finish` successfully registers that passkey.

A leaked signup link cannot be redeemed as a recovery link: token purposes are distinct and re-checked at consumption.

## Recovery

Recovery exists for users who lost every passkey. It deliberately requires the visitor to enrol a new visible passkey before any session is issued.

- `/auth/recovery/request` is enumeration-resistant. Registered addresses receive a recovery link and a separate recovery-requested notification email. Unknown addresses receive no email, because sending one would create an enumeration side channel.
- Recovery tokens are single-use, short-lived, hashed at rest, and scoped only to starting a passkey registration ceremony.
- Expired-token clicks are audited but do not send another notification.
- `/auth/recovery/finish` registers the new passkey, sends passkey-registered and recovery-completed notifications, and issues a session with a default 24h cool-down.
- The recovery-created passkey stores the same cool-down deadline as the recovery-issued session. The deadline is stored absolutely (recovery-completion instant + cool-down) and never re-derived from a later `created_at`. Authenticating with that passkey before the deadline creates another restricted session. Passkeys added from a restricted session inherit the active deadline. Pre-existing passkeys and pre-existing sessions remain unrestricted.
- A passkey registration ceremony started _before_ recovery completed cannot be used to attach a credential that escapes the cool-down: recovery invalidates the user's other outstanding registration challenges on completion.

During the cool-down, doorman blocks actions that could lock out the legitimate user: deleting a passkey, revoking another session, "sign out everywhere else", requesting an account-email change, and deleting the account. The session may still add another passkey and may revoke or log out itself. These checks live in the core managers (`PasskeyManager`, `SessionManager`, `AccountManager`), not only in the bundled `doorman-axum` routes, so the guarantee holds for any transport that drives the managers with the acting session. The gate trusts the session it is handed: a transport must pass a session resolved from storage for the current request (as `doorman-axum` does), since the check reads the cool-down deadline off the supplied snapshot rather than re-reading the row. Once the deadline has passed, checks treat that cool-down as inactive; no cleanup job is required. The cool-down is evaluated through the configured `Clock`, so all entry points agree and tests can drive it deterministically.

The cool-down length is the host's to set. By default doorman rejects a configured value below a one-hour floor, because the cool-down is the only thing protecting a freshly-recovered account from an attacker who phished the link before the owner reacted — a near-zero value would silently defeat that property. A host that has weighed the trade-off can go below the floor (down to zero) by setting `RecoveryConfig::danger_allow_cooldown_below_floor`. The floor is not a cap on host control; it only forces the choice to be deliberate rather than accidental.

## Sessions

- Session tokens are 256 bits of OS-CSPRNG output, URL-safe base64 encoded.
- Only SHA-256 token hashes are persisted.
- In-process token-hash equality is constant-time (`subtle`).
- Expiry is enforced server-side.
- Revocation is immediate because sessions are opaque server-side rows, not self-contained bearer claims.
- The Axum layer accepts either the HttpOnly cookie or an `Authorization: Bearer` token, parsed through one shared bearer-token helper so the session and CSRF layers agree on what counts as bearer auth.

On the DynamoDB adapter, bulk revocation — "log out everywhere", "sign out everywhere else", account deletion, and recovery's other-session sweep — is best-effort under write-after-write. Those paths enumerate the user's sessions (and verification tokens and registration ceremonies) through an eventually-consistent `owner-index` GSI, so a row created moments before the revoke may not yet be visible to the GSI and can survive it; it is reclaimed on a later revoke or by the expiry purge / native TTL. Single-session revocation and expiry are unaffected. Hosts that need hard, immediate "revoke all" should prefer a SQL system-of-record for sessions (which deletes by the authoritative table in one statement), optionally paired with Redis for ephemerals.

## CSRF and cookies

For browser cookie flows, keep the default CSRF layer enabled. When `external_origin` is configured, mutating requests that carry the session cookie must present a matching `Origin` header or, if `Origin` is absent, a matching `Referer` origin. The check **fails closed**: an unsafe-method cookie request with neither header is rejected.

Set session cookies with `HttpOnly`, `Secure` outside local HTTP development, `SameSite=Lax`, and `Path=/` unless you intentionally scope them tighter. Avoid a `Domain` attribute unless cross-subdomain sessions are required. A `__Host-`/`__Secure-` cookie name is validated at build time to imply the matching `Secure`/path/domain attributes.

Bearer-token clients are not in CSRF scope, but they must protect the raw token as a credential.

## Audit and rate limiting

Security-significant events are emitted to `AuditSink`: signup request and consume, recovery request/consume/failure, login success/failure, credential add/remove, session create/revoke/expire, email-change request/complete, and account deletion. Production hosts should ship these events to durable, queryable storage; `NoopAuditSink` discards them.

Managers consult `RateLimiter` before sensitive endpoints, including the passkey authentication start/finish endpoints (per-IP and per-credential). The limiter key is structured (operation + ordered dimensions) so layered limits are expressible. The built-in in-memory limiter is correct only inside one process; multi-node deployments need a shared backend.

Configurable per-user resource caps are available (all opt-in): maximum active sessions (evicts oldest), maximum credentials, and maximum outstanding registration challenges (both reject at the limit rather than evicting, so a relied-on authenticator is never silently dropped).

## Email transport

`TerminalEmailSender` and `FileEmailSender` are development transports. They expose signup/recovery links and security notices locally and do not deliver mail to users. Production hosts must implement `EmailSender` using their email provider and operate SPF, DKIM, DMARC, bounce handling, and provider-side abuse controls.

Link-delivery emails are best-effort from the caller's perspective: signup, recovery, and recovery-requested sends all route through one best-effort helper, so a forced bounce on a _registered_ address cannot surface as a distinct error response — that parity is what closes the enumeration oracle. A residual work-asymmetry remains: signup and recovery do more work for an _unknown_ address than for a registered one. Signup inverts the usual shape — an unknown address provisions a new (unverified) user, stores a token, and triggers a send, while a registered address silently no-ops; recovery does the reverse, sending to a registered address and no-op-ing for an unknown one. Either way one branch performs store writes and a send that the other skips. This timing signal is bounded by the request rate limits (signup: 5/hour per IP, 3/hour per email; recovery: 20/hour per IP, 5/hour per email) and is a transport-layer concern the host can further address by decoupling delivery (queue/spawn) at its own layer; the runtime-agnostic core does not spawn.

Security notifications are best-effort after the protected action has already succeeded; send failures are logged and do not roll back passkey or session changes.

## Defaults

| Knob                                                    | Default                                                                 | Notes                                                          |
| ------------------------------------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------- |
| Session lifetime                                        | 30 days                                                                 | Server-side revocable                                          |
| Passkey challenge lifetime                              | 5 minutes                                                               | Registration and authentication ceremonies                     |
| Signup token lifetime                                   | 15 minutes                                                              | Email link can only start first-passkey registration           |
| Signup request limits                                   | 5/hour per IP, 3/hour per email                                         | Enumeration-resistant response                                 |
| Recovery token lifetime                                 | 15 minutes                                                              | Email link can only start recovery passkey registration        |
| Recovery request limits                                 | 20/hour per IP, 5/hour per email, 10/day per email                      | Global ceiling off by default                                  |
| Passkey auth limits                                     | 60/min start-per-IP, 60/min finish-per-IP, 30/min finish-per-credential | Charged before the challenge is consumed                       |
| Recovery cool-down                                      | 24 hours                                                                | Configurable; 1-hour floor unless the host opts out explicitly |
| Per-user caps (sessions/credentials/pending challenges) | off                                                                     | Opt-in; sessions evict oldest, the others reject at the limit  |
| Cookie `secure`                                         | `true`                                                                  | Disable only for local plain-HTTP development                  |

## Reporting a vulnerability

Coordinated disclosure and the supported-version policy live in [`SECURITY.md`](../SECURITY.md) at the repository root.
