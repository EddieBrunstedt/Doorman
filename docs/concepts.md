# Concepts

This page explains the auth model doorman implements and the vocabulary the rest of the documentation uses. Read it once; the [flows](flows.md), [security](security.md), [integration](integration.md), and [operations](operations.md) pages build on it.

## The auth model in one paragraph

doorman gives an application exactly one steady-state way to log in: a **discoverable passkey** (WebAuthn). Email exists only to bootstrap an account (signup) or to re-enrol after losing every passkey (recovery), and an email link never creates a session by itself — it can only start a passkey registration ceremony. There are no passwords, no OAuth providers, no TOTP codes, and no general-purpose "magic link" login.

## Why passkey-only

A password is a shared secret the server must store and the user must remember; it is phishable and reusable. A passkey is an origin-bound public-key credential: the private key never leaves the authenticator, the signature is bound to the relying-party origin, and there is no secret on the server to leak. Restricting steady-state login to passkeys removes the most common account-takeover vectors (credential stuffing, password phishing, reused passwords) at the cost of requiring every user to hold a passkey-capable authenticator and a recoverable email address. doorman makes that trade deliberately; see [security.md](security.md) for what it does and does not defend.

## Discoverable credentials

doorman uses the **discoverable** (resident, "username-less") WebAuthn ceremony. Authentication starts with no email and no username: the server issues a challenge, the browser shows the user whichever passkeys it holds for the origin, and the server learns _which_ user signed in from the user handle in the WebAuthn response. This is what lets the login endpoint be enumeration-free — every caller gets the same challenge shape — and why registration forces resident credentials.

## Sessions are opaque server-side rows

A successful passkey assertion mints a **session**: a row in the session store keyed by a 256-bit random token. The client holds the token (in an HttpOnly cookie or as a bearer token); the server holds only its SHA-256 hash. Because the session is a server-side row and not a self-contained signed claim:

- revocation is immediate — deleting the row ends the session on the next request, with no token-expiry window to wait out;
- the token in the database is a hash, so a database read does not yield a usable bearer credential;
- token comparison on the hot path is constant-time.

This is the opposite trade from a stateless JWT: doorman pays a storage read per request (mitigated by the session cache) to buy instant revocation and hash-at-rest tokens.

## Opaque verification tokens

Signup, recovery, and email-change links carry an **opaque verification token** — the same 256-bit random / SHA-256-at-rest scheme as sessions, but single-use and short-lived. Each token is bound to a **purpose** (`Signup`, `Recovery`, `EmailChange`) at mint time _and_ re-checked at consumption, so a leaked signup link cannot be redeemed on the recovery endpoint or vice versa.

## Recovery cool-down

Recovery is the one flow where someone holding only the user's email can mint a new passkey. To bound the damage of a compromised inbox, a recovery-issued session — and the passkey enrolled during recovery — carry a **cool-down deadline** (`recovery_cooldown_until`, default 24h). Until that deadline, doorman blocks the actions that would let an attacker lock the real owner out: deleting passkeys, revoking other sessions, and "sign out everywhere else". The session may still add a passkey and may log itself out. After the deadline the same passkey and session are treated as unrestricted with no cleanup job — the check is a timestamp comparison, not a background sweep. See [flows.md](flows.md) and [security.md](security.md).

## The trait seams

doorman-core is framework-agnostic. It defines the behaviour as **managers** (`SessionManager`, `PasskeyManager`, `SignupManager`, `RecoveryManager`, `AccountManager`) that depend on a small set of host-provided **traits**:

| Trait                                                                                                    | Responsibility                                      |
| -------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `UserStore`, `SessionStore`, `VerificationTokenStore`, `PasskeyCredentialStore`, `PasskeyChallengeStore` | Persistence. Bundled together as `Storage`.         |
| `EmailSender`                                                                                            | Deliver signup/recovery links and security notices. |
| `AuditSink`                                                                                              | Receive security-significant events.                |
| `RateLimiter`                                                                                            | Throttle sensitive endpoints.                       |
| `Clock`                                                                                                  | Supply "now" (real or mocked in tests).             |

`doorman-sqlx` implements the five storage traits for SQLite and Postgres. `doorman-axum` wires the managers behind an HTTP router, extractors, a session layer, and a CSRF layer. See [integration.md](integration.md) for how to plug in your own implementations.

## Single tenant

doorman models one application ("relying party"). There is no built-in concept of tenants, organisations, roles, or per-application credential scoping; a user is global to the deployment. Multi-tenancy is intentionally out of scope — host it above doorman (one deployment or schema per tenant) if you need it. See [operations.md](operations.md#single-tenant-assumption).
