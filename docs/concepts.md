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

## Session lifetime: absolute cap and idle timeout

A session is governed by two configurable bounds (`SessionConfig`):

- **`absolute_lifetime`** — a hard cap measured from `created_at`. The session dies here no matter how active it is (default 30 days).
- **`idle_timeout`** — an optional idle window. `None` (the default) means pure absolute expiry: the deadline never moves. `Some(d)` makes the session expire `d` after its **last use**, sliding the deadline forward on each use.

The **effective expiry** is the earlier of the two: `min(created_at + absolute_lifetime, last_used_at + idle_timeout)`. The crucial design choice is that `Session.expires_at` stores this already-`min`'d effective deadline rather than the raw absolute cap. On each use the session is touched and `expires_at` is rewritten to the new `min(...)`, capped at the absolute lifetime so a slide never extends a session past its hard limit. `last_used_at` is recorded alongside as the legible "last active" field. Because `expires_at` already carries the idle deadline, validation stays a single comparison (`now >= expires_at`) and the existing absolute-expiry purge reclaims idle-dead rows unchanged — there is no separate idle sweep.

Sliding happens in `SessionResolver::resolve`, the one operation a front end runs per request. Touch writes are throttled so an active session writes at most once per cache-TTL window rather than on every request, and with `idle_timeout = None` there are no touch writes at all — the behaviour is byte-for-byte the fixed-lifetime path.

When a request slides the deadline, `resolve` reports it and `doorman-axum` refreshes the session cookie's `Max-Age` so a browser client's local expiry tracks the server's slid deadline. Bearer-token clients track expiry themselves and get no cookie refresh.

### Build-time invariants

When `idle_timeout` is `Some(d)`, the builder fails closed at `build()` time (rather than misbehaving at runtime) unless all of the following hold:

- `d` is non-zero and `<= MAX_LIFETIME` (the same bound the absolute lifetime is held to);
- `d <= absolute_lifetime` — the idle window cannot outlive the hard cap;
- `cache.ttl < d` — a **liveness** requirement, enforced by `SessionResolver::new`. Touches fire only on a cache miss, and misses only occur after a cached entry ages past the cache TTL. If `ttl >= idle_timeout`, a continuously-active user is served by cache hits (which never touch) right up to the idle deadline, so the session idles out in storage with no touch ever sliding it and the active user is logged out. Sliding only works when a miss-driven touch can fire before the idle deadline. A comfortable margin (e.g. `ttl <= d / 2`) is recommended.

### The cache re-checks expiry on hit

The session-resolution cache holds a short-TTL snapshot of the resolved session and short-circuits storage on a hit. To keep this correct under both absolute and idle expiry, the cache-hit path re-checks the snapshot's `expires_at` against the clock in memory: a hit whose effective deadline has already passed is treated as a miss and dropped, so an expired session is never served from a still-warm entry independent of the cache TTL. This is a free in-memory comparison and protects the **security** property (an expired session is never served); the **liveness** property (an active session staying alive) is what the `cache.ttl < idle_timeout` invariant above guarantees.

## Opaque verification tokens

Signup, recovery, and email-change links carry an **opaque verification token** — the same 256-bit random / SHA-256-at-rest scheme as sessions, but single-use and short-lived. Each token is bound to a **purpose** (`Signup`, `Recovery`, `EmailChange`) at mint time _and_ re-checked at consumption, so a leaked signup link cannot be redeemed on the recovery endpoint or vice versa.

## Recovery cool-down

Recovery is the one flow where someone holding only the user's email can mint a new passkey. To bound the damage of a compromised inbox, a recovery-issued session — and the passkey enrolled during recovery — carry a **cool-down deadline** (`recovery_cooldown_until`, default 24h). Until that deadline, doorman blocks the actions that would let an attacker lock the real owner out: deleting passkeys, revoking other sessions, and "sign out everywhere else". The session may still add a passkey and may log itself out. After the deadline the same passkey and session are treated as unrestricted with no cleanup job — the check is a timestamp comparison, not a background sweep. See [flows.md](flows.md) and [security.md](security.md).

## The trait seams

doorman-core is framework-agnostic. It defines the behaviour as **managers** (`SessionManager`, `PasskeyManager`, `SignupManager`, `RecoveryManager`, `AccountManager`) that depend on a small set of host-provided **traits**:

| Trait                                                                                                    | Responsibility                                                                         |
| -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `UserStore`, `SessionStore`, `VerificationTokenStore`, `PasskeyCredentialStore`, `PasskeyChallengeStore` | Persistence. Bundled together as `Storage`.                                            |
| `EmailSender`                                                                                            | Deliver signup/recovery links and security notices.                                    |
| `AuditSink`                                                                                              | Receive security-significant events.                                                   |
| `RateLimiter`                                                                                            | Throttle sensitive endpoints.                                                          |
| `Clock`                                                                                                  | Supply "now" (real or mocked in tests).                                                |
| `SignupPolicy`                                                                                           | Gate whether a signup attempt may proceed (allowlist / invite-only). Defaults to open. |

First-party adapters implement the five storage traits: `doorman-sqlx` (SQLite, Postgres, MySQL/MariaDB), `doorman-dynamodb`, `doorman-mongodb`, `doorman-redb`, and `doorman-redis` (ephemeral stores only). `doorman-axum` wires the managers behind an HTTP router, extractors, and a session layer that also runs the CSRF origin check. See [integration.md](integration.md) for how to plug in your own implementations.

## Single tenant

doorman models one application ("relying party"). There is no built-in concept of tenants, organisations, roles, or per-application credential scoping; a user is global to the deployment. Multi-tenancy is intentionally out of scope — host it above doorman (one deployment or schema per tenant) if you need it. See [operations.md](operations.md#single-tenant-assumption).
