# Operations

Running doorman in production: purging expired rows, configuration, rate limiting, observability, customizing user-facing copy, and the single-tenant assumption. See [security.md](security.md) for the threat model and [integration.md](integration.md) for wiring.

## Production checklist

`AuthCore::builder(..).build()` and `AuthService::builder(core).build()` are strict by default and fail closed (`AssemblyError` / `BuilderError`) until each required input is wired — there are no silent insecure defaults to remember to override. Make a deliberate choice for each:

- Replace `TerminalEmailSender` / `FileEmailSender` with a real `EmailSender`.
- Wire a durable `AuditSink`, or pass `NoopAuditSink` explicitly to discard security events.
- Wire a shared `RateLimiter`; `InMemoryRateLimiter` is per-process only, and `NoopRateLimiter` disables enforcement.
- Set `external_origin` to the exact public origin (enables the CSRF layer for browser cookie flows), or opt out with `CsrfConfig::disabled()`.
- Set real signup / recovery / account URL templates; the stock `example.invalid` placeholders are rejected.
- Keep secure, HttpOnly, SameSite session cookies outside local HTTP dev.
- Run storage migrations before serving traffic.
- Purge expired rows on a schedule (below).
- Monitor recovery activity, passkey add/remove, high-risk session revocations, and failed WebAuthn ceremonies.
- Prompt users with `passkey_count < 2` to add a backup passkey.

## Purging expired rows

Sessions, verification tokens, and passkey ceremony challenges expire by timestamp. Expiry is enforced on read, but the dead rows still accumulate — purge them. User and credential rows never expire and are untouched.

One call sweeps all three time-limited stores:

```rust
use chrono::Utc;

let summary = storage.purge_all_expired(Utc::now()).await?;
tracing::info!(
    sessions = summary.sessions,
    verification_tokens = summary.verification_tokens,
    passkey_challenges = summary.passkey_challenges,
    "purged expired rows",
);
```

For a background sweeper, enable the `background-purge` feature on `doorman-core` and spawn the bundled task — it sweeps on an interval (first sweep immediate), logs per-pass counts, and continues past a store error:

```rust
// requires doorman-core feature "background-purge"
use std::time::Duration;
doorman_core::purge::spawn_purge_task(storage.clone(), clock, Duration::from_secs(3600));
```

The default build does not pull this in, keeping the dependency surface lean.

### External schedulers (serverless, CronJob)

The in-process sweeper assumes a long-lived process. On a frozen or short-lived host — serverless / FaaS, scale-to-zero containers, a Kubernetes `CronJob` — its tokio timer never fires reliably, so those hosts run the purge as a **separate, short-lived process** driven by an external scheduler (cron, AWS EventBridge, a `CronJob`).

Enable the `purge-runner` feature on `doorman` and call `doorman::ops::run_purge` from a tiny host-owned binary. The runner is backend-blind: it parses two optional flags (`--now <rfc3339>`, `--json`), sweeps via `purge_all_expired`, prints the per-store `PurgeSummary`, and sets the process exit code (non-zero on a malformed flag or a store error, so a scheduler treats a failed sweep as a failed job).

```rust
// requires the `doorman` feature "purge-runner"
// bins/purge/src/main.rs — the host's whole purge binary
#[tokio::main]
async fn main() -> std::process::ExitCode {
    let storage = app::build_storage().await; // the SAME builder the server uses
    doorman::ops::run_purge(storage).await
}
```

doorman ships only this backend-blind runner — never a ready-made binary. A Rust binary is a leaf of the dependency graph, so doorman cannot ship one generic over a backend it does not know; the backend-aware `main` must live in the crate that knows the backend (yours). The payoff is that adding a new storage backend costs zero purge work: the runner is generic over `Storage`, and your existing storage builder already produces one.

**Single source of truth.** Put the storage construction in one shared function (`build_storage()`) that **both** the server and the purge binary call, so the two processes read the same database from the same environment:

```
myapp/
├── crates/app/   # shared lib — owns build_storage() ONCE
├── bins/server/  # main: app::build_storage() -> AuthCore::builder(..) -> AuthService::builder(core)
└── bins/purge/   # main: app::build_storage() -> doorman::ops::run_purge(storage)
```

(For a simple app this collapses to one crate with `src/lib.rs` + `src/bin/server.rs` + `src/bin/purge.rs`. See `examples/purge` for the runnable layout.)

**Watch for silent misconfiguration.** Each networked backend has one value that must match the running app — the DynamoDB table, the MongoDB database name, the Redis key prefix. Point the purge process at the wrong one and it sweeps an empty namespace, reports `0`, and looks like a clean success. The shared `build_storage()` is the defence: it removes the second config site entirely, so there is nowhere for the purge job to drift from the app. The runner still prints the counts on every run — including a zero sweep — so a genuine empty result is visible rather than mistaken for success.

The SQLx adapters ship `expires_at` indexes on the sessions, verification-token, and passkey-challenge tables, so the purge and the on-read expiry filters stay cheap as tables grow.

The Redis/Valkey adapter (`doorman-redis`) sets a per-key TTL, so the server evicts the value keys on its own. `purge_all_expired` still has work to do there: it reclaims the user-scoped secondary-index members that a TTL eviction leaves dangling (Redis sets have no per-member TTL). Keep calling it — or run the background sweeper — so those indexes stay bounded for users who never return.

## Configuration

All tunables flow through the builder configs; see the defaults table in [security.md](security.md#defaults). The values most deployments touch:

- **Session lifetime** (`SessionConfig`) — default 30 days; the cookie max-age derives from it so the two cannot drift.
- **Recovery cool-down** (`RecoveryConfig`) — default 24h, minimum 1h.
- **Cookie attributes** (`CookieConfig`) — keep `secure = true` outside local HTTP; `__Host-`/`__Secure-` names are validated at build time.
- **Per-user caps** (`SessionConfig` / `PasskeyConfig`) — opt-in maximums for active sessions (evicts oldest), credentials, and pending registration challenges (both reject at the limit).

## Rate limiting

Managers consult the `RateLimiter` before sensitive endpoints: signup request, recovery request, and passkey authentication start/finish (keyed per-IP and per-credential). The limiter key is structured — an operation plus ordered `(dimension, value)` pairs — so a single-string backend can flatten it via `RateLimitKey::canonical()` while a structured backend reads the dimensions directly.

The bundled `InMemoryRateLimiter` is correct only within one process. A multi-node deployment must supply a shared backend, or the limits are per-instance and trivially bypassed by spreading requests across instances. The first-party `doorman-redis` adapter provides one — a cross-replica sliding-window limiter wired with `AuthCore::builder(storage).limiter(redis.rate_limiter())`. Hosts on another stack implement `RateLimiter` themselves.

To put a host-side bot check (CAPTCHA, allow/deny lists) in front of signup, add it as Axum middleware on the signup route before it reaches doorman — doorman does not ship a CAPTCHA hook.

## Observability

Two seams:

- **`AuditSink`** receives security-significant events (signup, recovery, login success/failure, credential add/remove, session create/revoke/expire, email change, account deletion). Ship them to durable, queryable storage and alert on recovery volume, WebAuthn failures, and passkey deletions.
- **`MetricSink`** is a counter/timing hook for the hot paths; the default is `NoopMetricSink`. Implement it to feed Prometheus/StatsD.

The session-resolution cache is internal; `AuthService::cache()` exposes a handle mainly for tests and inspection.

## Customizing user-facing messages

doorman returns **machine error codes**, not end-user prose — the HTTP error body carries a stable `code` (see `crates/axum/src/error.rs`). The client maps those codes to human guidance; the bundled example client (`examples/web-client`) demonstrates a jargon-to-guidance mapping you can adapt. Branding the **emails** is separate and lives in `EmailTemplates` — see [integration.md](integration.md#custom-email-and-branding).

## `.eml` output growth

`FileEmailSender` (the `file-email` feature) writes one `.eml` per sent email into its directory and never prunes them. It is a development transport only — in a long-running dev session the directory grows unbounded. Point it at a scratch directory and clear it periodically; do not use it in production.

## Single-tenant assumption

doorman models exactly one relying party / application. There is no built-in tenant, organisation, or per-application credential scoping — a user and their passkeys are global to the deployment. If you need multi-tenancy, host it _above_ doorman: run one deployment (or one database/schema) per tenant and route to the right instance. Sharing one doorman deployment across tenants would let a passkey registered for one tenant authenticate against another, which the single-relying-party WebAuthn model does not partition. Multi-tenancy is intentionally out of scope for the 1.0 charter.
