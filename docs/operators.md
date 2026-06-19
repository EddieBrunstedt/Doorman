# Operator flows

This page covers **operator flows**: manager-level operations that let a host act on a user _other_ than the acting one — delete an account, remove a passkey, revoke sessions, or list a user's passkeys/sessions on behalf of a support agent, admin panel, CLI, or backend job. Everything else in doorman is **self-service** (the manager methods act on the acting user's own session); operator flows target a user by `UserId` instead. Read [concepts.md](concepts.md) for the vocabulary and [security.md](security.md) for the steady-state threat model.

The flows live on `OperatorManager`, reached through the deliberate `operator()` accessor on the Axum state (or constructed directly in `doorman-core`). They are **library-level only** — see [No HTTP routes](#no-http-routes).

## The one rule: doorman performs no authorization

**Operator flows perform no authorization check. The host's authorization is the single load-bearing control in front of every operator call.** This is not a formality or a defence-in-depth layer — it is the _only_ gate.

The self-service surface has several independent brakes: the recovery cool-down, per-endpoint rate limits, and an implicit ownership binding (a self-service action can only ever target `session.user_id`). The operator surface has **none of them**. There is no cool-down, no rate limit, and no per-request ownership binding — an operator flow names its target by id and acts. That is intended (doorman _can_ authenticate end users via passkeys but _cannot_ authenticate operators — operator identity is established outside doorman, in SSO/IAM/mTLS/an internal panel), but it means a missing or buggy host authorization check raises the blast radius from "one user harms themselves" to "one caller harms any user."

Because the flows live behind a distinct accessor that a handler must hold in scope, the boundary is visible in the type system: a route that never reaches for `operator()` cannot invoke an operator flow. That keeps an existing, lightly-authenticated route from accidentally calling one, but it does not authorize anything — the host still owns the decision.

## Two principals, kept separate

Every operator action involves two distinct identities. Conflating them is the main thing to avoid.

| Role                 | Meaning                             | Relationship to doorman                                                                                |
| -------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **Subject / target** | The user being acted _on_.          | Always a doorman user — identified by doorman's `UserId`.                                              |
| **Operator / actor** | Whoever is _performing_ the action. | **Not necessarily a doorman user.** An opaque, host-supplied `OperatorActor` recorded for attribution. |

The subject is always resolved against the `UserStore` before anything is mutated or read; a missing or typo'd target fails loudly (`UserNotFound` / `PasskeyNotFound` / `SessionNotFound`) rather than silently succeeding for a cascade that affected nothing. For the row-scoped flows (remove a specific passkey, revoke a specific session) the resolved row's owner must also equal the named target, so an action named against user X handed an id belonging to user Y mutates nothing and mis-attributes nothing.

## Host authorization patterns

doorman's `UserId` is a stable, public join key (a random UUIDv4, not a sequential counter, so exposing it creates no enumeration oracle). Whatever role data a host already has references users by `UserId`, or is independent of doorman entirely. **doorman's `UserStore` is never extended for operator authorization** — any host role storage lives in the host's own schema.

Most hosts need **no new storage** at all. From lightest to heaviest:

- **Static config allowlist.** A set of operator identities (emails, SSO subjects, service-account names) in config or an environment variable. The handler checks membership before calling the flow. No storage, no schema.
- **SSO / IdP claim.** The operator authenticates through your identity provider and the request carries a role/group claim (a JWT scope, an OIDC group, an mTLS client identity). The handler reads the claim and decides. No doorman storage.
- **Network / infrastructure boundary, or a CLI.** The operator surface is only reachable from an internal admin network, a bastion, or a CLI run with production credentials; reachability _is_ the authorization. No doorman storage.
- **Host-owned roles table.** A table in the host's schema mapping `UserId` (or an operator identity) to roles/permissions. This is the **heaviest and least common** option — reach for it only when you genuinely need fine-grained, data-driven roles. Even then the table is the host's, keyed by `UserId`; doorman's stores are untouched.

## The two-record audit pattern

Every operator action produces **two** records that a postmortem correlates:

1. **The host's authorization log** — written by the host _before_ it calls the flow, recording the authorization decision (who, what role check, what request). This is where the operator's verified identity and the policy decision live.
2. **doorman's audit event** — emitted by the flow itself, carrying the structured `Actor::Operator(..)` with the operator's asserted id.

Tie the two together with `OperatorActor::correlation_id`: set it to the id of the host's authorization-log entry, and doorman stamps it onto the audit event verbatim. A reader can then pivot from "doorman recorded operator X deleted account Y" to "here is the host's authorization decision that authorized it."

Operator events are distinguishable from self-service ones in the same stream. The audit `Actor` is a typed enum — `Actor::Subject { ip, user_agent }` for a self-service action doorman verified via the session, versus `Actor::Operator(OperatorActor)` for a host-asserted operator action. The `ip` / `user_agent` live _inside_ the actor, so the subject's and the operator's network metadata can never be misread for one another. Operator **reads** are audited too (`OperatorListedPasskeys` / `OperatorListedSessions`): inspecting another user's inventory is privacy-sensitive, so "who looked" lands in the same stream as "who changed what." Self-service reads stay unaudited.

## The actor is recorded verbatim, never verified

`OperatorActor::id` (and `correlation_id`) are **host-supplied, stored verbatim, and never verified.** For an operator action, doorman is a **witness to an assertion, not a verifier of one.** That makes the actor descriptor **untrusted input** wherever a host derives it from anything a user can influence (an email, a display name, an SSO claim). Three obligations follow for the host:

- **Neutralize on render.** A verbatim string with newlines or control characters can forge extra log lines or field separators once the audit row is rendered to text or shipped to a log processor. doorman stores the value unmodified (fidelity), so neutralization is the consumer's job — escape or strip control characters when you render it.
- **Keep it in the structured audit field.** Never pre-interpolate the actor id into a log line. Carry it as the structured `OperatorActor` field and let the consumer decide how to display it.
- **Cap its size.** A free-form value is an audit-store bloat / cost vector. doorman's `OperatorActor::new` already rejects an id or correlation id over `OperatorActor::MAX_FIELD_LEN` (1024 bytes); keep your own derivation well under that.

## Threat model

Operator auditing provides **accountability of legitimate operators**, not **defense against a compromised host.** Anyone able to invoke an operator flow can also assert any actor id — or write to the database directly. The audit line answers "which of our trusted operators did this?" for a postmortem; it does **not** prove a breached process didn't forge it. State this plainly so nobody over-trusts the operator audit line: the field has zero evidentiary weight against a caller who lies, including a compromised host process.

The strongest available attribution is the optional case where the operator is **also a doorman-authenticated user** who signed in with their own passkey. There the host adds only the role decision on top of a doorman-verified identity, rather than asserting an unverified string. This sits alongside the existing limits in [security.md](security.md#threat-model): doorman cannot defend against a compromised host process or a database attacker with read and write access, and the operator surface is no exception.

## Known limitations

These are properties an operator flow inherits from the cascade it reuses, not bugs. A host wiring operator flows must understand them.

### Leaky lockout — "remove all passkeys" is not a durable disable

There is **no "last passkey" guard**: an operator can remove every one of a user's passkeys, which is a _de-facto_ account lockout. But it is a **leaky** one — **recovery re-enrolls past it.** A user who still controls their recoverable email can run the recovery flow, enrol a new passkey, and regain access. Removing all passkeys is a useful soft-suspend primitive, but it is **not** a durable disable. A reversible, recovery-proof disable is a separate, later feature (it needs a user-state field that does not exist today); do not treat "remove all passkeys" as one.

### Staleness window — an operator revoke is not an instant global kill-switch

The session-resolution cache is **process-local**. An operator revoke (or delete) fires the invalidation hook on the replica that handled the call, evicting _that replica's_ cache — but in a multi-replica deployment the other replicas keep serving the target from their warm cache until each entry ages out at the configured TTL (default **60s**, `DEFAULT_CACHE_TTL`). So there is a per-replica window of up to one TTL where the target's existing sessions still resolve.

For self-service this is fine (a user logging themselves out tolerates a few seconds). For an operator locking out a **compromised or abusive** account the expectation is immediate, global lockout — which doorman cannot promise across processes. A host that needs hard immediacy (incident response) should **shorten the cache TTL** or **front the session store with a shared cache**, so the eviction is observed everywhere at once. doorman states the window rather than imply a guarantee it cannot make.

### Non-atomicity — "deleted" is not atomically or instantaneously global

The delete cascade spans five independent stores (sessions, credentials, verification tokens, registration ceremonies, the user row) with **no cross-store transaction** — the storage traits are per-concern. The operator delete reuses the same ordered cascade as self-service (sessions first, so no request resolves a half-deleted account; user row last, so a mid-cascade failure never orphans the parent), and closes the easy orphan window: the registration-finish path re-checks that the user still exists before adding a credential, and the operator delete re-sweeps pending ceremonies _after_ removing the user row.

What remains is a **narrow check-then-`add_passkey` TOCTOU** and the general absence of a cross-store transaction. A host must not assume "deleted" means "atomically and instantaneously gone." Mitigations are host-level: the cascade revokes sessions first, cutting an attacker's authenticated foothold before the rest runs, and any residual orphaned credential rows are inert (session resolution still does `find_user_by_id`, so no login can be minted against a missing user) and reclaimed out of band on a later sweep.

## No HTTP routes

doorman ships **no operator HTTP router** — mounted or unmounted. There is no type-level way to force a host's authorization middleware in front of an Axum `Router`, so shipping one would hand hosts a footgun that undercuts the type-level boundary the `operator()` accessor establishes. Hosts wire their own routes — or CLI / job entry points — with their own authorization in front, then call the flow:

```rust,ignore
use doorman::core::audit::OperatorActor;

async fn delete_user_route(
    state: AuthState,
    operator_identity: VerifiedOperator, // your extractor: verified + authorized
    Path(target): Path<UserId>,
) -> Result<StatusCode, AppError> {
    // The host's authorization decision happens HERE, before the flow call,
    // and is written to the host's own authorization log.
    let authz_record_id = audit_authz(&operator_identity, "delete_account", target);

    let actor = OperatorActor::new(
        operator_identity.id().to_string(), // verbatim, capped at MAX_FIELD_LEN
        Some(authz_record_id),              // correlation_id ties the two records
        operator_identity.ip(),
        operator_identity.user_agent(),
    )?;

    state.operator().delete_account(target, actor).await?;
    Ok(StatusCode::NO_CONTENT)
}
```

## The flow set

| Flow                                           | Audited as                              | Subject notice (default)                                               |
| ---------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------- |
| `delete_account(target, actor)`                | `AccountDeleted` (operator-actored)     | None — the mailbox owner is gone, regardless of policy                 |
| `remove_passkey(target, credential_id, actor)` | passkey-removal kind carrying the actor | **Sent** (operator-aware copy) — `NotificationPolicy::passkey_removed` |
| `revoke_all_sessions(target, actor)`           | `OperatorRevokedAllSessions`            | **Suppressed** — `NotificationPolicy::sessions_revoked` (opt-in)       |
| `revoke_session(target, session_id, actor)`    | session-revoke kind carrying the actor  | None                                                                   |
| `list_passkeys(target, actor)`                 | `OperatorListedPasskeys`                | n/a (read)                                                             |
| `list_sessions(target, actor)`                 | `OperatorListedSessions`                | n/a (read)                                                             |

Notices never use the self-service "was this you?" copy — that copy tells a user a legitimate admin action was a possible compromise. Operator notices use **operator-aware copy** ("an administrator removed a passkey from your account") instead, and the send-vs-suppress choice is a `NotificationPolicy` chosen once when the `OperatorManager` is constructed, not a per-call flag. The defaults are deliberately asymmetric: `passkey_removed` defaults to **`Send`** (self-service passkey removal already notifies, so the operator path keeps that transparency), while `sessions_revoked` defaults to **`Suppress`** (the underlying revoke-all primitive is silent today, so an operator notice there is a _new_ outbound email that ships opt-in). Listing flows project to `PasskeySummary` / `SessionSummary`, which omit the credential blob and the session `token_hash` respectively, so no secret-equivalent material crosses into an operator view.
</content>
</invoke>
