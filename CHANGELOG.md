# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See [Versioning and MSRV](README.md#versioning-and-msrv) for the pre-1.0 semver policy and the minimum supported Rust version.

This file tracks the workspace as a whole; every published crate (`doorman`, `doorman-core`, `doorman-axum`, and the storage adapters) shares the workspace version and is released together.

## [Unreleased]

Initial development toward the first `0.1.0` release. Highlights:

### Added

- Passkey-only (WebAuthn) authentication for Axum: signup, login, recovery, and reauthentication ceremonies wired through `doorman-axum`'s `router()`.
- `doorman` umbrella crate re-exporting `doorman-core`, `doorman-axum`, and the storage adapters behind cargo features.
- Storage adapters: `doorman-sqlx` (Postgres, MySQL/MariaDB, SQLite), `doorman-redb`, `doorman-mongodb`, `doorman-dynamodb`, and `doorman-redis` (ephemeral session/token/challenge stores and rate limiting).
- Pluggable collaborators wired explicitly at build time: `Clock`, `AuditSink`, `EmailSender`, `RateLimiter`, `MetricSink`, and `SignupPolicy`.
- Always-on account recovery as the all-passkeys-lost escape hatch, with a configurable cool-down.
- `OperatorManager` backend-only administration API (disable/enable/delete, remove-passkey, revoke-sessions, list).
- Security controls: opaque single-use tokens hashed at rest, constant-time token comparison, redacted `Debug` for token-bearing types, fail-closed builder validation, CSRF same-origin checks, and configurable rate limits.
- Trusted client identity for Axum rate limits, sessions, and audit events: socket metadata or a host-supplied `ClientIp` extension, canonical IP addresses, ignored forwarding headers, and rejection when identity is missing. See [client identity and proxies](docs/integration.md#client-identity-and-proxies).
- Audit emission funneled through a single dispatch that always writes a `doorman::audit` tracing event alongside the `AuditSink`, so an audit trail exists even with `NoopAuditSink`.
- Background expiry purge via `Storage::purge_all_expired` and the `background-purge` feature's `spawn_purge_task`.
- Optional `MetricSink` signals: logins, auth failures, ceremony latency, and session-cache hit/miss.
- Documentation set under `docs/`, runnable `examples/`, and a backend-agnostic storage-conformance suite (`doorman-conformance`).

[Unreleased]: https://codeberg.org/EddieBrunstedt/Doorman/commits/branch/main
