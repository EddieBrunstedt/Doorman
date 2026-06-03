# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0 (`0.y.z`), the public API may change between minor
versions; breaking changes are called out under **Changed**/**Removed**.

## [Unreleased]

### Added

- `file-email` cargo feature gating the bundled `FileEmailSender` (`.eml` file
  transport). It is the only thing in `bauth-core`'s default build that needs
  `tokio`'s filesystem support, so the default build now pulls no `tokio` at all.
  `bauth-axum` and the `bauth` umbrella expose passthrough `file-email` features.
- Publishable package metadata (`keywords`, `categories`, `documentation`,
  `homepage`) and `docs.rs` all-features rendering across the published crates.
- `LICENSE` (MIT), `CHANGELOG.md`, `RELEASING.md`, and a `cargo-deny`
  configuration (`deny.toml`).
- Continuous integration (Forgejo Actions): formatting, clippy, the test
  matrix, SQLite + Postgres storage conformance, doc build, feature-combination
  builds, an MSRV check, and a `cargo-deny` advisory/license scan.
- Workspace lints: `unsafe_code` is forbidden and `clippy::all` is denied across
  every crate. `missing_docs` is staged per published library (currently
  allowed; flipped to denied by the documentation rewrite).

### Changed

- License is now `MIT` (previously the dual `MIT OR Apache-2.0`).
- `bauth-core`'s `tokio` dependency is optional; enable `file-email` or
  `background-purge` to pull it in.

## [0.1.0] - Unreleased

Initial development release. Passkey-only authentication for Axum: discoverable
WebAuthn login, email-gated signup and recovery, server-side opaque sessions
with instant revocation, a passkey-bound post-recovery cool-down, security
notification emails, CSRF origin checks, audit and rate-limiter traits, and
first-party SQLx storage for SQLite and Postgres.

[Unreleased]: https://codeberg.org/EddieBrunstedt/bauth/compare/v0.1.0...HEAD
[0.1.0]: https://codeberg.org/EddieBrunstedt/bauth/releases/tag/v0.1.0
