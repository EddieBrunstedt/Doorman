# Releasing

This document describes how bauth is versioned and how a release is cut.

## Versioning policy

bauth follows [Semantic Versioning](https://semver.org/). All crates in the
workspace share a single version (set once in `[workspace.package]`) and are
released together, so a given `bauth` version always pairs with the matching
`bauth-core`, `bauth-axum`, and `bauth-sqlx`.

While the version is `0.y.z` (pre-1.0):

- The public API is not yet stable. Breaking changes may land in a `0.(y+1).0`
  minor release and are always recorded under **Changed**/**Removed** in
  [`CHANGELOG.md`](CHANGELOG.md).
- `0.y.(z+1)` patch releases are reserved for backwards-compatible fixes.

After 1.0, normal SemVer applies: breaking changes require a major bump.

## Minimum supported Rust version (MSRV)

The MSRV is declared once as `rust-version` in `[workspace.package]` and is
enforced by a dedicated CI job. Raising the MSRV is a notable change: record it
in the changelog. Treat an MSRV bump as at least a minor version change.

## Release checklist

1. Ensure CI is green on the default branch (fmt, clippy, tests, SQLite +
   Postgres conformance, doc build, feature combinations, MSRV, `cargo-deny`).
2. Move the `[Unreleased]` section of [`CHANGELOG.md`](CHANGELOG.md) under a new
   version heading with the release date, and update the comparison links.
3. Bump `version` in `[workspace.package]` in the root `Cargo.toml`.
4. Run `cargo publish --dry-run` for each published crate to confirm packaging.
5. Commit (`chore(release): vX.Y.Z`) and tag (`vX.Y.Z`).
6. Publish the crates in dependency order: `bauth-core`, then `bauth-sqlx` and
   `bauth-axum`, then the `bauth` umbrella.
7. Push the tag.

The published crates are `bauth-core`, `bauth-axum`, `bauth-sqlx`, and `bauth`.
The `bauth-test-support` crate and the examples are marked `publish = false` and
are never released.
