# doorman developer tasks. Run `just` (or `just --list`) to see them.
#
# The storage-conformance tests are self-contained: each starts its own
# throwaway database container via testcontainers, so the suite needs only a
# running Docker daemon — no compose services or *_URL env vars to set up.

# Show the recipe list.
default:
    @just --list

# Remove Cargo build artifacts.
clean:
    cargo clean

# Run the whole workspace test suite. This includes the storage-conformance
# tests, which start their own database containers, so a Docker daemon must be
# running. nextest runs the test binaries in parallel, so the containers start
# side by side rather than one after another. Needs cargo-nextest
# (`cargo install cargo-nextest --locked`). Use the per-backend recipes below to
# run just one adapter.
test *args:
    {{ nextest }} {{ args }}

nextest := "cargo nextest run --workspace --all-features --locked"

# The per-backend recipes filter the `test` run rather than build their crate
# alone, so they keep its flags and reuse its build.

# Run only the doorman-redis (redis + valkey) tests.
test-redis *args:
    {{ nextest }} -E 'package(doorman-redis)' {{ args }}

# Run only the doorman-sqlx postgres conformance test.
test-postgres *args:
    {{ nextest }} -E 'package(doorman-sqlx) & test(/^postgres::/)' {{ args }}

# Run only the doorman-sqlx mysql + mariadb conformance tests.
test-mysql *args:
    {{ nextest }} -E 'package(doorman-sqlx) & test(/^(mysql|mariadb)::/)' {{ args }}

# SQLite runs in memory, so this needs no Docker.
# Run only the doorman-sqlx sqlite tests.
test-sqlite *args:
    {{ nextest }} -E 'package(doorman-sqlx) & test(/^(sqlite|composability)::/)' {{ args }}

# Run only the doorman-mongodb tests.
test-mongodb *args:
    {{ nextest }} -E 'package(doorman-mongodb)' {{ args }}

# redb is embedded (a local file), so this needs no Docker.
# Run only the doorman-redb tests.
test-redb *args:
    {{ nextest }} -E 'package(doorman-redb)' {{ args }}

# Format the workspace.
fmt:
    cargo fmt --all

# Verify formatting without writing changes.
fmt-check:
    cargo fmt --all --check

# Check Markdown/TOML/YAML/JSON formatting (dprint), as CI does.
dprint-check:
    dprint check

# Type-check the whole workspace with all features.
check:
    cargo check --workspace --all-features --locked

# Lint with warnings denied.
clippy:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Build the docs with warnings denied.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

# Feature-combination builds, to catch `#[cfg(feature)]` breaks the all-features
# clippy run hides (a default build, a driver/backend enabled alone, two
# adapters pulling a shared dep at odds). The all-features run sees none of
# these. Needs cargo-hack (`cargo install cargo-hack`).
#
# `--depth 2` is the deliberate cut: the umbrella crate has 10 features, so a
# full powerset is 2^10 combinations, but feature-unification breaks surface
# pairwise (two adapters, or one adapter + a transport), and every pair is
# covered at depth 2 (66 combos) — a triple breaking when all its pairs build is
# vanishingly unlikely. doorman-sqlx has only three driver features, so it gets
# the full powerset for free.
#
# It builds into its own target directory, so `verify` can run it beside the
# test suite without either waiting on the other's build lock.
check-features:
    CARGO_TARGET_DIR={{ features_target }} cargo check --workspace --locked
    CARGO_TARGET_DIR={{ features_target }} cargo hack check -p doorman --feature-powerset --depth 2 --locked
    CARGO_TARGET_DIR={{ features_target }} cargo hack check -p doorman-sqlx --feature-powerset --locked

features_target := env("CARGO_TARGET_DIR", "target") / "check-features"

# Keep `1.99` in sync with `rust-version` in the manifest. The check below uses
# the pinned 1.99.0 toolchain, which must be installed via rustup.
msrv:
    cargo +1.99.0 check --workspace --all-features --locked

# Check dependencies against the advisory database and deny.toml's policy.
deny:
    cargo deny check

# Cheap-first ordering: format, dprint, lint, docs, MSRV, then the two slow
# steps side by side, since the feature-combination checks are CPU-bound while
# the test suite spends much of its time waiting on containers.
# `deny` stays out: it reads an advisory database that changes without any
# change here, so it could fail the gate for reasons unrelated to the change.
# The full local gate, running every check CI does except `deny`.
verify: fmt-check dprint-check clippy doc msrv slow-checks

[parallel]
[private]
slow-checks: check-features test
