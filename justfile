# doorman developer tasks. Run `just` (or `just --list`) to see them.
#
# The storage-conformance tests are self-contained: each starts its own
# throwaway database container via testcontainers, so the suite needs only a
# running Docker daemon — no compose services or *_URL env vars to set up.

# Show the recipe list.
default:
    @just --list

# Run the minimal-app example (examples/minimal-app). Extra args pass through
# to the binary.
minimal-app *args:
    cargo run -p doorman-minimal-app {{ args }}

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
    cargo nextest run --workspace --all-features --locked {{ args }}

# Run only the doorman-redis (redis + valkey) conformance suite.
test-redis *args:
    cargo nextest run -p doorman-redis --all-features {{ args }}

# Run only the doorman-sqlx mysql + mariadb conformance tests.
test-mysql *args:
    cargo nextest run -p doorman-sqlx --features mysql {{ args }}

# Run only the doorman-sqlx postgres conformance test.
test-postgres *args:
    cargo nextest run -p doorman-sqlx --features postgres {{ args }}

# Run only the doorman-dynamodb conformance suite.
test-dynamodb *args:
    cargo nextest run -p doorman-dynamodb {{ args }}

# Run only the doorman-mongodb conformance suite.
test-mongodb *args:
    cargo nextest run -p doorman-mongodb {{ args }}

# Run only the doorman-redb conformance suite. redb is embedded (a local
# file), so this is the one backend suite that needs no Docker.
test-redb *args:
    cargo nextest run -p doorman-redb {{ args }}

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
    cargo check --workspace --all-features

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
# `--depth 2` is the deliberate cut: the umbrella crate has 11 features, so a
# full powerset is 2^11 combinations, but feature-unification breaks surface
# pairwise (two adapters, or one adapter + a transport), and every pair is
# covered at depth 2 (78 combos) — a triple breaking when all its pairs build is
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

# Cheap-first ordering: format, dprint, lint, docs, MSRV, then the two slow
# steps side by side, since the feature-combination checks are CPU-bound while
# the test suite spends much of its time waiting on containers.
# The full local gate, running the same checks as CI.
verify: fmt-check dprint-check clippy doc msrv slow-checks

[parallel]
[private]
slow-checks: check-features test
