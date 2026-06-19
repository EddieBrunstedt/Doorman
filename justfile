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
# running. Use the per-backend recipes below to run just one adapter.
test *args:
    cargo test --workspace --all-features --locked {{ args }}

# Run only the doorman-redis (redis + valkey) conformance suite.
test-redis *args:
    cargo test -p doorman-redis --all-features {{ args }}

# Run only the doorman-sqlx mysql + mariadb conformance tests.
test-mysql *args:
    cargo test -p doorman-sqlx --features mysql {{ args }}

# Run only the doorman-sqlx postgres conformance test.
test-postgres *args:
    cargo test -p doorman-sqlx --features postgres {{ args }}

# Run only the doorman-dynamodb conformance suite.
test-dynamodb *args:
    cargo test -p doorman-dynamodb {{ args }}

# Run only the doorman-mongodb conformance suite.
test-mongodb *args:
    cargo test -p doorman-mongodb {{ args }}

# Run only the doorman-redb conformance suite. redb is embedded (a local
# file), so this is the one backend suite that needs no Docker.
test-redb *args:
    cargo test -p doorman-redb {{ args }}

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

# Isolated feature builds CI runs (default build and one driver/backend at a
# time) to catch `#[cfg(feature)]` breaks the all-features clippy run hides.
check-features:
    cargo check --workspace --locked
    cargo check -p doorman-sqlx --features sqlite --locked
    cargo check -p doorman-sqlx --features postgres --locked
    cargo check -p doorman-sqlx --features mysql --locked
    cargo check -p doorman --features axum,sqlite --locked

# Keep `1.94` in sync with `rust-version` in the manifest. The check below uses
# the pinned 1.94.1 toolchain, which must be installed via rustup.
msrv:
    cargo +1.94.1 check --workspace --all-features --locked

# Cheap-first ordering: format, dprint, lint, docs, feature isolation, MSRV,
# then the container-backed test suite. The full local gate, mirroring CI.
verify: fmt-check dprint-check clippy doc check-features msrv test
