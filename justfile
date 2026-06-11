# doorman developer tasks. Run `just` (or `just --list`) to see them.
#
# The storage-conformance tests are self-contained: each starts its own
# throwaway database container via testcontainers, so the suite needs only a
# running Docker daemon — no compose services or *_URL env vars to set up.

# Show the recipe list.
default:
    @just --list

# Run the whole workspace test suite. This includes the storage-conformance
# tests, which start their own database containers, so a Docker daemon must be
# running. Use the per-backend recipes below to run just one adapter.
test *args:
    cargo test --workspace --all-features {{ args }}

# Run only the doorman-redis (redis + valkey) conformance suite.
test-redis *args:
    cargo test -p doorman-redis --all-features {{ args }}

# Run only the doorman-sqlx mysql + mariadb conformance tests.
test-mysql *args:
    cargo test -p doorman-sqlx --features mysql {{ args }}

# Run only the doorman-sqlx postgres conformance test.
test-postgres *args:
    cargo test -p doorman-sqlx --features postgres {{ args }}

# Format the workspace.
fmt:
    cargo fmt --all

# Verify formatting without writing changes.
fmt-check:
    cargo fmt --all --check

# Type-check the whole workspace with all features.
check:
    cargo check --workspace --all-features

# Lint with warnings denied.
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Build the docs with warnings denied.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# The full local gate, mirroring CI: format, lint, docs, tests.
verify: fmt-check clippy doc test
