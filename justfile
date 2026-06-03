# doorman developer tasks. Run `just` (or `just --list`) to see them.
#
# The Redis/Valkey URLs are exported into every recipe's environment, so
# `just test` and friends pick up the live servers started by `just up`.
# Override on the command line if your servers live elsewhere, e.g.
#   just test REDIS_URL=redis://other:6379

export REDIS_URL := env_var_or_default("REDIS_URL", "redis://127.0.0.1:6379")
export VALKEY_URL := env_var_or_default("VALKEY_URL", "redis://127.0.0.1:6380")

# Show the recipe list.
default:
    @just --list

# Start the local Redis + Valkey containers and wait until they are healthy.
up:
    docker compose up -d --wait

# Stop and remove the local Redis + Valkey containers.
down:
    docker compose down

# Follow the container logs.
logs:
    docker compose logs -f

# Open a redis-cli inside the Redis container.
redis-cli *args:
    docker compose exec redis redis-cli {{ args }}

# Open a valkey-cli inside the Valkey container.
valkey-cli *args:
    docker compose exec valkey valkey-cli {{ args }}

# Run the whole workspace test suite (Redis/Valkey URLs preset).
test *args:
    cargo test --workspace --all-features {{ args }}

# Run only the doorman-redis suite against the live servers.
test-redis *args:
    cargo test -p doorman-redis --all-features {{ args }}

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
