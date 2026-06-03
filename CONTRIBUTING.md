# Contributing to bauth

Thanks for your interest. bauth is an opinionated, passkey-only authentication
library for Axum. This guide covers how to build, test, and submit changes.

For the auth model and what the library does, start with the
[README](README.md) and [`docs/`](docs). For the security model and how to
report a vulnerability, see [SECURITY.md](SECURITY.md) — **do not** open a
public issue for an unfixed security bug.

## Prerequisites

- A recent stable Rust toolchain. The workspace MSRV is declared as
  `rust-version` in the root `Cargo.toml`; build with that or newer.
- `rustfmt` and `clippy` components (`rustup component add rustfmt clippy`).
- No external services are needed for the default test suite. The Postgres
  storage tests are opt-in (see below).

## Workspace layout

```
crates/core/   framework-agnostic managers, storage/email/audit/rate-limit traits
crates/axum/   Axum router, extractors, session layer, CSRF layer, high-level builder
crates/sqlx/   SQLite/Postgres storage adapter (one feature per backend)
crates/bauth/  umbrella crate re-exporting the above behind features
examples/      runnable minimal-app and the web-client reference
docs/          the layered documentation tree
```

## Build, test, format

```sh
cargo build                                   # build the workspace
cargo test --workspace                        # run the default test suite
cargo test -p bauth-sqlx --features sqlite    # SQLite storage conformance (in-memory)
cargo fmt                                      # format (run before committing)
cargo clippy --workspace --all-targets        # lints (the workspace denies clippy::all)
cargo doc --no-deps --workspace               # build the API docs
```

The lib crates set `#![deny(missing_docs)]`, so every new public item needs
rustdoc. `unsafe` is forbidden workspace-wide.

### Postgres storage tests

The Postgres conformance suite runs only when `PG_URL` points at a disposable
database (it wipes the `public` schema first):

```sh
PG_URL=postgres://postgres:postgres@localhost/bauth_test \
  cargo test -p bauth-sqlx --features postgres
```

The shared conformance suite (`crates/sqlx/tests/conformance`) is the
executable contract for any storage adapter; run it against both dialects when
you touch storage.

## Running the example

```sh
cargo run -p bauth-minimal-app
```

Open <http://localhost:3000>. It uses `TerminalEmailSender`, so signup and
recovery links are printed to the process stdout — copy one into the browser to
finish a flow. The example is origin-portable: see its
[README](examples/minimal-app/README.md) for the `EXTERNAL_ORIGIN`,
`PASSKEY_RP_ID`, and other environment knobs.

## Coding conventions

These mirror [AGENTS.md](AGENTS.md) / [CLAUDE.md](CLAUDE.md), which automated
contributors also follow:

- **No `unsafe`.** It is forbidden workspace-wide.
- **No `unwrap`.** `expect` and `assert!`/`assert_eq!` are fine where an unmet
  expectation should crash; prefer returning a typed error otherwise.
- **Keep changes focused.** Avoid unrelated refactors unless asked.
- **Tests track behaviour.** After any non-docs change, add/revise/remove tests
  to match and run the relevant suite before considering it done. Do not weaken
  a test to get a green run.
- **Document behaviour changes.** Update rustdoc, `docs/`, and comments when you
  change behaviour, commands, or assumptions.
- **Don't preserve backward compatibility** unless explicitly requested — bauth
  is pre-1.0 and optimises for the best 1.0 surface.

## Commits and pull requests

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `<type>(optional-scope): <description>`. Common types: `feat`, `fix`, `docs`,
  `style`, `refactor`, `test`, `build`, `ci`, `chore`. Example:
  `fix(cli): handle missing config file`.
- No emojis in commits, issues, or PR comments.
- Before opening a PR: `cargo fmt`, `cargo clippy --workspace --all-targets`,
  and `cargo test --workspace` should all pass.
- Describe what changed and why; link any relevant issue.

## License

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed under [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT) (the
project's license), without any additional terms or conditions.
