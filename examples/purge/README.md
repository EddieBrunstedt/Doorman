# doorman purge example

A reference layout for hosts that purge expired rows from an **external scheduler** (cron, AWS EventBridge, a Kubernetes `CronJob`) instead of the in-process `background-purge` task. That is the path for a frozen or short-lived host — serverless / FaaS, scale-to-zero containers — where an in-process tokio timer never fires reliably.

## The pattern

One crate, one shared storage builder, two binaries:

```
examples/purge/
├── src/lib.rs          # build_storage() — the single source of truth
└── src/bin/
    ├── server.rs       # main: app::build_storage() -> AuthCore::builder(..) -> AuthService::builder(core)
    └── purge.rs        # main: app::build_storage() -> doorman::ops::run_purge(storage)
```

Both binaries construct their storage through the same `build_storage()`, so they read the same database from the same environment and their configuration **cannot drift**. That is what makes a host-owned purge job safe: a misconfiguration would have to be made in the one place both processes share, not re-entered on every purge invocation where it could silently sweep the wrong namespace and report a clean zero.

doorman ships the backend-blind half — the `doorman::ops::run_purge` runner (behind the `purge-runner` feature). The host ships the backend-aware half — the five-line `purge.rs` that hands the runner its own storage. A Rust binary is a leaf of the dependency graph, so doorman cannot ship a binary generic over a backend it does not know; the backend-aware `main` must live in the host's crate. Adding a different backend costs zero purge work: swap the `sqlite` feature and the body of `build_storage`, and nothing else changes.

This example targets SQLite so it runs with no external services — the point is the shared-builder pattern, not the backend. (A SQLite host is itself a long-lived box that would normally just use the in-process sweeper; the external pattern is really for the networked stores.)

## Run

Start the server (writes a few rows you can later purge):

```sh
cargo run -p doorman-purge-example --bin server
```

Run the purge job — a separate, short-lived process:

```sh
cargo run -p doorman-purge-example --bin purge
cargo run -p doorman-purge-example --bin purge -- --json
cargo run -p doorman-purge-example --bin purge -- --now 2026-01-01T00:00:00Z
```

The runner prints the per-store counts on every run — including a zero sweep — so a misconfigured invocation is visible rather than looking like success. It exits non-zero if a flag is malformed or a store errors, so a scheduler treats a failed sweep as a failed job.

## Flags

| Flag              | Default | Purpose                                                       |
| ----------------- | ------- | ------------------------------------------------------------- |
| `--now <rfc3339>` | now     | The sweep instant; rows with `expires_at <= now` are removed. |
| `--json`          | off     | Emit the summary as one JSON line instead of a text block.    |

## Environment

| Variable          | Default                                      | Purpose                                          |
| ----------------- | -------------------------------------------- | ------------------------------------------------ |
| `DATABASE_URL`    | `sqlite://doorman-purge-example.db?mode=rwc` | SQLite database URL — read by **both** binaries. |
| `EXTERNAL_ORIGIN` | `http://localhost:3000`                      | Public origin (server only).                     |
| `BIND_ADDR`       | `127.0.0.1:3000`                             | Socket address to bind (server only).            |
