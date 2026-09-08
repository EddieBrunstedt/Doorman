//! **Passkey-only authentication for Rust web apps.** doorman gives an [Axum](https://github.com/tokio-rs/axum) application a single, modern way to log in — discoverable passkeys (WebAuthn) — backed by email links that exist only to onboard and recover accounts.
//!
//! There are no passwords, no OAuth providers, no TOTP codes, and no general-purpose "email me a login link". Every account is anchored to one or more passkeys; email is used only to prove control of an address during signup, account recovery, and email changes.
//!
//! > doorman is pre-1.0. The public API is in good shape but breaking changes can still land before 1.0.
//!
//! ## Why passkey-only?
//!
//! Passwords are the root of most account-security problems: reuse, phishing, leaks, and the endless reset machinery built to paper over them. Passkeys are phishing-resistant by construction (the credential is bound to your site's origin) and need no shared secret on the server.
//!
//! doorman commits to that model fully instead of bolting passkeys onto a password system:
//!
//! - **One way in.** Returning users authenticate with a discoverable passkey — no username, no password, no second factor to juggle.
//! - **Email is a recovery channel, not a login.** A signup or recovery link only ever _starts a passkey registration_; it never issues a session by itself. A leaked email link cannot, on its own, log anyone in.
//! - **Lost-device recovery without a help desk.** Users recover through a verified email link that enrolls a fresh passkey, gated by a cool-down that disables destructive actions while a recovery is fresh.
//!
//! ## How it works
//!
//! doorman ships the server half of three WebAuthn ceremonies plus account management, wired into ready-to-mount Axum routes:
//!
//! | Flow        | What the user does                                                                  | What doorman does                                                                                                                   |
//! | ----------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
//! | **Sign up** | Enters an email, clicks the emailed link, registers a passkey                       | Mails a single-use link → the link starts passkey registration → on finish, registers the first passkey and _then_ issues a session |
//! | **Sign in** | Picks a passkey in the browser prompt                                               | Identifies the user from the WebAuthn response — no email or username needed (discoverable credentials)                             |
//! | **Recover** | Enters an email, clicks the link, registers a new passkey                           | Mails a recovery link → the link enrolls a fresh passkey → issues a session restricted by a post-recovery cool-down                 |
//! | **Manage**  | Lists/adds/removes passkeys, lists/revokes sessions, changes email, deletes account | Enforces the cool-down on destructive actions and sends security-notification emails                                                |
//!
//! Sessions are **server-side and opaque**: the cookie (or bearer token) is a random handle to a row doorman owns, so revocation is instant and there is no token to forge or decode.
//!
//! ## Quickstart
//!
//! ```toml
//! [dependencies]
//! doorman = { git = "https://codeberg.org/EddieBrunstedt/Doorman", features = ["axum", "sqlite"] }
//! axum = "0.8"
//! tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
//! ```
//!
//! `doorman` is an **umbrella crate**: one dependency, one version to bump. It re-exports the framework-agnostic core, the Axum integration, and the storage adapters behind features (`doorman::core`, `doorman::axum`, `doorman::sqlx`, `doorman::redis`, …). The `prelude` pulls in everything a typical host needs in one line.
//!
//! ```rust,no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//!
//! use axum::{routing::get, Router};
//! use doorman::prelude::*;
//! use doorman::core::memory::InMemoryRateLimiter;
//! use doorman::core::verification::TOKEN_PLACEHOLDER;
//! use url::Url;
//!
//! // 1. Open storage and run migrations.
//! let storage = SqliteStorage::connect("sqlite:///var/lib/app/auth.db?mode=rwc").await?;
//! storage.migrate().await?; // applies pending embedded migrations; idempotent, safe on every boot
//!
//! // 2. Build the auth service.
//! let origin: Url = "https://app.example.com".parse()?;
//! let base = origin.as_str().trim_end_matches('/');
//! let auth = AuthService::builder(storage.all_stores())
//!     .email(Arc::new(TerminalEmailSender)) // dev transport; swap for production
//!     .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
//!     .audit(Arc::new(NoopAuditSink)) // discards events; wire a durable sink in prod
//!     .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock)))) // per-process; share a backend across replicas
//!     .signup(SignupConfig {
//!         url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"),
//!         ..Default::default()
//!     })
//!     .recovery(RecoveryConfig {
//!         url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"),
//!         ..Default::default()
//!     })
//!     .account(AccountConfig {
//!         url_template: format!("{base}/account/email?token={TOKEN_PLACEHOLDER}"),
//!         ..Default::default()
//!     })
//!     .reauthentication(ReauthPolicy::required_for([ // required decision; or ReauthPolicy::disabled()
//!         ReauthAction::DeleteAccount,
//!         ReauthAction::RemovePasskey,
//!     ]))
//!     .external_origin(origin) // enables CSRF origin checks; required CSRF decision
//!     .cookie(CookieConfig::default())
//!     .build()?;
//!
//! // 3. Mount the routes and the session middleware.
//! let app = Router::new()
//!     .merge(auth.router()) // all /auth/* endpoints
//!     .route("/api/me", get(me)) // your own handlers
//!     .layer(auth.session_layer()); // resolves the session for extractors
//!
//! // 4. Supply socket identity for rate limits and session/audit metadata.
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//! axum::serve(
//!     listener,
//!     app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
//! ).await?;
//! # Ok(())
//! # }
//! #
//! # async fn me(_user: doorman::prelude::AuthUser) -> String {
//! #     String::new()
//! # }
//! ```
//!
//! `auth.router()` mounts every endpoint under `/auth`. `auth.session_layer()` resolves the session cookie or bearer token on each request so your handlers can use the extractors:
//!
//! ```rust,no_run
//! use doorman::prelude::*;
//!
//! // Requires a valid session — returns 401 otherwise.
//! async fn me(user: AuthUser) -> String {
//!     format!("hello, {}", user.0.id)
//! }
//!
//! // Present whether or not the request is authenticated.
//! async fn maybe(user: OptionalAuthUser) { /* ... */ }
//!
//! // The full session context (user + session + recovery cool-down state).
//! async fn whoami(auth: AuthSession) { /* ... */ }
//! ```
//!
//! Forwarding headers are ignored. Behind a proxy, use trusted host middleware to insert `ClientIp`; see [client identity](https://codeberg.org/EddieBrunstedt/Doorman/src/branch/main/docs/integration.md#client-identity-and-proxies). Requests requiring identity return `500 internal_error` when neither `ClientIp` nor socket metadata is present.
//!
//! `TerminalEmailSender` prints emails to stdout for local development. In production, implement `EmailSender` for your transactional email provider and keep `CookieConfig { secure: true, .. }`.
//!
//! ### Run the example app
//!
//! ```sh
//! cargo run -p doorman-minimal-app
//! ```
//!
//! Open <http://localhost:3000>. Signup and recovery emails are printed to the terminal — copy the link from stdout and finish the flow in the browser. The example uses SQLite, the bundled router, and a single static HTML page with no frontend build step.
//!
//! ## Cargo features
//!
//! `doorman` bundles every crate behind a feature flag; enable only what you wire up.
//!
//! - `axum` — the Axum HTTP integration (the supported user-facing surface), exposed at `doorman::axum`.
//! - **Storage adapters** — `sqlite`, `postgres`, `mysql`, `redis` (with its `valkey` alias), `dynamodb`, `mongodb`, `redb`; choose one per store, and mix backends if you like.
//! - `file-email` — bundled `.eml` file email transport for local development.
//! - `purge-runner` — the generic one-shot purge runner (`doorman::ops::run_purge`) for hosts that sweep expired rows from an external scheduler.

// Every public item in this crate carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test/bench helpers.
#![deny(missing_docs)]
// Lock in rustdoc quality alongside the coverage above: broken intra-doc links,
// malformed code blocks, bare URLs, and the rest of the rustdoc lint group warn
// here and become hard errors under the `-D warnings` doc gate.
#![warn(rustdoc::all)]

/// Framework-agnostic authentication primitives. Always available.
pub use doorman_core as core;

/// One-shot operational entrypoints for external schedulers — currently the
/// generic [`run_purge`](ops::run_purge) sweeper. Requires the `purge-runner`
/// feature.
#[cfg(feature = "purge-runner")]
pub mod ops;

/// Axum HTTP integration. Requires the `axum` feature.
#[cfg(feature = "axum")]
pub use doorman_axum as axum;

/// SQLx storage adapters. Requires the `sqlite` or `postgres` feature.
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub use doorman_sqlx as sqlx;

/// Redis/Valkey adapter. Requires the `redis` (or `valkey`) feature.
#[cfg(feature = "redis")]
pub use doorman_redis as redis;

/// Amazon DynamoDB adapter. Requires the `dynamodb` feature.
#[cfg(feature = "dynamodb")]
pub use doorman_dynamodb as dynamodb;

/// MongoDB adapter. Requires the `mongodb` feature.
#[cfg(feature = "mongodb")]
pub use doorman_mongodb as mongodb;

/// redb embedded key-value adapter. Requires the `redb` feature.
#[cfg(feature = "redb")]
pub use doorman_redb as redb;

/// One-line import for hosts wiring doorman into their app.
///
/// Re-exports the most complete prelude available — `doorman_axum::prelude`
/// when the `axum` feature is enabled (it already folds in the core
/// prelude), or [`doorman_core::prelude`] otherwise — plus the storage
/// adapter types for every enabled storage feature (sqlx, redis, dynamodb,
/// mongodb, redb).
pub mod prelude {
    #[cfg(feature = "axum")]
    pub use doorman_axum::prelude::*;

    #[cfg(not(feature = "axum"))]
    pub use doorman_core::prelude::*;

    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    pub use doorman_sqlx::*;

    #[cfg(feature = "redis")]
    pub use doorman_redis::*;

    #[cfg(feature = "dynamodb")]
    pub use doorman_dynamodb::*;

    #[cfg(feature = "mongodb")]
    pub use doorman_mongodb::*;

    #[cfg(feature = "redb")]
    pub use doorman_redb::*;
}
