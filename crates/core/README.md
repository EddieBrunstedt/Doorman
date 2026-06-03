# doorman-core

Framework-agnostic core of [doorman](../../README.md): the auth-flow managers (`SessionManager`, `PasskeyManager`, `SignupManager`, `RecoveryManager`, `AccountManager`) plus the host-provided trait seams they depend on — storage (`UserStore`, `SessionStore`, `VerificationTokenStore`, `PasskeyCredentialStore`, `PasskeyChallengeStore`), `EmailSender`, `AuditSink`, `RateLimiter`, and `Clock`.

This crate stays HTTP-framework-free so the auth logic can be tested and reasoned about without a router attached. Most hosts depend on the [`doorman`](../doorman) umbrella or [`doorman-axum`](../axum) rather than this crate directly; reach for `doorman-core` when implementing a custom storage adapter or a non-Axum HTTP surface.

- Concepts and the trait seams: [`docs/concepts.md`](../../docs/concepts.md)
- Custom stores: [`docs/integration.md`](../../docs/integration.md)
- Background expiry purge lives behind the `background-purge` feature.

API reference: `cargo doc -p doorman-core --open`.
