# doorman-axum

Axum HTTP integration for [doorman](../../README.md): the `AuthService` router, session-loading layer, `AuthUser` / `OptionalAuthUser` / `AuthSession` extractors, CSRF layer, and the high-level `AuthServiceBuilder` that wires [`doorman-core`](../core)'s managers from sensible defaults.

This is the supported user-facing integration. Hand `AuthService::builder` a `Storage` value (e.g. from [`doorman-sqlx`](../sqlx)), configure the relying party and email transport, mount `auth.router()`, and apply `auth.session_layer()`.

```rust,ignore
let auth = AuthService::builder(storage.storage())
    .email(Arc::new(TerminalEmailSender))
    .passkey(PasskeyConfig::from_origin(origin.clone(), "Example")?)
    .signup(SignupConfig { url_template, ..Default::default() })
    .recovery(RecoveryConfig { url_template, ..Default::default() })
    .external_origin(origin)
    .build()?;
let app = Router::new().merge(auth.router()).layer(auth.session_layer());
```

- Wiring, stores, branding: [`docs/integration.md`](../../docs/integration.md)
- Routes and flows: [`docs/flows.md`](../../docs/flows.md)
- Security model: [`docs/security.md`](../../docs/security.md)

API reference: `cargo doc -p doorman-axum --open`.
