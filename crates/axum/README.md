# doorman-axum

Axum HTTP integration for [doorman](../../README.md): the `AuthService` router, session-loading layer, `AuthUser` / `OptionalAuthUser` / `AuthSession` extractors, CSRF layer, and the `AuthServiceBuilder` that adds the cookie and CSRF settings to an `AuthCore` assembled by [`doorman-core`](../core).

This is the supported user-facing integration. Hand `AuthCore::builder` a `Storage` value (e.g. from [`doorman-sqlx`](../sqlx)) and configure the relying party, email transport, and flows; pass the built core to `AuthService::builder` for the HTTP settings; mount `auth.router()`; and apply `auth.session_layer()`.

```rust
let core = AuthCore::builder(storage.all_stores())
    .email(Arc::new(TerminalEmailSender))
    .passkey(PasskeyConfig::from_origin(origin.clone(), "Example")?)
    .signup(SignupConfig { url_template, ..Default::default() })
    .recovery(RecoveryConfig { url_template, ..Default::default() })
    .reauthentication(ReauthPolicy::required_for([ReauthAction::DeleteAccount, ReauthAction::RemovePasskey]))
    .build()?;
let auth = AuthService::builder(core)
    .external_origin(origin)
    .build()?;
let app = Router::new().merge(auth.router()).layer(auth.session_layer());
```

- Wiring, stores, branding: [`docs/integration.md`](../../docs/integration.md)
- Routes and flows: [`docs/flows.md`](../../docs/flows.md)
- Security model: [`docs/security.md`](../../docs/security.md)

API reference: `cargo doc -p doorman-axum --open`.
