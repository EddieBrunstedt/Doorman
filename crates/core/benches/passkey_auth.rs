//! Passkey-authentication benches: the only crypto-heavy steady-state path.
//!
//! A credential is registered once during setup; two benches then drive it:
//!
//! - `passkey_authenticate` — the full discoverable ceremony per iteration:
//!   `start_authentication`, the `SoftPasskey` signs the challenge, then
//!   `finish_authentication` verifies the assertion and issues a session. The
//!   headline login-throughput number.
//! - `passkey_finish` — isolates the server-side verify cost. Each iteration's
//!   `start_authentication` + signing happens in an untimed `iter_custom`
//!   setup, so only `finish_authentication` (assertion verification, counter
//!   check, user-handle binding, session issue) is timed.
//!
//! `SoftPasskey` cannot mint resident keys, so registration relaxes the
//! resident-key flags locally (doorman still issues `residentKey=required`)
//! and the bench records the user handle to replay it on authentication,
//! mirroring the test harness's `ResidentTestAuthenticator`.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p doorman-core --bench passkey_auth
//! ```

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use doorman_core::passkey::PasskeyManager;
use doorman_core::session::SessionContext;
use doorman_core::storage::{AccountStatus, Session, User, UserId};
use tokio::runtime::Runtime;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::prelude::Url as AuthUrl;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::PublicKeyCredential;
use webauthn_rs_proto::AllowCredentials;

fn auth_origin() -> AuthUrl {
    AuthUrl::parse("http://localhost:8080").expect("auth origin")
}

struct Scaffold {
    manager: PasskeyManager,
    session: Session,
}

async fn build_scaffold() -> Scaffold {
    let core = support::in_memory_core();

    let now = Utc::now();
    let user = User {
        id: UserId::new(),
        email: Some("bench@example.com".into()),
        email_verified_at: Some(now),
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    };
    let user_id = user.id;
    core.storage
        .users
        .create_user(user)
        .await
        .expect("create user");

    let session = core
        .session_manager
        .create(user_id, SessionContext::default())
        .await
        .expect("create session")
        .session;

    Scaffold {
        manager: core.passkey,
        session,
    }
}

/// Register a single credential and return its `(credential_id, user_handle)`.
async fn register(
    scaffold: &Scaffold,
    wa: &mut WebauthnAuthenticator<SoftPasskey>,
) -> (Vec<u8>, Vec<u8>) {
    let (challenge_id, ccr) = scaffold
        .manager
        .start_registration(&scaffold.session)
        .await
        .expect("start registration");
    let user_handle = ccr.public_key.user.id.as_ref().to_vec();

    let mut compatible = ccr;
    let selection = compatible
        .public_key
        .authenticator_selection
        .as_mut()
        .expect("authenticator selection");
    selection.require_resident_key = false;
    selection.resident_key = None;

    let response = wa
        .do_registration(auth_origin(), compatible)
        .expect("authenticator register");
    let credential_id = response.raw_id.as_ref().to_vec();
    scaffold
        .manager
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect("finish registration");
    (credential_id, user_handle)
}

fn passkey_auth(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let scaffold = runtime.block_on(build_scaffold());

    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (credential_id, user_handle) = runtime.block_on(register(&scaffold, &mut authenticator));
    // Shared so each iteration's future can own a handle without borrowing
    // `authenticator` from the (FnMut) closure. The lock is only held for
    // the synchronous signing call, never across an await.
    let authenticator = Arc::new(Mutex::new(authenticator));

    c.bench_function("passkey_authenticate", |b| {
        b.to_async(&runtime).iter(|| {
            let scaffold = &scaffold;
            let authenticator = authenticator.clone();
            let credential_id = credential_id.clone();
            let user_handle = user_handle.clone();
            async move {
                let (auth_id, rcr) = scaffold
                    .manager
                    .start_authentication(SessionContext::default())
                    .await
                    .expect("start authentication");

                // SoftPasskey needs an allow-list to pick a key; the
                // server-issued challenge stays discoverable.
                let mut compatible = rcr;
                compatible.public_key.allow_credentials = vec![AllowCredentials {
                    type_: "public-key".to_string(),
                    id: credential_id.into(),
                    transports: None,
                }];
                let mut assertion: PublicKeyCredential = authenticator
                    .lock()
                    .expect("authenticator poisoned")
                    .do_authentication(auth_origin(), compatible)
                    .expect("authenticator auth");
                assertion.response.user_handle = Some(user_handle.into());

                scaffold
                    .manager
                    .finish_authentication(auth_id, &assertion, SessionContext::default())
                    .await
                    .expect("finish authentication");
            }
        });
    });

    // Finish-only: start + sign in untimed setup, time just the verify path.
    c.bench_function("passkey_finish", |b| {
        b.to_async(&runtime).iter_custom(|iters| {
            let scaffold = &scaffold;
            let authenticator = authenticator.clone();
            let credential_id = credential_id.clone();
            let user_handle = user_handle.clone();
            async move {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    // Untimed: fresh challenge and a signed assertion for it.
                    let (auth_id, rcr) = scaffold
                        .manager
                        .start_authentication(SessionContext::default())
                        .await
                        .expect("start authentication");
                    let mut compatible = rcr;
                    compatible.public_key.allow_credentials = vec![AllowCredentials {
                        type_: "public-key".to_string(),
                        id: credential_id.clone().into(),
                        transports: None,
                    }];
                    let mut assertion: PublicKeyCredential = authenticator
                        .lock()
                        .expect("authenticator poisoned")
                        .do_authentication(auth_origin(), compatible)
                        .expect("authenticator auth");
                    assertion.response.user_handle = Some(user_handle.clone().into());

                    // Timed: server-side assertion verification + session issue.
                    let start = Instant::now();
                    scaffold
                        .manager
                        .finish_authentication(auth_id, &assertion, SessionContext::default())
                        .await
                        .expect("finish authentication");
                    total += start.elapsed();
                }
                total
            }
        });
    });
}

criterion_group!(benches, passkey_auth);
criterion_main!(benches);
