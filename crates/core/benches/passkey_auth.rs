mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use doorman_core::memory::InMemoryStorage;
use doorman_core::passkey::PasskeyManager;
use doorman_core::session::SessionContext;
use doorman_core::storage::{Session, User, UserId, UserStatus};
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
    let storage = InMemoryStorage::new().all_stores();
    let core = support::in_memory_core(storage.clone());

    let now = Utc::now();
    let user = User {
        id: UserId::new(),
        email: Some("bench@example.com".into()),
        email_verified_at: Some(now),
        status: UserStatus::Active,
        created_at: now,
        updated_at: now,
    };
    let user_id = user.id;
    storage.users.create_user(user).await.expect("create user");

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

    c.bench_function("passkey_finish", |b| {
        b.to_async(&runtime).iter_custom(|iters| {
            let scaffold = &scaffold;
            let authenticator = authenticator.clone();
            let credential_id = credential_id.clone();
            let user_handle = user_handle.clone();
            async move {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
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
