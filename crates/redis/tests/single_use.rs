//! Single-use / atomicity checks for the Redis `consume_*` and `take_*` paths.
//!
//! Each test creates one challenge, then spawns many concurrent redeemers and
//! asserts that exactly one succeeds — the guarantee `GETDEL` provides under
//! concurrency (§5.5). Skipped unless `REDIS_URL` is set.

mod common;

use chrono::{Duration, Utc};
use doorman_core::session::hash_token;
use doorman_core::storage::{
    PasskeyChallengeId, StoredPasskeyAuthentication, StoredPasskeyRegistration, UserId,
    VerificationPurpose, VerificationToken,
};

/// Number of concurrent redeemers racing for one challenge.
const RACERS: usize = 64;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verification_token_is_consumed_exactly_once() {
    let Some(storage) = common::storage("REDIS_URL").await else {
        return;
    };
    let tokens = storage.verification_tokens.clone();
    let hash = hash_token("race-consume-token");
    tokens
        .create_token(VerificationToken {
            token_hash: hash,
            user_id: UserId::new(),
            purpose: VerificationPurpose::Signup,
            new_email: None,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .expect("create token");

    let mut handles = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let tokens = tokens.clone();
        handles.push(tokio::spawn(async move {
            tokens
                .consume_token(&hash, VerificationPurpose::Signup)
                .await
                .expect("consume")
                .is_some()
        }));
    }

    let mut wins = 0;
    for handle in handles {
        if handle.await.expect("join") {
            wins += 1;
        }
    }
    assert_eq!(wins, 1, "exactly one consumer redeems the token");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registration_is_taken_exactly_once() {
    let Some(storage) = common::storage("REDIS_URL").await else {
        return;
    };
    let challenges = storage.passkey_challenges.clone();
    let id = PasskeyChallengeId::new();
    challenges
        .put_registration(StoredPasskeyRegistration {
            id,
            user_id: UserId::new(),
            state: b"race-registration-state".to_vec(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            recovery_cooldown_until: None,
        })
        .await
        .expect("put registration");

    let mut handles = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let challenges = challenges.clone();
        handles.push(tokio::spawn(async move {
            challenges
                .take_registration(id)
                .await
                .expect("take")
                .is_some()
        }));
    }

    let mut wins = 0;
    for handle in handles {
        if handle.await.expect("join") {
            wins += 1;
        }
    }
    assert_eq!(wins, 1, "exactly one caller takes the registration");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentication_is_taken_exactly_once() {
    let Some(storage) = common::storage("REDIS_URL").await else {
        return;
    };
    let challenges = storage.passkey_challenges.clone();
    let id = PasskeyChallengeId::new();
    challenges
        .put_authentication(StoredPasskeyAuthentication {
            id,
            state: b"race-authentication-state".to_vec(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .expect("put authentication");

    let mut handles = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let challenges = challenges.clone();
        handles.push(tokio::spawn(async move {
            challenges
                .take_authentication(id)
                .await
                .expect("take")
                .is_some()
        }));
    }

    let mut wins = 0;
    for handle in handles {
        if handle.await.expect("join") {
            wins += 1;
        }
    }
    assert_eq!(wins, 1, "exactly one caller takes the authentication");
}
