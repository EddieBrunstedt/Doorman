use crate::common;

use crate::common::Backend;
use chrono::{DateTime, Duration, Utc};
use doorman_core::encoding::hex;
use doorman_core::session::hash_token;
use doorman_core::storage::{
    AuthenticationPurpose, EmailLink, EmailLinkPurpose, PasskeyChallengeId, RegistrationPurpose,
    Session, SessionId, StoredPasskeyAuthentication, StoredPasskeyRegistration, UserId,
};
use redis::aio::MultiplexedConnection;

fn session(token: &str, now: DateTime<Utc>, expires_at: DateTime<Utc>) -> Session {
    Session {
        id: SessionId::new(),
        user_id: UserId::new(),
        token_hash: hash_token(token),
        created_at: now,
        last_used_at: now,
        expires_at,
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    }
}

async fn expire_time(conn: &mut MultiplexedConnection, key: String) -> i64 {
    redis::cmd("PEXPIRETIME")
        .arg(&key)
        .query_async(conn)
        .await
        .expect("PEXPIRETIME")
}

async fn run_every_row_expires_at_its_deadline(backend: Backend) {
    let (_node, stores, mut raw, prefix) = common::stores_with_raw(backend).await;
    let now = Utc::now();

    let created = session("native-expiry-session", now, now + Duration::hours(1));
    let session_key = format!("{prefix}session:{}", created.id.0);
    let hash_key = format!("{prefix}session:hash:{}", hex(&created.token_hash.0));
    stores
        .sessions
        .create_session(created.clone())
        .await
        .expect("create session");
    for key in [&session_key, &hash_key] {
        assert_eq!(
            expire_time(&mut raw, key.clone()).await,
            created.expires_at.timestamp_millis(),
            "{key} expires at the session's deadline",
        );
    }

    let slid = now + Duration::hours(2);
    stores
        .sessions
        .touch_session(created.id, now, slid)
        .await
        .expect("touch session");
    for key in [&session_key, &hash_key] {
        assert_eq!(
            expire_time(&mut raw, key.clone()).await,
            slid.timestamp_millis(),
            "{key} expires at the slid deadline",
        );
    }

    let link = EmailLink {
        token_hash: hash_token("native-expiry-link"),
        user_id: UserId::new(),
        purpose: EmailLinkPurpose::Signup,
        new_email: None,
        created_at: now,
        expires_at: now + Duration::minutes(30),
    };
    stores
        .email_links
        .replace_link(link.clone())
        .await
        .expect("replace link");
    assert_eq!(
        expire_time(
            &mut raw,
            format!("{prefix}email_link:{}", hex(&link.token_hash.0))
        )
        .await,
        link.expires_at.timestamp_millis(),
        "the email link expires at its deadline",
    );
    let shorter = EmailLink {
        token_hash: hash_token("native-expiry-shorter-link"),
        purpose: EmailLinkPurpose::Recovery,
        expires_at: now + Duration::minutes(10),
        ..link.clone()
    };
    stores
        .email_links
        .replace_link(shorter)
        .await
        .expect("replace shorter link");
    assert_eq!(
        expire_time(
            &mut raw,
            format!("{prefix}user:{}:email_links", link.user_id.0)
        )
        .await,
        link.expires_at.timestamp_millis(),
        "the owner's links expire with its longest-lived link",
    );

    let registration = StoredPasskeyRegistration {
        id: PasskeyChallengeId::new(),
        purpose: RegistrationPurpose::Signup,
        user_id: UserId::new(),
        state: b"registration-state".to_vec(),
        created_at: now,
        expires_at: now + Duration::minutes(5),
        recovery_cool_down_until: None,
    };
    stores
        .passkey_challenges
        .put_registration(registration.clone())
        .await
        .expect("put registration");
    assert_eq!(
        expire_time(&mut raw, format!("{prefix}pkreg:{}", registration.id.0)).await,
        registration.expires_at.timestamp_millis(),
        "the passkey registration expires at its deadline",
    );

    let authentication = StoredPasskeyAuthentication {
        id: PasskeyChallengeId::new(),
        purpose: AuthenticationPurpose::Login,
        state: b"authentication-state".to_vec(),
        created_at: now,
        expires_at: now + Duration::minutes(4),
    };
    stores
        .passkey_challenges
        .put_authentication(authentication.clone())
        .await
        .expect("put authentication");
    assert_eq!(
        expire_time(&mut raw, format!("{prefix}pkauth:{}", authentication.id.0)).await,
        authentication.expires_at.timestamp_millis(),
        "the passkey authentication expires at its deadline",
    );
}

async fn run_a_session_written_past_its_deadline_is_gone_at_once(backend: Backend) {
    let (_node, stores, _raw, _prefix) = common::stores_with_raw(backend).await;
    let now = Utc::now();

    let expired = session(
        "native-expiry-past",
        now - Duration::hours(2),
        now - Duration::hours(1),
    );
    stores
        .sessions
        .create_session(expired.clone())
        .await
        .expect("create session");
    assert!(
        stores
            .sessions
            .find_session_by_id(expired.id)
            .await
            .expect("find by id")
            .is_none(),
        "the backend dropped the row its own clock says has expired",
    );
    assert!(
        stores
            .sessions
            .find_session_by_token_hash(&expired.token_hash)
            .await
            .expect("find by hash")
            .is_none(),
        "the backend dropped the hash index with the row",
    );
}

#[tokio::test]
async fn redis_every_row_expires_at_its_deadline() {
    run_every_row_expires_at_its_deadline(Backend::Redis).await;
}

#[tokio::test]
async fn valkey_every_row_expires_at_its_deadline() {
    run_every_row_expires_at_its_deadline(Backend::Valkey).await;
}

#[tokio::test]
async fn redis_a_session_written_past_its_deadline_is_gone_at_once() {
    run_a_session_written_past_its_deadline_is_gone_at_once(Backend::Redis).await;
}

#[tokio::test]
async fn valkey_a_session_written_past_its_deadline_is_gone_at_once() {
    run_a_session_written_past_its_deadline_is_gone_at_once(Backend::Valkey).await;
}
