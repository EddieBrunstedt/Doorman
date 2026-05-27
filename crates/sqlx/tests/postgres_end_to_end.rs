//! End-to-end smoke test for the SQLx + Postgres adapter.
//!
//! Skipped unless the `PG_URL` environment variable points at a
//! disposable test database. CI provides this via a containerised
//! Postgres; locally you can set
//! `PG_URL=postgres://postgres:postgres@localhost/bauth_test`.
//!
//! The test wipes the database's `public` schema before running so the
//! migration state is fresh on every invocation. Do not point `PG_URL`
//! at a database whose `public` schema holds data you want to keep.

#![cfg(feature = "postgres")]

use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, MockClock};
use bauth_core::email::EmailSender;
use bauth_core::magic_link::{
    MagicLinkConfig, MagicLinkManager, MagicLinkRateLimits, TOKEN_PLACEHOLDER,
};
use bauth_core::memory::{InMemoryEmailSender, InMemoryRateLimiter};
use bauth_core::rate_limit::RateLimiter;
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::storage::{OAuthIdentity, UserId, VerificationPurpose};
use bauth_sqlx::PostgresStorage;
use chrono::{DateTime, TimeZone, Utc};
use sqlx::PgPool;

const MAGIC_URL: &str = "https://app.test/magic-link?token={token}";

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn token_from_email(body: &str) -> String {
    let prefix = MAGIC_URL
        .split(TOKEN_PLACEHOLDER)
        .next()
        .expect("template has prefix");
    let start = body.find(prefix).expect("body contains url prefix");
    let after = &body[start + prefix.len()..];
    after
        .split_whitespace()
        .next()
        .expect("token follows prefix")
        .to_string()
}

async fn fresh_storage() -> Option<PostgresStorage> {
    let url = match std::env::var("PG_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("PG_URL not set; skipping Postgres test");
            return None;
        }
    };

    let pool = PgPool::connect(&url).await.expect("pg connect");
    sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
        .execute(&pool)
        .await
        .expect("drop schema");
    sqlx::query("CREATE SCHEMA public")
        .execute(&pool)
        .await
        .expect("create schema");

    let storage = PostgresStorage::from_pool(pool);
    storage.migrate().await.expect("migrate");
    Some(storage)
}

#[tokio::test]
async fn postgres_full_smoke_test() {
    let Some(storage) = fresh_storage().await else {
        return;
    };

    let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let email: Arc<InMemoryEmailSender> = Arc::new(InMemoryEmailSender::new());
    let limiter: Arc<dyn RateLimiter> =
        Arc::new(InMemoryRateLimiter::new(clock.clone() as Arc<dyn Clock>));

    let session_manager = SessionManager::new(
        storage.session_store(),
        clock.clone() as Arc<dyn Clock>,
        audit.clone(),
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );
    let manager = MagicLinkManager::new(
        storage.user_store(),
        storage.verification_token_store(),
        session_manager,
        email.clone() as Arc<dyn EmailSender>,
        clock as Arc<dyn Clock>,
        audit,
        limiter,
        MagicLinkConfig {
            url_template: MAGIC_URL.to_string(),
            rate_limits: MagicLinkRateLimits::disabled(),
            ..MagicLinkConfig::default()
        },
    );

    manager
        .request_magic_link("alice@example.com", SessionContext::default())
        .await
        .expect("request");

    let users = storage.user_store();
    let persisted = users
        .find_user_by_email("alice@example.com")
        .await
        .expect("find")
        .expect("user persisted");
    assert!(persisted.email_verified_at.is_none());

    let magic_body = email
        .sent()
        .into_iter()
        .find(|e| e.subject == "Your sign-in link")
        .expect("magic-link email queued")
        .body_text;
    let token = token_from_email(&magic_body);
    let outcome = manager
        .consume_magic_link(&token, SessionContext::default())
        .await
        .expect("consume");
    assert!(outcome.is_new_user);
    assert!(outcome.user.email_verified_at.is_some());
    assert_eq!(outcome.user.id, persisted.id);
    assert_eq!(outcome.session.session.user_id, persisted.id);

    manager
        .request_magic_link("alice@example.com", SessionContext::default())
        .await
        .expect("second request");
    let second_body = email
        .sent()
        .into_iter()
        .rev()
        .find(|e| e.subject == "Your sign-in link")
        .expect("second magic-link email queued")
        .body_text;
    let second_token = token_from_email(&second_body);
    let second = manager
        .consume_magic_link(&second_token, SessionContext::default())
        .await
        .expect("second consume");
    assert!(!second.is_new_user);

    // OAuth identity round-trip on a fresh user, to exercise the
    // identity-store queries.
    let user_id = UserId::new();
    users
        .create_user(bauth_core::storage::User {
            id: user_id,
            email: Some("bob@example.com".into()),
            email_verified_at: None,
            created_at: ts(2026, 1, 1),
            updated_at: ts(2026, 1, 1),
        })
        .await
        .expect("create user");

    let identities = storage.oauth_identity_store();
    identities
        .link(OAuthIdentity {
            provider: "google".into(),
            subject: "sub-456".into(),
            user_id,
            email: Some("bob@example.com".into()),
            created_at: ts(2026, 1, 1),
            updated_at: ts(2026, 1, 1),
        })
        .await
        .expect("link");

    let listed = identities.list_for_user(user_id).await.expect("list");
    assert_eq!(listed.len(), 1);

    identities
        .unlink("google", "sub-456")
        .await
        .expect("unlink");

    // Verification-token atomic consume.
    let token_user = UserId::new();
    users
        .create_user(bauth_core::storage::User {
            id: token_user,
            email: Some("carol@example.com".into()),
            email_verified_at: None,
            created_at: ts(2026, 1, 1),
            updated_at: ts(2026, 1, 1),
        })
        .await
        .expect("user");

    let tokens = storage.verification_token_store();
    let hash = bauth_core::session::hash_token("pg-test-token");
    tokens
        .create_token(bauth_core::storage::VerificationToken {
            token_hash: hash,
            user_id: token_user,
            purpose: VerificationPurpose::MagicLink,
            created_at: ts(2026, 1, 1),
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("create");

    let first = tokens
        .consume_token(&hash, VerificationPurpose::MagicLink)
        .await
        .expect("consume");
    assert!(first.is_some(), "first consume returns the token");

    let second = tokens
        .consume_token(&hash, VerificationPurpose::MagicLink)
        .await
        .expect("consume again");
    assert!(second.is_none(), "second consume returns nothing");

    // Composite Storage handle returns the same backing pool.
    let composite = storage.storage();
    let _ = composite
        .users
        .find_user_by_email("alice@example.com")
        .await
        .expect("composite find");
}
