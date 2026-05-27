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

use bauth_core::storage::{UserId, VerificationPurpose};
use bauth_sqlx::PostgresStorage;
use chrono::{DateTime, TimeZone, Utc};
use sqlx::PgPool;

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
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

    let users = storage.user_store();
    let user_id = UserId::new();
    users
        .create_user(bauth_core::storage::User {
            id: user_id,
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
            user_id,
            purpose: VerificationPurpose::Signup,
            created_at: ts(2026, 1, 1),
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("create");

    let first = tokens
        .consume_token(&hash, VerificationPurpose::Signup)
        .await
        .expect("consume");
    assert!(first.is_some(), "first consume returns the token");

    let second = tokens
        .consume_token(&hash, VerificationPurpose::Signup)
        .await
        .expect("consume again");
    assert!(second.is_none(), "second consume returns nothing");

    // Composite Storage handle returns the same backing pool.
    let composite = storage.storage();
    let _ = composite
        .users
        .find_user_by_id(user_id)
        .await
        .expect("composite find");
}
