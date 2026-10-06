use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use doorman_core::session::hash_token;
use doorman_core::storage::{Session, SessionId, Storage, TokenHash, User, UserId, UserStatus};
use tokio::runtime::Runtime;

const SCALE_SIZES: [u32; 3] = [1, 100, 10_000];
const SEED_ROWS: u32 = 2_000;
const PURGE_EXPIRED_ROWS: u32 = 500;

fn make_session(
    id: SessionId,
    user_id: UserId,
    token_hash: TokenHash,
    now: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
) -> Session {
    Session {
        id,
        user_id,
        token_hash,
        created_at: now,
        last_used_at: now,
        expires_at,
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    }
}

async fn seed_user(storage: &Storage) -> UserId {
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
    user_id
}

async fn seed_sessions(storage: &Storage, user_id: UserId, count: u32, prefix: &str) {
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(1);
    for n in 0..count {
        storage
            .sessions
            .create_session(make_session(
                SessionId::new(),
                user_id,
                hash_token(&format!("{prefix}-{n}")),
                now,
                expires_at,
            ))
            .await
            .expect("seed session");
    }
}

fn run_backend(c: &mut Criterion, runtime: &Runtime, label: &str, make: &dyn Fn() -> Storage) {
    let fixed = make();
    let (user_id, seeded_token_hash, seeded_id) = runtime.block_on(async {
        let user_id = seed_user(&fixed).await;
        seed_sessions(&fixed, user_id, SEED_ROWS, "seed").await;

        let now = Utc::now();
        let seeded_token_hash = hash_token("seeded-token");
        let seeded_id = SessionId::new();
        fixed
            .sessions
            .create_session(make_session(
                seeded_id,
                user_id,
                seeded_token_hash,
                now,
                now + chrono::Duration::hours(1),
            ))
            .await
            .expect("seed known session");
        (user_id, seeded_token_hash, seeded_id)
    });

    let mut group = c.benchmark_group(label);
    group.measurement_time(Duration::from_secs(5));

    let now = Utc::now();
    let counter = AtomicU64::new(0);
    group.bench_function("session_create", |b| {
        b.to_async(runtime).iter(|| async {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            fixed
                .sessions
                .create_session(make_session(
                    SessionId::new(),
                    user_id,
                    hash_token(&format!("create-{n}")),
                    now,
                    now + chrono::Duration::hours(1),
                ))
                .await
                .expect("create session");
        });
    });

    group.bench_function("find_by_token_hash", |b| {
        b.to_async(runtime).iter(|| async {
            fixed
                .sessions
                .find_session_by_token_hash(&seeded_token_hash)
                .await
                .expect("find by token hash")
                .expect("session exists");
        });
    });

    group.bench_function("find_by_id", |b| {
        b.to_async(runtime).iter(|| async {
            fixed
                .sessions
                .find_session_by_id(seeded_id)
                .await
                .expect("find by id")
                .expect("session exists");
        });
    });

    for size in SCALE_SIZES {
        let store = make();
        let token_hash = runtime.block_on(async {
            let user_id = seed_user(&store).await;
            seed_sessions(&store, user_id, size, "scale").await;
            let token_hash = hash_token("scale-known");
            let now = Utc::now();
            store
                .sessions
                .create_session(make_session(
                    SessionId::new(),
                    user_id,
                    token_hash,
                    now,
                    now + chrono::Duration::hours(1),
                ))
                .await
                .expect("seed known session");
            token_hash
        });
        group.bench_with_input(
            BenchmarkId::new("find_by_token_hash", size),
            &token_hash,
            |b, token_hash| {
                b.to_async(runtime).iter(|| async {
                    store
                        .sessions
                        .find_session_by_token_hash(token_hash)
                        .await
                        .expect("find by token hash")
                        .expect("session exists");
                });
            },
        );
    }

    for size in SCALE_SIZES {
        let store = make();
        let scoped_user = runtime.block_on(async {
            let user_id = seed_user(&store).await;
            seed_sessions(&store, user_id, size, "list").await;
            user_id
        });
        group.throughput(Throughput::Elements(u64::from(size)));
        group.bench_with_input(
            BenchmarkId::new("list_for_user", size),
            &scoped_user,
            |b, &scoped_user| {
                b.to_async(runtime).iter(|| async {
                    let now = Utc::now();
                    let sessions = store
                        .sessions
                        .list_for_user(scoped_user, now)
                        .await
                        .expect("list for user");
                    std::hint::black_box(sessions);
                });
            },
        );
    }
    let purge_store = make();
    let purge_user = runtime.block_on(seed_user(&purge_store));
    group.throughput(Throughput::Elements(u64::from(PURGE_EXPIRED_ROWS)));
    group.sample_size(20);
    group.bench_function("purge_expired", |b| {
        b.to_async(runtime).iter_custom(|iters| {
            let store = &purge_store;
            async move {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let now = Utc::now();
                    let expired = now - chrono::Duration::hours(1);
                    for n in 0..PURGE_EXPIRED_ROWS {
                        store
                            .sessions
                            .create_session(make_session(
                                SessionId::new(),
                                purge_user,
                                hash_token(&format!("expired-{n}")),
                                now - chrono::Duration::hours(2),
                                expired,
                            ))
                            .await
                            .expect("seed expired session");
                    }
                    let start = Instant::now();
                    let removed = store
                        .sessions
                        .purge_expired(now)
                        .await
                        .expect("purge expired");
                    total += start.elapsed();
                    assert!(removed >= u64::from(PURGE_EXPIRED_ROWS));
                }
                total
            }
        });
    });

    group.finish();
}

#[cfg(feature = "sqlite")]
fn sqlite_storage(runtime: &Runtime) -> Storage {
    runtime.block_on(async {
        let storage = doorman_sqlx::SqliteStorage::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        storage.migrate().await.expect("migrate sqlite");
        storage.all_stores()
    })
}

fn storage(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");

    #[cfg(feature = "sqlite")]
    run_backend(c, &runtime, "sqlite", &|| sqlite_storage(&runtime));

    #[cfg(feature = "postgres")]
    {
        use testcontainers_modules::postgres::Postgres;
        use testcontainers_modules::testcontainers::runners::AsyncRunner;

        let (node, pool) = runtime.block_on(async {
            let node = Postgres::default()
                .start()
                .await
                .expect("start postgres container");
            let host = node.get_host().await.expect("container host");
            let port = node.get_host_port_ipv4(5432).await.expect("container port");
            let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
            let pool = sqlx::PgPool::connect(&url).await.expect("pg connect");
            (node, pool)
        });
        let make = || {
            runtime.block_on(async {
                sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
                    .execute(&pool)
                    .await
                    .expect("drop schema");
                sqlx::query("CREATE SCHEMA public")
                    .execute(&pool)
                    .await
                    .expect("create schema");
                let storage = doorman_sqlx::PostgresStorage::from_pool(pool.clone());
                storage.migrate().await.expect("migrate postgres");
                storage.all_stores()
            })
        };
        run_backend(c, &runtime, "postgres", &make);

        runtime
            .block_on(node.rm())
            .expect("remove postgres container");
    }
}

criterion_group!(benches, storage);
criterion_main!(benches);
