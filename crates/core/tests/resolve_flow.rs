mod common;

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::Error;
use doorman_core::assembly::AssemblyError;
use doorman_core::audit::OperatorActor;
use doorman_core::cache::{SessionCacheConfig, SessionCachePolicy};
use doorman_core::clock::Clock;
use doorman_core::metrics::MetricEvent;
use doorman_core::session::{SessionConfig, SessionContext, hash_token};
use doorman_core::storage::{AccountStatus, SessionStore, User, UserId, UserStore};

use common::{Harness, SIGNUP_URL, last_email_change_token, make_user, token_from_email};

fn sliding_config() -> SessionConfig {
    SessionConfig {
        absolute_lifetime: Duration::from_secs(60 * 60),
        idle_timeout: Some(Duration::from_secs(60 * 10)),
        ..SessionConfig::default()
    }
}

fn sliding_harness() -> Harness {
    Harness::builder().session_config(sliding_config()).build()
}

fn full_cache(ttl: Duration) -> SessionCachePolicy {
    SessionCachePolicy::full(SessionCacheConfig {
        ttl,
        ..SessionCacheConfig::default()
    })
}

fn full_cache_harness() -> Harness {
    Harness::builder()
        .session_cache(full_cache(Duration::from_secs(60)))
        .build()
}

async fn signed_in(h: &Harness, email: &str) -> (User, String) {
    let user = make_user(h, email).await;
    let issued = h
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("create session");
    (user, issued.token)
}

fn hits(h: &Harness) -> usize {
    h.metrics.count(MetricEvent::CacheHit)
}

fn misses(h: &Harness) -> usize {
    h.metrics.count(MetricEvent::CacheMiss)
}

#[tokio::test]
async fn resolves_from_storage_then_serves_from_cache() {
    let h = full_cache_harness();
    let (user, token) = signed_in(&h, "alice@example.com").await;

    let first = h
        .session_manager
        .resolve(&token)
        .await
        .expect("first resolve");
    assert_eq!(first.user.id, user.id);
    assert_eq!(first.session.user_id, user.id);
    assert_eq!((hits(&h), misses(&h)), (0, 1), "a cold token misses");

    h.sessions
        .delete_session(first.session.id)
        .await
        .expect("delete session row");
    let second = h
        .session_manager
        .resolve(&token)
        .await
        .expect("warm resolve");
    assert!(Arc::ptr_eq(&first.session, &second.session));
    assert_eq!((hits(&h), misses(&h)), (1, 1), "a warm token hits");

    h.clock.advance(ChronoDuration::seconds(60));
    let err = h.session_manager.resolve(&token).await.err();
    assert!(
        matches!(err, Some(Error::SessionNotFound)),
        "a stale entry re-reads storage, got {err:?}",
    );
}

#[tokio::test]
async fn a_revocation_reaches_another_process_at_once() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    other
        .session_manager
        .resolve(&token)
        .await
        .expect("the other process resolves the session");

    h.session_manager.revoke(&token).await.expect("revoke");
    let err = other.session_manager.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
}

#[tokio::test]
async fn a_warm_request_reads_only_the_session() {
    let h = Harness::fresh();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.user_store.reset();

    h.session_manager.resolve(&token).await.expect("cold");
    assert_eq!(
        h.user_store.reads_by_id(),
        1,
        "a cold request reads the user"
    );
    h.session_manager.resolve(&token).await.expect("warm");
    assert_eq!(h.user_store.reads_by_id(), 1, "a warm request does not");
    assert_eq!((hits(&h), misses(&h)), (1, 1));
}

#[tokio::test]
async fn another_process_sees_a_changed_email_after_its_ttl() {
    let h = Harness::fresh();
    let other = h.another_process();
    let (_, token) = signed_in(&h, "old@example.com").await;
    let warm = h.session_manager.resolve(&token).await.expect("warm");
    other
        .session_manager
        .resolve(&token)
        .await
        .expect("warm other");

    h.account
        .request_email_change(
            &warm.user,
            &warm.session,
            "new@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    h.account
        .confirm_email_change(&last_email_change_token(&h), SessionContext::default())
        .await
        .expect("confirm email change");

    let stale = other
        .session_manager
        .resolve(&token)
        .await
        .expect("resolve");
    assert_eq!(stale.user.email.as_deref(), Some("old@example.com"));

    h.clock.advance(ChronoDuration::seconds(60));
    let fresh = other
        .session_manager
        .resolve(&token)
        .await
        .expect("resolve");
    assert_eq!(fresh.user.email.as_deref(), Some("new@example.com"));
}

#[tokio::test]
async fn a_full_cache_serves_a_revoked_session_until_its_ttl() {
    let h = full_cache_harness();
    let other = h.another_process();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    other
        .session_manager
        .resolve(&token)
        .await
        .expect("warm the other process");

    h.session_manager.revoke(&token).await.expect("revoke");
    h.session_manager
        .resolve(&token)
        .await
        .err()
        .expect("the revoking process refuses it at once");

    h.clock.advance(ChronoDuration::seconds(59));
    other
        .session_manager
        .resolve(&token)
        .await
        .expect("the other process still serves its cached session");

    h.clock.advance(ChronoDuration::seconds(1));
    let err = other.session_manager.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
}

#[tokio::test]
async fn unknown_token_is_refused() {
    let h = Harness::fresh();
    let err = h.session_manager.resolve("not-a-session").await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
}

#[tokio::test]
async fn warm_entry_past_its_session_deadline_is_not_served() {
    let h = Harness::builder()
        .session_config(SessionConfig {
            absolute_lifetime: Duration::from_secs(30),
            ..SessionConfig::default()
        })
        .session_cache(full_cache(Duration::from_secs(60)))
        .build();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.session_manager
        .resolve(&token)
        .await
        .expect("warm the cache");

    h.clock.advance(ChronoDuration::seconds(31));
    let err = h.session_manager.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionExpired)), "got {err:?}");
    assert_eq!(hits(&h), 0, "the expired snapshot was never served");
}

#[tokio::test]
async fn revoke_evicts_the_warm_entry() {
    let h = full_cache_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.session_manager
        .resolve(&token)
        .await
        .expect("warm the cache");

    h.session_manager.revoke(&token).await.expect("revoke");
    let err = h.session_manager.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
    assert_eq!(hits(&h), 0);
}

#[tokio::test]
async fn revoke_by_id_evicts_the_warm_entry() {
    let h = full_cache_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    let warm = h.session_manager.resolve(&token).await.expect("warm");

    h.session_manager
        .revoke_by_id(warm.session.id)
        .await
        .expect("revoke by id");
    let err = h.session_manager.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
    assert_eq!(hits(&h), 0);
}

#[tokio::test]
async fn revoke_other_sessions_evicts_only_the_others() {
    let h = full_cache_harness();
    let (user, current) = signed_in(&h, "carol@example.com").await;
    let other = h
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("other session")
        .token;
    let warm = h.session_manager.resolve(&current).await.expect("warm");
    h.session_manager.resolve(&other).await.expect("warm other");

    let removed = h
        .account
        .revoke_other_sessions(&warm.user, &warm.session, None, SessionContext::default())
        .await
        .expect("revoke others");
    assert_eq!(removed, 1);
    let err = h.session_manager.resolve(&other).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
    h.session_manager
        .resolve(&current)
        .await
        .expect("the current session survives");
}

#[tokio::test]
async fn session_cap_eviction_evicts_the_warm_entry() {
    let h = Harness::builder()
        .session_config(SessionConfig {
            max_sessions_per_user: NonZeroU32::new(1),
            ..SessionConfig::default()
        })
        .session_cache(full_cache(Duration::from_secs(60)))
        .build();
    let (user, oldest) = signed_in(&h, "dave@example.com").await;
    h.session_manager.resolve(&oldest).await.expect("warm");

    h.session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("a session past the cap");
    let err = h.session_manager.resolve(&oldest).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
    assert_eq!(hits(&h), 0);
}

#[tokio::test]
async fn revoke_all_for_user_evicts_every_warm_entry() {
    let h = full_cache_harness();
    let (user, first) = signed_in(&h, "bob@example.com").await;
    let second = h
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("second session")
        .token;
    h.session_manager.resolve(&first).await.expect("warm first");
    h.session_manager
        .resolve(&second)
        .await
        .expect("warm second");

    let removed = h
        .session_manager
        .revoke_all_for_user(user.id)
        .await
        .expect("revoke all");
    assert_eq!(removed, 2);
    for token in [&first, &second] {
        let err = h.session_manager.resolve(token).await.err();
        assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
    }
    assert_eq!(hits(&h), 0);
}

#[tokio::test]
async fn disabled_account_is_refused_and_never_cached() {
    let h = full_cache_harness();
    let (user, token) = signed_in(&h, "frozen@example.com").await;
    let now = h.clock.now();
    h.users
        .set_user_status(user.id, AccountStatus::Disabled { at: now }, now)
        .await
        .expect("disable");

    for _ in 0..2 {
        let err = h.session_manager.resolve(&token).await.err();
        assert!(matches!(err, Some(Error::AccountDisabled)), "got {err:?}");
    }
    assert_eq!(
        (hits(&h), misses(&h)),
        (0, 2),
        "a refused session is never cached",
    );
}

#[tokio::test]
async fn operator_disable_evicts_the_warm_entry() {
    let h = full_cache_harness();
    let (user, token) = signed_in(&h, "locked@example.com").await;
    h.session_manager
        .resolve(&token)
        .await
        .expect("warm the cache");

    let actor = OperatorActor::new("support-agent-7", None, None, None).expect("operator actor");
    h.operator.disable(user.id, actor).await.expect("disable");

    let err = h.session_manager.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
    assert_eq!(hits(&h), 0);
}

#[tokio::test]
async fn email_change_evicts_the_warm_entry() {
    let h = full_cache_harness();
    let (_, token) = signed_in(&h, "old@example.com").await;
    let warm = h
        .session_manager
        .resolve(&token)
        .await
        .expect("warm the cache");

    h.account
        .request_email_change(
            &warm.user,
            &warm.session,
            "new@example.com",
            None,
            SessionContext::default(),
        )
        .await
        .expect("request email change");
    h.account
        .confirm_email_change(&last_email_change_token(&h), SessionContext::default())
        .await
        .expect("confirm email change");

    let resolved = h.session_manager.resolve(&token).await.expect("resolve");
    assert_eq!(resolved.user.email.as_deref(), Some("new@example.com"));
    assert_eq!(hits(&h), 0, "the stale snapshot was never served");
}

#[tokio::test]
async fn email_verification_evicts_the_warm_entry() {
    let h = full_cache_harness();
    let now = h.clock.now();
    let user = User {
        id: UserId::new(),
        email: Some("late@example.com".to_owned()),
        email_verified_at: None,
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    };
    h.users
        .create_user(user.clone())
        .await
        .expect("create user");
    let token = h
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("create session")
        .token;
    let warm = h
        .session_manager
        .resolve(&token)
        .await
        .expect("warm the cache");
    assert!(warm.user.email_verified_at.is_none());

    h.signup
        .request_signup("late@example.com", None, SessionContext::default())
        .await
        .expect("request signup");
    let link = h
        .email
        .sent()
        .last()
        .expect("signup link queued")
        .body_text
        .clone();
    h.signup
        .consume_signup(
            &token_from_email(&link, SIGNUP_URL),
            SessionContext::default(),
        )
        .await
        .expect("consume signup");

    let resolved = h.session_manager.resolve(&token).await.expect("resolve");
    assert!(resolved.user.email_verified_at.is_some());
    assert_eq!(hits(&h), 0, "the stale snapshot was never served");
}

#[tokio::test]
async fn session_whose_owner_is_gone_is_refused() {
    let h = Harness::fresh();
    let (user, token) = signed_in(&h, "gone@example.com").await;
    h.users.delete_user(user.id).await.expect("delete user row");

    let err = h.session_manager.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::UserNotFound)), "got {err:?}");
}

#[tokio::test]
async fn miss_after_the_throttle_slides_and_reports_it() {
    let h = sliding_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;

    h.clock.advance(ChronoDuration::seconds(90));
    let now = h.clock.now();
    let resolved = h.session_manager.resolve(&token).await.expect("resolve");
    assert!(resolved.slid, "the deadline moved");
    assert_eq!(resolved.session.last_used_at, now);
    assert_eq!(
        resolved.session.expires_at,
        now + ChronoDuration::minutes(10)
    );

    let stored = h
        .sessions
        .find_session_by_token_hash(&hash_token(&token))
        .await
        .expect("find")
        .expect("present");
    assert_eq!(stored.expires_at, resolved.session.expires_at, "persisted");
    assert_eq!(stored.last_used_at, now);
}

#[tokio::test]
async fn hit_never_slides() {
    let h = Harness::builder()
        .session_config(sliding_config())
        .session_cache(full_cache(Duration::from_secs(60)))
        .build();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.clock.advance(ChronoDuration::seconds(90));
    let slid = h.session_manager.resolve(&token).await.expect("slide");

    h.clock.advance(ChronoDuration::seconds(30));
    let hit = h.session_manager.resolve(&token).await.expect("hit");
    assert!(!hit.slid);
    assert_eq!(hit.session.expires_at, slid.session.expires_at);
    assert_eq!(hits(&h), 1);
}

#[tokio::test]
async fn read_within_the_slide_interval_does_not_slide() {
    let h = sliding_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.clock.advance(ChronoDuration::seconds(90));
    let first = h.session_manager.resolve(&token).await.expect("slide");

    h.clock.advance(ChronoDuration::seconds(30));
    let second = h.session_manager.resolve(&token).await.expect("read");
    assert!(!second.slid);
    assert_eq!(second.session.expires_at, first.session.expires_at);
    assert_eq!(second.session.last_used_at, first.session.last_used_at);
}

#[tokio::test]
async fn a_cached_session_due_to_slide_is_read_and_slid() {
    let h = Harness::builder()
        .session_config(sliding_config())
        .session_cache(full_cache(Duration::from_secs(5 * 60)))
        .build();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.session_manager.resolve(&token).await.expect("warm");

    h.clock.advance(ChronoDuration::seconds(90));
    let now = h.clock.now();
    let resolved = h.session_manager.resolve(&token).await.expect("resolve");
    assert!(
        resolved.slid,
        "a fresh entry does not hold back a due slide"
    );
    assert_eq!(resolved.session.last_used_at, now);
    assert_eq!((hits(&h), misses(&h)), (0, 2));
}

#[tokio::test]
async fn slide_is_clamped_at_the_absolute_cap() {
    let h = sliding_harness();
    let start = h.clock.now();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    let cap = start + ChronoDuration::minutes(60);

    let mut last = None;
    for _ in 0..11 {
        h.clock.advance(ChronoDuration::minutes(5));
        let resolved = h.session_manager.resolve(&token).await.expect("resolve");
        assert!(resolved.session.expires_at <= cap);
        last = Some(resolved);
    }
    let last = last.expect("resolved at least once");
    assert_eq!(last.session.expires_at, cap);
}

#[tokio::test]
async fn without_an_idle_timeout_nothing_slides() {
    let h = Harness::fresh();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    let issued = h
        .sessions
        .find_session_by_token_hash(&hash_token(&token))
        .await
        .expect("find")
        .expect("present");

    h.clock.advance(ChronoDuration::minutes(30));
    let resolved = h.session_manager.resolve(&token).await.expect("resolve");
    assert!(!resolved.slid);
    assert_eq!(resolved.session.expires_at, issued.expires_at);
    assert_eq!(resolved.session.last_used_at, issued.last_used_at);
}

#[tokio::test]
async fn disabled_account_is_not_slid() {
    let h = sliding_harness();
    let (user, token) = signed_in(&h, "frozen@example.com").await;
    h.clock.advance(ChronoDuration::seconds(90));
    let now = h.clock.now();
    h.users
        .set_user_status(user.id, AccountStatus::Disabled { at: now }, now)
        .await
        .expect("disable");

    let err = h.session_manager.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::AccountDisabled)), "got {err:?}");
    let stored = h
        .sessions
        .find_session_by_token_hash(&hash_token(&token))
        .await
        .expect("find")
        .expect("present");
    assert!(
        stored.last_used_at < now,
        "a refused session is not touched"
    );
}

#[tokio::test]
async fn validate_does_not_slide() {
    let h = sliding_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    let issued = h.session_manager.validate(&token).await.expect("validate");

    h.clock.advance(ChronoDuration::seconds(90));
    let validated = h.session_manager.validate(&token).await.expect("validate");
    assert_eq!(validated.last_used_at, issued.last_used_at);
    assert_eq!(validated.expires_at, issued.expires_at);
}

#[test]
fn slide_interval_must_be_strictly_below_the_idle_timeout() {
    let idle = Duration::from_secs(60 * 10);
    let build = |slide_interval| {
        Harness::builder()
            .session_config(SessionConfig {
                slide_interval,
                ..sliding_config()
            })
            .try_build()
    };

    let err = build(idle).err();
    assert!(
        matches!(err, Some(AssemblyError::IdleTimeoutInvalid { idle_timeout, .. }) if idle_timeout == idle),
        "a slide interval equal to the idle timeout is rejected, got {err:?}",
    );
    assert!(build(idle - Duration::from_secs(1)).is_ok());
}

#[test]
fn an_idle_timeout_does_not_bound_the_cache_ttl() {
    let built = Harness::builder()
        .session_config(SessionConfig {
            idle_timeout: Some(Duration::from_secs(2 * 60)),
            ..sliding_config()
        })
        .session_cache(full_cache(Duration::from_secs(5 * 60)))
        .try_build();
    assert!(built.is_ok());
}
