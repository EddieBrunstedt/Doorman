//! `SessionResolver::resolve`: the cache hit/miss path, the expiry re-check on
//! a hit, eviction on revocation, the account-status gate, and idle sliding —
//! all through the one request-time operation, with no HTTP.

mod common;

use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use doorman_core::Error;
use doorman_core::assembly::AssemblyError;
use doorman_core::audit::OperatorActor;
use doorman_core::cache::SessionCacheConfig;
use doorman_core::clock::Clock;
use doorman_core::metrics::MetricEvent;
use doorman_core::resolve::SessionResolver;
use doorman_core::session::{SessionConfig, SessionContext, hash_token};
use doorman_core::storage::{AccountStatus, SessionStore, User, UserStore};

use common::{Harness, make_user};

/// One hour absolute, ten minute idle — with the default 60s cache TTL, which
/// is also the touch throttle.
fn sliding_config() -> SessionConfig {
    SessionConfig {
        absolute_lifetime: Duration::from_secs(60 * 60),
        idle_timeout: Some(Duration::from_secs(60 * 10)),
        max_sessions_per_user: None,
    }
}

fn sliding_harness() -> Harness {
    Harness::builder().session_config(sliding_config()).build()
}

/// Provision a user and issue a session for them, returning the token.
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
    let h = Harness::fresh();
    let (user, token) = signed_in(&h, "alice@example.com").await;

    let first = h.resolver.resolve(&token).await.expect("first resolve");
    assert_eq!(first.user.id, user.id);
    assert_eq!(first.session.user_id, user.id);
    assert_eq!((hits(&h), misses(&h)), (0, 1), "a cold token misses");

    // Delete the row behind the resolver's back (no invalidation hook fires):
    // the warm entry still serves it, proving a hit never reads storage.
    h.sessions
        .delete_session(first.session.id)
        .await
        .expect("delete session row");
    let second = h.resolver.resolve(&token).await.expect("warm resolve");
    assert!(Arc::ptr_eq(&first.session, &second.session));
    assert_eq!((hits(&h), misses(&h)), (1, 1), "a warm token hits");

    // Once the entry ages past the TTL the unhooked deletion is observed.
    h.clock.advance(ChronoDuration::seconds(60));
    let err = h.resolver.resolve(&token).await.err();
    assert!(
        matches!(err, Some(Error::SessionNotFound)),
        "a stale entry re-reads storage, got {err:?}",
    );
}

#[tokio::test]
async fn unknown_token_is_refused() {
    let h = Harness::fresh();
    let err = h.resolver.resolve("not-a-session").await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
}

/// A warm entry whose session deadline has passed is a miss, even though the
/// entry itself is still inside the cache TTL.
#[tokio::test]
async fn warm_entry_past_its_session_deadline_is_not_served() {
    let h = Harness::builder()
        .session_config(SessionConfig {
            absolute_lifetime: Duration::from_secs(30),
            ..SessionConfig::default()
        })
        .build();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.resolver.resolve(&token).await.expect("warm the cache");

    h.clock.advance(ChronoDuration::seconds(31));
    let err = h.resolver.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionExpired)), "got {err:?}");
    assert_eq!(hits(&h), 0, "the expired snapshot was never served");
}

#[tokio::test]
async fn revoke_evicts_the_warm_entry() {
    let h = Harness::fresh();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.resolver.resolve(&token).await.expect("warm the cache");

    h.session_manager.revoke(&token).await.expect("revoke");
    let err = h.resolver.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
    assert_eq!(hits(&h), 0);
}

#[tokio::test]
async fn revoke_all_for_user_evicts_every_warm_entry() {
    let h = Harness::fresh();
    let (user, first) = signed_in(&h, "bob@example.com").await;
    let second = h
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("second session")
        .token;
    h.resolver.resolve(&first).await.expect("warm first");
    h.resolver.resolve(&second).await.expect("warm second");

    let removed = h
        .session_manager
        .revoke_all_for_user(user.id)
        .await
        .expect("revoke all");
    assert_eq!(removed, 2);
    for token in [&first, &second] {
        let err = h.resolver.resolve(token).await.err();
        assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
    }
    assert_eq!(hits(&h), 0);
}

#[tokio::test]
async fn disabled_account_is_refused_and_never_cached() {
    let h = Harness::fresh();
    let (user, token) = signed_in(&h, "frozen@example.com").await;
    let now = h.clock.now();
    h.users
        .set_user_status(user.id, AccountStatus::Disabled { at: now }, now)
        .await
        .expect("disable");

    for _ in 0..2 {
        let err = h.resolver.resolve(&token).await.err();
        assert!(matches!(err, Some(Error::AccountDisabled)), "got {err:?}");
    }
    assert_eq!(
        (hits(&h), misses(&h)),
        (0, 2),
        "a refused session is never cached",
    );
}

/// The operator flow revokes the live sessions, so the warm entry of a
/// just-disabled user is evicted rather than served until its TTL.
#[tokio::test]
async fn operator_disable_evicts_the_warm_entry() {
    let h = Harness::fresh();
    let (user, token) = signed_in(&h, "locked@example.com").await;
    h.resolver.resolve(&token).await.expect("warm the cache");

    let actor = OperatorActor::new("support-agent-7", None, None, None).expect("operator actor");
    h.operator.disable(user.id, actor).await.expect("disable");

    let err = h.resolver.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::SessionNotFound)), "got {err:?}");
    assert_eq!(hits(&h), 0);
}

#[tokio::test]
async fn session_whose_owner_is_gone_is_refused() {
    let h = Harness::fresh();
    let (user, token) = signed_in(&h, "gone@example.com").await;
    h.users.delete_user(user.id).await.expect("delete user row");

    let err = h.resolver.resolve(&token).await.err();
    assert!(matches!(err, Some(Error::UserNotFound)), "got {err:?}");
}

// ----- idle sliding ----------------------------------------------------

/// A miss more than one TTL after the last touch slides the deadline to one
/// idle window from now, persists it, and reports the slide.
#[tokio::test]
async fn miss_after_the_throttle_slides_and_reports_it() {
    let h = sliding_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;

    h.clock.advance(ChronoDuration::seconds(90));
    let now = h.clock.now();
    let resolved = h.resolver.resolve(&token).await.expect("resolve");
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
    let h = sliding_harness();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    h.clock.advance(ChronoDuration::seconds(90));
    let slid = h.resolver.resolve(&token).await.expect("slide");

    h.clock.advance(ChronoDuration::seconds(30));
    let hit = h.resolver.resolve(&token).await.expect("hit");
    assert!(!hit.slid);
    assert_eq!(hit.session.expires_at, slid.session.expires_at);
    assert_eq!(hits(&h), 1);
}

/// A miss within one TTL of the last touch (here forced by evicting the
/// entry) does not write: the throttle is the cache TTL.
#[tokio::test]
async fn miss_within_the_throttle_does_not_slide() {
    let h = sliding_harness();
    let (user, token) = signed_in(&h, "alice@example.com").await;
    h.clock.advance(ChronoDuration::seconds(90));
    let first = h.resolver.resolve(&token).await.expect("slide");

    h.resolver.cache().invalidate_user(user.id);
    h.clock.advance(ChronoDuration::seconds(30));
    let second = h.resolver.resolve(&token).await.expect("miss");
    assert!(!second.slid);
    assert_eq!(second.session.expires_at, first.session.expires_at);
    assert_eq!(second.session.last_used_at, first.session.last_used_at);
}

/// Sliding never carries a session past `created_at + absolute_lifetime`.
#[tokio::test]
async fn slide_is_clamped_at_the_absolute_cap() {
    let h = sliding_harness();
    let start = h.clock.now();
    let (_, token) = signed_in(&h, "alice@example.com").await;
    let cap = start + ChronoDuration::minutes(60);

    // Every five minutes (each a miss past the TTL, so each slides) until 55
    // minutes in, where now + idle would overshoot the cap.
    let mut last = None;
    for _ in 0..11 {
        h.clock.advance(ChronoDuration::minutes(5));
        let resolved = h.resolver.resolve(&token).await.expect("resolve");
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
    let resolved = h.resolver.resolve(&token).await.expect("resolve");
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

    let err = h.resolver.resolve(&token).await.err();
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

/// `SessionManager::validate` is a read: only `resolve` slides.
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

// ----- the cache-TTL / idle invariant -------------------------------------

#[test]
fn cache_ttl_must_be_strictly_below_the_idle_timeout() {
    let h = sliding_harness();
    let idle = Duration::from_secs(60 * 10);
    let build = |ttl| {
        SessionResolver::new(
            h.session_manager.clone(),
            h.users.clone() as Arc<dyn UserStore>,
            SessionCacheConfig {
                ttl,
                ..SessionCacheConfig::default()
            },
        )
    };

    let err = build(idle).err();
    assert!(
        matches!(err, Some(AssemblyError::IdleTimeoutInvalid { idle_timeout, .. }) if idle_timeout == idle),
        "a ttl equal to the idle timeout is rejected, got {err:?}",
    );
    assert!(build(idle - Duration::from_secs(1)).is_ok());
}

#[test]
fn without_an_idle_timeout_any_ttl_is_accepted() {
    let h = Harness::fresh();
    let resolver = SessionResolver::new(
        h.session_manager.clone(),
        h.users.clone() as Arc<dyn UserStore>,
        SessionCacheConfig {
            ttl: Duration::from_secs(60 * 60 * 24),
            ..SessionCacheConfig::default()
        },
    );
    assert!(resolver.is_ok());
}
