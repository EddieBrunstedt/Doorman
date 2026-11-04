use chrono::{DateTime, Duration, Utc};
use doorman_core::session::hash_token;
use doorman_core::storage::{ExpiringStores, Session, SessionId, SessionTransport, UserId};

use crate::fixtures::{RACERS, REVOKE_ROUNDS, days, dpop, present};

pub(crate) async fn sessions_crud_and_queries(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();
    let other_user = UserId::new();

    let sessions = &stores.sessions;
    let mk = |token: &str,
              owner: UserId,
              transport: SessionTransport,
              cool_down: Option<DateTime<Utc>>| Session {
        id: SessionId::new(),
        user_id: owner,
        token_hash: hash_token(token),
        transport,
        created_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(1),
        ip: "203.0.113.1".parse().expect("client IP"),
        user_agent: Some("agent".into()),
        recovery_cool_down_until: cool_down,
    };

    let keep = mk("keep", user_id, SessionTransport::Cookie, None);
    let other_a = mk("other-a", user_id, SessionTransport::Cookie, None);
    let other_b = mk("other-b", user_id, SessionTransport::Cookie, None);
    let neighbour = mk("neighbour", other_user, SessionTransport::Cookie, None);
    let cool_down_until = now + Duration::hours(24);
    let with_cool_down = mk("cool-down", user_id, dpop(1), Some(cool_down_until));

    for session in [&keep, &other_a, &other_b, &neighbour, &with_cool_down] {
        sessions
            .create_session(session.clone())
            .await
            .expect("create session");
    }

    let by_hash = sessions
        .find_session_by_token_hash(&hash_token("cool-down"))
        .await
        .expect("find by hash")
        .expect("session present");
    assert_eq!(by_hash.id, with_cool_down.id);
    assert_eq!(by_hash.transport, dpop(1));
    assert_eq!(by_hash.recovery_cool_down_until, Some(cool_down_until));
    assert_eq!(by_hash.ip.to_string(), "203.0.113.1");

    let by_id = sessions
        .find_session_by_id(with_cool_down.id)
        .await
        .expect("find by id")
        .expect("session present");
    assert_eq!(by_id.transport, dpop(1));
    assert_eq!(by_id.recovery_cool_down_until, Some(cool_down_until));

    let listed = sessions.list_for_user(user_id).await.expect("list");
    let listed_ids: std::collections::HashSet<_> = listed.iter().map(|s| s.id).collect();
    let expected: std::collections::HashSet<_> =
        [keep.id, other_a.id, other_b.id, with_cool_down.id].into();
    assert_eq!(
        listed_ids, expected,
        "list returns only this user's sessions"
    );
    for session in &listed {
        let expected = if session.id == with_cool_down.id {
            dpop(1)
        } else {
            SessionTransport::Cookie
        };
        assert_eq!(
            session.transport, expected,
            "list keeps each session's transport"
        );
    }

    let removed = sessions
        .delete_sessions_for_user(user_id, Some(keep.id))
        .await
        .expect("delete others");
    assert_eq!(removed, 3, "every session except the exception was removed");
    let after = sessions.list_for_user(user_id).await.expect("list after");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, keep.id);

    assert!(
        sessions
            .find_session_by_id(neighbour.id)
            .await
            .expect("find neighbour")
            .is_some()
    );

    let removed = sessions
        .delete_sessions_for_user(user_id, None)
        .await
        .expect("delete all");
    assert_eq!(removed, 1, "the surviving session was removed");
    assert!(
        sessions
            .list_for_user(user_id)
            .await
            .expect("list cleared")
            .is_empty()
    );
    sessions
        .delete_session(neighbour.id)
        .await
        .expect("delete neighbour");
    assert!(
        sessions
            .find_session_by_id(neighbour.id)
            .await
            .expect("find deleted neighbour")
            .is_none()
    );
}

pub(crate) async fn sessions_purge_expired(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let sessions = &stores.sessions;
    let expired = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("expired-session"),
        transport: SessionTransport::Cookie,
        created_at: now - Duration::hours(2),
        last_used_at: now - Duration::hours(2),
        expires_at: now - Duration::hours(1),
        ip: "192.0.2.1".parse().expect("client IP"),
        user_agent: None,
        recovery_cool_down_until: None,
    };
    let live = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("live-session"),
        transport: SessionTransport::Cookie,
        created_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(1),
        ip: "192.0.2.1".parse().expect("client IP"),
        user_agent: None,
        recovery_cool_down_until: None,
    };
    sessions
        .create_session(expired.clone())
        .await
        .expect("create expired");
    sessions
        .create_session(live.clone())
        .await
        .expect("create live");

    let removed = sessions.purge_expired(now).await.expect("purge");
    assert!(removed >= 1, "at least the expired session was purged");
    assert!(
        sessions
            .find_session_by_id(expired.id)
            .await
            .expect("find expired")
            .is_none(),
        "the expired session was purged",
    );
    assert!(
        sessions
            .find_session_by_id(live.id)
            .await
            .expect("find live")
            .is_some(),
        "the live session survived the purge",
    );
}

pub(crate) async fn session_touch_slides_deadline(stores: &ExpiringStores) {
    let created_at = present();
    let user_id = UserId::new();

    let sessions = &stores.sessions;
    let token_hash = hash_token("touch-slide");
    let original = Session {
        id: SessionId::new(),
        user_id,
        token_hash,
        transport: dpop(2),
        created_at,
        last_used_at: created_at,
        expires_at: days(365),
        ip: "203.0.113.9".parse().expect("client IP"),
        user_agent: Some("touch-agent".into()),
        recovery_cool_down_until: Some(days(516)),
    };
    sessions
        .create_session(original.clone())
        .await
        .expect("create session");

    let new_last_used_at = days(31);
    let new_expires_at = days(424);
    sessions
        .touch_session(original.id, new_last_used_at, new_expires_at)
        .await
        .expect("touch session");

    let by_id = sessions
        .find_session_by_id(original.id)
        .await
        .expect("find by id")
        .expect("session present after touch");
    assert_eq!(by_id.last_used_at, new_last_used_at, "last_used_at slid");
    assert_eq!(by_id.expires_at, new_expires_at, "expires_at slid");

    let by_hash = sessions
        .find_session_by_token_hash(&token_hash)
        .await
        .expect("find by hash")
        .expect("session present after touch by hash");
    assert_eq!(by_hash.last_used_at, new_last_used_at);
    assert_eq!(by_hash.expires_at, new_expires_at);

    assert_eq!(by_id.id, original.id);
    assert_eq!(by_id.token_hash, original.token_hash);
    assert_eq!(by_id.created_at, original.created_at);
    assert_eq!(by_id.ip, original.ip);
    assert_eq!(by_id.user_agent, original.user_agent);
    assert_eq!(
        by_id.recovery_cool_down_until,
        original.recovery_cool_down_until,
    );

    sessions
        .purge_expired(days(400))
        .await
        .expect("purge between the old and new deadlines");
    assert!(
        sessions
            .find_session_by_id(original.id)
            .await
            .expect("find after purge")
            .is_some(),
        "purge past the old deadline keeps the touched session",
    );

    sessions
        .delete_session(original.id)
        .await
        .expect("cleanup session");
}

pub(crate) async fn session_touch_does_not_resurrect(stores: &ExpiringStores) {
    let created_at = present();
    let user_id = UserId::new();

    let sessions = &stores.sessions;

    let phantom = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("touch-never-created"),
        transport: SessionTransport::Cookie,
        created_at,
        last_used_at: created_at,
        expires_at: days(365),
        ip: "192.0.2.1".parse().expect("client IP"),
        user_agent: None,
        recovery_cool_down_until: None,
    };
    sessions
        .touch_session(phantom.id, created_at, days(396))
        .await
        .expect("touch of never-created id is Ok");
    assert!(
        sessions
            .find_session_by_id(phantom.id)
            .await
            .expect("find never-created")
            .is_none(),
        "touching a never-created id must not create a row",
    );

    let revoked = Session {
        token_hash: hash_token("touch-after-delete"),
        transport: SessionTransport::Cookie,
        ..phantom.clone()
    };
    let revoked = Session {
        id: SessionId::new(),
        ..revoked
    };
    sessions
        .create_session(revoked.clone())
        .await
        .expect("create revoked");
    sessions
        .delete_session(revoked.id)
        .await
        .expect("delete revoked");
    sessions
        .touch_session(revoked.id, created_at, days(396))
        .await
        .expect("touch of deleted id is Ok");
    assert!(
        sessions
            .find_session_by_id(revoked.id)
            .await
            .expect("find deleted")
            .is_none(),
        "touching a deleted id must not resurrect the session",
    );
    assert!(
        sessions
            .find_session_by_token_hash(&revoked.token_hash)
            .await
            .expect("find deleted by hash")
            .is_none(),
        "the resurrected row must not be reachable by token hash either",
    );
}

pub(crate) async fn session_touch_races_revoke(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let raced: Vec<Session> = (0..RACERS)
        .map(|i| Session {
            id: SessionId::new(),
            user_id,
            token_hash: hash_token(&format!("touch-race-{i}")),
            transport: SessionTransport::Cookie,
            created_at: now,
            last_used_at: now,
            expires_at: days(365),
            ip: "192.0.2.1".parse().expect("client IP"),
            user_agent: None,
            recovery_cool_down_until: None,
        })
        .collect();
    for session in &raced {
        stores
            .sessions
            .create_session(session.clone())
            .await
            .expect("create raced session");
    }

    let mut tasks = Vec::new();
    for (i, session) in raced.iter().enumerate() {
        let id = session.id;
        let touch = {
            let sessions = stores.sessions.clone();
            async move {
                sessions
                    .touch_session(id, days(1), days(366))
                    .await
                    .expect("touch");
            }
        };
        let delete = {
            let sessions = stores.sessions.clone();
            async move { sessions.delete_session(id).await.expect("delete") }
        };
        // A delete started first lets its touch read the row before the delete
        // lands and write after it.
        if i % 2 == 0 {
            tasks.push(tokio::spawn(delete));
            tasks.push(tokio::spawn(touch));
        } else {
            tasks.push(tokio::spawn(touch));
            tasks.push(tokio::spawn(delete));
        }
    }
    for task in tasks {
        task.await.expect("race task");
    }

    for session in &raced {
        assert!(
            stores
                .sessions
                .find_session_by_id(session.id)
                .await
                .expect("find raced session")
                .is_none(),
            "a touch racing a delete must not resurrect the session",
        );
        assert!(
            stores
                .sessions
                .find_session_by_token_hash(&session.token_hash)
                .await
                .expect("find raced session by hash")
                .is_none(),
            "a touch racing a delete must not leave the session reachable by token hash",
        );
    }
    assert!(
        stores
            .sessions
            .list_for_user(user_id)
            .await
            .expect("list raced user")
            .is_empty(),
        "a touch racing a delete must not leave the session listed",
    );
}

pub(crate) async fn session_revoke_races_creation(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let session = |token: String| Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token(&token),
        transport: SessionTransport::Cookie,
        created_at: now,
        last_used_at: now,
        expires_at: days(365),
        ip: "192.0.2.1".parse().expect("client IP"),
        user_agent: None,
        recovery_cool_down_until: None,
    };
    let create = |session: Session| {
        let sessions = stores.sessions.clone();
        tokio::spawn(async move {
            sessions
                .create_session(session)
                .await
                .expect("create session");
        })
    };

    let mut created = Vec::new();
    for round in 0..REVOKE_ROUNDS {
        let kept = session(format!("revoke-race-{round}-kept"));
        stores
            .sessions
            .create_session(kept.clone())
            .await
            .expect("create kept session");
        let except = (round % 2 == 1).then_some(kept.id);

        let batch: Vec<Session> = (0..RACERS)
            .map(|i| session(format!("revoke-race-{round}-{i}")))
            .collect();
        let (before, after) = batch.split_at(RACERS / 2);
        let mut tasks: Vec<_> = before.iter().cloned().map(create).collect();
        let sessions = stores.sessions.clone();
        tasks.push(tokio::spawn(async move {
            sessions
                .delete_sessions_for_user(user_id, except)
                .await
                .expect("revoke");
        }));
        tasks.extend(after.iter().cloned().map(create));
        for task in tasks {
            task.await.expect("race task");
        }

        let kept_resolves = stores
            .sessions
            .find_session_by_token_hash(&kept.token_hash)
            .await
            .expect("find kept session")
            .is_some();
        assert_eq!(
            kept_resolves,
            except.is_some(),
            "a revoke deletes the pre-existing session unless it is the exception",
        );
        created.push(kept);
        created.extend(batch);
    }

    let listed: std::collections::HashSet<_> = stores
        .sessions
        .list_for_user(user_id)
        .await
        .expect("list")
        .iter()
        .map(|s| s.id)
        .collect();
    for s in &created {
        let resolves = stores
            .sessions
            .find_session_by_token_hash(&s.token_hash)
            .await
            .expect("find by hash")
            .is_some();
        assert!(
            !resolves || listed.contains(&s.id),
            "a session that survived a racing revoke is still listed",
        );
    }

    let removed = stores
        .sessions
        .delete_sessions_for_user(user_id, None)
        .await
        .expect("second revoke");
    assert_eq!(
        removed,
        listed.len() as u64,
        "the second revoke removes every survivor",
    );
    for s in &created {
        assert!(
            stores
                .sessions
                .find_session_by_token_hash(&s.token_hash)
                .await
                .expect("find by hash after second revoke")
                .is_none(),
            "no session resolves after the second revoke",
        );
    }
}
