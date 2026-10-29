use doorman_core::session::hash_token;
use doorman_core::storage::{EmailLink, EmailLinkPurpose, ExpiringStores, UserId};

use crate::fixtures::{RACERS, days, link, present};

pub(crate) async fn email_link_single_use(stores: &ExpiringStores) {
    let user_id = UserId::new();

    let tokens = &stores.email_links;
    let hash = hash_token("single-use-token");
    tokens
        .replace_link(EmailLink {
            token_hash: hash,
            user_id,
            purpose: EmailLinkPurpose::Signup,
            owner_email: None,
            new_email: None,
            created_at: present(),
            expires_at: days(365),
        })
        .await
        .expect("create");

    assert!(
        tokens
            .redeem_link(&hash)
            .await
            .expect("first redeem")
            .is_some(),
        "first redeem returns the token",
    );
    assert!(
        tokens
            .redeem_link(&hash)
            .await
            .expect("second redeem")
            .is_none(),
        "second redeem returns nothing",
    );

    let signup_hash = hash_token("purpose-carrying-token");
    tokens
        .replace_link(EmailLink {
            token_hash: signup_hash,
            user_id,
            purpose: EmailLinkPurpose::Signup,
            owner_email: None,
            new_email: None,
            created_at: present(),
            expires_at: days(365),
        })
        .await
        .expect("create scoped");
    let redeemed = tokens
        .redeem_link(&signup_hash)
        .await
        .expect("redeem by hash")
        .expect("the link redeems by its hash alone");
    assert_eq!(
        redeemed.purpose,
        EmailLinkPurpose::Signup,
        "the link comes back with the purpose it was stored under",
    );
}

pub(crate) async fn email_link_email_change_payload(stores: &ExpiringStores) {
    let user_id = UserId::new();

    let tokens = &stores.email_links;
    let hash = hash_token("email-change-token");
    tokens
        .replace_link(EmailLink {
            token_hash: hash,
            user_id,
            purpose: EmailLinkPurpose::EmailChange,
            owner_email: Some("old-address@example.com".to_string()),
            new_email: Some("new-address@example.com".to_string()),
            created_at: present(),
            expires_at: days(365),
        })
        .await
        .expect("create email-change token");

    let redeemed = tokens
        .redeem_link(&hash)
        .await
        .expect("redeem")
        .expect("token present");
    assert_eq!(redeemed.purpose, EmailLinkPurpose::EmailChange);
    assert_eq!(
        redeemed.new_email.as_deref(),
        Some("new-address@example.com"),
        "the target address round-trips through storage",
    );
    assert_eq!(
        redeemed.owner_email.as_deref(),
        Some("old-address@example.com"),
        "the owner's address round-trips through storage",
    );
}

pub(crate) async fn email_link_replaces_its_owners_link(stores: &ExpiringStores) {
    let owner = UserId::new();
    let bystander = UserId::new();

    let links = &stores.email_links;
    let first = link("replace-first", owner, EmailLinkPurpose::Signup);
    let other_purpose = link("replace-other-purpose", owner, EmailLinkPurpose::Recovery);
    let other_owner = link("replace-other-owner", bystander, EmailLinkPurpose::Signup);
    let second = link("replace-second", owner, EmailLinkPurpose::Signup);
    for l in [&first, &other_purpose, &other_owner, &second] {
        links.replace_link(l.clone()).await.expect("replace link");
    }

    assert!(
        links
            .redeem_link(&first.token_hash)
            .await
            .expect("redeem replaced")
            .is_none(),
        "a link replaced by its owner's next link of the same purpose no longer redeems",
    );
    assert_eq!(
        links
            .redeem_link(&second.token_hash)
            .await
            .expect("redeem replacement"),
        Some(second),
        "the replacing link redeems",
    );
    assert_eq!(
        links
            .redeem_link(&other_purpose.token_hash)
            .await
            .expect("redeem other purpose"),
        Some(other_purpose),
        "the owner's link of another purpose survives",
    );
    assert_eq!(
        links
            .redeem_link(&other_owner.token_hash)
            .await
            .expect("redeem other owner"),
        Some(other_owner),
        "another user's link of the same purpose survives",
    );
}

pub(crate) async fn email_link_racing_replaces_leave_one_link(stores: &ExpiringStores) {
    let owner = UserId::new();
    let raced: Vec<EmailLink> = (0..RACERS)
        .map(|i| {
            link(
                &format!("replace-race-{i}"),
                owner,
                EmailLinkPurpose::Signup,
            )
        })
        .collect();

    let tasks: Vec<_> = raced
        .iter()
        .cloned()
        .map(|l| {
            let links = stores.email_links.clone();
            tokio::spawn(async move { links.replace_link(l).await })
        })
        .collect();
    for task in tasks {
        task.await
            .expect("racer task")
            .expect("every racing replace is accepted");
    }

    let mut live = 0;
    for l in &raced {
        if stores
            .email_links
            .redeem_link(&l.token_hash)
            .await
            .expect("redeem raced link")
            .is_some()
        {
            live += 1;
        }
    }
    assert_eq!(
        live, 1,
        "racing replaces of one owner's link of one purpose leave exactly one link"
    );
}

pub(crate) async fn email_link_replaces_racing_across_owners_keep_every_link(
    stores: &ExpiringStores,
) {
    let raced: Vec<EmailLink> = (0..RACERS)
        .map(|i| {
            link(
                &format!("replace-across-owners-{i}"),
                UserId::new(),
                EmailLinkPurpose::Recovery,
            )
        })
        .collect();

    let tasks: Vec<_> = raced
        .iter()
        .cloned()
        .map(|l| {
            let links = stores.email_links.clone();
            tokio::spawn(async move { links.replace_link(l).await })
        })
        .collect();
    for task in tasks {
        task.await
            .expect("racer task")
            .expect("every racing replace is accepted");
    }

    for l in &raced {
        assert_eq!(
            stores
                .email_links
                .redeem_link(&l.token_hash)
                .await
                .expect("redeem raced link"),
            Some(l.clone()),
            "racing replaces by different users keep every user's link",
        );
    }
}

pub(crate) async fn email_link_purge_and_delete(stores: &ExpiringStores) {
    let user_id = UserId::new();
    let bystander = UserId::new();

    let tokens = &stores.email_links;
    let signup = link("delete-signup", user_id, EmailLinkPurpose::Signup);
    let recovery = link("delete-recovery", user_id, EmailLinkPurpose::Recovery);
    let survivor = link("delete-bystander", bystander, EmailLinkPurpose::Signup);
    for l in [&signup, &recovery, &survivor] {
        tokens.replace_link(l.clone()).await.expect("create link");
    }

    let removed = tokens
        .delete_links_for_user(user_id)
        .await
        .expect("delete the user's links");
    assert_eq!(removed, 2, "every purpose's link was deleted");
    for deleted in [&signup, &recovery] {
        assert!(
            tokens
                .redeem_link(&deleted.token_hash)
                .await
                .expect("redeem deleted")
                .is_none(),
            "a deleted link no longer redeems",
        );
    }
    assert!(
        tokens
            .redeem_link(&survivor.token_hash)
            .await
            .expect("redeem surviving")
            .is_some(),
        "another user's link survived the delete",
    );

    let expired = EmailLink {
        created_at: days(-2),
        expires_at: days(-1),
        ..link("expired-token", user_id, EmailLinkPurpose::Signup)
    };
    tokens
        .replace_link(expired.clone())
        .await
        .expect("create expired");
    let purged = tokens.purge_expired(present()).await.expect("purge");
    assert!(purged >= 1, "at least the expired token was purged");
    assert!(
        tokens
            .redeem_link(&expired.token_hash)
            .await
            .expect("redeem purged")
            .is_none(),
        "the expired token was removed by purge_expired",
    );
}
