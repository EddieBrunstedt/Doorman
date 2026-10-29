use chrono::Duration;
use doorman_core::error::StorageErrorKind;
use doorman_core::storage::{PasskeyUse, RecordStores, StoredPasskey, UserId};

use crate::fixtures::{assert_refused, days, passkey, present};

pub(crate) async fn passkeys_cool_down_round_trip(stores: &RecordStores) {
    let now = present();
    let user_id = UserId::new();

    let credential_id = b"conformance-passkey-id".to_vec();
    let passkey_blob = b"opaque-serialised-passkey-blob".to_vec();
    let cool_down_until = now + Duration::hours(24);
    let aaguid = uuid::Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
    let passkey = StoredPasskey {
        credential_id: credential_id.clone(),
        user_id,
        passkey: passkey_blob.clone(),
        name: Some("security key".into()),
        created_at: now,
        last_used_at: None,
        aaguid: Some(aaguid),
        transports: vec!["usb".into(), "nfc".into()],
        backup_eligible: false,
        backup_state: false,
        recovery_cool_down_until: Some(cool_down_until),
    };

    let passkeys = &stores.passkeys;
    passkeys
        .add_passkey(passkey.clone())
        .await
        .expect("create passkey");

    let by_id = passkeys
        .find_passkey_by_credential_id(&passkey.credential_id)
        .await
        .expect("find by credential id")
        .expect("passkey present");
    assert_eq!(by_id.user_id, user_id);
    assert_eq!(by_id.name.as_deref(), Some("security key"));
    assert_eq!(by_id.passkey, passkey_blob, "blob round-trips verbatim");
    assert_eq!(by_id.aaguid, Some(aaguid), "aaguid round-trips");
    assert_eq!(by_id.transports, vec!["usb".to_string(), "nfc".to_string()]);
    assert!(!by_id.backup_eligible);
    assert!(!by_id.backup_state);
    assert_eq!(by_id.recovery_cool_down_until, Some(cool_down_until));

    let updated_blob = b"opaque-serialised-passkey-blob-v2".to_vec();
    let used_at = now + Duration::minutes(5);
    passkeys
        .record_passkey_use(
            &credential_id,
            PasskeyUse {
                passkey: updated_blob.clone(),
                backup_eligible: true,
                backup_state: true,
                used_at,
            },
        )
        .await
        .expect("record use");
    passkeys
        .set_passkey_name(&credential_id, Some("renamed security key"))
        .await
        .expect("rename passkey");
    let updated = StoredPasskey {
        passkey: updated_blob.clone(),
        name: Some("renamed security key".into()),
        last_used_at: Some(used_at),
        backup_eligible: true,
        backup_state: true,
        ..by_id
    };

    let listed = passkeys
        .list_passkeys_for_user(user_id)
        .await
        .expect("list passkeys");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].credential_id, updated.credential_id);
    assert_eq!(listed[0].passkey, updated_blob, "updated blob round-trips");
    assert_eq!(listed[0].name.as_deref(), Some("renamed security key"));
    assert_eq!(listed[0].last_used_at, updated.last_used_at);
    assert_eq!(listed[0].aaguid, Some(aaguid), "aaguid preserved on update");
    assert_eq!(
        listed[0].transports,
        vec!["usb".to_string(), "nfc".to_string()],
        "transports preserved on update",
    );
    assert!(listed[0].backup_eligible, "backup flags refreshed on use");
    assert!(listed[0].backup_state);
    assert_eq!(
        listed[0].recovery_cool_down_until,
        Some(cool_down_until),
        "cool-down preserved on update",
    );

    let other_user_id = UserId::new();
    let hijack = StoredPasskey {
        credential_id: credential_id.clone(),
        user_id: other_user_id,
        passkey: b"hijacker-blob".to_vec(),
        name: Some("hijacker key".into()),
        created_at: now,
        last_used_at: None,
        aaguid: None,
        transports: vec![],
        backup_eligible: false,
        backup_state: false,
        recovery_cool_down_until: None,
    };
    assert_refused(
        passkeys.add_passkey(hijack).await,
        StorageErrorKind::Conflict,
        "duplicate credential id should error",
    );

    let still_owned = passkeys
        .find_passkey_by_credential_id(&credential_id)
        .await
        .expect("find by credential id after duplicate attempt")
        .expect("passkey still present");
    assert_eq!(
        still_owned.user_id, user_id,
        "the original owner is preserved after a duplicate-id attempt",
    );
}

pub(crate) async fn passkey_field_changes_compose(stores: &RecordStores) {
    let created_at = days(151);
    let used_at = days(152);
    let user_id = UserId::new();
    let passkeys = &stores.passkeys;
    let used = || PasskeyUse {
        passkey: b"opaque-serialised-passkey-blob-advanced".to_vec(),
        backup_eligible: true,
        backup_state: true,
        used_at,
    };

    for (credential_id, use_first) in [
        (&b"compose-use-first"[..], true),
        (&b"compose-rename-first"[..], false),
    ] {
        passkeys
            .add_passkey(passkey(user_id, credential_id, created_at))
            .await
            .expect("add passkey");
        if use_first {
            passkeys
                .record_passkey_use(credential_id, used())
                .await
                .expect("record use");
        }
        passkeys
            .set_passkey_name(credential_id, Some("laptop"))
            .await
            .expect("rename");
        if !use_first {
            passkeys
                .record_passkey_use(credential_id, used())
                .await
                .expect("record use");
        }

        let reread = passkeys
            .find_passkey_by_credential_id(credential_id)
            .await
            .expect("find")
            .expect("present");
        assert_eq!(
            reread.passkey,
            used().passkey,
            "the rename kept the recorded blob (use first: {use_first})",
        );
        assert_eq!(reread.last_used_at, Some(used_at));
        assert!(reread.backup_eligible && reread.backup_state);
        assert_eq!(
            reread.name.as_deref(),
            Some("laptop"),
            "the recorded use kept the rename (use first: {use_first})",
        );
        assert_eq!(reread.user_id, user_id, "the owner never moves");
        assert_eq!(reread.created_at, created_at, "registration time is fixed");
    }

    passkeys
        .set_passkey_name(b"compose-use-first", None)
        .await
        .expect("clear name");
    let cleared = passkeys
        .find_passkey_by_credential_id(b"compose-use-first")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(cleared.name, None, "a cleared name reads back as none");
    assert_eq!(cleared.last_used_at, Some(used_at));
}

pub(crate) async fn passkey_writes_refuse_missing_passkey(stores: &RecordStores) {
    let passkeys = &stores.passkeys;
    let missing = b"conformance-missing-passkey";
    assert_refused(
        passkeys
            .record_passkey_use(
                missing,
                PasskeyUse {
                    passkey: b"ghost-blob".to_vec(),
                    backup_eligible: false,
                    backup_state: false,
                    used_at: days(151),
                },
            )
            .await,
        StorageErrorKind::NotFound,
        "use of a missing passkey",
    );
    assert_refused(
        passkeys.set_passkey_name(missing, Some("ghost")).await,
        StorageErrorKind::NotFound,
        "rename of a missing passkey",
    );
    assert!(
        passkeys
            .find_passkey_by_credential_id(missing)
            .await
            .expect("find missing")
            .is_none(),
        "no write creates the passkey",
    );
}

pub(crate) async fn passkeys_bulk_delete_for_user(stores: &RecordStores) {
    let now = present();
    let target = UserId::new();
    let bystander = UserId::new();

    let passkeys = &stores.passkeys;
    let add = |user_id: UserId, credential_id: Vec<u8>| {
        let passkey = StoredPasskey {
            credential_id,
            user_id,
            passkey: b"opaque-serialised-passkey-blob".to_vec(),
            name: Some("security key".into()),
            created_at: now,
            last_used_at: None,
            aaguid: None,
            transports: vec!["usb".into()],
            backup_eligible: false,
            backup_state: false,
            recovery_cool_down_until: None,
        };
        async move {
            passkeys.add_passkey(passkey).await.expect("add passkey");
        }
    };

    add(target, b"bulk-delete-target-passkey-1".to_vec()).await;
    add(target, b"bulk-delete-target-passkey-2".to_vec()).await;
    add(target, b"bulk-delete-target-passkey-3".to_vec()).await;
    let bystander_passkey = b"bulk-delete-bystander-passkey".to_vec();
    add(bystander, bystander_passkey.clone()).await;

    let count = |user_id: UserId| async move {
        passkeys
            .list_passkeys_for_user(user_id)
            .await
            .expect("count passkeys")
            .len()
    };
    assert_eq!(count(target).await, 3, "count covers the owner's passkeys");
    assert_eq!(count(bystander).await, 1, "count excludes other users");
    passkeys
        .delete_passkey(b"bulk-delete-target-passkey-3")
        .await
        .expect("delete one passkey");
    assert_eq!(count(target).await, 2, "count drops after a single removal");

    let removed = passkeys
        .delete_passkeys_for_user(target)
        .await
        .expect("delete passkeys for user");
    assert_eq!(
        removed, 2,
        "the return count equals the target user's passkey count",
    );
    assert_eq!(
        count(target).await,
        0,
        "count is zero after the bulk delete"
    );
    assert_eq!(
        count(bystander).await,
        1,
        "another user's count is untouched"
    );

    assert!(
        passkeys
            .list_passkeys_for_user(target)
            .await
            .expect("list target after delete")
            .is_empty(),
        "all of the target user's passkeys are removed",
    );

    let surviving = passkeys
        .list_passkeys_for_user(bystander)
        .await
        .expect("list bystander after delete");
    assert_eq!(surviving.len(), 1, "another user's passkey survives");
    assert_eq!(surviving[0].credential_id, bystander_passkey);
}
