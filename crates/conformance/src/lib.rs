mod cross_store;
mod dpop_proofs;
mod email_links;
mod fixtures;
mod limits;
mod passkey_challenges;
mod passkeys;
mod runner;
mod sessions;
mod users;

use doorman_core::storage::{ExpiringStores, RecordStores, Storage};

use crate::cross_store::{
    absent_lookups_return_none, inserts_refuse_duplicate_keys, owner_indexes_track_removals,
    single_use_under_concurrency,
};
use crate::dpop_proofs::{
    dpop_proof_purge_expired, dpop_proof_single_use, dpop_proof_single_use_under_concurrency,
};
use crate::email_links::{
    email_link_email_change_payload, email_link_purge_and_delete,
    email_link_racing_replaces_leave_one_link, email_link_replaces_its_owners_link,
    email_link_replaces_racing_across_owners_keep_every_link, email_link_single_use,
};
use crate::limits::{expiring_hold_values_at_core_limits, records_hold_values_at_core_limits};
use crate::passkey_challenges::{
    passkey_authentication_single_use, passkey_challenge_purge_expired,
    passkey_registration_delete_for_user, passkey_registration_delete_races_creation,
    passkey_registration_round_trip,
};
use crate::passkeys::{
    passkey_field_changes_compose, passkey_writes_refuse_missing_passkey,
    passkeys_bulk_delete_for_user, passkeys_cool_down_round_trip,
};
use crate::runner::{Check, checks};
use crate::sessions::{
    session_revoke_races_creation, session_touch_does_not_resurrect, session_touch_races_revoke,
    session_touch_slides_deadline, sessions_crud_and_queries, sessions_purge_expired,
};
use crate::users::{
    users_email_change, users_email_matches_exactly, users_field_changes_compose, users_round_trip,
    users_setters_refuse_missing_user,
};

pub async fn run(storage: &Storage) {
    let records = runner::run(&storage.records, RECORD_CHECKS).await;
    let expiring = runner::run(&storage.expiring, EXPIRING_CHECKS).await;
    records.merge(expiring).assert_passed();
}

pub async fn run_records(stores: &RecordStores) {
    runner::run(stores, RECORD_CHECKS).await.assert_passed();
}

pub async fn run_expiring(stores: &ExpiringStores) {
    runner::run(stores, EXPIRING_CHECKS).await.assert_passed();
}

const RECORD_CHECKS: &[Check<RecordStores>] = checks![
    users_round_trip,
    users_email_change,
    users_email_matches_exactly,
    records_hold_values_at_core_limits,
    users_field_changes_compose,
    users_setters_refuse_missing_user,
    passkeys_cool_down_round_trip,
    passkey_field_changes_compose,
    passkey_writes_refuse_missing_passkey,
    passkeys_bulk_delete_for_user,
];

const EXPIRING_CHECKS: &[Check<ExpiringStores>] = checks![
    email_link_single_use,
    email_link_email_change_payload,
    email_link_replaces_its_owners_link,
    email_link_racing_replaces_leave_one_link,
    email_link_replaces_racing_across_owners_keep_every_link,
    email_link_purge_and_delete,
    sessions_crud_and_queries,
    sessions_purge_expired,
    session_touch_slides_deadline,
    session_touch_does_not_resurrect,
    session_touch_races_revoke,
    session_revoke_races_creation,
    passkey_registration_round_trip,
    passkey_registration_delete_for_user,
    passkey_registration_delete_races_creation,
    passkey_authentication_single_use,
    single_use_under_concurrency,
    passkey_challenge_purge_expired,
    dpop_proof_single_use,
    dpop_proof_single_use_under_concurrency,
    dpop_proof_purge_expired,
    owner_indexes_track_removals,
    absent_lookups_return_none,
    inserts_refuse_duplicate_keys,
    expiring_hold_values_at_core_limits,
];
