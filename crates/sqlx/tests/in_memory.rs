//! Runs the storage-conformance suite against the in-memory reference
//! stores in `bauth-core`. This verifies the stores the docs point hosts
//! at as a worked reference actually satisfy the same contract enforced
//! against the SQLx adapters, with no database or feature flag required.

mod conformance;

use std::sync::Arc;

use bauth_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::storage::Storage;

#[tokio::test]
async fn in_memory_storage_conformance() {
    let storage = Storage {
        users: Arc::new(InMemoryUserStore::new()),
        sessions: Arc::new(InMemorySessionStore::new()),
        verification_tokens: Arc::new(InMemoryVerificationTokenStore::new()),
        passkey_credentials: Arc::new(InMemoryPasskeyCredentialStore::new()),
        passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
    };
    conformance::run(&storage).await;
}
