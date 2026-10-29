use chrono::{DateTime, Utc};
use doorman_core::session::hash_token;
use doorman_core::storage::{DpopProofId, ExpiringStores, UsedDpopProof};
use uuid::Uuid;

use crate::fixtures::{RACERS, days, present};

fn proof(expires_at: DateTime<Utc>) -> UsedDpopProof {
    UsedDpopProof {
        id: DpopProofId(hash_token(&Uuid::new_v4().to_string()).0),
        expires_at,
    }
}

pub(crate) async fn dpop_proof_single_use(stores: &ExpiringStores) {
    let proofs = &stores.dpop_proofs;
    let used = proof(days(1));
    assert!(
        proofs.use_proof(used.clone()).await.expect("first use"),
        "a proof's first use is accepted",
    );
    assert!(
        !proofs.use_proof(used.clone()).await.expect("second use"),
        "a proof's second use is refused",
    );
    assert!(
        !proofs
            .use_proof(UsedDpopProof {
                expires_at: days(2),
                ..used
            })
            .await
            .expect("use with another deadline"),
        "a proof is refused by its id alone",
    );
    assert!(
        proofs
            .use_proof(proof(days(1)))
            .await
            .expect("another proof"),
        "another proof is accepted",
    );
}

pub(crate) async fn dpop_proof_single_use_under_concurrency(stores: &ExpiringStores) {
    let used = proof(days(1));
    let racers: Vec<_> = (0..RACERS)
        .map(|_| {
            let proofs = stores.dpop_proofs.clone();
            let used = used.clone();
            tokio::spawn(async move { proofs.use_proof(used).await.expect("use proof") })
        })
        .collect();
    let mut accepted = 0;
    for racer in racers {
        if racer.await.expect("racer task") {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 1, "exactly one caller uses the proof");
}

pub(crate) async fn dpop_proof_purge_expired(stores: &ExpiringStores) {
    let proofs = &stores.dpop_proofs;
    let expired = proof(days(-1));
    let live = proof(days(1));
    for used in [&expired, &live] {
        assert!(proofs.use_proof(used.clone()).await.expect("use proof"));
    }
    let purged = proofs.purge_expired(present()).await.expect("purge");
    assert!(purged >= 1, "the expired proof was purged");
    assert!(
        proofs.use_proof(expired).await.expect("use purged proof"),
        "the expired proof was removed by purge_expired",
    );
    assert!(
        !proofs.use_proof(live).await.expect("reuse live proof"),
        "the live proof survived the purge",
    );
}
