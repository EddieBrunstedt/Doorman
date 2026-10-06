use doorman_redb::RedbStorage;

#[tokio::test]
async fn redb_storage_conformance() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("conformance.redb");

    let storage = RedbStorage::open(&path).expect("open redb");

    doorman_conformance::run(&storage.all_stores()).await;
}
