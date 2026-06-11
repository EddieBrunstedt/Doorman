//! Runs the shared storage-conformance suite against the SQLx + MySQL adapter.
//!
//! Skipped unless the `MYSQL_URL` environment variable points at a disposable
//! test database. CI provides this via a containerised MySQL; locally you can
//! set `MYSQL_URL=mysql://root:root@localhost:3306/doorman_test` (`just up`
//! starts a server on that port).
//!
//! The test drops the adapter's tables before running so the migration state is
//! fresh on every invocation. Do not point `MYSQL_URL` at a database whose
//! tables hold data you want to keep.

#![cfg(feature = "mysql")]

mod common;

#[tokio::test]
async fn mysql_storage_conformance() {
    common::run_conformance("MYSQL_URL").await;
}
