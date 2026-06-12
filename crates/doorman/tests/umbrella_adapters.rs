//! Verify the umbrella crate re-exports each remaining storage adapter
//! through a single dependency: the `doorman::<adapter>` module path and the
//! adapter's storage handle folded into `doorman::prelude`. The redis and
//! axum+sqlite paths have their own sibling tests.
//!
//! Compile-only: nothing here opens a connection or a file, so it needs no
//! live server or Docker daemon.

#[cfg(feature = "dynamodb")]
#[test]
fn dynamodb_reexport_and_prelude_resolve() {
    let _: Option<doorman::dynamodb::DynamoDbStorage> = None;

    use doorman::prelude::*;
    let _: Option<DynamoDbStorage> = None;
}

#[cfg(feature = "mongodb")]
#[test]
fn mongodb_reexport_and_prelude_resolve() {
    let _: Option<doorman::mongodb::MongoDbStorage> = None;

    use doorman::prelude::*;
    let _: Option<MongoDbStorage> = None;
}

#[cfg(feature = "redb")]
#[test]
fn redb_reexport_and_prelude_resolve() {
    let _: Option<doorman::redb::RedbStorage> = None;

    use doorman::prelude::*;
    let _: Option<RedbStorage> = None;
}
