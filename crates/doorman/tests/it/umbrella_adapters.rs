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
