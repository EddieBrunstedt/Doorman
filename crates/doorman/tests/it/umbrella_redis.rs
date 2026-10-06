#![cfg(feature = "redis")]

#[test]
fn redis_reexport_and_prelude_resolve() {
    let _: Option<doorman::redis::RedisStorage> = None;

    use doorman::prelude::*;
    let _: Option<RedisStorage> = None;
}
