//! Verify the umbrella crate re-exports the Redis adapter through a single
//! dependency: both the `doorman::redis` module path and the `RedisStorage`
//! handle folded into `doorman::prelude`.
//!
//! Compile-only: it never opens a connection, so it needs no live server.

#![cfg(feature = "redis")]

#[test]
fn redis_reexport_and_prelude_resolve() {
    // The module path resolves.
    let _: Option<doorman::redis::RedisStorage> = None;

    // And the handle is reachable through the prelude glob.
    use doorman::prelude::*;
    let _: Option<RedisStorage> = None;
}
