//! Re-exports of the core session-resolution cache.
//!
//! The cache itself lives in [`doorman_core::cache`], owned by the
//! [`SessionResolver`](doorman_core::resolve::SessionResolver) this crate's
//! [`SessionLayer`](crate::session::SessionLayer) calls on the request path.
//! These re-exports keep the public import path stable for hosts and benches
//! that reach the cache through `doorman_axum`.

pub use doorman_core::cache::{
    CachedAuth, DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, SessionCache, SessionCacheConfig,
};
