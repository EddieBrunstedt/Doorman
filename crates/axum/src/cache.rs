//! Re-exports of the core session-resolution cache.
//!
//! The cache itself lives in [`doorman_core::cache`]: core owns it because
//! the assembly seam constructs one, installs its invalidator on the
//! [`SessionManager`](doorman_core::session::SessionManager), and hands the
//! handle to the front end. This crate's
//! [`SessionLayer`](crate::session::SessionLayer) consumes that handle on the
//! request path. These re-exports keep the public import path stable for
//! hosts and benches that reach the cache through `doorman_axum`.

pub use doorman_core::cache::{
    CachedAuth, DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, SessionCache, SessionCacheConfig,
};
