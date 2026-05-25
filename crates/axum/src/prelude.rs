//! Common imports for an Axum host wiring `bauth-axum` into its app.
//!
//! ```ignore
//! use bauth_axum::prelude::*;
//! ```
//!
//! Pulls in the [`bauth_core` prelude](bauth_core::prelude) plus the
//! axum-facing types: the [`BauthAxum`] entry point, the request
//! extractors, the cookie config, and the error response type. The
//! request/response DTOs stay under [`crate::dto`] — most handlers do
//! not need them directly, since the router lives behind
//! [`BauthAxum::router`].

pub use bauth_core::prelude::*;

pub use crate::config::CookieConfig;
pub use crate::error::{ErrorBody, ErrorPayload, ErrorResponse};
pub use crate::extractors::{AuthSession, AuthUser, OptionalAuthUser, RequestContext};
pub use crate::session::{AuthContext, SessionLayer};
pub use crate::{BauthAxum, BauthAxumBuilder, BuilderError};
