//! Common imports for an Axum host wiring `bauth-axum` into its app.
//!
//! ```ignore
//! use bauth_axum::prelude::*;
//! ```
//!
//! Pulls in the [`bauth_core` prelude](bauth_core::prelude) plus the
//! axum-facing types: the [`BauthAxum`] entry point, the request
//! extractors, the cookie config, the error response type, and the
//! response DTOs (`UserDto`, `SessionDto`, `AuthResponse`, `PasskeyDto`)
//! a host needs to serialize its own `/api/me`-style routes. The request
//! body DTOs stay under [`crate::dto`] — handlers rarely build those
//! directly, since the router lives behind [`BauthAxum::router`].

pub use bauth_core::prelude::*;

pub use crate::config::CookieConfig;
pub use crate::csrf::{CsrfConfig, CsrfLayer};
pub use crate::dto::{AuthResponse, PasskeyDto, SessionDto, UserDto};
pub use crate::error::{ErrorBody, ErrorPayload, ErrorResponse};
pub use crate::extractors::{AuthSession, AuthUser, OptionalAuthUser, RequestContext};
pub use crate::session::{AuthContext, SessionLayer};
pub use crate::state::BauthState;
pub use crate::{BauthAxum, BauthBuilder, BuilderError, ManagerBuilder};
