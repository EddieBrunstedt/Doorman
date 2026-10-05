//! Common imports for an Axum host wiring `doorman-axum` into its app.
//!
//! ```ignore
//! use doorman_axum::prelude::*;
//! ```
//!
//! Pulls in the [`doorman_core` prelude](doorman_core::prelude) plus the
//! axum-facing types: the [`AuthService`] entry point, the request
//! extractors, the cookie config, the error response type, and the
//! response DTOs (`UserDto`, `SessionDto`, `AuthResponse`, `PasskeyDto`)
//! a host needs to serialize its own `/api/me`-style routes. The request
//! body DTOs stay under [`crate::dto`] — handlers rarely build those
//! directly, since the router lives behind [`AuthService::router`].

pub use doorman_core::prelude::*;

pub use crate::config::CookieConfig;
pub use crate::csrf::{CsrfConfig, CsrfLayer};
pub use crate::dto::{AuthResponse, PasskeyDto, SessionDto, UserDto};
pub use crate::error::{ErrorBody, ErrorPayload, ErrorResponse};
pub use crate::extractors::{AuthSession, AuthUser, ClientIp, OptionalAuthUser, RequestContext};
pub use crate::session::{AuthContext, SessionLayer};
pub use crate::state::AuthState;
pub use crate::{AuthService, AuthServiceBuilder, BuilderError};
