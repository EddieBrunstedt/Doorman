//! [`AuthServiceBuilder`], reached via [`AuthService::builder`].
//!
//! Every portable option — collaborators, per-flow configs, the session and
//! cache settings, the re-auth and notification policies — is set on
//! [`AuthCore::builder`], which validates it and wires the managers. This
//! builder takes the resulting [`AuthCore`] and adds only the HTTP settings:
//! the session cookie (its `__Host-`/`__Secure-` prefix rules and its
//! `Max-Age` bound) and the CSRF posture. A new core option therefore never
//! touches this file.
//!
//! [`build`](AuthServiceBuilder::build) fails closed with a [`BuilderError`]:
//!
//! - a CSRF decision → [`BuilderError::CsrfDecisionRequired`] unless
//!   [`external_origin`](AuthServiceBuilder::external_origin) is set or CSRF
//!   is explicitly configured
//! - a `__Host-`/`__Secure-` cookie name without the attributes its prefix
//!   requires → [`BuilderError::InvalidCookiePrefix`]
//! - a cookie `Max-Age` longer than the session can go unused →
//!   [`BuilderError::CookieMaxAgeExceedsSessionLifetime`]

use std::sync::Arc;
use std::time::Duration;

use doorman_core::assembly::AuthCore;

use url::Url;

use crate::AuthService;
use crate::config::CookieConfig;
use crate::csrf::CsrfConfig;
use crate::session::{SessionLayer, SessionLayerState};
use crate::state::AuthState;

/// Errors returned when the HTTP settings layered over an [`AuthCore`] are
/// incomplete or invalid. Portable misconfiguration is reported earlier, by
/// [`AuthCore::builder`], as an
/// [`AssemblyError`](doorman_core::assembly::AssemblyError).
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    /// No CSRF decision was made: the builder was given neither an
    /// [`external_origin`](AuthServiceBuilder::external_origin) (which
    /// enables origin checks) nor an explicit
    /// [`csrf`](AuthServiceBuilder::csrf) config. Cookie-authenticated
    /// mutations would rest on `SameSite=Lax` alone, so the build refuses to
    /// guess: set the origin, or opt out deliberately with
    /// `.csrf(CsrfConfig::disabled())`.
    #[error(
        "a CSRF decision is required: set external_origin to enable origin checks, or pass CsrfConfig::disabled() to opt out"
    )]
    CsrfDecisionRequired,
    /// The session cookie name carries a `__Host-` or `__Secure-` prefix but
    /// the cookie attributes do not satisfy what that prefix requires (per
    /// the cookie-prefix spec). A browser would silently reject the cookie,
    /// so the build fails closed instead.
    #[error("cookie name `{name}` carries a {prefix} prefix but {requirement}")]
    InvalidCookiePrefix {
        /// The configured cookie name.
        name: String,
        /// The prefix that imposed the requirement (`__Host-`/`__Secure-`).
        prefix: &'static str,
        /// The attribute requirement that was not met.
        requirement: &'static str,
    },
    /// The session cookie `Max-Age` outlives the window the server will keep
    /// the session alive, so the browser would keep replaying a cookie whose
    /// session is already dead. The bound is
    /// [`SessionManager::unused_lifetime`](doorman_core::session::SessionManager::unused_lifetime):
    /// the idle window when sliding is on, otherwise the absolute lifetime.
    #[error(
        "cookie Max-Age ({cookie_max_age:?}) exceeds the session lifetime ({session_lifetime:?})"
    )]
    CookieMaxAgeExceedsSessionLifetime {
        /// The configured cookie `Max-Age`.
        cookie_max_age: Duration,
        /// The session lifetime it exceeds — the absolute lifetime, or the
        /// idle window when sliding is enabled.
        session_lifetime: Duration,
    },
}

/// Builder returned from [`AuthService::builder`]: an assembled [`AuthCore`]
/// plus the cookie and CSRF settings.
///
/// ```ignore
/// use doorman_axum::prelude::*;
/// use doorman_core::verification::TOKEN_PLACEHOLDER;
///
/// let base = origin.as_str().trim_end_matches('/');
/// let core = AuthCore::builder(storage)
///     .email(Arc::new(TerminalEmailSender))
///     .passkey(PasskeyConfig::new("example.com", origin.clone(), "Example"))
///     .audit(Arc::new(NoopAuditSink))
///     .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
///     .reauthentication(ReauthPolicy::required_for([ReauthAction::DeleteAccount, ReauthAction::RemovePasskey]))
///     .signup(SignupConfig { url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
///     .recovery(RecoveryConfig { url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
///     .account(AccountConfig { url_template: format!("{base}/account/email?token={TOKEN_PLACEHOLDER}"), ..Default::default() })
///     .build()?;
/// let auth = AuthService::builder(core)
///     .external_origin(origin)
///     .cookie(CookieConfig::default())
///     .build()?;
/// ```
pub struct AuthServiceBuilder {
    core: AuthCore,
    cookie_config: Option<CookieConfig>,
    csrf_config: Option<CsrfConfig>,
    external_origin: Option<Url>,
}

impl AuthServiceBuilder {
    pub(crate) fn new(core: AuthCore) -> Self {
        Self {
            core,
            cookie_config: None,
            csrf_config: None,
            external_origin: None,
        }
    }

    /// Override the default [`CookieConfig`].
    pub fn cookie(mut self, config: CookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }

    /// Set the CSRF origin-check behaviour explicitly. Setting
    /// [`external_origin`](Self::external_origin) already enables checks; call
    /// this with [`CsrfConfig::disabled`](crate::csrf::CsrfConfig::disabled)
    /// to opt out deliberately. With neither an origin nor an explicit config,
    /// [`build`](Self::build) returns [`BuilderError::CsrfDecisionRequired`]
    /// rather than silently leaving the check off.
    pub fn csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    /// Absolute public origin (scheme + host [+ port] [+ path prefix]) that
    /// clients use to reach the auth routes. Supplying an origin enables CSRF
    /// origin checks and satisfies the required CSRF decision (see
    /// [`csrf`](Self::csrf)).
    pub fn external_origin(mut self, origin: Url) -> Self {
        self.external_origin = Some(origin);
        self
    }

    /// Validate the HTTP settings and return a wired-up [`AuthService`], or
    /// the first [`BuilderError`] found.
    pub fn build(self) -> Result<AuthService, BuilderError> {
        let core = self.core;
        let cookie_config = self.cookie_config.unwrap_or_default();
        validate_cookie_prefix(&cookie_config)?;

        // A sliding session's cookie is refreshed to at most one idle window
        // per use, and the session never survives one idle window unused, so
        // the cookie must not outlive that window.
        let session_lifetime = core.session_manager.unused_lifetime();
        if cookie_config.session_max_age > session_lifetime {
            return Err(BuilderError::CookieMaxAgeExceedsSessionLifetime {
                cookie_max_age: cookie_config.session_max_age,
                session_lifetime,
            });
        }

        // CSRF is not guessed. Cookie-authenticated mutations need an origin
        // check or a deliberate opt-out; with neither an origin nor an
        // explicit config we cannot tell which the host intended, so fail
        // closed rather than silently leaving the check off.
        let csrf_config = match (self.csrf_config, self.external_origin) {
            (Some(config), _) => config,
            (None, Some(origin)) => CsrfConfig::new(origin),
            (None, None) => return Err(BuilderError::CsrfDecisionRequired),
        }
        .enabled_config();

        let cache = core.resolver.cache().clone();
        let layer_state = Arc::new(SessionLayerState {
            resolver: core.resolver,
            cookie: cookie_config.clone(),
            csrf: csrf_config,
        });

        let state = AuthState {
            session_manager: core.session_manager,
            user_store: core.storage.users.clone(),
            cookie_config: Arc::new(cookie_config),
            passkey: core.passkey,
            signup: core.signup,
            recovery: core.recovery,
            account: core.account,
            reauth: core.reauth,
            operator: core.operator,
        };

        Ok(AuthService {
            state,
            session_layer: SessionLayer::new(layer_state),
            cache,
            storage: core.storage,
        })
    }
}

/// Enforce the cookie-prefix rules from the cookie-name spec so a
/// misconfigured cookie fails the build instead of being silently dropped
/// by the browser at runtime.
///
/// - `__Host-` requires `Secure`, `Path=/`, and **no** `Domain` attribute.
/// - `__Secure-` requires `Secure`.
fn validate_cookie_prefix(config: &CookieConfig) -> Result<(), BuilderError> {
    let name = config.session_cookie_name.as_str();
    let invalid = |prefix, requirement| BuilderError::InvalidCookiePrefix {
        name: name.to_string(),
        prefix,
        requirement,
    };
    if name.starts_with("__Host-") {
        if !config.secure {
            return Err(invalid("__Host-", "requires secure = true"));
        }
        if config.path != "/" {
            return Err(invalid("__Host-", "requires path = \"/\""));
        }
        if config.domain.is_some() {
            return Err(invalid("__Host-", "must not set a Domain attribute"));
        }
    } else if name.starts_with("__Secure-") && !config.secure {
        return Err(invalid("__Secure-", "requires secure = true"));
    }
    Ok(())
}
