use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use doorman_core::audit::AuditEventKind;
use doorman_core::error::{Error, StorageError, StorageResult};
use doorman_core::rate_limit::{
    RateLimit, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter, RateLimiting,
    RateLimits,
};
use doorman_core::session::RequestTransport;
use doorman_core::storage::PasskeyChallengeId;
use doorman_test_support::{CLIENT_IP, request_context};
use webauthn_rs_proto::PublicKeyCredential;

use crate::common::{Harness, authenticator, kinds, make_user, register_passkey};

const EMAIL: &str = "alice@example.com";

#[derive(Default)]
struct Recording {
    armed: AtomicBool,
    limited: Option<usize>,
    failing: bool,
    charged: Mutex<Vec<String>>,
}

impl Recording {
    fn limiting(charge: usize) -> Self {
        Self {
            limited: Some(charge),
            ..Self::default()
        }
    }

    fn failing() -> Self {
        Self {
            failing: true,
            ..Self::default()
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn charged(&self) -> Vec<String> {
        self.charged.lock().expect("lock").clone()
    }
}

#[async_trait]
impl RateLimiter for Recording {
    async fn check_and_charge(
        &self,
        key: &RateLimitKey,
        _policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision> {
        // Unarmed, it lets a step's setup through without counting it.
        if !self.armed.load(Ordering::SeqCst) {
            return Ok(RateLimitDecision::Allowed);
        }
        if self.failing {
            return Err(StorageError::msg("limiter unavailable"));
        }
        let mut charged = self.charged.lock().expect("lock");
        charged.push(key.as_str().to_owned());
        if self.limited == Some(charged.len() - 1) {
            return Ok(RateLimitDecision::Limited {
                retry_after: Duration::from_secs(5),
            });
        }
        Ok(RateLimitDecision::Allowed)
    }
}

#[derive(Debug, Clone, Copy)]
enum Step {
    LoginStart,
    LoginFinish,
    SignupRequest,
    RecoveryRequest,
}

enum Prepared {
    LoginStart,
    LoginFinish {
        challenge_id: PasskeyChallengeId,
        assertion: Box<PublicKeyCredential>,
    },
    SignupRequest,
    RecoveryRequest,
}

impl Prepared {
    async fn run(self, h: &Harness) -> Result<(), Error> {
        match self {
            Self::LoginStart => h
                .passkey
                .start_authentication(request_context())
                .await
                .map(drop),
            Self::LoginFinish {
                challenge_id,
                assertion,
            } => h
                .passkey
                .finish_authentication(
                    challenge_id,
                    &assertion,
                    RequestTransport::Cookie,
                    request_context(),
                )
                .await
                .map(drop),
            Self::SignupRequest => {
                h.signup
                    .request_signup(EMAIL, None, request_context())
                    .await
            }
            Self::RecoveryRequest => h.recovery.request_recovery(EMAIL, request_context()).await,
        }
    }
}

impl Step {
    const ALL: [Step; 4] = [
        Self::LoginStart,
        Self::LoginFinish,
        Self::SignupRequest,
        Self::RecoveryRequest,
    ];

    async fn prepare(self, h: &Harness) -> Prepared {
        match self {
            Self::LoginStart => Prepared::LoginStart,
            Self::LoginFinish => {
                let user = make_user(h, EMAIL).await;
                let mut wa = authenticator();
                let passkey = register_passkey(h, user.id, &mut wa, None).await;
                let (challenge_id, options) = h
                    .passkey
                    .start_authentication(request_context())
                    .await
                    .expect("start login");
                let assertion = wa.do_authentication(options, &passkey.credential_id);
                Prepared::LoginFinish {
                    challenge_id,
                    assertion: Box::new(assertion),
                }
            }
            Self::SignupRequest => Prepared::SignupRequest,
            Self::RecoveryRequest => Prepared::RecoveryRequest,
        }
    }

    fn charges(self, passkey: &str) -> Vec<(RateLimit, String)> {
        let ip = CLIENT_IP;
        match self {
            Self::LoginStart => vec![(
                RateLimit::LoginStartPerIp,
                format!("login_start_per_ip:{ip}"),
            )],
            Self::LoginFinish => vec![
                (
                    RateLimit::LoginFinishPerIp,
                    format!("login_finish_per_ip:{ip}"),
                ),
                (
                    RateLimit::LoginFinishPerPasskey,
                    format!("login_finish_per_passkey:{passkey}"),
                ),
            ],
            Self::SignupRequest => vec![
                (
                    RateLimit::SignupRequestPerIp,
                    format!("signup_request_per_ip:{ip}"),
                ),
                (
                    RateLimit::SignupRequestPerEmail,
                    format!("signup_request_per_email:{EMAIL}"),
                ),
            ],
            Self::RecoveryRequest => vec![
                (
                    RateLimit::RecoveryRequestPerIp,
                    format!("recovery_request_per_ip:{ip}"),
                ),
                (
                    RateLimit::RecoveryRequestPerEmail,
                    format!("recovery_request_per_email:{EMAIL}"),
                ),
                (
                    RateLimit::RecoveryRequestPerEmailDaily,
                    format!("recovery_request_per_email_daily:{EMAIL}"),
                ),
                (
                    RateLimit::RecoveryRequestGlobal,
                    "recovery_request_global".to_owned(),
                ),
            ],
        }
    }
}

fn every_limit_on() -> RateLimits {
    RateLimits {
        recovery_request_global: Some(RateLimitPolicy::new(100, Duration::from_secs(60))),
        ..RateLimits::default()
    }
}

struct Outcome {
    result: Result<(), Error>,
    charges: Vec<(RateLimit, String)>,
    charged: Vec<String>,
    audited: Vec<AuditEventKind>,
}

async fn take(step: Step, limiter: Recording, limits: RateLimits) -> Outcome {
    let limiter = Arc::new(limiter);
    let h = Harness::builder()
        .rate_limiting(RateLimiting::Enforced {
            limiter: limiter.clone(),
            limits,
        })
        .build();
    let prepared = step.prepare(&h).await;
    let passkey = match &prepared {
        Prepared::LoginFinish { assertion, .. } => {
            URL_SAFE_NO_PAD.encode(assertion.raw_id.as_ref())
        }
        _ => String::new(),
    };
    let audited_before = h.audit.events().len();
    limiter.arm();

    let result = prepared.run(&h).await;

    Outcome {
        result,
        charges: step.charges(&passkey),
        charged: limiter.charged(),
        audited: kinds(&h.audit.events()[audited_before..]),
    }
}

fn audits_a_rate_limit(audited: &[AuditEventKind]) -> bool {
    audited
        .iter()
        .any(|kind| matches!(kind, AuditEventKind::RateLimited { .. }))
}

#[tokio::test]
async fn every_step_charges_its_rate_limits_in_order() {
    for step in Step::ALL {
        let outcome = take(step, Recording::default(), every_limit_on()).await;

        let keys: Vec<_> = outcome.charges.into_iter().map(|(_, key)| key).collect();
        assert_eq!(outcome.charged, keys, "{step:?}");
        assert!(!audits_a_rate_limit(&outcome.audited), "{step:?}");
    }
}

#[tokio::test]
async fn a_hit_rate_limit_refuses_the_step_audits_it_and_charges_nothing_after_it() {
    for step in Step::ALL {
        for hit in 0..step.charges("").len() {
            let outcome = take(step, Recording::limiting(hit), every_limit_on()).await;

            let (limit, _) = &outcome.charges[hit];
            assert!(
                matches!(outcome.result, Err(Error::RateLimited { retry_after }) if retry_after.as_secs() == 5),
                "{step:?} at {limit:?}: {:?}",
                outcome.result,
            );
            let keys: Vec<_> = outcome.charges[..=hit]
                .iter()
                .map(|(_, key)| key.clone())
                .collect();
            assert_eq!(outcome.charged, keys, "{step:?} at {limit:?}");
            assert_eq!(
                outcome.audited,
                [AuditEventKind::RateLimited { limit: *limit }],
                "{step:?} at {limit:?}",
            );
        }
    }
}

#[tokio::test]
async fn a_turned_off_rate_limit_is_never_charged() {
    for step in Step::ALL {
        let outcome = take(step, Recording::default(), RateLimits::disabled()).await;

        assert!(
            outcome.charged.is_empty(),
            "{step:?}: {:?}",
            outcome.charged
        );
    }
}

#[tokio::test]
async fn a_failing_limiter_refuses_the_step_without_auditing_a_rate_limit() {
    for step in Step::ALL {
        let outcome = take(step, Recording::failing(), every_limit_on()).await;

        assert!(
            matches!(outcome.result, Err(Error::Storage(_))),
            "{step:?}: {:?}",
            outcome.result,
        );
        assert!(!audits_a_rate_limit(&outcome.audited), "{step:?}");
    }
}
