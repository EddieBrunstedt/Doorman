//! One-shot operational entrypoints for hosts that drive doorman from an
//! external scheduler rather than a long-lived process.
//!
//! The headline is [`run_purge`](crate::ops::run_purge): a generic runner that turns any composite
//! [`Storage`](crate::core::storage::Storage) into a complete one-shot purge
//! binary — it parses a couple of flags, sweeps expired rows, prints the
//! [`PurgeSummary`](crate::core::purge::PurgeSummary), and sets the process
//! exit code. It names no storage backend: the host builds its own storage and
//! hands it in, so a host on any backend reuses the same runner.
//!
//! ```ignore
//! // The host's whole purge binary — run it from cron / EventBridge / a k8s CronJob.
//! #[tokio::main]
//! async fn main() -> std::process::ExitCode {
//!     let storage = app::build_storage().await; // the SAME builder the server uses
//!     doorman::ops::run_purge(storage).await
//! }
//! ```
//!
//! A Rust binary is a leaf of the dependency graph, so doorman cannot ship a
//! binary that is generic over the backend — the backend-aware `main` must live
//! in the host's own crate. doorman ships this library seam instead; see
//! `examples/purge` for the single-source-of-truth workspace layout.

use std::process::ExitCode;

use chrono::{DateTime, Utc};

use crate::core::error::StorageError;
use crate::core::purge::PurgeSummary;
use crate::core::storage::Storage;

/// Sweep expired rows from `storage` once, report the per-store counts, and
/// return the process exit code: [`ExitCode::SUCCESS`] when the sweep
/// completes, [`ExitCode::FAILURE`] when a flag is malformed or a store errors.
///
/// Reads two optional flags from the process arguments:
///
/// - `--now <rfc3339>` — the sweep instant (anything with `expires_at <= now`
///   is removed). Defaults to the current time. Useful for tests and for
///   pinning the instant across a fan-out of shards.
/// - `--json` — emit the summary as a single JSON line instead of the
///   human-readable block, for log scraping.
///
/// The counts are printed loudly on every run — including a zero sweep — so a
/// misconfigured invocation that quietly sweeps the wrong namespace is visible
/// rather than looking like a clean success. No argument carries a secret; the
/// storage (and thus every credential) is built by the host and handed in.
///
/// Reuses [`Storage::purge_all_expired`], so it sweeps exactly the stores the
/// in-process background task does.
pub async fn run_purge(storage: Storage) -> ExitCode {
    match execute(storage, std::env::args().skip(1)).await {
        Ok((options, summary)) => {
            print_summary(options.now, options.json, &summary);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("doorman purge: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Resolved flag values for a single purge run.
struct Options {
    /// The sweep instant — the parsed `--now`, or the current time.
    now: DateTime<Utc>,
    /// Whether `--json` was given.
    json: bool,
}

/// What went wrong before or during a run. Both variants map to a non-zero
/// exit; the split exists so the message can name the cause and so tests can
/// distinguish a flag error from a sweep error.
#[derive(Debug)]
enum PurgeError {
    /// A flag was missing a value or could not be parsed.
    Args(String),
    /// The sweep itself failed in the backend.
    Sweep(StorageError),
}

impl std::fmt::Display for PurgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PurgeError::Args(message) => write!(f, "{message}"),
            PurgeError::Sweep(error) => write!(f, "sweep failed: {error}"),
        }
    }
}

/// Parse the flags, run the sweep, and hand back the resolved options plus the
/// summary. Split out of [`run_purge`] so it is driveable from a test without
/// touching the process arguments or exit code.
async fn execute(
    storage: Storage,
    args: impl IntoIterator<Item = String>,
) -> Result<(Options, PurgeSummary), PurgeError> {
    let options = parse_args(args)?;
    let summary = storage
        .purge_all_expired(options.now)
        .await
        .map_err(PurgeError::Sweep)?;
    Ok((options, summary))
}

/// Hand-rolled parser for the two supported flags. Deliberately tiny — if this
/// ever wants subcommands or many options, that is a signal to reconsider the
/// shape, not to reach for a CLI-parser dependency.
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Options, PurgeError> {
    let mut now: Option<DateTime<Utc>> = None;
    let mut json = false;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--json" {
            json = true;
        } else if arg == "--now" {
            let value = args.next().ok_or_else(|| {
                PurgeError::Args("--now requires an RFC 3339 timestamp argument".to_string())
            })?;
            now = Some(parse_now(&value)?);
        } else if let Some(value) = arg.strip_prefix("--now=") {
            now = Some(parse_now(value)?);
        } else {
            return Err(PurgeError::Args(format!(
                "unrecognized argument `{arg}` (supported: --now <rfc3339>, --json)"
            )));
        }
    }

    Ok(Options {
        now: now.unwrap_or_else(Utc::now),
        json,
    })
}

/// Parse an RFC 3339 timestamp into a UTC instant.
fn parse_now(value: &str) -> Result<DateTime<Utc>, PurgeError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|error| {
            PurgeError::Args(format!(
                "could not parse --now `{value}` as an RFC 3339 timestamp: {error}"
            ))
        })
}

/// Print the sweep result. Always prints the counts so an unexpected zero is
/// not mistaken for a clean run against the right data.
fn print_summary(now: DateTime<Utc>, json: bool, summary: &PurgeSummary) {
    let now = now.to_rfc3339();
    if json {
        println!(
            "{{\"now\":\"{now}\",\"sessions\":{},\"verification_tokens\":{},\"passkey_challenges\":{},\"total\":{}}}",
            summary.sessions,
            summary.verification_tokens,
            summary.passkey_challenges,
            summary.total(),
        );
        return;
    }

    println!("doorman purge: swept expired rows as of {now}");
    println!("  sessions            = {}", summary.sessions);
    println!("  verification_tokens = {}", summary.verification_tokens);
    println!("  passkey_challenges  = {}", summary.passkey_challenges);
    println!("  total               = {}", summary.total());
    if summary.total() == 0 {
        println!(
            "  note: nothing matched — if you expected rows, confirm this process targets the \
             same backend and namespace as the running app"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::memory::InMemoryStorage;
    use crate::core::storage::{Session, SessionId, TokenHash, UserId};

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_reads_both_flags() {
        let options =
            parse_args(args(&["--now", "2020-01-01T00:00:00Z", "--json"])).expect("flags parse");
        assert!(options.json);
        assert_eq!(
            options.now,
            DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn parse_args_accepts_the_equals_form() {
        let options =
            parse_args(args(&["--now=2020-01-01T00:00:00Z"])).expect("equals form parses");
        assert!(!options.json);
    }

    #[test]
    fn parse_args_defaults_now_and_json() {
        let before = Utc::now();
        let options = parse_args(args(&[])).expect("no flags is valid");
        assert!(!options.json);
        assert!(options.now >= before);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        assert!(matches!(
            parse_args(args(&["--bogus"])),
            Err(PurgeError::Args(_))
        ));
    }

    #[test]
    fn parse_args_rejects_now_without_a_value() {
        assert!(matches!(
            parse_args(args(&["--now"])),
            Err(PurgeError::Args(_))
        ));
    }

    #[test]
    fn parse_args_rejects_an_unparseable_now() {
        assert!(matches!(
            parse_args(args(&["--now", "not-a-timestamp"])),
            Err(PurgeError::Args(_))
        ));
    }

    #[tokio::test]
    async fn execute_sweeps_the_storage_and_reports_counts() {
        let now = DateTime::<Utc>::from_timestamp(1_000_000, 0).expect("timestamp");
        let storage = InMemoryStorage::new().all_stores();

        // One expired session and one live session: the sweep removes exactly
        // the expired one.
        let user_id = UserId::new();
        let mk_session = |tag: u8, expires_at: DateTime<Utc>| Session {
            id: SessionId::new(),
            user_id,
            token_hash: TokenHash([tag; 32]),
            created_at: now - chrono::Duration::hours(2),
            expires_at,
            ip: None,
            user_agent: None,
            recovery_cooldown_until: None,
        };
        storage
            .sessions
            .create_session(mk_session(1, now - chrono::Duration::hours(1)))
            .await
            .expect("expired session");
        storage
            .sessions
            .create_session(mk_session(2, now + chrono::Duration::hours(1)))
            .await
            .expect("live session");

        let (options, summary) = execute(storage, args(&["--now", &now.to_rfc3339(), "--json"]))
            .await
            .expect("execute ok");

        assert!(options.json);
        assert_eq!(options.now, now);
        assert_eq!(summary.sessions, 1);
        assert_eq!(summary.total(), 1);
    }

    #[tokio::test]
    async fn execute_surfaces_a_flag_error() {
        let storage = InMemoryStorage::new().all_stores();
        assert!(matches!(
            execute(storage, args(&["--when", "now"])).await,
            Err(PurgeError::Args(_))
        ));
    }
}
