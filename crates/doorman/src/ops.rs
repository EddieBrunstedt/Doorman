use std::process::ExitCode;

use chrono::{DateTime, Utc};

use crate::core::error::StorageError;
use crate::core::purge::PurgeSummary;
use crate::core::storage::Storage;

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

struct Options {
    now: DateTime<Utc>,
    json: bool,
}

#[derive(Debug)]
enum PurgeError {
    Args(String),
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

fn parse_now(value: &str) -> Result<DateTime<Utc>, PurgeError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|error| {
            PurgeError::Args(format!(
                "could not parse --now `{value}` as an RFC 3339 timestamp: {error}"
            ))
        })
}

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

        let user_id = UserId::new();
        let mk_session = |tag: u8, expires_at: DateTime<Utc>| Session {
            id: SessionId::new(),
            user_id,
            token_hash: TokenHash([tag; 32]),
            created_at: now - chrono::Duration::hours(2),
            last_used_at: now - chrono::Duration::hours(2),
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
