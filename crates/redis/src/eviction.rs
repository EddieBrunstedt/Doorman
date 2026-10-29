use redis::Value;

use crate::client::RedisClient;

// Every key doorman writes has a deadline, so any other policy, `volatile-*` included, may evict
// one. An evicted owner index leaves its rows out of the delete that revokes them, and those
// sessions live on.
const KEEPS_EVERY_KEY: &str = "noeviction";

#[derive(Debug, thiserror::Error)]
pub enum EvictionPolicyError {
    #[error(
        "Redis runs maxmemory-policy `{policy}`, under which it may evict doorman's keys; doorman needs `noeviction`"
    )]
    Evicting { policy: String },
    #[error("Redis didn't report its maxmemory-policy; doorman needs it to be `noeviction`")]
    Unreported,
    #[error("couldn't read Redis's maxmemory-policy; doorman needs it to be `noeviction`")]
    Unreadable(#[source] redis::RedisError),
}

// Reads `INFO` rather than `CONFIG GET`: managed services that block `CONFIG` still serve `INFO`.
pub(crate) async fn check(client: &RedisClient) -> Result<(), EvictionPolicyError> {
    let reply = client
        .memory_info()
        .await
        .map_err(EvictionPolicyError::Unreadable)?;
    check_reply(reply)
}

// A cluster answers with each primary's report, keyed by its address. Every primary must keep
// every key, since a reshard can move the namespace's slot to any of them.
fn check_reply(reply: Value) -> Result<(), EvictionPolicyError> {
    let reports = match reply {
        Value::Map(nodes) => nodes.into_iter().map(|(_, report)| report).collect(),
        report => vec![report],
    };
    if reports.is_empty() {
        return Err(EvictionPolicyError::Unreported);
    }
    for report in reports {
        let policy = policy(report)?;
        if policy != KEEPS_EVERY_KEY {
            return Err(EvictionPolicyError::Evicting { policy });
        }
    }
    Ok(())
}

fn policy(report: Value) -> Result<String, EvictionPolicyError> {
    let text = match report {
        Value::BulkString(bytes) => {
            String::from_utf8(bytes).map_err(|_| EvictionPolicyError::Unreported)?
        }
        Value::VerbatimString { text, .. } | Value::SimpleString(text) => text,
        Value::ServerError(error) => return Err(EvictionPolicyError::Unreadable(error.into())),
        _ => return Err(EvictionPolicyError::Unreported),
    };
    text.lines()
        .find_map(|line| line.strip_prefix("maxmemory_policy:"))
        .map(|policy| policy.trim().to_owned())
        .ok_or(EvictionPolicyError::Unreported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::VerbatimFormat;

    fn report(policy: &str) -> Value {
        Value::BulkString(
            format!("# Memory\r\nmaxmemory:0\r\nmaxmemory_policy:{policy}\r\nlazyfree_lazy_eviction:0\r\n")
                .into_bytes(),
        )
    }

    fn node(address: &str, report: Value) -> (Value, Value) {
        (Value::BulkString(address.as_bytes().to_vec()), report)
    }

    #[test]
    fn only_noeviction_keeps_every_key() {
        assert!(check_reply(report("noeviction")).is_ok());
        for policy in [
            "volatile-lru",
            "volatile-lfu",
            "volatile-random",
            "volatile-ttl",
            "allkeys-lru",
            "allkeys-lfu",
            "allkeys-random",
        ] {
            assert!(
                matches!(
                    check_reply(report(policy)),
                    Err(EvictionPolicyError::Evicting { policy: reported }) if reported == policy
                ),
                "{policy}"
            );
        }
    }

    #[test]
    fn a_resp3_report_reads_like_a_resp2_one() {
        let verbatim = Value::VerbatimString {
            format: VerbatimFormat::Text,
            text: "# Memory\r\nmaxmemory_policy:allkeys-lru\r\n".to_owned(),
        };
        assert!(matches!(
            check_reply(verbatim),
            Err(EvictionPolicyError::Evicting { .. })
        ));
    }

    #[test]
    fn every_primary_of_a_cluster_must_keep_every_key() {
        let keeping = Value::Map(vec![
            node("a:6379", report("noeviction")),
            node("b:6379", report("noeviction")),
        ]);
        assert!(check_reply(keeping).is_ok());

        let one_evicting = Value::Map(vec![
            node("a:6379", report("noeviction")),
            node("b:6379", report("volatile-ttl")),
        ]);
        assert!(matches!(
            check_reply(one_evicting),
            Err(EvictionPolicyError::Evicting { policy }) if policy == "volatile-ttl"
        ));
    }

    #[test]
    fn a_policy_that_cant_be_read_is_refused() {
        assert!(matches!(
            check_reply(Value::BulkString(b"# Memory\r\nmaxmemory:0\r\n".to_vec())),
            Err(EvictionPolicyError::Unreported)
        ));
        assert!(matches!(
            check_reply(Value::Nil),
            Err(EvictionPolicyError::Unreported)
        ));
        assert!(matches!(
            check_reply(Value::Map(Vec::new())),
            Err(EvictionPolicyError::Unreported)
        ));
        let refused = redis::parse_redis_value(b"-NOPERM no permissions to run 'info'\r\n")
            .expect("a parsed error reply");
        assert!(matches!(
            check_reply(Value::Map(vec![
                node("a:6379", report("noeviction")),
                node("b:6379", refused),
            ])),
            Err(EvictionPolicyError::Unreadable(_))
        ));
    }
}
