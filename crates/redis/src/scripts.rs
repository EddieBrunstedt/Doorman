//! Lua scripts run server-side via `EVALSHA` (with an `EVAL` fallback).
//!
//! Lua is reserved for the one operation whose read-decide-write sequence must
//! be a single atomic step across replicas: the rate limiter's
//! check-and-charge. The ephemeral stores stay on plain commands — `GETDEL`
//! already gives their single-use guarantee without a script.

/// Sliding-window-log rate limiter, mirroring
/// [`InMemoryRateLimiter`](doorman_core::memory::InMemoryRateLimiter).
///
/// The bucket is a sorted set whose members are unique per attempt and whose
/// scores are the attempt timestamps in epoch milliseconds. Running the whole
/// evict/count/charge sequence as one script is what makes check-and-charge
/// atomic across replicas — the entire reason for moving the limiter off
/// per-process memory.
///
/// Arguments:
/// - `KEYS[1]` — the bucket key.
/// - `ARGV[1]` — `now` in epoch milliseconds (caller's clock).
/// - `ARGV[2]` — `window` in milliseconds.
/// - `ARGV[3]` — `max_attempts`.
/// - `ARGV[4]` — a unique member for this attempt (so two attempts at the same
///   millisecond are still two distinct log entries).
///
/// Returns a two-element array `{decision, retry_after_ms}` where `decision` is
/// `1` for allowed and `0` for limited; `retry_after_ms` is `0` when allowed.
pub(crate) const SLIDING_WINDOW: &str = r#"
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max    = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - window

-- Evict entries at or before the window cutoff. This mirrors the in-memory
-- limiter's `retain(|t| t > cutoff)`: an attempt exactly `window` old ages out.
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)

local count = redis.call('ZCARD', key)
if count >= max then
    -- Budget exhausted: the oldest live attempt frees a slot at `oldest + window`.
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after
    if oldest[2] == nil then
        -- No live attempts (e.g. a max_attempts of 0): a full window must pass.
        retry_after = window
    else
        retry_after = (tonumber(oldest[2]) + window) - now
        if retry_after < 0 then
            retry_after = 0
        end
    end
    return {0, retry_after}
end

-- Within budget: record this attempt and bound the key's lifetime to the window.
redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window)
return {1, 0}
"#;
