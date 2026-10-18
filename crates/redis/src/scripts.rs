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

pub(crate) const INSERT_ABSENT: &str = r#"
-- KEYS[1..claimed] are the row's unique keys, each set to its ARGV value; an
-- extra trailing key is the owner index set, which gains the last ARGV.
local claimed = tonumber(ARGV[1])
for i = 1, claimed do
    if redis.call('EXISTS', KEYS[i]) == 1 then
        return 0
    end
end

local pxat = tonumber(ARGV[2])
for i = 1, claimed do
    redis.call('SET', KEYS[i], ARGV[i + 2], 'PXAT', pxat)
end
if #KEYS > claimed then
    redis.call('SADD', KEYS[claimed + 1], ARGV[claimed + 3])
end
return 1
"#;

pub(crate) const REPLACE_EMAIL_LINK: &str = r#"
-- KEYS[1] is the new link's row, KEYS[2] its owner's hash of link token
-- hashes by purpose. ARGV: the row, its deadline, its purpose, its token hash,
-- and the prefix that turns a token hash into its row key.
if redis.call('EXISTS', KEYS[1]) == 1 then
    return 0
end

local pxat = tonumber(ARGV[2])
local replaced = redis.call('HGET', KEYS[2], ARGV[3])
if replaced then
    redis.call('DEL', ARGV[5] .. replaced)
end
redis.call('SET', KEYS[1], ARGV[1], 'PXAT', pxat)
redis.call('HSET', KEYS[2], ARGV[3], ARGV[4])
-- The hash lives as long as the longest-lived link it names. `GT` alone would
-- never set a first deadline, since it treats a key without one as immortal.
if redis.call('PTTL', KEYS[2]) < 0 then
    redis.call('PEXPIREAT', KEYS[2], pxat)
else
    redis.call('PEXPIREAT', KEYS[2], pxat, 'GT')
end
return 1
"#;

pub(crate) const DELETE_EMAIL_LINKS: &str = r#"
-- KEYS[1] is the owner's hash of link token hashes by purpose; ARGV[1] the
-- prefix that turns a token hash into its row key.
local removed = 0
for _, hash in ipairs(redis.call('HVALS', KEYS[1])) do
    removed = removed + redis.call('DEL', ARGV[1] .. hash)
end
redis.call('DEL', KEYS[1])
return removed
"#;
