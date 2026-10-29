use redis::Script;

// The `#!lua` line makes a cluster refuse a script that reaches a key outside the slot of the keys
// it declares; without it, a node that owns both slots runs the script anyway.
pub(crate) fn script(body: &str) -> Script {
    Script::new(&format!("#!lua\n{PRELUDE}\n{body}"))
}

// A server full under `noeviction` refuses a flagged script that doesn't allow OOM, even one that
// only deletes. Revoking must still work then, so a script that only removes keys allows it.
pub(crate) fn removing_script(body: &str) -> Script {
    Script::new(&format!("#!lua flags=allow-oom\n{PRELUDE}\n{body}"))
}

const PRELUDE: &str = r#"
local function server_now_ms()
    local time = redis.call('TIME')
    return tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
end

-- The key lives as long as its longest-lived entry. `GT` alone would never set a first deadline,
-- since it treats a key without one as immortal.
local function outlive(key, pxat)
    if redis.call('PTTL', key) < 0 then
        redis.call('PEXPIREAT', key, pxat)
    else
        redis.call('PEXPIREAT', key, pxat, 'GT')
    end
end

-- An index is a sorted set of row ids scored by deadline. Each write also drops the entries the
-- server's clock has passed, whose rows the server has already expired.
local function index(key, id, pxat)
    redis.call('ZADD', key, pxat, id)
    redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. server_now_ms())
    outlive(key, pxat)
end

local function forget_owner(key, ownership, field, id)
    if ownership == 'set' then
        redis.call('ZREM', key, id)
    elseif ownership == 'field' and redis.call('HGET', key, field) == id then
        redis.call('HDEL', key, field)
    end
end
"#;

pub(crate) const INSERT: &str = r#"
-- KEYS: the row and its lookups (ARGV[1] keys in all), the deadline index, then the owner index
-- unless ARGV[3] is 'none'.
-- ARGV: the key count, the deadline, the ownership ('none' or 'set'), the row id, then each key's
-- value in KEYS order.
local claimed = tonumber(ARGV[1])
local pxat = tonumber(ARGV[2])
for i = 1, claimed do
    if redis.call('EXISTS', KEYS[i]) == 1 then
        return 0
    end
end
for i = 1, claimed do
    redis.call('SET', KEYS[i], ARGV[i + 4], 'PXAT', pxat)
end
index(KEYS[claimed + 1], ARGV[4], pxat)
if ARGV[3] == 'set' then
    index(KEYS[claimed + 2], ARGV[4], pxat)
end
return 1
"#;

pub(crate) const REPLACE: &str = r#"
-- KEYS: the new row, the deadline index, the owner's hash, then the row its field named when the
-- caller read it, unless ARGV[5] is empty.
-- ARGV: the row, its deadline, its id, its field in the owner's hash, and the id the caller read
-- from that field ('' for none).
if redis.call('EXISTS', KEYS[1]) == 1 then
    return 0
end
-- The field decides which row is live, so a row it stops naming can't be taken even before it is
-- deleted. When another replace got in since the caller's read, KEYS[4] isn't the row the field
-- names now, and that row is left to its deadline.
local current = redis.call('HGET', KEYS[3], ARGV[4]) or ''
if current ~= '' and current == ARGV[5] then
    redis.call('DEL', KEYS[4])
    redis.call('ZREM', KEYS[2], current)
end
local pxat = tonumber(ARGV[2])
redis.call('SET', KEYS[1], ARGV[1], 'PXAT', pxat)
redis.call('HSET', KEYS[3], ARGV[4], ARGV[3])
outlive(KEYS[3], pxat)
index(KEYS[2], ARGV[3], pxat)
return 1
"#;

pub(crate) const UPDATE: &str = r#"
-- KEYS: the row, the deadline index, the row's lookups (ARGV[4] of them), then the owner index
-- when ARGV[5] is 'set'.
-- ARGV: the row, its deadline, its id, the lookup count, the ownership.
local pxat = tonumber(ARGV[2])
-- `XX` turns an update that lands after a delete into a no-op instead of a resurrected row.
if not redis.call('SET', KEYS[1], ARGV[1], 'XX', 'PXAT', pxat) then
    return 0
end
local lookups = tonumber(ARGV[4])
for i = 3, lookups + 2 do
    redis.call('PEXPIREAT', KEYS[i], pxat)
end
index(KEYS[2], ARGV[3], pxat)
if ARGV[5] == 'set' then
    index(KEYS[lookups + 3], ARGV[3], pxat)
end
return 1
"#;

pub(crate) const TAKE: &str = r#"
-- KEYS: the row, the deadline index, then the owner index unless ARGV[2] is 'none'.
-- ARGV: the row id, the ownership, the row's field in the owner's hash.
local value = redis.call('GET', KEYS[1])
if not value then
    return false
end
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[1])
if ARGV[2] == 'field' and redis.call('HGET', KEYS[3], ARGV[3]) ~= ARGV[1] then
    -- A replace has made another row live in this one's place.
    return false
end
if ARGV[2] ~= 'none' then
    forget_owner(KEYS[3], ARGV[2], ARGV[3], ARGV[1])
end
return value
"#;

pub(crate) const DELETE: &str = r#"
-- Runs even on a full server (see `removing_script`), so it only reads and removes.
-- KEYS[1] is the deadline index; each row then declares the row, its lookups and, unless its
-- ownership is 'none', its owner index.
-- ARGV[1] is the cutoff: a row whose deadline index entry is gone or later than it is kept, so a
-- row that slid since the caller read the index survives. '+inf' deletes regardless. Each row then
-- gives its id, its lookup count, its ownership and its field in the owner's hash.
local cutoff = ARGV[1]
local deleted = 0
local k = 2
for i = 2, #ARGV, 4 do
    local id, lookups, ownership, field = ARGV[i], tonumber(ARGV[i + 1]), ARGV[i + 2], ARGV[i + 3]
    local count = lookups + 1
    if ownership ~= 'none' then
        count = count + 1
    end
    local due = true
    if cutoff ~= '+inf' then
        local score = redis.call('ZSCORE', KEYS[1], id)
        due = score ~= false and tonumber(score) <= tonumber(cutoff)
    end
    if due then
        deleted = deleted + redis.call('DEL', KEYS[k])
        for j = k + 1, k + lookups do
            redis.call('DEL', KEYS[j])
        end
        redis.call('ZREM', KEYS[1], id)
        if ownership ~= 'none' then
            forget_owner(KEYS[k + lookups + 1], ownership, field, id)
        end
    end
    k = k + count
end
return deleted
"#;

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
