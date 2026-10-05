//! Connection handle, attribute-value helpers, and the low-level DynamoDB
//! operations the stores build on.
//!
//! The adapter models every doorman record in a **single table** (see
//! [`crate::model`] for the item layout). This module owns the thin wrapper
//! around the AWS SDK client plus the table name, the helpers that translate
//! between Rust values and DynamoDB [`AttributeValue`]s, and a small set of
//! reusable operations (`get`, `put`, the atomic `take`, the two GSI queries, a
//! filtered table scan, a batch delete, and the owner-scoped and expiry bulk
//! deletes built on them) that the per-trait stores compose.
//!
//! ## Indexes
//!
//! Two global secondary indexes back the secondary access patterns:
//!
//! - **`lookup-index`** ([`GSI1PK`]) — point lookups by a non-unique-constrained
//!   secondary key, currently a session's token hash. GSIs are eventually
//!   consistent, which is acceptable here: the manager re-resolves and a stale
//!   read self-heals on the next request.
//! - **`owner-index`** ([`GSI2PK`]) — the per-user collections (a user's
//!   sessions, passkeys, verification tokens of a purpose, and registration
//!   ceremonies) that back the listing, counting, and bulk-delete paths.
//!
//! Both project every attribute (`ALL`) so an owner query returns whole records
//! in one round trip. DynamoDB maintains the indexes automatically, so — unlike
//! a hand-rolled key-value index — deleting or TTL-evicting a row drops its
//! index entries for free; there are no dangling members to reclaim.
//!
//! The one secondary lookup that needs a *uniqueness* guarantee — a user's
//! email — cannot use a GSI (indexes enforce no constraints and are only
//! eventually consistent), so it lives as a strongly-consistent guard item on
//! the main table; see [`crate::stores::user`].

use std::collections::HashMap;
use std::time::Duration;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::client::Waiters as _;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, DeleteRequest, GlobalSecondaryIndex,
    KeySchemaElement, KeyType, Projection, ProjectionType, ReturnValue, ScalarAttributeType,
    Select, TimeToLiveSpecification, WriteRequest,
};
use chrono::{DateTime, SecondsFormat, Utc};
use doorman_core::error::{StorageError, StorageResult};
use uuid::Uuid;

use doorman_core::storage::TokenHash;

/// A DynamoDB item: the attribute map the SDK reads and writes.
pub(crate) type Item = HashMap<String, AttributeValue>;

/// The table's partition-key attribute. The table has no sort key — every
/// record is addressed by a single, globally-unique `pk` string.
pub(crate) const PK: &str = "pk";
/// Partition-key attribute of the `lookup-index` GSI.
pub(crate) const GSI1PK: &str = "gsi1pk";
/// Partition-key attribute of the `owner-index` GSI.
pub(crate) const GSI2PK: &str = "gsi2pk";
/// Native-TTL attribute (epoch seconds). Present only on ephemeral records, and
/// only when their expiry is in the wall-clock future (see [`ttl_attr`]).
pub(crate) const TTL: &str = "ttl";
/// Discriminator naming which kind of record an item holds; the purge scans
/// filter on it.
pub(crate) const ENTITY: &str = "entity";
/// Expiry timestamp attribute (RFC3339), read back for the purge/expiry filter.
pub(crate) const EXPIRES_AT: &str = "expires_at";

/// Name of the secondary-lookup GSI (token hash → session).
const GSI1: &str = "lookup-index";
/// Name of the per-user-collection GSI.
const GSI2: &str = "owner-index";

/// Wrap a concrete backend error as an opaque [`StorageError`].
pub(crate) fn err<E>(e: E) -> StorageError
where
    E: std::error::Error + Send + Sync + 'static,
{
    StorageError::new(e)
}

// ---------------------------------------------------------------------------
// AttributeValue builders
// ---------------------------------------------------------------------------

/// A DynamoDB string (`S`) attribute.
pub(crate) fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

/// A DynamoDB number (`N`) attribute from an `i64`.
pub(crate) fn n(v: i64) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

/// A DynamoDB binary (`B`) attribute.
pub(crate) fn b(bytes: Vec<u8>) -> AttributeValue {
    AttributeValue::B(Blob::new(bytes))
}

/// A DynamoDB boolean (`BOOL`) attribute.
pub(crate) fn boolean(v: bool) -> AttributeValue {
    AttributeValue::Bool(v)
}

/// A DynamoDB list (`L`) of strings. An ordered list (not a string set) so the
/// order and any empties of the source `Vec` survive the round trip.
pub(crate) fn list_s(items: impl IntoIterator<Item = String>) -> AttributeValue {
    AttributeValue::L(items.into_iter().map(AttributeValue::S).collect())
}

/// The TTL attribute value for a record expiring at `expires_at`, or `None`
/// when the expiry is already in the past.
///
/// DynamoDB's native TTL is a *production* memory-reclamation backstop, never a
/// correctness mechanism: deletion lags by up to ~48h, so the stores filter
/// `expires_at > now` on read and reclaim in `purge_expired` regardless. Gating
/// on a future expiry mirrors the Redis adapter's `PEXPIREAT` gate: the
/// conformance suite's fixed test instants sit in the real past, so without the
/// gate their rows would carry an already-elapsed TTL and could be swept out
/// from under the very purge/read-filter assertions that exercise them.
pub(crate) fn ttl_attr(expires_at: DateTime<Utc>) -> Option<AttributeValue> {
    (expires_at > Utc::now()).then(|| n(expires_at.timestamp()))
}

// ---------------------------------------------------------------------------
// AttributeValue extractors
// ---------------------------------------------------------------------------

fn missing(key: &str) -> StorageError {
    StorageError::msg(format!("item is missing attribute `{key}`"))
}

fn wrong_type(key: &str, want: &str) -> StorageError {
    StorageError::msg(format!("attribute `{key}` is not a {want}"))
}

/// Read a required string attribute.
pub(crate) fn get_s(item: &Item, key: &str) -> StorageResult<String> {
    item.get(key)
        .ok_or_else(|| missing(key))?
        .as_s()
        .map(ToOwned::to_owned)
        .map_err(|_| wrong_type(key, "string"))
}

/// Read an optional string attribute. A missing or `NULL` attribute is `None`.
pub(crate) fn get_opt_s(item: &Item, key: &str) -> StorageResult<Option<String>> {
    match item.get(key) {
        None | Some(AttributeValue::Null(_)) => Ok(None),
        Some(av) => av
            .as_s()
            .map(|v| Some(v.to_owned()))
            .map_err(|_| wrong_type(key, "string")),
    }
}

/// Read a required binary attribute as owned bytes.
pub(crate) fn get_b(item: &Item, key: &str) -> StorageResult<Vec<u8>> {
    item.get(key)
        .ok_or_else(|| missing(key))?
        .as_b()
        .map(|blob| blob.as_ref().to_vec())
        .map_err(|_| wrong_type(key, "binary"))
}

/// Read a required boolean attribute.
pub(crate) fn get_bool(item: &Item, key: &str) -> StorageResult<bool> {
    item.get(key)
        .ok_or_else(|| missing(key))?
        .as_bool()
        .copied()
        .map_err(|_| wrong_type(key, "bool"))
}

/// Read a list-of-strings attribute. A missing attribute yields an empty `Vec`.
pub(crate) fn get_list_s(item: &Item, key: &str) -> StorageResult<Vec<String>> {
    match item.get(key) {
        None => Ok(Vec::new()),
        Some(av) => av
            .as_l()
            .map_err(|_| wrong_type(key, "list"))?
            .iter()
            .map(|el| {
                el.as_s()
                    .map(ToOwned::to_owned)
                    .map_err(|_| wrong_type(key, "list of strings"))
            })
            .collect(),
    }
}

/// Read a UUID stored as a string attribute.
pub(crate) fn get_uuid(item: &Item, key: &str) -> StorageResult<Uuid> {
    Uuid::parse_str(&get_s(item, key)?).map_err(err)
}

/// Read a 32-byte token hash stored as a binary attribute.
pub(crate) fn get_token_hash(item: &Item, key: &str) -> StorageResult<TokenHash> {
    let arr: [u8; 32] = get_b(item, key)?
        .try_into()
        .map_err(|_| StorageError::msg("token_hash attribute was not 32 bytes"))?;
    Ok(TokenHash(arr))
}

/// Read a required timestamp attribute (RFC3339 string).
pub(crate) fn get_ts(item: &Item, key: &str) -> StorageResult<DateTime<Utc>> {
    parse_ts(&get_s(item, key)?)
}

/// Read an optional timestamp attribute (RFC3339 string).
pub(crate) fn get_opt_ts(item: &Item, key: &str) -> StorageResult<Option<DateTime<Utc>>> {
    match get_opt_s(item, key)? {
        Some(raw) => Ok(Some(parse_ts(&raw)?)),
        None => Ok(None),
    }
}

/// The primary key of a queried/scanned item, for addressing it in a delete.
pub(crate) fn item_pk(item: &Item) -> StorageResult<String> {
    get_s(item, PK)
}

/// Render a timestamp as a fixed-width RFC3339 string (nanosecond precision,
/// `Z` suffix). Fixed width keeps the encoding lossless and lexically ordered.
pub(crate) fn fmt_ts(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn parse_ts(raw: &str) -> StorageResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(err)
}

// ---------------------------------------------------------------------------
// The connection wrapper
// ---------------------------------------------------------------------------

/// A cloneable handle bundling the AWS SDK client with the table name.
///
/// Cloning is cheap: the SDK [`Client`] is internally reference-counted and the
/// table name is a small `String`, so each store holds its own clone.
#[derive(Clone)]
pub(crate) struct DynamoClient {
    client: Client,
    table: String,
}

impl DynamoClient {
    /// Build a handle over `client`, targeting `table`.
    pub(crate) fn new(client: Client, table: String) -> Self {
        Self { client, table }
    }

    /// The configured table name.
    pub(crate) fn table(&self) -> &str {
        &self.table
    }

    /// The underlying SDK client, for the few stores that issue conditional
    /// writes or transactions directly.
    pub(crate) fn inner(&self) -> &Client {
        &self.client
    }

    /// Strongly-consistent `GetItem` by primary key.
    pub(crate) async fn get(&self, pk: &str) -> StorageResult<Option<Item>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(PK, s(pk))
            .consistent_read(true)
            .send()
            .await
            .map_err(err)?;
        Ok(out.item)
    }

    /// Plain `PutItem`. This is an upsert (a repeated key overwrites), which the
    /// storage contract permits for the ephemeral, randomly-keyed records.
    pub(crate) async fn put(&self, item: Item) -> StorageResult<()> {
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(err)?;
        Ok(())
    }

    /// Conditional `PutItem` that writes only when an item with the same
    /// primary key already exists (`attribute_exists(pk)`). The
    /// `ConditionalCheckFailedException` raised when the row is absent is
    /// swallowed into a no-op `Ok(())`, so a touch never recreates a session
    /// deleted between resolution and write (the resurrection hazard).
    pub(crate) async fn put_if_exists(&self, item: Item) -> StorageResult<()> {
        let result = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", PK)
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.as_service_error()
                    .is_some_and(|svc| svc.is_conditional_check_failed_exception())
                {
                    // The row no longer exists; the conditional put is a no-op.
                    return Ok(());
                }
                Err(err(e))
            }
        }
    }

    /// `DeleteItem` by primary key. A delete of an absent key is a no-op.
    pub(crate) async fn delete(&self, pk: &str) -> StorageResult<()> {
        self.client
            .delete_item()
            .table_name(&self.table)
            .key(PK, s(pk))
            .send()
            .await
            .map_err(err)?;
        Ok(())
    }

    /// Atomic delete-and-return: `DeleteItem` with `ReturnValues=ALL_OLD`,
    /// guarded by `attribute_exists(pk)`.
    ///
    /// The condition is what makes the take single-use: a conditional write is
    /// evaluated against the item's current state, so under concurrency exactly
    /// one caller's delete succeeds and returns the old image. Every other
    /// caller fails the condition, which is swallowed into `None`. An
    /// unconditional delete gives no such guarantee; DynamoDB Local returns the
    /// old image to several concurrent deleters.
    pub(crate) async fn take(&self, pk: &str) -> StorageResult<Option<Item>> {
        let result = self
            .client
            .delete_item()
            .table_name(&self.table)
            .key(PK, s(pk))
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", PK)
            .return_values(ReturnValue::AllOld)
            .send()
            .await;
        match result {
            Ok(out) => Ok(out.attributes.filter(|m| !m.is_empty())),
            Err(e) => {
                if e.as_service_error()
                    .is_some_and(|svc| svc.is_conditional_check_failed_exception())
                {
                    // Absent, or another caller took it first.
                    return Ok(None);
                }
                Err(err(e))
            }
        }
    }

    /// Query the `owner-index` partition `key`, returning every projected item.
    pub(crate) async fn query_owner(&self, key: &str) -> StorageResult<Vec<Item>> {
        self.query_index(GSI2, GSI2PK, key).await
    }

    /// Query the `lookup-index` partition `key`, returning every projected item.
    pub(crate) async fn query_lookup(&self, key: &str) -> StorageResult<Vec<Item>> {
        self.query_index(GSI1, GSI1PK, key).await
    }

    /// Count the items in an `owner-index` partition without fetching them.
    pub(crate) async fn count_owner(&self, key: &str) -> StorageResult<u64> {
        let mut total: i64 = 0;
        let mut start: Option<Item> = None;
        loop {
            let mut req = self
                .client
                .query()
                .table_name(&self.table)
                .index_name(GSI2)
                .key_condition_expression("#k = :v")
                .expression_attribute_names("#k", GSI2PK)
                .expression_attribute_values(":v", s(key))
                .select(Select::Count);
            if let Some(start) = start.take() {
                req = req.set_exclusive_start_key(Some(start));
            }
            let resp = req.send().await.map_err(err)?;
            total += i64::from(resp.count);
            match resp.last_evaluated_key {
                Some(k) if !k.is_empty() => start = Some(k),
                _ => break,
            }
        }
        Ok(total.max(0) as u64)
    }

    async fn query_index(
        &self,
        index: &str,
        key_attr: &str,
        key_val: &str,
    ) -> StorageResult<Vec<Item>> {
        let mut out = Vec::new();
        let mut start: Option<Item> = None;
        loop {
            let mut req = self
                .client
                .query()
                .table_name(&self.table)
                .index_name(index)
                .key_condition_expression("#k = :v")
                .expression_attribute_names("#k", key_attr)
                .expression_attribute_values(":v", s(key_val));
            if let Some(start) = start.take() {
                req = req.set_exclusive_start_key(Some(start));
            }
            let resp = req.send().await.map_err(err)?;
            if let Some(items) = resp.items {
                out.extend(items);
            }
            match resp.last_evaluated_key {
                Some(k) if !k.is_empty() => start = Some(k),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Strongly-consistent table `Scan` returning every item whose `entity`
    /// discriminator is one of `entities`. Backs [`delete_expired`](Self::delete_expired),
    /// which then filters on `expires_at`. Consistent so a row written moments
    /// earlier (as the conformance suite does) is visible.
    async fn scan_entities(&self, entities: &[&str]) -> StorageResult<Vec<Item>> {
        let mut names = HashMap::new();
        names.insert("#e".to_string(), ENTITY.to_string());
        let mut values = HashMap::new();
        let mut placeholders = Vec::with_capacity(entities.len());
        for (i, entity) in entities.iter().enumerate() {
            let ph = format!(":e{i}");
            values.insert(ph.clone(), s(*entity));
            placeholders.push(ph);
        }
        let filter = format!("#e IN ({})", placeholders.join(", "));

        let mut out = Vec::new();
        let mut start: Option<Item> = None;
        loop {
            let mut req = self
                .client
                .scan()
                .table_name(&self.table)
                .consistent_read(true)
                .filter_expression(&filter)
                .set_expression_attribute_names(Some(names.clone()))
                .set_expression_attribute_values(Some(values.clone()));
            if let Some(start) = start.take() {
                req = req.set_exclusive_start_key(Some(start));
            }
            let resp = req.send().await.map_err(err)?;
            if let Some(items) = resp.items {
                out.extend(items);
            }
            match resp.last_evaluated_key {
                Some(k) if !k.is_empty() => start = Some(k),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Delete a batch of primary keys with `BatchWriteItem`, chunked to the
    /// 25-item limit and retrying any unprocessed items the service returns.
    pub(crate) async fn batch_delete(&self, pks: Vec<String>) -> StorageResult<()> {
        for chunk in pks.chunks(25) {
            let mut requests = Vec::with_capacity(chunk.len());
            for pk in chunk {
                let delete = DeleteRequest::builder()
                    .key(PK, s(pk))
                    .build()
                    .map_err(err)?;
                requests.push(WriteRequest::builder().delete_request(delete).build());
            }
            let mut pending: HashMap<String, Vec<WriteRequest>> = HashMap::new();
            pending.insert(self.table.clone(), requests);

            // DynamoDB may decline some writes under load; resubmit until drained.
            for _ in 0..8 {
                if pending.is_empty() {
                    break;
                }
                let resp = self
                    .client
                    .batch_write_item()
                    .set_request_items(Some(pending))
                    .send()
                    .await
                    .map_err(err)?;
                pending = resp.unprocessed_items.unwrap_or_default();
                pending.retain(|_, reqs| !reqs.is_empty());
            }
            if !pending.is_empty() {
                return Err(StorageError::msg(
                    "batch delete did not drain its unprocessed items",
                ));
            }
        }
        Ok(())
    }

    /// Delete every item in the `owner-index` partition `key`, returning how
    /// many were removed.
    ///
    /// The partition is read through the eventually-consistent GSI, so an item
    /// written immediately before the call may not be visible yet and survives
    /// it; a later bulk delete, `purge_expired`, or native TTL reclaims it.
    pub(crate) async fn delete_owned(&self, key: &str) -> StorageResult<u64> {
        let pks = self
            .query_owner(key)
            .await?
            .iter()
            .map(item_pk)
            .collect::<StorageResult<Vec<_>>>()?;
        let removed = pks.len() as u64;
        self.batch_delete(pks).await?;
        Ok(removed)
    }

    /// Delete every item of the given `entities` whose `expires_at` is at or
    /// before `now`, returning how many were removed. Backs the authoritative
    /// `purge_expired` sweeps; native TTL is only a memory backstop.
    pub(crate) async fn delete_expired(
        &self,
        entities: &[&str],
        now: DateTime<Utc>,
    ) -> StorageResult<u64> {
        let mut pks = Vec::new();
        for item in &self.scan_entities(entities).await? {
            if get_ts(item, EXPIRES_AT)? <= now {
                pks.push(item_pk(item)?);
            }
        }
        let removed = pks.len() as u64;
        self.batch_delete(pks).await?;
        Ok(removed)
    }

    /// Provision the table, its two GSIs, and native TTL — idempotently.
    ///
    /// Safe to call on every boot: an already-existing table short-circuits on
    /// the `ResourceInUseException`. Uses on-demand (`PAY_PER_REQUEST`) billing
    /// so a host need not provision throughput.
    pub(crate) async fn ensure_table(&self) -> StorageResult<()> {
        let string_attr = |name: &str| {
            AttributeDefinition::builder()
                .attribute_name(name)
                .attribute_type(ScalarAttributeType::S)
                .build()
                .map_err(err)
        };
        let hash_index = |name: &str, key_attr: &str| -> StorageResult<GlobalSecondaryIndex> {
            let key = KeySchemaElement::builder()
                .attribute_name(key_attr)
                .key_type(KeyType::Hash)
                .build()
                .map_err(err)?;
            GlobalSecondaryIndex::builder()
                .index_name(name)
                .key_schema(key)
                .projection(
                    Projection::builder()
                        .projection_type(ProjectionType::All)
                        .build(),
                )
                .build()
                .map_err(err)
        };
        let primary_key = KeySchemaElement::builder()
            .attribute_name(PK)
            .key_type(KeyType::Hash)
            .build()
            .map_err(err)?;

        let created = self
            .client
            .create_table()
            .table_name(&self.table)
            .billing_mode(BillingMode::PayPerRequest)
            .attribute_definitions(string_attr(PK)?)
            .attribute_definitions(string_attr(GSI1PK)?)
            .attribute_definitions(string_attr(GSI2PK)?)
            .key_schema(primary_key)
            .global_secondary_indexes(hash_index(GSI1, GSI1PK)?)
            .global_secondary_indexes(hash_index(GSI2, GSI2PK)?)
            .send()
            .await;
        match created {
            Ok(_) => {}
            Err(e) => {
                if e.as_service_error()
                    .is_some_and(|svc| svc.is_resource_in_use_exception())
                {
                    // The table already exists; assume it was provisioned by a
                    // previous call and leave its TTL settings as they are.
                    return Ok(());
                }
                return Err(err(e));
            }
        }

        // The table (and its GSIs) must be ACTIVE before TTL can be configured.
        self.client
            .wait_until_table_exists()
            .table_name(&self.table)
            .wait(Duration::from_secs(60))
            .await
            .map_err(err)?;

        let spec = TimeToLiveSpecification::builder()
            .enabled(true)
            .attribute_name(TTL)
            .build()
            .map_err(err)?;
        self.client
            .update_time_to_live()
            .table_name(&self.table)
            .time_to_live_specification(spec)
            .send()
            .await
            .map_err(err)?;
        Ok(())
    }
}
