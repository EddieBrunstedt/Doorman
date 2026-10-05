use std::collections::HashMap;
use std::time::Duration;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::client::Waiters as _;
use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, DeleteRequest, GlobalSecondaryIndex,
    KeySchemaElement, KeyType, KeysAndAttributes, Projection, ProjectionType, ReturnValue,
    ScalarAttributeType, Select, TimeToLiveSpecification, WriteRequest,
};
use chrono::{DateTime, SecondsFormat, Utc};
use doorman_core::error::{StorageError, StorageResult};
use uuid::Uuid;

use doorman_core::storage::TokenHash;

pub(crate) type Item = HashMap<String, AttributeValue>;

pub(crate) const PK: &str = "pk";
pub(crate) const GSI1PK: &str = "gsi1pk";
pub(crate) const GSI2PK: &str = "gsi2pk";
pub(crate) const TTL: &str = "ttl";
pub(crate) const ENTITY: &str = "entity";
pub(crate) const EXPIRES_AT: &str = "expires_at";

const GSI1: &str = "lookup-index";
const GSI2: &str = "owner-index";

pub(crate) fn err<E>(e: E) -> StorageError
where
    E: std::error::Error + Send + Sync + 'static,
{
    StorageError::new(e)
}

pub(crate) fn condition_err<E>(
    e: SdkError<E>,
    on_condition: impl FnOnce() -> StorageError,
) -> StorageError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    if is_condition_failure(&e) {
        on_condition()
    } else {
        err(e)
    }
}

pub(crate) fn is_condition_failure<E>(e: &SdkError<E>) -> bool
where
    E: ProvideErrorMetadata,
{
    e.as_service_error()
        .and_then(|svc| svc.code())
        .is_some_and(|code| code == "ConditionalCheckFailedException")
}

pub(crate) fn failed_conditions(e: &SdkError<TransactWriteItemsError>) -> Vec<usize> {
    match e.as_service_error() {
        Some(TransactWriteItemsError::TransactionCanceledException(cancelled)) => cancelled
            .cancellation_reasons()
            .iter()
            .enumerate()
            .filter(|(_, reason)| reason.code() == Some("ConditionalCheckFailed"))
            .map(|(i, _)| i)
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

pub(crate) fn n(v: i64) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

pub(crate) fn b(bytes: Vec<u8>) -> AttributeValue {
    AttributeValue::B(Blob::new(bytes))
}

pub(crate) fn boolean(v: bool) -> AttributeValue {
    AttributeValue::Bool(v)
}

pub(crate) fn list_s(items: impl IntoIterator<Item = String>) -> AttributeValue {
    AttributeValue::L(items.into_iter().map(AttributeValue::S).collect())
}

pub(crate) fn ss(items: impl IntoIterator<Item = String>) -> AttributeValue {
    AttributeValue::Ss(items.into_iter().collect())
}

pub(crate) fn ttl_attr(expires_at: DateTime<Utc>) -> Option<AttributeValue> {
    (expires_at > Utc::now()).then(|| n(expires_at.timestamp()))
}

fn missing(key: &str) -> StorageError {
    StorageError::msg(format!("item is missing attribute `{key}`"))
}

fn wrong_type(key: &str, want: &str) -> StorageError {
    StorageError::msg(format!("attribute `{key}` is not a {want}"))
}

pub(crate) fn get_s(item: &Item, key: &str) -> StorageResult<String> {
    item.get(key)
        .ok_or_else(|| missing(key))?
        .as_s()
        .map(ToOwned::to_owned)
        .map_err(|_| wrong_type(key, "string"))
}

pub(crate) fn get_opt_s(item: &Item, key: &str) -> StorageResult<Option<String>> {
    match item.get(key) {
        None | Some(AttributeValue::Null(_)) => Ok(None),
        Some(av) => av
            .as_s()
            .map(|v| Some(v.to_owned()))
            .map_err(|_| wrong_type(key, "string")),
    }
}

pub(crate) fn get_b(item: &Item, key: &str) -> StorageResult<Vec<u8>> {
    item.get(key)
        .ok_or_else(|| missing(key))?
        .as_b()
        .map(|blob| blob.as_ref().to_vec())
        .map_err(|_| wrong_type(key, "binary"))
}

pub(crate) fn get_bool(item: &Item, key: &str) -> StorageResult<bool> {
    item.get(key)
        .ok_or_else(|| missing(key))?
        .as_bool()
        .copied()
        .map_err(|_| wrong_type(key, "bool"))
}

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

pub(crate) fn get_ss(item: &Item, key: &str) -> StorageResult<Vec<String>> {
    match item.get(key) {
        None => Ok(Vec::new()),
        Some(av) => av
            .as_ss()
            .cloned()
            .map_err(|_| wrong_type(key, "string set")),
    }
}

pub(crate) fn get_uuid(item: &Item, key: &str) -> StorageResult<Uuid> {
    Uuid::parse_str(&get_s(item, key)?).map_err(err)
}

pub(crate) fn get_token_hash(item: &Item, key: &str) -> StorageResult<TokenHash> {
    let arr: [u8; 32] = get_b(item, key)?
        .try_into()
        .map_err(|_| StorageError::msg("token_hash attribute was not 32 bytes"))?;
    Ok(TokenHash(arr))
}

pub(crate) fn get_ts(item: &Item, key: &str) -> StorageResult<DateTime<Utc>> {
    parse_ts(&get_s(item, key)?)
}

pub(crate) fn get_opt_ts(item: &Item, key: &str) -> StorageResult<Option<DateTime<Utc>>> {
    match get_opt_s(item, key)? {
        Some(raw) => Ok(Some(parse_ts(&raw)?)),
        None => Ok(None),
    }
}

pub(crate) fn item_pk(item: &Item) -> StorageResult<String> {
    get_s(item, PK)
}

pub(crate) fn fmt_ts(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn parse_ts(raw: &str) -> StorageResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(err)
}

#[derive(Clone)]
pub(crate) struct DynamoClient {
    client: Client,
    table: String,
}

impl DynamoClient {
    pub(crate) fn new(client: Client, table: String) -> Self {
        Self { client, table }
    }

    pub(crate) fn table(&self) -> &str {
        &self.table
    }

    pub(crate) fn inner(&self) -> &Client {
        &self.client
    }

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
                    return Ok(None);
                }
                Err(err(e))
            }
        }
    }

    pub(crate) async fn query_owner(&self, key: &str) -> StorageResult<Vec<Item>> {
        self.query_index(GSI2, GSI2PK, key).await
    }

    pub(crate) async fn query_lookup(&self, key: &str) -> StorageResult<Vec<Item>> {
        self.query_index(GSI1, GSI1PK, key).await
    }

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

    pub(crate) async fn scan_entities(&self, entities: &[&str]) -> StorageResult<Vec<Item>> {
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

    pub(crate) async fn batch_get(&self, pks: &[String]) -> StorageResult<Vec<Item>> {
        let mut out = Vec::with_capacity(pks.len());
        for chunk in pks.chunks(100) {
            let mut keys = Vec::with_capacity(chunk.len());
            for pk in chunk {
                keys.push(HashMap::from([(PK.to_string(), s(pk))]));
            }
            let request = KeysAndAttributes::builder()
                .set_keys(Some(keys))
                .consistent_read(true)
                .build()
                .map_err(err)?;
            let mut pending = HashMap::from([(self.table.clone(), request)]);

            for _ in 0..8 {
                if pending.is_empty() {
                    break;
                }
                let resp = self
                    .client
                    .batch_get_item()
                    .set_request_items(Some(pending))
                    .send()
                    .await
                    .map_err(err)?;
                if let Some(mut responses) = resp.responses
                    && let Some(items) = responses.remove(&self.table)
                {
                    out.extend(items);
                }
                pending = resp.unprocessed_keys.unwrap_or_default();
                pending.retain(|_, request| !request.keys.is_empty());
            }
            if !pending.is_empty() {
                return Err(StorageError::msg(
                    "batch get did not drain its unprocessed keys",
                ));
            }
        }
        Ok(out)
    }

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
                    return Ok(());
                }
                return Err(err(e));
            }
        }

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
