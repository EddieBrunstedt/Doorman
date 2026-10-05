use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use aws_sdk_dynamodb::types::{Put, ReturnValue, TransactWriteItem, Update};
use chrono::{DateTime, Utc};
use doorman_core::error::StorageResult;
use doorman_core::storage::{Session, SessionId, SessionStore, TokenHash, UserId};

use crate::client::{self, DynamoClient, PK};
use crate::model::{self, ENTITY_SESSION, ENTITY_SESSION_INDEX, SESSION_IDS};

pub(crate) fn create_writes(
    table: &str,
    session: &Session,
) -> StorageResult<Vec<TransactWriteItem>> {
    let row = Put::builder()
        .table_name(table)
        .set_item(Some(model::session_item(session)))
        .build()
        .map_err(client::err)?;
    let index = Update::builder()
        .table_name(table)
        .key(PK, client::s(model::session_index_pk(session.user_id)))
        .update_expression("SET #entity = :entity, #user_id = :user_id ADD #ids :id")
        .expression_attribute_names("#entity", client::ENTITY)
        .expression_attribute_names("#user_id", "user_id")
        .expression_attribute_names("#ids", SESSION_IDS)
        .expression_attribute_values(":entity", client::s(ENTITY_SESSION_INDEX))
        .expression_attribute_values(":user_id", client::s(session.user_id.0.to_string()))
        .expression_attribute_values(":id", client::ss([session.id.0.to_string()]))
        .build()
        .map_err(client::err)?;
    Ok(vec![
        TransactWriteItem::builder().put(row).build(),
        TransactWriteItem::builder().update(index).build(),
    ])
}

pub(crate) struct DynamoSessionStore {
    client: DynamoClient,
}

impl DynamoSessionStore {
    pub(crate) fn new(client: DynamoClient) -> Self {
        Self { client }
    }

    async fn indexed_ids(&self, user_id: UserId) -> StorageResult<Vec<String>> {
        match self.client.get(&model::session_index_pk(user_id)).await? {
            Some(item) => client::get_ss(&item, SESSION_IDS),
            None => Ok(Vec::new()),
        }
    }

    async fn load(&self, ids: &[String]) -> StorageResult<(Vec<Session>, Vec<String>)> {
        let pks: Vec<String> = ids.iter().map(|id| model::session_pk_for(id)).collect();
        let sessions = self
            .client
            .batch_get(&pks)
            .await?
            .iter()
            .map(model::session_from_item)
            .collect::<StorageResult<Vec<_>>>()?;
        let found: HashSet<String> = sessions.iter().map(|s| s.id.0.to_string()).collect();
        let gone = ids
            .iter()
            .filter(|id| !found.contains(*id))
            .cloned()
            .collect();
        Ok((sessions, gone))
    }

    async fn unindex(&self, user_id: UserId, ids: Vec<String>) -> StorageResult<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let pk = model::session_index_pk(user_id);
        let updated = self
            .client
            .inner()
            .update_item()
            .table_name(self.client.table())
            .key(PK, client::s(&pk))
            .update_expression("DELETE #ids :ids")
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", PK)
            .expression_attribute_names("#ids", SESSION_IDS)
            .expression_attribute_values(":ids", client::ss(ids))
            .return_values(ReturnValue::AllNew)
            .send()
            .await;
        let emptied = match updated {
            Ok(out) => out
                .attributes
                .is_some_and(|item| !item.contains_key(SESSION_IDS)),
            Err(e) if client::is_condition_failure(&e) => false,
            Err(e) => return Err(client::err(e)),
        };
        if !emptied {
            return Ok(());
        }
        let deleted = self
            .client
            .inner()
            .delete_item()
            .table_name(self.client.table())
            .key(PK, client::s(&pk))
            .condition_expression("attribute_not_exists(#ids)")
            .expression_attribute_names("#ids", SESSION_IDS)
            .send()
            .await;
        match deleted {
            Ok(_) => Ok(()),
            Err(e) if client::is_condition_failure(&e) => Ok(()),
            Err(e) => Err(client::err(e)),
        }
    }
}

#[async_trait]
impl SessionStore for DynamoSessionStore {
    async fn create_session(&self, session: Session) -> StorageResult<()> {
        self.client
            .inner()
            .transact_write_items()
            .set_transact_items(Some(create_writes(self.client.table(), &session)?))
            .send()
            .await
            .map_err(client::err)?;
        Ok(())
    }

    async fn touch_session(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> StorageResult<()> {
        let mut request = self
            .client
            .inner()
            .update_item()
            .table_name(self.client.table())
            .key(PK, client::s(model::session_pk(id)))
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", PK)
            .expression_attribute_names("#last_used_at", "last_used_at")
            .expression_attribute_names("#expires_at", client::EXPIRES_AT)
            .expression_attribute_names("#ttl", client::TTL)
            .expression_attribute_values(":last_used_at", client::s(client::fmt_ts(last_used_at)))
            .expression_attribute_values(":expires_at", client::s(client::fmt_ts(expires_at)));
        request = match client::ttl_attr(expires_at) {
            Some(ttl) => request
                .update_expression(
                    "SET #last_used_at = :last_used_at, #expires_at = :expires_at, #ttl = :ttl",
                )
                .expression_attribute_values(":ttl", ttl),
            None => request.update_expression(
                "SET #last_used_at = :last_used_at, #expires_at = :expires_at REMOVE #ttl",
            ),
        };
        match request.send().await {
            Ok(_) => Ok(()),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|svc| svc.is_conditional_check_failed_exception()) =>
            {
                Ok(())
            }
            Err(e) => Err(client::err(e)),
        }
    }

    async fn find_session_by_token_hash(&self, hash: &TokenHash) -> StorageResult<Option<Session>> {
        let items = self
            .client
            .query_lookup(&model::session_hash_key(hash))
            .await?;
        let Some(item) = items.first() else {
            return Ok(None);
        };
        let id = SessionId(client::get_uuid(item, "id")?);
        self.find_session_by_id(id).await
    }

    async fn find_session_by_id(&self, id: SessionId) -> StorageResult<Option<Session>> {
        match self.client.get(&model::session_pk(id)).await? {
            Some(item) => Ok(Some(model::session_from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn list_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> StorageResult<Vec<Session>> {
        let ids = self.indexed_ids(user_id).await?;
        let (sessions, gone) = self.load(&ids).await?;
        let _ = self.unindex(user_id, gone).await;
        Ok(sessions
            .into_iter()
            .filter(|session| session.expires_at > now)
            .collect())
    }

    async fn delete_session(&self, id: SessionId) -> StorageResult<()> {
        if let Some(item) = self.client.take(&model::session_pk(id)).await? {
            let session = model::session_from_item(&item)?;
            self.unindex(session.user_id, vec![id.0.to_string()])
                .await?;
        }
        Ok(())
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: UserId,
        except: Option<SessionId>,
    ) -> StorageResult<u64> {
        let except = except.map(|id| id.0.to_string());
        let mut ids = self.indexed_ids(user_id).await?;
        ids.retain(|id| Some(id) != except.as_ref());
        if ids.is_empty() {
            return Ok(0);
        }
        let (sessions, _) = self.load(&ids).await?;
        let pks = ids.iter().map(|id| model::session_pk_for(id)).collect();
        self.client.batch_delete(pks).await?;
        self.unindex(user_id, ids).await?;
        Ok(sessions.len() as u64)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> StorageResult<u64> {
        let items = self
            .client
            .scan_entities(&[ENTITY_SESSION, ENTITY_SESSION_INDEX])
            .await?;
        let mut expired_pks = Vec::new();
        let mut expired: HashMap<UserId, Vec<String>> = HashMap::new();
        let mut live = HashSet::new();
        let mut indexes = Vec::new();
        for item in &items {
            if client::get_s(item, client::ENTITY)? == ENTITY_SESSION {
                let session = model::session_from_item(item)?;
                if session.expires_at <= now {
                    expired_pks.push(model::session_pk(session.id));
                    expired
                        .entry(session.user_id)
                        .or_default()
                        .push(session.id.0.to_string());
                } else {
                    live.insert(session.id.0.to_string());
                }
            } else {
                let user_id = UserId(client::get_uuid(item, "user_id")?);
                indexes.push((user_id, client::get_ss(item, SESSION_IDS)?));
            }
        }

        let mut removed = expired_pks.len() as u64;
        self.client.batch_delete(expired_pks).await?;
        for (user_id, ids) in indexes {
            let mut gone = expired.remove(&user_id).unwrap_or_default();
            let unseen: Vec<String> = ids
                .into_iter()
                .filter(|id| !live.contains(id) && !gone.contains(id))
                .collect();
            if !unseen.is_empty() {
                let (_, dangling) = self.load(&unseen).await?;
                removed += dangling.len() as u64;
                gone.extend(dangling);
            }
            self.unindex(user_id, gone).await?;
        }
        for (user_id, ids) in expired {
            self.unindex(user_id, ids).await?;
        }
        Ok(removed)
    }
}
