//! Thin wrapper over a shared [`libsql::Connection`] with the few query shapes
//! the stores need.
//!
//! Every store holds a clone of one `LibsqlConn`. A `libsql::Connection` is
//! cheaply clonable (reference-counted) and `Send + Sync`, so the clones share a
//! single underlying connection — the single-connection model the crate docs
//! describe. The helpers funnel every driver error through
//! [`convert::err`](crate::convert::err) so the stores deal only in
//! [`StorageResult`].

use doorman_core::error::StorageResult;
use libsql::Value;

use crate::convert::err;

/// Shared handle to the libSQL connection backing one or more stores.
#[derive(Clone)]
pub(crate) struct LibsqlConn {
    conn: libsql::Connection,
}

impl LibsqlConn {
    pub(crate) fn new(conn: libsql::Connection) -> Self {
        Self { conn }
    }

    /// A clone of the underlying connection, for the few callers that need the
    /// raw libSQL API (e.g. `execute_batch` for the schema migration) and want
    /// the driver's own error type rather than [`StorageError`].
    pub(crate) fn raw(&self) -> libsql::Connection {
        self.conn.clone()
    }

    /// Run a statement that returns no rows, yielding the affected row count.
    pub(crate) async fn execute(&self, sql: &str, params: Vec<Value>) -> StorageResult<u64> {
        self.conn.execute(sql, params).await.map_err(err)
    }

    /// Run a query and return the first row, if any. Also the shape the atomic
    /// `DELETE ... RETURNING` takes use.
    pub(crate) async fn query_opt(
        &self,
        sql: &str,
        params: Vec<Value>,
    ) -> StorageResult<Option<libsql::Row>> {
        let mut rows = self.conn.query(sql, params).await.map_err(err)?;
        rows.next().await.map_err(err)
    }

    /// Run a query and map every row, in order.
    ///
    /// Each row is mapped in place as the cursor yields it: a libSQL [`Row`] is
    /// only valid until the next `next()` call, so it cannot be collected into a
    /// `Vec` and mapped afterwards (the earlier rows read back as NULL).
    ///
    /// [`Row`]: libsql::Row
    pub(crate) async fn query_map<T, F>(
        &self,
        sql: &str,
        params: Vec<Value>,
        mut map: F,
    ) -> StorageResult<Vec<T>>
    where
        F: FnMut(&libsql::Row) -> StorageResult<T>,
    {
        let mut rows = self.conn.query(sql, params).await.map_err(err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(err)? {
            out.push(map(&row)?);
        }
        Ok(out)
    }

    /// Run a `SELECT COUNT(*)` style query and return the scalar count.
    pub(crate) async fn count(&self, sql: &str, params: Vec<Value>) -> StorageResult<u64> {
        let row = self
            .query_opt(sql, params)
            .await?
            .ok_or_else(|| crate::convert::err("count query returned no row"))?;
        Ok(crate::convert::col_int(&row, 0)?.max(0) as u64)
    }
}
