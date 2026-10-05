use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

#[derive(Clone)]
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub const DEFAULT_MAX_CONNECTIONS: u32 = 8;

    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let opts: SqliteConnectOptions = url.parse()?;
        let pool = SqlitePoolOptions::new()
            .max_connections(Self::DEFAULT_MAX_CONNECTIONS)
            .connect_with(opts.foreign_keys(true).create_if_missing(true))
            .await?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations/sqlite").run(&self.pool).await
    }
}

crate::stores::sqlx_stores! {
    storage: SqliteStorage,
    pool: SqlitePool,
    row: sqlx::sqlite::SqliteRow,
    placeholders: crate::common::ph_sqlite,
    timestamp: crate::common::ts_passthrough,
    take: returning,
}
