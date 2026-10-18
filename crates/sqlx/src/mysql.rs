use sqlx::MySqlPool;
use sqlx::mysql::MySqlPoolOptions;

#[derive(Clone)]
pub struct MySqlStorage {
    pool: MySqlPool,
}

impl MySqlStorage {
    pub const DEFAULT_MAX_CONNECTIONS: u32 = 8;

    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let pool = MySqlPoolOptions::new()
            .max_connections(Self::DEFAULT_MAX_CONNECTIONS)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: MySqlPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations/mysql").run(&self.pool).await
    }
}

crate::stores::sqlx_stores! {
    storage: MySqlStorage,
    pool: MySqlPool,
    row: sqlx::mysql::MySqlRow,
    placeholders: crate::common::ph_mysql,
    timestamp: crate::common::ts_mysql,
    take: txn,
    replace_link: update_or_insert,
}
