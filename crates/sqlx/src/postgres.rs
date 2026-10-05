use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

#[derive(Clone)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub const DEFAULT_MAX_CONNECTIONS: u32 = 8;

    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(Self::DEFAULT_MAX_CONNECTIONS)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations/postgres")
            .run(&self.pool)
            .await
    }
}

crate::stores::sqlx_stores! {
    storage: PostgresStorage,
    pool: PgPool,
    row: sqlx::postgres::PgRow,
    placeholders: crate::common::ph_postgres,
    timestamp: crate::common::ts_passthrough,
    take: returning,
}
