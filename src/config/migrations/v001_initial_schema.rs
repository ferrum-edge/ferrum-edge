use sqlx::AnyPool;

use super::Migration;
use super::sql_dialect::V001SqlBuilder;

/// V1: Initial schema — creates the baseline tables.
/// This matches the original inline schema from db_loader.rs.
pub struct V001InitialSchema;

impl Migration for V001InitialSchema {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "initial_schema"
    }

    fn checksum(&self) -> &str {
        "v001_initial_schema"
    }
}

impl V001InitialSchema {
    pub async fn up(&self, pool: &AnyPool, db_type: &str) -> Result<(), anyhow::Error> {
        V001SqlBuilder::new(db_type).apply(pool).await
    }
}
