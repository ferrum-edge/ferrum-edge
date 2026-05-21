use sqlx::AnyPool;

use super::Migration;

/// V2: Add admin audit event persistence table for SQL backends.
pub struct V002AddAuditEvents;

impl Migration for V002AddAuditEvents {
    fn version(&self) -> i64 {
        2
    }

    fn name(&self) -> &str {
        "add_audit_events"
    }

    fn checksum(&self) -> &str {
        "v002_add_audit_events"
    }
}

impl V002AddAuditEvents {
    pub async fn up(&self, pool: &AnyPool, db_type: &str) -> Result<(), anyhow::Error> {
        let sql = if db_type == "mysql" {
            r#"
            CREATE TABLE IF NOT EXISTS audit_events (
                id VARCHAR(255) COLLATE utf8mb4_0900_as_cs PRIMARY KEY,
                ts VARCHAR(50) NOT NULL,
                actor VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
                action VARCHAR(64) COLLATE utf8mb4_0900_as_cs NOT NULL,
                resource_type VARCHAR(128) COLLATE utf8mb4_0900_as_cs NOT NULL,
                resource_id VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
                namespace VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL DEFAULT 'ferrum',
                diff LONGTEXT NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                diff TEXT NOT NULL
            )
            "#
        };

        sqlx::query(sql).execute(pool).await?;
        Ok(())
    }
}
