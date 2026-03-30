use sqlx::AnyPool;

use super::Migration;

/// V2: Add `hash_on_cookie_config` column to the `upstreams` table.
///
/// Supports configurable sticky session cookies for consistent-hashing
/// load balancing (`hash_on: "cookie:<name>"`).
pub struct V002HashOnCookieConfig;

impl Migration for V002HashOnCookieConfig {
    fn version(&self) -> i64 {
        2
    }

    fn name(&self) -> &str {
        "hash_on_cookie_config"
    }

    fn checksum(&self) -> &str {
        "v002_hash_on_cookie_config"
    }
}

impl V002HashOnCookieConfig {
    pub async fn up(&self, pool: &AnyPool, db_type: &str) -> Result<(), anyhow::Error> {
        let sql = if db_type == "mysql" {
            "ALTER TABLE upstreams ADD COLUMN hash_on_cookie_config TEXT"
        } else {
            // PostgreSQL and SQLite
            "ALTER TABLE upstreams ADD COLUMN hash_on_cookie_config TEXT"
        };

        sqlx::query(sql).execute(pool).await?;
        Ok(())
    }
}
