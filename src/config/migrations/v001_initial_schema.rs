use sqlx::AnyConnection;
use std::sync::OnceLock;

use super::Migration;
use super::sql_dialect::V001SqlBuilder;

/// The committed identity of the frozen V001 baseline.
///
/// This is the value `V001InitialSchema::checksum()` computes from the
/// canonical rendering of every statement V001 executes on PostgreSQL, MySQL,
/// and SQLite ([`canonical_v001_baseline`]). Every database initialized by a
/// release records it in `_ferrum_migrations`, and every later binary must
/// compute the same value or that database refuses to start.
///
/// The golden test `tests/unit/config/v001_baseline_golden_tests.rs` fails
/// when the computed value differs from this constant. From 1.0.0 onward the
/// fix is never to change this constant: put the schema change in a new
/// forward migration (`V002`, `V003`, ...) instead. Releases before 1.0.0
/// updated it by copying the value that failing test prints.
pub const V001_BASELINE_CHECKSUM: &str =
    "sha256:4daeac1eeac715ef55084b92b863c36e042b648334ce16f3379717d0406dc17b";

/// Header of the canonical V001 rendering. Changing it changes the identity.
const CANONICAL_V001_HEADER: &str = "ferrum-edge core migration V001; canonical DDL format 1";

/// V1: Initial schema: creates the baseline tables, indexes, and the default
/// `ferrum` namespace row. Frozen from 1.0.0 onward: later schema changes ship
/// as new forward migrations and never edit this baseline.
pub struct V001InitialSchema;

impl Migration for V001InitialSchema {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "initial_schema"
    }

    /// `sha256:<hex>` over [`canonical_v001_baseline`], not over Rust source:
    /// comments, formatting, and helper refactors in `sql_dialect.rs` leave it
    /// unchanged, while any change to an executed statement changes it.
    fn checksum(&self) -> &str {
        static CHECKSUM: OnceLock<String> = OnceLock::new();
        CHECKSUM.get_or_init(|| super::canonical_checksum(&canonical_v001_baseline()))
    }
}

impl V001InitialSchema {
    pub async fn up(
        &self,
        connection: &mut AnyConnection,
        db_type: &str,
    ) -> Result<(), anyhow::Error> {
        V001SqlBuilder::new(db_type).apply(connection).await
    }
}

/// Canonical text whose SHA-256 is the V001 identity.
///
/// One section per dialect in the fixed order PostgreSQL, MySQL, SQLite, each
/// listing every executed statement in order (whitespace-collapsed, MySQL
/// index statements as actually sent). Exposed so the golden test can print
/// it when the baseline drifts.
pub fn canonical_v001_baseline() -> String {
    let mut text = String::with_capacity(64 * 1024);
    text.push_str(CANONICAL_V001_HEADER);
    text.push('\n');
    for db_type in ["postgres", "mysql", "sqlite"] {
        text.push_str("dialect ");
        text.push_str(db_type);
        text.push('\n');
        for line in V001SqlBuilder::new(db_type).canonical_steps() {
            text.push_str(&line);
            text.push('\n');
        }
    }
    text
}
