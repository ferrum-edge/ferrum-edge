//! Golden identity of the frozen V001 SQL baseline.
//!
//! `V001_BASELINE_CHECKSUM` is the identity every initialized PostgreSQL,
//! MySQL, and SQLite database records for V001. If the canonical rendering of
//! the baseline DDL changes, every existing database refuses to start, so a
//! change here is never a routine edit: from 1.0.0 onward schema changes ship
//! as new forward migrations (`V002`, `V003`, ...).

use ferrum_edge::config::migrations::Migration;
use ferrum_edge::config::migrations::SqlMigration;
use ferrum_edge::config::migrations::v001_initial_schema::{
    V001_BASELINE_CHECKSUM, V001InitialSchema, canonical_v001_baseline,
};

#[test]
fn v001_baseline_ddl_matches_the_committed_golden_checksum() {
    let computed = V001InitialSchema.checksum();
    assert!(
        computed == V001_BASELINE_CHECKSUM,
        "\n\nV001 baseline DDL drift detected.\n\
         \n\
         The statements V001 executes (src/config/migrations/sql_dialect.rs) no longer\n\
         render to the committed V001 identity, so every existing database would refuse\n\
         to start with a checksum-mismatch integrity error.\n\
         \n\
         From 1.0.0 onward the V001 baseline is frozen: revert the baseline edit and put\n\
         the schema change in a new forward migration (the next V00N, appended to\n\
         MigrationRunner::shipped_migrations in src/config/migrations/mod.rs; see\n\
         docs/migrations.md, \"Adding a forward migration\").\n\
         \n\
         Only for a deliberate baseline change before the 1.0.0 tag, replace the constant\n\
         in src/config/migrations/v001_initial_schema.rs with this line:\n\
         \n\
         pub const V001_BASELINE_CHECKSUM: &str =\n    \"{computed}\";\n\
         \n\
         committed: {V001_BASELINE_CHECKSUM}\n\
         computed:  {computed}\n\
         \n\
         Canonical V001 rendering that produced the computed value:\n\
         ----------------------------------------------------------\n\
         {canonical}\
         ----------------------------------------------------------\n",
        canonical = canonical_v001_baseline(),
    );
}

#[test]
fn v001_checksum_is_derived_from_the_canonical_rendering() {
    let canonical = canonical_v001_baseline();
    assert!(canonical.starts_with("ferrum-edge core migration V001; canonical DDL format 1\n"));
    // One section per dialect, in a fixed order.
    let postgres = canonical.find("\ndialect postgres\n").expect("postgres");
    let mysql = canonical.find("\ndialect mysql\n").expect("mysql");
    let sqlite = canonical.find("\ndialect sqlite\n").expect("sqlite");
    assert!(postgres < mysql && mysql < sqlite);

    // Executed statements only: MySQL index DDL appears as sent (no
    // `IF NOT EXISTS`), whitespace is collapsed, and no Rust source leaks in.
    let mysql_section = &canonical[mysql..sqlite];
    assert!(mysql_section.contains(
        "index CREATE INDEX idx_proxies_ns_upstream_id ON proxies (namespace, upstream_id)\n"
    ));
    assert!(!mysql_section.contains("CREATE INDEX IF NOT EXISTS"));
    assert!(canonical[sqlite..].contains("statement PRAGMA foreign_keys = ON\n"));
    assert!(canonical.contains("seed INSERT INTO namespaces"));
    assert!(canonical.contains("binds=[\"ferrum\", <now>, <now>]"));
    for line in canonical.lines() {
        assert!(!line.contains("  "), "uncollapsed whitespace: {line}");
        assert!(!line.contains("//"), "Rust comment leaked: {line}");
    }

    let checksum = V001InitialSchema.checksum();
    assert!(checksum.starts_with("sha256:"));
    assert_eq!(checksum.len(), "sha256:".len() + 64);
}

#[test]
fn forward_migration_checksum_is_canonical_and_layout_independent() {
    const COMPACT: SqlMigration = SqlMigration {
        version: 2,
        name: "add_example",
        postgres: &["CREATE TABLE IF NOT EXISTS example (id TEXT PRIMARY KEY)"],
        mysql: &["CREATE TABLE IF NOT EXISTS example (id VARCHAR(64) PRIMARY KEY)"],
        sqlite: &["CREATE TABLE IF NOT EXISTS example (id TEXT PRIMARY KEY)"],
    };
    const SAME_TOKENS: SqlMigration = SqlMigration {
        version: 2,
        name: "renamed_label_only",
        postgres: &["  CREATE TABLE IF NOT EXISTS\n example (id TEXT PRIMARY KEY)  "],
        mysql: &["CREATE TABLE IF NOT EXISTS example\t(id VARCHAR(64) PRIMARY KEY)"],
        sqlite: &["CREATE TABLE IF NOT EXISTS example (id TEXT PRIMARY KEY)\n"],
    };
    // Re-indentation and the recorded name never change the identity.
    assert_eq!(COMPACT.checksum(), SAME_TOKENS.checksum());

    let changed_sql = SqlMigration {
        sqlite: &["CREATE TABLE IF NOT EXISTS example (id INTEGER PRIMARY KEY)"],
        ..COMPACT
    };
    assert_ne!(COMPACT.checksum(), changed_sql.checksum());
    let changed_version = SqlMigration {
        version: 3,
        ..COMPACT
    };
    assert_ne!(COMPACT.checksum(), changed_version.checksum());
    assert_ne!(COMPACT.checksum(), V001InitialSchema.checksum());
}
