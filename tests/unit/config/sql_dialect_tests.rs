//! External regression tests for V001 dialect-specific SQL text.
//!
//! `V001SqlBuilder` is crate-private. Static inspection of `sql_dialect.rs`
//! pins cross-dialect unique-index definitions that migration and integration
//! tests assume.

const SQL_DIALECT_SOURCE: &str = include_str!("../../../src/config/migrations/sql_dialect.rs");

#[test]
fn proxy_stream_match_is_in_every_v001_sql_dialect() {
    assert_eq!(
        SQL_DIALECT_SOURCE
            .matches("stream_match MEDIUMTEXT")
            .count(),
        1,
        "MySQL V001 must persist bounded matcher JSON in MEDIUMTEXT"
    );
    assert_eq!(
        SQL_DIALECT_SOURCE.matches("stream_match TEXT").count(),
        1,
        "Postgres/SQLite V001 must persist matcher JSON in TEXT"
    );
}

#[test]
fn upstream_namespace_name_unique_index_across_dialects() {
    // Issue #2999: upstream (namespace, name) uniqueness must be a durable
    // DB invariant, not only an advisory admin precheck.
    assert!(
        SQL_DIALECT_SOURCE.contains(
            "CREATE UNIQUE INDEX idx_upstreams_namespace_name ON upstreams (namespace, name)"
        ),
        "MySQL must declare a non-partial unique index on upstreams (namespace, name)"
    );
    assert!(
        SQL_DIALECT_SOURCE.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_upstreams_namespace_name ON upstreams (namespace, name) WHERE name IS NOT NULL"
        ),
        "Postgres/SQLite must use a partial unique index so unnamed upstreams may coexist"
    );
}

/// Column names declared by every `CREATE TABLE IF NOT EXISTS <table>` dialect
/// variant of the V001 baseline, one set per variant.
fn baseline_columns(table: &str) -> Vec<std::collections::BTreeSet<String>> {
    const CONSTRAINT_KEYWORDS: &[&str] = &[
        "PRIMARY",
        "CONSTRAINT",
        "FOREIGN",
        "UNIQUE",
        "CHECK",
        "KEY",
        "INDEX",
    ];
    let header = format!("CREATE TABLE IF NOT EXISTS {table} (");
    SQL_DIALECT_SOURCE
        .split(header.as_str())
        .skip(1)
        .map(|definition| {
            definition
                .lines()
                .map(str::trim)
                .take_while(|line| *line != ")")
                .filter_map(|line| line.split_whitespace().next())
                .filter(|token| !CONSTRAINT_KEYWORDS.contains(token))
                .map(str::to_string)
                .collect()
        })
        .collect()
}

#[test]
fn deployment_known_columns_match_the_baseline_schema() {
    // A conditional deployment replacement rewrites only the known columns and
    // carries every other stored column forward. A baseline column missing
    // from the list would silently keep its old value on conditional PUT.
    use ferrum_edge::config::deployment_mutation::DEPLOYMENT_KNOWN_COLUMNS;

    let tables: Vec<&str> = DEPLOYMENT_KNOWN_COLUMNS.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        tables,
        ["proxies", "upstreams", "plugin_configs", "proxy_plugins"]
    );
    for (table, known) in DEPLOYMENT_KNOWN_COLUMNS {
        let listed: std::collections::BTreeSet<String> =
            known.iter().map(|column| column.to_string()).collect();
        assert_eq!(
            listed.len(), known.len(),
            "duplicate known column in {table}"
        );
        let variants = baseline_columns(table);
        assert_eq!(
            variants.len(), 2,
            "expected MySQL and Postgres/SQLite baseline definitions of {table}"
        );
        for columns in variants {
            assert!(columns.len() > 2, "failed to parse the {table} baseline");
            assert_eq!(
                columns, listed,
                "DEPLOYMENT_KNOWN_COLUMNS for {table} drifted from the V001 baseline"
            );
        }
    }
}
