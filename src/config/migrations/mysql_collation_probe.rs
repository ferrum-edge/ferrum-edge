//! Startup probe for stale MySQL identifier collations (#3626).
//!
//! Ferrum's V001 MySQL baseline pins identity-bearing VARCHAR columns to
//! `utf8mb4_0900_bin` so DB uniqueness matches the runtime's byte-keyed
//! indexes (and PostgreSQL / SQLite). Upgraded deployments that still carry
//! an older case-insensitive or NFC-folding collation must run a manual
//! `ALTER TABLE ... CONVERT TO` — build-out policy does not ship a migration
//! for that. This probe runs after `run_pending` on MySQL only, warns with
//! the exact remediation, and never refuses startup (data is already live).
//!
//! PostgreSQL, SQLite, and MongoDB are no-ops.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::{AnyConnection, Row};
use tracing::warn;

/// Required collation for Ferrum MySQL identity-bearing VARCHAR columns.
pub const REQUIRED_MYSQL_IDENTITY_COLLATION: &str = "utf8mb4_0900_bin";

/// Cap how many `table.column` pairs are expanded inline in the warn message.
const MAX_COLUMNS_IN_LOG: usize = 20;

/// One identity-bearing `(table, column)` that V001 pins to
/// [`REQUIRED_MYSQL_IDENTITY_COLLATION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentityBearingColumn {
    pub table: &'static str,
    pub column: &'static str,
}

/// Live `information_schema.COLUMNS` row relevant to the probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveColumnCollation {
    pub table_name: String,
    pub column_name: String,
    /// `None` when the column has no collation (non-string types).
    pub collation_name: Option<String>,
}

/// Live `information_schema.TABLES` row for a Ferrum table.
///
/// Retained for unit tests and operators who want to inspect table defaults;
/// the startup probe keys off column collations only. Fresh MySQL installs
/// commonly inherit a non-`utf8mb4_0900_bin` *table* default while every
/// identity column still carries an explicit `COLLATE utf8mb4_0900_bin`, so
/// warning on `TABLE_COLLATION` alone would false-positive on healthy schemas.
#[derive(Debug, Clone, PartialEq, Eq)]
// Consumed by the external `tests/` crate.
#[allow(dead_code)]
pub struct LiveTableCollation {
    pub table_name: String,
    pub table_collation: Option<String>,
}

/// A single stale collation observation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StaleCollationFinding {
    pub table_name: String,
    /// Column name, or `"(table default)"` when the table's default collation
    /// itself is stale.
    pub column_name: String,
    pub found_collation: String,
}

/// Ferrum tables / columns that must use [`REQUIRED_MYSQL_IDENTITY_COLLATION`].
///
/// Kept in sync with the explicit `COLLATE utf8mb4_0900_bin` clauses in
/// `sql_dialect.rs` (see the collation regression tests there).
pub fn identity_bearing_columns() -> &'static [IdentityBearingColumn] {
    &[
        // upstreams
        IdentityBearingColumn {
            table: "upstreams",
            column: "id",
        },
        IdentityBearingColumn {
            table: "upstreams",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "upstreams",
            column: "name",
        },
        IdentityBearingColumn {
            table: "upstreams",
            column: "backend_tls_sni",
        },
        IdentityBearingColumn {
            table: "upstreams",
            column: "api_spec_id",
        },
        // consumers
        IdentityBearingColumn {
            table: "consumers",
            column: "id",
        },
        IdentityBearingColumn {
            table: "consumers",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "consumers",
            column: "username",
        },
        IdentityBearingColumn {
            table: "consumers",
            column: "custom_id",
        },
        // consumer_credential_index
        IdentityBearingColumn {
            table: "consumer_credential_index",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "consumer_credential_index",
            column: "credential_type",
        },
        IdentityBearingColumn {
            table: "consumer_credential_index",
            column: "credential_hash",
        },
        IdentityBearingColumn {
            table: "consumer_credential_index",
            column: "consumer_id",
        },
        // consumer_identity_index
        IdentityBearingColumn {
            table: "consumer_identity_index",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "consumer_identity_index",
            column: "identity_value",
        },
        IdentityBearingColumn {
            table: "consumer_identity_index",
            column: "consumer_id",
        },
        // proxies
        IdentityBearingColumn {
            table: "proxies",
            column: "id",
        },
        IdentityBearingColumn {
            table: "proxies",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "proxies",
            column: "name",
        },
        IdentityBearingColumn {
            table: "proxies",
            column: "backend_host",
        },
        IdentityBearingColumn {
            table: "proxies",
            column: "upstream_id",
        },
        IdentityBearingColumn {
            table: "proxies",
            column: "upstream_subset",
        },
        IdentityBearingColumn {
            table: "proxies",
            column: "api_spec_id",
        },
        // plugin_configs
        IdentityBearingColumn {
            table: "plugin_configs",
            column: "id",
        },
        IdentityBearingColumn {
            table: "plugin_configs",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "plugin_configs",
            column: "plugin_name",
        },
        IdentityBearingColumn {
            table: "plugin_configs",
            column: "proxy_id",
        },
        IdentityBearingColumn {
            table: "plugin_configs",
            column: "api_spec_id",
        },
        // proxy_route_locks
        IdentityBearingColumn {
            table: "proxy_route_locks",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "proxy_route_locks",
            column: "route_key_hash",
        },
        // mtls_dns_admission_locks
        IdentityBearingColumn {
            table: "mtls_dns_admission_locks",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "mtls_dns_admission_locks",
            column: "restore_owner",
        },
        // proxy_plugins
        IdentityBearingColumn {
            table: "proxy_plugins",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "proxy_plugins",
            column: "proxy_id",
        },
        IdentityBearingColumn {
            table: "proxy_plugins",
            column: "plugin_config_id",
        },
        // config_change_locks
        IdentityBearingColumn {
            table: "config_change_locks",
            column: "lock_name",
        },
        // config_admission_locks
        IdentityBearingColumn {
            table: "config_admission_locks",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "config_admission_locks",
            column: "owner",
        },
        // config_change_retention
        IdentityBearingColumn {
            table: "config_change_retention",
            column: "namespace",
        },
        // config_changes
        IdentityBearingColumn {
            table: "config_changes",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "config_changes",
            column: "resource_type",
        },
        IdentityBearingColumn {
            table: "config_changes",
            column: "resource_id",
        },
        IdentityBearingColumn {
            table: "config_changes",
            column: "operation",
        },
        // api_specs
        IdentityBearingColumn {
            table: "api_specs",
            column: "id",
        },
        IdentityBearingColumn {
            table: "api_specs",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "api_specs",
            column: "proxy_id",
        },
        IdentityBearingColumn {
            table: "api_specs",
            column: "spec_version",
        },
        IdentityBearingColumn {
            table: "api_specs",
            column: "content_hash",
        },
        IdentityBearingColumn {
            table: "api_specs",
            column: "external_ref_digest",
        },
        // audit_events
        IdentityBearingColumn {
            table: "audit_events",
            column: "id",
        },
        IdentityBearingColumn {
            table: "audit_events",
            column: "actor",
        },
        IdentityBearingColumn {
            table: "audit_events",
            column: "action",
        },
        IdentityBearingColumn {
            table: "audit_events",
            column: "resource_type",
        },
        IdentityBearingColumn {
            table: "audit_events",
            column: "resource_id",
        },
        IdentityBearingColumn {
            table: "audit_events",
            column: "namespace",
        },
        IdentityBearingColumn {
            table: "audit_events",
            column: "namespace_at_event",
        },
        IdentityBearingColumn {
            table: "audit_events",
            column: "source_address",
        },
        IdentityBearingColumn {
            table: "audit_events",
            column: "request_id",
        },
        IdentityBearingColumn {
            table: "audit_events",
            column: "outcome",
        },
    ]
}

fn identity_tables() -> BTreeSet<&'static str> {
    identity_bearing_columns().iter().map(|c| c.table).collect()
}

fn identity_column_set() -> BTreeSet<(&'static str, &'static str)> {
    identity_bearing_columns()
        .iter()
        .map(|c| (c.table, c.column))
        .collect()
}

/// Evaluate live column collation rows against the identity-bearing inventory.
///
/// Columns that are not in the inventory, missing from the live schema, or
/// already on [`REQUIRED_MYSQL_IDENTITY_COLLATION`] are ignored. Columns with
/// a `NULL` collation are ignored (non-string types).
pub fn find_stale_column_collations(
    live_columns: &[LiveColumnCollation],
) -> Vec<StaleCollationFinding> {
    let inventory = identity_column_set();
    let mut findings = Vec::new();
    for row in live_columns {
        if !inventory.contains(&(row.table_name.as_str(), row.column_name.as_str())) {
            continue;
        }
        let Some(collation) = row.collation_name.as_deref() else {
            continue;
        };
        if collation == REQUIRED_MYSQL_IDENTITY_COLLATION {
            continue;
        }
        findings.push(StaleCollationFinding {
            table_name: row.table_name.clone(),
            column_name: row.column_name.clone(),
            found_collation: collation.to_string(),
        });
    }
    findings.sort();
    findings
}

/// Evaluate live table default collations for Ferrum identity tables.
///
/// A stale table default is reported even when every inventoried column is
/// already correct — future `ADD COLUMN` without an explicit `COLLATE` would
/// inherit the wrong default.
// Consumed by the external `tests/` crate.
#[allow(dead_code)]
pub fn find_stale_table_collations(
    live_tables: &[LiveTableCollation],
) -> Vec<StaleCollationFinding> {
    let tables = identity_tables();
    let mut findings = Vec::new();
    for row in live_tables {
        if !tables.contains(row.table_name.as_str()) {
            continue;
        }
        let Some(collation) = row.table_collation.as_deref() else {
            continue;
        };
        if collation == REQUIRED_MYSQL_IDENTITY_COLLATION {
            continue;
        }
        findings.push(StaleCollationFinding {
            table_name: row.table_name.clone(),
            column_name: "(table default)".to_string(),
            found_collation: collation.to_string(),
        });
    }
    findings.sort();
    findings
}

/// Merge column + table findings and dedupe by `(table, column)`.
// Consumed by the external `tests/` crate.
#[allow(dead_code)]
pub fn merge_stale_collation_findings(
    column_findings: Vec<StaleCollationFinding>,
    table_findings: Vec<StaleCollationFinding>,
) -> Vec<StaleCollationFinding> {
    let mut by_key: BTreeMap<(String, String), StaleCollationFinding> = BTreeMap::new();
    for finding in column_findings.into_iter().chain(table_findings) {
        by_key.insert(
            (finding.table_name.clone(), finding.column_name.clone()),
            finding,
        );
    }
    by_key.into_values().collect()
}

/// One `ALTER TABLE ... CONVERT TO` per distinct affected table, stable order.
pub fn remediation_alter_statements(findings: &[StaleCollationFinding]) -> Vec<String> {
    let tables: BTreeSet<&str> = findings.iter().map(|f| f.table_name.as_str()).collect();
    tables
        .into_iter()
        .map(|table| {
            format!(
                "ALTER TABLE {table} CONVERT TO CHARACTER SET utf8mb4 COLLATE {REQUIRED_MYSQL_IDENTITY_COLLATION}"
            )
        })
        .collect()
}

/// Human-readable summary of affected `table.column (found_collation)` pairs.
pub fn format_affected_columns_summary(findings: &[StaleCollationFinding]) -> String {
    let listed: Vec<String> = findings
        .iter()
        .take(MAX_COLUMNS_IN_LOG)
        .map(|f| format!("{}.{} ({})", f.table_name, f.column_name, f.found_collation))
        .collect();
    let omitted = findings.len().saturating_sub(listed.len());
    if omitted == 0 {
        listed.join(", ")
    } else {
        format!("{}, ... (+{omitted} more)", listed.join(", "))
    }
}

fn emit_stale_collation_warning(findings: &[StaleCollationFinding]) {
    let alters = remediation_alter_statements(findings);
    let tables: BTreeSet<&str> = findings.iter().map(|f| f.table_name.as_str()).collect();
    let tables_summary = tables.into_iter().collect::<Vec<_>>().join(", ");
    let columns_summary = format_affected_columns_summary(findings);
    let remediation = alters.join("; ");

    warn!(
        required_collation = REQUIRED_MYSQL_IDENTITY_COLLATION,
        affected_table_count = alters.len(),
        affected_column_count = findings.len(),
        affected_tables = %tables_summary,
        affected_columns = %columns_summary,
        remediation = %remediation,
        "MySQL schema has identity-bearing columns not using {} — \
         DB uniqueness may diverge from runtime byte-keyed indexes (case / NFC / trailing-space folds). \
         Build-out policy does not auto-migrate collations; run the ALTER TABLE statements below \
         (also listed in docs/configuration.md), then restart. Affected: {}. Remediation: {}",
        REQUIRED_MYSQL_IDENTITY_COLLATION,
        columns_summary,
        remediation,
    );
}

/// Inspect live MySQL identity-column collations. No-op (`Ok([])`) for non-MySQL.
///
/// Only inventoried identity-bearing *columns* are evaluated. Table default
/// collation is not a failure signal on its own (see [`LiveTableCollation`]).
pub async fn inspect_mysql_identity_collations(
    connection: &mut AnyConnection,
    db_type: &str,
) -> Result<Vec<StaleCollationFinding>, anyhow::Error> {
    if db_type != "mysql" {
        return Ok(Vec::new());
    }

    let column_rows = sqlx::query(
        "SELECT TABLE_NAME AS table_name, \
                COLUMN_NAME AS column_name, \
                COLLATION_NAME AS collation_name \
         FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA = DATABASE() \
           AND COLLATION_NAME IS NOT NULL",
    )
    .fetch_all(&mut *connection)
    .await?;

    let mut live_columns = Vec::with_capacity(column_rows.len());
    for row in column_rows {
        live_columns.push(LiveColumnCollation {
            table_name: row.try_get::<String, _>("table_name")?,
            column_name: row.try_get::<String, _>("column_name")?,
            collation_name: row.try_get::<Option<String>, _>("collation_name")?,
        });
    }

    Ok(find_stale_column_collations(&live_columns))
}

/// Run the MySQL collation probe and emit at most one structured warn.
///
/// Probe failures warn and continue — matching the pending-plugin-migration
/// probe posture in `database` / `cp` modes. Non-MySQL backends are no-ops.
pub async fn warn_stale_mysql_identity_collations(connection: &mut AnyConnection, db_type: &str) {
    match inspect_mysql_identity_collations(connection, db_type).await {
        Ok(findings) if findings.is_empty() => {}
        Ok(findings) => emit_stale_collation_warning(&findings),
        Err(error) => {
            warn!(
                error = %crate::startup::sanitize_startup_cause(error, &[]),
                "Could not inspect MySQL identity-column collations after migrations; \
                 if this deployment was upgraded from a pre-utf8mb4_0900_bin schema, \
                 verify information_schema.COLUMNS and run \
                 ALTER TABLE ... CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin \
                 on affected Ferrum tables (see docs/configuration.md)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_includes_consumer_identity_columns() {
        let cols = identity_column_set();
        assert!(cols.contains(&("consumers", "username")));
        assert!(cols.contains(&("consumers", "custom_id")));
        assert!(cols.contains(&("consumer_identity_index", "identity_value")));
        assert!(cols.contains(&("proxies", "backend_host")));
    }

    #[test]
    fn stale_column_detection_keeps_only_mismatches() {
        let live = vec![
            LiveColumnCollation {
                table_name: "consumers".into(),
                column_name: "username".into(),
                collation_name: Some("utf8mb4_general_ci".into()),
            },
            LiveColumnCollation {
                table_name: "consumers".into(),
                column_name: "custom_id".into(),
                collation_name: Some(REQUIRED_MYSQL_IDENTITY_COLLATION.into()),
            },
            LiveColumnCollation {
                table_name: "consumers".into(),
                column_name: "credentials".into(),
                collation_name: Some("utf8mb4_general_ci".into()),
            },
        ];
        let findings = find_stale_column_collations(&live);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].table_name, "consumers");
        assert_eq!(findings[0].column_name, "username");
        assert_eq!(findings[0].found_collation, "utf8mb4_general_ci");
    }

    #[test]
    fn correct_collations_yield_no_findings() {
        let live = vec![LiveColumnCollation {
            table_name: "consumers".into(),
            column_name: "username".into(),
            collation_name: Some(REQUIRED_MYSQL_IDENTITY_COLLATION.into()),
        }];
        assert!(find_stale_column_collations(&live).is_empty());
        let tables = vec![LiveTableCollation {
            table_name: "consumers".into(),
            table_collation: Some(REQUIRED_MYSQL_IDENTITY_COLLATION.into()),
        }];
        assert!(find_stale_table_collations(&tables).is_empty());
    }

    #[test]
    fn stale_table_default_is_reported() {
        let tables = vec![LiveTableCollation {
            table_name: "consumers".into(),
            table_collation: Some("utf8mb4_unicode_ci".into()),
        }];
        let findings = find_stale_table_collations(&tables);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].column_name, "(table default)");
        assert_eq!(findings[0].found_collation, "utf8mb4_unicode_ci");
    }

    #[test]
    fn remediation_emits_one_alter_per_table() {
        let findings = vec![
            StaleCollationFinding {
                table_name: "consumers".into(),
                column_name: "username".into(),
                found_collation: "utf8mb4_general_ci".into(),
            },
            StaleCollationFinding {
                table_name: "consumers".into(),
                column_name: "custom_id".into(),
                found_collation: "utf8mb4_general_ci".into(),
            },
            StaleCollationFinding {
                table_name: "proxies".into(),
                column_name: "name".into(),
                found_collation: "utf8mb4_bin".into(),
            },
        ];
        let alters = remediation_alter_statements(&findings);
        assert_eq!(
            alters,
            vec![
                "ALTER TABLE consumers CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
                    .to_string(),
                "ALTER TABLE proxies CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn summary_truncates_long_finding_lists() {
        let findings: Vec<StaleCollationFinding> = (0..25)
            .map(|i| StaleCollationFinding {
                table_name: "consumers".into(),
                column_name: format!("col{i}"),
                found_collation: "utf8mb4_general_ci".into(),
            })
            .collect();
        let summary = format_affected_columns_summary(&findings);
        assert!(summary.contains("... (+5 more)"));
        assert!(summary.contains("consumers.col0"));
    }
}
