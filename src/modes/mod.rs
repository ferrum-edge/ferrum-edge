//! Operating mode entry points for the Ferrum Edge gateway.
//!
//! The gateway binary runs in exactly one mode, selected by `FERRUM_MODE`:
//!
//! | Mode       | Proxy | Admin API   | Config Source                    |
//! |------------|-------|-------------|----------------------------------|
//! | `database` | Yes   | Read/Write  | PostgreSQL/MySQL/SQLite polling   |
//! | `file`     | Yes   | Read-only   | YAML/JSON file, SIGHUP reload    |
//! | `cp`       | No    | Read/Write  | DB polling + gRPC broadcast to DPs |
//! | `dp`       | Yes   | Read-only   | gRPC stream from CP              |
//! | `mesh`     | Yes   | Read-only   | xDS or native MeshSubscribe      |
//! | `injector`   | No    | No          | Kubernetes admission webhook     |
//! | `node_agent` | No    | Metrics     | Per-node eBPF/iptables capture   |
//! | `migrate`    | No    | No          | Runs DB migrations then exits    |
//!
//! All modes share the same `ProxyState` and atomic config swap mechanism.
//! Config changes (from any source) are validated, then swapped atomically
//! via `ArcSwap` — in-flight requests see old or new config, never partial.

pub mod control_plane;
pub mod data_plane;
pub mod database;
pub mod db_poll_supervision;
pub mod db_tls_reload;
pub mod file;
pub mod grpc_tls_reload;
pub mod injector;
pub mod mesh;
pub mod migrate;
pub mod node_agent;
pub mod node_agent_cni_server;
pub mod startup_security;
pub mod tls_reload;
pub(crate) mod tls_source_util;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "acme")]
use std::time::Duration;

use anyhow::Context as _;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::db_backend::DatabaseBackend;
use crate::config::env_config::EnvConfig;

pub(crate) type AdminReadReplicaDnsWatermark = Arc<Mutex<Option<Vec<IpAddr>>>>;

/// Schedule an admin-read replica reconnect without blocking authoritative config polling.
pub(crate) fn spawn_admin_read_replica_reconnect(
    db: Arc<dyn DatabaseBackend>,
    replica_url: String,
    in_flight: Arc<AtomicBool>,
    reason: &'static str,
    success_replica_ips: Option<(AdminReadReplicaDnsWatermark, Vec<IpAddr>)>,
) -> bool {
    if in_flight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }

    tokio::spawn(async move {
        match db.reconnect_read_replica(&replica_url).await {
            Ok(()) => {
                if let Some((last_replica_ips, ips)) = success_replica_ips {
                    *last_replica_ips.lock().await = Some(ips);
                }
            }
            Err(error) => {
                let safe_error =
                    crate::config::db_backend::redact_error_text(&error, &[&replica_url]);
                warn!(
                    reason = reason,
                    "Admin-read replica reconnect failed for {}: {}",
                    crate::config::db_backend::redact_url(&replica_url),
                    safe_error
                );
            }
        }
        in_flight.store(false, Ordering::Release);
    });

    true
}

/// Check whether the admin-read replica needs repair and schedule it in the background.
pub(crate) async fn schedule_admin_read_replica_reconnect_if_needed(
    db: Arc<dyn DatabaseBackend>,
    replica_url: Option<&str>,
    replica_hostname: Option<&str>,
    dns_cache: &crate::dns::DnsCache,
    last_replica_ips: AdminReadReplicaDnsWatermark,
    in_flight: Arc<AtomicBool>,
) {
    let Some(replica_url) = replica_url else {
        return;
    };

    if !db.read_replica_available() {
        // While the SQL store is failed over, the configured replica is
        // intentionally suppressed (it belongs to the unavailable primary
        // topology), not broken. Reconnecting it every cycle would never
        // converge because admin reads stay on the failover pool until
        // failback — so skip the reconnect until the replica is eligible again.
        if db.read_replica_suppressed() {
            return;
        }
        spawn_admin_read_replica_reconnect(
            db,
            replica_url.to_string(),
            in_flight,
            "replica unavailable",
            None,
        );
        return;
    }

    let Some(replica_hostname) = replica_hostname else {
        return;
    };
    let Ok(ips) = dns_cache.resolve_all(replica_hostname, None, None).await else {
        return;
    };

    let previous_ips = last_replica_ips.lock().await.clone();
    let Some(previous_ips) = previous_ips else {
        *last_replica_ips.lock().await = Some(ips);
        return;
    };

    let needs_reconnect = {
        let mut prev_sorted = previous_ips.clone();
        prev_sorted.sort();
        let mut cur_sorted = ips.clone();
        cur_sorted.sort();
        prev_sorted != cur_sorted
    };
    if needs_reconnect {
        info!(
            "Read replica DNS changed for '{}': {:?} -> {:?}, scheduling admin-read replica reconnect",
            replica_hostname, previous_ips, ips
        );
        let _scheduled = spawn_admin_read_replica_reconnect(
            db,
            replica_url.to_string(),
            in_flight,
            "replica DNS changed",
            Some((last_replica_ips, ips)),
        );
    }
}

/// Handle pending custom-plugin database migrations at startup for the
/// `database` and `cp` modes.
///
/// Behavior is controlled by `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS`:
///
/// - `false` (default): list any pending plugin migrations as a `warn!` log
///   line and leave them unapplied. The operator is expected to run
///   `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` before serving traffic
///   that depends on the new schema. This preserves the long-standing
///   contract that schema changes never run automatically at gateway boot.
///
/// - `true`: apply all pending plugin migrations now, before
///   `load_full_config()`. Useful for embedded deployments (e.g., SQLite
///   where the binary owns the database) that want a single binary upgrade
///   to also bring plugin schema up to date.
///
/// The warning ALWAYS fires when migrations are pending and auto-apply is
/// off, so operators always know what they need to run. When auto-apply is
/// on and the migration succeeds, an `info!` line records what was applied.
///
/// Errors propagate when auto-apply is on (a failed plugin migration is
/// fatal — the gateway should not come up with an inconsistent schema).
/// When auto-apply is off, the warning is informational and never fails
/// startup.
pub(crate) async fn handle_startup_plugin_migrations(
    db: &Arc<dyn DatabaseBackend>,
    auto_apply: bool,
    mode: &str,
) -> Result<(), anyhow::Error> {
    let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
    handle_startup_plugin_migrations_with_list(db, auto_apply, mode, &plugin_migrations).await
}

/// Recovery variant of [`handle_startup_plugin_migrations`].
///
/// Warn-only mode (`auto_apply=false`) matches ordinary startup: a pending-state
/// **probe failure** is logged and does not block recovered config publication
/// (in-place recovery must not be strictly weaker than a process restart against
/// the same database). Auto-apply mode stays fail-closed on probe/apply errors.
/// A probe that **succeeds** and reports pending migrations still follows the
/// warn-and-continue / auto-apply policy unchanged.
pub(crate) async fn handle_recovery_plugin_migrations(
    db: &Arc<dyn DatabaseBackend>,
    auto_apply: bool,
    mode: &str,
) -> Result<(), anyhow::Error> {
    let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
    handle_startup_plugin_migrations_with_list(db, auto_apply, mode, &plugin_migrations).await
}

pub(crate) fn start_acme_renewal_scheduler(
    env_config: &EnvConfig,
    dns_cache: crate::dns::DnsCache,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if !env_config.acme_auto_renew_enabled {
        return None;
    }

    #[cfg(not(feature = "acme"))]
    {
        let _ = (dns_cache, shutdown_rx);
        warn!(
            "FERRUM_ACME_AUTO_RENEW_ENABLED=true but this binary was built without the 'acme' feature"
        );
        None
    }

    #[cfg(feature = "acme")]
    {
        let Some(challenge_type) = crate::tls::acme::AcmeRenewalChallengeType::parse(
            &env_config.acme_renew_challenge_type,
        ) else {
            warn!(
                value = %env_config.acme_renew_challenge_type,
                "invalid FERRUM_ACME_RENEW_CHALLENGE_TYPE; ACME renewal scheduler disabled"
            );
            return None;
        };
        crate::tls::acme::start_renewal_scheduler(
            crate::tls::acme::AcmeRenewalSchedulerConfig {
                enabled: true,
                renew_when_remaining_days: env_config.acme_renew_when_remaining_days,
                check_interval: Duration::from_secs(env_config.acme_renew_check_interval_seconds),
                poll_timeout: Duration::from_secs(env_config.acme_renew_poll_timeout_seconds),
                challenge_type,
                dns01_hook_command: env_config.acme_dns01_hook_command.clone(),
                dns01_propagation: Duration::from_secs(env_config.acme_dns01_propagation_seconds),
                renewal_lease_ttl: Duration::from_secs(env_config.acme_renewal_lease_ttl_seconds),
                dns_cache,
            },
            shutdown_rx,
        )
    }
}

/// Internal entry point that takes the plugin-migration list as a parameter
/// so unit tests can pass a synthetic plugin without depending on the
/// build-time `collect_all_custom_plugin_migrations()` registry.
async fn handle_startup_plugin_migrations_with_list(
    db: &Arc<dyn DatabaseBackend>,
    auto_apply: bool,
    mode: &str,
    plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
) -> Result<(), anyhow::Error> {
    if plugin_migrations.is_empty() {
        return Ok(());
    }

    let pending = match db.pending_plugin_migrations(plugin_migrations).await {
        Ok(p) => p,
        Err(e) => {
            if auto_apply {
                return Err(e).with_context(|| {
                    format!(
                        "FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true but pending \
                         custom-plugin migrations could not be determined (mode={mode})"
                    )
                });
            }

            // Probe failure shouldn't block startup; the operator can still
            // run `FERRUM_MIGRATE_ACTION=up` to recover. Log loud enough.
            warn!(
                "Could not determine pending custom-plugin migrations ({}). \
                 Run FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up to verify \
                 schema if you have plugins with bundled migrations.",
                e
            );
            return Ok(());
        }
    };

    if pending.is_empty() {
        return Ok(());
    }

    const MAX_MIGRATIONS_IN_LOG: usize = 20;
    let pending_summary: Vec<String> = pending
        .iter()
        .take(MAX_MIGRATIONS_IN_LOG)
        .map(|m| format!("[{}] V{}: {}", m.plugin_name, m.version, m.name))
        .collect();
    let omitted_pending = pending.len().saturating_sub(pending_summary.len());
    let pending_suffix = if omitted_pending == 0 {
        String::new()
    } else {
        format!(", ... (+{omitted_pending} more)")
    };
    let pending_description = format!("{}{}", pending_summary.join(", "), pending_suffix);

    if auto_apply {
        info!(
            "FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true and {} pending custom-plugin migration(s) \
             detected ({}). Applying now (mode={}).",
            pending.len(),
            pending_description,
            mode
        );
        let applied = db.apply_plugin_migrations(plugin_migrations).await?;
        let applied_summary: Vec<String> = applied
            .iter()
            .take(MAX_MIGRATIONS_IN_LOG)
            .map(|m| {
                format!(
                    "[{}] V{}: {} ({}ms)",
                    m.plugin_name, m.version, m.name, m.execution_time_ms
                )
            })
            .collect();
        let omitted_applied = applied.len().saturating_sub(applied_summary.len());
        let applied_suffix = if omitted_applied == 0 {
            String::new()
        } else {
            format!(", ... (+{omitted_applied} more)")
        };
        let applied_description = format!("{}{}", applied_summary.join(", "), applied_suffix);
        info!(
            "Applied {} custom-plugin migration(s) at startup: {}",
            applied.len(),
            applied_description
        );
    } else {
        warn!(
            "{} pending custom-plugin migration(s) detected but \
             FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS is not enabled — schema NOT updated. \
             Pending: {}. Run FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up before serving \
             traffic that depends on the new schema, or set \
             FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true to auto-apply at startup.",
            pending.len(),
            pending_description
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared reachable-config-rejection handling for writable poll loops
// (database + control-plane), issues #2158 / #2997.
//
// Both the `database` and `cp` runtimes poll an authoritative primary and are
// WRITABLE through the admin API. When a reachable backend returns a
// semantically-invalid or undecodable full snapshot, admin writes are the
// in-band repair tool,
// so the poll loop must keep the admin API writable (rather than fail closed as
// it does for a genuine connectivity outage). These helpers centralize that
// classification so the two runtimes cannot drift.
// ---------------------------------------------------------------------------

/// Classify a poll-loop full-load failure: `true` for a reachable-backend config
/// rejection (semantic VALIDATION via
/// [`crate::config::validation_pipeline::ConfigValidationRejection`], or SQL
/// row DECODE via [`crate::config::db_loader::RowDecodeRejection`]), `false` for
/// a connectivity/driver failure. Both markers are downcast-discoverable through
/// the `anyhow` source chain so poll loops keep `db_available=true` (after the
/// migration gate) and raise `config_rejected` (issues #2158 / #2997).
pub(crate) fn is_poll_validation_rejection(err: &anyhow::Error) -> bool {
    crate::config::validation_pipeline::is_config_validation_rejection(err)
        || crate::config::db_loader::is_row_decode_rejection(err)
}

/// Apply the reachable-config-rejection state transition once the deferred
/// migration gate has decided whether admin writes may be re-enabled.
///
/// `writes_enabled` is the result of the migration gate: a semantic-validation
/// or row-decode rejection proves the backend is reachable, so writes are
/// re-enabled — but ONLY if any deferred migrations applied cleanly, so writes
/// never land on an unmigrated schema (issues #2158 / #2997).
/// `config_rejected` is raised regardless so the authenticated `/health` detail
/// reports the degraded snapshot. Logs loudly only on the transition INTO the
/// rejected state; repeats log at debug to avoid per-poll spam.
///
/// Kept pure (no async, no backend) so the state machine is unit-testable.
pub(crate) fn apply_config_validation_rejection(
    db_available: &AtomicBool,
    config_rejected: &AtomicBool,
    writes_enabled: bool,
    err: &anyhow::Error,
    context: &str,
) {
    db_available.store(writes_enabled, Ordering::Relaxed);
    if !config_rejected.swap(true, Ordering::Relaxed) {
        if writes_enabled {
            error!(
                "Full config load rejected by validation or row decode ({}); backend is reachable \
                 so KEEPING admin API writable to repair the offending resource in-band, serving \
                 last known-good runtime config: {}",
                context, err
            );
        } else {
            error!(
                "Full config load rejected by validation or row decode ({}); backend is reachable \
                 but deferred migrations are still pending, so admin writes stay BLOCKED until \
                 the schema is applied; serving last known-good runtime config: {}",
                context, err
            );
        }
    } else {
        debug!(
            "Full config load still rejected by validation or row decode ({}); serving \
             last known-good runtime config: {}",
            context, err
        );
    }
}

/// Raise the config-rejection signal for a full load rejected by the
/// runtime-config validation contract or by typed SQL row decoding (issues
/// #2158 / #2997). Either rejection is positive proof the backend is REACHABLE,
/// so re-enable admin writes so the offending resource can be repaired in-band
/// — but gate that on [`DatabaseBackend::maybe_apply_deferred_migrations`] first
/// so a reachable backend with a still-pending schema never enables writes
/// against an unmigrated schema (the common case is a cheap no-op). On migration
/// failure admin writes stay blocked while `config_rejected` is still raised.
/// The last-known-good runtime config keeps serving (the caches were never
/// rebuilt — the load returned `Err`).
pub(crate) async fn record_config_validation_rejection(
    db: &Arc<dyn DatabaseBackend>,
    db_available: &AtomicBool,
    config_rejected: &AtomicBool,
    err: &anyhow::Error,
    context: &str,
) {
    let writes_enabled = match db.maybe_apply_deferred_migrations().await {
        Ok(_) => true,
        Err(migration_err) => {
            warn!(
                "Deferred migrations failed while handling a reachable-backend config rejection \
                 ({}): {}. Admin writes remain blocked until the schema is applied.",
                context, migration_err
            );
            false
        }
    };
    apply_config_validation_rejection(db_available, config_rejected, writes_enabled, err, context);
}

/// Clear the standing config-rejection signal once a FULL config reload is
/// accepted (issue #2158). This is the ONLY site that clears `config_rejected`:
/// an accepted incremental/delta poll does not re-validate the whole snapshot,
/// so it must leave the flag set until a full reload proves the offending row is
/// gone. Logs the recovery only on the transition out of the rejected state to
/// avoid per-poll spam.
pub(crate) fn clear_config_rejected_after_accepted_full_reload(
    config_rejected: &AtomicBool,
    context: &str,
) {
    if config_rejected.swap(false, Ordering::Relaxed) {
        info!(
            "Full config snapshot accepted after a prior validation rejection ({}); \
             config_rejected cleared",
            context
        );
    }
}

#[cfg(test)]
mod tests {
    //! Inline tests for `handle_startup_plugin_migrations_with_list`.
    //!
    //! Per CLAUDE.md "Test Placement", tests for `pub(crate)` items live
    //! inline in source — they cannot be reached from the external
    //! `tests/` crate without changing visibility.
    use super::*;
    use crate::config::db_backend::DatabaseBackend;
    use crate::config::db_loader::{DatabaseStore, DbPoolConfig};
    use crate::config::migrations::CustomPluginMigration;

    async fn fresh_database_store() -> (Arc<DatabaseStore>, tempfile::TempDir) {
        // File-backed (not `::memory:`) so the multi-connection pool sees
        // a consistent view. `_ferrum_migrations` is created during
        // `connect_with_pool_config` and must be visible to subsequent
        // connections checked out from the pool.
        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let db_path = temp_dir.path().join("modes_handle_startup_test.db");
        let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
        let store =
            DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
                .await
                .expect("test store should connect");
        (Arc::new(store), temp_dir)
    }

    async fn fresh_store() -> (Arc<dyn DatabaseBackend>, tempfile::TempDir) {
        let (store, temp_dir) = fresh_database_store().await;
        let db: Arc<dyn DatabaseBackend> = store;
        (db, temp_dir)
    }

    async fn create_malformed_plugin_tracking_table(store: &DatabaseStore) {
        sqlx::query(
            "CREATE TABLE _ferrum_plugin_migrations (
                plugin_name TEXT PRIMARY KEY
            )",
        )
        .execute(&store.pool())
        .await
        .expect("malformed plugin tracking table should be created");
    }

    fn synthetic_pending_migration() -> Vec<(&'static str, Vec<CustomPluginMigration>)> {
        vec![(
            "modes_handle_startup_test",
            vec![CustomPluginMigration {
                version: 1,
                name: "create_modes_test_table",
                checksum: "v1_modes_handle_chk",
                sql: "CREATE TABLE IF NOT EXISTS modes_handle_test_data (id TEXT PRIMARY KEY)",
                sql_postgres: None,
                sql_mysql: None,
            }],
        )]
    }

    #[tokio::test]
    async fn auto_apply_true_runs_pending_migration() {
        // FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true: gateway must apply
        // pending plugin migrations at startup so plugin INSERT/SELECT
        // calls in `log()` don't fail with "no such table".
        let (db, _tmp) = fresh_store().await;
        let migrations = synthetic_pending_migration();

        // Sanity check: pending before invocation.
        let pending_before = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert_eq!(pending_before.len(), 1);

        handle_startup_plugin_migrations_with_list(&db, true, "database", &migrations)
            .await
            .expect("auto-apply path should not error");

        // After auto-apply, pending must be empty AND the table must exist.
        let pending_after = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert!(pending_after.is_empty(), "auto-apply must clear pending");

        // Reaching into the concrete store is awkward through `dyn`, so
        // query through a fresh helper: trying to apply again must be a
        // no-op, which proves V1 was committed.
        let second_apply = db.apply_plugin_migrations(&migrations).await.unwrap();
        assert!(
            second_apply.is_empty(),
            "second apply must be a no-op once auto-apply has committed V1"
        );
    }

    #[tokio::test]
    async fn auto_apply_false_warns_only_and_does_not_apply() {
        // FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=false (default): gateway
        // must NOT mutate the schema. Pending migrations stay pending,
        // and a warn! is emitted (not asserted here — log assertion is
        // brittle; the contract under test is that no schema change
        // occurs).
        let (db, _tmp) = fresh_store().await;
        let migrations = synthetic_pending_migration();

        let pending_before = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert_eq!(pending_before.len(), 1);

        handle_startup_plugin_migrations_with_list(&db, false, "database", &migrations)
            .await
            .expect("warn-only path should not error");

        // Pending is still pending — the gateway did not apply.
        let pending_after = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert_eq!(
            pending_after.len(),
            1,
            "warn-only path must NOT apply pending migrations"
        );
        assert_eq!(pending_after[0].plugin_name, "modes_handle_startup_test");
        assert_eq!(pending_after[0].version, 1);
    }

    #[tokio::test]
    async fn auto_apply_true_is_fatal_when_pending_probe_fails() {
        let (store, _tmp) = fresh_database_store().await;
        create_malformed_plugin_tracking_table(&store).await;
        let db: Arc<dyn DatabaseBackend> = store;
        let migrations = synthetic_pending_migration();

        let err = handle_startup_plugin_migrations_with_list(&db, true, "database", &migrations)
            .await
            .expect_err("auto-apply must fail startup when pending probe fails");

        assert!(
            err.to_string().contains(
                "FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true but pending custom-plugin migrations \
                 could not be determined"
            ),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn auto_apply_false_is_warn_only_when_pending_probe_fails() {
        let (store, _tmp) = fresh_database_store().await;
        create_malformed_plugin_tracking_table(&store).await;
        let db: Arc<dyn DatabaseBackend> = store;
        let migrations = synthetic_pending_migration();

        handle_startup_plugin_migrations_with_list(&db, false, "database", &migrations)
            .await
            .expect("warn-only path should swallow pending probe failures");
    }

    #[tokio::test]
    async fn recovery_warn_only_does_not_fail_publication_on_probe_error() {
        let (store, _tmp) = fresh_database_store().await;
        create_malformed_plugin_tracking_table(&store).await;
        let db: Arc<dyn DatabaseBackend> = store;
        let migrations = synthetic_pending_migration();

        handle_startup_plugin_migrations_with_list(&db, false, "database-recovery", &migrations)
            .await
            .expect("warn-only recovery must match warn-only startup probe behavior");
    }

    #[tokio::test]
    async fn empty_plugin_list_is_noop_in_both_modes() {
        let (db, _tmp) = fresh_store().await;
        let empty: Vec<(&str, Vec<CustomPluginMigration>)> = vec![];

        handle_startup_plugin_migrations_with_list(&db, false, "database", &empty)
            .await
            .expect("warn-only with empty list is a no-op");
        handle_startup_plugin_migrations_with_list(&db, true, "cp", &empty)
            .await
            .expect("auto-apply with empty list is a no-op");
    }

    #[tokio::test]
    async fn auto_apply_idempotent_across_repeated_startups() {
        // Restart-loop scenario: with auto-apply enabled, the second
        // startup must be a no-op once the first has committed.
        let (db, _tmp) = fresh_store().await;
        let migrations = synthetic_pending_migration();

        handle_startup_plugin_migrations_with_list(&db, true, "database", &migrations)
            .await
            .unwrap();
        handle_startup_plugin_migrations_with_list(&db, true, "database", &migrations)
            .await
            .expect("second startup with auto-apply should be a no-op");

        let pending = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert!(pending.is_empty());
    }

    // --- Shared config-validation-rejection handling (issue #2158) ---------

    fn validation_rejection_error() -> anyhow::Error {
        crate::config::validation_pipeline::ConfigValidationRejection {
            backend: "Database",
            errors: vec!["dangling upstream reference".to_string()],
        }
        .into_anyhow()
    }

    fn row_decode_rejection_error() -> anyhow::Error {
        anyhow::Error::new(crate::config::db_loader::RowDecodeRejection {
            resource_type: "consumer",
            resource_id: Some("bad".to_string()),
            reason: "Consumer bad: failed to parse credentials JSON: EOF".to_string(),
        })
    }

    #[test]
    fn is_poll_validation_rejection_classifies_marker_and_ignores_connectivity() {
        assert!(
            is_poll_validation_rejection(&validation_rejection_error()),
            "a ConfigValidationRejection must classify as a validation rejection"
        );
        // Context-wrapped rejections must still classify.
        let wrapped = validation_rejection_error().context("while polling authoritative primary");
        assert!(is_poll_validation_rejection(&wrapped));
        // Row-decode rejections from a reachable SQL backend (issue #2997).
        assert!(
            is_poll_validation_rejection(&row_decode_rejection_error()),
            "a RowDecodeRejection must classify as a poll rejection so admin stays writable"
        );
        let wrapped_decode =
            row_decode_rejection_error().context("while polling authoritative primary");
        assert!(is_poll_validation_rejection(&wrapped_decode));
        // A plain connectivity error must fall through to fail-closed handling.
        assert!(!is_poll_validation_rejection(&anyhow::anyhow!(
            "connection refused (os error 61)"
        )));
    }

    #[test]
    fn apply_rejection_with_writes_enabled_keeps_admin_writable_after_prior_outage() {
        // db_available was already false from a connectivity outage. A later
        // load that reaches the backend but fails only validation proves
        // reachability, so with the migration gate satisfied admin writes are
        // re-enabled and config_rejected is raised.
        let db_available = AtomicBool::new(false);
        let config_rejected = AtomicBool::new(false);
        apply_config_validation_rejection(
            &db_available,
            &config_rejected,
            true,
            &validation_rejection_error(),
            "unit",
        );
        assert!(
            db_available.load(Ordering::Relaxed),
            "a reachable validation rejection with schema ready must re-enable writes"
        );
        assert!(config_rejected.load(Ordering::Relaxed));
    }

    #[test]
    fn apply_rejection_with_pending_migrations_keeps_writes_blocked_but_flags_rejection() {
        // Issue #2158 P3/migration gate: a reachable backend whose deferred
        // migrations are still pending must NOT enable writes against an
        // unmigrated schema, yet config_rejected must still be raised.
        let db_available = AtomicBool::new(true);
        let config_rejected = AtomicBool::new(false);
        apply_config_validation_rejection(
            &db_available,
            &config_rejected,
            false,
            &validation_rejection_error(),
            "unit",
        );
        assert!(
            !db_available.load(Ordering::Relaxed),
            "pending migrations must keep admin writes blocked"
        );
        assert!(
            config_rejected.load(Ordering::Relaxed),
            "config_rejected must be raised even when the migration gate blocks writes"
        );
    }

    #[test]
    fn clear_config_rejected_only_transitions_from_true() {
        let flag = AtomicBool::new(true);
        clear_config_rejected_after_accepted_full_reload(&flag, "unit");
        assert!(!flag.load(Ordering::Relaxed));
        // Idempotent when already clear.
        clear_config_rejected_after_accepted_full_reload(&flag, "unit");
        assert!(!flag.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn record_rejection_applies_migration_gate_against_a_real_store() {
        // End-to-end through the migration gate on a real (already-migrated)
        // SQLite store: maybe_apply_deferred_migrations is a cheap no-op, so a
        // reachable-backend validation rejection re-enables writes and raises
        // config_rejected. This exercises the async gate wiring without a mock.
        let (db, _tmp) = fresh_store().await;
        let db_available = AtomicBool::new(false);
        let config_rejected = AtomicBool::new(false);

        record_config_validation_rejection(
            &db,
            &db_available,
            &config_rejected,
            &validation_rejection_error(),
            "unit poll",
        )
        .await;

        assert!(
            db_available.load(Ordering::Relaxed),
            "a migrated reachable store must re-enable writes on a validation rejection"
        );
        assert!(config_rejected.load(Ordering::Relaxed));
    }
}
