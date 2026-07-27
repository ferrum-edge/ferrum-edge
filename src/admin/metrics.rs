//! Typed `GET /admin/metrics` response contract.
//!
//! The handler serializes [`AdminMetrics`] directly. Unit tests build the same
//! structs as canonical fixtures so runtime JSON, OpenAPI components, and
//! `docs/admin_metrics.md` cannot silently drift.

use crate::modes::database::DatabaseDeltaPollMetricsSnapshot;
use crate::proxy::ProxyState;
use serde::Serialize;
use std::collections::BTreeMap;

/// Operating modes that construct an [`crate::admin::AdminState`] and serve
/// authenticated `GET /admin/metrics`.
// The binary target does not consume this contract inventory directly; the
// repository's external unit/OpenAPI contract suites do.
#[allow(dead_code)]
pub const ADMIN_METRICS_MODES: &[&str] = &["database", "file", "cp", "dp", "mesh", "node_agent"];

/// Top-level authenticated `/admin/metrics` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AdminMetrics {
    pub gateway: AdminMetricsGateway,
    pub connection_pools: AdminMetricsConnectionPools,
    pub circuit_breakers: Vec<AdminMetricsCircuitBreaker>,
    pub health_check: AdminMetricsHealthCheck,
    pub load_balancers: AdminMetricsLoadBalancers,
    pub caches: AdminMetricsCaches,
    pub consumer_index: AdminMetricsConsumerIndex,
    pub rate_limiting: AdminMetricsRateLimiting,
    pub tcp_connection_throttle: AdminMetricsTcpConnectionThrottle,
    /// Present only in database mode when the delta-poll registry is installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_polling: Option<DatabaseDeltaPollMetricsSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AdminMetricsGateway {
    /// One of [`ADMIN_METRICS_MODES`].
    pub mode: String,
    pub ferrum_version: String,
    pub uptime_seconds: u64,
    pub total_requests: u64,
    pub status_codes_total: BTreeMap<String, u64>,
    pub requests_per_second: u64,
    pub status_codes_per_second: BTreeMap<String, u64>,
    pub metrics_window_seconds: u64,
    pub config_last_updated_at: Option<String>,
    pub config_source_status: String,
    pub proxy_count: usize,
    pub consumer_count: usize,
    pub upstream_count: usize,
    pub plugin_config_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AdminMetricsConnectionPools {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<AdminMetricsHttpPool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc: Option<AdminMetricsPoolConnections>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http2: Option<AdminMetricsPoolConnections>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http3: Option<AdminMetricsPoolConnections>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AdminMetricsHttpPool {
    pub total_pools: usize,
    pub max_idle_per_host: usize,
    pub idle_timeout_seconds: u64,
    pub entries_per_host: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AdminMetricsPoolConnections {
    pub total_connections: usize,
}

/// Circuit breaker entry. Direct-backend proxies omit `target`; upstream
/// per-target breakers include `target` as `host:port`.
///
/// Runtime cache keys are namespace-qualified (`namespace|proxy_id` or
/// `namespace|proxy_id::host:port`). Authenticated admin output keeps the
/// original resource id in `proxy_id` and exposes `namespace` separately so
/// same-id tenants remain distinguishable without opaque composite IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsCircuitBreaker {
    pub namespace: String,
    pub proxy_id: String,
    /// Upstream target `host:port`. Absent for direct-backend (per-proxy) breakers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub state: String,
    pub failure_count: u32,
    pub success_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsHealthCheck {
    pub unhealthy_target_count: usize,
    pub unhealthy_targets: Vec<AdminMetricsUnhealthyTarget>,
}

/// One unhealthy target. Active probes are upstream-scoped (`type=active`,
/// `upstream_id` set, no `proxy_id`). Passive failure tracking is proxy-scoped
/// (`type=passive`, `proxy_id` set, no `upstream_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsUnhealthyTarget {
    pub namespace: String,
    /// Present only for passive health entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    /// Present only for active health entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_id: Option<String>,
    pub target: String,
    #[serde(rename = "type")]
    pub kind: AdminMetricsHealthKind,
    pub since_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminMetricsHealthKind {
    Active,
    Passive,
}

/// Active connection counts for one upstream, keyed by namespace + upstream id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsUpstreamConnections {
    pub namespace: String,
    pub upstream_id: String,
    /// `host:port` → active connection count (only counts > 0).
    pub targets: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AdminMetricsLoadBalancers {
    pub active_connections: Vec<AdminMetricsUpstreamConnections>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AdminMetricsCaches {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub router: Option<AdminMetricsRouterCache>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<AdminMetricsDnsCache>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsRouterCache {
    pub prefix_cache_entries: usize,
    pub regex_cache_entries: usize,
    pub prefix_eviction_count: u64,
    pub regex_eviction_count: u64,
    pub max_cache_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsDnsCache {
    pub cache_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsConsumerIndex {
    pub total_consumers: usize,
    pub key_auth_credentials: usize,
    pub basic_auth_credentials: usize,
    pub mtls_credentials: usize,
    pub jwt_credentials: usize,
    pub hmac_credentials: usize,
    pub identity_credentials: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsRateLimiting {
    pub tracked_key_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsTcpConnectionThrottle {
    pub enforcement_scope: &'static str,
    pub replica_limit_behavior: &'static str,
}

impl AdminMetricsTcpConnectionThrottle {
    pub const fn process_local() -> Self {
        Self {
            enforcement_scope: "process_local",
            replica_limit_behavior: "configured_limit_per_replica",
        }
    }
}

impl AdminMetricsCircuitBreaker {
    /// Direct-backend breaker keyed only by `(namespace, proxy_id)` (no upstream target).
    pub fn direct_backend(
        namespace: impl Into<String>,
        proxy_id: impl Into<String>,
        state: impl Into<String>,
        failure_count: u32,
        success_count: u32,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            proxy_id: proxy_id.into(),
            target: None,
            state: state.into(),
            failure_count,
            success_count,
        }
    }

    /// Per-target breaker for an upstream member (`namespace|proxy_id::host:port` at runtime).
    pub fn upstream_target(
        namespace: impl Into<String>,
        proxy_id: impl Into<String>,
        target: impl Into<String>,
        state: impl Into<String>,
        failure_count: u32,
        success_count: u32,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            proxy_id: proxy_id.into(),
            target: Some(target.into()),
            state: state.into(),
            failure_count,
            success_count,
        }
    }

    /// Parse a runtime circuit-breaker cache key into the authenticated admin shape.
    ///
    /// Accepts `namespace|proxy_id` or `namespace|proxy_id::host:port`. Malformed
    /// keys fail closed as `None` (no panic, no opaque composite id leakage).
    pub(crate) fn from_cache_key(
        key: &str,
        state: &str,
        failure_count: u32,
        success_count: u32,
    ) -> Option<Self> {
        let (namespace, id, target) = parse_namespaced_runtime_key(key)?;
        Some(match target {
            Some(target) => {
                Self::upstream_target(namespace, id, target, state, failure_count, success_count)
            }
            None => Self::direct_backend(namespace, id, state, failure_count, success_count),
        })
    }
}

impl AdminMetricsUnhealthyTarget {
    pub fn active(
        namespace: impl Into<String>,
        upstream_id: impl Into<String>,
        target: impl Into<String>,
        since_epoch_ms: u64,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            proxy_id: None,
            upstream_id: Some(upstream_id.into()),
            target: target.into(),
            kind: AdminMetricsHealthKind::Active,
            since_epoch_ms,
        }
    }

    pub fn passive(
        namespace: impl Into<String>,
        proxy_id: impl Into<String>,
        target: impl Into<String>,
        since_epoch_ms: u64,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            proxy_id: Some(proxy_id.into()),
            upstream_id: None,
            target: target.into(),
            kind: AdminMetricsHealthKind::Passive,
            since_epoch_ms,
        }
    }

    /// Parse an active-health runtime key (`namespace|upstream_id::host:port`).
    pub(crate) fn from_active_cache_key(key: &str, since_epoch_ms: u64) -> Option<Self> {
        let (namespace, upstream_id, target) = parse_namespaced_runtime_key(key)?;
        let target = target?;
        Some(Self::active(namespace, upstream_id, target, since_epoch_ms))
    }

    /// Parse a passive-health proxy partition key (`namespace|proxy_id`).
    pub(crate) fn from_passive_cache_key(
        proxy_key: &str,
        target: impl Into<String>,
        since_epoch_ms: u64,
    ) -> Option<Self> {
        let (namespace, proxy_id, scoped) = parse_namespaced_runtime_key(proxy_key)?;
        if scoped.is_some() {
            return None;
        }
        Some(Self::passive(namespace, proxy_id, target, since_epoch_ms))
    }
}

/// Parse `namespace|id` or `namespace|id::target` runtime keys.
///
/// Returns `None` when the key is missing the `|` delimiter, has an empty
/// namespace/id, or has an empty target suffix after `::`. Fail-closed: callers
/// must skip malformed keys rather than inventing identity.
fn parse_namespaced_runtime_key(key: &str) -> Option<(&str, &str, Option<&str>)> {
    let (namespace, rest) = key.split_once('|')?;
    if namespace.is_empty() || rest.is_empty() {
        return None;
    }
    match rest.split_once("::") {
        Some((id, target)) if !id.is_empty() && !target.is_empty() => {
            Some((namespace, id, Some(target)))
        }
        None => Some((namespace, rest, None)),
        Some(_) => None,
    }
}

/// Derive `gateway.config_source_status` from a lock-free `db_available`
/// snapshot. `None` means the mode has no DB-backed config source (`n/a`);
/// `Some(true)` / `Some(false)` map to `online` / `offline`.
pub fn config_source_status(db_available: Option<bool>) -> &'static str {
    match db_available {
        Some(true) => "online",
        Some(false) => "offline",
        None => "n/a",
    }
}

/// Skeleton response used when `AdminState.proxy_state` is absent (CP and
/// node_agent). Runtime counters are zeroed; pool/cache objects serialize as
/// empty maps. `config_source_status` defaults to `n/a`; callers that hold a
/// `db_available` flag (CP) overwrite it via [`build_admin_metrics`].
pub fn empty_proxy_metrics(mode: &str) -> AdminMetrics {
    AdminMetrics {
        gateway: AdminMetricsGateway {
            mode: mode.to_string(),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
            uptime_seconds: 0,
            total_requests: 0,
            status_codes_total: BTreeMap::new(),
            requests_per_second: 0,
            status_codes_per_second: BTreeMap::new(),
            metrics_window_seconds: 0,
            config_last_updated_at: None,
            config_source_status: "n/a".to_string(),
            proxy_count: 0,
            consumer_count: 0,
            upstream_count: 0,
            plugin_config_count: 0,
        },
        connection_pools: AdminMetricsConnectionPools::default(),
        circuit_breakers: Vec::new(),
        health_check: AdminMetricsHealthCheck {
            unhealthy_target_count: 0,
            unhealthy_targets: Vec::new(),
        },
        load_balancers: AdminMetricsLoadBalancers::default(),
        caches: AdminMetricsCaches::default(),
        consumer_index: AdminMetricsConsumerIndex {
            total_consumers: 0,
            key_auth_credentials: 0,
            basic_auth_credentials: 0,
            mtls_credentials: 0,
            jwt_credentials: 0,
            hmac_credentials: 0,
            identity_credentials: 0,
        },
        rate_limiting: AdminMetricsRateLimiting {
            tracked_key_count: 0,
        },
        tcp_connection_throttle: AdminMetricsTcpConnectionThrottle::process_local(),
        database_polling: None,
    }
}

/// Build the typed metrics snapshot from live admin/proxy state.
///
/// `db_available` is a lock-free snapshot of [`crate::admin::AdminState::db_available`]:
/// `None` → `"n/a"`, `Some(true)` → `"online"`, `Some(false)` → `"offline"`.
/// Callers must not probe the database for this field.
pub fn build_admin_metrics(
    mode: &str,
    db_available: Option<bool>,
    proxy_state: Option<&ProxyState>,
    database_polling: Option<DatabaseDeltaPollMetricsSnapshot>,
) -> AdminMetrics {
    let source_status = config_source_status(db_available).to_string();

    let Some(ps) = proxy_state else {
        let mut metrics = empty_proxy_metrics(mode);
        metrics.gateway.config_source_status = source_status;
        return metrics;
    };

    let config = ps.current_config();
    let mut status_codes_total = BTreeMap::new();
    for entry in ps.status_counts.iter() {
        status_codes_total.insert(
            entry.key().to_string(),
            entry.value().load(std::sync::atomic::Ordering::Relaxed),
        );
    }

    let http_pool_stats = ps.connection_pool.get_stats();
    let mut circuit_breakers: Vec<AdminMetricsCircuitBreaker> = ps
        .circuit_breaker_cache
        .snapshot()
        .into_iter()
        .filter_map(|(key, state, failures, successes)| {
            AdminMetricsCircuitBreaker::from_cache_key(&key, state, failures, successes)
        })
        .collect();
    circuit_breakers.sort_by(|a, b| {
        (&a.namespace, &a.proxy_id, &a.target).cmp(&(&b.namespace, &b.proxy_id, &b.target))
    });

    let mut unhealthy_targets: Vec<AdminMetricsUnhealthyTarget> = ps
        .health_checker
        .active_unhealthy_targets
        .iter()
        .filter_map(|entry| {
            AdminMetricsUnhealthyTarget::from_active_cache_key(entry.key(), *entry.value())
        })
        .collect();
    for proxy_entry in ps.health_checker.passive_health.iter() {
        let proxy_key = proxy_entry.key();
        for target_entry in proxy_entry.value().unhealthy.iter() {
            if let Some(entry) = AdminMetricsUnhealthyTarget::from_passive_cache_key(
                proxy_key,
                target_entry.key().clone(),
                target_entry.value().ejected_at_ms,
            ) {
                unhealthy_targets.push(entry);
            }
        }
    }
    unhealthy_targets.sort_by(|a, b| {
        (
            a.namespace.as_str(),
            a.kind,
            a.proxy_id.as_deref(),
            a.upstream_id.as_deref(),
            a.target.as_str(),
        )
            .cmp(&(
                b.namespace.as_str(),
                b.kind,
                b.proxy_id.as_deref(),
                b.upstream_id.as_deref(),
                b.target.as_str(),
            ))
    });

    let lb_snapshot = ps.load_balancer_cache.active_connections_snapshot();
    let mut active_connections = Vec::new();
    for (upstream_key, targets) in &lb_snapshot {
        let Some((namespace, upstream_id, scoped)) = parse_namespaced_runtime_key(upstream_key)
        else {
            continue;
        };
        if scoped.is_some() {
            continue;
        }
        let mut target_map = BTreeMap::new();
        for (target, count) in targets {
            target_map.insert(target.clone(), *count);
        }
        active_connections.push(AdminMetricsUpstreamConnections {
            namespace: namespace.to_string(),
            upstream_id: upstream_id.to_string(),
            targets: target_map,
        });
    }
    active_connections
        .sort_by(|a, b| (&a.namespace, &a.upstream_id).cmp(&(&b.namespace, &b.upstream_id)));

    let (prefix_entries, regex_entries, prefix_evictions, regex_evictions, max_entries) =
        ps.router_cache.cache_stats();
    let (
        keyauth_count,
        basic_count,
        mtls_count,
        jwt_count,
        hmac_count,
        identity_count,
        total_consumers,
    ) = ps.consumer_index.auth_type_counts();

    let mut status_codes_per_second = BTreeMap::new();
    for entry in ps.windowed_metrics.status_codes_per_second.iter() {
        status_codes_per_second.insert(
            entry.key().to_string(),
            entry.value().load(std::sync::atomic::Ordering::Relaxed),
        );
    }

    AdminMetrics {
        gateway: AdminMetricsGateway {
            mode: mode.to_string(),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
            uptime_seconds: ps.started_at.elapsed().as_secs(),
            total_requests: ps.request_count.load(std::sync::atomic::Ordering::Relaxed),
            status_codes_total,
            requests_per_second: ps
                .windowed_metrics
                .requests_per_second
                .load(std::sync::atomic::Ordering::Relaxed),
            status_codes_per_second,
            metrics_window_seconds: ps.windowed_metrics.window_seconds,
            config_last_updated_at: Some(config.loaded_at.to_rfc3339()),
            config_source_status: source_status,
            proxy_count: config.proxies.len(),
            consumer_count: config.consumers.len(),
            upstream_count: config.upstreams.len(),
            plugin_config_count: config.plugin_configs.len(),
        },
        connection_pools: AdminMetricsConnectionPools {
            http: Some(AdminMetricsHttpPool {
                total_pools: http_pool_stats.total_pools,
                max_idle_per_host: http_pool_stats.max_idle_per_host,
                idle_timeout_seconds: http_pool_stats.idle_timeout_seconds,
                entries_per_host: http_pool_stats.entries_per_host.into_iter().collect(),
            }),
            grpc: Some(AdminMetricsPoolConnections {
                total_connections: ps.grpc_pool.pool_size(),
            }),
            http2: Some(AdminMetricsPoolConnections {
                total_connections: ps.http2_pool.pool_size(),
            }),
            http3: Some(AdminMetricsPoolConnections {
                total_connections: ps.h3_pool.pool_size(),
            }),
        },
        circuit_breakers,
        health_check: AdminMetricsHealthCheck {
            unhealthy_target_count: unhealthy_targets.len(),
            unhealthy_targets,
        },
        load_balancers: AdminMetricsLoadBalancers { active_connections },
        caches: AdminMetricsCaches {
            router: Some(AdminMetricsRouterCache {
                prefix_cache_entries: prefix_entries,
                regex_cache_entries: regex_entries,
                prefix_eviction_count: prefix_evictions,
                regex_eviction_count: regex_evictions,
                max_cache_entries: max_entries,
            }),
            dns: Some(AdminMetricsDnsCache {
                cache_entries: ps.dns_cache.cache_len(),
            }),
        },
        consumer_index: AdminMetricsConsumerIndex {
            total_consumers,
            key_auth_credentials: keyauth_count,
            basic_auth_credentials: basic_count,
            mtls_credentials: mtls_count,
            jwt_credentials: jwt_count,
            hmac_credentials: hmac_count,
            identity_credentials: identity_count,
        },
        rate_limiting: AdminMetricsRateLimiting {
            tracked_key_count: ps.plugin_cache.total_rate_limiter_keys(),
        },
        tcp_connection_throttle: AdminMetricsTcpConnectionThrottle::process_local(),
        database_polling: if mode == "database" || mode == "cp" {
            database_polling
        } else {
            None
        },
    }
}

/// Canonical fixtures covering every mode and the circuit-breaker / health
/// variants the OpenAPI contract must accept. Used by contract tests so the
/// typed model remains the single source of truth for response shape.
// External test crates consume this helper through the library target; the
// separately compiled binary target has no production caller.
#[allow(dead_code)]
pub fn contract_fixtures() -> Vec<AdminMetrics> {
    let mut fixtures = Vec::new();

    for mode in ADMIN_METRICS_MODES {
        let mut base = empty_proxy_metrics(mode);
        // Modes with proxy state emit populated pool/cache objects even when
        // counters are zero — CP and node_agent keep the empty-skeleton shape.
        if matches!(*mode, "database" | "file" | "dp" | "mesh") {
            base = proxy_serving_fixture(mode);
        }
        if *mode == "database" || *mode == "cp" {
            base.database_polling = Some(sample_database_polling());
        }
        // CP holds a live database without proxy_state; healthy fixtures report
        // online so OpenAPI/docs cover the no-proxy DB-backed path.
        if *mode == "cp" {
            base.gateway.config_source_status = "online".to_string();
        }
        fixtures.push(base);
    }

    let mut breakers_and_health = proxy_serving_fixture("database");
    breakers_and_health.circuit_breakers = vec![
        AdminMetricsCircuitBreaker::direct_backend("ferrum", "proxy-payments-v2", "closed", 0, 0),
        AdminMetricsCircuitBreaker::upstream_target(
            "ferrum",
            "proxy-legacy-billing",
            "10.0.2.1:8080",
            "open",
            5,
            0,
        ),
        AdminMetricsCircuitBreaker::upstream_target(
            "ferrum",
            "proxy-legacy-billing",
            "10.0.2.2:8080",
            "closed",
            0,
            0,
        ),
        AdminMetricsCircuitBreaker::direct_backend("ferrum", "proxy-search", "half_open", 3, 1),
    ];
    breakers_and_health.health_check = AdminMetricsHealthCheck {
        unhealthy_target_count: 2,
        unhealthy_targets: vec![
            AdminMetricsUnhealthyTarget::active(
                "ferrum",
                "upstream-payments",
                "10.0.3.12:8080",
                1_711_720_800_000,
            ),
            AdminMetricsUnhealthyTarget::passive(
                "ferrum",
                "proxy-legacy-billing",
                "10.0.5.7:8080",
                1_711_720_920_000,
            ),
        ],
    };
    fixtures.push(breakers_and_health);

    // Offline enum coverage for DB-backed modes (database + CP).
    let mut database_offline = proxy_serving_fixture("database");
    database_offline.gateway.config_source_status = "offline".to_string();
    database_offline.database_polling = Some(sample_database_polling());
    fixtures.push(database_offline);

    let mut cp_offline = empty_proxy_metrics("cp");
    cp_offline.gateway.config_source_status = "offline".to_string();
    fixtures.push(cp_offline);

    fixtures
}

#[allow(dead_code)] // Called by the external contract-fixture entry point.
fn proxy_serving_fixture(mode: &str) -> AdminMetrics {
    let mut metrics = empty_proxy_metrics(mode);
    metrics.gateway.config_source_status = if mode == "database" {
        "online".to_string()
    } else {
        "n/a".to_string()
    };
    metrics.gateway.config_last_updated_at = Some("2026-03-29T14:23:07.482Z".to_string());
    metrics.gateway.metrics_window_seconds = 30;
    metrics.connection_pools = AdminMetricsConnectionPools {
        http: Some(AdminMetricsHttpPool {
            total_pools: 0,
            max_idle_per_host: 32,
            idle_timeout_seconds: 90,
            entries_per_host: BTreeMap::new(),
        }),
        grpc: Some(AdminMetricsPoolConnections {
            total_connections: 0,
        }),
        http2: Some(AdminMetricsPoolConnections {
            total_connections: 0,
        }),
        http3: Some(AdminMetricsPoolConnections {
            total_connections: 0,
        }),
    };
    metrics.caches = AdminMetricsCaches {
        router: Some(AdminMetricsRouterCache {
            prefix_cache_entries: 0,
            regex_cache_entries: 0,
            prefix_eviction_count: 0,
            regex_eviction_count: 0,
            max_cache_entries: 10_000,
        }),
        dns: Some(AdminMetricsDnsCache { cache_entries: 0 }),
    };
    metrics
}

#[allow(dead_code)] // Called by the external contract-fixture entry point.
fn sample_database_polling() -> DatabaseDeltaPollMetricsSnapshot {
    DatabaseDeltaPollMetricsSnapshot {
        rejected_deltas_total: 0,
        rejected_deltas_by_resource_category: BTreeMap::from([
            ("none", 0),
            ("proxy", 0),
            ("consumer", 0),
            ("plugin_config", 0),
            ("upstream", 0),
            ("mixed", 0),
        ]),
        consecutive_identical_rejections: 0,
        current_backoff_bucket: "none",
        current_backoff_seconds: 0,
        forced_full_reloads_total: 0,
        recoveries_total: 0,
        last_resource_category: "none",
        last_poll_completed_at: Some("2026-03-29T14:23:07.482Z".to_string()),
        last_poll_completed_at_unix_ms: 1_711_720_987_482,
        degraded: None,
    }
}
