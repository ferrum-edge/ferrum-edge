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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsCircuitBreaker {
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

/// One unhealthy target. Active probes are upstream-scoped (`type=active`, no
/// `proxy_id`). Passive failure tracking is proxy-scoped (`type=passive` and
/// requires `proxy_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminMetricsUnhealthyTarget {
    /// Present only for passive health entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    pub target: String,
    #[serde(rename = "type")]
    pub kind: AdminMetricsHealthKind,
    pub since_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminMetricsHealthKind {
    Active,
    Passive,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AdminMetricsLoadBalancers {
    pub active_connections: BTreeMap<String, BTreeMap<String, i64>>,
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
    /// Direct-backend breaker keyed only by `proxy_id` (no upstream target).
    pub fn direct_backend(
        proxy_id: impl Into<String>,
        state: impl Into<String>,
        failure_count: u32,
        success_count: u32,
    ) -> Self {
        Self {
            proxy_id: proxy_id.into(),
            target: None,
            state: state.into(),
            failure_count,
            success_count,
        }
    }

    /// Per-target breaker for an upstream member (`proxy_id::host:port` at runtime).
    pub fn upstream_target(
        proxy_id: impl Into<String>,
        target: impl Into<String>,
        state: impl Into<String>,
        failure_count: u32,
        success_count: u32,
    ) -> Self {
        Self {
            proxy_id: proxy_id.into(),
            target: Some(target.into()),
            state: state.into(),
            failure_count,
            success_count,
        }
    }

    pub(crate) fn from_cache_key(
        key: &str,
        state: &str,
        failure_count: u32,
        success_count: u32,
    ) -> Self {
        if let Some((proxy_id, target)) = key.split_once("::") {
            Self::upstream_target(proxy_id, target, state, failure_count, success_count)
        } else {
            Self::direct_backend(key, state, failure_count, success_count)
        }
    }
}

impl AdminMetricsUnhealthyTarget {
    pub fn active(target: impl Into<String>, since_epoch_ms: u64) -> Self {
        Self {
            proxy_id: None,
            target: target.into(),
            kind: AdminMetricsHealthKind::Active,
            since_epoch_ms,
        }
    }

    pub fn passive(
        proxy_id: impl Into<String>,
        target: impl Into<String>,
        since_epoch_ms: u64,
    ) -> Self {
        Self {
            proxy_id: Some(proxy_id.into()),
            target: target.into(),
            kind: AdminMetricsHealthKind::Passive,
            since_epoch_ms,
        }
    }
}

/// Skeleton response used when `AdminState.proxy_state` is absent (CP and
/// node_agent). Runtime counters are zeroed; pool/cache objects serialize as
/// empty maps.
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
pub fn build_admin_metrics(
    mode: &str,
    db_configured: bool,
    proxy_state: Option<&ProxyState>,
    database_polling: Option<DatabaseDeltaPollMetricsSnapshot>,
) -> AdminMetrics {
    let Some(ps) = proxy_state else {
        return empty_proxy_metrics(mode);
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
    let circuit_breakers = ps
        .circuit_breaker_cache
        .snapshot()
        .into_iter()
        .map(|(key, state, failures, successes)| {
            AdminMetricsCircuitBreaker::from_cache_key(&key, state, failures, successes)
        })
        .collect();

    let mut unhealthy_targets: Vec<AdminMetricsUnhealthyTarget> = ps
        .health_checker
        .active_unhealthy_targets
        .iter()
        .map(|entry| AdminMetricsUnhealthyTarget::active(entry.key().clone(), *entry.value()))
        .collect();
    for proxy_entry in ps.health_checker.passive_health.iter() {
        let proxy_id = proxy_entry.key();
        for target_entry in proxy_entry.value().unhealthy.iter() {
            unhealthy_targets.push(AdminMetricsUnhealthyTarget::passive(
                proxy_id.clone(),
                target_entry.key().clone(),
                *target_entry.value(),
            ));
        }
    }

    let lb_snapshot = ps.load_balancer_cache.active_connections_snapshot();
    let mut active_connections = BTreeMap::new();
    for (upstream_id, targets) in &lb_snapshot {
        let mut target_map = BTreeMap::new();
        for (target, count) in targets {
            target_map.insert(target.clone(), *count);
        }
        active_connections.insert(upstream_id.clone(), target_map);
    }

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

    let config_source_status = if db_configured { "online" } else { "n/a" };

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
            config_source_status: config_source_status.to_string(),
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
        database_polling: if mode == "database" {
            database_polling
        } else {
            None
        },
    }
}

/// Canonical fixtures covering every mode and the circuit-breaker / health
/// variants the OpenAPI contract must accept. Used by contract tests so the
/// typed model remains the single source of truth for response shape.
pub fn contract_fixtures() -> Vec<AdminMetrics> {
    let mut fixtures = Vec::new();

    for mode in ADMIN_METRICS_MODES {
        let mut base = empty_proxy_metrics(mode);
        // Modes with proxy state emit populated pool/cache objects even when
        // counters are zero — CP and node_agent keep the empty-skeleton shape.
        if matches!(*mode, "database" | "file" | "dp" | "mesh") {
            base = proxy_serving_fixture(mode);
        }
        if *mode == "database" {
            base.database_polling = Some(sample_database_polling());
        }
        fixtures.push(base);
    }

    let mut breakers_and_health = proxy_serving_fixture("database");
    breakers_and_health.circuit_breakers = vec![
        AdminMetricsCircuitBreaker::direct_backend("proxy-payments-v2", "closed", 0, 0),
        AdminMetricsCircuitBreaker::upstream_target(
            "proxy-legacy-billing",
            "10.0.2.1:8080",
            "open",
            5,
            0,
        ),
        AdminMetricsCircuitBreaker::upstream_target(
            "proxy-legacy-billing",
            "10.0.2.2:8080",
            "closed",
            0,
            0,
        ),
        AdminMetricsCircuitBreaker::direct_backend("proxy-search", "half_open", 3, 1),
    ];
    breakers_and_health.health_check = AdminMetricsHealthCheck {
        unhealthy_target_count: 2,
        unhealthy_targets: vec![
            AdminMetricsUnhealthyTarget::active("10.0.3.12:8080", 1_711_720_800_000),
            AdminMetricsUnhealthyTarget::passive(
                "proxy-legacy-billing",
                "10.0.5.7:8080",
                1_711_720_920_000,
            ),
        ],
    };
    fixtures.push(breakers_and_health);

    fixtures
}

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
        degraded: None,
    }
}
