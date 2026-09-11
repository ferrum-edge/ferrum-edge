//! Data-path Prometheus families for load shedding, upstream health, circuit
//! breakers, backend retries, connection pools, and frontend TLS admission.
//!
//! Every gauge here is sampled on the `/metrics` scrape from state the gateway
//! already maintains — [`crate::overload::OverloadState`] atomics, the
//! [`crate::health_check::HealthChecker`] two-layer maps, the
//! [`crate::circuit_breaker::CircuitBreakerCache`], and the pools' own resident
//! counts. Nothing on the proxy hot path is added, taken, or reshaped to
//! publish them; in particular the `CachePadded` overload atomics are read
//! through their ordinary `load()` accessors.
//!
//! The two process-global counters ([`record_backend_retry_attempt`] and
//! [`record_frontend_tls_handshake_failure`]) are incremented from single
//! choke points on cold failure paths — a scheduled backend retry and a
//! refused frontend TLS handshake — with one `Relaxed` `fetch_add` each.
//!
//! ## Cardinality
//!
//! Label sets are bounded by the *configuration*, never by traffic or by
//! endpoint churn:
//!
//! - `action`, `resource`, `state`, `pool`, and `reason` are closed
//!   compiled-in sets.
//! - `upstream_id` and `proxy_id` are configured resource identities, the same
//!   tier `ferrum_requests_total` already uses.
//! - No resolved endpoint address, SNI, peer IP, or certificate field is ever
//!   a label. Per-target health and per-target breaker state are aggregated to
//!   a count per upstream / per proxy precisely so that a churning endpoint set
//!   cannot grow the series count (see issue #4178).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::config::types::GatewayConfig;
use crate::health_check::HealthChecker;
use crate::overload::{OverloadLevel, OverloadState, RED_PROBABILITY_SCALE};
use crate::plugins::prometheus_metrics::escape_label_value;
use crate::proxy::ProxyState;

/// Frontend TLS handshakes abandoned because the configured budget elapsed.
static FRONTEND_TLS_HANDSHAKE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
/// Frontend TLS handshakes rejected by rustls (bad certificate, no shared
/// cipher, untrusted or revoked client certificate, malformed record).
static FRONTEND_TLS_HANDSHAKE_ERRORS: AtomicU64 = AtomicU64::new(0);
/// Backend request retries scheduled by the retry policy.
static BACKEND_RETRY_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

/// Bounded reason for a refused frontend TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendTlsHandshakeFailure {
    /// `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` elapsed first.
    Timeout,
    /// rustls refused the handshake.
    Error,
}

/// Record one refused frontend TLS handshake.
///
/// Called from the shared frontend admission helper in [`crate::tls`], which
/// every rustls-terminating listener surface funnels through. QUIC/HTTP-3 and
/// DTLS do not use that helper and are therefore not represented here.
pub fn record_frontend_tls_handshake_failure(reason: FrontendTlsHandshakeFailure) {
    let counter = match reason {
        FrontendTlsHandshakeFailure::Timeout => &FRONTEND_TLS_HANDSHAKE_TIMEOUTS,
        FrontendTlsHandshakeFailure::Error => &FRONTEND_TLS_HANDSHAKE_ERRORS,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Record one backend retry about to be dispatched.
///
/// Called from [`crate::retry::retry_delay`], which every retrying transport
/// (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, raw TCP) evaluates immediately
/// before replaying an attempt.
pub fn record_backend_retry_attempt() {
    BACKEND_RETRY_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
}

/// Backend retries scheduled since process start.
pub fn backend_retry_attempts_total() -> u64 {
    BACKEND_RETRY_ATTEMPTS.load(Ordering::Relaxed)
}

/// Refused frontend TLS handshakes since process start, as `(timeout, error)`.
pub fn frontend_tls_handshake_failures_total() -> (u64, u64) {
    (
        FRONTEND_TLS_HANDSHAKE_TIMEOUTS.load(Ordering::Relaxed),
        FRONTEND_TLS_HANDSHAKE_ERRORS.load(Ordering::Relaxed),
    )
}

/// Render every data-path family for one `/metrics` scrape.
///
/// `ns_label` is the registry's `,namespace="…"` fragment (empty before the
/// gateway namespace is published). The process-global counters render in
/// every mode; the sampled gauges render only where a [`ProxyState`] exists,
/// so CP and node-agent scrapes stay silent rather than reporting zeros for a
/// data path they do not run.
pub fn render_prometheus(proxy_state: Option<&ProxyState>, ns_label: &str) -> String {
    let mut output = String::new();
    render_process_families(&mut output, ns_label);
    if let Some(state) = proxy_state {
        render_overload(&mut output, &state.overload, ns_label);
        let config = state.current_config();
        render_upstream_health(&mut output, &config, &state.health_checker, ns_label);
        render_circuit_breakers(&mut output, &state.circuit_breaker_cache, ns_label);
        let (http_entries, max_idle_per_host) = state.connection_pool.pool_gauges();
        let pools = [
            ("http", http_entries),
            ("grpc", state.grpc_pool.pool_size()),
            ("http2", state.http2_pool.pool_size()),
            ("http3", state.h3_pool.pool_size()),
            ("hbone", state.hbone_pool.pool_size()),
            ("mesh_mtls", state.mesh_mtls_pool.pool_size()),
        ];
        render_connection_pools(&mut output, &pools, max_idle_per_host, ns_label);
    }
    output
}

/// Append the two process-global counters.
pub fn render_process_families(output: &mut String, ns_label: &str) {
    output.push_str(
        "# HELP ferrum_backend_retry_attempts_total Backend request retries scheduled by the retry policy across every dispatch transport.\n",
    );
    output.push_str("# TYPE ferrum_backend_retry_attempts_total counter\n");
    push_scalar(
        output,
        "ferrum_backend_retry_attempts_total",
        ns_label,
        backend_retry_attempts_total(),
    );

    let (timeouts, errors) = frontend_tls_handshake_failures_total();
    output.push_str(
        "# HELP ferrum_frontend_tls_handshake_failures_total Frontend TLS handshakes refused before any HTTP work, by bounded reason.\n",
    );
    output.push_str("# TYPE ferrum_frontend_tls_handshake_failures_total counter\n");
    // Emit both reason buckets even at zero so dashboards can pin them.
    for (reason, value) in [("timeout", timeouts), ("error", errors)] {
        output.push_str(&format!(
            "ferrum_frontend_tls_handshake_failures_total{{reason=\"{reason}\"{ns_label}}} {value}\n"
        ));
    }
}

/// Append the load-shedding families sampled from [`OverloadState`].
pub fn render_overload(output: &mut String, overload: &OverloadState, ns_label: &str) {
    let level = match overload.level() {
        OverloadLevel::Normal => 0_u64,
        OverloadLevel::Pressure => 1,
        OverloadLevel::Critical => 2,
    };
    output.push_str(
        "# HELP ferrum_overload_level Current overload pressure level: 0 normal, 1 pressure, 2 critical.\n",
    );
    output.push_str("# TYPE ferrum_overload_level gauge\n");
    push_scalar(output, "ferrum_overload_level", ns_label, level);

    output.push_str(
        "# HELP ferrum_overload_shedding_active Whether a progressive load-shedding action is currently engaged (1) or not (0).\n",
    );
    output.push_str("# TYPE ferrum_overload_shedding_active gauge\n");
    // Closed action set: emit all three every scrape so recovery is a value
    // change rather than a disappearing series.
    for (action, engaged) in [
        (
            "disable_keepalive",
            overload.disable_keepalive.load(Ordering::Relaxed),
        ),
        (
            "reject_new_connections",
            overload.reject_new_connections.load(Ordering::Relaxed),
        ),
        (
            "reject_new_requests",
            overload.reject_new_requests.load(Ordering::Relaxed),
        ),
    ] {
        output.push_str(&format!(
            "ferrum_overload_shedding_active{{action=\"{action}\"{ns_label}}} {}\n",
            u64::from(engaged)
        ));
    }

    output.push_str(
        "# HELP ferrum_overload_draining Whether the gateway is draining for shutdown (1) or serving normally (0).\n",
    );
    output.push_str("# TYPE ferrum_overload_draining gauge\n");
    push_scalar(
        output,
        "ferrum_overload_draining",
        ns_label,
        u64::from(overload.draining.load(Ordering::Relaxed)),
    );

    let red_scale = f64::from(RED_PROBABILITY_SCALE);
    let red_ratio = f64::from(overload.red_drop_probability.load(Ordering::Relaxed)) / red_scale;
    output.push_str(
        "# HELP ferrum_overload_red_drop_probability_ratio RED probabilistic keepalive-shedding probability between the pressure and critical thresholds, as a ratio in [0,1].\n",
    );
    output.push_str("# TYPE ferrum_overload_red_drop_probability_ratio gauge\n");
    push_float(
        output,
        "ferrum_overload_red_drop_probability_ratio",
        ns_label,
        red_ratio,
    );

    output.push_str(
        "# HELP ferrum_overload_port_exhaustion_events_total Ephemeral port exhaustion (EADDRNOTAVAIL) events observed since process start.\n",
    );
    output.push_str("# TYPE ferrum_overload_port_exhaustion_events_total counter\n");
    push_scalar(
        output,
        "ferrum_overload_port_exhaustion_events_total",
        ns_label,
        overload.port_exhaustion_events.load(Ordering::Relaxed),
    );

    output.push_str(
        "# HELP ferrum_overload_active_connections Live in-flight connections tracked by the accept-path RAII guard.\n",
    );
    output.push_str("# TYPE ferrum_overload_active_connections gauge\n");
    push_scalar(
        output,
        "ferrum_overload_active_connections",
        ns_label,
        overload.active_connections.load(Ordering::Relaxed),
    );

    output.push_str(
        "# HELP ferrum_overload_active_requests Live in-flight requests and multiplexed streams tracked by the request RAII guard.\n",
    );
    output.push_str("# TYPE ferrum_overload_active_requests gauge\n");
    push_scalar(
        output,
        "ferrum_overload_active_requests",
        ns_label,
        overload.active_requests.load(Ordering::Relaxed),
    );

    output.push_str(
        "# HELP ferrum_overload_resource_current Most recent overload-monitor sample of a tracked resource.\n",
    );
    output.push_str("# TYPE ferrum_overload_resource_current gauge\n");
    for (resource, value) in [
        ("fd", overload.fd_current.load(Ordering::Relaxed)),
        ("connections", overload.conn_current.load(Ordering::Relaxed)),
        ("requests", overload.req_current.load(Ordering::Relaxed)),
    ] {
        output.push_str(&format!(
            "ferrum_overload_resource_current{{resource=\"{resource}\"{ns_label}}} {value}\n"
        ));
    }

    output.push_str(
        "# HELP ferrum_overload_resource_limit Ceiling the overload monitor compares each tracked resource against.\n",
    );
    output.push_str("# TYPE ferrum_overload_resource_limit gauge\n");
    for (resource, value) in [
        ("fd", overload.fd_max.load(Ordering::Relaxed)),
        ("connections", overload.conn_max.load(Ordering::Relaxed)),
        ("requests", overload.req_max.load(Ordering::Relaxed)),
    ] {
        output.push_str(&format!(
            "ferrum_overload_resource_limit{{resource=\"{resource}\"{ns_label}}} {value}\n"
        ));
    }

    let loop_latency_us = overload.loop_latency_us.load(Ordering::Relaxed);
    let loop_latency_seconds = loop_latency_us as f64 / 1_000_000.0;
    output.push_str(
        "# HELP ferrum_overload_event_loop_latency_seconds Most recent tokio event-loop scheduling delay sampled by the overload monitor.\n",
    );
    output.push_str("# TYPE ferrum_overload_event_loop_latency_seconds gauge\n");
    push_float(
        output,
        "ferrum_overload_event_loop_latency_seconds",
        ns_label,
        loop_latency_seconds,
    );
}

/// Append the upstream-health families, aggregated per configured resource.
///
/// Active-probe ejections are upstream-scoped and passive ejections are
/// proxy-scoped, matching the two-layer split in
/// [`crate::health_check::HealthChecker`]. Both are reduced to a **count** so
/// the series set is bounded by the configuration rather than by the resolved
/// endpoint set.
pub fn render_upstream_health(
    output: &mut String,
    config: &GatewayConfig,
    health_checker: &HealthChecker,
    ns_label: &str,
) {
    // (namespace, upstream_id) → (configured targets, active-unhealthy targets)
    let mut upstreams: BTreeMap<(String, String), (u64, u64)> = BTreeMap::new();
    for upstream in &config.upstreams {
        let entry = upstreams
            .entry((upstream.namespace.clone(), upstream.id.clone()))
            .or_default();
        entry.0 += upstream.targets.len() as u64;
    }
    for entry in health_checker.active_unhealthy_targets.iter() {
        let Some((namespace, upstream_id, target)) =
            crate::admin::metrics::parse_namespaced_runtime_key(entry.key())
        else {
            continue;
        };
        if target.is_none() {
            continue;
        }
        let unhealthy = upstreams
            .entry((namespace.to_string(), upstream_id.to_string()))
            .or_default();
        unhealthy.1 += 1;
    }

    output.push_str(
        "# HELP ferrum_upstream_targets Targets configured on an upstream, including service-discovery resolved endpoints.\n",
    );
    output.push_str("# TYPE ferrum_upstream_targets gauge\n");
    for ((namespace, upstream_id), (configured, _)) in &upstreams {
        output.push_str(&format!(
            "ferrum_upstream_targets{{upstream_id=\"{}\",upstream_namespace=\"{}\"{ns_label}}} {configured}\n",
            escape_label_value(upstream_id),
            escape_label_value(namespace),
        ));
    }

    output.push_str(
        "# HELP ferrum_upstream_unhealthy_targets Targets an active health probe has ejected for this upstream; shared across every proxy using it.\n",
    );
    output.push_str("# TYPE ferrum_upstream_unhealthy_targets gauge\n");
    for ((namespace, upstream_id), (_, unhealthy)) in &upstreams {
        output.push_str(&format!(
            "ferrum_upstream_unhealthy_targets{{upstream_id=\"{}\",upstream_namespace=\"{}\"{ns_label}}} {unhealthy}\n",
            escape_label_value(upstream_id),
            escape_label_value(namespace),
        ));
    }

    // Passive ejections are isolated per proxy: proxy A's failures never
    // change proxy B's view, even on a shared upstream.
    let mut passive: BTreeMap<(String, String), u64> = BTreeMap::new();
    for proxy_entry in health_checker.passive_health.iter() {
        let Some((namespace, proxy_id, scoped)) =
            crate::admin::metrics::parse_namespaced_runtime_key(proxy_entry.key())
        else {
            continue;
        };
        if scoped.is_some() {
            continue;
        }
        passive.insert(
            (namespace.to_string(), proxy_id.to_string()),
            proxy_entry.value().unhealthy.len() as u64,
        );
    }

    output.push_str(
        "# HELP ferrum_proxy_passive_unhealthy_targets Targets this proxy has ejected from traffic-based passive health checking.\n",
    );
    output.push_str("# TYPE ferrum_proxy_passive_unhealthy_targets gauge\n");
    for ((namespace, proxy_id), count) in &passive {
        output.push_str(&format!(
            "ferrum_proxy_passive_unhealthy_targets{{proxy_id=\"{}\",proxy_namespace=\"{}\"{ns_label}}} {count}\n",
            escape_label_value(proxy_id),
            escape_label_value(namespace),
        ));
    }
}

/// Append the circuit-breaker families, aggregated per proxy.
///
/// Runtime breaker keys are `namespace|proxy_id` for direct-backend proxies
/// and `namespace|proxy_id::host:port` for per-target breakers. The `host:port`
/// suffix is deliberately NOT a label: with service discovery it is a resolved
/// endpoint that churns with pod lifecycle. Counting breakers per state keeps
/// "is anything open for this proxy?" answerable at fixed cardinality.
pub fn render_circuit_breakers(output: &mut String, cache: &CircuitBreakerCache, ns_label: &str) {
    // [closed, open, half_open]
    let mut by_proxy: BTreeMap<(String, String), [u64; 3]> = BTreeMap::new();
    for (key, state, _failures, _successes) in cache.snapshot() {
        let Some((namespace, proxy_id, _target)) =
            crate::admin::metrics::parse_namespaced_runtime_key(&key)
        else {
            continue;
        };
        let counts = by_proxy
            .entry((namespace.to_string(), proxy_id.to_string()))
            .or_default();
        match state {
            "closed" => counts[0] += 1,
            "open" => counts[1] += 1,
            "half_open" => counts[2] += 1,
            _ => {}
        }
    }

    output.push_str(
        "# HELP ferrum_circuit_breakers Upstream circuit breakers resident for this proxy, counted by breaker state.\n",
    );
    output.push_str("# TYPE ferrum_circuit_breakers gauge\n");
    for ((namespace, proxy_id), counts) in &by_proxy {
        for (state, count) in [
            ("closed", counts[0]),
            ("open", counts[1]),
            ("half_open", counts[2]),
        ] {
            output.push_str(&format!(
                "ferrum_circuit_breakers{{proxy_id=\"{}\",proxy_namespace=\"{}\",state=\"{state}\"{ns_label}}} {count}\n",
                escape_label_value(proxy_id),
                escape_label_value(namespace),
            ));
        }
    }

    output.push_str(
        "# HELP ferrum_circuit_breaker_cache_entries Circuit breakers resident in the shared breaker cache.\n",
    );
    output.push_str("# TYPE ferrum_circuit_breaker_cache_entries gauge\n");
    push_scalar(
        output,
        "ferrum_circuit_breaker_cache_entries",
        ns_label,
        cache.len() as u64,
    );

    output.push_str(
        "# HELP ferrum_circuit_breaker_cache_admission_refused_total Requests refused a cached breaker because the shared breaker cache was at its admission ceiling; each one ran on a transient breaker whose failures never accumulate.\n",
    );
    output.push_str("# TYPE ferrum_circuit_breaker_cache_admission_refused_total counter\n");
    push_scalar(
        output,
        "ferrum_circuit_breaker_cache_admission_refused_total",
        ns_label,
        cache.admission_refused_total(),
    );

    output.push_str(
        "# HELP ferrum_circuit_breaker_cache_max_entries Admission ceiling for the shared breaker cache; new keys are refused at this count.\n",
    );
    output.push_str("# TYPE ferrum_circuit_breaker_cache_max_entries gauge\n");
    push_scalar(
        output,
        "ferrum_circuit_breaker_cache_max_entries",
        ns_label,
        cache.max_entries() as u64,
    );
}

/// Append the connection-pool saturation families.
///
/// `pool` is a closed compiled-in set. Per-host pool keys are deliberately not
/// labels: they carry backend identity and grow with the resolved endpoint set.
pub fn render_connection_pools(
    output: &mut String,
    pools: &[(&str, usize)],
    max_idle_per_host: usize,
    ns_label: &str,
) {
    output.push_str(
        "# HELP ferrum_connection_pool_entries Resident entries per gateway backend pool: cached reqwest clients for http, live multiplexed connections for the others.\n",
    );
    output.push_str("# TYPE ferrum_connection_pool_entries gauge\n");
    for (pool, entries) in pools {
        output.push_str(&format!(
            "ferrum_connection_pool_entries{{pool=\"{pool}\"{ns_label}}} {entries}\n"
        ));
    }

    output.push_str(
        "# HELP ferrum_connection_pool_max_idle_per_host Configured idle-connection ceiling per backend host for the HTTP/1.1 and HTTP/2 reqwest pool.\n",
    );
    output.push_str("# TYPE ferrum_connection_pool_max_idle_per_host gauge\n");
    push_scalar(
        output,
        "ferrum_connection_pool_max_idle_per_host",
        ns_label,
        max_idle_per_host as u64,
    );
}

/// Emit one unlabeled sample, adding the namespace label when published.
fn push_scalar(output: &mut String, metric_name: &str, ns_label: &str, value: u64) {
    if ns_label.is_empty() {
        output.push_str(&format!("{metric_name} {value}\n"));
    } else {
        output.push_str(&format!(
            "{metric_name}{{{}}} {value}\n",
            ns_label.strip_prefix(',').unwrap_or(ns_label)
        ));
    }
}

/// Emit one unlabeled float sample with a fixed six-decimal rendering.
fn push_float(output: &mut String, metric_name: &str, ns_label: &str, value: f64) {
    if ns_label.is_empty() {
        output.push_str(&format!("{metric_name} {value:.6}\n"));
    } else {
        output.push_str(&format!(
            "{metric_name}{{{}}} {value:.6}\n",
            ns_label.strip_prefix(',').unwrap_or(ns_label)
        ));
    }
}
