//! Shared backend dispatch helpers used by both the main HTTP/1.1+HTTP/2 proxy
//! path (`proxy/mod.rs`) and the HTTP/3 frontend (`http3/server.rs`).
//!
//! These functions encapsulate upstream target selection, circuit breaker checks,
//! post-request outcome recording (CB, passive health, latency), and runtime
//! HTTP-flavor detection. Extracting them prevents logic drift between the
//! two frontend paths.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyper::Request;
use tracing::{debug, warn};

use crate::config::types::{HttpFlavor, Proxy, UpstreamTarget};
use crate::load_balancer::{HashOnStrategy, HealthContext, LoadBalancerCache};
use crate::proxy::ProxyState;
use crate::proxy::is_valid_websocket_key;

// ---------------------------------------------------------------------------
// Runtime HTTP flavor detection
// ---------------------------------------------------------------------------

/// Detect the HTTP flavor of an incoming request.
///
/// Called from the hot path for every HTTP-family request. Cost:
/// - Fast-fails on the WebSocket upgrade / Extended CONNECT signals
///   (4 header lookups, short-circuit).
/// - Falls through to a single content-type lookup + 16-byte ASCII prefix match.
/// - Total: ~80–100ns on a non-WebSocket, non-gRPC POST; well below noise.
///
/// **Do not cache the result per-proxy.** Flavors are per-request: a single
/// `Https` proxy can serve regular REST, gRPC, and WebSocket traffic mixed on
/// the same backend. A `DashMap` lookup would cost more than this function.
///
/// The body type `B` is generic so the same helper works for hyper's
/// `Incoming` body, the H3 request shell, and unit tests that pass `()`.
#[inline]
pub fn detect_http_flavor<B>(req: &Request<B>) -> HttpFlavor {
    // Cheap WebSocket check runs first — an Extended CONNECT with
    // `:protocol=websocket` carries no content-type, so the gRPC arm would
    // miss it.
    if is_extended_connect_websocket(req) || is_http1_websocket_upgrade(req) {
        return HttpFlavor::WebSocket;
    }

    if let Some(ct) = req.headers().get(hyper::header::CONTENT_TYPE)
        && let Some(prefix) = ct.as_bytes().get(..16)
        && prefix.eq_ignore_ascii_case(b"application/grpc")
    {
        return HttpFlavor::Grpc;
    }

    HttpFlavor::Plain
}

/// Extended CONNECT WebSocket check for HTTP/2 (RFC 8441) and HTTP/3
/// (RFC 9220). Mirrors `is_h2_websocket_connect` in `proxy/mod.rs` but lives
/// here so it can be called from both the H1/H2 server loop and the H3
/// frontend.
#[inline]
fn is_extended_connect_websocket<B>(req: &Request<B>) -> bool {
    req.method() == hyper::Method::CONNECT
        && matches!(
            req.version(),
            hyper::Version::HTTP_2 | hyper::Version::HTTP_3
        )
        && req
            .extensions()
            .get::<hyper::ext::Protocol>()
            .is_some_and(|p| p.as_ref().eq_ignore_ascii_case(b"websocket"))
}

/// HTTP/1.1 WebSocket upgrade check. Accepts only well-formed RFC 6455
/// handshakes: `Connection: Upgrade`, `Upgrade: websocket`, a base64-encoded
/// 16-byte `Sec-WebSocket-Key`, and `Sec-WebSocket-Version: 13`.
#[inline]
fn is_http1_websocket_upgrade<B>(req: &Request<B>) -> bool {
    let headers = req.headers();
    let Some(connection) = headers.get("connection").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    // `Connection` is a list header; any token == "upgrade" (case-insensitive).
    let has_upgrade_token = connection
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    if !has_upgrade_token {
        return false;
    }
    let is_websocket = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
    if !is_websocket {
        return false;
    }
    let key_ok = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_valid_websocket_key);
    let version_ok = headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        == Some("13");
    key_ok && version_ok
}

/// Result of upstream target selection.
pub(crate) struct UpstreamSelection {
    /// Hash key used for consistent-hashing and sticky cookie decisions.
    /// `None` when no upstream is configured — the key is never read in that case
    /// and skipping it avoids a per-request `client_ip.to_owned()` allocation.
    pub lb_hash_key: Option<String>,
    /// Selected upstream target, or `None` if no upstream is configured or all
    /// targets are unavailable.
    pub target: Option<Arc<UpstreamTarget>>,
    /// `true` when all targets were unhealthy and the selection fell back to the
    /// least-unhealthy target.
    pub is_fallback: bool,
    /// `true` when a sticky session cookie needs to be set on the response.
    pub sticky_cookie_needed: bool,
}

/// Select an upstream target for the given proxy using load balancing with
/// health-aware filtering.
///
/// When the proxy has no `upstream_id`, returns a no-op selection with
/// `lb_hash_key: None` — the key is never read without an upstream.
pub(crate) fn select_upstream_target(
    proxy: &Proxy,
    state: &ProxyState,
    client_ip: &str,
    proxy_headers: &HashMap<String, String>,
) -> UpstreamSelection {
    let Some(upstream_id) = &proxy.upstream_id else {
        return UpstreamSelection {
            lb_hash_key: None,
            target: None,
            is_fallback: false,
            sticky_cookie_needed: false,
        };
    };

    let proxy_passive = state
        .health_checker
        .passive_health
        .get(&proxy.id)
        .map(|r| r.value().clone());
    let health_ctx = HealthContext {
        active_unhealthy: &state.health_checker.active_unhealthy_targets,
        proxy_passive: proxy_passive.clone(),
    };

    // Single ArcSwap load for both strategy + selection
    let balancers = state.load_balancer_cache.load();
    let strategy = LoadBalancerCache::get_hash_on_strategy_from(&balancers, upstream_id);
    let (hash_key, needs_set) = resolve_hash_key(&strategy, client_ip, proxy_headers);

    match LoadBalancerCache::select_target_from(
        &balancers,
        upstream_id,
        &hash_key,
        Some(&health_ctx),
    ) {
        Some(selection) => {
            if selection.is_fallback {
                warn!(
                    proxy_id = %proxy.id,
                    upstream_id = %upstream_id,
                    target_host = %selection.target.host,
                    target_port = selection.target.port,
                    "All upstream targets unhealthy, using fallback target"
                );
            } else {
                debug!(
                    proxy_id = %proxy.id,
                    upstream_id = %upstream_id,
                    target_host = %selection.target.host,
                    target_port = selection.target.port,
                    "Upstream target selected"
                );
            }
            UpstreamSelection {
                lb_hash_key: Some(hash_key),
                target: Some(selection.target),
                is_fallback: selection.is_fallback,
                sticky_cookie_needed: needs_set,
            }
        }
        None => {
            warn!(proxy_id = %proxy.id, upstream_id = %upstream_id, "No upstream target available");
            UpstreamSelection {
                lb_hash_key: Some(hash_key),
                target: None,
                is_fallback: false,
                sticky_cookie_needed: false,
            }
        }
    }
}

/// Check whether the circuit breaker allows this request to proceed.
///
/// Returns `Ok(cb_target_key)` when the request is allowed, or `Err(())` when
/// the circuit is open and the request should be rejected with 503.
pub(crate) fn check_circuit_breaker(
    proxy: &Proxy,
    state: &ProxyState,
    upstream_target: Option<&UpstreamTarget>,
) -> Result<Option<String>, ()> {
    let cb_target_key =
        upstream_target.map(|t| crate::circuit_breaker::target_key(&t.host, t.port));

    if let Some(cb_config) = &proxy.circuit_breaker
        && state
            .circuit_breaker_cache
            .can_execute(&proxy.id, cb_target_key.as_deref(), cb_config)
            .is_err()
    {
        warn!(proxy_id = %proxy.id, "Request rejected: circuit breaker open");
        return Err(());
    }

    Ok(cb_target_key)
}

/// Record the outcome of a backend request across all observability systems:
/// - Circuit breaker (success/failure)
/// - Passive health checks
/// - Least-latency load balancer (backend TTFB)
/// - Least-connections load balancer (connection end)
pub(crate) fn record_backend_outcome(
    state: &ProxyState,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    final_cb_target_key: Option<&str>,
    response_status: u16,
    connection_error: bool,
    backend_elapsed: Duration,
) {
    // End connection tracking for least-connections
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, upstream_target) {
        state
            .load_balancer_cache
            .record_connection_end(upstream_id, target);
    }

    // Record backend TTFB for least-latency load balancing (passive path).
    // Only record when:
    //   1. No connection error (timeouts/refused don't reflect real latency)
    //   2. Response is non-5xx (error responses may have artificially low latency
    //      from fast-failing backends, which would skew the EWMA toward broken targets)
    //   3. No active health checks configured for this upstream — when active probes
    //      exist, they provide consistent, controlled RTT measurements and take
    //      precedence over passive TTFB which includes variable application processing time
    if !connection_error
        && response_status < 500
        && let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, upstream_target)
    {
        let upstream = state.load_balancer_cache.get_upstream(upstream_id);
        let has_active_hc = upstream
            .as_ref()
            .and_then(|u| u.health_checks.as_ref())
            .and_then(|hc| hc.active.as_ref())
            .is_some();
        if !has_active_hc {
            let latency_us = backend_elapsed.as_micros() as u64;
            state
                .load_balancer_cache
                .record_latency(upstream_id, target, latency_us);
        }
    }

    // Record circuit breaker result against the final target's breaker.
    // For retries, intermediate failures were already recorded per-target inside
    // the retry loop, so this only records the final attempt's outcome.
    if let Some(cb_config) = &proxy.circuit_breaker {
        let cb =
            state
                .circuit_breaker_cache
                .get_or_create(&proxy.id, final_cb_target_key, cb_config);
        if connection_error {
            // Connection errors are controlled by trip_on_connection_errors.
            // When disabled, connection errors are neutral — no state mutation.
            if cb.config().trip_on_connection_errors {
                cb.record_failure(response_status, true);
            }
        } else if cb.config().failure_status_codes.contains(&response_status) {
            cb.record_failure(response_status, false);
        } else {
            cb.record_success();
        }
    }

    // Passive health check reporting (O(1) upstream lookup via index)
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, upstream_target)
        && let Some(upstream) = state.load_balancer_cache.get_upstream(upstream_id)
        && let Some(hc) = &upstream.health_checks
    {
        state.health_checker.report_response(
            &proxy.id,
            target,
            response_status,
            connection_error,
            hc.passive.as_ref(),
        );
    }
}

/// Resolve the hash key for consistent-hashing or sticky-session load balancing.
pub(crate) fn resolve_hash_key(
    strategy: &HashOnStrategy,
    client_ip: &str,
    headers: &HashMap<String, String>,
) -> (String, bool) {
    match strategy {
        HashOnStrategy::Ip => (client_ip.to_owned(), false),
        HashOnStrategy::Header(name) => {
            // Header names in ctx.headers are stored as-is from hyper (lowercased)
            let value = headers.get(name.as_str()).cloned().unwrap_or_default();
            if value.is_empty() {
                (client_ip.to_owned(), false)
            } else {
                (value, false)
            }
        }
        HashOnStrategy::Cookie(name) => {
            // Parse the Cookie header to find the named cookie
            if let Some(cookie_header) = headers.get("cookie") {
                for part in cookie_header.split(';') {
                    let part = part.trim();
                    if let Some((k, v)) = part.split_once('=')
                        && k.trim() == name.as_str()
                    {
                        let v = v.trim();
                        if !v.is_empty() {
                            return (v.to_string(), false);
                        }
                    }
                }
            }
            // Cookie not found — use IP and signal that we need to set the cookie
            (client_ip.to_owned(), true)
        }
    }
}
