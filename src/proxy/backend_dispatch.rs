//! Shared backend dispatch helpers used by both the main HTTP/1.1+HTTP/2 proxy
//! path (`proxy/mod.rs`) and the HTTP/3 frontend (`http3/server.rs`).
//!
//! These functions encapsulate upstream target selection, circuit breaker checks,
//! post-request outcome recording (CB, passive health, latency), and runtime
//! HTTP-flavor detection. Extracting them prevents logic drift between the
//! two frontend paths.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::Request;
use tracing::{debug, warn};

use crate::config::types::{
    HttpFlavor, LoadBalancerAlgorithm, PassiveHealthCheck, Proxy, Upstream, UpstreamTarget,
};
use crate::health_check::HealthChecker;
use crate::load_balancer::{
    HashOnStrategy, HealthContext, LoadBalancer, LoadBalancerCache, LoadBalancerCacheInner,
};
use crate::plugins::{
    BackendAdmissionContext, BackendAdmissionDecision, BackendAdmissionPermit,
    BackendAdmissionPermitSet, Plugin, ProxyProtocol, RequestContext,
};
use crate::proxy::ProxyState;
use crate::proxy::is_valid_websocket_key;
use crate::request_epoch::RequestEpoch;
use crate::retry::ErrorClass;

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
        && is_native_grpc_content_type(ct.as_bytes())
    {
        return HttpFlavor::Grpc;
    }

    HttpFlavor::Plain
}

/// Classify a `content-type` value as native gRPC: `application/grpc`
/// optionally followed by a `+`/`;` parameter or OWS (optional whitespace).
/// Case-insensitive on the prefix; operates on raw bytes (no UTF-8 validation).
///
/// This is the canonical classifier for the H1/H2/H3 dispatch path and the
/// early-reject path (`is_grpc_request` / `request_uses_grpc_content_type`).
/// Plugin-local helpers in `body_validator` and `workload_metrics` use simpler
/// prefix forms suited to their own contexts and are not governed by this
/// function.
///
/// Accepted suffixes after `application/grpc`:
/// - nothing (bare `application/grpc`)
/// - `+<subtype>` (e.g. `application/grpc+proto`)
/// - `;` or OWS then `;` (e.g. `application/grpc ;charset=utf-8`)
/// - OWS at end-of-value (e.g. `application/grpc ` or `application/grpc\t`)
///
/// Rejected: `-` or alphanumeric next byte (e.g. `application/grpc-web`,
/// `application/grpcfoo`).
#[inline]
pub(crate) fn is_native_grpc_content_type(value: &[u8]) -> bool {
    const PREFIX: &[u8] = b"application/grpc";
    let Some(prefix) = value.get(..PREFIX.len()) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case(PREFIX) {
        return false;
    }

    match value.get(PREFIX.len()) {
        None => true,
        Some(b'+') | Some(b';') => true,
        Some(b' ' | b'\t') => {
            // Skip OWS run; accept if we reach end-of-value or a ';'.
            let after_prefix = &value[PREFIX.len()..];
            let non_ows = after_prefix
                .iter()
                .copied()
                .find(|b| !matches!(b, b' ' | b'\t'));
            matches!(non_ows, None | Some(b';'))
        }
        _ => false,
    }
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
        && (req
            .extensions()
            .get::<hyper::ext::Protocol>()
            .is_some_and(|p| p.as_ref().eq_ignore_ascii_case(b"websocket"))
            || req
                .extensions()
                .get::<h3::ext::Protocol>()
                .is_some_and(|p| p.as_str().eq_ignore_ascii_case("websocket")))
}

/// HTTP/1.1 WebSocket upgrade check. Accepts only well-formed RFC 6455
/// handshakes: `Connection: Upgrade`, `Upgrade: websocket`, a base64-encoded
/// 16-byte `Sec-WebSocket-Key`, and `Sec-WebSocket-Version: 13`.
#[inline]
fn is_http1_websocket_upgrade<B>(req: &Request<B>) -> bool {
    if req.version() != hyper::Version::HTTP_11 {
        return false;
    }

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
    /// Exact LB object used for selection, for same-generation accounting.
    pub balancer: Option<Arc<crate::load_balancer::LoadBalancer>>,
    /// `true` when all targets were unhealthy and the selection fell back to the
    /// least-unhealthy target.
    pub is_fallback: bool,
    /// `true` when a sticky session cookie needs to be set on the response.
    pub sticky_cookie_needed: bool,
}

/// Whether a direct HTTP-family dial would bypass a target's required mesh
/// transport.
///
/// Same-cluster plain HTTP can ride HBONE or mesh-mTLS only through the mesh
/// dispatch paths. Cross-cluster mesh targets additionally require east-west
/// SNI/trust-domain handling, so a direct dial is invalid even if the transport
/// tag is malformed or missing.
pub(crate) fn direct_http_mesh_transport_refusal(
    target: Option<&UpstreamTarget>,
) -> Option<&'static str> {
    let target = target?;
    let hbone = crate::proxy::hbone_pool::target_hbone_enabled(target);
    let mesh_mtls = crate::proxy::mesh_mtls_pool::target_mesh_mtls_enabled(target);
    let cross_cluster = crate::proxy::hbone_pool::target_hbone_cross_cluster(target)
        || crate::proxy::mesh_mtls_pool::target_mesh_mtls_cross_cluster(target);

    if cross_cluster {
        Some("cross-cluster mesh transport dispatch required for this backend target")
    } else if hbone {
        Some("HBONE dispatch required for this backend target")
    } else if mesh_mtls {
        Some("Sidecar mTLS dispatch required for this backend target")
    } else {
        None
    }
}

/// Select an upstream target for the given proxy using load balancing with
/// health-aware filtering.
///
/// When the effective upstream id (after plugin overrides) is `None`,
/// returns a no-op selection with `lb_hash_key: None` — the key is never
/// read without an upstream.
///
pub(crate) fn select_upstream_target(
    proxy: &Proxy,
    state: &ProxyState,
    epoch: &RequestEpoch,
    client_ip: &str,
    proxy_headers: &HashMap<String, String>,
    orig_dst: Option<SocketAddr>,
) -> UpstreamSelection {
    let Some(upstream_id) = proxy.upstream_id.as_deref() else {
        return UpstreamSelection {
            lb_hash_key: None,
            target: None,
            balancer: None,
            is_fallback: false,
            sticky_cookie_needed: false,
        };
    };

    let balancers = &epoch.load_balancer;

    // Resolve the ejection cap with the SAME precedence the passive-health
    // thresholds use in `passive_health_for_target` (per-port > per-subset >
    // upstream) so the cap and the thresholds are always drawn from one tier.
    let dispatch_port = initial_dispatch_port(
        proxy,
        LoadBalancerCache::initial_dispatch_port_override_from(
            balancers,
            &proxy.namespace,
            upstream_id,
        ),
    );
    let has_port_override =
        has_effective_port_override(proxy, balancers, upstream_id, dispatch_port);
    let port_scope = has_port_override.then_some(dispatch_port);
    let health_ctx = health_context_for_selection(
        proxy,
        &state.health_checker,
        balancers,
        upstream_id,
        port_scope,
    );

    let subset_name = proxy.upstream_subset.as_deref();
    let strategy = LoadBalancerCache::get_hash_on_strategy_for_selection_from(
        balancers,
        &proxy.namespace,
        upstream_id,
        port_scope,
        subset_name,
    );
    let (hash_key, needs_set) = resolve_hash_key(&strategy, client_ip, proxy_headers);

    let selected_balancer = balancers.get_balancer(&proxy.namespace, upstream_id);

    // PASSTHROUGH (Istio `loadBalancer.simple=PASSTHROUGH`): when this upstream's
    // effective algorithm is Passthrough, dial the captured original destination
    // if it matches a healthy target in the (subset∩port-scoped) candidate pool,
    // bypassing load balancing. Absent or unmatched orig-dst falls through to the
    // normal selection below, which treats Passthrough as round-robin.
    if LoadBalancerCache::effective_algorithm_from(
        balancers,
        &proxy.namespace,
        upstream_id,
        port_scope,
        subset_name,
    ) == Some(LoadBalancerAlgorithm::Passthrough)
    {
        match orig_dst {
            Some(dst) => {
                if let Some(target) = LoadBalancerCache::select_passthrough_from(
                    balancers,
                    &proxy.namespace,
                    upstream_id,
                    dst,
                    port_scope,
                    subset_name,
                    Some(&health_ctx),
                ) {
                    debug!(
                        proxy_id = %proxy.id,
                        upstream_id = %upstream_id,
                        target_host = %target.host,
                        target_port = target.port,
                        orig_dst = %dst,
                        "PASSTHROUGH: dialing captured original destination"
                    );
                    return UpstreamSelection {
                        lb_hash_key: Some(hash_key),
                        target: Some(target),
                        balancer: selected_balancer,
                        is_fallback: false,
                        sticky_cookie_needed: needs_set,
                    };
                }
                warn!(
                    proxy_id = %proxy.id,
                    upstream_id = %upstream_id,
                    orig_dst = %dst,
                    "PASSTHROUGH: original destination unmatched, falling back to round-robin"
                );
            }
            None => {
                warn!(
                    proxy_id = %proxy.id,
                    upstream_id = %upstream_id,
                    "PASSTHROUGH: original destination absent, falling back to round-robin"
                );
            }
        }
    }

    // Use subset routing when the proxy specifies an upstream_subset.
    let selection_result = if let Some(ref subset_name) = proxy.upstream_subset {
        if has_port_override {
            LoadBalancerCache::select_target_for_port_subset_from(
                balancers,
                &proxy.namespace,
                upstream_id,
                &hash_key,
                dispatch_port,
                subset_name,
                Some(&health_ctx),
            )
        } else {
            LoadBalancerCache::select_target_subset_from(
                balancers,
                &proxy.namespace,
                upstream_id,
                &hash_key,
                subset_name,
                Some(&health_ctx),
            )
        }
    } else if has_port_override {
        LoadBalancerCache::select_target_for_port_from(
            balancers,
            &proxy.namespace,
            upstream_id,
            &hash_key,
            dispatch_port,
            Some(&health_ctx),
        )
    } else {
        LoadBalancerCache::select_target_from(
            balancers,
            &proxy.namespace,
            upstream_id,
            &hash_key,
            Some(&health_ctx),
        )
    };

    match selection_result {
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
            // Recompute sticky-cookie decision when the selected target's
            // port differs from the initial dispatch port — the target may
            // have landed in a port override lane with a different hash_on
            // strategy.
            let selected_policy_port = selection.target.dispatch_policy_port();
            let needs_set = if selected_policy_port != dispatch_port {
                let tp = selected_policy_port;
                let tp_override = has_effective_port_override(proxy, balancers, upstream_id, tp);
                let tp_strategy = LoadBalancerCache::get_hash_on_strategy_for_selection_from(
                    balancers,
                    &proxy.namespace,
                    upstream_id,
                    tp_override.then_some(tp),
                    subset_name,
                );
                resolve_hash_key(&tp_strategy, client_ip, proxy_headers).1
            } else {
                needs_set
            };
            UpstreamSelection {
                lb_hash_key: Some(hash_key),
                target: Some(selection.target),
                balancer: selected_balancer,
                is_fallback: selection.is_fallback,
                sticky_cookie_needed: needs_set,
            }
        }
        None => {
            warn!(proxy_id = %proxy.id, upstream_id = %upstream_id, "No upstream target available");
            UpstreamSelection {
                lb_hash_key: Some(hash_key),
                target: None,
                balancer: None,
                is_fallback: false,
                sticky_cookie_needed: false,
            }
        }
    }
}

#[inline]
pub(crate) fn initial_dispatch_port(proxy: &Proxy, upstream_port_override: u16) -> u16 {
    if upstream_port_override != 0 {
        return upstream_port_override;
    }

    proxy.backend_port
}

#[inline]
pub(crate) fn has_effective_port_override(
    proxy: &Proxy,
    balancers: &LoadBalancerCacheInner,
    upstream_id: &str,
    port: u16,
) -> bool {
    proxy
        .dispatch_port_overrides
        .as_ref()
        .is_some_and(|overrides| overrides.contains_key(&port))
        && LoadBalancerCache::has_port_override_state_from(
            balancers,
            &proxy.namespace,
            upstream_id,
            port,
        )
}

#[inline]
pub(crate) fn stream_health_port_scope(
    proxy: &Proxy,
    balancers: &LoadBalancerCacheInner,
    upstream_id: &str,
    dispatch_port: u16,
) -> Option<u16> {
    (dispatch_port != 0
        && has_effective_port_override(proxy, balancers, upstream_id, dispatch_port))
    .then_some(dispatch_port)
}

pub(crate) fn health_context_for_selection<'a>(
    proxy: &Proxy,
    health_checker: &'a HealthChecker,
    balancers: &LoadBalancerCacheInner,
    upstream_id: &str,
    port_scope: Option<u16>,
) -> HealthContext<'a> {
    let proxy_passive = health_checker.passive_state(&proxy.namespace, &proxy.id);
    let max_ejection_percent = LoadBalancerCache::max_ejection_percent_resolved_from(
        balancers,
        &proxy.namespace,
        upstream_id,
        proxy,
        port_scope,
    );

    HealthContext {
        active_unhealthy: &health_checker.active_unhealthy_targets,
        proxy_passive,
        max_ejection_percent,
    }
}

#[inline]
pub(crate) fn hash_on_strategy_for_selected_target(
    proxy: &Proxy,
    balancers: &LoadBalancerCacheInner,
    upstream_id: &str,
    target: &UpstreamTarget,
) -> HashOnStrategy {
    let target_port = target.dispatch_policy_port();
    let port_scope = has_effective_port_override(proxy, balancers, upstream_id, target_port)
        .then_some(target_port);
    LoadBalancerCache::get_hash_on_strategy_for_selection_from(
        balancers,
        &proxy.namespace,
        upstream_id,
        port_scope,
        proxy.upstream_subset.as_deref(),
    )
}

/// Replace a wildcard upstream target host (for example `*.example.com`) with
/// the concrete request authority that matched the route. This is used by mesh
/// egress wildcard ServiceEntries with DNS/None resolution: the proxy route is
/// wildcard-hosted, but the backend dial target must be the concrete authority.
pub(crate) fn concretize_wildcard_target_for_request(
    target: Option<Arc<UpstreamTarget>>,
    request_host: Option<&str>,
) -> Option<Arc<UpstreamTarget>> {
    let target = target?;
    let Some(request_host) = request_host else {
        return Some(target);
    };
    if !target.host.starts_with("*.")
        || !crate::config::types::wildcard_matches(&target.host, request_host)
    {
        return Some(target);
    }

    let mut concrete = target.as_ref().clone();
    concrete.host = request_host.to_string();
    Some(Arc::new(concrete))
}

/// Check whether the circuit breaker allows this request to proceed.
///
/// Returns `Ok((cb_target_key, is_half_open_probe))` when the request is allowed,
/// or `Err(())` when the circuit is open and the request should be rejected with 503.
/// The `is_half_open_probe` flag MUST be threaded into every subsequent
/// `record_success` / `record_failure` call so the half-open in-flight counter
/// is only decremented for requests that actually hold a probe slot.
pub(crate) fn check_circuit_breaker(
    proxy: &Proxy,
    state: &ProxyState,
    upstream_target: Option<&UpstreamTarget>,
) -> Result<(Option<String>, bool, u64), ()> {
    let cb_target_key = circuit_breaker_target_key(proxy, upstream_target);

    if let Some(cb_config) = &proxy.circuit_breaker {
        // Capture the open generation at admission so a deferred streaming outcome
        // can detect that the breaker has since opened a new cycle (#1649 round-4 B)
        // and avoid healing/reopening a HALF_OPEN cycle it never probed. The epoch
        // is snapshotted BEFORE the admission decision (inside
        // `can_execute_with_admission_epoch`) so a concurrent open racing this
        // admission can only make the outcome look stale, never too-new (#1649 R6
        // finding 3).
        match state
            .circuit_breaker_cache
            .can_execute_with_admission_epoch(
                &proxy.namespace,
                &proxy.id,
                cb_target_key.as_deref(),
                cb_config,
            ) {
            Ok((_cb, is_half_open_probe, admission_open_epoch)) => {
                return Ok((cb_target_key, is_half_open_probe, admission_open_epoch));
            }
            Err(_) => {
                warn!(proxy_id = %proxy.id, "Request rejected: circuit breaker open");
                return Err(());
            }
        }
    }

    Ok((cb_target_key, false, 0))
}

fn circuit_breaker_target_key(
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
) -> Option<String> {
    upstream_target
        .map(|t| crate::circuit_breaker::target_key(&t.host, t.port))
        .or_else(|| {
            (proxy.upstream_id.is_none()
                && !proxy.backend_host.is_empty()
                && proxy.backend_port != 0)
                .then(|| {
                    crate::circuit_breaker::target_key(&proxy.backend_host, proxy.backend_port)
                })
        })
}

pub(crate) struct BackendAdmissionRejection {
    pub(crate) plugin_name: String,
    pub(crate) status_code: u16,
    pub(crate) body: Vec<u8>,
    pub(crate) headers: HashMap<String, String>,
}

pub(crate) fn run_backend_admission_plugins(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    protocol: ProxyProtocol,
) -> Result<Option<BackendAdmissionPermitSet>, BackendAdmissionRejection> {
    if plugins.is_empty() {
        return Ok(None);
    }

    let admission = BackendAdmissionContext {
        proxy,
        upstream_target,
        protocol,
    };
    let mut permits: Vec<Arc<dyn BackendAdmissionPermit>> = Vec::new();
    for plugin in plugins {
        match plugin.try_backend_admission(ctx, &admission) {
            BackendAdmissionDecision::Continue => {}
            BackendAdmissionDecision::Admit(permit) => permits.push(permit),
            BackendAdmissionDecision::Reject {
                status_code,
                body,
                headers,
            } => {
                return Err(BackendAdmissionRejection {
                    plugin_name: plugin.name().to_string(),
                    status_code,
                    body,
                    headers,
                });
            }
        }
    }

    Ok(BackendAdmissionPermitSet::new(permits))
}

/// Record the outcome of a backend request across all observability systems:
/// - Circuit breaker (success/failure)
/// - Passive health checks
/// - Least-latency load balancer (backend TTFB)
/// - Least-connections load balancer (connection end)
///
/// Route-override plugins must pass the shadowed effective proxy so passive
/// health and least-latency reporting attribute to the upstream that was
/// actually dispatched to.
///
/// Client-side outcomes that never reached a backend (client disconnects and
/// gateway request-body-limit rejects) are handled centrally: they carry no
/// signal about backend health, so they route the circuit breaker to
/// `record_neutral` AND skip the least-latency sample and passive-health report
/// entirely. Callers that detect these outcomes can therefore set
/// `connection_error` to whatever is most accurate for their path without
/// worrying about poisoning backend health — the neutral arm suppresses
/// latency/passive regardless, and is evaluated before `connection_error` for
/// the breaker.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_backend_outcome(
    state: &ProxyState,
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    selected_balancer: Option<&Arc<LoadBalancer>>,
    upstream_target: Option<&UpstreamTarget>,
    final_cb_target_key: Option<&str>,
    response_status: u16,
    connection_error: bool,
    error_class: Option<ErrorClass>,
    is_half_open_probe: bool,
    skip_circuit_breaker_record: bool,
    backend_elapsed: Duration,
) {
    record_backend_outcome_inner(
        state,
        proxy,
        lb_snapshot,
        selected_balancer,
        upstream_target,
        final_cb_target_key,
        response_status,
        connection_error,
        error_class,
        is_half_open_probe,
        skip_circuit_breaker_record,
        backend_elapsed,
        true,
    );
}

/// Like [`record_backend_outcome`] but records everything EXCEPT ending
/// least-connections connection tracking.
///
/// Use on dispatch paths where a `LoadBalancerConnectionGuard` already owns the
/// connection-end (so it is correctly deferred until a streaming response body
/// completes), or where the path never issued a matching
/// `record_connection_start`. This prevents the double-decrement that occurs
/// when both a guard and this function end the same connection — which silently
/// undercounts active connections and biases least-connections balancing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_backend_outcome_no_conn_end(
    state: &ProxyState,
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    selected_balancer: Option<&Arc<LoadBalancer>>,
    upstream_target: Option<&UpstreamTarget>,
    final_cb_target_key: Option<&str>,
    response_status: u16,
    connection_error: bool,
    error_class: Option<ErrorClass>,
    is_half_open_probe: bool,
    skip_circuit_breaker_record: bool,
    backend_elapsed: Duration,
) {
    record_backend_outcome_inner(
        state,
        proxy,
        lb_snapshot,
        selected_balancer,
        upstream_target,
        final_cb_target_key,
        response_status,
        connection_error,
        error_class,
        is_half_open_probe,
        skip_circuit_breaker_record,
        backend_elapsed,
        false,
    );
}

/// Whether an outcome's `error_class` carries NO signal about backend health,
/// so circuit-breaker / passive-health / least-latency / adaptive-concurrency
/// accounting must treat it as neutral (no failure ding, no permit shrink, no
/// latency sample):
///
/// * `ClientDisconnect` / `RequestBodyTooLarge` — client/gateway-side terminals;
///   the client gave up or over-sent, which says nothing about the backend.
/// * `DispatchPolicyRejected` — a gateway-side dispatch-policy shed BEFORE the
///   backend was dialed (backend-TLS-SNI reject, or the
///   `http1MaxPendingRequests` in-flight-overflow 503). The request never
///   reached the backend, so the synthetic 503 must not trip the backend's
///   circuit breaker / passive health, nor shrink its adaptive-concurrency
///   permit — those would penalize a backend that was never contacted and let
///   an overflow burst falsely eject a healthy target. Without this, default
///   CB/AC failure classification (which counts 503) would do exactly that.
#[inline]
pub(crate) fn client_side_no_backend_signal(error_class: Option<ErrorClass>) -> bool {
    matches!(
        error_class,
        Some(
            ErrorClass::ClientDisconnect
                | ErrorClass::RequestBodyTooLarge
                | ErrorClass::DispatchPolicyRejected
        )
    )
}

/// Whether a deferred streaming outcome admitted at `admission_open_epoch` is now
/// stale for the breaker's current cycle: the breaker has opened a new generation
/// since admission, so this completion must NOT heal/reopen a HALF_OPEN cycle it
/// never probed (#1649 R4-B). Returns `false` when the proxy has no breaker
/// configured (nothing to stale-check). Shared by the body-deferred path
/// (`record_deferred_backend_dispatch`) and the synchronous after_proxy-reject
/// fallbacks (direct-H2 + buffered-gRPC) so the epoch check has a single source of
/// truth.
pub(crate) fn deferred_circuit_breaker_is_stale(
    state: &ProxyState,
    proxy: &Proxy,
    final_cb_target_key: Option<&str>,
    admission_open_epoch: u64,
) -> bool {
    let Some(cfg) = proxy.circuit_breaker.as_ref() else {
        return false;
    };
    // Inspect the CURRENT cached breaker read-only (#1649 R8): `get_or_create`
    // with this request's captured `proxy`/`cfg` would, after a config reload that
    // replaced the breaker, treat the old config as a change and write a stale
    // (old-config) breaker back into the live cache. `peek` never mutates.
    match state
        .circuit_breaker_cache
        .peek(&proxy.namespace, &proxy.id, final_cb_target_key)
    {
        // Same config still cached: stale iff a new open generation has begun since
        // admission.
        Some(cb) if cb.config() == cfg => cb.open_epoch() != admission_open_epoch,
        // Breaker evicted, or replaced by a reloaded config: the cycle this stream
        // was admitted under is gone, so the deferred outcome is stale — drop it
        // rather than record against (or resurrect) a bygone breaker.
        _ => true,
    }
}

/// A post-wire backend failure: the request reached the backend's application
/// layer (response headers already arrived) and then the response stalled, the
/// transport broke, or the backend over-sent before the body/trailers completed.
///
/// These classes are NOT connection errors — the request went on the wire, so
/// `connection_error` stays false and connect-failure retry replay must respect
/// method idempotency — but they ARE backend-health failures that the circuit
/// breaker / passive health / least-latency accounting AND the adaptive
/// concurrency limiter (`AdaptiveConcurrencyPermit::record`) must count. Without
/// this, a backend that returns `200` headers and then times out / RSTs
/// mid-stream (or floods past the response-size cap) is recorded as healthy
/// because neither `connection_error` nor a 5xx status is set (see the streaming
/// `IdleReadTimeoutBody` / native-H3 read-timeout paths and
/// `record_deferred_backend_admission`).
///
/// `ResponseBodyTooLarge` IS included: an oversized backend response is a backend
/// fault (the existing limiter contract), even though the gateway is the one that
/// cuts it. `ClientDisconnect` / `RequestBodyTooLarge` are excluded — they are
/// client/gateway-side and already neutralized by `client_side_no_backend_signal`;
/// `GracefulRemoteClose` is a clean close.
#[inline]
pub(crate) fn error_class_is_post_wire_backend_failure(error_class: Option<ErrorClass>) -> bool {
    matches!(
        error_class,
        Some(
            ErrorClass::ReadWriteTimeout
                | ErrorClass::ConnectionReset
                | ErrorClass::ConnectionClosed
                | ErrorClass::ProtocolError
                | ErrorClass::ResponseBodyTooLarge
        )
    )
}

/// Classify a backend outcome and apply it to `cb`. This is the circuit-breaker
/// arm of [`record_backend_outcome_inner`], extracted so the gRPC streaming probe
/// recorder can settle the breaker at the upload-termination / response-completion
/// join (#1649 item 3) using the identical classification rules:
///   * client-side (disconnect / request-body-too-large) → NEUTRAL,
///   * pre-wire connection error → connection-level failure (gated by
///     `trip_on_connection_errors`),
///   * configured `failure_status_codes` → status failure (ungated),
///   * post-wire backend failure (mid-stream timeout / reset) → connection-level
///     failure even with a healthy status,
///   * otherwise → success.
pub(crate) fn apply_circuit_breaker_outcome(
    cb: &crate::circuit_breaker::CircuitBreaker,
    response_status: u16,
    connection_error: bool,
    error_class: Option<ErrorClass>,
    is_half_open_probe: bool,
) {
    if client_side_no_backend_signal(error_class) {
        cb.record_neutral(is_half_open_probe);
    } else if connection_error {
        cb.record_failure(response_status, true, is_half_open_probe);
    } else if cb.config().failure_status_codes.contains(&response_status) {
        cb.record_failure(response_status, false, is_half_open_probe);
    } else if error_class_is_post_wire_backend_failure(error_class) {
        cb.record_failure(response_status, true, is_half_open_probe);
    } else {
        cb.record_success(is_half_open_probe);
    }
}

/// Like [`apply_circuit_breaker_outcome`], but for a DEFERRED streaming outcome:
/// if the breaker has advanced to a new open generation since this request was
/// admitted (`cb.open_epoch() != admission_open_epoch`), the completion is stale
/// for the current cycle — a stream admitted while the breaker was CLOSED must
/// not heal/reopen a later HALF_OPEN cycle it never probed (#1649 round-4 B). In
/// that case record NEUTRAL (release any slot, no health change); otherwise apply
/// the outcome normally.
pub(crate) fn apply_deferred_circuit_breaker_outcome(
    cb: &crate::circuit_breaker::CircuitBreaker,
    response_status: u16,
    connection_error: bool,
    error_class: Option<ErrorClass>,
    is_half_open_probe: bool,
    admission_open_epoch: u64,
) {
    if cb.open_epoch() != admission_open_epoch {
        cb.record_neutral(is_half_open_probe);
        return;
    }
    apply_circuit_breaker_outcome(
        cb,
        response_status,
        connection_error,
        error_class,
        is_half_open_probe,
    );
}

/// Whether [`apply_circuit_breaker_outcome`] would record a backend FAILURE (as
/// opposed to a success or a client-side neutral). Lets the gRPC streaming probe
/// recorder record failures promptly at response completion while deferring a
/// clean SUCCESS until request-upload termination, so a late client-upload
/// overflow cannot falsely heal the breaker.
pub(crate) fn circuit_breaker_outcome_is_failure(
    failure_status_codes: &[u16],
    response_status: u16,
    connection_error: bool,
    error_class: Option<ErrorClass>,
) -> bool {
    if client_side_no_backend_signal(error_class) {
        false
    } else {
        connection_error
            || failure_status_codes.contains(&response_status)
            || error_class_is_post_wire_backend_failure(error_class)
    }
}

#[allow(clippy::too_many_arguments)]
fn record_backend_outcome_inner(
    state: &ProxyState,
    proxy: &Proxy,
    lb_snapshot: &LoadBalancerCacheInner,
    selected_balancer: Option<&Arc<LoadBalancer>>,
    upstream_target: Option<&UpstreamTarget>,
    final_cb_target_key: Option<&str>,
    response_status: u16,
    connection_error: bool,
    error_class: Option<ErrorClass>,
    is_half_open_probe: bool,
    skip_circuit_breaker_record: bool,
    backend_elapsed: Duration,
    end_connection: bool,
) {
    // End connection tracking for least-connections. Skipped when a
    // LoadBalancerConnectionGuard owns the end, or when no start was issued.
    if end_connection && let (Some(target), Some(balancer)) = (upstream_target, selected_balancer) {
        balancer.record_connection_end(target);
    }

    // Record backend TTFB for least-latency load balancing (passive path).
    // Only record when:
    //   1. The outcome is not a client-caused disconnect. A client that gave up
    //      before (or mid-) request tells us nothing about backend latency, so a
    //      synthetic status (e.g. a 413 we emitted) must not feed the EWMA.
    //   2. No connection error (timeouts/refused don't reflect real latency)
    //   3. Response is non-5xx (error responses may have artificially low latency
    //      from fast-failing backends, which would skew the EWMA toward broken targets)
    //   4. No active health checks configured for this upstream — when active probes
    //      exist, they provide consistent, controlled RTT measurements and take
    //      precedence over passive TTFB which includes variable application processing time
    let client_side_no_backend_signal = client_side_no_backend_signal(error_class);
    // A post-wire backend failure (a streaming `ReadWriteTimeout`, or a
    // mid-response reset/close) is NOT a `connection_error` — the request
    // reached the wire — but it must still count as a backend-health failure.
    // Fold it into the failure signal used for latency / circuit-breaker /
    // passive-health accounting below, WITHOUT touching `connection_error`
    // itself (which gates connect-failure retry replay).
    let backend_failure = connection_error || error_class_is_post_wire_backend_failure(error_class);

    if !client_side_no_backend_signal
        && let (Some(upstream_id), Some(target)) = (proxy.upstream_id.as_deref(), upstream_target)
    {
        let upstream =
            LoadBalancerCache::get_upstream_from(lb_snapshot, &proxy.namespace, upstream_id);
        let has_active_hc = upstream
            .as_ref()
            .and_then(|u| u.health_checks.as_ref())
            .and_then(|hc| hc.active.as_ref())
            .is_some();
        if !has_active_hc && let Some(balancer) = selected_balancer {
            if backend_failure || response_status >= 500 {
                // Failed attempts count toward warm-up exit with a penalty EWMA
                // so a persistently failing target cannot remain biased-best.
                balancer.record_failed_attempt(target);
            } else if response_status < 500 {
                let latency_us = backend_elapsed.as_micros() as u64;
                balancer.record_latency(target, latency_us);
            }
        }
    }

    // Record circuit breaker result against the final target's breaker.
    // For retries, intermediate failures were already recorded per-target inside
    // the retry loop, so this only records the final attempt's outcome.
    if !skip_circuit_breaker_record && let Some(cb_config) = &proxy.circuit_breaker {
        let cb = state.circuit_breaker_cache.get_or_create(
            &proxy.namespace,
            &proxy.id,
            final_cb_target_key,
            cb_config,
        );
        apply_circuit_breaker_outcome(
            &cb,
            response_status,
            connection_error,
            error_class,
            is_half_open_probe,
        );
    }

    // Passive health check reporting (O(1) upstream lookup via index).
    //
    // Skip entirely for client-caused disconnects: the client gave up before (or
    // mid-) request, so the outcome carries no signal about backend health. The
    // synthetic status we emit (e.g. a 413 on an oversized upload, or a 502 when
    // the client aborts the upload) must touch neither a phantom <500 success
    // that would reset failure tracking and re-admit an unhealthy target, nor a
    // failure when that status happens to be in `unhealthy_status_codes`. The
    // sibling H3 oversized/abort paths rely on this so their "must not poison
    // backend passive health" comments hold.
    if !client_side_no_backend_signal
        && let (Some(upstream_id), Some(target)) = (proxy.upstream_id.as_deref(), upstream_target)
        && let Some(upstream) =
            LoadBalancerCache::get_upstream_from(lb_snapshot, &proxy.namespace, upstream_id)
    {
        let passive = passive_health_for_target(proxy, &upstream, target);
        state.health_checker.report_response(
            &proxy.namespace,
            &proxy.id,
            upstream_id,
            target,
            response_status,
            backend_failure,
            passive,
        );
    }
}

pub(crate) fn passive_health_for_target<'a>(
    proxy: &'a Proxy,
    upstream: &'a Upstream,
    target: &UpstreamTarget,
) -> Option<&'a PassiveHealthCheck> {
    // Precedence: per-port override (portLevelSettings[].outlierDetection) >
    // per-subset (subsets[].trafficPolicy.outlierDetection) > upstream-level.
    proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&target.dispatch_policy_port()))
        .and_then(|override_config| override_config.passive_health_check.as_ref())
        .or_else(|| {
            // Subset-bound proxy: prefer the subset's resolved passive-health
            // overlay over the upstream-level one. The maxEjectionPercent cap is
            // resolved with this SAME precedence by
            // `LoadBalancerCache::max_ejection_percent_resolved_from`, so the cap
            // and these thresholds always come from the same tier.
            proxy
                .upstream_subset
                .as_deref()
                .and_then(|subset| upstream.resolved_subset_tls.get(subset))
                .and_then(|resolved| resolved.passive_health_check.as_ref())
        })
        .or_else(|| {
            upstream
                .health_checks
                .as_ref()
                .and_then(|hc| hc.passive.as_ref())
        })
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

/// Select the next retry target with per-port DestinationRule awareness.
///
/// Six retry sites (HTTP/H2, gRPC, and WebSocket in `src/proxy/mod.rs` plus
/// the three H3 paths in `src/http3/{cross_protocol,server,websocket}.rs`)
/// previously open-coded the same five-step sequence:
///
/// 1. Compute the per-port override port that covers `prev_target` (if any).
/// 2. If the failed target sits in an override lane, recompute the retry hash
///    key from the same effective selection strategy used by initial dispatch
///    (per-port, subset, then upstream) so consistent-hash buckets stay
///    consistent on the retry attempt; otherwise reuse the steady-state
///    `base_hash_key`.
/// 3. Build a `HealthContext` whose `max_ejection_percent` honours the
///    per-port `passive_health_check` override when one is configured.
/// 4. Dispatch to the appropriate `select_next_target_*_from` variant —
///    subset-vs-no-subset crossed with port-vs-no-port (four variants).
/// 5. Hand the next `Arc<UpstreamTarget>` back to the caller, which still
///    owns its own URL building, circuit-breaker key updates, and per-protocol
///    plumbing.
///
/// Drift between the open-coded copies of step 2 is what produced the H3
/// retry hash-key bug fixed in commit `a8d62bd1`. Centralising the sequence
/// here keeps future per-port LB additions from re-introducing that drift.
///
/// # Performance
///
/// Hot-path safe: `epoch.load_balancer` is an already-cloned `Arc` snapshot,
/// `HealthContext` is borrowed, and the only allocation is the optional
/// `String` produced by `resolve_hash_key()` when the override-lane branch
/// fires. Steady-state retries with no port override reuse the borrowed
/// `base_hash_key` with zero allocations.
pub(crate) fn select_next_retry_target(
    state: &ProxyState,
    epoch: &RequestEpoch,
    proxy: &Proxy,
    prev_target: &UpstreamTarget,
    base_hash_key: &str,
    client_ip: &str,
    proxy_headers: &HashMap<String, String>,
) -> Option<Arc<UpstreamTarget>> {
    let upstream_id = proxy.upstream_id.as_deref()?;

    let retry_override_port = crate::proxy::retry_port_override_dispatch_port(proxy, prev_target)
        .filter(|port| {
            LoadBalancerCache::has_port_override_state_from(
                &epoch.load_balancer,
                &proxy.namespace,
                upstream_id,
                *port,
            )
        });

    // Recompute the retry hash key from the same effective strategy used by
    // initial port/subset dispatch. Steady-state retries without a live port
    // lane reuse the borrowed `base_hash_key`, keeping zero-allocation behavior.
    let rehashed;
    let retry_key: &str = if let Some(port) = retry_override_port {
        let strategy = LoadBalancerCache::get_hash_on_strategy_for_selection_from(
            &epoch.load_balancer,
            &proxy.namespace,
            upstream_id,
            Some(port),
            proxy.upstream_subset.as_deref(),
        );
        rehashed = resolve_hash_key(&strategy, client_ip, proxy_headers).0;
        &rehashed
    } else {
        base_hash_key
    };

    let health_ctx = HealthContext {
        active_unhealthy: &state.health_checker.active_unhealthy_targets,
        proxy_passive: state
            .health_checker
            .passive_state(&proxy.namespace, &proxy.id),
        // Same precedence as the steady-state path and `passive_health_for_target`
        // (per-port > per-subset > upstream). `retry_override_port` is already
        // `Some` only when a live per-port override covers the retried target.
        max_ejection_percent: LoadBalancerCache::max_ejection_percent_resolved_from(
            &epoch.load_balancer,
            &proxy.namespace,
            upstream_id,
            proxy,
            retry_override_port,
        ),
    };

    if let Some(subset_name) = proxy.upstream_subset.as_deref() {
        if let Some(port) = retry_override_port {
            LoadBalancerCache::select_next_target_for_port_subset_from(
                &epoch.load_balancer,
                &proxy.namespace,
                upstream_id,
                retry_key,
                port,
                subset_name,
                prev_target,
                Some(&health_ctx),
            )
        } else {
            LoadBalancerCache::select_next_target_subset_from(
                &epoch.load_balancer,
                &proxy.namespace,
                upstream_id,
                retry_key,
                subset_name,
                prev_target,
                Some(&health_ctx),
            )
        }
    } else if let Some(port) = retry_override_port {
        LoadBalancerCache::select_next_target_for_port_from(
            &epoch.load_balancer,
            &proxy.namespace,
            upstream_id,
            retry_key,
            port,
            prev_target,
            Some(&health_ctx),
        )
    } else {
        LoadBalancerCache::select_next_target_from(
            &epoch.load_balancer,
            &proxy.namespace,
            upstream_id,
            retry_key,
            prev_target,
            Some(&health_ctx),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str) -> Arc<UpstreamTarget> {
        Arc::new(UpstreamTarget {
            host: host.to_string(),
            port: 443,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
    }

    fn target_with_tags(tags: &[(&str, &str)]) -> UpstreamTarget {
        UpstreamTarget {
            host: "10.0.0.10".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: tags
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            locality: None,
            path: None,
        }
    }

    #[test]
    fn direct_http_mesh_transport_refusal_detects_mesh_required_targets() {
        assert_eq!(direct_http_mesh_transport_refusal(None), None);
        assert_eq!(
            direct_http_mesh_transport_refusal(Some(&target_with_tags(&[]))),
            None
        );
        assert_eq!(
            direct_http_mesh_transport_refusal(Some(&target_with_tags(&[(
                crate::proxy::hbone_pool::HBONE_TARGET_TAG,
                "true",
            )]))),
            Some("HBONE dispatch required for this backend target")
        );
        assert_eq!(
            direct_http_mesh_transport_refusal(Some(&target_with_tags(&[(
                crate::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG,
                "true",
            )]))),
            Some("Sidecar mTLS dispatch required for this backend target")
        );
        assert_eq!(
            direct_http_mesh_transport_refusal(Some(&target_with_tags(&[(
                crate::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG,
                "true",
            )]))),
            Some("cross-cluster mesh transport dispatch required for this backend target")
        );
    }

    #[test]
    fn direct_http_mesh_transport_refusal_prioritizes_cross_cluster_shape() {
        assert_eq!(
            direct_http_mesh_transport_refusal(Some(&target_with_tags(&[
                (crate::proxy::hbone_pool::HBONE_TARGET_TAG, "true"),
                (crate::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG, "true",),
            ]))),
            Some("cross-cluster mesh transport dispatch required for this backend target")
        );
    }

    #[test]
    fn wildcard_target_uses_concrete_request_host() {
        let concrete = concretize_wildcard_target_for_request(
            Some(target("*.example.com")),
            Some("api.example.com"),
        )
        .expect("target remains");

        assert_eq!(concrete.host, "api.example.com");
        assert_eq!(concrete.port, 443);
    }

    #[test]
    fn wildcard_target_does_not_use_unmatched_request_host() {
        let original = target("*.example.com");
        let concrete =
            concretize_wildcard_target_for_request(Some(original.clone()), Some("example.net"))
                .expect("target remains");

        assert!(Arc::ptr_eq(&original, &concrete));
    }

    #[test]
    fn circuit_breaker_target_key_uses_direct_backend_override() {
        let proxy: Proxy = serde_json::from_value(serde_json::json!({
            "backend_host": "canary.svc",
            "backend_port": 9090,
        }))
        .expect("minimal proxy should deserialize");

        assert_eq!(
            circuit_breaker_target_key(&proxy, None).as_deref(),
            Some("canary.svc:9090"),
            "direct backend overrides must partition circuit breaker state by effective host:port"
        );
    }

    #[test]
    fn initial_dispatch_port_uses_precomputed_upstream_override() {
        let mut proxy: Proxy = serde_json::from_value(serde_json::json!({
            "backend_host": "unused.local",
            "backend_port": 0,
        }))
        .expect("minimal proxy should deserialize");
        proxy.dispatch_port_overrides = Some(HashMap::from([(
            8080,
            crate::config::types::ResolvedPortOverride::default(),
        )]));

        assert_eq!(initial_dispatch_port(&proxy, 0), 0);
        assert_eq!(initial_dispatch_port(&proxy, 8080), 8080);

        proxy.backend_port = 9090;
        assert_eq!(
            initial_dispatch_port(&proxy, 8080),
            8080,
            "a full-coverage upstream policy lane beats the proxy template backend_port"
        );
        assert_eq!(
            initial_dispatch_port(&proxy, 0),
            9090,
            "without a full-coverage lane, the proxy template backend_port remains the fallback"
        );
    }

    #[tokio::test]
    async fn upstream_selection_uses_port_override_when_proxy_backend_port_is_unset() {
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "consumers": [],
                "plugin_configs": [],
                "proxies": [{
                    "id": "mesh-egress",
                    "listen_path": "/",
                    "backend_scheme": "http",
                    "backend_host": "unused.local",
                    "backend_port": 0,
                    "upstream_id": "mesh-upstream"
                }],
                "upstreams": [{
                    "id": "mesh-upstream",
                    "targets": [
                        {"host": "10.0.0.1", "port": 8080},
                        {"host": "10.0.0.2", "port": 8080}
                    ],
                    "algorithm": "round_robin",
                    "port_overrides": {
                        "8080": {
                            "algorithm": "consistent_hashing",
                            "hash_on": "header:x-user"
                        }
                    }
                }]
            }))
            .expect("test config should deserialize");
        config.normalize_fields();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::env_config::EnvConfig::default();
        let (state, _) = crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
            .expect("test proxy state should build");
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let mut headers = HashMap::new();
        headers.insert("x-user".to_string(), "alice".to_string());

        let selection = select_upstream_target(proxy, &state, &epoch, "192.0.2.10", &headers, None);

        assert_eq!(selection.lb_hash_key.as_deref(), Some("alice"));
        assert_eq!(selection.target.as_ref().map(|t| t.port), Some(8080));
    }

    #[tokio::test]
    async fn upstream_selection_prefers_policy_port_lane_over_template_backend_port() {
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "consumers": [],
                "plugin_configs": [],
                "proxies": [{
                    "id": "mesh-egress",
                    "listen_path": "/",
                    "backend_scheme": "http",
                    "backend_host": "unused.local",
                    "backend_port": 8080,
                    "upstream_id": "mesh-upstream"
                }],
                "upstreams": [{
                    "id": "mesh-upstream",
                    "targets": [
                        {"host": "10.0.0.1", "port": 8080},
                        {"host": "10.0.0.2", "port": 8080}
                    ],
                    "algorithm": "round_robin",
                    "port_overrides": {
                        "80": {
                            "algorithm": "consistent_hashing",
                            "hash_on": "header:x-user"
                        }
                    }
                }]
            }))
            .expect("test config should deserialize");
        for target in &mut config.upstreams[0].targets {
            target.service_port_policy_key = Some(80);
        }
        config.normalize_fields();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::env_config::EnvConfig::default();
        let (state, _) = crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
            .expect("test proxy state should build");
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let mut headers = HashMap::new();
        headers.insert("x-user".to_string(), "alice".to_string());

        let selection = select_upstream_target(proxy, &state, &epoch, "192.0.2.10", &headers, None);

        let target = selection.target.as_ref().expect("target selected");
        assert_eq!(
            selection.lb_hash_key.as_deref(),
            Some("alice"),
            "selection must use the service-port lane policy, not the proxy template backend_port"
        );
        assert_eq!(target.port, 8080);
        assert_eq!(target.dispatch_policy_port(), 80);
    }

    #[tokio::test]
    async fn upstream_selection_does_not_apply_partial_port_override_before_selection() {
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "consumers": [],
                "plugin_configs": [],
                "proxies": [{
                    "id": "mesh-egress",
                    "listen_path": "/",
                    "backend_scheme": "http",
                    "backend_host": "unused.local",
                    "backend_port": 0,
                    "upstream_id": "mesh-upstream"
                }],
                "upstreams": [{
                    "id": "mesh-upstream",
                    "targets": [
                        {"host": "10.0.0.1", "port": 8080},
                        {"host": "10.0.0.2", "port": 9090}
                    ],
                    "algorithm": "round_robin",
                    "port_overrides": {
                        "8080": {
                            "algorithm": "consistent_hashing",
                            "hash_on": "header:x-user"
                        }
                    }
                }]
            }))
            .expect("test config should deserialize");
        config.normalize_fields();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::env_config::EnvConfig::default();
        let (state, _) = crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
            .expect("test proxy state should build");
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let mut headers = HashMap::new();
        headers.insert("x-user".to_string(), "alice".to_string());

        let first = select_upstream_target(proxy, &state, &epoch, "192.0.2.10", &headers, None);
        let second = select_upstream_target(proxy, &state, &epoch, "192.0.2.10", &headers, None);

        assert_eq!(first.lb_hash_key.as_deref(), Some("192.0.2.10"));
        assert_eq!(second.lb_hash_key.as_deref(), Some("192.0.2.10"));
        assert_ne!(
            first.target.as_ref().map(|t| t.port),
            second.target.as_ref().map(|t| t.port),
            "mixed-port upstreams must keep using the upstream-level balancer until a target is selected"
        );
    }

    #[tokio::test]
    async fn retry_selection_uses_subset_hash_strategy_for_port_subset_without_port_hash_on() {
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "consumers": [],
                "plugin_configs": [],
                "proxies": [{
                    "id": "mesh-egress",
                    "listen_path": "/",
                    "backend_scheme": "http",
                    "backend_host": "unused.local",
                    "backend_port": 8080,
                    "upstream_id": "mesh-upstream",
                    "upstream_subset": "v1"
                }],
                "upstreams": [{
                    "id": "mesh-upstream",
                    "targets": [
                        {
                            "host": "10.0.0.1",
                            "port": 8080,
                            "tags": {"version": "v1"}
                        },
                        {
                            "host": "10.0.0.2",
                            "port": 8080,
                            "tags": {"version": "v1"}
                        },
                        {
                            "host": "10.0.0.3",
                            "port": 8080,
                            "tags": {"version": "v1"}
                        },
                        {
                            "host": "10.0.0.4",
                            "port": 8080,
                            "tags": {"version": "v2"}
                        }
                    ],
                    "algorithm": "round_robin",
                    "hash_on": "ip",
                    "subsets": [{
                        "name": "v1",
                        "labels": {"version": "v1"},
                        "traffic_policy": {
                            "load_balancer_algorithm": "consistent_hashing",
                            "hash_on": "header:x-user-id"
                        }
                    }],
                    "port_overrides": {
                        "8080": {
                            "connect_timeout_ms": 250
                        }
                    }
                }]
            }))
            .expect("test config should deserialize");
        config.normalize_fields();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::env_config::EnvConfig::default();
        let (state, _) = crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
            .expect("test proxy state should build");
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let prev_target = &epoch.config.upstreams[0].targets[0];
        let mut headers = HashMap::new();
        headers.insert("x-user-id".to_string(), "alice".to_string());

        let expected = LoadBalancerCache::select_next_target_for_port_subset_from(
            &epoch.load_balancer,
            &proxy.namespace,
            "mesh-upstream",
            "alice",
            8080,
            "v1",
            prev_target,
            None,
        )
        .expect("expected subset retry target");
        let (client_ip, port_only_key) = [
            "192.0.2.10",
            "198.51.100.20",
            "203.0.113.30",
            "10.10.10.10",
            "172.16.4.8",
        ]
        .into_iter()
        .filter_map(|candidate| {
            let target = LoadBalancerCache::select_next_target_for_port_subset_from(
                &epoch.load_balancer,
                &proxy.namespace,
                "mesh-upstream",
                candidate,
                8080,
                "v1",
                prev_target,
                None,
            )?;
            ((target.host.as_str(), target.port) != (expected.host.as_str(), expected.port))
                .then_some((candidate, target))
        })
        .next()
        .expect("test keys must distinguish subset header hashing from upstream/IP hashing");
        let retry = select_next_retry_target(
            &state,
            &epoch,
            proxy,
            prev_target,
            client_ip,
            client_ip,
            &headers,
        )
        .expect("retry target should be selected");

        assert_eq!(
            (retry.host.as_str(), retry.port),
            (expected.host.as_str(), expected.port),
            "retry must preserve the subset-scoped hash_on key when the port override has no hash_on"
        );
        assert_ne!(
            (expected.host.as_str(), expected.port),
            (port_only_key.host.as_str(), port_only_key.port),
            "sanity check: selected client IP must exercise the old upstream/IP hash-key bug"
        );
    }

    /// Build a single-proxy `ProxyState` for an upstream using
    /// `loadBalancer.simple=PASSTHROUGH` (algorithm `passthrough`) with two
    /// same-port targets, so PASSTHROUGH orig-dst selection is unambiguous.
    async fn passthrough_state() -> crate::proxy::ProxyState {
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "consumers": [],
                "plugin_configs": [],
                "proxies": [{
                    "id": "mesh-egress",
                    "listen_path": "/",
                    "backend_scheme": "http",
                    "backend_host": "unused.local",
                    "backend_port": 8080,
                    "upstream_id": "mesh-upstream"
                }],
                "upstreams": [{
                    "id": "mesh-upstream",
                    "targets": [
                        {"host": "10.0.0.1", "port": 8080},
                        {"host": "10.0.0.2", "port": 8080}
                    ],
                    "algorithm": "passthrough"
                }]
            }))
            .expect("test config should deserialize");
        config.normalize_fields();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::env_config::EnvConfig::default();
        crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
            .expect("test proxy state should build")
            .0
    }

    /// PASSTHROUGH + orig-dst matching a pool target dials that exact target,
    /// repeatably (bypassing round-robin).
    #[tokio::test]
    async fn passthrough_selects_captured_orig_dst() {
        let state = passthrough_state().await;
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let orig: SocketAddr = "10.0.0.2:8080".parse().unwrap();
        for _ in 0..20 {
            let selection = select_upstream_target(
                proxy,
                &state,
                &epoch,
                "192.0.2.10",
                &HashMap::new(),
                Some(orig),
            );
            assert_eq!(
                selection.target.as_ref().map(|t| (t.host.as_str(), t.port)),
                Some(("10.0.0.2", 8080)),
                "PASSTHROUGH must dial the captured original destination"
            );
            assert!(!selection.is_fallback);
        }
    }

    /// PASSTHROUGH with no captured orig-dst falls back to round-robin
    /// (selects a target, rotating across the pool).
    #[tokio::test]
    async fn passthrough_absent_orig_dst_falls_back_to_round_robin() {
        let state = passthrough_state().await;
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let first =
            select_upstream_target(proxy, &state, &epoch, "192.0.2.10", &HashMap::new(), None);
        let second =
            select_upstream_target(proxy, &state, &epoch, "192.0.2.10", &HashMap::new(), None);
        assert!(first.target.is_some(), "RR fallback must select a target");
        assert!(second.target.is_some());
        // Two same-port targets under RR rotate.
        assert_ne!(
            first.target.as_ref().map(|t| t.host.clone()),
            second.target.as_ref().map(|t| t.host.clone()),
            "RR fallback should rotate across the pool"
        );
    }

    /// PASSTHROUGH with an orig-dst that matches no pool target falls back to
    /// round-robin (still selects a healthy target).
    #[tokio::test]
    async fn passthrough_unmatched_orig_dst_falls_back_to_round_robin() {
        let state = passthrough_state().await;
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let orig: SocketAddr = "10.9.9.9:8080".parse().unwrap();
        let selection = select_upstream_target(
            proxy,
            &state,
            &epoch,
            "192.0.2.10",
            &HashMap::new(),
            Some(orig),
        );
        assert!(
            selection.target.is_some(),
            "unmatched orig-dst must fall back to a round-robin target"
        );
        let host = selection.target.as_ref().map(|t| t.host.as_str());
        assert!(
            host == Some("10.0.0.1") || host == Some("10.0.0.2"),
            "RR fallback must pick a real pool target, got {host:?}"
        );
    }

    #[tokio::test]
    async fn upstream_selection_ignores_phantom_port_override_policy() {
        let port_passive = PassiveHealthCheck {
            unhealthy_threshold: 1,
            max_ejection_percent: Some(50),
            ..PassiveHealthCheck::default()
        };
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "consumers": [],
                "plugin_configs": [],
                "proxies": [{
                    "id": "mesh-egress",
                    "listen_path": "/",
                    "backend_scheme": "http",
                    "backend_host": "unused.local",
                    "backend_port": 8080,
                    "upstream_id": "mesh-upstream"
                }],
                "upstreams": [{
                    "id": "mesh-upstream",
                    "targets": [
                        {"host": "10.0.0.1", "port": 9090},
                        {"host": "10.0.0.2", "port": 9090}
                    ],
                    "algorithm": "round_robin"
                }]
            }))
            .expect("test config should deserialize");
        config.upstreams[0].port_overrides.insert(
            8080,
            crate::config::types::UpstreamPortOverride {
                passive_health_check: Some(port_passive.clone()),
                ..Default::default()
            },
        );
        config.normalize_fields();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::env_config::EnvConfig::default();
        let (state, _) = crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
            .expect("test proxy state should build");
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let first_target = UpstreamTarget {
            host: "10.0.0.1".to_string(),
            port: 9090,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        };
        let second_target = UpstreamTarget {
            host: "10.0.0.2".to_string(),
            port: 9090,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        };
        state.health_checker.report_response(
            &proxy.namespace,
            &proxy.id,
            "test-upstream",
            &first_target,
            500,
            false,
            Some(&port_passive),
        );
        state.health_checker.report_response(
            &proxy.namespace,
            &proxy.id,
            "test-upstream",
            &second_target,
            500,
            false,
            Some(&port_passive),
        );

        let selection =
            select_upstream_target(proxy, &state, &epoch, "192.0.2.10", &HashMap::new(), None);

        assert!(
            selection.is_fallback,
            "a configured override for a port with no balancer lane must not re-admit upstream-level targets with port-scoped ejection policy"
        );
        assert_eq!(
            selection.target.as_ref().map(|target| target.port),
            Some(9090)
        );
    }

    #[tokio::test]
    async fn record_backend_outcome_no_conn_end_preserves_active_connection_count() {
        // F06 regression: the HTTP dispatch path holds a
        // LoadBalancerConnectionGuard (start in ctor, end on drop) AND used to
        // call record_backend_outcome, which ALSO ended the connection -- so
        // the least-connections gauge was decremented twice per request.
        // record_backend_outcome_no_conn_end must record CB/health/latency
        // WITHOUT ending the connection (the guard owns that); the full
        // record_backend_outcome must still end it.
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "consumers": [],
                "plugin_configs": [],
                "proxies": [{
                    "id": "lc-proxy",
                    "listen_path": "/",
                    "backend_scheme": "http",
                    "backend_host": "unused.local",
                    "backend_port": 0,
                    "upstream_id": "lc-upstream"
                }],
                "upstreams": [{
                    "id": "lc-upstream",
                    "targets": [{"host": "10.0.0.1", "port": 8080}],
                    "algorithm": "least_connections"
                }]
            }))
            .expect("test config should deserialize");
        config.normalize_fields();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::env_config::EnvConfig::default();
        let (state, _) = crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
            .expect("test proxy state should build");
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];

        let selection =
            select_upstream_target(proxy, &state, &epoch, "192.0.2.10", &HashMap::new(), None);
        let balancer = selection
            .balancer
            .clone()
            .expect("least-connections upstream proxy should resolve a balancer");
        let target = selection
            .target
            .clone()
            .expect("a target should be selected");

        let active = || {
            balancer
                .active_connections
                .iter()
                .map(|entry| entry.value().load(std::sync::atomic::Ordering::Relaxed))
                .sum::<i64>()
        };

        // The guard's constructor would do this start.
        balancer.record_connection_start(target.as_ref());
        assert_eq!(active(), 1, "record_connection_start increments the gauge");

        // no_conn_end must NOT decrement -- the guard owns the end.
        record_backend_outcome_no_conn_end(
            &state,
            proxy,
            &epoch.load_balancer,
            Some(&balancer),
            Some(target.as_ref()),
            None,
            200,
            false,
            None,
            false,
            true,
            std::time::Duration::ZERO,
        );
        assert_eq!(
            active(),
            1,
            "record_backend_outcome_no_conn_end must not end the connection"
        );

        // The full variant DOES end it (used by the bare-start H3 paths).
        record_backend_outcome(
            &state,
            proxy,
            &epoch.load_balancer,
            Some(&balancer),
            Some(target.as_ref()),
            None,
            200,
            false,
            None,
            false,
            true,
            std::time::Duration::ZERO,
        );
        assert_eq!(
            active(),
            0,
            "record_backend_outcome must end the connection"
        );
    }

    #[tokio::test]
    async fn request_body_too_large_outcome_releases_half_open_probe_neutrally() {
        // HBONE/native-H3 can detect an oversized Content-Length after
        // check_circuit_breaker() has reserved a HALF_OPEN probe but before any
        // backend connection is attempted. That synthetic 413 is a client-side
        // gateway rejection, not backend recovery, so it must release the probe
        // slot without counting as a successful recovery probe.
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "consumers": [],
                "plugin_configs": [],
                "proxies": [{
                    "id": "cb-body-limit-proxy",
                    "listen_path": "/",
                    "backend_scheme": "http",
                    "backend_host": "backend.local",
                    "backend_port": 8080,
                    "circuit_breaker": {
                        "failure_threshold": 1,
                        "success_threshold": 1,
                        "timeout_seconds": 0,
                        "failure_status_codes": [500, 502, 503, 504],
                        "half_open_max_requests": 1,
                        "trip_on_connection_errors": true
                    }
                }],
                "upstreams": []
            }))
            .expect("test config should deserialize");
        config.normalize_fields();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::env_config::EnvConfig::default();
        let (state, _) = crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
            .expect("test proxy state should build");
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let cb_config = proxy
            .circuit_breaker
            .as_ref()
            .expect("proxy should have circuit breaker config");
        let cb_target_key = circuit_breaker_target_key(proxy, None);
        let cb = state.circuit_breaker_cache.get_or_create(
            &proxy.namespace,
            &proxy.id,
            cb_target_key.as_deref(),
            cb_config,
        );

        cb.record_failure(500, false, false);
        assert_eq!(cb.state_name(), "open");

        let (final_cb_target_key, is_half_open_probe, _admission_open_epoch) =
            check_circuit_breaker(proxy, &state, None).expect("timeout=0 admits a probe");
        assert!(
            is_half_open_probe,
            "the request must own a HALF_OPEN probe slot"
        );
        assert_eq!(cb.state_name(), "half_open");
        assert_eq!(cb.half_open_in_flight(), 1);

        record_backend_outcome_no_conn_end(
            &state,
            proxy,
            &epoch.load_balancer,
            None,
            None,
            final_cb_target_key.as_deref(),
            413,
            false,
            Some(ErrorClass::RequestBodyTooLarge),
            is_half_open_probe,
            false,
            std::time::Duration::ZERO,
        );

        assert_eq!(
            cb.state_name(),
            "half_open",
            "synthetic oversized-request 413 must not close the breaker as a successful backend probe"
        );
        assert_eq!(
            cb.success_count(),
            0,
            "request-body-limit rejects carry no backend recovery signal"
        );
        assert_eq!(
            cb.half_open_in_flight(),
            0,
            "neutral recording must release the reserved probe slot"
        );
    }

    #[tokio::test]
    async fn client_disconnect_outcome_does_not_record_passive_health() {
        // A client-caused disconnect carries no signal about backend health, so
        // record_backend_outcome_inner must skip the passive-health report even
        // when the (synthetic) status we emit sits in unhealthy_status_codes.
        // Otherwise the sibling H3 oversized-413 / client-abort-502 paths would
        // poison passive health for the selected target. The contrast call with
        // error_class=None proves both that the harness genuinely observes
        // passive state and that the skip is ClientDisconnect-specific.
        let passive = PassiveHealthCheck {
            unhealthy_status_codes: vec![502],
            unhealthy_threshold: 1,
            ..PassiveHealthCheck::default()
        };
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "consumers": [],
                "plugin_configs": [],
                "proxies": [{
                    "id": "ph-proxy",
                    "listen_path": "/",
                    "backend_scheme": "http",
                    "backend_host": "unused.local",
                    "backend_port": 0,
                    "upstream_id": "ph-upstream"
                }],
                "upstreams": [{
                    "id": "ph-upstream",
                    "targets": [{"host": "10.0.0.1", "port": 8080}],
                    "algorithm": "round_robin"
                }]
            }))
            .expect("test config should deserialize");
        config.upstreams[0].health_checks = Some(crate::config::types::HealthCheckConfig {
            active: None,
            passive: Some(passive),
        });
        config.normalize_fields();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::env_config::EnvConfig::default();
        let (state, _) = crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
            .expect("test proxy state should build");
        let epoch = state.request_epoch.load();
        let proxy = &epoch.config.proxies[0];
        let target = UpstreamTarget {
            host: "10.0.0.1".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        };

        let is_unhealthy = || {
            state
                .health_checker
                .passive_health
                .get(&crate::config::db_backend::namespaced_runtime_key(
                    &proxy.namespace,
                    &proxy.id,
                ))
                .is_some_and(|ph| ph.unhealthy.contains_key("10.0.0.1:8080"))
        };

        // ClientDisconnect 502 must NOT mark the target unhealthy even though
        // 502 is in unhealthy_status_codes and the threshold is 1.
        record_backend_outcome_no_conn_end(
            &state,
            proxy,
            &epoch.load_balancer,
            None,
            Some(&target),
            None,
            502,
            false,
            Some(ErrorClass::ClientDisconnect),
            false,
            true,
            std::time::Duration::ZERO,
        );
        assert!(
            !is_unhealthy(),
            "ClientDisconnect outcome must not poison passive health (no failure recorded for the backend target)"
        );

        // A genuine backend 502 (error_class=None) MUST mark it unhealthy,
        // proving the skip above is specific to ClientDisconnect and that the
        // harness actually observes passive-health state.
        record_backend_outcome_no_conn_end(
            &state,
            proxy,
            &epoch.load_balancer,
            None,
            Some(&target),
            None,
            502,
            false,
            None,
            false,
            true,
            std::time::Duration::ZERO,
        );
        assert!(
            is_unhealthy(),
            "a real backend 502 in unhealthy_status_codes must mark the target unhealthy"
        );
    }
}
