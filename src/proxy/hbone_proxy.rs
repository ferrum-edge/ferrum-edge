//! HBONE CONNECT relay transport.
//!
//! Mesh mode identifies HBONE in the main proxy path, then delegates the
//! backend connection, circuit-breaker accounting, relay task, and logging here.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{error, warn};

use super::{
    ClientRequestBody, LoadBalancerConnectionGuard, ProxyBody, ProxyState, backend_dispatch,
    build_response, build_response_from_normalized_reject,
    finalize_reject_response_with_after_proxy_hooks, log_rejected_request, record_request,
    tcp_proxy,
};
use crate::config::EnvConfig;
use crate::config::env_config::OperatingMode;
use crate::config::types::{Proxy, UpstreamTarget};
use crate::load_balancer::LoadBalancerCache;
use crate::plugins::{Direction, DisconnectCause, Plugin, RequestContext, TransactionSummary};
use crate::request_epoch::RequestEpoch;
use crate::retry;

struct HboneBackendConnection {
    stream: TcpStream,
    target_url: String,
    resolved_ip: Option<String>,
}

struct HboneConnectError {
    status: StatusCode,
    body: &'static [u8],
    phase: &'static str,
    class: retry::ErrorClass,
    message: String,
    target_url: Option<String>,
    resolved_ip: Option<String>,
}

pub(super) fn tag_request_metadata(ctx: &mut RequestContext) {
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    ctx.metadata.insert(
        "connection_security_policy".to_string(),
        "hbone".to_string(),
    );
}

pub(super) fn is_connect_request<B>(req: &Request<B>, env_config: &EnvConfig) -> bool {
    env_config.mode == OperatingMode::Mesh
        && req.extensions().get::<hyper::ext::Protocol>().is_none()
        && crate::modes::mesh::hbone::is_hbone_connect(req.method(), req.version(), req.headers())
}

pub(super) fn strip_egress_baggage_in_vec(
    headers: &mut Vec<(String, String)>,
    key_prefixes: &[String],
) {
    crate::modes::mesh::hbone::strip_egress_baggage_in_vec(headers, key_prefixes);
}

pub(super) fn strip_egress_baggage_in_proxy_headers(
    owned_proxy_headers: &mut Option<HashMap<String, String>>,
    fallback_headers: &HashMap<String, String>,
    key_prefixes: &[String],
) {
    if key_prefixes.is_empty()
        || !owned_proxy_headers
            .as_ref()
            .map(crate::modes::mesh::hbone::has_baggage_header_in_map)
            .unwrap_or_else(|| {
                crate::modes::mesh::hbone::has_baggage_header_in_map(fallback_headers)
            })
    {
        return;
    }

    let headers = owned_proxy_headers.get_or_insert_with(|| fallback_headers.clone());
    crate::modes::mesh::hbone::strip_egress_baggage_in_map(headers, key_prefixes);
}

fn relay_timeout(seconds: u64) -> Option<Duration> {
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

fn relay_timeout_millis(milliseconds: u64) -> Option<Duration> {
    (milliseconds > 0).then(|| Duration::from_millis(milliseconds))
}

// `pub(crate)`: shared with the raw-TCP mesh egress relay
// (`proxy::mesh_tcp_egress`), which derives its copy-loop bounds from the
// same proxy/env fields as the HBONE relay.
pub(crate) fn proxy_idle_timeout(proxy: &Proxy, env_config: &EnvConfig) -> Option<Duration> {
    relay_timeout(
        proxy
            .tcp_idle_timeout_seconds
            .unwrap_or(env_config.tcp_idle_timeout_seconds),
    )
}

pub(crate) fn proxy_half_close_cap(env_config: &EnvConfig) -> Option<Duration> {
    relay_timeout(env_config.tcp_half_close_max_wait_seconds)
}

pub(crate) fn backend_read_timeout(proxy: &Proxy) -> Option<Duration> {
    relay_timeout_millis(proxy.backend_read_timeout_ms)
}

pub(crate) fn backend_write_timeout(proxy: &Proxy) -> Option<Duration> {
    relay_timeout_millis(proxy.backend_write_timeout_ms)
}

fn hbone_relay_body_outcome(
    first_failure: Option<&tcp_proxy::StreamFirstFailure>,
) -> (bool, bool, Option<retry::ErrorClass>) {
    let Some((direction, class, side, _message)) = first_failure else {
        return (true, false, None);
    };
    let client_disconnected = matches!(
        tcp_proxy::disconnect_cause_for_failure(*direction, class, *side),
        DisconnectCause::RecvError
    );
    (false, client_disconnected, Some(*class))
}

#[allow(clippy::too_many_arguments)]
fn build_hbone_relay_summary(
    proxy: &Proxy,
    ctx: &RequestContext,
    method: &str,
    backend_target: String,
    backend_resolved_ip: Option<String>,
    start_time: Instant,
    backend_start: Instant,
    backend_connect_ms: f64,
    plugin_execution_ns: u64,
    bytes_client_to_backend: u64,
    bytes_backend_to_client: u64,
    body_completed: bool,
    client_disconnected: bool,
    body_error_class: Option<retry::ErrorClass>,
) -> TransactionSummary {
    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;
    let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let plugin_external_io_ms =
        ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let gateway_processing_ms = total_ms - backend_total_ms;
    let gateway_overhead_ms = (gateway_processing_ms - plugin_execution_ms).max(0.0);

    TransactionSummary {
        namespace: proxy.namespace.clone(),
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        auth_method: ctx.auth_method,
        http_method: method.to_string(),
        request_path: ctx.path.clone(),
        proxy_id: Some(proxy.id.clone()),
        proxy_name: proxy.name.clone(),
        backend_target: Some(backend_target),
        backend_resolved_ip,
        // 200 OK was already written to the client to accept the CONNECT.
        // body_completed + body_error_class capture relay outcomes; log/alert
        // consumers should use those fields, not this status, to detect failures.
        response_status_code: StatusCode::OK.as_u16(),
        // latency_total_ms and latency_backend_total_ms measure full tunnel
        // lifetime (tunnel open → close), not request-processing time.  Filter
        // latency dashboards on response_streamed=true or
        // request_protocol=hbone to avoid mixing these with per-request values.
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: gateway_processing_ms,
        latency_backend_ttfb_ms: backend_connect_ms,
        latency_backend_total_ms: backend_total_ms,
        latency_plugin_execution_ms: plugin_execution_ms,
        latency_plugin_external_io_ms: plugin_external_io_ms,
        latency_gateway_overhead_ms: gateway_overhead_ms,
        request_user_agent: ctx.headers.get("user-agent").cloned(),
        response_streamed: true,
        client_disconnected,
        body_error_class,
        body_completed,
        bytes_sent: bytes_client_to_backend,
        bytes_received: bytes_backend_to_client,
        metadata: crate::proxy::clone_log_metadata(ctx),
        ..TransactionSummary::default()
    }
}

fn classify_io_error(err: &io::Error) -> retry::ErrorClass {
    if retry::is_port_exhaustion(err) {
        return retry::ErrorClass::PortExhaustion;
    }

    match err.kind() {
        io::ErrorKind::ConnectionRefused => retry::ErrorClass::ConnectionRefused,
        io::ErrorKind::ConnectionReset => retry::ErrorClass::ConnectionReset,
        io::ErrorKind::TimedOut => retry::ErrorClass::ConnectionTimeout,
        io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe => {
            retry::ErrorClass::ConnectionClosed
        }
        _ => retry::ErrorClass::ConnectionRefused,
    }
}

async fn connect_backend(
    state: &ProxyState,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
) -> Result<HboneBackendConnection, HboneConnectError> {
    let (host, port) = upstream_target
        .map(|target| (target.host.as_str(), target.port))
        .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port));
    let target_url = format!("tcp://{host}:{port}");

    // Honor DestinationRule per-port `connect_timeout_ms` overrides on the
    // HBONE (ambient mesh) path. Single field read from the precomputed map.
    let effective_connect_timeout_ms = proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|m| m.get(&port))
        .and_then(|override_config| override_config.connect_timeout_ms)
        .unwrap_or(proxy.backend_connect_timeout_ms);

    let resolved_ip = state
        .dns_cache
        .resolve(
            host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .map_err(|err| HboneConnectError {
            status: StatusCode::BAD_GATEWAY,
            body: br#"{"error":"DNS resolution for backend failed"}"#,
            phase: "hbone_dns",
            class: retry::ErrorClass::DnsLookupError,
            message: err.to_string(),
            target_url: Some(target_url.clone()),
            resolved_ip: None,
        })?;
    let addr = SocketAddr::new(resolved_ip, port);

    let connect = crate::socket_opts::connect_with_socket_opts(addr);
    let stream = if effective_connect_timeout_ms > 0 {
        let timeout = Duration::from_millis(effective_connect_timeout_ms);
        match tokio::time::timeout(timeout, connect).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                let class = classify_io_error(&err);
                if class == retry::ErrorClass::PortExhaustion {
                    state.overload.record_port_exhaustion();
                }
                return Err(HboneConnectError {
                    status: StatusCode::BAD_GATEWAY,
                    body: br#"{"error":"Backend HBONE connection failed"}"#,
                    phase: "hbone_connect",
                    class,
                    message: err.to_string(),
                    target_url: Some(target_url),
                    resolved_ip: Some(resolved_ip.to_string()),
                });
            }
            Err(_) => {
                return Err(HboneConnectError {
                    status: StatusCode::GATEWAY_TIMEOUT,
                    body: br#"{"error":"Backend HBONE connection timed out"}"#,
                    phase: "hbone_connect_timeout",
                    class: retry::ErrorClass::ConnectionTimeout,
                    message: format!(
                        "backend connect timeout after {}ms",
                        effective_connect_timeout_ms
                    ),
                    target_url: Some(target_url),
                    resolved_ip: Some(resolved_ip.to_string()),
                });
            }
        }
    } else {
        match connect.await {
            Ok(stream) => stream,
            Err(err) => {
                let class = classify_io_error(&err);
                if class == retry::ErrorClass::PortExhaustion {
                    state.overload.record_port_exhaustion();
                }
                return Err(HboneConnectError {
                    status: StatusCode::BAD_GATEWAY,
                    body: br#"{"error":"Backend HBONE connection failed"}"#,
                    phase: "hbone_connect",
                    class,
                    message: err.to_string(),
                    target_url: Some(target_url),
                    resolved_ip: Some(resolved_ip.to_string()),
                });
            }
        }
    };

    let _ = stream.set_nodelay(true);

    Ok(HboneBackendConnection {
        stream,
        target_url,
        resolved_ip: Some(resolved_ip.to_string()),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_hbone_request(
    state: &ProxyState,
    proxy: &Arc<Proxy>,
    epoch: &RequestEpoch,
    ctx: &mut RequestContext,
    client_request_body: ClientRequestBody,
    plugins: &[Arc<dyn Plugin>],
    start_time: Instant,
    method: &str,
    plugin_execution_ns: u64,
) -> Response<ProxyBody> {
    // Apply route overrides set by `before_proxy` plugins (e.g.,
    // `mesh_route_dispatch` from a VirtualService header/method match). The
    // dispatcher in `proxy/mod.rs` runs the standard `before_proxy` chain on
    // the outer CONNECT request before branching here, so the HBONE path
    // honors the same per-rule routing / timeout / retry overrides as
    // H1/H2/H3 dispatch. The Arc is cloned only when an override actually
    // changes the effective destination — otherwise this is a no-op.
    let proxy_arc = ctx
        .apply_route_overrides_with_upstreams(Arc::clone(proxy), epoch.load_balancer.upstreams());
    let proxy: &Arc<Proxy> = &proxy_arc;
    ctx.matched_proxy = Some(Arc::clone(proxy));

    // HBONE relay trust boundary. The relay byte-copies this CONNECT stream
    // straight to the backend as a transparent TCP tunnel, so it must only
    // accept HBONE peers that the mTLS/HBONE listener authenticated. The
    // inbound mesh listener publishes the trust-domain-verified peer identity
    // into `ctx.peer_spiffe_id` (via the `spiffe_identity` plugin during
    // `on_request_received`, or the node-waypoint identity path) before this
    // branch runs, so a present `peer_spiffe_id` is exactly "a verified mesh
    // peer terminated mTLS on this listener". A bare (marker-less) CONNECT
    // with no authenticated peer — and equally a CONNECT that merely asserts
    // an `x-*-protocol: hbone` marker without a verified peer — is not a valid
    // HBONE tunnel; reject it here, before dialing or circuit-breaking any
    // backend, rather than silently relaying it. Tier 2b already verifies the
    // peer's trust domain at TLS time; this gate ensures the relay never opens
    // a tunnel for an unauthenticated peer.
    if ctx.peer_spiffe_id.is_none() {
        warn!(
            proxy_id = %proxy.id,
            "Rejected HBONE CONNECT with no authenticated peer identity"
        );
        ctx.metadata.insert(
            "mesh_authz.deny_policy".to_string(),
            "hbone_unauthenticated_peer".to_string(),
        );
        let reject = finalize_reject_response_with_after_proxy_hooks(
            plugins,
            ctx,
            StatusCode::FORBIDDEN,
            br#"{"error":"HBONE tunnel requires an authenticated mesh peer"}"#,
            HashMap::new(),
            false,
        )
        .await;
        log_rejected_request(
            plugins,
            ctx,
            reject.http_status.as_u16(),
            start_time,
            "hbone_unauthenticated_peer",
            plugin_execution_ns,
        )
        .await;
        record_request(state, reject.http_status.as_u16());
        return build_response_from_normalized_reject(reject);
    }

    let selection =
        backend_dispatch::select_upstream_target(proxy, state, epoch, &ctx.client_ip, &ctx.headers);
    let upstream_target = selection.target;
    let upstream_balancer = selection.balancer;

    let (cb_target_key, cb_is_half_open_probe) =
        match backend_dispatch::check_circuit_breaker(proxy, state, upstream_target.as_deref()) {
            Ok(result) => result,
            Err(()) => {
                let reject = finalize_reject_response_with_after_proxy_hooks(
                    plugins,
                    ctx,
                    StatusCode::SERVICE_UNAVAILABLE,
                    br#"{"error":"Service temporarily unavailable (circuit breaker open)"}"#,
                    HashMap::new(),
                    false,
                )
                .await;
                log_rejected_request(
                    plugins,
                    ctx,
                    reject.http_status.as_u16(),
                    start_time,
                    "hbone_circuit_breaker_open",
                    plugin_execution_ns,
                )
                .await;
                record_request(state, reject.http_status.as_u16());
                return build_response_from_normalized_reject(reject);
            }
        };

    let hbone_on_upgrade = match client_request_body {
        ClientRequestBody::Streaming(request) => {
            let (mut parts, _body) = (*request).into_parts();
            match parts.extensions.remove::<OnUpgrade>() {
                Some(on_upgrade) => on_upgrade,
                None => {
                    error!(
                        proxy_id = %proxy.id,
                        "HBONE CONNECT request reached relay without an upgrade handle"
                    );
                    let reject = finalize_reject_response_with_after_proxy_hooks(
                        plugins,
                        ctx,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        br#"{"error":"HBONE upgrade handle missing"}"#,
                        HashMap::new(),
                        false,
                    )
                    .await;
                    log_rejected_request(
                        plugins,
                        ctx,
                        reject.http_status.as_u16(),
                        start_time,
                        "hbone_upgrade_missing",
                        plugin_execution_ns,
                    )
                    .await;
                    record_request(state, reject.http_status.as_u16());
                    return build_response_from_normalized_reject(reject);
                }
            }
        }
        ClientRequestBody::Buffered(_) => {
            error!(
                proxy_id = %proxy.id,
                "HBONE CONNECT request was buffered before relay"
            );
            let reject = finalize_reject_response_with_after_proxy_hooks(
                plugins,
                ctx,
                StatusCode::INTERNAL_SERVER_ERROR,
                br#"{"error":"HBONE request buffering invariant violated"}"#,
                HashMap::new(),
                false,
            )
            .await;
            log_rejected_request(
                plugins,
                ctx,
                reject.http_status.as_u16(),
                start_time,
                "hbone_request_buffered",
                plugin_execution_ns,
            )
            .await;
            record_request(state, reject.http_status.as_u16());
            return build_response_from_normalized_reject(reject);
        }
    };

    let backend_start = Instant::now();
    let backend = match connect_backend(state, proxy, upstream_target.as_deref()).await {
        Ok(backend) => backend,
        Err(err) => {
            error!(
                proxy_id = %proxy.id,
                backend_target = ?err.target_url,
                backend_resolved_ip = ?err.resolved_ip,
                error_kind = retry::error_class_log_kind(err.class),
                error_class = %err.class,
                error = %err.message,
                "HBONE backend connection failed"
            );
            if let Some(cb_config) = &proxy.circuit_breaker {
                let cb = state.circuit_breaker_cache.get_or_create(
                    &proxy.id,
                    cb_target_key.as_deref(),
                    cb_config,
                );
                cb.record_failure(err.status.as_u16(), true, cb_is_half_open_probe);
            }
            ctx.metadata
                .insert("error_class".to_string(), err.class.to_string());
            let reject = finalize_reject_response_with_after_proxy_hooks(
                plugins,
                ctx,
                err.status,
                err.body,
                HashMap::new(),
                false,
            )
            .await;
            log_rejected_request(
                plugins,
                ctx,
                reject.http_status.as_u16(),
                start_time,
                err.phase,
                plugin_execution_ns,
            )
            .await;
            record_request(state, reject.http_status.as_u16());
            return build_response_from_normalized_reject(reject);
        }
    };
    let backend_elapsed = backend_start.elapsed();

    if let Some(cb_config) = &proxy.circuit_breaker {
        let cb = state.circuit_breaker_cache.get_or_create(
            &proxy.id,
            cb_target_key.as_deref(),
            cb_config,
        );
        cb.record_success(cb_is_half_open_probe);
    }
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, upstream_target.as_deref())
        && let Some(upstream) =
            LoadBalancerCache::get_upstream_from(&epoch.load_balancer, upstream_id)
    {
        let passive = backend_dispatch::passive_health_for_target(proxy, &upstream, target);
        state.health_checker.report_response(
            &proxy.id,
            target,
            StatusCode::OK.as_u16(),
            false,
            passive,
        );
    }

    let backend_target = backend.target_url.clone();
    let backend_resolved_ip = backend.resolved_ip.clone();
    let bytes_sent_observed = Arc::clone(&ctx.bytes_sent_observed);
    let relay_plugins: Vec<Arc<dyn Plugin>> = plugins.to_vec();
    let relay_ctx = ctx.clone();
    let relay_proxy = proxy.clone();
    let relay_method = method.to_string();
    let relay_backend_target = backend_target.clone();
    let relay_backend_resolved_ip = backend_resolved_ip.clone();
    let relay_start_time = start_time;
    let relay_backend_start = backend_start;
    let relay_backend_connect_ms = backend_elapsed.as_secs_f64() * 1000.0;
    let relay_plugin_execution_ns = plugin_execution_ns;
    let adaptive_buffer = Arc::clone(&state.adaptive_buffer);
    let relay_buffer_size = adaptive_buffer.get_buffer_size(&proxy.id);
    let relay_idle_timeout = proxy_idle_timeout(proxy, &state.env_config);
    let relay_half_close_cap = proxy_half_close_cap(&state.env_config);
    let relay_read_timeout = backend_read_timeout(proxy);
    let relay_write_timeout = backend_write_timeout(proxy);
    let lb_guard =
        LoadBalancerConnectionGuard::new(upstream_target.clone(), upstream_balancer.clone());
    let backend_stream = backend.stream;
    tokio::spawn(async move {
        let _lb_guard = lb_guard;
        match hbone_on_upgrade.await {
            Ok(upgraded) => {
                let client_stream = TokioIo::new(upgraded);
                let result = tcp_proxy::bidirectional_copy_for_relay(
                    client_stream,
                    backend_stream,
                    relay_idle_timeout,
                    relay_half_close_cap,
                    relay_read_timeout,
                    relay_write_timeout,
                    relay_buffer_size,
                )
                .await;
                bytes_sent_observed.fetch_add(result.bytes_client_to_backend, Ordering::Release);
                adaptive_buffer.record_connection(
                    &relay_proxy.id,
                    result
                        .bytes_client_to_backend
                        .saturating_add(result.bytes_backend_to_client),
                );
                if let Some((direction, class, side, message)) = result.first_failure.as_ref() {
                    crate::plugins::prometheus_metrics::global_registry()
                        .record_hbone_relay_failure(&relay_proxy.id, *direction, *class);
                    warn!(
                        proxy_id = %relay_proxy.id,
                        direction = ?direction,
                        io_side = ?side,
                        error_kind = retry::error_class_log_kind(*class),
                        error_class = %class,
                        error = %message,
                        "HBONE tunnel relay failed"
                    );
                }
                let (body_completed, client_disconnected, body_error_class) =
                    hbone_relay_body_outcome(result.first_failure.as_ref());
                let summary = build_hbone_relay_summary(
                    &relay_proxy,
                    &relay_ctx,
                    &relay_method,
                    relay_backend_target,
                    relay_backend_resolved_ip,
                    relay_start_time,
                    relay_backend_start,
                    relay_backend_connect_ms,
                    relay_plugin_execution_ns,
                    result.bytes_client_to_backend,
                    result.bytes_backend_to_client,
                    body_completed,
                    client_disconnected,
                    body_error_class,
                );
                // Release the LB connection guard before the (potentially slow)
                // log/mirror await so the upstream's active-connection counter
                // reflects the closed tunnel rather than skewing
                // least-connections target selection during log hooks.
                drop(_lb_guard);
                // log_with_mirror runs unconditionally so runtime transaction
                // metrics are always recorded regardless of whether logging
                // plugins are configured (empty-plugin loop is a no-op).
                crate::plugins::log_with_mirror(&relay_plugins, &summary, &relay_ctx).await;
            }
            Err(err) => {
                let error_class = retry::classify_boxed_error(&err);
                warn!(
                    proxy_id = %relay_proxy.id,
                    error = %err,
                    "HBONE client upgrade failed"
                );
                // Derive client_disconnected from the error class rather than
                // assuming client fault: an OnUpgrade error can be a local/
                // hyper-side failure (e.g. idle timeout fires before the upgrade
                // completes, which maps to IdleTimeout, not RecvError).
                let client_disconnected = matches!(
                    tcp_proxy::disconnect_cause_for_failure(
                        Direction::ClientToBackend,
                        &error_class,
                        Some(tcp_proxy::StreamIoSide::Read),
                    ),
                    DisconnectCause::RecvError
                );
                let summary = build_hbone_relay_summary(
                    &relay_proxy,
                    &relay_ctx,
                    &relay_method,
                    relay_backend_target,
                    relay_backend_resolved_ip,
                    relay_start_time,
                    relay_backend_start,
                    relay_backend_connect_ms,
                    relay_plugin_execution_ns,
                    0,
                    0,
                    false,
                    client_disconnected,
                    Some(error_class),
                );
                // log_with_mirror runs unconditionally so runtime transaction
                // metrics are always recorded regardless of whether logging
                // plugins are configured (empty-plugin loop is a no-op).
                crate::plugins::log_with_mirror(&relay_plugins, &summary, &relay_ctx).await;
            }
        }
    });

    record_request(state, StatusCode::OK.as_u16());

    Response::builder()
        .status(StatusCode::OK)
        .body(ProxyBody::empty())
        .unwrap_or_else(|err| {
            error!(error = %err, "Failed to build HBONE CONNECT response");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"Internal server error"}"#,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::{build_hbone_relay_summary, hbone_relay_body_outcome};
    use crate::config::types::Proxy;
    use crate::plugins::{Direction, RequestContext};
    use crate::proxy::tcp_proxy::{StreamFirstFailure, StreamIoSide};
    use crate::retry::ErrorClass;
    use std::time::Instant;

    fn minimal_proxy() -> Proxy {
        serde_json::from_value(serde_json::json!({
            "id": "hbone-proxy",
            "name": "HBONE Proxy",
            "backend_host": "backend.example",
            "backend_port": 15008
        }))
        .expect("minimal proxy should deserialize")
    }

    #[test]
    fn hbone_relay_body_outcome_reports_clean_completion() {
        assert_eq!(hbone_relay_body_outcome(None), (true, false, None));
    }

    #[test]
    fn hbone_relay_body_outcome_classifies_client_disconnect() {
        let failure: StreamFirstFailure = (
            Direction::ClientToBackend,
            ErrorClass::ConnectionReset,
            Some(StreamIoSide::Read),
            "client reset".to_string(),
        );

        assert_eq!(
            hbone_relay_body_outcome(Some(&failure)),
            (false, true, Some(ErrorClass::ConnectionReset))
        );
    }

    #[test]
    fn hbone_relay_body_outcome_preserves_backend_error_class() {
        let failure: StreamFirstFailure = (
            Direction::BackendToClient,
            ErrorClass::ConnectionReset,
            Some(StreamIoSide::Read),
            "backend reset".to_string(),
        );

        assert_eq!(
            hbone_relay_body_outcome(Some(&failure)),
            (false, false, Some(ErrorClass::ConnectionReset))
        );
    }

    /// `ReadWriteTimeout` (idle timeout) is never attributed to the client —
    /// it fires when neither side sends data, so `client_disconnected` must
    /// be `false`.
    #[test]
    fn hbone_relay_body_outcome_idle_timeout_not_client_disconnected() {
        let failure: StreamFirstFailure = (
            Direction::ClientToBackend,
            ErrorClass::ReadWriteTimeout,
            None,
            "idle timeout".to_string(),
        );

        let (body_completed, client_disconnected, body_error_class) =
            hbone_relay_body_outcome(Some(&failure));
        assert!(!body_completed);
        assert!(
            !client_disconnected,
            "idle timeout must not be attributed to the client"
        );
        assert_eq!(body_error_class, Some(ErrorClass::ReadWriteTimeout));
    }

    /// `BackendToClient` + `Write` means we could not write to the client —
    /// the client is gone, so `client_disconnected` must be `true`.
    #[test]
    fn hbone_relay_body_outcome_backend_to_client_write_is_client_disconnected() {
        let failure: StreamFirstFailure = (
            Direction::BackendToClient,
            ErrorClass::ConnectionReset,
            Some(StreamIoSide::Write),
            "write to client failed".to_string(),
        );

        let (body_completed, client_disconnected, body_error_class) =
            hbone_relay_body_outcome(Some(&failure));
        assert!(!body_completed);
        assert!(
            client_disconnected,
            "BackendToClient+Write means the client is gone"
        );
        assert_eq!(body_error_class, Some(ErrorClass::ConnectionReset));
    }

    #[test]
    fn build_hbone_relay_summary_records_relay_bytes_and_body_state() {
        let proxy = minimal_proxy();
        let mut ctx = RequestContext::new(
            "203.0.113.8".to_string(),
            "CONNECT".to_string(),
            "spiffe://cluster.local/ns/default/sa/backend".to_string(),
        );
        ctx.headers
            .insert("user-agent".to_string(), "hbone-client".to_string());
        ctx.metadata
            .insert("request_protocol".to_string(), "hbone".to_string());

        let summary = build_hbone_relay_summary(
            &proxy,
            &ctx,
            "CONNECT",
            "tcp://backend.example:15008".to_string(),
            Some("192.0.2.10".to_string()),
            Instant::now(),
            Instant::now(),
            3.5,
            2_000_000,
            123,
            456,
            false,
            true,
            Some(ErrorClass::ConnectionReset),
        );

        assert_eq!(summary.proxy_id.as_deref(), Some("hbone-proxy"));
        assert_eq!(summary.proxy_name.as_deref(), Some("HBONE Proxy"));
        assert_eq!(summary.http_method, "CONNECT");
        assert_eq!(
            summary.backend_target.as_deref(),
            Some("tcp://backend.example:15008")
        );
        assert_eq!(summary.backend_resolved_ip.as_deref(), Some("192.0.2.10"));
        assert!(summary.response_streamed);
        assert_eq!(summary.bytes_sent, 123);
        assert_eq!(summary.bytes_received, 456);
        assert!(!summary.body_completed);
        assert!(summary.client_disconnected);
        assert_eq!(summary.body_error_class, Some(ErrorClass::ConnectionReset));
        assert_eq!(
            summary.metadata.get("request_protocol").map(String::as_str),
            Some("hbone")
        );
        assert_eq!(summary.request_user_agent.as_deref(), Some("hbone-client"));
    }
}
