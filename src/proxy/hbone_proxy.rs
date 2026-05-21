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
use crate::plugins::{Plugin, RequestContext, TransactionSummary};
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

fn proxy_idle_timeout(proxy: &Proxy, env_config: &EnvConfig) -> Option<Duration> {
    relay_timeout(
        proxy
            .tcp_idle_timeout_seconds
            .unwrap_or(env_config.tcp_idle_timeout_seconds),
    )
}

fn proxy_half_close_cap(env_config: &EnvConfig) -> Option<Duration> {
    relay_timeout(env_config.tcp_half_close_max_wait_seconds)
}

fn backend_read_timeout(proxy: &Proxy) -> Option<Duration> {
    relay_timeout_millis(proxy.backend_read_timeout_ms)
}

fn backend_write_timeout(proxy: &Proxy) -> Option<Duration> {
    relay_timeout_millis(proxy.backend_write_timeout_ms)
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
    let relay_proxy_id = proxy.id.clone();
    let relay_buffer_proxy_id = proxy.id.clone();
    let prometheus_metrics_enabled = plugins
        .iter()
        .any(|plugin| plugin.name() == "prometheus_metrics");
    let adaptive_buffer = Arc::clone(&state.adaptive_buffer);
    let relay_buffer_size = adaptive_buffer.get_buffer_size(&relay_buffer_proxy_id);
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
                    &relay_buffer_proxy_id,
                    result
                        .bytes_client_to_backend
                        .saturating_add(result.bytes_backend_to_client),
                );
                if let Some((direction, class, side, message)) = result.first_failure {
                    if prometheus_metrics_enabled {
                        crate::plugins::prometheus_metrics::global_registry()
                            .record_hbone_relay_failure(&relay_proxy_id, direction, class);
                    }
                    warn!(
                        proxy_id = %relay_proxy_id,
                        direction = ?direction,
                        io_side = ?side,
                        error_kind = retry::error_class_log_kind(class),
                        error_class = %class,
                        error = %message,
                        "HBONE tunnel relay failed"
                    );
                }
            }
            Err(err) => {
                warn!(
                    proxy_id = %relay_proxy_id,
                    error = %err,
                    "HBONE client upgrade failed"
                );
            }
        }
    });

    record_request(state, StatusCode::OK.as_u16());
    if !plugins.is_empty() {
        let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let backend_connect_ms = backend_elapsed.as_secs_f64() * 1000.0;
        let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
        let plugin_external_io_ms =
            ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let gateway_overhead_ms = (total_ms - plugin_execution_ms).max(0.0);
        let summary = TransactionSummary {
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
            response_status_code: StatusCode::OK.as_u16(),
            latency_total_ms: total_ms,
            latency_gateway_processing_ms: total_ms,
            latency_backend_ttfb_ms: backend_connect_ms,
            latency_backend_total_ms: -1.0,
            latency_plugin_execution_ms: plugin_execution_ms,
            latency_plugin_external_io_ms: plugin_external_io_ms,
            latency_gateway_overhead_ms: gateway_overhead_ms,
            request_user_agent: ctx.headers.get("user-agent").cloned(),
            metadata: ctx.metadata.clone(),
            ..TransactionSummary::default()
        };
        crate::plugins::log_with_mirror(plugins, &summary, ctx).await;
    }

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
