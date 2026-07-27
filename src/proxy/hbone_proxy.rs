//! HBONE CONNECT relay transport.
//!
//! Mesh mode identifies HBONE in the main proxy path, then delegates the
//! backend connection, circuit-breaker accounting, relay task, and logging here.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

use super::{
    ClientRequestBody, LoadBalancerConnectionGuard, ProxyBody, ProxyState, backend_dispatch,
    build_response, build_response_from_normalized_reject,
    finalize_reject_response_with_after_proxy_hooks, inbound_hbone_relay_destination_allowed,
    log_rejected_request, record_request, tcp_proxy,
};
use crate::config::EnvConfig;
use crate::config::env_config::OperatingMode;
use crate::config::types::{Proxy, UpstreamTarget};
use crate::ebpf::NODE_WAYPOINT_INBOUND_AUTH_MARK;
use crate::load_balancer::LoadBalancerCache;
use crate::modes::mesh::MESH_INBOUND_HBONE_RELAY_PROXY_ID;
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

struct HboneUdpSocketOpenError {
    phase: &'static str,
    body: &'static [u8],
    message: String,
}

pub(super) fn tag_request_metadata(ctx: &mut RequestContext) {
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    ctx.metadata.insert(
        "connection_security_policy".to_string(),
        "hbone".to_string(),
    );
}

/// Metadata sub-key marking an HBONE CONNECT as the datagram (UDP) variant.
/// Carried ALONGSIDE `request_protocol = "hbone"` (not in place of it) so every
/// policy/authz consumer that exact-matches `request_protocol == "hbone"`
/// (`mesh_authz::is_hbone_request`, `workload_metrics`, `hmac_auth`) still
/// honors the HBONE CONNECT for a `udp`-marked tunnel — UDP HBONE must never be
/// weaker than byte-stream HBONE for authz. Only observability surfaces that
/// want to distinguish the datagram tunnel read this sub-key (codex r5 P1).
pub(super) use crate::modes::mesh::hbone::HBONE_DATAGRAM_METADATA_KEY;

/// Tag metadata for a datagram-over-HBONE CONNECT (F3 §3.3 Stage 4). It rides
/// the SAME SVID-mTLS H2 CONNECT as the byte-stream relay, so it keeps
/// `request_protocol = "hbone"` (NOT a distinct `"hbone-udp"`): consumers that
/// exact-match `request_protocol == "hbone"` — notably `mesh_authz` /
/// `is_hbone_request` — MUST recognize the UDP variant as HBONE, or a
/// `udp`-marked CONNECT would bypass HBONE-specific validation. The
/// datagram-ness is carried on a SEPARATE [`HBONE_DATAGRAM_METADATA_KEY`] that
/// only observability reads; the relay-dispatch branch keys off
/// `is_udp_hbone_connect` (the wire marker), not this metadata (codex r5 P1).
pub(super) fn tag_udp_request_metadata(ctx: &mut RequestContext) {
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    ctx.metadata.insert(
        "connection_security_policy".to_string(),
        "hbone".to_string(),
    );
    ctx.metadata
        .insert(HBONE_DATAGRAM_METADATA_KEY.to_string(), "udp".to_string());
}

pub(super) fn is_connect_request<B>(req: &Request<B>, env_config: &EnvConfig) -> bool {
    env_config.mode == OperatingMode::Mesh
        && req.extensions().get::<hyper::ext::Protocol>().is_none()
        && crate::modes::mesh::hbone::is_hbone_connect(req.method(), req.version(), req.headers())
}

/// Whether `req` is a datagram-over-HBONE CONNECT (F3 §3.3 Stage 4): a bare
/// HTTP/2 CONNECT (no `:protocol` extension) in mesh mode carrying the EXPLICIT
/// `x-ferrum-mesh-protocol: udp` marker. Mutually exclusive with
/// [`is_connect_request`] (which matches the `hbone`/marker-less byte-stream
/// shape): a `udp`-marked CONNECT is NOT an `is_connect_request` (its marker is
/// not `hbone`), so the two never both fire for one request.
pub(super) fn is_udp_connect_request<B>(req: &Request<B>, env_config: &EnvConfig) -> bool {
    env_config.mode == OperatingMode::Mesh
        && req.extensions().get::<hyper::ext::Protocol>().is_none()
        && crate::modes::mesh::hbone::is_udp_hbone_connect(
            req.method(),
            req.version(),
            req.headers(),
        )
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
        proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
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
    let (host, port) = effective_hbone_backend_target(proxy, upstream_target);
    let target_url = format!("tcp://{host}:{port}");

    // Honor DestinationRule per-port `connect_timeout_ms` overrides on the
    // HBONE (ambient mesh) path. Single field read from the precomputed map.
    let effective_connect_timeout_ms = proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|m| m.get(&port))
        .and_then(|override_config| override_config.connect_timeout_ms)
        .unwrap_or(proxy.backend_connect_timeout_ms);

    let candidates = state
        .dns_cache
        .resolve_candidates(
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
    let socket_mark = (proxy.id == MESH_INBOUND_HBONE_RELAY_PROXY_ID
        && node_waypoint_inbound_relay_mark_enabled())
    .then_some(NODE_WAYPOINT_INBOUND_AUTH_MARK);
    let timeout = Duration::from_millis(effective_connect_timeout_ms);
    let (stream, addr) = match crate::dns::connect_candidates(&candidates, port, timeout, |addr| {
        crate::socket_opts::connect_with_socket_opts_and_mark(addr, socket_mark)
    })
    .await
    {
        Ok(connected) => connected,
        Err(crate::dns::CandidateConnectError::Failed {
            last_addr,
            source: err,
        }) => {
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
                resolved_ip: Some(last_addr.ip().to_string()),
            });
        }
        Err(crate::dns::CandidateConnectError::TimedOut { last_addr }) => {
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
                resolved_ip: Some(last_addr.ip().to_string()),
            });
        }
    };

    let _ = stream.set_nodelay(true);

    Ok(HboneBackendConnection {
        stream,
        target_url,
        resolved_ip: Some(addr.ip().to_string()),
    })
}

fn effective_hbone_backend_target<'a>(
    proxy: &'a Proxy,
    upstream_target: Option<&'a UpstreamTarget>,
) -> (&'a str, u16) {
    upstream_target
        .map(|target| (target.host.as_str(), target.port))
        .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port))
}

fn inbound_hbone_relay_effective_destination_allowed(
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
    mesh: Option<&crate::modes::mesh::config::MeshConfig>,
) -> bool {
    let (app_host, app_port) = effective_hbone_backend_target(proxy, upstream_target);
    inbound_hbone_relay_destination_allowed(app_host, app_port, mesh)
}

fn node_waypoint_inbound_relay_mark_enabled() -> bool {
    crate::config::conf_file::resolve_ferrum_var("FERRUM_MESH_TOPOLOGY").is_some_and(|topology| {
        matches!(
            topology.trim().to_ascii_lowercase().as_str(),
            "node_waypoint" | "node-waypoint"
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_hbone_request(
    state: &ProxyState,
    proxy: &Arc<Proxy>,
    epoch: &RequestEpoch,
    ctx: &mut RequestContext,
    is_tls: bool,
    mesh_inbound_pre_handshake_app_port: Option<u16>,
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
    ctx.proxy_lifecycle_generation = epoch
        .plugin_cache
        .proxy_lifecycle_generation(&proxy.namespace, &proxy.id);

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

    let selection = backend_dispatch::select_upstream_target(
        proxy,
        state,
        epoch,
        &ctx.client_ip,
        &ctx.headers,
        ctx.orig_dst,
    );
    let upstream_target = selection.target;
    let upstream_balancer = selection.balancer;

    if let Some(mismatch) = super::mesh_inbound_peer_auth_transport_mismatch(
        state,
        ctx.mesh_direction,
        mesh_inbound_pre_handshake_app_port,
        proxy,
        upstream_target.as_deref(),
        is_tls,
        ctx.tls_client_cert_der.is_some(),
    ) {
        return super::reject_mesh_inbound_peer_auth_transport_mismatch(
            state,
            plugins,
            ctx,
            proxy,
            mismatch,
            is_tls,
            false,
            start_time,
            plugin_execution_ns,
            "hbone_peer_auth_transport_mismatch",
            None,
        )
        .await;
    }

    if proxy.id == MESH_INBOUND_HBONE_RELAY_PROXY_ID
        && !inbound_hbone_relay_effective_destination_allowed(
            proxy,
            upstream_target.as_deref(),
            epoch.config.mesh.as_deref(),
        )
    {
        let (app_host, app_port) =
            effective_hbone_backend_target(proxy, upstream_target.as_deref());
        warn!(
            proxy_id = %proxy.id,
            app_host,
            app_port,
            "Rejected HBONE CONNECT whose effective destination is outside the open-relay guard"
        );
        ctx.metadata.insert(
            "mesh_authz.deny_policy".to_string(),
            "hbone_relay_destination_denied".to_string(),
        );
        let reject = finalize_reject_response_with_after_proxy_hooks(
            plugins,
            ctx,
            StatusCode::FORBIDDEN,
            br#"{"error":"HBONE relay destination not allowed"}"#,
            HashMap::new(),
            false,
        )
        .await;
        log_rejected_request(
            plugins,
            ctx,
            reject.http_status.as_u16(),
            start_time,
            "hbone_relay_destination_denied",
            plugin_execution_ns,
        )
        .await;
        record_request(state, reject.http_status.as_u16());
        return build_response_from_normalized_reject(reject);
    }

    // HBONE records the circuit-breaker outcome at header time (its `StreamingH2`
    // responses are excluded from the deferred-dispatch path, #1649), so the
    // admission open-epoch is unused here.
    let (cb_target_key, cb_is_half_open_probe, _cb_admission_open_epoch) =
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
                    &proxy.namespace,
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
            &proxy.namespace,
            &proxy.id,
            cb_target_key.as_deref(),
            cb_config,
        );
        cb.record_success(cb_is_half_open_probe);
    }
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, upstream_target.as_deref())
        && let Some(upstream) = LoadBalancerCache::get_upstream_from(
            &epoch.load_balancer,
            &proxy.namespace,
            upstream_id,
        )
    {
        let passive = backend_dispatch::passive_health_for_target(proxy, &upstream, target);
        state.health_checker.report_response(
            &proxy.namespace,
            &proxy.id,
            upstream_id,
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
    let relay_buffer_size = adaptive_buffer.get_buffer_size(&proxy.namespace, &proxy.id);
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
                    &relay_proxy.namespace,
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

/// Destination-side handler for a datagram-over-HBONE CONNECT (F3 §3.3 Stage 4).
///
/// The source gateway opened a `udp`-marked CONNECT whose `:authority` is the
/// destination workload's UDP app `host:port`. This handler:
/// 1. requires an authenticated mesh peer (same trust boundary as the byte-stream
///    relay — a marker alone never authorizes a tunnel);
/// 2. opens a LOCAL `UdpSocket` connected to the CONNECT authority (the open-relay
///    guard already bounded the authority to a loopback / slice-known workload
///    addr+port when the synthesized relay proxy was built);
/// 3. on upgrade, runs two tasks over the tunnel: tunnel → unframe → `socket.send`
///    (datagram to the local app) and `socket.recv` → frame → tunnel (reply back).
///
/// Unlike the byte-stream relay there is NO TCP backend connect, circuit breaker,
/// or load balancer — the destination is a single local UDP socket. Backend dial
/// failure (bind/connect) fails closed with a 502 before the 200 CONNECT response.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_hbone_udp_request(
    state: &ProxyState,
    proxy: &Arc<Proxy>,
    epoch: &RequestEpoch,
    ctx: &mut RequestContext,
    is_tls: bool,
    mesh_inbound_pre_handshake_app_port: Option<u16>,
    client_request_body: ClientRequestBody,
    plugins: &[Arc<dyn Plugin>],
    start_time: Instant,
    method: &str,
    plugin_execution_ns: u64,
) -> Response<ProxyBody> {
    let proxy_arc = ctx
        .apply_route_overrides_with_upstreams(Arc::clone(proxy), epoch.load_balancer.upstreams());
    let proxy: &Arc<Proxy> = &proxy_arc;
    ctx.matched_proxy = Some(Arc::clone(proxy));
    ctx.proxy_lifecycle_generation = epoch
        .plugin_cache
        .proxy_lifecycle_generation(&proxy.namespace, &proxy.id);

    // Same trust boundary as the byte-stream relay: only an authenticated,
    // trust-domain-verified mesh peer may open a datagram tunnel into a local
    // socket. A bare/`udp`-marked CONNECT from an unauthenticated peer is
    // rejected before any socket is opened.
    if ctx.peer_spiffe_id.is_none() {
        warn!(
            proxy_id = %proxy.id,
            "Rejected datagram-over-HBONE CONNECT with no authenticated peer identity"
        );
        ctx.metadata.insert(
            "mesh_authz.deny_policy".to_string(),
            "hbone_udp_unauthenticated_peer".to_string(),
        );
        let reject = finalize_reject_response_with_after_proxy_hooks(
            plugins,
            ctx,
            StatusCode::FORBIDDEN,
            br#"{"error":"HBONE UDP tunnel requires an authenticated mesh peer"}"#,
            HashMap::new(),
            false,
        )
        .await;
        log_rejected_request(
            plugins,
            ctx,
            reject.http_status.as_u16(),
            start_time,
            "hbone_udp_unauthenticated_peer",
            plugin_execution_ns,
        )
        .await;
        record_request(state, reject.http_status.as_u16());
        return build_response_from_normalized_reject(reject);
    }

    // The CONNECT authority is the destination UDP app addr+port. For the
    // transparent inbound relay it is carried as the synthesized proxy's
    // backend_host:backend_port (already bounded by the open-relay guard); an
    // LB-selected target (route-override path) wins when present.
    let selection = backend_dispatch::select_upstream_target(
        proxy,
        state,
        epoch,
        &ctx.client_ip,
        &ctx.headers,
        ctx.orig_dst,
    );
    let upstream_target = selection.target;
    let (app_host, app_port) = upstream_target
        .as_deref()
        .map(|t| (t.host.as_str(), t.port))
        .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port));

    if let Some(mismatch) = super::mesh_inbound_peer_auth_transport_mismatch(
        state,
        ctx.mesh_direction,
        mesh_inbound_pre_handshake_app_port,
        proxy,
        upstream_target.as_deref(),
        is_tls,
        ctx.tls_client_cert_der.is_some(),
    ) {
        return super::reject_mesh_inbound_peer_auth_transport_mismatch(
            state,
            plugins,
            ctx,
            proxy,
            mismatch,
            is_tls,
            false,
            start_time,
            plugin_execution_ns,
            "hbone_udp_peer_auth_transport_mismatch",
            None,
        )
        .await;
    }

    if app_host.is_empty() || app_port == 0 {
        error!(proxy_id = %proxy.id, "HBONE UDP CONNECT has no resolvable local destination");
        let reject = finalize_reject_response_with_after_proxy_hooks(
            plugins,
            ctx,
            StatusCode::BAD_GATEWAY,
            br#"{"error":"HBONE UDP destination unresolved"}"#,
            HashMap::new(),
            false,
        )
        .await;
        log_rejected_request(
            plugins,
            ctx,
            reject.http_status.as_u16(),
            start_time,
            "hbone_udp_no_destination",
            plugin_execution_ns,
        )
        .await;
        record_request(state, reject.http_status.as_u16());
        return build_response_from_normalized_reject(reject);
    }

    // Re-run the open-relay guard on the EFFECTIVE (post-override) destination
    // (codex r6 P2). `build_inbound_hbone_relay_proxy` ran
    // `inbound_hbone_relay_destination_allowed` on the ORIGINAL CONNECT authority
    // when it synthesized the relay proxy, but a `before_proxy` route-override
    // plugin (e.g. a global `mesh_route_dispatch` — the synthesized relay proxy
    // has an unknown id, so it inherits the global plugin chain) can rewrite
    // `app_host`/`app_port` above via `apply_route_overrides_with_upstreams` +
    // `select_upstream_target`. Without re-checking, an authenticated peer could
    // ride a route override to open a local `UdpSocket` to a host/port outside
    // the loopback / slice-declared-workload allowlist. The un-overridden relay
    // destination was already guarded at build time, so this is a no-op for it.
    if !inbound_hbone_relay_destination_allowed(app_host, app_port, epoch.config.mesh.as_deref()) {
        warn!(
            proxy_id = %proxy.id,
            app_host,
            app_port,
            "Rejected datagram-over-HBONE CONNECT whose effective destination is outside the open-relay guard"
        );
        ctx.metadata.insert(
            "mesh_authz.deny_policy".to_string(),
            "hbone_udp_relay_destination_denied".to_string(),
        );
        let reject = finalize_reject_response_with_after_proxy_hooks(
            plugins,
            ctx,
            StatusCode::FORBIDDEN,
            br#"{"error":"HBONE UDP relay destination not allowed"}"#,
            HashMap::new(),
            false,
        )
        .await;
        log_rejected_request(
            plugins,
            ctx,
            reject.http_status.as_u16(),
            start_time,
            "hbone_udp_relay_destination_denied",
            plugin_execution_ns,
        )
        .await;
        record_request(state, reject.http_status.as_u16());
        return build_response_from_normalized_reject(reject);
    }

    // Extract the upgrade handle BEFORE building the 200 (the framed datagrams
    // ride the upgraded CONNECT body). Same invariant as the byte-stream relay:
    // the body must be streaming and carry an `OnUpgrade`.
    let on_upgrade = match client_request_body {
        ClientRequestBody::Streaming(request) => {
            let (mut parts, _body) = (*request).into_parts();
            match parts.extensions.remove::<OnUpgrade>() {
                Some(on_upgrade) => on_upgrade,
                None => {
                    return hbone_udp_internal_error(
                        state,
                        plugins,
                        ctx,
                        start_time,
                        plugin_execution_ns,
                        "hbone_udp_upgrade_missing",
                        br#"{"error":"HBONE UDP upgrade handle missing"}"#,
                    )
                    .await;
                }
            }
        }
        ClientRequestBody::Buffered(_) => {
            return hbone_udp_internal_error(
                state,
                plugins,
                ctx,
                start_time,
                plugin_execution_ns,
                "hbone_udp_request_buffered",
                br#"{"error":"HBONE UDP request buffering invariant violated"}"#,
            )
            .await;
        }
    };

    // Open a local UDP socket connected to the CONNECT authority. `connect`
    // pins the peer so `recv`/`send` only talk to that destination. Bind to the
    // unspecified address of the destination's family.
    // Timed from here so the transaction summary's backend-connect span covers
    // the DNS resolve + bind + connect, mirroring the byte-stream relay.
    let backend_start = Instant::now();
    let dest_candidates = match resolve_local_udp_dest(state, proxy, app_host).await {
        Ok(addresses) => addresses,
        Err((status, body, phase, message)) => {
            warn!(proxy_id = %proxy.id, error = %message, "HBONE UDP backend resolution failed");
            let reject = finalize_reject_response_with_after_proxy_hooks(
                plugins,
                ctx,
                status,
                body,
                HashMap::new(),
                false,
            )
            .await;
            log_rejected_request(
                plugins,
                ctx,
                reject.http_status.as_u16(),
                start_time,
                phase,
                plugin_execution_ns,
            )
            .await;
            record_request(state, reject.http_status.as_u16());
            return build_response_from_normalized_reject(reject);
        }
    };

    let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
    let (socket, dest_addr) = match crate::dns::connect_candidates(
        &dest_candidates,
        app_port,
        connect_timeout,
        |dest_addr| open_hbone_udp_relay_socket(state, dest_addr),
    )
    .await
    {
        Ok(connected) => connected,
        Err(crate::dns::CandidateConnectError::Failed { source, .. }) => {
            let error = source;
            warn!(proxy_id = %proxy.id, error = %error.message, "HBONE UDP local socket open failed");
            let reject = finalize_reject_response_with_after_proxy_hooks(
                plugins,
                ctx,
                StatusCode::BAD_GATEWAY,
                error.body,
                HashMap::new(),
                false,
            )
            .await;
            log_rejected_request(
                plugins,
                ctx,
                reject.http_status.as_u16(),
                start_time,
                error.phase,
                plugin_execution_ns,
            )
            .await;
            record_request(state, reject.http_status.as_u16());
            return build_response_from_normalized_reject(reject);
        }
        Err(crate::dns::CandidateConnectError::TimedOut { .. }) => {
            let error = HboneUdpSocketOpenError {
                phase: "hbone_udp_connect_timeout",
                body: br#"{"error":"HBONE UDP local socket connect timed out"}"#,
                message: format!(
                    "backend connect budget exhausted after {}ms",
                    proxy.backend_connect_timeout_ms
                ),
            };
            warn!(proxy_id = %proxy.id, error = %error.message, "HBONE UDP local socket open failed");
            let reject = finalize_reject_response_with_after_proxy_hooks(
                plugins,
                ctx,
                StatusCode::GATEWAY_TIMEOUT,
                error.body,
                HashMap::new(),
                false,
            )
            .await;
            log_rejected_request(
                plugins,
                ctx,
                reject.http_status.as_u16(),
                start_time,
                error.phase,
                plugin_execution_ns,
            )
            .await;
            record_request(state, reject.http_status.as_u16());
            return build_response_from_normalized_reject(reject);
        }
    };

    let backend_elapsed = backend_start.elapsed();

    // Observability parity with the byte-stream relay (`handle_hbone_request`):
    // record the transaction on BOTH the completion and the upgrade-failure
    // paths so a UDP HBONE tunnel surfaces the same runtime metrics + log hooks
    // a TCP one does (codex r5 P2). Clone the fields the spawned task needs.
    let relay_proxy_id = proxy.id.clone();
    let relay_method = method.to_string();
    let relay_ctx = ctx.clone();
    let relay_proxy = proxy.clone();
    let relay_plugins: Vec<Arc<dyn Plugin>> = plugins.to_vec();
    let relay_backend_target = format!("udp://{app_host}:{app_port}");
    let relay_backend_resolved_ip = Some(dest_addr.ip().to_string());
    let relay_start_time = start_time;
    let relay_backend_start = backend_start;
    let relay_backend_connect_ms = backend_elapsed.as_secs_f64() * 1000.0;
    let relay_plugin_execution_ns = plugin_execution_ns;
    // `udp_idle_timeout_seconds == 0` disables the idle window (None).
    let idle = relay_timeout(proxy.udp_idle_timeout_seconds);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                let (bytes_to_app, bytes_to_tunnel) = relay_hbone_udp(io, socket, idle).await;
                debug!(
                    proxy_id = %relay_proxy_id,
                    method = %relay_method,
                    bytes_in = bytes_to_app,
                    bytes_out = bytes_to_tunnel,
                    "HBONE UDP tunnel relay completed"
                );
                // The datagram relay ends cleanly on idle/EOF/peer-close; there
                // is no per-direction failure record (unlike the byte-stream
                // copy), so completion is body_completed=true / not a client
                // disconnect. `bytes_sent` is client→backend (tunnel→app).
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
                    bytes_to_app,
                    bytes_to_tunnel,
                    true,
                    false,
                    None,
                );
                // Runs unconditionally so runtime transaction metrics are always
                // recorded regardless of whether logging plugins are configured.
                crate::plugins::log_with_mirror(&relay_plugins, &summary, &relay_ctx).await;
            }
            Err(err) => {
                let error_class = retry::classify_boxed_error(&err);
                warn!(proxy_id = %relay_proxy_id, error = %err, "HBONE UDP client upgrade failed");
                // Derive client_disconnected from the error class rather than
                // assuming client fault (mirrors the byte-stream relay): an
                // OnUpgrade error can be a local/hyper-side failure.
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
                crate::plugins::log_with_mirror(&relay_plugins, &summary, &relay_ctx).await;
            }
        }
    });

    record_request(state, StatusCode::OK.as_u16());
    Response::builder()
        .status(StatusCode::OK)
        .body(ProxyBody::empty())
        .unwrap_or_else(|err| {
            error!(error = %err, "Failed to build HBONE UDP CONNECT response");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"Internal server error"}"#,
            )
        })
}

/// Resolve the CONNECT authority `host:port` to a concrete `SocketAddr` for the
/// local UDP dial (DNS via the shared cache; the relay destination is normally a
/// loopback / pod IP already). Returns a reject tuple on failure.
async fn resolve_local_udp_dest(
    state: &ProxyState,
    proxy: &Proxy,
    host: &str,
) -> Result<crate::dns::ResolvedAddresses, (StatusCode, &'static [u8], &'static str, String)> {
    state
        .dns_cache
        .resolve_candidates(
            host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                br#"{"error":"HBONE UDP destination DNS resolution failed"}"#.as_slice(),
                "hbone_udp_dns",
                e.to_string(),
            )
        })
}

async fn open_hbone_udp_relay_socket(
    state: &ProxyState,
    dest_addr: SocketAddr,
) -> Result<tokio::net::UdpSocket, HboneUdpSocketOpenError> {
    if let Some(std_socket) = maybe_bind_pod_netns_udp_relay_socket(state, dest_addr)? {
        return tokio::net::UdpSocket::from_std(std_socket).map_err(|e| HboneUdpSocketOpenError {
            phase: "hbone_udp_bind",
            body: br#"{"error":"HBONE UDP pod-netns socket adoption failed"}"#,
            message: e.to_string(),
        });
    }

    let bind_addr = match dest_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket =
        tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| HboneUdpSocketOpenError {
                phase: "hbone_udp_bind",
                body: br#"{"error":"HBONE UDP local socket bind failed"}"#,
                message: e.to_string(),
            })?;
    socket
        .connect(dest_addr)
        .await
        .map_err(|e| HboneUdpSocketOpenError {
            phase: "hbone_udp_connect",
            body: br#"{"error":"HBONE UDP local socket connect failed"}"#,
            message: e.to_string(),
        })?;
    Ok(socket)
}

#[cfg(target_os = "linux")]
fn maybe_bind_pod_netns_udp_relay_socket(
    state: &ProxyState,
    dest_addr: SocketAddr,
) -> Result<Option<std::net::UdpSocket>, HboneUdpSocketOpenError> {
    let Some(target) = registered_pod_target_for_udp_destination(
        &state.env_config.mesh_node_waypoint_pod_registry_dir,
        dest_addr.ip(),
    ) else {
        return Ok(None);
    };

    bind_pod_netns_udp_relay_socket(&target, dest_addr)
        .map(Some)
        .map_err(|e| HboneUdpSocketOpenError {
            phase: "hbone_udp_connect",
            body: br#"{"error":"HBONE UDP pod-netns local socket failed"}"#,
            message: e,
        })
}

#[cfg(not(target_os = "linux"))]
fn maybe_bind_pod_netns_udp_relay_socket(
    _state: &ProxyState,
    _dest_addr: SocketAddr,
) -> Result<Option<std::net::UdpSocket>, HboneUdpSocketOpenError> {
    Ok(None)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn registered_pod_target_for_udp_destination(
    registry_dir: &str,
    dest_ip: IpAddr,
) -> Option<super::netns_capture::PodCaptureTarget> {
    use super::netns_capture::PodCaptureSource;

    if dest_ip.is_loopback() {
        return None;
    }

    let source = super::netns_capture::DirectoryCaptureSource::new(registry_dir);
    source
        .list_targets()
        .into_iter()
        .find(|target| match dest_ip {
            IpAddr::V4(ip) => target.source_ips.ipv4 == Some(ip),
            IpAddr::V6(ip) => target.source_ips.ipv6 == Some(ip),
        })
}

#[cfg(target_os = "linux")]
fn bind_pod_netns_udp_relay_socket(
    target: &super::netns_capture::PodCaptureTarget,
    dest_addr: SocketAddr,
) -> Result<std::net::UdpSocket, String> {
    let expected_netns = super::netns_capture::netns_inode_for_cgroup(&target.cgroup_path)
        .map_err(|e| format!("resolve destination pod netns: {e}"))?;
    let netns = super::netns_capture::open_pod_netns_handle(&target.cgroup_path)
        .map_err(|e| format!("open destination pod netns: {e}"))?;
    let opened_netns = netns
        .metadata()
        .map(|m| std::os::unix::fs::MetadataExt::ino(&m))
        .map_err(|e| format!("stat destination pod netns: {e}"))?;
    if opened_netns != expected_netns {
        return Err(format!(
            "destination pod netns changed between registry scan and socket open \
             (expected {expected_netns}, opened {opened_netns})"
        ));
    }
    let host_netns =
        super::netns_capture::host_netns_inode().map_err(|e| format!("stat host netns: {e}"))?;
    if opened_netns == host_netns {
        return Err(
            "destination registry target resolves to the host/proxy netns; refusing host-netns UDP relay"
                .to_string(),
        );
    }

    super::netns_capture::run_in_netns(&netns, move || {
        let domain = match dest_addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        let bind_addr = match dest_addr {
            SocketAddr::V4(_) => "0.0.0.0:0"
                .parse::<SocketAddr>()
                .map_err(io::Error::other)?,
            SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>().map_err(io::Error::other)?,
        };
        socket.bind(&bind_addr.into())?;
        socket.connect(&dest_addr.into())?;
        Ok(socket.into())
    })
    .map_err(|e| format!("bind/connect destination pod-netns UDP socket: {e}"))
}

/// Fallback write deadline for a single framed app→tunnel `write_all` in
/// [`relay_hbone_udp`], used ONLY when the idle window is disabled
/// (`udp_idle_timeout_seconds == 0`). A stalled HBONE peer (stopped reading /
/// exhausted h2 flow-control) must not let the app→tunnel `write_all` stay
/// pending forever and pin the spawned relay task; bounding the write tears the
/// relay down instead. When an idle window IS configured, that window is reused
/// as the write deadline (a write blocked longer than the whole idle window is a
/// dead session anyway), so this only covers the idle-disabled case. Mirrors the
/// egress-side `EGRESS_TUNNEL_WRITE_DEADLINE` in `mesh_udp_capture.rs` (codex r3).
const HBONE_UDP_WRITE_DEADLINE: Duration = Duration::from_secs(30);

/// Two-way datagram relay between an upgraded `udp`-CONNECT tunnel (framed) and a
/// connected local `UdpSocket` (raw datagrams). Tunnel → unframe → `send`; `recv`
/// → frame → tunnel. Either direction ending (EOF, error) ends the relay; on
/// exit the tunnel write half is half-closed (h2 end-stream).
///
/// The idle window is refreshed on activity in **EITHER** direction — a shared
/// `last_activity` timestamp bumped by both the tunnel→app reads and the
/// app→tunnel reads, watched by a single watchdog (mirrors the plain UDP / DTLS
/// proxy's bidirectional keepalive). Without this a one-way flow (e.g.
/// telemetry/StatsD streaming tunnel→app while the app never replies) would time
/// out after `udp_idle_timeout_seconds` even though the tunnel is actively
/// delivering datagrams (codex r1 P2).
///
/// Each app→tunnel framed `write_all` is bounded by a write deadline (the idle
/// window when configured, else [`HBONE_UDP_WRITE_DEADLINE`]) so a stalled HBONE
/// peer cannot pin this task forever even with the idle watchdog disabled (codex
/// r3).
/// Returns the bytes relayed `(tunnel→app, app→tunnel)` — the datagram payload
/// totals (excluding the 2-byte frame prefix), used to build the transaction
/// summary so a completed UDP HBONE tunnel records the same observability as the
/// byte-stream relay (codex r5 P2).
async fn relay_hbone_udp<S>(
    tunnel: S,
    socket: tokio::net::UdpSocket,
    idle: Option<Duration>,
) -> (u64, u64)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use bytes::BytesMut;
    use std::sync::atomic::AtomicU64;
    use tokio::io::{AsyncWriteExt, split};

    let socket = Arc::new(socket);
    let (mut tunnel_read, mut tunnel_write) = split(tunnel);
    let max = crate::proxy::mesh_udp_frame::MAX_FRAME_PAYLOAD;
    // Datagram payload byte counters, bumped on each delivered datagram. Shared
    // (Arc) so the two relay arms can both report into them and the totals
    // survive the `select!` arm that drops the others.
    let bytes_tunnel_to_app = Arc::new(AtomicU64::new(0));
    let bytes_app_to_tunnel = Arc::new(AtomicU64::new(0));
    // Single framed-write deadline: reuse the idle window when configured, else a
    // fixed fallback so a stalled tunnel write can never hang forever (codex r3).
    // A write is ALWAYS bounded, even when the idle watchdog is disabled (`idle ==
    // None`) — which is exactly the case where an unbounded write would leak the
    // task.
    let write_deadline = idle.unwrap_or(HBONE_UDP_WRITE_DEADLINE);

    // Shared last-activity clock (monotonic millis — never rewinds under NTP
    // slew). Bumped on a delivered datagram in either direction; read by the
    // watchdog.
    let last_activity = Arc::new(AtomicU64::new(crate::socket_opts::monotonic_now_ms()));

    // Tunnel → local app: read framed datagrams off the tunnel and send each to
    // the connected destination socket. Activity here keeps the session alive.
    let send_socket = socket.clone();
    let to_app_activity = last_activity.clone();
    let to_app_bytes = bytes_tunnel_to_app.clone();
    let to_app = async move {
        let mut buf = BytesMut::with_capacity(max);
        while let Ok(Some(payload)) =
            crate::proxy::mesh_udp_frame::read_datagram(&mut tunnel_read, &mut buf).await
        {
            to_app_activity.store(
                crate::socket_opts::monotonic_now_ms(),
                std::sync::atomic::Ordering::Relaxed,
            );
            if send_socket.send(&payload).await.is_err() {
                break;
            }
            to_app_bytes.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
    };

    // Local app → tunnel: receive datagrams from the destination socket, frame
    // each, and write onto the tunnel. Activity here also keeps the session
    // alive; idle expiry is enforced by the shared watchdog below, not a
    // per-recv timeout (which would ignore tunnel→app activity).
    let from_app_activity = last_activity.clone();
    let from_app_bytes = bytes_app_to_tunnel.clone();
    let from_app = async move {
        let mut recv_buf = vec![0u8; max];
        let mut frame = BytesMut::with_capacity(2 + max);
        loop {
            let n = match socket.recv(&mut recv_buf).await {
                Ok(n) => n,
                Err(_) => break,
            };
            from_app_activity.store(
                crate::socket_opts::monotonic_now_ms(),
                std::sync::atomic::Ordering::Relaxed,
            );
            frame.clear();
            if crate::proxy::mesh_udp_frame::encode_datagram(&mut frame, &recv_buf[..n]).is_err() {
                continue;
            }
            // Bound the write: a stalled HBONE peer (stopped reading / h2
            // flow-control exhausted) must not pin this task forever, especially
            // when the idle watchdog is disabled (codex r3). On stall, tear the
            // relay down cleanly (break → tunnel half-close below).
            match tokio::time::timeout(write_deadline, tunnel_write.write_all(&frame)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => break,
                Err(_) => break, // write stalled past the deadline
            }
            from_app_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        let _ = tunnel_write.shutdown().await;
    };

    // Idle watchdog: ends the relay when neither direction has been active for
    // `idle`. `None` disables it (the future never resolves, so the two relay
    // arms drive). Polls at a fraction of the window (clamped 100ms..1s) so an
    // expiry fires within ~one poll of the deadline (mirrors the DTLS watchdog).
    let watchdog = async move {
        let Some(idle) = idle else {
            std::future::pending::<()>().await;
            return;
        };
        let idle_ms = idle.as_millis().min(u64::MAX as u128) as u64;
        let poll_ms = (idle_ms / 4).clamp(100, 1_000);
        let mut interval = tokio::time::interval(Duration::from_millis(poll_ms));
        loop {
            interval.tick().await;
            let last = last_activity.load(std::sync::atomic::Ordering::Relaxed);
            if crate::socket_opts::monotonic_now_ms().saturating_sub(last) > idle_ms {
                break;
            }
        }
    };

    tokio::select! {
        _ = to_app => {}
        _ = from_app => {}
        _ = watchdog => {}
    }

    (
        bytes_tunnel_to_app.load(std::sync::atomic::Ordering::Relaxed),
        bytes_app_to_tunnel.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// Shared INTERNAL_SERVER_ERROR reject for the HBONE UDP upgrade-handle
/// invariants (missing handle / buffered body), mirroring the byte-stream relay.
async fn hbone_udp_internal_error(
    state: &ProxyState,
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    start_time: Instant,
    plugin_execution_ns: u64,
    phase: &'static str,
    body: &'static [u8],
) -> Response<ProxyBody> {
    error!(phase, "HBONE UDP relay invariant violated");
    let reject = finalize_reject_response_with_after_proxy_hooks(
        plugins,
        ctx,
        StatusCode::INTERNAL_SERVER_ERROR,
        body,
        HashMap::new(),
        false,
    )
    .await;
    log_rejected_request(
        plugins,
        ctx,
        reject.http_status.as_u16(),
        start_time,
        phase,
        plugin_execution_ns,
    )
    .await;
    record_request(state, reject.http_status.as_u16());
    build_response_from_normalized_reject(reject)
}

#[cfg(test)]
mod tests {
    use super::{
        build_hbone_relay_summary, hbone_relay_body_outcome,
        inbound_hbone_relay_effective_destination_allowed,
        registered_pod_target_for_udp_destination,
    };
    use crate::config::types::{Proxy, UpstreamTarget};
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::modes::mesh::MESH_INBOUND_HBONE_RELAY_PROXY_ID;
    use crate::modes::mesh::config::{
        AppProtocol, MeshConfig, Workload, WorkloadPort, WorkloadSelector,
    };
    use crate::plugins::{Direction, RequestContext};
    use crate::proxy::tcp_proxy::{StreamFirstFailure, StreamIoSide};
    use crate::retry::ErrorClass;
    use std::collections::HashMap;
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

    fn target(host: &str, port: u16) -> UpstreamTarget {
        UpstreamTarget {
            host: host.to_string(),
            port,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }
    }

    fn mesh_with_workload_port(port: u16) -> MeshConfig {
        let mut mesh = MeshConfig::default();
        mesh.workloads.push(Workload {
            spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/default/sa/app").unwrap(),
            selector: WorkloadSelector::default(),
            service_name: "app".to_string(),
            addresses: vec!["10.1.2.3".to_string()],
            ports: vec![WorkloadPort {
                port,
                protocol: AppProtocol::Http,
                name: None,
            }],
            trust_domain: TrustDomain::new("cluster.local").unwrap(),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        });
        mesh
    }

    #[test]
    fn inbound_relay_effective_destination_guard_checks_route_override_target() {
        let mesh = mesh_with_workload_port(8080);
        let mut proxy = minimal_proxy();
        proxy.id = MESH_INBOUND_HBONE_RELAY_PROXY_ID.to_string();
        proxy.backend_host = "127.0.0.1".to_string();
        proxy.backend_port = 8080;

        assert!(inbound_hbone_relay_effective_destination_allowed(
            &proxy,
            None,
            Some(&mesh)
        ));
        assert!(inbound_hbone_relay_effective_destination_allowed(
            &proxy,
            Some(&target("127.0.0.1", 8080)),
            Some(&mesh)
        ));
        assert!(!inbound_hbone_relay_effective_destination_allowed(
            &proxy,
            Some(&target("203.0.113.10", 8080)),
            Some(&mesh)
        ));
        assert!(!inbound_hbone_relay_effective_destination_allowed(
            &proxy,
            Some(&target("127.0.0.1", 9999)),
            Some(&mesh)
        ));
    }

    #[test]
    fn udp_relay_registry_lookup_matches_destination_pod_ip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pod-a"),
            "/sys/fs/cgroup/pod-a\nipv4=10.0.0.5\nipv6=fd00::5\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pod-b"),
            "/sys/fs/cgroup/pod-b\nipv4=10.0.0.6\n",
        )
        .unwrap();

        let v4 = registered_pod_target_for_udp_destination(
            dir.path().to_str().unwrap(),
            "10.0.0.5".parse().unwrap(),
        )
        .expect("v4 pod target");
        assert_eq!(v4.pod_uid, "pod-a");

        let v6 = registered_pod_target_for_udp_destination(
            dir.path().to_str().unwrap(),
            "fd00::5".parse().unwrap(),
        )
        .expect("v6 pod target");
        assert_eq!(v6.pod_uid, "pod-a");

        assert!(
            registered_pod_target_for_udp_destination(
                dir.path().to_str().unwrap(),
                "127.0.0.1".parse().unwrap(),
            )
            .is_none(),
            "loopback relay destinations must stay in the current netns"
        );
        assert!(
            registered_pod_target_for_udp_destination(
                dir.path().to_str().unwrap(),
                "10.0.0.7".parse().unwrap(),
            )
            .is_none()
        );
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
