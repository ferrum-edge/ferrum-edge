//! Local raw-TCP Sidecar inbound relay.
//!
//! When Sidecar inbound TLS is disabled or absent in permissive mode, the
//! inbound listener can receive REDIRECT-captured plaintext TCP for local
//! stream-family app ports. Those bytes are not HTTP, so the accept loop routes
//! them here before Hyper parsing and relays directly to the prepared loopback
//! backend selected by the captured original-destination port.
//!
//! L4 policy (TCP `AuthorizationPolicy` / fault / rate-limit stream hooks) is
//! enforced HERE, before connecting to loopback: this captured plaintext stream
//! is itself the destination-side policy point (unlike mesh egress, which is
//! authorized by the destination's inbound CONNECT). The `on_stream_connect`
//! chain runs with the captured APP port as the stream destination so a
//! `destination.port`-scoped DENY targeting e.g. the Redis port is evaluated; a
//! `Reject` closes the connection without ever relaying to the app.
//!
//! Because the global TCP plugin chain runs here, this handler mirrors the
//! generic TCP proxy's stream lifecycle so stateful plugins behave correctly:
//! it conditionally peeks the opening client bytes (and the ClientHello SNI for
//! opaque-TLS app ports) BEFORE `on_stream_connect`, and it always builds a
//! `StreamTransactionSummary` and runs `on_stream_disconnect` once the
//! connection ends or fails. Without the disconnect pairing, per-connection
//! plugin state (e.g. `tcp_connection_throttle`'s active-count increment, stored
//! in connection metadata) would leak on every admitted connection.

use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{ProxyState, tcp_proxy};
use crate::consumer_index::ConsumerIndex;
use crate::modes::mesh::MeshTrafficDirection;
use crate::plugins::{
    DisconnectCause, PluginResult, ProxyProtocol, StreamBytesKind, StreamConnectionContext,
    StreamTransactionSummary,
};
use crate::request_epoch::RequestEpoch;
use crate::router_cache::MeshTcpInboundEntry;

pub(crate) async fn handle_mesh_tcp_inbound(
    client_stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    state: &Arc<ProxyState>,
    epoch: &RequestEpoch,
    entry: &Arc<MeshTcpInboundEntry>,
    orig_dst: std::net::SocketAddr,
) {
    let proxy = entry.relay_proxy.as_ref();
    // The captured app/container port (== `orig_dst.port()`, the loopback
    // backend port) is the L4 authorization destination, NOT the shared
    // `:15006` capture-listener port. `mesh_authz`'s stream path reads
    // `ctx.listen_port`, so stamping the app port here lets a port-scoped
    // AuthorizationPolicy DENY on the real service port be enforced.
    let app_port = proxy.backend_port;
    let client_ip = remote_addr.ip().to_canonical().to_string();
    let backend_target = entry.backend_addr.to_string();

    // Run the L4 stream plugin chain (mesh `on_stream_connect` hooks: authz,
    // fault, rate-limit) BEFORE dialing loopback. The synthesized relay proxy
    // is never in `config.proxies`, so the plugin cache resolves the GLOBAL
    // TCP-protocol chain via its global fallback — which carries the
    // mesh-injected `__mesh_authz` global. A `Reject` closes the captured
    // connection (drop) instead of relaying to the app.
    let plugins =
        epoch
            .plugin_cache
            .plugins_for_protocol(&proxy.namespace, &proxy.id, ProxyProtocol::Tcp);

    // No global TCP chain resolved: relay immediately. There is no plugin state
    // to track and no policy to evaluate, so the connect/disconnect lifecycle is
    // a no-op and we skip building a summary that nothing consumes.
    if plugins.is_empty() {
        relay_to_loopback(client_stream, state, entry, orig_dst, &client_ip).await;
        return;
    }

    // Smallest opening-byte prefix any first-bytes-aware plugin needs (e.g. the
    // 6-byte TLS record + handshake-type prefix the `tcp_require_tls` shape guard
    // inspects). Mirrors `tcp_proxy::handle_tcp_connection_inner`'s plaintext
    // peek tier; `0` for signature-only configs keeps the single-peek behavior.
    let scan_first_bytes = plugins.iter().any(|p| p.requires_stream_first_bytes());
    let first_bytes_min_len = if scan_first_bytes {
        plugins
            .iter()
            .map(|p| p.stream_first_bytes_min_len())
            .max()
            .unwrap_or(0)
    } else {
        0
    };

    // Bound the SNI / first-bytes peek by the frontend handshake clock so a peer
    // that connects and never speaks cannot park this task. `0` keeps the
    // historical "no timeout" single-peek behavior. Reused for both peeks below.
    let peek_timeout = if state.env_config.frontend_tls_handshake_timeout_seconds > 0 {
        Some(std::time::Duration::from_secs(
            state.env_config.frontend_tls_handshake_timeout_seconds,
        ))
    } else {
        None
    };

    // Opaque-TLS app ports (`AppProtocol::Tls`) materialize a raw-TCP inbound
    // route too (the captured original destination selects the destination
    // service, not SNI). For those the captured plaintext bytes are a real TLS
    // ClientHello, so an `AuthorizationPolicy` using `when: connection.sni` needs
    // the SNI populated before `on_stream_connect`. The peek is gated on the
    // route's opaque-TLS classification (`entry.tls_inspect`), NOT attempted for
    // every captured connection: server-first stream ports (Redis/MySQL/Postgres/
    // Mongo/plain TCP) send NO client bytes until the backend greeting, so a peek
    // there would block on the handshake clock (up to the frontend handshake
    // timeout, indefinitely when `0`) BEFORE the loopback dial — stalling every
    // such inbound connection. TLS ports speak first (the ClientHello), so the
    // peek there resolves immediately and matches the TCP passthrough path, which
    // only peeks ClientHello-first listeners.
    let sni_hostname = if entry.tls_inspect {
        super::sni::extract_sni_from_tcp_stream(&client_stream, peek_timeout).await
    } else {
        None
    };

    // Capture the opening client bytes when a first-bytes-aware plugin (stream
    // WAF, `tcp_require_tls`) is configured, so it inspects the same opening
    // prefix it would see on the generic TCP proxy. The peek is non-destructive;
    // the relay re-reads the same bytes.
    //
    // FIRST-BYTES GATE: only pre-dial peek when mesh has an explicit
    // client-first signal (opaque TLS). Ambiguous raw TCP and known server-first
    // protocols (Redis/Mongo/MySQL/Postgres) may not send client bytes until
    // the backend greeting, and peeking would park the relay on the handshake
    // clock before loopback is dialed.
    //
    // The byte-kind mirrors the generic TCP proxy's wire classification: this
    // handler NEVER terminates TLS (it relays the captured stream verbatim to
    // loopback), so the two cases are plaintext-wire vs encrypted-wire, never
    // `DecryptedApp`. For opaque-TLS app ports (`entry.tls_inspect`) the captured
    // prefix is a real TLS ClientHello the gateway never decrypts, so it is only
    // good for transport-shape checks (e.g. `tcp_require_tls` ClientHello shape)
    // — `EncryptedWire`, matching the passthrough branch. Marking it
    // `PlaintextWire` would tell a signature plugin like WAF `inspect_tcp` that
    // ciphertext handshake bytes are L7-inspectable, producing false
    // matches/blocks.
    let (first_bytes, first_bytes_kind) = if scan_first_bytes {
        if entry.first_bytes_inspect {
            let bytes =
                tcp_proxy::peek_tcp_first_bytes(&client_stream, peek_timeout, first_bytes_min_len)
                    .await;
            let kind = if entry.tls_inspect {
                StreamBytesKind::EncryptedWire
            } else {
                StreamBytesKind::PlaintextWire
            };
            (bytes, Some(kind))
        } else {
            // Known server-first protocols: do not block on client bytes pre-dial.
            (None, Some(StreamBytesKind::PlaintextWire))
        }
    } else {
        (None, None)
    };

    let consumer_index = Arc::new(ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index)));
    let mut stream_ctx = StreamConnectionContext::new(
        client_ip.clone(),
        // Mesh sidecar inbound relay never uses PROXY protocol (mesh peers speak
        // plain mTLS-HTTP or raw TCP over mesh tunnels, not PROXY protocol).
        // direct_client_ip always equals client_ip for mesh inbound connections.
        client_ip.clone(),
        proxy.id.clone(),
        proxy.name.clone(),
        // Authorize on the captured app port, not the capture listener.
        app_port,
        proxy.effective_scheme(),
        consumer_index,
    );
    stream_ctx.proxy_namespace = proxy.namespace.clone();
    stream_ctx.proxy_lifecycle_generation = epoch
        .plugin_cache
        .proxy_lifecycle_generation(&proxy.namespace, &proxy.id);
    // Populated above for opaque-TLS captures; `None` for raw-TCP streams.
    stream_ctx.sni_hostname = sni_hostname;
    // Captured plaintext Sidecar inbound is, by direction, inbound mesh
    // traffic — so `mesh_authz` treats `listen_port` as the inbound
    // destination port (parity with the materialized HTTP inbound path).
    stream_ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    // The constructor intentionally leaves per-pod scope absent because
    // Sidecar topology never installs the node-waypoint resolver;
    // `mesh_authz` evaluates mesh-wide + namespace/selector policies against
    // the connection identity.
    // Populate the first-byte snapshot captured above before hooks run.
    stream_ctx.first_bytes = first_bytes;
    stream_ctx.first_bytes_kind = first_bytes_kind;

    let connected_wall_at = chrono::Utc::now();
    let connected_at = std::time::Instant::now();

    for plugin in plugins.iter() {
        if let PluginResult::Reject { .. } = plugin.on_stream_connect(&mut stream_ctx).await {
            stream_ctx.release_admission_permits();
            debug!(
                service = %entry.service_fqdn,
                orig_dst = %orig_dst,
                app_port,
                client_ip = %client_ip,
                "Sidecar raw-TCP inbound connection rejected by stream policy; closing \
                 captured connection without relaying to loopback"
            );
            // The connection was admitted into the plugin chain, so any plugin
            // that allocated per-connection state before the rejecting one (e.g.
            // `tcp_connection_throttle`'s active count) must be released. Emit a
            // zero-byte disconnect summary attributed as a policy reject, NOT a
            // clean close: the generic TCP path wraps the same `on_stream_connect`
            // reject as `StreamSetupKind::RejectedByPlugin`, which it classifies
            // as a client-side `ErrorClass::RequestError` with a
            // `ClientToBackend` direction and a `RecvError` disconnect cause (see
            // `classify_stream_setup_kind` and `pre_copy_disconnect_{cause,
            // direction}`). Mirror that here so `record_stream_transaction`
            // counts the deny (it only records a failure when `error_class` is
            // present) instead of logging a zero-byte graceful close. The
            // `connection_error` text matches the generic path's
            // `STREAM_ERR_REJECTED_BY_PLUGIN` prefix so log consumers see
            // consistent wording across the two stream paths.
            emit_disconnect(
                &plugins,
                &mut stream_ctx,
                proxy,
                &client_ip,
                backend_target.clone(),
                connected_wall_at,
                connected_at,
                0,
                0,
                Some(tcp_proxy::STREAM_ERR_REJECTED_BY_PLUGIN.to_string()),
                Some(crate::retry::ErrorClass::RequestError),
                Some(crate::plugins::Direction::ClientToBackend),
                Some(DisconnectCause::RecvError),
            )
            .await;
            return;
        }
    }

    let connect = TcpStream::connect(entry.backend_addr);
    let backend_stream = if proxy.backend_connect_timeout_ms == 0 {
        connect.await
    } else {
        match tokio::time::timeout(
            std::time::Duration::from_millis(proxy.backend_connect_timeout_ms),
            connect,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    service = %entry.service_fqdn,
                    orig_dst = %orig_dst,
                    backend = %entry.backend_addr,
                    client_ip = %client_ip,
                    "Sidecar raw-TCP inbound loopback connect timed out; closing captured connection"
                );
                emit_disconnect(
                    &plugins,
                    &mut stream_ctx,
                    proxy,
                    &client_ip,
                    backend_target.clone(),
                    connected_wall_at,
                    connected_at,
                    0,
                    0,
                    Some("loopback connect timed out".to_string()),
                    Some(crate::retry::ErrorClass::ConnectionTimeout),
                    None,
                    Some(DisconnectCause::BackendError),
                )
                .await;
                return;
            }
        }
    };
    let backend_stream = match backend_stream {
        Ok(stream) => stream,
        Err(error) => {
            warn!(
                service = %entry.service_fqdn,
                orig_dst = %orig_dst,
                backend = %entry.backend_addr,
                client_ip = %client_ip,
                error = %error,
                "Sidecar raw-TCP inbound loopback connect failed; closing captured connection"
            );
            emit_disconnect(
                &plugins,
                &mut stream_ctx,
                proxy,
                &client_ip,
                backend_target.clone(),
                connected_wall_at,
                connected_at,
                0,
                0,
                Some(error.to_string()),
                Some(crate::retry::ErrorClass::ConnectionRefused),
                None,
                Some(DisconnectCause::BackendError),
            )
            .await;
            return;
        }
    };

    debug!(
        service = %entry.service_fqdn,
        orig_dst = %orig_dst,
        backend = %entry.backend_addr,
        client_ip = %client_ip,
        "Relaying captured sidecar raw-TCP inbound connection to loopback app"
    );
    let buffer_size = state
        .adaptive_buffer
        .get_buffer_size(&proxy.namespace, &proxy.id);
    let result = tcp_proxy::bidirectional_copy_for_relay(
        client_stream,
        backend_stream,
        super::hbone_proxy::proxy_idle_timeout(proxy, &state.env_config),
        super::hbone_proxy::proxy_half_close_cap(&state.env_config),
        super::hbone_proxy::backend_read_timeout(proxy),
        super::hbone_proxy::backend_write_timeout(proxy),
        buffer_size,
    )
    .await;
    state.adaptive_buffer.record_connection(
        &proxy.namespace,
        &proxy.id,
        result
            .bytes_client_to_backend
            .saturating_add(result.bytes_backend_to_client),
    );
    // Map the first half-failure (if any) to the same typed direction/class/cause
    // the generic TCP proxy records; a clean two-sided EOF is a graceful
    // shutdown.
    let (connection_error, error_class, disconnect_direction, disconnect_cause) =
        match result.first_failure.as_ref() {
            Some((direction, class, side, message)) => {
                warn!(
                    service = %entry.service_fqdn,
                    proxy_id = %proxy.id,
                    direction = ?direction,
                    io_side = ?side,
                    error_class = %class,
                    error = %message,
                    bytes_in = result.bytes_client_to_backend,
                    bytes_out = result.bytes_backend_to_client,
                    "Sidecar raw-TCP inbound relay failed"
                );
                (
                    Some(message.clone()),
                    Some(*class),
                    Some(*direction),
                    Some(tcp_proxy::disconnect_cause_for_failure(
                        *direction, class, *side,
                    )),
                )
            }
            None => {
                debug!(
                    service = %entry.service_fqdn,
                    bytes_in = result.bytes_client_to_backend,
                    bytes_out = result.bytes_backend_to_client,
                    "Sidecar raw-TCP inbound relay completed"
                );
                (None, None, None, Some(DisconnectCause::GracefulShutdown))
            }
        };

    emit_disconnect(
        &plugins,
        &mut stream_ctx,
        proxy,
        &client_ip,
        backend_target,
        connected_wall_at,
        connected_at,
        result.bytes_client_to_backend,
        result.bytes_backend_to_client,
        connection_error,
        error_class,
        disconnect_direction,
        disconnect_cause,
    )
    .await;
}

/// Relay the captured plaintext stream to the loopback backend without any
/// stream plugin lifecycle. Used only when no global TCP chain resolved, so
/// there is nothing to authorize or to track per connection.
async fn relay_to_loopback(
    client_stream: TcpStream,
    state: &Arc<ProxyState>,
    entry: &Arc<MeshTcpInboundEntry>,
    orig_dst: std::net::SocketAddr,
    client_ip: &str,
) {
    let proxy = entry.relay_proxy.as_ref();
    let connect = TcpStream::connect(entry.backend_addr);
    let backend_stream = if proxy.backend_connect_timeout_ms == 0 {
        connect.await
    } else {
        match tokio::time::timeout(
            std::time::Duration::from_millis(proxy.backend_connect_timeout_ms),
            connect,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    service = %entry.service_fqdn,
                    orig_dst = %orig_dst,
                    backend = %entry.backend_addr,
                    client_ip = %client_ip,
                    "Sidecar raw-TCP inbound loopback connect timed out; closing captured connection"
                );
                return;
            }
        }
    };
    let backend_stream = match backend_stream {
        Ok(stream) => stream,
        Err(error) => {
            warn!(
                service = %entry.service_fqdn,
                orig_dst = %orig_dst,
                backend = %entry.backend_addr,
                client_ip = %client_ip,
                error = %error,
                "Sidecar raw-TCP inbound loopback connect failed; closing captured connection"
            );
            return;
        }
    };

    debug!(
        service = %entry.service_fqdn,
        orig_dst = %orig_dst,
        backend = %entry.backend_addr,
        client_ip = %client_ip,
        "Relaying captured sidecar raw-TCP inbound connection to loopback app"
    );
    let buffer_size = state
        .adaptive_buffer
        .get_buffer_size(&proxy.namespace, &proxy.id);
    let result = tcp_proxy::bidirectional_copy_for_relay(
        client_stream,
        backend_stream,
        super::hbone_proxy::proxy_idle_timeout(proxy, &state.env_config),
        super::hbone_proxy::proxy_half_close_cap(&state.env_config),
        super::hbone_proxy::backend_read_timeout(proxy),
        super::hbone_proxy::backend_write_timeout(proxy),
        buffer_size,
    )
    .await;
    state.adaptive_buffer.record_connection(
        &proxy.namespace,
        &proxy.id,
        result
            .bytes_client_to_backend
            .saturating_add(result.bytes_backend_to_client),
    );
    if let Some((direction, class, side, message)) = result.first_failure.as_ref() {
        warn!(
            service = %entry.service_fqdn,
            proxy_id = %proxy.id,
            direction = ?direction,
            io_side = ?side,
            error_class = %class,
            error = %message,
            bytes_in = result.bytes_client_to_backend,
            bytes_out = result.bytes_backend_to_client,
            "Sidecar raw-TCP inbound relay failed"
        );
    } else {
        debug!(
            service = %entry.service_fqdn,
            bytes_in = result.bytes_client_to_backend,
            bytes_out = result.bytes_backend_to_client,
            "Sidecar raw-TCP inbound relay completed"
        );
    }
}

/// Build the `StreamTransactionSummary` and run the `on_stream_disconnect`
/// chain. Mirrors `tcp_proxy`'s accept-loop disconnect path so admission permits
/// release before observers run, stateful observers flush per connection, and
/// RST/transaction runtime metrics are recorded for captured inbound streams too.
#[allow(clippy::too_many_arguments)]
async fn emit_disconnect(
    plugins: &[Arc<dyn crate::plugins::Plugin>],
    stream_ctx: &mut StreamConnectionContext,
    proxy: &crate::config::types::Proxy,
    client_ip: &str,
    backend_target: String,
    connected_wall_at: chrono::DateTime<chrono::Utc>,
    connected_at: std::time::Instant,
    bytes_sent: u64,
    bytes_received: u64,
    connection_error: Option<String>,
    error_class: Option<crate::retry::ErrorClass>,
    disconnect_direction: Option<crate::plugins::Direction>,
    disconnect_cause: Option<DisconnectCause>,
) {
    // The relay (or setup attempt) has ended. Do not retain admission capacity
    // while asynchronous disconnect observers flush logs and metrics.
    stream_ctx.release_admission_permits();
    let disconnected_wall_at = chrono::Utc::now();
    let summary = StreamTransactionSummary {
        namespace: proxy.namespace.clone(),
        proxy_id: proxy.id.clone(),
        proxy_lifecycle_generation: stream_ctx.proxy_lifecycle_generation,
        proxy_name: proxy.name.clone(),
        client_ip: client_ip.to_string(),
        consumer_username: stream_ctx.effective_identity().map(str::to_owned),
        auth_method: stream_ctx.auth_method,
        backend_target,
        backend_resolved_ip: None,
        protocol: proxy.effective_scheme().to_string(),
        listen_port: stream_ctx.listen_port,
        duration_ms: connected_at.elapsed().as_secs_f64() * 1000.0,
        bytes_sent,
        bytes_received,
        connection_error,
        error_class,
        disconnect_direction,
        disconnect_cause,
        timestamp_connected: connected_wall_at.to_rfc3339(),
        timestamp_disconnected: disconnected_wall_at.to_rfc3339(),
        sni_hostname: stream_ctx.sni_hostname.clone(),
        metadata: stream_ctx.take_metadata(),
    };
    crate::runtime_metrics::global_ref().record_stream_transaction(&summary);
    if summary.error_class == Some(crate::retry::ErrorClass::ConnectionReset)
        && let Some(direction) = summary.disconnect_direction
    {
        crate::runtime_metrics::global_ref().record_tcp_rst(&summary.proxy_id, direction);
    }
    for plugin in plugins.iter() {
        plugin.on_stream_disconnect(&summary).await;
    }
}
