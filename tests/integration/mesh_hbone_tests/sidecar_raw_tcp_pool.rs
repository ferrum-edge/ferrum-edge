//! Pooled Sidecar raw-TCP egress against a real Ferrum destination
//! (issue #7537).
//!
//! The source side is the production `MeshMtlsConnectionPool::open_connect_tunnel`;
//! the destination is a real Ferrum mesh gateway terminating SPIFFE mTLS and
//! relaying each bare HTTP/2 CONNECT stream to a TCP backend — the same
//! terminator a peer sidecar's `:15006` listener runs. This proves the pooled
//! carriers interoperate with Ferrum's own inbound relay: tunnels share
//! connections up to the stream cap, every stream relays independently, and a
//! backend reset that the destination relay turns into `RST_STREAM` ends only
//! that tunnel.

use super::{
    create_mesh_proxy, create_mesh_proxy_state_with_config, create_mesh_proxy_state_with_env,
    mesh_env_config, spiffe_identity_plugin_config, spiffe_root, spiffe_svid_slot,
    start_gateway_mtls,
};
use crate::scaffolding::port_registry::TestSocket;

use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::PluginAssociation;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::proxy::hbone_pool::H2ConnectTunnel;
use ferrum_edge::proxy::mesh_mtls_pool::MeshMtlsConnectionPool;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const AUTHORITY_HOST: &str = "orders.default.svc.cluster.local";
const AUTHORITY_PORT: u16 = 8080;
const TIMEOUT: Duration = Duration::from_secs(15);

/// Multi-connection TCP echo backend. A connection whose first bytes are
/// `RESET` is closed with `SO_LINGER=0` (a TCP RST), the backend failure the
/// destination relay must surface as a reset of that one CONNECT stream; one
/// whose first bytes are `STALL` is never read again.
async fn start_resettable_echo_backend() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let addr = listener.local_addr().expect("echo backend addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_task = accepted.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            accepted_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if buf[..n].starts_with(b"STALL") {
                        // The application stops reading for good; keep the
                        // socket open so the relay's writes back up.
                        let _held = stream;
                        std::future::pending::<()>().await;
                        return;
                    }
                    if buf[..n].starts_with(b"RESET") {
                        let Ok(std_stream) = stream.into_std() else {
                            return;
                        };
                        let socket = socket2::Socket::from(std_stream);
                        let _ = socket.set_linger(Some(Duration::from_secs(0)));
                        drop(socket);
                        return;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, accepted, handle)
}

async fn echo(tunnel: &mut H2ConnectTunnel, payload: &[u8]) {
    tunnel.write_all(payload).await.expect("write tunnel");
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, tunnel.read_exact(&mut buf))
        .await
        .expect("timely relay echo")
        .expect("read relay echo");
    assert_eq!(buf, payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn sidecar_raw_tcp_tunnels_share_pooled_connections_through_a_ferrum_destination() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (root_der, root_pem, root_key_pem) = spiffe_root();
    let destination_id: SpiffeId = "spiffe://cluster.local/ns/default/sa/orders"
        .parse()
        .expect("destination id");
    let source_id: SpiffeId = "spiffe://cluster.local/ns/default/sa/client"
        .parse()
        .expect("source id");
    let destination_slot = spiffe_svid_slot(&destination_id, &root_der, &root_pem, &root_key_pem);
    let source_slot = spiffe_svid_slot(&source_id, &root_der, &root_pem, &root_key_pem);

    // Destination: a real Ferrum mesh gateway relaying CONNECT streams to the
    // echo backend, authenticating the source by its SPIFFE client cert.
    let (backend_addr, backend_accepted, backend_handle) = start_resettable_echo_backend().await;
    let mut destination_proxy = create_mesh_proxy(backend_addr.port());
    let spiffe_plugin = spiffe_identity_plugin_config(&destination_proxy.id);
    destination_proxy.plugins.push(PluginAssociation {
        plugin_config_id: spiffe_plugin.id.clone(),
    });
    let state = create_mesh_proxy_state_with_config(destination_proxy, vec![], vec![spiffe_plugin]);
    let server_config = ferrum_edge::tls::spiffe::build_spiffe_inbound_config(
        destination_slot,
        true,
        Arc::new(Vec::new()),
    )
    .expect("destination spiffe server config");
    let (gateway_addr, shutdown_tx) = start_gateway_mtls(state, server_config).await;

    // Source: the production pool, two streams per connection, room to widen.
    let pool = MeshMtlsConnectionPool::new(
        PoolConfig {
            http2_connections_per_host: 4,
            ..PoolConfig::default()
        },
        DnsCache::new(DnsConfig::default()),
        source_slot,
        4,
    );
    let mut source_proxy = create_mesh_proxy(AUTHORITY_PORT);
    source_proxy.pool_http2_max_concurrent_streams = Some(2);
    let open = || {
        pool.open_connect_tunnel(
            &source_proxy,
            "127.0.0.1",
            AUTHORITY_HOST,
            AUTHORITY_PORT,
            AUTHORITY_PORT,
            gateway_addr.port(),
            Some(&destination_id),
            None,
            None,
        )
    };

    // Five tunnels at two streams per connection: ⌈5 / 2⌉ = 3 connections,
    // five independent relays to the backend.
    let mut tunnels = Vec::new();
    for _ in 0..5 {
        let tunnel = tokio::time::timeout(TIMEOUT, open())
            .await
            .expect("timely tunnel open")
            .expect("pooled tunnel through the Ferrum destination");
        tunnels.push(tunnel);
    }
    for (index, tunnel) in tunnels.iter_mut().enumerate() {
        echo(tunnel, format!("stream-{index}").as_bytes()).await;
    }
    let stats = pool.tunnel_pool_stats();
    assert_eq!(stats.connections_opened, 3, "{stats:?}");
    assert_eq!(pool.tunnel_pool_size(), 3);
    assert_eq!(stats.active_streams, 5);
    assert_eq!(backend_accepted.load(Ordering::SeqCst), 5);

    // The backend resets one relayed connection; the destination relay ends
    // that CONNECT stream. Only that tunnel ends.
    let mut doomed = tunnels.remove(0);
    doomed.write_all(b"RESET").await.expect("reset trigger");
    let mut buf = [0u8; 8];
    let ended = tokio::time::timeout(TIMEOUT, doomed.read(&mut buf))
        .await
        .expect("the reset reaches the source tunnel");
    assert!(
        matches!(ended, Err(_) | Ok(0)),
        "the reset tunnel must end: {ended:?}"
    );
    drop(doomed);
    for (index, tunnel) in tunnels.iter_mut().enumerate() {
        echo(tunnel, format!("survivor-{index}").as_bytes()).await;
    }

    // The freed slot is reused on an existing connection: no new dial.
    let mut replacement = tokio::time::timeout(TIMEOUT, open())
        .await
        .expect("timely replacement open")
        .expect("replacement tunnel");
    echo(&mut replacement, b"replacement").await;
    assert_eq!(pool.tunnel_pool_stats().connections_opened, 3);
    assert_eq!(pool.tunnel_pool_size(), 3);

    shutdown_tx.send(true).expect("shutdown destination");
    backend_handle.abort();
}

/// The send direction against the real Ferrum frontend with TIGHT windows
/// (equal 64 KiB stream and connection windows, a valid configuration): one
/// tunnel's destination application stops reading indefinitely, so its relay
/// stops draining the CONNECT stream. The mesh inbound listener sizes its
/// connection window to cover every admitted stream (issue #7537), so sibling
/// tunnels on the same pooled connection keep flowing while the stalled
/// tunnel's writer is held by back-pressure.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_destination_application_never_starves_sibling_tunnels() {
    use ferrum_edge::modes::mesh::MeshTrafficDirection;
    use ferrum_edge::proxy::start_proxy_listener_with_bound_listener_and_mesh_direction;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let (root_der, root_pem, root_key_pem) = spiffe_root();
    let destination_id: SpiffeId = "spiffe://cluster.local/ns/default/sa/orders"
        .parse()
        .expect("destination id");
    let source_id: SpiffeId = "spiffe://cluster.local/ns/default/sa/client"
        .parse()
        .expect("source id");
    let destination_slot = spiffe_svid_slot(&destination_id, &root_der, &root_pem, &root_key_pem);
    let source_slot = spiffe_svid_slot(&source_id, &root_der, &root_pem, &root_key_pem);

    let (backend_addr, _backend_accepted, backend_handle) = start_resettable_echo_backend().await;
    let mut destination_proxy = create_mesh_proxy(backend_addr.port());
    // Keep the relay's own write deadline out of the picture: the stall must
    // be held by flow control for the whole test, not reset by a timeout.
    destination_proxy.backend_write_timeout_ms = 120_000;
    destination_proxy.backend_read_timeout_ms = 120_000;
    let spiffe_plugin = spiffe_identity_plugin_config(&destination_proxy.id);
    destination_proxy.plugins.push(PluginAssociation {
        plugin_config_id: spiffe_plugin.id.clone(),
    });
    let mut env = mesh_env_config();
    env.frontend_h2_initial_stream_window_size = 65_535;
    env.frontend_h2_initial_connection_window_size = 65_535;
    let state =
        create_mesh_proxy_state_with_env(destination_proxy, vec![], vec![spiffe_plugin], env);
    let server_config = ferrum_edge::tls::spiffe::build_spiffe_inbound_config(
        destination_slot,
        true,
        Arc::new(Vec::new()),
    )
    .expect("destination spiffe server config");
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind destination");
    let gateway_addr = listener.local_addr().expect("destination addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener_and_mesh_direction(
            listener,
            state,
            shutdown_rx,
            Some(server_config),
            Some(MeshTrafficDirection::Inbound),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let pool = MeshMtlsConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        source_slot,
        4,
    );
    let source_proxy = create_mesh_proxy(AUTHORITY_PORT);
    let open = || {
        pool.open_connect_tunnel(
            &source_proxy,
            "127.0.0.1",
            AUTHORITY_HOST,
            AUTHORITY_PORT,
            AUTHORITY_PORT,
            gateway_addr.port(),
            Some(&destination_id),
            None,
            None,
        )
    };

    let mut stalled = tokio::time::timeout(TIMEOUT, open())
        .await
        .expect("timely tunnel open")
        .expect("stalled tunnel");
    stalled.write_all(b"STALL").await.expect("stall trigger");
    let written = Arc::new(AtomicUsize::new(0));
    let written_task = written.clone();
    let writer = tokio::spawn(async move {
        let chunk = vec![0x42u8; 16 * 1024];
        while let Ok(n) = stalled.write(&chunk).await {
            written_task.fetch_add(n, Ordering::SeqCst);
        }
    });
    // Wait until the stalled tunnel's writer is held by flow control.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut last = usize::MAX;
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let now = written.load(Ordering::SeqCst);
        if now == last && now > 0 {
            break;
        }
        last = now;
        assert!(
            tokio::time::Instant::now() < deadline,
            "the stalled tunnel never reached back-pressure"
        );
    }
    assert!(
        !writer.is_finished(),
        "the stalled writer is held, not failed"
    );

    // Siblings on the same pooled connection still flow both ways.
    for index in 0..3 {
        let mut sibling = tokio::time::timeout(TIMEOUT, open())
            .await
            .expect("timely sibling open")
            .expect("sibling tunnel");
        let payload = vec![b'a' + index as u8; 256 * 1024];
        sibling.write_all(&payload).await.expect("sibling write");
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), sibling.read_exact(&mut echoed))
            .await
            .expect("a sibling is not starved by the stalled tunnel")
            .expect("sibling echo");
        assert_eq!(echoed, payload);
    }
    assert_eq!(
        pool.tunnel_pool_stats().connections_opened,
        1,
        "every tunnel shared the one pooled connection"
    );

    writer.abort();
    shutdown_tx.send(true).expect("shutdown destination");
    backend_handle.abort();
}
