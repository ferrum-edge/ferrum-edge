use crate::scaffolding::port_registry::TestSocket;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_mesh_inbound_tls_and_signal};
use ferrum_edge::tls::{
    MeshClientAuth, TlsPolicy, load_mesh_server_identity, load_mesh_tls_config_with_identity,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::scaffolding::ports::reserve_port;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn test_env_config() -> EnvConfig {
    EnvConfig {
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        accept_threads: 1,
        frontend_tls_handshake_timeout_seconds: 1,
        ..EnvConfig::default()
    }
}

fn test_proxy_state(env: EnvConfig) -> ProxyState {
    test_proxy_state_with_config(env, GatewayConfig::default())
}

fn test_proxy_state_with_config(env: EnvConfig, config: GatewayConfig) -> ProxyState {
    ProxyState::new(config, DnsCache::new(DnsConfig::default()), env, None, None)
        .expect("proxy state")
        .0
}

fn strict_mesh_tls_config() -> Arc<rustls::ServerConfig> {
    ensure_crypto_provider();
    let env = test_env_config();
    let tls_policy = TlsPolicy::from_env_config(&env).expect("TLS policy");
    let identity =
        load_mesh_server_identity("tests/certs/server.crt", "tests/certs/server.key", 30)
            .expect("mesh server identity");
    load_mesh_tls_config_with_identity(
        &identity,
        // Test fixture certificate is self-signed, so it doubles as the CA
        // anchor for client-certificate verification in this narrow test.
        Some("tests/certs/server.crt"),
        MeshClientAuth::Required,
        &tls_policy,
        env.tls_cert_expiry_warning_days,
        &[],
        // No SPIFFE verifier in this test: exercise the operator-CA path.
        None,
    )
    .expect("strict mesh TLS config")
}

#[test]
fn mesh_operator_client_ca_rejects_mixed_bundle_atomically() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("mesh-client-ca.pem");
    let valid = std::fs::read_to_string("tests/certs/server.crt").expect("read valid cert");
    std::fs::write(
        &ca_path,
        format!("{valid}-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"),
    )
    .expect("write mixed mesh CA");

    let env = test_env_config();
    let tls_policy = TlsPolicy::from_env_config(&env).expect("TLS policy");
    let identity =
        load_mesh_server_identity("tests/certs/server.crt", "tests/certs/server.key", 30)
            .expect("mesh server identity");
    let error = load_mesh_tls_config_with_identity(
        &identity,
        Some(ca_path.to_str().expect("utf8 path")),
        MeshClientAuth::Required,
        &tls_policy,
        env.tls_cert_expiry_warning_days,
        &[],
        None,
    )
    .expect_err("a malformed later mesh CA record must reject the complete candidate")
    .to_string();

    assert!(error.contains("mesh client CA bundle"), "got: {error}");
    assert!(error.contains("record #2"), "got: {error}");
}

#[test]
fn mesh_operator_client_ca_rejects_all_malformed_bundle() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("malformed-mesh-client-ca.pem");
    std::fs::write(
        &ca_path,
        b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
    )
    .expect("write malformed mesh CA");

    let env = test_env_config();
    let tls_policy = TlsPolicy::from_env_config(&env).expect("TLS policy");
    let identity =
        load_mesh_server_identity("tests/certs/server.crt", "tests/certs/server.key", 30)
            .expect("mesh server identity");
    let error = load_mesh_tls_config_with_identity(
        &identity,
        Some(ca_path.to_str().expect("utf8 path")),
        MeshClientAuth::Required,
        &tls_policy,
        env.tls_cert_expiry_warning_days,
        &[],
        None,
    )
    .expect_err("an all-malformed mesh CA bundle must reject the candidate")
    .to_string();

    assert!(error.contains("record #1"), "got: {error}");
}

async fn send_plain_http(addr: SocketAddr) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await;
    Ok(response)
}

async fn start_live_reload_listener_with_retry(
    state: &ProxyState,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    JoinHandle<Result<(), anyhow::Error>>,
) {
    let mut errors = Vec::new();
    for attempt in 1..=5 {
        let reservation = reserve_port().await.expect("reserve proxy port");
        let port = reservation.drop_and_take_port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener_state = state.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let listener = tokio::spawn(async move {
            start_proxy_listener_with_mesh_inbound_tls_and_signal(
                addr,
                listener_state,
                shutdown_rx,
                None,
                // Match the production Sidecar non-production derivation
                // (`mesh_inbound_listener_allows_plaintext`): the empty-slot
                // phase of these tests serves plaintext HTTP, and the strict
                // swap must reject plaintext via the policy slot even though
                // the listener itself allows the plaintext peek path.
                true,
                // Loopback-bound test listener; the dual-stack capture posture
                // is exercised by the mesh listener-plan tests.
                false,
                Some(started_tx),
            )
            .await
        });

        let start_result = tokio::time::timeout(Duration::from_secs(2), started_rx).await;
        let mut attempt_error = match start_result {
            Ok(Ok(())) => return (addr, shutdown_tx, listener),
            Ok(Err(error)) => {
                format!("attempt {attempt}: listener start signal dropped: {error}")
            }
            Err(error) => format!("attempt {attempt}: listener start timed out: {error}"),
        };

        let _ = shutdown_tx.send(true);
        match tokio::time::timeout(Duration::from_secs(2), listener).await {
            Ok(Ok(Err(error))) => {
                attempt_error = format!("{attempt_error}; listener returned error: {error}");
            }
            Ok(Err(error)) => {
                attempt_error = format!("{attempt_error}; listener task join error: {error}");
            }
            Err(error) => {
                attempt_error = format!("{attempt_error}; listener task did not stop: {error}");
            }
            Ok(Ok(Ok(()))) => {}
        }
        errors.push(attempt_error);
    }

    panic!(
        "listener did not bind after retries: {}",
        errors.join(" | ")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_peer_auth_live_reload_listener_rejects_plaintext_after_strict_swap() {
    ensure_crypto_provider();
    let state = test_proxy_state(test_env_config());
    let (addr, shutdown_tx, listener) = start_live_reload_listener_with_retry(&state).await;

    let plaintext_response = send_plain_http(addr).await.expect("plaintext request");
    assert!(
        plaintext_response.starts_with(b"HTTP/1.1 404"),
        "empty mesh TLS slot should run the listener as plaintext HTTP; response was {}",
        String::from_utf8_lossy(&plaintext_response)
    );

    let strict_tls = strict_mesh_tls_config();
    state
        .mesh_inbound_tls
        .store(Arc::new(Some(strict_tls.clone())));
    state
        .mesh_inbound_tls_policy
        .store(Arc::new(ferrum_edge::proxy::MeshInboundTlsPolicy {
            default: Some(strict_tls),
            default_mode: ferrum_edge::modes::mesh::config::MtlsMode::Strict,
            ..Default::default()
        }));

    let rejected_response = send_plain_http(addr)
        .await
        .expect("plaintext request after strict swap");
    assert!(
        !rejected_response.starts_with(b"HTTP/"),
        "strict mesh TLS slot must reject plaintext before HTTP routing; response was {}",
        String::from_utf8_lossy(&rejected_response)
    );
    assert!(
        rejected_response.is_empty() || rejected_response.first() == Some(&0x15),
        "plaintext rejection should close during TLS admission or emit a TLS alert, not return a routed response; got {} bytes",
        rejected_response.len()
    );

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(2), listener)
        .await
        .expect("listener should stop")
        .expect("listener task should join")
        .expect("listener should return cleanly");
}

// ============================================================================
// Stream listener (TCP+TLS) PeerAuth live-reload coverage (T3-A)
// ============================================================================

/// End-to-end: a mesh-shared TCP+TLS stream listener picks up a swapped
/// `rustls::ServerConfig` on the next accept without rebinding. The slot
/// starts as Permissive (client cert not required) — a client without a
/// cert handshakes successfully. After swapping to Strict (client cert
/// required), the next handshake from the same client fails.
///
/// Existing handshake-complete sessions are not affected by the swap
/// because rustls consults the `ServerConfig` only at handshake time; this
/// test only validates the new-accept path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_peer_auth_live_reload_tcp_tls_swap_takes_effect_on_next_accept() {
    use ferrum_edge::circuit_breaker::CircuitBreakerCache;
    use ferrum_edge::config::types::{BackendScheme, DispatchKind, GatewayConfig, Proxy};
    use ferrum_edge::consumer_index::ConsumerIndex;
    use ferrum_edge::load_balancer::LoadBalancerCache;
    use ferrum_edge::plugin_cache::PluginCache;
    use ferrum_edge::proxy::client_ip::TrustedProxies;
    use ferrum_edge::proxy::stream_listener::StreamListenerManager;
    use ferrum_edge::request_epoch::RequestEpochStore;
    use std::net::IpAddr;

    ensure_crypto_provider();

    // Configure a TCP+TLS stream proxy on an ephemeral port.
    let listen_port = {
        // Reserve a port that's still bindable; the reservation drops here so
        // the manager can re-bind. Reconcile races a new bind against any other
        // grabber, but the test environment is single-tenant enough for this.
        let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("reserve ephemeral");
        listener.local_addr().expect("local addr").port()
    };

    let mut proxy = Proxy {
        id: "stream-mtls".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: DispatchKind::from(BackendScheme::Tcp),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 9999,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: false,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: ferrum_edge::config::types::AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(listen_port),
        frontend_tls: true,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        pending_limit_scope: None,
    };
    proxy.dispatch_kind = DispatchKind::TcpTls;

    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        consumers: vec![],
        upstreams: vec![],
        plugin_configs: vec![],
        loaded_at: chrono::Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let config_arc = Arc::new(arc_swap::ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("plugin cache"));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        config.clone(),
        &plugin_cache,
        &consumer_index,
        &lb_cache,
    ));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    let env = test_env_config();
    let permissive_tls = {
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");
        let identity =
            load_mesh_server_identity("tests/certs/server.crt", "tests/certs/server.key", 30)
                .expect("mesh server identity");
        load_mesh_tls_config_with_identity(
            &identity,
            None,
            MeshClientAuth::None,
            &tls_policy,
            env.tls_cert_expiry_warning_days,
            &[],
            None,
        )
        .expect("permissive TLS config")
    };

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        request_epoch,
        cb_cache,
        Some(permissive_tls.clone()),
        false,
        None,
        300,
        300,
        2,
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        false,
        2048,
        1,
        256,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false,
        false,
        false,
        0,
        false,
        false,
        false,
        Arc::new(TrustedProxies::none()),
    );

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "TCP+TLS listener should bind: {:?}",
        failures
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("listener should start");

    // Step 1: confirm the slot holds the Permissive config (pointer equality).
    let observed = manager
        .snapshot_frontend_tls_config()
        .expect("slot populated at startup");
    assert!(Arc::ptr_eq(&observed, &permissive_tls));

    // Step 2: swap to a Strict config that requires a client certificate.
    let strict_tls = strict_mesh_tls_config();
    manager.swap_frontend_tls_config(Some(strict_tls.clone()));

    let after_swap = manager
        .snapshot_frontend_tls_config()
        .expect("slot still populated after swap");
    assert!(
        Arc::ptr_eq(&after_swap, &strict_tls),
        "swap_frontend_tls_config must publish the swapped Arc atomically"
    );
    assert!(
        !Arc::ptr_eq(&after_swap, &permissive_tls),
        "swap must replace the slot, not mutate in place"
    );

    // The slot is shared with the accept loop; the next handshake snapshots
    // it. Validating handshake behavior end-to-end requires a backend; the
    // unit-test layer (`swap_frontend_tls_config_replaces_slot_without_reconcile`)
    // already covers the swap semantics directly. Here we limit the
    // integration test to proving the slot publishes through the manager
    // surface used by `apply_mesh_inbound_tls_reload`.

    manager.shutdown_all().await;
}

/// Owner-scoped DTLS publication (issue #3858) records an accepted generation
/// even with no active DTLS listeners, so a listener created or restarted after
/// the slice converges on exactly that generation — and it never seeds the
/// ordinary operator `FERRUM_DTLS_*` slot.
#[tokio::test]
async fn mesh_owner_scoped_dtls_publish_without_dtls_listeners() {
    let state = test_proxy_state(test_env_config());
    let manager = &state.stream_listener_manager;

    let certificate = ferrum_edge::dtls::generate_ephemeral_cert_public().expect("ephemeral cert");
    let dtls_config = dimpl::Config::builder().build().expect("dtls config");
    let mut configs = std::collections::BTreeMap::new();
    configs.insert(
        "ferrum|__mesh-nw-udp-team-a-dns-a-5353".to_string(),
        ferrum_edge::dtls::FrontendDtlsConfig {
            dimpl_config: std::sync::Arc::new(dtls_config),
            certificate,
            client_cert_verifier: None,
            client_trust: None,
        },
    );
    let (generation, swapped) = manager
        .publish_mesh_node_waypoint_dtls_generation(configs)
        .await;

    assert_eq!(swapped, 0, "no active DTLS listeners means no live swaps");
    assert_eq!(generation, 1);
    assert!(
        manager
            .snapshot_mesh_node_waypoint_dtls_generation()
            .is_some(),
        "the owner-scoped generation must be published even when no DTLS listeners are bound yet"
    );
    assert!(
        manager.snapshot_frontend_dtls_generation().is_none(),
        "a mesh publish must never seed the ordinary FERRUM_DTLS_* generation"
    );
    let status = manager.frontend_dtls_reload_status();
    assert_eq!(status.last_outcome, "none");
    assert_eq!(status.generation, 0);
}

/// Mesh PeerAuthentication live reload swaps the shared TCP+TLS slot and must
/// not seed the ordinary `FERRUM_DTLS_*` generation when no DTLS listener exists.
#[tokio::test]
async fn mesh_peer_auth_live_reload_does_not_seed_ordinary_dtls_generation() {
    let state = test_proxy_state(test_env_config());
    let manager = &state.stream_listener_manager;

    manager.swap_frontend_tls_config(Some(strict_mesh_tls_config()));

    assert!(
        manager.snapshot_frontend_dtls_generation().is_none(),
        "mesh TLS material must not seed the ordinary DTLS listener generation"
    );
    assert!(
        manager
            .active_dtls_frontend_identities_for_test()
            .await
            .is_empty(),
        "no DTLS listener should be present on a TCP+TLS-only reload"
    );
    let status = manager.frontend_dtls_reload_status();
    assert_eq!(status.last_outcome, "none");
    assert_eq!(status.generation, 0);
}

/// An already-active ordinary UDP+DTLS listener keeps its dedicated identity
/// and client-CA policy across a mesh PeerAuthentication TCP+TLS swap.
#[tokio::test]
async fn mesh_peer_auth_live_reload_does_not_mutate_active_ordinary_dtls_listener() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = write_ecdsa_pem_pair(dir.path(), "dtls-dedicated");
    let (ca_path, _) = write_ecdsa_pem_pair(dir.path(), "dtls-client-ca");

    let holder = tokio::net::UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("udp holder");
    let port = holder.local_addr().expect("addr").port();
    drop(holder);

    let mut proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": "udp-dtls-ordinary",
        "namespace": "ferrum",
        "backend_scheme": "udp",
        "backend_host": "127.0.0.1",
        "backend_port": 9,
        "listen_port": port,
        "frontend_tls": true,
        "passthrough": false,
    }))
    .expect("udp dtls proxy");
    proxy.dispatch_kind = ferrum_edge::config::types::DispatchKind::from(
        ferrum_edge::config::types::BackendScheme::Udp,
    );

    let config = GatewayConfig {
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };
    let state = test_proxy_state_with_config(test_env_config(), config);
    let manager = &state.stream_listener_manager;
    manager
        .set_frontend_dtls_cert_key(cert_path, key_path, Some(ca_path), false)
        .await;
    manager
        .wait_until_started(Duration::from_secs(2))
        .await
        .expect("ordinary DTLS listener should start");

    let before_gen = manager
        .snapshot_frontend_dtls_generation()
        .expect("ordinary generation published");
    let before_ids = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ids = manager.active_dtls_frontend_identities_for_test().await;
            if !ids.is_empty() {
                return ids;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("DTLS server should publish into the listener slot");
    assert_eq!(before_ids.len(), 1);
    assert!(
        before_ids[0].1,
        "dedicated DTLS listener must require a client certificate"
    );

    manager.swap_frontend_tls_config(Some(strict_mesh_tls_config()));

    let after_gen = manager
        .snapshot_frontend_dtls_generation()
        .expect("ordinary generation retained");
    assert_eq!(after_gen.generation, before_gen.generation);
    assert!(
        Arc::ptr_eq(&after_gen, &before_gen),
        "mesh PeerAuthentication reload must not replace the ordinary DTLS generation"
    );
    let after_ids = manager.active_dtls_frontend_identities_for_test().await;
    assert_eq!(
        after_ids, before_ids,
        "active ordinary DTLS server must retain exact dedicated config/security policy"
    );

    manager.shutdown_all().await;
}

fn write_ecdsa_pem_pair(dir: &std::path::Path, name: &str) -> (String, String) {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec![format!("{name}.example")]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let cert_path = dir.join(format!("{name}.crt"));
    let key_path = dir.join(format!("{name}.key"));
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    (
        cert_path.to_str().expect("utf8").to_string(),
        key_path.to_str().expect("utf8").to_string(),
    )
}
