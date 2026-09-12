//! Hosted socket regressions for recovery, TLS names, and retry policy lanes.
use super::*;
use ferrum_edge::config::types::{BackoffStrategy, ResolvedPortOverride, RetryConfig, Upstream};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

#[allow(dead_code)]
#[path = "../../scaffolding/ports.rs"]
mod ports;

async fn read_bytes(stream: &mut (impl AsyncRead + Unpin), bytes: &mut [u8]) {
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(bytes))
        .await
        .expect("socket read must complete")
        .unwrap();
}

// Real bind collision is the barrier: the manager has already observed the
// occupied socket before it is released. Only the supervisor may reconcile it.
#[tokio::test]
async fn stream_supervisor_recovers_bind_without_config_change() {
    let mut bind_races = Vec::new();
    for attempt in 1..=ports::BIND_DROP_SPAWN_ATTEMPTS {
        let blocked = ports::reserve_port().await.unwrap();
        let port = blocked.port;
        let config = GatewayConfig {
            proxies: vec![create_stream_proxy("recovery", BackendScheme::Tcp, port)],
            ..empty_config()
        };
        let manager = Arc::new(create_manager(config));
        assert_eq!(manager.reconcile().await.len(), 1);
        assert!(!manager.is_ready());
        assert_eq!(manager.overload_snapshot().bind_failures_total, 1);
        manager.start_supervisor();
        manager.start_supervisor(); // Idempotent: there is only one retry owner.
        tokio::task::yield_now().await;
        drop(blocked);
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::time::resume();
        let started = manager.wait_until_started(Duration::from_secs(5)).await;
        if started.is_err() {
            let failures = manager.stream_bind_failures();
            // Prove a competitor owns the released port before retrying. The
            // original collision snapshot alone could hide a broken supervisor.
            let probe = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
            let stolen = probe
                .as_ref()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::AddrInUse);
            manager.shutdown_all().await;
            assert!(
                stolen && only_port_collision(&failures, port),
                "supervisor did not recover port {port}: {started:?}; failures={failures:?}"
            );
            bind_races.push(format!("attempt {attempt}, port {port}: {failures:?}"));
            continue;
        }
        assert!(manager.is_ready());
        assert_eq!(manager.overload_snapshot().bind_failures_total, 0);
        manager.shutdown_all().await;
        assert!(!manager.is_ready());
        return;
    }
    panic!("supervisor recovery exhausted fresh-port attempts: {bind_races:?}");
}

fn only_port_collision(
    failures: &[ferrum_edge::proxy::stream_listener::StreamBindFailure],
    port: u16,
) -> bool {
    !failures.is_empty()
        && failures.iter().all(|failure| {
            failure.listen_port == port
                && matches!(failure.kind, StreamListenerDegradation::BindFailed)
                && failure.error.contains("already in use")
        })
}

#[tokio::test]
async fn stream_supervisor_retries_soft_degradation_without_withdrawing_readiness() {
    let blocked = ports::reserve_port().await.unwrap();
    let mut proxy = create_stream_proxy("deferred", BackendScheme::Tcp, blocked.port);
    proxy.frontend_tls = true;
    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let manager = Arc::new(create_manager_with_config_arc(config_arc.clone(), &config));
    assert!(manager.reconcile().await.is_empty());
    assert!(manager.is_ready());
    assert!(manager.has_degraded_listeners());
    manager.start_supervisor();
    tokio::task::yield_now().await;
    // Only the supervisor may reconcile this withdrawal. It must retry soft
    // degradation even though readiness never went false.
    config_arc.store(Arc::new(empty_config()));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), async {
        while manager.has_degraded_listeners() {
            assert!(manager.is_ready());
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("supervisor must reconcile soft degradation using current config");
    assert!(manager.is_ready());
    manager.shutdown_all().await;
}

#[tokio::test]
async fn stream_readiness_grants_pending_bind_grace_but_rejects_exited_task() {
    let mut bind_races = Vec::new();
    for attempt in 1..=ports::BIND_DROP_SPAWN_ATTEMPTS {
        let port = ports::reserve_port().await.unwrap().drop_and_take_port();
        let mut config = GatewayConfig {
            proxies: vec![create_stream_proxy("pending", BackendScheme::Tcp, port)],
            ..empty_config()
        };
        let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
        let manager = create_manager_with_config_arc(config_arc.clone(), &config);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        manager.set_global_shutdown_rx(shutdown_rx);
        let failures = manager.reconcile().await;
        if failures.is_empty() {
            // On this current-thread runtime the spawned task has not been
            // polled yet. A zero-duration startup check proves it is pending.
            assert!(manager.wait_until_started(Duration::ZERO).await.is_err());
            assert!(manager.is_ready());
            assert!(!manager.has_degraded_listeners());
            let started = manager.wait_until_started(Duration::from_secs(5)).await;
            if started.is_ok() {
                assert!(manager.is_ready());
                // Force a normal runtime restart on the same port. Check each
                // reconcile suspension, including the old task's planned exit,
                // so a transient 503 cannot hide behind the final snapshot.
                config.proxies[0].passthrough = true;
                config_arc.store(Arc::new(config));
                let reconcile = manager.reconcile();
                tokio::pin!(reconcile);
                let failures = std::future::poll_fn(|cx| {
                    if manager.stream_bind_failures().is_empty() {
                        assert!(
                            manager.is_ready(),
                            "readiness flapped before reconcile poll"
                        );
                    }
                    let result = std::future::Future::poll(reconcile.as_mut(), cx);
                    if manager.stream_bind_failures().is_empty() {
                        assert!(manager.is_ready(), "readiness flapped after reconcile poll");
                    }
                    result
                })
                .await;
                let restarted = manager.wait_until_started(Duration::from_secs(5)).await;
                if !failures.is_empty() || restarted.is_err() {
                    let failures = manager.stream_bind_failures();
                    manager.shutdown_all().await;
                    assert!(
                        only_port_collision(&failures, port),
                        "runtime restart failed on port {port}: {restarted:?}; {failures:?}"
                    );
                    bind_races.push(format!("attempt {attempt}, port {port}: {failures:?}"));
                    continue;
                }
                assert!(manager.is_ready());
                shutdown_tx.send(true).unwrap();
                tokio::time::timeout(Duration::from_secs(5), async {
                    while manager.is_ready() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("completed listener task must withdraw readiness");
                // No manager stop/drain latch or hard error supplies this
                // verdict: a clean task exit alone must withdraw readiness.
                assert!(manager.has_degraded_listeners());
                assert!(manager.stream_bind_failures().is_empty());
                manager.shutdown_all().await;
                return;
            }
        }
        let failures = manager.stream_bind_failures();
        manager.shutdown_all().await;
        assert!(
            only_port_collision(&failures, port),
            "pending-bind fixture failed on port {port}: {failures:?}"
        );
        bind_races.push(format!("attempt {attempt}, port {port}: {failures:?}"));
    }
    panic!("pending-bind fixture exhausted fresh-port attempts: {bind_races:?}");
}

#[tokio::test]
async fn stream_supervisor_does_not_restore_withdrawn_or_shutdown_listener() {
    for shutdown in [false, true] {
        let blocked = ports::reserve_port().await.unwrap();
        let port = blocked.port;
        let config = GatewayConfig {
            proxies: vec![create_stream_proxy("withdrawn", BackendScheme::Tcp, port)],
            ..empty_config()
        };
        let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
        let manager = Arc::new(create_manager_with_config_arc(config_arc.clone(), &config));
        assert_eq!(manager.reconcile().await.len(), 1);
        manager.start_supervisor();
        tokio::task::yield_now().await;
        if shutdown {
            manager.shutdown_all().await;
        } else {
            config_arc.store(Arc::new(empty_config()));
            assert!(manager.reconcile().await.is_empty());
            assert!(manager.is_ready());
        }
        // Keep ownership across the tick instead of dropping and rebinding a
        // port another fixture could steal. Inspect the manager as well so a
        // stale recovery attempt cannot hide behind this occupied socket.
        let guard = blocked.into_listener();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();
        assert!(manager.active_binds().await.is_empty());
        if !shutdown {
            assert!(manager.stream_bind_failures().is_empty());
        }
        assert!(manager.reconcile().await.is_empty());
        drop(guard);
        manager.shutdown_all().await;
    }
}

fn tls_fixture(name: &str) -> (tempfile::TempDir, String, tokio_rustls::TlsAcceptor) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, cert.pem()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    (
        dir,
        path.to_str().unwrap().to_string(),
        tokio_rustls::TlsAcceptor::from(Arc::new(config)),
    )
}

async fn check_backend_tls_name(cert_name: &str, override_name: Option<&str>, succeeds: bool) {
    let (_dir, ca, acceptor) = tls_fixture(cert_name);
    let backend = ports::reserve_port().await.unwrap();
    let backend_port = backend.port;
    let listener = backend.into_listener();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        match acceptor.accept(socket).await {
            Ok(mut tls) => {
                let name = tls.get_ref().1.server_name().map(str::to_owned);
                let mut byte = [0];
                read_bytes(&mut tls, &mut byte).await;
                tls.write_all(&byte).await.unwrap();
                Some(name)
            }
            Err(_) => None,
        }
    });
    let (manager, port) = start_manager_on_fresh_tcp_port(|port| {
        let mut proxy = create_stream_proxy("tls-name", BackendScheme::Tcps, port);
        proxy.backend_port = backend_port;
        proxy.backend_tls_verify_server_cert = true;
        proxy.backend_tls_server_ca_cert_path = Some(ca.clone());
        proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
        proxy.resolved_tls.sni = override_name.map(str::to_owned);
        GatewayConfig {
            proxies: vec![proxy],
            ..empty_config()
        }
    })
    .await;
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    client.write_all(b"x").await.unwrap();
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut byte))
        .await
        .unwrap();
    assert_eq!(result.is_ok(), succeeds);
    let observed = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    if succeeds {
        assert_eq!(byte, *b"x");
        assert_eq!(observed, Some(override_name.map(str::to_owned)));
    } else {
        assert!(
            observed.is_none(),
            "a certificate for the dial IP must not satisfy the override"
        );
    }
    drop(client);
    manager.shutdown_all().await;
}

#[tokio::test]
async fn tcp_tls_sends_and_verifies_configured_name() {
    check_backend_tls_name("backend.example", Some("backend.example"), true).await;
}

#[tokio::test]
async fn tcp_tls_rejects_dial_host_certificate_when_name_overridden() {
    check_backend_tls_name("127.0.0.1", Some("backend.example"), false).await;
}

#[tokio::test]
async fn tcp_tls_without_override_still_verifies_dial_host() {
    check_backend_tls_name("127.0.0.1", None, true).await;
}

fn retry_config(port: u16, first: u16, second: u16, tls: bool, passthrough: bool) -> GatewayConfig {
    let scheme = if tls {
        BackendScheme::Tcps
    } else {
        BackendScheme::Tcp
    };
    let mut proxy = create_stream_proxy("retry-lanes", scheme, port);
    proxy.passthrough = passthrough;
    proxy.backend_port = first;
    proxy.upstream_id = Some("lanes".to_string());
    proxy.retry = Some(RetryConfig {
        max_retries: 1,
        backoff: BackoffStrategy::Fixed { delay_ms: 0 },
        ..Default::default()
    });
    proxy.dispatch_port_overrides = Some(std::collections::HashMap::from([
        (
            8001,
            ResolvedPortOverride {
                connect_timeout_ms: Some(5_000),
                tcp_idle_timeout_seconds: Some(0),
                ..Default::default()
            },
        ),
        (
            8002,
            ResolvedPortOverride {
                connect_timeout_ms: Some(250),
                tcp_idle_timeout_seconds: Some(1),
                ..Default::default()
            },
        ),
    ]));
    // With zero live connections least-connections selects the first target.
    // Unlike sharded round-robin, its initial choice has no thread phase.
    let mut upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id": "lanes", "algorithm": "least_connections",
        "targets": [{"host": "127.0.0.1", "port": first},
                    {"host": "127.0.0.1", "port": second}]
    }))
    .unwrap();
    upstream.targets[0].service_port_policy_key = Some(8001);
    upstream.targets[1].service_port_policy_key = Some(8002);
    GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        ..empty_config()
    }
}

#[tokio::test]
async fn tcp_tls_retry_uses_rotated_handshake_budget() {
    let first = ports::reserve_port().await.unwrap();
    let second = ports::reserve_port().await.unwrap();
    let first_port = first.port;
    let second_port = second.port;
    let (manager, port) = start_manager_on_fresh_tcp_port(|port| {
        retry_config(port, first_port, second_port, true, false)
    })
    .await;
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let first_listener = first.into_listener();
    let (first_socket, _) = tokio::time::timeout(Duration::from_secs(5), first_listener.accept())
        .await
        .unwrap()
        .unwrap();
    drop(first_socket); // Actual handshake failure forces rotation.
    let second_listener = second.into_listener();
    let (mut stalled_tls, _) =
        tokio::time::timeout(Duration::from_secs(5), second_listener.accept())
            .await
            .unwrap()
            .unwrap();
    // ClientHello proves this is the second TLS dial, whose server never replies.
    let mut hello = [0; 5];
    read_bytes(&mut stalled_tls, &mut hello).await;
    assert_eq!(hello[0], 22);
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .expect("second lane must expire before the first lane's five-second budget");
    assert!(matches!(result, Ok(0) | Err(_)));
    drop(stalled_tls);
    manager.shutdown_all().await;
}

#[tokio::test]
async fn tcp_retry_rotates_idle_budget_for_plain_and_passthrough() {
    for passthrough in [false, true] {
        let first = ports::reserve_refused_tcp_port().unwrap();
        let second = ports::reserve_port().await.unwrap();
        let second_port = second.port;
        let (manager, port) = start_manager_on_fresh_tcp_port(|port| {
            retry_config(port, first.port, second_port, false, passthrough)
        })
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let payload = tls_client_hello("backend.example");
        client.write_all(&payload).await.unwrap();
        let listener = second.into_listener();
        let (mut backend, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![0; payload.len()];
        read_bytes(&mut backend, &mut received).await;
        assert_eq!(received, payload);
        backend.write_all(b"y").await.unwrap();
        let mut byte = [0];
        read_bytes(&mut client, &mut byte).await;
        assert_eq!(byte, *b"y");
        let result = tokio::time::timeout(Duration::from_secs(4), client.read(&mut byte))
            .await
            .expect("successful lane's one-second idle budget must replace disabled idle");
        assert!(matches!(result, Ok(0) | Err(_)));
        drop(backend);
        manager.shutdown_all().await;
    }
}

#[tokio::test]
async fn tcp_initial_lane_keeps_disabled_idle_without_retry() {
    for passthrough in [false, true] {
        let backend = ports::reserve_port().await.unwrap();
        let backend_port = backend.port;
        let (manager, port) = start_manager_on_fresh_tcp_port(|port| {
            let mut config = retry_config(port, backend_port, backend_port, false, passthrough);
            config.upstreams[0].targets.truncate(1);
            config.proxies[0].retry = None;
            config
        })
        .await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let payload = tls_client_hello("backend.example");
        client.write_all(&payload).await.unwrap();
        let listener = backend.into_listener();
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![0; payload.len()];
        read_bytes(&mut socket, &mut received).await;
        assert_eq!(received, payload);
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(1_500), client.read(&mut byte))
                .await
                .is_err()
        );
        socket.write_all(b"z").await.unwrap();
        read_bytes(&mut client, &mut byte).await;
        assert_eq!(byte, *b"z");
        drop(client);
        drop(socket);
        manager.shutdown_all().await;
    }
}

#[tokio::test]
async fn tcp_tls_initial_lane_keeps_long_handshake_budget() {
    let backend = ports::reserve_port().await.unwrap();
    let backend_port = backend.port;
    let (manager, port) = start_manager_on_fresh_tcp_port(|port| {
        let mut config = retry_config(port, backend_port, backend_port, true, false);
        config.upstreams[0].targets.truncate(1);
        config.proxies[0].retry = None;
        config
    })
    .await;
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let listener = backend.into_listener();
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut hello = [0; 5];
    read_bytes(&mut socket, &mut hello).await;
    assert_eq!(hello[0], 22);
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(750), client.read(&mut byte))
            .await
            .is_err()
    );
    drop(socket);
    drop(client);
    manager.shutdown_all().await;
}

#[tokio::test]
async fn healthy_stream_listener_keeps_serving_across_supervisor_tick() {
    let backend = ports::reserve_port().await.unwrap();
    let backend_port = backend.port;
    let (manager, port) = start_manager_on_fresh_tcp_port(|port| {
        let mut proxy = create_stream_proxy("healthy", BackendScheme::Tcp, port);
        proxy.backend_port = backend_port;
        GatewayConfig {
            proxies: vec![proxy],
            ..empty_config()
        }
    })
    .await;
    let manager = Arc::new(manager);
    assert!(manager.is_ready());
    manager.start_supervisor();
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    client.write_all(b"a").await.unwrap();
    let listener = backend.into_listener();
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut byte = [0];
    read_bytes(&mut socket, &mut byte).await;
    assert_eq!(byte, *b"a");
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::task::yield_now().await;
    tokio::time::resume();
    assert!(manager.is_ready());
    assert_eq!(manager.overload_snapshot().bind_failures_total, 0);
    socket.write_all(b"b").await.unwrap();
    read_bytes(&mut client, &mut byte).await;
    assert_eq!(byte, *b"b");
    drop(client);
    drop(socket);
    manager.shutdown_all().await;
}
