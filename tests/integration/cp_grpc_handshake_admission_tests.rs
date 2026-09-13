//! Regression coverage for private advisory GHSA-2xqr-7j7p-77qp — "CP gRPC TLS
//! accept loop permits unauthenticated connection fan-out exhaustion".
//!
//! Before the fix the CP gRPC TLS accept loop spawned one task per accepted
//! socket *before* TLS, client-certificate, or JWT authentication, so an
//! unauthenticated client could open sockets faster than the handshake timeout
//! retired them and grow descriptor/memory/scheduler usage without bound.
//!
//! These tests drive the real listener helpers
//! (`cp_grpc_tls_incoming` / `cp_grpc_plain_incoming`) against a shared
//! `ConnLimiter` and assert, without relying on wall-clock timing for the
//! *positive* facts:
//!
//! * more incomplete TLS sessions than capacity never exceed the cap;
//! * excess sockets are closed promptly (the client observes EOF);
//! * a legitimate DP connects as soon as a permit is released;
//! * the same holds under mTLS (client certificates required);
//! * the cap is shared across certificate-reload generations;
//! * shutdown releases every permit exactly once;
//! * the per-IP share bounds one source below the global cap;
//! * the plaintext listener is bounded by the same limiter.
//!
//! Every wait is bounded and every assertion is on limiter state or socket
//! EOF, so the suite is deterministic enough for hosted CI.

use crate::scaffolding::port_registry::TestSocket;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use futures_util::StreamExt;
use rustls::pki_types::{CertificateRevocationListDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use ferrum_edge::modes::control_plane::{cp_grpc_plain_incoming, cp_grpc_tls_incoming};
use ferrum_edge::tls::backend::BackendTlsConfigBuilder;
use ferrum_edge::tls::source::{CertSource, MaterialKind};
use ferrum_edge::tls::{TlsPolicy, load_tls_config_with_client_auth_from_sources};
use ferrum_edge::util::conn_limit::ConnLimiter;

use crate::scaffolding::certs::TestCa;

/// Upper bound on any wait for the limiter to reach an expected state. Reached
/// only on failure; the happy path settles in milliseconds.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Window in which a socket the listener refused must be observably closed.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Window used to prove something does *not* happen (no extra admission).
const NEGATIVE_WINDOW: Duration = Duration::from_millis(750);
/// Long enough that an idle (never-completed) handshake stays parked for the
/// whole test rather than being retired by the timeout under test.
const LONG_HANDSHAKE_TIMEOUT_SECS: u64 = 120;

fn ensure_crypto_provider() {
    let _ = ferrum_edge::fips::base_crypto_provider().install_default();
}

fn pem_certs(pem: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .filter_map(Result::ok)
        .collect()
}

fn pem_key(pem: &str) -> rustls::pki_types::PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .expect("read private key")
        .expect("private key present")
}

/// Server-authenticated TLS config from a leaf issued by `ca`.
fn server_config(ca: &TestCa) -> Arc<ServerConfig> {
    ensure_crypto_provider();
    let (cert_pem, key_pem) = ca.valid().expect("server leaf");
    let config =
        ServerConfig::builder_with_provider(Arc::new(ferrum_edge::fips::base_crypto_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(pem_certs(&cert_pem), pem_key(&key_pem))
            .expect("server cert");
    Arc::new(config)
}

/// mTLS server config: the same leaf plus a required client-certificate
/// verifier anchored at `ca`.
fn mtls_server_config(ca: &TestCa) -> Arc<ServerConfig> {
    ensure_crypto_provider();
    let (cert_pem, key_pem) = ca.valid().expect("server leaf");
    let mut roots = RootCertStore::empty();
    for cert in pem_certs(&ca.cert_pem) {
        roots.add(cert).expect("add ca to client-auth roots");
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(ferrum_edge::fips::base_crypto_provider()),
    )
    .build()
    .expect("client verifier");
    let config =
        ServerConfig::builder_with_provider(Arc::new(ferrum_edge::fips::base_crypto_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(pem_certs(&cert_pem), pem_key(&key_pem))
            .expect("server cert");
    Arc::new(config)
}

/// Client that trusts `ca` and presents no client certificate.
fn client_config(ca: &TestCa) -> Arc<ClientConfig> {
    ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    for cert in pem_certs(&ca.cert_pem) {
        roots.add(cert).expect("add ca to client roots");
    }
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(ferrum_edge::fips::base_crypto_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Client that trusts `ca` and presents a leaf issued by `ca` (mTLS).
fn mtls_client_config(ca: &TestCa) -> Arc<ClientConfig> {
    ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    for cert in pem_certs(&ca.cert_pem) {
        roots.add(cert).expect("add ca to client roots");
    }
    let (cert_pem, key_pem) = ca.client_auth().expect("client leaf");
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(ferrum_edge::fips::base_crypto_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_client_auth_cert(pem_certs(&cert_pem), pem_key(&key_pem))
            .expect("client auth cert"),
    )
}

fn tls_slot(config: Arc<ServerConfig>) -> ferrum_edge::tls::SharedFrontendTls {
    Arc::new(ArcSwap::from_pointee(Some(config)))
}

async fn bind_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind_test(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind CP gRPC test listener");
    let addr = listener.local_addr().expect("local addr");
    (listener, addr)
}

/// Open a raw TCP connection and send **nothing** — the advisory's attack
/// primitive (a withheld TLS ClientHello).
async fn open_incomplete_session(addr: SocketAddr) -> TcpStream {
    TcpStream::connect(addr).await.expect("connect")
}

/// Poll until `predicate` holds, bounded by [`SETTLE_TIMEOUT`]. Returns the
/// last observed active count so failures report it.
async fn wait_for<F>(limiter: &Arc<ConnLimiter>, label: &str, predicate: F) -> u64
where
    F: Fn(&ferrum_edge::util::conn_limit::ConnLimiterSnapshot) -> bool,
{
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        let snapshot = limiter.snapshot();
        if predicate(&snapshot) {
            return snapshot.active_connections;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {label}; active={} rejected_global={} rejected_per_ip={}",
            snapshot.active_connections,
            snapshot.rejected_max_connections,
            snapshot.rejected_max_connections_per_ip,
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Assert the peer closed this socket (read returns EOF or an error) within
/// [`CLOSE_TIMEOUT`] — i.e. the refusal is prompt, not a parked socket.
async fn assert_closed_promptly(mut socket: TcpStream, label: &str) {
    let mut buf = [0u8; 1];
    match tokio::time::timeout(CLOSE_TIMEOUT, socket.read(&mut buf)).await {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("{label}: refused socket unexpectedly carried {n} byte(s)"),
        Err(_) => panic!("{label}: refused socket was not closed within {CLOSE_TIMEOUT:?}"),
    }
}

/// Complete a real TLS handshake, as a legitimate Data Plane would, and return
/// the live session so the caller keeps it open while asserting.
async fn complete_handshake(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let stream = TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from("localhost")?;
    Ok(connector.connect(server_name, stream).await?)
}

/// Drive an in-memory rustls handshake to completion. Both configs are built
/// through Ferrum's production TLS constructors; this helper only replaces the
/// socket so the assertion is deterministic and independent of runner timing.
fn drive_in_memory_handshake(
    client_config: ClientConfig,
    server_config: Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    let server_name = ServerName::try_from("localhost").expect("static server name");
    let mut client = ClientConnection::new(Arc::new(client_config), server_name)
        .expect("construct backend TLS client");
    let mut server = ServerConnection::new(server_config).expect("construct frontend TLS server");

    for _ in 0..32 {
        let mut to_server = Vec::new();
        while client.wants_write() {
            client
                .write_tls(&mut to_server)
                .expect("serialize client handshake records");
        }
        if !to_server.is_empty() {
            let mut records = to_server.as_slice();
            while !records.is_empty() {
                let read = server
                    .read_tls(&mut records)
                    .expect("read client handshake records");
                assert!(read > 0, "server TLS reader must make progress");
                server
                    .process_new_packets()
                    .expect("process client handshake records");
            }
        }

        let mut to_client = Vec::new();
        while server.wants_write() {
            server
                .write_tls(&mut to_client)
                .expect("serialize server handshake records");
        }
        if !to_client.is_empty() {
            let mut records = to_client.as_slice();
            while !records.is_empty() {
                let read = client
                    .read_tls(&mut records)
                    .expect("read server handshake records");
                assert!(read > 0, "client TLS reader must make progress");
                client
                    .process_new_packets()
                    .expect("process server handshake records");
            }
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            return (client, server);
        }
    }

    panic!("frontend/backend TLS handshake did not converge");
}

#[test]
fn frontend_and_backend_builders_complete_a_real_tls_handshake() {
    ensure_crypto_provider();
    let ca = TestCa::new("fips-surface-handshake").expect("test CA");
    let (cert_pem, key_pem) = ca.valid().expect("frontend certificate");
    let tls_policy = TlsPolicy::from_env_config(&ferrum_edge::config::EnvConfig::default())
        .expect("default TLS policy");

    let cert_source = CertSource::parse(cert_pem, MaterialKind::Cert);
    let key_source = CertSource::parse(key_pem, MaterialKind::Key);
    let server_config = load_tls_config_with_client_auth_from_sources(
        &cert_source,
        &key_source,
        None,
        false,
        &tls_policy,
        30,
        30,
        &[],
    )
    .expect("build production frontend TLS config");

    let temp_dir = TempDir::new().expect("temporary CA directory");
    let ca_path = temp_dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write backend CA");
    let ca_path_string = ca_path.display().to_string();
    let mut proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(json!({
        "id": "fips-backend-handshake",
        "listen_path": "/fips-handshake",
        "backend_scheme": "https",
        "backend_host": "localhost",
        "backend_port": 443,
        "backend_tls_server_ca_cert_path": ca_path_string,
    }))
    .expect("backend proxy fixture");
    proxy.resolved_tls.server_ca_cert_path = Some(ca_path.display().to_string());
    proxy.resolved_tls.verify_server_cert = true;

    let crls: Vec<CertificateRevocationListDer<'static>> = Vec::new();
    let client_config = BackendTlsConfigBuilder {
        proxy: &proxy,
        policy: Some(&tls_policy),
        global_ca: None,
        global_no_verify: false,
        global_client_cert: None,
        global_client_key: None,
        crls: &crls,
    }
    .build_rustls()
    .expect("build production backend TLS config");

    let (client, server) = drive_in_memory_handshake(client_config, server_config);
    assert_eq!(client.protocol_version(), server.protocol_version());
    let negotiated = client
        .negotiated_cipher_suite()
        .expect("a rustls cipher suite must be negotiated");
    assert_eq!(
        negotiated.suite(),
        server
            .negotiated_cipher_suite()
            .expect("server negotiated cipher suite")
            .suite()
    );
    #[cfg(feature = "fips")]
    assert!(
        negotiated.fips(),
        "the FIPS surface handshake must negotiate an approved cipher suite"
    );
}

#[tokio::test]
async fn more_incomplete_tls_sessions_than_capacity_never_exceed_the_cap() {
    const CAP: usize = 3;
    let ca = TestCa::new("cp-grpc-admission").expect("ca");
    let (listener, addr) = bind_listener().await;
    let limiter = Arc::new(ConnLimiter::new(CAP, 0));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let _incoming = cp_grpc_tls_incoming(
        listener,
        tls_slot(server_config(&ca)),
        shutdown_rx,
        LONG_HANDSHAKE_TIMEOUT_SECS,
        Arc::clone(&limiter),
    );

    // Fill the pool with sockets that never send a ClientHello.
    let mut parked = Vec::new();
    for _ in 0..CAP {
        parked.push(open_incomplete_session(addr).await);
    }
    wait_for(&limiter, "the pool to fill", |s| {
        s.active_connections == CAP as u64
    })
    .await;

    // Everything beyond the cap is refused in the accept loop, before any
    // handshake task exists, and closed immediately.
    let excess = 6;
    let mut refused = Vec::new();
    for _ in 0..excess {
        refused.push(open_incomplete_session(addr).await);
    }
    wait_for(&limiter, "excess connections to be rejected", |s| {
        s.rejected_max_connections >= excess
    })
    .await;

    let snapshot = limiter.snapshot();
    assert_eq!(
        snapshot.active_connections, CAP as u64,
        "active handshakes must never exceed the configured cap"
    );
    assert_eq!(
        snapshot.rejected_max_connections, excess,
        "every over-limit socket is accounted"
    );
    assert_eq!(snapshot.rejected_max_connections_per_ip, 0);

    for (i, socket) in refused.into_iter().enumerate() {
        assert_closed_promptly(socket, &format!("excess socket {i}")).await;
    }

    // Parked sockets still hold their permits.
    assert_eq!(limiter.snapshot().active_connections, CAP as u64);
    drop(parked);
}

#[tokio::test]
async fn legitimate_data_plane_connects_once_a_permit_is_released() {
    let ca = TestCa::new("cp-grpc-admission").expect("ca");
    let (listener, addr) = bind_listener().await;
    let limiter = Arc::new(ConnLimiter::new(1, 0));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let mut incoming = cp_grpc_tls_incoming(
        listener,
        tls_slot(server_config(&ca)),
        shutdown_rx,
        LONG_HANDSHAKE_TIMEOUT_SECS,
        Arc::clone(&limiter),
    );

    // One attacker socket occupies the only permit.
    let parked = open_incomplete_session(addr).await;
    wait_for(&limiter, "the single permit to be taken", |s| {
        s.active_connections == 1
    })
    .await;

    // A legitimate DP is refused while the pool is saturated: the listener
    // yields no connection and the socket is closed.
    let blocked = TcpStream::connect(addr).await.expect("connect");
    wait_for(&limiter, "the legitimate attempt to be rejected", |s| {
        s.rejected_max_connections >= 1
    })
    .await;
    assert!(
        tokio::time::timeout(NEGATIVE_WINDOW, incoming.next())
            .await
            .is_err(),
        "no connection may be delivered while the cap is saturated"
    );
    assert_closed_promptly(blocked, "blocked legitimate socket").await;

    // Releasing the attacker socket frees the permit (the parked handshake
    // fails on EOF and drops its permit) — no timeout wait required.
    drop(parked);
    wait_for(&limiter, "the permit to be released", |s| {
        s.active_connections == 0
    })
    .await;

    // Now a real handshake succeeds and is delivered to the gRPC server.
    let client = client_config(&ca);
    let handshake = tokio::spawn(async move { complete_handshake(addr, client).await });
    let delivered = tokio::time::timeout(SETTLE_TIMEOUT, incoming.next())
        .await
        .expect("a legitimate connection is delivered once a permit frees")
        .expect("stream is still open");
    assert!(delivered.is_ok(), "delivered connection is not an error");
    let _client_session = handshake
        .await
        .expect("join handshake")
        .expect("legitimate TLS handshake succeeds");

    // The delivered IO holds the permit for the session lifetime, so an idle
    // completed session is bounded too — dropping it releases exactly one.
    assert_eq!(limiter.snapshot().active_connections, 1);
    drop(delivered);
    wait_for(&limiter, "session permit release", |s| {
        s.active_connections == 0
    })
    .await;
}

#[tokio::test]
async fn mtls_listener_is_bounded_before_client_certificate_verification() {
    const CAP: usize = 2;
    let ca = TestCa::new("cp-grpc-admission-mtls").expect("ca");
    let (listener, addr) = bind_listener().await;
    let limiter = Arc::new(ConnLimiter::new(CAP, 0));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let mut incoming = cp_grpc_tls_incoming(
        listener,
        tls_slot(mtls_server_config(&ca)),
        shutdown_rx,
        LONG_HANDSHAKE_TIMEOUT_SECS,
        Arc::clone(&limiter),
    );

    // The client certificate is checked inside the (previously unbounded)
    // handshake task, so mTLS must be bounded by the same pre-auth gate.
    let mut parked = Vec::new();
    for _ in 0..CAP {
        parked.push(open_incomplete_session(addr).await);
    }
    wait_for(&limiter, "the mTLS pool to fill", |s| {
        s.active_connections == CAP as u64
    })
    .await;

    let refused = open_incomplete_session(addr).await;
    wait_for(&limiter, "the mTLS rejection", |s| {
        s.rejected_max_connections >= 1
    })
    .await;
    assert_eq!(limiter.snapshot().active_connections, CAP as u64);
    assert_closed_promptly(refused, "excess mTLS socket").await;

    // Free the pool and prove a real mTLS peer still gets through.
    parked.clear();
    wait_for(&limiter, "mTLS permits to release", |s| {
        s.active_connections == 0
    })
    .await;

    let client = mtls_client_config(&ca);
    let handshake = tokio::spawn(async move { complete_handshake(addr, client).await });
    let delivered = tokio::time::timeout(SETTLE_TIMEOUT, incoming.next())
        .await
        .expect("mTLS connection delivered")
        .expect("stream open");
    assert!(delivered.is_ok());
    let _client_session = handshake
        .await
        .expect("join handshake")
        .expect("mTLS handshake succeeds");
}

#[tokio::test]
async fn cap_is_shared_across_certificate_reload_generations() {
    let first_ca = TestCa::new("cp-grpc-cert-gen-1").expect("ca");
    let second_ca = TestCa::new("cp-grpc-cert-gen-2").expect("ca");
    let (listener, addr) = bind_listener().await;
    let limiter = Arc::new(ConnLimiter::new(1, 0));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let slot = tls_slot(server_config(&first_ca));

    let mut incoming = cp_grpc_tls_incoming(
        listener,
        Arc::clone(&slot),
        shutdown_rx,
        LONG_HANDSHAKE_TIMEOUT_SECS,
        Arc::clone(&limiter),
    );

    let parked = open_incomplete_session(addr).await;
    wait_for(&limiter, "the permit to be taken", |s| {
        s.active_connections == 1
    })
    .await;

    // Rotate the certificate, exactly as the CP gRPC TLS watcher does. The
    // listener and the limiter are unchanged; only the slot contents swap.
    slot.store(Arc::new(Some(server_config(&second_ca))));

    // The cap survives the reload: a post-reload connection is still refused.
    let refused = open_incomplete_session(addr).await;
    wait_for(&limiter, "a post-reload rejection", |s| {
        s.rejected_max_connections >= 1
    })
    .await;
    assert_eq!(
        limiter.snapshot().active_connections,
        1,
        "a certificate reload must not reset or duplicate the connection pool"
    );
    assert_closed_promptly(refused, "post-reload excess socket").await;

    // Release, then prove the rotated certificate is the one in use.
    drop(parked);
    wait_for(&limiter, "the permit to release", |s| {
        s.active_connections == 0
    })
    .await;

    let client = client_config(&second_ca);
    let handshake = tokio::spawn(async move { complete_handshake(addr, client).await });
    let delivered = tokio::time::timeout(SETTLE_TIMEOUT, incoming.next())
        .await
        .expect("post-reload connection delivered")
        .expect("stream open");
    assert!(delivered.is_ok());
    let _client_session = handshake
        .await
        .expect("join handshake")
        .expect("handshake against the rotated certificate succeeds");
}

#[tokio::test]
async fn shutdown_stops_admission_and_releases_permits_exactly_once() {
    const CAP: usize = 2;
    let ca = TestCa::new("cp-grpc-shutdown").expect("ca");
    let (listener, addr) = bind_listener().await;
    let limiter = Arc::new(ConnLimiter::new(CAP, 0));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let _incoming = cp_grpc_tls_incoming(
        listener,
        tls_slot(server_config(&ca)),
        shutdown_rx,
        LONG_HANDSHAKE_TIMEOUT_SECS,
        Arc::clone(&limiter),
    );

    let mut parked = Vec::new();
    for _ in 0..CAP {
        parked.push(open_incomplete_session(addr).await);
    }
    wait_for(&limiter, "the pool to fill", |s| {
        s.active_connections == CAP as u64
    })
    .await;

    shutdown_tx.send(true).expect("signal shutdown");

    // In-flight handshakes still hold their permits; closing their sockets
    // releases each exactly once, leaving no leaked or double-counted slot.
    parked.clear();
    wait_for(&limiter, "all permits to release on teardown", |s| {
        s.active_connections == 0
    })
    .await;

    let snapshot = limiter.snapshot();
    assert_eq!(snapshot.active_connections, 0);
    assert_eq!(
        snapshot.rejected_max_connections, 0,
        "no spurious rejections during teardown"
    );
}

#[tokio::test]
async fn per_ip_share_bounds_one_source_below_the_global_cap() {
    // Global room for 8, but a single source IP may hold only 2. Every socket
    // here originates from loopback, so the per-IP cap is the binding one.
    let ca = TestCa::new("cp-grpc-per-ip").expect("ca");
    let (listener, addr) = bind_listener().await;
    let limiter = Arc::new(ConnLimiter::new(8, 2));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let _incoming = cp_grpc_tls_incoming(
        listener,
        tls_slot(server_config(&ca)),
        shutdown_rx,
        LONG_HANDSHAKE_TIMEOUT_SECS,
        Arc::clone(&limiter),
    );

    let mut parked = Vec::new();
    for _ in 0..2 {
        parked.push(open_incomplete_session(addr).await);
    }
    wait_for(&limiter, "the per-IP share to fill", |s| {
        s.active_connections == 2
    })
    .await;

    let refused = open_incomplete_session(addr).await;
    wait_for(&limiter, "a per-IP rejection", |s| {
        s.rejected_max_connections_per_ip >= 1
    })
    .await;

    let snapshot = limiter.snapshot();
    assert_eq!(
        snapshot.active_connections, 2,
        "one source may not exceed its per-IP share even with global room left"
    );
    assert_eq!(
        snapshot.rejected_max_connections, 0,
        "the global cap was never the binding constraint"
    );
    assert_closed_promptly(refused, "per-IP excess socket").await;
    drop(parked);
}

#[tokio::test]
async fn plaintext_listener_shares_the_same_admission_gate() {
    let (listener, addr) = bind_listener().await;
    let limiter = Arc::new(ConnLimiter::new(1, 0));

    let mut incoming = cp_grpc_plain_incoming(listener, Arc::clone(&limiter));

    let _first = TcpStream::connect(addr).await.expect("connect first");
    let admitted = tokio::time::timeout(SETTLE_TIMEOUT, incoming.next())
        .await
        .expect("first plaintext connection delivered")
        .expect("stream open");
    assert!(admitted.is_ok());
    assert_eq!(limiter.snapshot().active_connections, 1);

    // The second socket is refused. Polling the stream is what drives the
    // filter, so the negative wait both exercises admission and proves no
    // second connection is produced.
    let second = TcpStream::connect(addr).await.expect("connect second");
    assert!(
        tokio::time::timeout(NEGATIVE_WINDOW, incoming.next())
            .await
            .is_err(),
        "over-limit plaintext connection must not be delivered"
    );
    // Polling is what advances this stream, so drive it once more (rather than
    // sleeping) in case the accept wake-up landed late on a loaded runner.
    let _ = tokio::time::timeout(NEGATIVE_WINDOW, incoming.next()).await;
    let snapshot = limiter.snapshot();
    assert_eq!(snapshot.rejected_max_connections, 1);
    assert_eq!(snapshot.active_connections, 1);
    assert_closed_promptly(second, "excess plaintext socket").await;

    // Releasing the admitted connection lets the next one through.
    drop(admitted);
    wait_for(&limiter, "plaintext permit release", |s| {
        s.active_connections == 0
    })
    .await;
    let _third = TcpStream::connect(addr).await.expect("connect third");
    let readmitted = tokio::time::timeout(SETTLE_TIMEOUT, incoming.next())
        .await
        .expect("plaintext connection delivered after release")
        .expect("stream open");
    assert!(readmitted.is_ok());
}
