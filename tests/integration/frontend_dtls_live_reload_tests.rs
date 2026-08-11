//! Frontend DTLS material live reload (issue #3730).
//!
//! Covers file-source fingerprint reload under the shared frontend live-reload
//! subscription contract, watcher shutdown/cancellation without leaks, and
//! live-path `DtlsServer::swap_frontend_config` acceptance (UDP socket retained,
//! established sessions kept, new handshakes observe the accepted identity /
//! client-CA / CRL generation).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::dtls::{
    BackendDtlsParams, DtlsConnection, DtlsServer, FrontendDtlsConfig, load_dtls_certificate,
    load_root_store_from_pem,
};
use ferrum_edge::tls::build_server_verifier_with_crls;
use ferrum_edge::tls::source::subscription::{
    AsyncMaterialSetReloadConfig, WatchedMaterialSource, request_material_set_reload,
    spawn_async_material_set_reload_task,
};
use ferrum_edge::tls::source::{CertSource, MaterialKind};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::CertificateRevocationListDer;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn write_ecdsa_material(
    dir: &std::path::Path,
    san: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    ensure_crypto_provider();
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec![san.to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let cert_path = dir.join(format!("{san}-cert.pem"));
    let key_path = dir.join(format!("{san}-key.pem"));
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    (cert_path, key_path)
}

fn build_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> ferrum_edge::dtls::FrontendDtlsConfig {
    ferrum_edge::dtls::build_frontend_dtls_config(
        cert_path.to_str().expect("cert utf8"),
        key_path.to_str().expect("key utf8"),
        None,
        &[],
    )
    .expect("build frontend dtls config")
}

#[tokio::test]
async fn dtls_material_watcher_rotates_on_file_change_and_exits_on_shutdown() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = write_ecdsa_material(dir.path(), "watch");

    let rebuilds = Arc::new(AtomicUsize::new(0));
    let rebuilds_for_task = rebuilds.clone();
    let cert_for_rebuild = cert_path.clone();
    let key_for_rebuild = key_path.clone();

    let (revision_tx, mut revision_rx) = watch::channel(0u64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = spawn_async_material_set_reload_task(
        AsyncMaterialSetReloadConfig {
            surface: "test_frontend_dtls_reload",
            sources: vec![
                WatchedMaterialSource::new(
                    "dtls_cert",
                    CertSource::parse(cert_path.to_string_lossy().into_owned(), MaterialKind::Cert),
                    MaterialKind::Cert,
                ),
                WatchedMaterialSource::new(
                    "dtls_key",
                    CertSource::parse(key_path.to_string_lossy().into_owned(), MaterialKind::Key),
                    MaterialKind::Key,
                ),
            ],
            interval: Duration::from_secs(3600),
            revision_tx,
            max_material_bytes: EnvConfig::default().tls_max_material_size_bytes,
            ready_tx: Some(ready_tx),
            rebuild: Box::new(move || {
                let rebuilds_for_task = rebuilds_for_task.clone();
                let cert_for_rebuild = cert_for_rebuild.clone();
                let key_for_rebuild = key_for_rebuild.clone();
                Box::pin(async move {
                    // Prove the production builder accepts the rotated bytes as
                    // one candidate generation before any listener publish.
                    let _ = build_config(&cert_for_rebuild, &key_for_rebuild);
                    rebuilds_for_task.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }),
        },
        Some(shutdown_rx),
    );
    ready_rx.await.expect("watcher fingerprint baseline");

    // Rotate cert+key content under the same source paths (file:// contract).
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("rotate key");
    let params = rcgen::CertificateParams::new(vec!["watch-rotated".to_string()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    std::fs::write(&cert_path, cert.pem()).expect("rewrite cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("rewrite key");

    assert!(request_material_set_reload("test_frontend_dtls_reload"));
    tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
        .await
        .expect("rotation should bump revision")
        .expect("watcher alive");
    assert_eq!(*revision_rx.borrow(), 1);
    assert_eq!(rebuilds.load(Ordering::SeqCst), 1);

    shutdown_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("watcher should exit on shutdown")
        .expect("watcher join");
}

#[tokio::test]
async fn dtls_material_watcher_keeps_prior_state_and_retries_same_failed_candidate() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = write_ecdsa_material(dir.path(), "fail");

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_task = attempts.clone();
    let (revision_tx, mut revision_rx) = watch::channel(0u64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = spawn_async_material_set_reload_task(
        AsyncMaterialSetReloadConfig {
            surface: "test_frontend_dtls_reload_fail",
            sources: vec![
                WatchedMaterialSource::new(
                    "dtls_cert",
                    CertSource::parse(cert_path.to_string_lossy().into_owned(), MaterialKind::Cert),
                    MaterialKind::Cert,
                ),
                WatchedMaterialSource::new(
                    "dtls_key",
                    CertSource::parse(key_path.to_string_lossy().into_owned(), MaterialKind::Key),
                    MaterialKind::Key,
                ),
            ],
            interval: Duration::from_secs(3600),
            revision_tx,
            max_material_bytes: EnvConfig::default().tls_max_material_size_bytes,
            ready_tx: Some(ready_tx),
            rebuild: Box::new(move || {
                let attempts_for_task = attempts_for_task.clone();
                Box::pin(async move {
                    let attempt = attempts_for_task.fetch_add(1, Ordering::SeqCst);
                    if attempt == 0 {
                        Err(anyhow::anyhow!("simulated transient rebuild failure"))
                    } else {
                        Ok(())
                    }
                })
            }),
        },
        Some(shutdown_rx),
    );
    ready_rx.await.expect("watcher fingerprint baseline");

    std::fs::write(&cert_path, b"not-a-certificate").expect("corrupt cert");
    assert!(request_material_set_reload(
        "test_frontend_dtls_reload_fail"
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        while attempts.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first failed rebuild attempt");
    assert_eq!(
        *revision_rx.borrow(),
        0,
        "failed rebuild must not bump the accepted revision"
    );

    assert!(request_material_set_reload(
        "test_frontend_dtls_reload_fail"
    ));
    tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
        .await
        .expect("stable failed candidate should be retried")
        .expect("watcher alive");
    assert_eq!(*revision_rx.borrow(), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    shutdown_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("watcher should exit on shutdown")
        .expect("watcher join");
}

#[test]
fn frontend_dtls_builder_rejects_expired_and_not_yet_valid_certificates() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");

    for (name, not_before, not_after, expected) in [
        (
            "expired",
            time::OffsetDateTime::now_utc() - time::Duration::days(2),
            time::OffsetDateTime::now_utc() - time::Duration::days(1),
            "expired",
        ),
        (
            "future",
            time::OffsetDateTime::now_utc() + time::Duration::days(1),
            time::OffsetDateTime::now_utc() + time::Duration::days(2),
            "not yet valid",
        ),
    ] {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("params");
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params.self_signed(&key_pair).expect("self-sign");
        let cert_path = dir.path().join(format!("{name}-cert.pem"));
        let key_path = dir.path().join(format!("{name}-key.pem"));
        std::fs::write(&cert_path, cert.pem()).expect("write cert");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");

        let error = ferrum_edge::dtls::build_frontend_dtls_config(
            cert_path.to_str().expect("cert utf8"),
            key_path.to_str().expect("key utf8"),
            None,
            &[],
        )
        .err()
        .expect("invalid certificate lifetime must be refused");
        assert!(
            error.to_string().contains(expected),
            "unexpected {name} error: {error}"
        );
    }
}

#[test]
fn frontend_dtls_live_reload_defaults_to_static_until_restart() {
    let env = EnvConfig::default();
    assert!(
        !env.frontend_tls_live_reload_enabled,
        "DTLS material stays static until restart unless the shared frontend live-reload flag is enabled"
    );
}

// ---------------------------------------------------------------------------
// Live-path DtlsServer swap acceptance (issue #3730)
// ---------------------------------------------------------------------------

struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    path: std::path::PathBuf,
}

struct SignedMaterial {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    serial: SerialNumber,
}

fn write_pem(dir: &std::path::Path, name: &str, pem: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, pem).expect("write pem");
    path
}

fn generate_test_ca(dir: &std::path::Path, cn: &str) -> TestCa {
    ensure_crypto_provider();
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    let path = write_pem(dir, &format!("{cn}.pem"), &cert.pem());
    TestCa {
        issuer: Issuer::new(params, key_pair),
        path,
    }
}

fn generate_signed_material(
    dir: &std::path::Path,
    ca: &TestCa,
    name: &str,
    sans: &[&str],
    serial: u64,
) -> SignedMaterial {
    ensure_crypto_provider();
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate leaf key");
    let serial = SerialNumber::from(serial);
    let san_strings: Vec<String> = sans.iter().map(|s| (*s).to_string()).collect();
    let mut params = CertificateParams::new(san_strings).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.serial_number = Some(serial.clone());
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    SignedMaterial {
        cert_path: write_pem(dir, &format!("{name}-cert.pem"), &cert.pem()),
        key_path: write_pem(dir, &format!("{name}-key.pem"), &key_pair.serialize_pem()),
        serial,
    }
}

fn build_crl(ca: &TestCa, revoked: &[SerialNumber]) -> Vec<CertificateRevocationListDer<'static>> {
    let now = time::OffsetDateTime::now_utc();
    let revoked_certs = revoked
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: serial.clone(),
            revocation_time: now,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(30),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl_pem = params
        .signed_by(&ca.issuer)
        .expect("sign CRL")
        .pem()
        .expect("encode CRL pem");
    rustls_pemfile::crls(&mut crl_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect()
}

fn path_str(path: &std::path::Path) -> &str {
    path.to_str().expect("utf8 path")
}

fn frontend_config(
    server: &SignedMaterial,
    client_ca: Option<&TestCa>,
    crls: &[CertificateRevocationListDer<'static>],
) -> FrontendDtlsConfig {
    ferrum_edge::dtls::build_frontend_dtls_config(
        path_str(&server.cert_path),
        path_str(&server.key_path),
        client_ca.map(|ca| path_str(&ca.path)),
        crls,
    )
    .expect("build frontend dtls config")
}

async fn spawn_echo_dtls_server(config: FrontendDtlsConfig) -> Arc<DtlsServer> {
    let server = Arc::new(
        DtlsServer::bind("127.0.0.1:0".parse().expect("bind addr"), config)
            .await
            .expect("bind dtls server"),
    );
    let runner = server.clone();
    tokio::spawn(async move {
        let _ = runner.run().await;
    });
    let acceptor = server.clone();
    tokio::spawn(async move {
        while let Ok((conn, _)) = acceptor.accept().await {
            tokio::spawn(async move {
                loop {
                    match conn.recv().await {
                        Ok(data) if !data.is_empty() => {
                            if conn.send(&data).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            });
        }
    });
    // Let the recv loop attach before the first ClientHello.
    tokio::time::sleep(Duration::from_millis(50)).await;
    server
}

async fn connect_dtls_client(
    server_addr: SocketAddr,
    client_material: &SignedMaterial,
    trust_ca: Option<&TestCa>,
    connect_timeout_ms: u64,
) -> Result<DtlsConnection, anyhow::Error> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(server_addr).await?;
    let certificate = load_dtls_certificate(
        path_str(&client_material.cert_path),
        path_str(&client_material.key_path),
    )?;
    let (server_name, server_cert_verifier) = if let Some(ca) = trust_ca {
        let roots = load_root_store_from_pem(path_str(&ca.path))?;
        let verifier = build_server_verifier_with_crls(roots, &[])?;
        (
            Some(
                rustls::pki_types::ServerName::try_from("localhost".to_string())
                    .expect("localhost server name"),
            ),
            Some(verifier as _),
        )
    } else {
        (None, None)
    };
    let params = BackendDtlsParams {
        config: Arc::new(
            dimpl::Config::builder()
                .build()
                .expect("client dimpl config"),
        ),
        certificate,
        server_name,
        server_cert_verifier,
        connect_timeout_ms,
    };
    DtlsConnection::connect(socket, params).await
}

async fn echo_round_trip(conn: &DtlsConnection, payload: &[u8]) {
    conn.send(payload).await.expect("send dtls payload");
    let reply = tokio::time::timeout(Duration::from_secs(5), conn.recv())
        .await
        .expect("echo recv timeout")
        .expect("echo recv");
    assert_eq!(
        reply, payload,
        "established DTLS session must remain usable"
    );
}

async fn assert_new_dtls_session_rejected(
    connection: Result<DtlsConnection, anyhow::Error>,
    reason: &str,
) {
    let Ok(conn) = connection else {
        return;
    };
    if conn.send(b"must-not-echo").await.is_ok()
        && let Ok(Ok(reply)) = tokio::time::timeout(Duration::from_secs(2), conn.recv()).await
    {
        panic!("{reason}; rejected session unexpectedly echoed {reply:?}");
    }
    conn.close().await;
}

async fn assert_udp_socket_still_owns(addr: SocketAddr) {
    let conflict = UdpSocket::bind(addr).await;
    assert!(
        conflict.is_err(),
        "live-swapped DtlsServer must retain the original UDP bind; rebinding {addr} unexpectedly succeeded"
    );
}

#[tokio::test]
async fn dtls_server_live_swap_keeps_socket_and_session_and_presents_new_identity() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let root_a = generate_test_ca(dir.path(), "dtls-root-a");
    let root_b = generate_test_ca(dir.path(), "dtls-root-b");
    let server_v1 = generate_signed_material(dir.path(), &root_a, "server-v1", &["localhost"], 11);
    let server_v2 = generate_signed_material(dir.path(), &root_b, "server-v2", &["localhost"], 12);
    // Ephemeral client identities (server does not require client certs here).
    let client_idle =
        generate_signed_material(dir.path(), &root_a, "client-idle", &["client.example"], 21);
    let client_new =
        generate_signed_material(dir.path(), &root_b, "client-new", &["client.example"], 22);

    let server = spawn_echo_dtls_server(frontend_config(&server_v1, None, &[])).await;
    let addr_before = server.local_addr();

    let established = connect_dtls_client(addr_before, &client_idle, Some(&root_a), 10_000)
        .await
        .expect("pre-swap handshake must present root-A identity");
    echo_round_trip(&established, b"pre-swap").await;

    server.swap_frontend_config(frontend_config(&server_v2, None, &[]));

    assert_eq!(
        server.local_addr(),
        addr_before,
        "swap_frontend_config must not rebind the UDP socket"
    );
    assert_udp_socket_still_owns(addr_before).await;
    echo_round_trip(&established, b"post-swap-established").await;

    let stale = connect_dtls_client(addr_before, &client_idle, Some(&root_a), 2_000).await;
    assert!(
        stale.is_err(),
        "new handshake must not present the retired root-A server identity"
    );

    let rotated = connect_dtls_client(addr_before, &client_new, Some(&root_b), 10_000)
        .await
        .expect("new handshake must present the accepted root-B identity");
    echo_round_trip(&rotated, b"post-swap-new").await;

    established.close().await;
    rotated.close().await;
    server.close().await;
}

#[tokio::test]
async fn dtls_server_live_swap_client_ca_replacement_rejects_old_ca_clients() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let server_ca = generate_test_ca(dir.path(), "dtls-server-ca");
    let client_ca_a = generate_test_ca(dir.path(), "dtls-client-ca-a");
    let client_ca_b = generate_test_ca(dir.path(), "dtls-client-ca-b");
    let server_id =
        generate_signed_material(dir.path(), &server_ca, "mtls-server", &["localhost"], 31);
    let client_a = generate_signed_material(
        dir.path(),
        &client_ca_a,
        "client-a",
        &["client-a.example"],
        32,
    );
    let client_b = generate_signed_material(
        dir.path(),
        &client_ca_b,
        "client-b",
        &["client-b.example"],
        33,
    );

    let server = spawn_echo_dtls_server(frontend_config(&server_id, Some(&client_ca_a), &[])).await;
    let addr = server.local_addr();

    let ok_a = connect_dtls_client(addr, &client_a, Some(&server_ca), 10_000)
        .await
        .expect("client signed by CA-A must be admitted before rotation");
    echo_round_trip(&ok_a, b"ca-a-ok").await;

    // Replace (do not merely disable) the client-CA trust snapshot.
    server.swap_frontend_config(frontend_config(&server_id, Some(&client_ca_b), &[]));
    assert_eq!(server.local_addr(), addr);
    assert_udp_socket_still_owns(addr).await;
    echo_round_trip(&ok_a, b"ca-a-session-retained").await;

    assert_new_dtls_session_rejected(
        connect_dtls_client(addr, &client_a, Some(&server_ca), 2_000).await,
        "clients trusted only by the removed CA-A must fail after client-CA replacement",
    )
    .await;

    let ok_b = connect_dtls_client(addr, &client_b, Some(&server_ca), 10_000)
        .await
        .expect("clients signed by the replacement CA-B must be admitted");
    echo_round_trip(&ok_b, b"ca-b-ok").await;

    ok_a.close().await;
    ok_b.close().await;
    server.close().await;
}

#[tokio::test]
async fn dtls_server_live_swap_crl_only_rejects_newly_revoked_client() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let server_ca = generate_test_ca(dir.path(), "dtls-crl-server-ca");
    let client_ca = generate_test_ca(dir.path(), "dtls-crl-client-ca");
    let server_id =
        generate_signed_material(dir.path(), &server_ca, "crl-server", &["localhost"], 41);
    let client = generate_signed_material(
        dir.path(),
        &client_ca,
        "crl-client",
        &["crl-client.example"],
        42,
    );

    let server = spawn_echo_dtls_server(frontend_config(&server_id, Some(&client_ca), &[])).await;
    let addr = server.local_addr();

    let established = connect_dtls_client(addr, &client, Some(&server_ca), 10_000)
        .await
        .expect("unrevoked client must connect before CRL-only rotation");
    echo_round_trip(&established, b"pre-crl").await;

    let crls = build_crl(&client_ca, std::slice::from_ref(&client.serial));
    assert!(!crls.is_empty(), "CRL must parse from PEM");
    server.swap_frontend_config(frontend_config(&server_id, Some(&client_ca), &crls));

    assert_eq!(server.local_addr(), addr);
    assert_udp_socket_still_owns(addr).await;
    echo_round_trip(&established, b"post-crl-established").await;

    assert_new_dtls_session_rejected(
        connect_dtls_client(addr, &client, Some(&server_ca), 2_000).await,
        "CRL-only generation must reject a newly revoked client on the next handshake",
    )
    .await;

    established.close().await;
    server.close().await;
}

#[tokio::test]
async fn dtls_server_multi_listener_live_swap_converges_on_same_generation() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let root_a = generate_test_ca(dir.path(), "multi-root-a");
    let root_b = generate_test_ca(dir.path(), "multi-root-b");
    let server_v1 =
        generate_signed_material(dir.path(), &root_a, "multi-server-v1", &["localhost"], 51);
    let server_v2 =
        generate_signed_material(dir.path(), &root_b, "multi-server-v2", &["localhost"], 52);
    let client_a = generate_signed_material(
        dir.path(),
        &root_a,
        "multi-client-a",
        &["client.example"],
        53,
    );
    let client_b = generate_signed_material(
        dir.path(),
        &root_b,
        "multi-client-b",
        &["client.example"],
        54,
    );

    let left = spawn_echo_dtls_server(frontend_config(&server_v1, None, &[])).await;
    let right = spawn_echo_dtls_server(frontend_config(&server_v1, None, &[])).await;
    let left_addr = left.local_addr();
    let right_addr = right.local_addr();
    assert_ne!(left_addr, right_addr);

    // Mirror StreamListenerManager::swap_active_dtls_frontend_config: one
    // prevalidated generation is live-swapped onto every active DtlsServer.
    let accepted = frontend_config(&server_v2, None, &[]);
    left.swap_frontend_config(accepted.clone());
    right.swap_frontend_config(accepted);

    assert_eq!(left.local_addr(), left_addr);
    assert_eq!(right.local_addr(), right_addr);
    assert_udp_socket_still_owns(left_addr).await;
    assert_udp_socket_still_owns(right_addr).await;

    for addr in [left_addr, right_addr] {
        assert!(
            connect_dtls_client(addr, &client_a, Some(&root_a), 2_000)
                .await
                .is_err(),
            "every live-swapped listener must leave the prior generation"
        );
        let conn = connect_dtls_client(addr, &client_b, Some(&root_b), 10_000)
            .await
            .expect("every live-swapped listener must serve the accepted generation");
        echo_round_trip(&conn, b"multi-ok").await;
        conn.close().await;
    }

    left.close().await;
    right.close().await;
}
