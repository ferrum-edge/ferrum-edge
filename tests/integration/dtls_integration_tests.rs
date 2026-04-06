//! Integration tests for the dimpl-based DTLS module.

use ferrum_edge::config::types::Proxy;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
}

fn generate_ca(cn: &str) -> GeneratedCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    let cert_pem = cert.pem();
    GeneratedCa {
        cert_pem,
        issuer: Issuer::new(params, key_pair),
    }
}

fn generate_signed_cert(ca: &GeneratedCa, cn: &str, sans: &[&str]) -> GeneratedCert {
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate leaf key");
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

fn write_pem(dir: &tempfile::TempDir, name: &str, data: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).expect("write PEM");
    path.to_string_lossy().into_owned()
}

fn build_dtls_proxy(backend_host: &str, backend_port: u16, ca_path: Option<String>) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "dtls-proxy-test",
        "listen_path": "/",
        "backend_protocol": "dtls",
        "backend_host": backend_host,
        "backend_port": backend_port,
        "listen_port": 40123,
        "backend_tls_verify_server_cert": true,
        "backend_tls_server_ca_cert_path": ca_path,
    }))
    .expect("build DTLS proxy")
}

async fn drain_dtls_client_outputs(
    client: &mut dimpl::Dtls,
    socket: &UdpSocket,
    out_buf: &mut [u8],
    next_timeout: &mut Option<Instant>,
    connected: &mut bool,
    received: &mut Option<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let mut saw_timeout_after_connected = false;
    for _ in 0..128 {
        match client.poll_output(out_buf) {
            dimpl::Output::Packet(data) => {
                socket.send(data).await?;
            }
            dimpl::Output::Timeout(t) => {
                *next_timeout = Some(t);
                if *connected && !saw_timeout_after_connected {
                    saw_timeout_after_connected = true;
                    continue;
                }
                break;
            }
            dimpl::Output::Connected => {
                *connected = true;
            }
            dimpl::Output::ApplicationData(data) => {
                *received = Some(data.to_vec());
            }
            dimpl::Output::PeerCert(_) | dimpl::Output::KeyingMaterial(_, _) => {}
            _ => {}
        }
    }
    Ok(())
}

async fn strict_dtls13_round_trip(
    server_addr: std::net::SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(server_addr).await?;

    let config = Arc::new(
        dimpl::Config::builder()
            .use_server_cookie(false)
            .build()
            .expect("build strict client config"),
    );
    let cert = dimpl::certificate::generate_self_signed_certificate()
        .expect("generate strict client cert");
    let mut client = dimpl::Dtls::new_13(config, cert, Instant::now());
    client.set_active(true);
    client
        .handle_timeout(Instant::now())
        .expect("prime strict client handshake");

    let mut out_buf = vec![0u8; 4096];
    let mut udp_buf = vec![0u8; 65536];
    let mut next_timeout = None;
    let mut connected = false;
    let mut received = None;

    drain_dtls_client_outputs(
        &mut client,
        &socket,
        &mut out_buf,
        &mut next_timeout,
        &mut connected,
        &mut received,
    )
    .await?;

    let handshake_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < handshake_deadline && !connected {
        let remaining = handshake_deadline.saturating_duration_since(Instant::now());
        let sleep_dur = next_timeout
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(200))
            .min(remaining)
            .min(Duration::from_millis(200));
        tokio::select! {
            result = socket.recv(&mut udp_buf) => {
                let len = result?;
                client.handle_packet(&udp_buf[..len])?;
            }
            _ = tokio::time::sleep(sleep_dur) => {
                if let Some(t) = next_timeout
                    && Instant::now() >= t
                {
                    client.handle_timeout(Instant::now())?;
                    next_timeout = None;
                }
            }
        }

        drain_dtls_client_outputs(
            &mut client,
            &socket,
            &mut out_buf,
            &mut next_timeout,
            &mut connected,
            &mut received,
        )
        .await?;
    }

    if !connected {
        anyhow::bail!("strict DTLS 1.3 handshake timed out");
    }

    client.send_application_data(payload)?;
    drain_dtls_client_outputs(
        &mut client,
        &socket,
        &mut out_buf,
        &mut next_timeout,
        &mut connected,
        &mut received,
    )
    .await?;

    let reply_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < reply_deadline {
        if let Some(reply) = received.take() {
            return Ok(reply);
        }

        let remaining = reply_deadline.saturating_duration_since(Instant::now());
        let sleep_dur = next_timeout
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(200))
            .min(remaining)
            .min(Duration::from_millis(200));
        tokio::select! {
            result = socket.recv(&mut udp_buf) => {
                let len = result?;
                client.handle_packet(&udp_buf[..len])?;
            }
            _ = tokio::time::sleep(sleep_dur) => {
                if let Some(t) = next_timeout
                    && Instant::now() >= t
                {
                    client.handle_timeout(Instant::now())?;
                    next_timeout = None;
                }
            }
        }

        drain_dtls_client_outputs(
            &mut client,
            &socket,
            &mut out_buf,
            &mut next_timeout,
            &mut connected,
            &mut received,
        )
        .await?;
    }

    anyhow::bail!("strict DTLS 1.3 echo timed out")
}

/// Raw dimpl handshake test — no wrappers, just state machines and UDP sockets.
/// This validates that dimpl itself works before testing our async wrappers.
#[tokio::test]
async fn test_dimpl_raw_handshake() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let server_cert =
        dimpl::certificate::generate_self_signed_certificate().expect("generate server cert");
    let client_cert =
        dimpl::certificate::generate_self_signed_certificate().expect("generate client cert");

    let config = Arc::new(
        dimpl::Config::builder()
            .use_server_cookie(false)
            .build()
            .expect("build config"),
    );

    // Bind sockets
    let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(server_addr).await.unwrap();
    let _client_addr = client_socket.local_addr().unwrap();

    // Create state machines
    let mut server = dimpl::Dtls::new_12(config.clone(), server_cert, Instant::now());
    // The server needs handle_timeout called to initialize its random/state
    let _ = server.handle_timeout(Instant::now());
    let mut client = dimpl::Dtls::new_auto(config, client_cert, Instant::now());
    client.set_active(true);

    let mut buf = vec![0u8; 4096];
    let mut udp_buf = vec![0u8; 65536];

    // ---- Client: produce ClientHello ----
    let mut client_timeout = None;
    loop {
        match client.poll_output(&mut buf) {
            dimpl::Output::Packet(data) => {
                eprintln!("[CLIENT] -> Packet {} bytes", data.len());
                client_socket.send(data).await.unwrap();
            }
            dimpl::Output::Timeout(t) => {
                eprintln!(
                    "[CLIENT] Timeout at +{:?}",
                    t.duration_since(Instant::now())
                );
                client_timeout = Some(t);
                break; // Timeout signals "no more outputs right now"
            }
            _ => break,
        }
    }

    // ---- Handshake loop ----
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut client_connected = false;
    let mut server_connected = false;

    while Instant::now() < deadline && !(client_connected && server_connected) {
        // Server: try to recv
        if let Ok(Ok((len, from))) = tokio::time::timeout(
            Duration::from_millis(200),
            server_socket.recv_from(&mut udp_buf),
        )
        .await
        {
            eprintln!("[SERVER] <- Recv {} bytes from {}", len, from);
            match server.handle_packet(&udp_buf[..len]) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("[SERVER] handle_packet ERROR: {}", e);
                }
            }
            // Drain server outputs — after Connected, skip one Timeout then
            // drain more to capture final flight packets (CCS + Finished).
            let mut saw_connected = false;
            let mut skipped_timeout = false;
            for drain_round in 0..128 {
                match server.poll_output(&mut buf) {
                    dimpl::Output::Packet(data) => {
                        eprintln!(
                            "[SERVER] -> Packet {} bytes to {} (drain {})",
                            data.len(),
                            from,
                            drain_round
                        );
                        server_socket.send_to(data, from).await.unwrap();
                    }
                    dimpl::Output::Connected => {
                        eprintln!("[SERVER] CONNECTED! (drain {})", drain_round);
                        server_connected = true;
                        saw_connected = true;
                    }
                    dimpl::Output::PeerCert(der) => {
                        eprintln!(
                            "[SERVER] PeerCert {} bytes (drain {})",
                            der.len(),
                            drain_round
                        );
                    }
                    dimpl::Output::Timeout(t) => {
                        eprintln!(
                            "[SERVER] Timeout +{:?} (drain {}, saw_connected={}, skipped={})",
                            t.duration_since(Instant::now()),
                            drain_round,
                            saw_connected,
                            skipped_timeout
                        );
                        if saw_connected && !skipped_timeout {
                            skipped_timeout = true;
                            continue;
                        }
                        break;
                    }
                    dimpl::Output::ApplicationData(_) => {}
                    dimpl::Output::KeyingMaterial(_, _) => {
                        eprintln!("[SERVER] KeyingMaterial (drain {})", drain_round);
                    }
                    _ => {
                        eprintln!("[SERVER] Unknown output (drain {})", drain_round);
                    }
                }
            }
        }

        // Client: try to recv
        match tokio::time::timeout(Duration::from_millis(200), client_socket.recv(&mut udp_buf))
            .await
        {
            Ok(Ok(len)) => {
                eprintln!("[CLIENT] <- Recv {} bytes", len);
                match client.handle_packet(&udp_buf[..len]) {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("[CLIENT] handle_packet ERROR: {}", e);
                    }
                }
                // Drain client outputs
                loop {
                    match client.poll_output(&mut buf) {
                        dimpl::Output::Packet(data) => {
                            eprintln!("[CLIENT] -> Packet {} bytes", data.len());
                            client_socket.send(data).await.unwrap();
                        }
                        dimpl::Output::Connected => {
                            eprintln!("[CLIENT] CONNECTED!");
                            client_connected = true;
                        }
                        dimpl::Output::PeerCert(der) => {
                            eprintln!("[CLIENT] PeerCert {} bytes", der.len());
                        }
                        dimpl::Output::Timeout(t) => {
                            eprintln!("[CLIENT] Timeout +{:?}", t.duration_since(Instant::now()));
                            client_timeout = Some(t);
                            break;
                        }
                        _ => break,
                    }
                }
            }
            _ => {
                // Check client retransmit timer
                if let Some(t) = client_timeout
                    && Instant::now() >= t
                {
                    eprintln!("[CLIENT] handle_timeout");
                    let _ = client.handle_timeout(Instant::now());
                    client_timeout = None;
                    loop {
                        match client.poll_output(&mut buf) {
                            dimpl::Output::Packet(data) => {
                                eprintln!("[CLIENT] -> Retransmit {} bytes", data.len());
                                client_socket.send(data).await.unwrap();
                            }
                            dimpl::Output::Timeout(t) => {
                                client_timeout = Some(t);
                                break;
                            }
                            _ => break,
                        }
                    }
                }
            }
        }
    }

    assert!(client_connected, "Client should have connected");
    assert!(server_connected, "Server should have connected");

    // ---- Test application data ----
    client.send_application_data(b"hello").unwrap();
    // Drain client -> send encrypted packet
    while let dimpl::Output::Packet(data) = client.poll_output(&mut buf) {
        client_socket.send(data).await.unwrap();
    }

    // Server: recv encrypted, get app data
    let (len, _) = server_socket.recv_from(&mut udp_buf).await.unwrap();
    server.handle_packet(&udp_buf[..len]).unwrap();
    let mut received = Vec::new();
    while let dimpl::Output::ApplicationData(data) = server.poll_output(&mut buf) {
        received.extend_from_slice(data);
    }
    assert_eq!(received, b"hello", "Server should receive app data");
    eprintln!("Application data exchange OK!");
}

/// Test the async DtlsConnection + DtlsServer wrappers.
#[tokio::test]
async fn test_dtls_client_server_handshake_and_echo() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let server_cert =
        dimpl::certificate::generate_self_signed_certificate().expect("generate server cert");

    let server_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_config = dimpl::Config::builder()
        .build()
        .expect("build server config");
    let frontend_config = ferrum_edge::dtls::FrontendDtlsConfig {
        dimpl_config: Arc::new(server_config),
        certificate: server_cert,
        client_cert_verifier: None,
    };

    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind(server_addr, frontend_config)
            .await
            .expect("bind server"),
    );
    let actual_addr = server.local_addr();

    // Spawn server recv loop
    let server_runner = server.clone();
    tokio::spawn(async move {
        let _ = server_runner.run().await;
    });

    // Spawn echo handler
    let server_acceptor = server.clone();
    tokio::spawn(async move {
        while let Ok((conn, _addr)) = server_acceptor.accept().await {
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

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client");
    client_socket
        .connect(actual_addr)
        .await
        .expect("connect client");

    let client_config = dimpl::Config::builder()
        .build()
        .expect("build client config");
    let params = ferrum_edge::dtls::BackendDtlsParams {
        config: Arc::new(client_config),
        certificate: dimpl::certificate::generate_self_signed_certificate()
            .expect("generate client cert"),
        server_name: None,
        server_cert_verifier: None,
    };

    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        ferrum_edge::dtls::DtlsConnection::connect(client_socket, params),
    )
    .await
    .expect("handshake timeout")
    .expect("handshake error");

    let msg = b"Hello DTLS!";
    conn.send(msg).await.expect("send");

    let reply = tokio::time::timeout(Duration::from_secs(5), conn.recv())
        .await
        .expect("recv timeout")
        .expect("recv error");

    assert_eq!(&reply, msg, "Echo should match");

    conn.close().await;
}

/// Test using PEM-loaded certificates (same path as the gateway binary).
/// This catches issues with `build_frontend_dtls_config` and PEM parsing.
#[tokio::test]
async fn test_dtls_pem_cert_handshake() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Generate ECDSA P-256 cert via rcgen and write to temp PEM files
    let temp_dir = tempfile::TempDir::new().unwrap();
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

    // Build config via the production code path
    let frontend_config = ferrum_edge::dtls::build_frontend_dtls_config(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        None,
        &[],
    )
    .expect("build frontend config");

    let server_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind(server_addr, frontend_config)
            .await
            .expect("bind server"),
    );
    let actual_addr = server.local_addr();

    let server_runner = server.clone();
    tokio::spawn(async move {
        let _ = server_runner.run().await;
    });

    let server_acceptor = server.clone();
    tokio::spawn(async move {
        while let Ok((conn, _addr)) = server_acceptor.accept().await {
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

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(actual_addr).await.unwrap();

    let client_config = dimpl::Config::builder().build().expect("client config");
    let params = ferrum_edge::dtls::BackendDtlsParams {
        config: Arc::new(client_config),
        certificate: dimpl::certificate::generate_self_signed_certificate().unwrap(),
        server_name: None,
        server_cert_verifier: None,
    };

    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        ferrum_edge::dtls::DtlsConnection::connect(client_socket, params),
    )
    .await
    .expect("PEM cert handshake timeout")
    .expect("PEM cert handshake error");

    let msg = b"PEM cert test!";
    conn.send(msg).await.expect("send");

    let reply = tokio::time::timeout(Duration::from_secs(5), conn.recv())
        .await
        .expect("recv timeout")
        .expect("recv error");

    assert_eq!(&reply, msg);
    conn.close().await;
}

#[tokio::test]
async fn test_frontend_dtls_config_disables_client_auth_without_ca() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let temp_dir = tempfile::TempDir::new().unwrap();
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

    let frontend_config = ferrum_edge::dtls::build_frontend_dtls_config(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        None,
        &[],
    )
    .expect("build frontend config");

    assert!(
        !frontend_config.dimpl_config.require_client_certificate(),
        "frontend DTLS should not require client certs when no DTLS client CA is configured"
    );
    assert!(
        frontend_config.client_cert_verifier.is_none(),
        "frontend DTLS should not build a client verifier when no DTLS client CA is configured"
    );
}

#[tokio::test]
async fn test_dtls_server_accepts_strict_dtls13_client() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let server_cert =
        dimpl::certificate::generate_self_signed_certificate().expect("generate server cert");
    let frontend_config = ferrum_edge::dtls::FrontendDtlsConfig {
        dimpl_config: Arc::new(
            dimpl::Config::builder()
                .use_server_cookie(false)
                .build()
                .expect("build frontend config"),
        ),
        certificate: server_cert,
        client_cert_verifier: None,
    };

    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind("127.0.0.1:0".parse().unwrap(), frontend_config)
            .await
            .expect("bind server"),
    );
    let server_addr = server.local_addr();

    let server_runner = server.clone();
    let run_task = tokio::spawn(async move { server_runner.run().await });

    let server_acceptor = server.clone();
    let accept_task = tokio::spawn(async move {
        let (conn, _) = server_acceptor
            .accept()
            .await
            .expect("accept strict client");
        let data = conn.recv().await.expect("recv strict client data");
        assert_eq!(data, b"strict-dtls13");
        conn.send(&data).await.expect("echo strict client data");
    });

    let reply = strict_dtls13_round_trip(server_addr, b"strict-dtls13")
        .await
        .expect("strict DTLS 1.3 round trip");
    assert_eq!(reply, b"strict-dtls13");

    server.close().await;
    tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .expect("accept task timeout")
        .expect("accept task join");
    let _ = tokio::time::timeout(Duration::from_secs(5), run_task)
        .await
        .expect("run task timeout")
        .expect("run task join");
}

#[tokio::test]
async fn test_backend_dtls_verification_rejects_hostname_mismatch() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let temp_dir = tempfile::TempDir::new().unwrap();
    let ca = generate_ca("Ferrum Test DTLS CA");
    let server_cert = generate_signed_cert(&ca, "localhost", &["localhost"]);

    let cert_path = write_pem(&temp_dir, "server-cert.pem", &server_cert.cert_pem);
    let key_path = write_pem(&temp_dir, "server-key.pem", &server_cert.key_pem);
    let ca_path = write_pem(&temp_dir, "ca.pem", &ca.cert_pem);

    let frontend_config =
        ferrum_edge::dtls::build_frontend_dtls_config(&cert_path, &key_path, None, &[])
            .expect("build frontend config");
    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind("127.0.0.1:0".parse().unwrap(), frontend_config)
            .await
            .expect("bind server"),
    );
    let server_addr = server.local_addr();
    let server_runner = server.clone();
    let run_task = tokio::spawn(async move { server_runner.run().await });

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(server_addr).await.unwrap();

    let proxy = build_dtls_proxy("wrong.example", server_addr.port(), Some(ca_path));
    let params = ferrum_edge::dtls::build_backend_dtls_config(
        &proxy,
        &proxy.backend_host,
        false,
        &std::sync::Arc::new(Vec::new()),
    )
    .unwrap();
    let err = match ferrum_edge::dtls::DtlsConnection::connect(client_socket, params).await {
        Ok(_) => panic!("hostname mismatch should fail DTLS verification"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("verification"),
        "expected verification error, got: {}",
        err
    );

    server.close().await;
    let _ = run_task.await.expect("run task join");
}

#[tokio::test]
async fn test_dtls_server_close_releases_socket() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let server_cert =
        dimpl::certificate::generate_self_signed_certificate().expect("generate server cert");
    let frontend_config = ferrum_edge::dtls::FrontendDtlsConfig {
        dimpl_config: Arc::new(dimpl::Config::builder().build().expect("build config")),
        certificate: server_cert,
        client_cert_verifier: None,
    };

    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind("127.0.0.1:0".parse().unwrap(), frontend_config)
            .await
            .expect("bind server"),
    );
    let server_addr = server.local_addr();
    let server_runner = server.clone();
    let run_task = tokio::spawn(async move { server_runner.run().await });

    server.close().await;
    let _ = run_task.await.expect("run task join");
    drop(server);

    let rebound = UdpSocket::bind(server_addr)
        .await
        .expect("server close should release UDP socket");
    drop(rebound);
}
