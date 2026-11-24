//! Spawned-listener readiness must wait for stream binds without sending UDP traffic.

use super::harness::{StreamListener, wait_for_spawned_gateway};
use super::port_registry::TestSocket;
use super::ports::{reserve_port, unbound_port, unbound_udp_port};
use crate::common::GatewayChildGuard;
use crate::common::gateway_harness::SpawnedGatewayIdentity;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

fn readiness_child() -> GatewayChildGuard {
    spawn_readiness_child(None)
}

fn spawn_readiness_child(identity: Option<(u16, SpawnedGatewayIdentity)>) -> GatewayChildGuard {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "scaffolding::harness_readiness_tests::hold_readiness_child",
            "--nocapture",
        ])
        .env("TEST_GATEWAY_READINESS_CHILD", "1")
        .env("FERRUM_ADMIN_HTTP_PORT", "0")
        .env("FERRUM_ADMIN_JWT_SECRET", "readiness-fixture-secret")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match identity {
        Some((port, identity)) => {
            GatewayChildGuard::spawn_with_identity(&mut command, port, identity)
        }
        None => GatewayChildGuard::spawn(&mut command),
    }
    .expect("spawn readiness fixture child")
}

/// Serve the admin contract with an explicit readiness barrier. Requests are
/// reported to the test so it can order the UDP bind without scheduler sleeps.
async fn readiness_admin(
    identity: SpawnedGatewayIdentity,
    ready: Arc<AtomicBool>,
    accept_jwt: bool,
) -> (
    u16,
    tokio::task::JoinHandle<()>,
    mpsc::UnboundedReceiver<()>,
) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let (observed, requests) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let len = stream.read(&mut chunk).await.unwrap();
                if len == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..len]);
            }
            let request = String::from_utf8(request).unwrap();
            let bearer = request.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if !name.eq_ignore_ascii_case("authorization") {
                    return None;
                }
                value.trim().strip_prefix("Bearer ")
            });
            let is_proxies = request.starts_with("GET /proxies ");
            let authorized = if is_proxies {
                let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
                validation.validate_exp = true;
                validation.set_issuer(&[&identity.jwt_issuer]);
                accept_jwt
                    && bearer.is_some_and(|token| {
                        jsonwebtoken::decode::<serde_json::Value>(
                            token,
                            &jsonwebtoken::DecodingKey::from_secret(identity.jwt_secret.as_bytes())
                                .unwrap(),
                            &validation,
                        )
                        .is_ok()
                    })
            } else {
                bearer == Some(identity.observability_token.as_str())
            };
            let status = if authorized {
                "200 OK"
            } else {
                "401 Unauthorized"
            };
            let body = if is_proxies {
                "[]".to_string()
            } else {
                serde_json::json!({
                    "status": "ok",
                    "ready": ready.load(Ordering::SeqCst),
                    "cached_config": {"available": true},
                })
                .to_string()
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = observed.send(());
        }
    });
    (port, task, requests)
}

#[test]
fn hold_readiness_child() {
    if std::env::var_os("TEST_GATEWAY_READINESS_CHILD").is_some() {
        // The parent owns the pipe; closing it lets the child exit during a probe.
        let _ = std::io::stdin().read_exact(&mut [0]);
        // Exceed a pipe buffer and the diagnostic budget. File-backed capture
        // must let the child exit and retain the tail of BOTH output streams.
        let padding = vec![b'x'; 128 * 1024];
        for mut output in [
            Box::new(std::io::stdout()) as Box<dyn Write>,
            Box::new(std::io::stderr()) as Box<dyn Write>,
        ] {
            output.write_all(&padding).unwrap();
            writeln!(output, "\nstartup failed: Address already in use").unwrap();
            writeln!(output, "readiness-fixture-secret").unwrap();
        }
        std::process::exit(1);
    }
}

#[tokio::test]
async fn http_accept_does_not_admit_unbound_udp_and_probe_sends_no_datagrams() {
    let identity = SpawnedGatewayIdentity::mint("udp-readiness");
    let bound = Arc::new(AtomicBool::new(false));
    let (admin_port, admin, mut requests) =
        readiness_admin(identity.clone(), Arc::clone(&bound), true).await;
    let mut child = spawn_readiness_child(Some((admin_port, identity)));
    let http = reserve_port().await.unwrap();
    let udp_port = unbound_udp_port().await.unwrap();

    // Reproduce the old probe's critical section deterministically. The parent
    // owns this lease, so bind_test accepts its probe after handoff. A concurrent
    // wildcard bind by the child then fails even though no other test has a lease.
    let probe = std::net::UdpSocket::bind_test(("127.0.0.1", udp_port)).unwrap();
    assert_eq!(
        super::port_registry::bind_udp_socket(([0, 0, 0, 0], udp_port).into())
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrInUse
    );
    let mut ready = Box::pin(wait_for_spawned_gateway(
        &mut child,
        http.port,
        Some(StreamListener::Udp(udp_port)),
    ));
    timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut ready => panic!("a UDP bind is not owned readiness: {result:?}"),
            request = requests.recv() => assert!(request.is_some()),
        }
    })
    .await
    .expect("UDP readiness must consult the admin barrier without rebinding");
    drop(probe);
    assert!(
        timeout(Duration::from_millis(100), &mut ready)
            .await
            .is_err(),
        "HTTP acceptance must not make an unbound UDP listener ready"
    );

    let udp = std::net::UdpSocket::bind_test(("0.0.0.0", udp_port)).unwrap();
    // A bound UDP port still does not establish that the child finished startup.
    assert!(
        timeout(Duration::from_millis(100), &mut ready)
            .await
            .is_err()
    );
    bound.store(true, Ordering::SeqCst);
    timeout(Duration::from_secs(5), ready)
        .await
        .expect("owned admin readiness must release the wait")
        .unwrap();
    udp.set_nonblocking(true).unwrap();
    assert_eq!(
        udp.recv_from(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "readiness must not send even an empty UDP datagram"
    );
    admin.abort();
}

#[tokio::test]
async fn udp_readiness_rejects_ready_admin_without_matching_jwt() {
    let identity = SpawnedGatewayIdentity::mint("foreign-udp-admin");
    let (admin_port, admin, _) =
        readiness_admin(identity.clone(), Arc::new(AtomicBool::new(true)), false).await;
    let mut child = spawn_readiness_child(Some((admin_port, identity)));
    let http = reserve_port().await.unwrap();
    let udp = super::ports::reserve_udp_port().await.unwrap();
    assert!(
        timeout(
            Duration::from_millis(500),
            wait_for_spawned_gateway(&mut child, http.port, Some(StreamListener::Udp(udp.port))),
        )
        .await
        .is_err(),
        "a bound UDP port and full ready health cannot replace JWT ownership"
    );
    admin.abort();
}

#[tokio::test]
async fn udp_readiness_requires_an_identity_instead_of_falling_back_to_a_bind() {
    let mut child = readiness_child();
    let http = reserve_port().await.unwrap();
    let udp = super::ports::reserve_udp_port().await.unwrap();
    let error =
        wait_for_spawned_gateway(&mut child, http.port, Some(StreamListener::Udp(udp.port)))
            .await
            .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("spawn_with_identity"));
}

#[tokio::test]
async fn http_accept_does_not_admit_unbound_tcp_stream() {
    let mut child = readiness_child();
    let http = reserve_port().await.unwrap();
    let tcp_port = unbound_port().await.unwrap();
    let mut ready = Box::pin(wait_for_spawned_gateway(
        &mut child,
        http.port,
        Some(StreamListener::Tcp(tcp_port)),
    ));
    assert!(
        timeout(Duration::from_millis(100), &mut ready)
            .await
            .is_err(),
        "HTTP acceptance must not make an unbound TCP stream listener ready"
    );

    let tcp = tokio::net::TcpListener::bind_test(("127.0.0.1", tcp_port))
        .await
        .unwrap();
    timeout(Duration::from_secs(5), ready)
        .await
        .expect("TCP bind must release readiness wait")
        .unwrap();
    let (mut stream, _) = tcp.accept().await.unwrap();
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn exited_child_fails_before_http_probe() {
    let mut child = readiness_child();
    child.child_mut().kill().unwrap();
    child.child_mut().wait().unwrap();
    let http_port = unbound_port().await.unwrap();
    let error = timeout(
        Duration::from_secs(1),
        wait_for_spawned_gateway(&mut child, http_port, None),
    )
    .await
    .expect("an exited child must not consume the readiness timeout")
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("exited with"), "{message}");
    assert!(message.contains("HTTP listener"), "{message}");
    assert!(message.contains(&http_port.to_string()), "{message}");
}

#[tokio::test]
async fn exited_child_reports_both_output_tails_and_all_listener_ports() {
    let mut child = readiness_child();
    drop(child.child_mut().stdin.take());
    let http_port = unbound_port().await.unwrap();
    let udp_port = unbound_udp_port().await.unwrap();
    let error = timeout(
        Duration::from_secs(5),
        wait_for_spawned_gateway(&mut child, http_port, Some(StreamListener::Udp(udp_port))),
    )
    .await
    .expect("child output must not block exit or readiness")
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("exited with"), "{message}");
    assert!(message.contains("gateway stderr tail"), "{message}");
    assert!(message.contains("gateway stdout tail"), "{message}");
    assert_eq!(
        message
            .matches("startup failed: Address already in use")
            .count(),
        2
    );
    assert!(message.contains(&http_port.to_string()), "{message}");
    assert!(message.contains(&udp_port.to_string()), "{message}");
    assert!(message.contains("FERRUM_ADMIN_HTTP_PORT"), "{message}");
    assert!(!message.contains("readiness-fixture-secret"));
    assert!(message.len() < 34 * 1024, "diagnostics must be bounded");
}

#[tokio::test]
async fn child_exit_during_udp_wait_reports_stream_stage() {
    let identity = SpawnedGatewayIdentity::mint("udp-exit");
    let (admin_port, admin, _) =
        readiness_admin(identity.clone(), Arc::new(AtomicBool::new(false)), true).await;
    let mut child = spawn_readiness_child(Some((admin_port, identity)));
    let release = child.child_mut().stdin.take().unwrap();
    let http = reserve_port().await.unwrap();
    let http_port = http.port;
    let http = http.into_listener();
    let udp_port = unbound_udp_port().await.unwrap();
    let mut ready = Box::pin(wait_for_spawned_gateway(
        &mut child,
        http_port,
        Some(StreamListener::Udp(udp_port)),
    ));
    // Wait for the helper to close its successful HTTP probe before killing the
    // child, so the stage assertion does not depend on scheduler timing.
    timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut ready => panic!("unbound UDP listener was admitted: {result:?}"),
            () = async {
                let (mut stream, _) = http.accept().await.unwrap();
                assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
            } => {}
        }
    })
    .await
    .expect("HTTP probe must complete before child exits");
    drop(release);
    let error = timeout(Duration::from_secs(5), ready)
        .await
        .expect("child exit must not consume the readiness timeout")
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("exited with"), "{message}");
    assert!(message.contains("UDP stream listener"), "{message}");
    assert!(message.contains(&udp_port.to_string()), "{message}");
    admin.abort();
}
