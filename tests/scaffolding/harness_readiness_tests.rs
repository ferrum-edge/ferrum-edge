//! Spawned-listener readiness must wait for stream binds without sending UDP traffic.

use super::harness::{StreamListener, wait_for_spawned_gateway};
use super::port_registry::TestSocket;
use super::ports::{reserve_port, unbound_port, unbound_udp_port};
use crate::common::GatewayChildGuard;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

fn readiness_child() -> GatewayChildGuard {
    GatewayChildGuard::new(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "scaffolding::harness_readiness_tests::hold_readiness_child",
            ])
            .env("TEST_GATEWAY_READINESS_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn readiness fixture child"),
    )
}

#[test]
fn hold_readiness_child() {
    if std::env::var_os("TEST_GATEWAY_READINESS_CHILD").is_some() {
        // The parent owns the pipe; closing it lets the child exit during a probe.
        let _ = std::io::stdin().read_exact(&mut [0]);
    }
}

#[tokio::test]
async fn http_accept_does_not_admit_unbound_udp_and_probe_sends_no_datagrams() {
    let mut child = readiness_child();
    let http = reserve_port().await.unwrap();
    let udp_port = unbound_udp_port().await.unwrap();
    let mut ready = Box::pin(wait_for_spawned_gateway(
        child.child_mut(),
        http.port,
        Some(StreamListener::Udp(udp_port)),
    ));
    assert!(
        timeout(Duration::from_millis(100), &mut ready)
            .await
            .is_err(),
        "HTTP acceptance must not make an unbound UDP listener ready"
    );

    // A pending probe must release its socket so the intended listener can bind.
    let udp = std::net::UdpSocket::bind_test(("127.0.0.1", udp_port)).unwrap();
    timeout(Duration::from_secs(5), ready)
        .await
        .expect("UDP bind must release readiness wait")
        .unwrap();
    udp.set_nonblocking(true).unwrap();
    assert_eq!(
        udp.recv_from(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "readiness must not send even an empty UDP datagram"
    );
}

#[tokio::test]
async fn http_accept_does_not_admit_unbound_tcp_stream() {
    let mut child = readiness_child();
    let http = reserve_port().await.unwrap();
    let tcp_port = unbound_port().await.unwrap();
    let mut ready = Box::pin(wait_for_spawned_gateway(
        child.child_mut(),
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
        wait_for_spawned_gateway(child.child_mut(), http_port, None),
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
async fn child_exit_during_udp_wait_reports_stream_stage() {
    let mut child = readiness_child();
    let release = child.child_mut().stdin.take().unwrap();
    let http = reserve_port().await.unwrap();
    let http_port = http.port;
    let http = http.into_listener();
    let udp_port = unbound_udp_port().await.unwrap();
    let mut ready = Box::pin(wait_for_spawned_gateway(
        child.child_mut(),
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
}
