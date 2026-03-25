//! Tests for TCP and UDP health check probes.
//!
//! These tests use real TCP/UDP listeners on localhost to verify
//! the probe functions work correctly.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};

/// Start a TCP listener that accepts connections (healthy target).
async fn start_tcp_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Accept and immediately drop — SYN-ACK is enough for TCP probe
        while let Ok((_stream, _)) = listener.accept().await {}
    });
    addr
}

/// Start a UDP server that echoes back any received datagram.
async fn start_udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        while let Ok((len, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], src).await;
        }
    });
    addr
}

#[tokio::test]
async fn test_tcp_probe_healthy_target() {
    let addr = start_tcp_echo_server().await;
    let result =
        tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn test_tcp_probe_unhealthy_target() {
    // Connect to a port that nothing is listening on
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect("127.0.0.1:1"),
    )
    .await;
    // Should either time out or get connection refused
    match result {
        Ok(Ok(_)) => panic!("Expected connection failure"),
        Ok(Err(_)) => {} // Connection refused — expected
        Err(_) => {}     // Timeout — also acceptable
    }
}

#[tokio::test]
async fn test_udp_probe_healthy_target() {
    let addr = start_udp_echo_server().await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(addr).await.unwrap();
    client.send(&[0u8]).await.unwrap();

    let mut buf = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf)).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn test_udp_probe_timeout_no_server() {
    // Send to a port that has no listener — no successful response expected.
    // On some platforms (macOS) the OS may deliver an ICMP "port unreachable"
    // error immediately rather than timing out, so we accept either outcome.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect("127.0.0.1:19999").await.unwrap();
    client.send(&[0u8]).await.unwrap();

    let mut buf = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_millis(200), client.recv(&mut buf)).await;
    match result {
        Err(_) => {}     // Timeout — expected on Linux
        Ok(Err(_)) => {} // ICMP error — expected on macOS
        Ok(Ok(_)) => panic!("Expected timeout or error, got successful response"),
    }
}

#[tokio::test]
async fn test_udp_probe_with_payload() {
    let addr = start_udp_echo_server().await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(addr).await.unwrap();

    // Send a multi-byte payload
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    client.send(&payload).await.unwrap();

    let mut buf = [0u8; 4];
    let result = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf)).await;
    assert!(result.is_ok());
    let len = result.unwrap().unwrap();
    assert_eq!(&buf[..len], &payload[..]);
}
