//! Unit tests for inbound PROXY protocol v1 (text) and v2 (binary) parsing.
//!
//! These tests exercise `src/proxy/proxy_protocol.rs` directly without any
//! real TCP socket: they feed bytes via `std::io::Cursor` (which implements
//! `AsyncRead` through the tokio compat layer).

use ferrum_edge::proxy::proxy_protocol::{
    ProxyProtocolError, ProxyProtocolResult, apply_proxy_result, read_proxy_header,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// Helper: feed raw bytes into read_proxy_header
async fn parse_bytes(data: &[u8]) -> Result<ProxyProtocolResult, ProxyProtocolError> {
    let mut cursor = std::io::Cursor::new(data.to_vec());
    read_proxy_header(&mut cursor, Some(1)).await
}

// ── PROXY v1 happy paths ──────────────────────────────────────────────────────

#[tokio::test]
async fn v1_tcp4_happy_path() {
    let header = b"PROXY TCP4 192.168.1.50 192.168.1.1 12345 80\r\n";
    let result = parse_bytes(header).await.expect("parse should succeed");
    match result {
        ProxyProtocolResult::Forwarded { src, dst } => {
            assert_eq!(src.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
            assert_eq!(src.port(), 12345);
            assert_eq!(dst.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(dst.port(), 80);
        }
        _ => panic!("expected Forwarded, got NoAddress"),
    }
}

#[tokio::test]
async fn v1_tcp6_happy_path() {
    let header = b"PROXY TCP6 2001:db8::1 2001:db8::2 50000 443\r\n";
    let result = parse_bytes(header).await.expect("parse should succeed");
    match result {
        ProxyProtocolResult::Forwarded { src, dst } => {
            assert_eq!(src.port(), 50000);
            assert_eq!(dst.port(), 443);
            // Just verify they are IPv6
            assert!(matches!(src.ip(), IpAddr::V6(_)));
            assert!(matches!(dst.ip(), IpAddr::V6(_)));
        }
        _ => panic!("expected Forwarded, got NoAddress"),
    }
}

#[tokio::test]
async fn v1_unknown_family_returns_no_address() {
    // Per spec, UNKNOWN means keep socket peer.
    let header = b"PROXY UNKNOWN some garbage here\r\n";
    let result = parse_bytes(header).await.expect("parse should succeed");
    assert!(matches!(result, ProxyProtocolResult::NoAddress));
}

#[tokio::test]
async fn v1_unknown_without_extra_fields() {
    let header = b"PROXY UNKNOWN\r\n";
    let result = parse_bytes(header).await.expect("parse should succeed");
    assert!(matches!(result, ProxyProtocolResult::NoAddress));
}

// ── PROXY v1 error paths ──────────────────────────────────────────────────────

#[tokio::test]
async fn v1_malformed_family() {
    let header = b"PROXY UDP4 1.2.3.4 5.6.7.8 100 200\r\n";
    let err = parse_bytes(header).await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::Malformed(_)));
}

#[tokio::test]
async fn v1_bad_ip_address() {
    let header = b"PROXY TCP4 not-an-ip 5.6.7.8 100 200\r\n";
    let err = parse_bytes(header).await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::Malformed(_)));
}

#[tokio::test]
async fn v1_bad_port() {
    let header = b"PROXY TCP4 1.2.3.4 5.6.7.8 not-a-port 200\r\n";
    let err = parse_bytes(header).await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::Malformed(_)));
}

#[tokio::test]
async fn v1_tcp4_with_ipv6_src_fails() {
    // Family mismatch: TCP4 header with an IPv6 address.
    let header = b"PROXY TCP4 2001:db8::1 5.6.7.8 100 200\r\n";
    let err = parse_bytes(header).await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::Malformed(_)));
}

#[tokio::test]
async fn v1_missing_dst_port() {
    let header = b"PROXY TCP4 1.2.3.4 5.6.7.8 100\r\n";
    let err = parse_bytes(header).await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::Malformed(_)));
}

#[tokio::test]
async fn v1_too_long_rejected() {
    // Build a header > 107 bytes before CRLF.
    let long_src = "1.2.3.4";
    let long_dst = "5.6.7.8";
    // Pad protocol field with spaces to exceed the limit.
    let mut header = format!("PROXY TCP4 {long_src} {long_dst} 100 200");
    while header.len() < 110 {
        header.push(' ');
    }
    header.push_str("\r\n");
    let err = parse_bytes(header.as_bytes())
        .await
        .expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::V1TooLong));
}

#[tokio::test]
async fn invalid_signature_rejected() {
    let header = b"HTTP/1.1 200 OK\r\n";
    let err = parse_bytes(header).await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::InvalidSignature));
}

#[tokio::test]
async fn truncated_header_returns_io_error() {
    // Only 3 bytes — even the prefix is incomplete.
    let err = parse_bytes(b"PRO").await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::Io(_)));
}

// ── PROXY v2 happy paths ──────────────────────────────────────────────────────

fn v2_header_tcp4(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    // Signature (12 bytes) + fixed header (4 bytes) + AF_INET address block (12 bytes) = 28 bytes total
    let mut h = Vec::new();
    // Signature
    h.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    // version=2, command=PROXY (0x21)
    h.push(0x21);
    // AF_INET (0x1) + STREAM (0x1) = 0x11
    h.push(0x11);
    // addr_len = 12 (AF_INET: 4+4+2+2)
    h.extend_from_slice(&12u16.to_be_bytes());
    // src IP
    h.extend_from_slice(&src);
    // dst IP
    h.extend_from_slice(&dst);
    // src port
    h.extend_from_slice(&src_port.to_be_bytes());
    // dst port
    h.extend_from_slice(&dst_port.to_be_bytes());
    h
}

fn v2_local_command() -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    // version=2, command=LOCAL (0x20)
    h.push(0x20);
    // AF_UNSPEC + UNSPEC (0x00)
    h.push(0x00);
    // addr_len = 0
    h.extend_from_slice(&0u16.to_be_bytes());
    h
}

fn v2_header_tcp6(src: [u8; 16], dst: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    // version=2, command=PROXY (0x21)
    h.push(0x21);
    // AF_INET6 (0x2) + STREAM (0x1) = 0x21
    h.push(0x21);
    // addr_len = 36 (AF_INET6: 16+16+2+2)
    h.extend_from_slice(&36u16.to_be_bytes());
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h.extend_from_slice(&src_port.to_be_bytes());
    h.extend_from_slice(&dst_port.to_be_bytes());
    h
}

#[tokio::test]
async fn v2_tcp4_happy_path() {
    let header = v2_header_tcp4([10, 0, 0, 1], [10, 0, 0, 2], 9000, 5432);
    let result = parse_bytes(&header).await.expect("parse should succeed");
    match result {
        ProxyProtocolResult::Forwarded { src, dst } => {
            assert_eq!(src.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
            assert_eq!(src.port(), 9000);
            assert_eq!(dst.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
            assert_eq!(dst.port(), 5432);
        }
        _ => panic!("expected Forwarded, got NoAddress"),
    }
}

#[tokio::test]
async fn v2_tcp6_happy_path() {
    let mut src = [0u8; 16];
    src[15] = 1; // ::1
    let mut dst = [0u8; 16];
    dst[15] = 2; // ::2
    let header = v2_header_tcp6(src, dst, 1234, 5678);
    let result = parse_bytes(&header).await.expect("parse should succeed");
    match result {
        ProxyProtocolResult::Forwarded { src, .. } => {
            assert_eq!(src.port(), 1234);
        }
        _ => panic!("expected Forwarded, got NoAddress"),
    }
}

#[tokio::test]
async fn v2_local_command_returns_no_address() {
    let header = v2_local_command();
    let result = parse_bytes(&header).await.expect("parse should succeed");
    assert!(matches!(result, ProxyProtocolResult::NoAddress));
}

#[tokio::test]
async fn v2_unspec_af_returns_no_address() {
    // AF_UNSPEC with PROXY command — keep socket peer.
    let mut h = Vec::new();
    h.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    h.push(0x21); // PROXY command
    h.push(0x00); // AF_UNSPEC + UNSPEC transport
    h.extend_from_slice(&0u16.to_be_bytes());
    let result = parse_bytes(&h).await.expect("parse should succeed");
    assert!(matches!(result, ProxyProtocolResult::NoAddress));
}

// ── PROXY v2 error paths ──────────────────────────────────────────────────────

#[tokio::test]
async fn v2_bad_version_rejected() {
    let mut h = Vec::new();
    h.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    // version=1 (0x10) instead of 2 (0x20)
    h.push(0x11);
    h.push(0x11);
    h.extend_from_slice(&12u16.to_be_bytes());
    h.extend_from_slice(&[0u8; 12]);
    let err = parse_bytes(&h).await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::Malformed(_)));
}

#[tokio::test]
async fn v2_length_exceeds_cap_rejected() {
    let mut h = Vec::new();
    h.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    h.push(0x21);
    h.push(0x11);
    // addr_len = 513 (> V2_MAX_ADDR_LEN = 512)
    h.extend_from_slice(&513u16.to_be_bytes());
    let err = parse_bytes(&h).await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::V2LengthExceeded(513)));
}

#[tokio::test]
async fn v2_truncated_addr_block_rejected() {
    // Claim 12 bytes but provide only 6
    let mut h = Vec::new();
    h.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    h.push(0x21);
    h.push(0x11);
    h.extend_from_slice(&12u16.to_be_bytes());
    h.extend_from_slice(&[0u8; 6]); // only 6 bytes, not 12
    let err = parse_bytes(&h).await.expect_err("should fail");
    assert!(matches!(err, ProxyProtocolError::Io(_)));
}

#[tokio::test]
async fn v2_unix_af_returns_no_address() {
    // AF_UNIX (0x03) — not supported, keep socket peer
    let mut h = Vec::new();
    h.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    h.push(0x21);
    h.push(0x31); // AF_UNIX (0x3) + STREAM (0x1)
    // AF_UNIX block: 108+108+2+2 = 220 bytes (but we claim 0 for simplicity — since we return early)
    // Actually let's claim 8 bytes and provide them
    h.extend_from_slice(&8u16.to_be_bytes());
    h.extend_from_slice(&[0u8; 8]);
    let result = parse_bytes(&h).await.expect("parse should succeed");
    assert!(matches!(result, ProxyProtocolResult::NoAddress));
}

// ── apply_proxy_result ───────────────────────────────────────────────────────

#[test]
fn apply_result_forwarded_separates_ips() {
    let peer: SocketAddr = "10.0.0.1:9999".parse().unwrap();
    let forwarded_src: SocketAddr = "203.0.113.5:12345".parse().unwrap();
    let forwarded_dst: SocketAddr = "10.0.0.2:80".parse().unwrap();
    let result = ProxyProtocolResult::Forwarded {
        src: forwarded_src,
        dst: forwarded_dst,
    };
    let (client_ip, direct_ip) = apply_proxy_result(result, &peer);
    assert_eq!(client_ip, "203.0.113.5");
    assert_eq!(direct_ip, "10.0.0.1");
}

#[test]
fn apply_result_no_address_uses_peer_for_both() {
    let peer: SocketAddr = "172.16.0.50:8888".parse().unwrap();
    let (client_ip, direct_ip) = apply_proxy_result(ProxyProtocolResult::NoAddress, &peer);
    assert_eq!(client_ip, "172.16.0.50");
    assert_eq!(direct_ip, "172.16.0.50");
}

// ── Boundary size test ────────────────────────────────────────────────────────

#[tokio::test]
async fn v1_exact_max_length_accepted() {
    // 107 bytes before CRLF = maximum allowed. Build one that's exactly at the limit.
    // "PROXY TCP4 " = 11 chars, "192.168.1.50 192.168.1.1 " = 26 chars, ports "12345 80" = 8 chars
    // Total so far = 45 chars. Pad with spaces to reach exactly 107 before CRLF.
    // But a real parser would reject extra fields — use the UNKNOWN form which ignores trailing data.
    let mut header = String::from("PROXY UNKNOWN ");
    while header.len() < 107 {
        header.push('x');
    }
    assert_eq!(header.len(), 107);
    header.push_str("\r\n");
    let result = parse_bytes(header.as_bytes())
        .await
        .expect("should succeed");
    assert!(matches!(result, ProxyProtocolResult::NoAddress));
}
