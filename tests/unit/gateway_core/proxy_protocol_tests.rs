//! Unit tests for inbound PROXY protocol v1 (text) and v2 (binary) parsing.
//!
//! These tests exercise `src/proxy/proxy_protocol.rs` directly without any
//! real TCP socket: they feed bytes via `std::io::Cursor` (which implements
//! `AsyncRead` through the tokio compat layer).

use ferrum_edge::proxy::proxy_protocol::{
    AcceptedProxyVersions, ProxyProtocolError, ProxyProtocolResult, apply_proxy_result,
    read_proxy_header, read_proxy_header_accepting, read_proxy_header_accepting_tcp,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

#[test]
fn apply_result_canonicalizes_mapped_ipv4_before_stream_plugins() {
    let peer = "[::ffff:10.0.0.1]:1234".parse().unwrap();
    let result = ProxyProtocolResult::Forwarded {
        src: "[::ffff:192.0.2.10]:4321".parse().unwrap(),
        dst: "[2001:db8::1]:443".parse().unwrap(),
    };

    let (client_ip, direct_ip) = apply_proxy_result(result, &peer);
    assert_eq!(client_ip, "192.0.2.10");
    assert_eq!(direct_ip, "10.0.0.1");
}

// ── PROXY v2 encoder (outbound) ───────────────────────────────────────────────

#[tokio::test]
async fn encode_v2_ipv4_round_trips_through_parser() {
    use ferrum_edge::proxy::proxy_protocol::encode_v2_proxy_header;
    use std::net::Ipv4Addr;

    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 12345);
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5432);
    let header = encode_v2_proxy_header(src, dst);
    assert_eq!(header.len(), 28, "AF_INET header is signature+fixed+12");

    let result = parse_bytes(&header)
        .await
        .expect("encoded header must parse");
    match result {
        ProxyProtocolResult::Forwarded {
            src: parsed_src,
            dst: parsed_dst,
        } => {
            assert_eq!(parsed_src, src);
            assert_eq!(parsed_dst, dst);
        }
        ProxyProtocolResult::NoAddress => panic!("expected Forwarded"),
    }
}

#[tokio::test]
async fn encode_v2_ipv6_round_trips_through_parser() {
    use ferrum_edge::proxy::proxy_protocol::encode_v2_proxy_header;
    use std::net::Ipv6Addr;

    let src = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        50000,
    );
    let dst = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        443,
    );
    let header = encode_v2_proxy_header(src, dst);
    assert_eq!(header.len(), 52, "AF_INET6 header is signature+fixed+36");

    let result = parse_bytes(&header)
        .await
        .expect("encoded header must parse");
    match result {
        ProxyProtocolResult::Forwarded {
            src: parsed_src,
            dst: parsed_dst,
        } => {
            assert_eq!(parsed_src, src);
            assert_eq!(parsed_dst, dst);
        }
        ProxyProtocolResult::NoAddress => panic!("expected Forwarded"),
    }
}

#[tokio::test]
async fn encode_v2_mixed_family_promotes_to_ipv6_mapped() {
    use ferrum_edge::proxy::proxy_protocol::encode_v2_proxy_header;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 4000);
    let dst = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        443,
    );
    let header = encode_v2_proxy_header(src, dst);
    assert_eq!(header.len(), 52);

    let result = parse_bytes(&header)
        .await
        .expect("mixed-family header must parse as AF_INET6");
    match result {
        ProxyProtocolResult::Forwarded {
            src: parsed_src,
            dst: parsed_dst,
        } => {
            assert_eq!(
                parsed_src.ip(),
                IpAddr::V6(Ipv4Addr::new(203, 0, 113, 10).to_ipv6_mapped())
            );
            assert_eq!(parsed_src.port(), 4000);
            assert_eq!(parsed_dst, dst);
        }
        ProxyProtocolResult::NoAddress => panic!("expected Forwarded"),
    }
}

#[test]
fn outbound_v2_addrs_preserve_original_destination_tuple() {
    use ferrum_edge::proxy::proxy_protocol::outbound_v2_addrs;
    use std::net::Ipv4Addr;

    let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let dest = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);
    let (src, dst) = outbound_v2_addrs(client, 4321, Some(dest), Some(8443), Some(local))
        .expect("addrs should resolve");
    assert_eq!(src, SocketAddr::new(client, 4321));
    assert_eq!(dst, SocketAddr::new(dest, 8443));
}

#[test]
fn outbound_v2_addrs_fall_back_to_local_listener() {
    use ferrum_edge::proxy::proxy_protocol::outbound_v2_addrs;
    use std::net::Ipv4Addr;

    let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);
    let (src, dst) =
        outbound_v2_addrs(client, 4321, None, None, Some(local)).expect("fallback should work");
    assert_eq!(src.port(), 4321);
    assert_eq!(dst.ip(), local.ip());
    assert_eq!(
        dst.port(),
        local.port(),
        "fallback preserves the accepted socket's complete local tuple"
    );
}

#[test]
fn outbound_v2_addrs_reject_half_populated_original_destination() {
    use ferrum_edge::proxy::proxy_protocol::outbound_v2_addrs;
    use std::net::Ipv4Addr;

    let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let dest = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
    assert!(outbound_v2_addrs(client, 4321, Some(dest), None, Some(local)).is_none());
    assert!(outbound_v2_addrs(client, 4321, None, Some(8443), Some(local)).is_none());
}

#[test]
fn outbound_v2_addrs_fail_closed_without_destination() {
    use ferrum_edge::proxy::proxy_protocol::outbound_v2_addrs;
    use std::net::Ipv4Addr;

    let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    assert!(outbound_v2_addrs(client, 4321, None, None, None).is_none());
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

// ── Version-restricted reads (issue #5768) ────────────────────────────────────

async fn parse_accepting(
    data: &[u8],
    accepted: AcceptedProxyVersions,
) -> (Result<ProxyProtocolResult, ProxyProtocolError>, u64) {
    let mut cursor = std::io::Cursor::new(data.to_vec());
    let result = read_proxy_header_accepting(&mut cursor, Some(1), accepted).await;
    (result, cursor.position())
}

const V1_TCP4: &[u8] = b"PROXY TCP4 192.168.1.50 192.168.1.1 12345 80\r\n";

#[tokio::test]
async fn v1_only_accepts_v1_and_refuses_v2() {
    let (result, _) = parse_accepting(V1_TCP4, AcceptedProxyVersions::V1Only).await;
    assert!(matches!(result, Ok(ProxyProtocolResult::Forwarded { .. })));

    let v2 = v2_header_tcp4([10, 0, 0, 1], [10, 0, 0, 2], 1000, 443);
    let (result, consumed) = parse_accepting(&v2, AcceptedProxyVersions::V1Only).await;
    assert!(matches!(
        result,
        Err(ProxyProtocolError::VersionNotAccepted("v2"))
    ));
    assert_eq!(consumed, 6, "only the signature prefix is read");
}

#[tokio::test]
async fn v2_only_accepts_v2_and_refuses_v1() {
    let v2 = v2_header_tcp4([10, 0, 0, 1], [10, 0, 0, 2], 1000, 443);
    let (result, _) = parse_accepting(&v2, AcceptedProxyVersions::V2Only).await;
    assert!(matches!(result, Ok(ProxyProtocolResult::Forwarded { .. })));

    let (result, consumed) = parse_accepting(V1_TCP4, AcceptedProxyVersions::V2Only).await;
    assert!(matches!(
        result,
        Err(ProxyProtocolError::VersionNotAccepted("v1"))
    ));
    assert_eq!(consumed, 6, "only the signature prefix is read");
}

#[tokio::test]
async fn any_accepts_both_versions_and_matches_read_proxy_header() {
    let v2 = v2_header_tcp4([10, 0, 0, 1], [10, 0, 0, 2], 1000, 443);
    for header in [V1_TCP4.to_vec(), v2] {
        let (result, consumed) = parse_accepting(&header, AcceptedProxyVersions::Any).await;
        assert!(matches!(result, Ok(ProxyProtocolResult::Forwarded { .. })));
        assert_eq!(consumed, header.len() as u64, "whole header consumed");
    }
    let (result, _) = parse_accepting(b"GET / HTTP/1.1\r\n", AcceptedProxyVersions::Any).await;
    assert!(matches!(result, Err(ProxyProtocolError::InvalidSignature)));
}

// ── Peek-based v1 reads on a raw TcpStream (issue #5839) ──────────────────────

/// A connected loopback pair: `(client, accepted)`. The client writes the
/// PROXY header; the accepted side is what the listener parses.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("listener addr");
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let client = client.expect("connect");
    client.set_nodelay(true).expect("nodelay");
    (client, accepted.expect("accept").0)
}

async fn parse_tcp(
    stream: &mut TcpStream,
    accepted: AcceptedProxyVersions,
) -> Result<ProxyProtocolResult, ProxyProtocolError> {
    read_proxy_header_accepting_tcp(stream, Some(2), accepted).await
}

/// Everything left in `stream` after the header: the client must have shut
/// down its write half so this terminates.
async fn remaining_bytes(stream: &mut TcpStream) -> Vec<u8> {
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
        .await
        .expect("remaining bytes within the deadline")
        .expect("read remaining bytes");
    rest
}

fn assert_v1_tcp4_forwarded(result: Result<ProxyProtocolResult, ProxyProtocolError>) {
    match result {
        Ok(ProxyProtocolResult::Forwarded { src, dst }) => {
            assert_eq!(src, "192.168.1.50:12345".parse::<SocketAddr>().unwrap());
            assert_eq!(dst, "192.168.1.1:80".parse::<SocketAddr>().unwrap());
        }
        other => panic!("expected Forwarded, got {other:?}"),
    }
}

#[tokio::test]
async fn tcp_v1_header_in_one_segment_leaves_following_request_bytes() {
    let (mut client, mut server) = tcp_pair().await;
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let mut segment = V1_TCP4.to_vec();
    segment.extend_from_slice(request);
    client.write_all(&segment).await.unwrap();
    client.shutdown().await.unwrap();

    assert_v1_tcp4_forwarded(parse_tcp(&mut server, AcceptedProxyVersions::V1Only).await);
    assert_eq!(
        remaining_bytes(&mut server).await,
        request,
        "request bytes after the CRLF must stay in the socket for Hyper"
    );
}

#[tokio::test]
async fn tcp_v1_header_leaves_a_following_client_hello_untouched() {
    let (mut client, mut server) = tcp_pair().await;
    // TLS handshake record header + ClientHello type and a few body bytes.
    let client_hello = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03];
    let mut segment = V1_TCP4.to_vec();
    segment.extend_from_slice(&client_hello);
    client.write_all(&segment).await.unwrap();
    client.shutdown().await.unwrap();

    assert_v1_tcp4_forwarded(parse_tcp(&mut server, AcceptedProxyVersions::Any).await);
    assert_eq!(remaining_bytes(&mut server).await, client_hello);
}

#[tokio::test]
async fn tcp_v1_header_split_across_delayed_writes() {
    let (mut client, mut server) = tcp_pair().await;
    let request = b"GET / HTTP/1.1\r\n\r\n";
    let writer = tokio::spawn(async move {
        // Split mid-token, then between CR and LF, with the request riding in
        // the same write as the final LF.
        let (head, lf) = V1_TCP4.split_at(V1_TCP4.len() - 1);
        for chunk in [&head[..3], &head[3..9], &head[9..27], &head[27..]] {
            client.write_all(chunk).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let mut last = lf.to_vec();
        last.extend_from_slice(request);
        client.write_all(&last).await.unwrap();
        client.shutdown().await.unwrap();
        client
    });

    assert_v1_tcp4_forwarded(parse_tcp(&mut server, AcceptedProxyVersions::V1Only).await);
    assert_eq!(remaining_bytes(&mut server).await, request);
    drop(writer.await.unwrap());
}

#[tokio::test]
async fn tcp_v1_oversized_header_without_crlf_is_refused() {
    let (mut client, mut server) = tcp_pair().await;
    let mut oversized = b"PROXY UNKNOWN ".to_vec();
    oversized.resize(200, b'x');
    client.write_all(&oversized).await.unwrap();
    client.shutdown().await.unwrap();

    let err = parse_tcp(&mut server, AcceptedProxyVersions::V1Only)
        .await
        .expect_err("a line with no CRLF inside the cap must be refused");
    assert!(matches!(err, ProxyProtocolError::V1TooLong), "{err:?}");
    // Exactly the capped 109 bytes were consumed, as with the byte-wise reader.
    assert_eq!(remaining_bytes(&mut server).await.len(), 200 - 109);
}

#[tokio::test]
async fn tcp_v1_oversized_header_split_across_writes_is_refused() {
    let (mut client, mut server) = tcp_pair().await;
    let writer = tokio::spawn(async move {
        client.write_all(b"PROXY UNKNOWN ").await.unwrap();
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if client.write_all(&[b'x'; 20]).await.is_err() {
                break;
            }
        }
        client
    });

    let err = parse_tcp(&mut server, AcceptedProxyVersions::Any)
        .await
        .expect_err("oversized line must be refused");
    assert!(matches!(err, ProxyProtocolError::V1TooLong), "{err:?}");
    drop(server);
    drop(writer.await.unwrap());
}

#[tokio::test]
async fn tcp_v1_exact_max_length_accepted() {
    let (mut client, mut server) = tcp_pair().await;
    let mut header = b"PROXY UNKNOWN ".to_vec();
    header.resize(107, b'x');
    header.extend_from_slice(b"\r\nnext");
    client.write_all(&header).await.unwrap();
    client.shutdown().await.unwrap();

    let result = parse_tcp(&mut server, AcceptedProxyVersions::V1Only).await;
    assert!(
        matches!(result, Ok(ProxyProtocolResult::NoAddress)),
        "{result:?}"
    );
    assert_eq!(remaining_bytes(&mut server).await, b"next");
}

#[tokio::test]
async fn tcp_v1_peer_close_mid_header_is_an_io_error() {
    let (mut client, mut server) = tcp_pair().await;
    client.write_all(b"PROXY TCP4 10.0.0.1 10.").await.unwrap();
    client.shutdown().await.unwrap();

    let err = parse_tcp(&mut server, AcceptedProxyVersions::V1Only)
        .await
        .expect_err("a truncated header must fail");
    match err {
        ProxyProtocolError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
        other => panic!("expected an UnexpectedEof I/O error, got {other:?}"),
    }
}

#[tokio::test]
async fn tcp_v1_peer_close_after_lone_cr_is_an_io_error() {
    let (mut client, mut server) = tcp_pair().await;
    let (head, _lf) = V1_TCP4.split_at(V1_TCP4.len() - 1);
    client.write_all(head).await.unwrap();
    client.shutdown().await.unwrap();

    let err = parse_tcp(&mut server, AcceptedProxyVersions::V1Only)
        .await
        .expect_err("a header without its LF must fail");
    assert!(matches!(err, ProxyProtocolError::Io(_)), "{err:?}");
}

#[tokio::test]
async fn tcp_v1_stalled_partial_header_times_out() {
    let (mut client, mut server) = tcp_pair().await;
    client.write_all(b"PROXY TCP4 192.168.1.50").await.unwrap();

    let started = std::time::Instant::now();
    let err = read_proxy_header_accepting_tcp(&mut server, Some(1), AcceptedProxyVersions::V1Only)
        .await
        .expect_err("a stalled header must time out");
    assert!(matches!(err, ProxyProtocolError::Timeout), "{err:?}");
    assert!(started.elapsed() >= Duration::from_millis(900));
    drop(client);
}

#[tokio::test]
async fn tcp_reader_matches_the_generic_reader() {
    let mut exact_max = b"PROXY UNKNOWN ".to_vec();
    exact_max.resize(107, b'x');
    exact_max.extend_from_slice(b"\r\n");
    let v2 = v2_header_tcp4([10, 0, 0, 1], [10, 0, 0, 2], 1000, 443);
    let cases: Vec<Vec<u8>> = vec![
        V1_TCP4.to_vec(),
        b"PROXY TCP6 2001:db8::1 2001:db8::2 1000 443\r\n".to_vec(),
        b"PROXY UNKNOWN\r\n".to_vec(),
        b"PROXY TCP5 1.2.3.4 5.6.7.8 1 2\r\n".to_vec(),
        b"PROXY TCP4 1.2.3.4 5.6.7.8 100\r\n".to_vec(),
        b"PROXY TCP4 1.2.3.4 5.6.7.8 1 \xff\r\n".to_vec(),
        b"PROXY \r\n".to_vec(),
        exact_max,
        v2,
        b"GET / HTTP/1.1\r\n".to_vec(),
    ];
    for accepted in [
        AcceptedProxyVersions::Any,
        AcceptedProxyVersions::V1Only,
        AcceptedProxyVersions::V2Only,
    ] {
        for case in &cases {
            let (generic, generic_consumed) = parse_accepting(case, accepted).await;

            let (mut client, mut server) = tcp_pair().await;
            client.write_all(case).await.unwrap();
            client.shutdown().await.unwrap();
            let tcp = parse_tcp(&mut server, accepted).await;
            let tcp_consumed = case.len() - remaining_bytes(&mut server).await.len();

            assert_eq!(
                format!("{tcp:?}"),
                format!("{generic:?}"),
                "outcome differs for {:?} ({accepted:?})",
                String::from_utf8_lossy(case)
            );
            assert_eq!(
                tcp_consumed as u64,
                generic_consumed,
                "consumed bytes differ for {:?} ({accepted:?})",
                String::from_utf8_lossy(case)
            );
        }
    }
}
