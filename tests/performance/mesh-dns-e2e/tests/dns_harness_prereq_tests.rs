//! Regression coverage for DNS-over-TCP framing, stub answers, and fail-closed
//! loadgen reporting. These tests compile with the standalone harness crate;
//! hosted CI is the execution gate.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use mesh_dns_e2e_perf::dns_wire::{
    QTYPE_A, QTYPE_AAAA, TcpDnsFrameError, build_query, decode_tcp_dns_length, frame_for_tcp,
    parse_response, unframe_from_tcp,
};
use mesh_dns_e2e_perf::metrics::{ClassReport, NameClass, Transport, selected_reports_failure};
use mesh_dns_e2e_perf::upstream_stub::{build_stub_response, handle_tcp_connection};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn sample_report(queries: u64, errors: u64, nxdomain: u64) -> ClassReport {
    ClassReport {
        name_class: "upstream-forward".to_string(),
        transport: "tcp".to_string(),
        duration_secs: 60,
        total_queries: queries,
        total_errors: errors,
        total_nxdomain: nxdomain,
        qps: queries as f64 / 60.0,
        latency_avg_us: 0,
        latency_stdev_us: 0,
        latency_max_us: 0,
        p50_us: 0,
        p90_us: 0,
        p95_us: 0,
        p99_us: 0,
        total_bytes: 0,
    }
}

#[test]
fn tcp_framing_round_trip_and_hostile_lengths() {
    let packet = build_query("example.com", QTYPE_A, 0x1111);
    let framed = frame_for_tcp(&packet).expect("query fits in u16 length");
    assert_eq!(
        u16::from_be_bytes([framed[0], framed[1]]) as usize,
        packet.len()
    );
    let (inner, rest) = unframe_from_tcp(&framed).expect("complete frame");
    assert_eq!(inner, packet.as_slice());
    assert!(rest.is_empty());

    assert_eq!(
        decode_tcp_dns_length([0, 0]),
        Err(TcpDnsFrameError::EmptyLength)
    );
    assert_eq!(
        unframe_from_tcp(&[0, 0]),
        Err(TcpDnsFrameError::EmptyLength)
    );
    assert_eq!(unframe_from_tcp(&[0]), Err(TcpDnsFrameError::Incomplete));
    assert_eq!(
        unframe_from_tcp(&[0, 5, 1, 2]),
        Err(TcpDnsFrameError::Incomplete)
    );
    assert!(frame_for_tcp(&[]).is_none());
    assert!(frame_for_tcp(&vec![0u8; (u16::MAX as usize) + 1]).is_none());
}

#[test]
fn stub_answers_a_and_aaaa_and_rejects_truncated() {
    let query = build_query("example.com", QTYPE_A, 7);
    let reply = build_stub_response(&query).expect("A query");
    let parsed = parse_response(&reply).expect("parseable");
    assert!(parsed.is_response);
    assert_eq!(parsed.txid, 7);
    assert_eq!(parsed.rcode, 0);
    assert_eq!(
        parsed.answers,
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
    );

    let aaaa = build_query("example.com", QTYPE_AAAA, 8);
    let reply = build_stub_response(&aaaa).expect("AAAA query");
    let parsed = parse_response(&reply).expect("parseable");
    assert_eq!(parsed.answer_count, 1);
    assert!(parsed.answers.iter().any(|ip| ip.is_ipv6()));

    assert!(build_stub_response(&[0u8; 4]).is_none());
    assert!(build_stub_response(&[]).is_none());
}

#[test]
fn selected_reports_fail_on_zero_success_or_errors() {
    let classes = [NameClass::UpstreamForward];
    let transports = [Transport::Tcp];
    assert!(selected_reports_failure(&[], &classes, &transports).is_some());
    let zero_success = selected_reports_failure(&[sample_report(0, 12, 0)], &classes, &transports)
        .expect("zero successful queries must fail");
    assert!(zero_success.contains("zero successful queries"));
    assert!(selected_reports_failure(&[sample_report(10, 1, 0)], &classes, &transports).is_some());
    assert!(selected_reports_failure(&[sample_report(10, 0, 1)], &classes, &transports).is_some());
    assert!(selected_reports_failure(&[sample_report(10, 0, 0)], &classes, &transports).is_none());
    let mixed = vec![sample_report(10, 0, 0), sample_report(0, 500, 0)];
    let reason = selected_reports_failure(&mixed, &classes, &transports)
        .expect("duplicate selected row must fail");
    assert!(reason.contains("collected 2 times"));

    let missing_udp = selected_reports_failure(
        &[sample_report(10, 0, 0)],
        &classes,
        &[Transport::Udp, Transport::Tcp],
    )
    .expect("missing selected UDP row must fail");
    assert!(missing_udp.contains("upstream-forward/udp was not collected"));

    let missing_class = selected_reports_failure(
        &[sample_report(10, 0, 0)],
        &[NameClass::UpstreamForward, NameClass::MeshInternal],
        &transports,
    )
    .expect("missing selected class row must fail");
    assert!(missing_class.contains("mesh-internal/tcp was not collected"));
}

#[tokio::test]
async fn tcp_stub_serves_length_framed_query() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral tcp bind");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        handle_tcp_connection(stream).await
    });

    let mut client = TcpStream::connect(addr).await.expect("connect stub");
    client.set_nodelay(true).expect("nodelay");
    let query = build_query("example.com", QTYPE_A, 42);
    let framed = frame_for_tcp(&query).expect("frame");
    client.write_all(&framed).await.expect("write query");

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut len_buf))
        .await
        .expect("length timeout")
        .expect("length read");
    let len = decode_tcp_dns_length(len_buf).expect("nonzero length");
    let mut payload = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut payload))
        .await
        .expect("payload timeout")
        .expect("payload read");
    let parsed = parse_response(&payload).expect("dns response");
    assert_eq!(parsed.txid, 42);
    assert_eq!(
        parsed.answers,
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
    );

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn tcp_stub_closes_on_empty_length_prefix() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral tcp bind");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        handle_tcp_connection(stream).await
    });

    let mut client = TcpStream::connect(addr).await.expect("connect stub");
    client.write_all(&[0, 0]).await.expect("empty length");
    // The stub must not hang treating a zero prefix as a valid loop iteration.
    let joined = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("stub should finish after hostile length");
    let result = joined.expect("join");
    assert!(result.is_err(), "empty TCP DNS length must fail closed");
}

#[tokio::test]
async fn tcp_stub_rejects_truncated_length_prefix() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral tcp bind");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        handle_tcp_connection(stream).await
    });

    let mut client = TcpStream::connect(addr).await.expect("connect stub");
    client.write_all(&[1]).await.expect("partial prefix");
    client.shutdown().await.expect("shutdown writer");
    let joined = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("stub should finish after truncated length");
    let result = joined.expect("join");
    assert!(result.is_err(), "truncated TCP DNS length must fail closed");
}
