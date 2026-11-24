//! The hyper HTTP/2 client builder every `PoolConfig`-driven pool family
//! constructs (`pool::hyper_h2_client_builder`): direct H2, gRPC, mesh mTLS and
//! the nested-HBONE gRPC dial. hyper's `Builder` has no getters, but it derives
//! `Debug` over its full HTTP/2 config, so most of these tests compare that
//! rendering; the last two drive a real handshake over an in-memory transport.
//!
//! Since issue #7071 every site gets the same wire settings, so the expected
//! builder is the one the direct-H2 and gRPC pools always had. The structural
//! pin that every site calls the shared helper lives in
//! `shared_invariant_parity_tests.rs`.

use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::hyper_h2_client_builder_for_test;
use ferrum_edge::config::PoolConfig;
use http_body_util::Empty;
use hyper::Request;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt, DuplexStream};

fn debug(builder: &http2::Builder<TokioExecutor>) -> String {
    format!("{builder:?}")
}

fn shared(pool_config: &PoolConfig) -> String {
    debug(&hyper_h2_client_builder_for_test(pool_config))
}

/// `GrpcConnectionPool::build_h2_builder` and
/// `Http2ConnectionPool::build_h2_builder` as they were hand-written before the
/// shared helper (identical apart from comments).
fn legacy_direct_h2_and_grpc(pool_config: &PoolConfig) -> http2::Builder<TokioExecutor> {
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());
    if pool_config.enable_http2 {
        builder
            .keep_alive_interval(Duration::from_secs(
                pool_config.http2_keep_alive_interval_seconds,
            ))
            .keep_alive_timeout(Duration::from_secs(
                pool_config.http2_keep_alive_timeout_seconds,
            ))
            .max_concurrent_reset_streams(4096);
    }
    builder
        .initial_stream_window_size(pool_config.http2_initial_stream_window_size)
        .initial_connection_window_size(pool_config.http2_initial_connection_window_size)
        .adaptive_window(pool_config.http2_adaptive_window)
        .max_frame_size(pool_config.http2_max_frame_size);
    if let Some(max_streams) = pool_config.http2_max_concurrent_streams {
        builder.max_concurrent_streams(max_streams);
        builder.initial_max_send_streams(max_streams as usize);
    }
    builder
}

/// A spread of pool configs over every input the builder reads.
fn pool_configs() -> Vec<PoolConfig> {
    let mut configs = Vec::new();
    for enable_http2 in [true, false] {
        for adaptive in [false, true] {
            for cap in [None, Some(1), Some(250)] {
                configs.push(PoolConfig {
                    enable_http2,
                    http2_adaptive_window: adaptive,
                    http2_max_concurrent_streams: cap,
                    http2_keep_alive_interval_seconds: 17,
                    http2_keep_alive_timeout_seconds: 9,
                    http2_initial_stream_window_size: 1_048_576,
                    http2_initial_connection_window_size: 4_194_304,
                    http2_max_frame_size: 32_768,
                    ..PoolConfig::default()
                });
            }
        }
    }
    configs
}

/// Characterization: the shared builder is exactly the direct-H2 / gRPC pools'
/// prior builder. Issue #7071 moved mesh mTLS (which did not seed the stream
/// cap) and the nested-HBONE gRPC dial (which applied neither keepalive nor
/// the seed) onto it as well, so all four sites now match this.
#[test]
fn shared_builder_keeps_the_direct_pools_wire_settings() {
    for pool_config in pool_configs() {
        assert_eq!(
            shared(&pool_config),
            debug(&legacy_direct_h2_and_grpc(&pool_config)),
            "{pool_config:?}"
        );
    }
}

/// Shared invariant (issue #5464): the builder honours the configured
/// flow-control mode. Fixed windows keep the configured sizes; adaptive mode
/// starts from the spec window and grows.
#[test]
fn builder_honours_the_configured_flow_control_mode() {
    for pool_config in pool_configs() {
        let rendered = shared(&pool_config);
        let expected = if pool_config.http2_adaptive_window {
            [
                "adaptive_window: true".to_string(),
                "initial_conn_window_size: 65535".to_string(),
                "initial_stream_window_size: 65535".to_string(),
            ]
        } else {
            [
                "adaptive_window: false".to_string(),
                format!(
                    "initial_conn_window_size: {}",
                    pool_config.http2_initial_connection_window_size
                ),
                format!(
                    "initial_stream_window_size: {}",
                    pool_config.http2_initial_stream_window_size
                ),
            ]
        };
        for needle in expected {
            assert!(rendered.contains(&needle), "{needle} missing: {rendered}");
        }
        assert!(
            rendered.contains("max_frame_size: Some(32768)"),
            "{rendered}"
        );
        let advertised = match pool_config.http2_max_concurrent_streams {
            Some(cap) => format!("max_concurrent_streams: Some({cap})"),
            None => "max_concurrent_streams: None".to_string(),
        };
        assert!(rendered.contains(&advertised), "{advertised}: {rendered}");
    }
}

/// The pool's PING keepalive and reset-stream cap apply whenever
/// `enable_http2` is set, on every site including the nested-HBONE dial.
#[test]
fn pool_keepalive_and_reset_stream_cap_follow_enable_http2() {
    let pool_config = PoolConfig {
        enable_http2: true,
        http2_keep_alive_interval_seconds: 17,
        http2_keep_alive_timeout_seconds: 9,
        ..PoolConfig::default()
    };
    let applied = shared(&pool_config);
    assert!(
        applied.contains("keep_alive_interval: Some(17s)"),
        "{applied}"
    );
    assert!(applied.contains("keep_alive_timeout: 9s"), "{applied}");
    assert!(
        applied.contains("max_concurrent_reset_streams: Some(4096)"),
        "{applied}"
    );

    let gated = shared(&PoolConfig {
        enable_http2: false,
        ..pool_config
    });
    assert!(gated.contains("keep_alive_interval: None"), "{gated}");
    assert!(
        gated.contains("max_concurrent_reset_streams: None"),
        "{gated}"
    );
}

/// The stream cap seeds hyper's initial outbound stream bound on every site;
/// without a cap hyper's default stands.
#[test]
fn stream_cap_seeds_the_initial_outbound_stream_bound() {
    let seeded = shared(&PoolConfig {
        http2_max_concurrent_streams: Some(7),
        ..PoolConfig::default()
    });
    assert!(seeded.contains("initial_max_send_streams: 7,"), "{seeded}");

    let uncapped = shared(&PoolConfig {
        http2_max_concurrent_streams: None,
        ..PoolConfig::default()
    });
    assert!(
        uncapped.contains("initial_max_send_streams: 100,"),
        "hyper's default must stand without a cap: {uncapped}"
    );
}

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_FRAME_HEADERS: u8 = 0x1;

fn get_request() -> Request<Empty<Bytes>> {
    Request::builder()
        .uri("http://destination.test/")
        .body(Empty::new())
        .expect("valid request")
}

/// Everything the client writes until it has been quiet for `quiet`.
async fn read_until_quiet(peer: &mut DuplexStream, quiet: Duration) -> Vec<u8> {
    let mut wire = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(Ok(read)) = tokio::time::timeout(quiet, peer.read(&mut chunk)).await {
        if read == 0 {
            break;
        }
        wire.extend_from_slice(&chunk[..read]);
    }
    wire
}

/// Number of complete HEADERS frames after the client connection preface.
fn headers_frames(wire: &[u8]) -> usize {
    assert!(
        wire.starts_with(H2_PREFACE),
        "client must open with the HTTP/2 preface"
    );
    let mut rest = &wire[H2_PREFACE.len()..];
    let mut headers = 0;
    while rest.len() >= 9 {
        let length =
            (usize::from(rest[0]) << 16) | (usize::from(rest[1]) << 8) | usize::from(rest[2]);
        if rest.len() < 9 + length {
            break;
        }
        if rest[3] == H2_FRAME_HEADERS {
            headers += 1;
        }
        rest = &rest[9 + length..];
    }
    headers
}

/// HEADERS frames a client built from `pool_config` puts on the wire for two
/// concurrent requests to a peer that never sends its SETTINGS.
async fn streams_opened_before_peer_settings(pool_config: &PoolConfig) -> usize {
    let (client_io, mut peer) = tokio::io::duplex(1 << 16);
    let (mut sender, connection) = hyper_h2_client_builder_for_test(pool_config)
        .handshake::<_, Empty<Bytes>>(TokioIo::new(client_io))
        .await
        .expect("client handshake writes its preface without waiting for the peer");
    let driver = tokio::spawn(connection);
    let mut requests = Vec::new();
    for _ in 0..2 {
        sender.ready().await.expect("sender ready");
        requests.push(tokio::spawn(sender.send_request(get_request())));
    }
    let wire = read_until_quiet(&mut peer, Duration::from_millis(500)).await;
    for request in requests {
        request.abort();
    }
    driver.abort();
    headers_frames(&wire)
}

/// Issue #7071 (B): `maxConcurrentStreams: 1` bounds a new connection from its
/// first stream. Mesh mTLS used to keep hyper's default of 100 until the peer's
/// SETTINGS arrived, so a second concurrent request opened a second stream.
#[tokio::test]
async fn stream_cap_holds_before_the_peers_settings_arrive() {
    let capped = PoolConfig {
        http2_max_concurrent_streams: Some(1),
        ..PoolConfig::default()
    };
    assert_eq!(
        streams_opened_before_peer_settings(&capped).await,
        1,
        "the second request must wait for the first stream or the peer's SETTINGS"
    );

    // Control: without a cap hyper's default lets both open, so the count above
    // is the cap's doing and not an artifact of the silent peer.
    let uncapped = PoolConfig {
        http2_max_concurrent_streams: None,
        ..PoolConfig::default()
    };
    assert_eq!(streams_opened_before_peer_settings(&uncapped).await, 2);
}

/// Issue #7071 (C): with the pool keepalive applied, a connection whose peer
/// stops answering is torn down by the PING timeout while a request is in
/// flight. The nested-HBONE dial used to apply no keepalive, so a stalled
/// destination app behind a live outer tunnel was never detected.
#[tokio::test]
async fn pool_keepalive_tears_down_a_silent_peer() {
    let pool_config = PoolConfig {
        enable_http2: true,
        http2_keep_alive_interval_seconds: 1,
        http2_keep_alive_timeout_seconds: 1,
        ..PoolConfig::default()
    };
    let (client_io, mut peer) = tokio::io::duplex(1 << 16);
    // The peer reads (so the client is never write-blocked) and never answers:
    // no SETTINGS, no response, no PING ACK.
    let silent_peer = tokio::spawn(async move {
        let mut sink = [0u8; 4096];
        while let Ok(read) = peer.read(&mut sink).await {
            if read == 0 {
                break;
            }
        }
    });
    let (mut sender, connection) = hyper_h2_client_builder_for_test(&pool_config)
        .handshake::<_, Empty<Bytes>>(TokioIo::new(client_io))
        .await
        .expect("client handshake");
    let driver = tokio::spawn(connection);
    sender.ready().await.expect("sender ready");
    let response = tokio::spawn(sender.send_request(get_request()));

    let ended = tokio::time::timeout(Duration::from_secs(10), driver).await;
    assert!(
        ended.is_ok(),
        "a silent peer must be torn down by the keepalive PING timeout"
    );
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("the in-flight request must end with its connection")
        .expect("request task must not panic");
    assert!(
        response.is_err(),
        "the in-flight request must fail once the connection is torn down"
    );
    silent_peer.abort();
}
