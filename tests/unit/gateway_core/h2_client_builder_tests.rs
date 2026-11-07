//! The hyper HTTP/2 client builder every `PoolConfig`-driven pool family
//! constructs (`pool::hyper_h2_client_builder`): direct H2, gRPC, mesh mTLS and
//! the nested-HBONE gRPC dial. hyper's `Builder` has no getters, but it derives
//! `Debug` over its full HTTP/2 config, so these tests compare that rendering.
//!
//! The `legacy_*` functions transcribe the four hand-written builders exactly as
//! they stood before the shared helper, so the characterization test fails if
//! any site's wire settings change. The structural pin that every site calls
//! the helper with its own options lives in `shared_invariant_parity_tests.rs`.

use std::time::Duration;

use ferrum_edge::_test_support::hyper_h2_client_builder_debug_for_test;
use ferrum_edge::config::PoolConfig;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioTimer};

fn debug(builder: &http2::Builder<TokioExecutor>) -> String {
    format!("{builder:?}")
}

/// `GrpcConnectionPool::build_h2_builder` and
/// `Http2ConnectionPool::build_h2_builder` (identical apart from comments).
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

/// The inline mesh-mTLS connection builder in `mesh_mtls_pool`.
fn legacy_mesh_mtls(pool_config: &PoolConfig) -> http2::Builder<TokioExecutor> {
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
    }
    builder
}

/// The inline nested-HBONE h2c gRPC builder in `grpc_proxy`.
fn legacy_nested_hbone_grpc(pool_config: &PoolConfig) -> http2::Builder<TokioExecutor> {
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());
    builder
        .initial_stream_window_size(pool_config.http2_initial_stream_window_size)
        .initial_connection_window_size(pool_config.http2_initial_connection_window_size)
        .adaptive_window(pool_config.http2_adaptive_window)
        .max_frame_size(pool_config.http2_max_frame_size);
    if let Some(max_streams) = pool_config.http2_max_concurrent_streams {
        builder.max_concurrent_streams(max_streams);
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

/// Characterization: every former call site gets exactly its prior builder.
#[test]
fn every_builder_site_keeps_its_prior_wire_settings() {
    for pool_config in pool_configs() {
        let direct = debug(&legacy_direct_h2_and_grpc(&pool_config));
        assert_eq!(
            hyper_h2_client_builder_debug_for_test(&pool_config, true, true),
            direct,
            "direct H2 / gRPC: {pool_config:?}"
        );
        assert_eq!(
            hyper_h2_client_builder_debug_for_test(&pool_config, true, false),
            debug(&legacy_mesh_mtls(&pool_config)),
            "mesh mTLS: {pool_config:?}"
        );
        assert_eq!(
            hyper_h2_client_builder_debug_for_test(&pool_config, false, false),
            debug(&legacy_nested_hbone_grpc(&pool_config)),
            "nested HBONE gRPC: {pool_config:?}"
        );
    }
}

/// Shared invariant (issue #5464): every option combination honours the
/// configured flow-control mode. Fixed windows keep the configured sizes;
/// adaptive mode starts from the spec window and grows.
#[test]
fn every_builder_honours_the_configured_flow_control_mode() {
    for pool_config in pool_configs() {
        for (keepalive, seed) in [(true, true), (true, false), (false, false), (false, true)] {
            let rendered = hyper_h2_client_builder_debug_for_test(&pool_config, keepalive, seed);
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
}

/// INTENTIONAL difference: the nested-HBONE gRPC dial does not apply the
/// pool's PING keepalive or reset-stream cap, even when `enable_http2` is set.
#[test]
fn keepalive_option_controls_pings_and_the_reset_stream_cap() {
    let pool_config = PoolConfig {
        enable_http2: true,
        http2_keep_alive_interval_seconds: 17,
        http2_keep_alive_timeout_seconds: 9,
        ..PoolConfig::default()
    };
    let applied = hyper_h2_client_builder_debug_for_test(&pool_config, true, true);
    assert!(
        applied.contains("keep_alive_interval: Some(17s)"),
        "{applied}"
    );
    assert!(applied.contains("keep_alive_timeout: 9s"), "{applied}");
    assert!(
        applied.contains("max_concurrent_reset_streams: Some(4096)"),
        "{applied}"
    );

    let not_applied = hyper_h2_client_builder_debug_for_test(&pool_config, false, true);
    assert!(
        not_applied.contains("keep_alive_interval: None"),
        "{not_applied}"
    );
    assert!(
        not_applied.contains("max_concurrent_reset_streams: None"),
        "{not_applied}"
    );

    // `enable_http2 = false` gates the pool keepalive off too.
    let disabled = PoolConfig {
        enable_http2: false,
        ..pool_config
    };
    let gated = hyper_h2_client_builder_debug_for_test(&disabled, true, true);
    assert!(gated.contains("keep_alive_interval: None"), "{gated}");
}

/// INTENTIONAL (today) difference: only direct H2 and gRPC seed hyper's initial
/// outbound stream bound from the cap; mesh mTLS and nested HBONE keep hyper's
/// default until the peer's SETTINGS arrive.
#[test]
fn initial_send_streams_option_controls_the_outbound_seed() {
    let pool_config = PoolConfig {
        http2_max_concurrent_streams: Some(7),
        ..PoolConfig::default()
    };
    let seeded = hyper_h2_client_builder_debug_for_test(&pool_config, true, true);
    assert!(seeded.contains("initial_max_send_streams: 7,"), "{seeded}");

    let unseeded = hyper_h2_client_builder_debug_for_test(&pool_config, true, false);
    assert!(
        unseeded.contains("initial_max_send_streams: 100,"),
        "hyper's default must stand: {unseeded}"
    );

    // Without a cap there is nothing to seed either way.
    let uncapped = PoolConfig {
        http2_max_concurrent_streams: None,
        ..PoolConfig::default()
    };
    assert_eq!(
        hyper_h2_client_builder_debug_for_test(&uncapped, true, true),
        hyper_h2_client_builder_debug_for_test(&uncapped, true, false)
    );
}
