//! Unit tests for TLS handshake offload runtime.

use ferrum_edge::tls_offload::*;

#[test]
fn test_offload_config_default() {
    let config = TlsOffloadConfig::default();
    assert_eq!(config.shards, 2);
    assert_eq!(config.threads_per_shard, 1);
}

#[test]
fn test_offload_runtime_disabled_when_zero_shards() {
    let config = TlsOffloadConfig {
        shards: 0,
        threads_per_shard: 1,
    };
    assert!(TlsOffloadRuntime::new(config).is_none());
}

#[test]
fn test_offload_runtime_disabled_when_zero_threads() {
    let config = TlsOffloadConfig {
        shards: 2,
        threads_per_shard: 0,
    };
    assert!(TlsOffloadRuntime::new(config).is_none());
}

#[test]
fn test_offload_runtime_creates_handles() {
    let config = TlsOffloadConfig {
        shards: 2,
        threads_per_shard: 1,
    };
    let rt = TlsOffloadRuntime::new(config);
    assert!(rt.is_some());
}

#[test]
fn test_offload_runtime_shard_affinity() {
    let config = TlsOffloadConfig {
        shards: 4,
        threads_per_shard: 1,
    };
    let rt = TlsOffloadRuntime::new(config).unwrap();
    // Same peer hash should always return same handle
    let h1 = rt.get_handle(42) as *const _;
    let h2 = rt.get_handle(42) as *const _;
    assert_eq!(h1, h2, "Same peer hash should route to same handle");

    // Different peer hashes may route to different handles
    // (not guaranteed, but different modular residues should differ)
    let h3 = rt.get_handle(43) as *const _;
    // Just verify it doesn't panic
    let _ = h3;
}
