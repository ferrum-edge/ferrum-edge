//! Publication-path reconciliation of the Unix backend pool (issue #3764).
//!
//! `unix_backend_pool_tests.rs` proves the pool's own fence. This file proves
//! the other half: that the fence is actually DRIVEN by every publication that
//! can become the current request epoch, through the production
//! `ProxyState` swap paths rather than a direct `retain_live_targets` call.
//!
//! The cases that used to slip through:
//!
//! * `apply_incremental` — database / CP-DP deltas publish through their own
//!   request-epoch path and never reconciled the pool at all;
//! * a publication whose `ConfigDelta` is empty but whose projected content
//!   changed (a same-timestamp `mesh.unix_socket` tag rewrite is exactly that
//!   shape) — it returned before the reconciliation ran.
//!
//! And the two that must NOT advance the pool's publication generation,
//! because neither becomes current: a rejected candidate and a genuinely
//! unchanged one.

#![cfg(unix)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use ferrum_edge::config::db_loader::{IncrementalResult, NamespacedResourceId};
use ferrum_edge::config::types::*;
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};

const UNIX_SOCKET_TAG: &str = "mesh.unix_socket";
const UNIX_SOCKET_H2C_TAG: &str = "mesh.unix_socket_h2c";
const PROXY_ID: &str = "sidecar-ingress-unix";
const UPSTREAM_ID: &str = "sidecar-ingress-unix-upstream";

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).expect("valid test timestamp")
}

/// Accepts and holds every connection, so a pooled carrier stays live.
struct HoldingPeer {
    task: tokio::task::JoinHandle<()>,
}

impl HoldingPeer {
    fn bind(path: &Path) -> Self {
        let listener = tokio::net::UnixListener::bind(path).expect("bind unix socket");
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        Self { task }
    }
}

impl Drop for HoldingPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// macOS temp dirs live behind `/var` → `/private/var`, so the configured root
/// must be the canonical one or containment rejects every path under it.
fn root_dir(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().canonicalize().expect("canonicalize temp dir")
}

fn roots(root: &Path) -> Vec<String> {
    vec![root.to_str().expect("utf-8 root").to_string()]
}

fn unix_target(socket_path: &str, h2c: bool) -> UpstreamTarget {
    let mut tags = HashMap::new();
    tags.insert(UNIX_SOCKET_TAG.to_string(), socket_path.to_string());
    tags.insert(
        UNIX_SOCKET_H2C_TAG.to_string(),
        if h2c { "true" } else { "false" }.to_string(),
    );
    UpstreamTarget {
        host: "127.0.0.1".to_string(),
        port: 15006,
        service_port_policy_key: None,
        weight: 100,
        tags,
        locality: None,
        path: None,
    }
}

fn unix_upstream(socket_path: &str, h2c: bool, stamp: DateTime<Utc>) -> Upstream {
    Upstream {
        id: UPSTREAM_ID.to_string(),
        namespace: default_namespace(),
        name: None,
        targets: vec![unix_target(socket_path, h2c)],
        algorithm: LoadBalancerAlgorithm::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: Default::default(),
        k8s_service_uid: None,
        pending_limit_scope: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: stamp,
        updated_at: stamp,
    }
}

fn unix_proxy(id: &str, listen_path: &str, stamp: DateTime<Utc>) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 15006,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: true,
        backend_connect_timeout_ms: 2_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        pending_limit_scope: None,
        upstream_id: Some(UPSTREAM_ID.to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: stamp,
        updated_at: stamp,
    }
}

fn config_with(socket_path: &str, h2c: bool, stamp: DateTime<Utc>) -> GatewayConfig {
    let mut config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![unix_proxy(PROXY_ID, "/", stamp)],
        consumers: Vec::new(),
        plugin_configs: Vec::new(),
        upstreams: vec![unix_upstream(socket_path, h2c, stamp)],
        loaded_at: stamp,
        known_namespaces: Vec::new(),
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    config
}

async fn state_from(config: GatewayConfig) -> ProxyState {
    let dns_cache = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let env_config = ferrum_edge::config::env_config::EnvConfig::default();
    let (state, _) = ProxyState::new(config, dns_cache, env_config, None, None)
        .expect("test proxy state should build");
    state
}

/// Pool exactly one idle HTTP/1.1 carrier for the config's Unix target,
/// through the production checkout/check-in path.
async fn pool_one_carrier(state: &ProxyState, socket: &Path, root: &Path) {
    let proxy = state
        .config
        .load_full()
        .proxies
        .iter()
        .find(|proxy| proxy.id == PROXY_ID)
        .cloned()
        .expect("the unix proxy is published");
    let lease = state
        .unix_backend_pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(root),
            &[],
        )
        .await
        .expect("checkout dials an admitted connection");
    state.unix_backend_pool.checkin_h1(lease);
    assert_eq!(
        state.unix_backend_pool.stats().idle_h1_connections,
        1,
        "the fixture must start with exactly one pooled carrier"
    );
}

/// Whether a checkout for the ORIGINAL identity is served from the pool.
async fn carrier_is_reused(state: &ProxyState, socket: &Path, root: &Path) -> bool {
    let proxy = unix_proxy(PROXY_ID, "/", ts(1_700_000_000));
    let lease = state
        .unix_backend_pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(root),
            &[],
        )
        .await
        .expect("checkout");
    lease.reused()
}

fn removal(id: &str) -> NamespacedResourceId {
    NamespacedResourceId {
        namespace: default_namespace(),
        id: id.to_string(),
    }
}

fn delta_removing_the_proxy(stamp: DateTime<Utc>) -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![removal(PROXY_ID)],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: stamp,
    }
}

fn delta_repointing_the_socket(socket_path: &str, stamp: DateTime<Utc>) -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![unix_upstream(socket_path, false, stamp)],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: stamp,
    }
}

/// `apply_incremental` is a separate publication path. A delta that withdraws
/// the proxy must retire the pooled carrier — it never travels through
/// `update_config`, so an `update_config`-only reconciliation missed it.
#[tokio::test]
async fn an_incremental_withdrawal_retires_the_pooled_unix_carrier() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let stamp = ts(1_700_000_000);

    let state = state_from(config_with(socket.to_str().expect("utf-8"), false, stamp)).await;
    pool_one_carrier(&state, &socket, &root).await;
    let before = state.unix_backend_pool.publication_generation();

    let outcome = state
        .apply_incremental(delta_removing_the_proxy(stamp + Duration::seconds(1)))
        .await;
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert!(
        state.unix_backend_pool.publication_generation() > before,
        "an incremental publication must advance the pool's generation"
    );
    assert_eq!(
        state.unix_backend_pool.stats().idle_h1_connections,
        0,
        "a target withdrawn by an incremental delta must retain no reusable carrier"
    );
    assert!(!carrier_is_reused(&state, &socket, &root).await);
}

/// A re-pointed `mesh.unix_socket` path is a different identity. Published
/// incrementally, it must still retire the carrier admitted for the old path.
#[tokio::test]
async fn an_incremental_socket_path_change_retires_the_old_carrier() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let moved = root.join("app-v2.sock");
    let _peer = HoldingPeer::bind(&socket);
    let _moved_peer = HoldingPeer::bind(&moved);
    let stamp = ts(1_700_000_000);

    let state = state_from(config_with(socket.to_str().expect("utf-8"), false, stamp)).await;
    pool_one_carrier(&state, &socket, &root).await;

    let outcome = state
        .apply_incremental(delta_repointing_the_socket(
            moved.to_str().expect("utf-8"),
            stamp + Duration::seconds(1),
        ))
        .await;
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert_eq!(
        state.unix_backend_pool.stats().idle_h1_connections,
        0,
        "the carrier admitted for the previous socket path must be retired"
    );
    assert!(!carrier_is_reused(&state, &socket, &root).await);
}

/// The `ConfigDelta`-free publication. A same-timestamp `http` → `http2` flip
/// changes only target tags, so the delta is empty and the epoch is published
/// through the projected-content branch that returns EARLY. Reconciliation has
/// to happen before that return.
#[tokio::test]
async fn a_same_timestamp_protocol_flip_retires_the_carrier_before_the_no_delta_return() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let stamp = ts(1_700_000_000);

    let state = state_from(config_with(socket.to_str().expect("utf-8"), false, stamp)).await;
    pool_one_carrier(&state, &socket, &root).await;
    let before = state.unix_backend_pool.publication_generation();

    // Identical timestamps, identical everything except the wire-protocol tag.
    let flipped = config_with(socket.to_str().expect("utf-8"), true, stamp);
    assert_eq!(state.update_config(flipped), ConfigApplyOutcome::Applied);

    assert!(
        state.unix_backend_pool.publication_generation() > before,
        "a delta-free but published epoch still advances the generation"
    );
    assert_eq!(
        state.unix_backend_pool.stats().idle_h1_connections,
        0,
        "an http -> http2 flip withdraws the HTTP/1.1 identity, carrier included"
    );
    assert!(!carrier_is_reused(&state, &socket, &root).await);
}

/// Deleting the proxy through the full snapshot path withdraws the identity
/// even though its upstream (and socket file) are untouched.
#[tokio::test]
async fn a_full_snapshot_proxy_deletion_retires_the_pooled_carrier() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let stamp = ts(1_700_000_000);

    let state = state_from(config_with(socket.to_str().expect("utf-8"), false, stamp)).await;
    pool_one_carrier(&state, &socket, &root).await;

    let later = stamp + Duration::seconds(1);
    let mut without_proxy = config_with(socket.to_str().expect("utf-8"), false, later);
    without_proxy.proxies.clear();
    assert_eq!(
        state.update_config(without_proxy),
        ConfigApplyOutcome::Applied
    );

    assert_eq!(
        state.unix_backend_pool.stats().idle_h1_connections,
        0,
        "no proxy declares the target any more, so nothing may stay reusable"
    );
    assert!(!carrier_is_reused(&state, &socket, &root).await);
}

/// A rejected candidate never becomes current, so it must not advance the
/// generation and must not disturb pooled carriers.
#[tokio::test]
async fn a_rejected_candidate_neither_advances_the_generation_nor_retires() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let stamp = ts(1_700_000_000);

    let state = state_from(config_with(socket.to_str().expect("utf-8"), false, stamp)).await;
    pool_one_carrier(&state, &socket, &root).await;
    let before = state.unix_backend_pool.publication_generation();

    // Two host-less proxies on one listen path is a validation conflict.
    let later = stamp + Duration::seconds(1);
    let mut invalid = config_with(socket.to_str().expect("utf-8"), false, later);
    invalid
        .proxies
        .push(unix_proxy("duplicate-listen-path", "/", later));
    assert!(matches!(
        state.update_config(invalid),
        ConfigApplyOutcome::Rejected { .. }
    ));

    assert_eq!(
        state.unix_backend_pool.publication_generation(),
        before,
        "a rejected candidate never becomes current, so nothing is superseded"
    );
    assert!(
        carrier_is_reused(&state, &socket, &root).await,
        "a rejected candidate must leave the pooled carrier reusable"
    );
}

/// A genuinely unchanged candidate publishes no epoch, so it must not advance
/// the generation either — otherwise a quiet config poll would retire every
/// in-flight lease in the fleet on every tick.
#[tokio::test]
async fn an_unchanged_candidate_does_not_advance_the_generation() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let stamp = ts(1_700_000_000);

    let state = state_from(config_with(socket.to_str().expect("utf-8"), false, stamp)).await;
    pool_one_carrier(&state, &socket, &root).await;
    let before = state.unix_backend_pool.publication_generation();

    assert_eq!(
        state.update_config(config_with(socket.to_str().expect("utf-8"), false, stamp)),
        ConfigApplyOutcome::Unchanged
    );

    assert_eq!(
        state.unix_backend_pool.publication_generation(),
        before,
        "an unchanged candidate publishes no epoch and supersedes nothing"
    );
    assert!(
        carrier_is_reused(&state, &socket, &root).await,
        "a quiet poll must leave the pool alone"
    );
}

// ---------------------------------------------------------------------------
// Effective keep-alive / reuse is part of the reusable live-identity set.
// ---------------------------------------------------------------------------

fn config_with_keep_alive(
    socket_path: &str,
    h2c: bool,
    stamp: DateTime<Utc>,
    pool_enable_http_keep_alive: Option<bool>,
) -> GatewayConfig {
    let mut config = config_with(socket_path, h2c, stamp);
    config.proxies[0].pool_enable_http_keep_alive = pool_enable_http_keep_alive;
    config
}

fn config_with_h1_and_h2c(
    h1_path: &str,
    h2c_path: &str,
    stamp: DateTime<Utc>,
    pool_enable_http_keep_alive: Option<bool>,
) -> GatewayConfig {
    let mut config = config_with(h1_path, false, stamp);
    config.proxies[0].pool_enable_http_keep_alive = pool_enable_http_keep_alive;
    config.upstreams[0]
        .targets
        .push(unix_target(h2c_path, true));
    config.normalize_fields();
    config
}

/// `collect_live_unix_target_identities` omits H1 when effective reuse is off,
/// honors per-proxy override over the process-lifetime default, and always
/// retains declared h2c identities across an H1-only reuse flip.
#[test]
fn collect_live_omits_h1_when_effective_keep_alive_is_false() {
    use ferrum_edge::proxy::collect_live_unix_target_identities;
    use ferrum_edge::proxy::unix_backend_pool::UnixWireProtocol;

    let stamp = ts(1_700_000_000);
    let h1 = "/tmp/ferrum-unix-h1.sock";
    let h2c = "/tmp/ferrum-unix-h2c.sock";

    // Global default false, no per-proxy override → H1 omitted.
    let from_global =
        collect_live_unix_target_identities(&config_with_h1_and_h2c(h1, h2c, stamp, None), false);
    assert!(
        from_global
            .iter()
            .all(|id| id.protocol == UnixWireProtocol::H2c),
        "global keep-alive=false must omit H1 from the reusable live set"
    );
    assert_eq!(from_global.len(), 1);

    // Global default true, per-proxy false → per-proxy wins, H1 omitted.
    let from_proxy = collect_live_unix_target_identities(
        &config_with_h1_and_h2c(h1, h2c, stamp, Some(false)),
        true,
    );
    assert!(
        from_proxy
            .iter()
            .all(|id| id.protocol == UnixWireProtocol::H2c),
        "per-proxy keep-alive=false must override a true global default"
    );
    assert_eq!(from_proxy.len(), 1);

    // Global default false, per-proxy true → H1 retained.
    let override_on = collect_live_unix_target_identities(&config_with(h1, false, stamp), false);
    // The plain helper leaves pool_enable_http_keep_alive = None, so global
    // false still omits; prove the Some(true) override restores H1.
    let restored = collect_live_unix_target_identities(
        &config_with_keep_alive(h1, false, stamp, Some(true)),
        false,
    );
    assert_eq!(
        override_on.len(),
        0,
        "None + global false must omit the H1 identity"
    );
    assert_eq!(
        restored.len(),
        1,
        "per-proxy keep-alive=true must restore H1 against a false global default"
    );
    assert!(
        restored
            .iter()
            .all(|id| id.protocol == UnixWireProtocol::Http1)
    );
}

/// Publishing a config that flips the proxy to keep-alive=false retires the
/// pooled H1 carrier through the production `ProxyState` swap path.
#[tokio::test]
async fn update_config_keep_alive_false_retires_pooled_h1_carriers() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let stamp = ts(1_700_000_000);
    let path = socket.to_str().expect("utf-8");

    let state = state_from(config_with(path, false, stamp)).await;
    pool_one_carrier(&state, &socket, &root).await;

    let later = stamp + Duration::seconds(1);
    assert_eq!(
        state.update_config(config_with_keep_alive(path, false, later, Some(false))),
        ConfigApplyOutcome::Applied
    );
    assert_eq!(
        state.unix_backend_pool.stats().idle_h1_connections,
        0,
        "publication must retire idle H1 carriers when effective reuse flips off"
    );
}
