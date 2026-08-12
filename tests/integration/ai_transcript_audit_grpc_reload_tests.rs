//! Reload / update / delete lifecycle for the `ai_transcript_audit` native gRPC
//! descriptor dependency (issue #3304).
//!
//! Startup construction is not the whole contract. `grpc.descriptor_path` is a
//! NODE-LOCAL file dependency, so every publication that rebuilds the plugin
//! cache has to decide it again: enabling the block must produce a genuinely
//! gRPC-capable generation, a descriptor that cannot be parsed must be refused
//! without disturbing the live one, and disabling or deleting the policy must
//! withdraw gRPC capture rather than leaving a stale instance behind.
//!
//! These tests drive the real publication paths — `ProxyState::apply_incremental`
//! for database/CP deltas (the path `ai_transcript_audit_descriptor_preload_required`
//! feeds) and `ProxyState::update_config` for full snapshots — and then read the
//! published generation through the same `PluginCache` protocol view the request
//! path uses. The observable is instance presence in the exact protocol view,
//! not any internal descriptor bookkeeping.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde_json::{Value, json};
use tempfile::TempDir;

use ferrum_edge::config::db_loader::{IncrementalResult, NamespacedResourceId};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, PluginAssociation, PluginConfig,
    PluginScope, Proxy, default_namespace,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::{Plugin, ProxyProtocol};
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};

const PROXY_ID: &str = "grpc-audit-proxy";
const AUDIT_PLUGIN_ID: &str = "grpc-audit";
const PLUGIN_NAME: &str = "ai_transcript_audit";

/// The checked-in `FileDescriptorSet` the enrolled method resolves against.
fn checked_in_descriptor() -> String {
    format!(
        "{}/tests/fixtures/test_validator.bin",
        env!("CARGO_MANIFEST_DIR")
    )
}

// ───────────────────────────────── fixtures ─────────────────────────────────

fn test_proxy() -> Proxy {
    Proxy {
        id: PROXY_ID.to_string(),
        namespace: default_namespace(),
        name: Some(PROXY_ID.to_string()),
        hosts: vec![],
        listen_path: Some("/audit".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
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
        plugins: vec![PluginAssociation {
            plugin_config_id: AUDIT_PLUGIN_ID.to_string(),
        }],
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
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

fn audit_plugin_config(config: Value) -> PluginConfig {
    PluginConfig {
        id: AUDIT_PLUGIN_ID.to_string(),
        namespace: default_namespace(),
        plugin_name: PLUGIN_NAME.to_string(),
        config,
        enabled: true,
        scope: PluginScope::Proxy,
        proxy_id: Some(PROXY_ID.to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        priority_override: None,
        trigger: None,
        api_spec_id: None,
    }
}

/// No `grpc` block: an ordinary HTTP transcript policy.
fn http_only_audit_config() -> Value {
    json!({
        "sink": {
            "type": "http",
            "endpoint_url": "https://audit.example.com/v1/transcripts"
        }
    })
}

/// One enrolled native gRPC method resolved against `descriptor_path`.
fn grpc_audit_config(descriptor_path: &str) -> Value {
    json!({
        "sink": {
            "type": "http",
            "endpoint_url": "https://audit.example.com/v1/transcripts"
        },
        "grpc": {
            "descriptor_path": descriptor_path,
            "methods": {
                "/test.Greeter/SayHello": {
                    "request_type": "test.HelloRequest",
                    "response_type": "test.HelloResponse"
                }
            }
        }
    })
}

fn gateway_config(audit_config: Value) -> GatewayConfig {
    GatewayConfig {
        version: ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: vec![test_proxy()],
        plugin_configs: vec![audit_plugin_config(audit_config)],
        ..Default::default()
    }
}

fn test_env_config() -> ferrum_edge::config::env_config::EnvConfig {
    ferrum_edge::config::env_config::EnvConfig {
        mode: ferrum_edge::config::env_config::OperatingMode::File,
        worker_threads: None,
        blocking_threads: None,
        max_connections: 0,
        tcp_listen_backlog: 2048,
        server_http2_max_concurrent_streams: 250,
        ..Default::default()
    }
}

fn proxy_state(mut config: GatewayConfig) -> ProxyState {
    // Production loaders normalize before `ProxyState::new`; without it the
    // stored snapshot and the first delta disagree on resolved fields.
    config.normalize_fields();
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: HashMap::new(),
        resolver_addresses: None,
        hosts_file_path: None,
        dns_order: None,
        ttl_override_seconds: None,
        min_ttl_seconds: 5,
        stale_ttl_seconds: 3600,
        error_ttl_seconds: 1,
        max_cache_size: 10_000,
        warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        slow_threshold_ms: None,
        refresh_threshold_percent: 90,
        failed_retry_interval_seconds: 10,
        try_tcp_on_error: true,
        num_concurrent_reqs: 3,
        max_active_requests: 512,
        max_concurrent_refreshes: 64,
        shard_amount: 0,
    });
    let (state, _health_check_handles) =
        ProxyState::new(config, dns_cache, test_env_config(), None, None)
            .expect("proxy state builds from the seed generation");
    state
}

fn empty_delta() -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    }
}

fn delta_with_plugin(plugin_config: PluginConfig) -> IncrementalResult {
    IncrementalResult {
        added_or_modified_plugin_configs: vec![plugin_config],
        ..empty_delta()
    }
}

fn delta_removing_audit_policy() -> IncrementalResult {
    IncrementalResult {
        removed_plugin_config_ids: vec![NamespacedResourceId::new(
            default_namespace(),
            AUDIT_PLUGIN_ID,
        )],
        ..empty_delta()
    }
}

/// A readable file that is not a `FileDescriptorSet`. A run of continuation
/// bytes is never a valid protobuf key varint, so the parse failure is
/// deterministic rather than dependent on how arbitrary bytes happen to decode.
fn write_unparseable_descriptor(directory: &TempDir) -> String {
    let path = directory.path().join("unparseable.bin");
    std::fs::write(&path, [0xFFu8; 32]).expect("write the unparseable descriptor fixture");
    path.to_string_lossy().into_owned()
}

// ─────────────────────────────── observables ────────────────────────────────

/// The `ai_transcript_audit` instance a request admitted right now would run on
/// `protocol`, read through the published plugin cache.
fn audit_instance(state: &ProxyState, protocol: ProxyProtocol) -> Option<Arc<dyn Plugin>> {
    state
        .plugin_cache
        .get_plugins_for_protocol(&default_namespace(), PROXY_ID, protocol)
        .iter()
        .find(|plugin| plugin.name() == PLUGIN_NAME)
        .cloned()
}

fn audits_protocol(state: &ProxyState, protocol: ProxyProtocol) -> bool {
    audit_instance(state, protocol).is_some()
}

/// The `grpc.descriptor_path` the published configuration currently names.
fn published_descriptor_path(state: &ProxyState) -> Option<String> {
    let config = state.config.load();
    config
        .plugin_configs
        .iter()
        .find(|pc| pc.id == AUDIT_PLUGIN_ID)?
        .config
        .get("grpc")?
        .get("descriptor_path")?
        .as_str()
        .map(str::to_string)
}

// ───────────────────────────────── enabling ─────────────────────────────────

/// Enabling a `grpc` block on an already-published HTTP-only policy must
/// produce a generation that is gRPC-capable in the view the request path
/// reads, not merely a config field that changed.
#[tokio::test(flavor = "multi_thread")]
async fn enabling_a_grpc_block_publishes_a_grpc_capable_generation() {
    let state = proxy_state(gateway_config(http_only_audit_config()));
    assert!(
        audits_protocol(&state, ProxyProtocol::Http),
        "the seed HTTP-only policy must be effective on the HTTP view"
    );
    assert!(
        !audits_protocol(&state, ProxyProtocol::Grpc),
        "an instance with no grpc block must not appear in the gRPC view"
    );

    let enrolled = audit_plugin_config(grpc_audit_config(&checked_in_descriptor()));
    let outcome = state.apply_incremental(delta_with_plugin(enrolled)).await;
    assert_eq!(
        outcome,
        ConfigApplyOutcome::Applied,
        "a valid checked-in descriptor must publish"
    );

    let instance = audit_instance(&state, ProxyProtocol::Grpc)
        .expect("the published generation must be effective on the gRPC view");
    assert!(
        instance
            .supported_protocols()
            .contains(&ProxyProtocol::Grpc),
        "the published instance must itself declare gRPC support"
    );
    assert!(
        instance.requires_request_body_buffering(),
        "gRPC capture needs the request body buffered to reach a final-body hook"
    );
    assert!(
        instance.requires_response_body_buffering(),
        "gRPC capture needs the response body buffered"
    );
    assert!(
        audits_protocol(&state, ProxyProtocol::Http),
        "enrolling gRPC must not withdraw the existing HTTP capture"
    );
}

/// Updating the enrolled method set on an already-gRPC-capable generation is
/// the ordinary reload case, and must keep the capability rather than
/// rebuilding it away.
#[tokio::test(flavor = "multi_thread")]
async fn updating_the_enrolled_method_set_keeps_the_generation_grpc_capable() {
    let descriptor = checked_in_descriptor();
    let state = proxy_state(gateway_config(grpc_audit_config(&descriptor)));
    assert!(audits_protocol(&state, ProxyProtocol::Grpc));

    // A real policy change against the same descriptor: narrow the captured
    // request projection to one field and tighten the frame budget.
    let mut updated = grpc_audit_config(&descriptor);
    updated["grpc"]["methods"]["/test.Greeter/SayHello"]["text_fields"] = json!(["name"]);
    updated["grpc"]["max_messages"] = json!(4);
    let candidate = audit_plugin_config(updated);
    let outcome = state.apply_incremental(delta_with_plugin(candidate)).await;
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    assert!(
        audits_protocol(&state, ProxyProtocol::Grpc),
        "an accepted policy update must republish a gRPC-capable generation"
    );
}

// ──────────────────────────── failing descriptors ───────────────────────────

/// A descriptor that exists but cannot be parsed is a REJECTION: the candidate
/// generation is refused and the live one keeps serving. Failing open here
/// would swap in an instance that silently stopped shaping enrolled payloads.
#[tokio::test(flavor = "multi_thread")]
async fn an_unparseable_descriptor_on_update_is_refused_and_retains_last_known_good() {
    let descriptor = checked_in_descriptor();
    let state = proxy_state(gateway_config(grpc_audit_config(&descriptor)));
    assert!(audits_protocol(&state, ProxyProtocol::Grpc));

    let directory = TempDir::new().expect("temp dir");
    let unparseable = write_unparseable_descriptor(&directory);
    let candidate = audit_plugin_config(grpc_audit_config(&unparseable));
    let outcome = state.apply_incremental(delta_with_plugin(candidate)).await;
    assert!(
        matches!(outcome, ConfigApplyOutcome::Rejected { .. }),
        "an unparseable descriptor must fail closed, got: {outcome:?}"
    );
    assert!(
        audits_protocol(&state, ProxyProtocol::Grpc),
        "the last-known-good gRPC-capable generation must survive a rejected update"
    );
    assert_eq!(
        published_descriptor_path(&state).as_deref(),
        Some(descriptor.as_str()),
        "a rejected candidate must not leave its descriptor path in the published config"
    );
}

/// An ABSENT node-local descriptor is deliberately not a rejection: enrollment
/// is retained so the method keeps being recognized, and the excerpt is omitted
/// at request time instead of being exported unshaped. What this pins is the
/// publication decision — accepted, and still gRPC-capable — and that it stays
/// distinct from the readable-but-unparseable case, which is refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_absent_descriptor_on_update_keeps_the_enrolled_generation() {
    let state = proxy_state(gateway_config(grpc_audit_config(&checked_in_descriptor())));
    let directory = TempDir::new().expect("temp dir");
    let absent = directory.path().join("never-written.bin");
    assert!(!absent.exists(), "the fixture path must not exist");

    let candidate = audit_plugin_config(grpc_audit_config(&absent.to_string_lossy()));
    let outcome = state.apply_incremental(delta_with_plugin(candidate)).await;
    assert_eq!(
        outcome,
        ConfigApplyOutcome::Applied,
        "an absent node-local descriptor must not reject the generation"
    );
    assert!(
        audits_protocol(&state, ProxyProtocol::Grpc),
        "enrollment must be retained so the enrolled method is still recognized"
    );
}

// ──────────────────────────────── withdrawal ────────────────────────────────

/// Disabling the policy must withdraw it from EVERY protocol view. A residual
/// gRPC instance would keep buffering and capturing native gRPC bodies for a
/// policy the operator turned off.
#[tokio::test(flavor = "multi_thread")]
async fn disabling_the_plugin_config_withdraws_the_grpc_capable_generation() {
    let state = proxy_state(gateway_config(grpc_audit_config(&checked_in_descriptor())));
    assert!(audits_protocol(&state, ProxyProtocol::Grpc));

    let mut disabled = audit_plugin_config(grpc_audit_config(&checked_in_descriptor()));
    disabled.enabled = false;
    let outcome = state.apply_incremental(delta_with_plugin(disabled)).await;
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    assert!(
        !audits_protocol(&state, ProxyProtocol::Grpc),
        "a disabled policy must leave no gRPC capture behind"
    );
    assert!(
        !audits_protocol(&state, ProxyProtocol::Http),
        "a disabled policy must leave no HTTP capture behind either"
    );
}

/// Deleting the policy row through an incremental removal must do the same.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_the_plugin_config_withdraws_the_grpc_capable_generation() {
    let state = proxy_state(gateway_config(grpc_audit_config(&checked_in_descriptor())));
    assert!(audits_protocol(&state, ProxyProtocol::Grpc));

    let outcome = state.apply_incremental(delta_removing_audit_policy()).await;
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    assert!(
        !audits_protocol(&state, ProxyProtocol::Grpc),
        "a deleted policy must leave no gRPC capture behind"
    );
    assert!(
        !audits_protocol(&state, ProxyProtocol::Http),
        "a deleted policy must leave no HTTP capture behind"
    );
}

/// The full-snapshot publication path must reach the same conclusion: dropping
/// the `grpc` block from a still-enabled policy leaves an HTTP-only instance,
/// with no residue in the gRPC view.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_publication_that_drops_the_grpc_block_withdraws_grpc_capability() {
    let state = proxy_state(gateway_config(grpc_audit_config(&checked_in_descriptor())));
    assert!(audits_protocol(&state, ProxyProtocol::Grpc));

    let mut candidate = gateway_config(http_only_audit_config());
    candidate.normalize_fields();
    let outcome = state.update_config(candidate);
    assert_eq!(outcome, ConfigApplyOutcome::Applied);

    assert!(
        !audits_protocol(&state, ProxyProtocol::Grpc),
        "withdrawing the grpc block must remove the instance from the gRPC view"
    );
    let instance = audit_instance(&state, ProxyProtocol::Http)
        .expect("the HTTP-only policy must remain effective");
    assert_eq!(
        instance.supported_protocols(),
        &[ProxyProtocol::Http],
        "the surviving instance must be HTTP-only — no stale gRPC capture"
    );
    assert_eq!(
        published_descriptor_path(&state),
        None,
        "the published config must no longer carry a descriptor dependency"
    );
}
