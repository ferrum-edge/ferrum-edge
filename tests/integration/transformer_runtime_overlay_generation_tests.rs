//! Generation-binding coverage for the transformer RTDS gates
//! (GHSA-83rc-23c9-3g9x).
//!
//! The defect these tests fence is a time-of-check/time-of-use split between a
//! transformer's gate and the rules that gate governs. Mesh published a new
//! `RequestEpoch` (config + plugin caches) and then, separately and later,
//! swapped process-global RTDS gate stores. That produced two straddle windows:
//!
//! 1. **Publication barrier** — between the epoch swap and the gate swap, a
//!    plugin built from the NEW slice read the OLD gate.
//! 2. **Mid-request barrier** — after the gate swap, an already-admitted request
//!    still holding the OLD plugin read the NEW gate, for as long as that
//!    request lived (a slow upload, a slow backend). Worse, one request could
//!    read *different* values at its different phases, so paired
//!    header/query/body rules applied under disagreeing states.
//!
//! The fix binds the accepted overlay's gate into each candidate instance's own
//! configuration on the cold path, so gate and rules are one indivisible
//! generation. These tests assert that from the outside: they drive the real
//! mesh materializer (`materialize_transformer_runtime_overlay_for_test`) and
//! the real `ProxyState::update_config` publication, then check that a plugin
//! handle pinned before a publication keeps answering with its own generation at
//! EVERY phase while the newly published generation answers with the new one.
//!
//! Both transitions (false→true and true→false) and both directions
//! (`request_transformer`, `response_transformer`) are covered, because the
//! failure modes are not symmetric: a false→true flip can apply new rules to old
//! scope/defaults, while a true→false flip can strip a body redaction while
//! leaving the header that advertised it.

use std::collections::HashMap;

use chrono::Utc;
use serde_json::{Value, json};

use ferrum_edge::_test_support::materialize_transformer_runtime_overlay_for_test;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, PluginAssociation, PluginConfig,
    PluginScope, Proxy, default_namespace,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
use ferrum_edge::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use ferrum_edge::proxy::ProxyState;

const SCOPE: &str = "gen-barrier";
const REQUEST_GATE_KEY: &str = "ferrum.request_transformer.gen-barrier.enabled";
const RESPONSE_GATE_KEY: &str = "ferrum.response_transformer.gen-barrier.enabled";

// ─────────────────────────────── fixtures ───────────────────────────────

fn overlay(key: &str, enabled: bool) -> MeshRuntimeOverlay {
    MeshRuntimeOverlay {
        fields: HashMap::from([(key.to_string(), RuntimeValue::Bool(enabled))]),
    }
}

fn test_proxy(id: &str, plugin_ids: &[&str]) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: default_namespace(),
        name: Some(id.to_string()),
        hosts: vec![],
        listen_path: Some(format!("/{id}")),
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
        plugins: plugin_ids
            .iter()
            .map(|id| PluginAssociation {
                plugin_config_id: (*id).to_string(),
            })
            .collect(),
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn plugin_config(id: &str, plugin_name: &str, config: Value) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        enabled: true,
        scope: PluginScope::Proxy,
        proxy_id: Some("gated".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        priority_override: None,
        api_spec_id: None,
    }
}

/// A `request_transformer` whose header rule and body rule are PAIRED: the
/// header advertises that the body was sanitized, the body rule performs the
/// sanitization. Applying one without the other is the advisory's sensitive
/// case, so the test can detect a phase split by inspecting the pair.
fn request_transformer_config() -> Value {
    json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Sanitized", "value": "yes"},
            {"operation": "remove", "target": "body", "key": "secret"}
        ],
        "runtime_overlay_scope": SCOPE,
        "default_enabled": true
    })
}

fn response_transformer_config() -> Value {
    json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Redacted", "value": "yes"},
            {"operation": "remove", "target": "body", "key": "secret"}
        ],
        "runtime_overlay_scope": SCOPE,
        "default_enabled": true
    })
}

/// Build the effective mesh config for one generation: the operator's static
/// plugin config with the accepted overlay's gate bound into it by the real
/// production materializer.
fn generation(
    plugin_name: &str,
    static_config: Value,
    gate_key: &str,
    enabled: bool,
) -> GatewayConfig {
    let mut config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![test_proxy("gated", &["gate"])],
        consumers: vec![],
        plugin_configs: vec![plugin_config("gate", plugin_name, static_config)],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_namespace_sources: Vec::new(),
        trust_bundles: None,
        mesh: None,
        mesh_revision: None,
        k8s_mesh_overlay: Default::default(),
    };
    materialize_transformer_runtime_overlay_for_test(&mut config, &overlay(gate_key, enabled));
    config.normalize_fields();
    config
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

fn proxy_state(config: GatewayConfig) -> ProxyState {
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
            .expect("proxy state builds from the materialized generation");
    state
}

/// The transformer handle a request admitted right now would run.
///
/// Goes through the mirrored `ProxyState::plugin_cache` (the epoch's own
/// `plugin_cache` is crate-private); `update_config` mirrors it under the epoch
/// writer lock, so it always reflects the published generation.
fn transformer_from(state: &ProxyState, plugin_name: &str) -> std::sync::Arc<dyn Plugin> {
    state
        .plugin_cache
        .request_view("ferrum", "gated", ProxyProtocol::Http)
        .plugins()
        .iter()
        .find(|plugin| plugin.name() == plugin_name)
        .cloned()
        .unwrap_or_else(|| panic!("{plugin_name} is cached for the gated proxy"))
}

fn ctx() -> RequestContext {
    RequestContext::new(
        "192.0.2.10".to_string(),
        "POST".to_string(),
        "/gated".to_string(),
    )
}

const BODY: &[u8] = br#"{"secret":"s3cr3t","keep":"ok"}"#;

/// Observe every request-side phase of one `request_transformer` handle.
async fn observe_request(plugin: &std::sync::Arc<dyn Plugin>) -> (bool, bool) {
    let mut request_ctx = ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut request_ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let header_applied = headers.contains_key("x-sanitized");
    let body_applied = plugin
        .transform_request_body(BODY, Some("application/json"), &headers)
        .await
        .is_some_and(|body| !String::from_utf8_lossy(&body).contains("secret"));
    (header_applied, body_applied)
}

/// Observe every response-side phase of one `response_transformer` handle,
/// including the pre-header buffering preflight that used to be able to
/// disagree with the later hooks.
async fn observe_response(plugin: &std::sync::Arc<dyn Plugin>) -> (bool, bool, bool) {
    let mut response_ctx = ctx();
    let buffers = plugin.should_buffer_response_body(&response_ctx);
    let mut headers: HashMap<String, String> =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    assert!(matches!(
        plugin
            .after_proxy(&mut response_ctx, 200, &mut headers)
            .await,
        PluginResult::Continue
    ));
    let header_applied = headers.contains_key("x-redacted");
    let body_applied = plugin
        .transform_response_body(BODY, Some("application/json"), &headers)
        .await.replaced_bytes()
        .is_some_and(|body| !String::from_utf8_lossy(&body).contains("secret"));
    (buffers, header_applied, body_applied)
}

// ─────────────────── request_transformer: both transitions ───────────────────

/// A gate flip that lands while an old request is in flight must not reach that
/// request, and must fully reach the newly published generation — at every
/// phase, for both transition directions.
#[tokio::test(flavor = "multi_thread")]
async fn request_transformer_gate_flip_does_not_straddle_a_published_generation() {
    for (from, to) in [(true, false), (false, true)] {
        let state = proxy_state(generation(
            "request_transformer",
            request_transformer_config(),
            REQUEST_GATE_KEY,
            from,
        ));
        // The handle an already-admitted request is holding.
        let in_flight = transformer_from(&state, "request_transformer");
        assert_eq!(
            observe_request(&in_flight).await,
            (from, from),
            "generation {from} must apply both paired rules consistently before any update"
        );

        // Publish the flipped generation, exactly as a mesh slice apply does.
        state.update_config(generation(
            "request_transformer",
            request_transformer_config(),
            REQUEST_GATE_KEY,
            to,
        ));

        // Publication barrier: the newly published generation answers `to` at
        // every phase — never a mix with the retired gate.
        let published = transformer_from(&state, "request_transformer");
        assert_eq!(
            observe_request(&published).await,
            (to, to),
            "the published generation must apply gate {to} to both paired rules"
        );

        // Mid-request barrier: the in-flight handle is still on `from`. Before
        // the fix this read the live process-global gate and returned `to`,
        // so a marker header could ship with an unredacted body.
        assert_eq!(
            observe_request(&in_flight).await,
            (from, from),
            "an in-flight request must stay wholly on the generation it pinned"
        );
    }
}

// ─────────────────── response_transformer: both transitions ──────────────────

/// The response side additionally has a pre-header buffering preflight. A gate
/// flip must not let the preflight and the later header/body hooks disagree:
/// that combination shipped a response marked as redacted whose body rules never
/// ran because streaming had already been selected.
#[tokio::test(flavor = "multi_thread")]
async fn response_transformer_preflight_and_hooks_never_disagree_across_a_publication() {
    for (from, to) in [(true, false), (false, true)] {
        let state = proxy_state(generation(
            "response_transformer",
            response_transformer_config(),
            RESPONSE_GATE_KEY,
            from,
        ));
        let in_flight = transformer_from(&state, "response_transformer");
        assert_eq!(
            observe_response(&in_flight).await,
            (from, from, from),
            "buffering preflight, header phase, and body phase must agree on gate {from}"
        );

        state.update_config(generation(
            "response_transformer",
            response_transformer_config(),
            RESPONSE_GATE_KEY,
            to,
        ));

        let published = transformer_from(&state, "response_transformer");
        assert_eq!(
            observe_response(&published).await,
            (to, to, to),
            "the published generation must apply gate {to} at preflight and at both hooks"
        );

        // The straddle the advisory describes: a request whose preflight said
        // `from` must not have its header/body phases answer `to`.
        assert_eq!(
            observe_response(&in_flight).await,
            (from, from, from),
            "a response that already selected its buffering strategy must keep that gate"
        );
    }
}

// ───────────────────────── publication coherence ─────────────────────────

/// An overlay-only change must actually rebuild the transformer instance.
///
/// RTDS is not one of the slice's version-coherence resource types, so an
/// RTDS-only update can leave `loaded_at` and every static field untouched. If
/// the generation reconciliation did not stamp the affected plugin, `ConfigDelta`
/// would see no plugin difference, retain the old instance, and leave the old
/// gate live under a nominally accepted slice.
#[tokio::test(flavor = "multi_thread")]
async fn overlay_only_change_publishes_a_new_transformer_instance() {
    let state = proxy_state(generation(
        "response_transformer",
        response_transformer_config(),
        RESPONSE_GATE_KEY,
        true,
    ));
    let before = transformer_from(&state, "response_transformer");

    let mut flipped = generation(
        "response_transformer",
        response_transformer_config(),
        RESPONSE_GATE_KEY,
        false,
    );
    // Simulate the real cold path: the candidate is rebuilt from the static mesh
    // source, so its timestamp does not advance on its own.
    let previous = state.config.load_full();
    ferrum_edge::_test_support::reconcile_runtime_overlay_plugin_generations_for_test(
        &mut flipped,
        &previous,
    );
    state.update_config(flipped);

    let after = transformer_from(&state, "response_transformer");
    assert!(
        !std::sync::Arc::ptr_eq(&before, &after),
        "an overlay-only gate flip must publish a rebuilt instance, not retain the old gate"
    );
    assert_eq!(
        observe_response(&after).await,
        (false, false, false),
        "the rebuilt instance must carry the new gate at every phase"
    );
}

/// A rejected candidate must leave the previous generation's gate serving.
#[tokio::test(flavor = "multi_thread")]
async fn rejected_candidate_keeps_the_last_known_good_gate() {
    let state = proxy_state(generation(
        "request_transformer",
        request_transformer_config(),
        REQUEST_GATE_KEY,
        true,
    ));
    let accepted = transformer_from(&state, "request_transformer");
    assert_eq!(observe_request(&accepted).await, (true, true));

    // A candidate whose transformer config cannot build. `update_config` must
    // refuse it wholesale rather than publish a partially gated generation.
    let mut invalid = generation(
        "request_transformer",
        request_transformer_config(),
        REQUEST_GATE_KEY,
        false,
    );
    invalid.plugin_configs[0]
        .config
        .as_object_mut()
        .expect("transformer config is an object")
        .insert("rules".to_string(), json!("not-an-array"));
    state.update_config(invalid);

    let still_serving = transformer_from(&state, "request_transformer");
    assert_eq!(
        observe_request(&still_serving).await,
        (true, true),
        "a rejected candidate must leave the last accepted gate and rules intact"
    );
}

// ─────────────────────── materialization semantics ───────────────────────

/// The reserved key is authoritative and scope-bound: it is rewritten from the
/// accepted overlay, removed when the overlay names no gate for the scope (so
/// `default_enabled` governs), and removed entirely for an instance that never
/// opted into a scope — so a stale or hostile value cannot pin a gate.
#[test]
fn materialization_is_authoritative_and_scope_bound() {
    let resolved = |config: &GatewayConfig| -> Option<bool> {
        config.plugin_configs[0]
            .config
            .get("runtime_overlay_resolved_enabled")
            .and_then(Value::as_bool)
    };

    // A named gate is bound.
    let bound = generation(
        "request_transformer",
        request_transformer_config(),
        REQUEST_GATE_KEY,
        false,
    );
    assert_eq!(resolved(&bound), Some(false));

    // A stale value from an earlier generation is overwritten, not merged.
    let mut stale = bound.clone();
    stale.plugin_configs[0]
        .config
        .as_object_mut()
        .expect("object")
        .insert("runtime_overlay_resolved_enabled".to_string(), json!(true));
    materialize_transformer_runtime_overlay_for_test(&mut stale, &overlay(REQUEST_GATE_KEY, false));
    assert_eq!(
        resolved(&stale),
        Some(false),
        "materialization must overwrite a value inherited from another generation"
    );

    // An overlay that names no gate for the scope leaves `default_enabled` in
    // charge rather than pinning the previous value.
    let mut unnamed = bound.clone();
    materialize_transformer_runtime_overlay_for_test(&mut unnamed, &MeshRuntimeOverlay::default());
    assert_eq!(
        resolved(&unnamed),
        None,
        "an overlay without the scope must fall back to default_enabled"
    );

    // The response namespace must not gate the request transformer.
    let mut cross = bound.clone();
    materialize_transformer_runtime_overlay_for_test(
        &mut cross,
        &overlay(RESPONSE_GATE_KEY, false),
    );
    assert_eq!(
        resolved(&cross),
        None,
        "a response_transformer key must not bind a request_transformer instance"
    );

    // An instance with no scope never carries the reserved key.
    let mut scopeless = generation(
        "request_transformer",
        json!({
            "rules": [
                {"operation": "add", "target": "header", "key": "X-Plain", "value": "v"}
            ]
        }),
        REQUEST_GATE_KEY,
        false,
    );
    assert_eq!(resolved(&scopeless), None);
    scopeless.plugin_configs[0]
        .config
        .as_object_mut()
        .expect("object")
        .insert("runtime_overlay_resolved_enabled".to_string(), json!(false));
    materialize_transformer_runtime_overlay_for_test(
        &mut scopeless,
        &overlay(REQUEST_GATE_KEY, false),
    );
    assert_eq!(
        resolved(&scopeless),
        None,
        "a scopeless instance must never retain a resolved gate"
    );
}
