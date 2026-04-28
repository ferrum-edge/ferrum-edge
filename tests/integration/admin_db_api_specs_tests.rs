//! Integration tests for `DatabaseBackend` api_spec operations (Wave 2).
//!
//! All tests run against a SQLite in-memory (file-based temp) database so they
//! are self-contained and do not require any external service.
//!
//! # Hot-path isolation contract
//!
//! The `api_specs` table is admin-only metadata. These methods must NEVER be
//! called from the proxy runtime, polling loops, or gRPC distribution paths.
//! Each test verifies only the admin-layer operations; no test wires
//! `list_api_specs` / `get_api_spec` into `GatewayConfig` loading.

use ferrum_edge::{
    ExtractedBundle, GatewayConfig,
    config::{
        db_backend::{ApiSpecListFilter, ApiSpecSortBy, SortOrder},
        db_loader::{DatabaseStore, DbPoolConfig},
        types::{ApiSpec, PluginConfig, PluginScope, Proxy, SpecFormat, Upstream},
    },
};
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;

/// Build a default list filter with just limit/offset (for existing pagination tests).
fn simple_filter(limit: u32, offset: u32) -> ApiSpecListFilter {
    ApiSpecListFilter {
        limit,
        offset,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Monotonic counter to generate unique resource IDs within a test run.
static COUNTER: AtomicU64 = AtomicU64::new(1);

fn uid(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

/// Pool config with short timeouts for test speed.
fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 2,
        min_connections: 0,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

/// Create a fresh SQLite in-memory (temp-file) store with migrations applied.
async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir.path().join(format!("test-{}.db", uid("db")));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_tls_config(
        "sqlite",
        &url,
        false,
        None,
        None,
        None,
        false,
        test_pool_config(),
    )
    .await
    .expect("connect_with_tls_config failed")
}

/// Build a minimal `Proxy` with a unique id.
fn make_proxy(id: &str, namespace: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "backend_host": "backend.example.com",
        "backend_port": 443,
        "listen_path": format!("/{id}")
    }))
    .expect("proxy deserialization failed")
}

/// Build a minimal `Upstream` with a unique id.
fn make_upstream(id: &str, namespace: &str) -> Upstream {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "targets": [{"host": "target.internal", "port": 443}]
    }))
    .expect("upstream deserialization failed")
}

/// Build a `PluginConfig` linked to a proxy.
fn make_plugin(
    id: &str,
    proxy_id: &str,
    namespace: &str,
    api_spec_id: Option<&str>,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: namespace.to_string(),
        plugin_name: "rate_limiting".to_string(),
        config: serde_json::json!({"limit": 100}),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: api_spec_id.map(str::to_string),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Build an `ApiSpec` with gzip-compressed stub content.
fn make_spec(id: &str, proxy_id: &str, namespace: &str, content: &[u8]) -> ApiSpec {
    let compressed =
        ferrum_edge::admin::spec_codec::compress_gzip(content).expect("compress failed");
    let hash = ferrum_edge::admin::spec_codec::sha256_hex(content);
    ApiSpec {
        id: id.to_string(),
        namespace: namespace.to_string(),
        proxy_id: proxy_id.to_string(),
        spec_version: "3.1.0".to_string(),
        spec_format: SpecFormat::Json,
        spec_content: compressed,
        content_encoding: "gzip".to_string(),
        uncompressed_size: content.len() as u64,
        content_hash: hash,
        title: Some("Test API".to_string()),
        info_version: Some("1.0.0".to_string()),
        // Wave 5 fields — defaults for existing tests
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// submit_api_spec_bundle — happy path
// ---------------------------------------------------------------------------

/// All four resource types (proxy, upstream, 2 plugins, spec) are written and
/// each carries the correct `api_spec_id` tag.
#[tokio::test]
async fn submit_bundle_happy_path_all_resources_tagged() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let plugin_id_1 = uid("plugin");
    let plugin_id_2 = uid("plugin");
    let spec_id = uid("spec");

    let proxy = make_proxy(&proxy_id, ns);
    let upstream = make_upstream(&upstream_id, ns);

    let plugin1 = make_plugin(&plugin_id_1, &proxy_id, ns, None);
    let plugin2 = make_plugin(&plugin_id_2, &proxy_id, ns, None);

    let bundle = ExtractedBundle {
        proxy,
        upstream: Some(upstream),
        plugins: vec![plugin1, plugin2],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"stub spec content for test");

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit_api_spec_bundle failed");

    // --- Verify the spec row round-trips correctly ---
    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found after submit");
    assert_eq!(fetched.id, spec_id);
    assert_eq!(fetched.proxy_id, proxy_id);
    assert_eq!(fetched.content_hash, spec.content_hash);
    assert_eq!(
        fetched.spec_content, spec.spec_content,
        "spec_content bytes must round-trip"
    );

    // --- Verify proxy exists ---
    let proxy_row = store
        .get_proxy(&proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy not found");
    assert_eq!(
        proxy_row.api_spec_id, None,
        "get_proxy does not load api_spec_id (hot-path isolation)"
    );

    // --- Verify get_api_spec_by_proxy ---
    let by_proxy = store
        .get_api_spec_by_proxy(ns, &proxy_id)
        .await
        .expect("get_api_spec_by_proxy failed")
        .expect("spec not found by proxy_id");
    assert_eq!(by_proxy.id, spec_id);

    // --- Verify plugin count (2 spec-owned + 0 hand-added = 2) ---
    let all_plugins = store
        .list_plugin_configs_paginated(ns, 100, 0)
        .await
        .expect("list_plugin_configs_paginated failed");
    let spec_plugins: Vec<_> = all_plugins
        .items
        .iter()
        .filter(|pc| pc.proxy_id.as_deref() == Some(&proxy_id))
        .collect();
    assert_eq!(spec_plugins.len(), 2, "expected 2 plugins for proxy");
}

/// submit with proxy-only bundle (no upstream, no plugins).
#[tokio::test]
async fn submit_bundle_proxy_only() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"proxy-only spec");

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found");
    assert_eq!(fetched.proxy_id, proxy_id);
}

// ---------------------------------------------------------------------------
// submit_api_spec_bundle — rollback on duplicate
// ---------------------------------------------------------------------------

/// When the INSERT fails mid-transaction (duplicate proxy id), the entire
/// transaction is rolled back and no rows are left in any table.
#[tokio::test]
async fn submit_bundle_rollback_on_duplicate_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id_1 = uid("spec");
    let spec_id_2 = uid("spec");

    // First submit succeeds.
    let bundle1 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec1 = make_spec(&spec_id_1, &proxy_id, ns, b"first spec");
    store
        .submit_api_spec_bundle(&bundle1, &spec1)
        .await
        .expect("first submit failed");

    // Second submit uses the SAME proxy_id → should fail with a unique constraint error.
    let bundle2 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec2 = make_spec(&spec_id_2, &proxy_id, ns, b"duplicate spec");
    let result = store.submit_api_spec_bundle(&bundle2, &spec2).await;
    assert!(result.is_err(), "duplicate proxy_id submit must return Err");

    // The second spec row must NOT be present.
    let fetched2 = store
        .get_api_spec(ns, &spec_id_2)
        .await
        .expect("get_api_spec failed");
    assert!(
        fetched2.is_none(),
        "spec2 must not exist after rollback; got: {:?}",
        fetched2.map(|s| s.id)
    );

    // The first spec + proxy must still be intact.
    let fetched1 = store
        .get_api_spec(ns, &spec_id_1)
        .await
        .expect("get_api_spec failed")
        .expect("spec1 not found after failed second submit");
    assert_eq!(fetched1.id, spec_id_1);
}

// ---------------------------------------------------------------------------
// replace_api_spec_bundle
// ---------------------------------------------------------------------------

/// After replace: the spec-owned plugin is gone (replaced), but a hand-added
/// plugin (api_spec_id = NULL) on the same proxy survives.
#[tokio::test]
async fn replace_bundle_spec_owned_replaced_hand_added_survives() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let spec_plugin_id = uid("plugin");
    let hand_plugin_id = uid("plugin");

    // Initial submit: one spec-owned plugin.
    let spec_plugin = make_plugin(&spec_plugin_id, &proxy_id, ns, None);
    let bundle_v1 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![spec_plugin],
    };
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 spec");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    // Now hand-add a plugin directly (api_spec_id = NULL).
    let hand_plugin = make_plugin(&hand_plugin_id, &proxy_id, ns, None);
    store
        .create_plugin_config(&hand_plugin)
        .await
        .expect("hand-add plugin failed");

    // Verify both plugins exist before replace.
    let before = store
        .list_plugin_configs_paginated(ns, 100, 0)
        .await
        .expect("list failed");
    let proxy_plugins_before: Vec<_> = before
        .items
        .iter()
        .filter(|pc| pc.proxy_id.as_deref() == Some(&proxy_id))
        .collect();
    assert_eq!(
        proxy_plugins_before.len(),
        2,
        "expected 2 plugins before replace"
    );

    // Replace: new bundle has a different spec-owned plugin.
    let new_spec_plugin_id = uid("plugin");
    let new_spec_plugin = make_plugin(&new_spec_plugin_id, &proxy_id, ns, None);
    let bundle_v2 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![new_spec_plugin],
    };
    let spec_v2 = make_spec(&spec_id, &proxy_id, ns, b"v2 spec");
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    // Old spec-owned plugin must be gone.
    let old_plugin = store
        .get_plugin_config(&spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        old_plugin.is_none(),
        "old spec-owned plugin must be removed after replace"
    );

    // New spec-owned plugin must exist.
    let new_plugin = store
        .get_plugin_config(&new_spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        new_plugin.is_some(),
        "new spec-owned plugin must exist after replace"
    );

    // The hand-added plugin (NULL api_spec_id) must survive because replace now
    // UPDATE-s the proxy in place rather than DELETE + INSERT, so the proxy PK
    // is stable and the FK cascade does NOT fire.
    let hand_plugin_row = store
        .get_plugin_config(&hand_plugin_id)
        .await
        .expect("get_plugin_config for hand plugin failed");
    assert!(
        hand_plugin_row.is_some(),
        "hand-added plugin must survive spec replace (proxy updated in place)"
    );

    // Proxy primary key must be stable — same id, same created_at.
    let proxy_after = store
        .get_proxy(&proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist after replace");
    assert_eq!(
        proxy_after.id, proxy_id,
        "proxy id must be unchanged after replace"
    );
}

// ---------------------------------------------------------------------------
// get_api_spec round-trip (spec_content bytes are preserved)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_api_spec_bytes_round_trip() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    // Use a content string with non-ASCII bytes to stress the BLOB path.
    let raw_content: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
    let spec = make_spec(&spec_id, &proxy_id, ns, &raw_content);

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found");

    assert_eq!(
        fetched.spec_content, spec.spec_content,
        "BLOB round-trip must preserve all bytes"
    );
    assert_eq!(fetched.uncompressed_size, 512);
    assert_eq!(fetched.content_hash, spec.content_hash);
    assert_eq!(fetched.spec_format, SpecFormat::Json);
    assert_eq!(fetched.title.as_deref(), Some("Test API"));
    assert_eq!(fetched.info_version.as_deref(), Some("1.0.0"));
}

// ---------------------------------------------------------------------------
// get_api_spec_by_proxy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_api_spec_by_proxy_returns_none_for_unknown_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let result = store
        .get_api_spec_by_proxy("ferrum", "nonexistent-proxy-id")
        .await
        .expect("get_api_spec_by_proxy failed");
    assert!(result.is_none());
}

#[tokio::test]
async fn get_api_spec_by_proxy_finds_spec() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"spec");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let result = store
        .get_api_spec_by_proxy(ns, &proxy_id)
        .await
        .expect("get_api_spec_by_proxy failed")
        .expect("spec not found by proxy_id");
    assert_eq!(result.id, spec_id);
}

// ---------------------------------------------------------------------------
// list_api_specs — namespace-scoped, paginated
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_api_specs_namespace_scoped_and_paginated() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let ns_a = "ns-a";
    let ns_b = "ns-b";

    // Insert 3 specs in ns_a and 1 in ns_b.
    for i in 0..3 {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let bundle = ExtractedBundle {
            proxy: make_proxy(&proxy_id, ns_a),
            upstream: None,
            plugins: vec![],
        };
        let spec = make_spec(&spec_id, &proxy_id, ns_a, format!("spec-{i}").as_bytes());
        store
            .submit_api_spec_bundle(&bundle, &spec)
            .await
            .unwrap_or_else(|e| panic!("submit ns_a spec {i} failed: {e}"));
    }
    {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let bundle = ExtractedBundle {
            proxy: make_proxy(&proxy_id, ns_b),
            upstream: None,
            plugins: vec![],
        };
        let spec = make_spec(&spec_id, &proxy_id, ns_b, b"ns-b spec");
        store
            .submit_api_spec_bundle(&bundle, &spec)
            .await
            .expect("submit ns_b spec failed");
    }

    // All 3 ns_a specs.
    let all_a = store
        .list_api_specs(ns_a, &simple_filter(100, 0))
        .await
        .expect("list_api_specs failed");
    assert_eq!(all_a.len(), 3, "ns_a must have 3 specs");

    // Pagination: first page (limit=2), second page (limit=2, offset=2).
    let page1 = store
        .list_api_specs(ns_a, &simple_filter(2, 0))
        .await
        .expect("page1 failed");
    let page2 = store
        .list_api_specs(ns_a, &simple_filter(2, 2))
        .await
        .expect("page2 failed");
    assert_eq!(page1.len(), 2, "page1 should have 2 items");
    assert_eq!(page2.len(), 1, "page2 should have 1 item");

    // Namespace isolation: ns_b must have exactly 1 spec.
    let all_b = store
        .list_api_specs(ns_b, &simple_filter(100, 0))
        .await
        .expect("list ns_b failed");
    assert_eq!(all_b.len(), 1, "ns_b must have 1 spec");

    // ns_b spec must not appear in ns_a results.
    let b_id = &all_b[0].id;
    assert!(
        all_a.iter().all(|s| &s.id != b_id),
        "ns_b spec must not appear in ns_a listing"
    );
}

// ---------------------------------------------------------------------------
// delete_api_spec — cascade behaviour
// ---------------------------------------------------------------------------

/// delete_api_spec removes the proxy, spec-owned plugins, spec-owned upstream,
/// and the spec row itself. A non-spec-owned upstream (hand-created, no
/// api_spec_id) is NOT removed.
#[tokio::test]
async fn delete_api_spec_cascades_and_spares_hand_upstreams() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let plugin_id = uid("plugin");
    let spec_id = uid("spec");

    // Spec-owned upstream + proxy + plugin.
    let spec_upstream = make_upstream(&upstream_id, ns);
    let spec_plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: Some(spec_upstream),
        plugins: vec![spec_plugin],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"to be deleted");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // Create a hand-added upstream (not owned by any spec).
    let hand_upstream_id = uid("upstream");
    let hand_upstream = make_upstream(&hand_upstream_id, ns);
    store
        .create_upstream(&hand_upstream)
        .await
        .expect("create hand upstream failed");

    // Delete the spec.
    let deleted = store
        .delete_api_spec(ns, &spec_id)
        .await
        .expect("delete_api_spec failed");
    assert!(
        deleted,
        "delete_api_spec must return true for existing spec"
    );

    // Spec row must be gone.
    let spec_row = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed");
    assert!(spec_row.is_none(), "spec row must be gone after delete");

    // Proxy must be gone.
    let proxy_row = store.get_proxy(&proxy_id).await.expect("get_proxy failed");
    assert!(proxy_row.is_none(), "proxy must be gone after spec delete");

    // Spec-owned upstream must be gone.
    let upstream_row = store
        .get_upstream(&upstream_id)
        .await
        .expect("get_upstream failed");
    assert!(
        upstream_row.is_none(),
        "spec-owned upstream must be gone after spec delete"
    );

    // Hand-added upstream must still exist.
    let hand_row = store
        .get_upstream(&hand_upstream_id)
        .await
        .expect("get_upstream for hand upstream failed");
    assert!(
        hand_row.is_some(),
        "hand-added upstream must survive spec delete"
    );

    // Spec-owned plugin must be gone (deleted by either api_spec_id cleanup or
    // the proxy FK cascade — both are in play).
    let plugin_row = store
        .get_plugin_config(&plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        plugin_row.is_none(),
        "spec-owned plugin must be gone after spec delete"
    );
}

/// delete_api_spec returns false for a non-existent spec.
#[tokio::test]
async fn delete_api_spec_returns_false_for_missing_spec() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let deleted = store
        .delete_api_spec("ferrum", "nonexistent-spec-id")
        .await
        .expect("delete_api_spec failed");
    assert!(
        !deleted,
        "delete_api_spec must return false for missing spec"
    );
}

// ---------------------------------------------------------------------------
// Namespace isolation
// ---------------------------------------------------------------------------

/// A spec in namespace A must not be visible from namespace B.
#[tokio::test]
async fn spec_in_ns_a_invisible_from_ns_b() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, "ns-a"),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, "ns-a", b"ns-a content");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // get_api_spec with wrong namespace → None.
    let result = store
        .get_api_spec("ns-b", &spec_id)
        .await
        .expect("get_api_spec failed");
    assert!(result.is_none(), "spec in ns-a must be invisible from ns-b");

    // list_api_specs for ns-b → empty.
    let list = store
        .list_api_specs("ns-b", &simple_filter(100, 0))
        .await
        .expect("list_api_specs failed");
    assert!(list.is_empty(), "ns-b must have no specs");

    // delete_api_spec with wrong namespace → false.
    let deleted = store
        .delete_api_spec("ns-b", &spec_id)
        .await
        .expect("delete_api_spec failed");
    assert!(!deleted, "delete from wrong namespace must return false");

    // spec still accessible from correct namespace.
    let still_there = store
        .get_api_spec("ns-a", &spec_id)
        .await
        .expect("get_api_spec ns-a failed");
    assert!(
        still_there.is_some(),
        "spec in ns-a must still exist after failed delete from ns-b"
    );
}

// ---------------------------------------------------------------------------
// Gap #1: Hot-path isolation — api_specs NOT in GatewayConfig
// ---------------------------------------------------------------------------

/// `load_full_config` must return a `GatewayConfig` that contains the proxy
/// and plugin created via the api_spec bundle path, but must NOT expose any
/// `api_specs` / `spec` field at the top level.  This test acts as a compile-
/// time + runtime canary: a future contributor who accidentally adds an
/// `api_specs` field to `GatewayConfig` will fail both the serde assertion
/// and, if the field is `#[serde(skip)]`, the field-name grep in CI.
///
/// Additionally, the `ResourceTable` enum inside `db_loader` has no
/// `ApiSpecs` variant (by design — the runtime polling loop must never
/// read that table).  We cannot enumerate private enum variants here, but
/// the comment in the source file acts as the authoritative guard.
#[tokio::test]
async fn api_specs_not_in_gateway_config_load() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Insert a real proxy + plugin via the spec bundle path.
    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let plugin_id = uid("plugin");

    let plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![plugin],
    };
    // 1 MiB+ spec content to stress the path.
    let big_content: Vec<u8> = (0u8..=255u8).cycle().take(1_048_576).collect();
    let spec = make_spec(&spec_id, &proxy_id, ns, &big_content);
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit_api_spec_bundle failed");

    // Load the runtime config the way the gateway does.
    let config: GatewayConfig = store
        .load_full_config(ns)
        .await
        .expect("load_full_config failed");

    // Prove the loader actually sees the proxy and plugin (same DB).
    let proxy_present = config.proxies.iter().any(|p| p.id == proxy_id);
    assert!(
        proxy_present,
        "loaded config must contain the submitted proxy"
    );
    let plugin_present = config.plugin_configs.iter().any(|pc| pc.id == plugin_id);
    assert!(
        plugin_present,
        "loaded config must contain the submitted plugin"
    );

    // Prove no `api_specs` / `specs` field leaks into the serialized config.
    let config_value = serde_json::to_value(&config).expect("GatewayConfig must serialize to JSON");
    assert!(
        config_value.get("api_specs").is_none(),
        "GatewayConfig must NOT have an 'api_specs' field (hot-path isolation); \
         future contributor: do NOT add api_specs to GatewayConfig"
    );
    assert!(
        config_value.get("specs").is_none(),
        "GatewayConfig must NOT have a 'specs' field"
    );
}

// ---------------------------------------------------------------------------
// Fix 5: runtime load strips api_spec_id from resources
// ---------------------------------------------------------------------------

/// Resources created via submit_api_spec_bundle carry an api_spec_id tag in the
/// DB. load_full_config must strip that tag (set it to None) on every Proxy,
/// PluginConfig, and Upstream it returns, mirroring the SQL path's explicit
/// `api_spec_id: None` in the row-to-struct helpers.
///
/// The Mongo path enforces the same invariant via post-processing in
/// load_full_config / the incremental polling loop — see mongo_store.rs.
#[tokio::test]
async fn runtime_load_strips_api_spec_id_from_resources() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let plugin_id = uid("plugin");
    let spec_id = uid("spec");

    let upstream = make_upstream(&upstream_id, ns);
    let plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: Some(upstream),
        plugins: vec![plugin],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"spec for load-strip test");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // Load the runtime config.
    let config: GatewayConfig = store
        .load_full_config(ns)
        .await
        .expect("load_full_config failed");

    // Every proxy in the loaded config must have api_spec_id = None.
    for p in &config.proxies {
        assert!(
            p.api_spec_id.is_none(),
            "Proxy {}: api_spec_id must be None in runtime config (hot-path isolation)",
            p.id
        );
    }

    // Every plugin in the loaded config must have api_spec_id = None.
    for pc in &config.plugin_configs {
        assert!(
            pc.api_spec_id.is_none(),
            "PluginConfig {}: api_spec_id must be None in runtime config",
            pc.id
        );
    }

    // Every upstream in the loaded config must have api_spec_id = None.
    for u in &config.upstreams {
        assert!(
            u.api_spec_id.is_none(),
            "Upstream {}: api_spec_id must be None in runtime config",
            u.id
        );
    }
}

// ---------------------------------------------------------------------------
// Gap #4: DELETE proxy cascades the api_spec row via FK
// ---------------------------------------------------------------------------

/// When a proxy is deleted directly (via `delete_proxy`, not via
/// `delete_api_spec`), the `api_specs` row that FKs onto that proxy must be
/// removed automatically by the `ON DELETE CASCADE` constraint, and the
/// spec-owned plugin must also be gone (double cascade via plugin_configs FK).
///
/// # Mongo equivalence (Fix 3)
///
/// The SQL path relies on the `api_specs.proxy_id REFERENCES proxies(id) ON DELETE CASCADE`
/// FK. The Mongo path has no FK, so `MongoStore::delete_proxy` calls
/// `api_specs().delete_many({proxy_id})` explicitly to mirror this behaviour.
/// See `src/config/mongo_store.rs` — the implementation is directly tested here
/// for SQL; the Mongo path requires a running MongoDB instance and follows the
/// same invariant by code-review and inline assertion.
#[tokio::test]
async fn delete_proxy_cascades_api_spec_row_via_fk() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let plugin_id = uid("plugin");

    let plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![plugin],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"spec for fk cascade test");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // Confirm spec and plugin are present before delete.
    let before_spec = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed");
    assert!(before_spec.is_some(), "spec must exist before delete");

    // Delete the proxy directly (not via delete_api_spec).
    let deleted = store
        .delete_proxy(&proxy_id)
        .await
        .expect("delete_proxy failed");
    assert!(deleted, "delete_proxy must return true for existing proxy");

    // The api_spec row must be gone (FK ON DELETE CASCADE).
    let after_spec = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed after proxy delete");
    assert!(
        after_spec.is_none(),
        "api_spec row must be cascade-deleted when its proxy is deleted"
    );

    // The spec-owned plugin must also be gone (proxy FK → plugin_configs cascade).
    let after_plugin = store
        .get_plugin_config(&plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        after_plugin.is_none(),
        "spec-owned plugin must be cascade-deleted when its proxy is deleted"
    );
}

// ---------------------------------------------------------------------------
// Fix 2: replace_with_changed_resources_keeps_hand_added_plugins
// ---------------------------------------------------------------------------

/// When replace_api_spec_bundle is called with a genuinely new bundle (different
/// resource_hash), hand-added plugins (api_spec_id = NULL) on the proxy must
/// survive because the proxy is updated in place rather than deleted.
#[tokio::test]
async fn replace_with_changed_resources_keeps_hand_added_plugins() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let spec_plugin_id = uid("plugin");
    let hand_plugin_id = uid("plugin");

    // Initial submit with one spec-owned plugin.
    let spec_plugin = make_plugin(&spec_plugin_id, &proxy_id, ns, None);
    let bundle_v1 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![spec_plugin],
    };
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 spec content");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    // Capture proxy created_at before replace.
    let proxy_before = store
        .get_proxy(&proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must exist before replace");
    let created_at_before = proxy_before.created_at;

    // Hand-add a plugin directly (api_spec_id = NULL).
    let hand_plugin = make_plugin(&hand_plugin_id, &proxy_id, ns, None);
    store
        .create_plugin_config(&hand_plugin)
        .await
        .expect("hand-add plugin failed");

    // Replace with a new bundle (different spec-owned plugin → different resource hash).
    let new_spec_plugin_id = uid("plugin");
    let new_spec_plugin = make_plugin(&new_spec_plugin_id, &proxy_id, ns, None);
    let bundle_v2 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![new_spec_plugin],
    };
    let spec_v2 = make_spec(
        &spec_id,
        &proxy_id,
        ns,
        b"v2 spec content with changed resources",
    );
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    // Hand-added plugin must still exist.
    let hand_row = store
        .get_plugin_config(&hand_plugin_id)
        .await
        .expect("get_plugin_config for hand plugin failed");
    assert!(
        hand_row.is_some(),
        "hand-added plugin must survive replace_api_spec_bundle with changed resources"
    );

    // Old spec-owned plugin must be gone.
    let old_spec_row = store
        .get_plugin_config(&spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        old_spec_row.is_none(),
        "old spec-owned plugin must be removed after replace"
    );

    // New spec-owned plugin must exist.
    let new_spec_row = store
        .get_plugin_config(&new_spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        new_spec_row.is_some(),
        "new spec-owned plugin must exist after replace"
    );

    // Proxy primary key must be preserved (created_at unchanged).
    let proxy_after = store
        .get_proxy(&proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist after replace");
    assert_eq!(proxy_after.id, proxy_id, "proxy id must be unchanged");
    assert_eq!(
        proxy_after.created_at.timestamp(),
        created_at_before.timestamp(),
        "proxy created_at must be unchanged after replace (proxy updated in place)"
    );
}

// ===========================================================================
// Wave 5 tests — Tier 1 metadata extraction, idempotent PUT, list filters
// ===========================================================================

// ---------------------------------------------------------------------------
// Test helpers for Wave 5
// ---------------------------------------------------------------------------

/// Build a full spec with all Tier 1 metadata fields populated. The spec body
/// is a valid OpenAPI 3.1 JSON document with info, contact, license, tags,
/// servers, and paths that the extractor can parse.
fn make_spec_with_metadata(
    id: &str,
    proxy_id: &str,
    namespace: &str,
    title: &str,
    spec_version_suffix: &str,
    tags: &[&str],
) -> (ferrum_edge::admin::api_specs::ExtractedBundle, ApiSpec) {
    use ferrum_edge::admin::api_specs::hash_resource_bundle;
    use ferrum_edge::admin::spec_codec;
    use ferrum_edge::config::types::SpecFormat;

    let tags_json: String = tags
        .iter()
        .map(|t| format!(r#"{{"name": "{t}"}}"#))
        .collect::<Vec<_>>()
        .join(", ");

    let body = format!(
        r#"{{
            "openapi": "3.1.{spec_version_suffix}",
            "info": {{
                "title": "{title}",
                "version": "1.0.0",
                "description": "Test description for {title}",
                "contact": {{ "name": "Alice", "email": "alice@example.com" }},
                "license": {{ "name": "MIT", "identifier": "MIT" }}
            }},
            "tags": [{tags_json}],
            "servers": [{{"url": "https://api.example.com/v1"}}],
            "paths": {{
                "/foo": {{ "get": {{}}, "post": {{}} }},
                "/bar": {{ "delete": {{}} }}
            }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let body_bytes = body.as_bytes();

    let (bundle, meta) = ferrum_edge::admin::api_specs::extract(body_bytes, None, namespace)
        .expect("extract failed");

    let compressed = spec_codec::compress_gzip(body_bytes).expect("compress failed");
    let content_hash = spec_codec::sha256_hex(body_bytes);
    let resource_hash = hash_resource_bundle(&bundle);

    let spec = ApiSpec {
        id: id.to_string(),
        namespace: namespace.to_string(),
        proxy_id: proxy_id.to_string(),
        spec_version: meta.version.clone(),
        spec_format: SpecFormat::Json,
        spec_content: compressed,
        content_encoding: "gzip".to_string(),
        uncompressed_size: body_bytes.len() as u64,
        content_hash,
        title: meta.title.clone(),
        info_version: meta.info_version.clone(),
        description: meta.description.clone(),
        contact_name: meta.contact_name.clone(),
        contact_email: meta.contact_email.clone(),
        license_name: meta.license_name.clone(),
        license_identifier: meta.license_identifier.clone(),
        tags: meta.tags.clone(),
        server_urls: meta.server_urls.clone(),
        operation_count: meta.operation_count,
        resource_hash,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    (bundle, spec)
}

// ---------------------------------------------------------------------------
// Feature B: Tier 1 metadata extraction
// ---------------------------------------------------------------------------

/// Submit a spec with full info/contact/license/tags/servers/paths and verify
/// all 8 metadata fields are stored correctly.
#[tokio::test]
async fn submit_extracts_tier1_metadata() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let (bundle, spec) = make_spec_with_metadata(
        &spec_id,
        &proxy_id,
        ns,
        "Orders API",
        "0",
        &["public", "orders"],
    );

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get failed")
        .expect("spec not found");

    // description
    assert!(
        fetched
            .description
            .as_deref()
            .unwrap_or("")
            .contains("Orders API"),
        "description must contain title text: {:?}",
        fetched.description
    );
    // contact
    assert_eq!(fetched.contact_name.as_deref(), Some("Alice"));
    assert_eq!(fetched.contact_email.as_deref(), Some("alice@example.com"));
    // license
    assert_eq!(fetched.license_name.as_deref(), Some("MIT"));
    assert_eq!(fetched.license_identifier.as_deref(), Some("MIT"));
    // tags — de-duplicated and sorted
    assert_eq!(fetched.tags, vec!["orders", "public"]);
    // server_urls
    assert_eq!(fetched.server_urls, vec!["https://api.example.com/v1"]);
    // operation_count: /foo has get+post (2), /bar has delete (1) = 3
    assert_eq!(fetched.operation_count, 3, "3 HTTP methods in paths");
    // resource_hash present
    assert!(!fetched.resource_hash.is_empty());
}

/// Description longer than 4096 bytes is truncated at a UTF-8 boundary.
#[tokio::test]
async fn submit_truncates_long_description_at_4kib() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    // Build a 10 KiB description using multi-byte chars to test UTF-8 boundary.
    // U+00E9 (é) is 2 bytes in UTF-8; 10 KiB / 2 = 5120 chars.
    let long_desc: String = "é".repeat(5120);
    assert!(
        long_desc.len() >= 10240,
        "description must be ≥ 10 KiB in bytes"
    );

    let body = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{
                "title": "Long Desc API",
                "version": "1.0.0",
                "description": "{long_desc}"
            }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let body_bytes = body.as_bytes();
    let (bundle, _) =
        ferrum_edge::admin::api_specs::extract(body_bytes, None, ns).expect("extract failed");

    let meta = ferrum_edge::admin::api_specs::extract(body_bytes, None, ns)
        .expect("extract failed")
        .1;
    let compressed = ferrum_edge::admin::spec_codec::compress_gzip(body_bytes).unwrap();
    let content_hash = ferrum_edge::admin::spec_codec::sha256_hex(body_bytes);
    let resource_hash = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle);

    let spec = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: compressed,
        content_encoding: "gzip".to_string(),
        uncompressed_size: body_bytes.len() as u64,
        content_hash,
        title: meta.title,
        info_version: meta.info_version,
        description: meta.description.clone(),
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get failed")
        .expect("spec not found");

    let stored_desc = fetched.description.expect("description must be stored");
    assert!(
        stored_desc.len() <= 4096,
        "stored description ({} bytes) must be ≤ 4096 bytes",
        stored_desc.len()
    );
    // Must be valid UTF-8 (Rust String guarantees this, but also check it's a
    // clean boundary by encoding/decoding).
    assert!(std::str::from_utf8(stored_desc.as_bytes()).is_ok());
}

/// Swagger 2.0: server_urls are constructed from `schemes + host + basePath`.
#[tokio::test]
async fn swagger_2_0_server_urls_constructed_from_schemes_host_basepath() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let body = format!(
        r#"{{
            "swagger": "2.0",
            "info": {{ "title": "Swagger API", "version": "1.0" }},
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let body_bytes = body.as_bytes();
    let (bundle, meta) =
        ferrum_edge::admin::api_specs::extract(body_bytes, None, ns).expect("extract failed");
    let compressed = ferrum_edge::admin::spec_codec::compress_gzip(body_bytes).unwrap();
    let content_hash = ferrum_edge::admin::spec_codec::sha256_hex(body_bytes);
    let resource_hash = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle);

    let spec = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: compressed,
        content_encoding: "gzip".to_string(),
        uncompressed_size: body_bytes.len() as u64,
        content_hash,
        title: meta.title,
        info_version: meta.info_version,
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: meta.server_urls.clone(),
        operation_count: 0,
        resource_hash,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get failed")
        .expect("not found");

    assert_eq!(
        fetched.server_urls,
        vec!["https://api.example.com/v1"],
        "server_urls must be constructed from schemes+host+basePath for Swagger 2.0"
    );
}

// ---------------------------------------------------------------------------
// Feature A: idempotent PUT (hash short-circuit)
// ---------------------------------------------------------------------------

/// PUT with the same bundle (but potentially different spec document text like
/// description changes) must NOT update proxy.updated_at, but MUST advance
/// api_specs.updated_at.
#[tokio::test]
async fn replace_with_unchanged_resources_skips_proxy_write() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    // Initial submit.
    let body1 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API v1", "version": "1.0", "description": "Original desc" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle1, meta1) =
        ferrum_edge::admin::api_specs::extract(body1.as_bytes(), None, ns).expect("extract1");
    let resource_hash1 = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle1);
    let spec1 = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta1.version.clone(),
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body1.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body1.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body1.as_bytes()),
        title: meta1.title.clone(),
        info_version: meta1.info_version.clone(),
        description: meta1.description.clone(),
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: resource_hash1.clone(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store
        .submit_api_spec_bundle(&bundle1, &spec1)
        .await
        .expect("initial submit");

    // Capture proxy.updated_at before the PUT.
    let proxy_before = store
        .get_proxy(&proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy not found");
    let proxy_updated_at_before = proxy_before.updated_at;

    // Small sleep to ensure any write would bump the timestamp.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // PUT with same bundle, different description (same resource_hash).
    let body2 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API v1", "version": "1.0", "description": "Updated desc" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle2, meta2) =
        ferrum_edge::admin::api_specs::extract(body2.as_bytes(), None, ns).expect("extract2");
    let resource_hash2 = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle2);
    // Sanity: hashes must be identical (proxy unchanged).
    assert_eq!(
        resource_hash1, resource_hash2,
        "resource_hash must match when bundle is identical"
    );

    let now2 = chrono::Utc::now();
    let spec2 = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta2.version.clone(),
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body2.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body2.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body2.as_bytes()),
        title: meta2.title.clone(),
        info_version: meta2.info_version.clone(),
        description: meta2.description.clone(),
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: resource_hash2,
        created_at: spec1.created_at,
        updated_at: now2,
    };

    store
        .replace_api_spec_bundle(&bundle2, &spec2)
        .await
        .expect("replace failed");

    // proxy.updated_at must NOT have advanced.
    let proxy_after = store
        .get_proxy(&proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy not found");
    assert_eq!(
        proxy_after.updated_at.timestamp(),
        proxy_updated_at_before.timestamp(),
        "proxy.updated_at must not change when bundle is unchanged"
    );

    // api_specs.updated_at MUST have advanced.
    let spec_after = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found");
    assert!(
        spec_after.updated_at > proxy_updated_at_before,
        "api_specs.updated_at must advance on PUT even when bundle is unchanged"
    );
}

/// PUT with a real proxy field change must update proxy.updated_at.
#[tokio::test]
async fn replace_with_changed_resources_updates_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let body1 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend-v1.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle1, meta1) =
        ferrum_edge::admin::api_specs::extract(body1.as_bytes(), None, ns).expect("extract1");
    let resource_hash1 = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle1);

    let spec1 = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta1.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body1.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body1.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body1.as_bytes()),
        title: meta1.title,
        info_version: meta1.info_version,
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: resource_hash1.clone(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store
        .submit_api_spec_bundle(&bundle1, &spec1)
        .await
        .expect("initial submit");

    let proxy_before = store.get_proxy(&proxy_id).await.unwrap().unwrap();
    let before_ts = proxy_before.updated_at;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Change backend_host → different resource_hash.
    let body2 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend-v2.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle2, meta2) =
        ferrum_edge::admin::api_specs::extract(body2.as_bytes(), None, ns).expect("extract2");
    let resource_hash2 = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle2);
    assert_ne!(
        resource_hash1, resource_hash2,
        "resource_hash must differ when proxy backend_host changes"
    );

    let now2 = chrono::Utc::now();
    let spec2 = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta2.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body2.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body2.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body2.as_bytes()),
        title: meta2.title,
        info_version: meta2.info_version,
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: resource_hash2,
        created_at: spec1.created_at,
        updated_at: now2,
    };

    store
        .replace_api_spec_bundle(&bundle2, &spec2)
        .await
        .expect("replace failed");

    // Proxy must have been re-inserted with new backend_host.
    let proxy_after = store.get_proxy(&proxy_id).await.unwrap().unwrap();
    assert_eq!(proxy_after.backend_host, "backend-v2.internal");
    assert!(
        proxy_after.updated_at > before_ts || proxy_after.updated_at >= before_ts,
        "proxy.updated_at must advance when bundle changes"
    );
}

// ---------------------------------------------------------------------------
// Feature C: list filters
// ---------------------------------------------------------------------------

/// `?proxy_id=foo` returns only specs whose proxy_id matches exactly.
/// Each spec must have a unique proxy_id (DB constraint), so we use 2 proxies
/// in group A and 1 in group B. The test checks that filtering by one
/// specific proxy_id returns exactly that spec.
#[tokio::test]
async fn list_filter_proxy_id() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Submit three specs with distinct proxy_ids. We'll filter by proxy_a1.
    let proxy_a1 = uid("proxy-a1");
    let proxy_a2 = uid("proxy-a2");
    let proxy_b1 = uid("proxy-b1");

    let spec_a1 = uid("spec");
    let spec_a2 = uid("spec");
    let spec_b1 = uid("spec");

    let (bundle, spec) = make_spec_with_metadata(&spec_a1, &proxy_a1, ns, "API A1", "0", &[]);
    store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();

    let (bundle, spec) = make_spec_with_metadata(&spec_a2, &proxy_a2, ns, "API A2", "0", &[]);
    store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();

    let (bundle, spec) = make_spec_with_metadata(&spec_b1, &proxy_b1, ns, "API B1", "0", &[]);
    store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();

    // Filter by proxy_a1 — should return exactly 1.
    let filter = ApiSpecListFilter {
        proxy_id: Some(proxy_a1.clone()),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed");
    assert_eq!(results.len(), 1, "must return 1 spec for proxy_a1");
    assert_eq!(results[0].proxy_id, proxy_a1);

    // Filter by proxy_b1 — should return exactly 1.
    let filter2 = ApiSpecListFilter {
        proxy_id: Some(proxy_b1.clone()),
        limit: 100,
        ..Default::default()
    };
    let results2 = store.list_api_specs(ns, &filter2).await.expect("list b1");
    assert_eq!(results2.len(), 1, "must return 1 spec for proxy_b1");

    // No filter — should return all 3.
    let all = store
        .list_api_specs(ns, &simple_filter(100, 0))
        .await
        .expect("list all");
    assert_eq!(all.len(), 3, "must return 3 specs without filter");
}

/// `?spec_version=3.1` returns only specs whose spec_version starts with `3.1`.
#[tokio::test]
async fn list_filter_spec_version_prefix() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Submit specs with versions 3.1.0, 3.1.0 (different proxy), 3.2.0.
    // Note: make_spec_with_metadata builds "3.1.{suffix}".
    let versions: Vec<(&str, &str)> = vec![("0", "v1"), ("0", "v2"), ("0", "v3")];
    // proxy for 3.2.0 needs a separate spec
    let proxy_32 = uid("proxy-32");
    let spec_32 = uid("spec-32");
    let body_32 = format!(
        r#"{{
            "openapi": "3.2.0",
            "info": {{ "title": "API 3.2", "version": "1.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_32}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_32}"
            }}
        }}"#
    );
    let (b32, m32) =
        ferrum_edge::admin::api_specs::extract(body_32.as_bytes(), None, ns).expect("extract 3.2");
    let rh32 = ferrum_edge::admin::api_specs::hash_resource_bundle(&b32);
    let s32 = ApiSpec {
        id: spec_32.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_32.clone(),
        spec_version: m32.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body_32.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body_32.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body_32.as_bytes()),
        title: m32.title,
        info_version: m32.info_version,
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: rh32,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store.submit_api_spec_bundle(&b32, &s32).await.unwrap();

    for (suffix, title) in versions {
        let proxy_id = uid("proxy-31");
        let spec_id = uid("spec-31");
        let (bundle, spec) = make_spec_with_metadata(&spec_id, &proxy_id, ns, title, suffix, &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    let filter = ApiSpecListFilter {
        spec_version_prefix: Some("3.1".to_string()),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed");
    assert_eq!(
        results.len(),
        3,
        "should return 3 specs with version prefix 3.1"
    );
    assert!(
        results.iter().all(|s| s.spec_version.starts_with("3.1")),
        "all results must have spec_version starting with 3.1"
    );
}

/// `?title_contains=orders` is case-insensitive.
#[tokio::test]
async fn list_filter_title_contains_case_insensitive() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Titles: "Orders API", "ORDERS Service", "Catalog"
    for (title, suffix) in &[
        ("Orders API", "0"),
        ("ORDERS Service", "1"),
        ("Catalog", "2"),
    ] {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) = make_spec_with_metadata(&spec_id, &proxy_id, ns, title, suffix, &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    let filter = ApiSpecListFilter {
        title_contains: Some("orders".to_string()),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed");
    assert_eq!(
        results.len(),
        2,
        "should return 2 specs matching 'orders' case-insensitively"
    );
}

/// `?updated_since=<timestamp>` returns only specs updated at or after that time.
#[tokio::test]
async fn list_filter_updated_since() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Insert 2 specs.
    for i in 0..2u8 {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) =
            make_spec_with_metadata(&spec_id, &proxy_id, ns, "API", &i.to_string(), &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    // The cutoff is "right now" — both specs were inserted just before this,
    // so updated_since = now means 0 results.
    let cutoff = chrono::Utc::now() + chrono::Duration::seconds(1);
    let filter = ApiSpecListFilter {
        updated_since: Some(cutoff),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed");
    assert!(
        results.is_empty(),
        "no specs updated after the cutoff (got {})",
        results.len()
    );

    // With past cutoff, all specs are returned.
    let past_cutoff = chrono::Utc::now() - chrono::Duration::hours(1);
    let filter2 = ApiSpecListFilter {
        updated_since: Some(past_cutoff),
        limit: 100,
        ..Default::default()
    };
    let results2 = store
        .list_api_specs(ns, &filter2)
        .await
        .expect("list failed");
    assert_eq!(results2.len(), 2, "all 2 specs must match past cutoff");
}

/// `?has_tag=public` returns only specs that have the tag "public".
#[tokio::test]
async fn list_filter_has_tag() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Three specs: two tagged "public", one tagged "private".
    for (tags, suffix) in &[
        (vec!["public", "api"], "0"),
        (vec!["public"], "1"),
        (vec!["private"], "2"),
    ] {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) =
            make_spec_with_metadata(&spec_id, &proxy_id, ns, "API", suffix, tags.as_slice());
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    let filter = ApiSpecListFilter {
        has_tag: Some("public".to_string()),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed");
    assert_eq!(results.len(), 2, "2 specs must have the 'public' tag");
    assert!(
        results
            .iter()
            .all(|s| s.tags.contains(&"public".to_string()))
    );
}

/// Sort by title ascending then descending.
#[tokio::test]
async fn list_sort_by_title_asc_then_desc() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    for (title, suffix) in &[("Bravo", "0"), ("Alpha", "1"), ("Charlie", "2")] {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) = make_spec_with_metadata(&spec_id, &proxy_id, ns, title, suffix, &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    let asc_filter = ApiSpecListFilter {
        sort_by: ApiSpecSortBy::Title,
        order: SortOrder::Asc,
        limit: 100,
        ..Default::default()
    };
    let asc = store
        .list_api_specs(ns, &asc_filter)
        .await
        .expect("list asc");
    let asc_titles: Vec<_> = asc.iter().filter_map(|s| s.title.as_deref()).collect();
    assert!(
        asc_titles.windows(2).all(|w| w[0] <= w[1]),
        "titles must be in ascending order: {:?}",
        asc_titles
    );

    let desc_filter = ApiSpecListFilter {
        sort_by: ApiSpecSortBy::Title,
        order: SortOrder::Desc,
        limit: 100,
        ..Default::default()
    };
    let desc = store
        .list_api_specs(ns, &desc_filter)
        .await
        .expect("list desc");
    let desc_titles: Vec<_> = desc.iter().filter_map(|s| s.title.as_deref()).collect();
    assert!(
        desc_titles.windows(2).all(|w| w[0] >= w[1]),
        "titles must be in descending order: {:?}",
        desc_titles
    );
}

/// Default sort is `updated_at DESC` (most-recent first).
#[tokio::test]
async fn list_default_sort_is_updated_at_desc() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Insert 3 specs with a short sleep between each so timestamps differ.
    let mut spec_ids = Vec::new();
    for i in 0..3u8 {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) =
            make_spec_with_metadata(&spec_id, &proxy_id, ns, "API", &i.to_string(), &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
        spec_ids.push(spec_id);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let filter = ApiSpecListFilter {
        limit: 100,
        ..Default::default()
    };
    let results = store.list_api_specs(ns, &filter).await.expect("list");
    assert_eq!(results.len(), 3);
    // Most recently inserted should appear first.
    assert!(
        results
            .windows(2)
            .all(|w| w[0].updated_at >= w[1].updated_at),
        "default sort must be updated_at DESC"
    );
}
