//! Backend-neutral persistence policy shared by the SQL (`db_loader`) and
//! MongoDB (`mongo_store`) config stores (`src/config/store_policy.rs`).
//!
//! These helpers used to be hand-copied into both stores. The tests pin the
//! shared policy itself, and a structural parity check fails if either store
//! grows its own copy again.

use ferrum_edge::ExtractedBundle;
use ferrum_edge::admin::api_specs::hash_resource_bundle;
use ferrum_edge::config::store_policy::{
    access_control_plugin_allows_consumer, consumer_identity_values,
    mesh_route_dispatch_referenced_upstream, mesh_route_dispatch_references_upstream_id,
    store_canonical_resource_hash,
};
use ferrum_edge::config::types::{Consumer, PluginConfig, PluginScope, Proxy};
use serde_json::{Value, json};
use std::collections::HashSet;

fn consumer(id: &str, username: &str, custom_id: Option<&str>) -> Consumer {
    Consumer {
        labels: Default::default(),
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        username: username.to_string(),
        custom_id: custom_id.map(str::to_string),
        credentials: Default::default(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn plugin(plugin_name: &str, enabled: bool, config: Value) -> PluginConfig {
    let now = chrono::Utc::now();
    PluginConfig {
        labels: Default::default(),
        id: "pc-1".to_string(),
        plugin_name: plugin_name.to_string(),
        namespace: "ferrum".to_string(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn dispatch_to(upstream_ids: &[&str]) -> Value {
    let rules: Vec<Value> = upstream_ids
        .iter()
        .map(|id| {
            json!({
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": id}
            })
        })
        .collect();
    json!({ "rules": rules })
}

fn proxy_with_hosts(hosts: &[&str], backend_host: &str) -> Proxy {
    serde_json::from_value(json!({
        "id": "spec-proxy",
        "namespace": "ferrum",
        "hosts": hosts,
        "backend_scheme": "http",
        "backend_host": backend_host,
        "backend_port": 8080
    }))
    .expect("proxy fixture")
}

// ── consumer identity keyspace ─────────────────────────────────────────────

#[test]
fn consumer_identity_values_cover_id_username_and_custom_id_sorted() {
    let values = consumer_identity_values(&consumer("c-id", "alice", Some("ext-7")));
    assert_eq!(values, vec!["alice", "c-id", "ext-7"]);
}

#[test]
fn consumer_identity_values_omit_absent_custom_id() {
    let values = consumer_identity_values(&consumer("c-id", "alice", None));
    assert_eq!(values, vec!["alice", "c-id"]);
}

#[test]
fn consumer_identity_values_dedupe_self_collisions() {
    // A consumer whose custom_id equals its own id (or username) is allowed;
    // the index must hold the value once so the consumer does not collide
    // with itself on the primary key / `_id`.
    let values = consumer_identity_values(&consumer("same", "same", Some("same")));
    assert_eq!(values, vec!["same"]);
    let values = consumer_identity_values(&consumer("c-id", "alice", Some("c-id")));
    assert_eq!(values, vec!["alice", "c-id"]);
}

// ── access_control consumer-delete refusal ─────────────────────────────────

#[test]
fn access_control_matches_allowed_consumer_byte_for_byte() {
    let config = json!({"allowed_consumers": ["alice", "bob"]});
    assert!(access_control_plugin_allows_consumer(&config, "alice"));
    assert!(access_control_plugin_allows_consumer(&config, "bob"));
    assert!(!access_control_plugin_allows_consumer(&config, "Alice"));
    assert!(!access_control_plugin_allows_consumer(&config, "alice "));
    assert!(!access_control_plugin_allows_consumer(&config, "carol"));
}

#[test]
fn access_control_ignores_non_string_entries_and_other_shapes() {
    assert!(!access_control_plugin_allows_consumer(
        &json!({"allowed_consumers": [1, null, {"username": "alice"}, ["alice"]]}),
        "alice"
    ));
    assert!(!access_control_plugin_allows_consumer(
        &json!({"allowed_consumers": "alice"}),
        "alice"
    ));
    assert!(!access_control_plugin_allows_consumer(&json!({}), "alice"));
    // Only the allow list pins a consumer; a deny-list entry does not.
    assert!(!access_control_plugin_allows_consumer(
        &json!({"disallowed_consumers": ["alice"]}),
        "alice"
    ));
}

// ── mesh_route_dispatch upstream-delete / spec-replace refusal ─────────────

#[test]
fn mesh_route_dispatch_reference_requires_enabled_parseable_dispatch_plugin() {
    let enabled = plugin("mesh_route_dispatch", true, dispatch_to(&["api"]));
    assert!(mesh_route_dispatch_references_upstream_id(&enabled, "api"));
    assert!(!mesh_route_dispatch_references_upstream_id(
        &enabled, "other"
    ));

    let disabled = plugin("mesh_route_dispatch", false, dispatch_to(&["api"]));
    assert!(!mesh_route_dispatch_references_upstream_id(
        &disabled, "api"
    ));

    let other_plugin = plugin("access_control", true, dispatch_to(&["api"]));
    assert!(!mesh_route_dispatch_references_upstream_id(
        &other_plugin,
        "api"
    ));

    let unparsable = plugin("mesh_route_dispatch", true, json!({"rules": "api"}));
    assert!(!mesh_route_dispatch_references_upstream_id(
        &unparsable,
        "api"
    ));
}

#[test]
fn mesh_route_dispatch_referenced_upstream_returns_first_spec_owned_in_rule_order() {
    let spec_upstreams: HashSet<String> = ["owned-b", "owned-a"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let plugin_config = plugin(
        "mesh_route_dispatch",
        true,
        dispatch_to(&["foreign", "owned-b", "owned-a"]),
    );
    assert_eq!(
        mesh_route_dispatch_referenced_upstream(&plugin_config, &spec_upstreams).as_deref(),
        Some("owned-b")
    );

    let unrelated = plugin("mesh_route_dispatch", true, dispatch_to(&["foreign"]));
    assert_eq!(
        mesh_route_dispatch_referenced_upstream(&unrelated, &spec_upstreams),
        None
    );
}

#[test]
fn mesh_route_dispatch_referenced_upstream_shares_the_reference_filter() {
    // Both predicates must agree on which plugin configs count as references.
    let spec_upstreams: HashSet<String> = ["api".to_string()].into_iter().collect();
    for (name, enabled, config) in [
        ("mesh_route_dispatch", true, dispatch_to(&["api"])),
        ("mesh_route_dispatch", false, dispatch_to(&["api"])),
        ("access_control", true, dispatch_to(&["api"])),
        ("mesh_route_dispatch", true, json!({"rules": "api"})),
    ] {
        let plugin_config = plugin(name, enabled, config);
        assert_eq!(
            mesh_route_dispatch_references_upstream_id(&plugin_config, "api"),
            mesh_route_dispatch_referenced_upstream(&plugin_config, &spec_upstreams).is_some(),
            "{name} enabled={enabled}"
        );
    }
}

// ── API-spec store resource hash ───────────────────────────────────────────

#[test]
fn store_canonical_resource_hash_is_invariant_under_admission_normalization() {
    let raw = ExtractedBundle {
        proxy: proxy_with_hosts(&["API.Example.COM"], "Backend.Example.COM"),
        upstream: None,
        plugins: vec![],
    };
    let normalized = ExtractedBundle {
        proxy: proxy_with_hosts(&["api.example.com"], "backend.example.com"),
        upstream: None,
        plugins: vec![],
    };

    // The raw bundle hash alone is case-sensitive...
    assert_ne!(
        hash_resource_bundle(&raw).unwrap(),
        hash_resource_bundle(&normalized).unwrap()
    );
    // ...the store hash normalizes first, so a resubmission that differs only
    // in host case matches the stored (normalized) resources.
    assert_eq!(
        store_canonical_resource_hash(&raw).unwrap(),
        store_canonical_resource_hash(&normalized).unwrap()
    );
    assert_eq!(
        store_canonical_resource_hash(&raw).unwrap(),
        hash_resource_bundle(&normalized).unwrap()
    );
}

// ── one home: neither store re-grows a private copy ────────────────────────

#[test]
fn sql_and_mongo_stores_do_not_redefine_shared_store_policy() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let shared = [
        "store_canonical_resource_hash",
        "access_control_plugin_allows_consumer",
        "mesh_route_dispatch_references_upstream_id",
        "mesh_route_dispatch_referenced_upstream",
    ];
    for store in ["src/config/db_loader.rs", "src/config/mongo_store.rs"] {
        let source = std::fs::read_to_string(root.join(store)).expect("read store source");
        for helper in shared {
            assert!(
                !source.contains(&format!("fn {helper}(")),
                "{store} redefines `{helper}`; use `config::store_policy::{helper}`"
            );
        }
    }
    // SQL uses the shared identity keyspace directly; Mongo may only wrap it
    // to take ownership of the values.
    let sql = std::fs::read_to_string(root.join("src/config/db_loader.rs")).unwrap();
    assert!(!sql.contains("fn consumer_identity_values("));
    let mongo = std::fs::read_to_string(root.join("src/config/mongo_store.rs")).unwrap();
    assert!(mongo.contains("crate::config::store_policy::consumer_identity_values(consumer)"));
}
