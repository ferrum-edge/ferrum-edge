//! Ownership recovery from an already admitted spec document must not re-run
//! the strict (1.0-closed) `PluginAssociation` decode: a stored document that
//! predates the closed schema may carry an extra association member, and a
//! `PUT /api-specs/{id}` that removes it must still be able to read the IDs
//! the old document declared.

use ferrum_edge::admin::api_specs::{SpecFormat, extract_declared_proxy_plugin_association_ids};
use serde_json::json;

fn spec_with_plugins(plugins: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "openapi": "3.0.3",
        "info": {"title": "t", "version": "1"},
        "paths": {},
        "x-ferrum-proxy": {
            "id": "p1",
            "listen_path": "/t",
            "backend_host": "backend.example",
            "backend_port": 8080,
            "plugins": plugins
        }
    }))
    .expect("serializes")
}

#[test]
fn stored_association_with_historical_extra_member_still_yields_its_id() {
    let body = spec_with_plugins(json!([
        {"plugin_config_id": "cors-1", "future_metadata": {"owner": "retained"}},
        {"plugin_config_id": "auth-1"},
        {"plugin_config_id": "cors-1"}
    ]));
    let ids = extract_declared_proxy_plugin_association_ids(&body, Some(SpecFormat::Json))
        .expect("a historical extra member must not block ownership recovery");
    assert_eq!(ids, vec!["cors-1".to_string(), "auth-1".to_string()]);
}

#[test]
fn stored_association_shape_is_still_validated() {
    for (plugins, why) in [
        (
            json!({"plugin_config_id": "cors-1"}),
            "plugins must be an array",
        ),
        (json!(["cors-1"]), "each association must be an object"),
        (json!([{"plugin_confg_id": "cors-1"}]), "the ID is required"),
        (json!([{"plugin_config_id": 7}]), "the ID must be a string"),
    ] {
        let body = spec_with_plugins(plugins);
        assert!(
            extract_declared_proxy_plugin_association_ids(&body, Some(SpecFormat::Json)).is_err(),
            "{why}"
        );
    }
}
