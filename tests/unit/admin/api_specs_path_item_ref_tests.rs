//! Path Item Object `$ref` resolution for API-spec import.
//!
//! Covers issue #2333: the importer must resolve local Path Item references
//! before enumerating HTTP methods for `openapi_validator` generation. External
//! Path Item refs remain rejected; sibling Path Item fields overlay the
//! referenced object; cycles and depth limits fail closed.

use ferrum_edge::admin::api_specs::{ExtractError, SpecFormat, extract};
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, openapi_validator::OpenapiValidator,
};
use serde_json::{Value, json};
use std::collections::HashMap;

fn proxy_block() -> &'static str {
    r#"{
    "id": "path-item-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  }"#
}

fn extract_validator_config(spec: &str) -> Value {
    let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect("spec extraction must succeed");
    let plugin = bundle
        .plugins
        .iter()
        .find(|plugin| plugin.plugin_name == "openapi_validator")
        .expect("generated openapi_validator plugin must be present");
    plugin.config.clone()
}

fn extract_err(spec: &str) -> ExtractError {
    extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").expect_err("spec extraction must fail")
}

fn operation_keys(config: &Value) -> Vec<(String, String)> {
    config["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .map(|op| {
            (
                op["method"].as_str().unwrap().to_string(),
                op["path_template"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn fully_referenced_path_item_contributes_operations() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Pets API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "pathItems": {{
      "Pets": {{
        "get": {{
          "responses": {{
            "200": {{
              "description": "ok",
              "content": {{
                "application/json": {{
                  "schema": {{
                    "type": "object",
                    "required": ["ok"],
                    "properties": {{"ok": {{"type": "boolean"}}}}
                  }}
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }},
  "paths": {{
    "/pets": {{"$ref": "#/components/pathItems/Pets"}}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        operation_keys(&config),
        vec![("GET".to_string(), "/pets".to_string())]
    );
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["ok"])
    );

    // Admission: generated config must construct a runtime validator.
    OpenapiValidator::new(&config).expect("referenced Path Item must admit");
}

#[test]
fn mixed_referenced_and_inline_paths_are_both_extracted() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Mixed API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "pathItems": {{
      "Pets": {{
        "get": {{
          "responses": {{"200": {{"description": "ok"}}}}
        }}
      }}
    }}
  }},
  "paths": {{
    "/pets": {{"$ref": "#/components/pathItems/Pets"}},
    "/health": {{
      "get": {{
        "responses": {{"200": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let mut keys = operation_keys(&config);
    keys.sort();
    assert_eq!(
        keys,
        vec![
            ("GET".to_string(), "/health".to_string()),
            ("GET".to_string(), "/pets".to_string()),
        ]
    );
    OpenapiValidator::new(&config).expect("mixed Path Item refs must admit");
}

#[test]
fn path_item_ref_siblings_override_referenced_fields() {
    // OAS leaves Path Item `$ref` sibling conflicts undefined; Ferrum overlays
    // sibling fields onto the referenced Path Item (sibling wins).
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Sibling Overlay API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "pathItems": {{
      "Pets": {{
        "get": {{
          "responses": {{"200": {{"description": "from-ref"}}}}
        }},
        "post": {{
          "responses": {{"201": {{"description": "create"}}}}
        }}
      }}
    }}
  }},
  "paths": {{
    "/pets": {{
      "$ref": "#/components/pathItems/Pets",
      "get": {{
        "responses": {{
          "200": {{
            "description": "sibling-wins",
            "content": {{
              "application/json": {{
                "schema": {{
                  "type": "object",
                  "required": ["from_sibling"],
                  "properties": {{"from_sibling": {{"type": "string"}}}}
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let mut keys = operation_keys(&config);
    keys.sort();
    assert_eq!(
        keys,
        vec![
            ("GET".to_string(), "/pets".to_string()),
            ("POST".to_string(), "/pets".to_string()),
        ]
    );
    let get_op = config["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["method"] == "GET")
        .expect("GET operation");
    assert_eq!(
        get_op["responses"]["200"]["application/json"]["required"],
        json!(["from_sibling"])
    );
}

#[test]
fn unresolved_path_item_ref_is_rejected() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Missing Path Item", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{"$ref": "#/components/pathItems/Missing"}}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::SchemaReference(_)),
        "unresolved Path Item ref must fail closed as SchemaReference: {err}"
    );
}

#[test]
fn external_path_item_ref_is_rejected() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "External Path Item", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{"$ref": "https://example.com/openapi.json#/paths/~1pets"}}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::UnsupportedExternalRef { .. }),
        "external Path Item ref must remain UnsupportedExternalRef: {err}"
    );
}

#[test]
fn cyclic_path_item_refs_are_rejected() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Cyclic Path Items", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "pathItems": {{
      "A": {{"$ref": "#/components/pathItems/B"}},
      "B": {{"$ref": "#/components/pathItems/A"}}
    }}
  }},
  "paths": {{
    "/pets": {{"$ref": "#/components/pathItems/A"}}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    // Mutual Path Item cycles are rejected on re-entry (GHSA-8jc7-c52g-85xr),
    // not after the depth ceiling has expanded every sibling branch first.
    let ExtractError::SchemaReferenceCycle { path } = &err else {
        panic!("cyclic Path Item refs must fail as SchemaReferenceCycle: {err}");
    };
    assert!(
        path.contains("#/components/pathItems/A") && path.contains("#/components/pathItems/B"),
        "cycle path must name both references in the loop: {path}"
    );
}

#[test]
fn deep_path_item_ref_chain_hits_depth_limit() {
    // Build a chain longer than MAX_SCHEMA_REF_DEPTH (32) so resolution fails
    // closed instead of expanding indefinitely.
    let mut path_items = String::from("{\n");
    for i in 0..40 {
        let next = i + 1;
        path_items.push_str(&format!(
            r##"  "P{i}": {{"$ref": "#/components/pathItems/P{next}"}}"##
        ));
        if i < 39 {
            path_items.push(',');
        }
        path_items.push('\n');
    }
    path_items.push_str(
        r#"  ,"P40": {"get": {"responses": {"200": {"description": "ok"}}}}
}"#,
    );

    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Deep Path Items", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "pathItems": {path_items}
  }},
  "paths": {{
    "/deep": {{"$ref": "#/components/pathItems/P0"}}
  }}
}}"##,
        proxy = proxy_block(),
        path_items = path_items
    );

    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::SchemaTooDeep { .. }),
        "deep Path Item ref chains must fail as SchemaTooDeep: {err}"
    );
}

#[test]
fn openapi_30_path_item_ref_to_another_path_resolves() {
    // OpenAPI 3.0 has Path Item `$ref` but not `components.pathItems`.
    let spec = format!(
        r##"{{
  "openapi": "3.0.3",
  "info": {{"title": "OAS30 Path Ref", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/shared": {{
      "get": {{
        "responses": {{"200": {{"description": "ok"}}}}
      }}
    }},
    "/alias": {{"$ref": "#/paths/~1shared"}}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let mut keys = operation_keys(&config);
    keys.sort();
    assert_eq!(
        keys,
        vec![
            ("GET".to_string(), "/alias".to_string()),
            ("GET".to_string(), "/shared".to_string()),
        ]
    );
}

#[tokio::test]
async fn referenced_path_item_matches_at_runtime() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Runtime Pets", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "pathItems": {{
      "Pets": {{
        "get": {{
          "responses": {{"200": {{"description": "ok"}}}}
        }}
      }}
    }}
  }},
  "paths": {{
    "/pets": {{"$ref": "#/components/pathItems/Pets"}}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let plugin = OpenapiValidator::new(&config).expect("admission must succeed");

    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/pets".into());
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Continue => {}
        other => panic!("GET /pets from Path Item ref must match: {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.matched_operation")
            .map(String::as_str),
        Some("GET /pets")
    );

    let mut unknown = RequestContext::new("127.0.0.1".into(), "GET".into(), "/missing".into());
    let mut unknown_headers = HashMap::new();
    match plugin
        .before_proxy(&mut unknown, &mut unknown_headers)
        .await
    {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("unknown operation must reject: {other:?}"),
    }
}

// ── OpenAPI 3.2 operation fields (issue #7201) ─────────────────────────────

fn openapi_32_spec(paths: Value, components: Value) -> String {
    let proxy: Value = serde_json::from_str(proxy_block()).expect("proxy block");
    json!({
        "openapi": "3.2.0",
        "info": {"title": "Query API", "version": "1.0.0"},
        "x-ferrum-proxy": proxy,
        "components": components,
        "paths": paths,
    })
    .to_string()
}

fn unsupported_location(error: ExtractError) -> String {
    match error {
        ExtractError::UnsupportedOperationField { location } => location,
        other => panic!("expected UnsupportedOperationField, got: {other}"),
    }
}

#[test]
fn openapi_32_query_operation_is_refused_at_import() {
    let spec = openapi_32_spec(
        json!({
            "/search": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "query": {"responses": {"200": {"description": "ok"}}}
            }
        }),
        json!({}),
    );
    assert_eq!(
        unsupported_location(extract_err(&spec)),
        "paths./search.query"
    );
}

#[test]
fn openapi_32_additional_operations_are_refused_at_import() {
    let spec = openapi_32_spec(
        json!({
            "/items": {
                "additionalOperations": {
                    "LINK": {"responses": {"200": {"description": "ok"}}}
                }
            }
        }),
        json!({}),
    );
    assert_eq!(
        unsupported_location(extract_err(&spec)),
        "paths./items.additionalOperations"
    );
}

#[test]
fn openapi_32_query_operation_in_a_referenced_path_item_is_refused() {
    let spec = openapi_32_spec(
        json!({"/search": {"$ref": "#/components/pathItems/Search"}}),
        json!({
            "pathItems": {
                "Search": {"query": {"responses": {"200": {"description": "ok"}}}}
            }
        }),
    );
    assert_eq!(
        unsupported_location(extract_err(&spec)),
        "components.pathItems.Search.query"
    );
}

#[test]
fn openapi_32_document_without_new_operation_fields_still_imports() {
    let spec = openapi_32_spec(
        json!({"/search": {"get": {"responses": {"200": {"description": "ok"}}}}}),
        json!({}),
    );
    let (_bundle, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect("a 3.2 document using only supported methods must import");
    assert_eq!(meta.version, "3.2.0");
    assert_eq!(meta.operation_count, 1);
}
