//! Server / `basePath` contribution to generated `openapi_validator` matchers.
//!
//! Covers issue #2332: operation `path_regex` / `path_template` must honor the
//! effective OpenAPI Server Object pathname or Swagger 2.0 `basePath`, including
//! Path Item and operation overrides, multiple servers, relative/absolute URLs,
//! and server-variable defaults. Runtime matching must accept the full inbound
//! request path (not only the raw Paths key).

use ferrum_edge::admin::api_specs::{ExtractError, SpecFormat, extract};
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, openapi_validator::OpenapiValidator,
};
use serde_json::Value;
use std::collections::HashMap;

fn proxy_block() -> &'static str {
    r#"{
    "id": "server-base-proxy",
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

fn op_templates(config: &Value) -> Vec<(String, String, String)> {
    config["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .map(|op| {
            (
                op["method"].as_str().unwrap().to_string(),
                op["path_template"].as_str().unwrap().to_string(),
                op["path_regex"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

async fn assert_matches(plugin: &OpenapiValidator, method: &str, path: &str) {
    let mut ctx = RequestContext::new("127.0.0.1".into(), method.into(), path.into());
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Continue => {}
        other => panic!("{method} {path} must match generated operation: {other:?}"),
    }
    assert!(
        ctx.metadata
            .contains_key("openapi_validator.matched_operation"),
        "{method} {path} must record matched_operation metadata"
    );
}

async fn assert_rejects_unknown(plugin: &OpenapiValidator, method: &str, path: &str) {
    let mut ctx = RequestContext::new("127.0.0.1".into(), method.into(), path.into());
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 400, "unknown operation rejects with 400");
        }
        other => panic!("{method} {path} must be rejected as unknown operation: {other:?}"),
    }
}

#[test]
fn root_server_path_prefixes_generated_matcher() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Root Server", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/v1"}}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![(
            "GET".to_string(),
            "/v1/pets".to_string(),
            "^/v1/pets$".to_string()
        )]
    );
}

#[tokio::test]
async fn root_server_path_matches_at_runtime() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Root Server Runtime", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/v1"}}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let plugin = OpenapiValidator::new(&config).expect("admission must succeed");
    assert_matches(&plugin, "GET", "/v1/pets").await;
    assert_rejects_unknown(&plugin, "GET", "/pets").await;
}

#[test]
fn path_item_servers_override_root() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Path Item Servers", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/v1"}}],
  "paths": {{
    "/pets": {{
      "servers": [{{"url": "/v2"}}],
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![(
            "GET".to_string(),
            "/v2/pets".to_string(),
            "^/v2/pets$".to_string()
        )]
    );
}

#[tokio::test]
async fn path_item_server_override_matches_at_runtime() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Path Item Runtime", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/v1"}}],
  "paths": {{
    "/pets": {{
      "servers": [{{"url": "/v2"}}],
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let plugin = OpenapiValidator::new(&config).expect("admission must succeed");
    assert_matches(&plugin, "GET", "/v2/pets").await;
    assert_rejects_unknown(&plugin, "GET", "/v1/pets").await;
}

#[test]
fn operation_servers_override_path_item_and_root() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Operation Servers", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/v1"}}],
  "paths": {{
    "/pets": {{
      "servers": [{{"url": "/v2"}}],
      "get": {{
        "servers": [{{"url": "/v3"}}],
        "responses": {{"200": {{"description": "ok"}}}}
      }},
      "post": {{
        "responses": {{"201": {{"description": "created"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let mut ops = op_templates(&config);
    ops.sort();
    assert_eq!(
        ops,
        vec![
            (
                "GET".to_string(),
                "/v3/pets".to_string(),
                "^/v3/pets$".to_string()
            ),
            (
                "POST".to_string(),
                "/v2/pets".to_string(),
                "^/v2/pets$".to_string()
            ),
        ]
    );
}

#[tokio::test]
async fn operation_server_override_matches_at_runtime() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Operation Runtime", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/v1"}}],
  "paths": {{
    "/pets": {{
      "servers": [{{"url": "/v2"}}],
      "get": {{
        "servers": [{{"url": "/v3"}}],
        "responses": {{"200": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let plugin = OpenapiValidator::new(&config).expect("admission must succeed");
    assert_matches(&plugin, "GET", "/v3/pets").await;
    assert_rejects_unknown(&plugin, "GET", "/v2/pets").await;
    assert_rejects_unknown(&plugin, "GET", "/v1/pets").await;
}

#[test]
fn swagger_base_path_prefixes_generated_matcher() {
    let spec = format!(
        r##"{{
  "swagger": "2.0",
  "info": {{"title": "Swagger Base", "version": "1.0.0"}},
  "basePath": "/v1",
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![(
            "GET".to_string(),
            "/v1/pets".to_string(),
            "^/v1/pets$".to_string()
        )]
    );
}

#[tokio::test]
async fn swagger_base_path_matches_at_runtime() {
    let spec = format!(
        r##"{{
  "swagger": "2.0",
  "info": {{"title": "Swagger Runtime", "version": "1.0.0"}},
  "basePath": "/v1",
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let plugin = OpenapiValidator::new(&config).expect("admission must succeed");
    assert_matches(&plugin, "GET", "/v1/pets").await;
    assert_rejects_unknown(&plugin, "GET", "/pets").await;
}

#[test]
fn multiple_distinct_servers_emit_deterministic_matchers() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Multi Server", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [
    {{"url": "/v1"}},
    {{"url": "https://api.example.com/v2"}},
    {{"url": "/v1"}},
    {{"url": "https://other.example.com/v2/"}}
  ],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![
            (
                "GET".to_string(),
                "/v1/pets".to_string(),
                "^/v1/pets$".to_string()
            ),
            (
                "GET".to_string(),
                "/v2/pets".to_string(),
                "^/v2/pets$".to_string()
            ),
        ],
        "equivalent pathnames must dedupe while preserving first-seen document order"
    );
}

#[tokio::test]
async fn multiple_server_pathnames_match_at_runtime() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Multi Server Runtime", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [
    {{"url": "/v1"}},
    {{"url": "https://api.example.com/v2"}}
  ],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let plugin = OpenapiValidator::new(&config).expect("admission must succeed");
    assert_matches(&plugin, "GET", "/v1/pets").await;
    assert_matches(&plugin, "GET", "/v2/pets").await;
    assert_rejects_unknown(&plugin, "GET", "/pets").await;
}

#[test]
fn relative_and_absolute_urls_use_pathname_only() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "URL Forms", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [
    {{"url": "/v1"}},
    {{"url": "https://api.example.com:8443/v1?x=1#frag"}},
    {{"url": "//cdn.example.com/v3"}}
  ],
  "paths": {{
    "/pets/{{id}}": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![
            (
                "GET".to_string(),
                "/v1/pets/{id}".to_string(),
                "^/v1/pets/[^/]+$".to_string()
            ),
            (
                "GET".to_string(),
                "/v3/pets/{id}".to_string(),
                "^/v3/pets/[^/]+$".to_string()
            ),
        ]
    );
}

#[test]
fn server_variables_use_defaults_only() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Server Vars", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{
    "url": "https://{{host}}/{{basePath}}",
    "variables": {{
      "host": {{"default": "api.example.com", "enum": ["api.example.com", "staging.example.com"]}},
      "basePath": {{"default": "v2"}}
    }}
  }}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![(
            "GET".to_string(),
            "/v2/pets".to_string(),
            "^/v2/pets$".to_string()
        )]
    );
}

#[tokio::test]
async fn server_variable_default_matches_at_runtime() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Server Vars Runtime", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{
    "url": "/{{version}}",
    "variables": {{
      "version": {{"default": "v9", "enum": ["v9", "v10"]}}
    }}
  }}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    let plugin = OpenapiValidator::new(&config).expect("admission must succeed");
    assert_matches(&plugin, "GET", "/v9/pets").await;
    assert_rejects_unknown(&plugin, "GET", "/v10/pets").await;
}

#[test]
fn root_path_key_under_server_base_preserves_base() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Root Path Key", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/v1"}}],
  "paths": {{
    "/": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![("GET".to_string(), "/v1".to_string(), "^/v1$".to_string())]
    );
}

#[tokio::test]
async fn root_only_servers_keep_raw_path_behavior() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Root Only Servers", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [
    {{"url": "https://api.example.com"}},
    {{"url": "https://other.example.com/"}}
  ],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![(
            "GET".to_string(),
            "/pets".to_string(),
            "^/pets$".to_string()
        )]
    );
    let plugin = OpenapiValidator::new(&config).expect("admission must succeed");
    assert_matches(&plugin, "GET", "/pets").await;
}

#[test]
fn path_item_ref_with_servers_uses_effective_base() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Ref Servers", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/root"}}],
  "components": {{
    "pathItems": {{
      "Pets": {{
        "servers": [{{"url": "/from-ref"}}],
        "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
      }}
    }}
  }},
  "paths": {{
    "/pets": {{
      "$ref": "#/components/pathItems/Pets",
      "servers": [{{"url": "/from-sibling"}}]
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![(
            "GET".to_string(),
            "/from-sibling/pets".to_string(),
            "^/from\\-sibling/pets$".to_string()
        )],
        "sibling Path Item servers must overlay referenced servers"
    );
}

#[test]
fn missing_server_variable_default_fails_closed() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Missing Default", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{
    "url": "/{{version}}",
    "variables": {{
      "version": {{"enum": ["v1"]}}
    }}
  }}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    assert!(
        matches!(
            err,
            ExtractError::MalformedExtension {
                which: "servers",
                ..
            }
        ),
        "missing variable default must fail closed: {err}"
    );
}

#[test]
fn default_outside_enum_fails_closed() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Bad Default", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{
    "url": "/{{version}}",
    "variables": {{
      "version": {{"default": "v9", "enum": ["v1", "v2"]}}
    }}
  }}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    assert!(
        matches!(
            err,
            ExtractError::MalformedExtension {
                which: "servers",
                ..
            }
        ),
        "default outside enum must fail closed: {err}"
    );
}

#[test]
fn traversal_like_server_pathname_fails_closed() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Traversal", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/v1/../admin"}}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    assert!(
        matches!(
            err,
            ExtractError::MalformedExtension {
                which: "servers",
                ..
            }
        ),
        "traversal-like pathname must fail closed: {err}"
    );
}

#[test]
fn percent_encoded_traversal_server_pathname_fails_closed() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Encoded Traversal", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "/v1/%2e%2E/admin"}}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    assert!(
        matches!(
            err,
            ExtractError::MalformedExtension {
                which: "servers",
                ..
            }
        ),
        "percent-encoded traversal pathname must fail closed: {err}"
    );
}

#[test]
fn relative_non_absolute_server_url_resolves_from_synthetic_document_root() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Relative Unsafe", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "v1"}}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![(
            "GET".to_string(),
            "/v1/pets".to_string(),
            "^/v1/pets$".to_string()
        )]
    );
}

#[test]
fn malformed_absolute_server_authority_fails_closed() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Malformed Authority", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [{{"url": "https://[::1/v1"}}],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    assert!(
        matches!(
            err,
            ExtractError::MalformedExtension {
                which: "servers",
                ..
            }
        ),
        "malformed absolute authority must fail closed: {err}"
    );
}

#[test]
fn swagger_base_path_rejects_absolute_url() {
    let spec = format!(
        r##"{{
  "swagger": "2.0",
  "info": {{"title": "Bad Swagger Base", "version": "1.0.0"}},
  "basePath": "https://api.example.com/v1",
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    assert!(
        matches!(
            err,
            ExtractError::MalformedExtension {
                which: "basePath",
                ..
            }
        ),
        "Swagger basePath absolute URL must fail closed: {err}"
    );
}

#[test]
fn empty_servers_array_fails_closed() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Empty Servers", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "servers": [],
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let err = extract_err(&spec);
    assert!(
        matches!(
            err,
            ExtractError::MalformedExtension {
                which: "servers",
                ..
            }
        ),
        "empty servers array must fail closed: {err}"
    );
}

#[test]
fn no_servers_keeps_raw_paths_key_matcher() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "No Servers", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{
      "get": {{"responses": {{"200": {{"description": "ok"}}}}}}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_config(&spec);
    assert_eq!(
        op_templates(&config),
        vec![(
            "GET".to_string(),
            "/pets".to_string(),
            "^/pets$".to_string()
        )]
    );
}
