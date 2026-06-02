use bytes::Bytes;
use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::plugins::{HTTP_ONLY_PROTOCOLS, PluginResult, create_plugin, priority};
use serde_json::{Value, json};
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::create_test_context;

fn transparent_config(upstream_url: &str) -> Value {
    json!({
        "enabled": true,
        "mode": "transparent_proxy",
        "endpoint": {
            "path": "/mcp",
            "protocol_versions": ["2025-11-25"]
        },
        "servers": {
            "github": {
                "upstream_url": upstream_url,
                "namespace": "github",
                "enabled": true
            }
        }
    })
}

fn aggregate_config(upstream_url: &str) -> Value {
    json!({
        "enabled": true,
        "mode": "aggregate_router",
        "endpoint": {
            "path": "/mcp",
            "protocol_versions": ["2025-11-25"]
        },
        "discovery": {
            "aggregate_tools": true,
            "aggregate_resources": true,
            "aggregate_prompts": true,
            "namespace_separator": ".",
            "cache_ttl_seconds": 300,
            "on_new_tool": "hide_until_configured"
        },
        "servers": {
            "github": {
                "upstream_url": upstream_url,
                "namespace": "github",
                "enabled": true,
                "expose_tools": true,
                "expose_resources": true,
                "expose_prompts": true
            }
        },
        "policy": {
            "default_action": "deny",
            "hide_denied_tools": true,
            "tools": {
                "github.create_pr": { "action": "allow" },
                "github.merge_pr": { "action": "deny" }
            }
        },
        "validation": {
            "validate_tool_arguments": true
        }
    })
}

fn mcp_ctx(
    body: Value,
) -> (
    ferrum_edge::plugins::RequestContext,
    HashMap<String, String>,
) {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.path = "/mcp".to_string();
    let body_bytes = serde_json::to_vec(&body).unwrap();
    ctx.metadata.insert(
        "request_body".to_string(),
        String::from_utf8(body_bytes.clone()).unwrap(),
    );
    ctx.request_body_bytes = Some(Bytes::from(body_bytes));
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    (ctx, headers)
}

fn reject_json(result: PluginResult) -> (u16, Value, HashMap<String, String>) {
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, serde_json::from_str(&body).unwrap(), headers),
        other => panic!("expected reject response, got {other:?}"),
    }
}

async fn start_mcp_catalog_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("mcp-session-id", "upstream-session")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "upstream",
                    "result": {
                        "tools": [
                            {
                                "name": "create_pr",
                                "description": "Create a pull request",
                                "inputSchema": {
                                    "type": "object",
                                    "required": ["repo"],
                                    "properties": {
                                        "repo": { "type": "string" }
                                    }
                                }
                            },
                            {
                                "name": "merge_pr",
                                "description": "Merge a pull request",
                                "inputSchema": { "type": "object" }
                            },
                            {
                                "name": "hidden_new",
                                "description": "Should stay hidden",
                                "inputSchema": { "type": "object" }
                            }
                        ],
                        "resources": [
                            {
                                "uri": "file:///project/README.md",
                                "name": "README",
                                "mimeType": "text/markdown"
                            }
                        ],
                        "prompts": [
                            {
                                "name": "code_review",
                                "description": "Review code"
                            }
                        ]
                    }
                })),
        )
        .mount(&server)
        .await;
    server
}

async fn initialize(plugin: &std::sync::Arc<dyn ferrum_edge::plugins::Plugin>) -> String {
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "unit-test", "version": "1" }
        }
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, response_headers) = reject_json(result);
    assert_eq!(status, 200);
    assert_eq!(body["result"]["serverInfo"]["name"], "ferrum-mcp-gateway");
    response_headers
        .get("mcp-session-id")
        .expect("synthetic initialize must return an MCP session")
        .clone()
}

#[test]
fn registered_and_exposes_expected_basics() {
    let plugin = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.internal:8080/mcp"),
    )
    .unwrap()
    .unwrap();

    assert_eq!(plugin.name(), "mcp_gateway");
    assert_eq!(plugin.priority(), priority::MCP_GATEWAY);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.needs_request_body_bytes());
    assert!(plugin.modifies_request_headers());
    assert!(ferrum_edge::plugins::available_plugins().contains(&"mcp_gateway"));
}

#[test]
fn invalid_config_shapes_are_rejected() {
    for config in [
        json!("bad"),
        json!({
            "mode": "bad",
            "endpoint": { "path": "/mcp" },
            "servers": { "github": { "upstream_url": "http://x/mcp", "namespace": "github" } }
        }),
        json!({
            "mode": "transparent_proxy",
            "endpoint": { "path": "mcp" },
            "servers": { "github": { "upstream_url": "http://x/mcp", "namespace": "github" } }
        }),
        json!({
            "mode": "transparent_proxy",
            "endpoint": { "path": "/mcp" },
            "servers": {}
        }),
        json!({
            "mode": "aggregate_router",
            "endpoint": { "path": "/mcp" },
            "servers": {
                "github": {
                    "upstream_url": "http://github/mcp",
                    "namespace": "dup",
                    "expose_tools": false,
                    "expose_resources": false,
                    "expose_prompts": false
                }
            }
        }),
        json!({
            "mode": "aggregate_router",
            "endpoint": { "path": "/mcp" },
            "servers": {
                "github": { "upstream_url": "http://github/mcp", "namespace": "dup" },
                "jira": { "upstream_url": "http://jira/mcp", "namespace": "dup" }
            }
        }),
        json!({
            "mode": "transparent_proxy",
            "endpoint": { "path": "/mcp" },
            "servers": { "github": { "upstream_url": "http://x/mcp", "namespace": "github" } },
            "policy": { "tools": { "github.x": { "action": "maybe" } } }
        }),
    ] {
        assert!(
            create_plugin("mcp_gateway", &config).is_err(),
            "config should be rejected: {config:?}"
        );
    }
}

#[tokio::test]
async fn transparent_post_sets_direct_route_override_and_metadata() {
    let plugin = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.internal:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.route_override_backend_scheme, Some(BackendScheme::Http));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("github-mcp.internal")
    );
    assert_eq!(ctx.route_override_backend_port, Some(8080));
    assert_eq!(ctx.route_override_path.as_deref(), Some("/mcp"));
    assert_eq!(
        headers.get("host").map(String::as_str),
        Some("github-mcp.internal:8080")
    );
    assert_eq!(
        ctx.metadata.get("mcp.method").map(String::as_str),
        Some("tools/list")
    );
    assert_eq!(
        ctx.metadata.get("mcp.server_id").map(String::as_str),
        Some("github")
    );
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("forward")
    );
}

#[tokio::test]
async fn aggregate_initialize_returns_synthetic_session_and_capabilities() {
    let server = start_mcp_catalog_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();

    let session_id = initialize(&plugin).await;
    assert!(!session_id.is_empty());
}

#[tokio::test]
async fn aggregate_tools_list_namespaces_and_hides_denied_or_unconfigured_tools() {
    let server = start_mcp_catalog_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    let tool_names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(tool_names, vec!["github.create_pr"]);
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("synthetic_response")
    );
    assert_eq!(
        ctx.metadata.get("mcp.catalog_version").map(String::as_str),
        Some("1")
    );
}

#[tokio::test]
async fn aggregate_tool_call_validates_arguments_routes_and_rewrites_name() {
    let server = start_mcp_catalog_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;

    let (mut list_ctx, mut list_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    list_headers.insert("mcp-session-id".to_string(), session_id.clone());
    let _ = plugin.before_proxy(&mut list_ctx, &mut list_headers).await;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "github.create_pr",
            "arguments": { "repo": "payments-api" }
        }
    });
    let (mut ctx, mut headers) = mcp_ctx(body.clone());
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.route_override_backend_scheme, Some(BackendScheme::Http));
    assert_eq!(ctx.route_override_path.as_deref(), Some("/mcp"));
    assert_eq!(
        headers.get("mcp-session-id").map(String::as_str),
        Some("upstream-session")
    );
    assert_eq!(
        ctx.metadata.get("mcp.public_tool_name").map(String::as_str),
        Some("github.create_pr")
    );
    assert_eq!(
        ctx.metadata
            .get("mcp.upstream_tool_name")
            .map(String::as_str),
        Some("create_pr")
    );
    assert_eq!(
        ctx.metadata
            .get("mcp.schema_validation")
            .map(String::as_str),
        Some("pass")
    );

    let rewritten = plugin
        .transform_request_body(
            serde_json::to_vec(&body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("tool call should be rewritten");
    let rewritten: Value = serde_json::from_slice(&rewritten).unwrap();
    assert_eq!(rewritten["params"]["name"], "create_pr");
    assert_eq!(rewritten["params"]["arguments"]["repo"], "payments-api");
}

#[tokio::test]
async fn aggregate_tool_call_rejects_invalid_arguments_as_json_rpc_error() {
    let server = start_mcp_catalog_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;

    let (mut list_ctx, mut list_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    list_headers.insert("mcp-session-id".to_string(), session_id.clone());
    let _ = plugin.before_proxy(&mut list_ctx, &mut list_headers).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "github.create_pr",
            "arguments": {}
        }
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    assert_eq!(body["id"], 4);
    assert_eq!(body["error"]["code"], -32602);
    assert_eq!(
        ctx.metadata
            .get("mcp.schema_validation")
            .map(String::as_str),
        Some("fail")
    );
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("deny")
    );
}
