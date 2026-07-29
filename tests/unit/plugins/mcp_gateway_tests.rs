use bytes::Bytes;
use ferrum_edge::config::types::{BackendScheme, BackendTlsConfig};
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, ai_tool_governor::AiToolGovernor,
    create_plugin, priority,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::{body_partial_json, method, path};
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

/// Context carrying an exact raw request body. Batch admission caps are
/// enforced on these bytes before any JSON parsing, so tests need a body that
/// is not round-tripped through `serde_json`.
fn mcp_ctx_raw(
    body: Vec<u8>,
) -> (
    ferrum_edge::plugins::RequestContext,
    HashMap<String, String>,
) {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.path = "/mcp".to_string();
    ctx.request_body_bytes = Some(Bytes::from(body));
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

fn reject_raw(result: PluginResult) -> (u16, String, HashMap<String, String>) {
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, body, headers),
        other => panic!("expected reject response, got {other:?}"),
    }
}

fn known_json_response_headers(body: &[u8]) -> HashMap<String, String> {
    HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), body.len().to_string()),
    ])
}

async fn reverse_mapped_tool_resource_uri(
    plugin: &Arc<dyn ferrum_edge::plugins::Plugin>,
    session_id: &str,
    id: u64,
) -> String {
    let request = json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "github.create_pr", "arguments": {"repo": "payments-api"}}
    });
    let (mut ctx, mut headers) = mcp_ctx(request.clone());
    headers.insert("mcp-session-id".to_string(), session_id.to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    plugin
        .transform_request_body_with_context(
            &mut ctx,
            &serde_json::to_vec(&request).unwrap(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("tool request should be rewritten");
    let response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": id, "result": {"content": [{
            "type": "resource_link", "uri": "file:///project/generated.txt", "name": "Generated"
        }]}
    }))
    .unwrap();
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &response,
            Some("application/json"),
            &known_json_response_headers(&response),
        )
        .await
        .expect("selected-server template should reverse-map the resource link");
    serde_json::from_slice::<Value>(&rewritten).unwrap()["result"]["content"][0]["uri"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn route_resource_uri(
    plugin: &Arc<dyn ferrum_edge::plugins::Plugin>,
    session_id: &str,
    id: u64,
    public_uri: &str,
) -> PluginResult {
    let request = json!({
        "jsonrpc": "2.0", "id": id, "method": "resources/read",
        "params": {"uri": public_uri}
    });
    let (mut ctx, mut headers) = mcp_ctx(request);
    headers.insert("mcp-session-id".to_string(), session_id.to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await
}

async fn start_mcp_catalog_server() -> MockServer {
    start_mcp_catalog_server_with_template("file:///project/{path}").await
}

async fn start_mcp_catalog_server_with_template(uri_template: &str) -> MockServer {
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
                        "resourceTemplates": [
                            {
                                "uriTemplate": uri_template,
                                "name": "Project file",
                                "mimeType": "text/plain"
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
    Mock::given(method("DELETE"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

async fn start_mcp_resource_templates_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "upstream",
            "result": {
                "resourceTemplates": [
                    {
                        "uriTemplate": "file:///project/{path}",
                        "name": "Project file",
                        "mimeType": "text/plain"
                    }
                ]
            }
        })))
        .mount(&server)
        .await;
    server
}

async fn start_mcp_paginated_tools_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "page-1",
            "result": {
                "tools": [
                    {
                        "name": "create_pr",
                        "inputSchema": {
                            "type": "object",
                            "required": ["repo"],
                            "properties": {
                                "repo": { "type": "string" }
                            }
                        }
                    }
                ],
                "nextCursor": "page-2"
            }
        })))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "page-2",
            "result": {
                "tools": [
                    {
                        "name": "second_tool",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .with_priority(2)
        .mount(&server)
        .await;
    server
}

async fn start_mcp_empty_cursor_tools_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "page-1",
            "result": {
                "tools": [
                    {
                        "name": "first_tool",
                        "inputSchema": { "type": "object" }
                    }
                ],
                "nextCursor": ""
            }
        })))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "tools/list", "params": {"cursor": ""}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "page-2",
            "result": {
                "tools": [
                    {
                        "name": "second_tool",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .with_priority(2)
        .mount(&server)
        .await;
    server
}

async fn start_mcp_oversized_json_tools_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "upstream-init",
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "oversized", "version": "1"}
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"jsonrpc":"2.0","id":"oversized","result":{{"tools":[{{"name":"huge_tool","description":"{}","inputSchema":{{"type":"object"}}}}]}}}}"#,
            "x".repeat(4 * 1024 * 1024)
        )))
        .mount(&server)
        .await;
    server
}

async fn start_mcp_stateless_tools_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "initialize",
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": { "name": "stateless", "version": "1" }
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "notifications/initialized"}),
        ))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "result": {
                "tools": [
                    {
                        "name": "stateless_tool",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .mount(&server)
        .await;
    server
}

async fn start_mcp_zero_arg_tool_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "result": {
                "tools": [
                    {
                        "name": "ping_tool",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .mount(&server)
        .await;
    server
}

async fn start_mcp_negotiated_protocol_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("mcp-session-id", "upstream-session")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "initialize",
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "serverInfo": { "name": "negotiated", "version": "1" }
                    }
                })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "notifications/initialized"}),
        ))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "result": {
                "tools": [
                    {
                        "name": "versioned_tool",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .mount(&server)
        .await;
    server
}

async fn start_mcp_sse_tools_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    "event: message\n\
                     data: {\"jsonrpc\":\"2.0\",\"id\":\"tools\",\"result\":{\"tools\":[{\"name\":\"sse_tool\",\"inputSchema\":{\"type\":\"object\"}}]}}\n\n",
                )
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&server)
        .await;
    server
}

async fn start_mcp_error_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "upstream-error",
            "error": {
                "code": -32000,
                "message": "catalog unavailable"
            }
        })))
        .mount(&server)
        .await;
    server
}

async fn start_mcp_initialize_error_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "initialize-error",
            "error": {
                "code": -32602,
                "message": "unsupported protocol version"
            }
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "fallback",
            "result": {
                "tools": [
                    {
                        "name": "create_pr",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .with_priority(2)
        .mount(&server)
        .await;
    server
}

async fn start_mcp_tool_collision_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/one"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "one",
            "result": {
                "tools": [
                    {
                        "name": "b.c",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/two"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "two",
            "result": {
                "tools": [
                    {
                        "name": "c",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .mount(&server)
        .await;
    server
}

async fn start_mcp_session_scoped_catalog_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("mcp-session-id", "upstream-session")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "initialize",
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "serverInfo": { "name": "session-test", "version": "1" }
                    }
                })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "notifications/initialized"}),
        ))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools-1",
            "result": {
                "tools": [
                    {
                        "name": "first",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools-2",
            "result": {
                "tools": [
                    {
                        "name": "second",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        })))
        .with_priority(2)
        .mount(&server)
        .await;
    server
}

async fn start_mcp_schema_change_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools-1",
            "result": {
                "tools": [
                    {
                        "name": "create_pr",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "repo": { "type": "string" }
                            }
                        }
                    }
                ]
            }
        })))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools-2",
            "result": {
                "tools": [
                    {
                        "name": "create_pr",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "repo": { "type": "string" },
                                "title": { "type": "string" }
                            }
                        }
                    }
                ]
            }
        })))
        .with_priority(2)
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

async fn aggregate_tool_names(
    plugin: &std::sync::Arc<dyn ferrum_edge::plugins::Plugin>,
    session_id: &str,
    request_id: i64,
) -> Vec<String> {
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id.to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (_, body, _) = reject_json(result);
    body["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list result missing tools array: {body}"))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn registered_and_exposes_expected_basics() {
    let plugin = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.example:8080/mcp"),
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
            "mode": "aggregate_router",
            "endpoint": { "path": "/mcp" },
            "capabilities": {
                "advertise_completions": true,
                "passthrough_unknown_methods": false
            },
            "servers": {
                "github": { "upstream_url": "http://github/mcp", "namespace": "github" }
            }
        }),
        json!({
            "mode": "transparent_proxy",
            "endpoint": { "path": "/mcp" },
            "servers": { "github": { "upstream_url": "http://x/mcp", "namespace": "github" } },
            "policy": { "tools": { "github.x": { "action": "maybe" } } }
        }),
        // Server id with a URI-reserved '/' would parse back to the wrong id in
        // public mcp:// resource URIs.
        json!({
            "mode": "aggregate_router",
            "endpoint": { "path": "/mcp" },
            "servers": {
                "team/a": {
                    "upstream_url": "http://x/mcp",
                    "namespace": "github",
                    "expose_tools": true
                }
            }
        }),
        // Invalid HTTP header name for a configured session header.
        json!({
            "mode": "transparent_proxy",
            "endpoint": { "path": "/mcp" },
            "sessions": { "downstream_session_header": "bad header" },
            "servers": { "github": { "upstream_url": "http://x/mcp", "namespace": "github" } }
        }),
        // validate_tool_results is not implemented; setting true must be rejected.
        json!({
            "mode": "transparent_proxy",
            "endpoint": { "path": "/mcp" },
            "validation": { "validate_tool_results": true },
            "servers": { "github": { "upstream_url": "http://x/mcp", "namespace": "github" } }
        }),
        // mode is required (no silent default).
        json!({
            "endpoint": { "path": "/mcp" },
            "servers": { "github": { "upstream_url": "http://x/mcp", "namespace": "github" } }
        }),
        // advertise_logging without passthrough advertises an unhandled capability.
        json!({
            "mode": "aggregate_router",
            "endpoint": { "path": "/mcp" },
            "capabilities": { "advertise_logging": true, "passthrough_unknown_methods": false },
            "servers": {
                "github": {
                    "upstream_url": "http://github/mcp",
                    "namespace": "github",
                    "expose_tools": true
                }
            }
        }),
    ] {
        assert!(
            create_plugin("mcp_gateway", &config).is_err(),
            "config should be rejected: {config:?}"
        );
    }
}

#[test]
fn validation_upstream_and_catalog_limits_parse() {
    let mut config = transparent_config("http://127.0.0.1:9/mcp");
    config["validation"] = json!({
        "max_upstream_response_bytes": 1024,
        "max_catalog_items_per_list": 5,
        "max_catalog_bytes_per_list": 2048,
        "max_batch_items": 8,
        "max_batch_bytes": 4096,
        "max_batch_item_bytes": 1024,
        "max_batch_response_bytes": 2048
    });
    assert!(
        create_plugin("mcp_gateway", &config).is_ok(),
        "positive upstream/catalog/batch limit overrides should be accepted"
    );
}

#[test]
fn validation_zero_limits_are_rejected() {
    // Zero would disable a DoS backstop, so each limit must reject 0.
    for field in [
        "max_upstream_response_bytes",
        "max_catalog_items_per_list",
        "max_catalog_bytes_per_list",
        "max_batch_items",
        "max_batch_bytes",
        "max_batch_item_bytes",
        "max_batch_response_bytes",
    ] {
        let mut config = transparent_config("http://127.0.0.1:9/mcp");
        let mut validation = serde_json::Map::new();
        validation.insert(field.to_string(), json!(0));
        config["validation"] = Value::Object(validation);

        let err = create_plugin("mcp_gateway", &config)
            .err()
            .unwrap_or_else(|| panic!("{field} = 0 must be rejected"));
        assert!(
            err.contains(field),
            "rejection should name {field}, got: {err}"
        );
    }
}

#[test]
fn protocol_version_2025_03_26_is_admitted_with_batch_support() {
    let mut config = aggregate_config("http://127.0.0.1:9/mcp");
    config["endpoint"]["protocol_versions"] = json!(["2025-03-26"]);
    assert!(
        create_plugin("mcp_gateway", &config).is_ok(),
        "2025-03-26 must be constructible now that JSON-RPC batches are supported"
    );
}

#[tokio::test]
async fn batch_limit_reload_update_and_delete_change_admission() {
    // Simulate config reload/update/delete by reconstructing plugin instances
    // and driving the SAME batch through admission each time: admission bounds
    // come from the published generation, not construction-only sticky state.
    let two_member_batch = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]);
    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["validation"] = json!({
        "max_batch_items": 2,
        "max_batch_bytes": 4096,
        "max_batch_item_bytes": 2048
    });
    let first = create_plugin("mcp_gateway", &config)
        .expect("initial batch limits must construct")
        .expect("plugin enabled");

    // Original generation: two members are within max_batch_items and both are
    // answered.
    let (mut ctx, mut headers) = mcp_ctx(two_member_batch.clone());
    let (status, body, _) = reject_json(first.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("original limit must admit the two-member batch");
    assert_eq!(responses.len(), 2);
    assert!(responses[0].get("result").is_some());
    assert!(responses[1].get("result").is_some());

    // Update: the new generation rejects the very same batch as a single
    // Invalid Request object, not an array of per-item results.
    config["validation"]["max_batch_items"] = json!(1);
    let updated = create_plugin("mcp_gateway", &config)
        .expect("updated batch limits must construct")
        .expect("plugin enabled");
    let (mut ctx, mut headers) = mcp_ctx(two_member_batch.clone());
    let (status, body, _) = reject_json(updated.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert!(
        body.is_object(),
        "updated max_batch_items must reject the whole batch: {body}"
    );
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "Invalid Request");
    assert!(
        !body.to_string().contains("\"result\""),
        "a rejected batch must not carry any member result: {body}"
    );

    // The original instance still admits it, proving the limit travels with the
    // published generation rather than any process-global state.
    let (mut ctx, mut headers) = mcp_ctx(two_member_batch.clone());
    let (_, body, _) = reject_json(first.before_proxy(&mut ctx, &mut headers).await);
    assert!(body.is_array());

    // Delete: an absent attachment is represented by a disabled instance, which
    // must neither handle nor reject the batch — it Continues so the request is
    // proxied without MCP batch semantics.
    config["enabled"] = json!(false);
    let deleted = create_plugin("mcp_gateway", &config)
        .expect("disabled mcp_gateway must construct")
        .expect("plugin object still returned");
    assert_eq!(deleted.name(), "mcp_gateway");
    let (mut ctx, mut headers) = mcp_ctx(two_member_batch);
    assert!(
        matches!(
            deleted.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ),
        "a deleted/disabled attachment must stop handling and stop rejecting batches"
    );
    assert!(!ctx.metadata.contains_key("mcp.batch"));
}

#[tokio::test]
async fn transparent_post_sets_direct_route_override_and_metadata() {
    let plugin = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.example:8080/mcp"),
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
        Some("github-mcp.example")
    );
    assert_eq!(ctx.route_override_backend_port, Some(8080));
    assert_eq!(
        ctx.route_override_resolved_tls,
        Some(BackendTlsConfig::default_verify())
    );
    assert_eq!(ctx.route_override_path.as_deref(), Some("/mcp"));
    assert!(ctx.route_override_path_is_absolute);
    assert_eq!(
        headers.get("host").map(String::as_str),
        Some("github-mcp.example:8080")
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
async fn aggregate_notifications_return_accepted_without_body() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    assert!(plugin.needs_final_request_body_context());
    let session_id = initialize(&plugin).await;
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, response_headers) = reject_raw(result);
    assert_eq!(status, 202);
    assert!(body.is_empty());
    assert!(response_headers.is_empty());
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
async fn aggregate_lazy_initialize_sends_initialized_notification_upstream() {
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
    let (status, _, _) = reject_json(result);
    assert_eq!(status, 200);

    let requests = server.received_requests().await.unwrap();
    let initialized = requests
        .iter()
        .find(|request| {
            request
                .body_json::<Value>()
                .ok()
                .and_then(|body| {
                    body.get("method")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .as_deref()
                == Some("notifications/initialized")
        })
        .expect("gateway should send initialized notification upstream");
    assert_eq!(
        initialized
            .headers
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok()),
        Some("upstream-session")
    );
}

#[tokio::test]
async fn aggregate_tools_list_keeps_discovery_hidden_tools_hidden_when_denied_tools_are_visible() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["hide_denied_items"] = json!(false);
    config["policy"]["hide_denied_tools"] = json!(false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
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
    let mut tool_names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    tool_names.sort_unstable();
    assert_eq!(tool_names, vec!["github.create_pr", "github.merge_pr"]);
}

#[tokio::test]
async fn aggregate_resource_templates_list_returns_resource_templates() {
    let server = start_mcp_resource_templates_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "resources/templates/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    assert!(body["result"].get("resources").is_none());
    let templates = body["result"]["resourceTemplates"].as_array().unwrap();
    assert_eq!(templates.len(), 1);
    assert_eq!(templates[0]["name"], "Project file");
    assert!(
        templates[0]["uriTemplate"]
            .as_str()
            .unwrap()
            .starts_with("mcp://github/")
    );
    assert!(
        templates[0]["uriTemplate"]
            .as_str()
            .unwrap()
            .contains("{path}")
    );
}

#[tokio::test]
async fn aggregate_resource_templates_list_honors_resource_aggregation_flag() {
    let server = start_mcp_resource_templates_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["aggregate_resources"] = json!(false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 17,
        "method": "resources/templates/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    assert_eq!(body["result"]["resourceTemplates"], json!([]));
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "disabled resource aggregation must not query upstream templates"
    );
}

#[tokio::test]
async fn aggregate_resource_read_routes_and_rewrites_template_generated_uri() {
    let server = start_mcp_resource_templates_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    assert!(plugin.needs_final_request_body_context());
    let session_id = initialize(&plugin).await;

    let (mut list_ctx, mut list_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "resources/templates/list",
        "params": {}
    }));
    list_headers.insert("mcp-session-id".to_string(), session_id.clone());
    let result = plugin.before_proxy(&mut list_ctx, &mut list_headers).await;
    let (_, body, _) = reject_json(result);
    let public_template = body["result"]["resourceTemplates"][0]["uriTemplate"]
        .as_str()
        .unwrap()
        .to_string();
    let public_uri = public_template.replace("{path}", "README.md");
    let read_body = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "resources/read",
        "params": {
            "uri": public_uri
        }
    });
    let (mut ctx, mut headers) = mcp_ctx(read_body.clone());
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.route_override_backend_scheme, Some(BackendScheme::Http));
    assert_eq!(ctx.route_override_path.as_deref(), Some("/mcp"));
    assert_eq!(
        ctx.metadata
            .get("mcp.upstream_resource_uri")
            .map(String::as_str),
        Some("file:///project/README.md")
    );

    let rewritten = plugin
        .transform_request_body_with_context(
            &mut ctx,
            serde_json::to_vec(&read_body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("resource read should be rewritten");
    let rewritten: Value = serde_json::from_slice(&rewritten).unwrap();
    assert_eq!(rewritten["params"]["uri"], "file:///project/README.md");
}

#[tokio::test]
async fn aggregate_resource_read_response_echoes_public_uri() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["observability"] = json!({ "emit_metadata": false });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut list_ctx, mut list_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "resources/list",
        "params": {}
    }));
    list_headers.insert("mcp-session-id".to_string(), session_id.clone());
    let (_, list_body, _) =
        reject_json(plugin.before_proxy(&mut list_ctx, &mut list_headers).await);
    let public_uri = list_body["result"]["resources"][0]["uri"]
        .as_str()
        .unwrap()
        .to_string();

    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "resources/read",
        "params": { "uri": public_uri }
    });
    let (mut ctx, mut headers) = mcp_ctx(request_body.clone());
    headers.insert("mcp-session-id".to_string(), session_id.clone());
    headers.insert("accept-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(!headers.contains_key("accept-encoding"));
    let _ = plugin
        .transform_request_body_with_context(
            &mut ctx,
            serde_json::to_vec(&request_body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("resource read request should be rewritten");
    assert!(
        ctx.metadata
            .values()
            .all(|value| value != "file:///project/README.md"),
        "internal response rewrite metadata must not retain upstream URIs"
    );

    // A concurrent template refresh changes the shared catalog version while
    // this read is in flight. The exact private request binding remains valid
    // and must still rewrite the upstream echo to the requested public URI.
    let (mut refresh_ctx, mut refresh_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "resources/templates/list",
        "params": {}
    }));
    refresh_headers.insert("mcp-session-id".to_string(), session_id.clone());
    let (refresh_status, _, _) = reject_json(
        plugin
            .before_proxy(&mut refresh_ctx, &mut refresh_headers)
            .await,
    );
    assert_eq!(refresh_status, 200);

    // Removing the session also removes its shared catalog, but must not
    // invalidate the exact binding already carried by this in-flight request.
    let (mut delete_ctx, mut delete_headers) = mcp_ctx(json!({}));
    delete_ctx.method = "DELETE".to_string();
    delete_headers.insert("mcp-session-id".to_string(), session_id);
    let (delete_status, _, _) = reject_json(
        plugin
            .before_proxy(&mut delete_ctx, &mut delete_headers)
            .await,
    );
    assert_eq!(delete_status, 200);

    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    assert!(plugin.should_release_response_body_under_retries(
        &ctx,
        200,
        &HashMap::from([(
            "content-type".to_string(),
            "text/event-stream; charset=utf-8".to_string(),
        )]),
    ));
    assert!(!plugin.should_release_response_body_under_retries(
        &ctx,
        200,
        &HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "128".to_string()),
        ]),
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "128".to_string()),
        ]),
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new(),
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &HashMap::from([("content-encoding".to_string(), "gzip".to_string(),)]),
    ));
    let oversized_headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        (
            "content-length".to_string(),
            (4 * 1024 * 1024 + 1).to_string(),
        ),
    ]);
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &oversized_headers,));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &oversized_headers,
    ));
    let unknown_length_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &unknown_length_headers,));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &unknown_length_headers,
    ));
    let upstream_response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 10,
        "result": {
            "contents": [{
                "uri": "file:///project/README.md",
                "mimeType": "text/markdown",
                "text": "read me"
            }]
        }
    }))
    .unwrap();
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        (
            "content-length".to_string(),
            upstream_response.len().to_string(),
        ),
        ("etag".to_string(), "\"upstream-body\"".to_string()),
        ("content-digest".to_string(), "sha-256=:old:".to_string()),
    ]);
    assert_eq!(
        response_headers.get("etag").map(String::as_str),
        Some("\"upstream-body\"")
    );
    assert!(response_headers.contains_key("content-digest"));

    // Another buffering policy must not let an unknown-length response bypass
    // MCP's rewrite cap at transform time.
    let mut unknown_length_response_headers = response_headers.clone();
    unknown_length_response_headers.remove("content-length");
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                upstream_response.as_slice(),
                Some("application/json"),
                &unknown_length_response_headers,
            )
            .await
            .is_none()
    );

    // Production response paths snapshot the origin headers before
    // `compression.after_proxy` decorates them. Gateway-added encoding must not
    // be mistaken for an encoded origin body, and the original known length
    // remains the MCP cap input after compression removes Content-Length.
    ctx.metadata.insert(
        "ferrum:original_response_metadata_stamped".to_string(),
        "true".to_string(),
    );
    ctx.metadata.insert(
        "ferrum:original_response_content_length".to_string(),
        upstream_response.len().to_string(),
    );
    response_headers.remove("content-length");
    response_headers.insert("content-encoding".to_string(), "gzip".to_string());
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            upstream_response.as_slice(),
            Some("application/json"),
            &response_headers,
        )
        .await
        .expect("resource read response should be reverse-mapped");
    plugin.on_response_body_transformed(&mut ctx, &mut response_headers);
    assert!(!response_headers.contains_key("etag"));
    assert!(!response_headers.contains_key("content-digest"));
    let rewritten: Value = serde_json::from_slice(&rewritten).unwrap();
    assert_eq!(rewritten["result"]["contents"][0]["uri"], public_uri);
}

#[tokio::test]
async fn aggregate_resource_read_preserves_requested_template_public_uri() {
    let server = start_mcp_catalog_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;

    let (mut template_ctx, mut template_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 31,
        "method": "resources/templates/list",
        "params": {}
    }));
    template_headers.insert("mcp-session-id".to_string(), session_id.clone());
    let (_, template_body, _) = reject_json(
        plugin
            .before_proxy(&mut template_ctx, &mut template_headers)
            .await,
    );
    let requested_public_uri = template_body["result"]["resourceTemplates"][0]["uriTemplate"]
        .as_str()
        .unwrap()
        .replace("{path}", "README.md");

    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 32,
        "method": "resources/read",
        "params": { "uri": requested_public_uri }
    });
    let (mut ctx, mut headers) = mcp_ctx(request_body.clone());
    headers.insert("mcp-session-id".to_string(), session_id);
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let rewritten_request = plugin
        .transform_request_body_with_context(
            &mut ctx,
            serde_json::to_vec(&request_body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("template resource read should be rewritten");
    let rewritten_request: Value = serde_json::from_slice(&rewritten_request).unwrap();
    assert_eq!(
        rewritten_request["params"]["uri"],
        "file:///project/README.md"
    );

    let upstream_response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 32,
        "result": {
            "contents": [{
                "uri": "file:///project/README.md",
                "mimeType": "text/markdown",
                "text": "read me"
            }]
        }
    }))
    .unwrap();
    let rewritten_response = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &upstream_response,
            Some("application/json"),
            &known_json_response_headers(&upstream_response),
        )
        .await
        .expect("resource echo should retain the routed public URI");
    let rewritten_response: Value = serde_json::from_slice(&rewritten_response).unwrap();
    assert_eq!(
        rewritten_response["result"]["contents"][0]["uri"],
        requested_public_uri
    );
}

#[tokio::test]
async fn aggregate_response_preserves_validators_when_no_uri_is_rewritten() {
    let server = start_mcp_catalog_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 14,
        "method": "tools/call",
        "params": {
            "name": "github.create_pr",
            "arguments": { "repo": "payments-api" }
        }
    });
    let (mut ctx, mut headers) = mcp_ctx(request_body.clone());
    headers.insert("mcp-session-id".to_string(), session_id);
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let _ = plugin
        .transform_request_body_with_context(
            &mut ctx,
            serde_json::to_vec(&request_body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("tool call request should be rewritten");

    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("etag".to_string(), "\"upstream-body\"".to_string()),
        (
            "last-modified".to_string(),
            "Thu, 10 Jul 2026 12:00:00 GMT".to_string(),
        ),
    ]);
    let upstream_response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 14,
        "result": { "content": [{ "type": "text", "text": "done" }] }
    }))
    .unwrap();
    response_headers.insert(
        "content-length".to_string(),
        upstream_response.len().to_string(),
    );
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &upstream_response,
                Some("application/json"),
                &response_headers,
            )
            .await
            .is_none()
    );
    assert_eq!(
        response_headers.get("etag").map(String::as_str),
        Some("\"upstream-body\"")
    );
    assert!(response_headers.contains_key("last-modified"));
}

#[tokio::test]
async fn aggregate_tool_call_response_rewrites_embedded_resource_uris() {
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
        "id": 11,
        "method": "resources/list",
        "params": {}
    }));
    list_headers.insert("mcp-session-id".to_string(), session_id.clone());
    let (_, list_body, _) =
        reject_json(plugin.before_proxy(&mut list_ctx, &mut list_headers).await);
    let public_uri = list_body["result"]["resources"][0]["uri"]
        .as_str()
        .unwrap()
        .to_string();

    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "github.create_pr",
            "arguments": { "repo": "payments-api" }
        }
    });
    let (mut ctx, mut headers) = mcp_ctx(request_body.clone());
    headers.insert("mcp-session-id".to_string(), session_id.clone());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let (mut template_ctx, mut template_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "resources/templates/list",
        "params": {}
    }));
    template_headers.insert("mcp-session-id".to_string(), session_id);
    let (_, template_body, _) = reject_json(
        plugin
            .before_proxy(&mut template_ctx, &mut template_headers)
            .await,
    );
    let public_template = template_body["result"]["resourceTemplates"][0]["uriTemplate"]
        .as_str()
        .unwrap();
    let generated_public_uri = public_template.replace("{path}", "generated.txt");
    let _ = plugin
        .transform_request_body_with_context(
            &mut ctx,
            serde_json::to_vec(&request_body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("tool call request should be rewritten");

    let upstream_response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 12,
        "result": {
            "content": [
                {
                    "type": "resource_link",
                    "uri": "file:///project/README.md",
                    "name": "README"
                },
                {
                    "type": "resource",
                    "resource": {
                        "uri": "file:///project/generated.txt",
                        "mimeType": "text/plain",
                        "text": "generated"
                    }
                }
            ]
        }
    }))
    .unwrap();
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &upstream_response,
            Some("application/json"),
            &known_json_response_headers(&upstream_response),
        )
        .await
        .expect("tool result resource URIs should be reverse-mapped");
    let rewritten: Value = serde_json::from_slice(&rewritten).unwrap();
    assert_eq!(rewritten["result"]["content"][0]["uri"], public_uri);
    assert_eq!(
        rewritten["result"]["content"][1]["resource"]["uri"],
        generated_public_uri
    );
}

#[tokio::test]
async fn aggregate_tool_call_reverse_maps_native_mcp_template_uri() {
    let server = start_mcp_catalog_server_with_template("mcp://github/{path}").await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 15,
        "method": "tools/call",
        "params": {
            "name": "github.create_pr",
            "arguments": { "repo": "payments-api" }
        }
    });
    let (mut ctx, mut headers) = mcp_ctx(request_body.clone());
    headers.insert("mcp-session-id".to_string(), session_id.clone());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let _ = plugin
        .transform_request_body_with_context(
            &mut ctx,
            serde_json::to_vec(&request_body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("tool call request should be rewritten");

    let upstream_response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 15,
        "result": {
            "content": [{
                "type": "resource_link",
                "uri": "mcp://github/generated.txt",
                "name": "Generated"
            }]
        }
    }))
    .unwrap();
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &upstream_response,
            Some("application/json"),
            &known_json_response_headers(&upstream_response),
        )
        .await
        .expect("native MCP template URI should be reverse-mapped");
    let rewritten: Value = serde_json::from_slice(&rewritten).unwrap();
    let public_uri = rewritten["result"]["content"][0]["uri"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        public_uri,
        "mcp://github/mcp%3A%2F%2Fgithub%2Fgenerated.txt"
    );

    let read_body = json!({
        "jsonrpc": "2.0",
        "id": 16,
        "method": "resources/read",
        "params": { "uri": public_uri }
    });
    let (mut read_ctx, mut read_headers) = mcp_ctx(read_body.clone());
    read_headers.insert("mcp-session-id".to_string(), session_id);
    assert!(matches!(
        plugin.before_proxy(&mut read_ctx, &mut read_headers).await,
        PluginResult::Continue
    ));
    let rewritten_read = plugin
        .transform_request_body_with_context(
            &mut read_ctx,
            serde_json::to_vec(&read_body).unwrap().as_slice(),
            Some("application/json"),
            &read_headers,
        )
        .await
        .expect("reverse-mapped template URI should route back upstream");
    let rewritten_read: Value = serde_json::from_slice(&rewritten_read).unwrap();
    assert_eq!(
        rewritten_read["params"]["uri"],
        "mcp://github/generated.txt"
    );
}

#[tokio::test]
async fn aggregate_template_reverse_mapping_preserves_upstream_percent_escapes() {
    let server = start_mcp_catalog_server_with_template("file:///{+path}").await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "github.create_pr",
            "arguments": { "repo": "payments-api" }
        }
    });
    let (mut ctx, mut headers) = mcp_ctx(request_body.clone());
    headers.insert("mcp-session-id".to_string(), session_id.clone());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let _ = plugin
        .transform_request_body_with_context(
            &mut ctx,
            serde_json::to_vec(&request_body).unwrap().as_slice(),
            Some("application/json"),
            &headers,
        )
        .await
        .expect("tool call request should be rewritten");

    let upstream_response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 20,
        "result": {
            "content": [
                {
                    "type": "resource_link",
                    "uri": "file:///a%2Fb",
                    "name": "Encoded path"
                },
                {
                    "type": "resource_link",
                    "uri": "file:///reports/Q1 draft.md",
                    "name": "Report draft"
                }
            ]
        }
    }))
    .unwrap();
    let rewritten = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &upstream_response,
            Some("application/json"),
            &known_json_response_headers(&upstream_response),
        )
        .await
        .expect("reserved template URI should be reverse-mapped");
    let rewritten: Value = serde_json::from_slice(&rewritten).unwrap();
    let public_uri = rewritten["result"]["content"][0]["uri"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(public_uri, "mcp://github/file%3A%2F%2F%2Fa%252Fb");
    let spaced_public_uri = rewritten["result"]["content"][1]["uri"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        spaced_public_uri,
        "mcp://github/file%3A%2F%2F%2Freports/Q1%20draft.md"
    );

    let read_body = json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "resources/read",
        "params": { "uri": public_uri }
    });
    let (mut read_ctx, mut read_headers) = mcp_ctx(read_body.clone());
    read_headers.insert("mcp-session-id".to_string(), session_id.clone());
    assert!(matches!(
        plugin.before_proxy(&mut read_ctx, &mut read_headers).await,
        PluginResult::Continue
    ));
    let rewritten_read = plugin
        .transform_request_body_with_context(
            &mut read_ctx,
            serde_json::to_vec(&read_body).unwrap().as_slice(),
            Some("application/json"),
            &read_headers,
        )
        .await
        .expect("percent-preserving public URI should route back upstream");
    let rewritten_read: Value = serde_json::from_slice(&rewritten_read).unwrap();
    assert_eq!(rewritten_read["params"]["uri"], "file:///a%2Fb");

    let spaced_read_body = json!({
        "jsonrpc": "2.0",
        "id": 22,
        "method": "resources/read",
        "params": { "uri": spaced_public_uri }
    });
    let (mut spaced_read_ctx, mut spaced_read_headers) = mcp_ctx(spaced_read_body.clone());
    spaced_read_headers.insert("mcp-session-id".to_string(), session_id);
    assert!(matches!(
        plugin
            .before_proxy(&mut spaced_read_ctx, &mut spaced_read_headers)
            .await,
        PluginResult::Continue
    ));
    let rewritten_spaced_read = plugin
        .transform_request_body_with_context(
            &mut spaced_read_ctx,
            serde_json::to_vec(&spaced_read_body).unwrap().as_slice(),
            Some("application/json"),
            &spaced_read_headers,
        )
        .await
        .expect("space-encoding public URI should route back upstream");
    let rewritten_spaced_read: Value = serde_json::from_slice(&rewritten_spaced_read).unwrap();
    assert_eq!(
        rewritten_spaced_read["params"]["uri"],
        "file:///reports/Q1 draft.md"
    );
}

#[tokio::test]
async fn aggregate_resource_read_reuses_selected_server_template_cache() {
    let primary = start_mcp_catalog_server().await;
    let unrelated = start_mcp_catalog_server().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "resources/templates/list"}),
        ))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&unrelated)
        .await;

    let mut config = aggregate_config(&format!("{}/mcp", primary.uri()));
    config["servers"]["unrelated"] = json!({
        "upstream_url": format!("{}/mcp", unrelated.uri()),
        "namespace": "unrelated",
        "enabled": true,
        "expose_tools": true,
        "expose_resources": true,
        "expose_prompts": true
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let tool_request = json!({
        "jsonrpc": "2.0",
        "id": 33,
        "method": "tools/call",
        "params": {
            "name": "github.create_pr",
            "arguments": { "repo": "payments-api" }
        }
    });
    let (mut tool_ctx, mut tool_headers) = mcp_ctx(tool_request.clone());
    tool_headers.insert("mcp-session-id".to_string(), session_id.clone());
    assert!(matches!(
        plugin.before_proxy(&mut tool_ctx, &mut tool_headers).await,
        PluginResult::Continue
    ));
    let _ = plugin
        .transform_request_body_with_context(
            &mut tool_ctx,
            serde_json::to_vec(&tool_request).unwrap().as_slice(),
            Some("application/json"),
            &tool_headers,
        )
        .await
        .expect("tool request should be rewritten");
    let tool_response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 33,
        "result": {
            "content": [{
                "type": "resource_link",
                "uri": "file:///project/generated.txt",
                "name": "Generated"
            }]
        }
    }))
    .unwrap();
    let rewritten_response = plugin
        .transform_response_body_with_context(
            &mut tool_ctx,
            &tool_response,
            Some("application/json"),
            &known_json_response_headers(&tool_response),
        )
        .await
        .expect("selected-server template should reverse-map the resource link");
    let rewritten_response: Value = serde_json::from_slice(&rewritten_response).unwrap();
    let public_uri = rewritten_response["result"]["content"][0]["uri"]
        .as_str()
        .unwrap()
        .to_string();

    let read_request = json!({
        "jsonrpc": "2.0",
        "id": 34,
        "method": "resources/read",
        "params": { "uri": public_uri }
    });
    let (mut read_ctx, mut read_headers) = mcp_ctx(read_request);
    read_headers.insert("mcp-session-id".to_string(), session_id);
    assert!(matches!(
        plugin.before_proxy(&mut read_ctx, &mut read_headers).await,
        PluginResult::Continue
    ));

    let unrelated_requests = unrelated.received_requests().await.unwrap();
    assert!(!unrelated_requests.iter().any(|request| {
        request
            .body_json::<Value>()
            .ok()
            .and_then(|body| {
                body.get("method")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("resources/templates/list")
    }));
    let primary_requests = primary.received_requests().await.unwrap();
    assert_eq!(
        primary_requests
            .iter()
            .filter(|request| {
                request
                    .body_json::<Value>()
                    .ok()
                    .and_then(|body| {
                        body.get("method")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some("resources/templates/list")
            })
            .count(),
        1,
        "a fresh selected-server template must be accepted without another refresh"
    );
}

#[tokio::test]
async fn aggregate_stale_resource_template_is_removed_by_selected_server_refresh() {
    let server = start_mcp_catalog_server().await;
    let unrelated = start_mcp_catalog_server().await;
    let template_requests = Arc::new(AtomicUsize::new(0));
    let response_counter = Arc::clone(&template_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "resources/templates/list"}),
        ))
        .respond_with(move |_: &wiremock::Request| {
            let templates = if response_counter.fetch_add(1, Ordering::SeqCst) == 0 {
                json!([{"uriTemplate": "file:///project/{path}", "name": "Project file"}])
            } else {
                json!([])
            };
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": "upstream", "result": {"resourceTemplates": templates}
            }))
        })
        .with_priority(1)
        .mount(&server)
        .await;
    let unrelated_template_requests = Arc::new(AtomicUsize::new(0));
    let unrelated_counter = Arc::clone(&unrelated_template_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "resources/templates/list"}),
        ))
        .respond_with(move |_: &wiremock::Request| {
            unrelated_counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(500)
        })
        .with_priority(1)
        .mount(&unrelated)
        .await;

    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["cache_ttl_seconds"] = json!(1);
    config["servers"]["unrelated"] = json!({
        "upstream_url": format!("{}/mcp", unrelated.uri()),
        "namespace": "unrelated",
        "enabled": true,
        "expose_tools": true,
        "expose_resources": true,
        "expose_prompts": true
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let public_uri = reverse_mapped_tool_resource_uri(&plugin, &session_id, 35).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let result = route_resource_uri(&plugin, &session_id, 36, &public_uri).await;
    let (_, body, _) = reject_json(result);
    assert_eq!(body["error"]["code"], -32007);
    assert_eq!(template_requests.load(Ordering::SeqCst), 2);
    assert_eq!(unrelated_template_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn aggregate_stale_resource_template_serves_stale_when_refresh_fails() {
    let server = start_mcp_catalog_server().await;
    let template_requests = Arc::new(AtomicUsize::new(0));
    let response_counter = Arc::clone(&template_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "resources/templates/list"}),
        ))
        .respond_with(move |_: &wiremock::Request| {
            if response_counter.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0", "id": "upstream", "result": {"resourceTemplates": [
                        {"uriTemplate": "file:///project/{path}", "name": "Project file"}
                    ]}
                }))
            } else {
                ResponseTemplate::new(500)
            }
        })
        .with_priority(1)
        .mount(&server)
        .await;

    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["cache_ttl_seconds"] = json!(1);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let public_uri = reverse_mapped_tool_resource_uri(&plugin, &session_id, 37).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    assert!(matches!(
        route_resource_uri(&plugin, &session_id, 38, &public_uri).await,
        PluginResult::Continue
    ));
    assert_eq!(template_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn aggregate_tool_only_server_skips_response_rewrite_and_template_refresh() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["servers"]["github"]["expose_resources"] = json!(false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 17,
        "method": "tools/call",
        "params": {
            "name": "github.create_pr",
            "arguments": { "repo": "payments-api" }
        }
    });
    let (mut ctx, mut headers) = mcp_ctx(request_body.clone());
    headers.insert("mcp-session-id".to_string(), session_id);
    headers.insert("accept-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        headers.get("accept-encoding").map(String::as_str),
        Some("gzip")
    );
    assert!(!plugin.should_buffer_response_body(&ctx));

    let requests = server.received_requests().await.unwrap();
    assert!(!requests.iter().any(|request| {
        request
            .body_json::<Value>()
            .ok()
            .and_then(|body| {
                body.get("method")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .as_deref()
            == Some("resources/templates/list")
    }));
}

#[tokio::test]
async fn aggregate_disabled_resources_skip_tool_and_prompt_response_rewrite() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["aggregate_resources"] = json!(false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    for (id, method, params) in [
        (
            18,
            "tools/call",
            json!({ "name": "github.create_pr", "arguments": { "repo": "payments-api" } }),
        ),
        (19, "prompts/get", json!({ "name": "github.code_review" })),
    ] {
        let request_body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        let (mut ctx, mut headers) = mcp_ctx(request_body);
        headers.insert("mcp-session-id".to_string(), session_id.clone());
        headers.insert("accept-encoding".to_string(), "gzip".to_string());
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        assert_eq!(
            headers.get("accept-encoding").map(String::as_str),
            Some("gzip")
        );
        assert!(!plugin.should_buffer_response_body(&ctx));
    }
}

#[tokio::test]
async fn aggregate_tools_list_follows_upstream_pagination() {
    let server = start_mcp_paginated_tools_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"]["tools"]["github.second_tool"] = json!({"action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    let mut tool_names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    tool_names.sort_unstable();
    assert_eq!(tool_names, vec!["github.create_pr", "github.second_tool"]);
}

#[tokio::test]
async fn aggregate_tools_list_rejects_oversized_upstream_json() {
    let server = start_mcp_oversized_json_tools_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 24,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    assert_eq!(body["error"]["code"], -32006);
    assert_eq!(body["error"]["message"], "MCP catalog unavailable");
}

#[tokio::test]
async fn aggregate_tools_list_follows_empty_string_pagination_cursor() {
    let server = start_mcp_empty_cursor_tools_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let mut tool_names = aggregate_tool_names(&plugin, &session_id, 25).await;
    tool_names.sort_unstable();
    assert_eq!(tool_names, vec!["github.first_tool", "github.second_tool"]);
}

#[tokio::test]
async fn aggregate_stateless_upstreams_initialize_once_and_send_streamable_accept() {
    let server = start_mcp_stateless_tools_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["cache_ttl_seconds"] = json!(1);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    assert_eq!(
        aggregate_tool_names(&plugin, &session_id, 26).await,
        vec!["github.stateless_tool"]
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        aggregate_tool_names(&plugin, &session_id, 27).await,
        vec!["github.stateless_tool"]
    );

    let requests = server.received_requests().await.unwrap();
    let initialize_count = requests
        .iter()
        .filter(|request| {
            request
                .body_json::<Value>()
                .ok()
                .and_then(|body| {
                    body.get("method")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .as_deref()
                == Some("initialize")
        })
        .count();
    assert_eq!(initialize_count, 1);
    for request in requests
        .iter()
        .filter(|request| request.method.as_str() == "POST")
    {
        assert_eq!(
            request
                .headers
                .get("accept")
                .and_then(|value| value.to_str().ok()),
            Some("application/json, text/event-stream")
        );
    }
}

#[tokio::test]
async fn aggregate_upstream_requests_use_negotiated_protocol_version() {
    let server = start_mcp_negotiated_protocol_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["endpoint"]["protocol_versions"] = json!(["2025-11-25", "2025-06-18"]);
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    assert_eq!(
        aggregate_tool_names(&plugin, &session_id, 31).await,
        vec!["github.versioned_tool"]
    );

    let requests = server.received_requests().await.unwrap();
    let initialized = requests
        .iter()
        .find(|request| {
            request
                .body_json::<Value>()
                .ok()
                .and_then(|body| {
                    body.get("method")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .as_deref()
                == Some("notifications/initialized")
        })
        .expect("initialized notification should be sent");
    assert_eq!(
        initialized
            .headers
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok()),
        Some("2025-06-18")
    );
    let tools_list = requests
        .iter()
        .find(|request| {
            request
                .body_json::<Value>()
                .ok()
                .and_then(|body| {
                    body.get("method")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .as_deref()
                == Some("tools/list")
        })
        .expect("tools/list should be sent");
    assert_eq!(
        tools_list
            .headers
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok()),
        Some("2025-06-18")
    );
}

#[tokio::test]
async fn aggregate_tools_list_accepts_upstream_sse_response() {
    let server = start_mcp_sse_tools_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    assert_eq!(
        aggregate_tool_names(&plugin, &session_id, 32).await,
        vec!["github.sse_tool"]
    );
}

#[tokio::test]
async fn aggregate_tools_list_treats_upstream_json_rpc_errors_as_failures() {
    let server = start_mcp_error_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    assert_eq!(body["error"]["code"], -32006);
    assert!(body["result"].is_null());
}

#[tokio::test]
async fn aggregate_initialize_treats_upstream_json_rpc_errors_as_failures() {
    let server = start_mcp_initialize_error_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    assert_eq!(body["error"]["code"], -32006);

    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().any(|request| {
        request
            .body_json::<Value>()
            .ok()
            .and_then(|body| {
                body.get("method")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .as_deref()
            == Some("initialize")
    }));
    assert!(!requests.iter().any(|request| {
        request
            .body_json::<Value>()
            .ok()
            .and_then(|body| {
                body.get("method")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .as_deref()
            == Some("notifications/initialized")
    }));
}

#[tokio::test]
async fn aggregate_tools_list_skips_colliding_public_tool_names() {
    let server = start_mcp_tool_collision_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &json!({
            "enabled": true,
            "mode": "aggregate_router",
            "endpoint": {"path": "/mcp"},
            "sessions": {"initialize_upstreams": "passthrough"},
            "discovery": {
                "aggregate_tools": true,
                "aggregate_resources": false,
                "aggregate_prompts": false,
                "namespace_separator": ".",
                "on_new_tool": "allow"
            },
            "servers": {
                "one": {
                    "upstream_url": format!("{}/one", server.uri()),
                    "namespace": "a",
                    "enabled": true,
                    "expose_tools": true,
                    "expose_resources": false,
                    "expose_prompts": false
                },
                "two": {
                    "upstream_url": format!("{}/two", server.uri()),
                    "namespace": "a.b",
                    "enabled": true,
                    "expose_tools": true,
                    "expose_resources": false,
                    "expose_prompts": false
                }
            },
            "policy": {
                "default_action": "allow"
            }
        }),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    // Colliding public names are skipped (exposed by neither upstream, so never
    // routed to the wrong one) rather than failing the whole catalog. Both tools
    // here collide to the same public name, so the tool list is empty and no
    // catalog error is returned.
    assert!(
        body["error"].is_null(),
        "collision must not fail the catalog: {body}"
    );
    assert_eq!(body["result"]["tools"], json!([]));
}

#[tokio::test]
async fn aggregate_sessions_are_bounded() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"max_sessions": 1, "session_ttl_seconds": 3600});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();

    let evicted_session_id = initialize(&plugin).await;
    let live_session_id = initialize(&plugin).await;
    assert_ne!(evicted_session_id, live_session_id);

    let (mut evicted_ctx, mut evicted_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    evicted_headers.insert("mcp-session-id".to_string(), evicted_session_id);
    let result = plugin
        .before_proxy(&mut evicted_ctx, &mut evicted_headers)
        .await;
    let (status, body, _) = reject_raw(result);
    assert_eq!(status, 404);
    assert!(body.is_empty());

    let (mut live_ctx, mut live_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list",
        "params": {}
    }));
    live_headers.insert("mcp-session-id".to_string(), live_session_id);
    let result = plugin.before_proxy(&mut live_ctx, &mut live_headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    assert!(body["result"]["tools"].as_array().is_some());
}

#[tokio::test]
async fn aggregate_max_session_eviction_deletes_initialized_upstream_session() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"max_sessions": 1, "session_ttl_seconds": 3600});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();

    let evicted_session_id = initialize(&plugin).await;
    let (mut list_ctx, mut list_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 18,
        "method": "tools/list",
        "params": {}
    }));
    list_headers.insert("mcp-session-id".to_string(), evicted_session_id);
    let _ = plugin.before_proxy(&mut list_ctx, &mut list_headers).await;

    let live_session_id = initialize(&plugin).await;
    assert!(!live_session_id.is_empty());

    let requests = server.received_requests().await.unwrap();
    let delete = requests
        .iter()
        .find(|request| request.method.as_str() == "DELETE")
        .expect("max-session eviction should delete initialized upstream session");
    assert_eq!(
        delete
            .headers
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok()),
        Some("upstream-session")
    );
}

#[tokio::test]
async fn aggregate_catalogs_are_scoped_per_downstream_session() {
    let server = start_mcp_session_scoped_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["on_new_tool"] = json!("allow");
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();

    let first_session_id = initialize(&plugin).await;
    let (mut first_ctx, mut first_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/list",
        "params": {}
    }));
    first_headers.insert("mcp-session-id".to_string(), first_session_id);
    let result = plugin
        .before_proxy(&mut first_ctx, &mut first_headers)
        .await;
    let (_, first_body, _) = reject_json(result);
    assert_eq!(first_body["result"]["tools"][0]["name"], "github.first");

    let second_session_id = initialize(&plugin).await;
    let (mut second_ctx, mut second_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/list",
        "params": {}
    }));
    second_headers.insert("mcp-session-id".to_string(), second_session_id);
    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    let (_, second_body, _) = reject_json(result);
    assert_eq!(second_body["result"]["tools"][0]["name"], "github.second");
}

#[tokio::test]
async fn aggregate_schema_changed_tools_stay_hidden_until_configured() {
    let server = start_mcp_schema_change_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["cache_ttl_seconds"] = json!(1);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["discovery"]["on_schema_change"] = json!("hide_until_configured");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    assert_eq!(
        aggregate_tool_names(&plugin, &session_id, 22).await,
        vec!["github.create_pr"]
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(
        aggregate_tool_names(&plugin, &session_id, 23)
            .await
            .is_empty(),
        "schema change should hide the tool"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(
        aggregate_tool_names(&plugin, &session_id, 24)
            .await
            .is_empty(),
        "schema-changed tool should stay hidden after the new schema becomes the catalog baseline"
    );
}

#[tokio::test]
async fn aggregate_passthrough_unknown_methods_uses_deterministic_primary_server() {
    let plugin = create_plugin(
        "mcp_gateway",
        &json!({
            "enabled": true,
            "mode": "aggregate_router",
            "endpoint": {"path": "/mcp"},
            "capabilities": {"passthrough_unknown_methods": true},
            "sessions": {"initialize_upstreams": "passthrough"},
            "servers": {
                "zeta": {
                    "upstream_url": "http://zeta-mcp.example/mcp",
                    "namespace": "zeta",
                    "enabled": true,
                    "expose_tools": true
                },
                "alpha": {
                    "upstream_url": "http://alpha-mcp.example/mcp",
                    "namespace": "alpha",
                    "enabled": true,
                    "expose_tools": true
                }
            }
        }),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "vendor/custom",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("alpha-mcp.example")
    );
    assert_eq!(
        ctx.metadata.get("mcp.server_id").map(String::as_str),
        Some("alpha")
    );
}

#[tokio::test]
async fn aggregate_passthrough_unknown_methods_initialize_upstream_session() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["capabilities"] = json!({"passthrough_unknown_methods": true});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "completion/complete",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        headers.get("mcp-session-id").map(String::as_str),
        Some("upstream-session")
    );

    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().any(|request| {
        request
            .body_json::<Value>()
            .ok()
            .and_then(|body| {
                body.get("method")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .as_deref()
            == Some("initialize")
    }));
    assert!(requests.iter().any(|request| {
        request
            .body_json::<Value>()
            .ok()
            .and_then(|body| {
                body.get("method")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .as_deref()
            == Some("notifications/initialized")
    }));
}

#[tokio::test]
async fn aggregate_unsupported_http_methods_fail_closed() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let mut ctx = create_test_context();
    ctx.method = "PATCH".to_string();
    ctx.path = "/mcp".to_string();
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 405);
    assert_eq!(body["error"], "unsupported MCP aggregate HTTP method");
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("deny")
    );
}

#[tokio::test]
async fn aggregate_unsupported_notifications_return_accepted_without_body() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": "job-1",
            "progress": 1
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_raw(result);
    assert_eq!(status, 202);
    assert!(body.is_empty());
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("synthetic_response")
    );
}

#[tokio::test]
async fn aggregate_rejects_unsupported_protocol_header_after_initialize() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 30,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);
    headers.insert("mcp-protocol-version".to_string(), "2099-01-01".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 400);
    assert_eq!(body["error"]["message"], "Unsupported MCP protocol version");
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("deny")
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
    assert!(plugin.needs_final_request_body_context());
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
        .transform_request_body_with_context(
            &mut ctx,
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
async fn aggregate_tool_call_treats_missing_arguments_as_empty_object() {
    let server = start_mcp_zero_arg_tool_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let _ = aggregate_tool_names(&plugin, &session_id, 28).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 29,
        "method": "tools/call",
        "params": {
            "name": "github.ping_tool"
        }
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mcp.schema_validation")
            .map(String::as_str),
        Some("pass")
    );
}

#[tokio::test]
async fn aggregate_delete_tears_down_upstream_session() {
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

    let mut ctx = create_test_context();
    ctx.method = "DELETE".to_string();
    ctx.path = "/mcp".to_string();
    let mut headers = HashMap::from([("mcp-session-id".to_string(), session_id)]);
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    assert_eq!(status, 200);
    assert_eq!(body, json!({}));

    let requests = server.received_requests().await.unwrap();
    let delete = requests
        .iter()
        .find(|request| request.method.as_str() == "DELETE")
        .expect("upstream DELETE should be sent");
    assert_eq!(
        delete
            .headers
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok()),
        Some("upstream-session")
    );
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

#[tokio::test]
async fn aggregate_initialize_notification_is_accepted_without_minting_session() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();

    // `initialize` without a JSON-RPC id is a notification: it must be accepted
    // with 202/no body and must not mint a synthetic session.
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "unit-test", "version": "1" }
        }
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, response_headers) = reject_raw(result);
    assert_eq!(status, 202);
    assert!(body.is_empty());
    assert!(!response_headers.contains_key("mcp-session-id"));
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("synthetic_response")
    );
}

#[tokio::test]
async fn aggregate_routing_strips_synthetic_downstream_session_id_from_upstream() {
    let server = start_mcp_stateless_tools_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    // Passthrough upstream init => the gateway never holds an upstream session
    // id, so the synthetic downstream id must be stripped rather than forwarded.
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let _ = aggregate_tool_names(&plugin, &session_id, 40).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 41,
        "method": "tools/call",
        "params": {
            "name": "github.stateless_tool",
            "arguments": {}
        }
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.route_override_backend_scheme, Some(BackendScheme::Http));
    assert_eq!(
        headers.get("mcp-session-id"),
        None,
        "synthetic downstream session id must not leak to a passthrough upstream"
    );
}

#[tokio::test]
async fn aggregate_routing_strips_client_supplied_upstream_session_header() {
    let server = start_mcp_stateless_tools_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    // Distinct downstream/upstream header names so a client can attempt to inject
    // the gateway-owned upstream header directly.
    config["sessions"] = json!({
        "initialize_upstreams": "passthrough",
        "downstream_session_header": "mcp-session-id",
        "upstream_session_header": "mcp-upstream-session"
    });
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let _ = aggregate_tool_names(&plugin, &session_id, 50).await;

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 51,
        "method": "tools/call",
        "params": { "name": "github.stateless_tool", "arguments": {} }
    }));
    headers.insert("mcp-session-id".to_string(), session_id);
    headers.insert(
        "mcp-upstream-session".to_string(),
        "forged-upstream".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    // The synthetic downstream id and the client-forged upstream id must both be
    // stripped; a passthrough upstream has no mediated session id to re-add.
    assert_eq!(headers.get("mcp-session-id"), None);
    assert_eq!(headers.get("mcp-upstream-session"), None);
}

#[tokio::test]
async fn aggregate_notification_form_request_methods_are_accepted_without_side_effects() {
    let server = start_mcp_catalog_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;

    // A `tools/list` carrying no JSON-RPC id is a notification: it must be
    // accepted with 202/no body and must not require a session or refresh the
    // upstream catalog.
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_raw(result);
    assert_eq!(status, 202);
    assert!(body.is_empty());
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("synthetic_response")
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "notification-form tools/list must not refresh the upstream catalog"
    );
}

#[tokio::test]
async fn aggregate_notification_form_request_with_unknown_session_is_accepted() {
    // Unreachable upstream: a notification must short-circuit before any session
    // validation or routing, so no network call happens.
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();

    // tools/list with no id and a session header that was never created. The
    // notification guard must run before session validation, so this is accepted
    // with 202 instead of rejected as session-not-found (404).
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {}
    }));
    headers.insert(
        "mcp-session-id".to_string(),
        "never-initialized".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_raw(result);
    assert_eq!(status, 202);
    assert!(body.is_empty());
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("synthetic_response")
    );
}

#[tokio::test]
async fn aggregate_missing_session_header_returns_400() {
    // Unreachable upstream is fine: the missing-session check fires before any
    // upstream call.
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();

    // A request method (has an id) but no Mcp-Session-Id header.
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/list",
        "params": {}
    }));

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    // 400 (missing) is distinct from 404 (terminated/unknown) and the message
    // reflects the real cause rather than blaming the upstream.
    assert_eq!(status, 400);
    assert_eq!(body["id"], 5);
    assert_eq!(body["error"]["code"], -32600);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Missing"),
        "message should name the missing session header: {body}"
    );
}

async fn start_mcp_collision_survivor_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/one"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "one",
            "result": {
                "tools": [
                    { "name": "b.c", "inputSchema": { "type": "object" } },
                    { "name": "unique", "inputSchema": { "type": "object" } }
                ]
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/two"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "two",
            "result": {
                "tools": [
                    { "name": "c", "inputSchema": { "type": "object" } }
                ]
            }
        })))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn aggregate_tools_list_skips_collision_keeps_other_tools() {
    let server = start_mcp_collision_survivor_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &json!({
            "enabled": true,
            "mode": "aggregate_router",
            "endpoint": {"path": "/mcp"},
            "sessions": {"initialize_upstreams": "passthrough"},
            "discovery": {
                "aggregate_tools": true,
                "aggregate_resources": false,
                "aggregate_prompts": false,
                "namespace_separator": ".",
                "on_new_tool": "allow"
            },
            "servers": {
                "one": {
                    "upstream_url": format!("{}/one", server.uri()),
                    "namespace": "a",
                    "enabled": true,
                    "expose_tools": true,
                    "expose_resources": false,
                    "expose_prompts": false
                },
                "two": {
                    "upstream_url": format!("{}/two", server.uri()),
                    "namespace": "a.b",
                    "enabled": true,
                    "expose_tools": true,
                    "expose_resources": false,
                    "expose_prompts": false
                }
            },
            "policy": {"default_action": "allow"}
        }),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&plugin).await;

    // "a.b.c" collides (server one's "b.c" vs server two's "c") and is dropped
    // from both; the non-colliding "a.unique" survives — one bad name no longer
    // takes down the whole catalog.
    let names = aggregate_tool_names(&plugin, &session_id, 60).await;
    assert_eq!(names, vec!["a.unique"]);
}

#[tokio::test]
async fn aggregate_schema_changed_configured_tool_stays_hidden_until_reconfigured() {
    let server = start_mcp_schema_change_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["cache_ttl_seconds"] = json!(1);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["discovery"]["on_schema_change"] = json!("hide_until_configured");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    // Explicit per-tool allow — the case the prior retention check missed (it only
    // preserved the hidden state for tools that were NOT explicitly configured).
    config["policy"] = json!({
        "default_action": "deny",
        "tools": { "github.create_pr": { "action": "allow" } }
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    assert_eq!(
        aggregate_tool_names(&plugin, &session_id, 70).await,
        vec!["github.create_pr"]
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(
        aggregate_tool_names(&plugin, &session_id, 71)
            .await
            .is_empty(),
        "schema change should hide the explicitly-configured tool"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(
        aggregate_tool_names(&plugin, &session_id, 72)
            .await
            .is_empty(),
        "explicitly-configured tool must stay hidden after the schema-changed baseline, not re-enable"
    );
}

#[tokio::test]
async fn aggregate_routed_call_forwards_upstream_negotiated_protocol_version() {
    let server = start_mcp_negotiated_protocol_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["endpoint"]["protocol_versions"] = json!(["2025-11-25", "2025-06-18"]);
    config["discovery"]["aggregate_resources"] = json!(false);
    config["discovery"]["aggregate_prompts"] = json!(false);
    config["discovery"]["on_new_tool"] = json!("allow");
    config["servers"]["github"]["expose_resources"] = json!(false);
    config["servers"]["github"]["expose_prompts"] = json!(false);
    config["policy"] = json!({"default_action": "allow"});
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    // Downstream session negotiates 2025-11-25 (the initialize helper's version).
    let session_id = initialize(&plugin).await;
    // Discovery initializes the upstream, which negotiates 2025-06-18.
    assert_eq!(
        aggregate_tool_names(&plugin, &session_id, 80).await,
        vec!["github.versioned_tool"]
    );

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 81,
        "method": "tools/call",
        "params": { "name": "github.versioned_tool", "arguments": {} }
    }));
    headers.insert("mcp-session-id".to_string(), session_id);
    // Client sends the downstream-negotiated version; the gateway must replace it
    // with the upstream-negotiated one on the routed call.
    headers.insert("mcp-protocol-version".to_string(), "2025-11-25".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        headers.get("mcp-protocol-version").map(String::as_str),
        Some("2025-06-18")
    );
}

/// Catch-all upstream serving one tool and empty prompt/resource/template
/// families; the shared body doubles as an initialize/notification response.
async fn start_mcp_single_tool_server(tool_name: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "upstream",
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": { "name": "single-tool", "version": "1" },
                "tools": [
                    { "name": tool_name, "inputSchema": { "type": "object" } }
                ],
                "prompts": [],
                "resources": [],
                "resourceTemplates": []
            }
        })))
        .mount(&server)
        .await;
    server
}

fn multi_server_tools_config(github_url: &str, flaky_url: &str) -> Value {
    json!({
        "enabled": true,
        "mode": "aggregate_router",
        "endpoint": { "path": "/mcp", "protocol_versions": ["2025-11-25"] },
        "sessions": { "initialize_upstreams": "passthrough" },
        "discovery": {
            "aggregate_tools": true,
            "aggregate_resources": false,
            "aggregate_prompts": false,
            "namespace_separator": ".",
            "cache_ttl_seconds": 1,
            "on_new_tool": "allow"
        },
        "policy": { "default_action": "allow" },
        "servers": {
            "github": {
                "upstream_url": github_url,
                "namespace": "github",
                "enabled": true,
                "expose_tools": true
            },
            "flaky": {
                "upstream_url": flaky_url,
                "namespace": "flaky",
                "enabled": true,
                "expose_tools": true
            }
        }
    })
}

async fn tools_list_with_metadata(
    plugin: &Arc<dyn ferrum_edge::plugins::Plugin>,
    session_id: &str,
    request_id: i64,
) -> (u16, Value, ferrum_edge::plugins::RequestContext) {
    aggregate_request_with_metadata(plugin, session_id, request_id, "tools/list", json!({})).await
}

async fn aggregate_request_with_metadata(
    plugin: &Arc<dyn ferrum_edge::plugins::Plugin>,
    session_id: &str,
    request_id: i64,
    method_name: &str,
    params: Value,
) -> (u16, Value, ferrum_edge::plugins::RequestContext) {
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method_name,
        "params": params
    }));
    headers.insert("mcp-session-id".to_string(), session_id.to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(result);
    (status, body, ctx)
}

fn sorted_tool_names(body: &Value) -> Vec<String> {
    let mut names: Vec<String> = body["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list result missing tools array: {body}"))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

fn sorted_prompt_names(body: &Value) -> Vec<String> {
    let mut names: Vec<String> = body["result"]["prompts"]
        .as_array()
        .unwrap_or_else(|| panic!("prompts/list result missing prompts array: {body}"))
        .iter()
        .map(|prompt| prompt["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

fn sorted_resource_uris(body: &Value) -> Vec<String> {
    let mut uris: Vec<String> = body["result"]["resources"]
        .as_array()
        .unwrap_or_else(|| panic!("resources/list result missing resources array: {body}"))
        .iter()
        .map(|resource| resource["uri"].as_str().unwrap().to_string())
        .collect();
    uris.sort();
    uris
}

fn collision_family_config(
    one_url: &str,
    two_url: &str,
    aggregate_tools: bool,
    aggregate_prompts: bool,
    aggregate_resources: bool,
) -> Value {
    json!({
        "enabled": true,
        "mode": "aggregate_router",
        "endpoint": { "path": "/mcp", "protocol_versions": ["2025-11-25"] },
        "sessions": { "initialize_upstreams": "passthrough" },
        "discovery": {
            "aggregate_tools": aggregate_tools,
            "aggregate_prompts": aggregate_prompts,
            "aggregate_resources": aggregate_resources,
            "namespace_separator": ".",
            "cache_ttl_seconds": 1,
            "on_new_tool": "allow"
        },
        "policy": { "default_action": "allow" },
        "servers": {
            "one": {
                "upstream_url": one_url,
                "namespace": "a",
                "enabled": true,
                "expose_tools": aggregate_tools,
                "expose_prompts": aggregate_prompts,
                "expose_resources": aggregate_resources
            },
            "two": {
                "upstream_url": two_url,
                "namespace": "a.b",
                "enabled": true,
                "expose_tools": aggregate_tools,
                "expose_prompts": aggregate_prompts,
                "expose_resources": aggregate_resources
            }
        }
    })
}

fn single_server_family_config(
    upstream_url: &str,
    aggregate_tools: bool,
    aggregate_prompts: bool,
    aggregate_resources: bool,
) -> Value {
    json!({
        "enabled": true,
        "mode": "aggregate_router",
        "endpoint": { "path": "/mcp", "protocol_versions": ["2025-11-25"] },
        "sessions": { "initialize_upstreams": "passthrough" },
        "discovery": {
            "aggregate_tools": aggregate_tools,
            "aggregate_prompts": aggregate_prompts,
            "aggregate_resources": aggregate_resources,
            "namespace_separator": ".",
            "cache_ttl_seconds": 1,
            "on_new_tool": "allow"
        },
        "policy": { "default_action": "allow" },
        "servers": {
            "github": {
                "upstream_url": upstream_url,
                "namespace": "github",
                "enabled": true,
                "expose_tools": aggregate_tools,
                "expose_prompts": aggregate_prompts,
                "expose_resources": aggregate_resources
            }
        }
    })
}

#[tokio::test]
async fn aggregate_tools_family_outage_keeps_prompts_healthy_and_recovers_on_ttl() {
    let server = MockServer::start().await;
    let tool_requests = Arc::new(AtomicUsize::new(0));
    let tool_counter = Arc::clone(&tool_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(move |_: &wiremock::Request| {
            if tool_counter.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "tools",
                    "result": {"tools": [
                        {"name": "recovered_tool", "inputSchema": {"type": "object"}}
                    ]}
                }))
            }
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "prompts/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "prompts",
            "result": {"prompts": [{"name": "healthy_prompt"}]}
        })))
        .mount(&server)
        .await;
    let config = single_server_family_config(&format!("{}/mcp", server.uri()), true, true, false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (status, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 101).await;
    assert_eq!(status, 200);
    assert_eq!(body["error"]["code"], -32006);
    assert!(body["result"].is_null());
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("github:tools")
    );

    let (_, body, _) =
        aggregate_request_with_metadata(&plugin, &session_id, 102, "prompts/list", json!({})).await;
    assert_eq!(
        body["result"]["prompts"][0]["name"],
        "github.healthy_prompt"
    );

    // The failed family is cached as unavailable, not healthy-and-empty, and
    // does not hammer the upstream again before the normal refresh window.
    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 103).await;
    assert_eq!(body["error"]["code"], -32006);
    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        104,
        "tools/call",
        json!({"name": "github.missing", "arguments": {}}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32006);
    assert_eq!(tool_requests.load(Ordering::SeqCst), 1);

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 105).await;
    assert_eq!(sorted_tool_names(&body), vec!["github.recovered_tool"]);
    assert!(!ctx.metadata.contains_key("mcp.catalog_degraded"));
    assert_eq!(tool_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn aggregate_prompts_family_outage_keeps_tools_healthy() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "result": {"tools": [
                {"name": "healthy_tool", "inputSchema": {"type": "object"}}
            ]}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "prompts/list"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let config = single_server_family_config(&format!("{}/mcp", server.uri()), true, true, false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (_, body, ctx) =
        aggregate_request_with_metadata(&plugin, &session_id, 105, "prompts/list", json!({})).await;
    assert_eq!(body["error"]["code"], -32006);
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("github:prompts")
    );

    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 106).await;
    assert_eq!(sorted_tool_names(&body), vec!["github.healthy_tool"]);

    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        107,
        "prompts/get",
        json!({"name": "github.missing"}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32006);
}

#[tokio::test]
async fn aggregate_resources_family_outage_keeps_tools_and_templates_healthy() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "result": {"tools": [
                {"name": "healthy_tool", "inputSchema": {"type": "object"}}
            ]}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "resources/list"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "resources/templates/list"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "templates",
            "result": {"resourceTemplates": [
                {"uriTemplate": "file:///{path}", "name": "Healthy template"}
            ]}
        })))
        .mount(&server)
        .await;
    let config = single_server_family_config(&format!("{}/mcp", server.uri()), true, false, true);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (_, body, _) =
        aggregate_request_with_metadata(&plugin, &session_id, 108, "resources/list", json!({}))
            .await;
    assert_eq!(body["error"]["code"], -32006);

    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 109).await;
    assert_eq!(sorted_tool_names(&body), vec!["github.healthy_tool"]);

    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        110,
        "resources/templates/list",
        json!({}),
    )
    .await;
    let public_uri = body["result"]["resourceTemplates"][0]["uriTemplate"]
        .as_str()
        .expect("healthy template family must remain listable")
        .replace("{path}", "README.md");
    assert!(matches!(
        route_resource_uri(&plugin, &session_id, 111, &public_uri).await,
        PluginResult::Continue
    ));

    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        112,
        "resources/read",
        json!({"uri": "mcp://github/missing"}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32006);
}

#[tokio::test]
async fn aggregate_resource_templates_distinguish_never_loaded_from_last_good_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "result": {"tools": [
                {"name": "healthy_tool", "inputSchema": {"type": "object"}}
            ]}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "resources/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "resources",
            "result": {"resources": []}
        })))
        .mount(&server)
        .await;
    let template_requests = Arc::new(AtomicUsize::new(0));
    let template_counter = Arc::clone(&template_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "resources/templates/list"}),
        ))
        .respond_with(move |_: &wiremock::Request| {
            match template_counter.fetch_add(1, Ordering::SeqCst) {
                0 | 2 => ResponseTemplate::new(500),
                1 => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "templates-empty",
                    "result": {"resourceTemplates": []}
                })),
                _ => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "templates-recovered",
                    "result": {"resourceTemplates": [
                        {"uriTemplate": "file:///{path}", "name": "Recovered"}
                    ]}
                })),
            }
        })
        .mount(&server)
        .await;
    let config = single_server_family_config(&format!("{}/mcp", server.uri()), true, false, true);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    // No successful template list exists yet, so the initial complete failure
    // is unavailable rather than a successful empty catalog.
    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        113,
        "resources/templates/list",
        json!({}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32006);

    // Another family remains isolated and usable during that outage.
    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 114).await;
    assert_eq!(sorted_tool_names(&body), vec!["github.healthy_tool"]);

    // A successful empty list establishes last-good state. A later failure
    // serves that empty result stale instead of reverting to unavailable.
    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        115,
        "resources/templates/list",
        json!({}),
    )
    .await;
    assert_eq!(body["result"]["resourceTemplates"], json!([]));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        116,
        "resources/templates/list",
        json!({}),
    )
    .await;
    assert_eq!(body["result"]["resourceTemplates"], json!([]));
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("github:resource_templates")
    );

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        117,
        "resources/templates/list",
        json!({}),
    )
    .await;
    assert_eq!(
        body["result"]["resourceTemplates"].as_array().map(Vec::len),
        Some(1)
    );
    assert!(!ctx.metadata.contains_key("mcp.catalog_degraded"));
    assert_eq!(template_requests.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn aggregate_partial_upstream_transport_failure_keeps_healthy_upstreams_usable() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    // Nothing listens on discard port 9: every list request to this upstream
    // fails at the transport layer (connection refused).
    config["servers"]["jira"] = json!({
        "upstream_url": "http://127.0.0.1:9/mcp",
        "namespace": "jira",
        "enabled": true,
        "expose_tools": true,
        "expose_resources": true,
        "expose_prompts": true
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (status, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 90).await;
    assert_eq!(status, 200);
    assert!(
        body["error"].is_null(),
        "healthy tools must not 32006: {body}"
    );
    assert_eq!(sorted_tool_names(&body), vec!["github.create_pr"]);
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("jira:prompts,jira:resources,jira:tools")
    );

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 91,
        "method": "prompts/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id.clone());
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert_eq!(body["result"]["prompts"][0]["name"], "github.code_review");

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 92,
        "method": "resources/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id.clone());
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert_eq!(
        body["result"]["resources"].as_array().map(Vec::len),
        Some(1)
    );

    // The healthy upstream's tool stays callable during the outage.
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 93,
        "method": "tools/call",
        "params": { "name": "github.create_pr", "arguments": { "repo": "payments-api" } }
    }));
    headers.insert("mcp-session-id".to_string(), session_id);
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn aggregate_partial_upstream_non_2xx_failure_keeps_healthy_upstreams_usable() {
    let server = start_mcp_catalog_server().await;
    let failing = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&failing)
        .await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["servers"]["flaky"] = json!({
        "upstream_url": format!("{}/mcp", failing.uri()),
        "namespace": "flaky",
        "enabled": true,
        "expose_tools": true
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (status, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 94).await;
    assert_eq!(status, 200);
    assert!(
        body["error"].is_null(),
        "healthy tools must not 32006: {body}"
    );
    assert_eq!(sorted_tool_names(&body), vec!["github.create_pr"]);
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("flaky:tools")
    );
}

#[tokio::test]
async fn aggregate_partial_upstream_json_rpc_list_failure_keeps_healthy_upstreams_usable() {
    let server = start_mcp_catalog_server().await;
    let failing = start_mcp_error_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    config["servers"]["flaky"] = json!({
        "upstream_url": format!("{}/mcp", failing.uri()),
        "namespace": "flaky",
        "enabled": true,
        "expose_tools": true
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (status, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 95).await;
    assert_eq!(status, 200);
    assert!(
        body["error"].is_null(),
        "healthy tools must not 32006: {body}"
    );
    assert_eq!(sorted_tool_names(&body), vec!["github.create_pr"]);
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("flaky:tools")
    );
    // The failure was at the JSON-RPC layer: the upstream did answer tools/list.
    let requests = failing.received_requests().await.unwrap();
    assert!(requests.iter().any(|request| {
        request
            .body_json::<Value>()
            .ok()
            .and_then(|body| {
                body.get("method")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .as_deref()
            == Some("tools/list")
    }));
}

#[tokio::test]
async fn aggregate_failed_upstream_serves_last_good_entries_stale_and_recovers() {
    let github = start_mcp_single_tool_server("steady_tool").await;
    let flaky = MockServer::start().await;
    let list_requests = Arc::new(AtomicUsize::new(0));
    let response_counter = Arc::clone(&list_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(move |_: &wiremock::Request| {
            match response_counter.fetch_add(1, Ordering::SeqCst) {
                0 => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0", "id": "tools", "result": {"tools": [
                        {"name": "flaky_tool", "inputSchema": {"type": "object"}}
                    ]}
                })),
                1 => ResponseTemplate::new(500),
                _ => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0", "id": "tools", "result": {"tools": [
                        {"name": "replacement_tool", "inputSchema": {"type": "object"}}
                    ]}
                })),
            }
        })
        .mount(&flaky)
        .await;
    let config = multi_server_tools_config(
        &format!("{}/mcp", github.uri()),
        &format!("{}/mcp", flaky.uri()),
    );
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (_, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 96).await;
    assert_eq!(
        sorted_tool_names(&body),
        vec!["flaky.flaky_tool", "github.steady_tool"]
    );
    assert!(!ctx.metadata.contains_key("mcp.catalog_degraded"));

    // Outage: the failed upstream's last-good tool is served stale alongside
    // the healthy upstream's fresh entries and the degraded state is emitted.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 97).await;
    assert_eq!(
        sorted_tool_names(&body),
        vec!["flaky.flaky_tool", "github.steady_tool"]
    );
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("flaky:tools")
    );

    // Recovery: a successful refresh replaces the stale entries and clears the
    // degraded state.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 98).await;
    assert_eq!(
        sorted_tool_names(&body),
        vec!["flaky.replacement_tool", "github.steady_tool"]
    );
    assert!(!ctx.metadata.contains_key("mcp.catalog_degraded"));
    assert_eq!(list_requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn aggregate_serves_full_catalog_stale_when_all_upstreams_fail() {
    let flaky = MockServer::start().await;
    let list_requests = Arc::new(AtomicUsize::new(0));
    let response_counter = Arc::clone(&list_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(move |_: &wiremock::Request| {
            if response_counter.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0", "id": "tools", "result": {"tools": [
                        {"name": "only_tool", "inputSchema": {"type": "object"}}
                    ]}
                }))
            } else {
                ResponseTemplate::new(500)
            }
        })
        .mount(&flaky)
        .await;
    let mut config = multi_server_tools_config(
        &format!("{}/mcp", flaky.uri()),
        &format!("{}/mcp", flaky.uri()),
    );
    config["servers"]["flaky"]["enabled"] = json!(false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 99).await;
    assert_eq!(sorted_tool_names(&body), vec!["github.only_tool"]);

    // With last-good entries available, a refresh where every upstream fails
    // serves the previous catalog stale instead of erasing it with -32006.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (status, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 100).await;
    assert_eq!(status, 200);
    assert_eq!(sorted_tool_names(&body), vec!["github.only_tool"]);
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("github:tools")
    );
}

#[tokio::test]
async fn aggregate_name_collision_tombstones_survive_partial_failure() {
    let one = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "one-tools",
            "result": {"tools": [
                {"name": "b.c", "inputSchema": {"type": "object"}}
            ]}
        })))
        .mount(&one)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "prompts/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "one-prompts",
            "result": {"prompts": [{"name": "b.c"}]}
        })))
        .mount(&one)
        .await;

    let two = MockServer::start().await;
    let tool_requests = Arc::new(AtomicUsize::new(0));
    let tool_counter = Arc::clone(&tool_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(move |_: &wiremock::Request| {
            match tool_counter.fetch_add(1, Ordering::SeqCst) {
                0 => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "two-tools-collision",
                    "result": {"tools": [
                        {"name": "c", "inputSchema": {"type": "object"}}
                    ]}
                })),
                1 => ResponseTemplate::new(500),
                _ => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "two-tools-cleared",
                    "result": {"tools": []}
                })),
            }
        })
        .mount(&two)
        .await;
    let prompt_requests = Arc::new(AtomicUsize::new(0));
    let prompt_counter = Arc::clone(&prompt_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "prompts/list"})))
        .respond_with(move |_: &wiremock::Request| {
            match prompt_counter.fetch_add(1, Ordering::SeqCst) {
                0 => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "two-prompts-collision",
                    "result": {"prompts": [{"name": "c"}]}
                })),
                1 => ResponseTemplate::new(500),
                _ => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "two-prompts-cleared",
                    "result": {"prompts": []}
                })),
            }
        })
        .mount(&two)
        .await;

    let config = collision_family_config(
        &format!("{}/mcp", one.uri()),
        &format!("{}/mcp", two.uri()),
        true,
        true,
        false,
    );
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 118).await;
    assert_eq!(sorted_tool_names(&body), Vec::<String>::new());
    let (_, body, _) =
        aggregate_request_with_metadata(&plugin, &session_id, 119, "prompts/list", json!({})).await;
    assert_eq!(sorted_prompt_names(&body), Vec::<String>::new());

    // Both names were collision-suppressed and therefore absent from the old
    // published maps. When server two fails, its healthy peer must not become
    // the temporary winner for either catalog family.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 120).await;
    assert_eq!(sorted_tool_names(&body), Vec::<String>::new());
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("two:prompts,two:tools")
    );
    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        121,
        "tools/call",
        json!({"name": "a.b.c", "arguments": {}}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32003);
    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        122,
        "prompts/get",
        json!({"name": "a.b.c"}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32008);

    // Only a fully successful family refresh can clear the tombstones. Server
    // two now authoritatively reports empty lists, so server one's entries are
    // safe to publish and route again.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) =
        aggregate_request_with_metadata(&plugin, &session_id, 123, "prompts/list", json!({})).await;
    assert_eq!(sorted_prompt_names(&body), vec!["a.b.c"]);
    assert!(!ctx.metadata.contains_key("mcp.catalog_degraded"));
    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 124).await;
    assert_eq!(sorted_tool_names(&body), vec!["a.b.c"]);
    assert_eq!(tool_requests.load(Ordering::SeqCst), 3);
    assert_eq!(prompt_requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn aggregate_collision_tombstones_use_all_server_list_bound() {
    let generation = Arc::new(AtomicUsize::new(0));

    let one = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "one-tools",
            "result": {"tools": [
                {"name": "z.c", "inputSchema": {"type": "object"}}
            ]}
        })))
        .mount(&one)
        .await;

    let two = MockServer::start().await;
    let two_generation = Arc::clone(&generation);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(move |_: &wiremock::Request| {
            if two_generation.load(Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "two-tools",
                    "result": {"tools": [
                        {"name": "c", "inputSchema": {"type": "object"}}
                    ]}
                }))
            } else {
                ResponseTemplate::new(500)
            }
        })
        .mount(&two)
        .await;

    let three = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "three-tools",
            "result": {"tools": [
                {"name": "a.c", "inputSchema": {"type": "object"}}
            ]}
        })))
        .mount(&three)
        .await;

    let four = MockServer::start().await;
    let four_generation = Arc::clone(&generation);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(move |_: &wiremock::Request| {
            if four_generation.load(Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "four-tools",
                    "result": {"tools": [
                        {"name": "c", "inputSchema": {"type": "object"}}
                    ]}
                }))
            } else {
                ResponseTemplate::new(500)
            }
        })
        .mount(&four)
        .await;

    let config = json!({
        "enabled": true,
        "mode": "aggregate_router",
        "endpoint": {"path": "/mcp", "protocol_versions": ["2025-11-25"]},
        "sessions": {"initialize_upstreams": "passthrough"},
        "discovery": {
            "aggregate_tools": true,
            "aggregate_resources": false,
            "aggregate_prompts": false,
            "namespace_separator": ".",
            "cache_ttl_seconds": 1,
            "on_new_tool": "allow"
        },
        "policy": {"default_action": "allow"},
        "validation": {"max_catalog_items_per_list": 1},
        "servers": {
            "one": {
                "upstream_url": format!("{}/mcp", one.uri()),
                "namespace": "root",
                "enabled": true,
                "expose_tools": true
            },
            "two": {
                "upstream_url": format!("{}/mcp", two.uri()),
                "namespace": "root.z",
                "enabled": true,
                "expose_tools": true
            },
            "three": {
                "upstream_url": format!("{}/mcp", three.uri()),
                "namespace": "other",
                "enabled": true,
                "expose_tools": true
            },
            "four": {
                "upstream_url": format!("{}/mcp", four.uri()),
                "namespace": "other.a",
                "enabled": true,
                "expose_tools": true
            }
        }
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    // Two current-cycle collisions exceed one server's list limit, but not the
    // four-server aggregate bound. Neither may be selected away by lexical
    // order while all four lists are authoritative.
    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 130).await;
    assert_eq!(sorted_tool_names(&body), Vec::<String>::new());

    // The second member of each collision now fails. Both historical keys must
    // remain suppressed; capping at one and retaining the lexical first would
    // incorrectly republish root.z.c from the healthy server. Mock behavior is
    // generation-controlled, so an extra TTL refresh between list and call
    // assertions can only replay this same degraded state.
    generation.store(1, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 131).await;
    assert_eq!(sorted_tool_names(&body), Vec::<String>::new());
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("four:tools,two:tools")
    );
    for (request_id, public_name) in [(132, "other.a.c"), (133, "root.z.c")] {
        let (_, body, _) = aggregate_request_with_metadata(
            &plugin,
            &session_id,
            request_id,
            "tools/call",
            json!({"name": public_name, "arguments": {}}),
        )
        .await;
        assert_eq!(body["error"]["code"], -32003);
    }
}

#[tokio::test]
async fn aggregate_collision_tombstone_overflow_fails_closed_until_authoritative_refresh() {
    let generation = Arc::new(AtomicUsize::new(0));

    let one = MockServer::start().await;
    let one_generation = Arc::clone(&generation);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(move |_: &wiremock::Request| {
            let refresh_generation = one_generation.load(Ordering::SeqCst);
            let name = match refresh_generation {
                0..=3 => format!("b.collision_{refresh_generation}"),
                4 => "b.collision_0".to_string(),
                _ => "safe".to_string(),
            };
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": "one-tools",
                "result": {"tools": [
                    {"name": name, "inputSchema": {"type": "object"}}
                ]}
            }))
        })
        .mount(&one)
        .await;

    let two = MockServer::start().await;
    let two_generation = Arc::clone(&generation);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(move |_: &wiremock::Request| {
            let refresh_generation = two_generation.load(Ordering::SeqCst);
            let tools = if refresh_generation < 4 {
                json!([{
                    "name": format!("collision_{refresh_generation}"),
                    "inputSchema": {"type": "object"}
                }])
            } else {
                json!([])
            };
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": "two-tools",
                "result": {"tools": tools}
            }))
        })
        .mount(&two)
        .await;

    let guard = MockServer::start().await;
    let guard_generation = Arc::clone(&generation);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(move |_: &wiremock::Request| {
            if guard_generation.load(Ordering::SeqCst) <= 4 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "guard-tools",
                    "result": {"tools": []}
                }))
            }
        })
        .mount(&guard)
        .await;

    let config = json!({
        "enabled": true,
        "mode": "aggregate_router",
        "endpoint": {"path": "/mcp", "protocol_versions": ["2025-11-25"]},
        "sessions": {"initialize_upstreams": "passthrough"},
        "discovery": {
            "aggregate_tools": true,
            "aggregate_resources": false,
            "aggregate_prompts": false,
            "namespace_separator": ".",
            "cache_ttl_seconds": 1,
            "on_new_tool": "allow"
        },
        "policy": {"default_action": "allow"},
        "validation": {"max_catalog_items_per_list": 1},
        "servers": {
            "one": {
                "upstream_url": format!("{}/mcp", one.uri()),
                "namespace": "a",
                "enabled": true,
                "expose_tools": true
            },
            "two": {
                "upstream_url": format!("{}/mcp", two.uri()),
                "namespace": "a.b",
                "enabled": true,
                "expose_tools": true
            },
            "guard": {
                "upstream_url": format!("{}/mcp", guard.uri()),
                "namespace": "guard",
                "enabled": true,
                "expose_tools": true
            }
        }
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    // Three attempted lists with a one-item per-list limit permit exactly
    // three retained collision keys. Repeated degraded refreshes reach that
    // cap without selecting between current and historical collisions. Each
    // mock response depends on the explicit generation rather than request
    // count, so scheduler stalls cannot advance the scenario unexpectedly.
    for (request_id, refresh_generation) in [(134, 0), (135, 1), (136, 2)] {
        if refresh_generation != 0 {
            generation.store(refresh_generation, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        }
        let (_, body, ctx) = tools_list_with_metadata(&plugin, &session_id, request_id).await;
        assert_eq!(sorted_tool_names(&body), Vec::<String>::new());
        assert_eq!(
            ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
            Some("guard:tools")
        );
    }
    for (request_id, public_name) in [(137, "a.b.collision_0"), (138, "a.b.collision_2")] {
        let (_, body, _) = aggregate_request_with_metadata(
            &plugin,
            &session_id,
            request_id,
            "tools/call",
            json!({"name": public_name, "arguments": {}}),
        )
        .await;
        assert_eq!(body["error"]["code"], -32003);
    }

    // The fourth distinct degraded collision exceeds the aggregate bound. No
    // lexical/current/history subset is retained: the entire tools family is
    // unavailable, so neither list nor route lookup can resurrect a winner.
    generation.store(3, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 139).await;
    assert_eq!(body["error"]["code"], -32006);
    assert_eq!(body["error"]["data"]["gateway"], "mcp_gateway");
    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        140,
        "tools/call",
        json!({"name": "a.b.collision_3", "arguments": {}}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32006);

    // On another degraded refresh, one upstream replays a previously
    // suppressed name while the guard remains unavailable. The sticky
    // overflow bit must keep both discovery and dispatch failed closed.
    generation.store(4, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, _) = tools_list_with_metadata(&plugin, &session_id, 141).await;
    assert_eq!(body["error"]["code"], -32006);
    assert_eq!(body["error"]["data"]["gateway"], "mcp_gateway");
    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        142,
        "tools/call",
        json!({"name": "a.b.collision_0", "arguments": {}}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32006);

    // A fully authoritative refresh can discard the uncertain history and
    // publish only the current, non-colliding catalog.
    generation.store(5, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) = tools_list_with_metadata(&plugin, &session_id, 143).await;
    assert_eq!(sorted_tool_names(&body), vec!["a.safe"]);
    assert!(!ctx.metadata.contains_key("mcp.catalog_degraded"));

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 144,
        "method": "tools/call",
        "params": {"name": "a.safe", "arguments": {}}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn aggregate_resource_collision_tombstone_requires_authoritative_refresh() {
    let one = MockServer::start().await;
    let one_resource_requests = Arc::new(AtomicUsize::new(0));
    let one_resource_counter = Arc::clone(&one_resource_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "resources/list"})))
        .respond_with(move |_: &wiremock::Request| {
            match one_resource_counter.fetch_add(1, Ordering::SeqCst) {
                0 => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "one-resources-collision",
                    "result": {"resources": [
                        {"uri": "file:///shared", "name": "First"},
                        {"uri": "file:///shared", "name": "Duplicate"}
                    ]}
                })),
                1 => ResponseTemplate::new(500),
                _ => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "one-resources-single",
                    "result": {"resources": [
                        {"uri": "file:///shared", "name": "Resolved"}
                    ]}
                })),
            }
        })
        .mount(&one)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "resources/templates/list"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "one-templates",
            "result": {"resourceTemplates": []}
        })))
        .mount(&one)
        .await;

    let two = MockServer::start().await;
    let two_resource_requests = Arc::new(AtomicUsize::new(0));
    let two_resource_counter = Arc::clone(&two_resource_requests);
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "resources/list"})))
        .respond_with(move |_: &wiremock::Request| {
            match two_resource_counter.fetch_add(1, Ordering::SeqCst) {
                2 => ResponseTemplate::new(500),
                _ => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": "two-resources",
                    "result": {"resources": [
                        {"uri": "file:///other", "name": "Other"}
                    ]}
                })),
            }
        })
        .mount(&two)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(
            json!({"method": "resources/templates/list"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "two-templates",
            "result": {"resourceTemplates": []}
        })))
        .mount(&two)
        .await;

    let config = collision_family_config(
        &format!("{}/mcp", one.uri()),
        &format!("{}/mcp", two.uri()),
        false,
        false,
        true,
    );
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let other_uri = "mcp://two/file%3A%2F%2F%2Fother";
    let shared_uri = "mcp://one/file%3A%2F%2F%2Fshared";

    let (_, body, _) =
        aggregate_request_with_metadata(&plugin, &session_id, 125, "resources/list", json!({}))
            .await;
    assert_eq!(sorted_resource_uris(&body), vec![other_uri]);

    // The colliding server fails while the other server succeeds. The old
    // resource tombstone must survive even though its entries are absent from
    // the published map.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) =
        aggregate_request_with_metadata(&plugin, &session_id, 126, "resources/list", json!({}))
            .await;
    assert_eq!(sorted_resource_uris(&body), vec![other_uri]);
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("one:resources")
    );

    // On the next pass the former collision source succeeds with one entry,
    // but the peer fails. That partial refresh is still not authoritative, so
    // it cannot clear the prior tombstone or make the shared URI routable.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) =
        aggregate_request_with_metadata(&plugin, &session_id, 127, "resources/list", json!({}))
            .await;
    assert_eq!(sorted_resource_uris(&body), vec![other_uri]);
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("two:resources")
    );
    let (_, body, _) = aggregate_request_with_metadata(
        &plugin,
        &session_id,
        128,
        "resources/read",
        json!({"uri": shared_uri}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32007);

    // Both servers now list successfully, authoritatively proving that the
    // duplicate disappeared and allowing the formerly suppressed URI back.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, body, ctx) =
        aggregate_request_with_metadata(&plugin, &session_id, 129, "resources/list", json!({}))
            .await;
    assert_eq!(sorted_resource_uris(&body), vec![shared_uri, other_uri]);
    assert!(!ctx.metadata.contains_key("mcp.catalog_degraded"));
    assert_eq!(one_resource_requests.load(Ordering::SeqCst), 4);
    assert_eq!(two_resource_requests.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn aggregate_initialize_negotiates_unsupported_newer_version_to_supported() {
    let server = start_mcp_catalog_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-03-01",
            "capabilities": {},
            "clientInfo": { "name": "unit-test", "version": "1" }
        }
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, response_headers) = reject_json(result);
    assert_eq!(status, 200);
    assert!(
        body["error"].is_null(),
        "negotiation must not error: {body}"
    );
    assert_eq!(body["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        ctx.metadata
            .get("mcp.protocol_version_negotiated")
            .map(String::as_str),
        Some("2025-11-25")
    );
    let session_id = response_headers
        .get("mcp-session-id")
        .expect("negotiated initialize must mint a session")
        .clone();

    // The session carries the negotiated version: post-initialize requests on
    // it succeed and the lazily initialized upstream receives it.
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id.clone());
    headers.insert("mcp-protocol-version".to_string(), "2025-11-25".to_string());
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert_eq!(sorted_tool_names(&body), vec!["github.create_pr"]);
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().any(|request| {
        request.body_json::<Value>().ok().is_some_and(|body| {
            body.get("method").and_then(Value::as_str) == Some("initialize")
                && body
                    .get("params")
                    .and_then(|params| params.get("protocolVersion"))
                    .and_then(Value::as_str)
                    == Some("2025-11-25")
        })
    }));

    // Post-initialize header validation stays fail-closed for the version the
    // client originally requested.
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-session-id".to_string(), session_id);
    headers.insert("mcp-protocol-version".to_string(), "2026-03-01".to_string());
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 400);
    assert_eq!(body["error"]["message"], "Unsupported MCP protocol version");
}

#[tokio::test]
async fn aggregate_initialize_negotiates_unsupported_older_version_to_supported() {
    let server = start_mcp_catalog_server().await;
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", server.uri())),
    )
    .unwrap()
    .unwrap();

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "unit-test", "version": "1" }
        }
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, response_headers) = reject_json(result);
    assert_eq!(status, 200);
    assert!(
        body["error"].is_null(),
        "negotiation must not error: {body}"
    );
    assert_eq!(body["result"]["protocolVersion"], "2025-11-25");
    assert!(response_headers.contains_key("mcp-session-id"));
}

#[tokio::test]
async fn aggregate_initialize_echoes_requested_supported_version() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["endpoint"]["protocol_versions"] = json!(["2025-11-25", "2025-06-18"]);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();

    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "unit-test", "version": "1" }
        }
    }));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, response_headers) = reject_json(result);
    assert_eq!(status, 200);
    // A supported requested version is echoed, not replaced by the preferred one.
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
    assert!(!ctx.metadata.contains_key("mcp.protocol_version_negotiated"));
    assert!(response_headers.contains_key("mcp-session-id"));
}

/// Drive production `ai_tool_governor` then `mcp_gateway` in real priority order
/// on the same MCP `tools/call` context (#2260 composition acceptance).
///
/// Covers omitted `params.arguments` and explicit `arguments: {}` through both
/// layers for permissive object schemas and for schemas/required_args that need
/// a missing property. Provider-response non-normalization remains covered by
/// the direct governor unit test.
#[tokio::test]
async fn composed_governor_and_mcp_gateway_normalize_omitted_mcp_arguments() {
    const {
        assert!(
            priority::AI_TOOL_GOVERNOR < priority::MCP_GATEWAY,
            "composition must run ai_tool_governor before mcp_gateway"
        );
    }

    // --- Permissive object schema: omitted and {} accepted by both layers ---
    let server = start_mcp_zero_arg_tool_server().await;
    let mut mcp_config = aggregate_config(&format!("{}/mcp", server.uri()));
    mcp_config["sessions"] = json!({"initialize_upstreams": "passthrough"});
    mcp_config["discovery"]["aggregate_resources"] = json!(false);
    mcp_config["discovery"]["aggregate_prompts"] = json!(false);
    mcp_config["discovery"]["on_new_tool"] = json!("allow");
    mcp_config["servers"]["github"]["expose_resources"] = json!(false);
    mcp_config["servers"]["github"]["expose_prompts"] = json!(false);
    mcp_config["policy"] = json!({"default_action": "allow"});
    let mcp = create_plugin("mcp_gateway", &mcp_config).unwrap().unwrap();
    assert_eq!(mcp.priority(), priority::MCP_GATEWAY);

    let governor = Arc::new(
        AiToolGovernor::new(
            &json!({
                "default_action": "deny",
                "tools": {
                    "github.ping_tool": {
                        "action": "allow",
                        "json_schema": {
                            "type": "object",
                            "additionalProperties": false
                        }
                    }
                },
                "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
            }),
            PluginHttpClient::default(),
        )
        .expect("permissive governor"),
    );
    assert_eq!(governor.priority(), priority::AI_TOOL_GOVERNOR);

    let session_id = initialize(&mcp).await;
    let _ = aggregate_tool_names(&mcp, &session_id, 28).await;

    for (request_id, params) in [
        (29i64, json!({ "name": "github.ping_tool" })),
        (
            30i64,
            json!({ "name": "github.ping_tool", "arguments": {} }),
        ),
    ] {
        let (mut ctx, mut headers) = mcp_ctx(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": params
        }));
        headers.insert("mcp-session-id".to_string(), session_id.clone());

        let governor_result = governor.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(governor_result, PluginResult::Continue),
            "governor must accept permissive zero-arg form {request_id}: {governor_result:?}"
        );
        let mcp_result = mcp.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(mcp_result, PluginResult::Continue),
            "mcp_gateway must accept permissive zero-arg form {request_id}: {mcp_result:?}"
        );
        assert_eq!(
            ctx.metadata
                .get("mcp.schema_validation")
                .map(String::as_str),
            Some("pass"),
            "composed permissive call {request_id} must pass mcp schema validation"
        );
    }

    // --- Required property: both layers reject omitted and {} ---
    let required_governor = Arc::new(
        AiToolGovernor::new(
            &json!({
                "default_action": "deny",
                "tools": {
                    "github.ping_tool": {
                        "action": "allow",
                        "required_args": ["repo"],
                        "json_schema": {
                            "type": "object",
                            "required": ["repo"],
                            "additionalProperties": false,
                            "properties": { "repo": { "type": "string" } }
                        }
                    }
                },
                "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
            }),
            PluginHttpClient::default(),
        )
        .expect("required-args governor"),
    );

    for (request_id, params) in [
        (31i64, json!({ "name": "github.ping_tool" })),
        (
            32i64,
            json!({ "name": "github.ping_tool", "arguments": {} }),
        ),
    ] {
        let (mut ctx, mut headers) = mcp_ctx(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": params
        }));
        headers.insert("mcp-session-id".to_string(), session_id.clone());

        let governor_result = required_governor.before_proxy(&mut ctx, &mut headers).await;
        let (status, _, _) = reject_raw(governor_result);
        assert_eq!(
            status, 403,
            "governor must reject missing required property for form {request_id}"
        );
        // Enforce-mode composition stops before mcp_gateway once the earlier
        // priority plugin rejects; parity for the gateway's required-schema
        // path is covered below with an allowlisted governor.
    }

    // Governor allows; mcp_gateway required inputSchema rejects both forms.
    let catalog = start_mcp_catalog_server().await;
    let mcp_required = create_plugin(
        "mcp_gateway",
        &aggregate_config(&format!("{}/mcp", catalog.uri())),
    )
    .unwrap()
    .unwrap();
    let allow_governor = Arc::new(
        AiToolGovernor::new(
            &json!({
                "default_action": "deny",
                "tools": {
                    "github.create_pr": { "action": "allow" }
                },
                "inspect": { "mcp_tool_calls": true, "response_tool_calls": false }
            }),
            PluginHttpClient::default(),
        )
        .expect("allow governor"),
    );
    let required_session = initialize(&mcp_required).await;
    let _ = aggregate_tool_names(&mcp_required, &required_session, 2).await;

    for (request_id, params) in [
        (4i64, json!({ "name": "github.create_pr" })),
        (5i64, json!({ "name": "github.create_pr", "arguments": {} })),
    ] {
        let (mut ctx, mut headers) = mcp_ctx(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": params
        }));
        headers.insert("mcp-session-id".to_string(), required_session.clone());

        assert!(
            matches!(
                allow_governor.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "allowlisted governor must continue for form {request_id}"
        );
        let mcp_result = mcp_required.before_proxy(&mut ctx, &mut headers).await;
        let (status, body, _) = reject_json(mcp_result);
        assert_eq!(status, 200);
        assert_eq!(body["id"], request_id);
        assert_eq!(body["error"]["code"], -32602);
        assert_eq!(
            ctx.metadata
                .get("mcp.schema_validation")
                .map(String::as_str),
            Some("fail"),
            "composed required-schema call {request_id} must fail mcp validation"
        );
    }
}

/// Cross-plugin aggregate-router regression for #2259: governor policy keys stay
/// on the public namespaced tool identity across `mcp_gateway`'s trusted
/// public→upstream rewrite.
///
/// Drives real `ai_tool_governor` then `mcp_gateway` in priority order with
/// `default_action: deny`, only `github.create_pr` allowed, upstream name
/// `create_pr`, through before_proxy → transform → final-body recheck. Covers
/// both metadata-observability settings and fail-closed cases (unrelated name
/// change; argument policy still enforced on the rewritten body).
#[tokio::test]
async fn composed_governor_keeps_public_policy_name_across_aggregate_tool_rewrite() {
    const {
        assert!(
            priority::AI_TOOL_GOVERNOR < priority::MCP_GATEWAY,
            "composition must run ai_tool_governor before mcp_gateway"
        );
    }

    for emit_metadata in [true, false] {
        let server = start_mcp_catalog_server().await;
        let mut mcp_config = aggregate_config(&format!("{}/mcp", server.uri()));
        mcp_config["observability"] = json!({ "emit_metadata": emit_metadata });
        let mcp = create_plugin("mcp_gateway", &mcp_config).unwrap().unwrap();
        assert_eq!(mcp.priority(), priority::MCP_GATEWAY);

        let governor = Arc::new(
            AiToolGovernor::new(
                &json!({
                    "default_action": "deny",
                    "tools": {
                        "github.create_pr": {
                            "action": "allow",
                            "required_args": ["repo"]
                        }
                    },
                    "inspect": { "mcp_tool_calls": true, "response_tool_calls": false },
                    "observability": { "emit_metadata": emit_metadata }
                }),
                PluginHttpClient::default(),
            )
            .expect("governor with public-name allowlist"),
        );
        assert_eq!(governor.priority(), priority::AI_TOOL_GOVERNOR);

        let session_id = initialize(&mcp).await;
        let (mut list_ctx, mut list_headers) = mcp_ctx(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }));
        list_headers.insert("mcp-session-id".to_string(), session_id.clone());
        let _ = mcp.before_proxy(&mut list_ctx, &mut list_headers).await;

        let public_body = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "github.create_pr",
                "arguments": { "repo": "payments-api" }
            }
        });
        let (mut ctx, mut headers) = mcp_ctx(public_body.clone());
        headers.insert("mcp-session-id".to_string(), session_id.clone());

        assert!(
            matches!(
                governor.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "initial governor pass must allow public name (emit_metadata={emit_metadata})"
        );
        assert!(
            matches!(
                mcp.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "mcp_gateway must route the allowlisted public tool (emit_metadata={emit_metadata})"
        );
        if emit_metadata {
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
        } else {
            assert!(
                !ctx.metadata.contains_key("mcp.public_tool_name"),
                "observability.emit_metadata=false must not publish public tool metadata"
            );
            assert!(
                !ctx.metadata.contains_key("mcp.upstream_tool_name"),
                "observability.emit_metadata=false must not publish upstream tool metadata"
            );
        }

        let rewritten = mcp
            .transform_request_body_with_context(
                &mut ctx,
                serde_json::to_vec(&public_body).unwrap().as_slice(),
                Some("application/json"),
                &headers,
            )
            .await
            .expect("aggregate router must rewrite the public tool name");
        let rewritten_json: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(
            rewritten_json["params"]["name"], "create_pr",
            "backend-visible name must be the upstream alias"
        );
        // Rewrite staging metadata is consumed by the transform; trust for the
        // governor recheck lives on the private request-context mapping.
        assert!(!ctx.metadata.contains_key("mcp.needs_request_rewrite"));
        assert!(!ctx.metadata.contains_key("mcp.rewrite.public_value"));
        assert!(!ctx.metadata.contains_key("mcp.rewrite.upstream_value"));

        assert!(
            matches!(
                governor
                    .on_final_request_body_with_context(&mut ctx, &headers, &rewritten)
                    .await,
                PluginResult::Continue
            ),
            "final governor recheck must allow under the public policy name after trusted rewrite (emit_metadata={emit_metadata})"
        );

        // Unrelated name change after the trusted rewrite must fail closed.
        let mut hijacked = rewritten_json.clone();
        hijacked["params"]["name"] = json!("create_pr_hijacked");
        let hijacked_bytes = serde_json::to_vec(&hijacked).unwrap();
        let (status, body, _) = reject_raw(
            governor
                .on_final_request_body_with_context(&mut ctx, &headers, &hijacked_bytes)
                .await,
        );
        assert_eq!(
            status, 403,
            "unrelated final name must deny under default_action=deny (emit_metadata={emit_metadata})"
        );
        assert!(
            body.contains("deny") || body.contains("ai_tool_governor"),
            "denial body should identify the governor decision: {body}"
        );

        // Final arguments are still re-evaluated under the public policy.
        let mut missing_repo = rewritten_json.clone();
        missing_repo["params"]["arguments"] = json!({});
        let missing_bytes = serde_json::to_vec(&missing_repo).unwrap();
        // Fresh request context so the prior denial metadata does not mask the
        // argument recheck: re-stage the same trusted mapping the gateway would
        // leave after a successful rewrite.
        let (mut arg_ctx, mut arg_headers) = mcp_ctx(public_body.clone());
        arg_headers.insert("mcp-session-id".to_string(), session_id.clone());
        assert!(matches!(
            governor.before_proxy(&mut arg_ctx, &mut arg_headers).await,
            PluginResult::Continue
        ));
        assert!(matches!(
            mcp.before_proxy(&mut arg_ctx, &mut arg_headers).await,
            PluginResult::Continue
        ));
        let _ = mcp
            .transform_request_body_with_context(
                &mut arg_ctx,
                serde_json::to_vec(&public_body).unwrap().as_slice(),
                Some("application/json"),
                &arg_headers,
            )
            .await
            .expect("rewrite for argument recheck");
        let (arg_status, _, _) = reject_raw(
            governor
                .on_final_request_body_with_context(&mut arg_ctx, &arg_headers, &missing_bytes)
                .await,
        );
        assert_eq!(
            arg_status, 403,
            "final arguments must still be governed under the public policy (emit_metadata={emit_metadata})"
        );
    }
}

#[tokio::test]
async fn aggregate_batch_empty_is_invalid_request() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert!(
        body.is_object(),
        "empty batch must yield a single Response object"
    );
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "Invalid Request");
}

#[tokio::test]
async fn aggregate_batch_oversized_item_count_is_rejected() {
    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["validation"] = json!({ "max_batch_items": 1 });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert!(body.is_object());
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "Invalid Request");
    let rendered = body.to_string();
    assert!(
        !rendered.contains("ping"),
        "admission errors must not reflect attacker method names: {rendered}"
    );
}

#[tokio::test]
async fn aggregate_batch_oversized_member_is_rejected_without_dropping_valid_sibling() {
    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["validation"] = json!({
        "max_batch_items": 4,
        "max_batch_bytes": 4096,
        "max_batch_item_bytes": 128
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": "too-large",
            "method": "ping",
            "params": { "padding": "x".repeat(512) }
        },
        { "jsonrpc": "2.0", "id": "valid", "method": "ping", "params": {} }
    ]));

    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("per-item admission must preserve valid siblings");
    assert_eq!(responses.len(), 2);
    // The oversized member is refused on its raw wire slice, before it is
    // materialized, so its id is never read and never echoed.
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(
        !body.to_string().contains("too-large"),
        "an oversized member's id must not be reflected: {body}"
    );
    assert_eq!(responses[1]["id"], "valid");
    assert!(responses[1].get("result").is_some());
}

// --- Raw wire-byte per-member admission -----------------------------------
//
// `validation.max_batch_item_bytes` is a *wire*-byte cap: it is measured on the
// member's exact raw JSON slice before that member is deserialized. The helpers
// below build members whose raw representation is far larger than the
// normalized reserialization a parse-then-measure implementation would compare
// against, so each test fails closed only if the cap really is a wire cap.

/// Exact batch framing: `[` + members joined by a single `,` + `]`. No
/// whitespace or padding between members, so a byte-exact per-member assertion
/// can never be satisfied (or defeated) by array separators.
fn raw_batch(members: &[&str]) -> Vec<u8> {
    format!("[{}]", members.join(",")).into_bytes()
}

fn canonical_member(id: &str) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "ping",
        "params": {}
    }))
    .unwrap()
}

/// A `ping` member whose only excess is internal whitespace after the opening
/// brace. Normalized reserialization drops every one of those bytes.
fn whitespace_inflated_member(id: &str, padding: usize) -> String {
    let canonical = canonical_member(id);
    format!("{{{}{}", " ".repeat(padding), &canonical[1..])
}

/// A `ping` member padded with `\/` escapes: two wire bytes each that
/// serde_json renders back as a single `/`.
fn escape_inflated_member(id: &str, escapes: usize) -> String {
    let mut member = String::new();
    member.push_str("{\"jsonrpc\":\"2.0\",\"id\":\"");
    member.push_str(id);
    member.push_str("\",\"method\":\"ping\",\"params\":{\"p\":\"");
    member.push_str(&"\\/".repeat(escapes));
    member.push_str("\"}}");
    member
}

/// A `ping` member carrying an attacker-sized id.
fn oversized_id_member(id_bytes: usize) -> String {
    let mut member = String::new();
    member.push_str("{\"jsonrpc\":\"2.0\",\"method\":\"ping\",");
    member.push_str("\"id\":\"");
    member.push_str(&"A".repeat(id_bytes));
    member.push_str("\"}");
    member
}

/// Bytes a parse-then-measure implementation would have compared against.
fn normalized_len(raw: &str) -> usize {
    let value: Value = serde_json::from_str(raw).unwrap();
    serde_json::to_vec(&value).unwrap().len()
}

fn batch_validation(item_bytes: usize) -> Value {
    json!({
        "max_batch_items": 8,
        "max_batch_bytes": 65536,
        "max_batch_item_bytes": item_bytes
    })
}

const NOTIFICATION_MEMBER: &str =
    r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;

#[tokio::test]
async fn aggregate_batch_item_cap_counts_raw_whitespace_bytes() {
    let oversized = whitespace_inflated_member("padded", 512);
    let sibling = canonical_member("valid");
    let item_cap = normalized_len(&oversized) + 32;
    assert!(
        oversized.len() > item_cap,
        "the raw member must exceed the cap on the wire"
    );
    assert!(
        normalized_len(&oversized) <= item_cap,
        "a normalized reserialization of the same member must fit under the cap"
    );

    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["validation"] = batch_validation(item_cap);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let batch = raw_batch(&[oversized.as_str(), NOTIFICATION_MEMBER, sibling.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);

    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("per-item admission must preserve valid siblings");
    assert_eq!(
        responses.len(),
        2,
        "the notification member must not gain a response: {body}"
    );
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(
        !body.to_string().contains("padded"),
        "an unadmitted member's id must not be reflected: {body}"
    );
    assert_eq!(responses[1]["id"], "valid");
    assert!(responses[1].get("result").is_some());
}

#[tokio::test]
async fn transparent_batch_item_cap_counts_raw_whitespace_bytes() {
    let oversized = whitespace_inflated_member("padded", 512);
    let sibling = canonical_member("valid");
    let item_cap = normalized_len(&oversized) + 32;
    assert!(oversized.len() > item_cap);
    assert!(normalized_len(&oversized) <= item_cap);

    let mut config = transparent_config("http://github-mcp.example:8080/mcp");
    config["validation"] = batch_validation(item_cap);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let batch = raw_batch(&[oversized.as_str(), NOTIFICATION_MEMBER, sibling.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);

    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("an inadmissible member must fail the batch closed");
    assert_eq!(
        responses.len(),
        2,
        "the notification member must not gain a response: {body}"
    );
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(!body.to_string().contains("padded"));
    assert_eq!(responses[1]["id"], "valid");
    assert_eq!(responses[1]["error"]["code"], -32600);
    assert!(
        ctx.route_override_backend_host.is_none(),
        "an inadmissible member must not be forwarded upstream"
    );
}

#[tokio::test]
async fn aggregate_batch_item_cap_counts_raw_escape_bytes() {
    let oversized = escape_inflated_member("escaped", 400);
    let sibling = canonical_member("valid");
    let item_cap = normalized_len(&oversized) + 32;
    assert!(
        oversized.len() > item_cap,
        "escape sequences must be measured as written on the wire"
    );
    assert!(normalized_len(&oversized) <= item_cap);

    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["validation"] = batch_validation(item_cap);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let batch = raw_batch(&[oversized.as_str(), sibling.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);

    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().expect("valid siblings must survive");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(!body.to_string().contains("escaped"));
    assert_eq!(responses[1]["id"], "valid");
    assert!(responses[1].get("result").is_some());
}

#[tokio::test]
async fn transparent_batch_item_cap_counts_raw_escape_bytes() {
    let oversized = escape_inflated_member("escaped", 400);
    let sibling = canonical_member("valid");
    let item_cap = normalized_len(&oversized) + 32;
    assert!(oversized.len() > item_cap);
    assert!(normalized_len(&oversized) <= item_cap);

    let mut config = transparent_config("http://github-mcp.example:8080/mcp");
    config["validation"] = batch_validation(item_cap);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let batch = raw_batch(&[oversized.as_str(), sibling.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);

    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().expect("per-item error array");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(!body.to_string().contains("escaped"));
    assert_eq!(responses[1]["id"], "valid");
    assert!(ctx.route_override_backend_host.is_none());
}

#[tokio::test]
async fn aggregate_batch_oversized_member_id_is_never_echoed() {
    let oversized = oversized_id_member(4096);
    let sibling = canonical_member("valid");
    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["validation"] = batch_validation(256);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let batch = raw_batch(&[oversized.as_str(), sibling.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);

    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let rendered = body.to_string();
    let responses = body.as_array().expect("valid siblings must survive");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(
        !rendered.contains("AAAA"),
        "an oversized id must never be materialized into the response"
    );
    assert!(
        rendered.len() < oversized.len(),
        "the bounded per-item error must be smaller than the refused member"
    );
    assert_eq!(responses[1]["id"], "valid");
    assert!(responses[1].get("result").is_some());
}

#[tokio::test]
async fn transparent_batch_oversized_member_id_is_never_echoed() {
    let oversized = oversized_id_member(4096);
    let sibling = canonical_member("valid");
    let mut config = transparent_config("http://github-mcp.example:8080/mcp");
    config["validation"] = batch_validation(256);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let batch = raw_batch(&[oversized.as_str(), sibling.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);

    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let rendered = body.to_string();
    let responses = body.as_array().expect("per-item error array");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(!rendered.contains("AAAA"));
    assert_eq!(responses[1]["id"], "valid");
    assert!(ctx.route_override_backend_host.is_none());
}

#[tokio::test]
async fn aggregate_batch_item_cap_boundary_is_exact_on_raw_bytes() {
    let member = canonical_member("boundary");
    // Single-member batches: the only framing bytes are the outer brackets, so
    // the assertion cannot be blurred by separators or inter-member padding.
    let item_cap = member.len();

    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["validation"] = batch_validation(item_cap);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();

    let batch = raw_batch(&[member.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().expect("at-limit member is admitted");
    assert_eq!(responses[0]["id"], "boundary");
    assert!(
        responses[0].get("result").is_some(),
        "a member exactly at max_batch_item_bytes must be admitted: {body}"
    );

    // Exactly one more raw byte, with no other change.
    let over_limit = whitespace_inflated_member("boundary", 1);
    assert_eq!(over_limit.len(), item_cap + 1);
    let batch = raw_batch(&[over_limit.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().expect("per-item error array");
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
}

#[tokio::test]
async fn transparent_batch_item_cap_boundary_is_exact_on_raw_bytes() {
    let member = canonical_member("boundary");
    let item_cap = member.len();

    let mut config = transparent_config("http://github-mcp.example:8080/mcp");
    config["validation"] = batch_validation(item_cap);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();

    let batch = raw_batch(&[member.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a member exactly at max_batch_item_bytes must be forwarded: {result:?}"
    );
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("github-mcp.example")
    );

    let over_limit = whitespace_inflated_member("boundary", 1);
    assert_eq!(over_limit.len(), item_cap + 1);
    let batch = raw_batch(&[over_limit.as_str()]);
    let (mut ctx, mut headers) = mcp_ctx_raw(batch);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().expect("per-item error array");
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(ctx.route_override_backend_host.is_none());
}

#[tokio::test]
async fn aggregate_batch_nested_array_is_per_item_invalid() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        [{ "jsonrpc": "2.0", "id": 1, "method": "ping" }],
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("non-object members must not reject the whole batch");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(
        responses[1].get("result").is_some(),
        "valid sibling must continue"
    );
}

#[tokio::test]
async fn aggregate_batch_all_notifications_returns_no_content() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} },
        { "jsonrpc": "2.0", "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_raw(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 202);
    assert!(body.is_empty());
    assert_eq!(
        ctx.metadata.get("mcp.batch").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata.get("mcp.batch_size").map(String::as_str),
        Some("2")
    );
}

#[tokio::test]
async fn aggregate_batch_mixed_notifications_and_requests_preserves_order_and_ids() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} },
        { "jsonrpc": "2.0", "id": "req-a", "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 7, "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("mixed batch must return a response array");
    assert_eq!(
        responses.len(),
        2,
        "notifications must be omitted from the response array"
    );
    assert_eq!(responses[0]["id"], "req-a");
    assert!(responses[0].get("result").is_some());
    assert_eq!(responses[1]["id"], 7);
    assert!(responses[1].get("result").is_some());
}

#[tokio::test]
async fn aggregate_batch_partial_invalidity_keeps_valid_siblings() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} },
        { "jsonrpc": "1.0", "id": 2, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 3, "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("partial invalidity must still return an array");
    assert_eq!(responses.len(), 3);
    assert!(responses[0].get("result").is_some());
    assert_eq!(responses[1]["id"], 2);
    assert_eq!(responses[1]["error"]["code"], -32600);
    assert!(responses[2].get("result").is_some());
    let rendered = body.to_string();
    assert!(
        !rendered.contains("attacker"),
        "per-item errors must stay bounded: {rendered}"
    );
}

#[tokio::test]
async fn aggregate_batch_duplicate_ids_preserve_both_responses() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().unwrap();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[1]["id"], 1);
}

#[tokio::test]
async fn aggregate_batch_routed_requests_reject_before_policy_or_catalog_work() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["on_new_tool"] = json!("allow");
    config["policy"] = json!({
        "default_action": "deny",
        "tools": {
            "github.create_pr": { "action": "allow" },
            "github.merge_pr": { "action": "deny" }
        }
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let _ = aggregate_tool_names(&plugin, &session_id, 10).await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "github.create_pr", "arguments": { "repo": "payments-api" } }
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "github.merge_pr", "arguments": {} }
        },
        { "jsonrpc": "2.0", "id": 3, "method": "ping", "params": {} }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);

    // Allowed or denied tools/call must both fail closed as singleton-only
    // before policy/catalog work. Mount a trap that fails if the gateway
    // regresses into upstream dialing from before_proxy.
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({
            "method": "tools/call",
            "params": { "name": "create_pr" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": "ok" }] }
        })))
        .expect(0)
        .mount(&server)
        .await;

    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().expect("routed batch must return an array");
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(
        responses[0]["error"]["code"], -32009,
        "allowed tools/call must fail closed before policy/catalog work: {}",
        responses[0]
    );
    assert_eq!(responses[1]["id"], 2);
    assert_eq!(
        responses[1]["error"]["code"], -32009,
        "denied tools/call must also fail closed before policy evaluation: {}",
        responses[1]
    );
    assert_eq!(responses[2]["id"], 3);
    assert!(responses[2].get("result").is_some());
}

#[tokio::test]
async fn transparent_batch_is_forwarded_after_admission() {
    let plugin = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]));
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("mcp.batch").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("github-mcp.example")
    );
}

#[tokio::test]
async fn aggregate_batch_tools_list_live_path() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["on_new_tool"] = json!("allow");
    config["endpoint"]["protocol_versions"] = json!(["2025-03-26", "2025-11-25"]);
    config["policy"] = json!({ "default_action": "allow" });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": "ping-1", "method": "ping", "params": {} }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().unwrap();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], "list-1");
    assert!(responses[0]["result"]["tools"].as_array().is_some());
    assert_eq!(responses[1]["id"], "ping-1");
    assert!(responses[1].get("result").is_some());
}

#[tokio::test]
async fn aggregate_batch_non_object_mixed_keeps_valid_siblings() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        "not-an-object",
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} },
        42
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("mixed non-object batch must return an array");
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert!(responses[1].get("result").is_some());
    assert_eq!(responses[2]["id"], Value::Null);
    assert_eq!(responses[2]["error"]["code"], -32600);
}

#[tokio::test]
async fn aggregate_batch_passthrough_notification_omits_response_and_fails_closed() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["capabilities"] = json!({ "passthrough_unknown_methods": true });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    // Trap any attempt to execute the notification's upstream side effect from
    // before_proxy after session init (initialize may already have contacted
    // upstream under lazy strategy).
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({ "method": "custom/notify" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": "should-not-run"
        })))
        .expect(0)
        .mount(&server)
        .await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "method": "custom/notify", "params": {} }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert!(
        body.is_object(),
        "upstream-bound notification-only batches must not return empty 202 or append a response element"
    );
    assert_eq!(body["error"]["code"], -32009);
    assert!(
        ctx.route_override_backend_host.is_none(),
        "fail-closed path must clear routing state"
    );
}

#[tokio::test]
async fn aggregate_batch_passthrough_notification_mixed_with_ping_omits_notify() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["capabilities"] = json!({ "passthrough_unknown_methods": true });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({ "method": "custom/notify" })))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "method": "custom/notify", "params": {} },
        { "jsonrpc": "2.0", "id": 9, "method": "ping", "params": {} }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("mixed batch keeps response-bearing members");
    assert_eq!(
        responses.len(),
        1,
        "notifications must never append a response element"
    );
    assert_eq!(responses[0]["id"], 9);
    assert!(responses[0].get("result").is_some());
}

#[tokio::test]
async fn aggregate_batch_initialize_member_is_rejected_with_custom_session_header_configured() {
    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["sessions"] = json!({
        "downstream_session_header": "X-MCP-Session",
        "upstream_session_header": "X-Upstream-Session",
        "session_ttl_seconds": 3600,
        "max_sessions": 64
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "unit-test", "version": "1" }
            }
        },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]));
    let (status, body, response_headers) =
        reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().unwrap();
    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0]["error"]["code"], -32010,
        "initialize must be a singleton request, not a batch member: {}",
        responses[0]
    );
    assert!(
        responses[1].get("result").is_some(),
        "the gateway-handled sibling still answers"
    );
    assert!(
        !response_headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("x-mcp-session")),
        "no batch may stamp a session header, custom or not: {response_headers:?}"
    );
    assert!(
        !response_headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("mcp-session-id")),
        "default session header must not leak either: {response_headers:?}"
    );
}

#[tokio::test]
async fn aggregate_batch_initialize_members_mint_no_session_and_evict_none() {
    // max_sessions = 1 is the sharpest case: if a batch initialize ran, the
    // first member would evict the live singleton session and the second would
    // evict the first, leaving a hidden session and a dead response header.
    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["sessions"] = json!({
        "session_ttl_seconds": 3600,
        "max_sessions": 1
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let live_session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "a", "version": "1" }
            }
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "b", "version": "1" }
            }
        }
    ]));
    let (status, body, response_headers) =
        reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().unwrap();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["error"]["code"], -32010);
    assert_eq!(responses[1]["error"]["code"], -32010);
    assert!(
        !responses
            .iter()
            .any(|response| response.get("result").is_some()),
        "no initialize member may produce a session result: {body}"
    );
    assert!(
        !response_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("mcp-session-id")),
        "a rejected lifecycle batch must not return any session header: {response_headers:?}"
    );

    // The pre-existing live session survived: it was neither evicted by a
    // hidden mint nor replaced by an undisclosed one. A single-slot store that
    // still honors this session proves no second session was ever created.
    // `ping` touches the session without any upstream I/O; a dead session
    // answers 404 with an empty body instead.
    let (mut ping_ctx, mut ping_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "ping",
        "params": {}
    }));
    ping_headers.insert("mcp-session-id".to_string(), live_session_id);
    let (status, body, _) = reject_raw(plugin.before_proxy(&mut ping_ctx, &mut ping_headers).await);
    assert_eq!(
        status, 200,
        "the live session must not have been evicted by a batch initialize: {body}"
    );
}

#[tokio::test]
async fn aggregate_batch_notification_initialize_fails_closed_at_batch_level() {
    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["sessions"] = json!({
        "session_ttl_seconds": 3600,
        "max_sessions": 1
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let live_session_id = initialize(&plugin).await;

    // Notification-form initialize carries no id, so it can never receive a
    // per-item response element. The batch reports the lifecycle restriction
    // once instead of claiming success with an empty 202.
    let (mut ctx, mut headers) = mcp_ctx(json!([
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "silent", "version": "1" }
            }
        }
    ]));
    let (status, body, response_headers) =
        reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert!(
        body.is_object(),
        "notification-only batches never return a response array: {body}"
    );
    assert_eq!(body["error"]["code"], -32010);
    assert!(
        !response_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("mcp-session-id")),
        "no session header may be minted by a notification initialize: {response_headers:?}"
    );

    // The single session slot still belongs to the pre-existing session.
    let (mut ping_ctx, mut ping_headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "ping",
        "params": {}
    }));
    ping_headers.insert("mcp-session-id".to_string(), live_session_id);
    let (status, body, _) = reject_raw(plugin.before_proxy(&mut ping_ctx, &mut ping_headers).await);
    assert_eq!(
        status, 200,
        "a notification initialize must not evict the live session: {body}"
    );
}

#[tokio::test]
async fn aggregate_batch_same_host_different_path_does_not_host_dispatch() {
    let server = MockServer::start().await;
    // Same host:port, different paths — the old before_proxy dispatcher matched
    // only backend host when emit_metadata=false and could cross-route.
    for path_suffix in ["/mcp-a", "/mcp-b"] {
        Mock::given(method("POST"))
            .and(path(path_suffix))
            .and(body_partial_json(json!({"method": "tools/list"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": "tools",
                "result": {
                    "tools": [{
                        "name": "create_pr",
                        "inputSchema": {
                            "type": "object",
                            "required": ["repo"],
                            "properties": { "repo": { "type": "string" } }
                        }
                    }]
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(path_suffix))
            .and(body_partial_json(json!({"method": "initialize"})))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("mcp-session-id", "upstream-session")
                    .set_body_json(json!({
                        "jsonrpc": "2.0",
                        "id": "initialize",
                        "result": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "serverInfo": { "name": "upstream", "version": "1" }
                        }
                    })),
            )
            .mount(&server)
            .await;
        // Lazy upstream initialization completes with notifications/initialized;
        // without this mock the catalog refresh fails closed with -32006 and the
        // batch member would never reach the routing decision under test.
        Mock::given(method("POST"))
            .and(path(path_suffix))
            .and(body_partial_json(
                json!({"method": "notifications/initialized"}),
            ))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(path_suffix))
            .and(body_partial_json(json!({"method": "tools/call"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "content": [{ "type": "text", "text": "leaked" }] }
            })))
            .expect(0)
            .mount(&server)
            .await;
    }

    let mut config = aggregate_config(&format!("{}/mcp-a", server.uri()));
    config["servers"] = json!({
        "alpha": {
            "upstream_url": format!("{}/mcp-a", server.uri()),
            "namespace": "alpha",
            "enabled": true,
            "expose_tools": true,
            "expose_resources": false,
            "expose_prompts": false
        },
        "beta": {
            "upstream_url": format!("{}/mcp-b", server.uri()),
            "namespace": "beta",
            "enabled": true,
            "expose_tools": true,
            "expose_resources": false,
            "expose_prompts": false
        }
    });
    config["observability"] = json!({ "emit_metadata": false });
    config["discovery"]["on_new_tool"] = json!("allow");
    config["policy"] = json!({ "default_action": "allow" });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let _ = aggregate_tool_names(&plugin, &session_id, 42).await;

    let (mut ctx, mut headers) = mcp_ctx(json!([{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "alpha.create_pr", "arguments": { "repo": "payments-api" } }
    }]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().unwrap();
    assert_eq!(
        responses[0]["error"]["code"], -32009,
        "must fail closed without host-only upstream dispatch: {}",
        responses[0]
    );
    assert!(ctx.route_override_backend_host.is_none());
    assert!(!ctx.metadata.contains_key("mcp.server_id"));
}

#[tokio::test]
async fn aggregate_batch_response_cap_fails_closed_without_partial_body() {
    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["validation"] = json!({
        "max_batch_items": 8,
        "max_batch_bytes": 65536,
        "max_batch_item_bytes": 4096,
        "max_batch_response_bytes": 120
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 3, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 4, "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert!(
        body.is_object(),
        "oversized aggregate response must fail closed as a single error, got {body}"
    );
    assert_eq!(body["error"]["code"], -32600);
    let rendered = body.to_string();
    assert!(
        !rendered.contains("\"result\""),
        "must not return a partially oversized batch body: {rendered}"
    );
}

#[tokio::test]
async fn aggregate_batch_clears_per_item_routing_state_between_members() {
    let plugin = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]));
    ctx.route_override_backend_host = Some("leak.example".to_string());
    ctx.metadata
        .insert("mcp.server_id".to_string(), "forged".to_string());
    ctx.metadata
        .insert("mcp.protocol_version".to_string(), "forged".to_string());
    ctx.metadata.insert(
        "mcp.catalog_degraded".to_string(),
        "forged:tools".to_string(),
    );
    let _ = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        ctx.route_override_backend_host.is_none(),
        "batch completion must clear sibling routing overrides"
    );
    assert!(!ctx.metadata.contains_key("mcp.server_id"));
    assert!(
        ferrum_edge::_test_support::mcp_trusted_tool_name_rewrite_is_none_for_test(&ctx),
        "batch completion must clear private trusted tool-name rewrites"
    );
    assert!(
        !ferrum_edge::_test_support::mcp_batch_forbids_upstream_for_test(&ctx),
        "batch completion must release the private upstream-dispatch guard"
    );
    // Item-scoped observability must not survive the batch either: only the
    // request-level summary and the terminal route decision remain.
    for stale_key in [
        "mcp.method",
        "mcp.message.kind",
        "mcp.jsonrpc",
        "mcp.tool_name",
        "mcp.public_tool_name",
        "mcp.upstream_tool_name",
        "mcp.session.downstream",
        "mcp.catalog_version",
        "mcp.item_name",
        "mcp.arguments_hash",
        // Both of these end up describing the *request*, but either can be
        // written by a single member (`params.protocolVersion`, one member's
        // catalog refresh). They must be republished from request-level inputs,
        // never carried over from a member or from pre-seeded scratch space.
        "mcp.protocol_version",
        "mcp.catalog_degraded",
    ] {
        assert!(
            !ctx.metadata.contains_key(stale_key),
            "stale per-item key {stale_key} must not survive a batch"
        );
    }
    // Per-item verdict fields fall back to their neutral request-start
    // baselines rather than carrying a sibling member's verdict.
    assert_eq!(
        ctx.metadata.get("mcp.policy_decision").map(String::as_str),
        Some("not_applicable")
    );
    assert_eq!(
        ctx.metadata
            .get("mcp.schema_validation")
            .map(String::as_str),
        Some("skipped")
    );
    assert_eq!(
        ctx.metadata.get("mcp.batch").map(String::as_str),
        Some("true"),
        "request-level batch summary is still allowed"
    );
}

#[tokio::test]
async fn aggregate_batch_preserves_degraded_catalog_summary_across_clean_sibling() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "prompts/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "prompts",
            "result": {"prompts": []}
        })))
        .mount(&server)
        .await;
    let config = single_server_family_config(&format!("{}/mcp", server.uri()), true, true, false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    // The first member degrades the tools catalog; the second is a clean,
    // gateway-local response that writes no catalog metadata. The request-level
    // summary must retain the first member's bounded degraded pair even though
    // per-item state is cleared before the clean sibling runs.
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);

    assert_eq!(status, 200);
    let responses = body.as_array().expect("batch response array");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["error"]["code"], -32006);
    assert!(responses[1]["result"].is_object());
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("github:tools"),
        "a later clean member must not erase the request's degraded-catalog union"
    );
}

#[tokio::test]
async fn aggregate_batch_preserves_degraded_catalog_summary_when_degraded_member_is_last() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "prompts/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "prompts",
            "result": {"prompts": []}
        })))
        .mount(&server)
        .await;
    let config = single_server_family_config(&format!("{}/mcp", server.uri()), true, true, false);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);

    assert_eq!(status, 200);
    let responses = body.as_array().expect("batch response array");
    assert_eq!(responses.len(), 2);
    assert!(responses[0]["result"].is_object());
    assert_eq!(responses[1]["error"]["code"], -32006);
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("github:tools"),
        "degraded state from the last member must still be unioned at request scope"
    );
}

#[tokio::test]
async fn aggregate_batch_unions_degraded_catalog_summary_across_multiple_members() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "prompts/list"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "resources/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "resources",
            "result": {"resources": []}
        })))
        .mount(&server)
        .await;
    let config = single_server_family_config(&format!("{}/mcp", server.uri()), true, true, true);
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "prompts/list", "params": {} }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);

    assert_eq!(status, 200);
    let responses = body.as_array().expect("batch response array");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["error"]["code"], -32006);
    assert_eq!(responses[1]["error"]["code"], -32006);
    assert_eq!(
        ctx.metadata.get("mcp.catalog_degraded").map(String::as_str),
        Some("github:prompts,github:tools"),
        "multiple degraded members must publish a bounded sorted union"
    );
}

#[tokio::test]
async fn aggregate_batch_oversized_body_is_rejected_before_json_parsing() {
    let mut config = aggregate_config("http://github-mcp.example:8080/mcp");
    config["validation"] = json!({
        "max_batch_items": 8,
        "max_batch_bytes": 256,
        "max_batch_item_bytes": 128
    });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();

    // Array-shaped and oversized, but *not* parseable JSON: the unterminated
    // array can only be refused by the byte cap if that cap runs before
    // serde_json. A parse-first implementation answers with the envelope
    // message ("Invalid MCP JSON-RPC request") instead.
    let mut oversized = Vec::with_capacity(1024);
    oversized.extend_from_slice(b"   [");
    oversized.extend(std::iter::repeat_n(b'a', 1024));
    assert!(oversized.len() > 256);
    let (mut ctx, mut headers) = mcp_ctx_raw(oversized.clone());
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(
        body["error"]["message"], "Invalid Request",
        "the raw-byte batch cap must reject before JSON parsing: {body}"
    );
    assert!(
        ctx.route_override_backend_host.is_none(),
        "malformed array-shaped input must stay fail closed"
    );

    // Under the cap, the same malformed array still fails closed — through the
    // ordinary parse path this time.
    let (mut ctx, mut headers) = mcp_ctx_raw(b"  [ {".to_vec());
    let (_, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "Invalid MCP JSON-RPC request");

    // Singleton (object-shaped) bodies are untouched by the batch cap even when
    // they exceed max_batch_bytes.
    let large_singleton = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ping",
        "params": { "padding": "x".repeat(1024) }
    });
    let raw_singleton = serde_json::to_vec(&large_singleton).unwrap();
    assert!(raw_singleton.len() > 256);
    let (mut ctx, mut headers) = mcp_ctx_raw(raw_singleton);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert!(
        body.get("result").is_some(),
        "the batch byte cap must not apply to singleton bodies: {body}"
    );
}

#[tokio::test]
async fn transparent_batch_unsupported_protocol_version_matches_singleton() {
    let plugin = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();

    // Singleton baseline: a post-initialize request under an unsupported
    // MCP-Protocol-Version is rejected with HTTP 400 and never routed.
    let (mut ctx, mut headers) = mcp_ctx(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }));
    headers.insert("mcp-protocol-version".to_string(), "1999-01-01".to_string());
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 400);
    assert_eq!(body["error"]["message"], "Unsupported MCP protocol version");
    assert!(ctx.route_override_backend_host.is_none());

    // The batch form of the same request must not be forwarded under a version
    // the singleton rejects, and must not be partially forwarded either.
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]));
    headers.insert("mcp-protocol-version".to_string(), "1999-01-01".to_string());
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        status, 400,
        "transparent batches must enforce the singleton protocol-version gate: {body}"
    );
    assert_eq!(body["error"]["message"], "Unsupported MCP protocol version");
    assert!(
        ctx.route_override_backend_host.is_none(),
        "an unsupported-version batch must never be forwarded"
    );
    assert_eq!(
        ctx.metadata.get("mcp.route_decision").map(String::as_str),
        Some("deny")
    );

    // A supported version still forwards the whole batch as before.
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]));
    headers.insert("mcp-protocol-version".to_string(), "2025-11-25".to_string());
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("github-mcp.example")
    );
}

#[tokio::test]
async fn aggregate_batch_upstream_guard_is_private_and_unforgeable() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["on_new_tool"] = json!("allow");
    config["policy"] = json!({ "default_action": "allow" });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let _ = aggregate_tool_names(&plugin, &session_id, 21).await;

    let tool_call = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "github.create_pr", "arguments": { "repo": "payments-api" } }
    });

    // Public metadata cannot *set* the guard: a singleton still routes upstream
    // even with the old public key forged onto the request.
    let (mut ctx, mut headers) = mcp_ctx(tool_call.clone());
    headers.insert("mcp-session-id".to_string(), session_id.clone());
    ctx.metadata
        .insert("mcp.batch_forbid_upstream".to_string(), "true".to_string());
    assert!(
        matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ),
        "forged public metadata must not seize the private dispatch boundary"
    );
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("127.0.0.1"),
        "the singleton must still route through the normal plugin chain"
    );

    // Public metadata cannot *clear* the guard either: the batch form still
    // fails closed with -32009 and never stages an upstream route.
    let (mut ctx, mut headers) = mcp_ctx(json!([tool_call]));
    headers.insert("mcp-session-id".to_string(), session_id);
    ctx.metadata
        .insert("mcp.batch_forbid_upstream".to_string(), "false".to_string());
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert_eq!(
        body.as_array().unwrap()[0]["error"]["code"],
        -32009,
        "a forged public key must not authorize upstream dispatch: {body}"
    );
    assert!(ctx.route_override_backend_host.is_none());
    assert!(
        !ferrum_edge::_test_support::mcp_batch_forbids_upstream_for_test(&ctx),
        "the private guard must be released when the batch completes"
    );
}

#[tokio::test]
async fn aggregate_batch_routed_notification_only_fails_closed_without_upstream_io() {
    for routed_method in ["tools/call", "prompts/get", "resources/read"] {
        let server = start_mcp_catalog_server().await;
        let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
        config["discovery"]["on_new_tool"] = json!("allow");
        config["policy"] = json!({ "default_action": "allow" });
        let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
        let session_id = initialize(&plugin).await;

        // Trap any upstream execution of the routed notification.
        Mock::given(method("POST"))
            .and(path("/mcp"))
            .and(body_partial_json(json!({ "method": routed_method })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "result": "should-not-run"
            })))
            .expect(0)
            .mount(&server)
            .await;

        // Notification form: no `id`, so it can never receive a per-item
        // response element. Previously this took the singleton no-op path and
        // the batch claimed success with an empty 202.
        let (mut ctx, mut headers) = mcp_ctx(json!([
            { "jsonrpc": "2.0", "method": routed_method, "params": {} }
        ]));
        headers.insert("mcp-session-id".to_string(), session_id);
        let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(status, 200);
        assert!(
            body.is_object(),
            "{routed_method}: notifications must not append a response element: {body}"
        );
        assert_eq!(
            body["error"]["code"], -32009,
            "{routed_method}: routed notification-only batches must fail closed: {body}"
        );
        assert!(
            ctx.route_override_backend_host.is_none(),
            "{routed_method}: no upstream route may be staged"
        );
    }
}

#[tokio::test]
async fn aggregate_batch_routed_requests_reject_before_catalog_io_when_cache_missing() {
    // Unreachable upstream: if the gateway still called ensure_catalog before
    // the -32009 boundary, the member would surface a catalog/transport error
    // instead of the deterministic singleton-routing code.
    let mut config = aggregate_config("http://127.0.0.1:1/mcp");
    config["discovery"]["on_new_tool"] = json!("allow");
    config["policy"] = json!({ "default_action": "allow" });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": "call",
            "method": "tools/call",
            "params": { "name": "github.create_pr", "arguments": { "repo": "payments-api" } }
        },
        {
            "jsonrpc": "2.0",
            "id": "prompt",
            "method": "prompts/get",
            "params": { "name": "github.code_review" }
        },
        {
            "jsonrpc": "2.0",
            "id": "resource",
            "method": "resources/read",
            "params": { "uri": "mcp://github/file:///project/README.md" }
        },
        { "jsonrpc": "2.0", "id": "ping", "method": "ping", "params": {} }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().expect("mixed batch must return an array");
    assert_eq!(responses.len(), 4);
    for (idx, expected_id) in ["call", "prompt", "resource"].into_iter().enumerate() {
        assert_eq!(responses[idx]["id"], expected_id);
        assert_eq!(
            responses[idx]["error"]["code"], -32009,
            "{expected_id} must reject before catalog I/O on a cold cache: {}",
            responses[idx]
        );
    }
    assert_eq!(responses[3]["id"], "ping");
    assert!(responses[3].get("result").is_some());
    assert!(ctx.route_override_backend_host.is_none());
}

#[tokio::test]
async fn aggregate_batch_routed_requests_reject_before_catalog_io_when_cache_warm() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["on_new_tool"] = json!("allow");
    config["policy"] = json!({ "default_action": "allow" });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;
    let _ = aggregate_tool_names(&plugin, &session_id, 21).await;

    // Warm catalog still must not dial discovery, templates, or the routed
    // methods themselves — the early boundary is independent of cache state.
    let baseline = server.received_requests().await.unwrap().len();
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({ "method": "tools/call" })))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({ "method": "prompts/get" })))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({ "method": "resources/read" })))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": "call",
            "method": "tools/call",
            "params": { "name": "github.create_pr", "arguments": { "repo": "payments-api" } }
        },
        {
            "jsonrpc": "2.0",
            "id": "prompt",
            "method": "prompts/get",
            "params": { "name": "github.code_review" }
        },
        {
            "jsonrpc": "2.0",
            "id": "resource",
            "method": "resources/read",
            "params": { "uri": "mcp://github/file:///project/README.md" }
        }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id.clone());
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body.as_array().unwrap();
    assert_eq!(responses.len(), 3);
    for response in responses {
        assert_eq!(
            response["error"]["code"], -32009,
            "warm-cache routed member must still be deterministic -32009: {response}"
        );
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        baseline,
        "warm-cache routed batch members must not trigger any upstream I/O"
    );
    assert!(ctx.route_override_backend_host.is_none());

    // Same members as notifications (mixed order) omit response elements while
    // a sibling request still gets -32009 — proving the early classification
    // covers both forms without catalog work.
    let baseline = server.received_requests().await.unwrap().len();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "method": "prompts/get", "params": { "name": "github.code_review" } },
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": "github.create_pr", "arguments": { "repo": "payments-api" } }
        },
        {
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": { "uri": "mcp://github/file:///project/README.md" }
        }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("mixed notification/request keeps response-bearing members");
    assert_eq!(
        responses.len(),
        1,
        "routed notifications must omit response elements: {body}"
    );
    assert_eq!(responses[0]["id"], 7);
    assert_eq!(responses[0]["error"]["code"], -32009);
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        baseline,
        "mixed routed notification/request ordering must not dial upstream"
    );
}

#[tokio::test]
async fn aggregate_batch_failed_notification_is_reported_once_at_batch_level() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["capabilities"] = json!({ "passthrough_unknown_methods": true });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({ "method": "custom/notify" })))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    // No session header: the passthrough notification cannot be dispatched. It
    // must not gain a per-item response element, and the batch must not claim
    // success with an empty 202 either.
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "method": "custom/notify", "params": {} }
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert!(
        body.is_object(),
        "a failed notification must not become a response element: {body}"
    );
    assert_eq!(body["error"]["code"], -32011);
    assert!(ctx.route_override_backend_host.is_none());
}

#[tokio::test]
async fn aggregate_batch_routed_notification_mixed_with_request_omits_notification() {
    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["on_new_tool"] = json!("allow");
    config["policy"] = json!({ "default_action": "allow" });
    let plugin = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let session_id = initialize(&plugin).await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({ "method": "tools/call" })))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "github.create_pr" } },
        { "jsonrpc": "2.0", "id": 9, "method": "ping", "params": {} }
    ]));
    headers.insert("mcp-session-id".to_string(), session_id);
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("mixed batch keeps response-bearing members");
    assert_eq!(
        responses.len(),
        1,
        "a blocked routed notification must never append a response element: {body}"
    );
    assert_eq!(responses[0]["id"], 9);
    assert!(responses[0].get("result").is_some());
    assert!(ctx.route_override_backend_host.is_none());
}

#[tokio::test]
async fn transparent_batch_invalid_sibling_fails_closed_without_forward() {
    let plugin = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        "bad-member",
        { "jsonrpc": "2.0", "id": 3, "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("transparent invalid sibling must be synthetic array");
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert_eq!(responses[1]["id"], Value::Null);
    assert_eq!(responses[2]["error"]["code"], -32600);
    assert!(
        ctx.route_override_backend_host.is_none(),
        "invalid transparent batch must not Continue to upstream"
    );
}

#[test]
fn transparent_invalid_batch_response_is_budgeted_while_assembled() {
    // The client-visible overflow shape was already a bounded single error, so
    // the regression is allocation ordering: the transparent invalid-sibling
    // path must not serialize a potentially much larger complete array before
    // enforcing max_batch_response_bytes.
    let source = include_str!("../../../src/plugins/mcp_gateway.rs");
    let handler = source
        .split("fn handle_transparent_jsonrpc_batch(")
        .nth(1)
        .expect("transparent batch handler")
        .split("/// Aggregate batches assemble")
        .next()
        .expect("bounded transparent batch handler");
    let invalid_path = handler
        .split("if invalid {")
        .nth(1)
        .expect("transparent invalid-sibling path");
    assert!(
        invalid_path.contains("self.push_bounded_batch_response("),
        "transparent invalid responses must enforce the aggregate budget item by item"
    );
    let incremental_check = invalid_path
        .find("self.push_bounded_batch_response(")
        .expect("incremental response-budget check");
    let final_serialize = invalid_path
        .find("self.bounded_batch_json_response(")
        .expect("final bounded response serialization");
    assert!(
        incremental_check < final_serialize,
        "the response cap must run before final array serialization"
    );
}

#[tokio::test]
async fn transparent_batch_invalid_sibling_does_not_respond_to_valid_notification() {
    let plugin = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} },
        "bad-member",
        { "jsonrpc": "2.0", "id": 3, "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_json(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    let responses = body
        .as_array()
        .expect("invalid sibling must produce a synthetic response array");
    assert_eq!(
        responses.len(),
        2,
        "the valid notification must not gain a synthetic response"
    );
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[1]["id"], 3);
    assert!(
        ctx.route_override_backend_host.is_none(),
        "invalid transparent batch must not Continue to upstream"
    );
}

#[tokio::test]
async fn transparent_batch_and_singleton_both_continue_for_request_transformer() {
    use ferrum_edge::plugins::request_transformer::RequestTransformer;

    let mcp = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let transformer = create_plugin(
        "request_transformer",
        &json!({
            "rules": [
                {
                    "target": "header",
                    "operation": "add",
                    "key": "x-batch-parity",
                    "value": "seen"
                }
            ]
        }),
    )
    .unwrap()
    .unwrap();
    assert!(transformer.priority() > mcp.priority());

    let singleton = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    let batch = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]);

    for body in [singleton, batch] {
        let (mut ctx, mut headers) = mcp_ctx(body);
        let mcp_result = mcp.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(mcp_result, PluginResult::Continue),
            "transparent MCP path must Continue so later plugins run"
        );
        let transformer_result = transformer.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(transformer_result, PluginResult::Continue));
        assert_eq!(
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-batch-parity"))
                .map(|(_, value)| value.as_str()),
            Some("seen"),
            "request_transformer must still run after mcp_gateway for batch and singleton"
        );
    }
    // Keep the concrete type referenced so refactors that drop the import fail.
    let _ = std::any::type_name::<RequestTransformer>();
}

#[tokio::test]
async fn aggregate_batch_upstream_routed_member_does_not_bypass_later_plugins() {
    use ferrum_edge::plugins::request_transformer::RequestTransformer;

    let server = start_mcp_catalog_server().await;
    let mut config = aggregate_config(&format!("{}/mcp", server.uri()));
    config["discovery"]["on_new_tool"] = json!("allow");
    config["policy"] = json!({ "default_action": "allow" });
    let mcp = create_plugin("mcp_gateway", &config).unwrap().unwrap();
    let transformer = create_plugin(
        "request_transformer",
        &json!({
            "rules": [
                {
                    "target": "header",
                    "operation": "add",
                    "key": "x-should-not-matter",
                    "value": "batch"
                }
            ]
        }),
    )
    .unwrap()
    .unwrap();
    let session_id = initialize(&mcp).await;
    let _ = aggregate_tool_names(&mcp, &session_id, 11).await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({ "method": "tools/call" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [] }
        })))
        .expect(0)
        .mount(&server)
        .await;

    let (mut ctx, mut headers) = mcp_ctx(json!([{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "github.create_pr", "arguments": { "repo": "payments-api" } }
    }]));
    headers.insert("mcp-session-id".to_string(), session_id);

    let batch_result = mcp.before_proxy(&mut ctx, &mut headers).await;
    let (status, body, _) = reject_json(batch_result);
    assert_eq!(status, 200);
    assert_eq!(body.as_array().unwrap()[0]["error"]["code"], -32009);

    // Because the batch terminated inside mcp_gateway, later before_proxy plugins
    // never see a Continue that already completed upstream I/O under weaker policy.
    let after = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(after, PluginResult::Continue));
    let _ = std::any::type_name::<RequestTransformer>();
}

/// A batch is not describable by any one of its members. `mcp.protocol_version`
/// must come from the request's `MCP-Protocol-Version` header rather than from
/// whichever member last declared a `params.protocolVersion`, and a transparent
/// batch — whose forwarded body is the whole array — must not be labelled with
/// the last member's envelope fields while it was routed from the first.
#[tokio::test]
async fn batch_request_metadata_is_not_described_by_a_single_member() {
    let aggregate = create_plugin(
        "mcp_gateway",
        &aggregate_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();

    // No request header, but a member declares a (supported, so non-gating)
    // protocolVersion in params. That is a member property, not the request's.
    let (mut ctx, mut headers) = mcp_ctx(json!([
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping",
            "params": { "protocolVersion": "2025-11-25" }
        },
        { "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {} }
    ]));
    let (status, body, _) = reject_json(aggregate.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert_eq!(body.as_array().map(Vec::len), Some(2));
    assert!(
        !ctx.metadata.contains_key("mcp.protocol_version"),
        "a member's params.protocolVersion must not label the whole batch: {:?}",
        ctx.metadata.get("mcp.protocol_version")
    );

    // With the shared request header present it is republished verbatim.
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} }
    ]));
    headers.insert("mcp-protocol-version".to_string(), "2025-11-25".to_string());
    let (status, _, _) = reject_json(aggregate.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status, 200);
    assert_eq!(
        ctx.metadata.get("mcp.protocol_version").map(String::as_str),
        Some("2025-11-25"),
        "the shared request header is the batch's protocol version"
    );

    let transparent = create_plugin(
        "mcp_gateway",
        &transparent_config("http://github-mcp.example:8080/mcp"),
    )
    .unwrap()
    .unwrap();
    let (mut ctx, mut headers) = mcp_ctx(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ping",
            "params": { "protocolVersion": "2025-11-25" }
        }
    ]));
    assert!(matches!(
        transparent.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("github-mcp.example")
    );
    assert!(
        !ctx.metadata.contains_key("mcp.protocol_version"),
        "a transparent batch member's params must not label the request"
    );
    for member_scoped in ["mcp.method", "mcp.message.kind", "mcp.jsonrpc"] {
        assert!(
            !ctx.metadata.contains_key(member_scoped),
            "{member_scoped} describes one member, but the forwarded body is the whole batch"
        );
    }
    assert_eq!(
        ctx.metadata.get("mcp.batch").map(String::as_str),
        Some("true"),
        "the request-level batch summary is what describes a forwarded batch"
    );
    assert_eq!(
        ctx.metadata.get("mcp.batch_size").map(String::as_str),
        Some("2")
    );
}
