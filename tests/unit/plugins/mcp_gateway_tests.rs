use bytes::Bytes;
use ferrum_edge::config::types::{BackendScheme, BackendTlsConfig};
use ferrum_edge::plugins::{HTTP_ONLY_PROTOCOLS, PluginResult, create_plugin, priority};
use serde_json::{Value, json};
use std::collections::HashMap;
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
        json!({
            "mode": "aggregate_router",
            "endpoint": { "path": "/mcp", "protocol_versions": ["2025-03-26"] },
            "servers": { "github": { "upstream_url": "http://x/mcp", "namespace": "github" } }
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
        "max_catalog_bytes_per_list": 2048
    });
    assert!(
        create_plugin("mcp_gateway", &config).is_ok(),
        "positive upstream/catalog limit overrides should be accepted"
    );
}

#[test]
fn validation_zero_limits_are_rejected() {
    // Zero would disable a DoS backstop, so each limit must reject 0.
    for field in [
        "max_upstream_response_bytes",
        "max_catalog_items_per_list",
        "max_catalog_bytes_per_list",
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
