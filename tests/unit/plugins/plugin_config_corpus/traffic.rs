//! Config contracts for traffic-shaping, routing, validation, and mesh routing
//! built-ins (issue #6616 sweep).
//!
//! Flat-config plugins in this family (`compression`, `tcp_connection_throttle`,
//! `adaptive_concurrency`, `correlation_id`, `grpc_deadline`, `grpc_web`,
//! `request_size_limiting`, `response_size_limiting`, `response_caching`,
//! `ws_rate_limiting`, `udp_rate_limiting`, `sse`, `request_deduplication`,
//! `mesh_outbound_registry`) have no nested object below the root, so their
//! minimal config is the whole contract. `request_transformer` and
//! `response_transformer` nest only their closed `rules[]` entries, which the
//! minimal config already reaches.

use ferrum_edge::plugins::PluginConfigContract;
use serde_json::json;

pub(super) fn contract(name: &str) -> Option<PluginConfigContract> {
    Some(match name {
        "mesh_authz" => PluginConfigContract::closed(vec![
            // Flat operator form: every scope kind and every matcher family.
            json!({
                "namespace": "default",
                "labels": {"app": "api"},
                "trust_domain_aliases": ["old.example.com"],
                "trusted_hbone_assertors": [{
                    "assertor": "spiffe://cluster.local/ns/istio-system/sa/ztunnel",
                    "asserts": ["spiffe://cluster.local/ns/default/sa/api"]
                }],
                "mesh_policies": [
                    {
                        "name": "deny-admin",
                        "namespace": "default",
                        "scope": {"kind": "namespace", "namespace": "default"},
                        "rules": [{
                            "from": [{"spiffe_id_pattern": "cluster.local/ns/default/sa/web"}],
                            "to": [{
                                "methods": ["POST"],
                                "paths": ["/admin/*"],
                                "headers": {"x-env": "prod"},
                                "ports": [8080]
                            }],
                            "when": [{"key": "source.namespace", "values": ["default"]}],
                            "source_negation": {
                                "not_namespace_patterns": ["kube-system"],
                                "ip_blocks": ["10.0.0.0/8"]
                            },
                            "action": "deny"
                        }]
                    },
                    {
                        "name": "allow-api",
                        "namespace": "default",
                        "scope": {
                            "kind": "workload_selector",
                            "selector": {"labels": {"app": "api"}}
                        },
                        "rules": [{"from": [{"namespace_pattern": "default"}], "action": "allow"}]
                    },
                    {
                        "name": "audit-mesh",
                        "namespace": "default",
                        "scope": {"kind": "mesh_wide"},
                        "rules": [{"to": [{"paths": ["/audit/*"]}], "action": "audit"}]
                    },
                    {
                        "name": "targeted",
                        "namespace": "default",
                        "scope": {
                            "kind": "target_refs",
                            "attachments": [
                                {"kind": "service", "namespace": "default", "name": "reviews"},
                                {"kind": "gateway", "namespace": "default", "name": "waypoint"}
                            ]
                        },
                        "rules": [{"to": [{"paths": ["/internal/*"]}], "action": "deny"}]
                    }
                ]
            }),
            // Injected slice form: a CUSTOM delegation bound to a slice-carried
            // ext-authz provider.
            json!({
                "mesh_slice": {
                    "node_id": "node-a",
                    "namespace": "default",
                    "version": "test",
                    "labels": {"app": "api"},
                    "mesh_policies": [{
                        "name": "delegate-admin",
                        "namespace": "default",
                        "scope": {"kind": "mesh_wide"},
                        "rules": [{
                            "to": [{"paths": ["/admin/*"]}],
                            "action": {"custom": {"provider": "sample-ext-authz"}}
                        }]
                    }],
                    "ext_authz_providers": [{
                        "name": "sample-ext-authz",
                        "service": "127.0.0.1",
                        "port": 9000,
                        "timeout_ms": 500,
                        "status_on_error": 403,
                        "include_additional_headers_in_check": [
                            {"name": "x-check-source", "value": "mesh"}
                        ],
                        "include_request_body_in_check": {"max_request_bytes": 64}
                    }]
                }
            }),
            // NodeWaypoint per-pod form with route upstream metadata.
            json!({
                "per_pod_policy_scoping": true,
                "cluster_domain": "cluster.local",
                "cluster_domains": ["cluster.local"],
                "node_waypoint_route_upstreams": [{
                    "id": "istio-vs-upstream-reviews",
                    "namespace": "default",
                    "targets": [{
                        "host": "10.0.0.10",
                        "port": 8080,
                        "service_namespace": "default",
                        "service_name": "reviews",
                        "service_port": 80
                    }]
                }]
            }),
        ])
        // Label maps are keyed by operator-chosen label names, and `to.headers`
        // by request header names.
        .with_free_form_objects(&[
            "labels",
            "mesh_slice.labels",
            "mesh_policies[].scope.selector.labels",
            "mesh_policies[].rules[].to[].headers",
        ]),
        "mesh_route_dispatch" => PluginConfigContract::closed(vec![
            json!({
                "reject_unmatched": true,
                "rules": [
                    {
                        "name": "canary-get",
                        "match": {
                            "methods": [{"exact": "GET"}],
                            "headers": {"x-canary": {"exact": "1"}},
                            "without_headers": {"x-skip": {"prefix": "y"}},
                            "query_params": {"debug": {"exact": "1"}},
                            "authority": {"exact": "api.example.com"},
                            "uri": {"prefix": "/api"},
                            "port": 8080
                        },
                        "destination": {
                            "backend_host": "backend.example.com",
                            "backend_port": 8443,
                            "backend_tls": {
                                "verify_server_cert": true,
                                "sni": "backend.example.com",
                                "san_allow_list": ["spiffe://cluster.local/ns/default/sa/backend"]
                            }
                        },
                        "timeout_ms": 1000,
                        "retry": {
                            "max_retries": 2,
                            "retryable_status_codes": [503],
                            "retryable_methods": ["GET"],
                            "backoff": {"exponential": {"base_ms": 50, "max_ms": 500}},
                            "retry_on_connect_failure": true
                        },
                        "request_transform": [{
                            "operation": "add",
                            "target": "header",
                            "key": "x-route",
                            "value": "canary"
                        }],
                        "response_transform": [{"operation": "remove", "key": "x-internal"}],
                        "fault": {
                            "delay": {"duration_ms": 10, "percentage": 1.0},
                            "abort": {"status_code": 503, "percentage": 1.0}
                        },
                        "rewrite": {
                            "uri": "/v2",
                            "match_prefix": "/api",
                            "authority": "api.internal"
                        }
                    },
                    {
                        "match": {"methods": ["POST"]},
                        "destination": {"upstream_id": "stable"},
                        "retry": {"backoff": {"fixed": {"delay_ms": 100}}}
                    }
                ]
            }),
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "redirect": {
                        "uri": "/new",
                        "match_prefix": "/old",
                        "authority": "www.example.com",
                        "scheme": "https",
                        "redirect_code": 301
                    }
                }]
            }),
        ])
        // Header and query-parameter match maps are keyed by request field
        // names; each matcher value is still walked and probed.
        .with_free_form_objects(&[
            "rules[].match.headers",
            "rules[].match.without_headers",
            "rules[].match.query_params",
        ]),
        "graphql" => PluginConfigContract::closed(vec![json!({
            "max_depth": 10,
            "max_complexity": 1000,
            "max_aliases": 10,
            "introspection_allowed": false,
            "type_rate_limits": {
                "query": {"max_requests": 100, "window_seconds": 60},
                "mutation": {"max_requests": 10, "window_seconds": 60}
            },
            "operation_rate_limits": {
                "GetUser": {"max_requests": 20, "window_seconds": 60}
            }
        })])
        // Keyed by operator-chosen GraphQL operation names.
        .with_free_form_objects(&["operation_rate_limits"]),
        "grpc_method_router" => PluginConfigContract::closed(vec![json!({
            "allow_methods": ["test.Svc/Method"],
            "method_rate_limits": {
                "test.Svc/Method": {"max_requests": 10, "window_seconds": 60}
            },
            "default_rate_limit": {"max_requests": 100, "window_seconds": 60}
        })])
        // Keyed by operator-chosen gRPC method names.
        .with_free_form_objects(&["method_rate_limits"]),
        "rate_limiting" => PluginConfigContract::closed(vec![json!({
            "limit_by": "consumer",
            "limits": [
                {"scope": "default", "window_seconds": 60, "max_requests": 100},
                {"scope": "consumers", "consumers": ["alice"], "requests_per_second": 5}
            ],
            "mcp_tool_calls": {
                "endpoint_path": "/mcp",
                "tools": ["search"],
                "per_tool": true
            }
        })]),
        "ws_message_size_limiting" => PluginConfigContract::closed(vec![json!({
            "max_frame_bytes": 65536,
            "client_to_backend": {"max_frame_bytes": 1024},
            "backend_to_client": {
                "max_frame_bytes": 131072,
                "max_message_bytes": 262144,
                "close_reason": "too big"
            }
        })]),
        "body_validator" => PluginConfigContract::closed(vec![
            json!({
                "json_schema": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {"name": {"type": "string"}}
                },
                "response_json_schema": {"type": "object"}
            }),
            json!({
                "protobuf_descriptor_path": "/nonexistent/descriptor.pb",
                "protobuf_method_messages": {
                    "/pkg.Svc/Method": {"request": "pkg.Req", "response": "pkg.Resp"}
                }
            }),
        ])
        // Keyed by operator-chosen gRPC method paths; each entry is closed.
        .with_free_form_objects(&["protobuf_method_messages"])
        // JSON Schema documents, compiled as schemas rather than read as config.
        .with_opaque_documents(&["json_schema", "response_json_schema"]),
        "openapi_validator" => PluginConfigContract::closed(vec![
            json!({
                "operations": [{
                    "method": "GET",
                    "path_template": "/users/{id}",
                    "path_regex": "^/users/[^/]+$",
                    "operation_label": "getUser",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string"}
                        },
                        {
                            "name": "verbose",
                            "in": "query",
                            "required": false,
                            "schema": {"type": "boolean"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {"application/json": {"type": "object"}}
                        }
                    }
                }],
                "bypass": {
                    "paths": ["^/health$"],
                    "methods": ["OPTIONS"],
                    "consumers": ["ops"],
                    "header_present": {"x-bypass": "0123456789abcdef0123"}
                },
                "error_response": {
                    "request_status_code": 422,
                    "response_status_code": 502,
                    "unsupported_media_type_status_code": 415,
                    "content_type": "application/problem+json"
                }
            }),
            json!({
                "operations": [{
                    "method": "PUT",
                    "path_template": "/items",
                    "path_regex": "^/items$",
                    "request_required": true,
                    "request_body": {
                        "content_type": "application/json",
                        "schema": {"type": "object"}
                    }
                }]
            }),
            json!({
                "operations": [{
                    "method": "POST",
                    "path_template": "/header",
                    "path_regex": "^/header$",
                    "request_body": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "required": ["title"],
                                    "properties": {"title": {"type": "string"}}
                                },
                                "encoding": {
                                    "title": {
                                        "headers": {
                                            "X-Part-Token": {
                                                "schema": {"type": "string", "minLength": 5}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }]
            }),
        ])
        // Keyed by response status, media type, schema property, or header
        // name; every value object is still walked and probed.
        .with_free_form_objects(&[
            "operations[].responses",
            "operations[].responses.*.content",
            "operations[].request_body.content",
            "operations[].request_body.content.*.encoding",
            "operations[].request_body.content.*.encoding.*.headers",
            "bypass.header_present",
        ])
        // Embedded JSON Schemas from the OpenAPI document, compiled as
        // schemas rather than read as plugin config.
        .with_opaque_documents(&[
            "operations[].parameters[].schema",
            "operations[].responses.*.content.*",
            "operations[].request_body.schema",
            "operations[].request_body.content.*.schema",
            "operations[].request_body.content.*.encoding.*.headers.*.schema",
        ]),
        "request_termination" => PluginConfigContract::closed(vec![
            json!({
                "status_code": 403,
                "message": "blocked",
                "headers": {"x-reason": "maintenance"},
                "trigger": {"header": "x-block", "header_value": "1"}
            }),
            json!({"trigger": {"path_prefix": "/admin"}}),
        ])
        // Keyed by operator-chosen response header names.
        .with_free_form_objects(&["headers"]),
        "response_mock" => PluginConfigContract::closed(vec![json!({
            "passthrough_on_no_match": true,
            "rules": [{
                "method": "GET",
                "path": "/users",
                "match": {
                    "headers": {"x-env": "test"},
                    "query_params": {"debug": "1"}
                },
                "status_code": 200,
                "headers": {"x-mock": "1"},
                "body": "{}",
                "delay_ms": 0
            }]
        })])
        // Keyed by operator-chosen header and query-parameter names.
        .with_free_form_objects(&[
            "rules[].headers",
            "rules[].match.headers",
            "rules[].match.query_params",
        ]),
        "fault_injection" => PluginConfigContract::closed(vec![json!({
            "abort": {
                "status_code": 503,
                "percentage": 50.0,
                "grpc_status": 14,
                "body": "{\"error\":\"injected\"}"
            },
            "delay": {"duration_ms": 100, "percentage": 10.0},
            "match": {"headers": {"x-fault": "on"}},
            "expires_at": "2099-01-01T00:00:00Z"
        })])
        // Keyed by operator-chosen request header names.
        .with_free_form_objects(&["match.headers"]),
        _ => return None,
    })
}
