//! Issues #5540/#5541: validate complete shared schemas against resource admission.

use ferrum_edge::config::types::{GatewayConfig, PluginConfig, Proxy, Upstream};
use serde_json::{Value, json};

fn spec() -> Value {
    serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("OpenAPI parses")
}

fn validator(spec: &Value, component: &str) -> jsonschema::Validator {
    jsonschema::draft202012::options()
        .build(&json!({
            "$ref": format!("#/components/schemas/{component}"),
            "components": spec["components"].clone()
        }))
        .expect("resource schema compiles")
}

fn proxy() -> Value {
    json!({
        "listen_path": "/audit",
        "backend_scheme": "http",
        "backend_host": "backend.example",
        "backend_port": 8080,
        "circuit_breaker": {},
        "retry": {}
    })
}

fn upstream() -> Value {
    json!({
        "targets": [{"host": "backend.example", "port": 8080}],
        "hash_on_cookie_config": {},
        "health_checks": {"active": {}, "passive": {}}
    })
}

fn runtime_valid(component: &str, body: &Value) -> bool {
    match component {
        "Proxy" | "ProxyCreate" => {
            let Ok(mut proxy) = serde_json::from_value::<Proxy>(body.clone()) else {
                return false;
            };
            proxy.normalize_fields();
            proxy.validate_fields().is_ok()
                && GatewayConfig {
                    proxies: vec![proxy],
                    ..Default::default()
                }
                .validate_stream_proxies()
                .is_ok()
        }
        "Upstream" | "UpstreamCreate" => serde_json::from_value::<Upstream>(body.clone())
            .is_ok_and(|upstream| upstream.validate_fields().is_ok()),
        "PluginConfigBase" | "PluginConfigCreate" | "PluginConfigReplace" | "PluginConfig" => {
            serde_json::from_value::<PluginConfig>(body.clone()).is_ok_and(|mut plugin| {
                plugin.normalize_fields();
                plugin.validate_fields().is_ok()
            })
        }
        _ => panic!("unknown resource {component}"),
    }
}

fn set_field(body: &mut Value, pointer: &str, value: Value) {
    let (parent, field) = pointer.rsplit_once('/').expect("field pointer");
    body.pointer_mut(parent)
        .expect("parent exists")
        .as_object_mut()
        .expect("parent is an object")
        .insert(field.to_string(), value);
}

fn assert_parity(schema: &jsonschema::Validator, component: &str, body: &Value, expected: bool) {
    assert_eq!(
        schema.is_valid(body),
        expected,
        "{component} schema mismatch: {body}"
    );
    assert_eq!(
        runtime_valid(component, body),
        expected,
        "{component} runtime mismatch: {body}"
    );
}

fn check_bounds(component: &str, baseline: &Value, bounds: &[(&str, i64, i64, bool)]) {
    let schema = validator(&spec(), component);
    assert_parity(&schema, component, baseline, true);
    for &(pointer, minimum, maximum, nullable) in bounds {
        for (value, expected) in [
            (json!(minimum), true),
            (json!(maximum), true),
            (json!(minimum - 1), false),
            (json!(maximum + 1), false),
            (json!(-1), false),
            (json!(u64::MAX), false),
            (json!(18446744073709551616.0_f64), false),
            (json!(minimum as f64 + 0.5), false),
            (Value::Null, nullable),
        ] {
            let mut body = baseline.clone();
            set_field(&mut body, pointer, value);
            assert_parity(&schema, component, &body, expected);
        }
    }
}

#[test]
fn proxy_numeric_bounds_match_runtime_including_nullable_pool_overrides() {
    for component in ["Proxy", "ProxyCreate"] {
        check_bounds(
            component,
            &proxy(),
            &[
                ("/backend_port", 1, 65535, false),
                ("/listen_port", 1, 65535, true),
                ("/backend_connect_timeout_ms", 1, 86400000, false),
                ("/backend_read_timeout_ms", 0, 86400000, false),
                ("/backend_write_timeout_ms", 0, 86400000, false),
                ("/dns_cache_ttl_seconds", 1, 86400, true),
                ("/pool_idle_timeout_seconds", 1, 3600, true),
                ("/pool_tcp_keepalive_seconds", 1, 86400, true),
                ("/pool_http2_keep_alive_interval_seconds", 1, 86400, true),
                ("/pool_http2_keep_alive_timeout_seconds", 1, 86400, true),
                (
                    "/pool_http2_initial_stream_window_size",
                    65535,
                    134217728,
                    true,
                ),
                (
                    "/pool_http2_initial_connection_window_size",
                    65535,
                    134217728,
                    true,
                ),
                ("/pool_http2_max_frame_size", 16384, 1048576, true),
                ("/pool_http2_max_concurrent_streams", 1, 2147483647, true),
                ("/pool_http3_connections_per_backend", 1, 256, true),
                ("/pool_max_requests_per_connection", 0, 2147483647, true),
                ("/tcp_idle_timeout_seconds", 0, 86400, true),
                ("/websocket_idle_timeout_seconds", 0, 86400, true),
                ("/udp_idle_timeout_seconds", 1, 3600, false),
                ("/circuit_breaker/failure_threshold", 1, 10000, false),
                ("/circuit_breaker/success_threshold", 1, 10000, false),
                ("/circuit_breaker/half_open_max_requests", 1, 10000, false),
                ("/circuit_breaker/timeout_seconds", 1, 86400, false),
                ("/circuit_breaker/cooldown_seconds", 1, 86400, false),
                ("/retry/max_retries", 0, 100, false),
            ],
        );
        check_bounds(
            component,
            &json!({"listen_path": "/upstream", "upstream_id": "pool"}),
            &[("/backend_port", 0, 65535, false)],
        );
        for (backoff, fields) in [
            (
                json!({"fixed": {"delay_ms": 0}}),
                vec!["/retry/backoff/fixed/delay_ms"],
            ),
            (
                json!({"exponential": {"base_ms": 0, "max_ms": 300000}}),
                vec![
                    "/retry/backoff/exponential/base_ms",
                    "/retry/backoff/exponential/max_ms",
                ],
            ),
        ] {
            let mut body = proxy();
            body["retry"]["backoff"] = backoff;
            for field in fields {
                check_bounds(component, &body, &[(field, 0, 300000, false)]);
            }
        }
    }
}

#[test]
fn upstream_numeric_bounds_match_runtime_for_targets_health_and_discovery() {
    for component in ["Upstream", "UpstreamCreate"] {
        check_bounds(
            component,
            &upstream(),
            &[
                ("/targets/0/port", 1, 65535, false),
                ("/targets/0/weight", 1, 65535, false),
                ("/hash_on_cookie_config/ttl_seconds", 0, 86400, false),
                ("/health_checks/active/interval_seconds", 1, 3600, false),
                ("/health_checks/active/timeout_ms", 1, 86400000, false),
                ("/health_checks/active/healthy_threshold", 1, 10000, false),
                ("/health_checks/active/unhealthy_threshold", 1, 10000, false),
                ("/health_checks/passive/unhealthy_threshold", 1, 1000, false),
                (
                    "/health_checks/passive/unhealthy_window_seconds",
                    1,
                    86400,
                    false,
                ),
                (
                    "/health_checks/passive/healthy_after_seconds",
                    0,
                    86400,
                    false,
                ),
                ("/health_checks/passive/max_ejection_percent", 0, 100, true),
            ],
        );
        for provider in ["dns_sd", "kubernetes", "consul", "mesh"] {
            let mut body = upstream();
            body["service_discovery"] = json!({
                "provider": provider,
                (provider): {"service_name": "backend"}
            });
            if provider == "consul" {
                body["service_discovery"][provider]["address"] = json!("http://consul:8500");
            }
            let interval = format!("/service_discovery/{provider}/poll_interval_seconds");
            check_bounds(
                component,
                &body,
                &[
                    ("/service_discovery/default_weight", 1, 65535, false),
                    (&interval, 1, 3600, false),
                ],
            );
            if provider == "mesh" {
                check_bounds(
                    component,
                    &body,
                    &[("/service_discovery/mesh/port", 1, 65535, true)],
                );
            }
            let schema = validator(&spec(), component);
            let inactive = if provider == "mesh" { "dns_sd" } else { "mesh" };
            body["service_discovery"][inactive] = json!({
                "service_name": "unused", "poll_interval_seconds": 0
            });
            assert_parity(&schema, component, &body, true);
            for (stale, expected) in [
                (Value::Null, true),
                (json!(0), true),
                (json!(4), false),
                (json!(5), true),
                (json!(86400), true),
                (json!(86401), false),
                (json!(-1), false),
                (json!(u64::MAX), false),
            ] {
                body["service_discovery"]["max_stale_seconds"] = stale;
                assert_parity(&schema, component, &body, expected);
            }
        }
    }
}

#[test]
fn status_code_lists_share_runtime_bounds_and_cardinality() {
    let spec = spec();
    for (component, baseline, fields) in [
        (
            "ProxyCreate",
            proxy(),
            vec![
                "/circuit_breaker/failure_status_codes",
                "/retry/retryable_status_codes",
            ],
        ),
        (
            "UpstreamCreate",
            upstream(),
            vec![
                "/health_checks/active/healthy_status_codes",
                "/health_checks/passive/unhealthy_status_codes",
                "/health_checks/passive/gateway_error_codes",
            ],
        ),
    ] {
        let schema = validator(&spec, component);
        for field in fields {
            for (codes, expected) in [
                (json!([]), true),
                (json!([100, 599]), true),
                (json!([99]), false),
                (json!([600]), false),
                (json!([-1]), false),
                (json!([65536]), false),
                (json!([200.5]), false),
                (json!(vec![200; 500]), true),
                (json!(vec![200; 501]), false),
            ] {
                let mut body = baseline.clone();
                set_field(&mut body, field, codes);
                assert_parity(&schema, component, &body, expected);
            }
        }
    }
}

#[test]
fn proxy_routing_and_stream_controls_match_runtime() {
    let spec = spec();
    for component in ["Proxy", "ProxyCreate"] {
        let schema = validator(&spec, component);
        for (extra, expected) in [
            (json!({"listen_path": null}), false),
            (json!({"listen_path": ""}), false),
            (json!({"listen_path": "", "hosts": ["api.example"]}), false),
            (json!({"listen_path": null, "hosts": ["api.example"]}), true),
            (json!({"listen_path": null, "hosts": []}), false),
            (json!({"backend_scheme": null}), true),
            (json!({"allowed_methods": []}), false),
            (json!({"allowed_methods": ["GET"]}), true),
            (json!({"allowed_methods": null}), true),
            (json!({"passthrough": true}), false),
            (json!({"stream_proxy_protocol": true}), false),
            (json!({"stream_proxy_protocol": false}), true),
            (json!({"stream_proxy_protocol": null}), true),
            (json!({"backend_proxy_protocol": "v2"}), false),
            (json!({"backend_proxy_protocol": null}), true),
            (json!({"stream_match": {}}), false),
            (json!({"stream_match": null}), true),
            (json!({"upstream_subset": ""}), false),
            (json!({"upstream_subset": "v1", "upstream_id": null}), false),
            (
                json!({"upstream_subset": "v1", "upstream_id": "pool"}),
                true,
            ),
            (json!({"upstream_subset": null}), true),
            (json!({"udp_max_response_amplification_factor": 0}), false),
            (json!({"udp_max_response_amplification_factor": 0.5}), true),
            (json!({"websocket_permessage_deflate": "strip"}), true),
            (json!({"websocket_permessage_deflate": "passthrough"}), true),
            (json!({"websocket_permessage_deflate": "terminate"}), true),
            (
                json!({"websocket_permessage_deflate": "Passthrough"}),
                false,
            ),
            (json!({"websocket_permessage_deflate": null}), false),
        ] {
            let mut body = proxy();
            body.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert_parity(&schema, component, &body, expected);
        }
        for scheme in ["http", "https"] {
            let mut body = proxy();
            body["backend_scheme"] = json!(scheme);
            body.as_object_mut().unwrap().remove("listen_path");
            assert_parity(&schema, component, &body, false);
            body["hosts"] = json!(["api.example"]);
            assert_parity(&schema, component, &body, true);
        }
        for scheme in ["tcp", "tcps", "udp", "dtls"] {
            let mut baseline = proxy();
            baseline.as_object_mut().unwrap().remove("listen_path");
            baseline["backend_scheme"] = json!(scheme);
            baseline["listen_port"] = json!(5432);
            assert_parity(&schema, component, &baseline, true);
            for (field, value, expected) in [
                ("listen_port", Value::Null, false),
                ("listen_port", json!(0), false),
                ("backend_scheme", Value::Null, false),
                ("listen_path", json!("/stream"), false),
                ("listen_path", json!(""), false),
                ("listen_path", Value::Null, true),
                ("passthrough", json!(true), true),
                ("stream_proxy_protocol", json!(true), true),
                (
                    "backend_proxy_protocol",
                    json!("v2"),
                    matches!(scheme, "tcp" | "tcps"),
                ),
                ("stream_match", json!({}), matches!(scheme, "tcp" | "tcps")),
                ("response_body_mode", json!("buffer"), false),
                ("websocket_permessage_deflate", json!("passthrough"), false),
                ("websocket_permessage_deflate", json!("terminate"), false),
                ("websocket_permessage_deflate", json!("strip"), true),
                ("websocket_permessage_deflate", json!("bogus"), false),
                (
                    "udp_max_response_amplification_factor",
                    json!(0),
                    matches!(scheme, "udp" | "dtls"),
                ),
                ("udp_max_response_amplification_factor", json!(1024), true),
                ("udp_max_response_amplification_factor", json!(1025), false),
            ] {
                let mut body = baseline.clone();
                body[field] = value;
                assert_parity(&schema, component, &body, expected);
            }
            let mut missing_port = baseline.clone();
            missing_port.as_object_mut().unwrap().remove("listen_port");
            assert_parity(&schema, component, &missing_port, false);
            baseline["passthrough"] = json!(true);
            baseline["frontend_tls"] = json!(true);
            assert_parity(&schema, component, &baseline, false);
        }
    }
}

#[test]
fn upstream_cardinality_and_nonempty_fields_match_runtime() {
    let spec = spec();
    for component in ["Upstream", "UpstreamCreate"] {
        let schema = validator(&spec, component);
        for (pointer, value, expected) in [
            ("/targets", json!([]), false),
            ("/targets/0/host", json!(""), false),
            ("/backend_tls_sni", json!(""), false),
            ("/backend_tls_sni", json!("backend.example"), true),
            ("/backend_tls_sni", Value::Null, true),
            ("/subsets", json!([]), false),
            ("/subsets", Value::Null, true),
            (
                "/subsets",
                json!([{"name": "v1", "labels": {"version": "v1"}}]),
                true,
            ),
            ("/hash_on_cookie_config/path", json!(""), false),
            ("/hash_on_cookie_config/path", json!("/"), true),
            ("/hash_on_cookie_config/domain", json!(""), false),
            ("/hash_on_cookie_config/domain", json!(".example.com"), true),
            ("/hash_on_cookie_config/domain", Value::Null, true),
        ] {
            let mut body = upstream();
            set_field(&mut body, pointer, value);
            assert_parity(&schema, component, &body, expected);
        }
        let mut body = json!({"targets": [], "service_discovery": null});
        assert_parity(&schema, component, &body, false);
        body["service_discovery"] = json!({
            "provider": "dns_sd", "dns_sd": {"service_name": "_http._tcp.backend.example"}
        });
        assert_parity(&schema, component, &body, true);
        body.as_object_mut().unwrap().remove("targets");
        assert_parity(&schema, component, &body, false);
        for (count, expected) in [(1000, true), (1001, false)] {
            let body = json!({"targets": vec![json!({"host": "backend", "port": 80}); count]});
            assert_parity(&schema, component, &body, expected);
        }
        for (count, expected) in [(100, true), (101, false)] {
            let mut body = upstream();
            body["subsets"] = (0..count)
                .map(|index| json!({"name": format!("v{index}"), "labels": {"version": "v1"}}))
                .collect();
            assert_parity(&schema, component, &body, expected);
        }
    }
}

#[test]
fn plugin_attachment_and_name_rules_apply_even_when_disabled() {
    let spec = spec();
    for component in [
        "PluginConfigBase",
        "PluginConfigCreate",
        "PluginConfigReplace",
        "PluginConfig",
    ] {
        let schema = validator(&spec, component);
        check_bounds(
            component,
            &json!({
                "plugin_name": "stdout_logging", "scope": "global",
                "config": {}, "enabled": true
            }),
            &[("/priority_override", 0, 10000, true)],
        );
        for enabled in [true, false] {
            for (extra, expected) in [
                (json!({"scope": "proxy"}), false),
                (json!({"scope": "proxy", "proxy_id": null}), false),
                (json!({"scope": "proxy", "proxy_id": ""}), false),
                (json!({"scope": "proxy", "proxy_id": " "}), false),
                (json!({"scope": "proxy", "proxy_id": "proxy-1"}), true),
                (json!({"scope": "global"}), true),
                (json!({"scope": "proxy_group"}), true),
                (json!({"plugin_name": ""}), false),
                (json!({"plugin_name": "  "}), false),
            ] {
                let mut body = json!({
                    "plugin_name": "stdout_logging", "scope": "global",
                    "config": {}, "enabled": enabled
                });
                body.as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().unwrap().clone());
                assert_parity(&schema, component, &body, expected);
            }
        }
    }
    let create = validator(&spec, "PluginConfigCreate");
    assert_parity(
        &create,
        "PluginConfigCreate",
        &json!({"plugin_name": "stdout_logging", "scope": "proxy", "config": {}}),
        false,
    );
}

#[test]
fn batch_restore_and_crud_share_resource_constraints() {
    let spec = spec();
    for (path, method, component) in [
        ("/proxies", "post", "ProxyCreate"),
        ("/proxies/{id}", "put", "ProxyCreate"),
        ("/upstreams", "post", "UpstreamCreate"),
        ("/upstreams/{id}", "put", "UpstreamCreate"),
        ("/plugins/config", "post", "PluginConfigCreate"),
        ("/plugins/config/{id}", "put", "PluginConfigReplace"),
    ] {
        assert_eq!(
            spec["paths"][path][method]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            json!(format!("#/components/schemas/{component}"))
        );
    }
    for component in ["BatchCreateRequest", "RestoreRequest"] {
        let schema = validator(&spec, component);
        for (field, valid, invalid) in [
            (
                "proxies",
                json!({"id": "proxy-1", "hosts": ["api.example"], "upstream_id": "pool"}),
                json!({"id": "proxy-1", "listen_path": "", "upstream_id": "pool"}),
            ),
            (
                "upstreams",
                json!({"id": "pool", "targets": [{"host": "backend.example", "port": 80}]}),
                json!({"id": "pool", "targets": []}),
            ),
            (
                "plugin_configs",
                json!({
                    "id": "plugin-1", "plugin_name": "stdout_logging", "scope": "proxy",
                    "proxy_id": "proxy-1", "config": {}, "enabled": false
                }),
                json!({
                    "id": "plugin-1", "plugin_name": "stdout_logging", "scope": "proxy",
                    "config": {}, "enabled": false
                }),
            ),
        ] {
            assert!(
                schema.is_valid(&json!({(field): [valid]})),
                "{component}.{field}"
            );
            assert!(
                !schema.is_valid(&json!({(field): [invalid]})),
                "{component}.{field}"
            );
        }
    }
}

fn check_schema_examples(spec: &Value, schema: &Value, path: &str) -> usize {
    let mut checked = 0;
    if let Some(examples) = schema.get("examples").and_then(Value::as_array) {
        let validator = jsonschema::draft202012::options()
            .build(&json!({"allOf": [schema], "components": spec["components"]}))
            .expect("example schema compiles");
        for example in examples {
            assert!(
                validator.is_valid(example),
                "invalid example at {path}: {example}"
            );
            checked += 1;
        }
    }
    match schema {
        Value::Object(object) => {
            for (key, child) in object {
                if !matches!(key.as_str(), "examples" | "example" | "default") {
                    checked += check_schema_examples(spec, child, &format!("{path}/{key}"));
                }
            }
        }
        Value::Array(children) => {
            for (index, child) in children.iter().enumerate() {
                checked += check_schema_examples(spec, child, &format!("{path}/{index}"));
            }
        }
        _ => {}
    }
    checked
}

#[test]
fn tightened_resource_schema_examples_remain_valid() {
    let spec = spec();
    let mut checked = 0;
    for component in [
        "Proxy",
        "ProxyCreate",
        "Upstream",
        "UpstreamCreate",
        "UpstreamTarget",
        "HashOnCookieConfig",
        "CircuitBreakerConfig",
        "RetryConfig",
        "BackoffStrategy",
        "HealthCheckConfig",
        "ActiveHealthCheck",
        "PassiveHealthCheck",
        "ServiceDiscoveryConfig",
        "PluginConfigBase",
        "PluginConfigCreate",
        "PluginConfigReplace",
        "PluginConfig",
    ] {
        let schema = &spec["components"]["schemas"][component];
        checked += check_schema_examples(&spec, schema, component);
        if let Some(examples) = schema["examples"].as_array() {
            for example in examples {
                assert!(runtime_valid(component, example), "{component}: {example}");
            }
        }
    }
    assert!(
        checked >= 12,
        "resource and field examples must be exercised"
    );
}
