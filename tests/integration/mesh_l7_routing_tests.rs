use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::config::types::{GatewayConfig, LoadBalancerAlgorithm, PluginConfig, Proxy};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::Value;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: if kind == "VirtualService" {
            "networking.istio.io/v1beta1".to_string()
        } else {
            "gateway.networking.k8s.io/v1".to_string()
        },
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: "sample".to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn dispatch_plugin_for_proxy<'a>(config: &'a GatewayConfig, proxy: &Proxy) -> &'a PluginConfig {
    config
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("mesh_route_dispatch plugin for proxy")
}

#[tokio::test]
async fn mesh_l7_routing_http_route_header_only_match_is_enforced() {
    let result = translate_k8s_objects(
        &[object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{"headers": [{"name": "x-canary", "value": "true"}]}],
                    "backendRefs": [{"name": "canary", "port": 8080}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("/"))
        .expect("catch-all proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(true)
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut headers = HashMap::from([("x-canary".to_string(), "true".to_string())]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/anything".to_string(),
    );
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(8080));

    let mut missing_headers = HashMap::new();
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/anything".to_string(),
    );
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut missing_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_istio_query_match_sets_route_override() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{
                        "queryParams": {"variant": {"exact": "beta"}}
                    }],
                    "route": [{"destination": {"host": "beta.default.svc.cluster.local", "port": {"number": 9090}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("~.*"))
        .expect("URI-less catch-all proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["query_params"]["variant"].as_str(),
        Some("beta")
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut headers = HashMap::new();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/search?variant=beta".to_string(),
    );
    ctx.query_params
        .insert("variant".to_string(), "beta".to_string());
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("beta.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(9090));
}

#[test]
fn mesh_l7_routing_virtual_service_weighted_split_uses_generated_upstream_weights() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"headers": {"x-canary": {"exact": "true"}}}],
                    "route": [
                        {"destination": {"host": "v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 900},
                        {"destination": {"host": "v2.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 90},
                        {"destination": {"host": "v3.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 10}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let upstream = result
        .config
        .upstreams
        .iter()
        .find(|upstream| upstream.targets.len() == 3)
        .expect("weighted upstream");
    assert_eq!(
        upstream.algorithm,
        LoadBalancerAlgorithm::WeightedRoundRobin
    );
    let plugin = result
        .config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .expect("dispatch plugin");
    assert_eq!(
        plugin.config["rules"][0]["destination"]["upstream_id"].as_str(),
        Some(upstream.id.as_str())
    );

    let lb = LoadBalancerCache::new(&result.config);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for i in 0..1000 {
        let target = lb
            .select_target("default", &upstream.id, &i.to_string(), None)
            .expect("target")
            .target;
        *counts.entry(target.host.clone()).or_default() += 1;
    }

    let v1 = counts
        .get("v1.default.svc.cluster.local")
        .copied()
        .unwrap_or_default();
    let v2 = counts
        .get("v2.default.svc.cluster.local")
        .copied()
        .unwrap_or_default();
    let v3 = counts
        .get("v3.default.svc.cluster.local")
        .copied()
        .unwrap_or_default();
    assert_eq!(v1, 900);
    assert_eq!(v2, 90);
    assert_eq!(v3, 10);
}

#[tokio::test]
async fn mesh_l7_routing_collapsed_istio_route_overrides_timeout_and_retry() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-canary": {"exact": "true"}}
                        }],
                        "timeout": "2s",
                        "retries": {
                            "attempts": 2,
                            "retryOn": "5xx,connect-failure",
                            "backoff": {"fixedDelay": "25ms"}
                        },
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    },
                    {
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let stable_proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| {
            proxy.listen_path.as_deref() == Some("/api")
                && proxy.backend_host == "stable.default.svc.cluster.local"
        })
        .expect("stable proxy selected by hot router");
    assert_eq!(stable_proxy.backend_read_timeout_ms, 30_000);
    assert!(stable_proxy.retry.is_none());

    let plugin_config = dispatch_plugin_for_proxy(&result.config, stable_proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["timeout_ms"].as_u64(),
        Some(2000)
    );
    assert_eq!(
        plugin_config.config["rules"][0]["retry"]["max_retries"].as_u64(),
        Some(2)
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::from([("x-canary".to_string(), "true".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let effective =
        ctx.apply_route_overrides_with_upstreams(Arc::new(stable_proxy.clone()), &HashMap::new());
    assert_eq!(effective.backend_host, "canary.default.svc.cluster.local");
    assert_eq!(effective.backend_port, 9090);
    assert_eq!(effective.backend_read_timeout_ms, 2000);
    assert_eq!(
        effective.retry.as_ref().map(|retry| retry.max_retries),
        Some(2)
    );

    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Continue
    ));
    let effective_miss = miss_ctx
        .apply_route_overrides_with_upstreams(Arc::new(stable_proxy.clone()), &HashMap::new());
    assert_eq!(
        effective_miss.backend_host,
        "stable.default.svc.cluster.local"
    );
    assert_eq!(effective_miss.backend_read_timeout_ms, 30_000);
    assert!(effective_miss.retry.is_none());
}

// ── VirtualService route-level header transforms ──────────────────────────
//
// Istio `VirtualService.http[].headers.{request,response}.{set,add,remove}`
// projects onto each emitted `mesh_route_dispatch` rule as
// `request_transform` / `response_transform` arrays, and the translator
// auto-emits a `request_transformer` / `response_transformer` instance so
// the per-rule transforms have a consumer at runtime.

#[tokio::test]
async fn mesh_l7_routing_virtual_service_header_set_emits_request_transform() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/v1"}}],
                    "headers": {
                        "request": {
                            "set": {"X-Api-Version": "v1"},
                            "add": {"X-Trace": "added"},
                            "remove": ["X-Debug"]
                        }
                    },
                    "route": [{"destination": {"host": "v1.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("/v1"))
        .expect("/v1 proxy");

    // Dispatch plugin must carry the per-rule request_transform array.
    let dispatch = dispatch_plugin_for_proxy(&result.config, proxy);
    let transforms = dispatch.config["rules"][0]["request_transform"]
        .as_array()
        .expect("request_transform array");
    assert_eq!(transforms.len(), 3, "set + add + remove → 3 rules");
    assert!(
        transforms
            .iter()
            .any(|r| r["operation"] == "update" && r["key"] == "X-Api-Version")
    );
    assert!(
        transforms
            .iter()
            .any(|r| r["operation"] == "add" && r["key"] == "X-Trace")
    );
    assert!(
        transforms
            .iter()
            .any(|r| r["operation"] == "remove" && r["key"] == "X-Debug")
    );

    // Translator must auto-emit a request_transformer instance on this
    // proxy so the per-rule overrides have a consumer at runtime.
    let auto_xform = result
        .config
        .plugin_configs
        .iter()
        .find(|p| {
            p.plugin_name == "request_transformer"
                && p.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("auto-emitted request_transformer plugin for proxy");
    assert_eq!(
        auto_xform.config["apply_route_overrides"].as_bool(),
        Some(true)
    );
    assert!(
        auto_xform.config["rules"].as_array().unwrap().is_empty(),
        "auto-emitted instance carries only route-level rules, no static ones"
    );

    // End-to-end: when the dispatch rule matches, the per-rule Arc lands on
    // the context, and applying it via the auto-emitted transformer rewrites
    // headers. We exercise both halves via the plugin classes directly.
    use ferrum_edge::plugins::request_transformer::RequestTransformer;
    let mrd = MeshRouteDispatch::new(&dispatch.config).expect("mrd plugin");
    let req_xform = RequestTransformer::new(&auto_xform.config).expect("auto request_transformer");
    assert!(req_xform.modifies_request_headers());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/v1/items".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("x-debug".to_string(), "yes".to_string());
    let _ = mrd.before_proxy(&mut ctx, &mut headers).await;
    let _ = req_xform.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("x-api-version").map(String::as_str), Some("v1"));
    assert_eq!(headers.get("x-trace").map(String::as_str), Some("added"));
    assert!(!headers.contains_key("x-debug"));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_header_remove_emits_response_transform() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/v1"}}],
                    "headers": {
                        "response": {
                            "set": {"X-Backend": "v1"},
                            "remove": ["Server"]
                        }
                    },
                    "route": [{"destination": {"host": "v1.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("/v1"))
        .expect("/v1 proxy");
    let dispatch = dispatch_plugin_for_proxy(&result.config, proxy);

    let transforms = dispatch.config["rules"][0]["response_transform"]
        .as_array()
        .expect("response_transform array");
    assert_eq!(transforms.len(), 2);
    // Request side must NOT be populated when the VS only configured
    // response-side transforms.
    assert!(
        dispatch.config["rules"][0]
            .get("request_transform")
            .is_none()
    );

    let auto_xform = result
        .config
        .plugin_configs
        .iter()
        .find(|p| {
            p.plugin_name == "response_transformer"
                && p.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("auto-emitted response_transformer plugin for proxy");
    assert_eq!(
        auto_xform.config["apply_route_overrides"].as_bool(),
        Some(true)
    );

    // No auto-emitted request_transformer when there are only response
    // transforms — the translator must avoid emitting plugins that would be
    // no-ops.
    let request_xform_emitted = result.config.plugin_configs.iter().any(|p| {
        p.plugin_name == "request_transformer" && p.proxy_id.as_deref() == Some(proxy.id.as_str())
    });
    assert!(
        !request_xform_emitted,
        "translator must not emit a request_transformer when only response-side transforms exist"
    );
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_headers_route_scope_does_not_leak_across_paths() {
    // Two http[] entries; only the /v1 entry has a header transform. The
    // header transform must NOT show up on the /v2 proxy.
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "headers": {"request": {"set": {"X-Api-Version": "v1"}}},
                        "route": [{"destination": {"host": "v1.default.svc.cluster.local", "port": {"number": 8080}}}]
                    },
                    {
                        "match": [{"uri": {"prefix": "/v2"}}],
                        "route": [{"destination": {"host": "v2.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let v1_proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/v1"))
        .expect("/v1 proxy");
    let v2_proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/v2"))
        .expect("/v2 proxy");

    // /v1's dispatch plugin carries request_transform; /v2's does not.
    let v1_dispatch = dispatch_plugin_for_proxy(&result.config, v1_proxy);
    assert!(
        v1_dispatch.config["rules"][0]["request_transform"]
            .as_array()
            .is_some_and(|arr| !arr.is_empty())
    );
    let v2_dispatch_plugin = result.config.plugin_configs.iter().find(|p| {
        p.plugin_name == "mesh_route_dispatch"
            && p.proxy_id.as_deref() == Some(v2_proxy.id.as_str())
    });
    if let Some(v2_dispatch) = v2_dispatch_plugin {
        // The /v2 proxy may have a dispatch plugin only if its match has a
        // non-URI predicate; in this VS it does not, so the dispatch plugin
        // may be absent. If present, no rule must carry request_transform.
        for rule in v2_dispatch.config["rules"]
            .as_array()
            .unwrap_or(&Vec::new())
        {
            assert!(rule.get("request_transform").is_none());
        }
    }

    // Only /v1's proxy gets the auto-emitted request_transformer.
    let v1_has_xform = result.config.plugin_configs.iter().any(|p| {
        p.plugin_name == "request_transformer"
            && p.proxy_id.as_deref() == Some(v1_proxy.id.as_str())
    });
    let v2_has_xform = result.config.plugin_configs.iter().any(|p| {
        p.plugin_name == "request_transformer"
            && p.proxy_id.as_deref() == Some(v2_proxy.id.as_str())
    });
    assert!(v1_has_xform);
    assert!(!v2_has_xform);
}

// ── VirtualService regex / prefix method matchers (T1-B.2) ─────────────────
//
// VirtualService `match[].method.regex` and `match[].method.prefix` are now
// first-class mesh_route_dispatch predicates. Each test below exercises the
// full translator → plugin construction → request hot path: the translator
// emits the tagged StringMatch shape, the plugin compiles the regex once
// at config-load time and uppercases prefix/regex patterns (methods are
// uppercase ASCII per RFC 9110 §9.1), and the request path routes vs
// 404s based on the pre-compiled matcher.

#[tokio::test]
async fn mesh_l7_routing_virtual_service_method_regex_match_routes_and_misses_fall_closed() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/api"},
                        "method": {"regex": "^(POST|PUT|PATCH)$"}
                    }],
                    "route": [{"destination": {"host": "writes.default.svc.cluster.local", "port": {"number": 9090}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    // Translator emits the tagged regex shape, NOT a request_termination.
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["methods"][0]["regex"].as_str(),
        Some("^(POST|PUT|PATCH)$")
    );
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(true),
        "guarded-route VS still enforces match semantics via reject_unmatched"
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match: each method satisfies the regex → route override applies.
    for method in ["POST", "PUT", "PATCH"] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            "/api/items".to_string(),
        );
        let mut headers = HashMap::new();
        assert!(
            matches!(
                dispatch.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "regex must match {method}"
        );
        assert_eq!(
            ctx.route_override_backend_host.as_deref(),
            Some("writes.default.svc.cluster.local"),
            "{method} should route to the writes backend"
        );
        assert_eq!(ctx.route_override_backend_port, Some(9090));
    }

    // Miss: GET does not satisfy the regex → 404, not silent fall-through to
    // the default backend (Envoy parity for VirtualService match semantics).
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_method_prefix_match_routes_and_falls_through_on_miss() {
    // Soft-fallback flavor of the regex test: a URI-only sibling branch
    // disables `reject_unmatched`, so prefix misses fall through to the
    // default backend rather than 404.
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [
                        {"uri": {"prefix": "/api"}},
                        {
                            "uri": {"prefix": "/api"},
                            "method": {"prefix": "PO"}
                        }
                    ],
                    "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["methods"][0]["prefix"].as_str(),
        Some("PO")
    );
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(false),
        "URI-only sibling disables reject_unmatched"
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match: POST starts with "PO".
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::new();
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    // Prefix match emits the same proxy's default backend on this VS, so the
    // override and the proxy's defaults agree — that's the intentional shape
    // of this fixture. The assertion is that the plugin Continued.

    // Miss: GET does not start with "PO" → fall through to the default proxy
    // backend (Continue, no override).
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Continue
    ));
    assert!(miss_ctx.route_override_backend_host.is_none());
}

// ── VirtualService regex / prefix header matchers (T1-B.1) ─────────────────
//
// VirtualService `match[].headers.X.regex` and `match[].headers.X.prefix`
// are now first-class mesh_route_dispatch predicates. Each test below
// exercises the full translator → plugin construction → request hot path:
// the translator emits the tagged StringMatch shape, the plugin compiles
// the regex once at config-load time, and the request path routes vs
// falls through (or 404s, depending on `reject_unmatched`) based on the
// pre-compiled matcher.

#[tokio::test]
async fn mesh_l7_routing_virtual_service_header_regex_match_routes_and_misses_fall_closed() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/api"},
                        "headers": {"x-user": {"regex": "^admin-.*"}}
                    }],
                    "route": [{"destination": {"host": "admin.default.svc.cluster.local", "port": {"number": 9090}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    // Translator emits the tagged regex shape, NOT a request_termination.
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["headers"]["x-user"]["regex"].as_str(),
        Some("^admin-.*")
    );
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(true),
        "guarded-route VS still enforces match semantics via reject_unmatched"
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match: header value satisfies the regex → route override applies.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::from([("x-user".to_string(), "admin-acme".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("admin.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(9090));

    // Miss: header present but regex misses → 404, not silent fall-through to
    // the default backend (Envoy parity for VirtualService match semantics).
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::from([("x-user".to_string(), "user-acme".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_header_prefix_match_routes_and_falls_through_on_miss() {
    // Soft-fallback flavor of the regex test: a URI-only sibling branch
    // disables `reject_unmatched`, so prefix misses fall through to the
    // default backend rather than 404. This is the existing
    // `mesh_l7_routing_mixed_uri_only_and_header_match` shape, extended
    // with a prefix predicate instead of exact.
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [
                        {"uri": {"prefix": "/api"}},
                        {
                            "uri": {"prefix": "/api"},
                            "headers": {"x-tenant": {"prefix": "admin-"}}
                        }
                    ],
                    "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["headers"]["x-tenant"]["prefix"].as_str(),
        Some("admin-")
    );
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(false),
        "URI-only sibling disables reject_unmatched"
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::from([("x-tenant".to_string(), "admin-acme".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    // Prefix match emits the same proxy's default backend on this VS, so the
    // override and the proxy's defaults agree — that's the intentional
    // shape of this fixture. The assertion is that the plugin Continued.

    // Miss: fall through to the default proxy backend (Continue, no override).
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::from([("x-tenant".to_string(), "user-acme".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Continue
    ));
    assert!(miss_ctx.route_override_backend_host.is_none());
}

// -- VirtualService sourceNamespace matcher (T1-B.4) ----------------------
//
// VirtualService `match[].sourceNamespace` is now a first-class
// mesh_route_dispatch predicate. The test below exercises the full
// translator → plugin construction → request hot path: the translator emits
// the bare-string `source_namespace` field, and the plugin's hot path
// resolves the source workload namespace from `ctx.peer_spiffe_id` via the
// `SpiffeId::namespace` helper (the same path-segment walk that `mesh_authz`
// uses for `namespace_pattern`, so the two surfaces cannot drift).
//
// The predicate is Istio exact-only (no `prefix`/`regex` arms in the CRD)
// and case-sensitive: Kubernetes namespaces are RFC 1123 lowercase and the
// matcher does not silently fold operator-provided casing. Outside mesh mode
// (no peer SPIFFE identity) the predicate fails closed.

#[tokio::test]
async fn mesh_l7_routing_virtual_service_source_namespace_match_routes_and_misses_fall_closed() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/api"},
                        "sourceNamespace": "prod"
                    }],
                    "route": [{"destination": {"host": "prod.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["source_namespace"].as_str(),
        Some("prod")
    );
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(true),
        "guarded-route VS still enforces match semantics via reject_unmatched"
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match: source peer identity is from `prod` namespace → route override applies.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    ctx.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/prod/sa/billing").expect("valid spiffe id"));
    let mut headers = HashMap::new();
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("prod.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(8080));

    // Miss: source peer identity is from a different namespace → 404 (not
    // silent fall-through to the default backend). This is the fail-closed
    // VirtualService semantic that the request_termination shim used to
    // provide; now it comes from the plugin's `reject_unmatched: true`.
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    miss_ctx.peer_spiffe_id = Some(
        SpiffeId::new("spiffe://cluster.local/ns/staging/sa/billing").expect("valid spiffe id"),
    );
    let mut miss_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));

    // Miss: request carries no peer SPIFFE identity (non-mesh path) → 404.
    // The predicate cannot match an absent identity; failing closed avoids
    // silently routing every unauthenticated request to the gated backend.
    let mut nomesh_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut nomesh_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut nomesh_ctx, &mut nomesh_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

// -- VirtualService authority matcher (T1-B.3) ----------------------------
//
// VirtualService `match[].authority.{exact,prefix,regex}` is now a
// first-class mesh_route_dispatch predicate. Each test below exercises the
// full translator → plugin construction → request hot path: the translator
// emits the correct StringMatch shape, the plugin compiles regex once at
// config-load time, and the request path routes vs 404s based on a raw
// `Host`/`:authority` StringMatch. Istio exact/prefix authority predicates
// are case-sensitive and explicit request ports are part of the matched value.

#[tokio::test]
async fn mesh_l7_routing_virtual_service_authority_exact_match_routes_and_misses_fall_closed() {
    // VirtualService `hosts: ["*.example.com"]` admits any subdomain, but a
    // per-rule `authority.exact: "internal.example.com"` narrows that route
    // to a single authority. Other admitted hosts on the same proxy must
    // fail closed via `reject_unmatched`.
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["*.example.com"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/api"},
                        "authority": {"exact": "internal.example.com"}
                    }],
                    "route": [{"destination": {"host": "internal.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["authority"].as_str(),
        Some("internal.example.com")
    );
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(true),
        "guarded-route VS still enforces match semantics via reject_unmatched"
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match: request `Host` equals the gated authority → route override applies.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::from([("host".to_string(), "internal.example.com".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("internal.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(8080));

    // Miss: Istio StringMatch exact is case-sensitive even for authority.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::from([("host".to_string(), "INTERNAL.EXAMPLE.COM".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));

    // Miss: explicit request ports are not stripped for the authority predicate.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut headers =
        HashMap::from([("host".to_string(), "internal.example.com:8443".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));

    // Miss: a different authority on the same wildcard-admitted proxy must
    // 404, not silently fall through to the default backend.
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::from([("host".to_string(), "public.example.com".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_authority_prefix_match_routes_and_misses_fall_closed() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["*.example.com"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/api"},
                        "authority": {"prefix": "api."}
                    }],
                    "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["authority"]["prefix"].as_str(),
        Some("api.")
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match: each host starts with "api." → routes to the configured backend.
    for host in ["api.example.com", "api.staging.example.com"] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api/items".to_string(),
        );
        let mut headers = HashMap::from([("host".to_string(), host.to_string())]);
        assert!(
            matches!(
                dispatch.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "prefix must match {host}"
        );
        assert_eq!(
            ctx.route_override_backend_host.as_deref(),
            Some("api.default.svc.cluster.local")
        );
    }

    // Miss: host doesn't start with the prefix → 404 (reject_unmatched).
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::from([("host".to_string(), "admin.example.com".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));

    // Miss: authority prefix matching is case-sensitive.
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::from([("host".to_string(), "API.example.com".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_authority_regex_match_routes_and_misses_fall_closed() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["*.example.com"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/api"},
                        "authority": {"regex": "^api\\.(prod|staging)\\.example\\.com$"}
                    }],
                    "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["authority"]["regex"].as_str(),
        Some("^api\\.(prod|staging)\\.example\\.com$")
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match: hosts that satisfy the regex.
    for host in ["api.prod.example.com", "api.staging.example.com"] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api/items".to_string(),
        );
        let mut headers = HashMap::from([("host".to_string(), host.to_string())]);
        assert!(
            matches!(
                dispatch.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "regex must match {host}"
        );
    }

    // Miss: regex doesn't match → 404.
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::from([("host".to_string(), "api.example.com".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

// ── VirtualService ignoreUriCase URI matcher (T1-B.5) ──────────────────────
//
// `ignoreUriCase: true` on a VirtualService match entry is now first-class.
// The translator widens the URI's listen_path to a case-insensitive regex
// so the proxy router admits both casings, and emits a `mesh_route_dispatch`
// rule carrying the original URI predicate + `ignore_uri_case: true`. The
// plugin re-evaluates with ASCII-only case folding (no Unicode equivalence
// — non-ASCII bytes compare byte-for-byte) and routes both casings to the
// override destination without per-request allocation.

#[tokio::test]
async fn mesh_l7_routing_virtual_service_ignore_uri_case_routes_both_casings() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/Api"},
                        "ignoreUriCase": true
                    }],
                    "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    // The proxy's listen_path is widened to a case-insensitive regex.
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("~(?i:/Api.*)"))
        .expect("widened case-insensitive listen_path");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    // The dispatch rule carries the operator's original URI predicate AND
    // the `ignore_uri_case: true` flag.
    let match_obj = &plugin_config.config["rules"][0]["match"];
    assert_eq!(match_obj["uri"]["prefix"].as_str(), Some("/Api"));
    assert_eq!(match_obj["ignore_uri_case"].as_bool(), Some(true));

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Both casings match — neither hits the implicit deny.
    for path in ["/api/items", "/API/items", "/Api/items"] {
        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), path.to_string());
        let mut headers = HashMap::new();
        assert!(
            matches!(
                dispatch.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ),
            "case-insensitive prefix must match {path}"
        );
    }

    // A non-prefix-matching path does not match the URI predicate, so the
    // dispatch rule does not fire and the override destination is not set.
    // With `ignoreUriCase: true`, the dispatch rule carries an explicit URI
    // predicate so its match_criteria is non-empty — `reject_unmatched: true`
    // applies and the plugin returns a 404 Reject (Envoy parity). In real
    // traffic the widened `~(?i:/Api.*)` regex listen_path would not have
    // admitted `/store/items` in the first place; the dispatch-level URI
    // check is defense-in-depth.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/store/items".to_string(),
    );
    let mut headers = HashMap::new();
    let result = dispatch.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 404,
                ..
            }
        ),
        "non-matching path must trip reject_unmatched (Envoy parity)"
    );
    assert!(
        ctx.route_override_upstream_id.is_none(),
        "non-matching path must not trigger the override destination"
    );
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_ignore_uri_case_fallback_keeps_original_uri_guard() {
    // Route order case:
    // 1. `/Api`, ignoreUriCase, plus header gate -> canary
    // 2. `/api` URI-only -> stable
    //
    // Ferrum collapses these onto one widened proxy to preserve Istio route
    // order, but the stable fallback must still carry its original
    // case-sensitive URI. Otherwise `/API` without the canary header would be
    // widened into stable even though no Istio route admitted it.
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/Api"},
                            "ignoreUriCase": true,
                            "headers": {"x-canary": {"exact": "v2"}}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    },
                    {
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("~(?i:/Api.*)"))
        .expect("widened listen_path");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(true)
    );
    assert_eq!(
        plugin_config.config["rules"].as_array().map(Vec::len),
        Some(2)
    );
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    let mut canary_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/API/items".to_string(),
    );
    let mut canary_headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut canary_ctx, &mut canary_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        canary_ctx.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );

    let mut stable_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut stable_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut stable_ctx, &mut stable_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        stable_ctx.route_override_backend_host.as_deref(),
        Some("stable.default.svc.cluster.local")
    );

    let mut widened_miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/API/items".to_string(),
    );
    let mut widened_miss_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut widened_miss_ctx, &mut widened_miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_ignore_uri_case_later_predicate_keeps_uri_guard() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/Api"},
                            "ignoreUriCase": true,
                            "headers": {"x-canary": {"exact": "v2"}}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    },
                    {
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "method": {"exact": "GET"}
                        }],
                        "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("~(?i:/Api.*)"))
        .expect("widened listen_path");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    let mut stable_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut stable_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut stable_ctx, &mut stable_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        stable_ctx.route_override_backend_host.as_deref(),
        Some("stable.default.svc.cluster.local")
    );

    let mut widened_miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/API/items".to_string(),
    );
    let mut widened_miss_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut widened_miss_ctx, &mut widened_miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_ignore_uri_case_inverse_order_guards_pending_route() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-canary": {"exact": "v2"}}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    },
                    {
                        "match": [{
                            "uri": {"prefix": "/Api"},
                            "ignoreUriCase": true
                        }],
                        "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("~(?i:/Api.*)"))
        .expect("widened listen_path");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    let mut canary_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut canary_headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut canary_ctx, &mut canary_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        canary_ctx.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );

    let mut stable_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/API/items".to_string(),
    );
    let mut stable_headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut stable_ctx, &mut stable_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        stable_ctx.route_override_backend_host.as_deref(),
        Some("stable.default.svc.cluster.local")
    );
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_ignore_uri_case_inverse_prefix_exact_preserves_fallthrough()
 {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-canary": {"exact": "v2"}}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    },
                    {
                        "match": [{
                            "uri": {"exact": "/Api"},
                            "ignoreUriCase": true
                        }],
                        "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        !result
            .config
            .proxies
            .iter()
            .any(|p| p.listen_path.as_deref() == Some("/api")),
        "the earlier prefix proxy must be consumed so predicate misses can fall through"
    );
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("~(?i:/api.*)"))
        .expect("synthesized widened prefix proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    let mut canary_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    let mut canary_headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut canary_ctx, &mut canary_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        canary_ctx.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );

    let mut stable_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    let mut stable_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut stable_ctx, &mut stable_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        stable_ctx.route_override_backend_host.as_deref(),
        Some("stable.default.svc.cluster.local")
    );

    let mut exact_miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/foo".to_string(),
    );
    let mut exact_miss_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut exact_miss_ctx, &mut exact_miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));

    let mut case_sensitive_miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/API".to_string(),
    );
    let mut case_sensitive_headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut case_sensitive_miss_ctx, &mut case_sensitive_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        case_sensitive_miss_ctx
            .route_override_backend_host
            .as_deref(),
        Some("stable.default.svc.cluster.local")
    );
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_ignore_uri_case_chained_inverse_prefix_consumes_later_route()
 {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-canary": {"exact": "v2"}}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    },
                    {
                        "match": [{
                            "uri": {"exact": "/Api"},
                            "ignoreUriCase": true
                        }],
                        "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                    },
                    {
                        "match": [{"uri": {"prefix": "/api/foo"}}],
                        "route": [{"destination": {"host": "foo.default.svc.cluster.local", "port": {"number": 7070}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        !result
            .config
            .proxies
            .iter()
            .any(|p| { matches!(p.listen_path.as_deref(), Some("/api") | Some("/api/foo")) }),
        "no stale prefix-tier proxy should bypass the widened ordered dispatcher"
    );
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("~(?i:/api.*)"))
        .expect("synthesized widened prefix proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    let mut canary_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    let mut canary_headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut canary_ctx, &mut canary_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        canary_ctx.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );

    let mut stable_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/API".to_string(),
    );
    let mut stable_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut stable_ctx, &mut stable_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        stable_ctx.route_override_backend_host.as_deref(),
        Some("stable.default.svc.cluster.local")
    );

    let mut foo_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/foo/bar".to_string(),
    );
    let mut foo_headers = HashMap::new();
    assert!(matches!(
        dispatch.before_proxy(&mut foo_ctx, &mut foo_headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        foo_ctx.route_override_backend_host.as_deref(),
        Some("foo.default.svc.cluster.local")
    );

    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/bar".to_string(),
    );
    let mut miss_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));

    let mut case_sensitive_miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/API/foo".to_string(),
    );
    let mut case_sensitive_headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut case_sensitive_miss_ctx, &mut case_sensitive_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_ignore_uri_case_prefix_preserves_order_before_exact() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/Api"},
                            "ignoreUriCase": true,
                            "headers": {"x-canary": {"exact": "v2"}}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    },
                    {
                        "match": [{"uri": {"exact": "/api/admin"}}],
                        "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("~(?i:/Api.*)"))
        .expect("widened listen_path");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    let mut canary_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/admin".to_string(),
    );
    let mut canary_headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut canary_ctx, &mut canary_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        canary_ctx.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );

    let mut stable_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/admin".to_string(),
    );
    let mut stable_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut stable_ctx, &mut stable_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        stable_ctx.route_override_backend_host.as_deref(),
        Some("stable.default.svc.cluster.local")
    );
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_ignore_uri_case_with_method_and_headers() {
    // Mixed: case-folded URI prefix + case-sensitive method + case-sensitive
    // header. All-of semantics: every predicate must hold.
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/Api"},
                        "ignoreUriCase": true,
                        "method": {"exact": "POST"},
                        "headers": {"x-canary": {"exact": "v2"}}
                    }],
                    "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("~(?i:/Api.*)"))
        .expect("widened listen_path");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // All three predicates hold → route override applies.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );

    // URI fold matches, method wrong → reject (reject_unmatched is true for
    // multi-predicate routes, matching Envoy semantics).
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/API/items".to_string(),
    );
    let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

// ── Matchless VirtualService routes with header transforms ────────────────
//
// A VirtualService http[] entry may omit the `match` key entirely while still
// defining `headers.{request,response}.{set,add,remove}` transforms. The
// translator must emit a catch-all dispatch rule that carries those transforms
// rather than silently dropping them via early return.

#[tokio::test]
async fn matchless_virtualservice_preserves_header_transforms() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    // No "match" key at all — this is a matchless route.
                    "headers": {
                        "request": {
                            "set": {"X-Injected": "yes"},
                            "add": {"X-Extra": "added"},
                            "remove": ["X-Strip"]
                        }
                    },
                    "route": [{"destination": {"host": "backend.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    // A matchless http[] produces a "/" proxy.
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/"))
        .expect("/ proxy must exist for matchless VS");

    // The dispatch plugin must exist and carry the transforms on a catch-all rule.
    let dispatch = result
        .config
        .plugin_configs
        .iter()
        .find(|p| {
            p.plugin_name == "mesh_route_dispatch"
                && p.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("mesh_route_dispatch plugin must be emitted for matchless route with transforms");

    let rules = dispatch.config["rules"].as_array().expect("rules array");
    assert!(
        !rules.is_empty(),
        "matchless route with transforms must emit at least one rule"
    );

    // The catch-all rule should have an empty match (no predicates) and carry
    // request_transform with the three operations (set → update, add, remove).
    let catch_all = &rules[rules.len() - 1];
    let match_obj = catch_all["match"]
        .as_object()
        .expect("match object on catch-all rule");
    assert!(
        match_obj.is_empty(),
        "catch-all rule match must be empty (no predicates)"
    );

    let transforms = catch_all["request_transform"]
        .as_array()
        .expect("request_transform array on catch-all rule");
    assert_eq!(transforms.len(), 3, "set + add + remove → 3 transform ops");
    assert!(
        transforms
            .iter()
            .any(|r| r["operation"] == "update" && r["key"] == "X-Injected"),
        "set must emit as update operation"
    );
    assert!(
        transforms
            .iter()
            .any(|r| r["operation"] == "add" && r["key"] == "X-Extra"),
        "add must emit as add operation"
    );
    assert!(
        transforms
            .iter()
            .any(|r| r["operation"] == "remove" && r["key"] == "X-Strip"),
        "remove must emit as remove operation"
    );

    // Translator must auto-emit a request_transformer instance so the
    // per-rule overrides have a consumer at runtime.
    let auto_xform = result
        .config
        .plugin_configs
        .iter()
        .find(|p| {
            p.plugin_name == "request_transformer"
                && p.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("auto-emitted request_transformer plugin for matchless route proxy");
    assert_eq!(
        auto_xform.config["apply_route_overrides"].as_bool(),
        Some(true)
    );

    // End-to-end: the dispatch catch-all rule matches any request, and the
    // auto-emitted transformer applies the per-rule header overrides.
    use ferrum_edge::plugins::request_transformer::RequestTransformer;
    let mrd = MeshRouteDispatch::new(&dispatch.config).expect("mrd plugin");
    let req_xform = RequestTransformer::new(&auto_xform.config).expect("auto request_transformer");

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/anything".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("x-strip".to_string(), "should-go".to_string());
    let _ = mrd.before_proxy(&mut ctx, &mut headers).await;
    let _ = req_xform.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        headers.get("x-injected").map(String::as_str),
        Some("yes"),
        "set transform must inject X-Injected header"
    );
    assert_eq!(
        headers.get("x-extra").map(String::as_str),
        Some("added"),
        "add transform must inject X-Extra header"
    );
    assert!(
        !headers.contains_key("x-strip"),
        "remove transform must strip X-Strip header"
    );
}

// ── Tier 3: mirror / rewrite / redirect / L4 ──────────────────────────────

/// A VirtualService `http[].mirror` translates to a proxy-scoped
/// `request_mirror` plugin whose config drives an actual fire-and-forget
/// mirror against the configured target.
#[tokio::test]
async fn mesh_tier3_mirror_vs_emits_working_request_mirror_plugin() {
    use ferrum_edge::plugins::create_plugin;

    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/v1"}}],
                    "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                    "mirror": {"host": "shadow.default.svc.cluster.local", "port": {"number": 9090}},
                    "mirrorPercentage": {"value": 100.0}
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let mirror = result
        .config
        .plugin_configs
        .iter()
        .find(|p| p.plugin_name == "request_mirror")
        .expect("request_mirror plugin emitted for http[].mirror");
    assert_eq!(
        mirror.config["mirror_host"].as_str(),
        Some("shadow.default.svc.cluster.local")
    );
    assert_eq!(mirror.config["mirror_port"].as_u64(), Some(9090));

    // The emitted config builds into a real plugin instance, and a 100%
    // mirror sets up a mirror result channel on the request context.
    let plugin = create_plugin("request_mirror", &mirror.config)
        .expect("plugin builds")
        .expect("plugin is Some");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/v1/widgets".to_string(),
    );
    // A matched_proxy is required so the mirror can derive its timeout budget.
    ctx.matched_proxy = Some(Arc::new(result.config.proxies[0].clone()));
    let mut headers = HashMap::new();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    assert!(
        ctx.mirror_result_rxs.len() == 1,
        "a 100% mirror must arm the mirror result channel (request was mirrored)"
    );
}

#[tokio::test]
async fn mesh_tier3_mirror_and_exact_rewrite_share_one_route_scope() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"exact": "/legacy"}}],
                    "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                    "rewrite": {
                        "uri": "/internal/exact",
                        "authority": "internal.example.com"
                    },
                    "mirror": {
                        "host": "shadow.default.svc.cluster.local",
                        "port": {"number": 9090}
                    },
                    "mirrorPercentage": {"value": 100.0}
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("=/legacy"))
        .expect("exact route proxy");
    let dispatch_config = dispatch_plugin_for_proxy(&result.config, proxy);
    let mirror_config = result
        .config
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "request_mirror"
                && plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("route-local mirror plugin");
    assert_eq!(
        mirror_config.config["mirror_host"].as_str(),
        Some("shadow.default.svc.cluster.local")
    );

    let rewrite = &dispatch_config.config["rules"][0]["rewrite"];
    assert_eq!(rewrite["uri"].as_str(), Some("/internal/exact"));
    assert_eq!(rewrite["authority"].as_str(), Some("internal.example.com"));
    assert!(
        rewrite.get("match_prefix").is_none(),
        "an exact rewrite replaces the whole request target"
    );

    let dispatch = MeshRouteDispatch::new(&dispatch_config.config).expect("dispatch config");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/legacy".to_string(),
    );
    let mut headers = HashMap::from([("host".to_string(), "api.example.com".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(ctx.route_override_path.as_deref(), Some("/internal/exact"));
    assert_eq!(
        ctx.route_override_authority.as_deref(),
        Some("internal.example.com")
    );
}

#[test]
fn mesh_tier3_route_local_mirror_fails_closed_when_route_collapse_is_required() {
    let error = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-canary": {"exact": "true"}}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}],
                        "rewrite": {
                            "uri": "/internal",
                            "authority": "canary.internal.example.com"
                        },
                        "mirror": {
                            "host": "shadow.default.svc.cluster.local",
                            "port": {"number": 9191}
                        },
                        "mirrorPercentage": {"value": 100.0}
                    },
                    {
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect_err("route-local mirror must fail closed instead of leaking to a sibling route");

    assert!(
        error.to_string().contains("traffic mirror")
            && error.to_string().contains("merged with another route"),
        "unexpected collapse error: {error}"
    );
}

/// A VirtualService `http[].rewrite.uri` rewrites the path forwarded to the
/// backend; with a prefix match, only the matched prefix is replaced.
#[tokio::test]
async fn mesh_tier3_rewrite_vs_rewrites_backend_path_and_authority() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/api"}}],
                    "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                    "rewrite": {"uri": "/internal", "authority": "internal.example.com"}
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("proxy for /api");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/users/42".to_string(),
    );
    let mut headers = HashMap::from([("host".to_string(), "public.example.com".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    // Prefix-rewrite: `/api` → `/internal`, tail `/users/42` preserved.
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/internal/users/42")
    );
    // Authority rewrite rebases the forwarded Host header.
    assert_eq!(
        headers.get("host").map(String::as_str),
        Some("internal.example.com")
    );
    assert_eq!(
        ctx.route_override_authority.as_deref(),
        Some("internal.example.com")
    );

    // The effective proxy honors the authority rewrite by preserving the
    // (rewritten) Host header instead of clobbering it with the backend host.
    // This route uses a direct backend (no upstream_id), so an empty upstream
    // map is sufficient to rebuild the effective proxy.
    let upstreams: HashMap<String, Arc<ferrum_edge::config::types::Upstream>> = HashMap::new();
    let effective = ctx.apply_route_overrides_with_upstreams(Arc::new(proxy.clone()), &upstreams);
    assert!(
        effective.preserve_host_header,
        "authority rewrite must flip preserve_host_header on the effective proxy"
    );
}

/// A VirtualService `http[].redirect` answers the request with a 3xx +
/// Location and never reaches a backend.
#[tokio::test]
async fn mesh_tier3_redirect_vs_returns_redirect_response() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/old"}}],
                    "redirect": {"uri": "/new", "authority": "api.example.com", "redirectCode": 308}
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    // No backend upstream is materialized for a redirect-only route.
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/old"))
        .expect("proxy for /old redirect");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/old/page".to_string(),
    );
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
    let mut headers = HashMap::new();
    match dispatch.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 308);
            assert_eq!(
                headers.get("location").map(String::as_str),
                Some("https://api.example.com/new")
            );
        }
        other => panic!("expected redirect Reject, got {other:?}"),
    }
}

/// VirtualService L4 `tcp[]` routing materializes a Ferrum TCP stream proxy
/// (listen-by-port → destination), reusing the stream machinery.
#[test]
fn mesh_tier3_l4_tcp_virtual_service_materializes_stream_proxy() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306}],
                    "route": [{"destination": {"host": "mysql.default.svc.cluster.local", "port": {"number": 3306}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("supported L4 tcp routing must translate, not fail closed");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(3306))
        .expect("tcp[] route materializes a stream proxy on the matched port");
    assert_eq!(proxy.backend_host, "mysql.default.svc.cluster.local");
    assert_eq!(proxy.backend_port, 3306);
    assert_eq!(
        proxy.backend_scheme,
        Some(ferrum_edge::config::types::BackendScheme::Tcp)
    );
    assert!(
        proxy.listen_path.is_none(),
        "stream proxy has no listen_path"
    );
    assert!(!proxy.passthrough, "plain tcp[] is not passthrough");
}

/// VirtualService L4 `tls[]` routing materializes a passthrough TCP stream proxy
/// keyed by SNI (encrypted bytes forwarded, no TLS termination).
#[test]
fn mesh_tier3_l4_tls_virtual_service_materializes_sni_passthrough_proxy() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["tls.example.com"],
                "tls": [{
                    "match": [{"sniHosts": ["secure.example.com"], "port": 8443}],
                    "route": [{"destination": {"host": "backend.default.svc.cluster.local", "port": {"number": 8443}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("supported L4 tls SNI routing must translate");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(8443))
        .expect("tls[] route materializes a stream proxy on the matched port");
    assert!(proxy.passthrough, "tls[] SNI routing is passthrough");
    assert_eq!(
        proxy.hosts,
        vec!["secure.example.com".to_string()],
        "SNI hosts drive passthrough routing"
    );
    assert_eq!(proxy.backend_host, "backend.default.svc.cluster.local");
    assert_eq!(proxy.backend_port, 8443);
}

/// VirtualService L4 routing still fails closed on match predicates Ferrum's
/// stream layer cannot express (here `sourceLabels`), rather than mis-routing.
#[test]
fn mesh_tier3_l4_virtual_service_unsupported_match_fails_closed() {
    let err = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306, "sourceLabels": {"app": "billing"}}],
                    "route": [{"destination": {"host": "mysql.default.svc.cluster.local", "port": {"number": 3306}}}]
                }]
            }),
        )],
        options(),
    )
    .expect_err("unsupported L4 match predicate must fail closed");
    let msg = format!("{err}");
    assert!(msg.contains("sourceLabels"), "got: {msg}");
}
