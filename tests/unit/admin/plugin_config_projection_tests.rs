//! Schema-aware plugin-configuration sensitivity contract
//! (GHSA-4988-2wph-67g2).
//!
//! These cover the projection itself. The role/audit/backup surfaces that
//! consume it are covered end to end in
//! `tests/integration/admin_audit_rbac_tests.rs`.

use ferrum_edge::admin::plugin_config_projection::{
    KAFKA_SAFE_PRODUCER_PROPERTIES, PLUGIN_SENSITIVITY_SCHEMAS, PlaceholderSiteRecorder,
    is_credential_bearing_url_config_key, is_redaction_placeholder,
    is_safe_kafka_producer_property, is_sensitive_plugin_config_key, normalize_config_key,
    project_plugin_config, project_plugin_config_with, project_plugin_trigger_with,
    redact_endpoint_url, sensitivity_rules_for,
};
use ferrum_edge::plugins::builtin_parity::BUILTIN_PLUGIN_PARITY_META;
use serde_json::{Value, json};

const REDACTED: &str = "[REDACTED]";

fn project(plugin: &str, config: Value) -> Value {
    let mut projected = config;
    project_plugin_config(plugin, &mut projected);
    projected
}

/// Assert none of `canaries` survives anywhere in the projected document.
fn assert_no_canaries(projected: &Value, canaries: &[&str]) {
    let serialized = projected.to_string();
    for canary in canaries {
        assert!(
            !serialized.contains(canary),
            "projection leaked {canary}: {serialized}"
        );
    }
}

// ---------------------------------------------------------------------------
// Future built-in parity
// ---------------------------------------------------------------------------

/// A new built-in plugin must not be able to ship without an explicit
/// sensitivity decision. This is the gate that keeps the contract exhaustive
/// instead of drifting back into name guessing.
#[test]
fn every_builtin_plugin_has_a_sensitivity_schema_entry() {
    let missing: Vec<&str> = BUILTIN_PLUGIN_PARITY_META
        .iter()
        .map(|meta| meta.name)
        .filter(|name| {
            !PLUGIN_SENSITIVITY_SCHEMAS
                .iter()
                .any(|(schema_name, _)| schema_name == name)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "built-in plugins without a sensitivity schema entry (add one to \
         PLUGIN_SENSITIVITY_SCHEMAS, using the empty rule set if nothing in the \
         plugin's config is credential-bearing): {missing:?}"
    );
}

/// The reverse direction: a schema entry for a plugin that no longer exists is
/// dead weight that hides a real gap behind a passing parity test.
#[test]
fn sensitivity_schema_has_no_entries_for_unknown_plugins() {
    let unknown: Vec<&str> = PLUGIN_SENSITIVITY_SCHEMAS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| {
            !BUILTIN_PLUGIN_PARITY_META
                .iter()
                .any(|meta| meta.name == *name)
        })
        .collect();
    assert!(
        unknown.is_empty(),
        "sensitivity schema entries for unknown plugins: {unknown:?}"
    );
}

#[test]
fn sensitivity_schema_has_no_duplicate_plugin_entries() {
    let mut names: Vec<&str> = PLUGIN_SENSITIVITY_SCHEMAS.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate plugin entries in schema");
}

#[test]
fn unknown_custom_plugins_get_no_schema_rules_but_still_project() {
    assert!(sensitivity_rules_for("some_custom_plugin").is_empty());

    let projected = project(
        "some_custom_plugin",
        json!({
            "api_key": "custom-plugin-api-key-canary",
            "sink_url": "https://user:custom-plugin-userinfo-canary@sink.example.com/ingest",
            "batch_size": 50
        }),
    );
    // A custom plugin cannot be classified, so every scalar leaf is withheld
    // and only the keys stay visible.
    assert_eq!(projected["api_key"], REDACTED);
    assert_eq!(projected["sink_url"], REDACTED);
    assert_eq!(projected["batch_size"], REDACTED);
    assert_no_canaries(
        &projected,
        &[
            "custom-plugin-api-key-canary",
            "custom-plugin-userinfo-canary",
        ],
    );
}

// ---------------------------------------------------------------------------
// Structural URL projection
// ---------------------------------------------------------------------------

#[test]
fn endpoint_url_projection_keeps_only_origin_and_structural_markers() {
    assert_eq!(
        redact_endpoint_url("https://user:pw@collector.example.com:4318/v1/traces?k=v#frag"),
        "https://redacted@collector.example.com:4318/[REDACTED_PATH]?[REDACTED_QUERY]#[REDACTED_FRAGMENT]"
    );
    // Userinfo gets its own marker even when the URL has no other suffix.
    assert_eq!(
        redact_endpoint_url("https://user:pw@collector.example.com"),
        "https://redacted@collector.example.com"
    );
    // Without userinfo or suffix components, the origin alone is emitted.
    assert_eq!(
        redact_endpoint_url("https://collector.example.com"),
        "https://collector.example.com"
    );
    assert_eq!(
        redact_endpoint_url("https://collector.example.com/"),
        "https://collector.example.com"
    );
    // IPv6 literals keep their brackets so the value stays a parseable origin.
    assert_eq!(
        redact_endpoint_url("https://[2001:db8::1]:8443/ingest"),
        "https://[2001:db8::1]:8443/[REDACTED_PATH]"
    );
    // Non-HTTP schemes are projected the same way.
    assert_eq!(
        redact_endpoint_url("ldaps://ldap.example.com:636/dc=example"),
        "ldaps://ldap.example.com:636/[REDACTED_PATH]"
    );
}

#[test]
fn endpoint_url_projection_fails_closed_for_unparseable_and_hostless_values() {
    assert_eq!(redact_endpoint_url("not a url at all"), REDACTED);
    assert_eq!(redact_endpoint_url(""), REDACTED);
    // No host to anchor the diagnostic on.
    assert_eq!(redact_endpoint_url("mailto:ops@example.com"), REDACTED);
}

// ---------------------------------------------------------------------------
// Advisory-named surfaces
// ---------------------------------------------------------------------------

#[test]
fn serverless_function_keys_and_trigger_urls_are_projected() {
    let projected = project(
        "serverless_function",
        json!({
            "provider": "azure_functions",
            "function_url": "https://fn.example.net/api/serverless-path-canary?code=serverless-query-canary",
            "azure_function_key": "serverless-function-key-canary",
            "timeout_ms": 3000
        }),
    );
    assert_eq!(
        projected["function_url"],
        "https://fn.example.net/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(projected["azure_function_key"], REDACTED);
    assert_eq!(projected["timeout_ms"], 3000);
    assert_eq!(projected["provider"], "azure_functions");
    assert_no_canaries(
        &projected,
        &[
            "serverless-path-canary",
            "serverless-query-canary",
            "serverless-function-key-canary",
        ],
    );
}

#[test]
fn http_logging_endpoint_and_every_custom_header_value_are_projected() {
    let projected = project(
        "http_logging",
        json!({
            "endpoint_url": "https://collector.example.com/ingest/http-path-canary?key=http-query-canary",
            "custom_headers": {
                // No substring pattern matches this vendor header name.
                "x-honeycomb-team": "http-header-canary",
                "X-Tenant": "http-tenant-canary"
            },
            "batch_size": 50
        }),
    );
    assert_eq!(
        projected["endpoint_url"],
        "https://collector.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(projected["custom_headers"]["x-honeycomb-team"], REDACTED);
    assert_eq!(projected["custom_headers"]["X-Tenant"], REDACTED);
    // Header NAMES stay visible; only values are secret.
    assert!(
        projected["custom_headers"]
            .as_object()
            .expect("headers object")
            .contains_key("x-honeycomb-team")
    );
    assert_eq!(projected["batch_size"], 50);
    assert_no_canaries(
        &projected,
        &[
            "http-path-canary",
            "http-query-canary",
            "http-header-canary",
            "http-tenant-canary",
        ],
    );
}

#[test]
fn ws_logging_endpoint_and_every_custom_header_value_are_projected() {
    let projected = project(
        "ws_logging",
        json!({
            "endpoint_url": "wss://collector.example.com/ingest/ws-path-canary?stream=ws-query-canary",
            "custom_headers": {
                "Authorization": "Bearer ws-header-canary",
                "X-Collector-Tenant": "ws-tenant-canary"
            },
            "batch_size": 50
        }),
    );
    assert_eq!(
        projected["endpoint_url"],
        "wss://collector.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(projected["custom_headers"]["Authorization"], REDACTED);
    assert_eq!(projected["custom_headers"]["X-Collector-Tenant"], REDACTED);
    assert!(
        projected["custom_headers"]
            .as_object()
            .expect("headers object")
            .contains_key("X-Collector-Tenant")
    );
    assert_eq!(projected["batch_size"], 50);
    assert_no_canaries(
        &projected,
        &[
            "ws-path-canary",
            "ws-query-canary",
            "ws-header-canary",
            "ws-tenant-canary",
        ],
    );
}

#[test]
fn waf_header_present_secret_values_are_projected() {
    let projected = project(
        "waf",
        json!({
            "mode": "enforce",
            "global_exemptions": {
                "paths": ["/health"],
                "header_present": { "x-skip-waf": "waf-exemption-secret-canary" }
            }
        }),
    );
    assert_eq!(
        projected["global_exemptions"]["header_present"]["x-skip-waf"],
        REDACTED
    );
    // Header names and unrelated exemption fields stay visible.
    assert_eq!(projected["global_exemptions"]["paths"], json!(["/health"]));
    assert_eq!(projected["mode"], "enforce");
    assert_no_canaries(&projected, &["waf-exemption-secret-canary"]);
}

/// `custom_rules[].conditions.headers` and
/// `rule_overrides.<id>.conditions.headers` scope a rule to a header value an
/// operator may set to a shared secret or a credential, under a vendor name no
/// heuristic matches. A `null` (presence-only) condition discloses nothing and
/// stays `null`.
#[test]
fn waf_condition_header_values_are_projected() {
    let raw = json!({
        "mode": "enforce",
        "custom_rules": [{
            "id": "custom-1",
            "category": "custom",
            "pattern": "drop table",
            "action": "block",
            "conditions": {
                "paths": ["/api"],
                "headers": {
                    "Ocp-Apim-Subscription-Key": "waf-custom-condition-canary",
                    "x-debug": null
                }
            }
        }],
        "rule_overrides": {
            "942100": {
                "action": "log",
                "conditions": {
                    "headers": {
                        "Ocp-Apim-Subscription-Key": "waf-override-condition-canary",
                        "x-debug": null
                    }
                }
            }
        }
    });
    assert!(
        placeholder_sites("waf", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("waf", raw);
    let custom = &projected["custom_rules"][0];
    let custom_headers = &custom["conditions"]["headers"];
    assert_eq!(custom_headers["Ocp-Apim-Subscription-Key"], REDACTED);
    assert_eq!(custom_headers["x-debug"], Value::Null);
    let override_headers = &projected["rule_overrides"]["942100"]["conditions"]["headers"];
    assert_eq!(override_headers["Ocp-Apim-Subscription-Key"], REDACTED);
    assert_eq!(override_headers["x-debug"], Value::Null);
    // Header names and rule metadata stay visible.
    assert_eq!(custom["id"], "custom-1");
    assert_eq!(custom["action"], "block");
    assert_eq!(custom["pattern"], "drop table");
    assert_eq!(custom["conditions"]["paths"], json!(["/api"]));
    assert_eq!(projected["rule_overrides"]["942100"]["action"], "log");
    assert_eq!(projected["mode"], "enforce");
    assert_no_canaries(
        &projected,
        &[
            "waf-custom-condition-canary",
            "waf-override-condition-canary",
        ],
    );

    // Echoing the masked values back is detected at both sites.
    let mut sites = placeholder_sites("waf", &projected);
    sites.sort();
    assert_eq!(
        sites,
        vec![
            "/config/custom_rules/0/conditions/headers/Ocp-Apim-Subscription-Key".to_string(),
            "/config/rule_overrides/942100/conditions/headers/Ocp-Apim-Subscription-Key"
                .to_string(),
        ]
    );
}

/// `mesh_route_dispatch` match operands select a route by a value the client
/// presents. Each operand is a bare string or a one-key `{exact|prefix|regex}`
/// object: the bare string is masked whole, and the object keeps its match kind
/// while its value is masked.
#[test]
fn mesh_route_dispatch_match_operands_are_projected() {
    let raw = json!({
        "reject_unmatched": true,
        "rules": [{
            "name": "canary",
            "match": {
                "methods": ["GET"],
                "headers": {
                    "Ocp-Apim-Subscription-Key": "mrd-bare-header-canary",
                    "x-tenant": {"prefix": "mrd-tagged-header-canary"}
                },
                "without_headers": {"x-debug": {"exact": "mrd-without-canary"}},
                "query_params": {
                    "access": "mrd-bare-query-canary",
                    "sig": {"regex": "mrd-tagged-query-canary.*"}
                }
            },
            "destination": {"upstream_id": "canary-pool"}
        }]
    });
    assert!(
        placeholder_sites("mesh_route_dispatch", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("mesh_route_dispatch", raw);
    let rule = &projected["rules"][0];
    let headers = &rule["match"]["headers"];
    assert_eq!(headers["Ocp-Apim-Subscription-Key"], REDACTED);
    assert_eq!(headers["x-tenant"], json!({"prefix": REDACTED}));
    let without = &rule["match"]["without_headers"];
    assert_eq!(without["x-debug"], json!({"exact": REDACTED}));
    let query = &rule["match"]["query_params"];
    assert_eq!(query["access"], REDACTED);
    assert_eq!(query["sig"], json!({"regex": REDACTED}));
    // Names, match kinds and routing metadata stay visible.
    assert_eq!(rule["match"]["methods"], json!(["GET"]));
    assert_eq!(rule["name"], "canary");
    assert_eq!(rule["destination"]["upstream_id"], "canary-pool");
    assert_eq!(projected["reject_unmatched"], true);
    assert_no_canaries(
        &projected,
        &[
            "mrd-bare-header-canary",
            "mrd-tagged-header-canary",
            "mrd-without-canary",
            "mrd-bare-query-canary",
            "mrd-tagged-query-canary",
        ],
    );

    // Echoing the masked operands back is detected at every site.
    let mut sites = placeholder_sites("mesh_route_dispatch", &projected);
    sites.sort();
    assert_eq!(
        sites,
        vec![
            "/config/rules/0/match/headers/Ocp-Apim-Subscription-Key".to_string(),
            "/config/rules/0/match/headers/x-tenant/prefix".to_string(),
            "/config/rules/0/match/query_params/access".to_string(),
            "/config/rules/0/match/query_params/sig/regex".to_string(),
            "/config/rules/0/match/without_headers/x-debug/exact".to_string(),
        ]
    );
}

/// `trigger.header_value` is the value a request must carry to be terminated:
/// an operator-chosen token. The header name and the response stay visible.
#[test]
fn request_termination_trigger_header_value_is_projected() {
    let raw = json!({
        "status_code": 503,
        "message": "maintenance",
        "trigger": {"header": "x-maintenance-bypass", "header_value": "rt-trigger-canary"}
    });
    assert!(
        placeholder_sites("request_termination", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("request_termination", raw);
    assert_eq!(projected["trigger"]["header_value"], REDACTED);
    assert_eq!(projected["trigger"]["header"], "x-maintenance-bypass");
    assert_eq!(projected["status_code"], 503);
    assert_eq!(projected["message"], "maintenance");
    assert_no_canaries(&projected, &["rt-trigger-canary"]);
    assert_eq!(
        placeholder_sites("request_termination", &projected),
        vec!["/config/trigger/header_value".to_string()]
    );
}

/// The `transaction_debugger` capture selector value is an operator-chosen
/// token a request must carry to be captured.
#[test]
fn transaction_debugger_capture_selector_value_is_projected() {
    let raw = json!({
        "log_request_body": true,
        "capture_request_header": "x-debug-session",
        "capture_request_header_value": "td-selector-canary"
    });
    assert!(
        placeholder_sites("transaction_debugger", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("transaction_debugger", raw);
    assert_eq!(projected["capture_request_header_value"], REDACTED);
    assert_eq!(projected["capture_request_header"], "x-debug-session");
    assert_eq!(projected["log_request_body"], true);
    assert_no_canaries(&projected, &["td-selector-canary"]);
    assert_eq!(
        placeholder_sites("transaction_debugger", &projected),
        vec!["/config/capture_request_header_value".to_string()]
    );
}

/// The `ai_semantic_firewall` snippet-hash salt keys the logged snippet
/// hashes; a reader holding it could confirm guessed snippets.
#[test]
fn ai_semantic_firewall_snippet_hash_salt_is_projected() {
    let raw = json!({
        "provider": {"endpoint": "https://guard.example.com"},
        "privacy": {"include_snippet_hash": true, "snippet_hash_salt": "asf-salt-canary"}
    });
    assert!(
        placeholder_sites("ai_semantic_firewall", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("ai_semantic_firewall", raw);
    assert_eq!(projected["privacy"]["snippet_hash_salt"], REDACTED);
    assert_eq!(projected["privacy"]["include_snippet_hash"], true);
    assert_no_canaries(&projected, &["asf-salt-canary"]);
    assert_eq!(
        placeholder_sites("ai_semantic_firewall", &projected),
        vec!["/config/privacy/snippet_hash_salt".to_string()]
    );
}

fn mesh_policy(canary: &str) -> Value {
    json!({
        "name": "payments",
        "namespace": "shop",
        "rules": [{
            "to": [{"headers": {"x-tenant": format!("{canary}-to")}}],
            "when": [{
                "key": "request.headers[x-gate]",
                "values": [format!("{canary}-when")],
                "not_values": [format!("{canary}-not")]
            }],
            "action": "allow"
        }]
    })
}

fn assert_mesh_policy_operands_redacted(policy: &Value) {
    let rule = &policy["rules"][0];
    assert_eq!(rule["to"][0]["headers"]["x-tenant"], REDACTED);
    assert_eq!(rule["when"][0]["values"], json!([REDACTED]));
    assert_eq!(rule["when"][0]["not_values"], json!([REDACTED]));
    assert_eq!(rule["action"], "allow");
    assert_eq!(policy["name"], "payments");
    assert_eq!(policy["namespace"], "shop");
}

/// `mesh_authz` header and condition operands are withheld in the flat
/// `mesh_policies` shape and in both policy lists of the mesh-mode
/// `mesh_slice`, as are the ext-authz check headers, ProxyConfig environment
/// values and extension payloads the slice carries, and the inline backend
/// client keys of its embedded VirtualService L4 proxies and upstreams. Its
/// collector, JWKS, control-plane and federation URLs get the structural
/// endpoint projection.
#[test]
fn mesh_authz_match_operands_and_check_headers_are_projected() {
    let inline_key = "-----BEGIN PRIVATE KEY-----\nmat-l4-key-canary\n-----END PRIVATE KEY-----\n";
    let raw = json!({
        "mesh_policies": [mesh_policy("mat-flat-canary")],
        "mesh_slice": {
            "node_id": "node-a",
            "mesh_policies": [mesh_policy("mat-slice-canary")],
            "node_waypoint_capture_mesh_policies": [mesh_policy("mat-capture-canary")],
            "ext_authz_providers": [{
                "name": "ext-check",
                "service": "authz.shop.svc.cluster.local",
                "port": 9000,
                "path_prefix": "/check/mat-prefix-canary",
                "include_additional_headers_in_check": [
                    {"name": "x-check-gate", "value": "mat-ext-header-canary"}
                ]
            }],
            "proxy_configs": [{
                "name": "defaults",
                "environment": {"VENDOR_LICENSE": "mat-env-canary"}
            }],
            "extension_configs": [{
                "name": "wasm-filter",
                "type_url": "type.example/filter",
                "value": "mat-extension-canary"
            }],
            "telemetry_resources": [{
                "name": "tracing",
                "namespace": "shop",
                "config": {"tracing": {"providers": [
                    {"kind": "zipkin",
                     "config": {"url": "https://zipkin.example.com/mat-zipkin-canary"}},
                    {"kind": "datadog",
                     "config": {"agent_url": "https://dd.example.com/?token=mat-dd-canary"}},
                    {"kind": "lightstep",
                     "config": {"collector_url": "https://ls.example.com/mat-ls-canary"}},
                    {"kind": "opentelemetry",
                     "config": {"endpoint": "https://otel.example.com/v1/mat-otel-canary"}}
                ]}}
            }],
            "request_authentications": [{
                "name": "jwt",
                "namespace": "shop",
                "jwt_rules": [{
                    "issuer": "https://issuer.example.com",
                    "jwks_uri": "https://issuer.example.com/keys?tenant=mat-jwks-canary"
                }]
            }],
            "virtual_service_l4_proxies": [{
                "id": "istio-vs-l4_shop_db",
                "backend_host": "db.shop.svc",
                "backend_port": 5432,
                "backend_tls_client_cert_path": "k8s://shop/db-client#tls.crt",
                "backend_tls_client_key_path": inline_key
            }],
            "virtual_service_l4_upstreams": [{
                "id": "istio-vs-l4-upstream-db",
                "backend_tls_client_key_path": "k8s://shop/db#tls.key",
                "port_overrides": {"5432": {"tls": {
                    "client_cert_path": "k8s://shop/db#tls.crt",
                    "client_key_path": inline_key
                }}}
            }],
            "multi_cluster": {
                "federation_endpoint": "https://fed.example.com/mat-fed-canary",
                "remote_clusters": [{
                    "name": "east",
                    "control_plane_url": "https://cp.east.example.com/mat-cp-canary",
                    "federation_endpoint": "https://fed.east.example.com/mat-remote-fed-canary"
                }]
            }
        }
    });
    assert!(
        placeholder_sites("mesh_authz", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("mesh_authz", raw);
    assert_mesh_policy_operands_redacted(&projected["mesh_policies"][0]);
    let slice = &projected["mesh_slice"];
    assert_mesh_policy_operands_redacted(&slice["mesh_policies"][0]);
    assert_mesh_policy_operands_redacted(&slice["node_waypoint_capture_mesh_policies"][0]);
    let provider = &slice["ext_authz_providers"][0];
    let check_header = &provider["include_additional_headers_in_check"][0];
    assert_eq!(check_header["value"], REDACTED);
    assert_eq!(check_header["name"], "x-check-gate");
    assert_eq!(provider["name"], "ext-check");
    assert_eq!(provider["path_prefix"], REDACTED);
    assert_eq!(provider["service"], "authz.shop.svc.cluster.local");
    assert_eq!(provider["port"], 9000);
    let l4_proxy = &slice["virtual_service_l4_proxies"][0];
    assert_eq!(l4_proxy["backend_tls_client_key_path"], REDACTED);
    assert_eq!(l4_proxy["backend_host"], "db.shop.svc");
    let l4_upstream = &slice["virtual_service_l4_upstreams"][0];
    assert_eq!(
        l4_upstream["backend_tls_client_key_path"],
        "k8s://shop/db#tls.key"
    );
    let port_tls = &l4_upstream["port_overrides"]["5432"]["tls"];
    assert_eq!(port_tls["client_key_path"], REDACTED);
    assert_eq!(port_tls["client_cert_path"], "k8s://shop/db#tls.crt");
    let proxy_config = &slice["proxy_configs"][0];
    assert_eq!(proxy_config["environment"]["VENDOR_LICENSE"], REDACTED);
    let extension = &slice["extension_configs"][0];
    assert_eq!(extension["value"], REDACTED);
    assert_eq!(extension["type_url"], "type.example/filter");
    assert_eq!(slice["node_id"], "node-a");

    let providers = &slice["telemetry_resources"][0]["config"]["tracing"]["providers"];
    let fields = ["url", "agent_url", "collector_url", "endpoint"];
    let expected_urls = [
        "https://zipkin.example.com/[REDACTED_PATH]",
        "https://dd.example.com?[REDACTED_QUERY]",
        "https://ls.example.com/[REDACTED_PATH]",
        "https://otel.example.com/[REDACTED_PATH]",
    ];
    for (index, (field, url)) in fields.iter().zip(expected_urls).enumerate() {
        assert_eq!(providers[index]["config"][*field], url);
    }
    assert_eq!(providers[1]["kind"], "datadog");
    let jwt_rule = &slice["request_authentications"][0]["jwt_rules"][0];
    assert_eq!(
        jwt_rule["jwks_uri"],
        "https://issuer.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(jwt_rule["issuer"], "https://issuer.example.com");
    let multi_cluster = &slice["multi_cluster"];
    assert_eq!(
        multi_cluster["federation_endpoint"],
        "https://fed.example.com/[REDACTED_PATH]"
    );
    let remote = &multi_cluster["remote_clusters"][0];
    assert_eq!(
        remote["control_plane_url"],
        "https://cp.east.example.com/[REDACTED_PATH]"
    );
    assert_eq!(
        remote["federation_endpoint"],
        "https://fed.east.example.com/[REDACTED_PATH]"
    );
    assert_eq!(remote["name"], "east");
    assert_no_canaries(
        &projected,
        &[
            "mat-flat-canary",
            "mat-slice-canary",
            "mat-capture-canary",
            "mat-ext-header-canary",
            "mat-env-canary",
            "mat-extension-canary",
            "mat-zipkin-canary",
            "mat-dd-canary",
            "mat-ls-canary",
            "mat-otel-canary",
            "mat-jwks-canary",
            "mat-fed-canary",
            "mat-cp-canary",
            "mat-remote-fed-canary",
            "mat-prefix-canary",
            "mat-l4-key-canary",
        ],
    );

    // Echoing the projection back is detected at every masked site, including
    // the condition `key` the name heuristic already masks and each entry of
    // the `values` / `not_values` lists.
    let mut expected = Vec::new();
    for policy in [
        "/config/mesh_policies/0",
        "/config/mesh_slice/mesh_policies/0",
        "/config/mesh_slice/node_waypoint_capture_mesh_policies/0",
    ] {
        for site in [
            "to/0/headers/x-tenant",
            "when/0/key",
            "when/0/values/0",
            "when/0/not_values/0",
        ] {
            expected.push(format!("{policy}/rules/0/{site}"));
        }
    }
    let telemetry = "/config/mesh_slice/telemetry_resources/0/config/tracing/providers";
    for (index, field) in fields.iter().enumerate() {
        expected.push(format!("{telemetry}/{index}/config/{field}"));
    }
    for site in [
        "ext_authz_providers/0/include_additional_headers_in_check/0/value",
        "ext_authz_providers/0/path_prefix",
        "virtual_service_l4_proxies/0/backend_tls_client_key_path",
        "virtual_service_l4_upstreams/0/port_overrides/5432/tls/client_key_path",
        "proxy_configs/0/environment/VENDOR_LICENSE",
        "extension_configs/0/value",
        "request_authentications/0/jwt_rules/0/jwks_uri",
        "multi_cluster/federation_endpoint",
        "multi_cluster/remote_clusters/0/control_plane_url",
        "multi_cluster/remote_clusters/0/federation_endpoint",
    ] {
        expected.push(format!("/config/mesh_slice/{site}"));
    }
    expected.sort();
    let mut sites = placeholder_sites("mesh_authz", &projected);
    sites.sort();
    assert_eq!(sites, expected);
}

fn tracing_provider_endpoint_fields(plugin: &str, prefix: &[&'static str]) -> Vec<&'static str> {
    let mut fields: Vec<&'static str> = sensitivity_rules_for(plugin)
        .iter()
        .filter(|rule| rule.path.starts_with(prefix))
        .filter_map(|rule| rule.path.last().copied())
        .collect();
    fields.sort_unstable();
    fields
}

/// The mesh slice's Telemetry tracing providers are the same `TracingProvider`
/// envelope `workload_metrics` carries, so both copies must project the same
/// collector fields.
#[test]
fn mesh_slice_tracing_providers_follow_the_workload_metrics_rules() {
    let workload = tracing_provider_endpoint_fields("workload_metrics", &["tracing_providers"]);
    let slice =
        tracing_provider_endpoint_fields("mesh_authz", &["mesh_slice", "telemetry_resources"]);
    assert_eq!(workload, ["agent_url", "collector_url", "endpoint", "url"]);
    assert_eq!(slice, workload);
}

/// TLS private-key sources accept inline PEM. Inline key material is withheld,
/// a reference (path, `k8s://`, …) stays visible, and an echoed placeholder is
/// detected.
#[test]
fn inline_private_key_sources_are_projected() {
    let pem = "-----BEGIN PRIVATE KEY-----\npk-inline-canary\n-----END PRIVATE KEY-----\n";
    let raw = json!({
        "rules": [
            {"match": {"methods": ["GET"]}, "destination": {"backend_tls": {
                "client_cert_path": "/etc/ferrum/route.crt",
                "client_key_path": pem
            }}},
            {"match": {"methods": ["POST"]}, "destination": {"backend_tls": {
                "client_key_path": "k8s://shop/tls#tls.key"
            }}}
        ]
    });
    assert!(
        placeholder_sites("mesh_route_dispatch", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("mesh_route_dispatch", raw);
    let inline = &projected["rules"][0]["destination"]["backend_tls"];
    assert_eq!(inline["client_key_path"], REDACTED);
    assert_eq!(inline["client_cert_path"], "/etc/ferrum/route.crt");
    let reference = &projected["rules"][1]["destination"]["backend_tls"];
    assert_eq!(reference["client_key_path"], "k8s://shop/tls#tls.key");
    assert_no_canaries(&projected, &["pk-inline-canary"]);
    let key_site = "/config/rules/0/destination/backend_tls/client_key_path";
    assert_eq!(
        placeholder_sites("mesh_route_dispatch", &projected),
        [key_site]
    );

    let udp = project(
        "udp_logging",
        json!({"host": "logs.internal", "dtls": true, "dtls_key_path": pem}),
    );
    assert_eq!(udp["dtls_key_path"], REDACTED);
    assert_eq!(udp["host"], "logs.internal");
    assert_no_canaries(&udp, &["pk-inline-canary"]);
}

/// A certificate or CA source keeps certificate-only PEM and references
/// visible but withholds a pasted certificate-plus-key bundle, through the same
/// classification the Proxy and Upstream projections use. A PEM private-key
/// block is withheld on any other path too, including a custom plugin's.
#[test]
fn certificate_plus_key_bundles_are_withheld_in_certificate_sources() {
    let cert = "-----BEGIN CERTIFICATE-----\ncert-only-visible\n-----END CERTIFICATE-----\n";
    let key = "-----BEGIN PRIVATE KEY-----\nbundle-key-canary\n-----END PRIVATE KEY-----\n";
    let bundle = format!("{cert}{key}");

    let route = json!({"rules": [
        {"match": {"methods": ["GET"]}, "destination": {"backend_tls": {
            "client_cert_path": bundle,
            "server_ca_cert_path": cert
        }}},
        {"match": {"methods": ["POST"]}, "destination": {"backend_tls": {
            "client_cert_path": "k8s://shop/tls#tls.crt"
        }}}
    ]});
    let udp = json!({
        "host": "logs.internal",
        "dtls": true,
        "dtls_cert_path": bundle,
        "dtls_ca_cert_path": cert
    });
    let soap = json!({
        "x509_signature": {"enabled": true, "trusted_certs": [cert, bundle]},
        "saml": {"enabled": true, "trusted_signing_certs": [bundle]}
    });
    let mtls = json!({"allowed_issuers": [{"cn": "Edge CA", "ca_certificate_pem": bundle}]});
    let custom = json!({"anything": {"nested": [bundle]}});
    let l4 = json!({"mesh_slice": {"virtual_service_l4_proxies": [{
        "id": "istio-vs-l4_shop_db",
        "backend_tls_server_ca_cert_path": bundle,
        "backend_tls_client_cert_path": cert
    }]}});

    for (plugin, raw, sites) in [
        (
            "mesh_route_dispatch",
            route,
            vec!["/config/rules/0/destination/backend_tls/client_cert_path"],
        ),
        ("udp_logging", udp, vec!["/config/dtls_cert_path"]),
        (
            "soap_ws_security",
            soap,
            vec![
                "/config/saml/trusted_signing_certs/0",
                "/config/x509_signature/trusted_certs/1",
            ],
        ),
        (
            "mtls_auth",
            mtls,
            vec!["/config/allowed_issuers/0/ca_certificate_pem"],
        ),
        ("custom_thing", custom, vec!["/config/anything/nested/0"]),
        (
            "mesh_authz",
            l4,
            vec!["/config/mesh_slice/virtual_service_l4_proxies/0/backend_tls_server_ca_cert_path"],
        ),
    ] {
        assert!(
            placeholder_sites(plugin, &raw).is_empty(),
            "{plugin}: the stored config carries no placeholder"
        );
        let projected = project(plugin, raw);
        for site in &sites {
            let pointer = site.strip_prefix("/config").expect("config pointer");
            assert_eq!(
                projected.pointer(pointer),
                Some(&json!(REDACTED)),
                "{plugin}: {projected}"
            );
        }
        assert_no_canaries(&projected, &["bundle-key-canary"]);
        assert!(
            projected.to_string().contains("cert-only-visible")
                || plugin == "mtls_auth"
                || plugin == "custom_thing",
            "{plugin}: certificate-only PEM was withheld: {projected}"
        );
        let mut found = placeholder_sites(plugin, &projected);
        found.sort();
        assert_eq!(found, sites, "{plugin}");
    }
}

/// `opa_host` may carry a base path that is kept in every decision URL, so it
/// is projected structurally; the origin and `policy_path` stay visible.
#[test]
fn opa_host_base_path_is_projected() {
    let raw = json!({
        "opa_host": "https://opa.example.com/opa-base-canary",
        "policy_path": "/v1/data/authz/allow",
        "timeout_ms": 500
    });
    assert!(
        placeholder_sites("opa", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("opa", raw);
    assert_eq!(
        projected["opa_host"],
        "https://opa.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["policy_path"], "/v1/data/authz/allow");
    assert_eq!(projected["timeout_ms"], 500);
    assert_no_canaries(&projected, &["opa-base-canary"]);
    assert_eq!(
        placeholder_sites("opa", &projected),
        vec!["/config/opa_host".to_string()]
    );

    // A bare origin has nothing to withhold and stays verbatim.
    let origin = project("opa", json!({"opa_host": "http://opa:8181"}));
    assert_eq!(origin["opa_host"], "http://opa:8181");
}

/// A custom plugin has no schema, so its config fails closed: every scalar
/// leaf (string, number, boolean) is withheld wherever it sits, under any key
/// spelling or list shape, while object keys, array shapes, and `null` values
/// stay visible. Built-ins keep their declared projection.
#[test]
fn custom_plugin_configs_fail_closed_at_every_scalar_leaf() {
    let raw = json!({
        "headers": {"x-honeycomb-team": "cfc-header-canary", "x-null": null},
        "auth_headers": [{"name": "X-Vendor-Token", "value": "cfc-pair-canary"}],
        "account": {"id": 987654321, "enabled": true},
        "sinks": [{"target": "cfc-sink-canary", "weights": [1, 2]}],
        "empty": {}
    });
    assert!(
        placeholder_sites("some_custom_plugin", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("some_custom_plugin", raw);
    assert_eq!(
        projected,
        json!({
            "headers": {"x-honeycomb-team": REDACTED, "x-null": null},
            "auth_headers": [{"name": REDACTED, "value": REDACTED}],
            "account": {"id": REDACTED, "enabled": REDACTED},
            "sinks": [{"target": REDACTED, "weights": [REDACTED, REDACTED]}],
            "empty": {}
        })
    );
    let mut sites = placeholder_sites("some_custom_plugin", &projected);
    sites.sort();
    assert_eq!(
        sites,
        [
            "/config/account/enabled",
            "/config/account/id",
            "/config/auth_headers/0/name",
            "/config/auth_headers/0/value",
            "/config/headers/x-honeycomb-team",
            "/config/sinks/0/target",
            "/config/sinks/0/weights/0",
            "/config/sinks/0/weights/1",
        ]
    );

    // Built-ins keep their declared projection: response headers they show on
    // purpose stay visible.
    let termination = project(
        "request_termination",
        json!({"status_code": 503, "headers": {"Retry-After": "120"}}),
    );
    assert_eq!(termination["headers"]["Retry-After"], "120");
    assert_eq!(termination["status_code"], 503);
    let mock = project(
        "response_mock",
        json!({"rules": [{"path": "/v1", "headers": {"x-mock": "static-value"}}]}),
    );
    assert_eq!(mock["rules"][0]["headers"]["x-mock"], "static-value");
}

/// A resource-level plugin `trigger` withholds every header, query and cookie
/// operand at any depth of the `all` / `any` / `not` tree; names, match kinds,
/// flags, structure, and non-client predicates stay visible.
#[test]
fn trigger_operands_are_withheld_at_every_depth() {
    let mut trigger = json!({"when": {"not": {"any": [
        {"match": {"header": {
            "name": "x-skip",
            "value": {"exact": ["trigger-a-canary", "trigger-b-canary"]}
        }}},
        {"all": [{"match": {"cookie": {
            "name": "tier",
            "value": {"regex": "trigger-c-canary", "case_insensitive": true}
        }}}]},
        {"match": {"path": {"prefix": ["/visible"]}}}
    ]}}});
    let recorder = PlaceholderSiteRecorder::default();
    project_plugin_trigger_with(&mut trigger, "/trigger", &recorder);
    assert!(
        recorder.into_sites().is_empty(),
        "the stored trigger carries no placeholder"
    );

    let any = &trigger["when"]["not"]["any"];
    let header = &any[0]["match"]["header"];
    assert_eq!(header["name"], "x-skip");
    assert_eq!(header["value"]["exact"], json!([REDACTED, REDACTED]));
    let cookie = &any[1]["all"][0]["match"]["cookie"];
    assert_eq!(cookie["name"], "tier");
    assert_eq!(cookie["value"]["regex"], REDACTED);
    assert_eq!(cookie["value"]["case_insensitive"], true);
    assert_eq!(any[2]["match"]["path"]["prefix"], json!(["/visible"]));
    assert_no_canaries(
        &trigger,
        &["trigger-a-canary", "trigger-b-canary", "trigger-c-canary"],
    );

    let recorder = PlaceholderSiteRecorder::default();
    let mut echoed = trigger.clone();
    project_plugin_trigger_with(&mut echoed, "/trigger", &recorder);
    assert_eq!(
        recorder.into_sites(),
        vec![
            "/trigger/when/not/any/0/match/header/value/exact/0".to_string(),
            "/trigger/when/not/any/0/match/header/value/exact/1".to_string(),
            "/trigger/when/not/any/1/all/0/match/cookie/value/regex".to_string(),
        ]
    );
}

/// A trigger shape `PluginTrigger` cannot have is withheld wholesale instead of
/// being walked, so hostile or legacy data never discloses an operand.
#[test]
fn malformed_trigger_shapes_fail_closed() {
    for case in [
        json!({"at": "", "trigger": "tfc-scalar-canary"}),
        json!({"at": "", "trigger": {"if": {"match": {"header": {"name": "tfc-if-canary"}}}}}),
        json!({"at": "/when", "trigger": {"when": "tfc-node-canary"}}),
        json!({"at": "/when/all", "trigger": {"when": {"all": {"match": "tfc-all-canary"}}}}),
        json!({"at": "/when/x", "trigger": {"when": {"match": {}, "x": "tfc-key-canary"}}}),
        json!({"at": "/when/match", "trigger": {"when": {"match": "tfc-leaf-canary"}}}),
        json!({"at": "/when/match/weird", "trigger": {"when": {"match": {"weird": "tfc-a"}}}}),
        json!({"at": "/when/match/header", "trigger": {"when": {"match": {"header": "tfc-b"}}}}),
        json!({
            "at": "/when/match/header/value",
            "trigger": {"when": {"match": {"header": {"name": "x", "value": "tfc-c"}}}}
        }),
        json!({
            "at": "/when/match/header/extra",
            "trigger": {"when": {"match": {"header": {"name": "x", "extra": "tfc-d"}}}}
        }),
    ] {
        let at = case["at"].as_str().expect("case pointer");
        let mut projected = case["trigger"].clone();
        let recorder = PlaceholderSiteRecorder::default();
        project_plugin_trigger_with(&mut projected, "/trigger", &recorder);
        assert_eq!(
            projected.pointer(at),
            Some(&json!(REDACTED)),
            "{case} -> {projected}"
        );
        assert!(
            !projected.to_string().contains("tfc-"),
            "{case} leaked: {projected}"
        );
    }
}

#[test]
fn fault_injection_match_header_values_are_projected() {
    let projected = project(
        "fault_injection",
        json!({
            "abort": { "status_code": 503, "percentage": 100.0 },
            "match": { "headers": { "x-chaos-test": "fault-target-secret-canary" } },
            "expires_at": "2026-11-01T12:30:00Z"
        }),
    );
    assert_eq!(projected["match"]["headers"]["x-chaos-test"], REDACTED);
    // Header names, fault shape, and the experiment bound stay visible.
    assert_eq!(projected["abort"]["status_code"], 503);
    assert_eq!(projected["expires_at"], "2026-11-01T12:30:00Z");
    assert_no_canaries(&projected, &["fault-target-secret-canary"]);
}

#[test]
fn otel_header_values_are_secret_by_default_regardless_of_name() {
    let projected = project(
        "otel_tracing",
        json!({
            "endpoint": "https://api.honeycomb.io/v1/traces",
            "headers": {
                "x-honeycomb-team": "otel-honeycomb-canary",
                "dd-api-key": "otel-datadog-canary",
                "lightstep-access-token": "otel-lightstep-canary",
                "x-tenant": "otel-tenant-canary"
            },
            "batch_size": 50,
            "include_url_path": true
        }),
    );
    for name in [
        "x-honeycomb-team",
        "dd-api-key",
        "lightstep-access-token",
        "x-tenant",
    ] {
        assert_eq!(projected["headers"][name], REDACTED, "header {name}");
    }
    assert_eq!(projected["batch_size"], 50);
    assert_eq!(projected["include_url_path"], true);
    assert_no_canaries(
        &projected,
        &[
            "otel-honeycomb-canary",
            "otel-datadog-canary",
            "otel-lightstep-canary",
            "otel-tenant-canary",
        ],
    );
}

#[test]
fn proxy_alerts_generic_webhook_url_headers_and_body_template_are_projected() {
    let projected = project(
        "proxy_alerts",
        json!({
            "channels": {
                "generic": {
                    "type": "webhook",
                    // Generic key `url`, not `webhook_url`: no substring match.
                    "url": "https://hooks.example.com/services/alerts-path-canary?t=alerts-query-canary",
                    "headers": {
                        "x-routing-key": "alerts-header-canary"
                    },
                    "body_template": "{\"routing_key\":\"alerts-template-canary\",\"msg\":\"${message}\"}",
                    "method": "POST"
                },
                "ops-slack": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/services/T0/B0/alerts-slack-canary"
                }
            },
            "rules": [{"name": "5xx", "type": "error_rate", "threshold": 5}]
        }),
    );
    let generic = &projected["channels"]["generic"];
    assert_eq!(
        generic["url"],
        "https://hooks.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(generic["headers"]["x-routing-key"], REDACTED);
    assert_eq!(generic["body_template"], REDACTED);
    // Safe-value controls: channel type/method and rules stay readable.
    assert_eq!(generic["type"], "webhook");
    assert_eq!(generic["method"], "POST");
    assert_eq!(projected["rules"][0]["name"], "5xx");
    assert_eq!(projected["rules"][0]["threshold"], 5);
    // The name-heuristic layer already fully redacts `webhook_url`; the schema
    // must not weaken that to a structural projection.
    assert_eq!(projected["channels"]["ops-slack"]["webhook_url"], REDACTED);
    assert_no_canaries(
        &projected,
        &[
            "alerts-path-canary",
            "alerts-query-canary",
            "alerts-header-canary",
            "alerts-template-canary",
            "alerts-slack-canary",
        ],
    );
}

#[test]
fn proxy_alerts_array_shaped_channels_are_projected_too() {
    let projected = project(
        "proxy_alerts",
        json!({
            "channels": [
                {
                    "type": "webhook",
                    "url": "https://hooks.example.com/array-path-canary",
                    "headers": {"x-routing-key": "array-header-canary"},
                    "body_template": "array-template-canary"
                }
            ]
        }),
    );
    assert_eq!(
        projected["channels"][0]["url"],
        "https://hooks.example.com/[REDACTED_PATH]"
    );
    assert_eq!(
        projected["channels"][0]["headers"]["x-routing-key"],
        REDACTED
    );
    assert_eq!(projected["channels"][0]["body_template"], REDACTED);
    assert_no_canaries(
        &projected,
        &[
            "array-path-canary",
            "array-header-canary",
            "array-template-canary",
        ],
    );
}

// ---------------------------------------------------------------------------
// Kafka producer properties
// ---------------------------------------------------------------------------

#[test]
fn kafka_producer_properties_redact_everything_outside_the_safe_allow_list() {
    let projected = project(
        "kafka_logging",
        json!({
            "broker_list": "broker.example.com:9093",
            "topic": "ferrum-logs",
            "security_protocol": "sasl_ssl",
            "producer_config": {
                // librdkafka marks each of these sensitive.
                "ssl.key.pem": "-----BEGIN PRIVATE KEY-----kafka-pem-canary-----END PRIVATE KEY-----",
                "ssl.key.password": "kafka-keypw-canary",
                "ssl.keystore.password": "kafka-keystorepw-canary",
                "sasl.password": "kafka-saslpw-canary",
                "sasl.oauthbearer.config": "kafka-oauth-canary",
                // Matches no name heuristic at all: only the allow-list saves it.
                "sasl.kerberos.keytab": "kafka-keytab-canary",
                // Safe tuning knobs survive as operator diagnostics.
                "linger.ms": "20",
                "compression.type": "lz4",
                "queue.buffering.max.messages": "100000"
            }
        }),
    );
    let props = &projected["producer_config"];
    for sensitive in [
        "ssl.key.pem",
        "ssl.key.password",
        "ssl.keystore.password",
        "sasl.password",
        "sasl.oauthbearer.config",
        "sasl.kerberos.keytab",
    ] {
        assert_eq!(props[sensitive], REDACTED, "property {sensitive}");
    }
    assert_eq!(props["linger.ms"], "20");
    assert_eq!(props["compression.type"], "lz4");
    assert_eq!(props["queue.buffering.max.messages"], "100000");
    assert_eq!(projected["topic"], "ferrum-logs");
    assert_eq!(projected["broker_list"], "broker.example.com:9093");
    assert_no_canaries(
        &projected,
        &[
            "kafka-pem-canary",
            "kafka-keypw-canary",
            "kafka-keystorepw-canary",
            "kafka-saslpw-canary",
            "kafka-oauth-canary",
            "kafka-keytab-canary",
        ],
    );
}

/// The allow-list is the load-bearing half of the Kafka rule: a stray entry
/// silently un-redacts a property forever.
#[test]
fn kafka_safe_property_allow_list_holds_no_credential_shaped_names() {
    for safe in KAFKA_SAFE_PRODUCER_PROPERTIES {
        for marker in [
            "password", "secret", "key", "pem", "token", "cert", "auth", "sasl", "ssl",
        ] {
            assert!(
                !safe.contains(marker),
                "allow-listed producer property {safe} contains credential marker {marker}"
            );
        }
    }
    assert!(is_safe_kafka_producer_property("LINGER.MS"));
    assert!(is_safe_kafka_producer_property(" linger.ms "));
    assert!(!is_safe_kafka_producer_property("ssl.key.pem"));
    assert!(!is_safe_kafka_producer_property("sasl.oauthbearer.config"));
    assert!(!is_safe_kafka_producer_property("sasl.kerberos.keytab"));
}

#[test]
fn kafka_non_object_producer_config_fails_closed() {
    let projected = project(
        "kafka_logging",
        json!({"producer_config": "kafka-scalar-canary"}),
    );
    assert_eq!(projected["producer_config"], REDACTED);
    assert_no_canaries(&projected, &["kafka-scalar-canary"]);
}

// ---------------------------------------------------------------------------
// Shape handling: nesting, arrays, case/delimiter variants, fail-closed
// ---------------------------------------------------------------------------

#[test]
fn normalize_config_key_equates_case_delimiter_and_compact_spellings() {
    let expected = "customheaders";
    for spelling in [
        "custom_headers",
        "custom-headers",
        "customHeaders",
        "CUSTOM_HEADERS",
        "custom.headers",
        "customheaders",
        "CUSTOMHEADERS",
        "Custom_Headers",
    ] {
        assert_eq!(
            normalize_config_key(spelling),
            expected,
            "spelling {spelling} did not compact to {expected}"
        );
    }

    // Exact normalized matching: nearby safe spellings stay distinct.
    assert_ne!(normalize_config_key("custom_headers_enabled"), expected);
    assert_ne!(normalize_config_key("customheader"), expected);
    assert_ne!(normalize_config_key("headers"), expected);
    assert_eq!(normalize_config_key("redisUrl"), "redisurl");
    assert_eq!(normalize_config_key("redis_url"), "redisurl");
    assert_eq!(normalize_config_key("endpointUrl"), "endpointurl");
    assert_ne!(normalize_config_key("redis_username"), "redisurl");
}

#[test]
fn schema_paths_match_case_and_delimiter_variants() {
    for spelling in [
        "custom_headers",
        "custom-headers",
        "customHeaders",
        "CUSTOM_HEADERS",
        "custom.headers",
        "customheaders",
    ] {
        let mut config = serde_json::Map::new();
        config.insert(
            spelling.to_string(),
            json!({"x-scope-orgid": "loki-variant-canary"}),
        );
        // Safe sibling that must not collapse onto the sensitive map rule.
        config.insert("custom_headers_enabled".to_string(), json!(true));
        config.insert("batch_size".to_string(), json!(10));
        let projected = project("loki_logging", Value::Object(config));
        assert_eq!(
            projected[spelling]["x-scope-orgid"], REDACTED,
            "spelling {spelling} bypassed the schema"
        );
        assert_eq!(projected["custom_headers_enabled"], true);
        assert_eq!(projected["batch_size"], 10);
        assert_no_canaries(&projected, &["loki-variant-canary"]);
    }
}

/// CamelCase / compact spellings must match schema paths at every depth, for
/// both arbitrary header-value maps and structural URL leaves.
#[test]
fn camelcase_and_compact_schema_paths_redact_at_nested_depths() {
    // Nested sink map: camelCase container + camelCase URL leaf.
    let projected = project(
        "ai_transcript_audit",
        json!({
            "sink": {
                "type": "http",
                "endpointUrl": "https://audit.example.com/ingest/nested-url-canary?token=nested-query-canary",
                "customHeaders": {"X-Audit-Token": "nested-header-canary"},
                "batch_size": 25
            },
            // Flat legacy aliases under compact spellings.
            "customheaders": {"Authorization": "flat-header-canary"},
            "endpointurl": "https://audit.example.com/flat-url-canary"
        }),
    );
    assert_eq!(
        projected["sink"]["endpointUrl"],
        "https://audit.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(
        projected["sink"]["customHeaders"]["X-Audit-Token"],
        REDACTED
    );
    assert_eq!(projected["customheaders"]["Authorization"], REDACTED);
    assert_eq!(
        projected["endpointurl"],
        "https://audit.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["sink"]["type"], "http");
    assert_eq!(projected["sink"]["batch_size"], 25);
    assert_no_canaries(
        &projected,
        &[
            "nested-url-canary",
            "nested-query-canary",
            "nested-header-canary",
            "flat-header-canary",
            "flat-url-canary",
        ],
    );

    // OTel headers map under compact spelling; endpoint under camelCase.
    let projected = project(
        "otel_tracing",
        json!({
            "endpoint": "https://otel.example.com/v1/traces/otel-path-canary",
            "Headers": {"x-honeycomb-team": "otel-header-canary"},
            "service_name": "edge"
        }),
    );
    assert_eq!(
        projected["endpoint"],
        "https://otel.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["Headers"]["x-honeycomb-team"], REDACTED);
    assert_eq!(projected["service_name"], "edge");
    assert_no_canaries(&projected, &["otel-path-canary", "otel-header-canary"]);
}

/// Unrelated safe fields must not normalize onto a sensitive schema segment.
#[test]
fn normalization_does_not_collapse_safe_fields_onto_sensitive_rules() {
    let projected = project(
        "http_logging",
        json!({
            "endpoint_url": "https://logs.example.com/ingest/http-path-canary",
            "custom_headers": {"X-Api-Key": "http-header-canary"},
            // Nearby names that share a prefix/suffix with sensitive segments.
            "custom_headers_enabled": true,
            "customheader": "safe-customheader-value",
            "headers_count": 3,
            "endpoint_url_timeout_ms": 1500,
            "batch_size": 50
        }),
    );
    assert_eq!(
        projected["endpoint_url"],
        "https://logs.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["custom_headers"]["X-Api-Key"], REDACTED);
    assert_eq!(projected["custom_headers_enabled"], true);
    assert_eq!(projected["customheader"], "safe-customheader-value");
    assert_eq!(projected["headers_count"], 3);
    assert_eq!(projected["endpoint_url_timeout_ms"], 1500);
    assert_eq!(projected["batch_size"], 50);
    assert_no_canaries(&projected, &["http-path-canary", "http-header-canary"]);
}

/// Direct heuristic / Redis-URL callers must honor the compact normalization.
#[test]
fn heuristic_and_redis_url_callers_match_compact_normalized_spellings() {
    for spelling in [
        "api_key", "api-key", "apiKey", "API_KEY", "api.key", "apikey",
    ] {
        assert!(
            is_sensitive_plugin_config_key(spelling),
            "heuristic missed sensitive spelling {spelling}"
        );
    }
    for spelling in [
        "redis_integrity_key",
        "redisIntegrityKey",
        "redisintegritykey",
        "client_secret",
        "clientSecret",
        "azure_function_key",
        "service_account_json",
        "serviceAccountJson",
    ] {
        assert!(
            is_sensitive_plugin_config_key(spelling),
            "heuristic missed sensitive spelling {spelling}"
        );
    }
    // Negative controls: safe neighbors must not trip the substring floor.
    assert!(!is_sensitive_plugin_config_key("batch_size"));
    assert!(!is_sensitive_plugin_config_key("redis_username"));
    assert!(!is_sensitive_plugin_config_key("integrity_status"));
    assert!(!is_sensitive_plugin_config_key("ttl_seconds"));
    assert!(!is_sensitive_plugin_config_key("api_version"));
    assert!(!is_sensitive_plugin_config_key("keyboard_layout"));

    for spelling in [
        "redis_url",
        "redis-url",
        "redisUrl",
        "REDIS_URL",
        "redis.url",
        "redisurl",
    ] {
        assert!(
            is_credential_bearing_url_config_key(spelling),
            "redis URL detector missed spelling {spelling}"
        );
    }
    assert!(!is_credential_bearing_url_config_key("redis_username"));
    assert!(!is_credential_bearing_url_config_key("redis_url_template"));
    assert!(!is_credential_bearing_url_config_key("url"));

    // End-to-end through the heuristic layer on a custom plugin (no schema).
    let projected = project(
        "some_custom_plugin",
        json!({
            "apiKey": "custom-apikey-canary",
            "redisUrl": "redis://cacheuser:custom-redis-canary@cache.internal:6379/2",
            "redisUsername": "cacheuser",
            "batchSize": 9
        }),
    );
    assert_eq!(projected["apiKey"], REDACTED);
    assert_eq!(
        projected["redisUrl"],
        "redis://redacted@cache.internal:6379/2"
    );
    assert_eq!(projected["redisUsername"], "cacheuser");
    assert_eq!(projected["batchSize"], 9);
    assert_no_canaries(&projected, &["custom-apikey-canary", "custom-redis-canary"]);
}

#[test]
fn nested_and_array_wrapped_endpoint_values_fail_closed() {
    // A header map that is not a map cannot be classified per-entry.
    let projected = project(
        "otel_tracing",
        json!({"headers": "otel-scalar-headers-canary"}),
    );
    assert_eq!(projected["headers"], REDACTED);
    assert_no_canaries(&projected, &["otel-scalar-headers-canary"]);

    // An endpoint that is an array of nested objects is replaced wholesale
    // rather than walked, so a credential at any depth cannot survive.
    let projected = project(
        "otel_tracing",
        json!({"endpoint": [null, {"nested": "https://c.example/x?code=otel-nested-canary"}]}),
    );
    assert_eq!(projected["endpoint"], REDACTED);
    assert_no_canaries(&projected, &["otel-nested-canary"]);
}

#[test]
fn null_values_are_preserved_and_null_config_is_untouched() {
    let projected = project(
        "otel_tracing",
        json!({"endpoint": null, "authorization": null, "headers": null}),
    );
    assert!(projected["endpoint"].is_null());
    assert!(projected["authorization"].is_null());
    assert!(projected["headers"].is_null());

    let mut null_config = Value::Null;
    project_plugin_config("otel_tracing", &mut null_config);
    assert!(null_config.is_null());
}

#[test]
fn non_object_configs_are_replaced_wholesale() {
    for shape in [
        json!("scalar-config-canary"),
        json!(["array-config-canary", {"nested": "nested-config-canary"}]),
        json!(42),
        json!(true),
    ] {
        let projected = project("loki_logging", shape);
        assert_eq!(projected, json!(REDACTED));
    }
}

#[test]
fn url_userinfo_is_stripped_on_paths_no_rule_names() {
    let projected = project(
        "mcp_gateway",
        json!({
            // Not in any rule for this plugin.
            "discovery": {
                "peers": [
                    "https://svc:userinfo-array-canary@peer.example.com/mcp",
                    "https://plain.example.com/mcp"
                ]
            },
            "upstream_url": "https://svc:upstream-userinfo-canary@up.example.com/mcp"
        }),
    );
    assert_eq!(
        projected["discovery"]["peers"][0],
        "https://redacted@peer.example.com/mcp"
    );
    // Safe-value control: a URL without userinfo is untouched by the sweep.
    assert_eq!(
        projected["discovery"]["peers"][1],
        "https://plain.example.com/mcp"
    );
    // The schema rule wins on the named path: userinfo is marked and the path
    // is replaced with its structural marker.
    assert_eq!(
        projected["upstream_url"],
        "https://redacted@up.example.com/[REDACTED_PATH]"
    );
    assert_no_canaries(
        &projected,
        &["userinfo-array-canary", "upstream-userinfo-canary"],
    );
}

/// Header *name* lists are not credentials. Redacting them would break routing
/// configuration readability and is exactly the mistake a substring-only rule
/// makes.
#[test]
fn header_name_lists_are_not_redacted() {
    let projected = project(
        "cors",
        json!({
            "allowed_headers": ["authorization", "content-type"],
            "exposed_headers": ["x-request-id"]
        }),
    );
    assert_eq!(
        projected["allowed_headers"],
        json!(["authorization", "content-type"])
    );
    assert_eq!(projected["exposed_headers"], json!(["x-request-id"]));

    let projected = project(
        "rate_limiting",
        json!({"expose_headers": true, "limit_by": "ip"}),
    );
    assert_eq!(projected["expose_headers"], true);
    assert_eq!(projected["limit_by"], "ip");
}

/// The documented Redis projection shape must survive the refactor: it is
/// pinned by `docs/admin_api.md` and matches the Redis client's log fields.
#[test]
fn redis_url_keeps_its_documented_projection_shape() {
    let projected = project(
        "rate_limiting",
        json!({
            "redis_url": "redis://cacheuser:redis-userinfo-canary@cache.internal:6379/3?token=redis-query-canary#redis-frag-canary",
            "redis_username": "cacheuser",
            "sync_mode": "redis"
        }),
    );
    assert_eq!(
        projected["redis_url"],
        "redis://redacted@cache.internal:6379/3?[REDACTED_QUERY]#[REDACTED_FRAGMENT]"
    );
    // `redis_username` is not secret material and stays visible.
    assert_eq!(projected["redis_username"], "cacheuser");
    assert_eq!(projected["sync_mode"], "redis");
    assert_no_canaries(
        &projected,
        &[
            "redis-userinfo-canary",
            "redis-query-canary",
            "redis-frag-canary",
        ],
    );
}

#[test]
fn redis_projection_placeholders_are_detected_at_the_masked_site() {
    for (raw_url, expected) in [
        ("redis://redacted@h:6379/0", "redis://redacted@h:6379/0"),
        (
            "redis://h:6379/0?[REDACTED_QUERY]",
            "redis://h:6379/0?[REDACTED_QUERY]",
        ),
    ] {
        let mut config = json!({"redis_url": raw_url, "sync_mode": "redis"});
        let recorder = PlaceholderSiteRecorder::default();
        project_plugin_config_with("rate_limiting", &mut config, "/config", &recorder);
        assert_eq!(config["redis_url"], expected);
        assert_eq!(recorder.into_sites(), vec!["/config/redis_url".to_string()]);
        assert!(is_redaction_placeholder(&config["redis_url"]));
    }
}

/// `workload_metrics` accepts the same tracing-provider endpoint families as
/// the standalone tracing path. Their path/query components can carry
/// collector credentials, so both its singleton compatibility shape and its
/// canonical provider list must be covered by the schema.
#[test]
fn workload_metrics_tracing_provider_endpoints_are_projected_in_both_shapes() {
    let singleton = project(
        "workload_metrics",
        json!({
            "tracing_provider": {
                "kind": "zipkin",
                "config": {
                    "url": "https://zipkin.example.com/api/v2/workload-singleton-canary?token=singleton-query-canary"
                }
            },
            "service_name": "checkout"
        }),
    );
    assert_eq!(
        singleton["tracing_provider"]["config"]["url"],
        "https://zipkin.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(singleton["tracing_provider"]["kind"], "zipkin");
    assert_eq!(singleton["service_name"], "checkout");
    assert_no_canaries(
        &singleton,
        &["workload-singleton-canary", "singleton-query-canary"],
    );

    let providers = project(
        "workload_metrics",
        json!({
            "tracing_providers": [
                {
                    "kind": "zipkin",
                    "config": {
                        "url": "https://zipkin.example.com/api/v2/list-zipkin-canary"
                    }
                },
                {
                    "kind": "datadog",
                    "config": {
                        "agent_url": "https://datadog.example.com/list-datadog-canary?key=datadog-query-canary",
                        "service": "payments"
                    }
                },
                {
                    "kind": "lightstep",
                    "config": {
                        "collector_url": "https://lightstep.example.com/list-lightstep-canary?token=lightstep-query-canary"
                    }
                },
                {
                    "kind": "opentelemetry",
                    "config": {
                        "endpoint": "https://otel.example.com/v1/list-otel-canary?key=otel-query-canary"
                    }
                }
            ],
            "span_reporting_disabled": false
        }),
    );
    for (idx, expected) in [
        "https://zipkin.example.com/[REDACTED_PATH]",
        "https://datadog.example.com/[REDACTED_PATH]?[REDACTED_QUERY]",
        "https://lightstep.example.com/[REDACTED_PATH]?[REDACTED_QUERY]",
        "https://otel.example.com/[REDACTED_PATH]?[REDACTED_QUERY]",
    ]
    .into_iter()
    .enumerate()
    {
        let key = match idx {
            0 => "url",
            1 => "agent_url",
            2 => "collector_url",
            _ => "endpoint",
        };
        assert_eq!(providers["tracing_providers"][idx]["config"][key], expected);
    }
    assert_eq!(
        providers["tracing_providers"][1]["config"]["service"],
        "payments"
    );
    assert_eq!(providers["span_reporting_disabled"], false);
    assert_no_canaries(
        &providers,
        &[
            "list-zipkin-canary",
            "list-datadog-canary",
            "datadog-query-canary",
            "list-lightstep-canary",
            "lightstep-query-canary",
            "list-otel-canary",
            "otel-query-canary",
        ],
    );
}

// ---------------------------------------------------------------------------
// Wildcard entry semantics over array-shaped containers
// ---------------------------------------------------------------------------

/// A `*` segment names *each entry of the container*. Over an array the entries
/// are the elements themselves, so the segment must be consumed at the array
/// rather than handed to each element's own fields — otherwise the remaining
/// path (`base_url`) resolves against sibling scalars and fail-closes every
/// non-credential provider field the schema never named.
#[test]
fn array_shaped_provider_entries_keep_their_non_credential_fields() {
    let projected = project(
        "ai_federation",
        json!({
            "providers": [{
                "name": "redaction-provider",
                "provider_type": "openai",
                "api_key": "federation-provider-api-key-canary",
                "base_url": "https://api.example.com/v1/federation-base-canary",
                "model_patterns": ["gpt-*"]
            }]
        }),
    );
    let provider = &projected["providers"][0];
    // The credential-bearing paths are still projected...
    assert_eq!(provider["api_key"], REDACTED);
    assert_eq!(
        provider["base_url"],
        "https://api.example.com/[REDACTED_PATH]"
    );
    // ...while the safe identifiers an operator reads a config back by survive.
    assert_eq!(provider["name"], "redaction-provider");
    assert_eq!(provider["provider_type"], "openai");
    assert_eq!(provider["model_patterns"][0], "gpt-*");
    assert_no_canaries(
        &projected,
        &[
            "federation-provider-api-key-canary",
            "federation-base-canary",
        ],
    );
}

/// The same wildcard rule over an object-keyed container, so the two shapes
/// stay one contract rather than two behaviors.
#[test]
fn object_keyed_provider_entries_keep_their_non_credential_fields() {
    let projected = project(
        "ai_stream_router",
        json!({
            "providers": {
                "primary": {
                    "endpoint": "https://router.example.com/v1/stream-endpoint-canary",
                    "weight": 70
                }
            }
        }),
    );
    assert_eq!(
        projected["providers"]["primary"]["endpoint"],
        "https://router.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["providers"]["primary"]["weight"], 70);
    assert_no_canaries(&projected, &["stream-endpoint-canary"]);
}

/// A wildcard entry that is a scalar where the schema expects a container
/// cannot be classified, so it must still fail closed.
#[test]
fn scalar_wildcard_entries_still_fail_closed() {
    let projected = project(
        "ai_federation",
        json!({"providers": ["https://svc:scalar-provider-canary@api.example.com/v1"]}),
    );
    assert_eq!(projected["providers"][0], REDACTED);
    assert_no_canaries(&projected, &["scalar-provider-canary"]);
}

// ---------------------------------------------------------------------------
// Nested sink / parameter maps
// ---------------------------------------------------------------------------

#[test]
fn ai_transcript_audit_sink_endpoint_and_header_values_are_projected() {
    let projected = project(
        "ai_transcript_audit",
        json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/ingest/transcript-path-canary?apikey=transcript-query-canary",
                "custom_headers": {"X-Audit-Token": "transcript-header-canary"},
                "batch_size": 25
            }
        }),
    );
    assert_eq!(
        projected["sink"]["endpoint_url"],
        "https://audit.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(
        projected["sink"]["custom_headers"]["X-Audit-Token"],
        REDACTED
    );
    // Safe-value controls: sink wiring stays legible.
    assert_eq!(projected["sink"]["type"], "http");
    assert_eq!(projected["sink"]["batch_size"], 25);
    assert_no_canaries(
        &projected,
        &[
            "transcript-path-canary",
            "transcript-query-canary",
            "transcript-header-canary",
        ],
    );
}

/// The identity plugins reject a top-level endpoint spelling at admission —
/// `jwks_auth`, `oauth2_introspection`, and `oidc_relying_party` all require a
/// `providers` array and `reject_unknown_fields` the rest. A rule anchored at
/// the config root therefore matches nothing a stored config can ever hold, so
/// the schema must address the nested path that admission actually produces.
#[test]
fn identity_provider_endpoints_are_projected_in_the_admitted_nested_shape() {
    let projected = project(
        "jwks_auth",
        json!({
            "providers": [{
                "issuer": "https://auth.example.com/",
                "jwks_uri": "https://auth.example.com/jwks/jwks-path-canary?tenant=jwks-query-canary",
                "audience": "edge"
            }]
        }),
    );
    let provider = &projected["providers"][0];
    assert_eq!(
        provider["jwks_uri"],
        "https://auth.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    // Safe-value controls: the identifiers an operator reads a provider back by.
    assert_eq!(provider["issuer"], "https://auth.example.com/");
    assert_eq!(provider["audience"], "edge");
    assert_no_canaries(&projected, &["jwks-path-canary", "jwks-query-canary"]);

    let projected = project(
        "oauth2_introspection",
        json!({
            "providers": [{
                "introspection_endpoint": "https://idp.example.com/introspect/oauth-path-canary",
                "issuer": "https://idp.example.com/",
                "client_auth": {"client_id": "edge", "client_secret": "oauth-secret-canary"}
            }]
        }),
    );
    let provider = &projected["providers"][0];
    assert_eq!(
        provider["introspection_endpoint"],
        "https://idp.example.com/[REDACTED_PATH]"
    );
    assert_eq!(provider["client_auth"]["client_secret"], REDACTED);
    assert_eq!(provider["client_auth"]["client_id"], "edge");
    assert_no_canaries(&projected, &["oauth-path-canary", "oauth-secret-canary"]);

    let projected = project(
        "oidc_relying_party",
        json!({
            "providers": [{
                "issuer": "https://idp.example.com/",
                "discovery_url": "https://idp.example.com/.well-known/oidc-discovery-canary",
                "token_endpoint": "https://idp.example.com/token/oidc-token-canary",
                "authorization_endpoint": "https://idp.example.com/authorize/oidc-authz-canary",
                "userinfo_endpoint": "https://idp.example.com/userinfo/oidc-userinfo-canary",
                "end_session_endpoint": "https://idp.example.com/logout/oidc-logout-canary",
                "jwks_uri": "https://idp.example.com/jwks/oidc-jwks-canary",
                "client_id": "edge"
            }],
            "session": {"ttl_secs": 3600}
        }),
    );
    let provider = &projected["providers"][0];
    for field in [
        "discovery_url",
        "userinfo_endpoint",
        "end_session_endpoint",
        "jwks_uri",
    ] {
        assert_eq!(
            provider[field], "https://idp.example.com/[REDACTED_PATH]",
            "provider field {field} was not projected"
        );
    }
    // The additive name-heuristic floor is deliberately stricter for these
    // spellings: `token` is classified per segment, while `authorization`
    // matches the built-in sensitive substring list. Schema projection must
    // never weaken that existing full redaction.
    assert_eq!(provider["token_endpoint"], REDACTED);
    assert_eq!(provider["authorization_endpoint"], REDACTED);
    assert_eq!(provider["client_id"], "edge");
    assert_eq!(projected["session"]["ttl_secs"], 3600);
    assert_no_canaries(
        &projected,
        &[
            "oidc-discovery-canary",
            "oidc-token-canary",
            "oidc-authz-canary",
            "oidc-userinfo-canary",
            "oidc-logout-canary",
            "oidc-jwks-canary",
        ],
    );
}

/// `mcp_gateway` carries its upstream URLs under `servers.<id>.upstream_url`;
/// there is no top-level spelling. Construction refuses userinfo, query, and
/// fragment, but a hosted MCP server's ingest token still rides the path — and
/// a config stored `enabled: false` skips construction entirely.
#[test]
fn mcp_gateway_per_server_upstream_urls_are_projected() {
    let projected = project(
        "mcp_gateway",
        json!({
            "servers": {
                "github": {
                    "upstream_url": "https://mcp.example.com/v1/mcp-token-canary/sse",
                    "namespace": "gh",
                    "enabled": true
                }
            },
            "endpoint": {"path": "/mcp"}
        }),
    );
    let server = &projected["servers"]["github"];
    assert_eq!(
        server["upstream_url"],
        "https://mcp.example.com/[REDACTED_PATH]"
    );
    // Safe-value controls: routing metadata an operator needs stays readable.
    assert_eq!(server["namespace"], "gh");
    assert_eq!(server["enabled"], true);
    assert_eq!(projected["endpoint"]["path"], "/mcp");
    assert_no_canaries(&projected, &["mcp-token-canary"]);
}

/// `mcp_gateway` `servers.<id>.headers`, `ai_tool_governor` `approval.headers`
/// and `openapi_validator` `bypass.header_present` accept literal values under
/// arbitrary header names. Vendor credential names such as
/// `Ocp-Apim-Subscription-Key` or `x-functions-key` match no name heuristic, so
/// the schema must withhold every value regardless of its header name.
#[test]
fn upstream_and_approval_header_values_are_secret_regardless_of_name() {
    let mcp = project(
        "mcp_gateway",
        json!({
            "servers": {
                "github": {
                    "upstream_url": "https://mcp.example.com/mcp",
                    "namespace": "gh",
                    "headers": {
                        "Ocp-Apim-Subscription-Key": "mcp-apim-canary",
                        "x-functions-key": "mcp-functions-canary",
                        "x-honeycomb-team": "mcp-honeycomb-canary"
                    }
                }
            }
        }),
    );
    let headers = &mcp["servers"]["github"]["headers"];
    for name in [
        "Ocp-Apim-Subscription-Key",
        "x-functions-key",
        "x-honeycomb-team",
    ] {
        assert_eq!(headers[name], REDACTED, "mcp_gateway header {name}");
    }
    // Header names and routing metadata stay visible.
    assert_eq!(mcp["servers"]["github"]["namespace"], "gh");
    assert_no_canaries(
        &mcp,
        &[
            "mcp-apim-canary",
            "mcp-functions-canary",
            "mcp-honeycomb-canary",
        ],
    );

    let governor = project(
        "ai_tool_governor",
        json!({
            "mode": "enforce",
            "approval": {
                "endpoint_url": "https://approvals.example.com",
                "timeout_ms": 1500,
                "headers": {
                    "Ocp-Apim-Subscription-Key": "governor-apim-canary",
                    "x-tenant": "governor-tenant-canary"
                }
            }
        }),
    );
    let headers = &governor["approval"]["headers"];
    for name in ["Ocp-Apim-Subscription-Key", "x-tenant"] {
        assert_eq!(headers[name], REDACTED, "ai_tool_governor header {name}");
    }
    assert_eq!(governor["approval"]["timeout_ms"], 1500);
    assert_eq!(governor["mode"], "enforce");
    assert_no_canaries(
        &governor,
        &["governor-apim-canary", "governor-tenant-canary"],
    );

    let validator = project(
        "openapi_validator",
        json!({
            "bypass": {
                "paths": ["/health"],
                "header_present": {"x-skip-validation": "openapi-bypass-secret-canary"}
            }
        }),
    );
    assert_eq!(
        validator["bypass"]["header_present"]["x-skip-validation"],
        REDACTED
    );
    assert_eq!(validator["bypass"]["paths"], json!(["/health"]));
    assert_no_canaries(&validator, &["openapi-bypass-secret-canary"]);
}

/// An `operator` write that echoes the masked header value back is refused
/// rather than overwriting the stored credential with the placeholder.
#[test]
fn masked_upstream_and_approval_header_values_are_placeholder_sites() {
    let mcp = project(
        "mcp_gateway",
        json!({
            "servers": {
                "gh": {
                    "upstream_url": "https://mcp.example.com",
                    "namespace": "gh",
                    "headers": {"x-functions-key": "mcp-functions-canary"}
                }
            }
        }),
    );
    assert_eq!(
        placeholder_sites("mcp_gateway", &mcp),
        vec!["/config/servers/gh/headers/x-functions-key".to_string()]
    );

    let governor = project(
        "ai_tool_governor",
        json!({
            "approval": {
                "endpoint_url": "https://approvals.example.com",
                "headers": {"x-tenant": "governor-tenant-canary"}
            }
        }),
    );
    assert_eq!(
        placeholder_sites("ai_tool_governor", &governor),
        vec!["/config/approval/headers/x-tenant".to_string()]
    );

    let validator = project(
        "openapi_validator",
        json!({
            "bypass": {"header_present": {"x-skip": "openapi-bypass-secret-canary"}}
        }),
    );
    assert_eq!(
        placeholder_sites("openapi_validator", &validator),
        vec!["/config/bypass/header_present/x-skip".to_string()]
    );
}

#[test]
fn chargeback_clickhouse_endpoint_and_insert_params_are_projected() {
    let projected = project(
        "api_chargeback_sink",
        json!({
            "clickhouse": {
                "url": "https://clickhouse.example.com:8443/chargeback-path-canary",
                "database": "ferrum",
                "table": "charges_raw",
                "insert_query_params": {"async_insert": "chargeback-param-canary"}
            }
        }),
    );
    assert_eq!(
        projected["clickhouse"]["url"],
        "https://clickhouse.example.com:8443/[REDACTED_PATH]"
    );
    assert_eq!(
        projected["clickhouse"]["insert_query_params"]["async_insert"],
        REDACTED
    );
    // Safe-value controls: routing metadata an operator needs stays readable.
    assert_eq!(projected["clickhouse"]["database"], "ferrum");
    assert_eq!(projected["clickhouse"]["table"], "charges_raw");
    assert_no_canaries(
        &projected,
        &["chargeback-path-canary", "chargeback-param-canary"],
    );
}

// ---------------------------------------------------------------------------
// Placeholder write-back detection (issue #5925)
// ---------------------------------------------------------------------------

/// The sites where `config` already carries a redaction placeholder, as the
/// admin write path finds them.
fn placeholder_sites(plugin: &str, config: &Value) -> Vec<String> {
    let recorder = PlaceholderSiteRecorder::default();
    let mut walked = config.clone();
    project_plugin_config_with(plugin, &mut walked, "/config", &recorder);
    recorder.into_sites()
}

#[test]
fn redaction_placeholder_matches_only_the_exact_markers() {
    for marker in [
        json!("[REDACTED]"),
        json!("https://collector.example.com/[REDACTED_PATH]"),
        json!("https://collector.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"),
        json!("https://collector.example.com?[REDACTED_QUERY]"),
        json!("https://collector.example.com#[REDACTED_FRAGMENT]"),
        json!("https://redacted@collector.example.com"),
        // A partial edit that keeps one marker still carries it.
        json!("https://other.example.com:8443/[REDACTED_PATH]?page=2"),
        json!("redis://redacted@cache.internal:6379/3?[REDACTED_QUERY]"),
        json!("postgres://redacted@db.internal/app"),
    ] {
        assert!(is_redaction_placeholder(&marker), "{marker} not matched");
    }

    for legitimate in [
        json!("[redacted]"),
        json!("[REDACTED] "),
        json!(" [REDACTED]"),
        json!("x[REDACTED]"),
        json!("REDACTED"),
        json!("redacted"),
        json!("https://collector.example.com"),
        json!("https://collector.example.com/v1/[REDACTED_PATH]"),
        json!("https://collector.example.com/[REDACTED_PATH]x"),
        json!("https://collector.example.com?q=[REDACTED_QUERY]"),
        json!("https://redacted:password@collector.example.com/"),
        json!("https://user@collector.example.com/"),
        json!("redis://cache.internal:6379/3"),
        json!(42),
        json!(true),
        Value::Null,
        json!(["[REDACTED]"]),
        json!({"key": "[REDACTED]"}),
    ] {
        assert!(
            !is_redaction_placeholder(&legitimate),
            "{legitimate} wrongly matched"
        );
    }
}

/// Every value an operator read masks is found again when that read is sent
/// back, and the stored (raw) config itself trips nothing.
#[test]
fn placeholder_sites_are_exactly_the_masked_sites_of_a_round_tripped_read() {
    let raw = json!({
        "endpoint_url": "https://collector.example.com/push/path-canary?api_key=query-canary",
        "custom_headers": {"x-honeycomb-team": "vendor-canary"},
        "api_key": "name-heuristic-canary",
        "fallback": "https://user:pass@backup.example.com/ingest",
        "batch_size": 50,
        "service": "orders"
    });
    assert!(
        placeholder_sites("http_logging", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("http_logging", raw);
    let mut sites = placeholder_sites("http_logging", &projected);
    sites.sort();
    assert_eq!(
        sites,
        vec![
            "/config/api_key".to_string(),
            "/config/custom_headers/x-honeycomb-team".to_string(),
            "/config/endpoint_url".to_string(),
            "/config/fallback".to_string(),
        ]
    );
}

/// A layered site (structural URL projection, then the name heuristic) is
/// judged on the value the caller sent, not on the earlier layer's output.
#[test]
fn placeholder_sites_ignore_a_later_layer_rendering_an_earlier_layers_output() {
    let raw = json!({
        "providers": [{
            "issuer": "https://idp.example.com/",
            "token_endpoint": "https://idp.example.com/oauth/token",
            "client_id": "edge"
        }]
    });
    assert!(placeholder_sites("oidc_relying_party", &raw).is_empty());

    let projected = project("oidc_relying_party", raw);
    assert_eq!(projected["providers"][0]["token_endpoint"], REDACTED);
    assert_eq!(
        placeholder_sites("oidc_relying_party", &projected),
        vec!["/config/providers/0/token_endpoint".to_string()]
    );
}

/// A structural URL marker only matters where the projection masks: the same
/// string in a field the read shows verbatim was put there by the caller, not
/// the read.
#[test]
fn url_marker_outside_a_masked_site_is_not_reported() {
    let config = json!({
        "service": "https://collector.example.com/[REDACTED_PATH]",
        "batch_size": 50
    });
    assert!(placeholder_sites("http_logging", &config).is_empty());
}

/// The exact `[REDACTED]` placeholder is reported at every string site: the
/// TLS-material layer withholds a PEM private-key block by content in any
/// field, so an echoed marker in an unclassified field cannot be told apart
/// from a masked key, and the placeholder is reserved instead.
#[test]
fn exact_placeholder_is_reported_at_any_string_site() {
    let config = json!({"service": "[REDACTED]", "batch_size": 50});
    assert_eq!(
        placeholder_sites("http_logging", &config),
        ["/config/service"]
    );
}

#[test]
fn response_mock_match_values_are_secret_and_mock_content_stays_visible() {
    let projected = project(
        "response_mock",
        json!({
            "rules": [
                {
                    "path": "/users",
                    "match": {
                        "headers": {"x-tenant-token": "rm-header-canary"},
                        "query_params": {"page": "rm-query-canary"}
                    },
                    "status_code": 200,
                    "headers": {"x-mock": "visible"},
                    "body": "[]"
                },
                {"path": "/plain", "body": "plain-body"}
            ]
        }),
    );
    let rules = projected["rules"].as_array().expect("rules stay an array");
    assert_eq!(rules[0]["match"]["headers"]["x-tenant-token"], REDACTED);
    assert_eq!(rules[0]["match"]["query_params"]["page"], REDACTED);
    assert_eq!(rules[0]["path"], "/users");
    assert_eq!(rules[0]["status_code"], 200);
    assert_eq!(rules[0]["headers"]["x-mock"], "visible");
    assert_eq!(rules[0]["body"], "[]");
    assert_eq!(rules[1]["body"], "plain-body");
    assert_no_canaries(&projected, &["rm-header-canary", "rm-query-canary"]);
}

#[test]
fn request_transformer_rule_values_are_secret_for_every_target() {
    let projected = project(
        "request_transformer",
        json!({
            "rules": [
                {"operation": "update", "target": "header", "key": "Authorization",
                 "value": "Bearer rt-header-canary"},
                {"operation": "add", "target": "header", "key": "X-Tenant",
                 "value": "rt-plain-header-canary"},
                {"operation": "add", "target": "query", "key": "api_key",
                 "value": "rt-query-canary"},
                {"operation": "update", "target": "body", "key": "auth.token",
                 "value": "rt-body-canary"},
                {"operation": "rename", "target": "header", "key": "X-Old",
                 "new_key": "X-New"},
                {"operation": "remove", "target": "query", "key": "debug"}
            ]
        }),
    );
    let rules = projected["rules"].as_array().expect("rules stay an array");
    for (index, rule) in rules.iter().take(4).enumerate() {
        assert_eq!(rule["value"], REDACTED, "rule {index}");
    }
    // Operations, targets and rename destinations stay visible; `key` is
    // masked by the pre-existing name heuristic.
    assert_eq!(rules[1]["key"], REDACTED);
    assert_eq!(rules[0]["operation"], "update");
    assert_eq!(rules[1]["target"], "header");
    assert_eq!(rules[2]["target"], "query");
    assert_eq!(rules[4]["new_key"], "X-New");
    assert!(rules[5].get("value").is_none());
    assert_no_canaries(
        &projected,
        &[
            "rt-header-canary",
            "rt-plain-header-canary",
            "rt-query-canary",
            "rt-body-canary",
        ],
    );
}

#[test]
fn mesh_route_dispatch_request_transform_values_are_secret() {
    let projected = project(
        "mesh_route_dispatch",
        json!({
            "rules": [{
                "match": {"path_prefix": "/api"},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "Authorization",
                     "value": "Bearer mrd-route-canary"},
                    {"operation": "remove", "target": "header", "key": "x-debug"}
                ],
                "response_transform": [
                    {"operation": "add", "target": "header", "key": "x-route",
                     "value": "api"}
                ]
            }]
        }),
    );
    let rule = &projected["rules"][0];
    assert_eq!(rule["request_transform"][0]["value"], REDACTED);
    assert_eq!(rule["request_transform"][1]["operation"], "remove");
    assert_eq!(rule["match"]["path_prefix"], "/api");
    // Response header values are sent to clients, not upstream.
    assert_eq!(rule["response_transform"][0]["value"], "api");
    assert_no_canaries(&projected, &["mrd-route-canary"]);
}
