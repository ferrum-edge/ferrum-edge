//! Collection-element admission, including a valid nonempty list at each guarded field.

use ferrum_edge::config::plugin_trigger::PluginTriggerNode;
use ferrum_edge::config::types as config;
use ferrum_edge::modes::mesh::config as mesh;
use ferrum_edge::modes::mesh::slice::{MeshEgressScopeSnapshot, MeshSlice};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// Exercise each field independently so a sibling's rejection cannot mask a
/// missing guard. Check the second element as well as successful round trips.
fn assert_lists<T: DeserializeOwned + Serialize>(base: Value, fields: &[(&str, Value)]) {
    for (field, element) in fields {
        let mut body = base.clone();
        body[*field] = json!([element]);
        let parsed: T = serde_json::from_value(body.clone())
            .unwrap_or_else(|error| panic!("{}.{field}: {error}", std::any::type_name::<T>()));
        let serialized = serde_json::to_value(parsed).unwrap();
        assert_eq!(serialized[*field].as_array().unwrap().len(), 1);
        assert!(serialized[*field][0].is_object());
        let roundtrip: T = serde_json::from_value(serialized.clone()).unwrap();
        assert_eq!(serde_json::to_value(roundtrip).unwrap(), serialized);

        for rejected in [
            json!([]),
            json!(["positional"]),
            json!(null),
            json!(7),
            json!(true),
        ] {
            body[*field] = json!([element, rejected]);
            let bytes = serde_json::to_vec(&body).unwrap();
            let error = match serde_json::from_slice::<T>(&bytes) {
                Ok(_) => panic!("{}.{field} admitted {rejected}", std::any::type_name::<T>()),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("expected a JSON object"), "{field}: {error}");
            if rejected.is_array() {
                assert!(error.contains("invalid type: sequence"), "{field}: {error}");
            }
        }
        body[*field] = json!([]);
        assert!(
            serde_json::from_value::<T>(body).is_ok(),
            "{field}: empty list"
        );
    }
}

fn workload() -> Value {
    json!({
        "spiffe_id": "spiffe://example.org/ns/ferrum/sa/app",
        "selector": {},
        "service_name": "app",
        "trust_domain": "example.org",
        "namespace": "ferrum"
    })
}

fn named() -> Value {
    json!({"name": "app", "namespace": "ferrum"})
}

fn policy() -> Value {
    json!({"name": "app", "namespace": "ferrum", "scope": {"kind": "mesh_wide"}})
}

fn provider() -> Value {
    json!({
        "name": "authz", "service": "authz.ferrum", "port": 8080,
        "timeout_ms": 1000, "status_on_error": 403
    })
}

fn service_entry() -> Value {
    json!({"name": "app", "namespace": "ferrum", "hosts": ["app.example.org"]})
}

fn destination_rule() -> Value {
    json!({"name": "app", "namespace": "ferrum", "host": "app.example.org"})
}

fn extension() -> Value {
    // Nonempty Base64 proves the element's custom byte deserializer survives.
    json!({"name": "ext", "type_url": "example.org/extension", "value": "AQID"})
}

fn shared_mesh_lists() -> Vec<(&'static str, Value)> {
    vec![
        ("workloads", workload()),
        ("services", named()),
        ("mesh_policies", policy()),
        ("ext_authz_providers", provider()),
        ("peer_authentications", named()),
        ("service_entries", service_entry()),
        ("request_authentications", policy()),
        (
            "telemetry_resources",
            json!({"name": "app", "namespace": "ferrum", "config": {}}),
        ),
        ("destination_rules", destination_rule()),
        (
            "virtual_service_cors_policies",
            json!({
                "name": "app", "namespace": "ferrum", "host": "app.example.org",
                "cors": {"allowed_origins": []}
            }),
        ),
        ("proxy_configs", named()),
        ("extension_configs", extension()),
    ]
}

#[test]
fn mesh_config_and_slice_collection_elements_require_objects() {
    let mut config_fields = shared_mesh_lists();
    config_fields.extend([("sidecars", named()), ("waypoint_bindings", named())]);
    assert_lists::<mesh::MeshConfig>(json!({}), &config_fields);

    let mut slice_fields = shared_mesh_lists();
    slice_fields.extend([
        ("virtual_service_l4_proxies", json!({"id": "route"})),
        (
            "virtual_service_l4_upstreams",
            json!({"id": "route", "targets": []}),
        ),
        ("service_waypoint_bound_services", named()),
        ("ambient_udp_source_workloads", workload()),
        ("node_waypoint_capture_destinations", workload()),
        ("node_waypoint_capture_peer_authentications", named()),
        ("local_inbound_services", named()),
        ("local_inbound_workloads", workload()),
        (
            "node_waypoint_assertors",
            json!({"spiffe_id": "spiffe://example.org/ns/ferrum/sa/node"}),
        ),
        (
            "local_ingress_listeners",
            json!({"port": 8080, "endpoint_host": "127.0.0.1", "endpoint_port": 8081}),
        ),
    ]);
    let base = json!({"node_id": "node", "namespace": "ferrum", "version": "1"});
    assert_lists::<MeshSlice>(base.clone(), &slice_fields);
    let mut null = base;
    null["local_inbound_workloads"] = Value::Null;
    assert!(
        serde_json::from_value::<MeshSlice>(null)
            .unwrap()
            .local_inbound_workloads
            .is_none()
    );
    assert_lists::<MeshEgressScopeSnapshot>(
        json!({}),
        &[
            ("destination_rules", named()),
            ("services", named()),
            ("service_entries", named()),
        ],
    );
}

#[test]
fn nested_mesh_collection_elements_require_objects() {
    let port = json!({"port": 8080});
    assert_lists::<mesh::Workload>(workload(), &[("ports", port.clone())]);
    assert_lists::<mesh::MeshService>(
        named(),
        &[
            ("ports", port.clone()),
            (
                "workloads",
                json!({"spiffe_id": "spiffe://example.org/ns/ferrum/sa/app"}),
            ),
        ],
    );
    assert_lists::<mesh::MeshPolicy>(policy(), &[("rules", json!({"action": "allow"}))]);
    assert_lists::<mesh::MeshRule>(
        json!({"action": "allow"}),
        &[
            ("from", json!({})),
            ("to", json!({})),
            ("when", json!({"key": "request.auth.claims[sub]"})),
        ],
    );
    assert_lists::<mesh::MeshExtAuthzProvider>(
        provider(),
        &[(
            "include_additional_headers_in_check",
            json!({"name": "x-app", "value": "app"}),
        )],
    );
    assert_lists::<mesh::MeshRequestAuthentication>(
        policy(),
        &[("jwt_rules", json!({"issuer": "https://issuer.example.org"}))],
    );
    assert_lists::<mesh::MeshJwtRule>(
        json!({"issuer": "https://issuer.example.org"}),
        &[
            ("from_headers", json!({"name": "authorization"})),
            (
                "output_claim_to_headers",
                json!({"header": "x-user", "claim": "sub"}),
            ),
        ],
    );
    assert_lists::<mesh::MeshMetricsConfig>(
        json!({}),
        &[(
            "tag_overrides",
            json!({"name": "user", "operation": {"type": "remove"}}),
        )],
    );
    assert_lists::<mesh::ServiceEntry>(
        service_entry(),
        &[
            ("endpoints", json!({"address": "127.0.0.1"})),
            ("ports", port),
        ],
    );
    assert_lists::<mesh::MeshSidecar>(
        named(),
        &[
            ("egress", json!({"hosts": ["./*"]})),
            ("ingress", json!({"port": 8080})),
        ],
    );
    assert_lists::<mesh::MultiClusterConfig>(
        json!({}),
        &[
            (
                "remote_clusters",
                json!({"name": "west", "trust_domain": "example.org"}),
            ),
            (
                "east_west_gateways",
                json!({"name": "west", "namespace": "ferrum", "host": "west", "port": 443}),
            ),
        ],
    );
    assert_lists::<mesh::MeshDestinationRule>(
        destination_rule(),
        &[("subsets", json!({"name": "canary"}))],
    );
    assert_lists::<mesh::MeshLocalityLbSetting>(
        json!({}),
        &[
            ("distribute", json!({"from": "east"})),
            ("failover", json!({"from": "east", "to": "west"})),
        ],
    );
    assert_lists::<mesh::MeshWaypointBinding>(named(), &[("services", named())]);
}

#[test]
fn gateway_trust_collection_elements_require_objects() {
    assert_lists::<mesh::TrustBundleSet>(
        json!({"local": {"trust_domain": "example.org"}}),
        &[("federated", json!({"trust_domain": "peer.example.org"}))],
    );
    assert_lists::<mesh::TrustBundle>(
        json!({"trust_domain": "example.org"}),
        &[(
            "jwt_authorities",
            json!({"key_id": "test", "public_key_pem": "test-key"}),
        )],
    );
}

#[test]
fn gateway_resources_and_nested_lists_require_object_elements() {
    assert_lists::<config::Upstream>(
        json!({"targets": []}),
        &[
            ("targets", json!({"host": "127.0.0.1", "port": 8080})),
            (
                "subsets",
                json!({"name": "canary", "labels": {"version": "v2"}}),
            ),
        ],
    );
    for body in [
        json!({"targets": []}),
        json!({"targets": [], "subsets": null}),
    ] {
        assert!(
            serde_json::from_value::<config::Upstream>(body)
                .unwrap()
                .subsets
                .is_none()
        );
    }
    assert_lists::<config::UpstreamLocalityLbSetting>(
        json!({}),
        &[
            ("distribute", json!({"from": "east"})),
            ("failover", json!({"from": "east", "to": "west"})),
        ],
    );
    assert_lists::<config::Proxy>(json!({}), &[("plugins", json!({"plugin_config_id": "p"}))]);
    assert_lists::<config::GatewayConfig>(
        json!({"version": "1", "proxies": [], "plugin_configs": []}),
        &[
            ("proxies", json!({"id": "p"})),
            ("consumers", json!({"username": "user"})),
            (
                "plugin_configs",
                json!({"plugin_name": "cors", "scope": "global"}),
            ),
            ("upstreams", json!({"targets": []})),
            (
                "frontend_tls_certificate_sources",
                json!({"namespace": "ferrum", "cert_path": "cert.pem", "key_path": "key.pem"}),
            ),
        ],
    );
    assert_lists::<ferrum_edge::proxy::stream_match::StreamMatchCriteria>(
        json!({}),
        &[("arms", json!({"source_namespace": "ferrum"}))],
    );
    let node = json!({"match": {"method": ["GET"]}});
    assert_lists::<PluginTriggerNode>(json!({}), &[("all", node.clone()), ("any", node)]);
    let nulls: PluginTriggerNode =
        serde_json::from_value(json!({"all": null, "any": null})).unwrap();
    assert!(nulls.all.is_none() && nulls.any.is_none());
}

#[test]
fn delta_resource_and_qualified_removal_lists_require_objects() {
    use ferrum_edge::config::db_backend::IncrementalResult;

    // Kind 1 ConfigUpdate.config_json must enforce the same resource-element
    // admission as the kind 0 GatewayConfig tested above.
    let base = json!({
        "added_or_modified_proxies": [], "removed_proxy_ids": [],
        "added_or_modified_consumers": [], "removed_consumer_ids": [],
        "added_or_modified_plugin_configs": [], "removed_plugin_config_ids": [],
        "added_or_modified_upstreams": [], "removed_upstream_ids": [],
        "sequence_cursor": 0, "poll_timestamp": "2026-09-16T00:00:00Z"
    });
    let key = json!({"namespace": "ferrum", "id": "removed"});
    assert_lists::<IncrementalResult>(
        base.clone(),
        &[
            ("added_or_modified_proxies", json!({"id": "p"})),
            ("added_or_modified_consumers", json!({"username": "user"})),
            (
                "added_or_modified_plugin_configs",
                json!({"plugin_name": "cors", "scope": "global"}),
            ),
            ("added_or_modified_upstreams", json!({"targets": []})),
            ("removed_proxy_ids", key.clone()),
            ("removed_consumer_ids", key.clone()),
            ("removed_plugin_config_ids", key.clone()),
            ("removed_upstream_ids", key),
        ],
    );

    let positional = json!([
        {},
        "replacement",
        null,
        "ferrum",
        [],
        "/replacement",
        "http",
        "127.0.0.1",
        12345
    ]);
    let proxy: config::Proxy = serde_json::from_value(positional.clone()).unwrap();
    assert_eq!(proxy.id, "replacement");
    let mut delta = base.clone();
    delta["added_or_modified_proxies"] = json!([positional]);
    let error = match serde_json::from_value::<IncrementalResult>(delta) {
        Ok(_) => panic!("the delta must reject the otherwise-valid positional Proxy"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("expected a JSON object"), "{error}");
}

#[test]
fn cp_dp_trust_bundle_key_elements_require_objects() {
    use ferrum_edge::grpc::cp_trust::CpDpTrustBundle;

    let secret = "test-only-cp-trust-key-at-least-32-bytes";
    let key = json!({
        "kid": "tenant", "algorithm": "HS256", "namespaces": ["ferrum"], "secret": secret
    });
    let valid = json!({"version": 1, "keys": [key]});
    assert_eq!(
        CpDpTrustBundle::from_document_str(&valid.to_string(), "test-bundle", None)
            .unwrap()
            .key_count(),
        1
    );
    for rejected in [
        json!(["tenant", "HS256", ["ferrum"], secret]),
        json!([]),
        json!(null),
        json!(7),
    ] {
        for keys in [json!([rejected]), json!([key, rejected])] {
            let body = json!({"version": 1, "keys": keys});
            let parsed = CpDpTrustBundle::from_document_str(&body.to_string(), "test-bundle", None);
            let error = match parsed {
                Ok(_) => panic!("trust keys must require objects"),
                Err(error) => error,
            };
            assert!(error.contains("expected a JSON object"), "{error}");
        }
    }
}

#[test]
fn cni_and_application_probe_collection_inputs_require_objects() {
    use ferrum_edge::cni::rpc::CniRpcRequest;
    use ferrum_edge::cni::spec::CniNetConfig;
    use ferrum_edge::modes::mesh::app_probe::{AppProbeHttpGet, AppProbeSpec};

    let attachment = json!({"containerID": "container", "ifname": "eth0"});
    assert_lists::<CniNetConfig>(
        json!({"cniVersion": "1.1.0", "name": "mesh", "type": "ferrum-cni"}),
        &[("cni.dev/valid-attachments", attachment.clone())],
    );
    assert_lists::<CniRpcRequest>(
        json!({"verb": "gc", "network_name": "mesh", "valid_attachments": []}),
        &[("valid_attachments", attachment)],
    );
    for verb in ["gc", "status"] {
        for attachments in [None, Some(Value::Null)] {
            let mut body = json!({"verb": verb, "network_name": "mesh"});
            if let Some(attachments) = attachments {
                body["valid_attachments"] = attachments;
            }
            assert_eq!(
                serde_json::from_value::<CniRpcRequest>(body).is_ok(),
                verb == "status"
            );
        }
    }
    assert_lists::<AppProbeHttpGet>(
        json!({"port": 8080}),
        &[("httpHeaders", json!({"name": "x-probe", "value": "ready"}))],
    );
    for field in ["httpGet", "tcpSocket", "grpc"] {
        let mut body = json!({field: {"port": 8080}});
        assert!(serde_json::from_value::<AppProbeSpec>(body.clone()).is_ok());
        body[field] = json!([]);
        let error = serde_json::from_value::<AppProbeSpec>(body)
            .unwrap_err()
            .to_string();
        assert!(error.contains("expected a JSON object"), "{field}: {error}");
    }
    let mut net = json!({"name": "mesh", "type": "ferrum-cni", "ferrum": {}});
    assert!(serde_json::from_value::<CniNetConfig>(net.clone()).is_ok());
    net["ferrum"] = json!([]);
    let error = serde_json::from_value::<CniNetConfig>(net)
        .unwrap_err()
        .to_string();
    assert!(error.contains("expected a JSON object"), "ferrum: {error}");
}

#[test]
fn durable_cni_attachment_file_rejects_otherwise_valid_positional_records() {
    use ferrum_edge::cni::ownership::{
        CNI_OWNERSHIP_STORE_VERSION, CniOwnershipStoreError, DurableCniOwnershipRecord,
        parse_durable_cni_ownership_bytes,
    };

    let positional = json!(["mesh", "container", "eth0", "pod-uid", {"attached": true}]);
    let record: DurableCniOwnershipRecord = serde_json::from_value(positional.clone()).unwrap();
    let valid = json!({"version": CNI_OWNERSHIP_STORE_VERSION, "attachments": [record]});
    assert_eq!(
        parse_durable_cni_ownership_bytes(&serde_json::to_vec(&valid).unwrap()).unwrap(),
        vec![record]
    );
    for rejected in [positional, json!([]), json!(null), json!(7)] {
        let mut body = valid.clone();
        body["attachments"].as_array_mut().unwrap().push(rejected);
        assert_eq!(
            parse_durable_cni_ownership_bytes(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            CniOwnershipStoreError::TruncatedOrInvalid
        );
    }
    let mut malformed = valid["attachments"][0].clone();
    malformed["cleanup"] = json!([]);
    let error = serde_json::from_value::<DurableCniOwnershipRecord>(malformed)
        .unwrap_err()
        .to_string();
    assert!(error.contains("expected a JSON object"), "cleanup: {error}");
}

#[test]
fn route_dispatch_lists_and_external_ref_snapshots_require_object_elements() {
    use ferrum_edge::admin::api_specs::external_refs::ExternalRefSnapshot;
    use ferrum_edge::plugins::mesh_route_dispatch::{MeshRouteDispatchConfig, RouteRule};

    let rule = json!({"match": {}, "destination": {}});
    assert_lists::<MeshRouteDispatchConfig>(json!({}), &[("rules", rule.clone())]);
    let transform = json!({"operation": "remove", "key": "x-user"});
    assert_lists::<RouteRule>(
        rule,
        &[
            ("request_transform", transform.clone()),
            ("response_transform", transform),
        ],
    );
    assert_lists::<ExternalRefSnapshot>(
        json!({
            "policy_digest": "p", "root_document_base": "r",
            "documents": [], "snapshot_digest": "s"
        }),
        &[(
            "documents",
            json!({"canonical_uri": "u", "content_digest": "d", "format": "json", "document": {}}),
        )],
    );
}

#[test]
fn restore_resource_lists_and_api_spec_items_require_objects() {
    use ferrum_edge::_test_support::restore_envelope_admission_for_test;

    let fields = [
        ("proxies", json!({"id": "p"})),
        ("consumers", json!({"id": "c", "username": "user"})),
        (
            "plugin_configs",
            json!({"id": "p", "plugin_name": "cors", "scope": "global"}),
        ),
        ("upstreams", json!({"id": "u", "targets": []})),
        (
            "gateway_trust_bundles",
            json!({"id": "trust", "bundle": {"local": {"trust_domain": "example.org"}}}),
        ),
    ];
    for (field, element) in fields {
        let body = json!({field: [element]});
        restore_envelope_admission_for_test(&serde_json::to_vec(&body).unwrap()).unwrap();
        for rejected in [json!([]), json!([{}, "positional"]), json!(null), json!(7)] {
            let body = json!({field: [element, rejected]});
            let error = restore_envelope_admission_for_test(&serde_json::to_vec(&body).unwrap())
                .unwrap_err()
                .to_string();
            assert!(error.contains("expected a JSON object"), "{field}: {error}");
        }
    }
    let item = json!({
        "id": "s", "proxy_id": "p", "spec_version": "3.0.0", "spec_format": "json",
        "spec_content_base64": "", "content_encoding": "gzip", "uncompressed_size": 0,
        "content_hash": "h", "created_at": "2026-09-16T00:00:00Z",
        "updated_at": "2026-09-16T00:00:00Z"
    });
    let body = json!({"api_specs": {"section_version": "2", "items": [item]}});
    restore_envelope_admission_for_test(&serde_json::to_vec(&body).unwrap()).unwrap();
    let mut rejected = body;
    rejected["api_specs"]["items"] = json!([[]]);
    let error = restore_envelope_admission_for_test(&serde_json::to_vec(&rejected).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("expected a JSON object"),
        "api_specs.items: {error}"
    );
}

#[test]
fn mesh_authz_raw_lists_require_object_elements_before_construction() {
    use ferrum_edge::plugins::mesh::authz::MeshAuthz;

    let upstream = json!({
        "id": "route", "namespace": "ferrum",
        "targets": [{"host": "127.0.0.1", "port": 8080}]
    });
    let valid = json!({
        "per_pod_policy_scoping": true,
        "mesh_policies": [policy()],
        "node_waypoint_route_upstreams": [upstream]
    });
    assert!(MeshAuthz::new(&valid).is_ok());
    for pointer in [
        "/mesh_policies/0",
        "/node_waypoint_route_upstreams/0",
        "/node_waypoint_route_upstreams/0/targets/0",
    ] {
        for rejected in [json!([]), json!(["positional"]), json!(7)] {
            let mut body = valid.clone();
            *body.pointer_mut(pointer).unwrap() = rejected;
            let error = match MeshAuthz::new(&body) {
                Ok(_) => panic!("mesh_authz admitted {pointer}"),
                Err(error) => error,
            };
            assert!(
                error.contains("expected a JSON object"),
                "{pointer}: {error}"
            );
        }
    }
}

#[test]
fn scalar_identity_lists_keep_their_string_wire_shapes() {
    let spiffe = "spiffe://example.org/ns/ferrum/sa/app";
    let valid = json!({"spiffe_id": spiffe, "asserts": [spiffe]});
    assert!(serde_json::from_value::<mesh::NodeWaypointAssertor>(valid).is_ok());
    let invalid = json!({"spiffe_id": spiffe, "asserts": [[]]});
    assert!(serde_json::from_value::<mesh::NodeWaypointAssertor>(invalid).is_err());
    for field in [
        "ip_blocks",
        "not_ip_blocks",
        "remote_ip_blocks",
        "not_remote_ip_blocks",
    ] {
        let valid = json!({field: ["10.0.0.0/8"]});
        assert!(serde_json::from_value::<mesh::SourceNegationMatch>(valid).is_ok());
        let invalid = json!({field: [[]]});
        assert!(serde_json::from_value::<mesh::SourceNegationMatch>(invalid).is_err());
    }
}
