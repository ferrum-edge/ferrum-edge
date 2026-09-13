use ferrum_edge::admin::provisioning::{provisioner, stamp_resources};
use ferrum_edge::config::types::{GatewayConfig, validate_resource_labels};
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn resource_labels_validate_bounds_and_round_trip_file_and_sync_documents() {
    let mut value = serde_json::to_value(GatewayConfig::default()).unwrap();
    value["consumers"] =
        json!([{"username":"alice","labels":{"provisioned-by":"ferrum-nexus","team":"platform"}}]);
    let config: GatewayConfig = serde_json::from_value(value).unwrap();
    let yaml = serde_yaml::to_string(&config).unwrap();
    let from_file: GatewayConfig = serde_yaml::from_str(&yaml).unwrap();
    let from_sync: GatewayConfig =
        serde_json::from_slice(&serde_json::to_vec(&from_file).unwrap()).unwrap();
    assert_eq!(from_sync.consumers[0].labels, config.consumers[0].labels);
    assert!(validate_resource_labels(&BTreeMap::from([("".into(), "value".into())])).is_err());
    assert!(validate_resource_labels(&BTreeMap::from([("key".into(), "x".repeat(513))])).is_err());
    assert!(
        validate_resource_labels(&BTreeMap::from([("key".into(), "line\nbreak".into())])).is_err()
    );
    assert!(
        validate_resource_labels(&(0..65).map(|i| (format!("key{i}"), "v".into())).collect())
            .is_err()
    );
    assert!(
        validate_resource_labels(&BTreeMap::from([("k".repeat(129), "value".into())])).is_err()
    );
    assert!(
        validate_resource_labels(&BTreeMap::from([("tab\tkey".into(), "value".into())])).is_err()
    );
    assert!(
        validate_resource_labels(&BTreeMap::from([("k".repeat(128), "v".repeat(512))])).is_ok()
    );
}

#[test]
fn provisioner_header_is_bounded_trimmed_and_rejects_non_text_values() {
    let header = |raw: &[u8]| {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "x-ferrum-provisioned-by",
            hyper::header::HeaderValue::from_bytes(raw).unwrap(),
        );
        provisioner(&headers)
    };
    assert_eq!(provisioner(&hyper::HeaderMap::new()).unwrap(), None);
    assert_eq!(
        header(b"  ferrum-nexus  ").unwrap().as_deref(),
        Some("ferrum-nexus")
    );
    assert!(header(b"").is_err());
    assert!(header(b"   ").is_err());
    assert!(header(b"ferrum\tnexus").is_err());
    assert!(header(&[b'a'; 513]).is_err());
    assert_eq!(header(&[b'a'; 512]).unwrap(), Some("a".repeat(512)));
    let err = header("caf\u{e9}".as_bytes()).unwrap_err();
    assert!(err.contains("must be text"), "{err}");
}

#[test]
fn resource_labels_header_and_restore_do_not_replace_existing_origins_or_spec_hash_graphs() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("x-ferrum-provisioned-by", "ferrum-foundry".parse().unwrap());
    assert_eq!(
        provisioner(&headers).unwrap().as_deref(),
        Some("ferrum-foundry")
    );
    headers.append("x-ferrum-provisioned-by", "other".parse().unwrap());
    assert!(provisioner(&headers).is_err());
    let mut original = serde_json::to_value(GatewayConfig::default()).unwrap();
    original["proxies"] = json!([
        {"id":"spec", "api_spec_id":"s", "backend_host":"example.com", "backend_port":443},
        {"id":"manual", "backend_host":"example.com", "backend_port":443, "labels":{"provisioned-by":"ferrum-nexus"}},
        {"id":"new", "backend_host":"example.com", "backend_port":443}
    ]);
    let mut config: GatewayConfig = serde_json::from_value(original).unwrap();
    stamp_resources(
        &mut config.proxies,
        &mut config.consumers,
        &mut config.upstreams,
        &mut config.plugin_configs,
        Some("ferrum-foundry"),
        true,
    );
    assert!(config.proxies[0].labels.is_empty());
    assert_eq!(config.proxies[1].labels["provisioned-by"], "ferrum-nexus");
    assert_eq!(config.proxies[2].labels["provisioned-by"], "ferrum-foundry");
}
