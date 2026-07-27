use std::collections::HashMap;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::{GatewayConfig, PluginScope, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, spiffe_id_to_san};
use ferrum_edge::plugins::ProxyProtocol;
use ferrum_edge::proxy::ProxyState;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use serde_json::json;

struct GeneratedSvid {
    _dir: tempfile::TempDir,
    cert_path: String,
    key_path: String,
    trust_bundle_path: String,
}

fn generate_gateway_svid() -> GeneratedSvid {
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    ca_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_pem = ca_cert.pem();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name = DistinguishedName::new();
    let id = SpiffeId::new("spiffe://corp.example/ns/gateway/sa/edge").expect("spiffe id");
    leaf_params
        .subject_alt_names
        .push(spiffe_id_to_san(&id).expect("spiffe san"));
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    leaf_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    leaf_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_issuer)
        .expect("leaf cert");

    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("gateway-svid.pem");
    let key_path = dir.path().join("gateway-svid.key");
    let trust_bundle_path = dir.path().join("gateway-trust.pem");
    std::fs::write(&cert_path, leaf_cert.pem()).expect("write cert");
    std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write key");
    std::fs::write(&trust_bundle_path, ca_pem).expect("write trust");

    GeneratedSvid {
        _dir: dir,
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
        trust_bundle_path: trust_bundle_path.to_string_lossy().to_string(),
    }
}

fn test_dns_cache() -> DnsCache {
    DnsCache::new(DnsConfig {
        global_overrides: HashMap::new(),
        resolver_addresses: None,
        hosts_file_path: None,
        dns_order: None,
        ttl_override_seconds: None,
        min_ttl_seconds: 5,
        stale_ttl_seconds: 3600,
        error_ttl_seconds: 1,
        max_cache_size: 10_000,
        warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        slow_threshold_ms: None,
        refresh_threshold_percent: 90,
        failed_retry_interval_seconds: 10,
        try_tcp_on_error: true,
        num_concurrent_reqs: 3,
        max_active_requests: 512,
        max_concurrent_refreshes: 64,
        shard_amount: 0,
    })
}

#[tokio::test]
async fn proxy_state_loads_gateway_svid_bundle_from_env_config() {
    let files = generate_gateway_svid();
    let env_config = EnvConfig {
        gateway_svid_cert_path: Some(files.cert_path),
        gateway_svid_key_path: Some(files.key_path),
        gateway_svid_trust_bundle_path: Some(files.trust_bundle_path),
        ..Default::default()
    };

    let (state, _handles) = ProxyState::new(
        GatewayConfig::default(),
        test_dns_cache(),
        env_config,
        None,
        None,
    )
    .expect("proxy state");

    let loaded = state.gateway_svid_bundle.load_full();
    let bundle = loaded.as_ref().as_ref().expect("gateway svid loaded");
    assert_eq!(
        bundle.spiffe_id.as_str(),
        "spiffe://corp.example/ns/gateway/sa/edge"
    );
    assert_eq!(bundle.trust_bundles.local.x509_authorities.len(), 1);
}

#[tokio::test]
async fn proxy_state_auto_injects_gateway_workload_metrics_from_svid() {
    let files = generate_gateway_svid();
    let env_config = EnvConfig {
        gateway_svid_cert_path: Some(files.cert_path),
        gateway_svid_key_path: Some(files.key_path),
        gateway_svid_trust_bundle_path: Some(files.trust_bundle_path),
        ..Default::default()
    };
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "edge-proxy",
        "listen_path": "/",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .expect("proxy fixture");
    let config = GatewayConfig {
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };

    let (state, _handles) =
        ProxyState::new(config, test_dns_cache(), env_config, None, None).expect("proxy state");

    let loaded_config = state.config.load_full();
    let plugin = loaded_config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == "__gateway_workload_metrics")
        .expect("gateway workload metrics plugin should be auto-injected");
    assert_eq!(plugin.plugin_name, "workload_metrics");
    assert_eq!(plugin.scope, PluginScope::Global);
    assert_eq!(
        plugin
            .config
            .get("workload_spiffe_id")
            .and_then(serde_json::Value::as_str),
        Some("spiffe://corp.example/ns/gateway/sa/edge")
    );

    let plugins =
        state
            .plugin_cache
            .get_plugins_for_protocol("ferrum", "edge-proxy", ProxyProtocol::Http);
    assert!(
        plugins
            .iter()
            .any(|plugin| plugin.name() == "workload_metrics"),
        "auto-injected workload_metrics should be active for HTTP proxies"
    );
}
