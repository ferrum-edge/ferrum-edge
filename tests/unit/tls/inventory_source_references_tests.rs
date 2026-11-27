//! Material-free TLS source references (issue #7394).
//!
//! The managed-TLS and ACME delete guards read every namespace in the
//! configuration store through `gateway_source_references`, so it must report
//! every kind of reference the inventory reports (proxy and upstream backend
//! TLS, managed JWKS consumers), with the configured scheme and identifier the
//! guards match on, and must not load any material.

use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy};
use ferrum_edge::time_compat::UtcTimestamp;
use ferrum_edge::tls::inventory::{TlsSourceReference, gateway_source_references};
use serde_json::json;

fn proxy_with_managed_ca(ca: &str) -> Proxy {
    serde_json::from_value::<Proxy>(json!({
        "id": "tenant-proxy",
        "namespace": "tenant-b",
        "listen_path": "/orders",
        "backend_scheme": "https",
        "backend_host": "orders.internal",
        "backend_port": 443,
        "backend_tls_server_ca_cert_path": ca,
        // Unreadable on purpose: collecting references must never open it.
        "backend_tls_client_cert_path": "/nonexistent-ferrum-tls/client.pem",
        "backend_tls_client_key_path": "/nonexistent-ferrum-tls/client-key.pem",
    }))
    .expect("proxy deserializes")
}

fn jwks_auth(id: &str, source: &str, enabled: bool) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: id.to_string(),
        namespace: "tenant-b".to_string(),
        plugin_name: "jwks_auth".to_string(),
        config: json!({ "providers": [{ "issuer": "https://idp.example", "jwks_source": source }] }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: UtcTimestamp::now(),
        updated_at: UtcTimestamp::now(),
    }
}

fn find<'a>(references: &'a [TlsSourceReference], field: &str) -> Option<&'a TlsSourceReference> {
    references
        .iter()
        .find(|reference| reference.usage.field == field)
}

#[test]
fn gateway_source_references_report_scheme_identifier_and_resource_without_loading() {
    let config = GatewayConfig {
        proxies: vec![proxy_with_managed_ca(
            "managed://ca-bundles/corp-ca#ca-bundle",
        )],
        plugin_configs: vec![
            jwks_auth("enabled-auth", "managed://jwks/corp-idp#jwks", true),
            jwks_auth("disabled-auth", "managed://jwks/staged-idp#jwks", false),
        ],
        ..Default::default()
    };

    let references = gateway_source_references(&config);

    let ca = find(&references, "backend_tls_server_ca_cert_path").expect("CA reference");
    assert_eq!(ca.source_kind, "managed");
    assert!(ca.identifier.contains("corp-ca"), "{}", ca.identifier);
    assert_eq!(ca.usage.resource_type, "proxy");
    assert_eq!(ca.usage.resource_id, "tenant-proxy");

    // The unreadable file sources are still listed: nothing was opened.
    let client = find(&references, "backend_tls_client_cert_path").expect("client cert");
    assert_eq!(client.source_kind, "file");

    let jwks = find(&references, "providers[].jwks_source").expect("JWKS reference");
    assert_eq!(jwks.source_kind, "managed");
    assert!(jwks.identifier.contains("corp-idp"), "{}", jwks.identifier);
    assert_eq!(jwks.usage.resource_type, "plugin_config");
    assert_eq!(jwks.usage.resource_id, "enabled-auth#provider[0]");

    // A disabled consumer reads nothing, so it holds no reference.
    assert!(
        !references
            .iter()
            .any(|reference| reference.identifier.contains("staged-idp")),
        "disabled jwks_auth must not count as a reference"
    );
}
