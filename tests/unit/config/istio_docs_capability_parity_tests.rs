//! CFG-03 / XDS-02: Istio capability claims in docs must match watcher,
//! status writer, and ECDS carrier sources.
//!
//! Pins the shared capability-dimension contract in
//! `docs/configuration.md` (`<!-- istio-capability-contract:v1 -->`) against
//! `ISTIO_CRDS`, `is_supported_istio_kind`, and `ProxyConfigsCarrier`, and
//! guards `docs/mesh.md` against the historical "ProxyConfig is native-only"
//! contradiction. Static `include_str!` inspection only — no mesh runtime.

use std::collections::BTreeSet;

const WATCHER_RS: &str = include_str!("../../../src/k8s_controller/watcher.rs");
const ISTIO_STATUS_RS: &str = include_str!("../../../src/k8s_controller/istio_status.rs");
const CARRIER_RS: &str = include_str!("../../../src/xds/carrier.rs");
const CONFIGURATION_MD: &str = include_str!("../../../docs/configuration.md");
const MESH_MD: &str = include_str!("../../../docs/mesh.md");

/// Nine kinds watched by `ISTIO_CRDS` (order must match `watcher.rs`).
const WATCHED_STATUS_KINDS: &[&str] = &[
    "AuthorizationPolicy",
    "PeerAuthentication",
    "RequestAuthentication",
    "VirtualService",
    "DestinationRule",
    "ServiceEntry",
    "WorkloadEntry",
    "Sidecar",
    "Telemetry",
];

fn extract_istio_crd_kinds(source: &str) -> Vec<String> {
    let start = source
        .find("pub const ISTIO_CRDS")
        .expect("ISTIO_CRDS declaration");
    let after = &source[start..];
    let end = after
        .find("\n];")
        .expect("ISTIO_CRDS closing bracket");
    let block = &after[..end];
    let mut kinds = Vec::new();
    for line in block.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("kind: \"") else {
            continue;
        };
        let Some(end_quote) = rest.find('"') else {
            continue;
        };
        kinds.push(rest[..end_quote].to_string());
    }
    kinds
}

fn extract_supported_status_kinds(source: &str) -> BTreeSet<String> {
    let start = source
        .find("fn is_supported_istio_kind")
        .expect("is_supported_istio_kind");
    let after = &source[start..];
    // Truncate at the next top-level `fn` so we only scan this predicate.
    let end = after[1..]
        .find("\nfn ")
        .map(|idx| idx + 1)
        .unwrap_or(after.len());
    let block = &after[..end];
    let mut kinds = BTreeSet::new();
    let bytes = block.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let key_start = i + 1;
            let mut key_end = key_start;
            while key_end < bytes.len() && bytes[key_end] != b'"' {
                key_end += 1;
            }
            if key_end < bytes.len() {
                let kind = &block[key_start..key_end];
                if kind
                    .chars()
                    .all(|c| c.is_ascii_alphabetic())
                    && kind.starts_with(|c: char| c.is_ascii_uppercase())
                    && kind.len() > 3
                {
                    kinds.insert(kind.to_string());
                }
                i = key_end + 1;
                continue;
            }
        }
        i += 1;
    }
    kinds
}

#[test]
fn istio_crds_are_exactly_the_nine_watched_status_kinds() {
    let kinds = extract_istio_crd_kinds(WATCHER_RS);
    let expected: Vec<String> = WATCHED_STATUS_KINDS.iter().map(|k| (*k).to_string()).collect();
    assert_eq!(
        kinds, expected,
        "ISTIO_CRDS kind list drifted from the documented nine watched/status kinds"
    );
    assert!(
        !kinds.iter().any(|k| k == "ProxyConfig"),
        "ProxyConfig must not be in ISTIO_CRDS (watcher/status gap is intentional)"
    );
}

#[test]
fn status_writer_supported_kinds_match_istio_crds() {
    let status_kinds = extract_supported_status_kinds(ISTIO_STATUS_RS);
    let expected: BTreeSet<_> = WATCHED_STATUS_KINDS.iter().map(|k| (*k).to_string()).collect();
    assert_eq!(
        status_kinds, expected,
        "is_supported_istio_kind must stay lock-step with ISTIO_CRDS"
    );
    assert!(
        !status_kinds.contains("ProxyConfig"),
        "ProxyConfig must not be a status-writer kind"
    );
}

#[test]
fn proxy_config_has_ecds_carrier_marker() {
    assert!(
        CARRIER_RS.contains("ProxyConfigsCarrier"),
        "carrier.rs must define ProxyConfigsCarrier"
    );
    assert!(
        CARRIER_RS.contains("ferrum-mesh-carrier/proxy-configs"),
        "carrier.rs must reserve the proxy-configs ECDS resource name"
    );
    assert!(
        CARRIER_RS.contains("FERRUM_ECDS_PROXY_CONFIGS_TYPE_URL"),
        "carrier.rs must export FERRUM_ECDS_PROXY_CONFIGS_TYPE_URL"
    );
}

#[test]
fn configuration_md_hosts_capability_contract_v1() {
    assert!(
        CONFIGURATION_MD.contains("<!-- istio-capability-contract:v1 -->"),
        "docs/configuration.md must host the shared capability-contract marker"
    );
    assert!(
        CONFIGURATION_MD.contains("#### Istio CRD capability dimensions"),
        "docs/configuration.md must expose the capability-dimensions heading"
    );
    for kind in WATCHED_STATUS_KINDS {
        assert!(
            CONFIGURATION_MD.contains(&format!("`{kind}`")),
            "capability contract must list watched kind {kind}"
        );
    }
    assert!(
        CONFIGURATION_MD.contains("| `ProxyConfig` |"),
        "capability contract must include an explicit ProxyConfig row"
    );
    assert!(
        CONFIGURATION_MD.contains("**No** (not in `ISTIO_CRDS`"),
        "ProxyConfig row must state watcher/RBAC is absent"
    );
    assert!(
        CONFIGURATION_MD.contains("ProxyConfigsCarrier"),
        "ProxyConfig row must acknowledge the xDS ECDS carrier"
    );
}

#[test]
fn configuration_md_rejects_stale_istio_capability_claims() {
    let stale = [
        "portLevelSettings[].tls` is parsed and warned but not enforced per-port",
        "AuthorizationPolicy` negative-match fields (`notMethods`, `notPaths`, `notHosts`, `notPorts` — rejected at translation time)",
        "including the negative-match siblings `notMethods`, `notPaths`, `notHosts`, and `notPorts` — is rejected at translation time",
        "Other Istio CRDs (`VirtualService`, `ServiceEntry`, `RequestAuthentication`, `Sidecar`, `Telemetry`, `WorkloadEntry`) are deferred to a follow-on",
        "patches `status.conditions[]` on `AuthorizationPolicy`, `PeerAuthentication`, and `DestinationRule` CRDs so",
    ];
    for phrase in stale {
        assert!(
            !CONFIGURATION_MD.contains(phrase),
            "docs/configuration.md must not retain stale claim: {phrase}"
        );
    }
    assert!(
        CONFIGURATION_MD.contains("portLevelSettings[].tls` is applied per-port"),
        "docs/configuration.md must state port-level TLS is applied"
    );
    assert!(
        CONFIGURATION_MD.contains("negative-match siblings `notMethods`, `notPaths`, `notHosts`, and `notPorts`"),
        "docs/configuration.md must document negative-match translation"
    );
    assert!(
        CONFIGURATION_MD.contains("all nine watched/translated Istio kinds"),
        "docs/configuration.md must claim status for all nine watched kinds"
    );
}

#[test]
fn mesh_md_proxy_config_transport_matches_carrier_semantics() {
    assert!(
        !MESH_MD.contains("ProxyConfig` is native-only"),
        "docs/mesh.md must not claim ProxyConfig is native-only"
    );
    assert!(
        !MESH_MD.contains(
            "Operators relying on ProxyConfig translation must use `FERRUM_MESH_CONFIG_PROTOCOL=native`"
        ),
        "docs/mesh.md must not require native-only for ProxyConfig"
    );
    assert!(
        MESH_MD.contains("ProxyConfigsCarrier"),
        "docs/mesh.md must document ProxyConfigsCarrier transport"
    );
    assert!(
        MESH_MD.contains("configuration.md#istio-crd-capability-dimensions"),
        "docs/mesh.md must link the shared capability-dimensions contract"
    );
    assert!(
        MESH_MD.contains("All nine translated kinds are covered"),
        "docs/mesh.md Istio CRD Status must keep the nine-kind claim"
    );
}
