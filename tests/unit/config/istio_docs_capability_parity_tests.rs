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
const OPENAPI_YAML: &str = include_str!("../../../openapi.yaml");
const CONTROL_PLANE_RBAC: &str =
    include_str!("../../../charts/ferrum-mesh/templates/control-plane-rbac.yaml");

/// Ten kinds watched by `ISTIO_CRDS` (order must match `watcher.rs`).
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
    "ProxyConfig",
];

fn extract_istio_crd_kinds(source: &str) -> Vec<String> {
    let start = source
        .find("pub const ISTIO_CRDS")
        .expect("ISTIO_CRDS declaration");
    let after = &source[start..];
    let end = after.find("\n];").expect("ISTIO_CRDS closing bracket");
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
                if kind.chars().all(|c| c.is_ascii_alphabetic())
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
fn istio_crds_are_exactly_the_ten_watched_status_kinds() {
    let kinds = extract_istio_crd_kinds(WATCHER_RS);
    let expected: Vec<String> = WATCHED_STATUS_KINDS
        .iter()
        .map(|k| (*k).to_string())
        .collect();
    assert_eq!(
        kinds, expected,
        "ISTIO_CRDS kind list drifted from the documented ten watched/status kinds"
    );
    assert!(
        kinds.iter().any(|k| k == "ProxyConfig"),
        "ProxyConfig must be in ISTIO_CRDS (issue #2396)"
    );
    assert!(
        WATCHER_RS.contains("version: \"v1beta1\"")
            && WATCHER_RS.contains("plural: \"proxyconfigs\""),
        "ProxyConfig watcher must target networking.istio.io/v1beta1 proxyconfigs"
    );
}

#[test]
fn status_writer_supported_kinds_match_istio_crds() {
    let status_kinds = extract_supported_status_kinds(ISTIO_STATUS_RS);
    let expected: BTreeSet<_> = WATCHED_STATUS_KINDS
        .iter()
        .map(|k| (*k).to_string())
        .collect();
    assert_eq!(
        status_kinds, expected,
        "is_supported_istio_kind must stay lock-step with ISTIO_CRDS"
    );
    assert!(
        status_kinds.contains("ProxyConfig"),
        "ProxyConfig must be a status-writer kind (Istio CRD declares subresources.status)"
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
fn helm_rbac_grants_proxyconfig_watch_and_status() {
    assert!(
        CONTROL_PLANE_RBAC.contains("proxyconfigs"),
        "chart Istio RBAC must grant get/list/watch on proxyconfigs"
    );
    assert!(
        CONTROL_PLANE_RBAC.contains("proxyconfigs/status"),
        "chart Istio RBAC must grant status verbs on proxyconfigs/status"
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
        CONFIGURATION_MD.contains("| `ProxyConfig` | Yes | Yes"),
        "ProxyConfig row must state watcher/RBAC is present"
    );
    assert!(
        !CONFIGURATION_MD.contains("**No** (not in `ISTIO_CRDS`"),
        "ProxyConfig row must not claim watcher/RBAC is absent"
    );
    assert!(
        CONFIGURATION_MD.contains("ProxyConfigsCarrier"),
        "ProxyConfig row must acknowledge the xDS ECDS carrier"
    );
    assert!(
        CONFIGURATION_MD.contains("fail-closed 0–100")
            || CONFIGURATION_MD.contains("fails closed on non-numeric or out-of-range"),
        "capability contract must document ProxyConfig tracing.sampling fail-closed bounds"
    );
    // Istio's authoritative `proxyconfigs.networking.istio.io` v1beta1 CRD has
    // a structural spec schema with exactly four properties (`selector`,
    // `concurrency`, `image`, `environmentVariables`) and no
    // `x-kubernetes-preserve-unknown-fields` on `spec`, so `spec.tracing` is
    // pruned by the API server. The capability contract must not imply the
    // watcher can observe `tracing.sampling`, or operators will apply a
    // ProxyConfig that is silently pruned and get no sampling change.
    assert!(
        CONFIGURATION_MD.contains("pruned by the Kubernetes API server"),
        "capability contract must disclose that ProxyConfig spec.tracing is pruned by K8s"
    );
    assert!(
        !CONFIGURATION_MD.contains("from watched `ProxyConfig.spec.tracing.sampling`"),
        "capability contract must not claim tracing.sampling arrives over the CRD watcher"
    );
}

/// The `docs/mesh.md` ECDS carrier-table row for the workload-scoped Sidecar
/// outbound policy (issue #3262).
const MESH_MD_SIDECAR_OUTBOUND_CARRIER_ROW: &str = concat!(
    "| `sidecar_outbound_traffic_policy` | `SidecarOutboundTrafficPolicyCarrier` ",
    "| `ferrum-mesh-carrier/sidecar-outbound-traffic-policy` |",
);

/// The pre-#3262 `Sidecar` capability row, which omitted `outboundTrafficPolicy`
/// entirely.
const STALE_SIDECAR_CAPABILITY_ROW: &str = concat!(
    "| `Sidecar` | Yes | Yes | Yes (egress/ingress scope) ",
    "| Yes (`SidecarEgressScopeCarrier` + ingress carriers) |",
);

/// Issue #3262: the `Sidecar` capability row must name workload-scoped
/// `outboundTrafficPolicy` support and its dedicated ECDS carrier, and the
/// carrier source must actually define them. Without this, the row silently
/// regresses to the pre-#3262 "egress/ingress scope" claim while the feature
/// stays shipped.
#[test]
fn capability_contract_sidecar_row_covers_outbound_traffic_policy() {
    let row = CONFIGURATION_MD
        .lines()
        .find(|line| line.trim_start().starts_with("| `Sidecar` |"))
        .expect("capability contract must include an explicit Sidecar row");
    assert!(
        row.contains("outboundTrafficPolicy"),
        "Sidecar row must claim native workload-scoped outboundTrafficPolicy support, got: {row}"
    );
    assert!(
        row.contains("SidecarOutboundTrafficPolicyCarrier"),
        "Sidecar row must name the xDS ECDS recovery carrier, got: {row}"
    );
    assert!(
        row.contains("SidecarEgressScopeCarrier"),
        "Sidecar row must keep the pre-existing egress-scope carrier claim, got: {row}"
    );
    // The claim must be backed by the carrier source, not just prose.
    assert!(
        CARRIER_RS.contains("SidecarOutboundTrafficPolicy(")
            && CARRIER_RS.contains("FERRUM_ECDS_SIDECAR_OUTBOUND_POLICY_TYPE_URL")
            && CARRIER_RS.contains("SidecarOutboundTrafficPolicyCarrier"),
        "carrier.rs must define the SidecarOutboundTrafficPolicy carrier variant + type URL"
    );
    assert!(
        CARRIER_RS.contains("ferrum-mesh-carrier/sidecar-outbound-traffic-policy"),
        "carrier.rs must reserve the sidecar-outbound-traffic-policy ECDS resource name"
    );
    // Two distinct precedence tiers, two distinct carriers.
    assert!(
        CARRIER_RS.contains("ferrum-mesh-carrier/outbound-traffic-policy"),
        "the mesh-wide outbound-traffic-policy carrier must stay separate"
    );
    // docs/mesh.md must carry the matching carrier table row and section.
    assert!(
        MESH_MD.contains(MESH_MD_SIDECAR_OUTBOUND_CARRIER_ROW),
        "docs/mesh.md ECDS carrier table must list the sidecar outbound policy carrier"
    );
    assert!(
        MESH_MD.contains("## Sidecar Outbound Traffic Policy"),
        "docs/mesh.md must host the Sidecar Outbound Traffic Policy section the row links to"
    );
    // The pre-#3262 row text must not come back.
    assert!(
        !CONFIGURATION_MD.contains(STALE_SIDECAR_CAPABILITY_ROW),
        "Sidecar capability row must not revert to the pre-#3262 egress/ingress-only claim"
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
        "what is missing is the Kubernetes watcher/RBAC/status path",
        "but it is not in `ISTIO_CRDS` and the status writer does not patch it",
        "all nine watched/translated Istio kinds",
        "wildcard `notPorts` patterns fail closed at translation",
        "literal `notPorts` only",
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
        CONFIGURATION_MD.contains(
            "negative-match siblings `notMethods`, `notPaths`, `notHosts`, and `notPorts`"
        ),
        "docs/configuration.md must document negative-match translation"
    );
    assert!(
        CONFIGURATION_MD.contains("not_port_patterns"),
        "docs/configuration.md must document wildcard notPorts projection into not_port_patterns"
    );
    assert!(
        !CONFIGURATION_MD.contains("wildcard `notPorts` patterns are rejected at translation time"),
        "docs/configuration.md must not claim wildcard notPorts are rejected"
    );
    assert!(
        CONFIGURATION_MD.contains("all ten watched/translated Istio kinds"),
        "docs/configuration.md must claim status for all ten watched kinds"
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
        !MESH_MD.contains("does **not** watch `ProxyConfig` CRDs"),
        "docs/mesh.md must not claim ProxyConfig is unwatched"
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
        MESH_MD.contains("All ten translated kinds are covered"),
        "docs/mesh.md Istio CRD Status must keep the ten-kind claim"
    );
    assert!(
        MESH_MD.contains("ten Istio CRDs"),
        "docs/mesh.md Migrating from Istio summary must count ten watched CRDs"
    );
    assert!(
        MESH_MD.contains("The ten translated CRDs"),
        "docs/mesh.md Migrating from Istio table must list ten translated CRDs"
    );
    assert!(
        MESH_MD.contains("`ProxyConfig`"),
        "docs/mesh.md Migrating from Istio summary must include ProxyConfig"
    );
    let stale_nine_kind = [
        "nine Istio CRDs",
        "The nine translated CRDs",
        "all nine watched/translated Istio kinds",
    ];
    for phrase in stale_nine_kind {
        assert!(
            !MESH_MD.contains(phrase),
            "docs/mesh.md must not retain stale nine-kind claim: {phrase}"
        );
    }
}

#[test]
fn openapi_workload_metrics_sampling_documents_proxy_config_source() {
    // Once ProxyConfig is watched, injected workload_metrics.sampling_percentage
    // is no longer Telemetry-only; keep the OpenAPI description in lock-step.
    assert!(
        OPENAPI_YAML.contains("sampling_percentage:"),
        "openapi.yaml must define workload_metrics.sampling_percentage"
    );
    assert!(
        OPENAPI_YAML.contains("ProxyConfig.spec.tracing.sampling"),
        "openapi.yaml sampling_percentage must cite ProxyConfig.spec.tracing.sampling"
    );
    assert!(
        !OPENAPI_YAML.contains("Tracing sampling percentage 0.0–100.0 (from Istio Telemetry CRD)."),
        "openapi.yaml must not claim sampling_percentage is Telemetry-only"
    );
    // ...but it must not claim the value arrives over the CRD watcher either:
    // Istio's ProxyConfig CRD schema has no `tracing` property, so the API
    // server prunes it and the baseline comes from native/file/xDS mesh config.
    assert!(
        OPENAPI_YAML.contains("MeshProxyConfig.tracing_sampling"),
        "openapi.yaml must name the mesh-model field that actually supplies the baseline"
    );
    assert!(
        !OPENAPI_YAML.contains("from watched `ProxyConfig.spec.tracing.sampling`"),
        "openapi.yaml must not claim tracing.sampling is watched from the ProxyConfig CRD"
    );
}

/// Istio's `proxyconfigs.networking.istio.io` v1beta1 CRD admits only
/// `selector`, `concurrency`, `image`, and `environmentVariables` in its
/// structural spec schema. `docs/mesh.md` must say so next to the
/// `spec.tracing.sampling` row rather than presenting it as an Istio field an
/// operator can `kubectl apply`.
#[test]
fn mesh_md_discloses_proxy_config_tracing_is_not_a_crd_field() {
    assert!(
        MESH_MD.contains("Ferrum mesh-model extension, not an Istio CRD field"),
        "docs/mesh.md ProxyConfig field table must flag tracing.sampling as a non-CRD field"
    );
    assert!(
        MESH_MD.contains("pruned by the Kubernetes API server"),
        "docs/mesh.md must state that spec.tracing.sampling is pruned by the API server"
    );
    for stale in [
        "Istio's ProxyConfig CRD types it as a bare `double` with no range validation",
        "reaches the watcher intact",
    ] {
        assert!(
            !MESH_MD.contains(stale),
            "docs/mesh.md must not retain the stale CRD-reachability claim: {stale}"
        );
    }
}
