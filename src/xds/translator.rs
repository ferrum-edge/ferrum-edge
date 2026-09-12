use crate::fips::approved::Sha256;
use prost::Message;
use std::collections::HashSet;
use tracing::warn;

use super::carrier::{
    FERRUM_CARRIER_RESOURCE_NAME_PREFIX, MeshSliceCarrier, build_slice_carriers,
    carrier_resource_name_for_type_url,
};
use super::proto;
use super::runtime_proto;
use super::snapshot::{XdsResource, XdsSnapshot};
use crate::modes::mesh::config::{
    FractionalPercentDenominator, MeshDestinationRule, MeshRuntimeOverlay,
    RuntimeFractionalPercent, RuntimeValue,
};
use crate::modes::mesh::slice::MeshSlice;

pub const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
pub const RDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
pub const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
pub const SDS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";
pub const ECDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig";
pub const RTDS_TYPE_URL: &str = "type.googleapis.com/envoy.service.runtime.v3.Runtime";

/// Inner `type_url` Ferrum uses for the DestinationRule-carrier ECDS payload.
/// CPs that want full DR semantics across xDS wrap the original DR JSON in a
/// TypedExtensionConfig with this inner type. GAP-2K's recovery path
/// recognizes the marker and applies the embedded DR locally.
pub const FERRUM_ECDS_DESTINATION_RULE_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier";
pub const FERRUM_DR_CARRIER_RESOURCE_NAME_PREFIX: &str = "ferrum-destination-rule-carrier/";

pub const XDS_TYPE_URLS: [&str; 7] = [
    LDS_TYPE_URL,
    RDS_TYPE_URL,
    CDS_TYPE_URL,
    EDS_TYPE_URL,
    SDS_TYPE_URL,
    ECDS_TYPE_URL,
    RTDS_TYPE_URL,
];

/// Closed-set log label for a top-level xDS `type_url`.
///
/// Recognized profile types map to a short operator label; any other
/// peer-supplied value collapses to a single `unknown` label. This keeps every
/// `type_url` that reaches a log field bounded regardless of input length, so a
/// hostile or misconfigured peer cannot inject arbitrary bytes into a log line
/// or amplify log volume (issue #4813).
pub fn xds_type_url_log_label(type_url: &str) -> &'static str {
    match type_url {
        CDS_TYPE_URL => "cds",
        EDS_TYPE_URL => "eds",
        LDS_TYPE_URL => "lds",
        RDS_TYPE_URL => "rds",
        SDS_TYPE_URL => "sds",
        ECDS_TYPE_URL => "ecds",
        RTDS_TYPE_URL => "rtds",
        _ => "unknown",
    }
}

pub fn translate_mesh_slice_to_snapshot(slice: &MeshSlice) -> XdsSnapshot {
    let mut resources = Vec::new();
    resources.extend(translate_lds(slice));
    resources.extend(translate_rds(slice));
    resources.extend(translate_cds(slice));
    resources.extend(translate_eds(slice));
    resources.extend(translate_sds(slice));
    resources.extend(translate_ecds(slice));
    resources.extend(translate_destination_rule_carriers(slice));
    // GAP-1a: emit the security- and policy-bearing slice fields as Ferrum
    // mesh-slice ECDS carriers so the xDS path reaches native parity. Without
    // these, the DP rebuilds the slice with authz/PeerAuth/JWT/trust-bundle/
    // ServiceEntry/ProxyConfig/workload fields emptied — an unprotected mesh.
    resources.extend(translate_mesh_slice_carriers(slice));
    // Per-resource versions are content-derived so two snapshots with the
    // same resource bytes carry identical resource versions. This is the
    // basis for delta xDS wire-byte reduction: clients that report the
    // resource via `initial_resource_versions` (or that previously ACKed it on
    // this stream) get the resource skipped on the next response when its
    // content hasn't changed. The aggregate `snapshot.version` still
    // changes whenever any resource bytes change.
    //
    // The per-resource hash deliberately excludes `slice.version` so a slice
    // bumping its base version (e.g. on a `loaded_at` timestamp tick) does
    // not invalidate every cached resource version on the client side.
    for resource in &mut resources {
        resource.version = per_resource_version(resource);
    }
    let version = content_version(&slice.version, &resources);
    XdsSnapshot::new(slice.node_id.clone(), version, resources)
}

pub fn translate_lds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for service in &slice.services {
        for port in &service.ports {
            let name = format!(
                "listener/{}/{}/{}",
                service.namespace, service.name, port.port
            );
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                LDS_TYPE_URL,
                &slice.version,
                proto::Listener { name },
            );
        }
    }
    resources
}

pub fn translate_rds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for service in &slice.services {
        let name = format!("route/{}/{}", service.namespace, service.name);
        push_unique_resource(
            &mut resources,
            &mut seen_names,
            name.clone(),
            RDS_TYPE_URL,
            &slice.version,
            proto::RouteConfiguration { name },
        );
    }
    resources
}

pub fn translate_cds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for service in &slice.services {
        for port in &service.ports {
            let name = cluster_name(&service.namespace, &service.name, port.port);
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                CDS_TYPE_URL,
                &slice.version,
                proto::Cluster { name },
            );
        }
    }
    for entry in &slice.service_entries {
        for port in &entry.ports {
            let name = cluster_name(&entry.namespace, &entry.name, port.port);
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                CDS_TYPE_URL,
                &slice.version,
                proto::Cluster { name },
            );
        }
    }
    resources
}

pub fn translate_eds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for service in &slice.services {
        for port in &service.ports {
            let name = cluster_name(&service.namespace, &service.name, port.port);
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                EDS_TYPE_URL,
                &slice.version,
                proto::ClusterLoadAssignment { cluster_name: name },
            );
        }
    }
    for entry in &slice.service_entries {
        for port in &entry.ports {
            let name = cluster_name(&entry.namespace, &entry.name, port.port);
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                EDS_TYPE_URL,
                &slice.version,
                proto::ClusterLoadAssignment { cluster_name: name },
            );
        }
    }
    resources
}

/// Translate operator-defined `MeshSlice.extension_configs` into ECDS resources.
///
/// Each entry becomes a top-level `XdsResource` whose `value` is the encoded
/// `envoy.config.core.v3.TypedExtensionConfig` (i.e., `{name, typed_config:
/// Any{type_url, value}}`). Clients subscribe under `ECDS_TYPE_URL` and
/// dispatch on the inner `typed_config.type_url`.
///
/// The GAP-2K DestinationRule-carrier path emits one entry per DR with the
/// inner `type_url == FERRUM_ECDS_DESTINATION_RULE_TYPE_URL` and the original
/// DR JSON as the inner bytes; the DP xDS consumer recognizes that marker
/// and applies the embedded DR locally.
pub fn translate_ecds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for extension in &slice.extension_configs {
        if extension.name.is_empty() || !seen_names.insert(extension.name.clone()) {
            continue;
        }
        if extension
            .name
            .starts_with(FERRUM_CARRIER_RESOURCE_NAME_PREFIX)
        {
            warn!(
                name = %extension.name,
                type_url = %extension.type_url,
                "Skipping operator ECDS extension config with reserved Ferrum mesh-slice carrier name"
            );
            continue;
        }
        if extension
            .name
            .starts_with(FERRUM_DR_CARRIER_RESOURCE_NAME_PREFIX)
        {
            warn!(
                name = %extension.name,
                type_url = %extension.type_url,
                "Skipping operator ECDS extension config with reserved Ferrum DestinationRule carrier name"
            );
            continue;
        }
        if carrier_resource_name_for_type_url(&extension.type_url).is_some() {
            warn!(
                name = %extension.name,
                type_url = %extension.type_url,
                "Skipping operator ECDS extension config with reserved Ferrum mesh-slice carrier type_url"
            );
            continue;
        }
        let typed_config = proto::Any {
            type_url: extension.type_url.clone(),
            value: extension.value.clone(),
        };
        let message = proto::TypedExtensionConfig {
            name: extension.name.clone(),
            typed_config: Some(typed_config),
        };
        resources.push(resource(
            extension.name.clone(),
            ECDS_TYPE_URL,
            &slice.version,
            message,
        ));
    }
    resources
}

/// Translate full `MeshDestinationRule` objects into Ferrum ECDS DR carriers.
///
/// CDS/EDS can only expose the effective Envoy cluster shape; they cannot
/// reconstruct the original Ferrum/Istio DR object. These reserved ECDS
/// resources carry the full JSON object so the DP recovers native-equivalent
/// DR semantics through the same `FERRUM_ECDS_DESTINATION_RULE_TYPE_URL` path
/// that operator-defined extension configs used historically.
pub fn translate_destination_rule_carriers(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    for dr in &slice.destination_rules {
        match encode_destination_rule_carrier(slice, dr) {
            Ok(resource) => resources.push(resource),
            Err(e) => warn!(
                node_id = %slice.node_id,
                namespace = %dr.namespace,
                name = %dr.name,
                error = %e,
                "Failed to encode DestinationRule ECDS carrier; DR will be missing from xDS slice"
            ),
        }
    }
    resources
}

fn encode_destination_rule_carrier(
    slice: &MeshSlice,
    dr: &MeshDestinationRule,
) -> Result<XdsResource, serde_json::Error> {
    let name = format!(
        "{FERRUM_DR_CARRIER_RESOURCE_NAME_PREFIX}{}/{}",
        dr.namespace, dr.name
    );
    let message = proto::TypedExtensionConfig {
        name: name.clone(),
        typed_config: Some(proto::Any {
            type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
            value: serde_json::to_vec(dr)?,
        }),
    };
    Ok(resource(name, ECDS_TYPE_URL, &slice.version, message))
}

/// Translate the security- and policy-bearing slice fields into Ferrum
/// mesh-slice ECDS carriers (GAP-1a).
///
/// Each non-empty field group becomes one ECDS `XdsResource` whose inner
/// `TypedExtensionConfig.typed_config.type_url` is a Ferrum-specific marker
/// (see [`super::carrier`]) and whose inner `value` is the JSON-serialized
/// field group. The DP's `reverse_translate` recognizes the markers and
/// reassembles the slice, giving xDS deployments the same authz / mTLS / JWT /
/// trust-bundle / ServiceEntry / ProxyConfig / workload behavior as native.
///
/// These ride the same ECDS resource list as the DestinationRule carrier and
/// any operator-defined `extension_configs`; the stable
/// `ferrum-mesh-carrier/<kind>` names avoid colliding with operator names.
/// A carrier whose JSON encode fails (should not happen for the in-repo
/// types) is logged and skipped so one bad field never drops the whole
/// snapshot.
pub fn translate_mesh_slice_carriers(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    for carrier in build_slice_carriers(slice) {
        match encode_slice_carrier(slice, &carrier) {
            Ok(resource) => resources.push(resource),
            Err(e) => warn!(
                node_id = %slice.node_id,
                type_url = carrier.type_url(),
                error = %e,
                "Failed to encode mesh-slice ECDS carrier; field will be missing from xDS slice"
            ),
        }
    }
    resources
}

fn encode_slice_carrier(
    slice: &MeshSlice,
    carrier: &MeshSliceCarrier,
) -> Result<XdsResource, serde_json::Error> {
    let inner_value = carrier.encode_value()?;
    let name = carrier.resource_name();
    let message = proto::TypedExtensionConfig {
        name: name.clone(),
        typed_config: Some(proto::Any {
            type_url: carrier.type_url().to_string(),
            value: inner_value,
        }),
    };
    Ok(resource(name, ECDS_TYPE_URL, &slice.version, message))
}

pub fn translate_sds(slice: &MeshSlice) -> Vec<XdsResource> {
    let Some(bundle_set) = slice.trust_bundles.as_ref() else {
        return Vec::new();
    };
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    let local = bundle_set.local.trust_domain.as_str();
    let local_name = format!("secret/spiffe-bundle/{local}");
    push_unique_resource(
        &mut resources,
        &mut seen_names,
        local_name.clone(),
        SDS_TYPE_URL,
        &slice.version,
        proto::Secret { name: local_name },
    );
    for bundle in &bundle_set.federated {
        let trust_domain = bundle.trust_domain.as_str();
        let name = format!("secret/spiffe-bundle/{trust_domain}");
        push_unique_resource(
            &mut resources,
            &mut seen_names,
            name.clone(),
            SDS_TYPE_URL,
            &slice.version,
            proto::Secret { name },
        );
    }
    resources
}

fn cluster_name(namespace: &str, name: &str, port: u16) -> String {
    format!("cluster/{namespace}/{name}/{port}")
}

fn push_unique_resource<M>(
    resources: &mut Vec<XdsResource>,
    seen_names: &mut HashSet<String>,
    name: String,
    type_url: &str,
    version: &str,
    message: M,
) where
    M: Message,
{
    if seen_names.insert(name.clone()) {
        resources.push(resource(name, type_url, version, message));
    }
}

fn resource<M>(name: String, type_url: &str, version: &str, message: M) -> XdsResource
where
    M: Message,
{
    XdsResource {
        name,
        type_url: type_url.to_string(),
        version: version.to_string(),
        value: message.encode_to_vec(),
    }
}

fn content_version(base_version: &str, resources: &[XdsResource]) -> String {
    let mut hasher = Sha256::new();
    let mut resources: Vec<&XdsResource> = resources.iter().collect();
    resources.sort_by(|left, right| {
        left.type_url
            .cmp(&right.type_url)
            .then_with(|| left.name.cmp(&right.name))
    });
    for resource in resources {
        hasher.update(resource.type_url.as_bytes());
        hasher.update([0]);
        hasher.update(resource.name.as_bytes());
        hasher.update([0]);
        hasher.update(&resource.value);
        hasher.update([0xff]);
    }
    let digest = hex::encode(hasher.finalize());
    format!("{base_version}:{}", &digest[..16])
}

/// Per-resource version: first 8 bytes (16 hex chars) of
/// `SHA-256(type_url || 0x00 || name || 0x00 || value)`. Truncation keeps the
/// version field small on the wire; with ~10k resources per type URL the
/// birthday-bound collision probability is ~3e-12. On a live stream, the
/// delta-response filter pairs this version check with a byte-equality check
/// on `value` against the previous ACKed snapshot before skipping a resource;
/// reconnect `initial_resource_versions` skips by the reported version match.
fn per_resource_version(resource: &XdsResource) -> String {
    let mut hasher = Sha256::new();
    hasher.update(resource.type_url.as_bytes());
    hasher.update([0]);
    hasher.update(resource.name.as_bytes());
    hasher.update([0]);
    hasher.update(&resource.value);
    hex::encode(&hasher.finalize()[..8])
}

/// Translate one Envoy `envoy.service.runtime.v3.Runtime` resource (one RTDS
/// "layer") into a `MeshRuntimeOverlay`.
///
/// This is the single decode site for one RTDS resource. The xDS accumulator
/// sorts all Runtime resources by name before merging them onto
/// `MeshSlice.runtime_overlay`. Fault percentages bind to the candidate
/// request epoch; transformer gates and tracing publish after acceptance.
///
/// Top-level fields in the Runtime's `layer` struct are flattened into
/// `MeshRuntimeOverlay.fields` keyed by field name. Field values are mapped:
///
///   - `number_value`        → `RuntimeValue::Number`
///   - `string_value`        → `RuntimeValue::String`
///   - `bool_value`          → `RuntimeValue::Bool`
///   - struct shaped like an Envoy `FractionalPercent`
///     (`numerator: number, denominator: "HUNDRED"|"TEN_THOUSAND"|"MILLION"`)
///     → `RuntimeValue::FractionalPercent`
///   - other struct / list / null values are silently skipped (RTDS layers
///     don't ship them in practice; avoid inventing placeholder semantics
///     until a consumer needs them)
pub fn translate_rtds_layer(layer: &runtime_proto::Runtime) -> MeshRuntimeOverlay {
    let Some(layer_struct) = layer.layer.as_ref() else {
        return MeshRuntimeOverlay::default();
    };
    let mut overlay = MeshRuntimeOverlay::default();
    for (key, value) in &layer_struct.fields {
        if let Some(runtime_value) = runtime_value_from_proto(value) {
            overlay.fields.insert(key.clone(), runtime_value);
        }
    }
    overlay
}

fn runtime_value_from_proto(value: &runtime_proto::Value) -> Option<RuntimeValue> {
    use runtime_proto::value::Kind;
    match value.kind.as_ref()? {
        Kind::NumberValue(number) => Some(RuntimeValue::Number(*number)),
        Kind::StringValue(string) => Some(RuntimeValue::String(string.clone())),
        Kind::BoolValue(boolean) => Some(RuntimeValue::Bool(*boolean)),
        Kind::StructValue(structure) => fractional_percent_from_struct(structure),
        Kind::NullValue(_) | Kind::ListValue(_) => None,
    }
}

fn fractional_percent_from_struct(structure: &runtime_proto::Struct) -> Option<RuntimeValue> {
    let numerator_value = structure.fields.get("numerator")?;
    let denominator_value = structure.fields.get("denominator")?;

    let numerator = match numerator_value.kind.as_ref()? {
        runtime_proto::value::Kind::NumberValue(number) if number.is_finite() && *number >= 0.0 => {
            *number as u32
        }
        _ => return None,
    };
    let denominator_token = match denominator_value.kind.as_ref()? {
        runtime_proto::value::Kind::StringValue(text) => text.as_str(),
        _ => return None,
    };
    let denominator = match denominator_token {
        "HUNDRED" => FractionalPercentDenominator::Hundred,
        "TEN_THOUSAND" => FractionalPercentDenominator::TenThousand,
        "MILLION" => FractionalPercentDenominator::Million,
        _ => return None,
    };

    // Only accept structs that look like an Envoy FractionalPercent
    // (numerator + denominator and nothing else). Larger structs would have
    // been a different `Value::struct_value` payload; rejecting them keeps
    // the mapping unambiguous and reversible.
    if structure.fields.len() != 2 {
        return None;
    }

    Some(RuntimeValue::FractionalPercent(RuntimeFractionalPercent {
        numerator,
        denominator,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::MAX_XDS_LOG_VALUE_CHARS;
    use super::{
        CDS_TYPE_URL, ECDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, RTDS_TYPE_URL,
        SDS_TYPE_URL, xds_type_url_log_label,
    };

    #[test]
    fn recognized_type_urls_map_to_short_labels() {
        for (type_url, label) in [
            (CDS_TYPE_URL, "cds"),
            (EDS_TYPE_URL, "eds"),
            (LDS_TYPE_URL, "lds"),
            (RDS_TYPE_URL, "rds"),
            (SDS_TYPE_URL, "sds"),
            (ECDS_TYPE_URL, "ecds"),
            (RTDS_TYPE_URL, "rtds"),
        ] {
            assert_eq!(xds_type_url_log_label(type_url), label);
        }
    }

    #[test]
    fn hostile_megabyte_type_url_collapses_to_unknown() {
        let hostile = format!("type.googleapis.com/{}", "x".repeat(1024 * 1024));
        let label = xds_type_url_log_label(&hostile);

        assert_eq!(label, "unknown");
        assert!(label.len() < MAX_XDS_LOG_VALUE_CHARS);
    }
}
