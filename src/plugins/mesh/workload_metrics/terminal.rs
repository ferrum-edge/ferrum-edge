//! Synchronous workload-metrics terminal preparation. No request/header map,
//! plugin handle, or custom future is retained by the returned operation.

use super::*;
use crate::plugins::terminal_preparation::{
    PreparedTerminalOp, ReachedRequestView, TerminalAdmissionError, TerminalBounds,
    TerminalDeclaration, TerminalFacts, TerminalPatch, TerminalRefusal,
};

pub(super) fn declaration() -> TerminalDeclaration {
    TerminalDeclaration::Prepared {
        bounds: TerminalBounds {
            control: 16 * 1024,
            output: 4 * 1024,
            workspace: 0,
        },
        prep_reads: TerminalFacts::METHOD
            .union(TerminalFacts::REQUEST_HEADERS)
            .union(TerminalFacts::IDENTITY)
            .union(TerminalFacts::TELEMETRY),
        prep_writes: TerminalFacts::TELEMETRY,
        trigger_reads: TerminalFacts::NONE,
        cursor_writes: TerminalFacts::RESPONSE_HEADERS,
    }
}

fn refusal() -> TerminalAdmissionError {
    TerminalAdmissionError::new(TerminalRefusal::ControlCapacity, 0, 16 * 1024)
}

struct Metadata<'a> {
    previous: &'a HashMap<String, String>,
    patch: TerminalPatch,
}

impl Metadata<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.patch
            .metadata_get(key)
            .unwrap_or_else(|| self.previous.get(key).map(String::as_str))
    }

    fn set(&mut self, key: &str, value: &str) -> Result<(), TerminalAdmissionError> {
        self.patch.set_metadata(key, value)
    }

    fn remove(&mut self, key: &str) -> Result<(), TerminalAdmissionError> {
        self.patch.remove(key)
    }

    fn sampled(&self) -> bool {
        if let Some(value) = self.get("trace_sampled") {
            return value.eq_ignore_ascii_case("true");
        }
        self.get(TRACEPARENT_HEADER)
            .and_then(traceparent_sampling_decision)
            .unwrap_or(false)
    }
}

impl WorkloadMetrics {
    pub(super) fn prepare_bounded_terminal(
        &self,
        view: &mut ReachedRequestView<'_>,
    ) -> Result<PreparedTerminalOp, TerminalAdmissionError> {
        let restamp = view
            .context
            .metadata
            .contains_key(IGNORED_UDP_SOURCE_SCOPE_METADATA)
            && view
                .context
                .metadata
                .get(MESH_SOURCE_PRINCIPAL)
                .map(String::as_str)
                != view.context.peer_spiffe_id.as_ref().map(SpiffeId::as_str);
        let mut response = view.patch(1)?;
        if restamp {
            let actions = 38usize
                .checked_add(self.custom_tags.len())
                .and_then(|count| count.checked_add(self.custom_header_tags.len() * 2))
                .and_then(|count| count.checked_add(self.tag_override_plans.len()))
                .ok_or_else(refusal)?;
            let patch = view.control_patch(actions)?;
            let mut metadata = Metadata {
                previous: &view.context.metadata,
                patch,
            };
            self.prepare_terminal_restamp(view.context, &mut metadata)?;
            if let Some(traceparent) = metadata.get(TRACEPARENT_HEADER) {
                response.set(TRACEPARENT_HEADER, traceparent, true)?;
            }
            for key in [
                CAPTURED_TRACEPARENT_METADATA,
                CAPTURED_TRACESTATE_METADATA,
                CAPTURED_B3_METADATA,
            ] {
                metadata.remove(key)?;
            }
            let Metadata { patch, .. } = metadata;
            view.apply_metadata(patch)?;
        } else {
            if let Some(traceparent) = view.context.metadata.get(TRACEPARENT_HEADER) {
                response.set(TRACEPARENT_HEADER, traceparent, true)?;
            }
            if view
                .context
                .precommit_response_phase_bound()
                .elapsed_authorization()
                .is_some()
            {
                return Err(TerminalAdmissionError::new(
                    TerminalRefusal::AuthorizationExpired,
                    0,
                    0,
                ));
            }
            view.context.metadata.remove(CAPTURED_TRACEPARENT_METADATA);
            view.context.metadata.remove(CAPTURED_TRACESTATE_METADATA);
            view.context.metadata.remove(CAPTURED_B3_METADATA);
        }
        Ok(PreparedTerminalOp::Fields(response))
    }

    fn prepare_terminal_restamp(
        &self,
        ctx: &RequestContext,
        metadata: &mut Metadata<'_>,
    ) -> Result<(), TerminalAdmissionError> {
        let headers = &ctx.headers;
        if let Some(value) = &self.node_id {
            metadata.set("mesh.node_id", value)?;
        }
        if let Some(value) = &self.topology {
            metadata.set("mesh.topology", value)?;
        }
        if let Some(sampled) = existing_sampling_decision(&ctx.metadata, headers)
            .or_else(|| self.sampling_percentage.map(trace_sampled))
        {
            metadata.set("trace_sampled", if sampled { "true" } else { "false" })?;
        }
        for key in self.custom_header_tags.keys() {
            metadata.remove(key)?;
        }
        for (key, value) in &self.custom_tags {
            metadata.set(key, value)?;
        }
        for (key, header_name) in &self.custom_header_tags {
            if let Some(value) = header_value(headers, header_name)
                && value.len() <= MAX_CUSTOM_TAG_VALUE_BYTES
            {
                metadata.set(key, value)?;
            }
        }
        if let Some(marker) = &self.custom_trace_attributes_marker {
            let existing = ctx
                .metadata
                .get(CUSTOM_TRACE_ATTRIBUTES_METADATA)
                .map_or("", String::as_str);
            metadata.patch.merge_metadata_names(
                CUSTOM_TRACE_ATTRIBUTES_METADATA,
                existing,
                marker,
            )?;
        }
        if let Some(marker) = &self.disabled_metrics_marker {
            metadata.set(MESH_METRICS_DISABLED_METADATA, marker)?;
        }
        for (family, plan) in &self.tag_override_plans {
            metadata.set(family.override_metadata_key(), plan)?;
        }
        let mut needs = MetricTagCelStampNeeds::default();
        for family in MeshMetricFamily::ALL {
            if let Some(plan) = metadata.get(family.override_metadata_key()) {
                needs.merge(
                    split_metric_tag_cel_plan(plan)
                        .map(|(needs, _)| needs)
                        .unwrap_or_else(MetricTagCelStampNeeds::all),
                );
            }
        }
        let has_trace =
            metadata.sampled() || has_valid_traceparent(headers) || has_b3_trace_context(headers);
        if self.trace_context_enabled() && has_trace {
            prepare_trace(metadata, headers)?;
            if let Some(value) = header_value(headers, TRACESTATE_HEADER) {
                metadata.set(TRACESTATE_HEADER, value)?;
            }
        }
        // This path is reached only after authz discarded UDP source scope.
        // resolve_peer_source_identity therefore ignores the baggage principal
        // unconditionally. Do not parse/copy a baggage tree just to discard it.
        let reason = ctx
            .metadata
            .get(IGNORED_UDP_SOURCE_SCOPE_METADATA)
            .ok_or_else(refusal)?;
        metadata.set("mesh.ignored_baggage", reason)?;
        for key in [
            MESH_SOURCE_PRINCIPAL,
            MESH_SOURCE_TRUST_DOMAIN,
            MESH_SOURCE_NAMESPACE,
            MESH_SOURCE_SERVICE_ACCOUNT,
        ] {
            metadata.remove(key)?;
        }
        let security_policy = if ctx.peer_spiffe_id.is_some() || ctx.tls_client_cert_der.is_some() {
            "mutual_tls"
        } else {
            "none"
        };
        metadata.set("mesh.connection_security_policy", security_policy)?;
        metadata.set("mesh.request_protocol", request_protocol(ctx, headers))?;
        if needs.request_host {
            let authority = ctx
                .request_authority
                .as_deref()
                .or_else(|| header_value(headers, "host"));
            if let Some(value) = authority.filter(|value| value.len() <= MAX_METRIC_TAG_VALUE_BYTES)
            {
                metadata.set(METRIC_TAG_CEL_REQUEST_HOST_METADATA, value)?;
            } else {
                metadata.remove(METRIC_TAG_CEL_REQUEST_HOST_METADATA)?;
            }
        } else {
            metadata.remove(METRIC_TAG_CEL_REQUEST_HOST_METADATA)?;
        }
        if needs.request_method
            && !ctx.method.is_empty()
            && ctx.method.len() <= MAX_METRIC_TAG_VALUE_BYTES
        {
            metadata.set(METRIC_TAG_CEL_REQUEST_METHOD_METADATA, &ctx.method)?;
        } else {
            metadata.remove(METRIC_TAG_CEL_REQUEST_METHOD_METADATA)?;
        }
        if needs.destination_port {
            if let Some(port) = mesh_metric_destination_port(ctx) {
                let mut encoded = [0u8; 5];
                let value = decimal_port(port, &mut encoded)?;
                metadata.set(METRIC_TAG_CEL_DESTINATION_PORT_METADATA, value)?;
            } else {
                metadata.remove(METRIC_TAG_CEL_DESTINATION_PORT_METADATA)?;
            }
        } else {
            metadata.remove(METRIC_TAG_CEL_DESTINATION_PORT_METADATA)?;
        }
        if let Some(direction) = ctx.mesh_direction {
            metadata.set(MESH_DIRECTION_METADATA, mesh_direction_str(direction))?;
        }
        match ctx.mesh_direction {
            Some(MeshTrafficDirection::Inbound) => {
                source_identity(metadata, ctx.peer_spiffe_id.as_ref())?;
                remote_source(metadata, ctx.peer_spiffe_id.as_ref())?;
                destination_identity(metadata, self.workload_spiffe_id.as_ref())?;
                if let Some(namespace) = &self.namespace {
                    metadata.set("mesh.destination.namespace", namespace)?;
                }
                let (workload, app, service) = self.local_workload_labels();
                destination_labels(metadata, workload, app, service)?;
            }
            Some(MeshTrafficDirection::Outbound) => {
                if ctx.node_waypoint_pod_uid.is_some()
                    && let Some(identity) = ctx.peer_spiffe_id.as_ref()
                {
                    source_identity(metadata, Some(identity))?;
                    remote_source(metadata, Some(identity))?;
                } else {
                    source_identity(metadata, self.workload_spiffe_id.as_ref())?;
                    self.terminal_local_source(metadata)?;
                }
                proxy_destination(metadata, ctx)?;
            }
            None => {
                source_identity(
                    metadata,
                    ctx.peer_spiffe_id
                        .as_ref()
                        .or(self.workload_spiffe_id.as_ref()),
                )?;
                self.terminal_local_source(metadata)?;
                proxy_destination(metadata, ctx)?;
            }
        }
        Ok(())
    }

    fn terminal_local_source(
        &self,
        metadata: &mut Metadata<'_>,
    ) -> Result<(), TerminalAdmissionError> {
        if let Some(namespace) = &self.namespace {
            metadata.set(MESH_SOURCE_NAMESPACE, namespace)?;
        }
        let (workload, app, service) = self.local_workload_labels();
        metadata.set("mesh.source.workload", workload)?;
        metadata.set("mesh.source.app", app)?;
        metadata.set("mesh.source.service", service)
    }
}

fn source_identity(
    metadata: &mut Metadata<'_>,
    identity: Option<&SpiffeId>,
) -> Result<(), TerminalAdmissionError> {
    if let Some(identity) = identity {
        metadata.set(MESH_SOURCE_PRINCIPAL, identity.as_str())?;
        metadata.set(MESH_SOURCE_TRUST_DOMAIN, identity.trust_domain().as_str())?;
        if let Some(namespace) = identity.namespace() {
            metadata.set(MESH_SOURCE_NAMESPACE, namespace)?;
        }
        if let Some(service_account) = identity.service_account() {
            metadata.set(MESH_SOURCE_SERVICE_ACCOUNT, service_account)?;
        }
    }
    Ok(())
}

fn destination_identity(
    metadata: &mut Metadata<'_>,
    identity: Option<&SpiffeId>,
) -> Result<(), TerminalAdmissionError> {
    if let Some(identity) = identity {
        metadata.set("mesh.destination.principal", identity.as_str())?;
        if let Some(namespace) = identity.namespace() {
            metadata.set("mesh.destination.namespace", namespace)?;
        }
    }
    Ok(())
}

fn remote_source(
    metadata: &mut Metadata<'_>,
    identity: Option<&SpiffeId>,
) -> Result<(), TerminalAdmissionError> {
    let workload = identity
        .and_then(SpiffeId::service_account)
        .unwrap_or("unknown");
    metadata.set("mesh.source.workload", workload)?;
    metadata.set("mesh.source.app", workload)?;
    metadata.set("mesh.source.service", workload)
}

fn destination_labels(
    metadata: &mut Metadata<'_>,
    workload: &str,
    app: &str,
    service: &str,
) -> Result<(), TerminalAdmissionError> {
    metadata.set("mesh.destination.workload", workload)?;
    metadata.set("mesh.destination.app", app)?;
    metadata.set("mesh.destination.service", service)
}

fn proxy_destination(
    metadata: &mut Metadata<'_>,
    ctx: &RequestContext,
) -> Result<(), TerminalAdmissionError> {
    if let Some(proxy) = &ctx.matched_proxy {
        let destination = proxy.name.as_deref().unwrap_or(&proxy.id);
        metadata.set("mesh.destination.namespace", &proxy.namespace)?;
        destination_labels(metadata, destination, destination, destination)?;
    }
    Ok(())
}

fn decimal_port(port: u16, encoded: &mut [u8; 5]) -> Result<&str, TerminalAdmissionError> {
    let mut value = port;
    let mut offset = encoded.len();
    loop {
        offset -= 1;
        encoded[offset] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    std::str::from_utf8(&encoded[offset..]).map_err(|_| refusal())
}

fn fixed_text(value: &[u8]) -> Result<&str, TerminalAdmissionError> {
    std::str::from_utf8(value).map_err(|_| refusal())
}

// Callers supply validated 32/16-byte IDs or the fixed encoder's arrays.
fn traceparent(trace: &str, span: &str, sampled: bool) -> [u8; 55] {
    let mut value = *b"00-00000000000000000000000000000000-0000000000000000-00";
    value[3..35].copy_from_slice(trace.as_bytes());
    value[36..52].copy_from_slice(span.as_bytes());
    value[54] = if sampled { b'1' } else { b'0' };
    value
}

fn prepare_trace(
    metadata: &mut Metadata<'_>,
    headers: &HashMap<String, String>,
) -> Result<(), TerminalAdmissionError> {
    if !has_valid_traceparent(headers)
        && metadata.get(TRACEPARENT_HEADER).is_none()
        && let Some(b3) = borrowed_b3_context(headers)
    {
        let mut trace = [b'0'; 32];
        let offset = 32 - b3.trace_id.len();
        for (target, source) in trace[offset..].iter_mut().zip(b3.trace_id.bytes()) {
            *target = source.to_ascii_lowercase();
        }
        let mut parent = [b'0'; 16];
        for (target, source) in parent.iter_mut().zip(b3.span_id.bytes()) {
            *target = source.to_ascii_lowercase();
        }
        let span = OtelTracing::generate_span_id_fixed()?;
        let traceparent = traceparent(
            fixed_text(&trace)?,
            fixed_text(&span)?,
            metadata.sampled(),
        );
        metadata.set("trace_id", fixed_text(&trace)?)?;
        metadata.set("parent_span_id", fixed_text(&parent)?)?;
        metadata.set("span_id", fixed_text(&span)?)?;
        metadata.set(TRACEPARENT_HEADER, fixed_text(&traceparent)?)?;
    }
    if metadata.get("trace_id").is_some() && metadata.get("span_id").is_some() {
        if metadata.get("trace_sampled").is_none() {
            let sampled = metadata
                .get(TRACEPARENT_HEADER)
                .and_then(traceparent_sampling_decision)
                .unwrap_or(true);
            metadata.set("trace_sampled", if sampled { "true" } else { "false" })?;
        }
        return Ok(());
    }
    if let Some(parsed) =
        header_value(headers, TRACEPARENT_HEADER).and_then(OtelTracing::parse_traceparent)
    {
        let sampled = u8::from_str_radix(parsed.flags, 16).map_err(|_| refusal())? & 1 != 0;
        let span = OtelTracing::generate_span_id_fixed()?;
        let parent = traceparent(parsed.trace_id, fixed_text(&span)?, sampled);
        metadata.set("trace_id", parsed.trace_id)?;
        metadata.set("parent_span_id", parsed.parent_span_id)?;
        metadata.set("span_id", fixed_text(&span)?)?;
        metadata.set("trace_sampled", if sampled { "true" } else { "false" })?;
        metadata.set(TRACEPARENT_HEADER, fixed_text(&parent)?)?;
    } else {
        let trace = OtelTracing::generate_trace_id_fixed()?;
        let span = OtelTracing::generate_span_id_fixed()?;
        let parent = traceparent(fixed_text(&trace)?, fixed_text(&span)?, true);
        metadata.set("trace_id", fixed_text(&trace)?)?;
        metadata.set("span_id", fixed_text(&span)?)?;
        metadata.set("trace_sampled", "true")?;
        metadata.set(TRACEPARENT_HEADER, fixed_text(&parent)?)?;
    }
    Ok(())
}
