//! Gateway API `BackendTLSPolicy` watch/index/apply helpers.
//!
//! Policies attach to same-namespace Services and overlay Ferrum upstream
//! `backend_tls_*` fields (SNI, CA trust, SAN allow-list) for Service-backed
//! HTTPRoute/GRPCRoute backends. Invalid or unrepresentable policies fail
//! closed for backends that target the affected Service.
//!
//! Two boundaries are load-bearing and deliberately explicit here:
//!
//! * `wellKnownCACertificates: System` projects the first-class
//!   [`SYSTEM_TRUST_ROOTS_SOURCE`] sentinel, never `None`. `None` means "no
//!   backend CA configured", which Ferrum's documented trust chain resolves to
//!   the cluster-global `FERRUM_TLS_CA_BUNDLE_PATH` — so a cluster-wide private
//!   CA would silently replace the public trust anchors the policy asked for.
//! * A route whose backend set MIXES policy-covered and uncovered targets fails
//!   closed. Ferrum encodes one backend scheme and one TLS identity per
//!   `Upstream`, so applying the overlay to the combined upstream would
//!   originate TLS (with the covered Service's SNI and trust) to a Service that
//!   no policy covers.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::config::types::{
    Upstream, validate_backend_tls_san_allow_list_entry, validate_backend_tls_sni,
};
use crate::tls::source::SYSTEM_TRUST_ROOTS_SOURCE;

use super::gateway_api::compare_creation_timestamps;
use super::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiBackendTlsPolicyStatus, K8sAccumulator, K8sObject,
    K8sResourceKey, K8sTranslateError, MAX_INDEXED_SERVICE_PORTS, RouteBackend, ServicePortIndex,
};

/// Maximum admitted `caCertificateRefs` entries. Bounds hostile input before
/// any ConfigMap/Secret resolution work.
const MAX_CA_CERTIFICATE_REFS: usize = 8;
/// Maximum admitted `subjectAltNames` entries.
///
/// Bounds hostile input well inside Ferrum's own `backend_tls_san_allow_list`
/// ceiling (`MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES`, 256), which is the limit a
/// projected overlay is ultimately validated against. The tighter number here is
/// the Gateway API CRD's own structural ceiling on
/// `spec.validation.subjectAltNames`, so a spec exceeding it could only reach
/// Ferrum from a source the API server never validated — which is exactly the
/// input this bound exists to refuse.
const MAX_SUBJECT_ALT_NAMES: usize = 5;
/// Gateway API v1.5.1 technically admits up to 16 targetRefs but explicitly
/// recommends that implementations support one until multi-target conflict and
/// status semantics are defined. Ferrum follows that fail-closed guidance.
const MAX_SUPPORTED_TARGET_REFS: usize = 1;
/// Structural CRD ceiling; also bounds raw/untrusted translation input.
const MAX_ADMITTED_TARGET_REFS: usize = 16;

/// Gateway API v1.5.1 `PolicyStatus.ancestors` is a hard MaxItems=16 list-map.
///
/// The spec is explicit that when the list is full an implementation MUST NOT
/// add another entry. This limit is only an output constraint for the status
/// writer; status owned by other controllers must not influence translation.
pub(crate) const MAX_POLICY_ANCESTORS: usize = 16;

/// Ferrum's desired `status.ancestors` set for one `BackendTLSPolicy`: the core
/// Services named by `spec.targetRefs`.
///
/// The ancestor is the **target Service**, not the managed Gateways that route
/// to it, and that is a statement about Ferrum's translation rather than a
/// convenience:
///
/// * a policy carries exactly one supported `targetRefs` entry
///   (`MAX_SUPPORTED_TARGET_REFS`), always a same-namespace core Service;
/// * the overlay decision (`lookup_for_service` → `resolve_backends_tls_policy`
///   → `apply_to_upstream`) consumes only the policy record and the rule's
///   backend Service identities — no Gateway is an input anywhere on that path;
/// * the `Accepted` / `ResolvedRefs` verdict (`record_status`) is computed
///   from the parse outcome, target resolution, Service existence, and
///   snapshot-wide precedence — again with no Gateway input.
///
/// So the verdict provably cannot vary per Gateway. A per-Gateway ancestor list
/// would be N byte-identical copies of one verdict whose length is driven by an
/// unrelated resource count, which is what made the 16-entry ceiling reachable
/// (and silently truncated) in the first place. The Service ancestor is exact,
/// and bounds Ferrum's own contribution at one entry by construction.
///
/// This reads the raw spec rather than the translated targets deliberately: a
/// rejected targetRef (cross-namespace, malformed) must still get a visible
/// condition on the resource the operator named. It is bounded by
/// `MAX_ADMITTED_TARGET_REFS` so a hostile spec cannot grow the set.
pub(crate) fn policy_status_ancestor_services(object: &K8sObject) -> BTreeSet<(String, String)> {
    object
        .spec
        .get("targetRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_ADMITTED_TARGET_REFS)
        .filter(|target_ref| {
            let group = target_ref
                .get("group")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let kind = target_ref
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("Service");
            group.is_empty() && kind == "Service"
        })
        .filter_map(|target_ref| {
            let name = target_ref
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())?;
            let namespace = target_ref
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|namespace| !namespace.is_empty())
                .unwrap_or(object.metadata.namespace.as_str());
            Some((namespace.to_string(), name.to_string()))
        })
        .collect()
}

/// Remaining `status.ancestors` capacity for Ferrum on a live policy status.
///
/// Only *other* controllers' entries consume capacity: Ferrum replaces its own
/// entries on every write, so counting them would oscillate between reconciles.
pub(crate) fn policy_status_ancestor_capacity(status: &Value) -> usize {
    let third_party = status
        .get("ancestors")
        .and_then(Value::as_array)
        .map_or(0, |ancestors| {
            ancestors
                .iter()
                .filter(|ancestor| {
                    ancestor.get("controllerName").and_then(Value::as_str)
                        != Some(FERRUM_GATEWAY_CONTROLLER_NAME)
                })
                .count()
        });
    MAX_POLICY_ANCESTORS.saturating_sub(third_party)
}

/// Resolved BackendTLSPolicy overlay projected onto an Upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BackendTlsPolicyOverlay {
    pub hostname: String,
    /// Configured backend CA source. Either resolved ConfigMap/Secret material
    /// or [`SYSTEM_TRUST_ROOTS_SOURCE`] for `wellKnownCACertificates: System`.
    /// Never `None` — see the module docs.
    pub ca_bundle_source: String,
    pub subject_alt_names: Vec<String>,
}

/// Why a BackendTLSPolicy could not be represented, classified against the
/// Gateway API `PolicyCondition` reason vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackendTlsPolicyRejection {
    /// The policy itself is malformed or unrepresentable
    /// (`Accepted=False`, `reason: Invalid`).
    Invalid,
    /// The policy names a target that does not exist — today, a
    /// `targetRefs[].sectionName` that names no port on the target Service
    /// (`Accepted=False`, `reason: TargetNotFound`).
    ///
    /// Gateway API v1.5.1 `LocalPolicyTargetReferenceWithSectionName`: "If a
    /// SectionName is specified, but does not exist on the targeted object,
    /// the Policy must fail to attach, and the policy implementation should
    /// record a `ResolvedRefs` or similar Condition in the Policy's status."
    /// `TargetNotFound` is the vocabulary's "policy is attached to an invalid
    /// target resource" reason and is field-specific here; `ResolvedRefs` on
    /// BackendTLSPolicy is reserved for `caCertificateRefs` outcomes, which
    /// resolved fine, so overloading it would misreport them.
    TargetNotFound,
    /// A `caCertificateRefs` entry names a ConfigMap/Secret that is missing or
    /// carries no usable `ca.crt` PEM bundle
    /// (`ResolvedRefs=False`, `reason: InvalidCACertificateRef`).
    InvalidCaCertificateRef,
    /// A `caCertificateRefs` entry names an unsupported group/kind
    /// (`ResolvedRefs=False`, `reason: InvalidKind`).
    InvalidKind,
    /// A cross-namespace reference Ferrum does not permit
    /// (`ResolvedRefs=False`, `reason: RefNotPermitted`).
    RefNotPermitted,
}

impl BackendTlsPolicyRejection {
    /// Whether this rejection is about a *reference* (surfaces on
    /// `ResolvedRefs`) rather than the policy body (surfaces on `Accepted`).
    fn is_reference_failure(self) -> bool {
        !matches!(self, Self::Invalid | Self::TargetNotFound)
    }

    fn resolved_refs_reason(self) -> &'static str {
        match self {
            Self::Invalid | Self::TargetNotFound => "ResolvedRefs",
            Self::InvalidCaCertificateRef => "InvalidCACertificateRef",
            Self::InvalidKind => "InvalidKind",
            Self::RefNotPermitted => "RefNotPermitted",
        }
    }
}

/// A classified parse failure: the condition reason plus a sanitized,
/// field-specific message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BackendTlsPolicyError {
    kind: BackendTlsPolicyRejection,
    message: String,
}

impl BackendTlsPolicyError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: BackendTlsPolicyRejection::Invalid,
            message: message.into(),
        }
    }

    fn of(kind: BackendTlsPolicyRejection, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendTlsPolicyRecord {
    Valid(BackendTlsPolicyOverlay),
    Invalid(BackendTlsPolicyError),
}

/// Which Service ports one indexed policy governs, resolved once against the
/// observed Service rather than re-derived per backend lookup.
///
/// Gateway API v1.5.1 GEP-1897: "BackendTLSPolicy applies only to TCP traffic."
/// The transport of the target port is therefore part of the attachment
/// decision, not an afterthought — which is why this is resolved at collect
/// time, where the complete Service index exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyPortScope {
    /// Governs every port of the target Service.
    ///
    /// Also the scope used to fail a whole Service closed when the target is
    /// unrepresentable, so a rejection cannot be narrowed away by a port match.
    AllPorts,
    /// Governs only the target Service's **TCP** ports.
    ///
    /// GEP-1897: "If the policy attaches to a mix of TCP and UDP ports,
    /// implementations SHOULD include a warning in the `Accepted` condition
    /// message (`ancestors.conditions`); the policy will only be effective for
    /// the TCP ports."
    ///
    /// Named for what it *admits* (TCP), not for what it excludes: the excluded
    /// set is every non-TCP transport — UDP, SCTP, and any unrecognized
    /// `protocol` — not UDP alone.
    TcpPortsOnly,
    /// Governs exactly this Service port number (a resolved `sectionName`).
    Port(u16),
    /// Governs nothing: the `sectionName` names no port on the Service, so the
    /// policy "must fail to attach" and must not leak onto sibling ports.
    NoPorts,
    /// The Service was never observed, so its ports are unknown. Preserves the
    /// pre-existing behaviour: a Service-wide policy still matches, a
    /// section-scoped one does not.
    ServiceNotObserved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedBackendTlsPolicy {
    policy_namespace: String,
    policy_name: String,
    /// Optional Service port name (`targetRefs[].sectionName`).
    section_name: Option<String>,
    /// Ports this policy governs, resolved against the target Service.
    port_scope: PolicyPortScope,
    creation_timestamp: Option<DateTime<Utc>>,
    record: BackendTlsPolicyRecord,
}

impl IndexedBackendTlsPolicy {
    /// Whether this policy governs the Service port a backend selected.
    ///
    /// `service_port` is `None` when the backend never resolved to a numeric
    /// Service port. A port-scoped policy cannot claim such a backend; a
    /// Service-wide one still does, exactly as before this port model existed.
    fn governs(&self, index: Option<&ServicePortIndex>, service_port: Option<u16>) -> bool {
        match self.port_scope {
            PolicyPortScope::AllPorts => true,
            PolicyPortScope::TcpPortsOnly => match (index, service_port) {
                // A port present in a COMPLETE index must be TCP. UDP, SCTP,
                // and any unrecognized `protocol` are all excluded here — the
                // predicate is "is TCP", not "is not UDP".
                (Some(index), Some(port)) => index
                    .port(port)
                    .is_none_or(|entry| entry.transport.is_tcp()),
                // The backend did not resolve to any port on this Service (the
                // index is complete, so the port genuinely is not a Service
                // port). Keep the Service-wide answer rather than silently
                // dropping this backend to plaintext: Ferrum only reaches here
                // for an HTTP-family backend, which is TCP by construction.
                _ => true,
            },
            PolicyPortScope::Port(scoped) => service_port == Some(scoped),
            PolicyPortScope::NoPorts => false,
            PolicyPortScope::ServiceNotObserved => self.section_name.is_none(),
        }
    }
}

/// Outcome of resolving one targetRef's Service-port scope.
struct TargetPortScope {
    scope: PolicyPortScope,
    /// Set when the Gateway API contract requires `Accepted=False`.
    rejection: Option<BackendTlsPolicyError>,
    /// Set when the contract asks for an `Accepted` condition *warning* while
    /// still accepting the policy (the mixed TCP/UDP SHOULD).
    warning: Option<String>,
}

/// Resolve a targetRef against the observed Service's ports.
///
/// Implements the Gateway API v1.5.1 GEP-1897 transport contract:
///
/// * "If a policy explicitly attaches to a UDP port of a Service (that is, the
///   `targetRef` has a `sectionName` specifying a single port or the service
///   has only 1 port), the `Accepted: False` Condition with `Reason: Invalid`
///   MUST be set."
/// * "If the policy attaches to a mix of TCP and UDP ports, implementations
///   SHOULD include a warning in the `Accepted` condition message
///   (`ancestors.conditions`); the policy will only be effective for the TCP
///   ports."
///
/// Both clauses are applied as the **TCP-eligibility** rule they express, not as
/// a UDP-exclusion rule. GEP-1897 names UDP because UDP is the transport a
/// Gateway API Service is otherwise likely to carry, but the normative statement
/// it is drawn from is that BackendTLSPolicy configures TLS for *TCP* traffic.
/// So a port is eligible only when its transport is proven `TCP`; `SCTP` and any
/// unrecognized `protocol` value are treated exactly like `UDP`. Reading the
/// clauses literally as "not UDP" is what let an `SCTP` port be accepted and
/// have backend TLS projected onto it — an implementation cannot start a TLS
/// handshake on an SCTP or unknown-transport port, so accepting one is a
/// misreport, and projecting TLS onto it is worse.
///
/// A Service-wide policy on a Service with more than one port and *no* TCP port
/// is not literally either clause. Ferrum rejects it the same way as the
/// single-port case: there is no TCP port for the policy to "only be effective
/// for", so the mixed clause degenerates to "effective nowhere", and reporting
/// `Accepted=True` for a policy that governs nothing is exactly the misreport
/// this resolver exists to remove.
fn resolve_target_port_scope(
    acc: &K8sAccumulator,
    service_namespace: &str,
    service_name: &str,
    section_name: Option<&str>,
) -> TargetPortScope {
    let Some(index) = acc.service_port_index(service_namespace, service_name) else {
        return TargetPortScope {
            scope: PolicyPortScope::ServiceNotObserved,
            rejection: None,
            warning: None,
        };
    };

    if index.truncated {
        // An incomplete port view cannot prove the target port IS TCP.
        // Fail the whole Service closed rather than assume TCP.
        return TargetPortScope {
            scope: PolicyPortScope::AllPorts,
            rejection: Some(BackendTlsPolicyError::invalid(format!(
                "Service {service_namespace:?}/{service_name:?} declares more than \
                 {MAX_INDEXED_SERVICE_PORTS} ports, so Ferrum cannot determine the transport of \
                 the targeted port"
            ))),
            warning: None,
        };
    }

    if let Some(section_name) = section_name {
        let Some(entry) = index.named(section_name) else {
            return TargetPortScope {
                scope: PolicyPortScope::NoPorts,
                rejection: Some(BackendTlsPolicyError::of(
                    BackendTlsPolicyRejection::TargetNotFound,
                    format!(
                        "spec.targetRefs[].sectionName {section_name:?} does not name a port on \
                         Service {service_namespace:?}/{service_name:?}, so this \
                         BackendTLSPolicy attaches to nothing"
                    ),
                )),
                warning: None,
            };
        };
        // Section-scoped: the named port must be proven TCP. UDP, SCTP, and an
        // unrecognized `protocol` are all `Accepted=False`/`Invalid` — a
        // section-scoped policy governs exactly this one port, so an ineligible
        // transport means the policy can never be effective.
        let rejection = (!entry.transport.is_tcp()).then(|| {
            BackendTlsPolicyError::invalid(format!(
                "spec.targetRefs[].sectionName {section_name:?} names port \"{}\" on Service \
                 {service_namespace:?}/{service_name:?}, whose protocol is {:?}; \
                 BackendTLSPolicy applies only to TCP traffic",
                entry.port,
                entry.transport.label()
            ))
        });
        return TargetPortScope {
            // Scope stays `Port` so a rejection cannot be narrowed away and a
            // sibling TCP port never inherits this policy.
            scope: PolicyPortScope::Port(entry.port),
            rejection,
            warning: None,
        };
    }

    // Service-wide. Count TCP ports rather than non-TCP ones so the "all
    // eligible" test is an equality against the port count: an empty `ports`
    // list then lands on `AllPorts` (nothing to reject) through the same arm.
    let tcp_ports = index
        .ports
        .iter()
        .filter(|entry| entry.transport.is_tcp())
        .count();
    if tcp_ports == index.ports.len() {
        return TargetPortScope {
            scope: PolicyPortScope::AllPorts,
            rejection: None,
            warning: None,
        };
    }
    if tcp_ports == 0 {
        return TargetPortScope {
            // `AllPorts` is the REJECTION scope: it fails the whole Service
            // closed so no port match can narrow the rejection away.
            scope: PolicyPortScope::AllPorts,
            rejection: Some(BackendTlsPolicyError::invalid(format!(
                "Service {service_namespace:?}/{service_name:?} declares no TCP ports ({} \
                 non-TCP port(s)); BackendTLSPolicy applies only to TCP traffic",
                index.ports.len()
            ))),
            warning: None,
        };
    }
    TargetPortScope {
        scope: PolicyPortScope::TcpPortsOnly,
        rejection: None,
        warning: Some(format!(
            "Service {service_namespace:?}/{service_name:?} mixes TCP and non-TCP ports; this \
             BackendTLSPolicy is effective only for its TCP ports"
        )),
    }
}

#[derive(Debug, Default)]
pub(super) struct BackendTlsPolicyIndex {
    /// `(service_namespace, service_name)` → candidate policies.
    by_service: HashMap<(String, String), Vec<IndexedBackendTlsPolicy>>,
}

impl BackendTlsPolicyIndex {
    fn insert(
        &mut self,
        service_namespace: String,
        service_name: String,
        entry: IndexedBackendTlsPolicy,
    ) {
        self.by_service
            .entry((service_namespace, service_name))
            .or_default()
            .push(entry);
    }

    /// Policies that lose Gateway API precedence everywhere they could apply.
    ///
    /// Runtime lookup already selects the oldest policy, then the lexical
    /// `{namespace}/{name}` winner. Status must make the same decision after the
    /// complete snapshot is indexed; deciding while collecting would be input
    /// order dependent because an older policy may appear later in the list.
    /// A Service-wide policy is also a loser when section-scoped policies own
    /// every eligible port, but stays accepted if it still wins any one port.
    pub(super) fn conflicted_policy_ids(
        &self,
        service_port_specs: &HashMap<String, HashMap<String, ServicePortIndex>>,
    ) -> HashSet<(String, String)> {
        let mut conflicted = HashSet::new();
        for ((service_namespace, service_name), entries) in &self.by_service {
            for candidate in entries {
                let candidate_id = (&candidate.policy_namespace, &candidate.policy_name);
                let loses = entries.iter().any(|other| {
                    let other_id = (&other.policy_namespace, &other.policy_name);
                    other_id != candidate_id
                        && other.section_name == candidate.section_name
                        && compare_policy_precedence(other, candidate) == Ordering::Less
                });
                if loses {
                    conflicted.insert((
                        candidate.policy_namespace.clone(),
                        candidate.policy_name.clone(),
                    ));
                    continue;
                }

                // A Service-wide policy is also fully conflicted when a more
                // specific section policy wins on EVERY Service port the
                // wildcard could govern. Runtime lookup already prefers those
                // section policies; reporting Accepted=True for the wildcard
                // after it has no effective port would make status disagree
                // with the data plane. Keep it accepted when it still wins on
                // even one eligible port.
                let Some(port_index) = service_port_specs
                    .get(service_namespace)
                    .and_then(|services| services.get(service_name))
                else {
                    continue;
                };
                let mut governs_any_port = false;
                let mut wins_any_port = false;
                for port in &port_index.ports {
                    if !candidate.governs(Some(port_index), Some(port.port)) {
                        continue;
                    }
                    governs_any_port = true;
                    let winner = entries
                        .iter()
                        .filter(|entry| entry.governs(Some(port_index), Some(port.port)))
                        .min_by(|left, right| compare_policy_for_lookup(left, right));
                    if winner.is_some_and(|winner| {
                        winner.policy_namespace == candidate.policy_namespace
                            && winner.policy_name == candidate.policy_name
                    }) {
                        wins_any_port = true;
                        break;
                    }
                }
                if governs_any_port && !wins_any_port {
                    conflicted.insert((
                        candidate.policy_namespace.clone(),
                        candidate.policy_name.clone(),
                    ));
                }
            }
        }
        conflicted
    }
}

/// Collect one BackendTLSPolicy into the accumulator index.
///
/// Structural and validation failures are recorded as warnings and indexed as
/// `Invalid` (or skipped) so a single bad policy cannot abort the whole
/// Kubernetes snapshot translation. Every outcome also records a status
/// projection so the Gateway API status writer can report it on
/// `status.ancestors` without retranslating.
pub(super) fn collect(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    let Some(target_refs) = object.spec.get("targetRefs").and_then(Value::as_array) else {
        let message = "spec.targetRefs is required".to_string();
        acc.warnings.push(format!(
            "Gateway API BackendTLSPolicy {:?}/{:?} is invalid: {message}",
            object.metadata.namespace, object.metadata.name
        ));
        record_status(
            acc,
            object,
            Err(&BackendTlsPolicyError::invalid(message)),
            None,
            None,
            &[],
            false,
        );
        return Ok(());
    };
    if target_refs.is_empty() {
        let message = "spec.targetRefs must contain at least one entry".to_string();
        acc.warnings.push(format!(
            "Gateway API BackendTLSPolicy {:?}/{:?} is invalid: {message}",
            object.metadata.namespace, object.metadata.name
        ));
        record_status(
            acc,
            object,
            Err(&BackendTlsPolicyError::invalid(message)),
            None,
            None,
            &[],
            false,
        );
        return Ok(());
    }
    let parsed = if target_refs.len() > MAX_SUPPORTED_TARGET_REFS {
        Err(BackendTlsPolicyError::invalid(format!(
            "spec.targetRefs must contain exactly one entry (received {}); Ferrum follows Gateway API v1.5.1 guidance and does not support multi-target BackendTLSPolicy status",
            target_refs
                .len()
                .min(MAX_ADMITTED_TARGET_REFS.saturating_add(1))
        )))
    } else {
        match object.spec.get("options") {
            Some(Value::Object(options)) if options.is_empty() => {
                parse_policy_validation(acc, object)
            }
            Some(Value::Object(_)) => Err(BackendTlsPolicyError::invalid(
                "spec.options is not supported by Ferrum and must be empty",
            )),
            Some(_) => Err(BackendTlsPolicyError::invalid(
                "spec.options must be an object when present",
            )),
            None => parse_policy_validation(acc, object),
        }
    };
    if let Err(error) = &parsed {
        acc.warnings.push(format!(
            "Gateway API BackendTLSPolicy {:?}/{:?} is invalid: {}",
            object.metadata.namespace, object.metadata.name, error.message
        ));
    }
    let record = match &parsed {
        Ok(overlay) => BackendTlsPolicyRecord::Valid(overlay.clone()),
        Err(error) => BackendTlsPolicyRecord::Invalid(error.clone()),
    };

    let creation_timestamp = object
        .metadata
        .creation_timestamp
        .as_deref()
        .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
        .map(|ts| ts.with_timezone(&Utc));

    let mut target_services: Vec<(String, String)> = Vec::new();
    let mut any_target_resolved = false;
    let mut target_error: Option<BackendTlsPolicyError> = None;
    let mut accepted_warning: Option<String> = None;
    for target_ref in target_refs.iter().take(MAX_ADMITTED_TARGET_REFS) {
        match parse_service_target_ref(object, target_ref) {
            Ok((service_name, section_name)) => {
                any_target_resolved = true;
                let namespace = object.metadata.namespace.clone();
                // The Service port view is complete by now: Services are
                // collected in the pass before BackendTLSPolicy, so the
                // transport of the targeted port is decided once, here, rather
                // than re-derived per backend lookup.
                let port_scope = resolve_target_port_scope(
                    acc,
                    &namespace,
                    &service_name,
                    section_name.as_deref(),
                );
                if let Some(warning) = &port_scope.warning {
                    acc.warnings.push(format!(
                        "Gateway API BackendTLSPolicy {:?}/{:?}: {warning}",
                        object.metadata.namespace, object.metadata.name
                    ));
                    if accepted_warning.is_none() {
                        accepted_warning = Some(warning.clone());
                    }
                }
                if let Some(error) = &port_scope.rejection {
                    acc.warnings.push(format!(
                        "Gateway API BackendTLSPolicy {:?}/{:?} is invalid: {}",
                        object.metadata.namespace, object.metadata.name, error.message
                    ));
                    if target_error.is_none() {
                        target_error = Some(error.clone());
                    }
                }
                // A port-scope rejection overrides an otherwise valid body: the
                // policy must not govern the port it named.
                let record = match &port_scope.rejection {
                    Some(error) => BackendTlsPolicyRecord::Invalid(error.clone()),
                    None => record.clone(),
                };
                if !target_services
                    .iter()
                    .any(|(ns, name)| ns == &namespace && name == &service_name)
                {
                    target_services.push((namespace.clone(), service_name.clone()));
                }
                acc.backend_tls_policies.insert(
                    namespace.clone(),
                    service_name,
                    IndexedBackendTlsPolicy {
                        policy_namespace: namespace,
                        policy_name: object.metadata.name.clone(),
                        section_name,
                        port_scope: port_scope.scope,
                        creation_timestamp,
                        record,
                    },
                );
            }
            Err(error) => {
                acc.warnings.push(format!(
                    "Gateway API BackendTLSPolicy {:?}/{:?} targetRef skipped: {}",
                    object.metadata.namespace, object.metadata.name, error.message
                ));
                if target_error.is_none() {
                    target_error = Some(error.clone());
                }
                // When the core Service identity is still unambiguous, index a
                // fail-closed record even though an ancillary targetRef field
                // (for example sectionName) was malformed. Silently skipping
                // the policy would send plaintext to the very Service whose TLS
                // posture the operator attempted to constrain.
                if let Some((service_name, section_name)) =
                    fail_closed_service_target(object, target_ref)
                {
                    let namespace = object.metadata.namespace.clone();
                    if !target_services
                        .iter()
                        .any(|(ns, name)| ns == &namespace && name == &service_name)
                    {
                        target_services.push((namespace.clone(), service_name.clone()));
                    }
                    acc.backend_tls_policies.insert(
                        namespace.clone(),
                        service_name,
                        IndexedBackendTlsPolicy {
                            policy_namespace: namespace,
                            policy_name: object.metadata.name.clone(),
                            section_name,
                            // Service-wide, matching the recovery rule above:
                            // the only errors that leave the core Service
                            // identity intact are sectionName errors, and those
                            // surrender the section, so there is no port to
                            // narrow to and narrowing would require guessing.
                            port_scope: PolicyPortScope::AllPorts,
                            creation_timestamp,
                            record: BackendTlsPolicyRecord::Invalid(error),
                        },
                    );
                }
            }
        }
    }

    record_status(
        acc,
        object,
        parsed.as_ref().map(|_| ()),
        target_error.as_ref(),
        accepted_warning.as_deref(),
        &target_services,
        any_target_resolved,
    );
    Ok(())
}

/// Recover only the unambiguous core-Service portion of a malformed targetRef
/// so the affected backend can fail closed. Invalid group/kind/namespace/name
/// shapes return `None`; a malformed sectionName deliberately becomes
/// Service-wide because narrowing it would require guessing.
fn fail_closed_service_target(
    object: &K8sObject,
    target_ref: &Value,
) -> Option<(String, Option<String>)> {
    let group = match target_ref.get("group") {
        None => "",
        Some(Value::String(group)) => group,
        Some(_) => return None,
    };
    let kind = match target_ref.get("kind") {
        None => "Service",
        Some(Value::String(kind)) => kind,
        Some(_) => return None,
    };
    if !group.is_empty() || kind != "Service" {
        return None;
    }
    let namespace = match target_ref.get("namespace") {
        None => object.metadata.namespace.as_str(),
        Some(Value::String(namespace)) => namespace,
        Some(_) => return None,
    };
    if namespace != object.metadata.namespace {
        return None;
    }
    let name = target_ref
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())?;
    let section_name = target_ref
        .get("sectionName")
        .and_then(Value::as_str)
        .filter(|section| !section.is_empty())
        .map(str::to_string);
    Some((name.to_string(), section_name))
}

/// Project one policy's translation outcome into the status the Gateway API
/// status writer publishes on `status.ancestors[].conditions`.
fn record_status(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    parsed: Result<(), &BackendTlsPolicyError>,
    target_error: Option<&BackendTlsPolicyError>,
    accepted_warning: Option<&str>,
    target_services: &[(String, String)],
    any_target_resolved: bool,
) {
    let targets_exist = target_services
        .iter()
        .any(|(namespace, name)| acc.service_exists(namespace, name));
    let body_error = parsed.err();
    let accepted_error = body_error.or(target_error);
    let reference_error = target_error
        .filter(|error| error.kind.is_reference_failure())
        .or_else(|| body_error.filter(|error| error.kind.is_reference_failure()));
    let status = match accepted_error {
        Some(error) => {
            let no_valid_ca = body_error.is_some_and(|body| {
                matches!(
                    body.kind,
                    BackendTlsPolicyRejection::InvalidCaCertificateRef
                        | BackendTlsPolicyRejection::InvalidKind
                        | BackendTlsPolicyRejection::RefNotPermitted
                )
            });
            // A `TargetNotFound` rejection means the policy attaches to
            // nothing, so no backend is failed closed on its account. Saying
            // otherwise would send an operator hunting for traffic Ferrum never
            // faulted.
            let attaches_to_nothing =
                matches!(error.kind, BackendTlsPolicyRejection::TargetNotFound);
            GatewayApiBackendTlsPolicyStatus {
                policy: K8sResourceKey::from_object(object),
                accepted: false,
                accepted_reason: if attaches_to_nothing {
                    "TargetNotFound".to_string()
                } else if no_valid_ca {
                    "NoValidCACertificate".to_string()
                } else {
                    "Invalid".to_string()
                },
                accepted_message: if attaches_to_nothing {
                    format!(
                        "Ferrum rejected this BackendTLSPolicy and it governs no backend: {}",
                        error.message
                    )
                } else {
                    format!(
                        "Ferrum rejected this BackendTLSPolicy and fails matching backends closed: {}",
                        error.message
                    )
                },
                resolved_refs: reference_error.is_none(),
                resolved_refs_reason: reference_error
                    .map(|reference| reference.kind.resolved_refs_reason())
                    .unwrap_or("ResolvedRefs")
                    .to_string(),
                resolved_refs_message: reference_error
                    .map(|reference| reference.message.clone())
                    .unwrap_or_else(|| {
                        "All BackendTLSPolicy references accepted by Ferrum".to_string()
                    }),
            }
        }
        None if !any_target_resolved => GatewayApiBackendTlsPolicyStatus {
            policy: K8sResourceKey::from_object(object),
            accepted: false,
            accepted_reason: "TargetNotFound".to_string(),
            accepted_message:
                "Ferrum found no supported core Service targetRef on this BackendTLSPolicy"
                    .to_string(),
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs".to_string(),
            resolved_refs_message: "All BackendTLSPolicy references accepted by Ferrum".to_string(),
        },
        None if !targets_exist => GatewayApiBackendTlsPolicyStatus {
            policy: K8sResourceKey::from_object(object),
            accepted: false,
            accepted_reason: "TargetNotFound".to_string(),
            accepted_message:
                "Ferrum did not observe any Service named by this BackendTLSPolicy targetRefs"
                    .to_string(),
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs".to_string(),
            resolved_refs_message: "All BackendTLSPolicy references accepted by Ferrum".to_string(),
        },
        // GEP-1897 asks for a *warning inside the Accepted condition message*
        // for a mixed TCP/UDP Service, not a rejection: the policy is accepted
        // and effective for the TCP ports only.
        None => GatewayApiBackendTlsPolicyStatus {
            policy: K8sResourceKey::from_object(object),
            accepted: true,
            accepted_reason: "Accepted".to_string(),
            accepted_message: match accepted_warning {
                Some(warning) => {
                    format!("Ferrum accepted this BackendTLSPolicy; warning: {warning}")
                }
                None => "Ferrum accepted this BackendTLSPolicy".to_string(),
            },
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs".to_string(),
            resolved_refs_message: "All BackendTLSPolicy references accepted by Ferrum".to_string(),
        },
    };
    acc.record_backend_tls_policy_status(status);
}

fn parse_service_target_ref(
    object: &K8sObject,
    target_ref: &Value,
) -> Result<(String, Option<String>), BackendTlsPolicyError> {
    let group = strict_optional_string(target_ref, "group", "spec.targetRefs[].group")
        .map_err(|error| {
            BackendTlsPolicyError::of(BackendTlsPolicyRejection::InvalidKind, error.message)
        })?
        .unwrap_or("");
    let kind = strict_optional_string(target_ref, "kind", "spec.targetRefs[].kind")
        .map_err(|error| {
            BackendTlsPolicyError::of(BackendTlsPolicyRejection::InvalidKind, error.message)
        })?
        .unwrap_or("Service");
    if !group.is_empty() || kind != "Service" {
        return Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::InvalidKind,
            "spec.targetRefs[] supports only core Service targets",
        ));
    }
    if let Some(namespace) =
        strict_optional_string(target_ref, "namespace", "spec.targetRefs[].namespace").map_err(
            |error| {
                BackendTlsPolicyError::of(BackendTlsPolicyRejection::RefNotPermitted, error.message)
            },
        )?
        && namespace != object.metadata.namespace
    {
        return Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::RefNotPermitted,
            "spec.targetRefs[].namespace must match the BackendTLSPolicy namespace (cross-namespace targets are invalid)",
        ));
    }
    let name = strict_optional_string(target_ref, "name", "spec.targetRefs[].name")?
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            BackendTlsPolicyError::invalid("spec.targetRefs[].name is required for Service targets")
        })?;
    let section_name =
        match strict_optional_string(target_ref, "sectionName", "spec.targetRefs[].sectionName")? {
            Some("") => {
                return Err(BackendTlsPolicyError::invalid(
                    "spec.targetRefs[].sectionName must not be empty when present",
                ));
            }
            Some(section_name) => Some(section_name.to_string()),
            None => None,
        };
    Ok((name.to_string(), section_name))
}

fn parse_policy_validation(
    acc: &K8sAccumulator,
    object: &K8sObject,
) -> Result<BackendTlsPolicyOverlay, BackendTlsPolicyError> {
    match object.spec.get("validation") {
        None => Err(BackendTlsPolicyError::invalid(
            "spec.validation is required",
        )),
        Some(validation) => parse_validation(acc, object, validation),
    }
}

fn strict_optional_string<'a>(
    value: &'a Value,
    field: &str,
    path: &str,
) -> Result<Option<&'a str>, BackendTlsPolicyError> {
    match value.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(BackendTlsPolicyError::invalid(format!(
            "{path} must be a string"
        ))),
    }
}

fn parse_validation(
    acc: &K8sAccumulator,
    object: &K8sObject,
    validation: &Value,
) -> Result<BackendTlsPolicyOverlay, BackendTlsPolicyError> {
    if !validation.is_object() {
        return Err(BackendTlsPolicyError::invalid(
            "spec.validation must be an object",
        ));
    }
    let hostname = strict_optional_string(validation, "hostname", "spec.validation.hostname")?
        .filter(|hostname| !hostname.is_empty())
        .ok_or_else(|| BackendTlsPolicyError::invalid("spec.validation.hostname is required"))?;
    validate_backend_tls_sni(hostname)
        .map_err(|e| BackendTlsPolicyError::invalid(format!("spec.validation.hostname: {e}")))?;

    let well_known = strict_optional_string(
        validation,
        "wellKnownCACertificates",
        "spec.validation.wellKnownCACertificates",
    )?;
    let ca_refs = match validation.get("caCertificateRefs") {
        None => None,
        Some(Value::Array(refs)) => Some(refs),
        Some(_) => {
            return Err(BackendTlsPolicyError::invalid(
                "spec.validation.caCertificateRefs must be an array",
            ));
        }
    };
    let has_ca_refs = ca_refs.is_some_and(|refs| !refs.is_empty());

    let ca_bundle_source = if let Some(value) = well_known.filter(|value| !value.is_empty()) {
        if has_ca_refs {
            return Err(BackendTlsPolicyError::invalid(
                "spec.validation must not set both caCertificateRefs and wellKnownCACertificates",
            ));
        }
        if value != "System" {
            return Err(BackendTlsPolicyError::invalid(format!(
                "spec.validation.wellKnownCACertificates value {value:?} is unsupported (only \
                 System)"
            )));
        }
        // `System` is a distinct trust posture, not "unset". Projecting `None`
        // here would let Ferrum's backend CA chain fall through to the
        // cluster-global `FERRUM_TLS_CA_BUNDLE_PATH`, so a cluster-wide private
        // CA could silently replace the public roots this policy demanded.
        SYSTEM_TRUST_ROOTS_SOURCE.to_string()
    } else if let Some(refs) = ca_refs.filter(|refs| !refs.is_empty()) {
        if refs.len() > MAX_CA_CERTIFICATE_REFS {
            return Err(BackendTlsPolicyError::invalid(format!(
                "spec.validation.caCertificateRefs must have at most {MAX_CA_CERTIFICATE_REFS} entries"
            )));
        }
        // Ferrum projects a single exclusive CA bundle path today. Multiple
        // refs are accepted only when they resolve to one usable source; more
        // than one distinct source fails closed rather than silently merging.
        let mut sources = Vec::new();
        for (index, reference) in refs.iter().enumerate() {
            match resolve_ca_certificate_ref(acc, object, reference) {
                Ok(source) => sources.push(source),
                Err(error) => {
                    return Err(BackendTlsPolicyError::of(
                        error.kind,
                        format!(
                            "spec.validation.caCertificateRefs[{index}]: {}",
                            error.message
                        ),
                    ));
                }
            }
        }
        sources.sort();
        sources.dedup();
        if sources.len() != 1 {
            return Err(BackendTlsPolicyError::invalid(
                "spec.validation.caCertificateRefs must resolve to exactly one CA bundle source",
            ));
        }
        sources.remove(0)
    } else {
        return Err(BackendTlsPolicyError::invalid(
            "spec.validation requires caCertificateRefs or wellKnownCACertificates",
        ));
    };

    let subject_alt_names = parse_subject_alt_names(validation)?;

    Ok(BackendTlsPolicyOverlay {
        hostname: hostname.to_ascii_lowercase(),
        ca_bundle_source,
        subject_alt_names,
    })
}

fn resolve_ca_certificate_ref(
    acc: &K8sAccumulator,
    object: &K8sObject,
    reference: &Value,
) -> Result<String, BackendTlsPolicyError> {
    if !reference.is_object() {
        return Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::InvalidKind,
            "entry must be an object",
        ));
    }
    let group = strict_optional_string(
        reference,
        "group",
        "spec.validation.caCertificateRefs[].group",
    )
    .map_err(|error| {
        BackendTlsPolicyError::of(BackendTlsPolicyRejection::InvalidKind, error.message)
    })?
    .unwrap_or("");
    if !group.is_empty() {
        return Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::InvalidKind,
            format!("group {group:?} is unsupported (only core ConfigMap/Secret)"),
        ));
    }
    let kind = strict_optional_string(
        reference,
        "kind",
        "spec.validation.caCertificateRefs[].kind",
    )
    .map_err(|error| {
        BackendTlsPolicyError::of(BackendTlsPolicyRejection::InvalidKind, error.message)
    })?
    .unwrap_or("ConfigMap");
    let name = strict_optional_string(
        reference,
        "name",
        "spec.validation.caCertificateRefs[].name",
    )
    .map_err(|error| {
        BackendTlsPolicyError::of(BackendTlsPolicyRejection::InvalidKind, error.message)
    })?
    .filter(|name| !name.is_empty())
    .ok_or_else(|| {
        BackendTlsPolicyError::of(BackendTlsPolicyRejection::InvalidKind, "name is required")
    })?;
    if let Some(namespace) = strict_optional_string(
        reference,
        "namespace",
        "spec.validation.caCertificateRefs[].namespace",
    )
    .map_err(|error| {
        BackendTlsPolicyError::of(BackendTlsPolicyRejection::RefNotPermitted, error.message)
    })? && namespace != object.metadata.namespace
    {
        return Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::RefNotPermitted,
            "cross-namespace caCertificateRefs are invalid; omit namespace or match the policy namespace",
        ));
    }
    let namespace = object.metadata.namespace.as_str();

    match kind {
        "ConfigMap" => {
            let pem = acc
                .configmap_ca_bundle_pem(namespace, name)
                .ok_or_else(|| {
                    BackendTlsPolicyError::of(
                        BackendTlsPolicyRejection::InvalidCaCertificateRef,
                        format!(
                            "ConfigMap {namespace:?}/{name:?} is missing or has no usable \
                         data.ca.crt PEM bundle"
                        ),
                    )
                })?;
            Ok(pem.to_string())
        }
        "Secret" => {
            let digest = acc
                .secret_ca_bundle_digest(namespace, name)
                .ok_or_else(|| {
                    BackendTlsPolicyError::of(
                        BackendTlsPolicyRejection::InvalidCaCertificateRef,
                        format!(
                            "Secret {namespace:?}/{name:?} is missing or has no usable data.ca.crt \
                         PEM bundle"
                        ),
                    )
                })?;
            Ok(format!("k8s://{namespace}/{name}#ca.crt?sha256={digest}"))
        }
        other => Err(BackendTlsPolicyError::of(
            BackendTlsPolicyRejection::InvalidKind,
            format!("kind {other:?} is unsupported (only ConfigMap or Secret)"),
        )),
    }
}

fn parse_subject_alt_names(validation: &Value) -> Result<Vec<String>, BackendTlsPolicyError> {
    let entries = match validation.get("subjectAltNames") {
        None => return Ok(Vec::new()),
        Some(Value::Array(entries)) => entries,
        Some(_) => {
            return Err(BackendTlsPolicyError::invalid(
                "spec.validation.subjectAltNames must be an array",
            ));
        }
    };
    if entries.len() > MAX_SUBJECT_ALT_NAMES {
        return Err(BackendTlsPolicyError::invalid(format!(
            "spec.validation.subjectAltNames must have at most {MAX_SUBJECT_ALT_NAMES} entries"
        )));
    }
    let mut out = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        if !entry.is_object() {
            return Err(BackendTlsPolicyError::invalid(format!(
                "spec.validation.subjectAltNames[{index}] must be an object"
            )));
        }
        let san_type = strict_optional_string(
            entry,
            "type",
            &format!("spec.validation.subjectAltNames[{index}].type"),
        )?
        .unwrap_or_default();
        let value = match san_type {
            "Hostname" => strict_optional_string(
                entry,
                "hostname",
                &format!("spec.validation.subjectAltNames[{index}].hostname"),
            )?
            .ok_or_else(|| {
                BackendTlsPolicyError::invalid(format!(
                    "spec.validation.subjectAltNames[{index}].hostname is required"
                ))
            })?
            .to_string(),
            "URI" => strict_optional_string(
                entry,
                "uri",
                &format!("spec.validation.subjectAltNames[{index}].uri"),
            )?
            .ok_or_else(|| {
                BackendTlsPolicyError::invalid(format!(
                    "spec.validation.subjectAltNames[{index}].uri is required"
                ))
            })?
            .to_string(),
            other => {
                return Err(BackendTlsPolicyError::invalid(format!(
                    "spec.validation.subjectAltNames[{index}].type {other:?} is unsupported"
                )));
            }
        };
        validate_backend_tls_san_allow_list_entry(&value).map_err(|e| {
            BackendTlsPolicyError::invalid(format!("spec.validation.subjectAltNames[{index}]: {e}"))
        })?;
        out.push(value);
    }
    Ok(out)
}

/// Lookup outcome for backends that reference a Service with BackendTLSPolicy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BackendTlsPolicyLookup {
    /// No policy targets this Service/port.
    None,
    /// Apply this overlay (enables HTTPS + SNI/CA/SAN).
    Apply(BackendTlsPolicyOverlay),
    /// A policy targets this Service/port but is invalid, conflicting, or
    /// covers only part of the rule's backend set.
    Fault { reason: String },
}

fn compare_policy_precedence(
    left: &IndexedBackendTlsPolicy,
    right: &IndexedBackendTlsPolicy,
) -> Ordering {
    compare_creation_timestamps(&left.creation_timestamp, &right.creation_timestamp).then_with(
        || {
            (&left.policy_namespace, &left.policy_name)
                .cmp(&(&right.policy_namespace, &right.policy_name))
        },
    )
}

fn compare_policy_for_lookup(
    left: &IndexedBackendTlsPolicy,
    right: &IndexedBackendTlsPolicy,
) -> Ordering {
    // A section-scoped policy is more specific than a Service-wide policy for
    // the port it names. Equal-specificity candidates use the Gateway API
    // oldest-creationTimestamp, then lexical resource-identity precedence.
    let left_specific = left.section_name.is_some();
    let right_specific = right.section_name.is_some();
    match (left_specific, right_specific) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => compare_policy_precedence(left, right),
    }
}

pub(super) fn lookup_for_service(
    acc: &K8sAccumulator,
    service_namespace: &str,
    service_name: &str,
    service_port: Option<u16>,
) -> BackendTlsPolicyLookup {
    let Some(entries) = acc
        .backend_tls_policies
        .by_service
        .get(&(service_namespace.to_string(), service_name.to_string()))
    else {
        return BackendTlsPolicyLookup::None;
    };
    if entries.is_empty() {
        return BackendTlsPolicyLookup::None;
    }

    // The port scope was resolved once, at collect time, against the complete
    // Service index — including each port's L4 transport. Matching here is a
    // pure predicate over that decision, so runtime attachment and the
    // published status cannot drift apart.
    let port_index = acc.service_port_index(service_namespace, service_name);

    let mut matching: Vec<&IndexedBackendTlsPolicy> = entries
        .iter()
        .filter(|entry| entry.governs(port_index, service_port))
        .collect();

    if matching.is_empty() {
        // Policies exist for this Service but none governs this port — a
        // sectionName scoped elsewhere, a sectionName that resolves to nothing,
        // or the UDP port of a mixed-transport Service. Treat it as no policy
        // for this backend rather than applying a TLS identity the operator
        // scoped to a different port.
        return BackendTlsPolicyLookup::None;
    }

    matching.sort_by(|left, right| compare_policy_for_lookup(left, right));

    let winner = matching[0];
    match &winner.record {
        BackendTlsPolicyRecord::Valid(overlay) => BackendTlsPolicyLookup::Apply(overlay.clone()),
        BackendTlsPolicyRecord::Invalid(error) => BackendTlsPolicyLookup::Fault {
            reason: format!(
                "BackendTLSPolicy {:?}/{:?}: {}",
                winner.policy_namespace, winner.policy_name, error.message
            ),
        },
    }
}

/// Human-readable identity of a route backend for a sanitized diagnostic.
///
/// Only translator-derived identity (Service coordinates, or the resolved
/// backend host/port) is emitted — never raw spec text.
fn backend_target_label(backend: &RouteBackend) -> String {
    match (
        backend.service_namespace.as_deref(),
        backend.service_name.as_deref(),
    ) {
        (Some(namespace), Some(name)) => match backend.service_port {
            Some(port) => format!("Service {namespace:?}/{name:?}:\"{port}\""),
            None => format!("Service {namespace:?}/{name:?}"),
        },
        _ => format!("backend {:?}:\"{}\"", backend.host, backend.port),
    }
}

/// Resolve a single BackendTLSPolicy overlay for a set of route backends.
///
/// Returns `None` when no backend carries a policy. Any of the following fails
/// closed instead of silently widening or narrowing TLS:
///
/// * an invalid/unrepresentable policy on a referenced Service;
/// * two backends whose valid overlays disagree (one Upstream carries one TLS
///   identity);
/// * a **mixed** set where at least one backend is policy-covered and at least
///   one is not. Ferrum folds a rule's backends into one `Upstream` with one
///   `backend_scheme` and one `backend_tls_*` identity, so applying the overlay
///   would originate TLS — with the covered Service's SNI and trust anchors —
///   to a Service no policy covers, and dropping it would silently ignore an
///   explicitly requested TLS policy. Neither is safe, so the rule aborts.
pub(super) fn resolve_backends_tls_policy(
    acc: &mut K8sAccumulator,
    backends: &[RouteBackend],
) -> BackendTlsPolicyLookup {
    let mut selected: Option<BackendTlsPolicyOverlay> = None;
    let mut covered_label: Option<String> = None;
    let mut uncovered_label: Option<String> = None;
    for backend in backends {
        let lookup = match (
            backend.service_namespace.as_deref(),
            backend.service_name.as_deref(),
        ) {
            (Some(namespace), Some(name)) => {
                lookup_for_service(acc, namespace, name, backend.service_port)
            }
            // A backend Ferrum could not resolve to a Service identity can
            // never be policy-covered, so it counts as uncovered rather than
            // being skipped: skipping it is exactly how a mixed set used to
            // become uniformly HTTPS.
            _ => BackendTlsPolicyLookup::None,
        };
        match lookup {
            BackendTlsPolicyLookup::None => {
                if uncovered_label.is_none() {
                    uncovered_label = Some(backend_target_label(backend));
                }
            }
            BackendTlsPolicyLookup::Fault { reason } => {
                acc.warnings.push(format!(
                    "Gateway API BackendTLSPolicy for {} fails closed: {reason}",
                    backend_target_label(backend)
                ));
                return BackendTlsPolicyLookup::Fault { reason };
            }
            BackendTlsPolicyLookup::Apply(overlay) => {
                if covered_label.is_none() {
                    covered_label = Some(backend_target_label(backend));
                }
                match &selected {
                    None => selected = Some(overlay),
                    Some(existing) if existing == &overlay => {}
                    Some(_) => {
                        let reason = format!(
                            "conflicting BackendTLSPolicy overlays across backends including {}",
                            backend_target_label(backend)
                        );
                        acc.warnings.push(format!(
                            "Gateway API BackendTLSPolicy fails closed: {reason}"
                        ));
                        return BackendTlsPolicyLookup::Fault { reason };
                    }
                }
            }
        }
    }

    match (selected, covered_label, uncovered_label) {
        (Some(_), Some(covered), Some(uncovered)) => {
            let reason = format!(
                "spec.rules[].backendRefs mixes BackendTLSPolicy-covered and uncovered backends ({covered} is covered, {uncovered} is not); Ferrum cannot encode per-backend TLS identity in one upstream"
            );
            acc.warnings.push(format!(
                "Gateway API BackendTLSPolicy fails closed: {reason}"
            ));
            BackendTlsPolicyLookup::Fault { reason }
        }
        (Some(overlay), _, _) => BackendTlsPolicyLookup::Apply(overlay),
        (None, _, _) => BackendTlsPolicyLookup::None,
    }
}

pub(super) fn apply_to_upstream(upstream: &mut Upstream, overlay: &BackendTlsPolicyOverlay) {
    upstream.backend_tls_verify_server_cert = true;
    upstream.backend_tls_client_cert_path = None;
    upstream.backend_tls_client_key_path = None;
    upstream.backend_tls_server_ca_cert_path = Some(overlay.ca_bundle_source.clone());
    upstream.backend_tls_sni = Some(overlay.hostname.clone());
    upstream.backend_tls_san_allow_list = overlay.subject_alt_names.clone();
}
