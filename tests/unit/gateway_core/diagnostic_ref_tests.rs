//! Gateway-owned diagnostic references (issue #5767).
//!
//! * A reference is `fd1_` plus 128 CSPRNG bits in lowercase hex, embeds
//!   nothing, and is minted only for a response that carries a closed-set
//!   `X-Gateway-Error` token.
//! * Every stamp strips a forged or leftover copy first, and the backend
//!   boundary predicate strips a backend copy, so a client never sees a
//!   reference the gateway did not mint.
//! * The store is bounded by TTL and entry count, and the lookup is scoped:
//!   scope and namespace binding are required, and an out-of-namespace
//!   reference is indistinguishable from an unknown one (the store is not even
//!   read).
//! * Every lookup attempt, a refused one included, is charged against a
//!   per-subject share; only an authorized credential's attempt also spends
//!   the global budget. Refused and rate-limited audit events are throttled.
//! * `all` mode (issue #5846) also references a gateway rejection without an
//!   `X-Gateway-Error` token, and only one a rejection site recorded; the
//!   detail names the rejecting phase and plugin and every backend attempt,
//!   with closed TLS labels, and stays bounded.
//! * A replica-tagged store (issue #5846) mints `fd2_<replica>_<32 hex>`
//!   references and resolves only its own. Another replica answers the plain
//!   miss, plus the owner hint only for a caller authorized for its namespace;
//!   `fd1_` references keep resolving on the untagged store that minted them.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ferrum_edge::diagnostic_ref::{
    DIAGNOSTIC_REF_HEADER, DIAGNOSTIC_REF_LEN, DIAGNOSTIC_REF_OWNER_REPLICA_HEADER,
    DIAGNOSTIC_REF_PREFIX, DIAGNOSTIC_REF_SCHEMA_VERSION, DIAGNOSTIC_REF_TAGGED_LEN,
    DIAGNOSTIC_REF_TAGGED_PREFIX, DiagnosticDetail, DiagnosticProtocol, DiagnosticRefLookup,
    DiagnosticRefLookupAudit, DiagnosticRefLookupResult, DiagnosticRefMode, DiagnosticRefStore,
    DiagnosticRefStoreConfig, DiagnosticRejection, DiagnosticRejectionSource, DiagnosticReplicaId,
    DiagnosticSlot, DiagnosticTlsDetail, MAX_RECORDED_ATTEMPTS, MAX_TRACKED_LOOKUP_SUBJECTS,
    REPLICA_ID_HEX_LEN, authorize_lookup, backend_origin, duration_bucket, insert_owner_hint,
    is_well_formed_ref, reference_replica, stamp_response_headers, strip_response_header,
    tls_detail, tls_detail_from_rustls,
};
use ferrum_edge::grpc::auth::AllowedNamespaces;
use ferrum_edge::plugins::TransactionSummary;
use ferrum_edge::proxy::headers::is_backend_response_strip_header;
use ferrum_edge::retry::{ErrorClass, HTTP_OBSERVABILITY_ERROR_CLASSES};

const NAMESPACE: &str = "ferrum";
const UNKNOWN_REF: &str = "fd1_00000000000000000000000000000000";
const OPERATOR: &str = "operator";

fn store_with(max_entries: usize, ttl: Duration, rate: u32) -> DiagnosticRefStore {
    let config = DiagnosticRefStoreConfig {
        ttl,
        max_entries,
        lookup_rate_per_second: rate,
    };
    DiagnosticRefStore::new(NAMESPACE, config)
}

fn default_store() -> DiagnosticRefStore {
    store_with(10_000, Duration::from_secs(900), 10_000)
}

fn namespaces(names: &[&str]) -> AllowedNamespaces {
    AllowedNamespaces::claimed(names.iter().map(|name| name.to_string()).collect())
}

fn gateway_error_headers(token: &str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("x-gateway-error", token.parse().unwrap());
    headers
}

fn mint(store: &DiagnosticRefStore, status: u16, token: &'static str) -> String {
    store
        .mint(DiagnosticProtocol::Http1, status, token, None)
        .expect("CSPRNG-backed mint")
}

fn stamp(
    store: &DiagnosticRefStore,
    protocol: DiagnosticProtocol,
    status: u16,
    headers: &mut http::HeaderMap,
) -> Option<String> {
    stamp_response_headers(store, None, protocol, status, headers)
}

fn label(outcome: &DiagnosticRefLookup) -> &'static str {
    match outcome {
        DiagnosticRefLookup::Found(_) => "found",
        DiagnosticRefLookup::NotFound => "not_found",
        DiagnosticRefLookup::NotOwned(_) => "not_owned",
        DiagnosticRefLookup::MissingScope => "missing_scope",
        DiagnosticRefLookup::MissingNamespaceBinding => "missing_namespace_binding",
        DiagnosticRefLookup::RateLimited => "rate_limited",
    }
}

fn with_rejection_phase(mut summary: TransactionSummary, phase: &str) -> TransactionSummary {
    let key = "rejection_phase".to_string();
    summary.metadata.insert(key, phase.to_string());
    summary
}

fn summary(status: u16, class: Option<ErrorClass>) -> TransactionSummary {
    TransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: NAMESPACE.to_string(),
        timestamp_received: "2026-09-27T00:00:00Z".to_string(),
        client_ip: "203.0.113.7".to_string(),
        consumer_username: Some("alice".to_string()),
        auth_method: None,
        http_method: "POST".to_string(),
        request_path: "/orders/secret-path?token=abc".to_string(),
        proxy_id: Some("orders-api".to_string()),
        proxy_name: Some("orders".to_string()),
        backend_target: Some(
            "https://svc:hunter2@orders.internal:8443/v1/private?api_key=abc#frag".to_string(),
        ),
        backend_resolved_ip: Some("10.0.0.9".to_string()),
        response_status_code: status,
        latency_total_ms: 42.0,
        latency_gateway_processing_ms: 1.0,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        latency_plugin_execution_ms: 0.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 1.0,
        request_user_agent: Some("curl/8".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: class,
        body_error_class: None,
        body_completed: false,
        bytes_sent: 0,
        bytes_received: 0,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata: HashMap::new(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

// ── configuration ──────────────────────────────────────────────────────────

#[test]
fn mode_parses_only_off_errors_and_all() {
    assert_eq!(DiagnosticRefMode::parse("off"), Ok(DiagnosticRefMode::Off));
    assert_eq!(
        DiagnosticRefMode::parse(" Errors "),
        Ok(DiagnosticRefMode::Errors)
    );
    assert_eq!(DiagnosticRefMode::parse("ALL"), Ok(DiagnosticRefMode::All));
    assert_eq!(DiagnosticRefMode::All.as_str(), "all");
    assert_eq!(DiagnosticRefMode::default(), DiagnosticRefMode::Off);
    assert!(!DiagnosticRefMode::Off.is_enabled());
    assert!(DiagnosticRefMode::Errors.is_enabled());
    assert!(DiagnosticRefMode::All.is_enabled());
    assert!(!DiagnosticRefMode::Errors.covers_gateway_rejections());
    assert!(DiagnosticRefMode::All.covers_gateway_rejections());
    for rejected in ["", "on", "every", "true", "error", "errors,all"] {
        assert!(
            DiagnosticRefMode::parse(rejected).is_err(),
            "{rejected:?} must fail closed at startup"
        );
    }
}

#[test]
fn protocol_follows_the_client_http_version() {
    let cases = [
        (http::Version::HTTP_10, DiagnosticProtocol::Http1),
        (http::Version::HTTP_11, DiagnosticProtocol::Http1),
        (http::Version::HTTP_2, DiagnosticProtocol::Http2),
        (http::Version::HTTP_3, DiagnosticProtocol::Http3),
    ];
    for (version, expected) in cases {
        assert_eq!(DiagnosticProtocol::from_http_version(version), expected);
    }
}

#[test]
fn store_bounds_are_clamped_never_unbounded() {
    let tiny = store_with(0, Duration::ZERO, 0);
    assert_eq!(tiny.ttl(), Duration::from_secs(1));
    assert_eq!(tiny.capacity(), 16);

    let huge = store_with(usize::MAX, Duration::from_secs(u64::MAX), u32::MAX);
    assert_eq!(huge.ttl(), Duration::from_secs(86_400));
    assert!(huge.capacity() <= 1_000_000);

    let exact = store_with(10_000, Duration::from_secs(900), 10);
    assert!(exact.capacity() <= 10_000);
}

// ── reference format ───────────────────────────────────────────────────────

#[test]
fn references_are_opaque_well_formed_and_unique() {
    let store = default_store();
    let mut seen = HashSet::new();
    for _ in 0..2_000 {
        let reference = mint(&store, 502, "connection_failure");
        assert_eq!(reference.len(), DIAGNOSTIC_REF_LEN);
        assert!(reference.starts_with(DIAGNOSTIC_REF_PREFIX));
        let hex = &reference[DIAGNOSTIC_REF_PREFIX.len()..];
        assert_eq!(hex.len(), 32, "128 bits of randomness");
        let lowercase_hex = hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        assert!(lowercase_hex, "lowercase hex only: {reference}");
        assert!(!reference.contains("connection_failure"));
        assert!(!reference.contains(NAMESPACE));
        assert!(is_well_formed_ref(&reference));
        assert!(seen.insert(reference), "references must never repeat");
    }
}

#[test]
fn malformed_references_never_resolve() {
    let store = default_store();
    let good = mint(&store, 503, "overload");
    let now = Instant::now();
    assert!(store.lookup_at(now, &good).is_some());

    let hex = &good[DIAGNOSTIC_REF_PREFIX.len()..];
    let upper = format!("{DIAGNOSTIC_REF_PREFIX}{}", hex.to_ascii_uppercase());
    let wrong_prefix = format!("fd2_{hex}");
    let short = good[..good.len() - 1].to_string();
    let long = format!("{good}0");
    let non_hex = format!("{short}g");
    let multibyte = format!("{}é", &good[..good.len() - 2]);
    let malformed = [
        upper.as_str(),
        wrong_prefix.as_str(),
        short.as_str(),
        long.as_str(),
        non_hex.as_str(),
        multibyte.as_str(),
        "",
        "fd1_",
        "../../etc/passwd",
    ];
    for bad in malformed {
        assert!(!is_well_formed_ref(bad), "{bad:?}");
        assert!(store.lookup_at(now, bad).is_none(), "{bad:?}");
    }
}

// ── store behaviour ────────────────────────────────────────────────────────

#[test]
fn lookup_returns_the_versioned_view_and_detail_arrives_later() {
    let store = default_store();
    let slot = DiagnosticSlot::shared();
    let protocol = DiagnosticProtocol::Http3;
    let reference = store
        .mint(protocol, 502, "connection_failure", Some(&slot))
        .unwrap();
    let now = Instant::now();

    let pending = store.lookup_at(now, &reference).expect("minted reference");
    assert_eq!(pending.schema_version, DIAGNOSTIC_REF_SCHEMA_VERSION);
    assert_eq!(pending.reference, reference);
    assert_eq!(pending.namespace, NAMESPACE);
    assert_eq!(pending.protocol, DiagnosticProtocol::Http3);
    assert_eq!(pending.status, 502);
    assert_eq!(pending.gateway_error, Some("connection_failure"));
    assert!(!pending.detail_available);
    assert!(pending.detail.is_none());

    // The terminal transaction log may run after the response head was
    // stamped (a streamed response); the store reads the shared slot.
    let dns = summary(502, Some(ErrorClass::DnsLookupError));
    let recorded = DiagnosticDetail::from_summary(&dns, "pre_wire_failure", None);
    slot.record_detail(recorded);
    let resolved = store.lookup_at(now, &reference).unwrap();
    assert!(resolved.detail_available);
    let detail = resolved.detail.expect("detail recorded");
    assert_eq!(detail.error_class, Some("dns_lookup_error"));
    assert_eq!(detail.backend_dispatch, "pre_wire_failure");

    let view = store.lookup_at(now, &reference).unwrap();
    let body = serde_json::to_value(view).unwrap();
    let keys: HashSet<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected = HashSet::from([
        "schema_version",
        "ref",
        "namespace",
        "created_at",
        "expires_at",
        "protocol",
        "status",
        "gateway_error",
        "detail_available",
        "detail",
    ]);
    assert_eq!(keys, expected);
    assert_eq!(body["protocol"], "http3");
    assert_eq!(body["schema_version"], "ferrum.diagnostic_ref.v1");
}

#[test]
fn first_recorded_detail_wins() {
    let slot = DiagnosticSlot::shared();
    let timeout = summary(504, Some(ErrorClass::ReadWriteTimeout));
    let refused = summary(502, Some(ErrorClass::ConnectionRefused));
    let first = DiagnosticDetail::from_summary(&timeout, "backend_response", Some("dispatch"));
    let second = DiagnosticDetail::from_summary(&refused, "pre_wire_failure", None);
    slot.record_detail(first);
    slot.record_detail(second);
    let detail = slot.detail().unwrap();
    assert_eq!(detail.error_class, Some("read_write_timeout"));
    assert_eq!(detail.route_timeout_phase, Some("dispatch"));
}

#[test]
fn one_request_never_gets_two_references() {
    let store = default_store();
    let slot = DiagnosticSlot::shared();
    let protocol = DiagnosticProtocol::Http3;
    let first = store.mint(protocol, 502, "backend_error", Some(&slot));
    let second = store.mint(protocol, 502, "backend_error", Some(&slot));
    assert!(first.is_some());
    assert_eq!(first, second);
    assert_eq!(slot.minted_ref(), first.as_deref());
    assert_eq!(store.minted_total(), 1);
    assert_eq!(store.len(), 1);
}

#[test]
fn references_expire_after_the_ttl() {
    let store = store_with(10_000, Duration::from_secs(5), 10_000);
    let start = Instant::now();
    let protocol = DiagnosticProtocol::Http1;
    let reference = store
        .mint_at(start, protocol, 504, "backend_timeout", None)
        .unwrap();
    let before = start + Duration::from_secs(4);
    let at_ttl = start + Duration::from_secs(5);
    assert!(store.lookup_at(before, &reference).is_some());
    assert!(
        store.lookup_at(at_ttl, &reference).is_none(),
        "a reference must not resolve once its TTL elapsed"
    );
    assert_eq!(store.evicted_expired_total(), 1);
    assert!(store.is_empty(), "expired entries are purged");
}

#[test]
fn overflow_evicts_the_oldest_and_never_exceeds_capacity() {
    let store = store_with(16, Duration::from_secs(900), 10_000);
    let start = Instant::now();
    let protocol = DiagnosticProtocol::Http1;
    let mut minted = Vec::new();
    for offset in 0..400u64 {
        let at = start + Duration::from_millis(offset);
        let reference = store.mint_at(at, protocol, 502, "backend_error", None);
        minted.push(reference.unwrap());
        assert!(store.len() <= store.capacity());
    }
    assert_eq!(store.minted_total(), 400);
    assert_eq!(
        store.evicted_capacity_total() + store.len() as u64,
        400,
        "every minted reference is either retained or counted as evicted"
    );
    let now = start + Duration::from_secs(1);
    let resolvable = minted
        .iter()
        .filter(|reference| store.lookup_at(now, reference).is_some())
        .count();
    assert_eq!(resolvable, store.len());
    let newest = minted.last().unwrap();
    assert!(
        store.lookup_at(now, newest).is_some(),
        "the newest reference always survives its own insertion"
    );
}

#[test]
fn lookup_rate_limit_is_a_fixed_one_second_window() {
    let store = store_with(10_000, Duration::from_secs(900), 3);
    let start = Instant::now() + Duration::from_secs(1);
    assert!(store.try_acquire_lookup_at(start));
    assert!(store.try_acquire_lookup_at(start));
    assert!(store.try_acquire_lookup_at(start));
    assert!(!store.try_acquire_lookup_at(start));
    let same_second = start + Duration::from_millis(10);
    let next_second = start + Duration::from_secs(1);
    assert!(!store.try_acquire_lookup_at(same_second));
    assert!(store.try_acquire_lookup_at(next_second));
}

// ── response stamping ──────────────────────────────────────────────────────

#[test]
fn stamp_replaces_a_forged_reference_on_a_gateway_error_response() {
    let store = default_store();
    let forged = format!("{DIAGNOSTIC_REF_PREFIX}{}", "0".repeat(32));
    let mixed_case: http::HeaderName = "X-Ferrum-Diagnostic-Ref".parse().unwrap();
    let second_forged = "fd1_ffffffffffffffffffffffffffffffff";
    let mut headers = gateway_error_headers("connection_failure");
    headers.append(DIAGNOSTIC_REF_HEADER, forged.parse().unwrap());
    headers.append(mixed_case, second_forged.parse().unwrap());

    let stamped = stamp(&store, DiagnosticProtocol::Http2, 502, &mut headers)
        .expect("gateway-error response is stamped");

    let values: Vec<_> = headers.get_all(DIAGNOSTIC_REF_HEADER).iter().collect();
    assert_eq!(values.len(), 1, "exactly one reference reaches the client");
    assert_eq!(values[0].to_str().unwrap(), stamped);
    assert_ne!(stamped, forged);
    assert!(store.lookup_at(Instant::now(), &forged).is_none());
    let view = store.lookup_at(Instant::now(), &stamped).unwrap();
    assert_eq!(view.gateway_error, Some("connection_failure"));
    assert_eq!(view.status, 502);
    assert_eq!(view.protocol, DiagnosticProtocol::Http2);
}

#[test]
fn stamp_strips_a_reference_from_a_response_without_gateway_error() {
    let store = default_store();
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", "text/plain".parse().unwrap());
    headers.insert(DIAGNOSTIC_REF_HEADER, UNKNOWN_REF.parse().unwrap());
    let stamped = stamp(&store, DiagnosticProtocol::Http1, 200, &mut headers);
    assert!(stamped.is_none());
    assert!(!headers.contains_key(DIAGNOSTIC_REF_HEADER));
    assert_eq!(store.minted_total(), 0);
}

#[test]
fn stamp_ignores_an_out_of_vocabulary_gateway_error_value() {
    let store = default_store();
    let mut headers = gateway_error_headers("dns_lookup_error");
    let stamped = stamp(&store, DiagnosticProtocol::Http1, 502, &mut headers);
    assert!(
        stamped.is_none(),
        "only the closed nine-token vocabulary is gateway-authored"
    );
    assert!(!headers.contains_key(DIAGNOSTIC_REF_HEADER));
    assert_eq!(store.minted_total(), 0);
}

#[test]
fn every_public_token_is_stamped() {
    let store = default_store();
    for token in HTTP_OBSERVABILITY_ERROR_CLASSES {
        let mut headers = gateway_error_headers(token);
        let stamped = stamp(&store, DiagnosticProtocol::Http1, 503, &mut headers)
            .unwrap_or_else(|| panic!("{token} must carry a reference"));
        let view = store.lookup_at(Instant::now(), &stamped).unwrap();
        assert_eq!(view.gateway_error, Some(*token));
        let public = headers.get("x-gateway-error").unwrap();
        assert_eq!(
            public.to_str().unwrap(),
            *token,
            "the public token itself is never rewritten"
        );
    }
}

#[test]
fn strip_drops_every_copy_and_keeps_the_public_token() {
    let mut headers = gateway_error_headers("connection_failure");
    let mixed_case: http::HeaderName = "X-Ferrum-Diagnostic-Ref".parse().unwrap();
    headers.append(DIAGNOSTIC_REF_HEADER, UNKNOWN_REF.parse().unwrap());
    headers.append(mixed_case, UNKNOWN_REF.parse().unwrap());
    strip_response_header(&mut headers);
    assert!(!headers.contains_key(DIAGNOSTIC_REF_HEADER));
    let public = headers.get("x-gateway-error").unwrap();
    assert_eq!(public.to_str().unwrap(), "connection_failure");
}

/// The header is gateway-owned whatever `FERRUM_DIAGNOSTIC_REFS` says: both
/// final client boundaries strip a plugin- or hook-written copy when the store
/// is off, not only when an enabled store stamps.
#[test]
fn final_client_boundaries_strip_the_header_when_references_are_off() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let boundaries = [
        (
            "src/proxy/mod.rs",
            "None => crate::diagnostic_ref::strip_response_header(resp.headers_mut()),",
        ),
        (
            "src/diagnostic_ref.rs",
            "None => strip_response_header(response.headers_mut()),",
        ),
    ];
    for (file, off_arm) in boundaries {
        let path = root.join(file);
        let source = std::fs::read_to_string(&path).expect("read source");
        assert!(
            source.lines().any(|line| line.trim() == off_arm),
            "{file}: the off-mode boundary must strip the reference header"
        );
    }
}

/// Detached terminal logging can be refused by `FERRUM_LOG_DELIVERY_MAX_TASKS`,
/// so the detail a client's reference resolves to is recorded on the request
/// task before the delivery is admitted, never only inside the spawned task.
#[test]
fn detached_terminal_logging_records_detail_before_admission() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/plugins/mod.rs");
    let source = std::fs::read_to_string(&path).expect("read source");
    let start = source
        .find("pub fn spawn_bounded_terminal_summary_log(")
        .expect("detached terminal logger");
    let body = &source[start..];
    let record = body
        .find("crate::diagnostic_ref::record_request_detail(slot, &summary, ctx);")
        .expect("synchronous detail record");
    let spawn = body
        .find("spawn_deadline_cleanup(")
        .expect("bounded delivery spawn");
    assert!(record < spawn, "detail must be recorded before admission");
}

#[test]
fn backend_boundary_strips_the_reference_header_in_any_case() {
    assert!(is_backend_response_strip_header(DIAGNOSTIC_REF_HEADER));
    assert!(is_backend_response_strip_header("X-Ferrum-Diagnostic-Ref"));
}

// ── scoped lookup ──────────────────────────────────────────────────────────

#[test]
fn lookup_requires_scope_then_namespace_binding_before_reading_the_store() {
    let store = default_store();
    let reference = mint(&store, 502, "connection_failure");
    let now = Instant::now();
    let bound = namespaces(&[NAMESPACE]);
    let unbound = AllowedNamespaces::empty();

    let no_scope = authorize_lookup(Some(&store), OPERATOR, false, &bound, &reference, now);
    assert_eq!(label(&no_scope), "missing_scope");
    let no_binding = authorize_lookup(Some(&store), OPERATOR, true, &unbound, &reference, now);
    assert_eq!(label(&no_binding), "missing_namespace_binding");
    let forbidden = store.lookups_total(DiagnosticRefLookupResult::Forbidden);
    assert_eq!(forbidden, 2);
}

#[test]
fn out_of_namespace_reference_is_indistinguishable_from_unknown() {
    let store = default_store();
    let reference = mint(&store, 502, "connection_failure");
    let now = Instant::now();
    let staging = namespaces(&["staging"]);
    let both = namespaces(&["staging", NAMESPACE]);

    let other_tenant = authorize_lookup(Some(&store), OPERATOR, true, &staging, &reference, now);
    let unknown = authorize_lookup(Some(&store), OPERATOR, true, &staging, UNKNOWN_REF, now);
    assert_eq!(label(&other_tenant), "not_found");
    assert_eq!(label(&unknown), "not_found");

    match authorize_lookup(Some(&store), OPERATOR, true, &both, &reference, now) {
        DiagnosticRefLookup::Found(view) => assert_eq!(view.reference, reference),
        other => panic!("authorized lookup must resolve, got {other:?}"),
    }
    let not_found = store.lookups_total(DiagnosticRefLookupResult::NotFound);
    let found = store.lookups_total(DiagnosticRefLookupResult::Found);
    assert_eq!(not_found, 2);
    assert_eq!(found, 1);
}

#[test]
fn lookup_with_the_feature_off_is_not_found() {
    let bound = namespaces(&[NAMESPACE]);
    let outcome = authorize_lookup(None, OPERATOR, true, &bound, UNKNOWN_REF, Instant::now());
    assert_eq!(label(&outcome), "not_found");
}

#[test]
fn lookup_is_rate_limited_and_counted() {
    let store = store_with(10_000, Duration::from_secs(900), 1);
    let reference = mint(&store, 502, "connection_failure");
    let now = Instant::now() + Duration::from_secs(1);
    let bound = namespaces(&[NAMESPACE]);
    let first = authorize_lookup(Some(&store), OPERATOR, true, &bound, &reference, now);
    let second = authorize_lookup(Some(&store), OPERATOR, true, &bound, &reference, now);
    assert_eq!(label(&first), "found");
    assert_eq!(label(&second), "rate_limited");
    let limited = store.lookups_total(DiagnosticRefLookupResult::RateLimited);
    assert_eq!(limited, 1);
}

#[test]
fn refused_attempts_are_charged_against_the_lookup_budget() {
    // A budget of 2 per second leaves each subject a share of 1.
    let store = store_with(10_000, Duration::from_secs(900), 2);
    assert_eq!(store.per_subject_lookup_rate_per_second(), 1);
    let reference = mint(&store, 502, "connection_failure");
    let now = Instant::now() + Duration::from_secs(1);
    let bound = namespaces(&[NAMESPACE]);

    let no_scope = authorize_lookup(Some(&store), OPERATOR, false, &bound, &reference, now);
    assert_eq!(label(&no_scope), "missing_scope");
    let retry = authorize_lookup(Some(&store), OPERATOR, true, &bound, &reference, now);
    assert_eq!(
        label(&retry),
        "rate_limited",
        "the refused attempt spent the subject's share"
    );
    let later = now + Duration::from_secs(1);
    let fresh = authorize_lookup(Some(&store), OPERATOR, true, &bound, &reference, later);
    assert_eq!(label(&fresh), "found");
}

#[test]
fn one_subject_cannot_exhaust_the_global_lookup_budget() {
    let store = store_with(10_000, Duration::from_secs(900), 4);
    assert_eq!(store.per_subject_lookup_rate_per_second(), 2);
    let now = Instant::now() + Duration::from_secs(1);
    let admitted = |subject: &str| store.try_acquire_subject_lookup_at(now, subject, true);

    assert!(admitted("reader-a"));
    assert!(admitted("reader-a"));
    assert!(!admitted("reader-a"), "reader-a spent its share");
    // The refused attempt above charged nothing globally: two slots remain.
    assert!(admitted("reader-b"));
    assert!(admitted("reader-b"));
    assert!(!admitted("reader-c"), "the global budget is spent");

    let later = now + Duration::from_secs(1);
    assert!(store.try_acquire_subject_lookup_at(later, "reader-a", true));
}

#[test]
fn unauthorized_subjects_cannot_exhaust_the_global_lookup_budget() {
    // A budget of 2 per second leaves each subject a share of 1: before the
    // fix, the first refused attempt of each unauthorized credential spent
    // one global slot, locking the operator out for the rest of the window.
    let store = store_with(10_000, Duration::from_secs(900), 2);
    let reference = mint(&store, 502, "connection_failure");
    let now = Instant::now() + Duration::from_secs(1);
    let bound = namespaces(&[NAMESPACE]);
    let unbound = AllowedNamespaces::empty();
    let no_scope = || authorize_lookup(Some(&store), "no-scope", false, &bound, &reference, now);
    let no_ns = || authorize_lookup(Some(&store), "no-ns", true, &unbound, &reference, now);

    assert_eq!(label(&no_scope()), "missing_scope");
    assert_eq!(label(&no_ns()), "missing_namespace_binding");
    for _ in 0..20 {
        assert_eq!(label(&no_scope()), "rate_limited", "share spent");
        assert_eq!(label(&no_ns()), "rate_limited", "share spent");
    }
    let operator = authorize_lookup(Some(&store), OPERATOR, true, &bound, &reference, now);
    assert_eq!(label(&operator), "found", "the global budget is untouched");
}

#[test]
fn out_of_namespace_subjects_cannot_exhaust_the_global_lookup_budget() {
    // A budget of 2 per second leaves each subject a share of 1. These
    // credentials have the scope and an `ns` claim, but cannot read this store.
    let store = store_with(10_000, Duration::from_secs(900), 2);
    let reference = mint(&store, 502, "connection_failure");
    let now = Instant::now() + Duration::from_secs(1);
    let outside = namespaces(&["staging"]);
    let bound = namespaces(&[NAMESPACE]);

    for subject in ["staging-reader-a", "staging-reader-b"] {
        let first = authorize_lookup(Some(&store), subject, true, &outside, &reference, now);
        assert_eq!(label(&first), "not_found");
        for _ in 0..20 {
            let retry = authorize_lookup(Some(&store), subject, true, &outside, &reference, now);
            assert_eq!(label(&retry), "rate_limited", "subject share spent");
        }
    }

    let operator = authorize_lookup(Some(&store), OPERATOR, true, &bound, &reference, now);
    assert_eq!(label(&operator), "found", "the global budget is untouched");
}

#[test]
fn authorized_subject_over_its_share_is_rate_limited() {
    let store = store_with(10_000, Duration::from_secs(900), 4);
    assert_eq!(store.per_subject_lookup_rate_per_second(), 2);
    let reference = mint(&store, 502, "connection_failure");
    let now = Instant::now() + Duration::from_secs(1);
    let bound = namespaces(&[NAMESPACE]);
    let lookup = || authorize_lookup(Some(&store), OPERATOR, true, &bound, &reference, now);

    assert_eq!(label(&lookup()), "found");
    assert_eq!(label(&lookup()), "found");
    assert_eq!(label(&lookup()), "rate_limited");
}

#[test]
fn a_global_refusal_does_not_spend_the_subject_share() {
    let store = store_with(10_000, Duration::from_secs(900), 2);
    assert_eq!(store.per_subject_lookup_rate_per_second(), 1);
    let now = Instant::now() + Duration::from_secs(1);

    assert!(store.try_acquire_subject_lookup_at(now, "reader-a", true));
    assert!(store.try_acquire_subject_lookup_at(now, "reader-b", true));
    assert!(
        !store.try_acquire_subject_lookup_at(now, "reader-c", true),
        "the global budget is spent"
    );
    assert!(
        store.try_acquire_subject_lookup_at(now, "reader-c", false),
        "the globally refused attempt left reader-c's share intact"
    );
    assert!(!store.try_acquire_subject_lookup_at(now, "reader-c", false));
}

#[test]
fn subject_table_is_bounded_and_fails_closed_when_full() {
    let store = default_store();
    let now = Instant::now() + Duration::from_secs(1);
    for index in 0..MAX_TRACKED_LOOKUP_SUBJECTS {
        let subject = format!("reader-{index}");
        assert!(store.try_acquire_subject_lookup_at(now, &subject, true));
    }
    let overflow = store.try_acquire_subject_lookup_at(now, "one-too-many", true);
    assert!(!overflow, "a full table never evicts a live subject");
    assert!(
        store.try_acquire_subject_lookup_at(now, "reader-0", true),
        "a tracked subject keeps its share"
    );
    let later = now + Duration::from_secs(1);
    assert!(
        store.try_acquire_subject_lookup_at(later, "one-too-many", true),
        "earlier windows are purged to admit a new subject"
    );
}

#[test]
fn out_of_namespace_lookup_never_reads_the_store() {
    // A lookup purges expired entries on the shard it reads, so the expiry
    // counter shows whether the store was read at all.
    let store = store_with(10_000, Duration::from_secs(1), 10_000);
    let start = Instant::now();
    let protocol = DiagnosticProtocol::Http1;
    let reference = store
        .mint_at(start, protocol, 502, "connection_failure", None)
        .unwrap();
    let later = start + Duration::from_secs(5);
    let staging = namespaces(&["staging"]);
    let bound = namespaces(&[NAMESPACE]);

    let other = authorize_lookup(Some(&store), OPERATOR, true, &staging, &reference, later);
    assert_eq!(label(&other), "not_found");
    assert_eq!(store.evicted_expired_total(), 0, "the store was not read");
    let own = authorize_lookup(Some(&store), OPERATOR, true, &bound, &reference, later);
    assert_eq!(label(&own), "not_found");
    assert_eq!(store.evicted_expired_total(), 1);
}

#[test]
fn refused_and_rate_limited_audit_events_are_throttled() {
    let audit = DiagnosticRefLookupAudit::new();
    let start_ms = 10_000;
    for result in [
        DiagnosticRefLookupResult::Forbidden,
        DiagnosticRefLookupResult::RateLimited,
    ] {
        let emitted = (0..100)
            .filter(|offset| audit.admit(result, start_ms + offset).is_some())
            .count();
        assert_eq!(emitted, 1, "{result:?}: one event per window");
        assert_eq!(
            audit.admit(result, start_ms + 1_000),
            Some(99),
            "{result:?}: the next window reports every suppressed event"
        );
    }
    for result in [
        DiagnosticRefLookupResult::Found,
        DiagnosticRefLookupResult::NotFound,
    ] {
        for _ in 0..10 {
            assert_eq!(audit.admit(result, start_ms), Some(0), "{result:?}");
        }
    }
}

// ── detail content ─────────────────────────────────────────────────────────

#[test]
fn detail_carries_closed_classes_and_no_request_material() {
    let shed = with_rejection_phase(summary(503, None), "adaptive_concurrency");
    let detail = DiagnosticDetail::from_summary(&shed, "not_dispatched", None);
    assert_eq!(detail.rejection_phase, Some("concurrency_limit"));
    assert_eq!(detail.error_class, None);
    assert_eq!(detail.proxy_id.as_deref(), Some("orders-api"));
    assert_eq!(
        detail.backend_target.as_deref(),
        Some("https://orders.internal:8443"),
        "userinfo, path, query, and fragment are removed"
    );
    assert_eq!(detail.duration_bucket, "lt_100ms");

    let rendered = serde_json::to_string(&detail).unwrap();
    let request_material = [
        "hunter2",
        "api_key",
        "secret-path",
        "token=abc",
        "203.0.113.7",
        "10.0.0.9",
        "alice",
        "curl/8",
        "/v1/private",
    ];
    for leaked in request_material {
        assert!(!rendered.contains(leaked), "leaked {leaked}: {rendered}");
    }

    let hostile = with_rejection_phase(summary(502, None), "attacker-chosen");
    let hostile_detail = DiagnosticDetail::from_summary(&hostile, "not_dispatched", None);
    assert_eq!(
        hostile_detail.rejection_phase, None,
        "an unknown phase is dropped, never echoed"
    );
}

#[test]
fn backend_origin_keeps_only_scheme_host_and_port() {
    let kept = [
        ("http://127.0.0.1:9/api?x=1", "http://127.0.0.1:9"),
        ("HTTPS://user@[::1]:8443/#x", "https://[::1]:8443"),
        ("orders.internal:8443", "orders.internal:8443"),
    ];
    for (target, origin) in kept {
        assert_eq!(backend_origin(target).as_deref(), Some(origin), "{target}");
    }
    let long_host = format!("http://{}:80/", "a".repeat(400));
    let dropped = [
        "",
        "http://",
        "unix:///var/run/app.sock",
        "http://host name:80/",
        "not a url/with/path",
        "ht tp://host:80",
        long_host.as_str(),
    ];
    for target in dropped {
        assert_eq!(backend_origin(target), None, "{target:?}");
    }
}

#[test]
fn duration_buckets_are_closed() {
    assert_eq!(duration_bucket(-1.0), "unknown");
    assert_eq!(duration_bucket(f64::NAN), "unknown");
    assert_eq!(duration_bucket(0.0), "lt_10ms");
    assert_eq!(duration_bucket(10.0), "lt_100ms");
    assert_eq!(duration_bucket(999.9), "lt_1s");
    assert_eq!(duration_bucket(9_999.0), "lt_10s");
    assert_eq!(duration_bucket(10_000.0), "ge_10s");
}

// ── metrics ────────────────────────────────────────────────────────────────

#[test]
fn prometheus_exposition_names_every_family_with_bounded_labels() {
    let store = store_with(16, Duration::from_secs(900), 10);
    let _ = mint(&store, 502, "backend_error");
    store.record_lookup(DiagnosticRefLookupResult::Found);
    let text = store.render_prometheus();
    let expected = [
        "# TYPE ferrum_diagnostic_ref_lookups_total counter",
        "ferrum_diagnostic_ref_lookups_total{result=\"found\"} 1",
        "ferrum_diagnostic_ref_lookups_total{result=\"not_found\"} 0",
        "ferrum_diagnostic_ref_lookups_total{result=\"forbidden\"} 0",
        "ferrum_diagnostic_ref_lookups_total{result=\"rate_limited\"} 0",
        "# TYPE ferrum_diagnostic_refs_entries gauge",
        "ferrum_diagnostic_refs_entries 1",
        "# TYPE ferrum_diagnostic_refs_evicted_total counter",
        "ferrum_diagnostic_refs_evicted_total{reason=\"capacity\"} 0",
        "ferrum_diagnostic_refs_evicted_total{reason=\"expired\"} 0",
        "# TYPE ferrum_diagnostic_refs_minted_total counter",
        "ferrum_diagnostic_refs_minted_total 1",
    ];
    for line in expected {
        assert!(text.lines().any(|l| l == line), "missing `{line}`:\n{text}");
    }
    assert!(!text.contains("namespace="), "no tenant label");
}

// ── HTTP/3 stamp coverage ──────────────────────────────────────────────────

const STAMP: &str = "crate::diagnostic_ref::stamp_h3_response";

/// Every HTTP/3 response head is stamped: each `send_response(..)` site in
/// `src/http3` is preceded by the `stamp_h3_response` rebinding of the head it
/// writes, so a new writer cannot ship a gateway-error head without its
/// reference (or with a plugin-forged one).
#[test]
fn every_http3_response_head_is_stamped() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/http3");
    let mut sites = 0;
    for entry in std::fs::read_dir(&dir).expect("read src/http3") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read http3 source");
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            let Some(start) = code.find(".send_response(") else {
                continue;
            };
            let argument = &code[start + ".send_response(".len()..];
            let Some(end) = argument.find(')') else {
                continue;
            };
            let value = &argument[..end];
            let stamp = format!("let {value} = {STAMP}({value});");
            let window = &lines[index.saturating_sub(12)..index];
            assert!(
                window.iter().any(|prior| prior.trim() == stamp),
                "{}:{}: `{}` is not stamped",
                path.display(),
                index + 1,
                code
            );
            sites += 1;
        }
    }
    assert!(sites >= 17, "only {sites} HTTP/3 head writes");
}

// ── `all` mode, rejection detail, and attempts (issue #5846) ───────────────

fn all_mode_store() -> DiagnosticRefStore {
    default_store().with_mode(DiagnosticRefMode::All)
}

fn rejection_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers
}

fn plugin_rejected_slot(phase: &str, plugin: &str, status: u16) -> std::sync::Arc<DiagnosticSlot> {
    let slot = DiagnosticSlot::shared();
    slot.note_rejecting_plugin(plugin);
    slot.record_rejection(DiagnosticRejection::new(
        phase,
        slot.rejecting_plugin(),
        status,
    ));
    slot
}

#[test]
fn store_mode_defaults_to_errors_and_off_never_widens_it() {
    assert_eq!(default_store().mode(), DiagnosticRefMode::Errors);
    assert_eq!(all_mode_store().mode(), DiagnosticRefMode::All);
    let off = default_store().with_mode(DiagnosticRefMode::Off);
    assert_eq!(off.mode(), DiagnosticRefMode::Errors);
}

#[test]
fn all_mode_stamps_a_recorded_rejection_without_a_gateway_error_token() {
    let store = all_mode_store();
    let slot = plugin_rejected_slot("authenticate", "key_auth", 401);
    let mut headers = rejection_headers();
    headers.insert(DIAGNOSTIC_REF_HEADER, UNKNOWN_REF.parse().unwrap());

    let stamped = stamp_response_headers(
        &store,
        Some(&slot),
        DiagnosticProtocol::Http2,
        401,
        &mut headers,
    )
    .expect("a recorded plugin rejection is referenced in `all` mode");

    let values: Vec<_> = headers.get_all(DIAGNOSTIC_REF_HEADER).iter().collect();
    assert_eq!(values.len(), 1, "exactly one reference reaches the client");
    assert_eq!(values[0].to_str().unwrap(), stamped);
    assert!(!headers.contains_key("x-gateway-error"));
    let view = store.lookup_at(Instant::now(), &stamped).unwrap();
    assert_eq!(view.gateway_error, None);
    assert_eq!(view.status, 401);
    assert_eq!(slot.minted_ref(), Some(stamped.as_str()));
    let body = serde_json::to_value(&view).unwrap();
    assert!(body["gateway_error"].is_null(), "{body}");
}

#[test]
fn errors_mode_never_stamps_a_rejection_without_a_gateway_error_token() {
    let store = default_store();
    let slot = plugin_rejected_slot("authorize", "access_control", 403);
    let mut headers = rejection_headers();
    headers.insert(DIAGNOSTIC_REF_HEADER, UNKNOWN_REF.parse().unwrap());
    let stamped = stamp_response_headers(
        &store,
        Some(&slot),
        DiagnosticProtocol::Http1,
        403,
        &mut headers,
    );
    assert!(stamped.is_none(), "`errors` keeps its #5767 contract");
    assert!(!headers.contains_key(DIAGNOSTIC_REF_HEADER));
    assert_eq!(store.minted_total(), 0);

    // A gateway-error response is still referenced exactly as before.
    let mut gateway_error = gateway_error_headers("overload");
    let stamped = stamp_response_headers(
        &store,
        Some(&slot),
        DiagnosticProtocol::Http1,
        503,
        &mut gateway_error,
    );
    assert!(stamped.is_some());
}

#[test]
fn all_mode_leaves_responses_without_a_recorded_rejection_unmarked() {
    let store = all_mode_store();
    // A backend's own error relayed to the client: nothing recorded a
    // gateway rejection in the request's slot.
    let relayed = DiagnosticSlot::shared();
    for status in [400u16, 404, 429, 500, 503] {
        let mut headers = rejection_headers();
        headers.insert(DIAGNOSTIC_REF_HEADER, UNKNOWN_REF.parse().unwrap());
        let stamped = stamp_response_headers(
            &store,
            Some(&relayed),
            DiagnosticProtocol::Http1,
            status,
            &mut headers,
        );
        assert!(stamped.is_none(), "{status}: backend-authored");
        assert!(!headers.contains_key(DIAGNOSTIC_REF_HEADER), "{status}");
    }
    // No slot at all (a head written outside a request task).
    let mut headers = rejection_headers();
    assert!(stamp(&store, DiagnosticProtocol::Http3, 404, &mut headers).is_none());
    // A recorded rejection whose response is a success (a plugin
    // short-circuit answering 2xx) is not an error response.
    let short_circuit = plugin_rejected_slot("before_proxy", "request_termination", 200);
    let mut headers = rejection_headers();
    let stamped = stamp_response_headers(
        &store,
        Some(&short_circuit),
        DiagnosticProtocol::Http1,
        200,
        &mut headers,
    );
    assert!(stamped.is_none());
    assert_eq!(store.minted_total(), 0);
}

#[test]
fn all_mode_stamps_grpc_trailers_only_rejections() {
    let store = all_mode_store();
    let slot = plugin_rejected_slot("authenticate", "jwt_auth", 200);
    let mut headers = rejection_headers();
    headers.insert("grpc-status", "16".parse().unwrap());
    let stamped = stamp_response_headers(
        &store,
        Some(&slot),
        DiagnosticProtocol::Http2,
        200,
        &mut headers,
    );
    assert!(stamped.is_some(), "grpc-status 16 is an error response");

    let ok = plugin_rejected_slot("before_proxy", "request_termination", 200);
    let mut headers = rejection_headers();
    headers.insert("grpc-status", "0".parse().unwrap());
    let stamped = stamp_response_headers(
        &store,
        Some(&ok),
        DiagnosticProtocol::Http2,
        200,
        &mut headers,
    );
    assert!(stamped.is_none(), "grpc-status 0 is a success");
}

#[test]
fn error_response_classification_is_status_or_grpc_status() {
    use ferrum_edge::diagnostic_ref::is_error_response;
    let empty = http::HeaderMap::new();
    assert!(!is_error_response(200, &empty));
    assert!(!is_error_response(304, &empty));
    assert!(is_error_response(400, &empty));
    assert!(is_error_response(599, &empty));
    let mut grpc = http::HeaderMap::new();
    grpc.insert("grpc-status", "7".parse().unwrap());
    assert!(is_error_response(200, &grpc));
    grpc.insert("grpc-status", " 0 ".parse().unwrap());
    assert!(!is_error_response(200, &grpc));
}

#[test]
fn rejection_detail_carries_only_bounded_labels() {
    let plugin = DiagnosticRejection::new("authorize", Some("access_control"), 403);
    assert_eq!(plugin.source, DiagnosticRejectionSource::Plugin);
    assert_eq!(plugin.phase, "authorize");
    assert_eq!(plugin.plugin.as_deref(), Some("access_control"));
    assert_eq!(plugin.status, 403);
    // A built-in plugin's name is its own static label, never a copy.
    let borrowed = matches!(plugin.plugin, Some(Cow::Borrowed(_)));
    assert!(borrowed, "{:?}", plugin.plugin);
    // A custom plugin's short label is kept.
    let custom = DiagnosticRejection::new("before_proxy", Some("acme_custom-gate"), 429);
    assert_eq!(custom.plugin.as_deref(), Some("acme_custom-gate"));

    let hook_without_plugin = DiagnosticRejection::new("authenticate", None, 401);
    assert_eq!(
        hook_without_plugin.source,
        DiagnosticRejectionSource::Plugin
    );
    assert_eq!(hook_without_plugin.plugin, None);

    let fence = DiagnosticRejection::new("websocket_connection_limit", None, 429);
    assert_eq!(fence.source, DiagnosticRejectionSource::Gateway);
    let routing = DiagnosticRejection::routing("route_not_found", 404);
    assert_eq!(routing.source, DiagnosticRejectionSource::Routing);
    assert_eq!(routing.phase, "route_not_found");
    let admission = DiagnosticRejection::gateway_fence("overload", 503);
    assert_eq!(admission.phase, "overload");

    // The phase is a closed set: a well-formed label the gateway does not
    // ship is `other`, exactly like free text.
    let unlisted = DiagnosticRejection::new("made_up_phase", None, 400);
    assert_eq!(unlisted.phase, "other");
    assert_eq!(unlisted.source, DiagnosticRejectionSource::Gateway);
    let long_plugin = "p".repeat(65);
    let hostile = DiagnosticRejection::new(
        "phase /orders?token=abc",
        Some("Bearer eyJhbGciOiJIUzI1NiJ9"),
        401,
    );
    assert_eq!(hostile.phase, "other", "free text is never echoed");
    assert_eq!(hostile.plugin, None, "free text is never echoed");
    let too_long = DiagnosticRejection::new(&"x".repeat(65), Some(long_plugin.as_str()), 400);
    assert_eq!(too_long.phase, "other");
    assert_eq!(too_long.plugin, None);

    // The status is kept for the stamp, never rendered in the detail.
    let rendered = serde_json::to_value(&plugin).unwrap();
    assert_eq!(rendered["source"], "plugin");
    let without_plugin = serde_json::to_value(&fence).unwrap();
    let keys: HashSet<&str> = without_plugin
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, HashSet::from(["source", "phase"]));

    let slot = DiagnosticSlot::shared();
    slot.note_rejecting_plugin("bad name with spaces");
    assert_eq!(slot.rejecting_plugin(), None);
}

#[test]
fn errors_mode_detail_shape_is_unchanged_without_rejection_or_attempts() {
    let detail = DiagnosticDetail::from_summary(
        &summary(502, Some(ErrorClass::ConnectionRefused)),
        "pre_wire_failure",
        None,
    );
    let body = serde_json::to_value(&detail).unwrap();
    let keys: HashSet<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected = HashSet::from([
        "error_class",
        "body_error_class",
        "rejection_phase",
        "route_timeout_phase",
        "backend_dispatch",
        "proxy_id",
        "backend_target",
        "duration_bucket",
    ]);
    assert_eq!(keys, expected);
}

#[test]
fn attempts_are_ordered_bounded_and_carry_tls_detail() {
    let store = default_store();
    let slot = DiagnosticSlot::shared();
    let protocol = DiagnosticProtocol::Http1;
    let reference = store
        .mint(protocol, 502, "connection_failure", Some(&slot))
        .unwrap();
    let expired = DiagnosticTlsDetail {
        failure: "certificate_verification",
        reason: Some("expired"),
    };

    // A TLS failure keeps its noted detail; a status is never recorded for a
    // failed attempt.
    slot.note_tls_failure(expired);
    slot.record_attempt(Some(ErrorClass::TlsError), false, Some(502));
    // A noted detail is discarded when the attempt is not a TLS failure.
    slot.note_tls_failure(expired);
    slot.record_attempt(Some(ErrorClass::ConnectionRefused), false, None);
    // A backend response keeps its status.
    slot.record_attempt(None, true, Some(503));
    // A post-wire failure is ambiguous.
    slot.record_attempt(Some(ErrorClass::ReadWriteTimeout), true, None);

    let (attempts, omitted) = slot.attempts();
    assert_eq!(omitted, 0);
    assert_eq!(attempts.len(), 4);
    let numbers: Vec<u32> = attempts.iter().map(|attempt| attempt.attempt).collect();
    assert_eq!(numbers, [1, 2, 3, 4]);
    assert_eq!(attempts[0].backend_dispatch, "pre_wire_failure");
    assert_eq!(attempts[0].error_class, Some("tls_error"));
    assert_eq!(attempts[0].status, None);
    assert_eq!(attempts[0].tls, Some(expired));
    assert_eq!(attempts[1].error_class, Some("connection_refused"));
    assert_eq!(attempts[1].tls, None);
    assert_eq!(attempts[2].backend_dispatch, "backend_response");
    assert_eq!(attempts[2].status, Some(503));
    assert_eq!(attempts[2].error_class, None);
    assert_eq!(attempts[3].backend_dispatch, "ambiguous_failure");

    // The lookup only shows attempts once the detail is recorded.
    let pending = store.lookup_at(Instant::now(), &reference).unwrap();
    assert!(pending.detail.is_none());
    let refused = summary(502, Some(ErrorClass::ConnectionRefused));
    slot.record_detail(DiagnosticDetail::from_summary(
        &refused,
        "ambiguous_failure",
        None,
    ));

    // Later attempts are counted, never retained.
    for _ in 0..(MAX_RECORDED_ATTEMPTS + 3) {
        slot.record_attempt(Some(ErrorClass::ConnectionRefused), false, None);
    }
    let view = store.lookup_at(Instant::now(), &reference).unwrap();
    let detail = view.detail.expect("detail recorded");
    assert_eq!(detail.attempts.len(), MAX_RECORDED_ATTEMPTS);
    // 4 + MAX + 3 attempts recorded, MAX retained.
    let omitted = 7u32;
    assert_eq!(detail.attempts_omitted, omitted);
    let body = serde_json::to_value(&detail).unwrap();
    assert_eq!(
        body["attempts"][0]["tls"]["failure"],
        "certificate_verification"
    );
    assert_eq!(body["attempts"][0]["tls"]["reason"], "expired");
    assert!(body["attempts"][1].get("tls").is_none(), "{body}");
    assert!(body["attempts"][1].get("status").is_none(), "{body}");
    assert_eq!(body["attempts_omitted"], omitted);
}

#[test]
fn tls_detail_maps_rustls_errors_to_closed_labels() {
    use rustls::{AlertDescription, CertificateError, Error};
    let cases = [
        (
            Error::InvalidCertificate(CertificateError::Expired),
            "certificate_verification",
            Some("expired"),
        ),
        (
            Error::InvalidCertificate(CertificateError::UnknownIssuer),
            "certificate_verification",
            Some("unknown_issuer"),
        ),
        (
            Error::InvalidCertificate(CertificateError::NotValidForName),
            "certificate_verification",
            Some("not_valid_for_name"),
        ),
        (
            Error::InvalidCertificate(CertificateError::Revoked),
            "certificate_verification",
            Some("revoked"),
        ),
        (
            Error::AlertReceived(AlertDescription::UnknownCA),
            "alert_received",
            Some("unknown_ca"),
        ),
        (
            Error::AlertReceived(AlertDescription::HandshakeFailure),
            "alert_received",
            Some("handshake_failure"),
        ),
        (
            Error::AlertReceived(AlertDescription::CertificateRequired),
            "alert_received",
            Some("certificate_required"),
        ),
        (
            Error::NoCertificatesPresented,
            "no_certificates_presented",
            None,
        ),
        (Error::DecryptError, "decrypt_error", None),
        (
            Error::NoApplicationProtocol,
            "no_application_protocol",
            None,
        ),
        (Error::General("secret-host.internal".into()), "other", None),
    ];
    for (error, failure, reason) in cases {
        let detail = tls_detail_from_rustls(&error);
        assert_eq!(detail.failure, failure, "{error:?}");
        assert_eq!(detail.reason, reason, "{error:?}");
        let rendered = serde_json::to_string(&detail).unwrap();
        assert!(!rendered.contains("secret-host"), "{rendered}");
    }

    // The typed error is found through an `io::Error` wrapper, as rustls
    // failures reach the dispatch paths.
    let wrapped = std::io::Error::other(Error::InvalidCertificate(CertificateError::BadSignature));
    let detail = tls_detail(&wrapped).expect("rustls error in the chain");
    assert_eq!(detail.reason, Some("bad_signature"));
    let plain = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    assert_eq!(tls_detail(&plain), None);
}

#[test]
fn request_context_records_attempts_into_its_slot_only() {
    use ferrum_edge::_test_support::{
        record_backend_attempt_for_test, set_diagnostic_slot_for_test,
    };
    use ferrum_edge::plugins::RequestContext;

    // Without a slot (references off) recording is a no-op.
    let ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    record_backend_attempt_for_test(&ctx, None, true, Some(200));

    let slot = DiagnosticSlot::shared();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    set_diagnostic_slot_for_test(&mut ctx, std::sync::Arc::clone(&slot));
    record_backend_attempt_for_test(&ctx, Some(ErrorClass::ConnectionRefused), false, None);
    // A context clone shares the request's slot.
    let clone = ctx.clone();
    record_backend_attempt_for_test(&clone, None, true, Some(200));
    let (attempts, _) = slot.attempts();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].status, Some(200));
}

/// A request context carrying `slot`, as the HTTP frontends build one when
/// references are enabled.
fn context_with_slot(
    slot: &std::sync::Arc<DiagnosticSlot>,
) -> ferrum_edge::plugins::RequestContext {
    use ferrum_edge::_test_support::set_diagnostic_slot_for_test;

    let mut ctx =
        ferrum_edge::plugins::RequestContext::new("203.0.113.7".into(), "GET".into(), "/".into());
    set_diagnostic_slot_for_test(&mut ctx, std::sync::Arc::clone(slot));
    ctx
}

async fn log_rejection(ctx: &ferrum_edge::plugins::RequestContext, status: u16, phase: &str) {
    ferrum_edge::proxy::log_rejected_request(&[], ctx, status, Instant::now(), phase, 0).await;
}

// No store is installed in this process, so the funnel sees `errors`-mode
// gating: only a `5xx` rejection is recorded. `all` mode is exercised end to
// end by the functional tests.
#[tokio::test]
async fn rejection_log_funnel_records_the_rejecting_phase_and_plugin() {
    let slot = DiagnosticSlot::shared();
    let ctx = context_with_slot(&slot);
    slot.note_rejecting_plugin("rate_limiting");
    log_rejection(&ctx, 503, "before_proxy").await;
    let rejection = slot.rejection().expect("funnel recorded the rejection");
    assert_eq!(rejection.source, DiagnosticRejectionSource::Plugin);
    assert_eq!(rejection.phase, "before_proxy");
    assert_eq!(rejection.plugin.as_deref(), Some("rate_limiting"));
    assert_eq!(rejection.status, 503);
    assert!(slot.authored_status(503));
    assert!(!slot.authored_status(200));

    let fence_slot = DiagnosticSlot::shared();
    let fence_ctx = context_with_slot(&fence_slot);
    log_rejection(&fence_ctx, 503, "circuit_breaker_open").await;
    let rejection = fence_slot.rejection().expect("gateway fence recorded");
    assert_eq!(rejection.source, DiagnosticRejectionSource::Gateway);
    assert_eq!(rejection.phase, "circuit_breaker_open");
    assert_eq!(rejection.plugin, None);

    // The recorded phase is a compiled-in label, whatever the caller passed.
    let unlisted_slot = DiagnosticSlot::shared();
    let unlisted_ctx = context_with_slot(&unlisted_slot);
    log_rejection(&unlisted_ctx, 500, "operator-configured-policy-name").await;
    let rejection = unlisted_slot.rejection().expect("rejection recorded");
    assert_eq!(rejection.phase, "other");
}

// Outside `all` mode a `4xx` rejection can never carry a reference (it has no
// `X-Gateway-Error`), so the funnel does no rejection bookkeeping for it.
#[tokio::test]
async fn rejection_log_funnel_skips_client_error_bookkeeping_outside_all_mode() {
    let slot = DiagnosticSlot::shared();
    let ctx = context_with_slot(&slot);
    slot.note_rejecting_plugin("key_auth");
    log_rejection(&ctx, 401, "authenticate").await;
    assert!(slot.rejection().is_none());
    assert!(!slot.authored_status(401));
}

// A plugin that answered with an origin-authored representation (a cache
// hit, a replay, a serverless terminate reply, a provider response) authored
// no gateway rejection, whatever the status.
#[tokio::test]
async fn origin_representations_are_never_recorded_as_rejections() {
    use ferrum_edge::_test_support::set_serverless_terminate_response_for_test;

    // Marked by the rejecting plugin itself (`rejects_with_origin_response`).
    let slot = DiagnosticSlot::shared();
    let ctx = context_with_slot(&slot);
    slot.note_rejecting_plugin("response_caching");
    slot.note_origin_response();
    log_rejection(&ctx, 503, "before_proxy").await;
    assert!(slot.rejection().is_none(), "a cached backend 503");
    assert!(!slot.authored_status(503));

    // Marked on the request by a plugin whose short-circuit is origin content
    // on this path only.
    let slot = DiagnosticSlot::shared();
    let mut ctx = context_with_slot(&slot);
    set_serverless_terminate_response_for_test(&mut ctx, true);
    log_rejection(&ctx, 502, "before_proxy").await;
    assert!(slot.rejection().is_none(), "a serverless function's 502");
}

// An origin-authored representation a plugin replayed (a `response_caching`
// HIT of a stored backend `502`) is never stamped, in `errors` mode as in
// `all`, even when it carries an `X-Gateway-Error` token (issue #5860). A
// gateway-authored `502` on an unmarked slot still is, on every protocol.
#[test]
fn origin_representations_are_never_stamped_in_any_mode() {
    let protocols = [
        DiagnosticProtocol::Http1,
        DiagnosticProtocol::Http2,
        DiagnosticProtocol::Http3,
    ];
    for store in [default_store(), all_mode_store()] {
        let mode = store.mode();
        for protocol in protocols {
            let replayed = DiagnosticSlot::shared();
            replayed.note_rejecting_plugin("response_caching");
            replayed.note_origin_response();
            let mut headers = gateway_error_headers("backend_error");
            headers.insert(DIAGNOSTIC_REF_HEADER, UNKNOWN_REF.parse().unwrap());
            let stamped =
                stamp_response_headers(&store, Some(&replayed), protocol, 502, &mut headers);
            assert!(stamped.is_none(), "{mode:?}/{protocol:?}: a cached 502");
            assert!(
                !headers.contains_key(DIAGNOSTIC_REF_HEADER),
                "{mode:?}/{protocol:?}: the forged copy is still stripped"
            );
            assert!(headers.contains_key("x-gateway-error"));
            assert_eq!(replayed.minted_ref(), None);

            let generated = DiagnosticSlot::shared();
            let mut headers = gateway_error_headers("connection_failure");
            let stamped =
                stamp_response_headers(&store, Some(&generated), protocol, 502, &mut headers);
            assert!(
                stamped.is_some(),
                "{mode:?}/{protocol:?}: a gateway-generated 502 is referenced"
            );
        }
        assert_eq!(store.minted_total(), protocols.len() as u64, "{mode:?}");
    }
}

// A replay the request itself marks (an idempotent replay, a serverless
// terminate reply) reaches the stamp through the rejection-log funnel, which
// carries the marker into the slot whatever the status and mode.
#[tokio::test]
async fn rejection_funnel_carries_request_origin_markers_into_the_slot() {
    use ferrum_edge::_test_support::set_serverless_terminate_response_for_test;

    let store = default_store();
    for status in [502u16, 404] {
        let slot = DiagnosticSlot::shared();
        let mut ctx = context_with_slot(&slot);
        set_serverless_terminate_response_for_test(&mut ctx, true);
        log_rejection(&ctx, status, "before_proxy").await;
        assert!(slot.serves_origin_response(), "{status}");
        assert!(slot.rejection().is_none(), "{status}");
        let mut headers = gateway_error_headers("backend_error");
        let stamped = stamp_response_headers(
            &store,
            Some(&slot),
            DiagnosticProtocol::Http2,
            status,
            &mut headers,
        );
        assert!(stamped.is_none(), "{status}");
    }
    // An ordinary gateway rejection leaves the slot unmarked.
    let slot = DiagnosticSlot::shared();
    let ctx = context_with_slot(&slot);
    log_rejection(&ctx, 503, "circuit_breaker_open").await;
    assert!(!slot.serves_origin_response());
    assert_eq!(store.minted_total(), 0);
}

#[tokio::test]
async fn origin_response_plugins_declare_it() {
    let caching = ferrum_edge::plugins::create_plugin("response_caching", &serde_json::json!({}))
        .expect("valid response_caching config")
        .expect("built-in plugin");
    assert!(caching.rejects_with_origin_response());
}

#[test]
fn all_mode_stamps_only_the_status_the_rejection_authored() {
    let store = all_mode_store();
    // A plugin rejected with 401, but the head that reached the client
    // carries another status: the rejection did not author it.
    let slot = plugin_rejected_slot("authenticate", "key_auth", 401);
    for status in [404u16, 500, 502] {
        let mut headers = rejection_headers();
        let stamped = stamp_response_headers(
            &store,
            Some(&slot),
            DiagnosticProtocol::Http1,
            status,
            &mut headers,
        );
        assert!(stamped.is_none(), "{status}");
        assert!(!headers.contains_key(DIAGNOSTIC_REF_HEADER), "{status}");
    }
    assert_eq!(store.minted_total(), 0);

    let mut headers = rejection_headers();
    let stamped = stamp_response_headers(
        &store,
        Some(&slot),
        DiagnosticProtocol::Http1,
        401,
        &mut headers,
    );
    assert!(stamped.is_some());
}

/// Every routing `404` and admission fence records its rejection before the
/// response head is written, on HTTP/1.1, HTTP/2, and HTTP/3, and every plugin
/// or gateway rejection passes through the shared rejection-log funnel.
#[test]
fn routing_misses_and_admission_fences_record_their_rejection() {
    // How many lines after counting a fence's status its diagnostic rejection
    // must be recorded.
    const FENCE_WINDOW: usize = 6;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |file: &str| std::fs::read_to_string(root.join(file)).expect("read source");
    let proxy = read("src/proxy/mod.rs");
    let h3 = read("src/http3/server.rs");

    // Every error status the frontend admission wrapper counts is a fence,
    // and each records its diagnostic rejection right after counting it.
    let start = proxy
        .find("async fn admit_proxy_request_on_frontend_port(")
        .expect("admission wrapper");
    let wrapper = &proxy[start..];
    let len = wrapper.find("\n}\n").expect("admission wrapper end");
    let lines: Vec<&str> = wrapper[..len].lines().collect();
    let mut fences = 0;
    for (index, line) in lines.iter().enumerate() {
        let Some(rest) = line.trim().strip_prefix("record_request(&state, ") else {
            continue;
        };
        let status: u16 = rest.trim_end_matches(");").parse().expect("status");
        if status < 400 {
            continue;
        }
        let window_end = (index + 1 + FENCE_WINDOW).min(lines.len());
        let records_fence = lines[index + 1..window_end]
            .iter()
            .any(|next| next.contains("diagnostic_ref::record_admission_fence("));
        assert!(
            records_fence,
            "admission fence `record_request(&state, {status})` records no diagnostic rejection"
        );
        fences += 1;
    }
    assert!(fences >= 4, "only {fences} admission fences found");

    let route_miss = "diagnostic_ref::ROUTE_NOT_FOUND_PHASE,";
    let registry_miss = "diagnostic_ref::MESH_REGISTRY_ONLY_PHASE,";
    let funnel = "diagnostic_ref::record_rejection(ctx, rejection_phase, status_code);";
    let expectations = [
        ("src/proxy/mod.rs", &proxy, route_miss, 1),
        ("src/proxy/mod.rs", &proxy, registry_miss, 1),
        ("src/proxy/mod.rs", &proxy, funnel, 1),
        ("src/http3/server.rs", &h3, route_miss, 1),
    ];
    for (file, source, needle, expected) in expectations {
        let found = source.matches(needle).count();
        assert_eq!(found, expected, "{file}: `{needle}`");
    }
    // The funnel records before its no-consumer early return.
    let start = proxy
        .find("async fn log_rejected_request_with_path_and_backend_state(")
        .expect("rejection-log funnel");
    let body = &proxy[start..];
    let record = body.find(funnel).expect("funnel records the rejection");
    let early_return = body
        .find("if plugins.is_empty() && !diagnostic_detail_wanted {")
        .expect("no-consumer early return");
    assert!(record < early_return);
}

// ── cross-replica lookup (issue #5846) ─────────────────────────────────────

const REPLICA_A: DiagnosticReplicaId = DiagnosticReplicaId::from_bytes([0x1a, 0x2b, 0x3c, 0x4d]);
const REPLICA_B: DiagnosticReplicaId = DiagnosticReplicaId::from_bytes([0xf0, 0x0d, 0xca, 0xfe]);

fn tagged_store(replica: DiagnosticReplicaId) -> DiagnosticRefStore {
    default_store().with_replica(replica)
}

#[test]
fn replica_tagged_references_embed_only_the_replica_id() {
    let store = tagged_store(REPLICA_A);
    assert_eq!(store.replica(), Some(REPLICA_A));
    assert_eq!(REPLICA_A.to_hex(), "1a2b3c4d");
    assert_eq!(REPLICA_A.to_hex().len(), REPLICA_ID_HEX_LEN);
    let mut seen = HashSet::new();
    for _ in 0..500 {
        let reference = mint(&store, 502, "connection_failure");
        assert_eq!(reference.len(), DIAGNOSTIC_REF_TAGGED_LEN, "{reference}");
        let rest = reference
            .strip_prefix(DIAGNOSTIC_REF_TAGGED_PREFIX)
            .expect("tagged prefix");
        let (replica, key) = rest.split_once('_').expect("replica separator");
        assert_eq!(replica, "1a2b3c4d");
        assert_eq!(key.len(), 32, "128 bits of randomness");
        assert!(!reference.contains(NAMESPACE));
        assert!(!reference.contains("connection_failure"));
        assert!(is_well_formed_ref(&reference));
        assert_eq!(reference_replica(&reference), Some(REPLICA_A));
        assert!(seen.insert(key.to_string()), "keys must never repeat");
    }
}

#[test]
fn untagged_store_keeps_the_fd1_format_and_names_no_replica() {
    let store = default_store();
    assert_eq!(store.replica(), None);
    let reference = mint(&store, 502, "connection_failure");
    assert!(reference.starts_with(DIAGNOSTIC_REF_PREFIX));
    assert_eq!(reference.len(), DIAGNOSTIC_REF_LEN);
    assert_eq!(reference_replica(&reference), None);
    assert_eq!(store.foreign_owner(&reference), None);
    let view = store.lookup_at(Instant::now(), &reference).unwrap();
    assert_eq!(view.replica_id, None);
    let body = serde_json::to_value(&view).unwrap();
    assert!(body.get("replica_id").is_none(), "fd1 body is unchanged");
}

#[test]
fn malformed_tagged_references_never_resolve_or_name_an_owner() {
    let owner = tagged_store(REPLICA_A);
    let other = tagged_store(REPLICA_B);
    let good = mint(&owner, 503, "overload");
    let now = Instant::now();
    assert!(owner.lookup_at(now, &good).is_some());

    let key = &good[good.len() - 32..];
    let upper_replica = format!("{DIAGNOSTIC_REF_TAGGED_PREFIX}1A2B3C4D_{key}");
    let key_upper = key.to_uppercase();
    let upper_key = format!("{DIAGNOSTIC_REF_TAGGED_PREFIX}1a2b3c4d_{key_upper}");
    let other_separator = format!("{DIAGNOSTIC_REF_TAGGED_PREFIX}1a2b3c4d-{key}");
    let no_separator = format!("{DIAGNOSTIC_REF_TAGGED_PREFIX}1a2b3c4d{key}0");
    let short_replica = format!("{DIAGNOSTIC_REF_TAGGED_PREFIX}1a2b3c_{key}00");
    let v1_prefix = format!("{DIAGNOSTIC_REF_PREFIX}1a2b3c4d_{key}");
    let non_hex_replica = format!("{DIAGNOSTIC_REF_TAGGED_PREFIX}1a2b3c4g_{key}");
    let short = good[..good.len() - 1].to_string();
    let long = format!("{good}0");
    let malformed = [
        upper_replica.as_str(),
        upper_key.as_str(),
        other_separator.as_str(),
        no_separator.as_str(),
        short_replica.as_str(),
        v1_prefix.as_str(),
        non_hex_replica.as_str(),
        short.as_str(),
        long.as_str(),
        "fd2_",
    ];
    for bad in malformed {
        assert!(!is_well_formed_ref(bad), "{bad:?}");
        assert_eq!(reference_replica(bad), None, "{bad:?}");
        assert!(owner.lookup_at(now, bad).is_none(), "{bad:?}");
        assert_eq!(other.foreign_owner(bad), None, "{bad:?}");
    }
}

#[test]
fn owned_tagged_lookup_resolves_with_its_replica_id() {
    let store = tagged_store(REPLICA_A);
    let reference = mint(&store, 502, "connection_failure");
    let reader = namespaces(&[NAMESPACE]);
    let now = Instant::now();
    match authorize_lookup(Some(&store), OPERATOR, true, &reader, &reference, now) {
        DiagnosticRefLookup::Found(view) => {
            assert_eq!(view.reference, reference);
            assert_eq!(view.replica_id.as_deref(), Some("1a2b3c4d"));
            let body = serde_json::to_value(&*view).unwrap();
            assert_eq!(body["replica_id"], "1a2b3c4d");
            assert_eq!(body["schema_version"], DIAGNOSTIC_REF_SCHEMA_VERSION);
        }
        other => panic!("owned lookup must resolve, got {other:?}"),
    }
    assert_eq!(store.foreign_owner(&reference), None, "own reference");
    assert_eq!(store.lookups_total(DiagnosticRefLookupResult::Found), 1);
}

#[test]
fn non_owned_lookup_is_a_miss_with_the_owner_hint_only_when_authorized() {
    let owner = tagged_store(REPLICA_A);
    let peer = tagged_store(REPLICA_B);
    let reference = mint(&owner, 502, "connection_failure");
    let now = Instant::now();
    let reader = namespaces(&[NAMESPACE]);

    // The other replica never resolves it, even for the right caller...
    assert!(peer.lookup_at(now, &reference).is_none());
    // ...and names the owner only on the fully authorized path.
    let hinted = authorize_lookup(Some(&peer), OPERATOR, true, &reader, &reference, now);
    match &hinted {
        DiagnosticRefLookup::NotOwned(replica) => assert_eq!(*replica, REPLICA_A),
        other => panic!("expected the owner hint, got {other:?}"),
    }
    assert_eq!(
        hinted.result(),
        DiagnosticRefLookupResult::NotFound,
        "a non-owned lookup is counted and audited as a miss"
    );

    let unbound = AllowedNamespaces::empty();
    let refusals = [
        authorize_lookup(Some(&peer), OPERATOR, false, &reader, &reference, now),
        authorize_lookup(Some(&peer), OPERATOR, true, &unbound, &reference, now),
    ];
    let labels: Vec<&str> = refusals.iter().map(label).collect();
    assert_eq!(labels, ["missing_scope", "missing_namespace_binding"]);

    assert_eq!(peer.lookups_total(DiagnosticRefLookupResult::NotFound), 1);
    assert_eq!(peer.lookups_total(DiagnosticRefLookupResult::Forbidden), 2);
    assert_eq!(peer.lookups_total(DiagnosticRefLookupResult::Found), 0);
}

#[test]
fn non_owned_lookup_never_hints_across_namespaces() {
    let owner = tagged_store(REPLICA_A);
    let peer = tagged_store(REPLICA_B);
    let reference = mint(&owner, 502, "connection_failure");
    let now = Instant::now();
    let staging = namespaces(&["staging"]);

    let cross = authorize_lookup(Some(&peer), OPERATOR, true, &staging, &reference, now);
    let unknown = authorize_lookup(Some(&peer), OPERATOR, true, &staging, UNKNOWN_REF, now);
    assert_eq!(label(&cross), "not_found", "no cross-namespace hint");
    assert_eq!(label(&unknown), "not_found");

    // A store in another namespace never hints for a caller bound only to the
    // owner's namespace either: the answering store's namespace gates it.
    let elsewhere = DiagnosticRefStore::new("staging", DiagnosticRefStoreConfig::default())
        .with_replica(REPLICA_B);
    let reader = namespaces(&[NAMESPACE]);
    let other_ns = authorize_lookup(Some(&elsewhere), OPERATOR, true, &reader, &reference, now);
    assert_eq!(label(&other_ns), "not_found");

    // Feature off on the answering process: no store, no namespace, no hint.
    let off = authorize_lookup(None, OPERATOR, true, &reader, &reference, now);
    assert_eq!(label(&off), "not_found");
}

#[test]
fn own_expired_or_unknown_tagged_reference_is_a_plain_miss() {
    let store = store_with(10_000, Duration::from_secs(5), 10_000);
    let store = store.with_replica(REPLICA_A);
    let start = Instant::now();
    let reference = store
        .mint_at(
            start,
            DiagnosticProtocol::Http2,
            504,
            "backend_timeout",
            None,
        )
        .unwrap();
    let reader = namespaces(&[NAMESPACE]);
    let later = start + Duration::from_secs(6);
    let expired = authorize_lookup(Some(&store), OPERATOR, true, &reader, &reference, later);
    assert_eq!(label(&expired), "not_found", "no hint at itself");

    let unknown_own = format!("{DIAGNOSTIC_REF_TAGGED_PREFIX}1a2b3c4d_{}", "0".repeat(32));
    let unknown = authorize_lookup(Some(&store), OPERATOR, true, &reader, &unknown_own, start);
    assert_eq!(label(&unknown), "not_found");
}

#[test]
fn reference_formats_resolve_only_on_a_store_that_mints_them() {
    let untagged = default_store();
    let tagged = tagged_store(REPLICA_A);
    let v1 = mint(&untagged, 502, "connection_failure");
    let v2 = mint(&tagged, 502, "connection_failure");
    let now = Instant::now();
    let reader = namespaces(&[NAMESPACE]);

    // Old references still resolve on the replica that minted them.
    assert!(untagged.lookup_at(now, &v1).is_some());
    assert!(tagged.lookup_at(now, &v2).is_some());

    // The same random key in the other format is a different reference.
    let v1_as_v2 = format!(
        "{DIAGNOSTIC_REF_TAGGED_PREFIX}1a2b3c4d_{}",
        &v1[DIAGNOSTIC_REF_PREFIX.len()..]
    );
    let v2_as_v1 = format!("{DIAGNOSTIC_REF_PREFIX}{}", &v2[v2.len() - 32..]);
    assert!(untagged.lookup_at(now, &v2_as_v1).is_none());
    assert!(tagged.lookup_at(now, &v1_as_v2).is_none());

    // A tagged replica asked for an untagged reference cannot name an owner.
    let v1_on_tagged = authorize_lookup(Some(&tagged), OPERATOR, true, &reader, &v1, now);
    assert_eq!(label(&v1_on_tagged), "not_found");

    // An untagged replica in a mixed fleet still points at a tagged owner.
    match authorize_lookup(Some(&untagged), OPERATOR, true, &reader, &v2, now) {
        DiagnosticRefLookup::NotOwned(replica) => assert_eq!(replica, REPLICA_A),
        other => panic!("expected the owner hint, got {other:?}"),
    }
}

#[test]
fn re_spelling_a_reference_misses_on_the_store_that_minted_its_key() {
    let untagged = default_store();
    let tagged = tagged_store(REPLICA_A);
    let v1 = mint(&untagged, 502, "connection_failure");
    let v2 = mint(&tagged, 502, "connection_failure");
    let now = Instant::now();
    let v1_key = &v1[DIAGNOSTIC_REF_PREFIX.len()..];
    let v2_key = &v2[v2.len() - 32..];

    // Each key is live in the store that minted it; only the spelling differs.
    let tagged_as_v1 = format!("{DIAGNOSTIC_REF_PREFIX}{v2_key}");
    let untagged_as_v2 = format!("{DIAGNOSTIC_REF_TAGGED_PREFIX}1a2b3c4d_{v1_key}");
    let tagged_as_other = format!("{DIAGNOSTIC_REF_TAGGED_PREFIX}f00dcafe_{v2_key}");
    assert!(tagged.lookup_at(now, &tagged_as_v1).is_none());
    assert!(untagged.lookup_at(now, &untagged_as_v2).is_none());
    assert!(tagged.lookup_at(now, &tagged_as_other).is_none());

    // The spelling each store mints still resolves.
    assert!(untagged.lookup_at(now, &v1).is_some());
    assert!(tagged.lookup_at(now, &v2).is_some());
}

#[test]
fn owner_hint_is_one_header_and_leaves_the_miss_body_alone() {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    insert_owner_hint(&mut headers, REPLICA_A);
    insert_owner_hint(&mut headers, REPLICA_A);
    let values: Vec<&str> = headers
        .get_all(DIAGNOSTIC_REF_OWNER_REPLICA_HEADER)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(values, ["1a2b3c4d"]);
    assert_eq!(headers.len(), 2);
}

#[test]
fn random_replica_ids_are_drawn_per_store() {
    let mut ids = HashSet::new();
    for _ in 0..64 {
        ids.insert(DiagnosticReplicaId::random().expect("CSPRNG"));
    }
    assert!(ids.len() > 60, "replica ids come from the CSPRNG");
}

#[test]
fn replica_info_metric_is_exported_only_when_tagged() {
    let untagged = store_with(16, Duration::from_secs(900), 10);
    let untagged = untagged.render_prometheus();
    assert!(!untagged.contains("ferrum_diagnostic_ref_replica_info"));

    let tagged = tagged_store(REPLICA_A).render_prometheus();
    let expected = [
        "# HELP ferrum_diagnostic_ref_replica_info Replica id this gateway process embeds in its \
         diagnostic references (value is always 1).",
        "# TYPE ferrum_diagnostic_ref_replica_info gauge",
        "ferrum_diagnostic_ref_replica_info{replica_id=\"1a2b3c4d\"} 1",
    ];
    for line in expected {
        assert!(tagged.lines().any(|l| l == line), "missing `{line}`");
    }
}
