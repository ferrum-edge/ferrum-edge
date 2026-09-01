//! RFC 9298 CONNECT-UDP over HTTP/3 — boundary parsing, destination admission,
//! and the RFC 9297 capsule codec (`src/http3/connect_udp.rs`).
//!
//! These exercise the production functions the H3 listener calls, not
//! re-implementations: `handle_h3_connect_udp` parses its target with
//! [`parse_connect_udp_target`], admits its destination with
//! [`admit_connect_udp_destination`], decodes the client stream with
//! [`CapsuleDecoder`], and frames target datagrams with
//! [`encode_udp_datagram_capsule`].

use dashmap::DashMap;
use ferrum_edge::_test_support::{
    H3AuthorizedHeadersWrite, await_authorized_headers_write_for_test,
    await_deadline_first_for_test, request_received_at_for_test,
    set_request_credential_deadline_for_test,
};
use ferrum_edge::config::types::{GatewayConfig, HttpFlavor, Proxy, Upstream};
use ferrum_edge::http3::connect_udp::{
    AdmittedConnectUdpDestination, CONNECT_UDP_MAX_PAYLOAD_BYTES,
    CONNECT_UDP_NON_FRAGMENTATION_ENFORCEABLE, CapsuleDecodeError, CapsuleDecoder, CapsuleEvent,
    ConnectUdpDestinationRefusal, ConnectUdpRequestRejection, ConnectUdpTargetRejection,
    H3ExtendedConnect, RelayDirection, SendHalfTeardownJoin, SessionEnd, StreamCloseKind,
    UdpRecvFault, UdpSendFault, admit_connect_udp_destination, classify_h3_extended_connect,
    classify_relay_join, classify_send_half_teardown, classify_udp_recv_error,
    classify_udp_send_error, destination_is_configured, dns_override_pin_unchanged,
    encode_udp_datagram_capsule, first_forbidden_capsule_protocol_field, parse_connect_udp_target,
    reconcile_authorization_teardown, resolve_send_half_close_command,
    strip_forbidden_capsule_protocol_response_fields, validate_connect_udp_request_shape,
};
use ferrum_edge::load_balancer::{HealthContext, LoadBalancerCache, LoadBalancerCacheInner};
use ferrum_edge::plugins::RequestContext;
use ferrum_edge::proxy::auth_lifetime::{
    ComposedAuthBound, StreamAuthDeadline, StreamAuthProtocolFamily, StreamAuthTermination,
    StreamAuthTerminationLatch, counters, effective_request_auth_deadline, expired_authorization,
};
use ferrum_edge::proxy::backend_dispatch::detect_http_flavor;
use ferrum_edge::proxy::hbone_pool::HBONE_TARGET_TAG;
use ferrum_edge::proxy::mesh_mtls_pool::{MESH_CROSS_CLUSTER_TAG, MESH_MTLS_TARGET_TAG};
use ferrum_edge::proxy::unix_backend::MESH_UNIX_SOCKET_TAG;

// ---------------------------------------------------------------------------
// URI Template parsing (RFC 9298 §2 / §3)
// ---------------------------------------------------------------------------

#[test]
fn parses_the_rfc9298_default_masque_template() {
    let target = parse_connect_udp_target("/.well-known/masque/udp/dns.example/853/")
        .expect("default template must parse");
    assert_eq!(target.host, "dns.example");
    assert_eq!(target.port, 853);
}

#[test]
fn parses_an_operator_prefixed_template() {
    let target = parse_connect_udp_target("/tenant-a/masque/udp/relay.internal/9000/")
        .expect("operator prefix must parse");
    assert_eq!(target.host, "relay.internal");
    assert_eq!(target.port, 9000);
}

#[test]
fn lowercases_the_target_host_so_admission_compares_exactly() {
    let target = parse_connect_udp_target("/udp/DNS.Example/53/").expect("must parse");
    assert_eq!(target.host, "dns.example");
}

#[test]
fn parses_ipv4_and_ipv6_literals_in_canonical_form() {
    let v4 = parse_connect_udp_target("/udp/192.0.2.10/443/").expect("ipv4 literal");
    assert_eq!(v4.host, "192.0.2.10");

    // RFC 9298 percent-encodes the colons; policy-path canonicalization has
    // already decoded them by the time the handler parses the path.
    let v6 = parse_connect_udp_target("/udp/2001:0db8:0000:0000:0000:0000:0000:0001/443/")
        .expect("ipv6 literal");
    assert_eq!(v6.host, "2001:db8::1");
}

#[test]
fn rejects_a_path_without_the_udp_anchor() {
    assert_eq!(
        parse_connect_udp_target("/.well-known/masque/tcp/dns.example/853/"),
        Err(ConnectUdpTargetRejection::TemplateAnchorMissing)
    );
    assert_eq!(
        parse_connect_udp_target("/dns.example/853/"),
        Err(ConnectUdpTargetRejection::TemplateAnchorMissing)
    );
}

#[test]
fn rejects_a_case_folded_udp_anchor() {
    // RFC 9298 §2 expands the literal `udp` segment; URI path matching is
    // case-sensitive. A case-insensitive compare would admit `/UDP/.../`
    // which is not template output.
    for path in [
        "/UDP/dns.example/53/",
        "/Udp/dns.example/53/",
        "/.well-known/masque/UDP/dns.example/53/",
        "/.well-known/masque/Udp/dns.example/53/",
    ] {
        assert_eq!(
            parse_connect_udp_target(path),
            Err(ConnectUdpTargetRejection::TemplateAnchorMissing),
            "{path} must be refused"
        );
    }
}

#[test]
fn rejects_a_path_without_the_template_trailing_slash() {
    assert_eq!(
        parse_connect_udp_target("/udp/dns.example/853"),
        Err(ConnectUdpTargetRejection::TrailingSlashMissing)
    );
}

#[test]
fn rejects_empty_template_variables() {
    assert_eq!(
        parse_connect_udp_target("/udp//853/"),
        Err(ConnectUdpTargetRejection::TargetHostEmpty)
    );
    assert_eq!(
        parse_connect_udp_target("/udp/dns.example//"),
        Err(ConnectUdpTargetRejection::TargetPortEmpty)
    );
}

#[test]
fn rejects_an_oversized_target_host() {
    let host = "a".repeat(300);
    assert_eq!(
        parse_connect_udp_target(&format!("/udp/{host}/53/")),
        Err(ConnectUdpTargetRejection::TargetHostTooLong)
    );
}

#[test]
fn rejects_hostile_target_host_spellings() {
    // Not an LDH label; root dot; bracketed IPv6; zone identifier; leading and
    // trailing hyphen labels; empty label; whitespace; colon-bearing non-literal.
    for host in [
        "under_score.example",
        "trailing.dot.",
        "[2001:db8::1]",
        "2001:db8::1%eth0",
        "-leading.example",
        "trailing-.example",
        "double..dot",
        "sp ace.example",
        "not:an:ipv6",
    ] {
        assert_eq!(
            parse_connect_udp_target(&format!("/udp/{host}/53/")),
            Err(ConnectUdpTargetRejection::TargetHostMalformed),
            "host {host} must be refused"
        );
    }
}

#[test]
fn rejects_hostile_target_ports() {
    assert_eq!(
        parse_connect_udp_target("/udp/dns.example/0/"),
        Err(ConnectUdpTargetRejection::TargetPortOutOfRange)
    );
    assert_eq!(
        parse_connect_udp_target("/udp/dns.example/65536/"),
        Err(ConnectUdpTargetRejection::TargetPortOutOfRange)
    );
    for port in ["+53", "53a", "0x35", " 53", "999999"] {
        assert!(
            matches!(
                parse_connect_udp_target(&format!("/udp/dns.example/{port}/")),
                Err(ConnectUdpTargetRejection::TargetPortMalformed
                    | ConnectUdpTargetRejection::TargetPortOutOfRange)
            ),
            "port {port} must be refused"
        );
    }
}

#[test]
fn rejection_diagnostics_are_field_specific_and_echo_nothing() {
    let rejection = parse_connect_udp_target("/udp/under_score/53/").expect_err("must reject");
    assert_eq!(rejection.reason(), "target_host_malformed");
    assert!(rejection.client_error_body().contains("target_host"));
    assert!(!rejection.client_error_body().contains("under_score"));
}

// ---------------------------------------------------------------------------
// Destination admission
// ---------------------------------------------------------------------------

fn direct_proxy(host: &str, port: u16) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "connect-udp",
        "backend_host": host,
        "backend_port": port,
        "listen_path": "/.well-known/masque",
    }))
    .expect("minimal direct proxy")
}

fn upstream_proxy(upstream_id: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "connect-udp",
        "backend_host": "unused.example",
        "backend_port": 1,
        "upstream_id": upstream_id,
        "listen_path": "/.well-known/masque",
    }))
    .expect("minimal upstream proxy")
}

fn upstream_with_targets(id: &str, targets: &[(&str, u16)]) -> Upstream {
    let targets: Vec<serde_json::Value> = targets
        .iter()
        .map(|(host, port)| serde_json::json!({ "host": host, "port": port }))
        .collect();
    serde_json::from_value(serde_json::json!({ "id": id, "targets": targets }))
        .expect("minimal upstream")
}

fn lb_cache(upstreams: Vec<Upstream>) -> LoadBalancerCache {
    let config = GatewayConfig {
        upstreams,
        ..GatewayConfig::default()
    };
    LoadBalancerCache::new(&config)
}

fn all_healthy<'a>(active: &'a DashMap<String, u64>) -> HealthContext<'a> {
    HealthContext {
        active_unhealthy: active,
        proxy_passive: None,
        max_ejection_percent: None,
    }
}

#[test]
fn admits_only_the_configured_direct_backend() {
    let cache = lb_cache(Vec::new());
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = direct_proxy("dns.example", 853);

    assert!(destination_is_configured(
        &proxy,
        lb,
        "dns.example",
        853,
        None,
    ));
    // Case-insensitive on the host, exact on the port.
    assert!(destination_is_configured(
        &proxy,
        lb,
        "DNS.example",
        853,
        None,
    ));
    assert!(!destination_is_configured(
        &proxy,
        lb,
        "dns.example",
        53,
        None,
    ));
    assert!(!destination_is_configured(
        &proxy,
        lb,
        "attacker.example",
        853,
        None,
    ));
}

#[test]
fn admits_any_target_of_the_referenced_upstream_and_nothing_else() {
    let cache = lb_cache(vec![upstream_with_targets(
        "udp-pool",
        &[("relay-a.internal", 5353), ("relay-b.internal", 5353)],
    )]);
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = upstream_proxy("udp-pool");

    assert!(destination_is_configured(
        &proxy,
        lb,
        "relay-a.internal",
        5353,
        None,
    ));
    assert!(destination_is_configured(
        &proxy,
        lb,
        "relay-b.internal",
        5353,
        None,
    ));
    // The proxy's own backend_host is NOT admitted once an upstream governs it.
    assert!(!destination_is_configured(
        &proxy,
        lb,
        "unused.example",
        1,
        None,
    ));
    assert!(!destination_is_configured(
        &proxy,
        lb,
        "relay-a.internal",
        53,
        None,
    ));
}

#[test]
fn a_withdrawn_upstream_admits_nothing() {
    // Exactly the reload/delete shape: the proxy still names an upstream, but
    // the published snapshot no longer contains it.
    let cache = lb_cache(Vec::new());
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = upstream_proxy("udp-pool");

    assert!(!destination_is_configured(
        &proxy,
        lb,
        "relay-a.internal",
        5353,
        None,
    ));
}

// ---------------------------------------------------------------------------
// Requested-target transport screening
//
// The destination a CONNECT-UDP request names is admitted, never load
// balanced, so admission has to be evaluated against the member the CLIENT
// named — and that member's own transport requirement decides whether a direct
// UDP socket may reach it at all.
// ---------------------------------------------------------------------------

/// An upstream built from a literal JSON document, so a target can carry the
/// mesh transport tags that `upstream_with_targets` deliberately never sets.
fn upstream_from_json(document: serde_json::Value) -> Upstream {
    serde_json::from_value(document).expect("minimal tagged upstream")
}

#[test]
fn a_transport_constrained_target_is_refused_even_when_a_sibling_is_directly_dialable() {
    // The exact mixed-upstream hazard: one member of the SAME upstream is an
    // ordinary direct target, the other must ride HBONE. Whichever member a
    // load balancer would have picked is irrelevant — the client named the
    // HBONE one, so tunnelling it over a direct UDP socket would bypass the
    // transport the operator configured for it.
    let upstream = upstream_from_json(serde_json::json!({
        "id": "mixed-pool",
        "targets": [
            { "host": "direct.internal", "port": 5353 },
            {
                "host": "hbone.internal",
                "port": 5353,
                "tags": { (HBONE_TARGET_TAG): "true" }
            }
        ]
    }));
    let cache = lb_cache(vec![upstream]);
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = upstream_proxy("mixed-pool");

    let admitted = admit_connect_udp_destination(&proxy, lb, "direct.internal", 5353, None)
        .expect("the direct member is tunnelable");
    match admitted {
        AdmittedConnectUdpDestination::UpstreamTarget(target) => {
            assert_eq!(target.host, "direct.internal");
            assert_eq!(target.port, 5353);
        }
        other => panic!("expected the requested upstream target, got {other:?}"),
    }

    assert_eq!(
        admit_connect_udp_destination(&proxy, lb, "hbone.internal", 5353, None,).unwrap_err(),
        ConnectUdpDestinationRefusal::TransportRequired(
            "HBONE dispatch required for this backend target"
        ),
        "a directly dialable sibling must not make an HBONE target tunnelable"
    );
    // And the boolean projection the live re-check uses agrees.
    assert!(!destination_is_configured(
        &proxy,
        lb,
        "hbone.internal",
        5353,
        None,
    ));
}

#[test]
fn every_non_direct_transport_class_is_refused() {
    let upstream = upstream_from_json(serde_json::json!({
        "id": "mesh-pool",
        "targets": [
            {
                "host": "mtls.internal",
                "port": 5353,
                "tags": { (MESH_MTLS_TARGET_TAG): "true" }
            },
            {
                "host": "xc.internal",
                "port": 5353,
                "tags": {
                    (MESH_MTLS_TARGET_TAG): "true",
                    (MESH_CROSS_CLUSTER_TAG): "true"
                }
            },
            {
                "host": "unix.internal",
                "port": 5353,
                "tags": { (MESH_UNIX_SOCKET_TAG): "/run/ferrum/app.sock" }
            }
        ]
    }));
    let cache = lb_cache(vec![upstream]);
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = upstream_proxy("mesh-pool");

    for host in ["mtls.internal", "xc.internal", "unix.internal"] {
        assert!(
            matches!(
                admit_connect_udp_destination(&proxy, lb, host, 5353, None),
                Err(ConnectUdpDestinationRefusal::TransportRequired(_))
            ),
            "{host} requires a transport a direct UDP dial cannot provide"
        );
    }
}

#[test]
fn a_direct_duplicate_cannot_launder_a_transport_constrained_sibling() {
    // Same host:port listed twice — legitimate for weights, localities, and
    // subsets. Screening only the first match would let the untagged copy
    // authorize a direct dial to a destination another copy says must ride
    // HBONE, so the whole matching set is screened.
    let upstream = upstream_from_json(serde_json::json!({
        "id": "duplicate-pool",
        "targets": [
            { "host": "relay.internal", "port": 5353 },
            {
                "host": "relay.internal",
                "port": 5353,
                "tags": { (HBONE_TARGET_TAG): "true" }
            }
        ]
    }));
    let cache = lb_cache(vec![upstream]);
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = upstream_proxy("duplicate-pool");

    assert!(
        matches!(
            admit_connect_udp_destination(&proxy, lb, "relay.internal", 5353, None,),
            Err(ConnectUdpDestinationRefusal::TransportRequired(_))
        ),
        "admission must fail closed across every matching target"
    );
}

#[test]
fn admission_returns_the_requested_member_never_a_balanced_one() {
    // Admission is a pure function of the requested host:port and the epoch's
    // snapshot: it is stable across repeats (no round-robin cursor is touched)
    // and every member is independently reachable, so no single "selected"
    // target can stand in for another.
    let cache = lb_cache(vec![upstream_with_targets(
        "udp-pool",
        &[("relay-a.internal", 5353), ("relay-b.internal", 5353)],
    )]);
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = upstream_proxy("udp-pool");

    for _ in 0..8 {
        for host in ["relay-a.internal", "relay-b.internal"] {
            let admitted = admit_connect_udp_destination(&proxy, lb, host, 5353, None)
                .expect("every configured member is admissible");
            match admitted {
                AdmittedConnectUdpDestination::UpstreamTarget(target) => {
                    assert_eq!(target.host, host, "must describe the requested member");
                }
                other => panic!("expected an upstream target, got {other:?}"),
            }
        }
    }
}

#[test]
fn dns_sd_standby_tier_is_not_admitted_while_primary_is_healthy() {
    let priority_tag = ferrum_edge::_test_support::srv_priority_tag_for_test();
    let upstream = upstream_from_json(serde_json::json!({
        "id": "dns-sd-pool",
        "targets": [
            {
                "host": "primary.internal",
                "port": 5353,
                "tags": { (priority_tag): "10" }
            },
            {
                "host": "standby.internal",
                "port": 5353,
                "tags": { (priority_tag): "20" }
            }
        ]
    }));
    let cache = lb_cache(vec![upstream]);
    let guard = cache.load();
    let proxy = upstream_proxy("dns-sd-pool");
    let active = DashMap::new();
    let health = all_healthy(&active);

    assert!(
        admit_connect_udp_destination(&proxy, &guard, "primary.internal", 5353, Some(&health),)
            .is_ok()
    );
    assert_eq!(
        admit_connect_udp_destination(&proxy, &guard, "standby.internal", 5353, Some(&health),)
            .unwrap_err(),
        ConnectUdpDestinationRefusal::SrvPriorityTierNotActive,
    );
    assert_eq!(
        ConnectUdpDestinationRefusal::SrvPriorityTierNotActive.reason(),
        "connect_udp_target_srv_tier_standby"
    );
    // Live re-check is configuration-only: a standby that was admitted
    // while the primary was down must not be withdrawn when health is
    // not consulted.
    assert!(destination_is_configured(
        &proxy,
        &guard,
        "standby.internal",
        5353,
        None,
    ));
}

#[test]
fn untagged_upstream_is_unaffected_by_srv_priority_admission() {
    let cache = lb_cache(vec![upstream_with_targets(
        "udp-pool",
        &[("relay-a.internal", 5353), ("relay-b.internal", 5353)],
    )]);
    let guard = cache.load();
    let proxy = upstream_proxy("udp-pool");
    let active = DashMap::new();
    let health = all_healthy(&active);

    for host in ["relay-a.internal", "relay-b.internal"] {
        assert!(
            admit_connect_udp_destination(&proxy, &guard, host, 5353, Some(&health),).is_ok(),
            "{host} has no SRV priority tags and must stay admissible"
        );
        assert!(
            destination_is_configured(&proxy, &guard, host, 5353, None),
            "{host} remains configured for the live re-check"
        );
    }
}

#[test]
fn a_route_backend_destination_is_admitted_as_the_route_backend() {
    let cache = lb_cache(Vec::new());
    let guard = cache.load();
    let lb: &LoadBalancerCacheInner = &guard;
    let proxy = direct_proxy("dns.example", 853);

    assert!(matches!(
        admit_connect_udp_destination(&proxy, lb, "dns.example", 853, None,),
        Ok(AdmittedConnectUdpDestination::RouteBackend)
    ));
    assert_eq!(
        admit_connect_udp_destination(&proxy, lb, "attacker.example", 853, None,).unwrap_err(),
        ConnectUdpDestinationRefusal::NotConfigured
    );
}

#[test]
fn every_refusal_kind_carries_a_distinct_gateway_reason() {
    // The client-visible refusal is identical for every kind (403, one
    // body), so the only place they may differ is the gateway-side
    // log/phase token.
    assert_eq!(
        ConnectUdpDestinationRefusal::NotConfigured.reason(),
        "connect_udp_target_not_allowed"
    );
    assert_eq!(
        ConnectUdpDestinationRefusal::SrvPriorityTierNotActive.reason(),
        "connect_udp_target_srv_tier_standby"
    );
    assert_eq!(
        ConnectUdpDestinationRefusal::TransportRequired("HBONE dispatch required").reason(),
        "connect_udp_target_transport_required"
    );
}

// ---------------------------------------------------------------------------
// Capsule codec (RFC 9297 §3, RFC 9298 §4/§5)
// ---------------------------------------------------------------------------

/// Hand-rolled DATAGRAM capsule so the decoder is tested against an
/// independently constructed encoding, not against its own encoder.
fn datagram_capsule(context_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00]; // Capsule Type = 0x00
    let value_len = 1 + payload.len();
    assert!(value_len < 64, "helper only emits 1-byte length varints");
    out.push(value_len as u8);
    out.push(context_id);
    out.extend_from_slice(payload);
    out
}

fn drain(decoder: &mut CapsuleDecoder) -> Vec<CapsuleEvent> {
    let mut events = Vec::new();
    loop {
        match decoder.decode_next().expect("no decode fault expected") {
            Some(event) => events.push(event),
            None => return events,
        }
    }
}

#[test]
fn decodes_a_context_zero_datagram_capsule() {
    let mut decoder = CapsuleDecoder::new(1200);
    decoder
        .push(&datagram_capsule(0, b"hello"))
        .expect("push must succeed");
    assert_eq!(
        drain(&mut decoder),
        vec![CapsuleEvent::UdpPayload(bytes::Bytes::from_static(
            b"hello"
        ))]
    );
}

#[test]
fn decodes_several_capsules_from_one_data_frame() {
    let mut decoder = CapsuleDecoder::new(1200);
    let mut wire = datagram_capsule(0, b"one");
    wire.extend_from_slice(&datagram_capsule(0, b"two"));
    decoder.push(&wire).expect("push must succeed");
    assert_eq!(
        drain(&mut decoder),
        vec![
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"one")),
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"two")),
        ]
    );
}

#[test]
fn reassembles_a_capsule_split_across_data_frames() {
    let wire = datagram_capsule(0, b"fragmented-payload");
    let mut decoder = CapsuleDecoder::new(1200);
    for split in 1..wire.len() {
        let mut decoder_at_split = CapsuleDecoder::new(1200);
        decoder_at_split.push(&wire[..split]).expect("first half");
        assert!(
            drain(&mut decoder_at_split).is_empty(),
            "a partial capsule must not yield an event at split {split}"
        );
        decoder_at_split.push(&wire[split..]).expect("second half");
        assert_eq!(
            drain(&mut decoder_at_split),
            vec![CapsuleEvent::UdpPayload(bytes::Bytes::from_static(
                b"fragmented-payload"
            ))],
            "split {split} must reassemble"
        );
    }
    // Byte-at-a-time is the same contract.
    for byte in &wire {
        decoder.push(&[*byte]).expect("byte push");
    }
    assert_eq!(drain(&mut decoder).len(), 1);
}

#[test]
fn drops_datagrams_naming_an_unregistered_context() {
    let mut decoder = CapsuleDecoder::new(1200);
    let mut wire = datagram_capsule(2, b"client-allocated");
    wire.extend_from_slice(&datagram_capsule(0, b"udp"));
    decoder.push(&wire).expect("push must succeed");
    assert_eq!(
        drain(&mut decoder),
        vec![
            CapsuleEvent::UnregisteredContext(2),
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"udp")),
        ],
        "an unregistered context must be reported as droppable, never proxied"
    );
}

#[test]
fn skips_unknown_capsule_types_and_keeps_parsing() {
    let mut decoder = CapsuleDecoder::new(1200);
    // Capsule Type = 0x17 (unregistered here), length 3, then a real datagram.
    let mut wire = vec![0x17, 0x03, 0xaa, 0xbb, 0xcc];
    wire.extend_from_slice(&datagram_capsule(0, b"after"));
    decoder.push(&wire).expect("push must succeed");
    assert_eq!(
        drain(&mut decoder),
        vec![
            CapsuleEvent::UnknownCapsuleType(0x17),
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"after")),
        ]
    );
}

// ---------------------------------------------------------------------------
// RFC 9297 §3.1: an unknown capsule is DROPPED AND SKIPPED, at any length
//
// "An endpoint that receives a Capsule Type it does not understand MUST
// silently drop that capsule and skip over it." Nothing there permits refusing
// one for being large, and the DATAGRAM ceiling is a property of the payloads
// this gateway materializes, not of the capsule stream's framing. A peer may
// legitimately negotiate an extension whose capsules dwarf the UDP ceiling; the
// tunnel must survive them, in bounded memory, and resume exact parsing after.
// ---------------------------------------------------------------------------

/// A capsule header: type varint + length varint, both in 8-byte QUIC varint
/// form so hostile lengths are expressible verbatim.
fn eight_byte_varint(value: u64) -> [u8; 8] {
    let mut encoded = value.to_be_bytes();
    encoded[0] |= 0xc0;
    encoded
}

#[test]
fn an_unknown_capsule_larger_than_the_udp_ceiling_is_skipped_not_refused() {
    const PAYLOAD_CEILING: usize = 1200;
    // Ten times the whole configured UDP ceiling — far above the DATAGRAM
    // capsule limit that used to reject it and reset the stream.
    const UNKNOWN_VALUE_LEN: usize = PAYLOAD_CEILING * 10;

    let mut decoder = CapsuleDecoder::new(PAYLOAD_CEILING);
    let feed_limit = decoder.feed_limit();

    let mut wire: Vec<u8> = vec![0x17];
    wire.extend_from_slice(&eight_byte_varint(UNKNOWN_VALUE_LEN as u64));
    wire.resize(wire.len() + UNKNOWN_VALUE_LEN, 0xa5);
    wire.extend_from_slice(&datagram_capsule(0, b"after-the-skip"));

    let mut events = Vec::new();
    let mut peak_buffered = 0usize;
    for chunk in wire.chunks(feed_limit) {
        decoder
            .push(chunk)
            .expect("a bounded feed must be accepted");
        events.extend(drain(&mut decoder));
        peak_buffered = peak_buffered.max(decoder.buffered_len());
    }

    assert_eq!(
        events,
        vec![
            CapsuleEvent::UnknownCapsuleType(0x17),
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"after-the-skip")),
        ],
        "RFC 9297 §3.1: the unknown capsule is reported once and skipped, and the capsule \
         AFTER it must still decode exactly"
    );
    assert!(
        peak_buffered <= feed_limit,
        "the skipped value must never be retained: peak buffered {peak_buffered} bytes for a \
         {UNKNOWN_VALUE_LEN}-byte unknown capsule"
    );
    decoder
        .finish_stream()
        .expect("the stream ended on a capsule boundary");
}

#[test]
fn an_unknown_capsule_split_at_hostile_boundaries_still_resumes_exactly() {
    let mut decoder = CapsuleDecoder::new(64);
    let mut wire: Vec<u8> = vec![0x17];
    // Declared length 4096 — above the 64 + 8 DATAGRAM ceiling.
    wire.extend_from_slice(&eight_byte_varint(4096));
    wire.resize(wire.len() + 4096, 0x5a);
    wire.extend_from_slice(&datagram_capsule(0, b"tail"));

    // One byte at a time: every split point lands inside the type varint, the
    // length varint, the skipped value, and the following capsule in turn.
    let mut events = Vec::new();
    for byte in &wire {
        decoder.push(&[*byte]).expect("single-byte push");
        events.extend(drain(&mut decoder));
        assert!(
            decoder.buffered_len() <= decoder.feed_limit(),
            "the decoder must stay bounded at every split point"
        );
    }
    assert_eq!(
        events,
        vec![
            CapsuleEvent::UnknownCapsuleType(0x17),
            CapsuleEvent::UdpPayload(bytes::Bytes::from_static(b"tail")),
        ]
    );
}

#[test]
fn a_hostile_unknown_capsule_length_neither_overflows_nor_allocates() {
    // The largest length a QUIC varint can express. Materializing it would be
    // an instant OOM (and on a 32-bit target a `usize` truncation); skipping it
    // must cost nothing at all.
    const VARINT_MAX: u64 = (1u64 << 62) - 1;
    let mut decoder = CapsuleDecoder::new(1200);
    let mut wire: Vec<u8> = vec![0x17];
    wire.extend_from_slice(&eight_byte_varint(VARINT_MAX));
    wire.extend_from_slice(b"the first bytes of an unreachable value");
    decoder.push(&wire).expect("push must succeed");

    assert_eq!(
        drain(&mut decoder),
        vec![CapsuleEvent::UnknownCapsuleType(0x17)],
        "the header is reported once; the value is never materialized"
    );
    assert_eq!(
        decoder.buffered_len(),
        0,
        "every delivered byte of the skipped value is discarded, not retained"
    );
    assert!(
        decoder.is_mid_capsule(),
        "the stream is still positioned inside the unknown capsule"
    );
    assert_eq!(
        decoder.finish_stream(),
        Err(CapsuleDecodeError::TruncatedAtStreamEnd),
        "RFC 9297 §3.3: a FIN inside the skipped value is still a malformed message"
    );
}

#[test]
fn the_datagram_ceiling_still_bounds_the_capsules_the_gateway_materializes() {
    // The unknown-type skip must not have widened the DATAGRAM bound: a
    // Context ID 0 capsule over the ceiling is still a fatal stream fault,
    // because its value IS buffered and relayed.
    let mut decoder = CapsuleDecoder::new(64);
    let mut wire: Vec<u8> = vec![0x00];
    wire.extend_from_slice(&eight_byte_varint(4096));
    decoder.push(&wire).expect("push must succeed");
    assert_eq!(
        decoder.decode_next(),
        Err(CapsuleDecodeError::CapsuleTooLarge)
    );
}

#[test]
fn refuses_a_datagram_capsule_with_no_context_id() {
    let mut decoder = CapsuleDecoder::new(1200);
    // Type 0x00, length 0 — no room for the mandatory Context ID varint.
    decoder.push(&[0x00, 0x00]).expect("push must succeed");
    assert_eq!(
        decoder.decode_next(),
        Err(CapsuleDecodeError::DatagramCapsuleTruncated)
    );
}

#[test]
fn refuses_a_capsule_declaring_a_length_above_the_ceiling() {
    let mut decoder = CapsuleDecoder::new(64);
    // Type 0x00, 2-byte varint length 0x4400 = 1024, far above 64 + slack.
    decoder
        .push(&[0x00, 0x44, 0x00])
        .expect("push must succeed");
    assert_eq!(
        decoder.decode_next(),
        Err(CapsuleDecodeError::CapsuleTooLarge)
    );
}

#[test]
fn refuses_a_context_zero_payload_above_the_configured_ceiling() {
    let mut decoder = CapsuleDecoder::new(4);
    // Fits under the capsule ceiling (4 + 8 slack) but exceeds the payload cap.
    decoder
        .push(&datagram_capsule(0, b"1234567"))
        .expect("push must succeed");
    assert_eq!(
        decoder.decode_next(),
        Err(CapsuleDecodeError::PayloadTooLarge)
    );
}

#[test]
fn refuses_a_push_that_would_exceed_the_transient_buffer_bound() {
    let mut decoder = CapsuleDecoder::new(64);
    let oversized = vec![0u8; decoder.feed_limit() * 2 + 1];
    assert_eq!(
        decoder.push(&oversized),
        Err(CapsuleDecodeError::BufferOverflow)
    );
}

#[test]
fn encodes_a_context_zero_datagram_capsule_on_the_wire() {
    let mut out = bytes::BytesMut::new();
    let capsule = encode_udp_datagram_capsule(&mut out, b"pong");
    assert_eq!(
        capsule.as_ref(),
        &[0x00, 0x05, 0x00, b'p', b'o', b'n', b'g']
    );
}

#[test]
fn encoder_and_decoder_round_trip_at_the_rfc_payload_ceiling() {
    let payload = vec![0x5a; CONNECT_UDP_MAX_PAYLOAD_BYTES];
    let mut out = bytes::BytesMut::new();
    let capsule = encode_udp_datagram_capsule(&mut out, &payload);

    let mut decoder = CapsuleDecoder::new(CONNECT_UDP_MAX_PAYLOAD_BYTES);
    let feed_limit = decoder.feed_limit();
    for chunk in capsule.chunks(feed_limit) {
        decoder.push(chunk).expect("push must succeed");
    }
    match decoder.decode_next().expect("decode must succeed") {
        Some(CapsuleEvent::UdpPayload(decoded)) => assert_eq!(decoded.len(), payload.len()),
        other => panic!("expected a context-0 payload, got {other:?}"),
    }
}

#[test]
fn encoder_reuses_its_scratch_buffer_across_datagrams() {
    let mut out = bytes::BytesMut::new();
    let first = encode_udp_datagram_capsule(&mut out, b"a");
    let second = encode_udp_datagram_capsule(&mut out, b"b");
    assert_eq!(first.as_ref(), &[0x00, 0x02, 0x00, b'a']);
    assert_eq!(second.as_ref(), &[0x00, 0x02, 0x00, b'b']);
}

// ---------------------------------------------------------------------------
// Extended CONNECT classification
// ---------------------------------------------------------------------------

fn connect_request(protocol: Option<h3::ext::Protocol>) -> http::Request<()> {
    let mut req = http::Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_3)
        .uri("https://gateway.test/.well-known/masque/udp/dns.example/853/")
        .body(())
        .expect("request");
    if let Some(protocol) = protocol {
        req.extensions_mut().insert(protocol);
    }
    req
}

#[test]
fn classifies_the_two_dispatchable_extended_connect_profiles() {
    assert_eq!(
        classify_h3_extended_connect(&connect_request(Some(h3::ext::Protocol::CONNECT_UDP))),
        H3ExtendedConnect::ConnectUdp
    );
    assert_eq!(
        classify_h3_extended_connect(&connect_request(Some(h3::ext::Protocol::WEB_SOCKET))),
        H3ExtendedConnect::WebSocket
    );
}

#[test]
fn classifies_registered_but_unimplemented_protocols_as_unsupported() {
    assert_eq!(
        classify_h3_extended_connect(&connect_request(Some(h3::ext::Protocol::WEB_TRANSPORT))),
        H3ExtendedConnect::Unsupported,
        "webtransport must not be dispatched as a tunnel"
    );
}

#[test]
fn a_bare_connect_and_a_non_connect_request_are_not_extended_connect() {
    assert_eq!(
        classify_h3_extended_connect(&connect_request(None)),
        H3ExtendedConnect::None
    );

    let mut get = http::Request::builder()
        .method(http::Method::GET)
        .version(http::Version::HTTP_3)
        .uri("https://gateway.test/udp/dns.example/853/")
        .body(())
        .expect("request");
    // Even a spoofed `:protocol` extension on a non-CONNECT request must not
    // reach the tunnel dispatcher.
    get.extensions_mut().insert(h3::ext::Protocol::CONNECT_UDP);
    assert_eq!(classify_h3_extended_connect(&get), H3ExtendedConnect::None);
}

#[test]
fn connect_udp_classification_ignores_spoofed_grpc_content_types() {
    // The wire classifier keys native gRPC on Content-Type, so a hostile
    // CONNECT-UDP can look like gRPC until the handler's Extended CONNECT
    // override forces Plain. Classification itself must still be ConnectUdp
    // so the RFC 9297 field refusal runs.
    for content_type in ["application/grpc", "application/grpc-web+proto"] {
        let mut req = connect_request(Some(h3::ext::Protocol::CONNECT_UDP));
        req.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            content_type.parse().expect("content-type"),
        );
        assert_eq!(
            classify_h3_extended_connect(&req),
            H3ExtendedConnect::ConnectUdp,
            "{content_type} must not hide connect-udp"
        );
        if content_type == "application/grpc" {
            assert_eq!(
                detect_http_flavor(&req),
                HttpFlavor::Grpc,
                "the shared wire classifier still sees native gRPC Content-Type; \
                 handle_h3_request must override that to Plain"
            );
        } else {
            assert_eq!(
                detect_http_flavor(&req),
                HttpFlavor::Plain,
                "gRPC-Web stays Plain in detect_http_flavor; the handler must \
                 still suppress gRPC-Web response shaping"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 9298 §3 request shape
// ---------------------------------------------------------------------------

fn uri(text: &str) -> http::Uri {
    text.parse().expect("test uri")
}

#[test]
fn accepts_the_rfc9298_https_bootstrap_shape() {
    validate_connect_udp_request_shape(&uri(
        "https://gateway.test/.well-known/masque/udp/dns.example/853/",
    ))
    .expect("the RFC 9298 §3 shape must be accepted");
}

#[test]
fn refuses_a_connect_udp_request_without_the_https_scheme() {
    // The classifier reads only :method and :protocol, so without this check
    // the handler would assume HTTPS and tunnel anyway.
    assert_eq!(
        validate_connect_udp_request_shape(&uri(
            "http://gateway.test/.well-known/masque/udp/dns.example/853/"
        )),
        Err(ConnectUdpRequestRejection::SchemeNotHttps)
    );
    assert_eq!(
        validate_connect_udp_request_shape(&uri(
            "ftp://gateway.test/.well-known/masque/udp/dns.example/853/"
        )),
        Err(ConnectUdpRequestRejection::SchemeNotHttps)
    );
    // An origin-form URI carries no :scheme at all.
    assert_eq!(
        validate_connect_udp_request_shape(&uri("/.well-known/masque/udp/dns.example/853/")),
        Err(ConnectUdpRequestRejection::SchemeMissing)
    );
}

#[test]
fn refuses_a_connect_udp_request_without_an_authority() {
    // `http::Uri` enforces this boundary before the H3 dispatcher: an HTTPS
    // absolute URI cannot be represented without an authority. Keep the
    // validator's fixed diagnostic covered directly as defense in depth.
    assert!(
        "https:///udp/dns.example/853/"
            .parse::<http::Uri>()
            .is_err(),
        "the HTTP URI type must reject an HTTPS URI without authority"
    );
    assert_eq!(
        ConnectUdpRequestRejection::AuthorityMissing.reason(),
        "connect_udp_authority_missing"
    );
    assert_eq!(
        ConnectUdpRequestRejection::AuthorityMissing.client_error_body(),
        r#"{"error":"CONNECT-UDP requires the :authority pseudo-header"}"#
    );
}

#[test]
fn request_shape_diagnostics_are_field_specific_and_echo_nothing() {
    let rejection = validate_connect_udp_request_shape(&uri(
        "http://secret-tenant.internal/udp/dns.example/853/",
    ))
    .expect_err("must reject");
    assert_eq!(rejection.reason(), "connect_udp_scheme_not_https");
    assert!(rejection.client_error_body().contains(":scheme"));
    assert!(
        !rejection
            .client_error_body()
            .contains("secret-tenant.internal")
    );
}

// ---------------------------------------------------------------------------
// RFC 9297 §3.2 forbidden fields
// ---------------------------------------------------------------------------

#[test]
fn refuses_every_field_the_capsule_protocol_forbids() {
    for (name, expected) in [
        (
            "content-length",
            ConnectUdpRequestRejection::ForbiddenContentLength,
        ),
        (
            "Content-Length",
            ConnectUdpRequestRejection::ForbiddenContentLength,
        ),
        (
            "content-type",
            ConnectUdpRequestRejection::ForbiddenContentType,
        ),
        (
            "CONTENT-TYPE",
            ConnectUdpRequestRejection::ForbiddenContentType,
        ),
        (
            "transfer-encoding",
            ConnectUdpRequestRejection::ForbiddenTransferEncoding,
        ),
        (
            "Transfer-Encoding",
            ConnectUdpRequestRejection::ForbiddenTransferEncoding,
        ),
    ] {
        assert_eq!(
            first_forbidden_capsule_protocol_field([name]),
            Some(expected),
            "{name} must be refused on a Capsule Protocol message"
        );
    }
}

#[test]
fn permits_the_fields_the_capsule_protocol_requires() {
    assert_eq!(
        first_forbidden_capsule_protocol_field(["capsule-protocol", "user-agent", "authorization"]),
        None
    );
}

#[test]
fn strips_forbidden_fields_a_response_policy_tried_to_author() {
    // A plugin/policy-finalized response map is the second half of the
    // boundary: rejecting only the client's headers would let
    // `response_transformer` put Content-Type on a Capsule Protocol message.
    let mut headers = std::collections::HashMap::from([
        ("content-length".to_string(), "42".to_string()),
        ("Content-Type".to_string(), "text/plain".to_string()),
        ("transfer-encoding".to_string(), "chunked".to_string()),
        ("x-tenant".to_string(), "keep-me".to_string()),
    ]);
    strip_forbidden_capsule_protocol_response_fields(&mut headers);
    assert_eq!(
        headers,
        std::collections::HashMap::from([("x-tenant".to_string(), "keep-me".to_string())]),
        "only the RFC 9297 §3.2 fields may be removed, and all of them must be"
    );
}

// ---------------------------------------------------------------------------
// RFC 9297 §3.3: a FIN mid-capsule is malformed, not EOF
// ---------------------------------------------------------------------------

#[test]
fn a_client_fin_on_a_capsule_boundary_is_a_clean_end_of_stream() {
    let mut decoder = CapsuleDecoder::new(1200);
    decoder
        .push(&datagram_capsule(0, b"complete"))
        .expect("push");
    assert_eq!(drain(&mut decoder).len(), 1);
    assert_eq!(decoder.buffered_len(), 0);
    decoder
        .finish_stream()
        .expect("a FIN with nothing buffered is an ordinary close");
}

#[test]
fn a_client_fin_inside_a_capsule_is_a_malformed_message_not_an_eof() {
    let mut decoder = CapsuleDecoder::new(1200);
    // Header declares 32 bytes of value; only 3 arrive.
    decoder.push(&[0x00, 0x20, 0x00, 0xde, 0xad]).expect("push");
    assert!(
        drain(&mut decoder).is_empty(),
        "an incomplete capsule must not yield an event"
    );
    assert!(
        decoder.buffered_len() > 0,
        "the partial capsule must still be buffered"
    );
    assert_eq!(
        decoder.finish_stream(),
        Err(CapsuleDecodeError::TruncatedAtStreamEnd),
        "RFC 9297 §3.3: a stream closed mid-capsule is malformed, never a clean EOF"
    );
    assert_eq!(
        CapsuleDecodeError::TruncatedAtStreamEnd.reason(),
        "capsule_truncated_at_stream_end"
    );
}

#[test]
fn a_dangling_capsule_header_prefix_is_also_a_truncated_stream() {
    let mut decoder = CapsuleDecoder::new(1200);
    // A 2-byte varint type whose second byte never arrives.
    decoder.push(&[0x40]).expect("push");
    assert!(drain(&mut decoder).is_empty());
    assert_eq!(
        decoder.finish_stream(),
        Err(CapsuleDecodeError::TruncatedAtStreamEnd)
    );
}

// ---------------------------------------------------------------------------
// RFC 9298 §3.1 socket behaviour
// ---------------------------------------------------------------------------

#[test]
fn an_oversized_datagram_is_dropped_but_an_unusable_socket_is_terminal() {
    // Portable, errno-free arms first: `io::Error::from(ErrorKind)` carries no
    // raw OS error, so these exercise the kind-based fallback directly.
    for kind in [
        std::io::ErrorKind::WouldBlock,
        std::io::ErrorKind::Interrupted,
    ] {
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from(kind)),
            UdpSendFault::DropDatagram,
            "{kind:?} is a transient local condition, not a dead socket"
        );
    }
    for kind in [
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::HostUnreachable,
        std::io::ErrorKind::NetworkUnreachable,
        std::io::ErrorKind::NetworkDown,
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::NotConnected,
        std::io::ErrorKind::Other,
    ] {
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from(kind)),
            UdpSendFault::Terminal,
            "{kind:?} means the socket itself is unusable"
        );
    }

    // EMSGSIZE is the expected result of the RFC 9298 §3.1 do-not-fragment
    // policy for an over-path datagram, so it must NOT kill the tunnel. Spelled
    // numerically because the test crate does not link `libc`.
    #[cfg(target_os = "linux")]
    const EMSGSIZE: i32 = 90;
    #[cfg(target_vendor = "apple")]
    const EMSGSIZE: i32 = 40;
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(EMSGSIZE)),
            UdpSendFault::DropDatagram,
            "EMSGSIZE must drop one datagram, never tear down the tunnel"
        );
        // EBADF is 9 on both.
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(9)),
            UdpSendFault::Terminal,
            "a closed descriptor is not per-datagram loss"
        );
    }

    assert_eq!(UdpSendFault::DropDatagram.as_str(), "datagram_dropped");
    assert_eq!(UdpSendFault::Terminal.as_str(), "socket_unusable");
}

#[test]
fn icmp_destination_unreachable_is_terminal_in_both_directions() {
    // RFC 9298 §3.1: when the OS reports the connected UDP socket unusable,
    // the proxy MUST close the request stream. ICMP Destination Unreachable is
    // the named example. The kernel surfaces that condition on whichever
    // syscall runs next, so send and recv must agree it is Terminal — never a
    // silent per-datagram drop that leaves a dead tunnel looking healthy.
    for kind in [
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::HostUnreachable,
        std::io::ErrorKind::NetworkUnreachable,
        std::io::ErrorKind::NetworkDown,
    ] {
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from(kind)),
            UdpRecvFault::Terminal,
            "{kind:?} on recv is ICMP/destination-unreachable: close the stream"
        );
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from(kind)),
            UdpSendFault::Terminal,
            "{kind:?} on send is ICMP/destination-unreachable: close the stream"
        );
    }

    // errno arms. Spelled numerically because the test crate does not link
    // `libc`. Linux icmp_err_convert maps dest-unreach onto ECONNREFUSED
    // (port), ENOPROTOOPT (protocol), EHOSTUNREACH / ENETUNREACH (host/net).
    // ENETDOWN / EHOSTDOWN / ECONNRESET are the remaining dest-unreach /
    // refused / reset / down spellings the classifier must not swallow.
    #[cfg(target_os = "linux")]
    const ICMP_UNUSABLE: [i32; 7] = [
        111, // ECONNREFUSED
        104, // ECONNRESET
        113, // EHOSTUNREACH
        101, // ENETUNREACH
        100, // ENETDOWN
        112, // EHOSTDOWN
        92,  // ENOPROTOOPT (ICMP protocol unreachable)
    ];
    #[cfg(target_vendor = "apple")]
    const ICMP_UNUSABLE: [i32; 7] = [
        61, // ECONNREFUSED
        54, // ECONNRESET
        65, // EHOSTUNREACH
        51, // ENETUNREACH
        50, // ENETDOWN
        64, // EHOSTDOWN
        42, // ENOPROTOOPT
    ];
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        for code in ICMP_UNUSABLE {
            assert_eq!(
                classify_udp_recv_error(&std::io::Error::from_raw_os_error(code)),
                UdpRecvFault::Terminal,
                "errno {code} is ICMP/destination-unreachable: recv must terminate"
            );
            assert_eq!(
                classify_udp_send_error(&std::io::Error::from_raw_os_error(code)),
                UdpSendFault::Terminal,
                "errno {code} is ICMP/destination-unreachable: send must terminate"
            );
        }
        // EBADF is 9 on both: a closed descriptor is not per-datagram loss.
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(9)),
            UdpRecvFault::Terminal
        );
    }

    // Windows ICMP/socket-unusable spellings. WSAECONNRESET (10054) is the
    // ICMP port-unreachable report on a connected datagram socket.
    #[cfg(windows)]
    {
        for code in [
            10050, // WSAENETDOWN
            10051, // WSAENETUNREACH
            10052, // WSAENETRESET
            10054, // WSAECONNRESET
            10061, // WSAECONNREFUSED
            10064, // WSAEHOSTDOWN
            10065, // WSAEHOSTUNREACH
        ] {
            assert_eq!(
                classify_udp_recv_error(&std::io::Error::from_raw_os_error(code)),
                UdpRecvFault::Terminal,
                "WSA {code} is destination-unreachable/unusable: recv must terminate"
            );
            assert_eq!(
                classify_udp_send_error(&std::io::Error::from_raw_os_error(code)),
                UdpSendFault::Terminal,
                "WSA {code} is destination-unreachable/unusable: send must terminate"
            );
        }
    }

    assert_eq!(UdpRecvFault::DropDatagram.as_str(), "datagram_dropped");
    assert_eq!(UdpRecvFault::AwaitReadable.as_str(), "socket_not_ready");
    assert_eq!(UdpRecvFault::Terminal.as_str(), "socket_unusable");
}

#[test]
fn recv_wouldblock_awaits_readability_and_emsgsize_remains_a_datagram_drop() {
    // Interrupted is still per-datagram loss in both directions.
    assert_eq!(
        classify_udp_recv_error(&std::io::Error::from(std::io::ErrorKind::Interrupted)),
        UdpRecvFault::DropDatagram,
        "EINTR/Interrupted on recv drops one attempt, never the tunnel"
    );
    assert_eq!(
        classify_udp_send_error(&std::io::Error::from(std::io::ErrorKind::Interrupted)),
        UdpSendFault::DropDatagram,
        "EINTR/Interrupted on send drops one datagram, never the tunnel"
    );

    // `WouldBlock` is recv's own arm: retrying the syscall immediately would
    // spin, so the relay awaits readability again instead. It is never a drop
    // and never terminal. Send has no AwaitReadable arm; not-ready there is a
    // dropped datagram.
    assert_eq!(
        classify_udp_recv_error(&std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        UdpRecvFault::AwaitReadable,
        "a not-ready socket must send the relay back to awaiting readiness"
    );
    assert_eq!(
        classify_udp_send_error(&std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        UdpSendFault::DropDatagram,
        "WouldBlock on send is a transient local drop, not a dead socket"
    );

    for kind in [
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::NotConnected,
        std::io::ErrorKind::Other,
    ] {
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from(kind)),
            UdpRecvFault::Terminal,
            "{kind:?} means the socket itself is unusable"
        );
    }

    // errno arms. Spelled numerically because the test crate does not link
    // `libc`.
    #[cfg(target_os = "linux")]
    const EMSGSIZE: i32 = 90;
    #[cfg(target_vendor = "apple")]
    const EMSGSIZE: i32 = 40;
    #[cfg(target_os = "linux")]
    const EAGAIN: i32 = 11;
    #[cfg(target_vendor = "apple")]
    const EAGAIN: i32 = 35;
    #[cfg(target_os = "linux")]
    const ENOBUFS: i32 = 105;
    #[cfg(target_vendor = "apple")]
    const ENOBUFS: i32 = 55;
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(EMSGSIZE)),
            UdpRecvFault::DropDatagram,
            "EMSGSIZE on recv is the DF/PMTU one-datagram drop"
        );
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(EMSGSIZE)),
            UdpSendFault::DropDatagram,
            "EMSGSIZE on send is the DF/PMTU one-datagram drop"
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(EAGAIN)),
            UdpRecvFault::AwaitReadable,
            "EAGAIN on recv must await readability, never spin and never terminate"
        );
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(EAGAIN)),
            UdpSendFault::DropDatagram,
            "EAGAIN on send is a transient local drop"
        );
        // EINTR is 4 on both.
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(4)),
            UdpRecvFault::DropDatagram
        );
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(4)),
            UdpSendFault::DropDatagram
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(ENOBUFS)),
            UdpRecvFault::DropDatagram,
            "ENOBUFS is transient local buffer pressure, not a dead socket"
        );
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(ENOBUFS)),
            UdpSendFault::DropDatagram,
            "ENOBUFS is transient local buffer pressure, not a dead socket"
        );
    }

    #[cfg(windows)]
    {
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(10040)),
            UdpRecvFault::DropDatagram,
            "WSAEMSGSIZE is the DF/PMTU one-datagram drop"
        );
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(10040)),
            UdpSendFault::DropDatagram,
            "WSAEMSGSIZE is the DF/PMTU one-datagram drop"
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(10035)),
            UdpRecvFault::AwaitReadable,
            "WSAEWOULDBLOCK on recv must await readability"
        );
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(10035)),
            UdpSendFault::DropDatagram,
            "WSAEWOULDBLOCK on send is a transient local drop"
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(10004)),
            UdpRecvFault::DropDatagram,
            "WSAEINTR is interruption, not a dead socket"
        );
        assert_eq!(
            classify_udp_send_error(&std::io::Error::from_raw_os_error(10055)),
            UdpSendFault::DropDatagram,
            "WSAENOBUFS is transient local buffer pressure"
        );
    }
}

// ---------------------------------------------------------------------------
// Session teardown classification
//
// Which outcomes may FIN the capsule stream and which must reset it is a
// client-visible security contract, and a live tunnel is the wrong place to
// pin it down: the relay task that owns the QUIC send half classifies its own
// terminal outcomes through `SessionEnd::close_kind` (the supervisor cannot
// change a send half after that task has already returned), so asserting this
// one mapping is what makes the relay's decision structurally testable.
// ---------------------------------------------------------------------------

/// Every session end, listed once. A new arm that is not classified here fails
/// this module rather than silently defaulting to a clean FIN somewhere.
const EVERY_SESSION_END: [SessionEnd; 11] = [
    SessionEnd::ClientClosed,
    SessionEnd::RelayTaskFailed,
    SessionEnd::TargetSocketUnusable,
    SessionEnd::Idle,
    SessionEnd::Draining,
    SessionEnd::RouteWithdrawn,
    SessionEnd::RouteTargetPinChanged,
    SessionEnd::RouteAuthorizationUnreconstructable,
    SessionEnd::CapsuleProtocolError,
    // Both bounded authorization-lifetime classes (issue #3860). Listing them
    // separately is deliberate: each must independently be a non-clean close.
    SessionEnd::AuthorizationExpired(StreamAuthTermination::CredentialExpired),
    SessionEnd::AuthorizationExpired(StreamAuthTermination::AuthenticatedStreamMaxLifetime),
];

#[test]
fn an_unusable_tunnel_socket_resets_instead_of_presenting_a_clean_fin() {
    // The target-bound relay's terminal `recv` failure and the client-bound
    // relay's terminal `send` fault are the same condition — the tunnel's own
    // connected socket is unusable — so they end the session the same way. A
    // FIN here would tell the client the tunnel ended normally while the
    // gateway silently stopped being able to carry its traffic.
    assert_eq!(
        SessionEnd::TargetSocketUnusable.close_kind(),
        StreamCloseKind::InternalError
    );
    assert_eq!(
        SessionEnd::TargetSocketUnusable.as_str(),
        "target_socket_unusable"
    );
}

#[test]
fn a_capsule_fault_still_closes_with_the_rfc_9114_message_error() {
    // Unchanged by the internal-error classification above: RFC 9297 §3.3/§3.5
    // makes a malformed capsule stream a malformed HTTP MESSAGE, which is
    // `H3_MESSAGE_ERROR`, not an internal failure of the gateway.
    assert_eq!(
        SessionEnd::CapsuleProtocolError.close_kind(),
        StreamCloseKind::MessageError
    );
    assert_eq!(
        SessionEnd::CapsuleProtocolError.as_str(),
        "capsule_protocol_error"
    );
    // And those outcomes are the ONLY non-clean closes, so no ordinary end
    // of tunnel can drift into a reset either.
    for end in EVERY_SESSION_END {
        let must_reset = matches!(
            end,
            SessionEnd::TargetSocketUnusable
                | SessionEnd::CapsuleProtocolError
                | SessionEnd::RelayTaskFailed
                | SessionEnd::AuthorizationExpired(_)
        );
        assert_eq!(
            end.close_kind() != StreamCloseKind::Clean,
            must_reset,
            "{} classifies its stream close wrong",
            end.as_str()
        );
    }
}

// ---------------------------------------------------------------------------
// Authorization lifetime (issue #3860)
//
// A CONNECT-UDP tunnel is a long-lived native H3 relay that owns the request
// stream and the UDP socket directly, so it cannot inherit the shared
// authorization-lifetime contract through the ordinary `ProxyBody` wrapper.
// These pin the pieces the handler plumbs explicitly: the derivation, the
// pre-commitment predicate, the non-clean post-commitment terminal, once-only
// attribution under the bounded `StreamUdp` family, and the teardown
// reconciliation a flow-control-stalled client forces.
// ---------------------------------------------------------------------------

const CONNECT_UDP_MAX_LIFETIME: u64 = 3_600;

fn authenticated_connect_udp_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "CONNECT".to_string(),
        "/.well-known/masque/udp/dns.example/853/".to_string(),
    );
    // Any admitted principal. The contract keys on "a principal was accepted",
    // not on which mechanism accepted it.
    ctx.authenticated_identity = Some("spiffe://cluster.local/ns/ferrum/sa/masque".to_string());
    ctx
}

#[tokio::test]
async fn an_unauthenticated_connect_udp_tunnel_keeps_its_pre_existing_bounds() {
    // No principal was admitted, so there is no authorization lifetime to
    // enforce. The handler derives `None`, the supervisor arm can never fire,
    // and every RFC 9298 bound the tunnel already had is untouched.
    let ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "CONNECT".to_string(),
        "/.well-known/masque/udp/dns.example/853/".to_string(),
    );
    let plan = effective_request_auth_deadline(&ctx, CONNECT_UDP_MAX_LIFETIME);
    assert!(
        plan.is_none(),
        "an unauthenticated CONNECT-UDP request must not be bounded by this contract"
    );
    assert!(
        expired_authorization(plan).is_none(),
        "the pre-commitment gate must never refuse an unauthenticated tunnel"
    );
}

#[tokio::test]
async fn a_short_lived_credential_bounds_the_tunnel_before_the_configured_maximum() {
    // The JWT `exp` / mTLS `notAfter` shape: authentication published an
    // authoritative deadline well inside the configured maximum, so the
    // credential's own expiry is the bound AND the reported class.
    let mut ctx = authenticated_connect_udp_ctx();
    let received_at = request_received_at_for_test(&ctx);
    let credential_at = received_at + std::time::Duration::from_secs(30);
    set_request_credential_deadline_for_test(&mut ctx, Some(credential_at));

    let plan = effective_request_auth_deadline(&ctx, CONNECT_UDP_MAX_LIFETIME)
        .expect("an admitted principal must produce a plan");
    assert_eq!(plan.at, credential_at);
    assert_eq!(plan.termination, StreamAuthTermination::CredentialExpired);
}

#[tokio::test]
async fn a_credential_with_no_authoritative_expiry_still_gets_a_finite_tunnel() {
    // A credential that carries no expiry does not buy an indefinite tunnel:
    // the finite configured maximum bounds it, anchored at request RECEIPT so a
    // slow admission cannot buy extra authorized lifetime.
    let ctx = authenticated_connect_udp_ctx();
    let received_at = request_received_at_for_test(&ctx);

    let plan = effective_request_auth_deadline(&ctx, 45)
        .expect("an admitted principal must produce a plan");
    assert_eq!(plan.at, received_at + std::time::Duration::from_secs(45));
    assert_eq!(
        plan.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
}

#[tokio::test(start_paused = true)]
async fn relayed_datagrams_can_never_move_the_tunnel_deadline() {
    // The supervisor arms ONE `sleep_until` on the derived instant and never
    // rearms it. The derivation itself is the proof that nothing later can
    // move that instant: it is anchored to request receipt and to the accepted
    // credential, both fixed before the tunnel existed, so re-deriving it after
    // an arbitrary amount of relayed traffic yields the identical absolute
    // instant rather than a refreshed one.
    let mut ctx = authenticated_connect_udp_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(
        &mut ctx,
        Some(received_at + std::time::Duration::from_secs(20)),
    );
    let anchored = effective_request_auth_deadline(&ctx, CONNECT_UDP_MAX_LIFETIME)
        .expect("an admitted principal must produce a plan")
        .at;

    // Time passes and datagrams cross the tunnel in both directions.
    tokio::time::advance(std::time::Duration::from_secs(15)).await;

    let after_traffic = effective_request_auth_deadline(&ctx, CONNECT_UDP_MAX_LIFETIME)
        .expect("an admitted principal must produce a plan")
        .at;
    assert_eq!(
        after_traffic, anchored,
        "activity must never extend an admitted principal's authorization lifetime"
    );

    // And once that absolute instant has passed, it stays passed.
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    let elapsed_plan = effective_request_auth_deadline(&ctx, CONNECT_UDP_MAX_LIFETIME);
    assert_eq!(
        expired_authorization(elapsed_plan),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_deadline_is_refused_before_any_tunnel_resource_exists() {
    // The pre-commitment predicate the handler runs ahead of the session
    // permit, DNS, the UDP socket, and the 200. A live plan must NOT refuse
    // (otherwise every authenticated tunnel would be rejected); an elapsed one
    // must, and must name the bounded class.
    let mut ctx = authenticated_connect_udp_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(
        &mut ctx,
        Some(received_at + std::time::Duration::from_secs(30)),
    );
    let live_plan = effective_request_auth_deadline(&ctx, CONNECT_UDP_MAX_LIFETIME);
    assert!(
        expired_authorization(live_plan).is_none(),
        "a live credential must open the tunnel"
    );

    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    let elapsed_plan = effective_request_auth_deadline(&ctx, CONNECT_UDP_MAX_LIFETIME);
    assert_eq!(
        expired_authorization(elapsed_plan),
        Some(StreamAuthTermination::CredentialExpired),
        "an expired credential must be refused before the tunnel commits"
    );
}

#[test]
fn an_authorization_expiry_never_presents_a_completed_capsule_stream() {
    // Post-commitment: the 200 is on the wire and capsule DATA may already have
    // flowed, so the only honest terminal is a reset. A clean FIN would tell
    // the client its tunnel ended normally at exactly the moment the gateway
    // took it away from an unauthorized principal.
    for termination in [
        StreamAuthTermination::CredentialExpired,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    ] {
        let end = SessionEnd::AuthorizationExpired(termination);
        assert_eq!(
            end.close_kind(),
            StreamCloseKind::InternalError,
            "{} must reset the capsule stream",
            termination.as_str()
        );
        assert_ne!(end.close_kind(), StreamCloseKind::Clean);
        // The reason token is the SHARED compiled-in literal, so the session
        // log, the counter, and the `authorization.termination_reason`
        // transaction-summary metadata all name the same closed set.
        assert_eq!(end.as_str(), termination.as_str());
    }
    assert_eq!(
        SessionEnd::AuthorizationExpired(StreamAuthTermination::CredentialExpired).as_str(),
        "credential_expired"
    );
    assert_eq!(
        SessionEnd::AuthorizationExpired(StreamAuthTermination::AuthenticatedStreamMaxLifetime)
            .as_str(),
        "authenticated_stream_max_lifetime"
    );
}

#[test]
fn a_connect_udp_expiry_is_attributed_once_under_the_bounded_stream_udp_family() {
    // The supervisor's expiry arm and any other authorization exit on the same
    // request share ONE latch, so a race between them records exactly one
    // correctly attributed counter rather than two.
    let latch = StreamAuthTerminationLatch::default();
    assert!(
        latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "the first authorization exit owns the termination"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "a concurrent exit must observe the class, not count a second one"
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired),
        "the winner's class is the one reported"
    );

    // The family is the existing closed one, deliberately reused rather than
    // adding a `connect_udp` series: no route, target, or credential label is
    // created by this transport.
    assert_eq!(StreamAuthProtocolFamily::StreamUdp.as_str(), "stream_udp");
    let snapshot = counters();
    let max_lifetime_families = &snapshot.authenticated_stream_max_lifetime;
    assert!(snapshot.credential_expired.contains_key("stream_udp"));
    assert!(max_lifetime_families.contains_key("stream_udp"));
    assert!(
        !snapshot.credential_expired.contains_key("connect_udp"),
        "CONNECT-UDP must not publish a new protocol family"
    );
}

#[test]
fn a_flow_control_stalled_client_cannot_relabel_its_own_expiry_as_a_gateway_fault() {
    // A client-bound relay parked in QUIC send flow control is raced with the
    // supervisor close command so `stop_stream` can land. If that write still
    // never returns, it is aborted after CLOSE_GRACE — which is how teardown
    // stays bounded. Quinn would `finish()` that abort on drop, so
    // `ConnectUdpSendHalf` RESETS unless a close was already applied. That
    // abort is the DESIGNED path for an authorization expiry only when the
    // join is a cancellation AND the grace timed out. The terminal stays
    // non-clean instead of being demoted to an internal relay failure the
    // gateway never suffered.
    for termination in [
        StreamAuthTermination::CredentialExpired,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    ] {
        let supervisor = SessionEnd::AuthorizationExpired(termination);
        let reported =
            reconcile_authorization_teardown(supervisor, SendHalfTeardownJoin::Cancelled, true);
        assert_eq!(reported, supervisor);
        assert_eq!(
            reported.close_kind(),
            StreamCloseKind::InternalError,
            "the terminal is still non-clean"
        );
    }
}

#[test]
fn a_send_half_panic_after_an_authorization_verdict_stays_a_relay_failure() {
    // classify_send_half_teardown maps both Panicked and Cancelled to
    // RelayTaskFailed. Reconciliation must NOT then relabel a panic as
    // AuthorizationExpired: a genuine task failure is warning/internal, not
    // ordinary client-triggerable credential expiry.
    for termination in [
        StreamAuthTermination::CredentialExpired,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    ] {
        let supervisor = SessionEnd::AuthorizationExpired(termination);
        let reported =
            reconcile_authorization_teardown(supervisor, SendHalfTeardownJoin::Panicked, true);
        assert_eq!(
            reported,
            SessionEnd::RelayTaskFailed,
            "a panicked send half must not be relabeled as {}",
            termination.as_str()
        );
        assert_eq!(reported.close_kind(), StreamCloseKind::InternalError);
        assert_eq!(reported.as_str(), "relay_task_failed");
    }
}

#[test]
fn an_unrelated_send_half_cancellation_after_an_authorization_verdict_stays_a_relay_failure() {
    // Cancellation without CLOSE_GRACE timeout is not this session's designed
    // abort of a flow-control-stalled send half. It stays RelayTaskFailed even
    // when the supervisor had already selected AuthorizationExpired.
    let supervisor = SessionEnd::AuthorizationExpired(StreamAuthTermination::CredentialExpired);
    let reported =
        reconcile_authorization_teardown(supervisor, SendHalfTeardownJoin::Cancelled, false);
    assert_eq!(reported, SessionEnd::RelayTaskFailed);
    assert_eq!(reported.close_kind(), StreamCloseKind::InternalError);
}

#[test]
fn only_an_authorization_expiry_survives_an_unapplied_send_half_close() {
    // The substitution above is narrow. Every other supervisor verdict whose
    // close never landed stays `RelayTaskFailed`, because the client did not
    // see the FIN or reset that verdict implied.
    for supervisor in [
        SessionEnd::Idle,
        SessionEnd::Draining,
        SessionEnd::RouteWithdrawn,
        SessionEnd::RouteTargetPinChanged,
        SessionEnd::RouteAuthorizationUnreconstructable,
        SessionEnd::ClientClosed,
        SessionEnd::CapsuleProtocolError,
        SessionEnd::TargetSocketUnusable,
    ] {
        assert_eq!(
            reconcile_authorization_teardown(supervisor, SendHalfTeardownJoin::Cancelled, true),
            SessionEnd::RelayTaskFailed,
            "{} must not survive a close the client never saw",
            supervisor.as_str()
        );
    }
    // And the substitution never overrides a send half that DID apply a close.
    // A relay that reached its own terminal outcome before the supervisor's
    // command arrived is authoritative about what the client saw, expiry or
    // not; only an unapplied close is reconciled.
    let expiry = SessionEnd::AuthorizationExpired(StreamAuthTermination::CredentialExpired);
    let completed = SendHalfTeardownJoin::Completed(SessionEnd::ClientClosed);
    assert_eq!(
        reconcile_authorization_teardown(expiry, completed, true),
        SessionEnd::ClientClosed,
        "a COMPLETED send-half join is authoritative; only an unapplied close is reconciled"
    );
}

fn connect_udp_handler_source() -> &'static str {
    let src = include_str!("../../../src/http3/connect_udp.rs");
    let start = src
        .find("pub(crate) async fn handle_h3_connect_udp(")
        .expect("handle_h3_connect_udp must exist");
    let rest = &src[start..];
    let end = rest
        .find("\n/// Feed one client DATA chunk")
        .expect("handler must end before relay_client_chunk");
    &rest[..end]
}

#[test]
fn connect_udp_precommit_gates_and_header_write_follow_the_captured_plan() {
    // Resource ordering without test-only production instrumentation: the
    // early elapsed gate is before the session permit / DNS / socket, the
    // awaited setup is composed against the captured plan, the final gate
    // sits at the last instant before the 200 is offered, and the HEADERS
    // write uses the shared H3 utility. A successful 200 is counted only
    // after that write actually succeeds.
    let squeezed = squeeze(connect_udp_handler_source());
    let early = squeezed
        .find("ifletSome(termination)=crate::proxy::auth_lifetime::expired_authorization(auth_deadline)")
        .expect("early elapsed gate");
    let permit = squeezed
        .find("state.h3_connect_udp_sessions.as_ref()")
        .expect("session permit");
    let dns = squeezed
        .find("letdns_bound=crate::proxy::auth_lifetime::ComposedAuthBound::compose(")
        .expect("composed DNS bound");
    let dns_wait = squeezed
        .find("crate::plugins::await_deadline_first(dns_bound.deadline(),")
        .expect("DNS wait must use await_deadline_first");
    let socket = squeezed
        .find("bind_tunnel_socket(bind_addr)")
        .expect("tunnel socket");
    let connect = squeezed
        .find("letconnect_bound=crate::proxy::auth_lifetime::ComposedAuthBound::compose(None,auth_deadline)")
        .expect("composed connect bound");
    let final_gate = squeezed
        .rfind("ifletSome(termination)=crate::proxy::auth_lifetime::expired_authorization(auth_deadline)")
        .expect("final pre-200 gate");
    let header_write = squeezed
        .find("crate::http3::stream_util::await_authorized_headers_write(")
        .expect("HEADERS write must use the shared H3 utility");
    let written = squeezed
        .find("H3AuthorizedHeadersWrite::Written")
        .expect("successful HEADERS write arm");
    let counted = squeezed
        .find("crate::proxy::record_request(&state,200)")
        .expect("200 must be counted");
    let abort = squeezed
        .find("crate::http3::stream_util::abort_response_stream(&mutstream)")
        .expect("stalled 200 write must abort/reset");
    let summary = squeezed
        .find("emit_session_summary(")
        .expect("established-tunnel summary");

    assert!(
        early < permit && permit < dns && dns < dns_wait && dns_wait < socket && socket < connect,
        "already-expired requests must be refused before permit, DNS, and the socket"
    );
    assert!(
        connect < final_gate
            && final_gate < header_write
            && header_write < written
            && written < counted,
        "the final gate must precede the HEADERS write, and a 200 must be counted only after Written"
    );
    assert!(
        header_write < abort && abort < summary && counted < summary,
        "an expired stalled HEADERS write must abort before any session summary; the \
         established-tunnel summary is emitted only after a successful 200"
    );
    assert_eq!(
        squeezed.matches("emit_session_summary(").count(),
        1,
        "the established-tunnel TransactionSummary is the intentional single summary"
    );
    assert_eq!(
        squeezed
            .matches("crate::proxy::record_request(&state,200)")
            .count(),
        1,
        "a 200 must be counted exactly once, and only after Written"
    );
    assert!(
        squeezed.contains("H3AuthorizedHeadersWrite::AuthorizationExpired(termination)"),
        "authorization expiry during the 200 write must be a distinct arm"
    );
    assert!(
        !squeezed[abort..summary].contains("send_h3_reject_body"),
        "an expired stalled 200 write must not attempt another blocking terminal write"
    );
    let abort_log = squeezed[abort..summary]
        .find("crate::proxy::log_rejected_request_with_path(")
        .expect("stalled 200 expiry must still complete the rejection access log");
    let abort_return = squeezed[abort..summary]
        .find("returnOk(())")
        .expect("stalled 200 expiry must return before the established-tunnel summary");
    assert!(
        abort_log < abort_return,
        "the rejection summary must be the only access-log completion on a stalled 200 expiry"
    );
}

#[test]
fn connect_udp_supervisor_attributes_authorization_first_on_a_tie() {
    // Scheduler-tie classification is the production supervisor: biased
    // select with the authorization arm first, so idle / drain / withdrawal /
    // relay halt that become ready in the same poll lose to the security
    // decision. This inspects the production loop rather than restating it.
    let src = include_str!("../../../src/http3/connect_udp.rs");
    let relay = src
        .split("async fn relay(")
        .nth(1)
        .expect("relay")
        .split("\n/// Log a receive-half teardown join")
        .next()
        .expect("relay body");
    let squeezed = squeeze(relay);
    let biased = squeezed
        .find("tokio::select!{biased;")
        .expect("supervisor must be biased");
    let auth = squeezed
        .find("termination=&mutauthorization_expiry=>")
        .expect("authorization arm");
    let idle = squeezed.find("breakSessionEnd::Idle").expect("idle arm");
    let drain = squeezed
        .find("breakSessionEnd::Draining")
        .expect("drain arm");
    let withdrawn = squeezed
        .find("breakSessionEnd::RouteWithdrawn")
        .expect("route-withdrawal arm");
    let pin = squeezed
        .find("breakSessionEnd::RouteTargetPinChanged")
        .expect("target-pin arm");
    let relay_join = squeezed
        .find("breakclassify_relay_join(")
        .expect("relay-join arm");
    assert!(
        biased < auth
            && auth < relay_join
            && auth < drain
            && auth < idle
            && auth < pin
            && auth < withdrawn,
        "authorization must be the first biased arm so idle, drain, withdrawal, \
         target-pin, and relay halt lose a same-poll tie to the security decision"
    );
}

#[tokio::test(start_paused = true)]
async fn connect_udp_dns_composition_is_authorization_first_on_a_tie() {
    // Production `ComposedAuthBound` + `await_deadline_first`: a DNS-like wait
    // that shares an instant with the captured plan never polls the lookup,
    // and the expiry is attributed to authorization. A strictly earlier
    // protocol bound keeps protocol-timeout attribution.
    let now = tokio::time::Instant::now();
    let plan = StreamAuthDeadline {
        at: now,
        termination: StreamAuthTermination::CredentialExpired,
    };
    let auth_bound = ComposedAuthBound::compose(Some(now), Some(plan));
    assert_eq!(
        auth_bound.expired_authorization(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    let mut polled = false;
    let outcome = await_deadline_first_for_test(auth_bound.deadline(), async {
        polled = true;
        "resolved"
    })
    .await;
    assert_eq!(outcome, Err(()));
    assert!(!polled, "an elapsed authorization bound must not poll DNS");

    let protocol_at = now + std::time::Duration::from_secs(1);
    let later_plan = StreamAuthDeadline {
        at: now + std::time::Duration::from_secs(5),
        termination: StreamAuthTermination::CredentialExpired,
    };
    let protocol_bound = ComposedAuthBound::compose(Some(protocol_at), Some(later_plan));
    assert_eq!(
        protocol_bound.expired_authorization(),
        None,
        "a strictly earlier protocol bound must not be reported as authorization"
    );

    let unauthenticated = ComposedAuthBound::compose(Some(protocol_at), None);
    assert_eq!(unauthenticated.expired_authorization(), None);
    assert_eq!(unauthenticated.deadline(), Some(protocol_at));
}

#[tokio::test(start_paused = true)]
async fn a_stalled_connect_udp_headers_write_expires_under_stream_udp() {
    // Production `await_authorized_headers_write` with the CONNECT-UDP family:
    // a never-ready HEADERS write expires at the captured plan, records
    // exactly once under stream_udp, and does not treat the write as committed.
    let now = tokio::time::Instant::now();
    let plan = StreamAuthDeadline {
        at: now + std::time::Duration::from_secs(1),
        termination: StreamAuthTermination::CredentialExpired,
    };
    let bound = ComposedAuthBound::compose(None, Some(plan));
    let latch = StreamAuthTerminationLatch::default();
    let started = tokio::time::Instant::now();
    let outcome = await_authorized_headers_write_for_test(
        bound,
        StreamAuthProtocolFamily::StreamUdp,
        &latch,
        std::future::pending::<Result<(), ()>>(),
    )
    .await;
    assert_eq!(
        tokio::time::Instant::now() - started,
        std::time::Duration::from_secs(1)
    );
    assert_eq!(
        outcome,
        H3AuthorizedHeadersWrite::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "the HEADERS-write expiry must occupy the once-only latch"
    );
}

#[tokio::test]
async fn an_unauthenticated_connect_udp_headers_write_never_registers_a_timer() {
    let bound = ComposedAuthBound::compose(None, None);
    assert_eq!(bound.deadline(), None);
    let latch = StreamAuthTerminationLatch::default();
    let outcome = await_authorized_headers_write_for_test(
        bound,
        StreamAuthProtocolFamily::StreamUdp,
        &latch,
        async { Ok::<(), ()>(()) },
    )
    .await;
    assert_eq!(outcome, H3AuthorizedHeadersWrite::Written);
    assert_eq!(latch.observed(), None);
}

#[tokio::test]
async fn a_relay_join_failure_is_an_internal_failure_never_a_client_fin() {
    // The supervisor reaches `classify_relay_join` only for a handle it has NOT
    // aborted, so a join failure there is a panic or a cancellation this
    // session never requested. Neither is a lifecycle outcome, and mapping
    // either to `ClientClosed` would present the client an orderly FIN for a
    // tunnel the gateway actually lost control of.
    //
    // The failure is induced by cancelling a task, not by panicking one: this
    // asserts the classification without putting a panic on any code path.
    for relay in [
        RelayDirection::ClientToTarget,
        RelayDirection::TargetToClient,
    ] {
        let handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            SessionEnd::ClientClosed
        });
        handle.abort();
        let joined = handle.await;
        assert!(joined.is_err(), "the aborted task must not have completed");
        assert_eq!(
            classify_relay_join(joined, relay, "proxy-under-test"),
            SessionEnd::RelayTaskFailed,
            "{} join failure must not be reported as a client close",
            relay.as_str()
        );
    }

    // And it resets rather than FINs.
    assert_eq!(
        SessionEnd::RelayTaskFailed.close_kind(),
        StreamCloseKind::InternalError,
        "an internal relay failure must reset with H3_INTERNAL_ERROR"
    );
    assert_eq!(SessionEnd::RelayTaskFailed.as_str(), "relay_task_failed");
    assert_eq!(RelayDirection::ClientToTarget.as_str(), "client_to_target");
    assert_eq!(RelayDirection::TargetToClient.as_str(), "target_to_client");
}

#[tokio::test]
async fn a_relay_that_ran_to_completion_keeps_its_own_verdict() {
    // The other half of the contract: classification must not overwrite an
    // outcome the relay decided for itself, or an ordinary client FIN would
    // start resetting.
    for end in EVERY_SESSION_END {
        let handle = tokio::spawn(async move { end });
        let joined = handle.await;
        assert_eq!(
            classify_relay_join(joined, RelayDirection::TargetToClient, "proxy-under-test"),
            end,
            "{} is the relay's own verdict and must survive the join",
            end.as_str()
        );
    }
}

#[test]
fn a_consumed_supervisor_close_command_is_the_applied_send_half_outcome() {
    // If the send-half task consumes the oneshot, that command is what it
    // applies and returns — even when a competing self-decided halt exists as
    // a hypothetical alternative. Teardown then takes the completed join
    // verbatim, so the reported SessionEnd matches the close that landed.
    for command in EVERY_SESSION_END {
        assert_eq!(
            resolve_send_half_close_command(Some(command), SessionEnd::TargetSocketUnusable),
            command,
            "{} consumed from the supervisor must be applied, not a stale \
             self-decided socket failure",
            command.as_str()
        );
        assert_eq!(
            classify_send_half_teardown(SendHalfTeardownJoin::Completed(command)),
            command,
            "{} applied by the send-half owner must survive teardown",
            command.as_str()
        );
    }
}

#[test]
fn a_self_decided_send_half_halt_survives_a_stale_supervisor_verdict() {
    // The race: the supervisor selected idle/drain/withdrawal (or an ordinary
    // client close), then the send-half task reached its own terminal outcome
    // before consuming the oneshot. The task applies its own close_kind; the
    // unread command is discarded. Teardown must keep that joined outcome —
    // including a socket failure that resets and a client close that FINs —
    // rather than reporting the supervisor's pending verdict.
    let self_decided = [
        SessionEnd::TargetSocketUnusable,
        SessionEnd::ClientClosed,
        SessionEnd::CapsuleProtocolError,
        SessionEnd::RelayTaskFailed,
    ];
    for end in self_decided {
        assert_eq!(
            resolve_send_half_close_command(None, end),
            end,
            "{} must be kept when the supervisor command was not consumed",
            end.as_str()
        );
        assert_eq!(
            classify_send_half_teardown(SendHalfTeardownJoin::Completed(end)),
            end,
            "a completed send-half join is authoritative; a stale supervisor \
             Idle cannot overwrite {}",
            end.as_str()
        );
    }
    // Pin the security-visible half of the race: a self-decided socket
    // failure resets, and that reset must not be reported as a clean idle FIN.
    assert_eq!(
        classify_send_half_teardown(SendHalfTeardownJoin::Completed(
            SessionEnd::TargetSocketUnusable,
        ))
        .close_kind(),
        StreamCloseKind::InternalError
    );
    assert_eq!(SessionEnd::Idle.close_kind(), StreamCloseKind::Clean);
}

#[test]
fn aborting_the_send_half_after_close_grace_is_not_a_clean_supervisor_fin() {
    // CLOSE_GRACE expiry aborts the send-half task and always joins it. A
    // cancelled join means finish()/reset did not complete, so a clean
    // supervisor reason (idle, drain, withdrawal, ordinary client close) must
    // not be reported: the client never saw that FIN.
    for supervisor in [
        SessionEnd::Idle,
        SessionEnd::Draining,
        SessionEnd::RouteWithdrawn,
        SessionEnd::RouteTargetPinChanged,
        SessionEnd::RouteAuthorizationUnreconstructable,
        SessionEnd::ClientClosed,
    ] {
        assert_eq!(
            supervisor.close_kind(),
            StreamCloseKind::Clean,
            "{} is a clean supervisor outcome",
            supervisor.as_str()
        );
        let reported = classify_send_half_teardown(SendHalfTeardownJoin::Cancelled);
        assert_eq!(reported, SessionEnd::RelayTaskFailed);
        assert_eq!(reported.close_kind(), StreamCloseKind::InternalError);
        assert_ne!(
            reported.close_kind(),
            supervisor.close_kind(),
            "aborting after grace must not report the clean FIN {} never applied",
            supervisor.as_str()
        );
    }
    assert_eq!(
        classify_send_half_teardown(SendHalfTeardownJoin::Panicked),
        SessionEnd::RelayTaskFailed
    );
    // When the task DID consume the command and complete, the joined clean
    // reason is kept — grace abort is the only path that drops it.
    for end in [
        SessionEnd::Idle,
        SessionEnd::Draining,
        SessionEnd::RouteWithdrawn,
        SessionEnd::ClientClosed,
    ] {
        assert_eq!(
            classify_send_half_teardown(SendHalfTeardownJoin::Completed(end)),
            end
        );
        assert_eq!(end.close_kind(), StreamCloseKind::Clean);
    }
}

#[tokio::test]
async fn a_cancelled_send_half_join_is_never_the_task_pending_clean_reason() {
    // Abort-then-join is deterministic: the task has not reached its return,
    // so the JoinError is cancellation, not the Idle it would have returned.
    // Mapping that to RelayTaskFailed is what keeps a grace-timeout abort
    // from being logged as a clean supervisor FIN.
    let handle = tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        SessionEnd::Idle
    });
    handle.abort();
    let joined = handle.await;
    assert!(joined.is_err(), "the aborted task must not have completed");
    let observed = match joined {
        Ok(_) => unreachable!("asserted is_err"),
        Err(error) if error.is_panic() => SendHalfTeardownJoin::Panicked,
        Err(_) => SendHalfTeardownJoin::Cancelled,
    };
    assert_eq!(observed, SendHalfTeardownJoin::Cancelled);
    assert_eq!(
        classify_send_half_teardown(observed),
        SessionEnd::RelayTaskFailed
    );
    assert_eq!(
        SessionEnd::RelayTaskFailed.close_kind(),
        StreamCloseKind::InternalError
    );
}

#[test]
fn send_half_teardown_wires_the_joined_outcome_as_authoritative() {
    // Production wiring for the race the classifiers above pin down: the
    // oneshot carries SessionEnd, the send-half task resolves command vs
    // self-decided halt, teardown classifies the joined result (never
    // discarding a successful SessionEnd via join_panicked), and CLOSE_GRACE
    // expiry aborts then joins rather than detaching.
    let squeezed = squeeze(include_str!("../../../src/http3/connect_udp.rs"));
    assert!(
        squeezed.contains("tokio::sync::oneshot::channel::<SessionEnd>()"),
        "the close command must carry SessionEnd so a consumed command is unambiguous"
    );
    assert!(
        squeezed.contains("breakresolve_send_half_close_command("),
        "the send-half task must resolve a consumed supervisor command vs a self-decided halt"
    );
    assert!(
        squeezed.contains("let_=close_tx.send(end);"),
        "teardown must send the supervisor SessionEnd, not only its close-kind"
    );
    assert!(
        squeezed.contains(
            "end=reconcile_authorization_teardown(supervisor_verdict,observe_send_half_join("
        ),
        "teardown must reconcile the send-half join against the supervisor verdict"
    );
    assert!(
        !squeezed.contains("join_panicked(joined,RelayDirection::TargetToClient"),
        "join_panicked discards a successful joined SessionEnd and must not classify the send half"
    );
    assert!(
        squeezed.contains("from_target.abort();(from_target.await,true)"),
        "CLOSE_GRACE expiry must abort then join the send-half task, never detach"
    );
    assert!(
        squeezed.contains("send_capsule_or_supervisor_close("),
        "a flow-control-stalled send_data must share a select with the supervisor close command"
    );
    assert!(
        squeezed.contains("ConnectUdpSendHalf::new(h3_send)"),
        "the client-bound send half must RESET on drop unless finish/stop_stream already ran"
    );
    assert!(
        squeezed.contains(
            "ifself.reset_on_drop{self.stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);}"
        ),
        "Quinn finish-on-drop must not present a clean FIN for an aborted stalled send half"
    );
}

#[test]
fn every_session_end_reason_is_a_distinct_fixed_cardinality_token() {
    // These reach logs (and, through them, operators' metric labels), so they
    // must stay a closed set of fixed literals: no target host, address, or
    // errno may reach a session-end token.
    let mut reasons: Vec<&'static str> = EVERY_SESSION_END
        .into_iter()
        .map(SessionEnd::as_str)
        .collect();
    let count = reasons.len();
    reasons.sort_unstable();
    reasons.dedup();
    assert_eq!(reasons.len(), count, "session-end reasons must be distinct");
    for reason in reasons {
        assert!(
            reason.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{reason} must be a lowercase snake_case literal"
        );
    }
}

// ---------------------------------------------------------------------------
// Live re-check: the destination ADDRESS pin, not just the destination name
// ---------------------------------------------------------------------------

#[test]
fn an_unchanged_effective_dns_override_keeps_the_tunnel_pinned() {
    // The ordinary reload: the generation moved, but the route still maps this
    // destination exactly where the connected socket already points.
    assert!(dns_override_pin_unchanged(None, None));
    assert!(dns_override_pin_unchanged(
        Some("10.0.0.7"),
        Some("10.0.0.7")
    ));
    assert!(dns_override_pin_unchanged(
        Some("2001:db8::7"),
        Some("2001:db8::7")
    ));
}

#[test]
fn any_effective_dns_override_change_fails_the_live_tunnel_closed() {
    // A connected UDP socket cannot be re-pinned, and the requested host:port
    // is still configured in every one of these shapes — so `destination_is_
    // configured` alone would keep relaying to the address the route has just
    // stopped naming. Some/None changes count in both directions.
    for (admitted, live) in [
        (Some("10.0.0.7"), Some("10.0.0.8")),
        (Some("10.0.0.7"), None),
        (None, Some("10.0.0.7")),
        (Some("10.0.0.7"), Some("2001:db8::7")),
        // Same address, different spelling. The comparison is exact and
        // resolves nothing, so this fails closed — the safe direction.
        (Some("10.0.0.7"), Some("::ffff:10.0.0.7")),
    ] {
        assert!(
            !dns_override_pin_unchanged(admitted, live),
            "{admitted:?} -> {live:?} moves the address this tunnel is pinned to"
        );
    }
    // It ends the session the way every other config withdrawal does: an
    // orderly close, with a fixed reason that names no address.
    assert_eq!(
        SessionEnd::RouteTargetPinChanged.close_kind(),
        StreamCloseKind::Clean
    );
    assert_eq!(
        SessionEnd::RouteTargetPinChanged.as_str(),
        "route_target_pin_changed"
    );
}

#[cfg(unix)]
#[test]
fn the_do_not_fragment_option_installs_on_a_real_udp_socket() {
    use std::os::unix::io::AsRawFd;

    use ferrum_edge::socket_opts::{UDP_DONT_FRAGMENT_SUPPORTED, set_udp_dont_fragment};

    // The runtime contract the tunnel socket depends on: on a platform that
    // advertises the option, installing it on a freshly bound UDP socket must
    // succeed — the production path refuses the tunnel when it does not.
    //
    // On a target that advertises no option the call must FAIL, not silently
    // succeed. RFC 9298 §3.1 is a MUST, so "the option was not installed" may
    // never be reported to a caller as "the guarantee is in force"; the profile
    // is refused at startup and at admission instead.
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let Ok(socket) = std::net::UdpSocket::bind(bind) else {
            // No IPv6 loopback on this runner; the IPv4 arm still runs.
            continue;
        };
        let is_ipv4 = socket.local_addr().expect("local addr").is_ipv4();
        let result = set_udp_dont_fragment(socket.as_raw_fd(), is_ipv4);
        if UDP_DONT_FRAGMENT_SUPPORTED {
            result.unwrap_or_else(|error| {
                panic!("do-not-fragment must install on {bind}: {error}");
            });
        } else {
            let error = result.expect_err(
                "a target with no do-not-fragment option must report that, never succeed",
            );
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        }
    }
}

#[test]
fn the_rfc9298_profile_is_only_offered_where_non_fragmentation_is_enforceable() {
    // The capability gate and the socket option are the same fact, so they can
    // never disagree about whether this build can honour RFC 9298 §3.1. Bound
    // to locals so the assertions are real runtime comparisons rather than
    // constant folds.
    let gate = CONNECT_UDP_NON_FRAGMENTATION_ENFORCEABLE;
    let socket_option = ferrum_edge::socket_opts::UDP_DONT_FRAGMENT_SUPPORTED;
    assert_eq!(
        gate, socket_option,
        "the CONNECT-UDP capability gate must be exactly the do-not-fragment capability"
    );
    // Every target this repository builds and tests the data plane on can
    // enforce it, so the profile is available rather than refused here. A
    // target that cannot is refused at startup by
    // `validate_h3_connect_udp_limits`.
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    assert!(
        gate,
        "Linux and Apple both expose a do-not-fragment option; losing that would silently \
         disable the whole profile"
    );
}

/// Collapse whitespace so rustfmt wrapping cannot hide a source-contract needle.
fn squeeze(source: &str) -> String {
    let collapsed: String = source.split_whitespace().collect();
    collapsed.replace(",)", ")")
}

fn handle_h3_request_source() -> &'static str {
    let src = include_str!("../../../src/http3/server.rs");
    let start = src
        .find("async fn handle_h3_request(")
        .expect("handle_h3_request must exist");
    &src[start..]
}

#[test]
fn handle_h3_request_rejects_connect_udp_in_early_data_before_routing() {
    // Functional admission contract of the live H3 handler: every CONNECT-UDP
    // request in TLS 1.3 early data is 425, regardless of the CONNECT
    // allowlist, and that refusal is ordered before 501/400, the generic
    // method gate, routing, plugins, DNS, and the tunnel handler.
    let squeezed = squeeze(handle_h3_request_source());
    let connect_udp_425 = squeezed
        .find("ifis_connect_udp_request&&is_early_data{")
        .expect("CONNECT-UDP 0-RTT must have a categorical early-data gate");
    let profile_501 = squeezed
        .find("connect_udp_profile_available")
        .expect("disabled-profile 501 must remain present");
    let malformed = squeezed
        .find("validate_connect_udp_request_shape")
        .expect("RFC 9298 shape check must remain present");
    let generic_425 = squeezed
        .find("ifis_early_data&&!state.early_data_methods.contains(&method){")
        .expect("generic 0-RTT method allowlist must remain present");
    let routing = squeezed
        .find("state.router_cache.find_proxy_in_epoch(")
        .expect("route lookup must remain present");
    let plugins = squeezed
        .find("letrequest_protocol=h3_plugin_protocol_for_request(")
        .expect("plugin protocol selection must remain present");
    let dns = squeezed
        .find("letbackend_resolved_ip=ifis_connect_udp_request{None}else{")
        .expect("CONNECT-UDP must skip the ordinary-backend DNS lookup");
    let tunnel = squeezed
        .find("crate::http3::connect_udp::boxed_handle_h3_connect_udp(")
        .expect("CONNECT-UDP dispatch must remain present");

    let arm = &squeezed[connect_udp_425..profile_501];
    assert!(
        arm.contains("StatusCode::TOO_EARLY"),
        "CONNECT-UDP 0-RTT must emit 425 Too Early"
    );
    assert!(
        arm.contains(r#"{"error":"CONNECT-UDPisnotallowedin0-RTTearlydata"}"#),
        "CONNECT-UDP 0-RTT must use a CONNECT-UDP-specific 425 body"
    );
    assert!(
        !arm.contains("early_data_methods.contains"),
        "CONNECT-UDP 0-RTT refusal must not consult the generic CONNECT allowlist"
    );
    assert!(
        connect_udp_425 < profile_501
            && connect_udp_425 < malformed
            && connect_udp_425 < generic_425
            && generic_425 < routing
            && routing < plugins
            && plugins < dns
            && dns < tunnel,
        "CONNECT-UDP 425 must precede 501/400, the generic method gate, routing, \
         plugins, DNS, and tunnel dispatch"
    );
}

#[test]
fn handle_h3_request_forces_plain_connect_udp_flavor_over_content_type() {
    let handler = handle_h3_request_source();
    let squeezed = squeeze(handler);
    assert!(
        squeezed.contains("letgrpc_web_response_content_type_owned=ifdetected_http_flavor==HttpFlavor::WebSocket||is_connect_udp_request{None}"),
        "CONNECT-UDP must suppress gRPC-Web shaping the same way WebSocket does"
    );
    assert!(
        squeezed.contains("lethttp_flavor=ifis_connect_udp_request{HttpFlavor::Plain}elseifgrpc_web_response_content_type.is_some(){HttpFlavor::Grpc}"),
        "CONNECT-UDP must force Plain rejection/plugin flavor before gRPC-Web promotion"
    );
    assert!(
        squeezed.contains("letrequest_protocol=h3_plugin_protocol_for_request(ifis_connect_udp_request{HttpFlavor::Plain}else{detected_http_flavor}"),
        "CONNECT-UDP plugin selection must use Plain, not a spoofed gRPC wire flavor"
    );
}

#[test]
fn handle_h3_request_skips_ordinary_backend_dns_for_connect_udp() {
    let handler = handle_h3_request_source();
    let squeezed = squeeze(handler);
    let skip = squeezed
        .find("letbackend_resolved_ip=ifis_connect_udp_request{None}else{")
        .expect("CONNECT-UDP must bind backend_resolved_ip to None without resolving");
    let resolve = squeezed[skip..]
        .find("state.dns_cache.resolve(")
        .expect("ordinary H3 dispatch must still resolve the selected backend");
    let tunnel = squeezed
        .find("crate::http3::connect_udp::boxed_handle_h3_connect_udp(")
        .expect("CONNECT-UDP dispatch must remain present");
    assert!(
        skip < tunnel,
        "the DNS skip must sit on the CONNECT-UDP path before tunnel dispatch"
    );
    assert!(
        skip + resolve < tunnel,
        "the ordinary resolve must remain in the else-arm, not run for CONNECT-UDP"
    );
}

#[test]
fn handle_h3_request_boxes_connect_udp_off_the_generic_h3_poll_frame() {
    // Stack-budget invariant: `handle_h3_request` is polled for every H3
    // stream, including ordinary Plain over ambient HBONE. Awaiting
    // `handle_h3_connect_udp` inline charges that capsule-relay future to
    // every request. The never-inlined trampoline must be the only dispatch
    // from the generic handler.
    let handler = handle_h3_request_source();
    assert!(
        handler.contains("crate::http3::connect_udp::boxed_handle_h3_connect_udp("),
        "CONNECT-UDP must leave handle_h3_request through the boxed factory"
    );
    assert!(
        !handler.contains("crate::http3::connect_udp::handle_h3_connect_udp("),
        "handle_h3_request must not materialize handle_h3_connect_udp in its poll frame"
    );

    let src = include_str!("../../../src/http3/connect_udp.rs");
    let factory = src
        .split("pub(crate) fn boxed_handle_h3_connect_udp(")
        .nth(1)
        .expect("boxed_handle_h3_connect_udp must exist")
        .split("pub(crate) async fn handle_h3_connect_udp(")
        .next()
        .expect("boxed factory must precede handle_h3_connect_udp");
    assert!(
        src.contains("#[inline(never)]\npub(crate) fn boxed_handle_h3_connect_udp("),
        "the CONNECT-UDP factory must be a never-inlined leaf"
    );
    let squeezed_factory = squeeze(factory);
    assert!(
        squeezed_factory
            .contains("Box::pin(asyncmove{handle_h3_connect_udp(stream,request).await})"),
        "the factory must box a trampoline, not construct handle_h3_connect_udp in its own frame"
    );
}

#[test]
fn functional_connect_udp_suite_covers_plain_grpc_content_type_rejection() {
    let src = include_str!("../../functional/functional_http3_connect_udp_test.rs");
    assert!(
        src.contains("functional_h3_connect_udp_refuses_spoofed_grpc_content_types_as_plain_400"),
        "the live suite must pin native-gRPC and gRPC-Web Content-Type as plain 400"
    );
    assert!(src.contains("application/grpc-web+proto"));
    assert!(src.contains("must be a plain malformed CONNECT-UDP rejection, not a gRPC 200"));
    assert!(
        src.contains("functional_h3_connect_udp_mtls_not_after_terminates_a_live_tunnel"),
        "the hosted H3 shard must cover mTLS notAfter as the CONNECT-UDP deadline"
    );
    assert!(
        src.contains("functional_h3_connect_udp_expiry_before_200_is_a_fixed_redacted_401"),
        "the hosted H3 shard must cover expiry before 200 commitment"
    );
    assert!(src.contains(
        "functional_h3_connect_udp_credential_expiry_terminates_a_continuously_active_tunnel"
    ));
    assert!(src.contains(
        "functional_h3_connect_udp_configured_maximum_lifetime_terminates_an_active_tunnel"
    ));
    assert!(src.contains(
        "functional_h3_connect_udp_flow_control_stalled_client_cannot_outlive_its_credential"
    ));
    assert!(src.contains(
        "functional_h3_connect_udp_unauthenticated_tunnels_are_untouched_by_the_contract"
    ));
}
