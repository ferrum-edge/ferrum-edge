//! Issue #2416 — the H1/H2 WebSocket backend dial must be configured from the
//! effective policy of the target it is actually dialing.
//!
//! Before the fix the WebSocket branch received only the retry-capped BASE
//! proxy and used it for every attempt: retry rotation moved the URL, the
//! admission target, and the circuit-breaker key to the next port but left the
//! dial's connect timeout, trust roots, client identity, and verification
//! posture at the unresolved route-level values. These tests pin the projection
//! itself (per attempt, per target) and the source-level wiring that feeds it,
//! plus the H3 parity the fix is written against. DNS override and TTL remain
//! route-level fields; the selected target changes the resolution hostname.

use std::borrow::Cow;
use std::collections::HashMap;

use ferrum_edge::_test_support::{
    resolve_backend_connection_proxy_for_target, websocket_backend_tls_sni_unsupported,
};
use ferrum_edge::config::types::{
    BackendScheme, BackendTlsConfig, Proxy, ResolvedPortOverride, UpstreamTarget,
};
use ferrum_edge::retry::{
    ErrorClass, WS_BACKEND_TLS_SNI_UNSUPPORTED, classify_boxed_setup_error, request_reached_wire,
};
use serde_json::json;

const PROXY_SOURCE: &str = include_str!("../../../src/proxy/mod.rs");
const H3_WS_SOURCE: &str = include_str!("../../../src/http3/websocket.rs");

// ── fixtures ────────────────────────────────────────────────────────────────

/// Base proxy: TLS backend, 5s connect budget, no per-port policy yet.
fn base_proxy() -> Proxy {
    let mut proxy: Proxy = serde_json::from_value(json!({
        "id": "ws-proxy",
        "backend_host": "chat.svc.cluster.local",
        "backend_port": 8443,
        "backend_scheme": "https",
        "backend_connect_timeout_ms": 5_000u64,
        "upstream_id": "chat-upstream",
    }))
    .expect("test proxy should deserialize");
    proxy.resolved_tls = BackendTlsConfig {
        server_ca_cert_path: Some("/etc/ferrum/base-ca.pem".to_string()),
        verify_server_cert: true,
        ..BackendTlsConfig::default_verify()
    };
    proxy
}

fn target(port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: "chat.svc.cluster.local".to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

/// A target whose declared Service (policy) port differs from the workload port
/// it dials — the Kubernetes `targetPort` remap shape.
fn remapped_target(dial_port: u16, policy_port: u16) -> UpstreamTarget {
    UpstreamTarget {
        service_port_policy_key: Some(policy_port),
        ..target(dial_port)
    }
}

fn tls_for_port(tag: &str) -> BackendTlsConfig {
    BackendTlsConfig {
        client_cert_path: Some(format!("/etc/ferrum/{tag}-client.pem")),
        client_key_path: Some(format!("/etc/ferrum/{tag}-client.key")),
        server_ca_cert_path: Some(format!("/etc/ferrum/{tag}-ca.pem")),
        verify_server_cert: true,
        sni: None,
        san_allow_list: vec![format!("spiffe://example.org/ns/default/sa/{tag}")],
        san_allow_list_key_digest: None,
        tls_refused: false,
    }
}

fn set_overrides(proxy: &mut Proxy, overrides: Vec<(u16, ResolvedPortOverride)>) {
    proxy.dispatch_port_overrides = Some(overrides.into_iter().collect());
}

/// The exact call the WebSocket dial loops make for one attempt.
fn dial_policy_for(proxy: &Proxy, selected: &UpstreamTarget) -> Proxy {
    resolve_backend_connection_proxy_for_target(proxy, Some(selected)).into_owned()
}

// ── initial target: distinct connect timeout ────────────────────────────────

#[test]
fn initial_target_uses_its_own_connect_timeout_not_the_base_budget() {
    let mut proxy = base_proxy();
    set_overrides(
        &mut proxy,
        vec![
            (
                8443,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(250),
                    ..Default::default()
                },
            ),
            (
                9443,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(7_000),
                    ..Default::default()
                },
            ),
        ],
    );

    // Selecting 9443 first must dial on 9443's budget — not the proxy default
    // and not the sibling port's.
    let on_9443 = dial_policy_for(&proxy, &target(9443));
    assert_eq!(on_9443.backend_connect_timeout_ms, 7_000);
    assert_eq!(on_9443.backend_port, 9443);

    let on_8443 = dial_policy_for(&proxy, &target(8443));
    assert_eq!(on_8443.backend_connect_timeout_ms, 250);

    assert_eq!(
        proxy.backend_connect_timeout_ms, 5_000,
        "the base proxy must not be mutated by a per-attempt projection"
    );
}

// ── initial target: distinct CA / client cert / verification ────────────────

#[test]
fn initial_target_uses_its_own_ca_client_cert_and_verification() {
    let mut proxy = base_proxy();
    let strict = tls_for_port("strict");
    let lenient = BackendTlsConfig {
        verify_server_cert: false,
        ..tls_for_port("lenient")
    };
    set_overrides(
        &mut proxy,
        vec![
            (
                8443,
                ResolvedPortOverride {
                    tls: Some(strict.clone()),
                    ..Default::default()
                },
            ),
            (
                9443,
                ResolvedPortOverride {
                    tls: Some(lenient.clone()),
                    ..Default::default()
                },
            ),
        ],
    );

    let on_9443 = dial_policy_for(&proxy, &target(9443));
    assert_eq!(on_9443.resolved_tls, lenient);
    assert!(
        !on_9443.resolved_tls.verify_server_cert,
        "9443's verification posture must reach the dial"
    );
    assert_eq!(
        on_9443.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/etc/ferrum/lenient-ca.pem"),
    );
    assert_eq!(
        on_9443.resolved_tls.client_cert_path.as_deref(),
        Some("/etc/ferrum/lenient-client.pem"),
    );

    let on_8443 = dial_policy_for(&proxy, &target(8443));
    assert_eq!(on_8443.resolved_tls, strict);
    assert!(on_8443.resolved_tls.verify_server_cert);
    assert_ne!(
        on_8443.resolved_tls, on_9443.resolved_tls,
        "sibling ports with distinct DestinationRule tls must not share trust material"
    );
    assert_ne!(
        proxy.resolved_tls, on_8443.resolved_tls,
        "the projection must actually replace the base trust material"
    );
}

// ── retry rotation across ports ─────────────────────────────────────────────

#[test]
fn every_retry_attempt_uses_the_policy_for_its_own_current_target() {
    let mut proxy = base_proxy();
    set_overrides(
        &mut proxy,
        vec![
            (
                8443,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(250),
                    tls: Some(tls_for_port("a")),
                    ..Default::default()
                },
            ),
            (
                9443,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(1_500),
                    tls: Some(tls_for_port("b")),
                    ..Default::default()
                },
            ),
            (
                7443,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(9_000),
                    tls: Some(tls_for_port("c")),
                    ..Default::default()
                },
            ),
        ],
    );

    // The attempt sequence a retry loop walks: initial target, then each
    // rotation. Resolution happens per iteration, so attempt N must see port
    // N's policy — never the previous attempt's carried forward.
    let rotation = [
        (8443u16, 250u64, "a"),
        (9443, 1_500, "b"),
        (7443, 9_000, "c"),
    ];
    let mut previous: Option<Proxy> = None;
    for (port, expected_timeout, tag) in rotation {
        let attempt = dial_policy_for(&proxy, &target(port));
        assert_eq!(
            attempt.backend_connect_timeout_ms, expected_timeout,
            "attempt on port {port} must dial on its own connect budget"
        );
        assert_eq!(
            attempt.resolved_tls.server_ca_cert_path.as_deref(),
            Some(format!("/etc/ferrum/{tag}-ca.pem").as_str()),
            "attempt on port {port} must dial with its own trust roots"
        );
        assert_eq!(attempt.backend_port, port);
        if let Some(prev) = previous {
            assert_ne!(
                prev.backend_connect_timeout_ms, attempt.backend_connect_timeout_ms,
                "a rotated attempt must not carry the previous target's timeout"
            );
            assert_ne!(
                prev.resolved_tls, attempt.resolved_tls,
                "a rotated attempt must not carry the previous target's TLS policy"
            );
        }
        previous = Some(attempt);
    }
}

#[test]
fn rotation_into_a_port_without_an_override_falls_back_to_the_base_policy() {
    let mut proxy = base_proxy();
    set_overrides(
        &mut proxy,
        vec![(
            8443,
            ResolvedPortOverride {
                connect_timeout_ms: Some(250),
                tls: Some(tls_for_port("a")),
                ..Default::default()
            },
        )],
    );

    let first = dial_policy_for(&proxy, &target(8443));
    assert_eq!(first.backend_connect_timeout_ms, 250);

    // Rotating to an unconfigured port must land on the PROXY default, not on
    // the previous target's tightened 250ms budget or its trust roots.
    let rotated = dial_policy_for(&proxy, &target(9443));
    assert_eq!(rotated.backend_connect_timeout_ms, 5_000);
    assert_eq!(rotated.resolved_tls, proxy.resolved_tls);
}

// ── no policy override: borrow only when no target rebase is needed ─────────

#[test]
fn matching_target_without_override_keeps_the_base_proxy_byte_for_byte() {
    let proxy = base_proxy();
    let selected = target(8443);
    let resolved = resolve_backend_connection_proxy_for_target(&proxy, Some(&selected));

    assert!(
        matches!(resolved, Cow::Borrowed(_)),
        "a matching target with no per-port override must not allocate a clone"
    );
    // `Proxy` has no `PartialEq`; compare its serialized form instead.
    assert_eq!(
        serde_json::to_value(resolved.as_ref()).expect("serialize"),
        serde_json::to_value(&proxy).expect("serialize")
    );

    // And with no selected target at all (direct-backend proxy).
    let none = resolve_backend_connection_proxy_for_target(&proxy, None);
    assert!(matches!(none, Cow::Borrowed(_)));
    assert_eq!(
        serde_json::to_value(none.as_ref()).expect("serialize"),
        serde_json::to_value(&proxy).expect("serialize")
    );
}

#[test]
fn different_target_without_policy_override_rebases_the_dial_identity() {
    let proxy = base_proxy();
    let selected = target(9443);
    let resolved = resolve_backend_connection_proxy_for_target(&proxy, Some(&selected));

    assert!(
        matches!(resolved, Cow::Owned(_)),
        "a different selected host/port needs a dispatch-local proxy clone"
    );
    assert_eq!(resolved.backend_host, selected.host);
    assert_eq!(resolved.backend_port, 9443);
    assert_eq!(resolved.backend_connect_timeout_ms, 5_000);
    assert_eq!(resolved.resolved_tls, proxy.resolved_tls);
}

#[test]
fn override_matching_the_base_value_still_avoids_a_clone() {
    let mut proxy = base_proxy();
    set_overrides(
        &mut proxy,
        vec![(
            8443,
            ResolvedPortOverride {
                connect_timeout_ms: Some(5_000),
                ..Default::default()
            },
        )],
    );
    let selected = target(8443);
    let resolved = resolve_backend_connection_proxy_for_target(&proxy, Some(&selected));
    assert!(
        matches!(resolved, Cow::Borrowed(_)),
        "an override equal to the base value must stay on the zero-alloc path"
    );
}

// ── policy port vs transport dial port (HBONE / mesh-mTLS) ──────────────────

#[test]
fn mesh_hbone_target_projects_the_policy_port_not_the_transport_dial_port() {
    let mut proxy = base_proxy();
    set_overrides(
        &mut proxy,
        vec![
            // The declared Service port — the POLICY port target selection chose.
            (
                80,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(1_200),
                    tls: Some(tls_for_port("service-80")),
                    ..Default::default()
                },
            ),
            // The workload port the plain transport would dial.
            (
                8080,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(4_444),
                    tls: Some(tls_for_port("workload-8080")),
                    ..Default::default()
                },
            ),
            // The Ambient HBONE transport listener. Never a policy source.
            (
                15008,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(60_000),
                    ..Default::default()
                },
            ),
        ],
    );

    let mut hbone = remapped_target(8080, 80);
    hbone.tags.insert("mesh.hbone".to_string(), "1".to_string());
    hbone
        .tags
        .insert("mesh.hbone_port".to_string(), "15008".to_string());

    let dial = dial_policy_for(&proxy, &hbone);
    assert_eq!(
        dial.backend_connect_timeout_ms, 1_200,
        "the HBONE dial budget comes from the selected POLICY port (80)"
    );
    assert_eq!(
        dial.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/etc/ferrum/service-80-ca.pem"),
        "the HBONE dial policy comes from the selected POLICY port, not the workload port"
    );
    assert_ne!(
        dial.backend_connect_timeout_ms, 60_000,
        "the HBONE tunnel listener port is a transport address, never a policy source"
    );

    // The transport still dials the target's own port; only the POLICY is
    // rebased. The dial-port key is mirrored to the selected service port's
    // policy so dial-port-keyed lookups (socket keepalive) agree with it.
    assert_eq!(dial.backend_port, 8080);
    let mirrored = dial
        .dispatch_port_overrides
        .as_ref()
        .and_then(|m| m.get(&8080))
        .expect("the dial port entry must exist");
    assert_eq!(mirrored.connect_timeout_ms, Some(1_200));
    assert_eq!(
        dial.dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&15008))
            .and_then(|o| o.connect_timeout_ms),
        Some(60_000),
        "the transport listener's own entry must be left untouched"
    );
}

#[test]
fn mesh_mtls_target_projects_the_policy_port_not_the_sidecar_listener() {
    let mut proxy = base_proxy();
    set_overrides(
        &mut proxy,
        vec![
            (
                443,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(900),
                    ..Default::default()
                },
            ),
            (
                15006,
                ResolvedPortOverride {
                    connect_timeout_ms: Some(45_000),
                    ..Default::default()
                },
            ),
        ],
    );

    let mut mtls = remapped_target(8443, 443);
    mtls.tags.insert("mesh.mtls".to_string(), "1".to_string());
    mtls.tags
        .insert("mesh.mtls_port".to_string(), "15006".to_string());

    let dial = dial_policy_for(&proxy, &mtls);
    assert_eq!(
        dial.backend_connect_timeout_ms, 900,
        "the sidecar mesh-mTLS dial budget comes from the declared Service port"
    );
    assert_ne!(dial.backend_connect_timeout_ms, 45_000);
}

// ── fail closed on a policy this transport cannot apply ─────────────────────

#[test]
fn per_target_sni_override_fails_the_websocket_dial_closed() {
    let mut proxy = base_proxy();
    assert!(
        !websocket_backend_tls_sni_unsupported(&proxy),
        "the base proxy carries no SNI override"
    );
    set_overrides(
        &mut proxy,
        vec![(
            9443,
            ResolvedPortOverride {
                tls: Some(BackendTlsConfig {
                    sni: Some("chat.internal.example".to_string()),
                    ..tls_for_port("sni")
                }),
                ..Default::default()
            },
        )],
    );

    // The override belongs to 9443 only: 8443 keeps dialing normally.
    let on_8443 = dial_policy_for(&proxy, &target(8443));
    let on_9443 = dial_policy_for(&proxy, &target(9443));
    assert!(
        !websocket_backend_tls_sni_unsupported(&on_8443),
        "a sibling port without an SNI override must keep dialing"
    );
    assert!(
        websocket_backend_tls_sni_unsupported(&on_9443),
        "a per-port SNI override must be caught for its own target rather than silently dropped"
    );
}

#[test]
fn plaintext_websocket_backends_are_unaffected_by_the_sni_guard() {
    let mut proxy = base_proxy();
    proxy.backend_scheme = Some(BackendScheme::Http);
    proxy.resolved_tls.sni = Some("chat.internal.example".to_string());
    assert!(
        !websocket_backend_tls_sni_unsupported(&proxy),
        "a plaintext ws:// backend has no server name to verify"
    );
}

#[test]
fn sni_refusal_is_non_retryable_and_backend_health_neutral() {
    let error: Box<dyn std::error::Error + Send + Sync> = WS_BACKEND_TLS_SNI_UNSUPPORTED.into();
    let class = classify_boxed_setup_error(error.as_ref());
    assert_eq!(
        class,
        ErrorClass::DispatchPolicyRejected,
        "a gateway-side pre-dial refusal must not be reported as a backend TLS failure \
         (TlsError would replay under retry_on_connect_failure and charge the breaker)"
    );
    // Both WebSocket dial loops gate a replay on `!request_reached_wire(class)`
    // and route `DispatchPolicyRejected` into the health-neutral egress-denied
    // arm, so this refusal neither retries nor charges backend health.
    assert!(
        request_reached_wire(class),
        "a terminal gateway decision must not satisfy the pre-wire retry gate"
    );
    assert!(
        !WS_BACKEND_TLS_SNI_UNSUPPORTED.contains("chat.internal"),
        "the refusal must not carry the configured server name"
    );
}

// ── source wiring: resolution happens per attempt, inside the loop ──────────
//
// The projection tests above prove the POLICY is per-target. These pin the
// WIRING that feeds it: that the resolution lives inside the retry loop (so a
// rotation re-resolves rather than reusing attempt one's value) and that both
// dial arms consume it. Needles are matched against a whitespace-stripped copy
// of the source so rustfmt line-wrapping cannot make them brittle.

/// Collapse all whitespace so `foo(\n  a,\n  b,\n)` and `foo(a, b)` match.
fn squeeze(source: &str) -> String {
    source.split_whitespace().collect()
}

/// Byte offsets of the H1/H2 WebSocket backend-handshake loop.
fn h1_h2_ws_loop() -> &'static str {
    let handler = PROXY_SOURCE
        .find("async fn handle_websocket_request_authenticated(")
        .expect("H1/H2 WebSocket handler must remain present");
    let loop_start = PROXY_SOURCE[handler..]
        .find("let backend_handshake = loop {")
        .map(|offset| handler + offset)
        .expect("H1/H2 WebSocket backend handshake loop must remain present");
    let loop_end = PROXY_SOURCE[loop_start..]
        .find("match ws_dial_result {")
        .map(|offset| loop_start + offset)
        .expect("H1/H2 WebSocket dial dispatch must remain present");
    &PROXY_SOURCE[loop_start..loop_end]
}

/// The H3 WebSocket backend-handshake loop, for parity comparisons. Bounded at
/// the inline test module so H3's own source-grep guard (which embeds these
/// same needles as string literals) cannot satisfy the assertions below.
fn h3_ws_loop() -> &'static str {
    let start = H3_WS_SOURCE
        .find("let backend_handshake = loop {")
        .expect("H3 WebSocket backend handshake loop must remain present");
    let end = H3_WS_SOURCE[start..]
        .find("#[cfg(test)]")
        .map(|offset| start + offset)
        .unwrap_or(H3_WS_SOURCE.len());
    &H3_WS_SOURCE[start..end]
}

#[test]
fn h1_h2_websocket_loop_resolves_the_effective_proxy_inside_the_retry_loop() {
    let body = squeeze(h1_h2_ws_loop());
    let resolve = body
        .find("resolve_backend_connection_proxy_for_target(&proxy,current_target.as_deref())")
        .expect("H1/H2 WebSocket dial must resolve the effective proxy for current_target");
    let dispatch = body
        .find("letws_dial_result:")
        .expect("the H1/H2 WebSocket dial dispatch must remain present");
    assert!(
        resolve < dispatch,
        "the per-attempt policy must be resolved before the dial is dispatched"
    );
}

#[test]
fn both_h1_h2_websocket_dial_paths_receive_the_target_effective_proxy() {
    let body = squeeze(h1_h2_ws_loop());
    assert!(
        body.contains("connect_mesh_websocket_backend(&state,ws_dial_proxy,"),
        "the mesh WebSocket dial must use the target-effective proxy"
    );
    assert!(
        body.contains("connect_websocket_backend(&current_backend_url,ws_dial_proxy,"),
        "the direct WebSocket dial must use the target-effective proxy"
    );

    // The unresolved base proxy must not reach either dial. Both call sites
    // formerly passed `&proxy`; a regression would reintroduce exactly that.
    assert!(
        !body.contains("connect_websocket_backend(&current_backend_url,&proxy,"),
        "the direct WebSocket dial must never fall back to the unresolved base proxy"
    );
    assert!(
        !body.contains("connect_mesh_websocket_backend(&state,&proxy,"),
        "the mesh WebSocket dial must never fall back to the unresolved base proxy"
    );
}

#[test]
fn h1_h2_and_h3_websocket_bridges_share_one_target_effective_helper() {
    // Protocol-drift guard: both bridges must project per attempt through the
    // SAME helper, so a future change to one cannot silently diverge.
    // No closing paren in the needle: rustfmt gives the vertically-formatted H3
    // call a trailing comma the inline H1/H2 call does not have.
    const HELPER: &str =
        "resolve_backend_connection_proxy_for_target(&proxy,current_target.as_deref()";
    assert!(
        squeeze(h1_h2_ws_loop()).contains(HELPER),
        "the H1/H2 WebSocket loop must use the shared target-effective helper"
    );

    let h3_body = squeeze(h3_ws_loop());
    let h3_resolve = h3_body
        .find(HELPER)
        .expect("the H3 WebSocket loop must keep using the shared target-effective helper");
    let h3_dial = h3_body
        .find("connect_websocket_backend(&current_backend_url,ws_dial_proxy,")
        .expect("the H3 WebSocket dial must use the target-effective proxy");
    assert!(
        h3_resolve < h3_dial,
        "H3 must keep resolving the policy before dialing (no regression)"
    );
}

#[test]
fn websocket_max_connections_gate_stays_keyed_on_the_policy_port() {
    // The DestinationRule maxConnections admission check is target-specific by
    // POLICY port on both bridges; the fix must not move it to the dial port.
    for (label, body) in [
        ("H1/H2", squeeze(h1_h2_ws_loop())),
        ("H3", squeeze(h3_ws_loop())),
    ] {
        assert!(
            body.contains("resolve_backend_max_connections(&proxy,ws_policy_port)"),
            "{label} WebSocket maxConnections gate must stay keyed on the policy port"
        );
        assert!(
            body.contains("try_acquire(ws_dial_host,ws_policy_port,ws_max_connections,)"),
            "{label} WebSocket connection-limit slot must be keyed on the policy port"
        );
    }
}

#[test]
fn websocket_retry_rotation_rechecks_destination_rule_max_retries() {
    // Mixed-port retry rotation must re-check DestinationRule maxRetries against
    // the original route ceiling: a stricter/zero candidate is refused before
    // dial, while a looser candidate may continue up to min(route, candidate_cap).
    //
    // H1/H2's existing loop slice ends at `match ws_dial_result` (before the
    // Err-arm retry rotation), so inspect the full authenticated handler there.
    let h1_handler = {
        let start = PROXY_SOURCE
            .find("async fn handle_websocket_request_authenticated(")
            .expect("H1/H2 WebSocket handler must remain present");
        let end = PROXY_SOURCE[start..]
            .find("\nasync fn ")
            .map(|offset| start + offset)
            .unwrap_or(PROXY_SOURCE.len());
        squeeze(&PROXY_SOURCE[start..end])
    };
    let h3_body = squeeze(h3_ws_loop());

    for (label, body) in [("H1/H2", h1_handler.as_str()), ("H3", h3_body.as_str())] {
        assert!(
            body.contains("retry_attempt_allowed_for_target("),
            "{label} WebSocket retry must re-check DestinationRule maxRetries for candidates"
        );
        assert!(
            body.contains("current_retry_attempt_allowed("),
            "{label} WebSocket retry must re-check DestinationRule maxRetries for the current target"
        );
        assert!(
            body.contains("route_retry_ceiling"),
            "{label} WebSocket retry must authorize against the original route ceiling"
        );
        let selection_needle = if label == "H3" {
            "select_next_h3_eligible_retry_target("
        } else {
            "select_next_retry_target("
        };
        let selection = body.find(selection_needle).unwrap_or_else(|| {
            panic!("{label} WebSocket retry rotation must remain present ({selection_needle})")
        });
        let candidate_cap = body
            .find("retry_attempt_allowed_for_target(")
            .unwrap_or_else(|| {
                panic!("{label} WebSocket candidate maxRetries gate must remain present")
            });
        assert!(
            selection < candidate_cap,
            "{label} WebSocket must re-resolve maxRetries after selecting the retry candidate"
        );
    }
}

/// Bounded source of `handle_h3_websocket` so rustfmt wrapping and the inline
/// test module cannot satisfy the Host/authority parity needles below.
fn h3_ws_handler() -> &'static str {
    let start = H3_WS_SOURCE
        .find("pub(crate) async fn handle_h3_websocket(")
        .expect("H3 WebSocket handler must remain present");
    let end = H3_WS_SOURCE[start..]
        .find("#[cfg(test)]")
        .map(|offset| start + offset)
        .unwrap_or(H3_WS_SOURCE.len());
    &H3_WS_SOURCE[start..end]
}

fn h1_h2_ws_handler() -> &'static str {
    let start = PROXY_SOURCE
        .find("async fn handle_websocket_request_authenticated(")
        .expect("H1/H2 WebSocket handler must remain present");
    let end = PROXY_SOURCE[start..]
        .find("\nasync fn ")
        .map(|offset| start + offset)
        .unwrap_or(PROXY_SOURCE.len());
    &PROXY_SOURCE[start..end]
}

fn mesh_ws_connector() -> &'static str {
    let start = PROXY_SOURCE
        .find("pub(crate) async fn connect_mesh_websocket_backend(")
        .expect("shared mesh WebSocket connector must remain present");
    let end = PROXY_SOURCE[start..]
        .find("\npub(crate) async fn ")
        .map(|offset| start + offset)
        .unwrap_or(PROXY_SOURCE.len());
    &PROXY_SOURCE[start..end]
}

/// H3 WebSocket mesh egress must pass the materialized client Host (including
/// an explicit port such as `Example.COM:8443`) into the shared connector, just
/// as H1/H2 does. The normalized `request_host` stays the routing / retry key.
#[test]
fn h3_websocket_mesh_egress_uses_materialized_host_not_routing_host() {
    const MATERIALIZED_HOST: &str = "Example.COM:8443";

    // Routing / retry hashing is intentionally portless and lowercased.
    assert_eq!(
        ferrum_edge::proxy::normalize_request_host_for_routing(MATERIALIZED_HOST).as_deref(),
        Some("example.com"),
        "retry selection and wildcard concretization keep the normalized routing host"
    );

    let h1_body = squeeze(h1_h2_ws_handler());
    let h3_body = squeeze(h3_ws_handler());

    const HOST_CAPTURE: &str = "letws_client_host=ctx.headers.get(\"host\").cloned();";
    assert!(
        h1_body.contains(HOST_CAPTURE),
        "H1/H2 WebSocket mesh egress must read the client Host from the materialized header map"
    );
    assert!(
        h3_body.contains(HOST_CAPTURE),
        "H3 WebSocket mesh egress must read the client Host from the materialized header map, \
         matching H1/H2 (including an H3 `:authority` back-fill such as `{MATERIALIZED_HOST}`)"
    );

    const MESH_WITH_CLIENT_HOST: &str = "connect_mesh_websocket_backend(&state,ws_dial_proxy,target,egress,ws_client_host.as_deref(),";
    const MESH_WITH_ROUTING_HOST: &str = "connect_mesh_websocket_backend(&state,ws_dial_proxy,target,egress,request_host.as_deref(),";
    assert!(
        h1_body.contains(MESH_WITH_CLIENT_HOST),
        "H1/H2 must pass the materialized Host verbatim to the shared mesh WS connector"
    );
    assert!(
        h3_body.contains(MESH_WITH_CLIENT_HOST),
        "H3 must pass the materialized Host (e.g. `{MATERIALIZED_HOST}`) verbatim to the \
         shared mesh WS connector"
    );
    assert!(
        !h3_body.contains(MESH_WITH_ROUTING_HOST),
        "H3 must not substitute the port-stripped routing host into the mesh WS connector"
    );
    assert!(
        h3_body.contains("request_authority:request_host.as_deref()"),
        "H3 WebSocket retry selection must keep using the normalized routing host"
    );

    // H3 synthesizes a missing Host from `:authority` without stripping the
    // explicit port or lowercasing, so `{MATERIALIZED_HOST}` survives into
    // `ctx.headers["host"]` for the capture above.
    let h3_server = squeeze(include_str!("../../../src/http3/server.rs"));
    assert!(
        h3_server
            .contains("ctx.headers.insert(\"host\".to_string(),authority.as_str().to_string());"),
        "H3 must materialize a missing Host from `:authority` verbatim, including an explicit port"
    );

    // Service-authority-tag branch: when `mesh.mtls_authority_host` replaces
    // Host, the shared connector stamps `x-forwarded-host` from `client_host`.
    // H3 must not duplicate that rewrite; passing the materialized Host is
    // enough for `{MATERIALIZED_HOST}` to appear on `x-forwarded-host`.
    let connector = squeeze(mesh_ws_connector());
    let service_tag = connector
        .find("target_mesh_mtls_authority_host(target)")
        .expect("sidecar service-authority tag must still select the peer :authority");
    let xfh = connector[service_tag..]
        .find("augmented.push((\"x-forwarded-host\".to_string(),host.to_string()));")
        .expect(
            "service-authority tag must stamp x-forwarded-host from the connector's client_host",
        );
    let host_from_client = connector[service_tag..]
        .find("client_host.filter(|host|!host.is_empty())")
        .expect("x-forwarded-host must be sourced from the connector client_host argument");
    assert!(
        host_from_client < xfh,
        "x-forwarded-host must be copied from client_host before the service-authority rewrite"
    );
    assert!(
        !h3_body.contains("x-forwarded-host"),
        "H3 must not duplicate the shared connector's x-forwarded-host rewrite"
    );
}

/// Ambient HBONE WebSocket establishment captures one absolute deadline
/// before tunnel acquisition and reuses it for the inner H1 101 wait
/// (issue #3620). A fresh relative `timeout` after the tunnel would give
/// one establishment two full connect budgets.
#[test]
fn ambient_hbone_websocket_reuses_one_establishment_deadline() {
    let connector = mesh_ws_connector();
    let ambient = connector
        .split("MeshWsEgress::AmbientHbone =>")
        .nth(1)
        .expect("Ambient HBONE WebSocket branch must remain present");

    let deadline = ambient
        .find("establishment_deadline")
        .expect("one absolute establishment deadline must be captured");
    let tunnel = ambient
        .find("get_ws_byte_tunnel(")
        .expect("HBONE byte-tunnel acquisition must remain present");
    let handshake = ambient
        .find("client_async_with_config(")
        .expect("inner H1 WebSocket handshake must remain present");
    assert!(
        deadline < tunnel,
        "the establishment deadline must be captured before tunnel acquisition"
    );
    assert!(
        tunnel < handshake,
        "the inner handshake must follow tunnel acquisition"
    );

    let first_helper = ambient
        .find("await_deadline_first(")
        .expect("tunnel acquisition must race the expiration-first helper");
    let second_helper = ambient[first_helper + 1..]
        .find("await_deadline_first(")
        .map(|offset| first_helper + 1 + offset)
        .expect("the inner handshake must reuse the same expiration-first helper");
    assert!(
        first_helper < tunnel && tunnel < second_helper && second_helper < handshake,
        "both tunnel acquisition and the inner handshake must be bounded by \
         await_deadline_first on the shared deadline"
    );
    assert!(
        !ambient.contains("tokio::time::timeout("),
        "Ambient establishment must not start a second full relative connect budget"
    );
    assert!(
        !ambient.contains("timeout_at("),
        "Ambient establishment must not use inner-first timeout_at ordering"
    );
    assert!(
        ambient.contains("POST-wire"),
        "the inner handshake timeout must be documented as POST-wire: the \
         RFC 6455 upgrade is written before awaiting 101"
    );
}
