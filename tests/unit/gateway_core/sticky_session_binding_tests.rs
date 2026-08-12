//! Backend-bound sticky-session token coverage (issue #3278 / PR #3585).
//!
//! Gateway API session persistence requires a client to return to the backend
//! that served its initial response — not merely to *a* deterministic backend.
//! These tests pin the read side of that contract (`LoadBalancer::select_sticky`)
//! and the boundary handling of untrusted cookie input:
//!
//! - a token minted for a target resolves to that exact target;
//! - malformed, oversized, empty, uppercase, and non-hex values are rejected by
//!   bounded validation and never resolve;
//! - a token minted under another upstream identity (another route / service /
//!   namespace / BackendLBPolicy) does not steer traffic across that boundary;
//! - a token whose backend was removed, ejected by health, or lives outside the
//!   selected subset / port lane resolves to nothing, so the caller falls back
//!   to ordinary selection instead of dialing an ineligible target;
//! - two entries of ONE upstream that share a pod IP and dial port but differ in
//!   Service identity or declared Service port keep separate bindings, and
//!   neither reaches into the other's per-port policy lane;
//! - a wildcard-hosted target is dialed through a per-request concretized clone
//!   whose host is the request authority, yet mints — and honors — the cookie of
//!   the CONFIGURED entry the binding index is keyed by;
//! - retry selection reconciles that dial clone back to the configured identity
//!   for exclusion, re-concretizes the next candidate, and fails closed rather
//!   than dialing a literal `*.example.com`.
//!
//! Translation and the emitted `Set-Cookie` shape live in
//! `gateway_backend_lb_policy_tests.rs`.

use std::collections::HashMap;

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, Proxy, SubsetDefinition, Upstream, UpstreamPortOverride,
    UpstreamTarget,
};
use ferrum_edge::config::types::{
    UPSTREAM_TARGET_SERVICE_NAME_TAG, UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG,
    UPSTREAM_TARGET_SERVICE_PORT_TAG,
};
use ferrum_edge::load_balancer::{
    HealthContext, LoadBalancerCache, STICKY_SESSION_TOKEN_LEN, is_sticky_session_token,
    sticky_session_token,
};
use sha2::{Digest, Sha256};

const NAMESPACE: &str = "ferrum";
const UPSTREAM_ID: &str = "gwapi-route-upstream-default-sample-r0";

fn target(host: &str, port: u16) -> UpstreamTarget {
    tagged_target(host, port, &[])
}

fn tagged_target(host: &str, port: u16, tags: &[(&str, &str)]) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: tags
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        locality: None,
        path: None,
    }
}

fn sticky_upstream(targets: Vec<UpstreamTarget>) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: UPSTREAM_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        name: Some(UPSTREAM_ID.to_string()),
        targets,
        algorithm: LoadBalancerAlgorithm::ConsistentHashing,
        hash_on: Some("cookie:lb-affinity-fe-0123456789abcdef".to_string()),
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: HashMap::new(),
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
        k8s_service_uid: None,
        pending_limit_scope: None,
    }
}

fn cache_for(upstream: Upstream) -> LoadBalancerCache {
    LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    })
}

/// The scope string a token is bound to: the namespace-qualified upstream
/// identity `LoadBalancerCache` keys balancers by.
fn scope(namespace: &str, upstream_id: &str) -> String {
    format!("{namespace}|{upstream_id}")
}

fn token_for(namespace: &str, upstream_id: &str, target: &UpstreamTarget) -> String {
    sticky_session_token(&scope(namespace, upstream_id), target)
        .expect("test cryptographic provider must initialize the sticky-session key")
}

#[test]
fn emitted_token_resolves_to_the_exact_minting_backend() {
    let targets = vec![
        target("10.1.0.10", 8080),
        target("10.1.0.11", 8080),
        target("10.1.0.12", 8080),
    ];
    let cache = cache_for(sticky_upstream(targets.clone()));
    let snapshot = cache.load();

    for expected in &targets {
        let token = token_for(NAMESPACE, UPSTREAM_ID, expected);
        assert!(is_sticky_session_token(&token));
        assert_eq!(token.len(), STICKY_SESSION_TOKEN_LEN);

        // Repeat: the binding must not drift request to request.
        for _ in 0..10 {
            let bound = LoadBalancerCache::select_sticky_from(
                &snapshot,
                NAMESPACE,
                UPSTREAM_ID,
                &token,
                None,
                None,
                None,
            )
            .expect("minted token must resolve to its backend");
            assert_eq!(bound.host, expected.host);
            assert_eq!(bound.port, expected.port);
        }
    }
}

#[test]
fn distinct_backends_mint_distinct_tokens() {
    let a = target("10.1.0.10", 8080);
    let b = target("10.1.0.11", 8080);
    let other_port = target("10.1.0.10", 9090);
    let token_a = token_for(NAMESPACE, UPSTREAM_ID, &a);
    let token_b = token_for(NAMESPACE, UPSTREAM_ID, &b);
    let token_other_port = token_for(NAMESPACE, UPSTREAM_ID, &other_port);
    assert_ne!(token_a, token_b);
    assert_ne!(token_a, token_other_port);
}

#[test]
fn predictable_route_and_backend_metadata_cannot_forge_a_binding() {
    let backend = target("10.1.0.11", 8080);
    let cache = cache_for(sticky_upstream(vec![backend.clone()]));
    let snapshot = cache.load();

    // This mirrors the vulnerable unkeyed construction: knowing the public
    // domain, route scope, and endpoint was sufficient to manufacture a token.
    let mut digest = Sha256::new();
    digest.update(b"ferrum-sticky-session-v3");
    digest.update([0x1f]);
    digest.update((scope(NAMESPACE, UPSTREAM_ID).len() as u64).to_be_bytes());
    digest.update(scope(NAMESPACE, UPSTREAM_ID));
    digest.update((backend.host.len() as u64).to_be_bytes());
    digest.update(backend.host.as_bytes());
    digest.update(backend.port.to_be_bytes());
    digest.update([0, 0, 0]);
    digest.update([0, 0]);
    digest.update(0u64.to_be_bytes());
    let forged = hex::encode(digest.finalize());

    assert!(is_sticky_session_token(&forged));
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &forged,
            None,
            None,
            None,
        )
        .is_none(),
        "an unkeyed digest of predictable metadata must not authenticate"
    );
}

#[test]
fn a_reload_keeps_outstanding_bindings_resolvable() {
    let pinned = target("10.1.0.10", 8080);
    let targets = vec![pinned.clone(), target("10.1.0.11", 8080)];
    let cache = cache_for(sticky_upstream(targets.clone()));
    let token = token_for(NAMESPACE, UPSTREAM_ID, &pinned);

    assert!(
        LoadBalancerCache::select_sticky_from(
            &cache.load(),
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .is_some(),
        "the freshly minted binding must resolve before the reload"
    );

    // The authentication key is process-local, NOT per-balancer. A reload
    // rebuilds every binding index from the configured targets, and those
    // indexes must still be keyed by the tokens clients are already holding.
    // Were the key re-derived per build, every outstanding session would miss,
    // fall back to ordinary selection, and be handed a fresh cookie on every
    // response — the reissue churn that mint/index disagreement produces.
    cache.rebuild(&GatewayConfig {
        upstreams: vec![sticky_upstream(targets)],
        ..GatewayConfig::default()
    });

    let after = cache.load();
    let bound = LoadBalancerCache::select_sticky_from(
        &after,
        NAMESPACE,
        UPSTREAM_ID,
        &token,
        None,
        None,
        None,
    )
    .expect("a reload must not invalidate an outstanding binding");
    assert_eq!(bound.host, pinned.host);
    assert_eq!(bound.port, pinned.port);
}

#[test]
fn malformed_and_oversized_tokens_are_rejected_at_the_boundary() {
    let pinned = target("10.1.0.10", 8080);
    let targets = vec![pinned.clone(), target("10.1.0.11", 8080)];
    let cache = cache_for(sticky_upstream(targets));
    let snapshot = cache.load();
    let valid = token_for(NAMESPACE, UPSTREAM_ID, &pinned);

    let hostile = [
        String::new(),
        "not-a-token".to_string(),
        valid[..STICKY_SESSION_TOKEN_LEN - 1].to_string(),
        format!("{valid}0"),
        valid.to_ascii_uppercase(),
        // Right length, wrong alphabet.
        "g".repeat(STICKY_SESSION_TOKEN_LEN),
        format!("{}\n{}", &valid[..32], &valid[32..]),
        // Oversized: length is checked first, so this costs one comparison.
        "a".repeat(1024 * 1024),
        format!("{valid}; Path=/"),
    ];

    for value in &hostile {
        assert!(
            !is_sticky_session_token(value),
            "hostile value must fail bounded validation"
        );
        assert!(
            LoadBalancerCache::select_sticky_from(
                &snapshot,
                NAMESPACE,
                UPSTREAM_ID,
                value,
                None,
                None,
                None,
            )
            .is_none(),
            "hostile value must not resolve to a backend"
        );
    }

    // A well-formed but unknown token (right shape, never minted here) is
    // likewise unbound rather than a wildcard.
    let unknown = "0".repeat(STICKY_SESSION_TOKEN_LEN);
    assert!(is_sticky_session_token(&unknown));
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &unknown,
            None,
            None,
            None,
        )
        .is_none()
    );

    // The genuine token still works — the rejections above are not blanket.
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &valid,
            None,
            None,
            None,
        )
        .is_some()
    );
}

#[test]
fn tokens_do_not_cross_route_service_or_namespace_scopes() {
    let pinned = target("10.1.0.10", 8080);
    let targets = vec![pinned.clone(), target("10.1.0.11", 8080)];
    let cache = cache_for(sticky_upstream(targets));
    let snapshot = cache.load();
    let local = token_for(NAMESPACE, UPSTREAM_ID, &pinned);

    // Same backend address, minted under a different route rule's upstream, a
    // different Service-derived upstream, and a different namespace. All three
    // are foreign scopes and must not steer traffic here.
    let foreign_scopes = [
        (NAMESPACE, "gwapi-route-upstream-default-sample-r1"),
        (NAMESPACE, "gwapi-route-upstream-default-other-r0"),
        ("tenant-b", UPSTREAM_ID),
    ];
    for (ns, id) in foreign_scopes {
        let foreign = token_for(ns, id, &pinned);
        assert_ne!(foreign, local, "foreign scopes must differ");
        assert!(
            LoadBalancerCache::select_sticky_from(
                &snapshot,
                NAMESPACE,
                UPSTREAM_ID,
                &foreign,
                None,
                None,
                None,
            )
            .is_none(),
            "foreign-scope token must not resolve inside {NAMESPACE}|{UPSTREAM_ID}"
        );
    }
}

#[test]
fn stale_token_for_a_removed_backend_does_not_resolve() {
    let removed = target("10.1.0.12", 8080);
    let token = token_for(NAMESPACE, UPSTREAM_ID, &removed);

    let full = vec![
        target("10.1.0.10", 8080),
        target("10.1.0.11", 8080),
        removed.clone(),
    ];
    let before = cache_for(sticky_upstream(full));
    assert!(
        LoadBalancerCache::select_sticky_from(
            &before.load(),
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .is_some(),
        "precondition: the token resolves while the backend exists"
    );

    // Scale-down / EndpointSlice update drops that endpoint; the index is
    // rebuilt with the balancer, so the old token becomes unbound.
    let shrunk = vec![target("10.1.0.10", 8080), target("10.1.0.11", 8080)];
    let after = cache_for(sticky_upstream(shrunk));
    assert!(
        LoadBalancerCache::select_sticky_from(
            &after.load(),
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .is_none(),
        "a token for a removed backend must not resolve"
    );
}

#[test]
fn unhealthy_pinned_backend_is_not_selected() {
    let pinned = target("10.1.0.10", 8080);
    let targets = vec![pinned.clone(), target("10.1.0.11", 8080)];
    let cache = cache_for(sticky_upstream(targets));
    let snapshot = cache.load();
    let token = token_for(NAMESPACE, UPSTREAM_ID, &pinned);

    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(format!("{NAMESPACE}|{UPSTREAM_ID}::10.1.0.10:8080"), 0u64);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            Some(&health),
        )
        .is_none(),
        "an ejected pinned backend must not be dialed"
    );
    // Recovery re-pins without a new cookie: the binding itself is unchanged.
    active_unhealthy.clear();
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            Some(&health),
        )
        .is_some()
    );
}

#[test]
fn sticky_binding_respects_subset_scoping() {
    let v1 = tagged_target("10.1.0.10", 8080, &[("version", "v1")]);
    let v2 = tagged_target("10.1.0.11", 8080, &[("version", "v2")]);
    let mut upstream = sticky_upstream(vec![v1.clone(), v2.clone()]);
    upstream.subsets = Some(vec![
        SubsetDefinition {
            name: "v1".to_string(),
            labels: HashMap::from([("version".to_string(), "v1".to_string())]),
            traffic_policy: None,
        },
        SubsetDefinition {
            name: "v2".to_string(),
            labels: HashMap::from([("version".to_string(), "v2".to_string())]),
            traffic_policy: None,
        },
    ]);
    let cache = cache_for(upstream);
    let snapshot = cache.load();
    let v1_token = token_for(NAMESPACE, UPSTREAM_ID, &v1);

    let in_subset = LoadBalancerCache::select_sticky_from(
        &snapshot,
        NAMESPACE,
        UPSTREAM_ID,
        &v1_token,
        None,
        Some("v1"),
        None,
    )
    .expect("v1 token resolves inside the v1 subset");
    assert_eq!(in_subset.host, "10.1.0.10");

    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &v1_token,
            None,
            Some("v2"),
            None,
        )
        .is_none(),
        "a v1 binding must not escape into the v2 subset"
    );
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &v1_token,
            None,
            Some("does-not-exist"),
            None,
        )
        .is_none(),
        "an unknown subset has no candidate pool at all"
    );
}

#[test]
fn sticky_binding_respects_port_lane_scoping() {
    let http = target("10.1.0.10", 8080);
    let grpc = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![http.clone(), grpc.clone()]);
    upstream
        .port_overrides
        .insert(8080, UpstreamPortOverride::default());
    upstream
        .port_overrides
        .insert(9090, UpstreamPortOverride::default());
    let cache = cache_for(upstream);
    let snapshot = cache.load();
    let http_token = token_for(NAMESPACE, UPSTREAM_ID, &http);

    let same_lane = LoadBalancerCache::select_sticky_from(
        &snapshot,
        NAMESPACE,
        UPSTREAM_ID,
        &http_token,
        Some(8080),
        None,
        None,
    )
    .expect("token resolves inside its own port lane");
    assert_eq!(same_lane.port, 8080);

    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &http_token,
            Some(9090),
            None,
            None,
        )
        .is_none(),
        "an 8080-lane binding must not be dialed on the 9090 lane"
    );
}

#[test]
fn non_cookie_upstreams_build_no_binding_index() {
    // An upstream that cannot mint tokens must not resolve one either, so the
    // index stays empty (and free) outside session-persistence configurations.
    let pinned = target("10.1.0.10", 8080);
    let targets = vec![pinned.clone(), target("10.1.0.11", 8080)];
    let mut upstream = sticky_upstream(targets);
    upstream.hash_on = Some("ip".to_string());
    let cache = cache_for(upstream);

    assert!(
        LoadBalancerCache::select_sticky_from(
            &cache.load(),
            NAMESPACE,
            UPSTREAM_ID,
            &token_for(NAMESPACE, UPSTREAM_ID, &pinned),
            None,
            None,
            None,
        )
        .is_none()
    );
}

#[test]
fn unknown_upstream_identity_never_panics() {
    let pinned = target("10.1.0.10", 8080);
    let cache = cache_for(sticky_upstream(vec![pinned.clone()]));
    assert!(
        LoadBalancerCache::select_sticky_from(
            &cache.load(),
            "no-such-namespace",
            "no-such-upstream",
            &token_for(NAMESPACE, UPSTREAM_ID, &pinned),
            None,
            None,
            None,
        )
        .is_none()
    );
}

// ---------------------------------------------------------------------------
// Retry-rotation reissue (root review finding 1)
// ---------------------------------------------------------------------------
//
// Selection decides "does this response need a cookie?" BEFORE any backend is
// dialed, so an honored binding carries `false`. Every retry-capable dispatch
// path (H1/H2, direct gRPC, WebSocket incl. H2 extended CONNECT, native H3, the
// H3→HTTP and H3→gRPC cross-protocol bridges, H3 WebSocket) can then rotate off
// that target. Carrying the stale `false` through to response-cookie injection
// leaves the client pinned to the backend that just failed — retry rotation
// does not necessarily eject it. These pin the shared derivation every one of
// those paths now routes through.

/// Two distinct `UpstreamTarget` values for the same endpoint, so the assertion
/// cannot pass merely because both sides are the same allocation.
fn distinct_clone(t: &UpstreamTarget) -> UpstreamTarget {
    target(&t.host, t.port)
}

#[test]
fn honored_binding_that_served_its_own_backend_is_not_reissued() {
    let bound = target("10.1.0.10", 8080);
    let served = distinct_clone(&bound);

    assert!(
        ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
            false,
            Some(&bound),
            Some(&served),
        )
        .is_none(),
        "a binding honored end-to-end must not re-mint the identical token"
    );
}

#[test]
fn honored_binding_reissues_for_the_backend_a_retry_rotated_onto() {
    let bound = target("10.1.0.10", 8080);
    let rotated = target("10.1.0.11", 8080);

    let reissue = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
        // Selection honored the presented cookie: `false` at selection time.
        false,
        Some(&bound),
        // Retry then rotated; this is the backend that produced the response.
        Some(&rotated),
    )
    .expect("a rotation off the bound backend must reissue");
    assert_eq!((reissue.host.as_str(), reissue.port), ("10.1.0.11", 8080));

    // ... and the token that reissue mints resolves back to that same backend,
    // so the client's NEXT request lands there instead of on the failed one.
    let cache = cache_for(sticky_upstream(vec![bound.clone(), rotated.clone()]));
    let next = LoadBalancerCache::select_sticky_from(
        &cache.load(),
        NAMESPACE,
        UPSTREAM_ID,
        &token_for(NAMESPACE, UPSTREAM_ID, reissue),
        None,
        None,
        None,
    )
    .expect("the reissued token must resolve");
    assert_eq!(next.host, rotated.host);
    assert_eq!(next.port, rotated.port);
    assert!(
        next.host != bound.host || next.port != bound.port,
        "the reissued binding must not point back at the rotated-away backend"
    );
}

#[test]
fn a_rotation_that_only_changed_ports_still_reissues() {
    // The dial `host:port` is part of the affinity identity: the same host on a
    // different port is a different endpoint and a different token. (It is not
    // the WHOLE identity — see the sticky-target-identity section below.)
    let bound = target("10.1.0.10", 8080);
    let rotated = target("10.1.0.10", 9090);

    let reissue = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
        false,
        Some(&bound),
        Some(&rotated),
    )
    .expect("a port rotation is still a different backend");
    assert_eq!(reissue.port, 9090);
    assert_ne!(
        token_for(NAMESPACE, UPSTREAM_ID, &bound),
        token_for(NAMESPACE, UPSTREAM_ID, &rotated),
    );
}

#[test]
fn a_first_ever_request_always_mints_for_the_backend_that_served_it() {
    let selected = target("10.1.0.10", 8080);
    let rotated = target("10.1.0.11", 8080);

    for served in [&selected, &rotated] {
        let reissue = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
            true,
            Some(&selected),
            Some(served),
        )
        .expect("a request with no usable binding always mints one");
        assert_eq!(reissue.host, served.host);
        assert_eq!(reissue.port, served.port);
    }
}

#[test]
fn a_response_no_backend_served_never_claims_a_binding() {
    // Gateway-synthesized refusals (mesh-transport / egress screens on a
    // ROTATED candidate that was never dialed, or no target at all) pass
    // `None`: a rejected response must not pin the client to a backend that
    // did not serve it — least of all one the gateway refuses to dial.
    let selected = target("10.1.0.10", 8080);
    for needs_set in [false, true] {
        assert!(
            ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
                needs_set,
                Some(&selected),
                None,
            )
            .is_none()
        );
    }
}

// ---------------------------------------------------------------------------
// Selected-port policy precedence for a resolved binding (root review finding 2)
// ---------------------------------------------------------------------------
//
// The binding lookup runs before the target is known, so it is validated
// against the INITIAL dispatch port's lane. When that port carries no per-port
// override the candidate pool is the whole upstream, so a resolved target can
// sit in a DIFFERENT `dispatch_policy_port()` lane whose effective algorithm is
// not consistent hashing, or whose `hashOn` names a different cookie. Honoring
// a binding there would reach past the per-port policy that actually governs
// the target. `resolve_sticky_binding` fails closed to ordinary selection and a
// fresh binding instead.

const COOKIE_NAME: &str = "lb-affinity-fe-0123456789abcdef";

/// Production-shaped `(cache, proxy)` pair: `resolve_dispatch_port_overrides`
/// projects the upstream's `port_overrides` onto the proxy exactly as config
/// resolution does, so `has_effective_port_override` sees what it sees at
/// runtime.
fn resolved_fixture(
    upstream: Upstream,
    proxy_backend_port: u16,
    subset: Option<&str>,
) -> (LoadBalancerCache, Proxy) {
    let proxy_json = serde_json::json!({
        "id": "sticky-proxy",
        "listen_path": "/sticky",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": proxy_backend_port,
        "upstream_id": UPSTREAM_ID,
    });
    let mut proxy: Proxy = serde_json::from_value(proxy_json).expect("proxy fixture");
    proxy.namespace = NAMESPACE.to_string();
    proxy.upstream_subset = subset.map(str::to_string);

    let mut config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let proxy = config.proxies[0].clone();
    (LoadBalancerCache::new(&config), proxy)
}

fn port_override(
    algorithm: Option<LoadBalancerAlgorithm>,
    hash_on: Option<&str>,
) -> UpstreamPortOverride {
    UpstreamPortOverride {
        algorithm,
        hash_on: hash_on.map(str::to_string),
        ..UpstreamPortOverride::default()
    }
}

#[test]
fn binding_fails_closed_when_the_targets_port_lane_is_not_cookie_hashing() {
    // Initial dispatch port 8080 has no override, so the raw binding index
    // spans the whole upstream — but 9090 is a round-robin lane.
    let http = target("10.1.0.10", 8080);
    let other_lane = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![http.clone(), other_lane.clone()]);
    upstream.port_overrides.insert(
        9090,
        port_override(Some(LoadBalancerAlgorithm::RoundRobin), None),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();
    let token = token_for(NAMESPACE, UPSTREAM_ID, &other_lane);

    // The raw index alone WOULD hand back the cross-lane target: the guard is
    // load-bearing, not a restatement of `select_sticky`'s own scoping.
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .is_some(),
        "fixture must actually exercise the cross-lane case"
    );
    assert!(
        ferrum_edge::_test_support::resolve_sticky_binding_for_test(
            &proxy,
            &snapshot,
            UPSTREAM_ID,
            &token,
            COOKIE_NAME,
            None,
            None,
        )
        .is_none(),
        "a round-robin port lane must not honor a session-persistence binding"
    );

    // A binding inside the un-overridden lane the lookup was validated against
    // is still honored, so the guard is not simply refusing everything.
    let same_lane = ferrum_edge::_test_support::resolve_sticky_binding_for_test(
        &proxy,
        &snapshot,
        UPSTREAM_ID,
        &token_for(NAMESPACE, UPSTREAM_ID, &http),
        COOKIE_NAME,
        None,
        None,
    )
    .expect("same-lane binding stays honored");
    assert_eq!(same_lane.port, 8080);
}

#[test]
fn binding_fails_closed_when_the_targets_port_lane_names_another_cookie() {
    let http = target("10.1.0.10", 8080);
    let other_lane = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![http, other_lane.clone()]);
    upstream.port_overrides.insert(
        9090,
        port_override(
            Some(LoadBalancerAlgorithm::ConsistentHashing),
            Some("cookie:some-other-session"),
        ),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);

    assert!(
        ferrum_edge::_test_support::resolve_sticky_binding_for_test(
            &proxy,
            &cache.load(),
            UPSTREAM_ID,
            &token_for(NAMESPACE, UPSTREAM_ID, &other_lane),
            COOKIE_NAME,
            None,
            None,
        )
        .is_none(),
        "a lane keyed on a different cookie must not honor this cookie's binding"
    );
}

#[test]
fn binding_is_honored_when_the_targets_port_lane_keeps_the_same_cookie() {
    let http = target("10.1.0.10", 8080);
    let other_lane = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![http, other_lane.clone()]);
    upstream.port_overrides.insert(
        9090,
        port_override(
            Some(LoadBalancerAlgorithm::ConsistentHashing),
            Some(&format!("cookie:{COOKIE_NAME}")),
        ),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);

    let bound = ferrum_edge::_test_support::resolve_sticky_binding_for_test(
        &proxy,
        &cache.load(),
        UPSTREAM_ID,
        &token_for(NAMESPACE, UPSTREAM_ID, &other_lane),
        COOKIE_NAME,
        None,
        None,
    )
    .expect("an equivalent cookie lane keeps the session");
    assert_eq!(bound.port, 9090);
}

#[test]
fn port_lane_precedence_composes_with_subset_scoping() {
    // The subset dimension keeps its own scoping under the port guard: an
    // in-lane, in-subset binding is honored; the same target outside the
    // selected subset is not, and neither is a cross-lane one.
    let v1 = tagged_target("10.1.0.10", 8080, &[("version", "v1")]);
    let v2 = tagged_target("10.1.0.11", 9090, &[("version", "v2")]);
    let mut upstream = sticky_upstream(vec![v1.clone(), v2.clone()]);
    upstream.subsets = Some(vec![
        SubsetDefinition {
            name: "v1".to_string(),
            labels: HashMap::from([("version".to_string(), "v1".to_string())]),
            traffic_policy: None,
        },
        SubsetDefinition {
            name: "v2".to_string(),
            labels: HashMap::from([("version".to_string(), "v2".to_string())]),
            traffic_policy: None,
        },
    ]);
    upstream.port_overrides.insert(
        9090,
        port_override(Some(LoadBalancerAlgorithm::RoundRobin), None),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, Some("v1"));
    let snapshot = cache.load();

    assert!(
        ferrum_edge::_test_support::resolve_sticky_binding_for_test(
            &proxy,
            &snapshot,
            UPSTREAM_ID,
            &token_for(NAMESPACE, UPSTREAM_ID, &v1),
            COOKIE_NAME,
            None,
            Some("v1"),
        )
        .is_some(),
        "an in-subset, in-lane binding stays honored"
    );
    assert!(
        ferrum_edge::_test_support::resolve_sticky_binding_for_test(
            &proxy,
            &snapshot,
            UPSTREAM_ID,
            &token_for(NAMESPACE, UPSTREAM_ID, &v2),
            COOKIE_NAME,
            None,
            Some("v1"),
        )
        .is_none(),
        "subset scoping still rejects a foreign-subset binding"
    );
}

// ---------------------------------------------------------------------------
// The shared mint site — and with it the fully-streaming native-gRPC fast path
// ---------------------------------------------------------------------------
//
// The direct H1/H2 native-gRPC dispatch has two response arms. The BUFFERED arm
// minted the affinity cookie; the FULLY-STREAMING arm committed its HEADERS
// frame and returned first, so a GRPCRoute with no response-body-buffering
// plugin and no retry selected a backend and never issued the initial cookie —
// session persistence silently did nothing for exactly the RPC shape gRPC is
// used for. Both arms now write through the one shared mint site exercised here,
// composed the same way the call sites compose it.

/// Mint exactly as the streaming native-gRPC fast path does: derive the reissue
/// target from the post-dispatch derivation, then hand it (and nothing else) to
/// the shared mint site.
fn mint_like_a_grpc_dispatch_arm(
    proxy: &Proxy,
    balancers: &ferrum_edge::load_balancer::LoadBalancerCacheInner,
    selection_needs_set: bool,
    selected: Option<&UpstreamTarget>,
    served: Option<&UpstreamTarget>,
    response_headers: &mut HashMap<String, String>,
) -> bool {
    let reissue_target = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
        selection_needs_set,
        selected,
        served,
    );
    ferrum_edge::_test_support::inject_sticky_affinity_cookie_for_test(
        proxy,
        balancers,
        reissue_target,
        reissue_target.is_some(),
        response_headers,
    )
}

/// The `Set-Cookie` line the production builder emits for `target`.
fn expected_affinity_cookie(target: &UpstreamTarget) -> String {
    ferrum_edge::_test_support::build_sticky_cookie_header_for_test(
        COOKIE_NAME,
        NAMESPACE,
        UPSTREAM_ID,
        target,
        &ferrum_edge::config::types::HashOnCookieConfig::default(),
    )
}

#[test]
fn a_streaming_dispatch_mints_the_initial_affinity_cookie() {
    // No usable cookie was presented, so selection asked for a fresh binding and
    // the streaming response owes the client one. On 0e9f3c31 this arm wrote
    // nothing at all.
    let served = target("10.1.0.10", 8080);
    let upstream = sticky_upstream(vec![served.clone(), target("10.1.0.11", 8080)]);
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    assert!(
        mint_like_a_grpc_dispatch_arm(
            &proxy,
            &snapshot,
            true,
            Some(&served),
            Some(&served),
            &mut response_headers,
        ),
        "a first-ever streaming gRPC response must issue the affinity cookie"
    );
    assert_eq!(
        response_headers.get("set-cookie"),
        Some(&expected_affinity_cookie(&served)),
        "the minted cookie must name the backend that produced the response"
    );

    // End-to-end: the emitted cookie is the token that steers the NEXT request
    // back to this exact backend, so the mint is usable and not merely present.
    let minted_value = response_headers["set-cookie"]
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_string())
        .expect("minted Set-Cookie carries a name=value pair");
    let rebound = ferrum_edge::_test_support::resolve_sticky_binding_for_test(
        &proxy,
        &snapshot,
        UPSTREAM_ID,
        &minted_value,
        COOKIE_NAME,
        None,
        None,
    )
    .expect("the minted token must resolve back to a backend");
    assert_eq!((rebound.host.as_str(), rebound.port), ("10.1.0.10", 8080));
}

#[test]
fn a_streaming_dispatch_does_not_reissue_an_honored_binding() {
    // The client presented a valid cookie, selection honored it, and no retry
    // rotated: re-minting the identical token would be pure wire noise, and a
    // reissue here is how a "mint on every response" regression would show up.
    let served = target("10.1.0.10", 8080);
    let bound = distinct_clone(&served);
    let upstream = sticky_upstream(vec![served.clone(), target("10.1.0.11", 8080)]);
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    assert!(
        !mint_like_a_grpc_dispatch_arm(
            &proxy,
            &snapshot,
            false,
            Some(&bound),
            Some(&served),
            &mut response_headers,
        ),
        "an honored binding that served its own backend must not be re-issued"
    );
    assert!(
        !response_headers.contains_key("set-cookie"),
        "no gateway cookie may be written when the binding was honored"
    );
}

#[test]
fn a_streaming_dispatch_appends_beside_a_backend_set_cookie() {
    // RFC 6265 forbids folding Set-Cookie into one value; the proxy keeps the
    // lines newline-separated and every response builder splits them back out.
    // A backend cookie must survive the affinity append untouched.
    let served = target("10.1.0.10", 8080);
    let upstream = sticky_upstream(vec![served.clone()]);
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert(
        "set-cookie".to_string(),
        "backend_session=abc; Path=/".to_string(),
    );
    assert!(mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&served),
        Some(&served),
        &mut response_headers,
    ));

    let expected = expected_affinity_cookie(&served);
    let lines: Vec<&str> = response_headers["set-cookie"].split('\n').collect();
    assert_eq!(
        lines,
        vec!["backend_session=abc; Path=/", expected.as_str()],
        "the affinity cookie is appended as its own line, leaving the backend's intact"
    );
}

#[test]
fn a_streaming_dispatch_writes_nothing_for_a_non_cookie_lane() {
    // The served target's OWN per-port policy lane decides the mint. A rotation
    // (or an upstream whose landing lane is round-robin) must not hand the
    // client a token that lane would never honor.
    let cookie_lane = target("10.1.0.10", 8080);
    let round_robin_lane = target("10.1.0.11", 9090);
    let mut upstream = sticky_upstream(vec![cookie_lane.clone(), round_robin_lane.clone()]);
    upstream.port_overrides.insert(
        9090,
        port_override(Some(LoadBalancerAlgorithm::RoundRobin), None),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    assert!(
        !mint_like_a_grpc_dispatch_arm(
            &proxy,
            &snapshot,
            true,
            Some(&round_robin_lane),
            Some(&round_robin_lane),
            &mut response_headers,
        ),
        "a non-cookie landing lane must not mint an affinity cookie"
    );
    assert!(response_headers.is_empty());
}

#[test]
fn a_streaming_dispatch_that_served_nothing_never_pins_a_client() {
    // A gateway-synthesized refusal that dialed no backend passes `None`, and a
    // route with no upstream has no binding scope at all. Neither may write.
    let served = target("10.1.0.10", 8080);
    let upstream = sticky_upstream(vec![served.clone()]);
    let (cache, mut proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let mut response_headers: HashMap<String, String> = HashMap::new();
    assert!(!mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&served),
        None,
        &mut response_headers,
    ));
    assert!(response_headers.is_empty());

    proxy.upstream_id = None;
    assert!(!mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&served),
        Some(&served),
        &mut response_headers,
    ));
    assert!(response_headers.is_empty());
}

// ---------------------------------------------------------------------------
// Anti-drift: every mint site routes through the shared derivation
// ---------------------------------------------------------------------------

#[test]
fn every_retry_capable_mint_site_uses_the_shared_reissue_derivation() {
    // The defect this guards is copy-paste drift: a response path that mints
    // from the immutable selection-time flag instead of the post-dispatch
    // derivation silently pins clients to rotated-away backends again. Each
    // dispatch file that can rotate targets must reference the shared
    // derivation, and the mint-site count is locked so a NEW site cannot be
    // added without revisiting this contract.
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let h3_server_src = include_str!("../../../src/http3/server.rs");
    let h3_cross_src = include_str!("../../../src/http3/cross_protocol.rs");
    let h3_ws_src = include_str!("../../../src/http3/websocket.rs");

    for (label, source) in [
        ("proxy/mod.rs", proxy_src),
        ("http3/server.rs", h3_server_src),
        ("http3/cross_protocol.rs", h3_cross_src),
        ("http3/websocket.rs", h3_ws_src),
    ] {
        assert!(
            source.contains("sticky_cookie_reissue_target("),
            "{label} owns a retry-capable sticky dispatch path and must derive \
             the reissue decision from \
             backend_dispatch::sticky_cookie_reissue_target"
        );
    }

    // `build_sticky_cookie_header` is reached from exactly ONE place: the shared
    // `inject_sticky_affinity_cookie` mint site in proxy/mod.rs. So proxy/mod.rs
    // holds 1 definition + that 1 call, and every other dispatch file holds
    // none — the H1/H2, gRPC (buffered AND fully-streaming), WebSocket, and H3
    // paths all append through the shared site. A new count here means a path
    // grew its own copy, which is how the streaming gRPC arm came to omit the
    // cookie entirely.
    let mint_sites = |src: &str| src.matches("build_sticky_cookie_header(").count();
    assert_eq!(mint_sites(proxy_src), 2);
    assert_eq!(mint_sites(h3_server_src), 0);
    assert_eq!(mint_sites(h3_ws_src), 0);
    assert_eq!(mint_sites(h3_cross_src), 0);

    assert!(
        proxy_src.contains(
            "sticky_dispatch_refused = matches!(\n                result.error_class,\n                Some(retry::ErrorClass::DispatchPolicyRejected)"
        ),
        "the generic retry helpers can refuse a target before dialing it; their \
         DispatchPolicyRejected result must suppress sticky-cookie reissue"
    );

    // Mapping the served backend onto its CONFIGURED identity is what makes a
    // wildcard-hosted upstream's cookie resolvable at all. The mint site in
    // proxy/mod.rs owns one use; retry selection lives in backend_dispatch and
    // must NOT grow a second mint-site copy in any dispatch file.
    let identity_mapping = "configured_sticky_identity_target_from(";
    assert_eq!(proxy_src.matches(identity_mapping).count(), 1);
    assert_eq!(h3_server_src.matches(identity_mapping).count(), 0);
    assert_eq!(h3_ws_src.matches(identity_mapping).count(), 0);
    assert_eq!(h3_cross_src.matches(identity_mapping).count(), 0);
}

#[test]
fn both_direct_grpc_response_arms_inject_the_affinity_cookie() {
    // The regression this locks: the direct H1/H2 native-gRPC dispatch returns
    // its FULLY-STREAMING response from its own match arm, ahead of the buffered
    // arm's injection. An arm that stops calling the shared mint site ships a
    // GRPCRoute that selects a backend and never binds the client to it.
    let proxy_src = include_str!("../../../src/proxy/mod.rs");

    let streaming_arm = proxy_src
        .split_once("Ok(GrpcResponseKind::Streaming(grpc_streaming)) => {")
        .expect("direct gRPC dispatch keeps a fully-streaming response arm")
        .1;
    let (streaming_arm, buffered_arm) = streaming_arm
        .split_once("Ok(GrpcResponseKind::Buffered(grpc_resp)) => {")
        .expect("direct gRPC dispatch keeps a buffered response arm");
    // Bound the buffered arm at the sibling `Err` arm of the same match;
    // otherwise the slice runs to end-of-file and the plain H1/H2 mint site
    // would satisfy the assertion for it.
    let buffered_arm = buffered_arm
        .split_once("\n            Err(e) => {")
        .expect("direct gRPC dispatch keeps an error arm after the buffered arm")
        .0;

    for (label, arm) in [
        ("fully-streaming", streaming_arm),
        ("buffered", buffered_arm),
    ] {
        assert!(
            arm.contains("inject_sticky_affinity_cookie_with_deadline_provenance("),
            "the direct gRPC {label} response arm must inject the sticky-affinity \
             cookie through the shared mint site before its headers are committed"
        );
    }
}

// ---------------------------------------------------------------------------
// Sticky target identity: one endpoint reached through two Services / lanes
// ---------------------------------------------------------------------------
//
// A Gateway API route rule fans several `backendRefs` into ONE materialized
// Upstream. Two of those entries can resolve to the same pod IP and dial port
// while naming different Services, different declared Service ports (and so
// different `dispatch_policy_port()` policy lanes), different subset tags,
// localities, or backend path overrides.
//
// Deriving the token from the health-check key — which is `host:port` ONLY, on
// purpose — collapsed such entries into a single binding-index entry with
// first-index-wins. The cookie minted for the later target then resolved onto
// the first one, crossing Service and per-port policy semantics inside the
// route while still reporting "exact backend-bound" behavior. The token now
// digests the target's full identity.

/// A target with explicit control of every identity-bearing field.
fn identity_target(
    host: &str,
    port: u16,
    service_port_policy_key: Option<u16>,
    tags: &[(&str, &str)],
    locality: Option<&str>,
    path: Option<&str>,
) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key,
        weight: 1,
        tags: tags
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        locality: locality.map(str::to_string),
        path: path.map(str::to_string),
    }
}

/// One route `backendRef`, shaped exactly as `upstream_for_route_with_session`
/// materializes it: Service identity tags plus the declared Service port as the
/// per-port policy key.
fn service_backend(service: &str, service_port: u16, host: &str, port: u16) -> UpstreamTarget {
    let service_port_tag = service_port.to_string();
    identity_target(
        host,
        port,
        Some(service_port),
        &[
            (UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG, "default"),
            (UPSTREAM_TARGET_SERVICE_NAME_TAG, service),
            (UPSTREAM_TARGET_SERVICE_PORT_TAG, service_port_tag.as_str()),
        ],
        None,
        None,
    )
}

/// Which Service a resolved binding actually landed on.
fn service_name_of(target: &UpstreamTarget) -> String {
    target
        .tags
        .get(UPSTREAM_TARGET_SERVICE_NAME_TAG)
        .cloned()
        .unwrap_or_default()
}

#[test]
fn one_endpoint_through_two_services_keeps_two_bindings() {
    // Same pod IP, same dial port, same declared Service port: only the Service
    // identity differs. On the `host:port` digest both minted the SAME token and
    // the second Service had no reachable binding at all.
    let checkout = service_backend("checkout", 80, "10.1.0.10", 8080);
    let legacy = service_backend("legacy-checkout", 80, "10.1.0.10", 8080);
    assert_eq!(checkout.host, legacy.host);
    assert_eq!(checkout.port, legacy.port);

    let checkout_token = token_for(NAMESPACE, UPSTREAM_ID, &checkout);
    let legacy_token = token_for(NAMESPACE, UPSTREAM_ID, &legacy);
    assert_ne!(
        checkout_token, legacy_token,
        "two Services on one endpoint must not share a session binding"
    );

    let pool = vec![checkout.clone(), legacy.clone()];
    let cache = cache_for(sticky_upstream(pool));
    let snapshot = cache.load();

    for (token, expected) in [(&checkout_token, &checkout), (&legacy_token, &legacy)] {
        let bound = LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            token,
            None,
            None,
            None,
        )
        .expect("each Service's token must resolve to its own backend");
        assert_eq!(bound.host, expected.host);
        assert_eq!(bound.port, expected.port);
        assert_eq!(service_name_of(&bound), service_name_of(expected));
    }

    // Weight is deliberately outside the identity: it only sizes a target's
    // share of UNBOUND selections, so a canary weight shift must not invalidate
    // every outstanding session on the route.
    let mut heavier = checkout.clone();
    heavier.weight = 97;
    let heavier_token = token_for(NAMESPACE, UPSTREAM_ID, &heavier);
    assert_eq!(
        heavier_token, checkout_token,
        "a weight change must not re-key an established session"
    );
}

#[test]
fn every_identity_bearing_field_changes_the_token() {
    let base = identity_target(
        "10.1.0.10",
        8080,
        Some(80),
        &[("version", "v1")],
        Some("us-east-1/us-east-1a"),
        Some("/v1"),
    );
    let base_token = token_for(NAMESPACE, UPSTREAM_ID, &base);
    let differs = |label: &str, mutated: &UpstreamTarget| {
        let token = token_for(NAMESPACE, UPSTREAM_ID, mutated);
        assert_ne!(
            token, base_token,
            "a changed {label} must produce a different sticky binding"
        );
    };

    let mut host = base.clone();
    host.host = "10.1.0.11".to_string();
    differs("dial host", &host);

    let mut port = base.clone();
    port.port = 9090;
    differs("dial port", &port);

    let mut policy_key = base.clone();
    policy_key.service_port_policy_key = Some(8080);
    differs("declared Service port", &policy_key);

    let mut no_policy_key = base.clone();
    no_policy_key.service_port_policy_key = None;
    differs("absent declared Service port", &no_policy_key);

    let mut tag_value = base.clone();
    tag_value
        .tags
        .insert("version".to_string(), "v2".to_string());
    differs("subset tag value", &tag_value);

    let mut extra_tag = base.clone();
    extra_tag
        .tags
        .insert("canary".to_string(), "on".to_string());
    differs("additional tag", &extra_tag);

    let mut locality = base.clone();
    locality.locality = Some("us-east-1/us-east-1b".to_string());
    differs("locality", &locality);

    let mut no_locality = base.clone();
    no_locality.locality = None;
    differs("absent locality", &no_locality);

    let mut path = base.clone();
    path.path = Some("/v2".to_string());
    differs("backend path override", &path);

    let mut no_path = base.clone();
    no_path.path = None;
    differs("absent backend path override", &no_path);

    // An empty value must not read as an absent field.
    let mut empty_path = base.clone();
    empty_path.path = Some(String::new());
    differs("empty backend path override", &empty_path);
}

#[test]
fn tag_map_iteration_order_does_not_change_the_token() {
    // Tags live in a `HashMap`, whose iteration order is neither insertion order
    // nor stable between instances. A binding that depended on it would differ
    // between gateway replicas and between restarts of one replica.
    let labels: Vec<(String, String)> = (0..32)
        .map(|i| (format!("tag-{i:02}"), format!("value-{i:02}")))
        .collect();

    let mut forward = identity_target("10.1.0.10", 8080, Some(80), &[], None, None);
    for (key, value) in labels.iter() {
        forward.tags.insert(key.clone(), value.clone());
    }
    let mut reverse = identity_target("10.1.0.10", 8080, Some(80), &[], None, None);
    for (key, value) in labels.iter().rev() {
        reverse.tags.insert(key.clone(), value.clone());
    }

    let forward_token = token_for(NAMESPACE, UPSTREAM_ID, &forward);
    let reverse_token = token_for(NAMESPACE, UPSTREAM_ID, &reverse);
    assert_eq!(
        forward_token, reverse_token,
        "the tag encoding must be canonically ordered, not map-iteration ordered"
    );
}

#[test]
fn identical_duplicate_targets_share_one_deterministic_binding() {
    // Entries identical in every identity-bearing field are interchangeable —
    // dispatching to either is the same request — so collapsing them onto one
    // binding is safe. What must hold is determinism across rebuilds, and that
    // the collapse never swallows a genuinely distinct neighbour.
    let checkout = service_backend("checkout", 80, "10.1.0.10", 8080);
    let duplicate = checkout.clone();
    let neighbour = service_backend("legacy-checkout", 80, "10.1.0.10", 8080);

    let token = token_for(NAMESPACE, UPSTREAM_ID, &checkout);
    assert_eq!(token, token_for(NAMESPACE, UPSTREAM_ID, &duplicate));
    let neighbour_token = token_for(NAMESPACE, UPSTREAM_ID, &neighbour);
    assert_ne!(token, neighbour_token);

    // A fresh `LoadBalancerCache` is exactly what a config reload builds.
    for _ in 0..3 {
        let pool = vec![checkout.clone(), duplicate.clone(), neighbour.clone()];
        let cache = cache_for(sticky_upstream(pool));
        let snapshot = cache.load();

        let bound = LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .expect("a duplicated target keeps one stable binding");
        assert_eq!(service_name_of(&bound), "checkout");

        let neighbour_bound = LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &neighbour_token,
            None,
            None,
            None,
        )
        .expect("the distinct neighbour keeps its own binding");
        assert_eq!(service_name_of(&neighbour_bound), "legacy-checkout");
    }
}

#[test]
fn the_minted_cookie_is_the_exact_index_key_for_a_shared_endpoint() {
    // The response mint site and the constructor's binding index must derive the
    // identical value; otherwise the gateway emits a cookie that resolves to a
    // different backend, or to nothing at all. The shared-endpoint pair is where
    // any drift between the two surfaces first.
    let checkout = service_backend("checkout", 80, "10.1.0.10", 8080);
    let legacy = service_backend("legacy-checkout", 80, "10.1.0.10", 8080);
    let pool = vec![checkout.clone(), legacy.clone()];
    let cache = cache_for(sticky_upstream(pool));
    let snapshot = cache.load();

    for expected in [&checkout, &legacy] {
        let cookie = expected_affinity_cookie(expected);
        let token = cookie
            .split_once('=')
            .and_then(|(_, rest)| rest.split(';').next())
            .expect("the mint site emits `name=token; ...`");
        let bound = LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            token,
            None,
            None,
            None,
        )
        .expect("an emitted cookie value must be a live binding-index key");
        assert_eq!(bound.tags, expected.tags);
        assert_eq!(bound.host, expected.host);
        assert_eq!(bound.port, expected.port);
    }
}

#[test]
fn a_shared_endpoints_bindings_never_cross_each_others_policy_lane() {
    // Both entries dial 10.1.0.10:8080, but their declared Service ports put
    // them in different `dispatch_policy_port()` lanes. The 9090 lane is
    // round-robin — it does not elect this cookie — so its binding must fail
    // closed, while the 80 lane's binding stays honored and still names ITS
    // target rather than the other lane's.
    let cookie_lane = identity_target("10.1.0.10", 8080, Some(80), &[], None, None);
    let rr_lane = identity_target("10.1.0.10", 8080, Some(9090), &[], None, None);
    let pool = vec![cookie_lane.clone(), rr_lane.clone()];
    let mut upstream = sticky_upstream(pool);
    upstream.port_overrides.insert(
        9090,
        port_override(Some(LoadBalancerAlgorithm::RoundRobin), None),
    );
    let (cache, proxy) = resolved_fixture(upstream, 8080, None);
    let snapshot = cache.load();

    let cookie_token = token_for(NAMESPACE, UPSTREAM_ID, &cookie_lane);
    let rr_token = token_for(NAMESPACE, UPSTREAM_ID, &rr_lane);
    assert_ne!(
        cookie_token, rr_token,
        "one endpoint in two policy lanes must not share a session binding"
    );

    // The raw index really does hand back the round-robin lane's target, so the
    // lane guard below is load-bearing and not a restatement of pool scoping.
    let raw = LoadBalancerCache::select_sticky_from(
        &snapshot,
        NAMESPACE,
        UPSTREAM_ID,
        &rr_token,
        None,
        None,
        None,
    )
    .expect("fixture must actually exercise the cross-lane case");
    assert_eq!(raw.service_port_policy_key, Some(9090));

    assert!(
        ferrum_edge::_test_support::resolve_sticky_binding_for_test(
            &proxy,
            &snapshot,
            UPSTREAM_ID,
            &rr_token,
            COOKIE_NAME,
            None,
            None,
        )
        .is_none(),
        "a round-robin policy lane must not honor this cookie's binding"
    );

    let honored = ferrum_edge::_test_support::resolve_sticky_binding_for_test(
        &proxy,
        &snapshot,
        UPSTREAM_ID,
        &cookie_token,
        COOKIE_NAME,
        None,
        None,
    )
    .expect("the cookie lane's own binding stays honored");
    assert_eq!(honored.service_port_policy_key, Some(80));
}

#[test]
fn a_rotation_between_two_services_on_one_endpoint_reissues() {
    // `same_affinity_endpoint` decides whether the cookie a client already holds
    // still names the backend that served the response. Comparing `host:port`
    // alone reported "same backend" for a rotation onto the OTHER Service on
    // this endpoint and skipped the reissue, leaving the client pinned to a
    // target that did not serve it.
    let checkout = service_backend("checkout", 80, "10.1.0.10", 8080);
    let legacy = service_backend("legacy-checkout", 80, "10.1.0.10", 8080);

    let reissue = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
        false,
        Some(&checkout),
        Some(&legacy),
    )
    .expect("a rotation onto another Service on one endpoint must reissue");
    assert_eq!(service_name_of(reissue), "legacy-checkout");

    let pool = vec![checkout.clone(), legacy.clone()];
    let cache = cache_for(sticky_upstream(pool));
    let bound = LoadBalancerCache::select_sticky_from(
        &cache.load(),
        NAMESPACE,
        UPSTREAM_ID,
        &token_for(NAMESPACE, UPSTREAM_ID, reissue),
        None,
        None,
        None,
    )
    .expect("the reissued token must resolve");
    assert_eq!(service_name_of(&bound), "legacy-checkout");

    // A rotation that changed nothing identity-bearing (a distinct allocation
    // differing only in weight) must still not re-mint the identical token.
    let mut same_identity = checkout.clone();
    same_identity.weight = 42;
    let quiet = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
        false,
        Some(&checkout),
        Some(&same_identity),
    );
    assert!(
        quiet.is_none(),
        "an identity-preserving rotation must not re-mint the identical token"
    );
}

// ---------------------------------------------------------------------------
// Wildcard upstreams: the DIAL target is not the CONFIGURED identity
// ---------------------------------------------------------------------------
//
// A mesh egress wildcard `ServiceEntry` (or any wildcard-hosted upstream)
// configures `host: "*.example.com"`. Every request path — H1/H2 and H3 alike —
// then runs `concretize_wildcard_target_for_request`, which CLONES that entry
// with `host` replaced by the matched request authority, because the dial, DNS
// resolution, and SNI have to use the concrete name.
//
// `host` is identity-bearing, so the clone's digest is absent from the binding
// index the balancer built from the configured targets. Minting the response
// cookie from the clone therefore emitted a token that could never resolve: a
// returning client missed the index, fell back to ordinary selection, and was
// reissued a fresh cookie on every single response — session persistence that
// reported success and delivered nothing. The mint site now maps the served
// target back to its configured identity while dispatch keeps the concrete
// clone.

/// The per-request DIAL target the proxy actually builds for `request_host`,
/// through the production concretization helper.
fn dialed(configured: &UpstreamTarget, request_host: &str) -> UpstreamTarget {
    let selected = std::sync::Arc::new(configured.clone());
    let concrete = ferrum_edge::_test_support::concretize_wildcard_target_for_request_for_test(
        Some(selected),
        Some(request_host),
    )
    .expect("a selected target survives concretization");
    (*concrete).clone()
}

/// The opaque token out of a minted `Set-Cookie` line.
fn minted_token(response_headers: &HashMap<String, String>) -> String {
    response_headers
        .get("set-cookie")
        .expect("a cookie must have been minted")
        .split_once('=')
        .and_then(|(_, rest)| rest.split(';').next())
        .expect("the mint site emits `name=token; ...`")
        .to_string()
}

/// A wildcard-hosted (or plain) `backendRef` distinguished by Service identity.
fn wildcard_backend(service: &str, host: &str, port: u16) -> UpstreamTarget {
    identity_target(
        host,
        port,
        None,
        &[
            (UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG, "default"),
            (UPSTREAM_TARGET_SERVICE_NAME_TAG, service),
        ],
        None,
        None,
    )
}

#[test]
fn a_wildcard_dial_clone_mints_its_configured_targets_binding() {
    let configured = wildcard_backend("egress", "*.example.com", 8080);
    let (cache, proxy) = resolved_fixture(sticky_upstream(vec![configured.clone()]), 8080, None);
    let snapshot = cache.load();

    // Dispatch dials the concrete authority, not the pattern.
    let served = dialed(&configured, "api.example.com");
    assert_eq!(served.host, "api.example.com");
    assert_eq!(served.tags, configured.tags);
    assert_ne!(
        token_for(NAMESPACE, UPSTREAM_ID, &served),
        token_for(NAMESPACE, UPSTREAM_ID, &configured),
        "the dial clone digests to a different value — minting THAT was the defect"
    );
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token_for(NAMESPACE, UPSTREAM_ID, &served),
            None,
            None,
            None,
        )
        .is_none(),
        "the dial clone's own digest is not an index key, which is why it could \
         never resolve"
    );

    let mut response_headers: HashMap<String, String> = HashMap::new();
    assert!(mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&served),
        Some(&served),
        &mut response_headers,
    ));
    assert_eq!(
        response_headers.get("set-cookie"),
        Some(&expected_affinity_cookie(&configured)),
        "the cookie must name the CONFIGURED wildcard target, not the dial clone"
    );

    // End to end: the emitted value is a live key of the binding index, and the
    // target it resolves to is re-concretized for its own dial.
    let bound = LoadBalancerCache::select_sticky_from(
        &snapshot,
        NAMESPACE,
        UPSTREAM_ID,
        &minted_token(&response_headers),
        None,
        None,
        None,
    )
    .expect("a wildcard-backed cookie must resolve to its configured target");
    assert_eq!(bound.host, "*.example.com");
    assert_eq!(dialed(&bound, "api.example.com").host, "api.example.com");
}

#[test]
fn a_returning_wildcard_binding_is_honored_instead_of_reissued_forever() {
    // The user-visible defect: every response carried a fresh `Set-Cookie` and
    // the client was never actually pinned.
    let a = wildcard_backend("egress-a", "*.example.com", 8080);
    let b = wildcard_backend("egress-b", "*.example.com", 8080);
    let (cache, proxy) = resolved_fixture(sticky_upstream(vec![a.clone(), b.clone()]), 8080, None);
    let snapshot = cache.load();

    // Request 1: no cookie presented, served through a dial clone of `a`.
    let served = dialed(&a, "api.example.com");
    let mut first: HashMap<String, String> = HashMap::new();
    assert!(mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&served),
        Some(&served),
        &mut first,
    ));

    // Request 2: the presented cookie is honored by the production resolver —
    // including its port-lane guard — and lands on `a`, not `b`.
    let honored = ferrum_edge::_test_support::resolve_sticky_binding_for_test(
        &proxy,
        &snapshot,
        UPSTREAM_ID,
        &minted_token(&first),
        COOKIE_NAME,
        None,
        None,
    )
    .expect("a returning client's wildcard binding must be honored");
    assert_eq!(service_name_of(&honored), "egress-a");

    // Selection therefore asked for no fresh binding, and the response it
    // serves — through the honored target's own dial clone — writes nothing.
    let honored_dial = dialed(&honored, "api.example.com");
    let mut second: HashMap<String, String> = HashMap::new();
    assert!(!mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        false,
        Some(&honored_dial),
        Some(&honored_dial),
        &mut second,
    ));
    assert!(
        second.is_empty(),
        "an honored wildcard binding must not be re-minted on every response"
    );
}

#[test]
fn two_wildcard_backends_on_one_authority_keep_separate_bindings() {
    // Both entries concretize onto the SAME dial authority, so mapping a served
    // clone back by host alone would collapse them into one binding — exactly
    // the failure the full-identity digest exists to prevent, one level up.
    let a = wildcard_backend("egress-a", "*.example.com", 8080);
    let b = wildcard_backend("egress-b", "*.example.com", 8080);
    let (cache, proxy) = resolved_fixture(sticky_upstream(vec![a.clone(), b.clone()]), 8080, None);
    let snapshot = cache.load();

    let served_a = dialed(&a, "api.example.com");
    let served_b = dialed(&b, "api.example.com");
    assert_eq!(served_a.host, served_b.host);

    let mut cookie_a: HashMap<String, String> = HashMap::new();
    let mut cookie_b: HashMap<String, String> = HashMap::new();
    for (served, headers) in [(&served_a, &mut cookie_a), (&served_b, &mut cookie_b)] {
        assert!(mint_like_a_grpc_dispatch_arm(
            &proxy,
            &snapshot,
            true,
            Some(served),
            Some(served),
            headers,
        ));
    }
    let token_a = minted_token(&cookie_a);
    let token_b = minted_token(&cookie_b);
    assert_ne!(
        token_a, token_b,
        "two Services behind one wildcard authority must not share a binding"
    );

    for (token, expected_service) in [(token_a, "egress-a"), (token_b, "egress-b")] {
        let bound = LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .expect("each wildcard binding resolves");
        assert_eq!(service_name_of(&bound), expected_service);
    }
}

#[test]
fn wildcard_backends_that_differ_only_in_policy_lane_keep_separate_bindings() {
    // Same wildcard pattern, same dial port, no tags at all: only the declared
    // Service port — the `dispatch_policy_port()` lane — differs.
    let lane_80 = identity_target("*.example.com", 8080, Some(80), &[], None, None);
    let lane_9090 = identity_target("*.example.com", 8080, Some(9090), &[], None, None);
    let (cache, proxy) = resolved_fixture(
        sticky_upstream(vec![lane_80.clone(), lane_9090.clone()]),
        8080,
        None,
    );
    let snapshot = cache.load();

    let mut minted: Vec<String> = Vec::new();
    for configured in [&lane_80, &lane_9090] {
        let served = dialed(configured, "api.example.com");
        let mut headers: HashMap<String, String> = HashMap::new();
        assert!(mint_like_a_grpc_dispatch_arm(
            &proxy,
            &snapshot,
            true,
            Some(&served),
            Some(&served),
            &mut headers,
        ));
        assert_eq!(
            headers.get("set-cookie"),
            Some(&expected_affinity_cookie(configured)),
            "each policy lane mints its own configured identity"
        );
        let bound = LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &minted_token(&headers),
            None,
            None,
            None,
        )
        .expect("each lane's binding resolves");
        let lane = configured.service_port_policy_key;
        assert_eq!(bound.service_port_policy_key, lane);
        minted.push(minted_token(&headers));
    }
    assert_ne!(
        minted[0], minted[1],
        "one wildcard authority in two policy lanes must not share a binding"
    );
}

#[test]
fn a_retry_rotation_between_wildcard_backends_reissues_for_the_serving_one() {
    let a = wildcard_backend("egress-a", "*.example.com", 8080);
    let b = wildcard_backend("egress-b", "*.example.com", 8080);
    let (cache, proxy) = resolved_fixture(sticky_upstream(vec![a.clone(), b.clone()]), 8080, None);
    let snapshot = cache.load();

    // Selection honored the client's binding to `a` and the request dialed a's
    // clone. `select_next_retry_target` then hands back a DIAL clone of `b`
    // (re-concretized with the request authority), so cover both shapes the
    // served target can take: the configured entry, and a concretized clone.
    let bound_dial = dialed(&a, "api.example.com");
    for served in [b.clone(), dialed(&b, "api.example.com")] {
        let reissue = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
            false,
            Some(&bound_dial),
            Some(&served),
        )
        .expect("a rotation onto the other wildcard backend must reissue");
        assert_eq!(service_name_of(reissue), "egress-b");

        let mut headers: HashMap<String, String> = HashMap::new();
        assert!(
            ferrum_edge::_test_support::inject_sticky_affinity_cookie_for_test(
                &proxy,
                &snapshot,
                Some(reissue),
                true,
                &mut headers,
            )
        );
        assert_eq!(
            headers.get("set-cookie"),
            Some(&expected_affinity_cookie(&b)),
            "the reissued cookie must name the backend that actually served"
        );
        let bound = LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &minted_token(&headers),
            None,
            None,
            None,
        )
        .expect("the reissued token must resolve");
        assert_eq!(
            service_name_of(&bound),
            "egress-b",
            "the client must not be sent back to the rotated-away backend"
        );
    }
}

#[test]
fn an_authority_outside_the_configured_wildcard_is_granted_no_binding() {
    let configured = wildcard_backend("egress", "*.example.com", 8080);
    let (cache, proxy) = resolved_fixture(sticky_upstream(vec![configured.clone()]), 8080, None);
    let snapshot = cache.load();

    // A request authority that does not match the pattern is not concretized at
    // all, so no dial clone — and no binding — is invented for it.
    assert_eq!(dialed(&configured, "example.net").host, "*.example.com");

    // And a served target carrying a foreign concrete authority, identical to
    // the configured entry in every other identity field, must NOT be folded
    // onto that entry's binding: the mapping is host-matched, not "any
    // wildcard in the upstream".
    let foreign = identity_target(
        "api.other.test",
        8080,
        None,
        &[
            (UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG, "default"),
            (UPSTREAM_TARGET_SERVICE_NAME_TAG, "egress"),
        ],
        None,
        None,
    );
    let mut headers: HashMap<String, String> = HashMap::new();
    assert!(mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&foreign),
        Some(&foreign),
        &mut headers,
    ));
    let token = minted_token(&headers);
    let configured_token = token_for(NAMESPACE, UPSTREAM_ID, &configured);
    assert_ne!(
        token, configured_token,
        "an unmatched authority must not be handed the wildcard target's token"
    );
    assert!(
        LoadBalancerCache::select_sticky_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            &token,
            None,
            None,
            None,
        )
        .is_none(),
        "an unmatched authority must not resolve into the eligible pool"
    );
}

#[test]
fn a_concrete_backend_beside_a_wildcard_keeps_its_own_binding() {
    // The wildcard concretizes onto the very authority the concrete entry
    // names, so both dial `api.example.com:8080`. They are still distinct
    // configured identities and must keep distinct bindings.
    let wildcard = wildcard_backend("egress", "*.example.com", 8080);
    let concrete = wildcard_backend("direct", "api.example.com", 8080);
    let (cache, proxy) = resolved_fixture(
        sticky_upstream(vec![wildcard.clone(), concrete.clone()]),
        8080,
        None,
    );
    let snapshot = cache.load();

    for (served, expected) in [
        (dialed(&wildcard, "api.example.com"), &wildcard),
        (concrete.clone(), &concrete),
    ] {
        assert_eq!(served.host, "api.example.com");
        let mut headers: HashMap<String, String> = HashMap::new();
        assert!(mint_like_a_grpc_dispatch_arm(
            &proxy,
            &snapshot,
            true,
            Some(&served),
            Some(&served),
            &mut headers,
        ));
        assert_eq!(
            headers.get("set-cookie"),
            Some(&expected_affinity_cookie(expected)),
            "a shared dial authority must not collapse two configured identities"
        );
    }
}

#[test]
fn an_exact_configured_identity_wins_over_a_wildcard_that_also_matches() {
    // When a concrete entry and a wildcard entry are identical in every field
    // but `host`, a served clone is indistinguishable from the concrete entry.
    // The exact configured identity is chosen — deliberately, because a session
    // pinned to it stays pinned to that host whatever authority the client
    // sends later, while a wildcard binding follows the authority. Both dial
    // the same endpoint under the same policy, so neither is a mis-route.
    let wildcard = wildcard_backend("egress", "*.example.com", 8080);
    let concrete = wildcard_backend("egress", "api.example.com", 8080);
    let (cache, proxy) = resolved_fixture(
        sticky_upstream(vec![wildcard.clone(), concrete.clone()]),
        8080,
        None,
    );
    let snapshot = cache.load();

    let served = dialed(&wildcard, "api.example.com");
    let mut headers: HashMap<String, String> = HashMap::new();
    assert!(mint_like_a_grpc_dispatch_arm(
        &proxy,
        &snapshot,
        true,
        Some(&served),
        Some(&served),
        &mut headers,
    ));
    assert_eq!(
        headers.get("set-cookie"),
        Some(&expected_affinity_cookie(&concrete)),
    );
    let bound = LoadBalancerCache::select_sticky_from(
        &snapshot,
        NAMESPACE,
        UPSTREAM_ID,
        &minted_token(&headers),
        None,
        None,
        None,
    )
    .expect("the binding resolves");
    assert_eq!(bound.host, "api.example.com");
}

#[test]
fn an_all_concrete_upstream_is_untouched_by_the_wildcard_identity_mapping() {
    // Parity guard: with no wildcard target configured, the mapping is a
    // precomputed boolean and returns the served target itself — the mint site
    // behaves exactly as it did before the seam existed, with no scan.
    let a = target("10.1.0.10", 8080);
    let b = target("10.1.0.11", 8080);
    let cache = cache_for(sticky_upstream(vec![a.clone(), b.clone()]));
    let snapshot = cache.load();

    for served in [&a, &b] {
        let identity = LoadBalancerCache::configured_sticky_identity_target_from(
            &snapshot,
            NAMESPACE,
            UPSTREAM_ID,
            served,
        );
        assert!(
            std::ptr::eq(identity, served),
            "an all-concrete upstream must hand back the served target itself"
        );
    }

    // An upstream this snapshot does not know cannot remap anything either.
    let unknown = LoadBalancerCache::configured_sticky_identity_target_from(
        &snapshot,
        "no-such-namespace",
        "no-such-upstream",
        &a,
    );
    assert!(std::ptr::eq(unknown, &a));
}

// ---------------------------------------------------------------------------
// Wildcard retry selection: configured identity vs dial identity
// ---------------------------------------------------------------------------
//
// Initial selection returns a configured wildcard; dispatch concretizes it for
// the dial. Retry must reconcile that dial clone back to the configured entry
// for exclusion, then re-concretize the next configured candidate before
// returning — otherwise exclusion misses and callers dial `*.example.com`.

fn rr_upstream(targets: Vec<UpstreamTarget>) -> Upstream {
    let mut upstream = sticky_upstream(targets);
    upstream.algorithm = LoadBalancerAlgorithm::RoundRobin;
    upstream.hash_on = None;
    upstream.hash_on_cookie_config = None;
    upstream
}

async fn retry_state_for(upstream: Upstream) -> (ferrum_edge::proxy::ProxyState, Proxy) {
    let proxy_json = serde_json::json!({
        "id": "retry-proxy",
        "listen_path": "/retry",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "upstream_id": UPSTREAM_ID,
        "namespace": NAMESPACE,
    });
    let mut proxy: Proxy = serde_json::from_value(proxy_json).expect("proxy fixture");
    proxy.namespace = NAMESPACE.to_string();
    let mut config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    config.resolve_dispatch_port_overrides();
    let proxy = config.proxies[0].clone();
    let dns_cache = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let env_config = ferrum_edge::config::env_config::EnvConfig::default();
    let (state, _) = ferrum_edge::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
        .expect("test proxy state should build");
    (state, proxy)
}

#[tokio::test]
async fn retry_excludes_concretized_previous_wildcard_and_returns_dial_target() {
    // Non-sticky round-robin: has_wildcard must work without cookie minting.
    let a = wildcard_backend("egress-a", "*.example.com", 8080);
    let b = wildcard_backend("egress-b", "*.example.com", 8080);
    let (state, proxy) = retry_state_for(rr_upstream(vec![a.clone(), b.clone()])).await;
    let epoch = state.request_epoch.load();
    let prev_dial = dialed(&a, "api.example.com");
    assert_eq!(prev_dial.host, "api.example.com");

    let next = ferrum_edge::_test_support::select_next_retry_target_for_test(
        &state,
        &epoch,
        &proxy,
        &prev_dial,
        ferrum_edge::_test_support::RetryTargetRequestForTest {
            base_hash_key: "retry-key",
            client_ip: "192.0.2.10",
            proxy_headers: &HashMap::new(),
            request_authority: Some("api.example.com"),
        },
    )
    .expect("a second wildcard backend must be available for retry");

    assert_eq!(
        next.host, "api.example.com",
        "retry must return a DIAL target, not the configured literal wildcard"
    );
    assert_eq!(
        service_name_of(&next),
        "egress-b",
        "the just-tried configured wildcard identity must be excluded"
    );
    assert!(!next.host.starts_with("*."));
}

#[tokio::test]
async fn retry_aborts_without_literal_wildcard_when_authority_missing_or_unmatched() {
    let a = wildcard_backend("egress-a", "*.example.com", 8080);
    let b = wildcard_backend("egress-b", "*.example.com", 8080);
    let (state, proxy) = retry_state_for(rr_upstream(vec![a.clone(), b.clone()])).await;
    let epoch = state.request_epoch.load();
    let prev_dial = dialed(&a, "api.example.com");

    assert!(
        ferrum_edge::_test_support::select_next_retry_target_for_test(
            &state,
            &epoch,
            &proxy,
            &prev_dial,
            ferrum_edge::_test_support::RetryTargetRequestForTest {
                base_hash_key: "retry-key",
                client_ip: "192.0.2.10",
                proxy_headers: &HashMap::new(),
                request_authority: None,
            },
        )
        .is_none(),
        "missing authority must fail closed rather than dial *.example.com"
    );
    assert!(
        ferrum_edge::_test_support::select_next_retry_target_for_test(
            &state,
            &epoch,
            &proxy,
            &prev_dial,
            ferrum_edge::_test_support::RetryTargetRequestForTest {
                base_hash_key: "retry-key",
                client_ip: "192.0.2.10",
                proxy_headers: &HashMap::new(),
                request_authority: Some("example.net"),
            },
        )
        .is_none(),
        "non-matching authority must fail closed rather than invent a host"
    );
}

#[tokio::test]
async fn full_identity_exclusion_keeps_sibling_sharing_host_port() {
    // Same dial endpoint, different Service identity — exclusion by host/port
    // alone would drop the sibling; full sticky identity must keep it.
    let tried = identity_target(
        "10.1.0.10",
        8080,
        None,
        &[
            (UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG, "default"),
            (UPSTREAM_TARGET_SERVICE_NAME_TAG, "svc-a"),
        ],
        None,
        None,
    );
    let sibling = identity_target(
        "10.1.0.10",
        8080,
        None,
        &[
            (UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG, "default"),
            (UPSTREAM_TARGET_SERVICE_NAME_TAG, "svc-b"),
        ],
        None,
        None,
    );
    let (state, proxy) = retry_state_for(rr_upstream(vec![tried.clone(), sibling.clone()])).await;
    let epoch = state.request_epoch.load();

    let next = ferrum_edge::_test_support::select_next_retry_target_for_test(
        &state,
        &epoch,
        &proxy,
        &tried,
        ferrum_edge::_test_support::RetryTargetRequestForTest {
            base_hash_key: "retry-key",
            client_ip: "192.0.2.10",
            proxy_headers: &HashMap::new(),
            request_authority: None,
        },
    )
    .expect("sibling sharing host:port must remain eligible");
    assert_eq!(service_name_of(&next), "svc-b");
    assert_eq!(next.host, "10.1.0.10");
    assert_eq!(next.port, 8080);
}

#[tokio::test]
async fn cookie_reissue_after_wildcard_retry_rotation_names_configured_backend() {
    let a = wildcard_backend("egress-a", "*.example.com", 8080);
    let b = wildcard_backend("egress-b", "*.example.com", 8080);
    let (state, proxy) = retry_state_for(sticky_upstream(vec![a.clone(), b.clone()])).await;
    let epoch = state.request_epoch.load();
    let snapshot = state.load_balancer_cache.load();
    let prev_dial = dialed(&a, "api.example.com");

    let rotated = ferrum_edge::_test_support::select_next_retry_target_for_test(
        &state,
        &epoch,
        &proxy,
        &prev_dial,
        ferrum_edge::_test_support::RetryTargetRequestForTest {
            base_hash_key: "retry-key",
            client_ip: "192.0.2.10",
            proxy_headers: &HashMap::new(),
            request_authority: Some("api.example.com"),
        },
    )
    .expect("wildcard retry must rotate onto the sibling dial target");
    assert_eq!(rotated.host, "api.example.com");
    assert_eq!(service_name_of(&rotated), "egress-b");

    let reissue = ferrum_edge::_test_support::sticky_cookie_reissue_target_for_test(
        false,
        Some(&prev_dial),
        Some(&rotated),
    )
    .expect("rotation onto the sibling must reissue");
    assert_eq!(service_name_of(reissue), "egress-b");

    let mut headers: HashMap<String, String> = HashMap::new();
    assert!(
        ferrum_edge::_test_support::inject_sticky_affinity_cookie_for_test(
            &proxy,
            &snapshot,
            Some(reissue),
            true,
            &mut headers,
        )
    );
    assert_eq!(
        headers.get("set-cookie"),
        Some(&expected_affinity_cookie(&b)),
        "reissue must name the CONFIGURED wildcard backend"
    );
    let bound = LoadBalancerCache::select_sticky_from(
        &snapshot,
        NAMESPACE,
        UPSTREAM_ID,
        &minted_token(&headers),
        None,
        None,
        None,
    )
    .expect("reissued token must resolve on the next request");
    assert_eq!(bound.host, "*.example.com");
    assert_eq!(service_name_of(&bound), "egress-b");
    assert_eq!(dialed(&bound, "api.example.com").host, "api.example.com");
}

#[test]
fn all_six_retry_callers_pass_request_authority_to_shared_helper() {
    // Anti-drift: every retry transport must thread the validated inbound
    // authority into select_next_retry_target and must not open-code a literal
    // wildcard dial around that helper.
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let h3_server = include_str!("../../../src/http3/server.rs");
    let h3_cross = include_str!("../../../src/http3/cross_protocol.rs");
    let h3_ws = include_str!("../../../src/http3/websocket.rs");

    // Three call sites in proxy/mod.rs (HTTP/H2, direct gRPC, WebSocket) and
    // one each in the three H3 retry paths.
    assert_eq!(
        proxy_src.matches("select_next_retry_target(").count(),
        3,
        "proxy/mod.rs must keep exactly the three retry call sites"
    );
    assert_eq!(h3_server.matches("select_next_retry_target(").count(), 1);
    assert_eq!(
        h3_cross.matches("select_next_retry_target(").count(),
        1,
        "cross-protocol must funnel through one shared wrapper call"
    );
    assert_eq!(h3_ws.matches("select_next_retry_target(").count(), 1);

    // Every production call passes the validated inbound host near the helper.
    for (label, source, expected_calls) in [
        ("proxy/mod.rs", proxy_src, 3usize),
        ("http3/server.rs", h3_server, 1),
        ("http3/websocket.rs", h3_ws, 1),
    ] {
        let mut remaining = source;
        let mut seen = 0usize;
        while let Some(idx) = remaining.find("select_next_retry_target(") {
            let window: String = remaining[idx..].chars().take(600).collect();
            assert!(
                window.contains("request_host.as_deref()"),
                "{label} select_next_retry_target call must pass request_host.as_deref(): {window}"
            );
            seen += 1;
            remaining = &remaining[idx + "select_next_retry_target(".len()..];
        }
        assert_eq!(
            seen, expected_calls,
            "{label} must keep {expected_calls} select_next_retry_target call(s)"
        );
    }

    assert!(
        h3_cross.contains("pub request_authority: Option<&'a str>,"),
        "CrossProtocolRequest must carry the validated inbound authority"
    );
    let cross_call = h3_cross
        .split("crate::proxy::backend_dispatch::select_next_retry_target(")
        .nth(1)
        .expect("cross-protocol shared helper call")
        .split(')')
        .next()
        .expect("call close");
    assert!(
        cross_call.contains("request_authority"),
        "H3 cross-protocol must pass request_authority into the shared helper"
    );

    // No dispatch path may open-code dialing a literal configured wildcard
    // beside the shared helper (the helper is the only place allowed to turn a
    // configured `*.` into a concrete dial host for retries).
    for (label, source) in [
        ("proxy/mod.rs", proxy_src),
        ("http3/server.rs", h3_server),
        ("http3/cross_protocol.rs", h3_cross),
        ("http3/websocket.rs", h3_ws),
    ] {
        let mut remaining = source;
        while let Some(idx) = remaining.find("select_next_retry_target(") {
            let after = &remaining[idx..];
            let window: String = after.chars().take(800).collect();
            assert!(
                !window.contains("starts_with(\"*.\")"),
                "{label} must not open-code wildcard dial logic beside select_next_retry_target"
            );
            remaining = &after["select_next_retry_target(".len()..];
        }
    }
}
