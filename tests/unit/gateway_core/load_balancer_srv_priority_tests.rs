//! Health-aware RFC 2782 SRV priority-tier selection (issue #4291).
//!
//! DNS-SD publishes every admissible SRV priority tier, stamping each target
//! with the reserved `ferrum.srv.priority` tag (see
//! `service_discovery_tests.rs`). The load balancer's shared candidate filter
//! then decides, per selection and from LIVE health, which tier serves traffic:
//!
//! * only the numerically-smallest tier with a healthy member is eligible;
//! * a healthy higher-numbered tier is never mixed with a healthy lower one;
//! * the next tier becomes eligible only when every lower tier is unhealthy,
//!   and stops being eligible the moment a lower tier recovers;
//! * targets WITHOUT the tag (static / non-SRV-provider) are unprioritized and
//!   stay eligible in every tier.
//!
//! The filter lives inside the health computation shared by every selection
//! entry point, so HTTP/1.1, H2, H3, gRPC, WebSocket, TCP and UDP dispatch
//! cannot diverge; the tests below assert that parity directly rather than
//! per protocol.

use chrono::Utc;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, SubsetDefinition, Upstream, UpstreamPortOverride,
    UpstreamTarget,
};
use ferrum_edge::health_check::ActiveUnhealthyTargets;
use ferrum_edge::load_balancer::{
    HealthContext, LoadBalancer, LoadBalancerCache, sticky_session_token, target_key,
};
use std::collections::HashMap;
use std::sync::Arc;

const UPSTREAM: &str = "srv-priority-upstream";

fn tag() -> &'static str {
    ferrum_edge::_test_support::srv_priority_tag_for_test()
}

/// Target carrying an explicit RFC 2782 SRV priority tag.
fn tiered(host: &str, weight: u32, priority: &str) -> UpstreamTarget {
    let mut tags = HashMap::new();
    tags.insert(tag().to_string(), priority.to_string());
    UpstreamTarget {
        host: host.to_string(),
        port: 8080,
        service_port_policy_key: None,
        weight,
        tags,
        locality: None,
        path: None,
    }
}

/// Target with NO SRV tier — a static / operator-authored entry.
fn untiered(host: &str, weight: u32) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port: 8080,
        service_port_policy_key: None,
        weight,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

fn health_ctx(active: &ActiveUnhealthyTargets) -> HealthContext<'_> {
    HealthContext {
        active_unhealthy: active,
        proxy_passive: None,
        max_ejection_percent: None,
    }
}

fn mark_unhealthy(active: &ActiveUnhealthyTargets, targets: &[UpstreamTarget], hosts: &[&str]) {
    active.clear();
    for target in targets {
        if hosts.contains(&target.host.as_str()) {
            active.insert(target_key(UPSTREAM, target), 1);
        }
    }
}

/// Every host `select` yields over enough draws to cover the pool.
fn selected_hosts(
    lb: &LoadBalancer,
    health: Option<&HealthContext<'_>>,
    draws: usize,
) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for i in 0..draws {
        let sel = lb
            .select(&format!("ctx-{i}"), health)
            .expect("selection must never fail while any target exists");
        if !hosts.contains(&sel.target.host) {
            hosts.push(sel.target.host.clone());
        }
    }
    hosts.sort();
    hosts
}

fn two_tier_targets() -> Vec<UpstreamTarget> {
    vec![
        tiered("p1", 1, "10"),
        tiered("p2", 1, "10"),
        tiered("dr1", 1, "20"),
        tiered("dr2", 1, "20"),
    ]
}

fn rr(targets: &[UpstreamTarget]) -> LoadBalancer {
    LoadBalancer::new(UPSTREAM, LoadBalancerAlgorithm::RoundRobin, targets, None)
}

#[test]
fn two_healthy_tiers_select_only_priority_ten() {
    let targets = two_tier_targets();
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 200),
        vec!["p1".to_string(), "p2".to_string()],
        "a healthy DR tier must never share traffic with a healthy primary tier"
    );
}

#[test]
fn priority_twenty_becomes_selectable_only_after_every_priority_ten_peer_is_unhealthy() {
    let targets = two_tier_targets();
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    // One primary down: the surviving primary still blocks the DR tier.
    mark_unhealthy(&active, &targets, &["p1"]);
    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 200),
        vec!["p2".to_string()],
        "a surviving priority-10 peer must block priority 20"
    );

    // Both primaries down: the DR tier takes over, whole.
    mark_unhealthy(&active, &targets, &["p1", "p2"]);
    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 200),
        vec!["dr1".to_string(), "dr2".to_string()],
        "priority 20 must become eligible once no priority-10 target is healthy"
    );

    // A primary recovers: preference snaps back immediately.
    mark_unhealthy(&active, &targets, &["p2"]);
    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 200),
        vec!["p1".to_string()],
        "a recovered priority-10 target must win again without any latch or hysteresis"
    );
}

#[test]
fn three_tiers_walk_down_and_back_up_one_step_at_a_time() {
    let targets = vec![
        tiered("p", 1, "0"),
        tiered("mid", 1, "10"),
        tiered("far", 1, "20"),
    ];
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    for (down, expected) in [
        (vec![], "p"),
        (vec!["p"], "mid"),
        (vec!["p", "mid"], "far"),
        (vec!["mid", "far"], "p"),
    ] {
        mark_unhealthy(&active, &targets, &down);
        assert_eq!(
            selected_hosts(&lb, Some(&health_ctx(&active)), 60),
            vec![expected.to_string()],
            "with {down:?} unhealthy the best reachable tier is {expected}"
        );
    }
}

#[test]
fn every_target_unhealthy_keeps_the_existing_degraded_fallback() {
    let targets = two_tier_targets();
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();
    mark_unhealthy(&active, &targets, &["p1", "p2", "dr1", "dr2"]);

    let sel = lb
        .select("ctx", Some(&health_ctx(&active)))
        .expect("all-unhealthy must still fall back rather than fail closed");
    assert!(
        sel.is_fallback,
        "the all-unhealthy fallback contract is unchanged by tier selection"
    );
}

#[test]
fn tier_selection_is_independent_of_target_order() {
    let forward = vec![
        tiered("p1", 1, "10"),
        tiered("dr1", 1, "20"),
        tiered("p2", 1, "10"),
    ];
    let reversed: Vec<UpstreamTarget> = forward.iter().rev().cloned().collect();
    let active = ActiveUnhealthyTargets::new();

    assert_eq!(
        selected_hosts(&rr(&forward), Some(&health_ctx(&active)), 200),
        vec!["p1".to_string(), "p2".to_string()]
    );
    assert_eq!(
        selected_hosts(&rr(&reversed), Some(&health_ctx(&active)), 200),
        vec!["p1".to_string(), "p2".to_string()],
        "tier choice must not depend on the order targets appear in"
    );
}

#[test]
fn priority_zero_is_a_real_tier_not_an_unset_marker() {
    let targets = vec![tiered("zero", 1, "0"), tiered("ten", 1, "10")];
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 100),
        vec!["zero".to_string()]
    );

    mark_unhealthy(&active, &targets, &["zero"]);
    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 100),
        vec!["ten".to_string()],
        "priority 0 must fail over like any other tier"
    );
}

#[test]
fn max_priority_is_a_real_tier_and_distinguishable_from_untagged() {
    // 65535 is a legal RFC 2782 priority; the internal "no tier" sentinel must
    // not collide with it.
    let targets = vec![tiered("hi", 1, "10"), tiered("lowest", 1, "65535")];
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 100),
        vec!["hi".to_string()]
    );
    mark_unhealthy(&active, &targets, &["hi"]);
    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 100),
        vec!["lowest".to_string()]
    );
}

// ── Static / unprioritized merge contract ──

#[test]
fn untagged_static_targets_stay_eligible_in_every_tier() {
    let targets = vec![
        tiered("p1", 1, "10"),
        tiered("dr1", 1, "20"),
        untiered("static1", 1),
    ];
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 200),
        vec!["p1".to_string(), "static1".to_string()],
        "a static target has no SRV tier, so it must not be demoted behind one"
    );

    mark_unhealthy(&active, &targets, &["p1"]);
    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 200),
        vec!["dr1".to_string(), "static1".to_string()],
        "the static target stays eligible while the SRV tier fails over around it"
    );

    mark_unhealthy(&active, &targets, &["p1", "dr1"]);
    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 200),
        vec!["static1".to_string()],
        "with every SRV tier unhealthy the static target alone serves — not a fallback"
    );
    assert!(
        !lb.select("ctx", Some(&health_ctx(&active)))
            .expect("static target is healthy")
            .is_fallback,
        "a healthy static target is a normal selection, not degraded routing"
    );
}

#[test]
fn an_all_untagged_upstream_is_completely_unaffected() {
    let targets = vec![untiered("a", 1), untiered("b", 1), untiered("c", 1)];
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 200),
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );
    assert_eq!(selected_hosts(&lb, None, 200).len(), 3);
}

#[test]
fn a_single_tier_upstream_behaves_exactly_like_an_untagged_one() {
    let targets = vec![tiered("a", 1, "10"), tiered("b", 1, "10")];
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 200),
        vec!["a".to_string(), "b".to_string()],
        "one tier is a no-op; the filter must not narrow a single-tier pool"
    );
}

// ── Poisoned / forged tag values fail OPEN ──

#[test]
fn a_malformed_priority_tag_disables_tiering_instead_of_inventing_one() {
    for spoof in ["", "abc", "010", " 10", "-1", "65536"] {
        let targets = vec![
            tiered("p1", 1, "10"),
            tiered("dr1", 1, "20"),
            tiered("forged", 1, spoof),
        ];
        let lb = rr(&targets);
        let active = ActiveUnhealthyTargets::new();
        assert_eq!(
            selected_hosts(&lb, Some(&health_ctx(&active)), 300),
            vec!["dr1".to_string(), "forged".to_string(), "p1".to_string()],
            "a malformed tag value ({spoof:?}) must disable SRV tiering, never define a tier"
        );
    }
}

#[test]
fn more_tiers_than_the_bound_disables_tiering() {
    let max = ferrum_edge::_test_support::max_srv_priority_tiers_for_test();
    let targets: Vec<UpstreamTarget> = (0..(max + 1))
        .map(|i| tiered(&format!("h{i}"), 1, &(i as u16 * 10).to_string()))
        .collect();
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 600).len(),
        max + 1,
        "an over-cardinality tier map must fail open to flat selection, not allocate tiers"
    );
}

// ── Same-tier weight and algorithm behavior ──

#[test]
fn weighted_round_robin_respects_weights_inside_the_selected_tier_only() {
    let targets = vec![
        tiered("heavy", 9, "10"),
        tiered("light", 1, "10"),
        tiered("dr", 100, "20"),
    ];
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );
    let active = ActiveUnhealthyTargets::new();
    let ctx = health_ctx(&active);

    let mut counts: HashMap<String, usize> = HashMap::new();
    for i in 0..1000 {
        let sel = lb.select(&format!("c{i}"), Some(&ctx)).unwrap();
        *counts.entry(sel.target.host.clone()).or_default() += 1;
    }

    assert_eq!(
        counts.get("dr"),
        None,
        "the DR tier must receive no traffic"
    );
    let heavy = *counts.get("heavy").unwrap_or(&0);
    let light = *counts.get("light").unwrap_or(&0);
    assert_eq!(heavy + light, 1000);
    assert!(
        heavy > light * 4,
        "same-tier SRV weights must still drive WRR (heavy={heavy}, light={light})"
    );
}

#[test]
fn consistent_hash_is_stable_within_the_selected_tier() {
    let targets = vec![
        tiered("p1", 1, "10"),
        tiered("p2", 1, "10"),
        tiered("dr", 1, "20"),
    ];
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::ConsistentHashing,
        &targets,
        None,
    );
    let active = ActiveUnhealthyTargets::new();
    let ctx = health_ctx(&active);

    let first = lb
        .select("sticky-key", Some(&ctx))
        .unwrap()
        .target
        .host
        .clone();
    assert_ne!(first, "dr");
    for _ in 0..50 {
        assert_eq!(
            lb.select("sticky-key", Some(&ctx)).unwrap().target.host,
            first,
            "consistent hashing must stay stable inside the selected tier"
        );
    }
}

#[test]
fn least_connections_and_random_also_stay_inside_the_selected_tier() {
    for algorithm in [
        LoadBalancerAlgorithm::LeastConnections,
        LoadBalancerAlgorithm::Random,
        LoadBalancerAlgorithm::RoundRobin,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        LoadBalancerAlgorithm::ConsistentHashing,
        LoadBalancerAlgorithm::LeastLatency,
    ] {
        let targets = two_tier_targets();
        let lb = LoadBalancer::new(UPSTREAM, algorithm, &targets, None);
        let active = ActiveUnhealthyTargets::new();
        let hosts = selected_hosts(&lb, Some(&health_ctx(&active)), 300);
        assert!(
            hosts.iter().all(|h| h == "p1" || h == "p2"),
            "{algorithm:?} leaked the DR tier: {hosts:?}"
        );
    }
}

// ── Parity across selection entry points ──

#[test]
fn subset_selection_applies_the_same_tier_filter() {
    let mut labels = HashMap::new();
    labels.insert("app".to_string(), "checkout".to_string());

    let with_label = |host: &str, priority: &str| {
        let mut t = tiered(host, 1, priority);
        t.tags.insert("app".to_string(), "checkout".to_string());
        t
    };
    let targets = vec![
        with_label("p1", "10"),
        with_label("dr1", "20"),
        tiered("other", 1, "10"),
    ];
    let subsets = vec![SubsetDefinition {
        name: "checkout".to_string(),
        labels,
        traffic_policy: None,
    }];
    let lb = LoadBalancer::with_subsets(
        UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        Some(&subsets),
    );
    let active = ActiveUnhealthyTargets::new();

    for i in 0..100 {
        let sel = lb
            .select_from_subset(&format!("c{i}"), "checkout", Some(&health_ctx(&active)))
            .expect("subset selection must resolve");
        assert_eq!(sel.target.host, "p1", "subset dispatch leaked the DR tier");
    }

    mark_unhealthy(&active, &targets, &["p1"]);
    let sel = lb
        .select_from_subset("c", "checkout", Some(&health_ctx(&active)))
        .expect("subset selection must fail over inside the subset");
    assert_eq!(
        sel.target.host, "dr1",
        "subset dispatch must fail over to the DR tier once the subset's primary tier is down"
    );
}

#[test]
fn per_port_selection_applies_the_same_tier_filter() {
    let mut targets = two_tier_targets();
    for target in &mut targets {
        target.port = 9000;
    }
    let lb = LoadBalancer::with_subsets(
        UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        None,
    );
    let active = ActiveUnhealthyTargets::new();

    // No override registered for this port: `select_for_port` delegates to
    // `select`, which is the same shared candidate filter.
    for i in 0..100 {
        let sel = lb
            .select_for_port(&format!("c{i}"), 9000, Some(&health_ctx(&active)))
            .expect("port selection must resolve");
        assert!(
            sel.target.host == "p1" || sel.target.host == "p2",
            "per-port dispatch leaked the DR tier: {}",
            sel.target.host
        );
    }
}

#[test]
fn retry_exclusion_falls_over_within_the_tier_before_leaving_it() {
    let targets = two_tier_targets();
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    // Excluding one primary must land on the OTHER primary, not on the DR tier.
    let retry = lb
        .select_excluding("ctx", &targets[0], Some(&health_ctx(&active)))
        .expect("retry must find a peer");
    assert_eq!(
        retry.host, "p2",
        "retry must exhaust the best tier before considering a lower one"
    );
}

#[test]
fn sticky_session_eligibility_follows_the_tier_filter() {
    let targets = two_tier_targets();
    // `select_sticky` fail-closes on an empty binding index. The index is
    // materialized only for Cookie hash-on (Gateway API session persistence),
    // so this balancer must mint sticky tokens or the assertion never reaches
    // the shared SRV-tier health filter.
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        Some("cookie:lb-affinity-fe-0123456789abcdef".to_string()),
    );
    let active = ActiveUnhealthyTargets::new();

    // Resolve the DR target's sticky token through the balancer's own index by
    // selecting it while the primary tier is down.
    mark_unhealthy(&active, &targets, &["p1", "p2"]);
    let dr = lb
        .select("ctx", Some(&health_ctx(&active)))
        .expect("DR tier serves while the primary tier is down")
        .target;
    let token =
        sticky_session_token(UPSTREAM, &dr).expect("a selected target must mint a sticky token");

    assert!(
        lb.select_sticky(&token, None, None, Some(&health_ctx(&active)))
            .is_some(),
        "the DR binding is honored while it is the best reachable tier"
    );

    active.clear();
    assert!(
        lb.select_sticky(&token, None, None, Some(&health_ctx(&active)))
            .is_none(),
        "once priority 10 recovers, a DR-tier sticky binding is no longer eligible"
    );
}

// ── >128-target Vec fallback path ──

#[test]
fn vec_fallback_path_applies_the_same_tier_filter() {
    let mut targets: Vec<UpstreamTarget> = (0..130)
        .map(|i| tiered(&format!("p{i}"), 1, "10"))
        .collect();
    targets.push(tiered("dr", 1, "20"));
    let lb = rr(&targets);
    let active = ActiveUnhealthyTargets::new();

    let hosts = selected_hosts(&lb, Some(&health_ctx(&active)), 600);
    assert!(
        !hosts.contains(&"dr".to_string()),
        ">128-target Vec fallback leaked the DR tier"
    );

    let down: Vec<String> = (0..130).map(|i| format!("p{i}")).collect();
    let down_refs: Vec<&str> = down.iter().map(String::as_str).collect();
    mark_unhealthy(&active, &targets, &down_refs);
    assert_eq!(
        selected_hosts(&lb, Some(&health_ctx(&active)), 50),
        vec!["dr".to_string()],
        ">128-target Vec fallback must still fail over to the DR tier"
    );
}

#[test]
fn no_health_context_still_prefers_the_best_tier() {
    let targets = two_tier_targets();
    let lb = rr(&targets);
    assert_eq!(
        selected_hosts(&lb, None, 200),
        vec!["p1".to_string(), "p2".to_string()],
        "an upstream with no health checks configured must still honor RFC 2782 priority"
    );
}

// ── Indexed candidate-pool paths under a PRESENT, EMPTY health context ──
//
// `select_from_subset` and the per-port-override arm of `select_for_port` do
// not reuse the whole-upstream health bitset: they compute an index-scoped one
// so a passive max-ejection cap is sized against the actual candidate pool.
// That helper has its own "both health maps are empty, so every candidate is
// healthy" fast return, which is exactly the state a healthy pool is in almost
// all of the time. Tier selection is NOT a health filter and must run there
// too, or an all-healthy subset / per-port dispatch would silently round-robin
// a DR tier alongside its primary tier — the one case these entry points are
// most likely to be in. The tests below pin that fast return specifically: the
// health context is present (`Some`) and its maps are empty, so no target is
// ever ejected and no other branch of the helper can be reached.

/// Multi-member subset, present-but-empty health: only the best healthy tier
/// plus unprioritized targets are eligible, and the DR tier is never drawn.
#[test]
fn subset_indexed_path_filters_tiers_with_a_present_empty_health_context() {
    let mut labels = HashMap::new();
    labels.insert("app".to_string(), "checkout".to_string());

    let with_label = |mut t: UpstreamTarget| {
        t.tags.insert("app".to_string(), "checkout".to_string());
        t
    };
    // Two primaries and two DRs so a leak cannot be masked by round-robin
    // landing on the same host, plus an untagged static member that must stay
    // eligible, plus an out-of-subset primary that must never be drawn.
    let targets = vec![
        with_label(tiered("p1", 1, "10")),
        with_label(tiered("p2", 1, "10")),
        with_label(tiered("dr1", 1, "20")),
        with_label(tiered("dr2", 1, "20")),
        with_label(untiered("static1", 1)),
        tiered("outside", 1, "10"),
    ];
    let subsets = vec![SubsetDefinition {
        name: "checkout".to_string(),
        labels,
        traffic_policy: None,
    }];
    let lb = LoadBalancer::with_subsets(
        UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        Some(&subsets),
    );

    // Present health context whose active map is empty and whose passive map is
    // absent: the indexed helper's all-healthy fast return.
    let active = ActiveUnhealthyTargets::new();
    assert!(
        active.is_empty(),
        "this test must exercise the empty-health fast return, not the ejection path"
    );

    let mut seen: Vec<String> = Vec::new();
    for i in 0..300 {
        let sel = lb
            .select_from_subset(&format!("c{i}"), "checkout", Some(&health_ctx(&active)))
            .expect("subset selection must resolve while the subset has healthy members");
        if !seen.contains(&sel.target.host) {
            seen.push(sel.target.host.clone());
        }
    }
    seen.sort();
    assert_eq!(
        seen,
        vec!["p1".to_string(), "p2".to_string(), "static1".to_string()],
        "an all-healthy subset must serve only the best SRV tier plus unprioritized targets"
    );

    // Health semantics are unchanged: the DR tier is still reachable, and only
    // once every primary in the subset is unhealthy.
    mark_unhealthy(&active, &targets, &["p1"]);
    let mut partial: Vec<String> = Vec::new();
    for i in 0..300 {
        let sel = lb
            .select_from_subset(&format!("d{i}"), "checkout", Some(&health_ctx(&active)))
            .expect("subset selection must resolve");
        if !partial.contains(&sel.target.host) {
            partial.push(sel.target.host.clone());
        }
    }
    partial.sort();
    assert_eq!(
        partial,
        vec!["p2".to_string(), "static1".to_string()],
        "one surviving primary must keep the DR tier out of the subset pool"
    );

    mark_unhealthy(&active, &targets, &["p1", "p2"]);
    let mut failed_over: Vec<String> = Vec::new();
    for i in 0..300 {
        let sel = lb
            .select_from_subset(&format!("e{i}"), "checkout", Some(&health_ctx(&active)))
            .expect("subset selection must fail over inside the subset");
        if !failed_over.contains(&sel.target.host) {
            failed_over.push(sel.target.host.clone());
        }
    }
    failed_over.sort();
    assert_eq!(
        failed_over,
        vec!["dr1".to_string(), "dr2".to_string(), "static1".to_string()],
        "the DR tier becomes eligible only after every primary in the subset is unhealthy"
    );
}

/// Build a real per-port override so `select_for_port` takes its indexed
/// candidate-pool arm instead of delegating to `select`. `UpstreamPortOverride`
/// is only wired through the config-driven `LoadBalancerCache`, so the balancer
/// is built the way production builds it.
fn lb_with_port_override(targets: Vec<UpstreamTarget>, port: u16) -> Arc<LoadBalancer> {
    let now = Utc::now();
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        port,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let upstream = Upstream {
        labels: Default::default(),
        id: "u1".to_string(),
        namespace: "ferrum".to_string(),
        name: Some("u1".to_string()),
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides,
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
    };
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    cache
        .load()
        .get_balancer("ferrum", "u1")
        .expect("configured upstream must be in the LB cache")
}

/// Registered per-port override, present-but-empty health: the port's indexed
/// candidate pool is tier-filtered exactly like the whole-upstream pool.
#[test]
fn per_port_indexed_path_filters_tiers_with_a_present_empty_health_context() {
    let on_port = |host: &str, priority: &str, port: u16| {
        let mut t = tiered(host, 1, priority);
        t.port = port;
        t
    };
    let mut static_on_9000 = untiered("static1", 1);
    static_on_9000.port = 9000;

    // Port 9000 carries two primaries, two DRs and one untagged target; the
    // 9001 targets exist only to prove the override's pool is index-scoped.
    let targets = vec![
        on_port("p1", "10", 9000),
        on_port("p2", "10", 9000),
        on_port("dr1", "20", 9000),
        on_port("dr2", "20", 9000),
        static_on_9000,
        on_port("other-port", "10", 9001),
    ];
    let lb = lb_with_port_override(targets.clone(), 9000);

    // `other-port` is a healthy priority-10 target, so it would be drawn if
    // `select_for_port` had fallen through to whole-upstream `select`. Its
    // absence below is the proof that the registered override's indexed
    // candidate-pool arm — the one being pinned here — actually ran.
    let active = ActiveUnhealthyTargets::new();
    let mut seen: Vec<String> = Vec::new();
    for i in 0..300 {
        let sel = lb
            .select_for_port(&format!("c{i}"), 9000, Some(&health_ctx(&active)))
            .expect("per-port selection must resolve while the port has healthy members");
        if !seen.contains(&sel.target.host) {
            seen.push(sel.target.host.clone());
        }
    }
    seen.sort();
    assert_eq!(
        seen,
        vec!["p1".to_string(), "p2".to_string(), "static1".to_string()],
        "an all-healthy per-port pool must serve only the best SRV tier plus unprioritized targets"
    );

    // Active-health keys are scoped to the runtime upstream key the cache built
    // this balancer with, not the bare upstream id.
    let lb_key = ferrum_edge::config::db_backend::namespaced_runtime_key("ferrum", "u1");
    let mark_port_unhealthy = |hosts: &[&str]| {
        active.clear();
        for target in &targets {
            if hosts.contains(&target.host.as_str()) {
                active.insert(target_key(&lb_key, target), 1);
            }
        }
    };

    mark_port_unhealthy(&["p1", "p2"]);
    let mut failed_over: Vec<String> = Vec::new();
    for i in 0..300 {
        let sel = lb
            .select_for_port(&format!("d{i}"), 9000, Some(&health_ctx(&active)))
            .expect("per-port selection must fail over inside the port pool");
        if !failed_over.contains(&sel.target.host) {
            failed_over.push(sel.target.host.clone());
        }
    }
    failed_over.sort();
    assert_eq!(
        failed_over,
        vec!["dr1".to_string(), "dr2".to_string(), "static1".to_string()],
        "the per-port DR tier becomes eligible only after every primary on the port is unhealthy"
    );
}
