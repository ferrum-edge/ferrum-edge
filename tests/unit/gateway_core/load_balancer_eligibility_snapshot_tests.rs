//! Generation-cached health eligibility snapshots (issue #5041).
//!
//! `LoadBalancer` projects the shared active-probe map and each proxy's
//! passive ejection map onto its targets once per map generation and reuses
//! the projection until the health checker publishes a change. These tests
//! pin the invalidation contract (every mutation path — ejection, recovery,
//! in-place edit, retain, clear — must be observed by the very next
//! selection), cross-proxy passive isolation, the max-ejection re-admit
//! order, duplicate `host:port` targets, and the `> 128` Vec path.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use ferrum_edge::config::types::{LoadBalancerAlgorithm, PassiveHealthCheck, UpstreamTarget};
use ferrum_edge::health_check::{
    ActiveUnhealthyTargets, HealthChecker, PassiveEjection, PassiveUnhealthyTargets,
    ProxyHealthState, VacantInsert,
};
use ferrum_edge::load_balancer::{HealthContext, LoadBalancer, target_host_port_key, target_key};

const NS: &str = "default";
const UPSTREAM_KEY: &str = "default|snapshot-upstream";

fn target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

fn make_targets(n: usize) -> Vec<UpstreamTarget> {
    (0..n)
        .map(|i| target(&format!("10.0.0.{i}"), 8080))
        .collect()
}

fn balancer(targets: &[UpstreamTarget]) -> LoadBalancer {
    LoadBalancer::new(
        UPSTREAM_KEY,
        LoadBalancerAlgorithm::RoundRobin,
        targets,
        None,
    )
}

fn passive_cfg(max_ejection_percent: Option<u8>) -> PassiveHealthCheck {
    PassiveHealthCheck {
        unhealthy_status_codes: vec![500, 502, 503, 504],
        unhealthy_threshold: 1,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 0,
        max_ejection_percent,
        ..Default::default()
    }
}

fn ejection(tick: u64, target: &UpstreamTarget) -> PassiveEjection {
    PassiveEjection {
        ejected_at_ms: tick,
        ejected_at_tick_ms: tick,
        recover_at_tick_ms: tick,
        auto_recover: false,
        upstream_id: UPSTREAM_KEY.to_string(),
        host: target.host.clone(),
        port: target.port,
        consecutive_generation: None,
    }
}

fn passive_state(checker: &HealthChecker, proxy_id: &str) -> Arc<ProxyHealthState> {
    checker
        .passive_health
        .get(&format!("{NS}|{proxy_id}"))
        .map(|entry| entry.clone())
        .expect("passive state exists after report_response")
}

/// Hosts selected over enough rounds to cover every eligible target.
fn selected_hosts(
    lb: &LoadBalancer,
    ctx: Option<&HealthContext<'_>>,
    rounds: usize,
) -> BTreeSet<String> {
    (0..rounds)
        .map(|_| lb.select("", ctx).expect("selection").target.host.clone())
        .collect()
}

fn hosts(targets: &[UpstreamTarget], indices: &[usize]) -> BTreeSet<String> {
    indices.iter().map(|&i| targets[i].host.clone()).collect()
}

#[test]
fn active_ejection_and_recovery_invalidate_cached_snapshot() {
    let targets = make_targets(4);
    let lb = balancer(&targets);
    let active = ActiveUnhealthyTargets::new();
    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    // Warm the snapshot with everything healthy.
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 1, 2, 3])
    );

    // Ejection is observed on the very next selection.
    active.insert(target_key(UPSTREAM_KEY, &targets[1]), 1);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 2, 3])
    );

    // A second ejection while the first is cached.
    active.insert(target_key(UPSTREAM_KEY, &targets[3]), 1);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 2])
    );

    // Recovery through `remove` and `remove_if` both invalidate.
    active.remove(&target_key(UPSTREAM_KEY, &targets[1]));
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 1, 2])
    );
    active.remove_if(&target_key(UPSTREAM_KEY, &targets[3]), |_, _| true);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 1, 2, 3])
    );

    // `retain` and `clear` are mutation paths too.
    active.insert(target_key(UPSTREAM_KEY, &targets[0]), 1);
    active.insert(target_key(UPSTREAM_KEY, &targets[2]), 1);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[1, 3])
    );
    let keep = target_key(UPSTREAM_KEY, &targets[2]);
    active.retain(|key, _| *key == keep);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 1, 3])
    );
    active.clear();
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 1, 2, 3])
    );
}

#[test]
fn unrelated_upstream_active_failure_does_not_touch_this_balancer() {
    let targets = make_targets(3);
    let lb = balancer(&targets);
    let active = ActiveUnhealthyTargets::new();
    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive: None,
        max_ejection_percent: None,
    };
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 12),
        hosts(&targets, &[0, 1, 2])
    );

    // Same host:port under another upstream — must not eject ours.
    active.insert(target_key("default|other-upstream", &targets[0]), 1);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 12),
        hosts(&targets, &[0, 1, 2])
    );

    // And our own ejection is still seen while the unrelated one is present.
    active.insert(target_key(UPSTREAM_KEY, &targets[2]), 1);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 12),
        hosts(&targets, &[0, 1])
    );
}

#[test]
fn active_snapshot_is_not_reused_across_different_active_maps() {
    // Two active maps at the same process-wide generation: a balancer that
    // cached map A's projection must recompute when handed map B.
    let targets = make_targets(3);
    let lb = balancer(&targets);
    let map_a = ActiveUnhealthyTargets::new();
    let map_b = ActiveUnhealthyTargets::new();
    map_b.insert(target_key(UPSTREAM_KEY, &targets[0]), 1);
    assert_eq!(map_a.generation(), map_b.generation());

    let ctx_a = HealthContext {
        active_unhealthy: &map_a,
        proxy_passive: None,
        max_ejection_percent: None,
    };
    let ctx_b = HealthContext {
        active_unhealthy: &map_b,
        proxy_passive: None,
        max_ejection_percent: None,
    };
    // Cache A's (all-healthy) projection, then swap maps with no mutation in
    // between: B's ejection must still be honored.
    assert_eq!(
        selected_hosts(&lb, Some(&ctx_a), 12),
        hosts(&targets, &[0, 1, 2])
    );
    assert_eq!(
        selected_hosts(&lb, Some(&ctx_b), 12),
        hosts(&targets, &[1, 2])
    );
    assert_eq!(
        selected_hosts(&lb, Some(&ctx_a), 12),
        hosts(&targets, &[0, 1, 2])
    );

    map_a.insert(target_key(UPSTREAM_KEY, &targets[2]), 1);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx_a), 12),
        hosts(&targets, &[0, 1])
    );
    assert_eq!(
        selected_hosts(&lb, Some(&ctx_b), 12),
        hosts(&targets, &[1, 2])
    );
}

#[test]
fn passive_ejection_and_recovery_invalidate_cached_projection() {
    let targets = make_targets(4);
    let lb = balancer(&targets);
    let checker = HealthChecker::new();
    let active = ActiveUnhealthyTargets::new();
    let cfg = passive_cfg(None);

    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[0],
        200,
        false,
        Some(&cfg),
    );
    let ps = passive_state(&checker, "proxy-a");
    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(Arc::clone(&ps)),
        max_ejection_percent: None,
    };
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 1, 2, 3])
    );

    // Eject via the real reporting path.
    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[2],
        503,
        false,
        Some(&cfg),
    );
    assert_eq!(ps.unhealthy.len(), 1);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 1, 3])
    );

    // Direct insert (what tests and the recovery scanner's siblings use).
    ps.unhealthy
        .insert(target_host_port_key(&targets[1]), ejection(5, &targets[1]));
    assert_eq!(ps.unhealthy.len(), 2);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 3])
    );

    // Success-based recovery through the reporting path.
    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[2],
        200,
        false,
        Some(&cfg),
    );
    assert_eq!(ps.unhealthy.len(), 1);
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 2, 3])
    );

    // Direct removal.
    ps.unhealthy.remove(&target_host_port_key(&targets[1]));
    assert_eq!(ps.unhealthy.len(), 0);
    assert!(ps.unhealthy.is_empty());
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[0, 1, 2, 3])
    );
}

#[test]
fn passive_projection_is_isolated_per_proxy_on_a_shared_balancer() {
    let targets = make_targets(3);
    let lb = balancer(&targets);
    let checker = HealthChecker::new();
    let active = ActiveUnhealthyTargets::new();
    let cfg = passive_cfg(None);

    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[0],
        200,
        false,
        Some(&cfg),
    );
    checker.report_response(
        NS,
        "proxy-b",
        UPSTREAM_KEY,
        &targets[0],
        200,
        false,
        Some(&cfg),
    );
    let ps_a = passive_state(&checker, "proxy-a");
    let ps_b = passive_state(&checker, "proxy-b");
    let ctx_a = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(Arc::clone(&ps_a)),
        max_ejection_percent: None,
    };
    let ctx_b = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(Arc::clone(&ps_b)),
        max_ejection_percent: None,
    };

    // Proxy A ejects target 1; proxy B ejects target 2. Interleave selections
    // so both projections live in the same balancer table at once.
    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[1],
        503,
        false,
        Some(&cfg),
    );
    checker.report_response(
        NS,
        "proxy-b",
        UPSTREAM_KEY,
        &targets[2],
        503,
        false,
        Some(&cfg),
    );
    for _ in 0..4 {
        assert_eq!(
            selected_hosts(&lb, Some(&ctx_a), 12),
            hosts(&targets, &[0, 2])
        );
        assert_eq!(
            selected_hosts(&lb, Some(&ctx_b), 12),
            hosts(&targets, &[0, 1])
        );
    }

    // Proxy B recovers; proxy A's view must not change.
    checker.report_response(
        NS,
        "proxy-b",
        UPSTREAM_KEY,
        &targets[2],
        200,
        false,
        Some(&cfg),
    );
    assert_eq!(
        selected_hosts(&lb, Some(&ctx_b), 12),
        hosts(&targets, &[0, 1, 2])
    );
    assert_eq!(
        selected_hosts(&lb, Some(&ctx_a), 12),
        hosts(&targets, &[0, 2])
    );

    // A context with no passive state at all sees everything.
    let ctx_none = HealthContext {
        active_unhealthy: &active,
        proxy_passive: None,
        max_ejection_percent: None,
    };
    assert_eq!(
        selected_hosts(&lb, Some(&ctx_none), 12),
        hosts(&targets, &[0, 1, 2])
    );
}

#[test]
fn in_place_passive_edit_publishes_a_new_generation() {
    let targets = make_targets(3);
    let checker = HealthChecker::new();
    let cfg = passive_cfg(None);
    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[0],
        503,
        false,
        Some(&cfg),
    );
    let ps = passive_state(&checker, "proxy-a");
    let key = target_host_port_key(&targets[0]);

    let before = ps.unhealthy.generation();
    {
        let mut entry = ps.unhealthy.get_mut(&key).expect("ejected");
        entry.ejected_at_tick_ms = 42;
        // Not yet published while the guard is alive...
        assert_eq!(ps.unhealthy.generation(), before);
    }
    // ...published on drop, before any reader can see the new value under
    // the old generation.
    assert!(ps.unhealthy.generation() > before);
    assert_eq!(
        ps.unhealthy.get(&key).expect("ejected").ejected_at_tick_ms,
        42
    );
    assert_eq!(ps.unhealthy.len(), 1);
}

#[test]
fn max_ejection_cap_readmits_earliest_then_lowest_index_from_cached_projection() {
    let targets = make_targets(4);
    let lb = balancer(&targets);
    let checker = HealthChecker::new();
    let active = ActiveUnhealthyTargets::new();
    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[0],
        200,
        false,
        Some(&passive_cfg(None)),
    );
    let ps = passive_state(&checker, "proxy-a");

    // Ticks: host3 earliest (100), host1 and host2 tie at 200, host0 at 300.
    ps.unhealthy.insert(
        target_host_port_key(&targets[3]),
        ejection(100, &targets[3]),
    );
    ps.unhealthy.insert(
        target_host_port_key(&targets[1]),
        ejection(200, &targets[1]),
    );
    ps.unhealthy.insert(
        target_host_port_key(&targets[2]),
        ejection(200, &targets[2]),
    );
    ps.unhealthy.insert(
        target_host_port_key(&targets[0]),
        ejection(300, &targets[0]),
    );

    // 50% of 4 = at most 2 ejected → 2 re-admitted: host3 (earliest), then
    // host1 (tie at 200 broken by lower index).
    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(Arc::clone(&ps)),
        max_ejection_percent: Some(50),
    };
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[1, 3])
    );

    // Without a cap, everything is ejected → degraded fallback to the full
    // pool (selection never black-holes).
    let ctx_no_cap = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(Arc::clone(&ps)),
        max_ejection_percent: None,
    };
    let sel = lb
        .select("", Some(&ctx_no_cap))
        .expect("fallback selection");
    assert!(sel.is_fallback);

    // An active ejection is never cap-readmitted and does not count toward
    // the passive cap: eject host3 actively and the 3 remaining passive
    // ejections (cap 2) re-admit exactly one — host1 (tick 200, lowest index).
    active.insert(target_key(UPSTREAM_KEY, &targets[3]), 1);
    assert_eq!(selected_hosts(&lb, Some(&ctx), 16), hosts(&targets, &[1]));

    // Recovering the earliest passive ejection moves the cap window.
    active.clear();
    ps.unhealthy.remove(&target_host_port_key(&targets[3]));
    // 3 ejected of 4 at 50% → 1 re-admitted: host1 (200, lowest index).
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 16),
        hosts(&targets, &[1, 3])
    );
}

#[test]
fn duplicate_host_port_targets_are_both_ejected_by_one_passive_entry() {
    // Two entries share 10.0.0.1:8080 (different weights); a passive
    // ejection of that host:port must remove both indices.
    let mut targets = vec![
        target("10.0.0.0", 8080),
        target("10.0.0.1", 8080),
        target("10.0.0.1", 8080),
    ];
    targets[2].weight = 3;
    let lb = LoadBalancer::new(
        UPSTREAM_KEY,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );
    let checker = HealthChecker::new();
    let active = ActiveUnhealthyTargets::new();
    let cfg = passive_cfg(None);
    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[1],
        503,
        false,
        Some(&cfg),
    );
    let ps = passive_state(&checker, "proxy-a");
    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(Arc::clone(&ps)),
        max_ejection_percent: None,
    };
    for _ in 0..32 {
        let sel = lb.select("", Some(&ctx)).expect("selection");
        assert_eq!(sel.target.host, "10.0.0.0");
        assert!(!sel.is_fallback);
    }
    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[1],
        200,
        false,
        Some(&cfg),
    );
    assert_eq!(
        selected_hosts(&lb, Some(&ctx), 32),
        hosts(&targets, &[0, 1])
    );
}

#[test]
fn vec_path_above_bitset_limit_honors_active_passive_and_cap() {
    let targets = make_targets(200);
    let lb = balancer(&targets);
    let checker = HealthChecker::new();
    let active = ActiveUnhealthyTargets::new();
    checker.report_response(
        NS,
        "proxy-a",
        UPSTREAM_KEY,
        &targets[0],
        200,
        false,
        Some(&passive_cfg(None)),
    );
    let ps = passive_state(&checker, "proxy-a");
    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(Arc::clone(&ps)),
        max_ejection_percent: None,
    };
    let all: BTreeSet<String> = targets.iter().map(|t| t.host.clone()).collect();
    assert_eq!(selected_hosts(&lb, Some(&ctx), 2_000), all);

    // Active ejection of a high index (beyond 128) and a low one.
    active.insert(target_key(UPSTREAM_KEY, &targets[150]), 1);
    active.insert(target_key(UPSTREAM_KEY, &targets[3]), 1);
    let seen = selected_hosts(&lb, Some(&ctx), 2_000);
    assert!(!seen.contains(&targets[150].host) && !seen.contains(&targets[3].host));
    assert_eq!(seen.len(), 198);

    // Passive ejections of three targets (ticks 10, 20, 30) on top.
    ps.unhealthy.insert(
        target_host_port_key(&targets[199]),
        ejection(30, &targets[199]),
    );
    ps.unhealthy.insert(
        target_host_port_key(&targets[64]),
        ejection(10, &targets[64]),
    );
    ps.unhealthy.insert(
        target_host_port_key(&targets[130]),
        ejection(20, &targets[130]),
    );
    let seen = selected_hosts(&lb, Some(&ctx), 2_000);
    assert_eq!(seen.len(), 195);
    for idx in [3, 64, 130, 150, 199] {
        assert!(
            !seen.contains(&targets[idx].host),
            "target {idx} should be ejected"
        );
    }

    // Cap of 1% over 200 targets → floor((200*2-1)/100) = 3 may stay
    // ejected; 3 passive ejected → none re-admitted.
    let ctx_cap1 = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(Arc::clone(&ps)),
        max_ejection_percent: Some(1),
    };
    assert_eq!(selected_hosts(&lb, Some(&ctx_cap1), 2_000).len(), 195);

    // Cap of 0% → floor((200*1-1)/100) = 1 may stay ejected → the two
    // earliest passive ejections (64 @10, 130 @20) are re-admitted, 199 @30
    // stays out, and the active ejections stay out regardless.
    let ctx_cap0 = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(Arc::clone(&ps)),
        max_ejection_percent: Some(0),
    };
    let seen = selected_hosts(&lb, Some(&ctx_cap0), 2_000);
    assert_eq!(seen.len(), 197);
    for idx in [64, 130] {
        assert!(
            seen.contains(&targets[idx].host),
            "target {idx} should be re-admitted"
        );
    }
    for idx in [3, 150, 199] {
        assert!(
            !seen.contains(&targets[idx].host),
            "target {idx} should stay ejected"
        );
    }

    // Recovery on the Vec path.
    ps.unhealthy.clear();
    active.clear();
    assert_eq!(selected_hosts(&lb, Some(&ctx), 2_000), all);
}

#[test]
fn passive_projection_table_evicts_beyond_cap_without_losing_correctness() {
    // More proxies than the per-balancer projection table holds (32): every
    // proxy must still see exactly its own ejections, evicted or not.
    let targets = make_targets(4);
    let lb = balancer(&targets);
    let checker = HealthChecker::new();
    let active = ActiveUnhealthyTargets::new();
    let cfg = passive_cfg(None);
    let proxies: Vec<String> = (0..40).map(|i| format!("proxy-{i}")).collect();
    let mut states = Vec::new();
    for (i, proxy) in proxies.iter().enumerate() {
        // Proxy i ejects target i % 4.
        checker.report_response(
            NS,
            proxy,
            UPSTREAM_KEY,
            &targets[i % 4],
            503,
            false,
            Some(&cfg),
        );
        states.push(passive_state(&checker, proxy));
    }
    for round in 0..3 {
        for (i, ps) in states.iter().enumerate() {
            let ctx = HealthContext {
                active_unhealthy: &active,
                proxy_passive: Some(Arc::clone(ps)),
                max_ejection_percent: None,
            };
            let expected: BTreeSet<String> = (0..4)
                .filter(|&t| t != i % 4)
                .map(|t| targets[t].host.clone())
                .collect();
            assert_eq!(
                selected_hosts(&lb, Some(&ctx), 16),
                expected,
                "round {round} proxy {i}"
            );
        }
    }
}

#[test]
fn active_unhealthy_targets_publish_generation_only_on_change() {
    let active = ActiveUnhealthyTargets::new();
    let g0 = active.generation();

    assert_eq!(active.insert("a".into(), 1), None);
    let g1 = active.generation();
    assert!(g1 > g0);

    // Removing an absent key is not a mutation.
    assert!(active.remove("missing").is_none());
    assert_eq!(active.generation(), g1);
    assert!(active.remove_if("a", |_, _| false).is_none());
    assert_eq!(active.generation(), g1);

    // Vacant insert publishes; occupied / declined do not.
    assert_eq!(
        active.insert_if_vacant("a".into(), || Some(2)),
        VacantInsert::Occupied
    );
    assert_eq!(active.generation(), g1);
    assert_eq!(
        active.insert_if_vacant("b".into(), || None),
        VacantInsert::Declined
    );
    assert_eq!(active.generation(), g1);
    assert!(!active.contains_key("b"));
    assert_eq!(
        active.insert_if_vacant("b".into(), || Some(3)),
        VacantInsert::Inserted
    );
    let g2 = active.generation();
    assert!(g2 > g1);
    assert_eq!(active.get("b").map(|v| *v), Some(3));

    // Retain that keeps everything is not a mutation; one that drops is.
    active.retain(|_, _| true);
    assert_eq!(active.generation(), g2);
    active.retain(|key, _| key == "a");
    assert!(active.generation() > g2);
    assert_eq!(active.len(), 1);
    assert!(active.iter().all(|entry| entry.key() == "a"));
}

#[test]
fn passive_unhealthy_targets_keep_len_and_generation_in_sync() {
    let targets = make_targets(3);
    let passive = PassiveUnhealthyTargets::new();
    assert!(passive.is_empty());
    let g0 = passive.generation();

    let k0 = target_host_port_key(&targets[0]);
    let k1 = target_host_port_key(&targets[1]);
    let k2 = target_host_port_key(&targets[2]);

    assert!(
        passive
            .insert(k0.clone(), ejection(1, &targets[0]))
            .is_none()
    );
    assert_eq!(passive.len(), 1);
    let g1 = passive.generation();
    assert!(g1 > g0);

    // Replacing an existing key changes contents but not the count.
    assert!(
        passive
            .insert(k0.clone(), ejection(2, &targets[0]))
            .is_some()
    );
    assert_eq!(passive.len(), 1);
    assert!(passive.generation() > g1);

    // insert_if: declined leaves everything untouched.
    let g2 = passive.generation();
    assert!(
        !passive.insert_if(k1.clone(), ejection(3, &targets[1]), |existing| {
            assert!(existing.is_none());
            false
        })
    );
    assert_eq!(passive.len(), 1);
    assert_eq!(passive.generation(), g2);
    assert!(passive.insert_if(k1.clone(), ejection(3, &targets[1]), |_| true));
    assert_eq!(passive.len(), 2);
    assert!(passive.generation() > g2);
    // insert_if replace on an occupied key: count unchanged, published.
    let g3 = passive.generation();
    assert!(
        passive.insert_if(k1.clone(), ejection(4, &targets[1]), |existing| {
            existing.is_some_and(|e| e.ejected_at_tick_ms == 3)
        })
    );
    assert_eq!(passive.len(), 2);
    assert!(passive.generation() > g3);

    // remove_if that declines: no change. Then a real removal.
    let g4 = passive.generation();
    assert!(passive.remove_if(&k1, |_, _| false).is_none());
    assert_eq!(passive.len(), 2);
    assert_eq!(passive.generation(), g4);
    assert!(
        passive
            .remove_if(&k1, |_, e| e.ejected_at_tick_ms == 4)
            .is_some()
    );
    assert_eq!(passive.len(), 1);
    assert!(passive.generation() > g4);

    // retain / clear.
    passive.insert(k2.clone(), ejection(5, &targets[2]));
    assert_eq!(passive.len(), 2);
    let g5 = passive.generation();
    passive.retain(|_, _| true);
    assert_eq!(passive.generation(), g5);
    passive.retain(|key, _| *key == k2);
    assert_eq!(passive.len(), 1);
    assert!(passive.contains_key(&k2) && !passive.contains_key(&k0));
    passive.clear();
    assert!(passive.is_empty());
    assert_eq!(passive.iter().count(), 0);
}
