use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, LocalityDistribute, LocalityFailover, SubsetDefinition,
    Upstream, UpstreamLocalityLbSetting, UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::load_balancer::{HealthContext, LoadBalancerCache, target_key};

fn target(host: &str, locality: Option<&str>) -> UpstreamTarget {
    target_on_port(host, 8080, locality)
}

fn target_on_port(host: &str, port: u16, locality: Option<&str>) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: locality.map(str::to_string),
        path: None,
    }
}

fn weighted_target(host: &str, locality: Option<&str>, weight: u32) -> UpstreamTarget {
    let mut target = target(host, locality);
    target.weight = weight;
    target
}

fn tagged_target(
    host: &str,
    port: u16,
    locality: Option<&str>,
    tag: (&str, &str),
) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::from([(tag.0.to_string(), tag.1.to_string())]),
        locality: locality.map(str::to_string),
        path: None,
    }
}

fn make_upstream(
    id: &str,
    algorithm: LoadBalancerAlgorithm,
    source_locality: Option<&str>,
    targets: Vec<UpstreamTarget>,
) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: id.to_string(),
        name: Some(id.to_string()),
        namespace: "ferrum".to_string(),
        targets,
        algorithm,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: source_locality.map(str::to_string),
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
    }
}

fn upstream(source_locality: &str, targets: Vec<UpstreamTarget>) -> Upstream {
    make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some(source_locality),
        targets,
    )
}

fn config(upstream: Upstream) -> GatewayConfig {
    GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    }
}

fn no_health() -> Option<&'static HealthContext<'static>> {
    None
}

#[test]
fn locality_priority_prefers_exact_tier() {
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![
            target("exact.local", Some("us-west/us-west-1/a")),
            target("same-zone.local", Some("us-west/us-west-1/b")),
            target("same-region.local", Some("us-west/us-west-2/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();

    for i in 0..8 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("ctx-{i}"),
            no_health(),
        )
        .expect("target selected");
        assert_eq!(selection.target.host, "exact.local");
        assert!(!selection.is_fallback);
    }
}

#[test]
fn locality_priority_falls_back_to_zone_when_exact_unhealthy() {
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            target("same-zone.local", Some("us-west/us-west-1/b")),
            target("same-region.local", Some("us-west/us-west-2/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &exact), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection =
        LoadBalancerCache::select_target_from(&snapshot, "ferrum", "u1", "ctx", Some(&health))
            .expect("target selected");

    assert_eq!(selection.target.host, "same-zone.local");
    assert!(!selection.is_fallback);
}

#[test]
fn locality_priority_falls_back_to_region_when_zone_unavailable() {
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let zone = target("same-zone.local", Some("us-west/us-west-1/b"));
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            zone.clone(),
            target("same-region.local", Some("us-west/us-west-2/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &exact), 1);
    active_unhealthy.insert(target_key("ferrum|u1", &zone), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection =
        LoadBalancerCache::select_target_from(&snapshot, "ferrum", "u1", "ctx", Some(&health))
            .expect("target selected");

    assert_eq!(selection.target.host, "same-region.local");
    assert!(!selection.is_fallback);
}

#[test]
fn locality_priority_falls_back_to_any_when_all_preferred_tiers_unhealthy() {
    // exact, zone, and region are all unhealthy; only the rank-3 "other"
    // target remains. Selection must still succeed — the locality filter
    // must not strand the upstream when no preferred-tier target survives.
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let zone = target("same-zone.local", Some("us-west/us-west-1/b"));
    let region = target("same-region.local", Some("us-west/us-west-2/a"));
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            zone.clone(),
            region.clone(),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &exact), 1);
    active_unhealthy.insert(target_key("ferrum|u1", &zone), 1);
    active_unhealthy.insert(target_key("ferrum|u1", &region), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection =
        LoadBalancerCache::select_target_from(&snapshot, "ferrum", "u1", "ctx", Some(&health))
            .expect("target selected");
    assert_eq!(selection.target.host, "other.local");
    assert!(!selection.is_fallback);
}

#[test]
fn locality_priority_targets_without_locality_treated_as_no_preference() {
    // Mix targets that have locality with one that has none. With a healthy
    // exact-tier target available, the unannotated target is rank-3 and
    // must not be chosen. Removing the exact target lets the rank-3 target
    // share the residual pool (the function returns the original candidates
    // when no rank-0/1/2 candidates remain).
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let unannotated = target("unannotated.local", None);
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![exact.clone(), unannotated.clone()],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();

    for i in 0..8 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("a-{i}"),
            no_health(),
        )
        .expect("target selected");
        assert_eq!(
            selection.target.host, "exact.local",
            "exact-tier target must always win when healthy"
        );
    }

    // Knock the exact target out — unannotated should now be reachable as
    // the residual fallback (no rank 0/1/2 candidates left).
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &exact), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };
    let selection =
        LoadBalancerCache::select_target_from(&snapshot, "ferrum", "u1", "fb", Some(&health))
            .expect("target selected");
    assert_eq!(selection.target.host, "unannotated.local");
}

#[test]
fn locality_priority_applies_inside_subset_selection() {
    let exact = tagged_target("exact.local", 8080, Some("us-west/us-west-1/a"), ("v", "1"));
    let region = tagged_target(
        "same-region.local",
        8080,
        Some("us-west/us-west-2/a"),
        ("v", "1"),
    );
    let other = tagged_target(
        "other.local",
        8080,
        Some("eu-central/eu-central-1/a"),
        ("v", "1"),
    );
    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some("us-west/us-west-1/a"),
        vec![exact.clone(), region, other],
    );
    up.subsets = Some(vec![SubsetDefinition {
        name: "v1".into(),
        labels: HashMap::from([("v".to_string(), "1".to_string())]),
        traffic_policy: None,
    }]);

    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..6 {
        let selection = LoadBalancerCache::select_target_subset_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("k-{i}"),
            "v1",
            no_health(),
        )
        .expect("subset selection");
        assert_eq!(selection.target.host, "exact.local");
    }
}

#[test]
fn locality_priority_applies_inside_port_override_selection() {
    let exact = target_on_port("exact.local", 8080, Some("us-west/us-west-1/a"));
    let region = target_on_port("region.local", 8080, Some("us-west/us-west-2/a"));
    let mut port_overrides = HashMap::new();
    port_overrides.insert(8080, UpstreamPortOverride::default());

    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some("us-west/us-west-1/a"),
        vec![exact, region],
    );
    up.port_overrides = port_overrides;

    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..6 {
        let selection = LoadBalancerCache::select_target_for_port_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("p-{i}"),
            8080,
            no_health(),
        )
        .expect("port selection");
        assert_eq!(selection.target.host, "exact.local");
    }
}

#[test]
fn locality_priority_applies_to_port_subset_selection() {
    let exact = tagged_target("exact.local", 8080, Some("us-west/us-west-1/a"), ("v", "1"));
    let region = tagged_target(
        "region.local",
        8080,
        Some("us-west/us-west-2/a"),
        ("v", "1"),
    );
    let mut port_overrides = HashMap::new();
    port_overrides.insert(8080, UpstreamPortOverride::default());

    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some("us-west/us-west-1/a"),
        vec![exact.clone(), region],
    );
    up.subsets = Some(vec![SubsetDefinition {
        name: "v1".into(),
        labels: HashMap::from([("v".to_string(), "1".to_string())]),
        traffic_policy: None,
    }]);
    up.port_overrides = port_overrides;

    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..6 {
        let selection = LoadBalancerCache::select_target_for_port_subset_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("ps-{i}"),
            8080,
            "v1",
            no_health(),
        )
        .expect("port+subset selection");
        assert_eq!(selection.target.host, "exact.local");
    }
}

#[test]
fn locality_priority_applies_when_excluding_a_target() {
    // First select picks exact; retry path excludes exact and must fall
    // through to the next-best tier (zone), not jump to a rank-3 target.
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let zone = target("zone.local", Some("us-west/us-west-1/b"));
    let other = target("other.local", Some("eu-central/eu-central-1/a"));
    let up = upstream(
        "us-west/us-west-1/a",
        vec![exact.clone(), zone.clone(), other.clone()],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let next = LoadBalancerCache::select_next_target_from(
        &snapshot,
        "ferrum",
        "u1",
        "rk",
        &exact,
        no_health(),
    )
    .expect("retry selected");
    assert_eq!(
        next.host, "zone.local",
        "after excluding exact, locality preference must still skip the rank-3 target"
    );
}

#[test]
fn locality_priority_works_with_consistent_hashing() {
    // Same hash key must produce a stable selection inside the preferred
    // tier. Two healthy exact-tier targets — the hash-bound choice must be
    // reproducible across calls and never escape into the rank-2 tier.
    let exact_a = target("ex-a.local", Some("us-west/us-west-1/a"));
    let exact_b = target("ex-b.local", Some("us-west/us-west-1/a"));
    let region = target("region.local", Some("us-west/us-west-2/a"));
    let up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::ConsistentHashing,
        Some("us-west/us-west-1/a"),
        vec![exact_a, exact_b, region],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let preferred: HashSet<&str> = ["ex-a.local", "ex-b.local"].into_iter().collect();
    let first =
        LoadBalancerCache::select_target_from(&snapshot, "ferrum", "u1", "hash-key", no_health())
            .expect("hash selection");
    assert!(preferred.contains(first.target.host.as_str()));
    for _ in 0..5 {
        let again = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            "hash-key",
            no_health(),
        )
        .expect("hash selection");
        assert_eq!(
            again.target.host, first.target.host,
            "consistent hash must return the same target for the same key"
        );
    }
}

#[test]
fn locality_priority_vec_fallback_path_picks_preferred_tier_above_128_targets() {
    // Force the >128 Vec fallback path: 160 targets, half exact-tier, half
    // rank-3. After 32 rounds, every selection must come from the exact
    // tier (host name starts with "exact-").
    let mut targets = Vec::with_capacity(160);
    for i in 0..80 {
        targets.push(target(
            &format!("exact-{i}.local"),
            Some("us-west/us-west-1/a"),
        ));
    }
    for i in 0..80 {
        targets.push(target(
            &format!("other-{i}.local"),
            Some("eu-central/eu-central-1/a"),
        ));
    }
    let up = upstream("us-west/us-west-1/a", targets);
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..32 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("k-{i}"),
            no_health(),
        )
        .expect("vec-fallback selection");
        assert!(
            selection.target.host.starts_with("exact-"),
            "Vec fallback selected non-preferred target {}",
            selection.target.host
        );
        assert!(!selection.is_fallback);
    }
}

#[test]
fn locality_priority_bitset_and_vec_paths_agree_on_preferred_set() {
    // Run the same logical upstream through both representations: a small
    // upstream (n=4, bitset path) and a large one synthesised from the same
    // template (n=200, Vec path). For round-robin selection on a healthy
    // set, every chosen target must come from the exact tier in both
    // representations.
    let small = upstream(
        "us-west/us-west-1/a",
        vec![
            target("ex-1.local", Some("us-west/us-west-1/a")),
            target("ex-2.local", Some("us-west/us-west-1/a")),
            target("zone.local", Some("us-west/us-west-1/b")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let mut big_targets = Vec::with_capacity(200);
    for i in 0..50 {
        big_targets.push(target(
            &format!("ex-{i}.local"),
            Some("us-west/us-west-1/a"),
        ));
    }
    for i in 0..50 {
        big_targets.push(target(
            &format!("zone-{i}.local"),
            Some("us-west/us-west-1/b"),
        ));
    }
    for i in 0..100 {
        big_targets.push(target(
            &format!("other-{i}.local"),
            Some("eu-central/eu-central-1/a"),
        ));
    }
    let big = upstream("us-west/us-west-1/a", big_targets);

    let small_cache = LoadBalancerCache::new(&config(small));
    let big_cache = LoadBalancerCache::new(&config(big));
    let small_snapshot = small_cache.load();
    let big_snapshot = big_cache.load();

    for i in 0..50 {
        let small_sel = LoadBalancerCache::select_target_from(
            &small_snapshot,
            "ferrum",
            "u1",
            &format!("p-{i}"),
            no_health(),
        )
        .expect("bitset selection");
        let big_sel = LoadBalancerCache::select_target_from(
            &big_snapshot,
            "ferrum",
            "u1",
            &format!("p-{i}"),
            no_health(),
        )
        .expect("vec selection");
        assert!(
            small_sel.target.host.starts_with("ex"),
            "bitset path selected non-preferred target: {}",
            small_sel.target.host
        );
        assert!(
            big_sel.target.host.starts_with("ex-"),
            "vec path selected non-preferred target: {}",
            big_sel.target.host
        );
    }
}

#[test]
fn locality_priority_disabled_when_source_locality_absent() {
    // No source locality means every target is rank-3 (no preference) and
    // round-robin distributes evenly across all healthy targets.
    let up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        None,
        vec![
            target("a.local", Some("us-west/us-west-1/a")),
            target("b.local", Some("us-west/us-west-1/b")),
            target("c.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let mut seen: HashSet<String> = HashSet::new();
    for i in 0..30 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("k-{i}"),
            no_health(),
        )
        .expect("selected");
        seen.insert(selection.target.host.clone());
    }
    assert_eq!(
        seen.len(),
        3,
        "without source locality, round-robin must visit every target — saw {:?}",
        seen
    );
}

// ── FERRUM_MESH_LOCALITY_LB_STRICT (strict local-first) ───────────────────

/// Explicit per-target remote-provenance marker (matches
/// `multicluster::MESH_REMOTE_TAG`). Strict local-first LB keys local vs.
/// remote on the PRESENCE of this tag — stamped at materialization from the
/// workload's cross-cluster identity — NOT on the locality string. Tests use
/// this helper so they exercise the real signal rather than a locality prefix.
fn remote_target(host: &str, locality: Option<&str>) -> UpstreamTarget {
    tagged_target(host, 8080, locality, ("mesh.remote", "true"))
}

/// Build an upstream with `locality_lb_strict` set and (optionally) no source
/// locality, mirroring how `project_mesh_source_locality` stamps the flag at
/// slice apply. Remote endpoints carry the explicit `mesh.remote` tag
/// ([`remote_target`]); local ones do not.
fn strict_upstream(source_locality: Option<&str>, targets: Vec<UpstreamTarget>) -> Upstream {
    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        source_locality,
        targets,
    );
    up.locality_lb_strict = true;
    up
}

fn seen_hosts(snapshot: &ferrum_edge::load_balancer::LoadBalancerCacheInner) -> HashSet<String> {
    let mut seen: HashSet<String> = HashSet::new();
    for i in 0..40 {
        let selection = LoadBalancerCache::select_target_from(
            snapshot,
            "ferrum",
            "u1",
            &format!("k-{i}"),
            no_health(),
        )
        .expect("selected");
        seen.insert(selection.target.host.clone());
    }
    seen
}

#[test]
fn strict_locality_absent_source_selects_only_local_endpoints() {
    // Absent source locality + strict ON: selection must restrict to LOCAL
    // endpoints (no `mesh.remote` tag) and NEVER pick the remote-cluster
    // targets, even though every target is healthy.
    let up = strict_upstream(
        None,
        vec![
            target("local-a.local", Some("us-west/us-west-1/a")),
            target("local-b.local", Some("us-west/us-west-1/b")),
            remote_target("remote-a.local", Some("remote-cluster-east")),
            remote_target("remote-b.local", Some("remote-cluster-east/net2")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let seen = seen_hosts(&snapshot);
    assert!(
        seen.contains("local-a.local") && seen.contains("local-b.local"),
        "strict mode must keep serving local endpoints — saw {seen:?}"
    );
    assert!(
        !seen.contains("remote-a.local") && !seen.contains("remote-b.local"),
        "strict mode must NOT widen to remote endpoints when locals exist — saw {seen:?}"
    );
}

#[test]
fn strict_locality_local_region_named_remote_stays_local() {
    // Regression guard for the codex finding: remote provenance must NOT be
    // inferred from a `remote-` locality prefix. A real local Kubernetes region
    // literally named `remote-us` (carrying NO `mesh.remote` tag) must remain a
    // LOCAL endpoint under strict mode and keep receiving traffic — while a
    // genuinely remote-cluster target (with the tag) is excluded.
    let up = strict_upstream(
        None,
        vec![
            // Local workload whose region happens to be named "remote-us".
            target("local-region-remote-us.local", Some("remote-us/zone-a")),
            // Actually remote-cluster-discovered endpoint.
            remote_target("really-remote.local", Some("remote-cluster-east")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let seen = seen_hosts(&snapshot);
    assert!(
        seen.contains("local-region-remote-us.local"),
        "a local region named `remote-us` must stay LOCAL (provenance is the \
         mesh.remote tag, not the locality prefix) — saw {seen:?}"
    );
    assert!(
        !seen.contains("really-remote.local"),
        "the tagged remote-cluster target must be excluded while a local exists — saw {seen:?}"
    );
}

#[test]
fn strict_locality_absent_source_treats_unlabeled_targets_as_local() {
    // A target with NO `mesh.remote` tag is treated as local (not remote): it
    // must remain eligible under strict mode while tagged remote targets are
    // excluded.
    let up = strict_upstream(
        None,
        vec![
            target("unlabeled.local", None),
            remote_target("remote-only.local", Some("remote-cluster-east")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let seen = seen_hosts(&snapshot);
    assert!(
        seen.contains("unlabeled.local"),
        "unlabeled target must count as local under strict mode — saw {seen:?}"
    );
    assert!(
        !seen.contains("remote-only.local"),
        "remote target must be excluded while a local exists — saw {seen:?}"
    );
}

#[test]
fn non_strict_absent_source_returns_mixed_local_and_remote() {
    // Default (strict OFF): absent source locality must keep today's fail-open
    // behavior and visit BOTH local and remote endpoints. Same target set as
    // the strict test above, only the flag differs.
    let up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        None,
        vec![
            target("local-a.local", Some("us-west/us-west-1/a")),
            target("local-b.local", Some("us-west/us-west-1/b")),
            remote_target("remote-a.local", Some("remote-cluster-east")),
            remote_target("remote-b.local", Some("remote-cluster-east/net2")),
        ],
    );
    assert!(
        !up.locality_lb_strict,
        "default upstream must not be strict"
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let seen = seen_hosts(&snapshot);
    assert_eq!(
        seen.len(),
        4,
        "without strict mode, absent source locality must visit every target \
         (mixed local + remote) — saw {seen:?}"
    );
}

/// A CROSS-CLUSTER east-west GATEWAY target — carries BOTH the remote-provenance
/// tag (so it counts as remote) AND the `mesh.cross_cluster` marker, mirroring
/// `append_cross_cluster_mesh_targets`. Its presence forces local-first
/// selection regardless of the `locality_lb_strict` opt-in.
fn cross_cluster_target(host: &str, locality: Option<&str>) -> UpstreamTarget {
    let mut t = remote_target(host, locality);
    t.tags
        .insert("mesh.cross_cluster".to_string(), "true".to_string());
    t
}

#[test]
fn cross_cluster_gateway_target_is_local_first_without_strict_opt_in() {
    // [R4-2] No source locality + locality_lb_strict at its DEFAULT false: a
    // cross-cluster east-west GATEWAY target (mesh.cross_cluster=true) is
    // always-failover, so selection must restrict to healthy LOCAL endpoints and
    // NOT round-robin onto the remote gateway — UNLIKE a plain `mesh.remote`
    // target (see `non_strict_absent_source_returns_mixed_local_and_remote`,
    // which stays mixed). This is the optional-locality default the M5 east-west
    // datapath must get right.
    let up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        None,
        vec![
            target("local-a.local", Some("us-west/us-west-1/a")),
            target("local-b.local", Some("us-west/us-west-1/b")),
            cross_cluster_target("eastwest-gw.local", Some("remote-cluster-east")),
        ],
    );
    assert!(
        !up.locality_lb_strict,
        "test premise: locality_lb_strict stays at its default false"
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let seen = seen_hosts(&snapshot);
    assert!(
        seen.contains("local-a.local") && seen.contains("local-b.local"),
        "local endpoints must keep serving — saw {seen:?}"
    );
    assert!(
        !seen.contains("eastwest-gw.local"),
        "the cross-cluster gateway target must NOT be selected while local endpoints are healthy, \
         even with locality_lb_strict at its default false — saw {seen:?}"
    );
}

#[test]
fn cross_cluster_gateway_target_serves_when_no_local_endpoint() {
    // A service that exists ONLY remotely (no local endpoint): local-first must
    // WIDEN to the cross-cluster gateway rather than black-holing.
    let up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        None,
        vec![cross_cluster_target(
            "eastwest-gw.local",
            Some("remote-cluster-east"),
        )],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let seen = seen_hosts(&snapshot);
    assert!(
        seen.contains("eastwest-gw.local"),
        "with no local endpoint, selection must widen to the cross-cluster gateway — saw {seen:?}"
    );
}

#[test]
fn cross_cluster_unhealthy_local_fails_over_to_healthy_gateway() {
    // [R5-2] No source locality, locality_lb_strict OFF: when the LOCAL endpoint
    // is unhealthy (health-checked down) and the cross-cluster gateway is
    // healthy, selection must fail OVER to the healthy gateway — NOT fail closed
    // to the unhealthy local (the strict-mode contract, which is the OPPOSITE of
    // what a deliberate failover target wants).
    let local = target("local-a.local", Some("us-west/us-west-1/a"));
    let up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        None,
        vec![
            local.clone(),
            cross_cluster_target("eastwest-gw.local", Some("remote-cluster-east")),
        ],
    );
    assert!(!up.locality_lb_strict, "test premise: strict stays off");
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &local), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    for i in 0..8 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("xc-failover-{i}"),
            Some(&health),
        )
        .expect("failover selected");
        assert_eq!(
            selection.target.host, "eastwest-gw.local",
            "unhealthy local must fail OVER to the healthy cross-cluster gateway, not fail closed"
        );
    }
}

#[test]
fn cross_cluster_local_first_when_source_locality_present_but_locals_unlabeled() {
    // [R6-1] Source HAS a locality but the LOCAL endpoints carry no locality
    // metadata: every ranked tier misses, so without the cross-cluster pre-filter
    // selection would fall through to the mixed pool and round-robin onto the
    // gateway. The pre-filter keeps it local-first.
    let up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some("us-west/us-west-1/a"),
        vec![
            target("local-a.local", None),
            target("local-b.local", None),
            cross_cluster_target("eastwest-gw.local", Some("remote-cluster-east")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let seen = seen_hosts(&snapshot);
    assert!(
        seen.contains("local-a.local") && seen.contains("local-b.local"),
        "unlabeled local endpoints must keep serving — saw {seen:?}"
    );
    assert!(
        !seen.contains("eastwest-gw.local"),
        "cross-cluster gateway must not round-robin with healthy locals even when ranked tiers \
         miss (source locality present, locals unlabeled) — saw {seen:?}"
    );
}

#[test]
fn cross_cluster_local_first_when_locality_lb_disabled() {
    // [R6-2] `localityLbSetting.enabled=false` short-circuits the tier logic; the
    // cross-cluster failover pre-filter runs BEFORE that short-circuit, so the
    // gateway stays failover-only behind healthy locals.
    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        None,
        vec![
            target("local-a.local", Some("us-west/us-west-1/a")),
            target("local-b.local", Some("us-west/us-west-1/b")),
            cross_cluster_target("eastwest-gw.local", Some("remote-cluster-east")),
        ],
    );
    up.locality_lb_setting = Some(UpstreamLocalityLbSetting {
        enabled: false,
        distribute: Vec::new(),
        failover: Vec::new(),
    });
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let seen = seen_hosts(&snapshot);
    assert!(
        seen.contains("local-a.local") && seen.contains("local-b.local"),
        "local endpoints must keep serving with locality LB disabled — saw {seen:?}"
    );
    assert!(
        !seen.contains("eastwest-gw.local"),
        "cross-cluster gateway must stay failover-only even when localityLbSetting.enabled=false \
         — saw {seen:?}"
    );
}

#[test]
fn strict_locality_present_source_unchanged_priority_tier() {
    // With a resolved source locality, strict mode is inert: priority-tier
    // preference still picks the exact-match local target and ignores the flag.
    let up = strict_upstream(
        Some("us-west/us-west-1/a"),
        vec![
            target("exact.local", Some("us-west/us-west-1/a")),
            target("same-zone.local", Some("us-west/us-west-1/b")),
            remote_target("remote.local", Some("remote-cluster-east")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..8 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("c-{i}"),
            no_health(),
        )
        .expect("selected");
        assert_eq!(
            selection.target.host, "exact.local",
            "present source locality must keep exact-tier preference under strict mode"
        );
    }
}

#[test]
fn strict_locality_absent_source_falls_back_to_unhealthy_local_not_remote() {
    // Strict mode is a fail-closed-to-local control: if configured local
    // endpoints are currently unhealthy/ejected while remote endpoints remain
    // healthy, selection may use a local fallback but must not widen to remote.
    let local = target("local-a.local", Some("us-west/us-west-1/a"));
    let up = strict_upstream(
        None,
        vec![
            local.clone(),
            remote_target("remote-a.local", Some("remote-cluster-east")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &local), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    for i in 0..8 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("strict-local-fallback-{i}"),
            Some(&health),
        )
        .expect("local fallback selected");
        assert_eq!(selection.target.host, "local-a.local");
        assert!(
            selection.is_fallback,
            "selecting an unhealthy local instead of a healthy remote must be marked as fallback"
        );
    }
}

#[test]
fn strict_locality_vec_path_falls_back_to_unhealthy_local_not_remote() {
    // Same regression guard for the >128-target Vec fallback path.
    let mut targets = Vec::with_capacity(130);
    let mut locals = Vec::new();
    for i in 0..2 {
        let local = target(&format!("local-{i}.local"), Some("us-west/us-west-1/a"));
        locals.push(local.clone());
        targets.push(local);
    }
    for i in 0..128 {
        targets.push(remote_target(
            &format!("remote-{i}.local"),
            Some("remote-cluster-east"),
        ));
    }
    let up = strict_upstream(None, targets);
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    for local in &locals {
        active_unhealthy.insert(target_key("ferrum|u1", local), 1);
    }
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let mut seen = HashSet::new();
    for i in 0..8 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("strict-local-vec-fallback-{i}"),
            Some(&health),
        )
        .expect("local fallback selected");
        assert!(selection.target.host.starts_with("local-"));
        assert!(selection.is_fallback);
        seen.insert(selection.target.host.clone());
    }
    assert!(
        seen.iter().all(|host| host.starts_with("local-")),
        "strict Vec fallback must not widen to remote endpoints — saw {seen:?}"
    );
}

#[test]
fn strict_locality_no_local_endpoints_falls_back_to_full_pool() {
    // Strict ON, absent source locality, and EVERY target is remote (tagged):
    // rather than black-holing, selection must widen to the full healthy pool so
    // traffic still flows.
    let up = strict_upstream(
        None,
        vec![
            remote_target("remote-a.local", Some("remote-cluster-east")),
            remote_target("remote-b.local", Some("remote-cluster-west")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let seen = seen_hosts(&snapshot);
    assert_eq!(
        seen.len(),
        2,
        "with no local endpoints, strict mode must widen to the full pool — saw {seen:?}"
    );
}

#[test]
fn strict_locality_port_scope_falls_back_to_unhealthy_local_not_remote() {
    // Port-scoped regression guard: a per-port lane whose local endpoint is
    // unhealthy while a remote endpoint on the same port is healthy must fail
    // closed to the unhealthy local (marked fallback), not widen to remote.
    let local = target("local-a.local", Some("us-west/us-west-1/a"));
    let mut port_overrides = HashMap::new();
    port_overrides.insert(8080, UpstreamPortOverride::default());
    let mut up = strict_upstream(
        None,
        vec![
            local.clone(),
            remote_target("remote-a.local", Some("remote-cluster-east")),
        ],
    );
    up.port_overrides = port_overrides;
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &local), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    for i in 0..8 {
        let selection = LoadBalancerCache::select_target_for_port_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("strict-port-fallback-{i}"),
            8080,
            Some(&health),
        )
        .expect("port-scoped local fallback selected");
        assert_eq!(selection.target.host, "local-a.local");
        assert!(
            selection.is_fallback,
            "port-scoped strict fail-closed to unhealthy local must be marked fallback"
        );
    }
}

#[test]
fn strict_locality_remote_only_port_scope_does_not_black_hole() {
    // Port-scoped regression guard for the inverse: a port lane that is
    // genuinely remote-only (no local endpoint on that port) must NOT black-hole
    // just because a local endpoint exists on a DIFFERENT port. Strict mode
    // widens within that remote-only scope so traffic still flows.
    let mut port_overrides = HashMap::new();
    // Port 9090 lane contains only the remote endpoint.
    port_overrides.insert(9090, UpstreamPortOverride::default());
    let mut up = strict_upstream(
        None,
        vec![
            // Local endpoint lives on a different port (8080), not in the lane.
            target_on_port("local-a.local", 8080, Some("us-west/us-west-1/a")),
            tagged_target(
                "remote-a.local",
                9090,
                Some("remote-cluster-east"),
                ("mesh.remote", "true"),
            ),
        ],
    );
    up.port_overrides = port_overrides;
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..8 {
        let selection = LoadBalancerCache::select_target_for_port_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("strict-remote-only-port-{i}"),
            9090,
            no_health(),
        )
        .expect("remote-only port lane must not black-hole");
        assert_eq!(selection.target.host, "remote-a.local");
        assert!(
            !selection.is_fallback,
            "serving a healthy remote in a remote-only scope is normal, not a degraded fallback"
        );
    }
}

#[test]
fn strict_locality_subset_scope_falls_back_to_unhealthy_local_not_remote() {
    // Subset-scoped regression guard: a subset whose local member is unhealthy
    // while a remote member of the same subset is healthy must fail closed to
    // the unhealthy local member, not widen to the remote one.
    let local = tagged_target(
        "local-a.local",
        8080,
        Some("us-west/us-west-1/a"),
        ("v", "1"),
    );
    let mut remote = tagged_target(
        "remote-a.local",
        8080,
        Some("remote-cluster-east"),
        ("v", "1"),
    );
    // Carry BOTH the subset label and the remote provenance tag.
    remote
        .tags
        .insert("mesh.remote".to_string(), "true".to_string());
    let mut up = strict_upstream(None, vec![local.clone(), remote]);
    up.subsets = Some(vec![SubsetDefinition {
        name: "v1".into(),
        labels: HashMap::from([("v".to_string(), "1".to_string())]),
        traffic_policy: None,
    }]);
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &local), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    for i in 0..8 {
        let selection = LoadBalancerCache::select_target_subset_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("strict-subset-fallback-{i}"),
            "v1",
            Some(&health),
        )
        .expect("subset-scoped local fallback selected");
        assert_eq!(selection.target.host, "local-a.local");
        assert!(
            selection.is_fallback,
            "subset-scoped strict fail-closed to unhealthy local must be marked fallback"
        );
    }
}

#[test]
fn strict_locality_retry_excluding_only_local_fails_closed_not_remote() {
    let local = target("local-a.local", Some("us-west/us-west-1/a"));
    let up = strict_upstream(
        None,
        vec![
            local.clone(),
            remote_target("remote-a.local", Some("remote-cluster-east")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..8 {
        let next = LoadBalancerCache::select_next_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("strict-retry-{i}"),
            &local,
            no_health(),
        )
        .expect("strict retry should fail closed to local");
        assert_eq!(next.host, "local-a.local");
    }
}

#[test]
fn strict_locality_port_retry_excluding_only_local_fails_closed_not_remote() {
    let local = target("local-a.local", Some("us-west/us-west-1/a"));
    let mut port_overrides = HashMap::new();
    port_overrides.insert(8080, UpstreamPortOverride::default());
    let mut up = strict_upstream(
        None,
        vec![
            local.clone(),
            remote_target("remote-a.local", Some("remote-cluster-east")),
        ],
    );
    up.port_overrides = port_overrides;
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..8 {
        let next = LoadBalancerCache::select_next_target_for_port_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("strict-port-retry-{i}"),
            8080,
            &local,
            no_health(),
        )
        .expect("strict port retry should fail closed to local");
        assert_eq!(next.host, "local-a.local");
    }
}

#[test]
fn strict_locality_vec_retry_excluding_only_local_fails_closed_not_remote() {
    let local = target("local-a.local", Some("us-west/us-west-1/a"));
    let mut targets = Vec::with_capacity(130);
    targets.push(local.clone());
    for i in 0..129 {
        targets.push(remote_target(
            &format!("remote-{i}.local"),
            Some("remote-cluster-east"),
        ));
    }
    let up = strict_upstream(None, targets);
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..8 {
        let next = LoadBalancerCache::select_next_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("strict-vec-retry-{i}"),
            &local,
            no_health(),
        )
        .expect("strict Vec retry should fail closed to local");
        assert_eq!(next.host, "local-a.local");
    }
}

// ── localityLbSetting.distribute ──────────────────────────────────────────

fn upstream_with_locality_lb(
    source_locality: &str,
    targets: Vec<UpstreamTarget>,
    setting: UpstreamLocalityLbSetting,
) -> Upstream {
    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some(source_locality),
        targets,
    );
    up.locality_lb_setting = Some(setting);
    up
}

#[test]
fn locality_distribute_overrides_priority_tier_with_weights() {
    // Source is `us-west/us-west-1/a`; distribute sends 80% to `us-west`
    // and 20% to `us-east`. Even though the exact-tier target is healthy,
    // distribute MUST override the priority preference (Istio semantics —
    // distribute and priority are mutually exclusive).
    let mut to = BTreeMap::new();
    to.insert("us-west".to_string(), 80);
    to.insert("us-east".to_string(), 20);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west-a.local", Some("us-west/us-west-1/a")),
            target("west-b.local", Some("us-west/us-west-2/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let mut by_target: HashMap<String, u32> = HashMap::new();
    for i in 0..2000 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("d-{i}"),
            no_health(),
        )
        .expect("distribute selection");
        *by_target.entry(selection.target.host.clone()).or_default() += 1;
    }

    let west_a = by_target.get("west-a.local").copied().unwrap_or(0);
    let west_b = by_target.get("west-b.local").copied().unwrap_or(0);
    let east = by_target.get("east.local").copied().unwrap_or(0);
    let total = west_a + west_b + east;
    assert_eq!(total, 2000);

    // `us-west` is the 80% locality share, split across west-a and west-b;
    // `us-east` is the 20% locality share with one endpoint. Effective
    // endpoint ratios are therefore 0.4 / 0.4 / 0.2. Allow ±6% slack for
    // the golden-ratio PRNG.
    let west_a_ratio = f64::from(west_a) / f64::from(total);
    let west_b_ratio = f64::from(west_b) / f64::from(total);
    let east_ratio = f64::from(east) / f64::from(total);
    assert!(
        (west_a_ratio - 0.4).abs() < 0.06,
        "west-a ratio {west_a_ratio:.3} outside ±0.06 of 0.4"
    );
    assert!(
        (west_b_ratio - 0.4).abs() < 0.06,
        "west-b ratio {west_b_ratio:.3} outside ±0.06 of 0.4"
    );
    assert!(
        (east_ratio - 0.2).abs() < 0.04,
        "east ratio {east_ratio:.3} outside ±0.04 of 0.2"
    );
}

#[test]
fn locality_distribute_excludes_targets_with_zero_weight() {
    // distribute weights only `us-east`; the exact-tier `us-west` target
    // gets weight 0 and must NEVER be selected.
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..100 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("k-{i}"),
            no_health(),
        )
        .expect("distribute selection");
        assert_eq!(
            selection.target.host, "east.local",
            "distribute weight 0 for west.local must exclude it from selection"
        );
    }
}

#[test]
fn locality_distribute_treats_all_zero_endpoint_weight_locality_as_ineligible() {
    // The only endpoint in the weighted distribute locality is drained via
    // weight=0, so distribute must not synthesize a fallback share for it.
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            weighted_target("east-drained.local", Some("us-east/us-east-1/a"), 0),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..100 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("drained-{i}"),
            no_health(),
        )
        .expect("selection should fall through to healthy locality priority");
        assert_eq!(
            selection.target.host, "west.local",
            "drained distribute locality must not receive synthetic traffic"
        );
    }
}

#[test]
fn locality_distribute_preserves_endpoint_weights_within_locality_share() {
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::WeightedRoundRobin,
        Some("us-west/us-west-1/a"),
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            weighted_target("east-heavy.local", Some("us-east/us-east-1/a"), 9),
            weighted_target("east-light.local", Some("us-east/us-east-1/a"), 1),
        ],
    );
    up.locality_lb_setting = Some(setting);
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let mut by_target: HashMap<String, u32> = HashMap::new();
    for i in 0..2000 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("endpoint-weight-{i}"),
            no_health(),
        )
        .expect("weighted distribute selection");
        *by_target.entry(selection.target.host.clone()).or_default() += 1;
    }

    assert_eq!(by_target.get("west.local").copied().unwrap_or(0), 0);
    let heavy = by_target.get("east-heavy.local").copied().unwrap_or(0);
    let light = by_target.get("east-light.local").copied().unwrap_or(0);
    let total = heavy + light;
    assert_eq!(total, 2000);

    let heavy_ratio = f64::from(heavy) / f64::from(total);
    assert!(
        (heavy_ratio - 0.9).abs() < 0.04,
        "east-heavy ratio {heavy_ratio:.3} outside +/-0.04 of 0.9"
    );
}

#[test]
fn locality_distribute_assigns_overlapping_to_localities_once() {
    let mut to = BTreeMap::new();
    to.insert("us-west".to_string(), 50);
    to.insert("us-west/us-west-1".to_string(), 50);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-east/us-east-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-east/us-east-1/a",
        vec![
            target("west-zone-1.local", Some("us-west/us-west-1/a")),
            target("west-zone-2.local", Some("us-west/us-west-2/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let mut by_target: HashMap<String, u32> = HashMap::new();
    for i in 0..2000 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("overlap-{i}"),
            no_health(),
        )
        .expect("overlap distribute selection");
        *by_target.entry(selection.target.host.clone()).or_default() += 1;
    }

    let zone_1 = by_target.get("west-zone-1.local").copied().unwrap_or(0);
    let zone_2 = by_target.get("west-zone-2.local").copied().unwrap_or(0);
    let total = zone_1 + zone_2;
    assert_eq!(total, 2000);

    let zone_1_ratio = f64::from(zone_1) / f64::from(total);
    let zone_2_ratio = f64::from(zone_2) / f64::from(total);
    assert!(
        (zone_1_ratio - 0.5).abs() < 0.06,
        "west-zone-1 ratio {zone_1_ratio:.3} outside +/-0.06 of 0.5"
    );
    assert!(
        (zone_2_ratio - 0.5).abs() < 0.06,
        "west-zone-2 ratio {zone_2_ratio:.3} outside +/-0.06 of 0.5"
    );
}

#[test]
fn locality_distribute_preserves_consistent_hashing_within_selected_locality() {
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::ConsistentHashing,
        Some("us-west/us-west-1/a"),
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            target("east-a.local", Some("us-east/us-east-1/a")),
            target("east-b.local", Some("us-east/us-east-1/a")),
        ],
    );
    up.locality_lb_setting = Some(setting);
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let first = LoadBalancerCache::select_target_from(
        &snapshot,
        "ferrum",
        "u1",
        "sticky-user",
        no_health(),
    )
    .expect("consistent hash distribute selection");
    assert!(first.target.host.starts_with("east-"));

    for _ in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            "sticky-user",
            no_health(),
        )
        .expect("consistent hash distribute selection");
        assert_eq!(
            selection.target.host, first.target.host,
            "distribute must preserve consistent hashing within the selected locality"
        );
    }
}

#[test]
fn locality_distribute_vec_fallback_preserves_consistent_hashing_within_selected_locality() {
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let mut targets = Vec::with_capacity(131);
    targets.push(target("west.local", Some("us-west/us-west-1/a")));
    for i in 0..130 {
        targets.push(target(
            &format!("east-{i}.local"),
            Some("us-east/us-east-1/a"),
        ));
    }
    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::ConsistentHashing,
        Some("us-west/us-west-1/a"),
        targets,
    );
    up.locality_lb_setting = Some(setting);
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let first = LoadBalancerCache::select_target_from(
        &snapshot,
        "ferrum",
        "u1",
        "sticky-user-vec",
        no_health(),
    )
    .expect("consistent hash distribute vec selection");
    assert!(first.target.host.starts_with("east-"));

    for _ in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            "sticky-user-vec",
            no_health(),
        )
        .expect("consistent hash distribute vec selection");
        assert_eq!(
            selection.target.host, first.target.host,
            "Vec fallback distribute must preserve consistent hashing within the selected locality"
        );
    }
}

#[test]
fn locality_distribute_from_terminal_wildcard_matches_source_subzone() {
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/*".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("wild-{i}"),
            no_health(),
        )
        .expect("wildcard distribute selection");
        assert_eq!(
            selection.target.host, "east.local",
            "terminal wildcard in distribute.from must activate distribute weighting"
        );
    }
}

#[test]
fn locality_distribute_from_region_only_matches_zoned_source_locality() {
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("region-only-{i}"),
            no_health(),
        )
        .expect("region-only distribute selection");
        assert_eq!(
            selection.target.host, "east.local",
            "region-only distribute.from must activate for zoned source locality"
        );
    }
}

#[test]
fn locality_distribute_from_global_wildcard_matches_any_source_locality() {
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "*".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("global-wild-{i}"),
            no_health(),
        )
        .expect("global wildcard distribute selection");
        assert_eq!(
            selection.target.host, "east.local",
            "bare wildcard in distribute.from must activate distribute weighting for any source"
        );
    }
}

#[test]
fn locality_distribute_falls_through_when_every_weighted_target_is_unhealthy() {
    // distribute weights east at 100. If the only east target is unhealthy
    // selection MUST continue through locality priority before the residual
    // candidate set instead of jumping directly to arbitrary candidates.
    let east = target("east.local", Some("us-east/us-east-1/a"));
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            east.clone(),
            target("eu.local", Some("eu-central/eu-central-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &east), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    for i in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("fb-{i}"),
            Some(&health),
        )
        .expect("fallthrough selection");
        assert_eq!(
            selection.target.host, "west.local",
            "empty distribute mask must preserve locality priority before residual fallback"
        );
    }
}

#[test]
fn locality_distribute_vec_fallback_empty_mask_preserves_priority_tier() {
    let east = target("east.local", Some("us-east/us-east-1/a"));
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let mut targets = Vec::with_capacity(132);
    targets.push(target("west.local", Some("us-west/us-west-1/a")));
    targets.push(east.clone());
    for i in 0..130 {
        targets.push(target(
            &format!("eu-{i}.local"),
            Some("eu-central/eu-central-1/a"),
        ));
    }
    let up = upstream_with_locality_lb("us-west/us-west-1/a", targets, setting);
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &east), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    for i in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("vec-fb-{i}"),
            Some(&health),
        )
        .expect("vec fallthrough selection");
        assert_eq!(
            selection.target.host, "west.local",
            "Vec empty distribute mask must preserve locality priority before residual fallback"
        );
    }
}

#[test]
fn locality_distribute_no_matching_from_uses_priority_tier() {
    // distribute.from is `eu-central`, source is `us-west` — no entry
    // matches, so distribute does NOT activate and the existing priority
    // tier preference takes over.
    let mut to = BTreeMap::new();
    to.insert("eu-central".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "eu-central/eu-central-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("exact.local", Some("us-west/us-west-1/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("p-{i}"),
            no_health(),
        )
        .expect("priority selection");
        assert_eq!(
            selection.target.host, "exact.local",
            "distribute.from mismatch must leave priority tier preference intact"
        );
    }
}

// ── localityLbSetting.failover ────────────────────────────────────────────

#[test]
fn locality_failover_overrides_region_fallback_when_all_local_tiers_unhealthy() {
    // Source region `us-west`; failover routes to `us-east`. With exact,
    // zone, and region tiers all unhealthy, the failover region MUST win
    // over the unannotated rank-3 `eu` target.
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let zone = target("zone.local", Some("us-west/us-west-1/b"));
    let region = target("region.local", Some("us-west/us-west-2/a"));
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: Vec::new(),
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            zone.clone(),
            region.clone(),
            target("eu.local", Some("eu-central/eu-central-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &exact), 1);
    active_unhealthy.insert(target_key("ferrum|u1", &zone), 1);
    active_unhealthy.insert(target_key("ferrum|u1", &region), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    for i in 0..6 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("k-{i}"),
            Some(&health),
        )
        .expect("failover selection");
        assert_eq!(
            selection.target.host, "east.local",
            "failover region must win over rank-3 unannotated targets"
        );
    }
}

#[test]
fn locality_failover_does_not_apply_when_local_tier_is_healthy() {
    // Even with failover configured, a healthy exact-tier target wins.
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: Vec::new(),
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("exact.local", Some("us-west/us-west-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    for i in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("h-{i}"),
            no_health(),
        )
        .expect("priority selection");
        assert_eq!(
            selection.target.host, "exact.local",
            "failover must not preempt a healthy exact-tier target"
        );
    }
}

#[test]
fn locality_failover_falls_through_when_failover_region_is_also_empty() {
    // Failover region has no targets at all — selection must still succeed
    // by falling through to the rank-3 unannotated set.
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: Vec::new(),
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            target("eu.local", Some("eu-central/eu-central-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("ferrum|u1", &exact), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection =
        LoadBalancerCache::select_target_from(&snapshot, "ferrum", "u1", "ft", Some(&health))
            .expect("fallthrough selection");
    assert_eq!(selection.target.host, "eu.local");
}

#[test]
fn locality_lb_enabled_false_disables_priority_distribute_and_failover() {
    // `enabled: false` matches Istio semantics — every locality-aware
    // path is suppressed and the configured algorithm picks across the
    // unfiltered candidate set.
    let setting = UpstreamLocalityLbSetting {
        enabled: false,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to: BTreeMap::from([("us-west".to_string(), 100)]),
        }],
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("exact.local", Some("us-west/us-west-1/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let mut seen: HashSet<String> = HashSet::new();
    for i in 0..30 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "ferrum",
            "u1",
            &format!("k-{i}"),
            no_health(),
        )
        .expect("selected");
        seen.insert(selection.target.host.clone());
    }
    assert_eq!(
        seen.len(),
        2,
        "enabled=false must let RR visit both targets across the full set — saw {seen:?}"
    );
}
