//! Per-target load-balancer runtime state across balancer rebuilds (issue #5693).
//!
//! A service-discovery target update, a modified upstream, or a full rebuild
//! builds a fresh `LoadBalancer`. Every target whose `host:port` survives in
//! the same upstream must keep its live active-connection count and its
//! latency EWMA / sample count, and a connection opened through the old
//! balancer must release the counter the new balancer reads. Removed targets'
//! state is dropped, so a re-added target starts clean, and no release can
//! drive a count negative.

use chrono::Utc;
use ferrum_edge::config::types::{GatewayConfig, LoadBalancerAlgorithm, Upstream, UpstreamTarget};
use ferrum_edge::load_balancer::{LoadBalancer, LoadBalancerCache};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn ns() -> String {
    ferrum_edge::config::types::default_namespace()
}

fn target(host: &str) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port: 8080,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

fn upstream(id: &str, algorithm: LoadBalancerAlgorithm, targets: Vec<UpstreamTarget>) -> Upstream {
    Upstream {
        labels: Default::default(),
        id: id.to_string(),
        namespace: ns(),
        name: Some(format!("upstream-{id}")),
        targets,
        algorithm,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: Default::default(),
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
        k8s_service_uid: None,
        pending_limit_scope: None,
    }
}

fn cache_with(upstreams: Vec<Upstream>) -> LoadBalancerCache {
    LoadBalancerCache::new(&GatewayConfig {
        upstreams,
        ..GatewayConfig::default()
    })
}

fn balancer(cache: &LoadBalancerCache, id: &str) -> Arc<LoadBalancer> {
    cache
        .load()
        .get_balancer(&ns(), id)
        .expect("balancer published for upstream")
}

fn connections(lb: &LoadBalancer, target: &UpstreamTarget) -> i64 {
    lb.target_runtime_state(target)
        .expect("target present in balancer")
        .active_connections()
}

#[test]
fn least_connections_preference_survives_service_discovery_update() {
    let (a, b, c) = (target("a"), target("b"), target("c"));
    let initial = upstream(
        "lc",
        LoadBalancerAlgorithm::LeastConnections,
        vec![a.clone(), b.clone()],
    );
    let cache = cache_with(vec![initial]);
    let old = balancer(&cache, "lc");
    // Long-lived sessions on `a`, opened through the old balancer.
    for _ in 0..1_000 {
        old.record_connection_start(&a);
    }

    // Scale-up: discovery publishes a new target set that still contains `a`.
    cache.update_targets(
        &ns(),
        "lc",
        vec![a.clone(), b.clone(), c.clone()],
        LoadBalancerAlgorithm::LeastConnections,
        None,
    );
    let new = balancer(&cache, "lc");
    assert!(
        !Arc::ptr_eq(&old, &new),
        "update must publish a new balancer"
    );

    assert_eq!(connections(&new, &a), 1_000);
    assert_eq!(connections(&new, &b), 0);
    assert_eq!(connections(&new, &c), 0);
    for _ in 0..50 {
        let selected = new.select("", None).expect("target selected");
        assert_ne!(
            selected.target.host, "a",
            "the loaded target must not look idle after a target-set change"
        );
    }
}

#[test]
fn least_latency_ewma_and_samples_survive_service_discovery_update() {
    let (slow, fast, joiner) = (target("slow"), target("fast"), target("joiner"));
    let initial = upstream(
        "ll",
        LoadBalancerAlgorithm::LeastLatency,
        vec![slow.clone(), fast.clone()],
    );
    let cache = cache_with(vec![initial]);
    let old = balancer(&cache, "ll");
    for _ in 0..10 {
        old.record_latency(&slow, 50_000);
        old.record_latency(&fast, 5_000);
    }
    let slow_ewma = old
        .target_runtime_state(&slow)
        .and_then(|state| state.latency_ewma_us())
        .expect("slow EWMA recorded");

    cache.update_targets(
        &ns(),
        "ll",
        vec![slow.clone(), fast.clone(), joiner.clone()],
        LoadBalancerAlgorithm::LeastLatency,
        None,
    );
    let new = balancer(&cache, "ll");

    let slow_state = new.target_runtime_state(&slow).expect("slow present");
    assert_eq!(slow_state.latency_ewma_us(), Some(slow_ewma));
    assert_eq!(slow_state.latency_sample_count(), 10);
    let fast_state = new.target_runtime_state(&fast).expect("fast present");
    assert_eq!(fast_state.latency_ewma_us(), Some(5_000));
    assert_eq!(fast_state.latency_sample_count(), 10);
    let joiner_state = new.target_runtime_state(&joiner).expect("joiner present");
    assert_eq!(joiner_state.latency_ewma_us(), None);
    assert_eq!(joiner_state.latency_sample_count(), 0);

    // No return to round-robin warm-up: the known-slow target gets nothing, the
    // fast one keeps the majority, and only the new target is explored.
    let mut hits: HashMap<String, usize> = HashMap::new();
    for _ in 0..200 {
        let selected = new.select("", None).expect("target selected");
        *hits.entry(selected.target.host.clone()).or_default() += 1;
    }
    assert_eq!(
        hits.get("slow"),
        None,
        "known-slow target must not regain traffic"
    );
    assert!(hits.get("fast").copied().unwrap_or(0) > 100, "{hits:?}");
}

#[test]
fn release_through_old_balancer_decrements_the_counter_the_new_balancer_reads() {
    let (a, b) = (target("a"), target("b"));
    let initial = upstream(
        "guard",
        LoadBalancerAlgorithm::LeastConnections,
        vec![a.clone(), b.clone()],
    );
    let cache = cache_with(vec![initial]);
    // Paired start/end calls on the one balancer instance the connection was
    // started on, as a caller holding that balancer would make them.
    let old = balancer(&cache, "guard");
    old.record_connection_start(&a);
    old.record_connection_start(&a);

    cache.update_targets(
        &ns(),
        "guard",
        vec![a.clone(), b.clone(), target("c")],
        LoadBalancerAlgorithm::LeastConnections,
        None,
    );
    let new = balancer(&cache, "guard");
    let runtime_key = ferrum_edge::config::db_backend::namespaced_runtime_key(&ns(), "guard");
    assert_eq!(
        cache.active_connections_snapshot(),
        vec![(runtime_key, vec![("a:8080".to_string(), 2)])],
        "metrics must report connections opened before the rebuild"
    );

    old.record_connection_end(&a);
    assert_eq!(connections(&new, &a), 1);

    // A second rebuild retires `old` from the cache; its holder still releases
    // into the shared counter.
    cache.update_targets(
        &ns(),
        "guard",
        vec![a.clone(), b.clone()],
        LoadBalancerAlgorithm::LeastConnections,
        None,
    );
    let newest = balancer(&cache, "guard");
    assert_eq!(connections(&newest, &a), 1);
    old.record_connection_end(&a);
    drop(old);
    assert_eq!(connections(&newest, &a), 0);
    assert_eq!(connections(&new, &a), 0);
    assert!(cache.active_connections_snapshot().is_empty());

    // An extra release saturates instead of going negative.
    newest.record_connection_end(&a);
    assert_eq!(connections(&newest, &a), 0);
}

#[test]
fn removed_then_readded_target_starts_clean_and_late_release_never_goes_negative() {
    let (a, b) = (target("a"), target("b"));
    let initial = upstream(
        "readd",
        LoadBalancerAlgorithm::LeastLatency,
        vec![a.clone(), b.clone()],
    );
    let cache = cache_with(vec![initial]);
    let first = balancer(&cache, "readd");
    first.record_connection_start(&a);
    first.record_connection_start(&a);
    for _ in 0..10 {
        first.record_latency(&a, 7_000);
    }

    // `a` leaves the discovered set, then comes back.
    cache.update_targets(
        &ns(),
        "readd",
        vec![b.clone()],
        LoadBalancerAlgorithm::LeastLatency,
        None,
    );
    let without_a = balancer(&cache, "readd");
    assert!(without_a.target_runtime_state(&a).is_none());
    cache.update_targets(
        &ns(),
        "readd",
        vec![a.clone(), b.clone()],
        LoadBalancerAlgorithm::LeastLatency,
        None,
    );
    let readded = balancer(&cache, "readd");
    let state = readded.target_runtime_state(&a).expect("a re-added");
    assert_eq!(
        state.active_connections(),
        0,
        "removed state must not return"
    );
    assert_eq!(state.latency_ewma_us(), None);
    assert_eq!(state.latency_sample_count(), 0);

    readded.record_connection_start(&a);
    // Connections from before the removal release their own (orphaned) slot,
    // never the re-added target's live count.
    first.record_connection_end(&a);
    first.record_connection_end(&a);
    first.record_connection_end(&a);
    assert_eq!(connections(&first, &a), 0);
    assert_eq!(connections(&readded, &a), 1);

    readded.record_connection_end(&a);
    readded.record_connection_end(&a);
    assert_eq!(connections(&readded, &a), 0);
}

#[test]
fn modified_upstream_delta_keeps_surviving_target_state() {
    let (a, b, c) = (target("a"), target("b"), target("c"));
    let original = upstream(
        "delta",
        LoadBalancerAlgorithm::LeastConnections,
        vec![a.clone(), b.clone()],
    );
    let cache = cache_with(vec![original]);
    let old = balancer(&cache, "delta");
    old.record_connection_start(&a);
    old.record_latency(&b, 3_000);

    // Target `b` is removed and the algorithm changes; `a` survives.
    let modified = upstream(
        "delta",
        LoadBalancerAlgorithm::LeastLatency,
        vec![a.clone(), c.clone()],
    );
    let config = GatewayConfig {
        upstreams: vec![modified.clone()],
        ..GatewayConfig::default()
    };
    cache.apply_delta(&config, &[], &[], &[modified]);
    let new = balancer(&cache, "delta");

    assert_eq!(connections(&new, &a), 1);
    assert_eq!(connections(&new, &c), 0);
    assert!(new.target_runtime_state(&b).is_none());
    old.record_connection_end(&a);
    assert_eq!(connections(&new, &a), 0);
}

#[test]
fn full_rebuild_keeps_surviving_target_state_per_upstream() {
    let shared = target("shared");
    let config = GatewayConfig {
        upstreams: vec![
            upstream(
                "u1",
                LoadBalancerAlgorithm::LeastConnections,
                vec![shared.clone(), target("u1-only")],
            ),
            upstream(
                "u2",
                LoadBalancerAlgorithm::LeastConnections,
                vec![shared.clone()],
            ),
        ],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    balancer(&cache, "u1").record_connection_start(&shared);
    balancer(&cache, "u1").record_latency(&shared, 4_000);

    cache.rebuild(&config);

    let u1 = balancer(&cache, "u1");
    assert_eq!(connections(&u1, &shared), 1);
    assert_eq!(
        u1.target_runtime_state(&shared)
            .and_then(|state| state.latency_ewma_us()),
        Some(4_000)
    );
    // The identity is `host:port` WITHIN one upstream: another upstream that
    // lists the same endpoint keeps its own state.
    let u2 = balancer(&cache, "u2");
    assert_eq!(connections(&u2, &shared), 0);
    assert_eq!(
        u2.target_runtime_state(&shared)
            .and_then(|state| state.latency_ewma_us()),
        None
    );
}

#[test]
fn duplicate_host_port_entries_share_one_slot_across_rebuilds() {
    let mut lane_80 = target("dup");
    lane_80.service_port_policy_key = Some(80);
    let mut lane_81 = target("dup");
    lane_81.service_port_policy_key = Some(81);
    let other = target("other");
    let initial = upstream(
        "dup",
        LoadBalancerAlgorithm::LeastConnections,
        vec![lane_80.clone(), lane_81.clone(), other.clone()],
    );
    let cache = cache_with(vec![initial]);
    let old = balancer(&cache, "dup");
    old.record_connection_start(&lane_80);
    old.record_connection_start(&lane_81);
    assert_eq!(connections(&old, &lane_80), 2);
    let counts = old.active_connection_counts();
    assert_eq!(
        counts.len(),
        2,
        "one entry per distinct host:port: {counts:?}"
    );
    assert!(counts.contains(&("dup:8080".to_string(), 2)), "{counts:?}");

    cache.update_targets(
        &ns(),
        "dup",
        vec![lane_81.clone(), other.clone(), lane_80.clone()],
        LoadBalancerAlgorithm::LeastConnections,
        None,
    );
    let new = balancer(&cache, "dup");
    assert_eq!(connections(&new, &lane_80), 2);
    assert_eq!(connections(&new, &lane_81), 2);
    old.record_connection_end(&lane_80);
    old.record_connection_end(&lane_81);
    assert_eq!(connections(&new, &lane_80), 0);
    assert_eq!(connections(&new, &lane_81), 0);
}

#[test]
fn rebuilt_balancer_adopts_the_previous_slot_only_for_surviving_targets() {
    let (a, b, c) = (target("a"), target("b"), target("c"));
    let initial = upstream(
        "adopt",
        LoadBalancerAlgorithm::LeastConnections,
        vec![a.clone(), b.clone()],
    );
    let cache = cache_with(vec![initial]);
    let previous = balancer(&cache, "adopt");
    previous.record_connection_start(&a);
    previous.record_connection_start(&b);

    cache.update_targets(
        &ns(),
        "adopt",
        vec![b.clone(), c.clone()],
        LoadBalancerAlgorithm::LeastConnections,
        None,
    );
    let next = balancer(&cache, "adopt");

    assert!(next.target_runtime_state(&a).is_none());
    assert_eq!(connections(&next, &b), 1);
    assert_eq!(connections(&next, &c), 0);
    let next_b = next.target_runtime_state(&b).expect("b present");
    let previous_b = previous.target_runtime_state(&b).expect("b present");
    assert!(
        std::ptr::eq(next_b, previous_b),
        "surviving target shares one slot"
    );
    drop(previous);
    assert_eq!(connections(&next, &b), 1);
}

#[test]
fn lease_taken_before_a_rebuild_releases_the_counter_the_new_balancer_reads() {
    let (a, b) = (target("a"), target("b"));
    let initial = upstream(
        "lease",
        LoadBalancerAlgorithm::LeastConnections,
        vec![a.clone(), b.clone()],
    );
    let cache = cache_with(vec![initial]);
    let lease = balancer(&cache, "lease")
        .lease_connection(&a)
        .expect("a is a target");
    assert!(
        balancer(&cache, "lease")
            .lease_connection(&target("absent"))
            .is_none(),
        "no lease for a target outside the balancer"
    );

    // The lease holds the slot, not the balancer: two rebuilds retire the
    // balancer it was taken through without disturbing the count.
    for targets in [vec![a.clone(), b.clone(), target("c")], vec![a.clone()]] {
        cache.update_targets(
            &ns(),
            "lease",
            targets,
            LoadBalancerAlgorithm::LeastConnections,
            None,
        );
    }
    let newest = balancer(&cache, "lease");
    assert_eq!(connections(&newest, &a), 1);

    drop(lease);
    assert_eq!(connections(&newest, &a), 0);
    assert!(cache.active_connections_snapshot().is_empty());
}

/// Counts a churn worker as finished even if it panics, so the publisher loop
/// cannot spin forever.
struct Finished<'a>(&'a AtomicUsize);

impl Drop for Finished<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Connections opened and closed from several threads while service
/// discovery and config deltas keep republishing the balancer must settle at
/// exactly zero: no start may be lost, no end may be applied twice, and no
/// count may go negative while the churn is running.
#[test]
fn concurrent_connection_churn_across_rebuilds_settles_to_zero() {
    const WORKERS: usize = 4;
    const ITERATIONS: usize = 2_000;
    let (a, b, c) = (target("a"), target("b"), target("c"));
    let initial = upstream(
        "churn",
        LoadBalancerAlgorithm::LeastConnections,
        vec![a.clone(), b.clone()],
    );
    let cache = cache_with(vec![initial]);
    let finished = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        for worker in 0..WORKERS {
            let (cache, finished) = (&cache, &finished);
            let (a, b) = (&a, &b);
            scope.spawn(move || {
                let _finished = Finished(finished);
                let mut held = std::collections::VecDeque::new();
                for i in 0..ITERATIONS {
                    let lb = balancer(cache, "churn");
                    let chosen = if (i + worker) % 2 == 0 { a } else { b };
                    if i % 3 == 0 {
                        // Paired calls on the one balancer instance.
                        lb.record_connection_start(chosen);
                        std::thread::yield_now();
                        lb.record_connection_end(chosen);
                    } else {
                        // Leases stay open across later rebuilds.
                        held.push_back(lb.lease_connection(chosen));
                        if held.len() > 8 {
                            drop(held.pop_front());
                        }
                    }
                }
                drop(held);
            });
        }

        let mut round = 0usize;
        while finished.load(Ordering::SeqCst) < WORKERS {
            match round % 4 {
                0 => cache.update_targets(
                    &ns(),
                    "churn",
                    vec![a.clone(), b.clone(), c.clone()],
                    LoadBalancerAlgorithm::LeastConnections,
                    None,
                ),
                1 => {
                    let modified = upstream(
                        "churn",
                        LoadBalancerAlgorithm::LeastLatency,
                        vec![b.clone(), a.clone()],
                    );
                    let config = GatewayConfig {
                        upstreams: vec![modified.clone()],
                        ..GatewayConfig::default()
                    };
                    cache.apply_delta(&config, &[], &[], &[modified]);
                }
                // `b` leaves and comes back: its old slot is orphaned.
                2 => cache.update_targets(
                    &ns(),
                    "churn",
                    vec![a.clone(), c.clone()],
                    LoadBalancerAlgorithm::LeastConnections,
                    None,
                ),
                _ => cache.update_targets(
                    &ns(),
                    "churn",
                    vec![a.clone(), b.clone()],
                    LoadBalancerAlgorithm::LeastConnections,
                    None,
                ),
            }
            for (key, count) in balancer(&cache, "churn").active_connection_counts() {
                assert!(count >= 0, "{key} went negative: {count}");
            }
            round += 1;
            std::thread::yield_now();
        }
    });

    cache.update_targets(
        &ns(),
        "churn",
        vec![a.clone(), b.clone(), c.clone()],
        LoadBalancerAlgorithm::LeastConnections,
        None,
    );
    let settled = balancer(&cache, "churn");
    for target in [&a, &b, &c] {
        assert_eq!(connections(&settled, target), 0, "{}", target.host);
    }
    assert!(cache.active_connections_snapshot().is_empty());
}

/// Byte offset of every occurrence of `needle` in `haystack` that is not the
/// tail of a longer identifier (so `LoadBalancer::new(` does not match
/// `FooLoadBalancer::new(`).
fn standalone_matches(haystack: &str, needle: &str) -> Vec<usize> {
    haystack
        .match_indices(needle)
        .filter(|(at, _)| {
            haystack[..*at]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
        })
        .map(|(at, _)| at)
        .collect()
}

fn rust_sources(dir: &Path, out: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(dir).expect("read source directory");
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let source = std::fs::read_to_string(&path).expect("read source file");
            out.push((path.display().to_string(), source));
        }
    }
}

/// The body of `fn <name>(` in `source`, up to the next `\n    fn ` or
/// `\n    pub`.
fn fn_body<'a>(source: &'a str, name: &str) -> &'a str {
    let signature = format!("fn {name}(");
    let start = source
        .find(signature.as_str())
        .unwrap_or_else(|| panic!("fn {name} present"));
    let rest = &source[start + 1..];
    let end = ["\n    fn ", "\n    pub", "\n}\n"]
        .into_iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .unwrap_or(rest.len());
    &source[start..start + 1 + end]
}

/// Every production `LoadBalancer` construction must hand the published
/// balancer over so surviving targets keep their state. The cache builds all
/// of its balancers through one builder that passes `previous`; any other
/// construction site (`LoadBalancer::new(`, `LoadBalancer::with_subsets(`, or
/// a second `with_subsets_and_port_overrides(` call) anywhere in production
/// code would silently bring back #5693 for that path.
#[test]
fn every_production_balancer_construction_hands_over_runtime_state() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    rust_sources(&src, &mut sources);
    assert!(sources.len() > 10, "source walk found {}", sources.len());

    let mut builder_calls = Vec::new();
    for (path, source) in &sources {
        // Everything before the first top-level inline test module.
        let production = source
            .split("\n#[cfg(test)]\nmod ")
            .next()
            .unwrap_or_default();
        for needle in ["LoadBalancer::new(", "LoadBalancer::with_subsets("] {
            assert!(
                standalone_matches(production, needle).is_empty(),
                "{path}: production `{needle}` bypasses the cache builder"
            );
        }
        let full = "LoadBalancer::with_subsets_and_port_overrides(";
        for at in standalone_matches(production, full) {
            builder_calls.push((path.clone(), at));
        }
    }
    assert_eq!(
        builder_calls.len(),
        1,
        "exactly one production construction site: {builder_calls:?}"
    );

    let (path, at) = &builder_calls[0];
    assert!(path.ends_with("load_balancer.rs"), "{path}");
    let source = &sources
        .iter()
        .find(|(candidate, _)| candidate == path)
        .expect("builder source")
        .1;
    let builder = fn_body(source, "build_balancer_with_targets");
    let builder_start = source.find(builder).expect("builder body");
    assert!(
        (builder_start..builder_start + builder.len()).contains(at),
        "the one construction must be inside build_balancer_with_targets"
    );
    assert!(
        builder.contains("previous,\n        ))"),
        "the builder must hand `previous` to the constructor"
    );
    for cache_path in [
        "build_balancer",
        "build_balancers",
        "build_delta_inner",
        "build_update_targets_inner",
    ] {
        let body = fn_body(source, cache_path);
        assert!(
            body.contains("Self::build_balancer"),
            "{cache_path} must build through the runtime-state-inheriting builder"
        );
    }
}
