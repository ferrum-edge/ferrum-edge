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
use std::ops::Range;
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
    let old = balancer(&cache, "lease");
    let first = old.lease_connection(&a).expect("a is a target");
    let second = old.lease_connection(&a).expect("a is a target");
    let third = old.lease_connection(&a).expect("a is a target");
    drop(old);
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
    assert_eq!(connections(&newest, &a), 3);

    // Each drop releases exactly one count: a double release or a lost start
    // would show here rather than saturating at zero.
    drop(second);
    assert_eq!(connections(&newest, &a), 2);
    drop(first);
    assert_eq!(connections(&newest, &a), 1);
    drop(third);
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

/// Identity of the runtime-state slot `lb` counts `target` against. A held
/// lease keeps its slot alive, so the address cannot be reused while it is
/// compared.
fn slot_id(lb: &LoadBalancer, target: &UpstreamTarget) -> usize {
    let state = lb
        .target_runtime_state(target)
        .expect("target present in balancer");
    std::ptr::from_ref(state).addr()
}

/// Connections opened and closed from several threads while service
/// discovery and config deltas keep republishing the balancer. No count may
/// go negative while the churn runs. Afterwards the workers hand back the
/// leases they still hold: each target's live count must equal exactly the
/// number of those leases taken against its current slot (a lost start or a
/// double release would show, since the count is above zero), and releasing
/// them must bring every count back to zero.
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

    let held: Vec<_> = std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(WORKERS);
        for worker in 0..WORKERS {
            let (cache, finished) = (&cache, &finished);
            let (a, b) = (&a, &b);
            workers.push(scope.spawn(move || {
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
                    } else if let Some(lease) = lb.lease_connection(chosen) {
                        // Leases stay open across later rebuilds; remember
                        // which slot each one counts against.
                        held.push_back((slot_id(&lb, chosen), lease));
                        if held.len() > 8 {
                            drop(held.pop_front());
                        }
                    }
                }
                held
            }));
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

        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("churn worker panicked"))
            .collect()
    });

    cache.update_targets(
        &ns(),
        "churn",
        vec![a.clone(), b.clone(), c.clone()],
        LoadBalancerAlgorithm::LeastConnections,
        None,
    );
    let settled = balancer(&cache, "churn");
    let leased = |target: &UpstreamTarget| {
        let slot = slot_id(&settled, target);
        let count = held.iter().filter(|(id, _)| *id == slot).count();
        i64::try_from(count).expect("lease count fits i64")
    };
    // `a` is in every published target set, so every lease on it counts
    // against the one live slot.
    assert!(leased(&a) > 0, "workers must still hold leases on `a`");
    for target in [&a, &b, &c] {
        assert_eq!(
            connections(&settled, target),
            leased(target),
            "{} must count exactly the leases held against its slot",
            target.host
        );
    }

    drop(held);
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

/// Replace every byte in `range` except newlines with a space, so byte
/// offsets and line numbers stay unchanged.
fn blank(code: &mut [u8], range: Range<usize>) {
    for byte in &mut code[range] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_whitespace(code: &[u8], mut at: usize) -> usize {
    while code.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

/// Index of the delimiter closing the `(`, `[` or `{` at `open`.
fn matching_close(code: &[u8], open: usize) -> usize {
    let mut depth = 0i32;
    for (at, byte) in code.iter().copied().enumerate().skip(open) {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return at;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced delimiter at byte {open}");
}

/// Number of `#`s when a raw string literal (`r"`, `r#"`, `br#"`) starts at
/// `at`; `None` for anything else, including a raw identifier (`r#type`).
fn raw_string_hashes(code: &[u8], at: usize) -> Option<usize> {
    if code[at] != b'r' {
        return None;
    }
    let prefix_ok = match at.checked_sub(1).map(|before| code[before]) {
        None => true,
        Some(b'b') => at < 2 || !is_ident_byte(code[at - 2]),
        Some(before) => !is_ident_byte(before),
    };
    let hashes = code[at + 1..]
        .iter()
        .take_while(|byte| **byte == b'#')
        .count();
    let opens = prefix_ok && code.get(at + 1 + hashes) == Some(&b'"');
    opens.then_some(hashes)
}

/// End (exclusive) of the character literal starting at `at`, or `None` when
/// the quote opens a lifetime or a label instead.
fn char_literal_end(source: &str, at: usize) -> Option<usize> {
    let code = source.as_bytes();
    if code.get(at + 1) == Some(&b'\\') {
        // Skip the escaped character itself: it may be a quote.
        return code
            .get(at + 3..)?
            .iter()
            .position(|byte| *byte == b'\'')
            .map(|found| at + 3 + found + 1);
    }
    let next = source[at + 1..].chars().next()?;
    let close = at + 1 + next.len_utf8();
    (code.get(close) == Some(&b'\'')).then_some(close + 1)
}

/// `source` with comments and the contents of string and character literals
/// blanked, so delimiter matching and needle searches see code only.
fn mask_literals_and_comments(source: &str) -> String {
    let code = source.as_bytes();
    let mut masked = code.to_vec();
    let mut at = 0;
    while at < code.len() {
        let rest = &code[at..];
        if rest.starts_with(b"//") {
            let end = rest
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(code.len(), |found| at + found);
            blank(&mut masked, at..end);
            at = end;
        } else if rest.starts_with(b"/*") {
            // Block comments nest.
            let mut depth = 0usize;
            let mut end = at;
            while end < code.len() {
                if code[end..].starts_with(b"/*") {
                    depth += 1;
                    end += 2;
                } else if code[end..].starts_with(b"*/") {
                    depth -= 1;
                    end += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    end += 1;
                }
            }
            let end = end.min(code.len());
            blank(&mut masked, at..end);
            at = end;
        } else if let Some(hashes) = raw_string_hashes(code, at) {
            let open = at + hashes + 2;
            let terminator: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let close = code[open..]
                .windows(terminator.len())
                .position(|window| window == terminator.as_slice())
                .map_or(code.len(), |found| open + found);
            blank(&mut masked, open..close);
            at = close + terminator.len();
        } else if code[at] == b'"' {
            let mut close = at + 1;
            while close < code.len() && code[close] != b'"' {
                close += if code[close] == b'\\' { 2 } else { 1 };
            }
            let close = close.min(code.len());
            blank(&mut masked, at + 1..close);
            at = close + 1;
        } else if code[at] == b'\'' {
            match char_literal_end(source, at) {
                Some(end) => {
                    blank(&mut masked, at + 1..end - 1);
                    at = end;
                }
                None => at += 1,
            }
        } else {
            at += 1;
        }
    }
    String::from_utf8(masked).expect("blanking keeps the source valid UTF-8")
}

/// Whether `at` starts a struct field or a field initialiser (`name: ...`,
/// optionally `pub` / `pub(...)`), rather than an item or a statement.
fn is_field_start(code: &[u8], at: usize) -> bool {
    let mut at = at;
    let after_pub = code.get(at + 3).copied();
    if code[at..].starts_with(b"pub") && !after_pub.is_some_and(is_ident_byte) {
        at += 3;
        if code.get(at) == Some(&b'(') {
            at = matching_close(code, at) + 1;
        }
        at = skip_whitespace(code, at);
    }
    let name = code[at..]
        .iter()
        .take_while(|byte| is_ident_byte(**byte))
        .count();
    let colon = skip_whitespace(code, at + name);
    name > 0 && code.get(colon) == Some(&b':') && code.get(colon + 1) != Some(&b':')
}

/// End (exclusive) of the item, statement, or field that the attribute at
/// `attr` applies to: through its `;` or its `{ ... }` body, or through the
/// trailing `,` of a field. Stops before a closing delimiter that belongs to
/// the enclosing item.
fn test_item_end(code: &[u8], attr: usize) -> usize {
    // This attribute and any that follow it.
    let mut at = skip_whitespace(code, attr);
    while code[at..].starts_with(b"#[") {
        at = skip_whitespace(code, matching_close(code, at + 1) + 1);
    }
    let field = is_field_start(code, at);
    let mut depth = 0i32;
    while at < code.len() {
        match code[at] {
            b'{' if depth == 0 && !field => return matching_close(code, at) + 1,
            b';' if depth == 0 => return at + 1,
            b',' if depth == 0 && field => return at + 1,
            b')' | b']' | b'}' if depth == 0 => return at,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'<' if field => depth += 1,
            b'>' if field && !matches!(code[at - 1], b'-' | b'=') => depth -= 1,
            _ => {}
        }
        at += 1;
    }
    code.len()
}

/// `source` reduced to production code: comments and literal contents are
/// blanked, and so is every `#[cfg(test)]` / `#[cfg(all(test, ...))]` item
/// wherever it sits (test modules, test-only functions, fields and
/// statements), not only a trailing test module. Byte offsets are unchanged.
fn production_code(source: &str) -> String {
    let masked = mask_literals_and_comments(source);
    if masked.contains("#![cfg(test)]") {
        return String::new();
    }
    let mut production = masked.clone().into_bytes();
    for marker in ["#[cfg(test)]", "#[cfg(all(test"] {
        for (at, _) in masked.match_indices(marker) {
            let end = test_item_end(masked.as_bytes(), at);
            blank(&mut production, at..end);
        }
    }
    String::from_utf8(production).expect("blanking keeps the source valid UTF-8")
}

/// Byte range of `fn <name>`, from `fn` through its closing brace, inside
/// `within`.
fn fn_span(code: &str, within: Range<usize>, name: &str) -> Range<usize> {
    let signature = format!("fn {name}");
    let start = standalone_matches(&code[within.clone()], &signature)
        .into_iter()
        .map(|at| within.start + at)
        .find(|at| {
            code[at + signature.len()..]
                .trim_start()
                .starts_with(['(', '<'])
        })
        .unwrap_or_else(|| panic!("fn {name} present"));
    let bytes = code.as_bytes();
    let mut body = start;
    let mut depth = 0i32;
    while bytes[body] != b'{' || depth != 0 {
        match bytes[body] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            _ => {}
        }
        body += 1;
    }
    start..matching_close(bytes, body) + 1
}

/// `code[range]` with all whitespace removed.
fn stripped(code: &str, range: Range<usize>) -> String {
    code[range].split_whitespace().collect()
}

/// The top-level arguments, whitespace removed, of each call to `callee`
/// (which ends in `(`) inside `within`.
fn call_args(code: &str, within: Range<usize>, callee: &str) -> Vec<Vec<String>> {
    standalone_matches(&code[within.clone()], callee)
        .into_iter()
        .map(|at| {
            let open = within.start + at + callee.len() - 1;
            let close = matching_close(code.as_bytes(), open);
            let mut args = vec![String::new()];
            let mut depth = 0i32;
            for c in code[open + 1..close].chars() {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth -= 1,
                    ',' if depth == 0 => {
                        args.push(String::new());
                        continue;
                    }
                    _ => {}
                }
                if !c.is_whitespace() {
                    args.last_mut().expect("an argument slot").push(c);
                }
            }
            args.retain(|arg| !arg.is_empty());
            args
        })
        .collect()
}

/// The last argument of each call.
fn last_args(calls: &[Vec<String>]) -> Vec<&str> {
    calls
        .iter()
        .map(|args| args.last().map_or("", String::as_str))
        .collect()
}

const FULL_CONSTRUCTOR: &str = "LoadBalancer::with_subsets_and_port_overrides(";
const SELF_FULL_CONSTRUCTOR: &str = "Self::with_subsets_and_port_overrides(";
const SELF_WITH_SUBSETS: &str = "Self::with_subsets(";
const BUILD: &str = "Self::build_balancer(";
const BUILD_WITH_TARGETS: &str = "Self::build_balancer_with_targets(";

/// Assert that `caller` calls `callee` exactly once and passes `previous`
/// (compared without whitespace) as its last argument: the balancer currently
/// published for the upstream, never `None`.
fn assert_hands_over(code: &str, caller: &str, callee: &str, previous: &str) {
    let calls = call_args(code, fn_span(code, 0..code.len(), caller), callee);
    assert_eq!(
        last_args(&calls),
        [previous],
        "{caller} must hand the published balancer to `{callee}`"
    );
}

/// Every production `LoadBalancer` construction must hand the published
/// balancer over so surviving targets keep their state, and production code
/// must count connections through the RAII lease, never with bare
/// `record_connection_start` / `record_connection_end` pairs (a rebuild no
/// longer resets a leaked count).
///
/// The scan covers every file under `src/` with comments, literal contents
/// and all `#[cfg(test)]` items blanked, and compares call arguments with
/// whitespace removed, so it does not depend on rustfmt layout. Any other
/// construction site (`LoadBalancer::new(`, `LoadBalancer::with_subsets(`,
/// their `Self::` forms inside `impl LoadBalancer`, or a second call to the
/// full constructor) would silently bring back #5693 for that path.
#[test]
fn every_production_balancer_construction_hands_over_runtime_state() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    rust_sources(&src, &mut sources);
    assert!(sources.len() > 10, "source walk found {}", sources.len());
    let lb_path = src.join("load_balancer.rs").display().to_string();

    let mut constructions = Vec::new();
    let mut lb_code = None;
    for (path, source) in &sources {
        let code = production_code(source);
        for needle in ["LoadBalancer::new(", "LoadBalancer::with_subsets("] {
            assert!(
                standalone_matches(&code, needle).is_empty(),
                "{path}: production `{needle}` bypasses the cache builder"
            );
        }
        for at in standalone_matches(&code, FULL_CONSTRUCTOR) {
            constructions.push((path.clone(), at));
        }
        if *path == lb_path {
            lb_code = Some(code);
            continue;
        }
        for needle in ["record_connection_start(", "record_connection_end("] {
            assert!(
                standalone_matches(&code, needle).is_empty(),
                "{path}: production code must count connections with \
                 `LoadBalancerConnectionGuard`, not `{needle}`"
            );
        }
    }
    let code = lb_code.expect("src/load_balancer.rs scanned");
    let whole = 0..code.len();

    // Exactly one construction site: the cache builder, which passes the
    // published balancer as `previous`.
    assert_eq!(
        constructions.len(),
        1,
        "exactly one production construction site: {constructions:?}"
    );
    let (path, at) = &constructions[0];
    assert_eq!(*path, lb_path);
    let builder = fn_span(&code, whole.clone(), "build_balancer_with_targets");
    assert!(
        builder.contains(at),
        "the one construction must be inside build_balancer_with_targets"
    );
    assert_eq!(
        last_args(&call_args(&code, builder, FULL_CONSTRUCTOR)),
        ["previous"],
        "the builder must hand `previous` to the constructor"
    );

    // Inside `impl LoadBalancer` the public constructors only delegate: `new`
    // to `with_subsets`, and `with_subsets` to the full constructor.
    let mut impl_blocks = 0;
    for at in standalone_matches(&code, "impl LoadBalancer") {
        let open = skip_whitespace(code.as_bytes(), at + "impl LoadBalancer".len());
        if code.as_bytes()[open] != b'{' {
            continue;
        }
        impl_blocks += 1;
        let body = open..matching_close(code.as_bytes(), open) + 1;
        let new = fn_span(&code, body.clone(), "new");
        let with_subsets = fn_span(&code, body.clone(), "with_subsets");
        let delegates = |callee: &str, hit: usize| match callee {
            SELF_WITH_SUBSETS => new.contains(&hit),
            SELF_FULL_CONSTRUCTOR => with_subsets.contains(&hit),
            _ => false,
        };
        for callee in ["Self::new(", SELF_WITH_SUBSETS, SELF_FULL_CONSTRUCTOR] {
            for hit in standalone_matches(&code[body.clone()], callee) {
                assert!(
                    delegates(callee, body.start + hit),
                    "`{callee}` inside `impl LoadBalancer` builds a balancer without `previous`"
                );
            }
        }
    }
    assert!(impl_blocks > 0, "no `impl LoadBalancer` block found");

    // Every cache path reaches the builder through one of these calls, each
    // passing the balancer currently published under the same key.
    let mut build_calls = 0;
    for callee in [BUILD, BUILD_WITH_TARGETS] {
        build_calls += standalone_matches(&code, callee).len();
    }
    assert_eq!(
        build_calls, 4,
        "a new cache build path must hand over `previous` and be checked here"
    );
    assert_hands_over(&code, "build_balancers", BUILD, "prior.map(Arc::as_ref)");
    assert_hands_over(&code, "build_balancer", BUILD_WITH_TARGETS, "previous");
    assert_hands_over(&code, "build_delta_inner", BUILD, "previous");
    assert_hands_over(
        &code,
        "build_update_targets_inner",
        BUILD_WITH_TARGETS,
        "current.balancers.get(&key).map(Arc::as_ref)",
    );
    let text = |caller: &str| stripped(&code, fn_span(&code, whole.clone(), caller));
    let prior = "letprior=previous.and_then(|inner|inner.balancers.get(&key));";
    assert!(
        text("build_balancers").contains(prior),
        "build_balancers must take `prior` from the published snapshot"
    );
    let published = "letprevious=new_balancers.get(&key).map(Arc::as_ref);";
    assert!(
        text("build_delta_inner").contains(published),
        "build_delta_inner must take `previous` from the published balancers"
    );
    let inherits = "Self::build_inner_inheriting(config,Some(&*current))";
    assert!(
        text("rebuild").contains(inherits),
        "a full rebuild must inherit from the published snapshot"
    );
}
