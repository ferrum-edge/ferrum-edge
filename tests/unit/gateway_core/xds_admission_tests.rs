//! Aggregate xDS ADS admission control (issue #3741).
//!
//! These cover the budget arithmetic, the `Node.id` contract, principal
//! isolation and permit release. The
//! wire-level behaviour (both ADS methods sharing one budget, response-receiver
//! drop while the request sender stays alive, task abort, the no-first-message
//! deadline, first-message Node omission metrics) is exercised in
//! `tests/integration/cp_dp_grpc_tests.rs`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use ferrum_edge::xds::admission::{
    DEFAULT_XDS_FIRST_REQUEST_TIMEOUT_SECS, DEFAULT_XDS_MAX_ACTIVE_NODES,
    DEFAULT_XDS_MAX_NODE_ID_BYTES, DEFAULT_XDS_MAX_STREAMS_PER_NAMESPACE,
    DEFAULT_XDS_MAX_STREAMS_PER_NODE, DEFAULT_XDS_MAX_STREAMS_PER_PRINCIPAL,
    DEFAULT_XDS_MAX_TOTAL_STREAMS, XdsAdmissionController, XdsAdmissionLimits,
    XdsAdmissionRejection, XdsStreamPermit, principal_key, redacted_identifier, validate_node_id,
    xds_state_key,
};

fn controller(limits: XdsAdmissionLimits) -> XdsAdmissionController {
    XdsAdmissionController::new(limits)
}

fn generous() -> XdsAdmissionLimits {
    XdsAdmissionLimits {
        max_total_streams: 100_000,
        max_streams_per_namespace: 100_000,
        max_streams_per_principal: 100_000,
        max_streams_per_node: 100_000,
        max_active_nodes: 100_000,
        max_node_id_bytes: DEFAULT_XDS_MAX_NODE_ID_BYTES,
        first_request_timeout: Duration::from_secs(30),
    }
}

// ── Defaults are finite ────────────────────────────────────────────────────

#[test]
fn default_admission_limits_are_finite_and_production_safe() {
    let limits = XdsAdmissionLimits::default();
    assert_eq!(limits.max_total_streams, DEFAULT_XDS_MAX_TOTAL_STREAMS);
    assert_eq!(
        limits.max_streams_per_namespace,
        DEFAULT_XDS_MAX_STREAMS_PER_NAMESPACE
    );
    assert_eq!(
        limits.max_streams_per_principal,
        DEFAULT_XDS_MAX_STREAMS_PER_PRINCIPAL
    );
    assert_eq!(
        limits.max_streams_per_node,
        DEFAULT_XDS_MAX_STREAMS_PER_NODE
    );
    assert_eq!(limits.max_active_nodes, DEFAULT_XDS_MAX_ACTIVE_NODES);
    assert_eq!(limits.max_node_id_bytes, DEFAULT_XDS_MAX_NODE_ID_BYTES);
    assert_eq!(
        limits.first_request_timeout,
        Duration::from_secs(DEFAULT_XDS_FIRST_REQUEST_TIMEOUT_SECS)
    );
    assert!(
        !limits.has_unbounded_scope(),
        "no default budget may be silently unbounded"
    );
    assert!(limits.unbounded_scope_names().is_empty());
}

#[test]
fn unbounded_scope_names_lists_every_zeroed_budget() {
    let limits = XdsAdmissionLimits {
        max_total_streams: 0,
        max_streams_per_namespace: 4,
        max_streams_per_principal: 0,
        max_streams_per_node: 4,
        max_active_nodes: 0,
        max_node_id_bytes: 0,
        first_request_timeout: Duration::from_secs(0),
    };
    assert!(limits.has_unbounded_scope());
    let names: HashSet<&str> = limits.unbounded_scope_names().into_iter().collect();
    assert_eq!(
        names,
        HashSet::from([
            "FERRUM_XDS_MAX_TOTAL_STREAMS",
            "FERRUM_XDS_MAX_STREAMS_PER_PRINCIPAL",
            "FERRUM_XDS_MAX_ACTIVE_NODES",
            "FERRUM_XDS_MAX_NODE_ID_BYTES",
            "FERRUM_XDS_FIRST_REQUEST_TIMEOUT_SECONDS",
        ])
    );
}

#[test]
fn node_id_and_first_request_zeroes_are_unbounded_scopes_by_themselves() {
    let limits = XdsAdmissionLimits {
        max_node_id_bytes: 0,
        ..XdsAdmissionLimits::default()
    };
    assert!(limits.has_unbounded_scope());

    let limits = XdsAdmissionLimits {
        first_request_timeout: Duration::ZERO,
        ..XdsAdmissionLimits::default()
    };
    assert!(limits.has_unbounded_scope());
}

// ── The issue's core attack: thousands of unique node ids ──────────────────

#[test]
fn thousands_of_unique_node_ids_are_stopped_by_the_aggregate_budget() {
    // The per-node ceiling alone admits one stream per node id forever. With a
    // finite total budget, a client cycling unique ids is refused once the
    // aggregate is full — this is the exact bypass issue #3741 describes.
    let limits = XdsAdmissionLimits {
        max_total_streams: 64,
        max_streams_per_namespace: 10_000,
        max_streams_per_principal: 10_000,
        max_streams_per_node: 4,
        max_active_nodes: 10_000,
        ..generous()
    };
    let controller = controller(limits);
    let principal = principal_key("spiffe://cluster.local/ns/default/sa/attacker");

    let mut held: Vec<XdsStreamPermit> = Vec::new();
    let mut rejections = 0usize;
    for index in 0..5_000u32 {
        match controller.reserve_stream("ferrum", &principal) {
            Ok(mut permit) => {
                let node_id = format!("node-{index}");
                let state_key = xds_state_key("ferrum", &principal, &node_id);
                permit
                    .register_node(&state_key)
                    .expect("each unique node id is its own node key");
                held.push(permit);
            }
            Err(rejection) => {
                assert_eq!(rejection, XdsAdmissionRejection::TotalStreams);
                rejections += 1;
            }
        }
    }

    assert_eq!(held.len(), 64, "the total budget is the binding ceiling");
    assert_eq!(rejections, 5_000 - 64);
    assert_eq!(controller.active_streams(), 64);
    assert_eq!(controller.active_nodes(), 64);

    // Every map and counter returns to baseline once the streams end.
    held.clear();
    assert_eq!(controller.active_streams(), 0);
    assert_eq!(controller.active_nodes(), 0);
    assert_eq!(controller.tracked_namespaces(), 0);
    assert_eq!(controller.tracked_principals(), 0);
    assert_eq!(controller.node_streams("ferrum:principal:node-0"), 0);
}

#[test]
fn distinct_node_cardinality_is_bounded_independently_of_stream_count() {
    // Plenty of stream budget, but only 8 distinct nodes may be active at once.
    let controller = controller(XdsAdmissionLimits {
        max_active_nodes: 8,
        ..generous()
    });
    let principal = principal_key("dp");

    let mut held = Vec::new();
    for index in 0..8u32 {
        let mut permit = controller.reserve_stream("ferrum", &principal).unwrap();
        permit.register_node(&format!("node-{index}")).unwrap();
        held.push(permit);
    }
    assert_eq!(controller.active_nodes(), 8);

    let mut ninth = controller
        .reserve_stream("ferrum", &principal)
        .expect("aggregate stream budget is not the binding scope here");
    assert_eq!(
        ninth.register_node("node-8"),
        Err(XdsAdmissionRejection::NodeCardinality)
    );
    // A second stream on an ALREADY active node needs no new node slot.
    assert!(ninth.register_node("node-0").is_ok());
    assert_eq!(controller.active_nodes(), 8);

    drop(ninth);
    held.clear();
    assert_eq!(controller.active_nodes(), 0);
    assert_eq!(controller.active_streams(), 0);
}

#[test]
fn a_node_budget_above_the_total_stream_budget_can_never_bind() {
    // A node state key exists only while an admitted stream holds it, so
    // distinct active nodes can never exceed active streams. Pinned because the
    // shipped defaults put the node ceiling ABOVE the total-stream ceiling
    // (2048 > 1024), which makes the distinct-node budget defense-in-depth
    // rather than an active limit — `docs/configuration.md`,
    // `docs/mesh.md` -> "xDS ADS admission budgets", and `ferrum.conf` all say
    // so, and this test is what keeps that claim true.
    let defaults = XdsAdmissionLimits::default();
    assert!(
        defaults.max_active_nodes >= defaults.max_total_streams,
        "if the node ceiling ever drops below the total-stream ceiling the \
         documented default relationship must be updated with it: nodes={} \
         streams={}",
        defaults.max_active_nodes,
        defaults.max_total_streams
    );

    let total = 16usize;
    let controller = controller(XdsAdmissionLimits {
        max_total_streams: total,
        max_active_nodes: total * 4,
        max_streams_per_node: 1,
        ..generous()
    });
    let principal = principal_key("dp");

    // Every admitted stream takes a brand-new node key — the most node slots a
    // client can possibly consume.
    let mut held = Vec::new();
    for index in 0..total {
        let mut permit = controller
            .reserve_stream("ferrum", &principal)
            .expect("within the total-stream budget");
        permit
            .register_node(&format!("node-{index}"))
            .expect("a node ceiling above the total budget never refuses");
        held.push(permit);
    }
    assert_eq!(controller.active_streams(), total);
    assert_eq!(
        controller.active_nodes(),
        total,
        "distinct nodes track streams exactly when every stream is a new node"
    );

    // The total budget — not the node ceiling — is what refuses the next one.
    assert_eq!(
        controller.reserve_stream("ferrum", &principal).unwrap_err(),
        XdsAdmissionRejection::TotalStreams
    );

    // And the node ceiling DOES bind once it is set below the total budget.
    // (`XdsAdmissionController::new` directly, because the `controller` helper
    // is shadowed by the binding above.)
    let tight = XdsAdmissionController::new(XdsAdmissionLimits {
        max_total_streams: total,
        max_active_nodes: 2,
        max_streams_per_node: 1,
        ..generous()
    });
    let mut tight_held = Vec::new();
    for index in 0..2u32 {
        let mut permit = tight.reserve_stream("ferrum", &principal).unwrap();
        permit.register_node(&format!("node-{index}")).unwrap();
        tight_held.push(permit);
    }
    let mut third = tight
        .reserve_stream("ferrum", &principal)
        .expect("stream budget still has room");
    assert_eq!(
        third.register_node("node-2"),
        Err(XdsAdmissionRejection::NodeCardinality),
        "below the total budget the node ceiling is the binding scope"
    );

    drop(third);
    tight_held.clear();
    held.clear();
    assert_eq!(controller.active_streams(), 0);
    assert_eq!(controller.active_nodes(), 0);
    assert_eq!(tight.active_streams(), 0);
    assert_eq!(tight.active_nodes(), 0);
}

// ── Precedence: total → namespace → principal → node → cardinality ─────────

#[test]
fn total_budget_saturates_before_namespace_and_principal() {
    let controller = controller(XdsAdmissionLimits {
        max_total_streams: 2,
        max_streams_per_namespace: 100,
        max_streams_per_principal: 100,
        ..generous()
    });
    let principal = principal_key("dp");
    let _a = controller.reserve_stream("ferrum", &principal).unwrap();
    let _b = controller.reserve_stream("other", &principal).unwrap();
    let rejection = controller
        .reserve_stream("third", &principal_key("other-dp"))
        .expect_err("the total budget is full");
    assert_eq!(
        rejection,
        XdsAdmissionRejection::TotalStreams,
        "the outermost scope is reported even for an untouched namespace/principal"
    );
}

#[test]
fn namespace_budget_saturates_before_principal() {
    let controller = controller(XdsAdmissionLimits {
        max_total_streams: 100,
        max_streams_per_namespace: 1,
        max_streams_per_principal: 100,
        ..generous()
    });
    let _held = controller
        .reserve_stream("tenant-a", &principal_key("dp-1"))
        .unwrap();
    let rejection = controller
        .reserve_stream("tenant-a", &principal_key("dp-2"))
        .expect_err("the tenant budget is full");
    assert_eq!(rejection, XdsAdmissionRejection::NamespaceStreams);
    // Another tenant is unaffected.
    assert!(
        controller
            .reserve_stream("tenant-b", &principal_key("dp-2"))
            .is_ok()
    );
}

#[test]
fn principal_budget_saturates_before_the_node_ceiling() {
    let controller = controller(XdsAdmissionLimits {
        max_total_streams: 100,
        max_streams_per_namespace: 100,
        max_streams_per_principal: 1,
        max_streams_per_node: 100,
        ..generous()
    });
    let principal = principal_key("one-credential");
    let _held = controller.reserve_stream("ferrum", &principal).unwrap();
    let rejection = controller
        .reserve_stream("ferrum", &principal)
        .expect_err("the principal budget is full");
    assert_eq!(
        rejection,
        XdsAdmissionRejection::PrincipalStreams,
        "one credential is bounded before it ever reaches a node key"
    );
    // A different principal in the same namespace still gets its own budget.
    assert!(
        controller
            .reserve_stream("ferrum", &principal_key("another-credential"))
            .is_ok()
    );
}

#[test]
fn node_ceiling_is_the_innermost_guard() {
    let controller = controller(XdsAdmissionLimits {
        max_streams_per_node: 2,
        ..generous()
    });
    let principal = principal_key("dp");
    let mut permits: Vec<XdsStreamPermit> = (0..3)
        .map(|_| controller.reserve_stream("ferrum", &principal).unwrap())
        .collect();
    assert!(permits[0].register_node("node-a").is_ok());
    assert!(permits[1].register_node("node-a").is_ok());
    assert_eq!(
        permits[2].register_node("node-a"),
        Err(XdsAdmissionRejection::NodeStreams)
    );
    assert_eq!(controller.node_streams("node-a"), 2);

    // A rejected registration consumed nothing, so dropping it frees no slot.
    permits.remove(2);
    assert_eq!(controller.node_streams("node-a"), 2);

    // Releasing a registered stream does free one.
    permits.remove(0);
    assert_eq!(controller.node_streams("node-a"), 1);
    let mut fresh = controller.reserve_stream("ferrum", &principal).unwrap();
    assert!(fresh.register_node("node-a").is_ok());
}

#[test]
fn a_failed_inner_reservation_rolls_the_outer_scopes_back() {
    let controller = controller(XdsAdmissionLimits {
        max_total_streams: 100,
        max_streams_per_namespace: 100,
        max_streams_per_principal: 1,
        ..generous()
    });
    let principal = principal_key("dp");
    let held = controller.reserve_stream("ferrum", &principal).unwrap();
    assert_eq!(controller.active_streams(), 1);
    assert_eq!(controller.namespace_streams("ferrum"), 1);

    assert!(controller.reserve_stream("ferrum", &principal).is_err());
    assert_eq!(
        controller.active_streams(),
        1,
        "the refused reservation must not leave the total incremented"
    );
    assert_eq!(
        controller.namespace_streams("ferrum"),
        1,
        "the refused reservation must not leave the namespace incremented"
    );
    assert_eq!(controller.principal_streams(&principal), 1);

    drop(held);
    assert_eq!(controller.active_streams(), 0);
    assert_eq!(controller.namespace_streams("ferrum"), 0);
    assert_eq!(controller.principal_streams(&principal), 0);
}

#[test]
fn a_ceiling_of_one_admits_exactly_one_stream_in_every_scope() {
    for limits in [
        XdsAdmissionLimits {
            max_total_streams: 1,
            ..generous()
        },
        XdsAdmissionLimits {
            max_streams_per_namespace: 1,
            ..generous()
        },
        XdsAdmissionLimits {
            max_streams_per_principal: 1,
            ..generous()
        },
    ] {
        let controller = controller(limits);
        let principal = principal_key("dp");
        let _first = controller
            .reserve_stream("ferrum", &principal)
            .expect("first stream admitted");
        assert!(
            controller.reserve_stream("ferrum", &principal).is_err(),
            "a ceiling of 1 admits exactly one concurrent stream"
        );
    }
}

#[test]
fn zero_disables_a_scope() {
    let controller = controller(XdsAdmissionLimits {
        max_total_streams: 0,
        max_streams_per_namespace: 0,
        max_streams_per_principal: 0,
        max_streams_per_node: 0,
        max_active_nodes: 0,
        ..generous()
    });
    let principal = principal_key("dp");
    let mut held = Vec::new();
    for _ in 0..2_000 {
        let mut permit = controller.reserve_stream("ferrum", &principal).unwrap();
        permit.register_node("one-node").unwrap();
        held.push(permit);
    }
    assert_eq!(controller.active_streams(), 2_000);
    held.clear();
    assert_eq!(controller.active_streams(), 0);
    assert_eq!(controller.active_nodes(), 0);
}

// ── Rapid connect/disconnect returns to baseline ───────────────────────────

#[test]
fn rapid_connect_disconnect_cycles_leave_every_counter_at_baseline() {
    let controller = controller(XdsAdmissionLimits {
        max_total_streams: 4,
        ..generous()
    });
    let principal = principal_key("dp");
    for index in 0..2_000u32 {
        let mut permit = controller.reserve_stream("ferrum", &principal).unwrap();
        permit
            .register_node(&format!("node-{}", index % 7))
            .unwrap();
        drop(permit);
    }
    assert_eq!(controller.active_streams(), 0);
    assert_eq!(controller.active_nodes(), 0);
    assert_eq!(controller.tracked_namespaces(), 0);
    assert_eq!(controller.tracked_principals(), 0);
    // The budget is fully available again after the churn.
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(controller.reserve_stream("ferrum", &principal).unwrap());
    }
    assert!(controller.reserve_stream("ferrum", &principal).is_err());
}

#[test]
fn releasing_a_node_is_idempotent_and_reports_the_last_stream() {
    let controller = controller(generous());
    let principal = principal_key("dp");
    let mut first = controller.reserve_stream("ferrum", &principal).unwrap();
    let mut second = controller.reserve_stream("ferrum", &principal).unwrap();
    first.register_node("node-a").unwrap();
    second.register_node("node-a").unwrap();

    assert!(
        !first.release_node(),
        "one stream remains, so node-scoped state must be retained"
    );
    assert!(
        !first.release_node(),
        "a second release is a no-op, not a double decrement"
    );
    assert_eq!(controller.node_streams("node-a"), 1);

    assert!(
        second.release_node(),
        "the last stream owns node-scoped cleanup"
    );
    assert_eq!(controller.node_streams("node-a"), 0);
    assert_eq!(controller.active_nodes(), 0);

    // The aggregate reservation is still held until the permits drop.
    assert_eq!(controller.active_streams(), 2);
    drop(first);
    drop(second);
    assert_eq!(controller.active_streams(), 0);
}

#[test]
fn last_node_cleanup_excludes_same_key_successor_registration() {
    let controller = controller(generous());
    let principal = principal_key("dp");
    let mut departing = controller.reserve_stream("ferrum", &principal).unwrap();
    departing.register_node("node-a").unwrap();

    let published_state = Arc::new(AtomicUsize::new(1));
    let (cleanup_entered_tx, cleanup_entered_rx) = mpsc::channel();
    let (finish_cleanup_tx, finish_cleanup_rx) = mpsc::channel();
    let cleanup_state = Arc::clone(&published_state);
    let releaser = thread::spawn(move || {
        ferrum_edge::_test_support::release_xds_node_with_cleanup_for_test(&mut departing, || {
            cleanup_state.store(0, Ordering::Release);
            cleanup_entered_tx.send(()).unwrap();
            finish_cleanup_rx.recv().unwrap();
        })
    });
    cleanup_entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("last-stream cleanup should start");

    let successor_controller = controller.clone();
    let successor_principal = principal.clone();
    let successor_state = Arc::clone(&published_state);
    let (successor_registered_tx, successor_registered_rx) = mpsc::channel();
    let successor = thread::spawn(move || {
        let mut permit = successor_controller
            .reserve_stream("ferrum", &successor_principal)
            .unwrap();
        permit.register_node("node-a").unwrap();
        successor_state.store(2, Ordering::Release);
        successor_registered_tx.send(()).unwrap();
        permit
    });

    assert!(
        successor_registered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "same-key registration must wait until old node-scoped cleanup finishes"
    );
    finish_cleanup_tx.send(()).unwrap();
    assert!(releaser.join().unwrap());
    successor_registered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("successor should register after cleanup");
    let successor_permit = successor.join().unwrap();

    assert_eq!(published_state.load(Ordering::Acquire), 2);
    assert_eq!(controller.node_streams("node-a"), 1);
    drop(successor_permit);
    assert_eq!(controller.node_streams("node-a"), 0);
}

// ── Node.id contract ───────────────────────────────────────────────────────

#[test]
fn node_id_length_boundary_is_exact_in_utf8_bytes() {
    let max = 253usize;
    let exact = "a".repeat(max);
    assert_eq!(exact.len(), max);
    assert!(
        validate_node_id(&exact, max).is_ok(),
        "an id of exactly the ceiling is valid"
    );

    let one_over = "a".repeat(max + 1);
    assert_eq!(
        validate_node_id(&one_over, max),
        Err(XdsAdmissionRejection::NodeIdTooLong)
    );

    assert!(validate_node_id("n", max).is_ok());
    assert!(
        validate_node_id(&"a".repeat(1024 * 1024), max).is_err(),
        "a megabyte id is refused"
    );
}

#[test]
fn node_id_length_is_measured_in_bytes_not_characters() {
    // "é" is two UTF-8 bytes. Even ignoring the ASCII rule, the ceiling is a
    // wire-size bound, so a 3-char id can exceed a 4-byte ceiling.
    let id = "ééé";
    assert_eq!(id.chars().count(), 3);
    assert_eq!(id.len(), 6);
    assert_eq!(
        validate_node_id(id, 4),
        Err(XdsAdmissionRejection::NodeIdTooLong)
    );
    // Within the byte ceiling it is still refused, as a non-ASCII form.
    assert_eq!(
        validate_node_id(id, 64),
        Err(XdsAdmissionRejection::NodeIdUnsafeCharacters)
    );
}

#[test]
fn node_id_rejects_empty_control_and_unsafe_forms() {
    let max = DEFAULT_XDS_MAX_NODE_ID_BYTES;
    assert_eq!(
        validate_node_id("", max),
        Err(XdsAdmissionRejection::NodeIdEmpty)
    );
    // LF/CRLF log injection, NUL, tab, spaces, DEL, bidi override, zero-width
    // space, BOM, a non-ASCII homoglyph carrier, and an ANSI escape.
    for hostile in [
        "node\na",
        "node\r\ninject",
        "node\0a",
        "node\ta",
        "node a",
        " node",
        "node ",
        "node\u{7f}a",
        "node\u{202e}a",
        "node\u{200b}a",
        "node\u{feff}a",
        "nodé",
        "\u{1b}[31mnode",
    ] {
        assert_eq!(
            validate_node_id(hostile, max),
            Err(XdsAdmissionRejection::NodeIdUnsafeCharacters),
            "must reject hostile node id: {hostile:?}"
        );
    }
}

#[test]
fn node_id_accepts_real_world_shapes() {
    let max = DEFAULT_XDS_MAX_NODE_ID_BYTES;
    for valid in [
        "ferrum-mesh-node",
        "reviews-v1-5c9d8f7b6d-abcde",
        "sidecar~10.0.0.1~reviews-v1.default~default.svc.cluster.local",
        "spiffe://cluster.local/ns/default/sa/reviews",
        "node_1.example.com:15010",
    ] {
        assert!(
            validate_node_id(valid, max).is_ok(),
            "must accept real-world node id: {valid}"
        );
    }
}

#[test]
fn zero_max_node_id_bytes_disables_only_the_length_rule() {
    assert!(validate_node_id(&"a".repeat(10_000), 0).is_ok());
    assert_eq!(
        validate_node_id("bad\nid", 0),
        Err(XdsAdmissionRejection::NodeIdUnsafeCharacters),
        "disabling the length ceiling must not disable the character contract"
    );
    assert_eq!(
        validate_node_id("", 0),
        Err(XdsAdmissionRejection::NodeIdEmpty)
    );
}

// ── Principal isolation ────────────────────────────────────────────────────

#[test]
fn unrelated_principals_do_not_alias_one_state_key() {
    let alice = principal_key("spiffe://cluster.local/ns/default/sa/alice");
    let bob = principal_key("spiffe://cluster.local/ns/default/sa/bob");
    assert_ne!(alice, bob);

    // Same namespace, same client-chosen Node.id, different principals.
    let alice_key = xds_state_key("ferrum", &alice, "shared-node-id");
    let bob_key = xds_state_key("ferrum", &bob, "shared-node-id");
    assert_ne!(
        alice_key, bob_key,
        "two principals must never share one mutable xDS state key"
    );
    assert!(
        alice_key.contains(&alice) && !alice_key.contains("sa/alice"),
        "the state key carries the full-width principal digest, never the raw \
         authenticated subject"
    );

    // And the per-node quota is therefore separate too.
    let controller = controller(XdsAdmissionLimits {
        max_streams_per_node: 1,
        ..generous()
    });
    let mut alice_permit = controller.reserve_stream("ferrum", &alice).unwrap();
    let mut bob_permit = controller.reserve_stream("ferrum", &bob).unwrap();
    assert!(alice_permit.register_node(&alice_key).is_ok());
    assert!(
        bob_permit.register_node(&bob_key).is_ok(),
        "one principal must not exhaust another principal's per-node quota"
    );
}

#[test]
fn state_keys_partition_by_namespace_and_resist_delimiter_forgery() {
    let principal = principal_key("dp");
    assert_ne!(
        xds_state_key("tenant-a", &principal, "node"),
        xds_state_key("tenant-b", &principal, "node")
    );
    // Length prefixes stop a crafted namespace/node pair from colliding with
    // another tenant's key.
    assert_ne!(
        xds_state_key("a", &principal, "b:node"),
        xds_state_key("a:b", &principal, "node")
    );
    assert_ne!(
        xds_state_key("ab", &principal, "node"),
        xds_state_key("a", &principal, "bnode")
    );
}

/// Full SHA-256, hex encoded. A principal key is a state-key and quota
/// boundary, so it is deliberately NOT truncated.
const PRINCIPAL_KEY_HEX_LEN: usize = 64;
/// A redacted log identifier only has to correlate occurrences, so it stays
/// short — and must never be mistaken for a principal key.
const LOG_IDENTIFIER_HEX_LEN: usize = 16;

#[test]
fn principal_key_is_stable_non_reversible_and_full_width() {
    let subject = "spiffe://cluster.local/ns/default/sa/reviews";
    let key = principal_key(subject);
    assert_eq!(key, principal_key(subject), "stable for one subject");
    assert_eq!(
        key.len(),
        PRINCIPAL_KEY_HEX_LEN,
        "a principal key must be the FULL SHA-256 digest: it keys mutable \
         per-principal state and quota, so a truncated digest would give an \
         attacker choosing its own JWT subject a tractable collision target"
    );
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        !key.contains("spiffe") && !key.contains("reviews"),
        "the raw subject must never appear in a stored key"
    );
    assert_ne!(
        key,
        principal_key("spiffe://cluster.local/ns/default/sa/ratings"),
        "distinct subjects must get distinct keys"
    );
    // A hostile, oversized subject still yields the same bounded width.
    assert_eq!(
        principal_key(&"x".repeat(1_000_000)).len(),
        PRINCIPAL_KEY_HEX_LEN
    );
}

#[test]
fn redacted_identifier_never_echoes_the_raw_value() {
    let hostile = "node\n\rINJECTED-LOG-LINE\u{202e}";
    let redacted = redacted_identifier(hostile);
    assert_eq!(redacted.len(), LOG_IDENTIFIER_HEX_LEN);
    assert!(redacted.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!redacted.contains("INJECTED"));
    assert_eq!(redacted, redacted_identifier(hostile), "stable per value");
    assert_ne!(redacted, redacted_identifier("node"));
}

#[test]
fn log_identifiers_and_principal_keys_are_separate_domains() {
    // Same input text, two purposes: the digests must not be interchangeable.
    let value = "same";
    let log_id = redacted_identifier(value);
    let key = principal_key(value);
    assert_ne!(log_id, key, "the two digests are domain-separated");
    assert!(
        log_id.len() < key.len(),
        "the log identifier is the SHORT digest; the principal key is full width"
    );
    // The log identifier must not be a prefix of the principal key either: a
    // shared hash domain would make a leaked log field a partial state key.
    assert!(
        !key.starts_with(&log_id),
        "a log identifier must never be a truncation of the principal key"
    );
}

// ── Rejection surface ──────────────────────────────────────────────────────

#[test]
fn rejection_reasons_are_fixed_cardinality_and_leak_nothing() {
    let all = [
        XdsAdmissionRejection::TotalStreams,
        XdsAdmissionRejection::NamespaceStreams,
        XdsAdmissionRejection::PrincipalStreams,
        XdsAdmissionRejection::NodeStreams,
        XdsAdmissionRejection::NodeCardinality,
        XdsAdmissionRejection::NodeIdEmpty,
        XdsAdmissionRejection::NodeIdTooLong,
        XdsAdmissionRejection::NodeIdUnsafeCharacters,
        XdsAdmissionRejection::FirstRequestTimeout,
    ];
    let reasons: HashSet<&'static str> = all.iter().map(|r| r.metric_reason()).collect();
    assert_eq!(reasons.len(), all.len(), "reason labels must be distinct");
    for reason in &reasons {
        let plain = reason.chars().all(|c| c.is_ascii_lowercase() || c == '_');
        assert!(
            plain,
            "metric label must be a plain snake_case constant: {reason}"
        );
    }
    for rejection in all {
        let status = rejection.into_status();
        let expected = if rejection.is_capacity() {
            tonic::Code::ResourceExhausted
        } else if rejection == XdsAdmissionRejection::FirstRequestTimeout {
            tonic::Code::DeadlineExceeded
        } else {
            tonic::Code::InvalidArgument
        };
        assert_eq!(status.code(), expected, "unexpected code for {rejection:?}");
        assert!(!status.message().is_empty());
    }
}

// ── Forced task cancellation ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn aborting_a_permit_holding_task_returns_the_controller_to_baseline() {
    // The ADS relay task owns its permit. `JoinHandle::abort()` unwinds the
    // task's locals, so the permit's `Drop` is still the single release path —
    // no cancellation-specific cleanup exists or is needed.
    let controller = controller(XdsAdmissionLimits {
        max_total_streams: 2,
        ..generous()
    });
    let principal = principal_key("dp");

    let task_controller = controller.clone();
    let task_principal = principal.clone();
    let handle = tokio::spawn(async move {
        let mut permit = task_controller
            .reserve_stream("ferrum", &task_principal)
            .expect("capacity available");
        permit.register_node("node-a").expect("node admitted");
        // Park forever; only cancellation ends this task.
        std::future::pending::<()>().await;
    });

    let admitted = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if controller.active_streams() == 1 && controller.active_nodes() == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(admitted.is_ok(), "the spawned task should have reserved");

    handle.abort();
    let _ = handle.await;

    let released = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if controller.active_streams() == 0 && controller.active_nodes() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "an aborted task must release its permit: streams={} nodes={}",
        controller.active_streams(),
        controller.active_nodes()
    );
    assert_eq!(controller.tracked_namespaces(), 0);
    assert_eq!(controller.tracked_principals(), 0);

    // The freed capacity is genuinely reusable.
    let _reused = controller
        .reserve_stream("ferrum", &principal)
        .expect("capacity is available again");
}
