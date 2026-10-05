//! Exact admission/ownership tests for the staged terminal primitives.
//! These do not stand in for terminal-runner or real-socket acceptance tests.

use ferrum_edge::plugins::terminal_preparation::{
    CARRIER_BYTES, CARRIER_OVERHEAD_BYTES, CARRIER_OWNED_BYTES, CONTROL_BYTES, MAX_PARTICIPANTS,
    PROCESS_BYTES, PreparationLedger, PreparationUsage, REQUEST_TICKETS, ROOT_BYTES, SLOT_BYTES,
    TerminalBounds, TerminalDeclaration, TerminalEligibility, TerminalFacts, TerminalInstanceToken,
    TerminalManifest, TerminalManifestEntry, TerminalRefusal, WORKSPACE_BYTES, WRAPPER_BYTES,
};
use ferrum_edge::plugins::{Plugin, RequestContext};
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

use super::response_coalescing_allocation_tests::measure;

fn entry(id: u64, declaration: TerminalDeclaration) -> TerminalManifestEntry {
    TerminalManifestEntry {
        instance: TerminalInstanceToken(id),
        declaration,
        eligibility: TerminalEligibility {
            rejection: true,
            charged: true,
        },
        wrapped: false,
    }
}

fn prepared(bounds: TerminalBounds) -> TerminalDeclaration {
    TerminalDeclaration::Prepared {
        bounds,
        prep_reads: TerminalFacts::NONE,
        prep_writes: TerminalFacts::NONE,
        trigger_reads: TerminalFacts::NONE,
        cursor_writes: TerminalFacts::NONE,
    }
}

fn zero_usage() -> PreparationUsage {
    PreparationUsage {
        bytes: 0,
        tickets: 0,
    }
}

#[test]
fn empty_union_allocates_nothing_and_opens_no_ticket() {
    let ledger = PreparationLedger::new();
    let manifest = TerminalManifest::new();
    let (allocation, admitted) = measure(|| manifest.admit(&ledger));
    assert_eq!(allocation, (0, 0));
    assert!(admitted.unwrap().is_none());
    assert_eq!(ledger.usage(), zero_usage());
}

#[test]
fn manifest_counts_charged_default_false_and_every_noop_slot() {
    let mut manifest = TerminalManifest::new();
    for id in 0..MAX_PARTICIPANTS as u64 {
        let mut participant = entry(id, TerminalDeclaration::PureNoop);
        participant.eligibility.rejection = false;
        participant.wrapped = true;
        manifest.push(participant).unwrap();
    }
    assert_eq!(manifest.participant_count(), MAX_PARTICIPANTS);
    let expected = ROOT_BYTES
        + CARRIER_BYTES
        + MAX_PARTICIPANTS * (SLOT_BYTES + TerminalBounds::PURE_NOOP.control + WRAPPER_BYTES);
    assert_eq!(manifest.control_bytes(), expected);
    assert_eq!(manifest.workspace_bytes(), 0);
    let refused = manifest
        .push(entry(64, TerminalDeclaration::PureNoop))
        .unwrap_err();
    assert_eq!(refused.reason, TerminalRefusal::TooManyParticipants);
    assert_eq!(refused.required, 65);
    assert_eq!(refused.allowed, 64);
    assert_eq!(manifest.participant_count(), 64);
}

#[test]
fn statically_ineligible_rows_do_not_enroll_even_when_undeclared() {
    let mut manifest = TerminalManifest::new();
    let mut participant = entry(0, TerminalDeclaration::Undeclared);
    participant.eligibility = TerminalEligibility {
        rejection: false,
        charged: false,
    };
    manifest.push(participant).unwrap();
    assert_eq!(manifest.participant_count(), 0);
    assert_eq!(manifest.control_bytes(), 0);
}

#[test]
fn exact_control_limit_one_byte_beyond_and_overflow_refuse_atomically() {
    let mut manifest = TerminalManifest::new();
    let bounds = TerminalBounds {
        control: CONTROL_BYTES - ROOT_BYTES - CARRIER_BYTES - SLOT_BYTES,
        output: 0,
        workspace: 0,
    };
    manifest.push(entry(1, prepared(bounds))).unwrap();
    assert_eq!(manifest.control_bytes(), CONTROL_BYTES);

    let mut beyond = TerminalManifest::new();
    let refused = beyond
        .push(entry(
            1,
            prepared(TerminalBounds {
                control: bounds.control + 1,
                ..bounds
            }),
        ))
        .unwrap_err();
    assert_eq!(refused.reason, TerminalRefusal::ControlCapacity);
    assert_eq!(refused.required, CONTROL_BYTES + 4096);
    assert_eq!(beyond.participant_count(), 0);
    assert_eq!(beyond.control_bytes(), 0);

    let mut overflowing = TerminalManifest::new();
    let refused = overflowing
        .push(entry(
            1,
            prepared(TerminalBounds {
                control: usize::MAX,
                output: 1,
                workspace: 0,
            }),
        ))
        .unwrap_err();
    assert_eq!(refused.reason, TerminalRefusal::ArithmeticOverflow);
    assert_eq!(overflowing.participant_count(), 0);
}

#[test]
fn a_rejected_manifest_cannot_admit_a_prefix_that_omits_the_bad_participant() {
    let ledger = PreparationLedger::new();
    let mut manifest = TerminalManifest::new();
    manifest.push(entry(1, TerminalDeclaration::PureNoop)).unwrap();
    let first = manifest
        .push(entry(2, TerminalDeclaration::Undeclared))
        .unwrap_err();
    assert_eq!(first.reason, TerminalRefusal::Undeclared);
    let (allocation, refused) = measure(|| manifest.admit(&ledger));
    assert_eq!(allocation, (0, 0));
    assert_eq!(refused.unwrap_err(), first);
    assert_eq!(
        manifest
            .push(entry(3, TerminalDeclaration::PureNoop))
            .unwrap_err(),
        first
    );
    assert_eq!(ledger.usage(), zero_usage());
}

#[test]
fn audits_reuse_maximum_workspace_and_excess_refuses_before_admission() {
    let mut manifest = TerminalManifest::new();
    let audit = TerminalBounds {
        control: 8192,
        output: 8192,
        workspace: WORKSPACE_BYTES,
    };
    manifest.push(entry(1, prepared(audit))).unwrap();
    manifest.push(entry(2, prepared(audit))).unwrap();
    assert_eq!(manifest.workspace_bytes(), WORKSPACE_BYTES);
    let before = manifest.control_bytes();
    let refused = manifest
        .push(entry(
            3,
            prepared(TerminalBounds {
                workspace: WORKSPACE_BYTES + 1,
                ..audit
            }),
        ))
        .unwrap_err();
    assert_eq!(refused.reason, TerminalRefusal::WorkspaceCapacity);
    assert_eq!(manifest.control_bytes(), before);
    assert_eq!(manifest.participant_count(), 2);
}

#[test]
fn workspace_rounding_and_duplicate_instance_refusal_preserve_candidate() {
    let mut manifest = TerminalManifest::new();
    let declaration = prepared(TerminalBounds {
        control: 1024,
        output: 1024,
        workspace: 1,
    });
    manifest.push(entry(7, declaration)).unwrap();
    assert_eq!(manifest.workspace_bytes(), 4096);
    let before = manifest.control_bytes();
    let refused = manifest.push(entry(7, declaration)).unwrap_err();
    assert_eq!(refused.reason, TerminalRefusal::DuplicateInstance);
    assert_eq!(manifest.control_bytes(), before);
    assert_eq!(manifest.participant_count(), 1);
}

#[test]
fn two_maximum_transaction_debugger_declarations_exceed_control_capacity() {
    let mut manifest = TerminalManifest::new();
    let declaration = prepared(TerminalBounds {
        control: 16_384,
        output: 1_048_576,
        workspace: 0,
    });
    manifest.push(entry(1, declaration)).unwrap();
    assert_eq!(
        manifest.push(entry(2, declaration)).unwrap_err().reason,
        TerminalRefusal::ControlCapacity
    );
}

#[test]
fn cursor_only_results_cannot_supply_later_preparation_or_trigger_facts() {
    for trigger in [false, true] {
        let mut manifest = TerminalManifest::new();
        manifest
            .push(entry(
                1,
                TerminalDeclaration::Prepared {
                    bounds: TerminalBounds::CUSTOM_STARTER,
                    prep_reads: TerminalFacts::NONE,
                    prep_writes: TerminalFacts::NONE,
                    trigger_reads: TerminalFacts::NONE,
                    cursor_writes: TerminalFacts::ACCOUNTING,
                },
            ))
            .unwrap();
        let refused = manifest
            .push(entry(
                2,
                TerminalDeclaration::Prepared {
                    bounds: TerminalBounds::CUSTOM_STARTER,
                    prep_reads: if trigger {
                        TerminalFacts::NONE
                    } else {
                        TerminalFacts::ACCOUNTING
                    },
                    prep_writes: TerminalFacts::NONE,
                    trigger_reads: if trigger {
                        TerminalFacts::ACCOUNTING
                    } else {
                        TerminalFacts::NONE
                    },
                    cursor_writes: TerminalFacts::NONE,
                },
            ))
            .unwrap_err();
        assert_eq!(refused.reason, TerminalRefusal::CursorDependency);
        assert_eq!(refused.instance, Some(TerminalInstanceToken(2)));
        assert_eq!(manifest.participant_count(), 1);
    }
}

#[test]
fn request_facts_cannot_be_written_after_suspension() {
    for fact in [
        TerminalFacts::BODY,
        TerminalFacts::METHOD,
        TerminalFacts::REQUEST_HEADERS,
        TerminalFacts::IDENTITY,
        TerminalFacts::PATH,
        TerminalFacts::ENROLLMENT,
        TerminalFacts::TRIGGER,
        TerminalFacts::PROVIDER_USAGE,
    ] {
        let mut manifest = TerminalManifest::new();
        let refused = manifest
            .push(entry(
                1,
                TerminalDeclaration::Prepared {
                    bounds: TerminalBounds::CUSTOM_STARTER,
                    prep_reads: TerminalFacts::NONE,
                    prep_writes: TerminalFacts::NONE,
                    trigger_reads: TerminalFacts::NONE,
                    cursor_writes: fact,
                },
            ))
            .unwrap_err();
        assert_eq!(refused.reason, TerminalRefusal::PreparationWriteAfterSuspension);
        assert_eq!(manifest.participant_count(), 0);
    }
}

#[test]
fn response_scope_is_a_cursor_input_and_cannot_be_predecided() {
    for response_fact in [TerminalFacts::RESPONSE_STATUS, TerminalFacts::RESPONSE_HEADERS] {
        let mut manifest = TerminalManifest::new();
        let refused = manifest
            .push(entry(
                1,
                TerminalDeclaration::Prepared {
                    bounds: TerminalBounds::CUSTOM_STARTER,
                    prep_reads: response_fact,
                    prep_writes: TerminalFacts::NONE,
                    trigger_reads: TerminalFacts::NONE,
                    cursor_writes: TerminalFacts::NONE,
                },
            ))
            .unwrap_err();
        assert_eq!(refused.reason, TerminalRefusal::ResponseReadDuringPreparation);
    }
}

#[test]
fn process_byte_failure_allocates_nothing_and_leaks_no_ticket() {
    let ledger = PreparationLedger::new();
    let owners: Vec<_> = (0..PROCESS_BYTES / CONTROL_BYTES)
        .map(|_| ledger.reserve_control(CONTROL_BYTES).unwrap())
        .collect();
    let before = ledger.usage();
    assert_eq!(before.bytes, PROCESS_BYTES);
    let (allocation, refused) = measure(|| ledger.reserve_control(ROOT_BYTES));
    assert_eq!(allocation, (0, 0));
    assert_eq!(refused.unwrap_err().reason, TerminalRefusal::ProcessCapacity);
    assert_eq!(ledger.usage(), before);
    drop(owners);
    assert_eq!(ledger.usage(), zero_usage());
}

#[test]
fn ticket_1025_refuses_under_small_control_carriers_and_returns_every_lease() {
    let ledger = PreparationLedger::new();
    let owners: Vec<_> = (0..REQUEST_TICKETS)
        .map(|_| ledger.reserve_control(ROOT_BYTES).unwrap())
        .collect();
    assert_eq!(ledger.usage().tickets, REQUEST_TICKETS);
    assert!(ledger.usage().bytes < PROCESS_BYTES);
    let before = ledger.usage();
    let (allocation, refused) = measure(|| ledger.reserve_control(ROOT_BYTES));
    assert_eq!(allocation, (0, 0));
    let refused = refused.unwrap_err();
    assert_eq!(refused.reason, TerminalRefusal::TicketCapacity);
    assert_eq!(refused.required, 1025);
    assert_eq!(refused.allowed, 1024);
    assert_eq!(ledger.usage(), before);
    drop(owners);
    assert_eq!(ledger.usage(), zero_usage());
}

#[test]
fn cloned_detached_owners_share_one_ticket_until_the_last_owner_drops() {
    let ledger = PreparationLedger::new();
    let control = Arc::new(ledger.reserve_control(ROOT_BYTES).unwrap());
    let cleanup = Arc::clone(&control);
    let retry = Arc::clone(&control);
    assert_eq!(ledger.usage().tickets, 1);
    drop(control);
    drop(retry);
    assert_eq!(ledger.usage().tickets, 1);
    drop(cleanup);
    assert_eq!(ledger.usage(), zero_usage());
}

#[test]
fn synchronous_workspace_returns_before_control_cleanup_and_can_be_reused() {
    let ledger = PreparationLedger::new();
    let control = ledger.reserve_control(CONTROL_BYTES).unwrap();
    let (allocation, workspace) = measure(|| control.workspace(WORKSPACE_BYTES));
    assert_eq!(allocation, (0, 0), "workspace credit is not an eager buffer");
    let workspace = workspace.unwrap();
    assert_eq!(workspace.bytes(), WORKSPACE_BYTES);
    assert_eq!(ledger.usage().bytes, CONTROL_BYTES + WORKSPACE_BYTES);
    assert_eq!(ledger.usage().tickets, 1);
    assert_eq!(
        control.workspace(ROOT_BYTES).unwrap_err().reason,
        TerminalRefusal::WorkspaceAlreadyBorrowed
    );
    drop(workspace);
    assert_eq!(ledger.usage().bytes, CONTROL_BYTES);
    let next = control.workspace(WORKSPACE_BYTES).unwrap();
    drop(next);
    drop(control);
    assert_eq!(ledger.usage(), zero_usage());
}

#[test]
fn fourth_maximum_workspace_refuses_then_recovers_without_another_ticket() {
    let ledger = PreparationLedger::new();
    let controls: Vec<_> = (0..4)
        .map(|_| ledger.reserve_control(CONTROL_BYTES).unwrap())
        .collect();
    let mut workspaces: Vec<_> = controls[..3]
        .iter()
        .map(|control| control.workspace(WORKSPACE_BYTES).unwrap())
        .collect();
    let before = ledger.usage();
    let (allocation, refused) = measure(|| controls[3].workspace(WORKSPACE_BYTES));
    assert_eq!(allocation, (0, 0));
    assert_eq!(refused.unwrap_err().reason, TerminalRefusal::ProcessCapacity);
    assert_eq!(ledger.usage(), before);
    drop(workspaces.pop());
    let fourth = controls[3].workspace(WORKSPACE_BYTES).unwrap();
    assert_eq!(ledger.usage().tickets, 4);
    drop(fourth);
    drop(workspaces);
    drop(controls);
    assert_eq!(ledger.usage(), zero_usage());
}

#[test]
fn zero_and_unrounded_control_are_refused_and_workspace_zero_is_finite_noop() {
    let ledger = PreparationLedger::new();
    assert_eq!(
        ledger.reserve_control(0).unwrap_err().reason,
        TerminalRefusal::ControlCapacity
    );
    assert_eq!(
        ledger.reserve_control(ROOT_BYTES + 1).unwrap_err().reason,
        TerminalRefusal::UnroundedReservation
    );
    assert_eq!(
        ledger.reserve_control(CONTROL_BYTES + 4096).unwrap_err().reason,
        TerminalRefusal::ControlCapacity
    );
    assert_eq!(ledger.usage(), zero_usage());
    let control = ledger.reserve_control(ROOT_BYTES).unwrap();
    assert_eq!(
        control.workspace(WORKSPACE_BYTES + 4096).unwrap_err().reason,
        TerminalRefusal::WorkspaceCapacity
    );
    let empty = control.workspace(0).unwrap();
    assert_eq!(empty.bytes(), 0);
    assert_eq!(ledger.usage().bytes, ROOT_BYTES);
    drop(empty);
    drop(control);
    assert_eq!(ledger.usage(), zero_usage());
}

#[test]
fn concurrent_admission_cannot_overbook_combined_byte_ticket_state() {
    let ledger = PreparationLedger::new();
    let barrier = Barrier::new(8);
    let owners = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..8 {
            let ledger = &ledger;
            let barrier = &barrier;
            workers.push(scope.spawn(move || {
                barrier.wait();
                let mut admitted = Vec::new();
                for _ in 0..16 {
                    match ledger.reserve_control(CONTROL_BYTES) {
                        Ok(owner) => admitted.push(owner),
                        Err(error) => assert_eq!(error.reason, TerminalRefusal::ProcessCapacity),
                    }
                }
                admitted
            }));
        }
        let mut owners = Vec::new();
        for worker in workers {
            owners.extend(worker.join().unwrap());
        }
        owners
    });
    assert_eq!(owners.len(), 64);
    assert_eq!(ledger.usage().bytes, PROCESS_BYTES);
    assert_eq!(ledger.usage().tickets, 64);
    drop(owners);
    assert_eq!(ledger.usage(), zero_usage());
}

#[async_trait::async_trait]
impl Plugin for SpoofedBuiltin {
    fn name(&self) -> &str {
        "security_headers"
    }

    fn priority(&self) -> u16 {
        1
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _status: u16,
        _headers: &mut HashMap<String, String>,
    ) -> ferrum_edge::plugins::PluginResult {
        std::future::ready(()).await;
        ferrum_edge::plugins::PluginResult::Continue
    }
}

struct SpoofedBuiltin;

struct InheritedNoop;

impl Plugin for InheritedNoop {
    fn name(&self) -> &str {
        "custom_inherited_noop"
    }

    fn priority(&self) -> u16 {
        1
    }
}

#[test]
fn inherited_noop_custom_hook_still_needs_an_explicit_declaration() {
    let plugin = InheritedNoop;
    assert_eq!(plugin.terminal_declaration(), TerminalDeclaration::Undeclared);
    let mut manifest = TerminalManifest::new();
    let mut participant = entry(1, plugin.terminal_declaration());
    participant.eligibility.rejection = false;
    assert_eq!(
        manifest.push(participant).unwrap_err().reason,
        TerminalRefusal::Undeclared
    );
}

#[test]
fn default_declaration_does_not_trust_an_overridden_hook_or_builtin_name() {
    let plugin = SpoofedBuiltin;
    assert_eq!(plugin.terminal_declaration(), TerminalDeclaration::Undeclared);
    let mut manifest = TerminalManifest::new();
    assert_eq!(
        manifest
            .push(entry(1, plugin.terminal_declaration()))
            .unwrap_err()
            .reason,
        TerminalRefusal::Undeclared
    );
}

#[test]
fn one_participant_reserves_one_carrier_and_returns_it_with_the_ticket() {
    let mut manifest = TerminalManifest::new();
    manifest.push(entry(1, TerminalDeclaration::PureNoop)).unwrap();
    let ledger = PreparationLedger::new();
    let owner = manifest.admit(&ledger).unwrap().unwrap();
    assert_eq!(CARRIER_BYTES, CARRIER_OWNED_BYTES + CARRIER_OVERHEAD_BYTES);
    assert_eq!(owner.bytes(), 139_264);
    assert_eq!(ledger.usage().bytes, 139_264);
    assert_eq!(ledger.usage().tickets, 1);
    drop(owner);
    assert_eq!(ledger.usage(), zero_usage());
}

#[test]
fn approved_nine_symbol_bounds_follow_the_checked_sum_and_page_rounding() {
    // OTel, correlation, CORS, security headers, OIDC, response transformer,
    // compression, audit, limiter. The illustrative proposal total differs
    // from its table; this pins the stated algorithm and actual table rows.
    let bounds = [
        (1024, 1024, 0),
        (12_288, 12_288, 0),
        (16_384, 16_384, 0),
        (1024, 65_536, 0),
        (16_384, 16_384, 0),
        (4096, 65_536, 0),
        (4096, 4096, 0),
        (8192, 8192, WORKSPACE_BYTES),
        (262_144, 8192, 0),
    ];
    for (wrapped, expected_control) in [(false, 648 * 1024), (true, 652 * 1024)] {
        let mut manifest = TerminalManifest::new();
        for (id, (control, output, workspace)) in bounds.into_iter().enumerate() {
            let mut participant = entry(
                id as u64,
                prepared(TerminalBounds {
                    control,
                    output,
                    workspace,
                }),
            );
            participant.wrapped = wrapped;
            manifest.push(participant).unwrap();
        }
        assert_eq!(manifest.participant_count(), 9);
        assert_eq!(manifest.control_bytes(), expected_control);
        assert_eq!(manifest.workspace_bytes(), WORKSPACE_BYTES);
    }
}

#[test]
fn explicit_noop_inventory_has_no_after_proxy_override() {
    let sources = [
        (
            "custom_plugins/examples/example_audit_plugin.rs",
            include_str!("../../../custom_plugins/examples/example_audit_plugin.rs"),
        ),
        (
            "src/plugins/access_control.rs",
            include_str!("../../../src/plugins/access_control.rs"),
        ),
        (
            "src/plugins/adaptive_concurrency.rs",
            include_str!("../../../src/plugins/adaptive_concurrency.rs"),
        ),
        (
            "src/plugins/ai_prompt_compressor.rs",
            include_str!("../../../src/plugins/ai_prompt_compressor.rs"),
        ),
        (
            "src/plugins/ai_prompt_shield.rs",
            include_str!("../../../src/plugins/ai_prompt_shield.rs"),
        ),
        (
            "src/plugins/ai_request_guard.rs",
            include_str!("../../../src/plugins/ai_request_guard.rs"),
        ),
        (
            "src/plugins/ai_semantic_firewall.rs",
            include_str!("../../../src/plugins/ai_semantic_firewall.rs"),
        ),
        (
            "src/plugins/ai_token_metrics.rs",
            include_str!("../../../src/plugins/ai_token_metrics.rs"),
        ),
        (
            "src/plugins/ai_tool_governor.rs",
            include_str!("../../../src/plugins/ai_tool_governor.rs"),
        ),
        (
            "src/plugins/api_chargeback.rs",
            include_str!("../../../src/plugins/api_chargeback.rs"),
        ),
        (
            "src/plugins/api_chargeback_sink.rs",
            include_str!("../../../src/plugins/api_chargeback_sink.rs"),
        ),
        (
            "src/plugins/bot_detection.rs",
            include_str!("../../../src/plugins/bot_detection.rs"),
        ),
        (
            "src/plugins/fault_injection.rs",
            include_str!("../../../src/plugins/fault_injection.rs"),
        ),
        (
            "src/plugins/geo_restriction.rs",
            include_str!("../../../src/plugins/geo_restriction.rs"),
        ),
        (
            "src/plugins/graphql.rs",
            include_str!("../../../src/plugins/graphql.rs"),
        ),
        (
            "src/plugins/grpc_deadline.rs",
            include_str!("../../../src/plugins/grpc_deadline.rs"),
        ),
        (
            "src/plugins/grpc_method_router.rs",
            include_str!("../../../src/plugins/grpc_method_router.rs"),
        ),
        (
            "src/plugins/http_logging.rs",
            include_str!("../../../src/plugins/http_logging.rs"),
        ),
        (
            "src/plugins/ip_restriction.rs",
            include_str!("../../../src/plugins/ip_restriction.rs"),
        ),
        (
            "src/plugins/jwks_auth.rs",
            include_str!("../../../src/plugins/jwks_auth.rs"),
        ),
        (
            "src/plugins/kafka_logging.rs",
            include_str!("../../../src/plugins/kafka_logging.rs"),
        ),
        (
            "src/plugins/load_testing.rs",
            include_str!("../../../src/plugins/load_testing.rs"),
        ),
        (
            "src/plugins/loki_logging.rs",
            include_str!("../../../src/plugins/loki_logging.rs"),
        ),
        (
            "src/plugins/mesh/authz.rs",
            include_str!("../../../src/plugins/mesh/authz.rs"),
        ),
        (
            "src/plugins/mesh/bpf_metrics.rs",
            include_str!("../../../src/plugins/mesh/bpf_metrics.rs"),
        ),
        (
            "src/plugins/mesh/outbound_registry.rs",
            include_str!("../../../src/plugins/mesh/outbound_registry.rs"),
        ),
        (
            "src/plugins/mesh/spiffe_identity.rs",
            include_str!("../../../src/plugins/mesh/spiffe_identity.rs"),
        ),
        (
            "src/plugins/mesh_route_dispatch.rs",
            include_str!("../../../src/plugins/mesh_route_dispatch.rs"),
        ),
        (
            "src/plugins/oauth2_introspection.rs",
            include_str!("../../../src/plugins/oauth2_introspection.rs"),
        ),
        (
            "src/plugins/opa.rs",
            include_str!("../../../src/plugins/opa.rs"),
        ),
        (
            "src/plugins/prometheus_metrics.rs",
            include_str!("../../../src/plugins/prometheus_metrics.rs"),
        ),
        (
            "src/plugins/proxy_alerts/mod.rs",
            include_str!("../../../src/plugins/proxy_alerts/mod.rs"),
        ),
        (
            "src/plugins/request_deduplication.rs",
            include_str!("../../../src/plugins/request_deduplication.rs"),
        ),
        (
            "src/plugins/request_mirror.rs",
            include_str!("../../../src/plugins/request_mirror.rs"),
        ),
        (
            "src/plugins/request_size_limiting.rs",
            include_str!("../../../src/plugins/request_size_limiting.rs"),
        ),
        (
            "src/plugins/request_termination.rs",
            include_str!("../../../src/plugins/request_termination.rs"),
        ),
        (
            "src/plugins/request_transformer.rs",
            include_str!("../../../src/plugins/request_transformer.rs"),
        ),
        (
            "src/plugins/response_mock.rs",
            include_str!("../../../src/plugins/response_mock.rs"),
        ),
        (
            "src/plugins/serverless_function.rs",
            include_str!("../../../src/plugins/serverless_function.rs"),
        ),
        (
            "src/plugins/soap_ws_security.rs",
            include_str!("../../../src/plugins/soap_ws_security.rs"),
        ),
        (
            "src/plugins/statsd_logging.rs",
            include_str!("../../../src/plugins/statsd_logging.rs"),
        ),
        (
            "src/plugins/stdout_logging.rs",
            include_str!("../../../src/plugins/stdout_logging.rs"),
        ),
        (
            "src/plugins/tcp_connection_throttle.rs",
            include_str!("../../../src/plugins/tcp_connection_throttle.rs"),
        ),
        (
            "src/plugins/tcp_logging.rs",
            include_str!("../../../src/plugins/tcp_logging.rs"),
        ),
        (
            "src/plugins/transaction_log_schema.rs",
            include_str!("../../../src/plugins/transaction_log_schema.rs"),
        ),
        (
            "src/plugins/udp_logging.rs",
            include_str!("../../../src/plugins/udp_logging.rs"),
        ),
        (
            "src/plugins/udp_rate_limiting.rs",
            include_str!("../../../src/plugins/udp_rate_limiting.rs"),
        ),
        (
            "src/plugins/utils/auth_flow.rs",
            include_str!("../../../src/plugins/utils/auth_flow.rs"),
        ),
        (
            "src/plugins/waf/websocket.rs",
            include_str!("../../../src/plugins/waf/websocket.rs"),
        ),
        (
            "src/plugins/ws_frame_logging.rs",
            include_str!("../../../src/plugins/ws_frame_logging.rs"),
        ),
        (
            "src/plugins/ws_logging.rs",
            include_str!("../../../src/plugins/ws_logging.rs"),
        ),
        (
            "src/plugins/ws_message_size_limiting.rs",
            include_str!("../../../src/plugins/ws_message_size_limiting.rs"),
        ),
        (
            "src/plugins/ws_rate_limiting.rs",
            include_str!("../../../src/plugins/ws_rate_limiting.rs"),
        ),
    ];
    for (path, source) in sources {
        assert!(
            !source.contains("async fn after_proxy("),
            "a no-op declaration must migrate with an override: {path}"
        );
        assert!(source.contains("fn terminal_declaration("), "{path}");
    }
}

#[test]
fn auth_macro_noop_declaration_is_backed_by_every_current_expansion() {
    let sources = [
        include_str!("../../../src/plugins/mtls_auth.rs"),
        include_str!("../../../src/plugins/jwt_auth.rs"),
        include_str!("../../../src/plugins/key_auth.rs"),
        include_str!("../../../src/plugins/ldap_auth.rs"),
        include_str!("../../../src/plugins/basic_auth.rs"),
        include_str!("../../../src/plugins/hmac_auth.rs"),
    ];
    for source in sources {
        assert!(source.contains("impl_auth_plugin!("));
        assert!(!source.contains("async fn after_proxy("));
    }
}
