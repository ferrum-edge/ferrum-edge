//! Hosted-only fixtures with the binary's actual global allocator. The ordinary
//! unit target deliberately uses System, which cannot adopt jemalloc Strings.

#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(not(windows))]
mod qualified {
    use std::collections::HashMap;
    use std::sync::Arc;

    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::MeshTrafficDirection;
    use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
    use ferrum_edge::plugins::rate_limiting::RateLimiting;
    use ferrum_edge::plugins::terminal_preparation::{
        CONTROL_BYTES, MAX_FIELD_OCCURRENCES, PROCESS_BYTES, PreparationLedger,
        PreparedTerminalChain, PreparedTerminalOp, REQUEST_TICKETS, ROOT_BYTES,
        SelectedTerminalCarrier, TerminalAdmissionError, TerminalDeclaration, TerminalFieldLineage,
        TerminalFieldOrigin, TerminalFieldSection, TerminalRefusal, TerminalResult,
        compile_terminal_manifest, field_declaration, validate_terminal_headers,
    };
    use ferrum_edge::plugins::terminal_storage::{AllocationPlan, TerminalTicket};
    use ferrum_edge::plugins::{Plugin, PluginHttpClient, RequestContext};
    use serde_json::json;

    fn allocator_profile() {
        // SAFETY: this test binary installs the same locked jemalloc above.
        // Registration never changes an allocator and is idempotent.
        unsafe { ferrum_edge::plugins::terminal_storage::register_global_jemalloc() };
    }

    fn ledger() -> &'static PreparationLedger {
        Box::leak(Box::new(PreparationLedger::new()))
    }

    fn context() -> RequestContext {
        RequestContext::new("127.0.0.1".into(), "POST".into(), "/terminal".into())
    }

    fn pin(plugins: &[Arc<dyn Plugin>], ctx: &mut RequestContext) {
        Arc::new(compile_terminal_manifest(plugins).unwrap())
            .pin(ctx)
            .unwrap();
    }

    fn backend() -> TerminalFieldLineage {
        TerminalFieldLineage {
            origin: TerminalFieldOrigin::Backend,
            policy_contribution: false,
            section: TerminalFieldSection::Initial,
            epoch: 0,
        }
    }

    struct Fields {
        values: Vec<(&'static str, String)>,
        override_existing: bool,
    }

    #[async_trait::async_trait]
    impl Plugin for Fields {
        fn name(&self) -> &str {
            "fixture_fields"
        }

        fn priority(&self) -> u16 {
            1
        }

        fn applies_after_proxy_on_reject(&self) -> bool {
            true
        }

        fn terminal_declaration(&self) -> TerminalDeclaration {
            field_declaration(1024, 65_536)
        }

        fn terminal_preparation_available(&self) -> bool {
            true
        }

        fn prepare_terminal(
            &self,
            view: &mut ferrum_edge::plugins::terminal_preparation::ReachedRequestView<'_>,
        ) -> Result<PreparedTerminalOp, TerminalAdmissionError> {
            let mut patch = view.patch(self.values.len())?;
            for (name, value) in &self.values {
                patch.set_policy(name, value, self.override_existing)?;
            }
            Ok(PreparedTerminalOp::Fields(patch))
        }
    }

    struct Noop;

    struct Cookie {
        key: &'static str,
    }

    struct Replay {
        operation: std::sync::Mutex<Option<PreparedTerminalOp>>,
    }

    #[async_trait::async_trait]
    impl Plugin for Replay {
        fn name(&self) -> &str {
            "fixture_replay"
        }

        fn priority(&self) -> u16 {
            1
        }

        fn applies_after_proxy_on_reject(&self) -> bool {
            true
        }

        fn terminal_declaration(&self) -> TerminalDeclaration {
            field_declaration(1024, 65_536)
        }

        fn terminal_preparation_available(&self) -> bool {
            true
        }

        fn prepare_terminal(
            &self,
            _view: &mut ferrum_edge::plugins::terminal_preparation::ReachedRequestView<'_>,
        ) -> Result<PreparedTerminalOp, TerminalAdmissionError> {
            Ok(self.operation.lock().unwrap().take().unwrap())
        }
    }

    #[async_trait::async_trait]
    impl Plugin for Cookie {
        fn name(&self) -> &str {
            "fixture_cookie"
        }

        fn priority(&self) -> u16 {
            1
        }

        fn applies_after_proxy_on_reject(&self) -> bool {
            true
        }

        fn terminal_declaration(&self) -> TerminalDeclaration {
            field_declaration(16_384, 16_384)
        }

        fn terminal_preparation_available(&self) -> bool {
            true
        }

        fn prepare_terminal(
            &self,
            view: &mut ferrum_edge::plugins::terminal_preparation::ReachedRequestView<'_>,
        ) -> Result<PreparedTerminalOp, TerminalAdmissionError> {
            Ok(view
                .take_cookie_metadata(self.key)?
                .map_or(PreparedTerminalOp::Noop, PreparedTerminalOp::Cookie))
        }
    }

    #[async_trait::async_trait]
    impl Plugin for Noop {
        fn name(&self) -> &str {
            "fixture_noop"
        }

        fn priority(&self) -> u16 {
            1
        }

        fn terminal_declaration(&self) -> TerminalDeclaration {
            TerminalDeclaration::PureNoop
        }
    }

    #[test]
    fn actual_backing_and_ticket_remain_until_the_last_carrier_owner_drops() {
        let ledger = ledger();
        let ticket = ledger.reserve_owned(CONTROL_BYTES).unwrap();
        assert_eq!(
            std::mem::size_of::<TerminalTicket>(),
            std::mem::size_of::<usize>(),
        );
        assert!(ticket.allocated_backing_bytes() > 0);
        let mut carrier = SelectedTerminalCarrier::new(&ticket).unwrap();
        carrier.push("x-owner", b"retained", backend()).unwrap();
        let clone = ticket.clone();
        let backing = ticket.allocated_backing_bytes();
        let deallocated = tikv_jemalloc_ctl::thread::deallocatedp::read().unwrap();
        let before_deallocation = deallocated.get();
        drop(ticket);
        drop(clone);
        assert_eq!(deallocated.get(), before_deallocation);
        assert_eq!(ledger.usage().tickets, 1);
        assert_eq!(carrier.occurrences().next().unwrap().1, b"retained");
        drop(carrier);
        assert_eq!(deallocated.get() - before_deallocation, backing as u64);
        assert_eq!(ledger.usage().bytes, 0);
        assert_eq!(ledger.usage().tickets, 0);
    }

    #[test]
    fn admission_refuses_before_new_backing_at_byte_and_ticket_pressure() {
        let ledger = ledger();
        let owners: Vec<_> = (0..PROCESS_BYTES / CONTROL_BYTES)
            .map(|_| ledger.reserve_owned(CONTROL_BYTES).unwrap())
            .collect();
        assert_eq!(ledger.usage().bytes, PROCESS_BYTES);
        let before = ledger.usage();
        let allocated = tikv_jemalloc_ctl::thread::allocatedp::read().unwrap();
        let before_allocation = allocated.get();
        assert_eq!(
            ledger.reserve_owned(ROOT_BYTES).unwrap_err().reason,
            TerminalRefusal::ProcessCapacity,
        );
        assert_eq!(allocated.get(), before_allocation);
        assert_eq!(ledger.usage(), before);
        drop(owners);
        let owners: Vec<_> = (0..REQUEST_TICKETS)
            .map(|_| ledger.reserve_owned(ROOT_BYTES).unwrap())
            .collect();
        let before = ledger.usage();
        let allocated = tikv_jemalloc_ctl::thread::allocatedp::read().unwrap();
        let before_allocation = allocated.get();
        assert_eq!(
            ledger.reserve_owned(ROOT_BYTES).unwrap_err().reason,
            TerminalRefusal::TicketCapacity,
        );
        assert_eq!(allocated.get(), before_allocation);
        assert_eq!(ledger.usage(), before);
        drop(owners);
        assert_eq!(ledger.usage().bytes, 0);
    }

    #[test]
    fn a_carrier_claim_refuses_before_native_allocation_and_preserves_the_ticket() {
        let ledger = ledger();
        let ticket = ledger.reserve_owned(ROOT_BYTES).unwrap();
        let before = ledger.usage();
        let allocated = tikv_jemalloc_ctl::thread::allocatedp::read().unwrap();
        let before_allocation = allocated.get();
        assert!(SelectedTerminalCarrier::new(&ticket).is_err());
        assert_eq!(allocated.get(), before_allocation);
        assert_eq!(ledger.usage(), before);
        drop(ticket);
        assert_eq!(ledger.usage().bytes, 0);
    }

    #[test]
    fn synchronous_workspace_backing_and_credit_end_before_the_next_interval() {
        let ledger = ledger();
        let ticket = ledger.reserve_owned(ROOT_BYTES).unwrap();
        for _ in 0..2 {
            let copied = ticket
                .with_workspace(2048, |workspace| {
                    assert_eq!(ledger.usage().bytes, ROOT_BYTES + 4096);
                    assert_eq!(workspace.len(), 2048);
                    let allocated = tikv_jemalloc_ctl::thread::allocatedp::read().unwrap();
                    let before_allocation = allocated.get();
                    assert_eq!(
                        ticket.workspace(4096).unwrap_err().reason,
                        TerminalRefusal::WorkspaceAlreadyBorrowed,
                    );
                    assert_eq!(allocated.get(), before_allocation);
                    workspace[..4].copy_from_slice(b"fact");
                    Ok(<[u8; 4]>::try_from(&workspace[..4]).unwrap())
                })
                .unwrap();
            assert_eq!(&copied, b"fact");
            assert_eq!(ledger.usage().bytes, ROOT_BYTES);
        }
        drop(ticket);
        assert_eq!(ledger.usage().bytes, 0);
    }

    #[test]
    fn huge_caller_capacity_and_repeated_cookie_values_are_checked_before_copy() {
        let mut oversized = String::with_capacity(131_072);
        oversized.push('x');
        let headers = HashMap::from([("x-small".into(), oversized)]);
        let allocated = tikv_jemalloc_ctl::thread::allocatedp::read().unwrap();
        let before_allocation = allocated.get();
        assert_eq!(
            validate_terminal_headers(&headers).unwrap_err().reason,
            TerminalRefusal::FieldCapacity,
        );
        assert_eq!(allocated.get(), before_allocation);
        let cookies = format!("{}\n{}", "a".repeat(8192), "b".repeat(8192));
        let headers = HashMap::from([("set-cookie".into(), cookies)]);
        assert!(validate_terminal_headers(&headers).is_ok());
    }

    #[test]
    fn a_repeated_actual_instance_cannot_obtain_two_different_instance_nonces() {
        let plugin: Arc<dyn Plugin> = Arc::new(Noop);
        let plugins = [Arc::clone(&plugin), plugin];
        assert_eq!(
            compile_terminal_manifest(&plugins).unwrap_err().reason,
            TerminalRefusal::DuplicateInstance,
        );
    }

    #[test]
    fn a_real_operation_cannot_be_replayed_by_another_configured_producer() {
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(Fields {
            values: vec![("x-owner", "original".into())],
            override_existing: true,
        })];
        let mut ctx = context();
        pin(&plugins, &mut ctx);
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        let operation = chain.next_operation().unwrap();
        drop(chain);
        drop(ctx);
        let replay: Vec<Arc<dyn Plugin>> = vec![Arc::new(Replay {
            operation: std::sync::Mutex::new(Some(operation)),
        })];
        let mut ctx = context();
        pin(&replay, &mut ctx);
        assert!(matches!(
            PreparedTerminalChain::prepare(&replay, &mut ctx, false, false),
            Err(error) if error.reason == TerminalRefusal::PinnedGeneration,
        ));
    }

    #[test]
    fn the_cursor_has_exactly_n_allocated_slots_and_a_small_inline_root() {
        assert!(std::mem::size_of::<PreparedTerminalChain>() <= ROOT_BYTES);
        let mut observed = Vec::new();
        for count in [1, 64] {
            let plugins: Vec<Arc<dyn Plugin>> = (0..count)
                .map(|_| Arc::new(Noop) as Arc<dyn Plugin>)
                .collect();
            let mut ctx = context();
            pin(&plugins, &mut ctx);
            let chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
            observed.push(chain.allocated_backing_bytes());
        }
        let one = AllocationPlan::array::<Option<PreparedTerminalOp>>(1)
            .unwrap()
            .backing_bytes();
        let many = AllocationPlan::array::<Option<PreparedTerminalOp>>(64)
            .unwrap()
            .backing_bytes();
        assert_eq!(observed[1] - observed[0], many - one);
        assert!(observed[0] < ROOT_BYTES);
    }

    #[test]
    fn refusing_a_candidate_keeps_the_old_generation_and_its_real_instances_live() {
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(Noop)];
        let mut ctx = context();
        pin(&plugins, &mut ctx);
        let candidate: Vec<Arc<dyn Plugin>> = (0..65)
            .map(|_| Arc::new(Noop) as Arc<dyn Plugin>)
            .collect();
        assert_eq!(
            compile_terminal_manifest(&candidate).unwrap_err().reason,
            TerminalRefusal::TooManyParticipants,
        );
        drop(candidate);
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        assert!(matches!(chain.next_operation(), Some(PreparedTerminalOp::Noop)));
        assert!(chain.next_operation().is_none());
    }

    #[test]
    fn whole_patch_failure_leaves_every_existing_occurrence_and_origin_unchanged() {
        let ticket = ledger().reserve_owned(CONTROL_BYTES).unwrap();
        let mut carrier = SelectedTerminalCarrier::new(&ticket).unwrap();
        for _ in 0..5 {
            carrier.push("x", &[b'a'; 16_384], backend()).unwrap();
        }
        carrier.push("x", &[b'b'; 16_100], backend()).unwrap();
        let before: Vec<_> = carrier
            .occurrences()
            .map(|(name, value, origin)| (name.to_vec(), value.to_vec(), origin))
            .collect();
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(Fields {
            values: vec![("x-first", "fits".into()), ("x-last", "z".repeat(16_384))],
            override_existing: true,
        })];
        let mut ctx = context();
        pin(&plugins, &mut ctx);
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
            panic!("field operation")
        };
        assert!(carrier.apply(&patch).is_err());
        let after: Vec<_> = carrier
            .occurrences()
            .map(|(name, value, origin)| (name.to_vec(), value.to_vec(), origin))
            .collect();
        assert_eq!(after, before);
    }

    #[test]
    fn identical_values_rename_and_duplicate_cookies_do_not_bless_backend_origin() {
        for override_existing in [false, true] {
            let ticket = ledger().reserve_owned(CONTROL_BYTES).unwrap();
            let mut carrier = SelectedTerminalCarrier::new(&ticket).unwrap();
            carrier.push("vary", b"Origin", backend()).unwrap();
            carrier.push("set-cookie", b"opaque=same", backend()).unwrap();
            carrier.push("set-cookie", b"opaque=same", backend()).unwrap();
            let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(Fields {
                values: vec![("vary", "Origin".into())],
                override_existing,
            })];
            let mut ctx = context();
            pin(&plugins, &mut ctx);
            let mut chain =
                PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
            let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
                panic!("field operation")
            };
            carrier.apply(&patch).unwrap();
            carrier.rename("vary", "x-renamed").unwrap();
            let origin = carrier
                .occurrences()
                .find(|(name, _, _)| *name == b"x-renamed")
                .unwrap()
                .2;
            if override_existing {
                assert!(matches!(
                    origin.origin,
                    TerminalFieldOrigin::GatewayInstance(_),
                ));
            } else {
                assert_eq!(origin, backend());
            }
            let cookies: Vec<_> = carrier
                .occurrences()
                .filter(|(name, _, _)| *name == b"set-cookie")
                .map(|(_, value, origin)| (value.to_vec(), origin))
                .collect();
            assert_eq!(cookies, vec![(b"opaque=same".to_vec(), backend()); 2]);
        }
    }

    #[test]
    fn non_utf8_backend_value_survives_compaction_with_its_origin() {
        let ticket = ledger().reserve_owned(CONTROL_BYTES).unwrap();
        let mut carrier = SelectedTerminalCarrier::new(&ticket).unwrap();
        carrier.push("x-opaque", &[0x80, 0xff], backend()).unwrap();
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(Fields {
            values: vec![("x-new", "visible".into())],
            override_existing: true,
        })];
        let mut ctx = context();
        pin(&plugins, &mut ctx);
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
            panic!("field operation")
        };
        carrier.apply(&patch).unwrap();
        let (_, value, lineage) = carrier
            .occurrences()
            .find(|(name, _, _)| *name == b"x-opaque")
            .unwrap();
        assert_eq!(value, &[0x80, 0xff]);
        assert_eq!(lineage, backend());
    }

    #[test]
    fn legacy_capacity_refusal_does_not_apply_a_prefix_of_the_patch() {
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(Fields {
            values: vec![("x-first", "visible".into()), ("x-last", "z".repeat(1024))],
            override_existing: true,
        })];
        let mut ctx = context();
        pin(&plugins, &mut ctx);
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
            panic!("field operation")
        };
        let mut retained = String::with_capacity(98_000);
        retained.push('x');
        let mut headers = HashMap::from([("x-retained".to_string(), retained)]);
        assert!(
            ferrum_edge::plugins::terminal_preparation::apply_terminal_patch(patch, &mut headers)
                .is_err(),
        );
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get("x-retained").unwrap(), "x");
    }

    #[test]
    fn separate_cookie_occurrences_share_the_carrier_without_an_aggregate_value_limit() {
        let plugins: Vec<Arc<dyn Plugin>> = vec![
            Arc::new(Cookie { key: "first" }),
            Arc::new(Cookie { key: "second" }),
        ];
        let mut ctx = context();
        let value = format!("opaque={}", "x".repeat(8185));
        assert_eq!(value.len(), 8192);
        ctx.metadata.insert("first".into(), value.clone());
        ctx.metadata.insert("second".into(), value.clone());
        pin(&plugins, &mut ctx);
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        assert!(!ctx.metadata.contains_key("first"));
        assert!(!ctx.metadata.contains_key("second"));
        let mut headers = HashMap::new();
        while let Some(operation) = chain.next_operation() {
            let TerminalResult::Cookie(cookie) = operation.execute() else {
                panic!("cookie operation")
            };
            ferrum_edge::plugins::terminal_preparation::apply_terminal_cookie(cookie, &mut headers)
                .unwrap();
        }
        let values: Vec<_> = headers.get("set-cookie").unwrap().split('\n').collect();
        assert_eq!(values, [value.as_str(), value.as_str()]);
    }

    #[tokio::test]
    async fn real_metrics_udp_restamp_matches_the_ordinary_hook_and_keeps_private_peer_identity() {
        allocator_profile();
        let plugin = Arc::new(
            WorkloadMetrics::new(&json!({
                "namespace": "local",
                "workload_spiffe_id": "spiffe://mesh.local/ns/local/sa/service",
                "node_id": "node",
                "topology": "sidecar",
                "sampling_percentage": 0.0,
                "custom_tags": {"region": "west"},
                "custom_header_tags": {"tag": "x-tag"}
            }))
            .unwrap(),
        );
        let mut ctx = context();
        ctx.metadata.reserve(128);
        ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
        ctx.peer_spiffe_id = Some(SpiffeId::new("spiffe://mesh.local/peer").unwrap());
        ctx.headers.insert("x-tag".into(), "visible".into());
        ctx.headers.insert(
            "baggage".into(),
            "source.principal=spiffe://evil/ns/forged/sa/forged".into(),
        );
        ctx.metadata.insert(
            "mesh_authz.ignored_udp_source_scope".into(),
            "pod_uid_mismatch".into(),
        );
        ctx.metadata.insert(
            "mesh.source.principal".into(),
            "spiffe://evil/ns/forged/sa/forged".into(),
        );
        ctx.metadata.insert("mesh.source.namespace".into(), "forged".into());
        ctx.metadata.insert("mesh.source.service_account".into(), "forged".into());
        ctx.metadata.insert(
            "traceparent".into(),
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-00".into(),
        );
        ctx.metadata.insert(
            "workload_metrics.captured_traceparent".into(),
            "true".into(),
        );
        let mut ordinary = ctx.clone();
        let mut ordinary_headers = HashMap::new();
        plugin.after_proxy(&mut ordinary, 403, &mut ordinary_headers).await;
        let plugins: Vec<Arc<dyn Plugin>> = vec![plugin];
        pin(&plugins, &mut ctx);
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
            panic!("metrics operation")
        };
        let mut headers = HashMap::new();
        ferrum_edge::plugins::terminal_preparation::apply_terminal_patch(patch, &mut headers)
            .unwrap();
        assert_eq!(ctx.metadata, ordinary.metadata);
        assert_eq!(headers, ordinary_headers);
        assert_eq!(
            ctx.metadata.get("mesh.source.principal").unwrap(),
            "spiffe://mesh.local/peer",
        );
        assert!(!ctx.metadata.contains_key("mesh.source.namespace"));
        assert!(!ctx.metadata.contains_key("mesh.source.service_account"));
        assert_eq!(ctx.metadata.get("tag").unwrap(), "visible");
    }

    #[tokio::test]
    async fn real_metrics_b3_import_preserves_sampling_parent_and_single_header_precedence() {
        allocator_profile();
        for mode in [0, 1, 2] {
            let plugin = Arc::new(
                WorkloadMetrics::new(&json!({"sampling_percentage": 0.0})).unwrap(),
            );
            let mut ctx = context();
            ctx.metadata.reserve(128);
            ctx.peer_spiffe_id =
                Some(SpiffeId::new("spiffe://mesh.local/ns/peer/sa/workload").unwrap());
            ctx.metadata.insert(
                "mesh_authz.ignored_udp_source_scope".into(),
                "pod_uid_mismatch".into(),
            );
            if mode == 0 {
                ctx.headers.insert(
                    "b3".into(),
                    "0123456789ABCDEF-0123456789ABCDEF-0".into(),
                );
            } else {
                ctx.headers.insert("x-b3-traceid".into(), "0123456789ABCDEF".into());
                ctx.headers.insert("x-b3-spanid".into(), "0123456789ABCDEF".into());
                ctx.headers.insert("x-b3-sampled".into(), "0".into());
                if mode == 2 {
                    ctx.headers.insert("b3".into(), "invalid".into());
                }
            }
            let mut ordinary = ctx.clone();
            let mut ordinary_headers = HashMap::new();
            plugin.after_proxy(&mut ordinary, 403, &mut ordinary_headers).await;
            let plugins: Vec<Arc<dyn Plugin>> = vec![plugin];
            pin(&plugins, &mut ctx);
            let mut chain =
                PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
            let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
                panic!("metrics trace operation")
            };
            let mut headers = HashMap::new();
            ferrum_edge::plugins::terminal_preparation::apply_terminal_patch(patch, &mut headers)
                .unwrap();
            if mode == 2 {
                assert!(headers.is_empty());
                assert!(!ctx.metadata.contains_key("trace_id"));
                assert_eq!(ctx.metadata, ordinary.metadata);
                continue;
            }
            let traceparent = headers.get("traceparent").unwrap();
            assert!(traceparent.starts_with("00-00000000000000000123456789abcdef-"));
            assert_eq!(traceparent.len(), 55);
            assert!(traceparent.ends_with("-00"));
            assert_eq!(ctx.metadata.get("parent_span_id").unwrap(), "0123456789abcdef");
            // Independent hooks mint distinct spans; all other facts must agree.
            for key in ["span_id", "traceparent"] {
                ctx.metadata.remove(key);
                ordinary.metadata.remove(key);
            }
            assert_eq!(ctx.metadata, ordinary.metadata);
        }
    }

    #[tokio::test]
    async fn numeric_telemetry_preserves_valid_long_leading_zero_values() {
        let plugin = Arc::new(
            RateLimiting::new(
                &json!({
                    "expose_headers": true,
                    "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 10}]
                }),
                PluginHttpClient::default(),
            )
            .unwrap(),
        );
        let mut ctx = context();
        let value = format!("{}7", "0".repeat(512));
        ctx.metadata.insert("ratelimit_limit".into(), value.clone());
        let mut ordinary = ctx.clone();
        let mut ordinary_headers = HashMap::new();
        ordinary_headers.insert("x-ratelimit-identity".into(), "private".into());
        plugin.after_proxy(&mut ordinary, 403, &mut ordinary_headers).await;
        let plugins: Vec<Arc<dyn Plugin>> = vec![plugin];
        pin(&plugins, &mut ctx);
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
            panic!("rate-limit operation")
        };
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-identity".into(), "private".into());
        ferrum_edge::plugins::terminal_preparation::apply_terminal_patch(patch, &mut headers)
            .unwrap();
        assert_eq!(headers, ordinary_headers);
        assert_eq!(headers.get("x-ratelimit-limit"), Some(&value));
        assert!(!headers.contains_key("x-ratelimit-identity"));
    }

    #[test]
    fn all_wire_slots_are_real_and_the_next_occurrence_refuses_without_mutation() {
        let ticket = ledger().reserve_owned(CONTROL_BYTES).unwrap();
        let mut carrier = SelectedTerminalCarrier::new(&ticket).unwrap();
        for _ in 0..MAX_FIELD_OCCURRENCES {
            carrier.push("set-cookie", b"same", backend()).unwrap();
        }
        assert!(carrier.push("set-cookie", b"extra", backend()).is_err());
        assert_eq!(carrier.field_count(), MAX_FIELD_OCCURRENCES);
        assert!(
            carrier
                .occurrences()
                .all(|(_, value, origin)| value == b"same" && origin == backend()),
        );
    }
}

#[cfg(windows)]
#[test]
fn an_unqualified_windows_allocator_is_explicitly_unavailable() {
    use ferrum_edge::plugins::terminal_preparation::TerminalRefusal;
    use ferrum_edge::plugins::terminal_storage::AllocationPlan;
    assert_eq!(
        AllocationPlan::array::<u8>(1).unwrap_err().reason,
        TerminalRefusal::AllocatorUnavailable,
    );
    assert_eq!(AllocationPlan::array::<u8>(0).unwrap().backing_bytes(), 0);
}
