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
    use ferrum_edge::plugins::cors::CorsPlugin;
    use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
    use ferrum_edge::plugins::rate_limiting::RateLimiting;
    use ferrum_edge::plugins::terminal_preparation::{
        CONTROL_BYTES, MAX_FIELD_OCCURRENCES, PROCESS_BYTES, PreparationLedger,
        PreparedTerminalChain, PreparedTerminalOp, REQUEST_TICKETS, ROOT_BYTES,
        SelectedTerminalCarrier, TerminalAdmissionError, TerminalDeclaration, TerminalFieldLineage,
        TerminalFieldOrigin, TerminalFieldSection, TerminalRefusal, TerminalResult,
        apply_terminal_patch, compile_terminal_manifest, field_declaration,
        validate_terminal_headers,
    };
    use ferrum_edge::plugins::terminal_storage::{AllocationPlan, TerminalTicket};
    use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
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
        let candidate: Vec<Arc<dyn Plugin>> =
            (0..65).map(|_| Arc::new(Noop) as Arc<dyn Plugin>).collect();
        assert_eq!(
            compile_terminal_manifest(&candidate).unwrap_err().reason,
            TerminalRefusal::TooManyParticipants,
        );
        drop(candidate);
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        assert!(matches!(
            chain.next_operation(),
            Some(PreparedTerminalOp::Noop)
        ));
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
            carrier
                .push("set-cookie", b"opaque=same", backend())
                .unwrap();
            carrier
                .push("set-cookie", b"opaque=same", backend())
                .unwrap();
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
        ctx.metadata
            .insert("mesh.source.namespace".into(), "forged".into());
        ctx.metadata
            .insert("mesh.source.service_account".into(), "forged".into());
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
        plugin
            .after_proxy(&mut ordinary, 403, &mut ordinary_headers)
            .await;
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
            let plugin =
                Arc::new(WorkloadMetrics::new(&json!({"sampling_percentage": 0.0})).unwrap());
            let mut ctx = context();
            ctx.metadata.reserve(128);
            ctx.peer_spiffe_id =
                Some(SpiffeId::new("spiffe://mesh.local/ns/peer/sa/workload").unwrap());
            ctx.metadata.insert(
                "mesh_authz.ignored_udp_source_scope".into(),
                "pod_uid_mismatch".into(),
            );
            if mode == 0 {
                ctx.headers
                    .insert("b3".into(), "0123456789ABCDEF-0123456789ABCDEF-0".into());
            } else {
                ctx.headers
                    .insert("x-b3-traceid".into(), "0123456789ABCDEF".into());
                ctx.headers
                    .insert("x-b3-spanid".into(), "0123456789ABCDEF".into());
                ctx.headers.insert("x-b3-sampled".into(), "0".into());
                if mode == 2 {
                    ctx.headers.insert("b3".into(), "invalid".into());
                }
            }
            let mut ordinary = ctx.clone();
            let mut ordinary_headers = HashMap::new();
            plugin
                .after_proxy(&mut ordinary, 403, &mut ordinary_headers)
                .await;
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
            assert_eq!(
                ctx.metadata.get("parent_span_id").unwrap(),
                "0123456789abcdef"
            );
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
        plugin
            .after_proxy(&mut ordinary, 403, &mut ordinary_headers)
            .await;
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

    fn cors_policy() -> serde_json::Value {
        json!({
            "allowed_origins": [{"exact": "https://fixture.example"}],
            "allowed_methods": ["GET", "POST", "OPTIONS"],
            "allowed_headers": ["content-type", "authorization"],
            "exposed_headers": ["X-Visible"],
            "allow_credentials": true,
            "max_age": 600,
            "unmatched_preflights": "forward"
        })
    }

    struct ReportedCorsName(&'static str);

    impl Plugin for ReportedCorsName {
        fn name(&self) -> &str {
            self.0
        }

        fn priority(&self) -> u16 {
            100
        }

        fn applies_after_proxy_on_reject(&self) -> bool {
            true
        }
    }

    #[test]
    fn reported_cors_or_finalizer_names_do_not_grant_terminal_preparation() {
        for name in ["cors", "__cors_finalizer"] {
            let plugin: Arc<dyn Plugin> = Arc::new(ReportedCorsName(name));
            assert!(plugin.cors_terminal_config().is_none());
            assert_eq!(
                compile_terminal_manifest(&[plugin]).unwrap_err().reason,
                TerminalRefusal::Undeclared
            );
        }
    }

    fn cors_cache(policies: &[serde_json::Value]) -> ferrum_edge::PluginCache {
        use chrono::Utc;
        use ferrum_edge::config::types::{
            GatewayConfig, PluginAssociation, PluginConfig, PluginScope,
        };
        let mut config = GatewayConfig::default();
        let mut proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(json!({
            "id": "cors-route",
            "namespace": "default",
            "backend_host": "127.0.0.1",
            "backend_port": 8080,
            "backend_scheme": "http"
        }))
        .unwrap();
        for (index, policy) in policies.iter().enumerate() {
            let id = format!("cors-{index}");
            proxy.plugins.push(PluginAssociation {
                plugin_config_id: id.clone(),
            });
            config.plugin_configs.push(PluginConfig {
                labels: Default::default(),
                id,
                plugin_name: "cors".into(),
                namespace: "default".into(),
                config: policy.clone(),
                scope: PluginScope::Proxy,
                proxy_id: Some(proxy.id.clone()),
                enabled: true,
                priority_override: Some(100 + index as u16),
                trigger: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
        }
        config.proxies.push(proxy);
        ferrum_edge::PluginCache::new(&config).unwrap()
    }

    async fn cors_request(plugins: &[Arc<dyn Plugin>], preflight: bool) -> RequestContext {
        let mut ctx = context();
        ctx.method = if preflight { "OPTIONS" } else { "GET" }.into();
        ctx.headers
            .insert("origin".into(), "https://fixture.example".into());
        if preflight {
            ctx.headers
                .insert("access-control-request-method".into(), "POST".into());
        }
        for plugin in plugins {
            if !matches!(
                plugin.on_request_received(&mut ctx).await,
                PluginResult::Continue
            ) {
                break;
            }
        }
        pin(plugins, &mut ctx);
        ctx
    }

    #[tokio::test]
    async fn actual_cors_direct_and_cache_finalizer_match_the_ordinary_policy() {
        use ferrum_edge::plugins::ProxyProtocol;
        for protocol in [ProxyProtocol::Http, ProxyProtocol::Grpc] {
            for deferred in [false, true] {
                for preflight in [false, true] {
                    let policies = if deferred {
                        vec![cors_policy(), cors_policy()]
                    } else {
                        vec![cors_policy()]
                    };
                    let cache = cors_cache(&policies);
                    let plugins =
                        cache.get_plugins_for_protocol("default", "cors-route", protocol);
                    let manifest = compile_terminal_manifest(&plugins).unwrap();
                    assert_eq!(manifest.participant_count(), if deferred { 3 } else { 1 });
                    assert!(manifest.entries().all(|entry| matches!(
                        entry.declaration,
                        TerminalDeclaration::Prepared { .. }
                    )));
                    assert_eq!(manifest.workspace_bytes(), 0);
                    assert!(
                        manifest
                            .entries()
                            .take(policies.len())
                            .all(|entry| entry.wrapped)
                    );
                    if deferred {
                        assert_eq!(plugins.last().unwrap().name(), "__cors_finalizer");
                    }
                    let mut ctx = cors_request(&plugins, preflight).await;
                    ctx.metadata
                        .insert("ferrum:rejection_response".into(), "true".into());
                    ctx.metadata.insert("request_body".into(), "retired".into());
                    let mut expected = HashMap::from([
                        ("access-control-allow-origin".into(), "*".into()),
                        ("Access-Control-Allow-Private-Network".into(), "true".into()),
                        ("vary".into(), "Accept-Encoding, oRiGiN".into()),
                        (
                            "set-cookie".into(),
                            "opaque=1; HttpOnly\nopaque=1; HttpOnly".into(),
                        ),
                    ]);
                    let mut ordinary = ctx.clone();
                    for plugin in plugins.iter() {
                        assert!(matches!(
                            plugin.after_proxy(&mut ordinary, 403, &mut expected).await,
                            PluginResult::Continue
                        ));
                    }
                    let mut chain =
                        PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
                    assert!(!ctx.metadata.contains_key("request_body"));
                    let mut actual = HashMap::from([
                        ("access-control-allow-origin".into(), "*".into()),
                        ("Access-Control-Allow-Private-Network".into(), "true".into()),
                        ("vary".into(), "Accept-Encoding, oRiGiN".into()),
                        (
                            "set-cookie".into(),
                            "opaque=1; HttpOnly\nopaque=1; HttpOnly".into(),
                        ),
                    ]);
                    drop(ctx);
                    drop(plugins);
                    drop(cache);
                    while let Some(operation) = chain.next_operation() {
                        match operation.execute() {
                            TerminalResult::Noop => {}
                            TerminalResult::Fields(patch) => {
                                apply_terminal_patch(patch, &mut actual).unwrap();
                            }
                            _ => panic!("CORS must only decorate fields"),
                        }
                    }
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[tokio::test]
    async fn distinct_cors_policies_keep_intersection_credentials_and_finalizer_instance() {
        let first = json!({
            "allowed_origins": ["https://fixture.example"],
            "allowed_methods": ["GET", "POST"],
            "allowed_headers": ["content-type", "authorization"],
            "exposed_headers": ["X-Visible", "X-First"],
            "allow_credentials": true,
            "max_age": 900
        });
        let second = json!({
            "allowed_origins": ["https://fixture.example"],
            "allowed_methods": ["POST", "PUT"],
            "allowed_headers": ["AUTHORIZATION", "x-second"],
            "exposed_headers": ["x-visible"],
            "allow_credentials": false,
            "max_age": 60
        });
        let cache = cors_cache(&[first, second]);
        let plugins = cache.get_plugins_for_protocol(
            "default",
            "cors-route",
            ferrum_edge::plugins::ProxyProtocol::Http,
        );
        let manifest = compile_terminal_manifest(&plugins).unwrap();
        assert_eq!(manifest.participant_count(), 3);
        let finalizer = manifest.entries().last().unwrap().instance;
        let mut ctx = cors_request(&plugins, true).await;
        let mut ordinary = ctx.clone();
        let mut expected = HashMap::new();
        for plugin in plugins.iter() {
            plugin.after_proxy(&mut ordinary, 204, &mut expected).await;
        }
        assert_eq!(expected.get("access-control-allow-methods").unwrap(), "POST");
        assert_eq!(
            expected.get("access-control-allow-headers").unwrap(),
            "authorization"
        );
        assert_eq!(
            expected.get("access-control-expose-headers").unwrap(),
            "X-Visible"
        );
        assert_eq!(expected.get("access-control-max-age").unwrap(), "60");
        assert!(!expected.contains_key("access-control-allow-credentials"));
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        let mut carrier = chain.new_selected_carrier().unwrap();
        drop(ctx);
        drop(plugins);
        drop(cache);
        let mut field_operations = 0;
        while let Some(operation) = chain.next_operation() {
            match operation.execute() {
                TerminalResult::Noop => {}
                TerminalResult::Fields(patch) => {
                    carrier.apply(&patch).unwrap();
                    field_operations += 1;
                }
                _ => panic!("CORS must preserve status and body"),
            }
        }
        assert_eq!(field_operations, 1);
        let actual: HashMap<_, _> = carrier
            .occurrences()
            .map(|(name, value, lineage)| {
                assert_eq!(lineage.origin, TerminalFieldOrigin::GatewayInstance(finalizer));
                (
                    std::str::from_utf8(name).unwrap().to_string(),
                    std::str::from_utf8(value).unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(carrier.token_contributions().count(), 3);
        assert!(
            carrier
                .token_contributions()
                .all(|(_, _, lineage, authored)| {
                    authored && lineage.origin == TerminalFieldOrigin::GatewayInstance(finalizer)
                })
        );
    }

    #[tokio::test]
    async fn unmatched_preflight_native_forward_and_ignore_keep_status_body_and_vary() {
        use ferrum_edge::_test_support::apply_replaceable_after_proxy_hooks_to_rejection_for_test;

        for mode in [None, Some("forward"), Some("ignore")] {
            let mut policy = cors_policy();
            if let Some(mode) = mode {
                policy["unmatched_preflights"] = json!(mode);
            } else {
                policy.as_object_mut().unwrap().remove("unmatched_preflights");
            }
            let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(CorsPlugin::new(&policy).unwrap())];
            let mut ctx = context();
            ctx.method = "OPTIONS".into();
            ctx.headers
                .insert("origin".into(), "https://elsewhere.example".into());
            ctx.headers
                .insert("access-control-request-method".into(), "POST".into());
            let (mut status, mut body, mut headers) =
                match plugins[0].on_request_received(&mut ctx).await {
                    PluginResult::Continue => {
                        assert_eq!(mode, Some("forward"));
                        (418, bytes::Bytes::from_static(b"selected body"), HashMap::new())
                    }
                    PluginResult::Reject {
                        status_code,
                        body,
                        headers,
                    } => {
                        assert_eq!(status_code, if mode.is_none() { 403 } else { 200 });
                        (status_code, bytes::Bytes::from(body), headers)
                    }
                    _ => panic!("unexpected CORS request result"),
                };
            headers.insert("access-control-allow-origin".into(), "*".into());
            headers.insert("vary".into(), "Accept-Encoding, oRiGiN".into());
            let original_status = status;
            let original_body = body.clone();
            let mut expected = headers.clone();
            let mut ordinary = ctx.clone();
            ordinary
                .metadata
                .insert("ferrum:rejection_response".into(), "true".into());
            plugins[0]
                .after_proxy(&mut ordinary, status, &mut expected)
                .await;
            pin(&plugins, &mut ctx);
            apply_replaceable_after_proxy_hooks_to_rejection_for_test(
                &plugins,
                &mut ctx,
                &mut status,
                &mut body,
                &mut headers,
            )
            .await;
            assert_eq!(status, original_status);
            assert_eq!(body, original_body);
            assert_eq!(body.as_ptr(), original_body.as_ptr());
            assert_eq!(headers, expected);
            assert!(!headers.contains_key("access-control-allow-origin"));
            assert_eq!(
                headers.get("vary").unwrap(),
                "Accept-Encoding, oRiGiN, Access-Control-Request-Method, Access-Control-Request-Headers"
            );
        }
    }

    #[tokio::test]
    async fn cors_vary_segments_cookies_and_identical_token_contributions_keep_their_origins() {
        let plugin: Arc<dyn Plugin> = Arc::new(CorsPlugin::new(&cors_policy()).unwrap());
        let plugins = vec![plugin];
        let mut ctx = cors_request(&plugins, true).await;
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        let mut carrier = chain.new_selected_carrier().unwrap();
        carrier
            .push("vary", b"Accept-Encoding, opaque-\xff, oRiGiN", backend())
            .unwrap();
        carrier
            .push("set-cookie", b"opaque=1; HttpOnly", backend())
            .unwrap();
        carrier
            .push("set-cookie", b"opaque=\xff; HttpOnly", backend())
            .unwrap();
        carrier
            .push("set-cookie", b"opaque=1; HttpOnly", backend())
            .unwrap();
        carrier
            .push("Access-Control-Allow-Private-Network", b"true", backend())
            .unwrap();
        let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
            panic!("CORS fields")
        };
        carrier.apply(&patch).unwrap();
        assert!(!carrier.occurrences().any(|(name, _, _)| {
            name.eq_ignore_ascii_case(b"access-control-allow-private-network")
        }));
        let tokens: Vec<_> = carrier.token_contributions().collect();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].1, b"oRiGiN");
        assert!(!tokens[0].3);
        assert!(tokens.iter().all(|(_, _, lineage, _)| lineage.policy_contribution));
        let segments: Vec<_> = carrier.value_segments("vary").collect();
        assert_eq!(
            segments[0],
            (b"Accept-Encoding, opaque-\xff, oRiGiN".as_slice(), backend())
        );
        assert_eq!(segments[1].0, b", Access-Control-Request-Method");
        assert_eq!(segments[2].0, b", Access-Control-Request-Headers");
        assert!(segments[1..].iter().all(|(_, lineage)| matches!(
            lineage.origin,
            TerminalFieldOrigin::GatewayInstance(_)
        )));
        assert_eq!(
            carrier
                .occurrences()
                .filter(|(name, value, lineage)| {
                    name.eq_ignore_ascii_case(b"set-cookie")
                        && *value == b"opaque=1; HttpOnly"
                        && *lineage == backend()
                })
                .count(),
            2
        );
        assert!(carrier.occurrences().any(|(name, value, lineage)| {
            name == b"set-cookie" && value == b"opaque=\xff; HttpOnly" && lineage == backend()
        }));
        carrier.rename("vary", "x-renamed-vary").unwrap();
        assert!(
            carrier
                .token_contributions()
                .all(|(name, _, _, _)| name == b"x-renamed-vary")
        );
        assert_eq!(carrier.value_segments("x-renamed-vary").count(), 3);
    }

    #[tokio::test]
    async fn cors_prefix_and_field_writes_are_atomic_when_vary_fields_or_bytes_exceed_capacity() {
        let plugins: Vec<Arc<dyn Plugin>> =
            vec![Arc::new(CorsPlugin::new(&cors_policy()).unwrap())];
        for overflow in 0..3 {
            let mut ctx = cors_request(&plugins, false).await;
            let mut chain =
                PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
            let mut carrier = chain.new_selected_carrier().unwrap();
            carrier
                .push("access-control-backend-extension", b"stale", backend())
                .unwrap();
            match overflow {
                0 => {
                    carrier.push("vary", &vec![b'x'; 16_384], backend()).unwrap();
                }
                1 => {
                    for _ in 1..MAX_FIELD_OCCURRENCES {
                        carrier.push("set-cookie", b"opaque", backend()).unwrap();
                    }
                }
                _ => {
                    for _ in 0..5 {
                        carrier
                            .push("x-filled", &vec![b'x'; 16_384], backend())
                            .unwrap();
                    }
                    carrier
                        .push("x-filled", &vec![b'x'; 16_280], backend())
                        .unwrap();
                }
            }
            let before: Vec<_> = carrier
                .occurrences()
                .map(|(name, value, lineage)| (name.to_vec(), value.to_vec(), lineage))
                .collect();
            let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
                panic!("CORS fields")
            };
            assert!(carrier.apply(&patch).is_err());
            let after: Vec<_> = carrier
                .occurrences()
                .map(|(name, value, lineage)| (name.to_vec(), value.to_vec(), lineage))
                .collect();
            assert_eq!(before, after);
            assert_eq!(carrier.token_contributions().count(), 0);
        }
    }

    #[tokio::test]
    async fn cors_operations_reject_another_requests_carrier_and_preserve_vary_wildcard() {
        let plugins: Vec<Arc<dyn Plugin>> =
            vec![Arc::new(CorsPlugin::new(&cors_policy()).unwrap())];
        let mut ctx = cors_request(&plugins, true).await;
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        let mut own = chain.new_selected_carrier().unwrap();
        own.push("Vary", b"Accept-Encoding, *", backend()).unwrap();
        let mut foreign =
            SelectedTerminalCarrier::new(&ledger().reserve_owned(CONTROL_BYTES).unwrap()).unwrap();
        foreign.push("vary", b"untouched", backend()).unwrap();
        let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
            panic!("CORS fields")
        };
        assert_eq!(
            foreign.apply(&patch).unwrap_err().reason,
            TerminalRefusal::PinnedGeneration
        );
        assert_eq!(foreign.occurrences().next().unwrap().1, b"untouched");
        own.apply(&patch).unwrap();
        assert_eq!(
            own.value_segments("vary").next().unwrap(),
            (b"Accept-Encoding, *".as_slice(), backend())
        );
        assert_eq!(own.token_contributions().count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn actual_cors_rejection_runner_preserves_http_grpc_payloads_and_deadline_ownership() {
        use bytes::Bytes;
        use ferrum_edge::_test_support::{
            apply_replaceable_after_proxy_hooks_to_rejection_for_test,
            mark_native_grpc_request_for_test,
            normalize_reject_response_bytes_with_context, set_grpc_deadline_budget_for_test,
        };
        for grpc in [false, true] {
            for deadline in [false, true] {
                let plugins: Vec<Arc<dyn Plugin>> =
                    vec![Arc::new(CorsPlugin::new(&cors_policy()).unwrap())];
                let mut ctx = cors_request(&plugins, false).await;
                if grpc {
                    ctx.headers
                        .insert("content-type".into(), "application/grpc".into());
                    mark_native_grpc_request_for_test(&mut ctx);
                }
                if deadline {
                    set_grpc_deadline_budget_for_test(&mut ctx, Some(10));
                    tokio::time::advance(std::time::Duration::from_millis(11)).await;
                }
                let mut status = 403;
                let mut body = Bytes::from_static(b"selected rejection");
                let original = body.clone();
                let mut headers = HashMap::new();
                apply_replaceable_after_proxy_hooks_to_rejection_for_test(
                    &plugins,
                    &mut ctx,
                    &mut status,
                    &mut body,
                    &mut headers,
                )
                .await;
                assert_eq!(
                    headers.get("access-control-allow-origin").unwrap(),
                    "https://fixture.example"
                );
                assert_eq!(headers.get("vary").unwrap(), "Origin");
                let wire = normalize_reject_response_bytes_with_context(
                    &ctx,
                    http::StatusCode::from_u16(status).unwrap(),
                    body.clone(),
                    &headers,
                    grpc,
                );
                assert_eq!(
                    wire.headers.get("access-control-allow-origin"),
                    headers.get("access-control-allow-origin")
                );
                assert_eq!(wire.headers.get("vary"), headers.get("vary"));
                if grpc {
                    assert_eq!(wire.http_status, http::StatusCode::OK);
                    assert_eq!(wire.grpc_status, Some(if deadline { 4 } else { 7 }));
                    assert!(wire.body.is_empty());
                } else {
                    assert_eq!(wire.http_status.as_u16(), status);
                    assert_eq!(wire.body, body);
                }
                if deadline {
                    assert_eq!(status, 200);
                    assert!(body.is_empty());
                    assert_eq!(headers.get("grpc-status").unwrap(), "4");
                } else {
                    assert_eq!(status, 403);
                    assert_eq!(body.as_ptr(), original.as_ptr());
                    assert_eq!(body, original);
                }
            }
        }
    }

    struct CorsRawOwner {
        dropped: Arc<std::sync::atomic::AtomicUsize>,
        bytes: Vec<u8>,
    }

    impl AsRef<[u8]> for CorsRawOwner {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for CorsRawOwner {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn cors_preparation_drops_raw_owners_without_copying_request_headers_or_policy_lists() {
        let plugins: Vec<Arc<dyn Plugin>> =
            vec![Arc::new(CorsPlugin::new(&cors_policy()).unwrap())];
        let mut ctx = cors_request(&plugins, false).await;
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        ctx.request_body_bytes = Some(bytes::Bytes::from_owner(CorsRawOwner {
            dropped: Arc::clone(&dropped),
            bytes: vec![b'r'; 1024 * 1024],
        }));
        ctx.headers
            .insert("x-large-raw".into(), "h".repeat(1024 * 1024));
        let allocated = tikv_jemalloc_ctl::thread::allocatedp::read().unwrap();
        let before = allocated.get();
        let mut chain = PreparedTerminalChain::prepare(&plugins, &mut ctx, false, false).unwrap();
        assert!(allocated.get() - before < 16_384);
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(ctx.request_body_bytes.is_none());
        drop(ctx);
        drop(plugins);
        let before = allocated.get();
        let mut carrier = chain.new_selected_carrier().unwrap();
        let backing = allocated.get() - before;
        assert!(backing >= 98_304);
        assert!(backing <= 131_072);
        let TerminalResult::Fields(patch) = chain.next_operation().unwrap().execute() else {
            panic!("CORS fields")
        };
        carrier.apply(&patch).unwrap();
        assert!(carrier.occurrences().any(|(name, value, _)| {
            name == b"access-control-allow-origin" && value == b"https://fixture.example"
        }));
    }

    #[tokio::test]
    async fn cors_originless_unmatched_native_and_istio_charged_states_keep_policy_semantics() {
        for native in [false, true] {
            for origin in [
                None,
                Some("https://fixture.example"),
                Some("https://FIXTURE.example"),
                Some("https://elsewhere.example"),
            ] {
                let policy = if native {
                    json!({
                        "allowed_origins": ["https://fixture.example"],
                        "allow_credentials": true
                    })
                } else {
                    cors_policy()
                };
                let plugins: Vec<Arc<dyn Plugin>> =
                    vec![Arc::new(CorsPlugin::new(&policy).unwrap())];
                let mut ctx = context();
                if let Some(origin) = origin {
                    ctx.headers.insert("origin".into(), origin.into());
                }
                let result = plugins[0].on_request_received(&mut ctx).await;
                if native && origin == Some("https://elsewhere.example") {
                    assert!(matches!(
                        result,
                        PluginResult::Reject { status_code: 403, .. }
                    ));
                } else {
                    assert!(matches!(result, PluginResult::Continue));
                }
                pin(&plugins, &mut ctx);
                ctx.metadata
                    .insert("ferrum:rejection_response".into(), "true".into());
                let initial = HashMap::from([
                    ("access-control-allow-origin".into(), "*".into()),
                    ("access-control-unlisted-extension".into(), "stale".into()),
                    ("vary".into(), "Accept-Encoding, *".into()),
                ]);
                let mut expected = initial.clone();
                let mut ordinary = ctx.clone();
                plugins[0]
                    .after_proxy(&mut ordinary, 504, &mut expected)
                    .await;
                let mut chain =
                    PreparedTerminalChain::prepare(&plugins, &mut ctx, true, true).unwrap();
                let mut actual = initial;
                while let Some(operation) = chain.next_operation() {
                    if let TerminalResult::Fields(patch) = operation.execute() {
                        apply_terminal_patch(patch, &mut actual).unwrap();
                    }
                }
                assert_eq!(actual, expected);
            }
        }
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
