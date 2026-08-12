use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ferrum_edge::config::types::HttpFlavor;
use ferrum_edge::plugins::{Plugin, RequestContext, TransactionSummary};
use http::StatusCode;

/// Normalize source before matching a source-shape needle: collapse every run
/// of whitespace away, then drop rustfmt's wrapped-call trailing comma so
/// `foo(\n    a,\n    b,\n)` and `foo(a, b)` produce the same text. Needles
/// written against this form survive reflow when an argument list grows past
/// `fn_call_width` — an exact one-line substring does not.
fn squeeze(source: &str) -> String {
    let collapsed: String = source.split_whitespace().collect();
    collapsed.replace(",)", ")")
}

#[test]
fn h3_terminal_final_body_dispatch_follows_path_policy_and_precedes_breaker() {
    let source = include_str!("../../../src/http3/server.rs");
    // Match without the `let` binder: the initial selection is now `let mut
    // selection` so the deferred-override rebind can replace it wholesale. The
    // first occurrence is still the pre-deferred lookup this ordering pins.
    let selection = source
        .find("selection = crate::proxy::backend_dispatch::select_upstream_target(")
        .expect("H3 backend selection must remain present");
    let path_policy = source[selection..]
        .find("if backend_path_is_policy_bound {")
        .map(|offset| selection + offset)
        .expect("H3 selected-path policy must remain present");
    let terminal_marker = source[path_policy..]
        .find("// Terminal final-body hooks may perform provider egress.")
        .map(|offset| path_policy + offset)
        .expect("H3 terminal final-body dispatch boundary must remain present");
    let terminal_gate = source[terminal_marker..]
        .find("if final_body_before_backend_dispatch {")
        .map(|offset| terminal_marker + offset)
        .expect("H3 terminal final-body dispatch gate must remain present");
    let routing_deferred = source[path_policy..terminal_gate]
        .find("BackendPathBeforeProxyPass::RoutingHeaderDeferred")
        .map(|offset| path_policy + offset)
        .expect("H3 routing-header deferred pass must remain present");
    let remaining_deferred = source[routing_deferred..terminal_gate]
        .find("BackendPathBeforeProxyPass::RemainingDeferred")
        .map(|offset| routing_deferred + offset)
        .expect("H3 remaining deferred pass must remain present");
    let breaker = source[selection..]
        .find("check_circuit_breaker(")
        .map(|offset| selection + offset)
        .expect("H3 backend circuit-breaker gate must remain present");
    let terminal_path = &source[terminal_gate..breaker];

    assert!(terminal_path.contains("run_final_request_body_hooks("));
    assert!(terminal_path.contains("apply_reject_after_proxy_and_synthetic_body_hooks("));
    assert!(selection < path_policy);
    assert!(path_policy < routing_deferred);
    assert!(routing_deferred < remaining_deferred);
    assert!(remaining_deferred < terminal_gate);
    assert!(terminal_gate < breaker);
}

/// A RemainingDeferred provider claim can rewrite destination/path after the
/// initial H3 selection. Native H3 must rebind every destination-dependent
/// dispatch input before query capture, terminal egress, admission, or dial —
/// matching the H1/H2 ladder — and must gate reselection on actual movement.
#[test]
fn h3_deferred_destination_override_is_rebound_before_dispatch() {
    let source = include_str!("../../../src/http3/server.rs");
    let handler = source
        .split_once("async fn handle_h3_request(")
        .map(|(_, handler)| handler)
        .expect("native H3 request handler must remain present");
    let deferred = handler
        .find("BackendPathBeforeProxyPass::RemainingDeferred")
        .expect("remaining deferred pass must remain present");
    let after_deferred = &handler[deferred..];
    let rebind = after_deferred
        .find("routing_proxy = ctx")
        .and_then(|offset| {
            after_deferred[offset..]
                .find("apply_route_overrides_with_upstreams(")
                .map(|inner| offset + inner)
        })
        .expect("deferred destination overrides must rebind the routing-base proxy");
    let moved = after_deferred
        .find("let destination_rebound = !Arc::ptr_eq(&previous_routing_proxy, &routing_proxy);")
        .expect("the rebind must detect a committed destination by routing-proxy identity");
    let rebase = after_deferred
        .find("path = crate::proxy::rebase_route_override_path(&mut ctx, path);")
        .expect("deferred destination overrides must rebase the dispatch path");
    let reselect = after_deferred
        .find("upstream_target =")
        .and_then(|offset| {
            after_deferred[offset..]
                .find("concretize_wildcard_target_for_request(")
                .map(|inner| offset + inner)
        })
        .expect("deferred destination overrides must replace the pinned target");
    let query_capture = after_deferred
        .find("effective_backend_query_string_with_raw(&ctx, &query_string)")
        .expect("backend query must be captured after the remaining deferred pass");
    let terminal = after_deferred
        .find("if final_body_before_backend_dispatch {")
        .expect("terminal final-body dispatch gate must remain present");

    assert!(
        rebind < moved
            && moved < rebase
            && rebase < reselect
            && reselect < query_capture
            && query_capture < terminal,
        "H3 must rebind/rebase/reselect before query capture and terminal egress"
    );

    let gate = after_deferred[..reselect]
        .rfind("if destination_rebound {")
        .expect("deferred re-selection must be gated on the destination having moved");
    assert!(gate > rebase);

    // Whole selection replace, not target-only: balancer + sticky ride `selection`.
    let whole = after_deferred
        .find("selection = crate::proxy::backend_dispatch::select_upstream_target(")
        .expect("the gated rebind must re-run upstream selection wholesale");
    let sticky = after_deferred
        .find("let sticky_cookie_needed = selection.sticky_cookie_needed;")
        .expect("sticky accounting must still read the live selection");
    assert!(
        whole < sticky,
        "re-selection must overwrite `selection` before sticky accounting consumes it"
    );

    // DestinationRule overlays must be rebuilt for the rebound destination so
    // TLS/timeouts/pool keys cannot keep describing the pre-claim target.
    let recap = after_deferred[reselect..]
        .find("selected_base_proxy = crate::proxy::cap_proxy_retry_for_target(")
        .expect("rebound destinations must re-cap the selected base proxy");
    let reresolve = after_deferred[reselect..]
        .find("resolve_effective_proxy_for_target(")
        .expect("rebound destinations must re-resolve the effective proxy");
    assert!(recap < reresolve);
    assert!(
        after_deferred[reselect..]
            .contains("ctx.matched_proxy = Some(Arc::clone(&selected_base_proxy));"),
        "matched_proxy must describe the rebound selected base"
    );
}

#[test]
fn h3_frontend_caps_retry_before_retry_dependent_decisions() {
    let source = squeeze(include_str!("../../../src/http3/server.rs"));
    // `selection` is mutable so a deferred destination claim can replace it;
    // the first occurrence is still the pre-deferred lookup pinned here.
    let selection = source
        .find("letmutselection=crate::proxy::backend_dispatch::select_upstream_target(")
        .expect("H3 selected-target lookup must remain present");
    let after_selection = &source[selection..];

    let cap = after_selection
        .find("letmutselected_base_proxy=crate::proxy::cap_proxy_retry_for_target(")
        .expect("H3 frontend must cap retry policy by selected target");
    let effective = after_selection
        .find("leteffective_proxy=crate::proxy::resolve_effective_proxy_for_target(")
        .expect("H3 frontend must resolve selected-target effective proxy");
    assert!(
        after_selection.contains("route_retry_ceiling"),
        "H3 frontend must retain the original route retry ceiling after target selection"
    );
    assert!(
        after_selection[effective..].contains("&selected_base_proxy"),
        "H3 effective proxy resolution must use the post-selection selected base proxy"
    );
    // `cap_proxy_retry_for_target` deliberately returns the proxy with
    // `Proxy.retry` UNCHANGED at the original route ceiling, so that a retry
    // rotation is not permanently pinned to the initial port's DestinationRule
    // cap. That makes the seam above a positioning contract only: the selected
    // target's own `maxRetries` still has to be re-checked here, or a
    // `maxRetries: 0` target reads a retry-enabled `Proxy.retry` and forces
    // request-body buffering on a path that can never retry.
    let target_retry_gate = after_selection
        .find("letselected_target_allows_retry=crate::proxy::current_retry_attempt_allowed(")
        .expect("H3 retry-dependent decisions must re-check the selected target's retry budget");
    let has_retry = after_selection
        .find("lethas_retry=")
        .expect("retry-dependent buffering decision must remain present");
    let native_h3_decision = after_selection
        .find("letbackend_supports_native_h3=")
        .expect("native-H3 dispatch decision must remain present");
    let circuit_breaker = after_selection
        .find("check_circuit_breaker(")
        .expect("H3 circuit-breaker check must remain present");

    assert!(
        after_selection[target_retry_gate..has_retry]
            .contains("route_retry_ceiling,&proxy,upstream_target.as_deref(),0)"),
        "the selected-target retry budget must be evaluated for the selected target at \
         attempt 0 against the original route ceiling"
    );
    assert!(
        after_selection[has_retry..].starts_with("lethas_retry=selected_target_allows_retry&&"),
        "the retry-dependent buffering decision must be gated on the selected target's \
         retry budget, not on the uncapped route-level Proxy.retry alone"
    );
    assert!(
        cap < target_retry_gate && target_retry_gate < has_retry,
        "retry cap must run before retry-dependent buffering/native-H3 gates"
    );
    assert!(
        effective < native_h3_decision,
        "effective proxy must be resolved before native-H3 capability decisions"
    );
    assert!(
        effective < circuit_breaker,
        "effective proxy must be resolved before circuit-breaker/admission dispatch"
    );
}

#[test]
fn h3_plain_and_grpc_bridges_keep_unresolved_base_proxy_for_retries() {
    let source = include_str!("../../../src/http3/server.rs");
    let bridge_call = source
        .find(
            "crate::http3::cross_protocol::run(crate::http3::cross_protocol::CrossProtocolRequest",
        )
        .expect("H3 cross-protocol bridge call must remain present");
    let bridge = &source[bridge_call..];
    // Only Plain and Grpc reach this bridge (WebSocket returns via its
    // dedicated bridge earlier), and both resolve the effective proxy per
    // attempt inside their dispatch loops — so the capped, UNRESOLVED base
    // proxy must be passed unconditionally, with no flavor-forked fallback to
    // the first target's effective proxy.
    let proxy_field = bridge
        .find("proxy: selected_base_proxy.as_ref(),")
        .expect("H3 plain/gRPC bridge must pass the capped unresolved base proxy unconditionally");
    let stream_field = bridge
        .find("stream: &mut stream,")
        .expect("H3 cross-protocol request literal must remain present");
    assert!(
        proxy_field < stream_field,
        "the base-proxy field must belong to this CrossProtocolRequest literal"
    );
    assert!(
        !bridge[..stream_field].contains("proxy: if matches!"),
        "the flavor-forked proxy selection was dead code (WebSocket never reaches this bridge); \
         do not reintroduce it"
    );
}

#[test]
fn h3_native_retry_loop_resolves_effective_proxy_per_attempt() {
    let source = include_str!("../../../src/http3/server.rs");
    let retry_loop = source
        .find(") = if let Some(retry_config) = &proxy.retry {")
        .expect("buffered native-H3 retry loop must remain present");
    let loop_src = &source[retry_loop..];

    // Initial attempt: resolve from the post-selection BASE proxy (never the
    // first target's effective proxy) before dispatching.
    let initial_resolve = loop_src
        .find("let attempt_dispatch_proxy = crate::proxy::resolve_effective_proxy_for_target(")
        .expect("native-H3 retry loop must resolve the attempt dispatch proxy");
    assert!(
        loop_src[initial_resolve..].contains("&selected_base_proxy"),
        "per-attempt resolution must feed from the post-selection base proxy"
    );
    let initial_dispatch = loop_src
        .find("proxy_to_backend_h3(")
        .expect("buffered native-H3 dispatch must remain present");
    assert!(
        initial_resolve < initial_dispatch,
        "the initial native-H3 attempt must dispatch with the resolved attempt proxy"
    );
    assert!(
        loop_src[initial_dispatch..].contains("attempt_dispatch_proxy.as_ref(),"),
        "proxy_to_backend_h3 must receive the per-attempt resolved proxy"
    );

    assert!(
        loop_src.contains("route_retry_ceiling"),
        "native-H3 retry must authorize against the original route ceiling"
    );
    // Rotated attempt: a rotation can cross from the SD fallback into a policy
    // port with its own per-port override (TLS/SNI/connectTimeout), so the
    // loop must RE-resolve after `select_next_retry_target` and before the
    // retried dispatch.
    let rotation = loop_src
        .find("select_next_retry_target(")
        .expect("native-H3 retry rotation must remain present");
    assert!(
        loop_src.contains("retry_attempt_allowed_for_target("),
        "native-H3 retry must re-check DestinationRule maxRetries for rotated candidates"
    );
    assert!(
        loop_src.contains("current_retry_attempt_allowed("),
        "native-H3 retry must re-check DestinationRule maxRetries for the current target"
    );
    let re_resolve = loop_src[rotation..]
        .find("let attempt_dispatch_proxy = crate::proxy::resolve_effective_proxy_for_target(")
        .expect("rotated native-H3 retry attempts must re-resolve the effective proxy");
    let rotated_dispatch = loop_src[rotation..]
        .find("result = proxy_to_backend_h3(")
        .expect("rotated native-H3 dispatch must remain present");
    assert!(
        re_resolve < rotated_dispatch,
        "the rotated attempt must re-resolve the effective proxy before dispatching"
    );
}

#[test]
fn h3_frontend_exposes_retry_capped_base_proxy_to_plugins() {
    // H1/H2 parity: `handle_proxy_request_inner` assigns `ctx.matched_proxy`
    // the BASE proxy after the post-selection retry seam (original route
    // ceiling retained), so plugins/logging must not see per-port TLS/timeout
    // overrides baked into the proxy on the H3 frontend only.
    let source = include_str!("../../../src/http3/server.rs");
    assert!(
        source.contains("ctx.matched_proxy = Some(Arc::clone(&selected_base_proxy));"),
        "H3 must expose the base proxy via ctx.matched_proxy (H1/H2 parity)"
    );
    assert!(
        source.contains("route_retry_ceiling"),
        "H3 must retain the original route retry ceiling for DestinationRule maxRetries"
    );
}

#[test]
fn h3_websocket_bridge_keeps_unresolved_base_proxy_for_retries() {
    let source = include_str!("../../../src/http3/server.rs");
    let websocket_call = source
        .find("crate::http3::websocket::handle_h3_websocket(")
        .expect("H3 WebSocket bridge call must remain present");
    let websocket_args = &source[websocket_call..];
    let proxy_arg = websocket_args
        .find("Arc::clone(&selected_base_proxy)")
        .expect("H3 WebSocket bridge must receive the post-selection unresolved base proxy");
    let effective_proxy_arg = websocket_args
        .find("\n            proxy,")
        .unwrap_or(usize::MAX);

    assert!(
        proxy_arg < effective_proxy_arg,
        "H3 WebSocket bridge must not inherit the first target's effective proxy"
    );
    assert!(
        websocket_args.contains("backend_path_is_policy_bound,"),
        "H3 WebSocket retries must receive the backend-path policy binding"
    );

    let websocket_source = include_str!("../../../src/http3/websocket.rs");
    assert!(
        websocket_source.contains("retry_target_preserves_backend_path("),
        "H3 WebSocket target rotation must preserve the authorized backend path"
    );
    assert!(
        websocket_source.contains("if retry_admitted_by_cb && !retry_path_mismatch"),
        "H3 WebSocket path mismatches must abort rather than retry the failed target"
    );
}

#[test]
fn h3_grpc_streaming_bridge_keeps_unresolved_base_proxy_for_selected_target() {
    let source = include_str!("../../../src/http3/server.rs");
    let streaming_call = source
        .find("crate::http3::cross_protocol::dispatch_grpc_streaming(")
        .expect("H3 streaming gRPC bridge call must remain present");
    let streaming_args = &source[streaming_call..];
    let base_proxy_arg = streaming_args
        .find("&selected_base_proxy")
        .expect("H3 streaming gRPC bridge must receive the capped unresolved base proxy");
    let effective_proxy_arg = streaming_args
        .find("\n                &proxy,")
        .unwrap_or(usize::MAX);

    assert!(
        base_proxy_arg < effective_proxy_arg,
        "H3 streaming gRPC bridge must not inherit the first target's effective proxy"
    );
}

#[test]
fn h3_backend_path_policy_runs_after_target_selection_and_before_dispatch() {
    let source = include_str!("../../../src/http3/server.rs");
    let backend_path_plugins = source
        .find("let backend_path_plugins = plugin_cache_view.backend_path_plugins();")
        .expect("H3 must load the prefiltered backend-path policy list");
    let selection = source
        .find("selection = crate::proxy::backend_dispatch::select_upstream_target(")
        .expect("H3 selected-target lookup must remain present");
    assert!(
        backend_path_plugins < selection,
        "H3 must load the cached backend-path plugin view before target selection"
    );
    let after_selection = &source[selection..];
    let path_policy = after_selection
        .find("if backend_path_is_policy_bound {")
        .expect("H3 must enforce backend-path policy after selecting a target");
    let circuit_breaker = after_selection
        .find("check_circuit_breaker(")
        .expect("H3 circuit-breaker check must remain present");
    assert!(
        path_policy < circuit_breaker,
        "backend-effective path policy must run before circuit breaking or backend dispatch"
    );

    let policy_block = &after_selection[path_policy..circuit_breaker];
    assert!(
        policy_block.contains("crate::proxy::build_backend_effective_path("),
        "H3 policy must use the shared backend URL path assembler"
    );
    assert!(
        policy_block.contains("target.path.as_deref()"),
        "H3 policy must include the initially selected target path"
    );
    assert!(
        policy_block.contains("run_h3_backend_path_plugins_or_send_reject("),
        "H3 policy rejections must be emitted before dispatch"
    );
    assert!(
        source.contains("let request_protocol = h3_plugin_protocol_for_request(")
            && source.contains(".grpc_web_request_view(&proxy.namespace, &proxy.id)"),
        "H3 gRPC-Web must retain its HTTP protocol key and use the composed cache view"
    );
    assert!(
        policy_block.contains("grpc_web_response_content_type,"),
        "H3 backend-path rejects must retain the client's gRPC-Web response encoding"
    );
    assert!(
        !source.contains("backend_dispatch::upstream_selection_hash_key("),
        "H3 external deferred hooks must not reselect a different target"
    );
    assert_eq!(
        policy_block
            .matches("run_h3_backend_path_plugins_or_send_reject(")
            .count(),
        1,
        "H3 must enforce policy exactly once on the pinned path"
    );
    assert!(
        source.contains("BackendPathBeforeProxyPass::RemainingDeferred"),
        "H3 must keep remaining side-effect hooks behind any required reauthorization"
    );
    let routing_hook = after_selection
        .find("BackendPathBeforeProxyPass::RoutingHeaderDeferred")
        .expect("H3 routing-header hook must remain present");
    assert!(
        path_policy < routing_hook && routing_hook < circuit_breaker,
        "H3 stateful path policy must reject before deferred external work"
    );
    let native_retry = source
        .find("// Resolve and validate the retry target before charging this")
        .expect("native H3 retry path must preflight the candidate path");
    let after_native_retry = &source[native_retry..];
    let native_mismatch = after_native_retry
        .find("Aborting H3 retry because the candidate would change")
        .expect("native H3 retry must reject a path-changing candidate");
    let native_intermediate_record = after_native_retry
        .find("record_h3_backend_admission_outcome(")
        .expect("native H3 retry intermediate accounting must remain present");
    assert!(
        native_mismatch < native_intermediate_record
            && after_native_retry[native_mismatch..native_intermediate_record].contains("break;"),
        "native H3 path mismatch must abort before intermediate retry accounting"
    );

    let cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    let retry_policy = cross_protocol
        .find("retry_target_preserves_backend_path(")
        .expect("cross-protocol H3 retry must retain the authorized target path");
    let retry_url = cross_protocol
        .find("let next_url = crate::proxy::build_backend_url_with_target(")
        .expect("cross-protocol retry URL reconstruction must remain present");
    assert!(
        retry_policy < retry_url,
        "retry target path policy must run before rebuilding the backend URL"
    );
    assert!(
        cross_protocol.contains("CrossProtocolRetryTarget::BackendPathMismatch"),
        "cross-protocol retries must distinguish a path mismatch from no target rotation"
    );
    assert!(
        cross_protocol.contains("CrossProtocolRetryTarget::RetryBudgetExceeded"),
        "cross-protocol retries must distinguish a DestinationRule maxRetries miss from path mismatch"
    );
    assert!(
        cross_protocol.contains("retry_attempt_allowed_for_target("),
        "cross-protocol candidate selection must re-resolve DestinationRule maxRetries"
    );
    assert!(
        cross_protocol.contains("route_retry_ceiling"),
        "cross-protocol HTTP/gRPC retries must authorize against the original route ceiling"
    );
    let grpc_retry = cross_protocol
        .rfind("let retry_target = select_next_cross_protocol_retry_target(")
        .expect("cross-protocol gRPC retry selection must remain present");
    let after_grpc_retry = &cross_protocol[grpc_retry..];
    let mismatch = after_grpc_retry
        .find("CrossProtocolRetryTarget::BackendPathMismatch")
        .expect("cross-protocol gRPC retry must inspect the mismatch result");
    let budget = after_grpc_retry
        .find("CrossProtocolRetryTarget::RetryBudgetExceeded")
        .expect("cross-protocol gRPC retry must inspect the retry-budget result");
    let failure_record = after_grpc_retry
        .find("let retry_error_class =")
        .expect("cross-protocol gRPC retry failure recording must remain present");
    assert!(
        mismatch < failure_record
            && budget < failure_record
            && after_grpc_retry[mismatch.min(budget)..failure_record].contains("break;"),
        "cross-protocol gRPC retries must abort before recording an intermediate retry attempt"
    );
}

#[test]
fn h3_grpc_web_policy_flavor_is_separate_from_backend_transport() {
    let source = include_str!("../../../src/http3/server.rs");
    let detected = source
        .find("let detected_http_flavor =")
        .expect("H3 must retain the original wire flavor");
    let websocket_precedence = source
        .find("detected_http_flavor == HttpFlavor::WebSocket")
        .expect("H3 WebSocket classification must suppress gRPC-Web promotion");
    let effective = source
        .find("let http_flavor = if grpc_web_response_content_type.is_some()")
        .expect("H3 must derive one effective gRPC flavor for gRPC-Web");
    let post_guard = source
        .find("if matches!(http_flavor, HttpFlavor::Grpc) && method != \"POST\"")
        .expect("H3 POST policy must use the effective flavor");
    let plugin_protocol = source
        .find("let request_protocol = h3_plugin_protocol_for_request(")
        .expect("H3 plugin selection must account for recognized gRPC-Web requests");
    let wire_flavor_stamp = source
        .find("ctx.set_request_http_flavor(detected_http_flavor)")
        .expect("H3 fault shaping must retain the immutable client wire flavor");
    let backend_flavor = source
        .find("let backend_http_flavor = if grpc_web_response_content_type.is_some()")
        .expect("H3 must derive backend transport flavor after request plugins");
    let translated_marker = source
        .find("request_is_grpc_web_translated(&ctx)")
        .expect("H3 backend promotion must require the trusted translation marker");
    let bridge = source
        .find(
            "crate::http3::cross_protocol::run(crate::http3::cross_protocol::CrossProtocolRequest",
        )
        .expect("H3 cross-protocol backend dispatch must remain present");

    assert!(
        detected < websocket_precedence
            && websocket_precedence < effective
            && effective < plugin_protocol
            && plugin_protocol < wire_flavor_stamp
            && wire_flavor_stamp < post_guard
            && plugin_protocol < backend_flavor
            && backend_flavor <= translated_marker
            && plugin_protocol < bridge,
        "wire classification, WebSocket precedence, policy promotion, route policy selection, \
         immutable wire-flavor stamping, POST policy, translation-aware backend flavor, and \
         dispatch must stay in that order"
    );
    assert!(
        source[bridge..].contains("flavor: backend_http_flavor,"),
        "the backend bridge must receive the translation-aware transport flavor"
    );
    let squeezed = squeeze(source);
    assert!(
        squeezed.contains("lethas_retry=selected_target_allows_retry&&matchbackend_http_flavor{")
            && squeezed.contains("letuse_native_h3_grpc=backend_http_flavor==HttpFlavor::Grpc"),
        "retry and native-gRPC transport decisions must use backend flavor"
    );

    let cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    assert!(
        cross_protocol.contains("write_grpc_error_for_request(")
            && cross_protocol.contains("translated_error_response("),
        "gRPC bridge failures must retain translated gRPC-Web client shaping"
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommittedObservation {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Default)]
struct CommittedCapturePlugin {
    committed_calls: AtomicUsize,
    log_saw_committed_calls: AtomicUsize,
    observation: Mutex<Option<CommittedObservation>>,
    committed: tokio::sync::Notify,
}

struct StalledCommittedPlugin {
    calls: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Notify>,
    completed: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl Plugin for StalledCommittedPlugin {
    fn name(&self) -> &str {
        "stalled_h3_committed"
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.release.notified().await;
        self.completed.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl Plugin for CommittedCapturePlugin {
    fn name(&self) -> &str {
        "h3_committed_capture"
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) {
        self.committed_calls.fetch_add(1, Ordering::SeqCst);
        *self.observation.lock().expect("observation lock") = Some(CommittedObservation {
            status: response_status,
            headers: response_headers.clone(),
            body: body.to_vec(),
        });
        self.committed.notify_one();
    }

    async fn log(&self, _summary: &TransactionSummary) {
        self.log_saw_committed_calls.store(
            self.committed_calls.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
}

#[tokio::test]
async fn h3_grpc_web_reject_commits_final_wire_shape_once_before_log() {
    let capture = Arc::new(CommittedCapturePlugin::default());
    let plugins: Vec<Arc<dyn Plugin>> = vec![capture.clone()];
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/pkg.Service/Denied".to_string(),
    );

    let reject_headers = HashMap::from([
        (
            "access-control-allow-origin".to_string(),
            "https://browser.example".to_string(),
        ),
        ("x-grpc-ratelimit-limit".to_string(), "10".to_string()),
        ("content-type".to_string(), "text/plain".to_string()),
        ("content-length".to_string(), "999".to_string()),
        ("grpc-status".to_string(), "7".to_string()),
        ("connection".to_string(), "keep-alive".to_string()),
    ]);
    ferrum_edge::_test_support::run_h3_reject_response_committed_hooks(
        &plugins,
        &mut ctx,
        HttpFlavor::Grpc,
        Some("application/grpc-web-text+proto"),
        StatusCode::FORBIDDEN,
        bytes::Bytes::from_static(br#"{"error":"blocked"}"#),
        &reject_headers,
    )
    .await;
    capture.log(&TransactionSummary::default()).await;

    assert_eq!(capture.committed_calls.load(Ordering::SeqCst), 1);
    assert_eq!(capture.log_saw_committed_calls.load(Ordering::SeqCst), 1);
    let observed = capture
        .observation
        .lock()
        .expect("observation lock")
        .clone()
        .expect("committed response observation");
    assert_eq!(observed.status, StatusCode::OK.as_u16());
    assert_eq!(
        observed.headers.get("content-type").map(String::as_str),
        Some("application/grpc-web-text+proto")
    );
    assert_eq!(
        observed
            .headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://browser.example")
    );
    assert_eq!(
        observed
            .headers
            .get("x-grpc-ratelimit-limit")
            .map(String::as_str),
        Some("10")
    );
    assert_eq!(
        observed
            .headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok()),
        Some(observed.body.len())
    );
    assert!(!observed.headers.contains_key("grpc-status"));
    assert!(!observed.headers.contains_key("connection"));
    let decoded = BASE64.decode(&observed.body).expect("decode text response");
    assert_eq!(decoded.first(), Some(&0x80));
    assert!(
        decoded
            .windows(b"grpc-status: 7\r\n".len())
            .any(|window| window == b"grpc-status: 7\r\n")
    );
}

#[tokio::test]
async fn h3_reject_committed_timeout_selects_status_four_and_runs_remaining_hooks_once() {
    use ferrum_edge::_test_support::{
        gateway_deadline_response_selected_for_test, set_grpc_deadline_budget_for_test,
    };

    for grpc_web_content_type in [None, Some("application/grpc-web+proto")] {
        let stalled_calls = Arc::new(AtomicUsize::new(0));
        let stalled_release = Arc::new(tokio::sync::Notify::new());
        let stalled_completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let capture = Arc::new(CommittedCapturePlugin::default());
        let plugins: Vec<Arc<dyn Plugin>> = vec![
            Arc::new(StalledCommittedPlugin {
                calls: Arc::clone(&stalled_calls),
                release: Arc::clone(&stalled_release),
                completed: Arc::clone(&stalled_completed),
            }),
            capture.clone(),
        ];
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/pkg.Service/Denied".to_string(),
        );
        set_grpc_deadline_budget_for_test(&mut ctx, Some(5));
        let headers = HashMap::from([
            (
                "access-control-allow-origin".to_string(),
                "https://browser.example".to_string(),
            ),
            ("content-length".to_string(), "999".to_string()),
            ("grpc-status".to_string(), "7".to_string()),
        ]);

        let replaced = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            ferrum_edge::_test_support::run_h3_reject_response_committed_hooks(
                &plugins,
                &mut ctx,
                HttpFlavor::Grpc,
                grpc_web_content_type,
                StatusCode::FORBIDDEN,
                bytes::Bytes::from_static(br#"{"error":"blocked"}"#),
                &headers,
            ),
        )
        .await
        .expect("stalled committed observer must not retain the H3 handler");

        assert!(replaced);
        assert!(gateway_deadline_response_selected_for_test(&ctx));
        assert_eq!(stalled_calls.load(Ordering::SeqCst), 1);
        assert!(!stalled_completed.load(Ordering::SeqCst));
        assert_eq!(capture.committed_calls.load(Ordering::SeqCst), 0);

        stalled_release.notify_waiters();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            capture.committed.notified(),
        )
        .await
        .expect("detached H3 committed observers must continue in plugin order");
        assert!(stalled_completed.load(Ordering::SeqCst));
        assert_eq!(capture.committed_calls.load(Ordering::SeqCst), 1);
        let observed = capture
            .observation
            .lock()
            .expect("observation lock")
            .clone()
            .expect("remaining committed observer");
        assert_eq!(observed.status, StatusCode::OK.as_u16());
        assert_eq!(
            observed
                .headers
                .get("access-control-allow-origin")
                .map(String::as_str),
            Some("https://browser.example")
        );
        if grpc_web_content_type.is_some() {
            assert!(!observed.headers.contains_key("grpc-status"));
            assert_eq!(observed.body.first(), Some(&0x80));
            assert!(
                observed
                    .body
                    .windows(b"grpc-status: 4".len())
                    .any(|window| window == b"grpc-status: 4")
            );
        } else {
            assert_eq!(
                observed.headers.get("grpc-status").map(String::as_str),
                Some("4")
            );
            assert!(observed.body.is_empty());
        }
    }
}

#[test]
fn h3_grpc_web_accept_rejection_keeps_http_406_contract() {
    let source = include_str!("../../../src/http3/server.rs");
    let send_start = source
        .find("async fn send_h3_grpc_web_reject_with_recv_halt(")
        .expect("gRPC-Web reject sender must remain present");
    let send_end = source[send_start..]
        .find("pub(crate) async fn run_h3_reject_response_committed_hooks(")
        .map(|offset| send_start + offset)
        .expect("gRPC-Web sender must remain bounded");
    let send = &source[send_start..send_end];
    assert!(
        send.contains("reject_headers_mark_accept_not_acceptable(")
            && send.contains("normalize_reject_response("),
        "H3 gRPC-Web reject sender must preserve Accept negotiation HTTP 406 via the shared normalizer"
    );

    let committed_start = source
        .find("async fn run_h3_deadline_bounded_reject_committed_hooks_with_policy(")
        .expect("bounded committed-hook helper must remain present");
    let committed = &source[committed_start..];
    let committed_end = committed
        .find("async fn finalize_h3_upload_deadline_rejection(")
        .expect("committed-hook helper boundary must remain present");
    let committed = &committed[..committed_end];
    assert!(
        committed.contains("reject_headers_mark_accept_not_acceptable("),
        "H3 committed reject observers must see Accept negotiation as HTTP 406, not gRPC-Web 200"
    );

    let log_start = source
        .find("fn h3_reject_log_status_and_metadata(")
        .expect("H3 reject log helper must remain present");
    let log = &source[log_start..];
    let log_end = log
        .find("pub(crate) fn replace_buffered_h3_response_with_grpc_deadline(")
        .expect("H3 reject log helper boundary must remain present");
    let log = &log[..log_end];
    assert!(
        log.contains("reject_headers_mark_accept_not_acceptable("),
        "H3 reject logging must keep Accept negotiation failures as HTTP 406"
    );
    assert!(
        !log.contains("Bytes::copy_from_slice(http_body)"),
        "H3 reject logging must not full-copy an authorized terminate body merely for metadata"
    );
    assert!(
        log.contains("intact_framed_unary_terminate_signal("),
        "H3 reject logging must share the borrowed framed-unary predicate with the normalizer"
    );
}

#[test]
fn h3_plugin_reject_commit_is_not_deferred_to_send_helpers() {
    let source = include_str!("../../../src/http3/server.rs");
    let send_start = source
        .find("async fn send_h3_grpc_web_reject(")
        .expect("gRPC-Web reject sender must remain present");
    let grpc_web_send_end = source[send_start..]
        .find("pub(crate) async fn run_h3_reject_response_committed_hooks(")
        .map(|offset| send_start + offset)
        .expect("gRPC-Web sender must remain bounded");
    let plugin_send_start = source
        .find("async fn send_h3_plugin_reject_flavor_aware(")
        .expect("plugin reject sender must remain present");
    let plugin_send_end = source[plugin_send_start..]
        .find("/// Send a trailers-only gRPC error response over H3.")
        .map(|offset| plugin_send_start + offset)
        .expect("plugin reject sender must remain bounded");
    assert!(
        !source[send_start..grpc_web_send_end].contains("on_response_committed(")
            && !source[plugin_send_start..plugin_send_end].contains("on_response_committed("),
        "wire send helpers must not run committed hooks after rejection logging"
    );

    assert!(
        source.contains("run_h3_deadline_bounded_reject_committed_hooks_with_policy("),
        "every public and policy-aware H3 rejection helper must share one bounded contract"
    );
    let committed_boundaries = source
        .matches("run_h3_reject_response_committed_hooks(")
        .count()
        + source
            .matches("run_h3_deadline_bounded_reject_committed_hooks(")
            .count();
    let plugin_reject_sends = source
        .matches("send_h3_plugin_reject_flavor_aware(")
        .count();
    // TimedOut terminal uploads call the recv-halt variant directly (halt_recv=
    // false). Exclude its definition and the thin aware() wrapper's internal call.
    let direct_recv_halt_plugin_rejects = source
        .matches("send_h3_plugin_reject_flavor_aware_with_recv_halt(")
        .count()
        .saturating_sub(2);
    let terminal_finalizer = source
        .split("async fn finalize_h3_terminal_body_read_rejection(")
        .nth(1)
        .expect("shared terminal-body rejection finalizer")
        .split("/// Optional HTTP/3 listener settings")
        .next()
        .expect("bounded terminal-body rejection finalizer");
    let shared_terminal_commit_definitions = terminal_finalizer
        .matches("run_h3_reject_response_committed_hooks(")
        .count();
    assert_eq!(
        shared_terminal_commit_definitions, 1,
        "the terminal-body finalizer must own exactly one committed boundary"
    );

    // The terminal provider path shares one finalizer across three writable
    // rejection exits. Expand that shared boundary when comparing call sites,
    // and exclude the separate final-body and finalized-egress plugin
    // rejections, which commit before a non-plugin-aware sender.
    let shared_terminal_reject_sends = source
        .matches("let rejection = finalize_h3_terminal_body_read_rejection(")
        .count();
    assert_eq!(shared_terminal_reject_sends, 3);
    let terminal_dispatch = source
        .split("// Terminal final-body hooks may perform provider egress.")
        .nth(1)
        .expect("terminal provider dispatch")
        .split("let backend_admission_plugins = plugin_cache_view.backend_admission_plugins();")
        .next()
        .expect("bounded terminal provider dispatch");
    let non_plugin_terminal_boundaries = terminal_dispatch
        .matches("run_h3_reject_response_committed_hooks(")
        .count();
    assert_eq!(
        non_plugin_terminal_boundaries, 2,
        "the final-body and finalized-egress plugin rejections each need a committed boundary"
    );
    let effective_plugin_committed_boundaries =
        committed_boundaries - shared_terminal_commit_definitions - non_plugin_terminal_boundaries
            + shared_terminal_reject_sends;
    assert_eq!(
        effective_plugin_committed_boundaries,
        plugin_reject_sends + direct_recv_halt_plugin_rejects + 1,
        "every plugin-aware reject send needs one direct or shared committed boundary; the extra count is the second helper definition"
    );

    for (start_marker, end_marker, phase) in [
        (
            "// Execute on_request_received hooks",
            "// Materialize query params before authentication.",
            "on_request_received",
        ),
        (
            "// Authentication phase (pre-computed auth plugin list",
            "// Authorization plugins that inspect bodies buffer only after",
            "authenticate",
        ),
        (
            "// Authorization phase (pre-computed authorize plugin list",
            "let maybe_needs_request_buffering =",
            "authorize",
        ),
    ] {
        let start = source.find(start_marker).expect("reject phase start");
        let end = source[start..]
            .find(end_marker)
            .map(|offset| start + offset)
            .expect("reject phase end");
        let phase_source = &source[start..end];
        let committed = phase_source
            .rfind("run_h3_reject_response_committed_hooks(")
            .unwrap_or_else(|| panic!("{phase} must commit its final reject"));
        let log = phase_source
            .rfind("log_rejected_request(")
            .unwrap_or_else(|| panic!("{phase} must log its reject"));
        let send = phase_source
            .rfind("send_h3_plugin_reject_flavor_aware(")
            .unwrap_or_else(|| panic!("{phase} must send its reject"));
        assert!(
            committed < log && log < send,
            "{phase} must commit exactly before log, then send"
        );
    }
}

#[test]
fn h3_grpc_web_early_plugin_rejects_use_client_wire_shape() {
    let source = include_str!("../../../src/http3/server.rs");
    let phases = [
        (
            "// Execute on_request_received hooks",
            "// Materialize query params before authentication.",
            "on_request_received",
        ),
        (
            "// Authentication phase (pre-computed auth plugin list",
            "// Authorization plugins that inspect bodies buffer only after",
            "authentication",
        ),
        (
            "// Authorization phase (pre-computed authorize plugin list",
            "// before_proxy hooks — only clone headers",
            "authorization",
        ),
    ];

    for (start_marker, end_marker, phase) in phases {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("H3 {phase} phase must remain present"));
        let end = source[start..]
            .find(end_marker)
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("H3 {phase} phase must remain bounded"));
        let phase_source = &source[start..end];
        assert!(
            phase_source.contains("matches!(http_flavor, HttpFlavor::Grpc)"),
            "H3 {phase} rejects must normalize with the effective gRPC flavor"
        );
        assert!(
            phase_source.contains("send_h3_plugin_reject_flavor_aware(")
                && phase_source.contains("grpc_web_response_content_type,"),
            "H3 {phase} rejects must retain the original gRPC-Web response encoding"
        );
    }
}

#[test]
fn h3_deferred_hooks_cannot_spoof_backend_gateway_assertions() {
    let source = include_str!("../../../src/http3/server.rs");
    let routing_hook = source
        .rfind("BackendPathBeforeProxyPass::RoutingHeaderDeferred")
        .expect("H3 deferred routing-header hook must remain present");
    let after_routing_hook = &source[routing_hook..];
    let refresh = after_routing_hook
        .find("refresh_backend_gateway_assertion_headers(&ctx, &mut proxy_headers)")
        .expect("H3 must refresh gateway assertions after deferred routing hooks");
    let baggage_strip = after_routing_hook
        .find("strip_egress_baggage_in_map(")
        .expect("H3 must reapply egress baggage policy after deferred routing hooks");
    let remaining_hook = after_routing_hook
        .find("BackendPathBeforeProxyPass::RemainingDeferred")
        .expect("H3 remaining deferred hook pass must remain present");
    assert!(
        refresh < baggage_strip && baggage_strip < remaining_hook,
        "H3 must restore gateway assertions and baggage policy before final enforcement"
    );
    assert!(
        !after_routing_hook[..remaining_hook].contains("select_upstream_target("),
        "H3 deferred headers must not steer onto a different target"
    );

    let remaining_hook = routing_hook + remaining_hook;
    assert!(
        source[remaining_hook..]
            .contains("refresh_backend_gateway_assertion_headers(&ctx, &mut proxy_headers)"),
        "H3 must restore gateway assertions after every deferred hook pass"
    );
    assert!(
        source[remaining_hook..].contains("strip_egress_baggage_in_map("),
        "H3 must restore egress baggage policy after every deferred hook pass"
    );

    let websocket = include_str!("../../../src/http3/websocket.rs");
    assert!(websocket.contains("\"x-geo-country\","));
    assert!(websocket.contains("if let Some(country) = ctx.backend_geo_country()"));

    // Native H3 request trailers are sanitized through the shared late-boundary
    // helper (not an inline strip). Pin both the call site and the geo arm so a
    // refactor cannot drop the reserved assertion from either side.
    let h3_client = include_str!("../../../src/http3/client.rs");
    let trailer_recv = h3_client
        .find("frontend_stream.recv_trailers().await")
        .expect("native H3 relay must read client request trailers");
    let trailer_finish = h3_client[trailer_recv..]
        .find("backend_stream\n            .finish()")
        .or_else(|| h3_client[trailer_recv..].find("backend_stream.finish()"))
        .expect("native H3 relay must finish the backend stream after trailers");
    let trailer_block = &h3_client[trailer_recv..trailer_recv + trailer_finish];
    assert!(
        trailer_block.contains("sanitize_backend_request_trailers(&mut trailers)"),
        "H3 client request trailers must pass through the shared backend-trailer sanitizer"
    );

    let headers = include_str!("../../../src/proxy/headers.rs");
    let forbidden_start = headers
        .find("fn is_forbidden_backend_request_trailer_name")
        .expect("shared request-trailer forbid helper must remain present");
    let forbidden_tail = &headers[forbidden_start..];
    let forbidden_end = forbidden_tail
        .find("\npub(crate) fn sanitize_backend_request_trailers")
        .expect("sanitize helper must follow the forbid predicate");
    let forbidden = &forbidden_tail[..forbidden_end];
    assert!(
        forbidden.contains("\"x-geo-country\""),
        "H3 client trailers must not reintroduce a reserved geo assertion"
    );
    assert!(
        forbidden.contains("name.starts_with(\"x-consumer-\")"),
        "shared request-trailer forbid helper must reject consumer identity assertions"
    );
}

#[test]
fn h3_flavor_aware_reject_metrics_match_the_http_wire_status() {
    let source = include_str!("../../../src/http3/server.rs");
    let helper = source
        .find("fn record_h3_flavor_aware_reject(")
        .map(|start| &source[start..])
        .expect("H3 flavor-aware metric helper must remain present");
    assert!(helper.contains("matches!(flavor, HttpFlavor::Grpc)"));
    assert!(helper.contains("StatusCode::OK.as_u16()"));

    for (status, phase) in [
        (404, "route miss"),
        (405, "method reject"),
        (413, "body reject"),
    ] {
        assert!(
            source.contains(&format!(
                "record_h3_flavor_aware_reject(&state, http_flavor, {status})"
            )),
            "H3 {phase} must record its normalized gRPC/gRPC-Web wire status"
        );
    }
}

#[test]
fn h3_cross_protocol_http1_admission_uses_logical_scope_lane() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let pending_gate = source
        .find("let pending_cap =")
        .expect("H3-to-plain pending gate");
    let gate_tail = &source[pending_gate..];
    let acquisition = gate_tail
        .find(".try_acquire(")
        .expect("scope-keyed H1 admission");
    let acquisition_tail = &gate_tail[acquisition..];
    let acquisition_end = acquisition_tail
        .find("Some(cap),")
        .expect("pending cap argument");
    let acquisition_call = &acquisition_tail[..acquisition_end];

    assert!(
        acquisition_call.contains("pending_scope.as_ref()")
            || acquisition_call.contains("pending_limit_scope_for_proxy"),
        "the H3-to-plain bridge must acquire against the precomputed logical scope"
    );
    assert!(
        !acquisition_call.contains("effective_host"),
        "selected endpoint host must not key the H1 pending lane"
    );
}

/// The H1 admission lane must be keyed by the DestinationRule POLICY port —
/// `UpstreamTarget::dispatch_policy_port()`, the declared Service port under
/// `targetPort` remapping — exactly like `proxy_to_backend` /
/// `proxy_to_backend_retry`. Keying the bridge by the DIAL port instead splits
/// one destination's in-flight budget across two lanes for H1/H2 vs H3, so a
/// cap of N admits 2N combined, and it makes an explicit
/// `portLevelSettings[{port: 80}]` cap invisible to the bridge.
#[test]
fn h3_cross_protocol_http1_admission_keys_the_policy_port_not_the_dial_port() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let pending_gate = source
        .find("let pending_cap =")
        .expect("H3-to-plain pending gate");
    let gate_tail = &source[pending_gate..];
    let acquisition = gate_tail
        .find(".try_acquire(")
        .expect("scope-keyed H1 admission");
    let cap_lookup = &gate_tail[..acquisition];
    let acquisition_tail = &gate_tail[acquisition..];
    let acquisition_end = acquisition_tail
        .find("Some(cap),")
        .expect("pending cap argument");
    let acquisition_call = &acquisition_tail[..acquisition_end];

    assert!(
        cap_lookup.contains("dispatch_policy_port"),
        "the per-port http1MaxPendingRequests cap lookup must use the DR policy port"
    );
    assert!(
        !cap_lookup.contains("dispatch_dial_port"),
        "the dial port is a transport address, not a policy source"
    );
    assert!(
        acquisition_call.contains("dispatch_policy_port,"),
        "the H3-to-plain bridge must acquire in the policy-port lane the H1/H2 path uses"
    );
    assert!(
        !acquisition_call.contains("dispatch_dial_port"),
        "the H3 bridge must not open a dial-port-keyed second admission lane"
    );
    assert!(
        !acquisition_call.contains("effective_host"),
        "logical scope identity replaces the selected-host key (issue #3778)"
    );

    // Both bridge dispatch sites (buffered retry loop and streaming dispatch)
    // must derive that port through the one shared helper.
    let helper = "let dispatch_policy_port = crate::proxy::dispatch_policy_port_for_target(";
    assert_eq!(
        source.matches(helper).count(),
        2,
        "both H3-to-plain dispatch sites must derive the policy port via the shared helper"
    );

    // ...and the H1/H2 path must derive it through the same helper, so the two
    // frontends cannot drift apart again.
    let h1h2 = include_str!("../../../src/proxy/mod.rs");
    for binding in ["pending_policy_port", "retry_policy_port"] {
        let expected =
            format!("let {binding} = dispatch_policy_port_for_target(proxy, upstream_target);");
        assert!(
            h1h2.contains(&expected),
            "the H1/H2 H1-admission lane port `{binding}` must come from the shared helper"
        );
    }
}
