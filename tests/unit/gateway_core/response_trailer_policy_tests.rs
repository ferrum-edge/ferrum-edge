//! Backend trailers must not re-open the response-header policy a protocol
//! path already applied — and must survive untouched when no policy governs
//! them.
//!
//! `after_proxy` and every later response-header phase see only the INITIAL
//! header map, so a backend trailer repeating a governed field name lands on
//! the wire after the policy boundary. The reconciliation here is the boundary
//! that closes that gap on the buffered native-HTTP/3 send path, on the plain
//! native/refined HTTP/3 streaming relays, on the plain direct-HTTP/2 streaming
//! relay, and — for application metadata only — on every NATIVE STREAMING gRPC
//! relay (GHSA-r78v-rc86-6r86), without punishing chains that apply no
//! response-header policy at all (issue #2941 — auth/logging-only plugins keep
//! their trailers).
//!
//! Reserved-field handling is selected STRUCTURALLY by the call site
//! (`TrailerSectionKind`), never from a trailer's own name: on a native gRPC
//! terminal section the three reserved status fields survive, and on a plain
//! response the very same names get no exemption at all.
//!
//! The streaming relays commit their initial HEADERS frame before the backend's
//! trailers exist, so they retain the pre-policy header map instead of
//! per-trailer values and derive the witness at the trailer frame; the
//! `reconcile_streaming` cases below pin that capture decision as well as the
//! shared governance rules.

use std::collections::HashMap;

use ferrum_edge::_test_support::govern_streaming_grpc_web_terminal_frame_for_test as grpc_web_frame;
use ferrum_edge::_test_support::govern_streaming_h2_backend_trailers_for_test as govern_h2;
use ferrum_edge::_test_support::govern_streaming_h2_native_grpc_trailers_for_test as govern_h2_grpc;
use ferrum_edge::_test_support::reconcile_backend_trailers_with_response_policy_for_test as reconcile;
use ferrum_edge::_test_support::reconcile_streaming_backend_trailers_for_test as reconcile_streaming;
use ferrum_edge::_test_support::reconcile_streaming_native_grpc_trailers_for_test as reconcile_grpc;

fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect()
}

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn has(trailers: &[(String, String)], name: &str) -> bool {
    trailers.iter().any(|(key, _)| key == name)
}

#[test]
fn auth_logging_only_chain_preserves_every_backend_trailer() {
    // No declared policy names and no observed header mutation: nothing about
    // this chain can be re-opened by a trailer, so all of them are forwarded.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[
            ("x-backend-finished", "true"),
            ("x-request-id", "trail-auth-1"),
        ],
        &backend,
        &backend,
        &[],
        false,
    );
    assert_eq!(surviving.len(), 2, "surviving trailers: {surviving:?}");
    assert!(has(&surviving, "x-backend-finished"));
    assert!(has(&surviving, "x-request-id"));
}

#[test]
fn declared_policy_name_strips_only_that_trailer_field() {
    // The removal was a NO-OP on the initial map — the backend never sent
    // `x-powered-by` as a header — so only the config-time declaration can
    // catch it. Every ungoverned trailer must still survive.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[
            ("x-powered-by", "backend/1.2"),
            ("x-backend-finished", "true"),
        ],
        &backend,
        &backend,
        &names(&["x-powered-by", "x-frame-options"]),
        false,
    );
    assert_eq!(surviving.len(), 1, "surviving trailers: {surviving:?}");
    assert!(!has(&surviving, "x-powered-by"));
    assert!(has(&surviving, "x-backend-finished"));
}

#[test]
fn declared_policy_name_matches_case_insensitively() {
    let backend = headers(&[]);
    let surviving = reconcile(
        &[("x-powered-by", "backend/1.2")],
        &backend,
        &backend,
        &names(&["X-Powered-By"]),
        false,
    );
    assert!(surviving.is_empty(), "surviving trailers: {surviving:?}");
}

#[test]
fn every_duplicate_field_line_of_a_governed_trailer_is_removed() {
    // `HeaderMap` keeps repeated field lines; a single-shot removal would leave
    // the later copies on the wire and defeat the whole reconciliation.
    let backend = headers(&[]);
    let surviving = reconcile(
        &[
            ("x-powered-by", "first"),
            ("x-powered-by", "second"),
            ("x-powered-by", "third"),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &names(&["x-powered-by"]),
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn observed_header_removal_strips_the_matching_trailer_without_a_declaration() {
    // A plugin that declares nothing (custom plugin, request-time route
    // override) still cannot be bypassed: the diff against the pre-policy
    // witness sees the field disappear from the header map.
    let before = headers(&[
        ("x-internal-token", "leaked"),
        ("content-type", "text/plain"),
    ]);
    let after = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[("x-internal-token", "leaked"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn observed_header_override_and_injection_both_strip_the_trailer_copy() {
    let before = headers(&[("x-frame-options", "ALLOWALL")]);
    let after = headers(&[("x-frame-options", "DENY"), ("x-added", "gateway")]);
    let surviving = reconcile(
        &[
            ("x-frame-options", "ALLOWALL"),
            ("x-added", "backend-spoof"),
            ("x-keep", "yes"),
        ],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn mixed_case_header_mutation_is_still_observed() {
    // Plugins may synthesize mixed-case keys; the trailer channel is always
    // lowercase, so the comparison has to be case-insensitive on both sides.
    let before = headers(&[("X-Internal-Token", "leaked")]);
    let after = headers(&[]);
    let surviving = reconcile(
        &[("x-internal-token", "leaked")],
        &before,
        &after,
        &[],
        false,
    );
    assert!(surviving.is_empty(), "surviving trailers: {surviving:?}");
}

#[test]
fn duplicate_case_variants_before_policy_are_ambiguous_and_governed() {
    // Two case variants of one field name in the pre-policy map: no single
    // value represents the field, so the reconciliation cannot prove the chain
    // left it alone and must not forward the trailer copy. A "first match wins"
    // lookup would have compared against whichever variant iteration happened
    // to reach first and called it unchanged.
    let before = headers(&[("x-name", "same"), ("X-Name", "same")]);
    let after = headers(&[("x-name", "same"), ("X-Name", "same")]);
    let surviving = reconcile(
        &[("x-name", "same"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn duplicate_case_variants_after_policy_are_ambiguous_and_governed() {
    // A plugin synthesized a second case variant carrying a different value.
    // One of the two matches the backend's pre-policy value exactly, so an
    // arbitrary first-match lookup could report "unchanged" and let the backend
    // trailer through beside the plugin's copy.
    let before = headers(&[("x-name", "backend")]);
    let after = headers(&[("x-name", "backend"), ("X-Name", "gateway")]);
    let surviving = reconcile(
        &[("x-name", "backend"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn an_absent_backend_field_is_unchanged_only_with_zero_final_matches() {
    // The backend sent the field only as a trailer. Any case variant appearing
    // in the final map is a gateway-owned value the trailer would contradict.
    let before = headers(&[]);
    let after = headers(&[("X-Name", "gateway")]);
    let surviving = reconcile(
        &[("x-name", "backend"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn unbounded_policy_drops_every_reconcilable_trailer() {
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[("x-backend-finished", "true"), ("x-request-id", "abc")],
        &backend,
        &backend,
        &[],
        true,
    );
    assert!(surviving.is_empty(), "surviving trailers: {surviving:?}");
}

#[test]
fn unbounded_policy_drops_trailer_only_representation_metadata() {
    // `ai_stream_router`'s Anthropic SSE normalization removes / invalidates
    // these fields on the INITIAL header map. When the backend sent them ONLY
    // as trailers, the pre-policy and final maps both lack the name
    // (absent → absent), so the mutation witness forwards them unless the
    // plugin's Unbounded declaration fails closed.
    let backend = headers(&[("content-type", "text/event-stream")]);
    let surviving = reconcile(
        &[
            ("content-encoding", "gzip"),
            ("content-length", "42"),
            ("vary", "accept-encoding"),
            ("etag", "\"provider-repr\""),
            ("digest", "sha-256=:AAAA:"),
            ("signature", "sig1=:BBBB:"),
            ("x-amz-checksum-sha256", "deadbeef"),
            ("x-checksum-crc32", "AAAAAA=="),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &[],
        true,
    );
    assert!(
        surviving.is_empty(),
        "trailer-only representation metadata must not survive Unbounded: {surviving:?}"
    );
}

#[test]
fn a_grpc_named_trailer_gets_no_exemption_from_the_unbounded_arm() {
    // `reconcile` here is the PLAIN-section entry point. Reserved-field handling
    // is selected structurally by the call site (`TrailerSectionKind`), never by
    // the trailer's own name, so on a plain response a `grpc-*` trailer is an
    // ordinary backend field. Exempting it by NAME would hand any non-gRPC
    // backend a one-word bypass of a fail-closed response-header policy.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[
            ("grpc-status", "0"),
            ("grpc-message", "backend said so"),
            ("grpc-status-details-bin", "AAAA"),
            ("x-powered-by", "backend/1.2"),
        ],
        &backend,
        &backend,
        &[],
        true,
    );
    assert!(
        surviving.is_empty(),
        "a grpc-* name must not bypass the unbounded arm: {surviving:?}"
    );
}

#[test]
fn a_grpc_named_trailer_gets_no_exemption_from_observed_mutation() {
    // The mirror bypass: a non-gRPC backend names its smuggled field
    // `grpc-status` and the gateway's observed removal of that same field from
    // the initial header map would be undone by the trailer copy.
    let before = headers(&[
        ("grpc-status", "13"),
        ("x-internal-token", "leaked"),
        ("content-type", "text/plain"),
    ]);
    let after = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile(
        &[
            ("grpc-status", "13"),
            ("x-internal-token", "leaked"),
            ("x-keep", "yes"),
        ],
        &before,
        &after,
        &[],
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn an_explicitly_named_grpc_control_trailer_is_still_removed() {
    // Naming `grpc-status` in a response-header policy remains a deliberate
    // operator declaration and removes it, exactly as any other declared name.
    let backend = headers(&[]);
    let surviving = reconcile(
        &[("grpc-status", "0"), ("grpc-message", "ok")],
        &backend,
        &backend,
        &names(&["Grpc-Status"]),
        false,
    );
    assert_eq!(
        surviving,
        vec![("grpc-message".to_string(), "ok".to_string())]
    );
}

#[test]
fn sse_style_trailer_only_content_length_removal_is_bound_by_the_declaration() {
    // The load-bearing built-in-ownership case. `sse` with
    // `strip_content_length` removes `content-length` from the INITIAL map; when
    // the backend sent the field only as a TRAILER that removal is a no-op, so
    // the observed-mutation witness proves absent -> absent and forwards the
    // trailer. Only the config-time declaration closes it.
    let backend = headers(&[("content-type", "text/event-stream")]);

    let undeclared = reconcile(
        &[("content-length", "4096"), ("x-keep", "yes")],
        &backend,
        &backend,
        &[],
        false,
    );
    assert!(
        has(&undeclared, "content-length"),
        "without a declaration the no-op removal is invisible: {undeclared:?}"
    );

    let declared = reconcile(
        &[("content-length", "4096"), ("x-keep", "yes")],
        &backend,
        &backend,
        &names(&[
            "content-type",
            "cache-control",
            "x-accel-buffering",
            "content-length",
        ]),
        false,
    );
    assert_eq!(declared, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn an_idempotent_gateway_write_is_bound_by_the_declaration_only() {
    // The second shape the witness cannot see: the gateway writes a value the
    // backend already sent verbatim (`response_caching`'s guessable
    // `x-cache-status: MISS`, an echoed `traceparent`, an already-nominated
    // `vary` token). Before == after, so the diff is empty.
    let before = headers(&[("x-cache-status", "MISS")]);
    let after = headers(&[("x-cache-status", "MISS")]);

    let undeclared = reconcile(&[("x-cache-status", "HIT")], &before, &after, &[], false);
    assert!(
        has(&undeclared, "x-cache-status"),
        "an idempotent write leaves no observable diff: {undeclared:?}"
    );

    let declared = reconcile(
        &[("x-cache-status", "HIT")],
        &before,
        &after,
        &names(&["x-cache-status"]),
        false,
    );
    assert!(declared.is_empty(), "surviving trailers: {declared:?}");
}

// ────────────────────────────────────────────────────────────────────────────
// Streaming relays: the initial HEADERS frame is already on the wire when the
// backend's trailer section arrives, so the same policy boundary has to be
// re-applied at the trailer frame. The last argument is
// `header_phases_can_mutate` — whether any response-header phase can run for
// the response at all, which is what decides if a pre-policy snapshot is worth
// retaining.
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn streaming_relay_without_a_header_phase_preserves_backend_trailers() {
    // No plugins and no sticky-cookie injection: nothing can have rewritten the
    // headers, so no snapshot is retained and every trailer survives (#2941).
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[
            ("x-backend-finished", "true"),
            ("x-request-id", "trail-stream-1"),
        ],
        &backend,
        &backend,
        &[],
        false,
        false,
    );
    assert_eq!(surviving.len(), 2, "surviving trailers: {surviving:?}");
    assert!(has(&surviving, "x-backend-finished"));
    assert!(has(&surviving, "x-request-id"));
}

#[test]
fn streaming_relay_reconciles_observed_header_mutations() {
    // The chain removed the field from the initial header map, which already
    // went on the wire; the trailer copy must not reintroduce it afterwards.
    let before = headers(&[
        ("x-internal-token", "leaked"),
        ("content-type", "text/plain"),
    ]);
    let after = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[("x-internal-token", "leaked"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_relay_binds_declared_policy_names_without_a_mutation() {
    // The removal was a no-op on the initial map — the backend sent the field
    // only as a trailer — so only the config-time declaration can bind it, with
    // or without a retained snapshot.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[("x-powered-by", "backend/1.2"), ("x-keep", "yes")],
        &backend,
        &backend,
        &names(&["x-powered-by"]),
        false,
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_relay_unbounded_policy_fails_closed_without_evidence() {
    // The unbounded arm drops the reconcilable section regardless of what the
    // headers did, so the relay retains no snapshot at all — and the outcome is
    // identical to the buffered path's unbounded arm.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[("x-backend-finished", "true"), ("grpc-status", "0")],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert!(
        surviving.is_empty(),
        "the streaming fail-closed arm exempts no name, grpc-* included: {surviving:?}"
    );
}

#[test]
fn streaming_relay_unbounded_drops_trailer_only_representation_metadata() {
    // Streaming H3 commits initial HEADERS before TRAILERS exist. Without
    // an unbounded policy owner, a trailer-only
    // `content-encoding` / validator / `x-amz-checksum-*` reconciles as
    // absent→absent and reintroduces representation metadata the normalization
    // already invalidated on the header channel.
    let backend = headers(&[("content-type", "text/event-stream")]);
    let surviving = reconcile_streaming(
        &[
            ("content-encoding", "br"),
            ("content-length", "99"),
            ("vary", "accept-encoding"),
            ("etag", "\"sse-repr\""),
            ("content-digest", "sha-256=:CCCC:"),
            ("signature-input", "sig1=()"),
            ("x-amz-checksum-crc32", "AAAAAA=="),
            ("x-checksum-sha256", "cafebabe"),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert!(
        surviving.is_empty(),
        "streaming Unbounded must drop trailer-only representation metadata: {surviving:?}"
    );
}

#[test]
fn streaming_relay_binds_the_gateway_synthesized_default_content_type() {
    // Wire parity for the relays' `content-type: application/json` default. The
    // relay writes that field into the response-header MAP before building the
    // response, and counts the synthesis as a header phase, so the pre-policy
    // snapshot (backend: no content-type) versus the final map (gateway:
    // application/json) is a visible mutation and the backend's conflicting
    // `content-type` TRAILER is dropped.
    //
    // If the default only ever reached the builder, the final map would still
    // lack the field, reconciliation would prove absent -> absent, and the
    // trailer would land on the wire contradicting a header the gateway sent.
    let backend_without_content_type = headers(&[("x-backend", "1")]);
    let wire_headers = headers(&[("x-backend", "1"), ("content-type", "application/json")]);
    let surviving = reconcile_streaming(
        &[("content-type", "text/html"), ("x-keep", "yes")],
        &backend_without_content_type,
        &wire_headers,
        &[],
        false,
        // The relay passes `true` here precisely because it will synthesize the
        // default, even for an auth/logging-only chain.
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_relay_keeps_trailers_when_the_backend_supplied_content_type() {
    // The mirror case: the backend already sent `content-type`, so the relay
    // synthesizes nothing, `header_phases_can_mutate` stays false for an
    // auth/logging-only chain, no snapshot is retained, and the #2941
    // pass-through is preserved with zero clones.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_streaming(
        &[("x-backend-finished", "true")],
        &backend,
        &backend,
        &[],
        false,
        false,
    );
    assert_eq!(
        surviving,
        vec![("x-backend-finished".to_string(), "true".to_string())]
    );
}

#[test]
fn streaming_relay_duplicate_case_variants_are_governed() {
    // Same fail-closed ambiguity rule as the buffered path: a plugin-synthesized
    // duplicate case variant must never let the backend trailer through.
    let before = headers(&[("x-name", "backend")]);
    let after = headers(&[("x-name", "backend"), ("X-Name", "gateway")]);
    let surviving = reconcile_streaming(
        &[("x-name", "backend"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

// ── Streaming HTTP/2 (direct-H2) ────────────────────────────────────────────
//
// The plain direct-H2 `ResponseBody::StreamingH2` relay crosses the same
// boundary as the native-H3 streaming relays: its initial HEADERS frame is
// committed before the backend's TRAILERS frame exists. It cannot borrow the
// handler's locals the way an inline H3 relay can — the body is handed to hyper
// and the handler returns — so the boundary travels with the body as an owned
// `StreamingResponseTrailerGovernor`. These cases pin that owned form against
// the same governance contract, including the hop-by-hop strip the body wrapper
// applies immediately before reconciling.

#[test]
fn streaming_h2_security_headers_removal_binds_a_trailer_only_field() {
    // The reported case: `security_headers` with `{"remove": ["x-powered-by"]}`
    // is a NO-OP on the initial header map because the backend sent the field
    // ONLY as a trailer. `after_proxy` therefore had nothing to remove, and
    // without the config-time declaration the trailer would land on the wire
    // after the policy boundary and reintroduce exactly what was removed.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
        &[("x-powered-by", "backend/1.2"), ("x-keep", "yes")],
        &backend,
        &backend,
        &names(&["x-powered-by"]),
        false,
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_h2_without_a_header_phase_preserves_backend_trailers() {
    // Exact no-policy behavior: an auth/logging-only chain with no gateway
    // header write retains no evidence and forwards every trailer (#2941).
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
        &[
            ("x-backend-finished", "true"),
            ("x-request-id", "trail-h2-1"),
        ],
        &backend,
        &backend,
        &[],
        false,
        false,
    );
    assert_eq!(surviving.len(), 2, "surviving trailers: {surviving:?}");
    assert!(has(&surviving, "x-backend-finished"));
    assert!(has(&surviving, "x-request-id"));
}

#[test]
fn streaming_h2_observed_header_removal_binds_the_trailer_copy() {
    // No declaration at all — a custom plugin that simply deleted the field
    // from the initial map. The retained pre-policy snapshot is what proves the
    // mutation once the trailer frame finally arrives.
    let before = headers(&[
        ("x-internal-token", "leaked"),
        ("content-type", "text/plain"),
    ]);
    let after = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
        &[("x-internal-token", "leaked"), ("x-keep", "yes")],
        &before,
        &after,
        &[],
        false,
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_h2_unbounded_policy_fails_closed_without_evidence() {
    // `response_transformer` / `ai_stream_router` (and anything else declaring
    // `Unbounded`) drops the whole reconcilable trailer section, so the relay
    // retains no snapshot at all. Same outcome as the buffered and streaming
    // H3 unbounded arms.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
        &[("x-backend-finished", "true"), ("x-keep", "yes")],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert!(
        surviving.is_empty(),
        "unbounded policy must drop every reconcilable trailer: {surviving:?}"
    );
}

#[test]
fn streaming_h2_unbounded_drops_trailer_only_representation_metadata() {
    // Direct-H2 StreamingH2 commits HEADERS before TRAILERS, identical to the
    // native-H3 streaming relays. Trailer-only representation metadata that
    // `ai_stream_router` invalidated on the header channel must not survive.
    let backend = headers(&[("content-type", "text/event-stream")]);
    let surviving = govern_h2(
        &[
            ("content-encoding", "gzip"),
            ("content-length", "12"),
            ("vary", "accept-encoding"),
            ("last-modified", "Mon, 01 Jan 2024 00:00:00 GMT"),
            ("repr-digest", "sha-256=:DDDD:"),
            ("content-signature", "sig1=:EEEE:"),
            ("x-amz-checksum-sha256", "feedface"),
            ("x-checksum-crc32c", "BBBBBB=="),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert!(
        surviving.is_empty(),
        "H2 Unbounded must drop trailer-only representation metadata: {surviving:?}"
    );
}

#[test]
fn streaming_h2_gateway_only_wire_header_binds_the_matching_trailer() {
    // `via` / `alt-svc` / `X-Gateway-*` are written straight onto the response
    // BUILDER, not into the plugin header map. The governor is handed the map
    // PLUS those fields, so a backend `via` trailer is seen as contradicting a
    // gateway header instead of reconciling absent->absent.
    let backend = headers(&[("content-type", "text/plain")]);
    let wire = headers(&[("content-type", "text/plain"), ("via", "2 ferrum-edge")]);
    let surviving = govern_h2(
        &[("via", "1.1 backend"), ("x-keep", "yes")],
        &backend,
        &wire,
        &[],
        false,
        true,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

#[test]
fn streaming_h2_gateway_owned_idempotent_write_binds_each_builder_field() {
    // Exact-value pre-seeding: the backend already sent the identical string the
    // gateway builder will write. Folding into `final_headers` alone leaves the
    // mutation witness with before == after; only the per-response
    // `gateway_owned_headers` declaration closes the trailer channel — the same
    // idempotent-write shape plugin declarations handle.
    use ferrum_edge::_test_support::govern_streaming_h2_backend_trailers_governed_for_test as govern_owned;

    for (owned, seed_value, trailer_value) in [
        ("via", "2 ferrum-edge", "1.1 backend"),
        ("alt-svc", "h3=\":443\"; ma=86400", "h3=\":443\"; ma=1"),
        ("x-gateway-error", "backend_error", "spoofed"),
        ("x-gateway-upstream-status", "degraded", "ok"),
    ] {
        let seeded = headers(&[("content-type", "text/plain"), (owned, seed_value)]);
        let surviving = govern_owned(
            &[(owned, trailer_value), ("x-keep", "yes")],
            &seeded,
            &seeded,
            &[],
            &[],
            &names(&[owned]),
            false,
            true,
        );
        assert_eq!(
            surviving,
            vec![("x-keep".to_string(), "yes".to_string())],
            "idempotent gateway write of {owned} must bind the trailer"
        );
    }
}

#[test]
fn streaming_h2_builder_field_ungoverned_when_gateway_did_not_write_it() {
    // Ownership is per-response and write-gated: a backend `via` trailer must
    // survive when this response never wrote `via` onto the builder.
    use ferrum_edge::_test_support::govern_streaming_h2_backend_trailers_governed_for_test as govern_owned;

    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = govern_owned(
        &[("via", "1.1 backend"), ("x-keep", "yes")],
        &backend,
        &backend,
        &[],
        &[],
        &[], // gateway wrote none of the builder-owned fields
        false,
        false,
    );
    assert_eq!(surviving.len(), 2, "surviving trailers: {surviving:?}");
    assert!(has(&surviving, "via"));
    assert!(has(&surviving, "x-keep"));
}

#[test]
fn streaming_h2_gateway_owned_name_matches_mixed_case_trailer() {
    use ferrum_edge::_test_support::govern_streaming_h2_backend_trailers_governed_for_test as govern_owned;

    let seeded = headers(&[("content-type", "text/plain"), ("via", "2 ferrum-edge")]);
    let surviving = govern_owned(
        &[("Via", "1.1 backend"), ("x-keep", "yes")],
        &seeded,
        &seeded,
        &[],
        &[],
        &names(&["VIA"]),
        false,
        true,
    );
    assert_eq!(
        surviving,
        vec![("x-keep".to_string(), "yes".to_string())],
        "mixed-case trailer must still fail closed under gateway ownership"
    );
}

#[test]
fn cors_prefix_binds_trailer_only_non_enumerated_access_control_field() {
    // `finalize_cors_response` calls `remove_access_control_headers`, which
    // strips the open-ended `access-control-` prefix. A trailer-only extension
    // such as `access-control-allow-private-network` is absent from the initial
    // map and absent from any finite write list, so only the prefix declaration
    // can bind it.
    use ferrum_edge::_test_support::reconcile_backend_trailers_governed_for_test as reconcile_owned;

    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_owned(
        &[
            ("access-control-allow-private-network", "true"),
            ("access-control-allow-origin", "https://evil.example"),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &names(&["vary"]),
        &names(&["access-control-"]),
        &[],
        false,
    );
    assert_eq!(
        surviving,
        vec![("x-keep".to_string(), "yes".to_string())],
        "trailer-only access-control-* must not bypass CORS sanitization: {surviving:?}"
    );
}

#[test]
fn auth_logging_only_trailer_pass_through_remains_intact_with_new_signals() {
    // Empty names, empty prefixes, empty gateway ownership, no mutation, no
    // Unbounded: the #2941 pass-through must still forward every trailer.
    use ferrum_edge::_test_support::reconcile_backend_trailers_governed_for_test as reconcile_owned;

    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = reconcile_owned(
        &[
            ("x-backend-finished", "true"),
            ("x-request-id", "trail-auth-2"),
            ("access-control-allow-private-network", "true"),
        ],
        &backend,
        &backend,
        &[],
        &[],
        &[],
        false,
    );
    assert_eq!(surviving.len(), 3, "surviving trailers: {surviving:?}");
    assert!(has(&surviving, "x-backend-finished"));
    assert!(has(&surviving, "x-request-id"));
    assert!(has(&surviving, "access-control-allow-private-network"));
}

#[test]
fn streaming_h2_strips_hop_by_hop_trailers_before_reconciling() {
    // The body wrapper strips hop-by-hop names first, so they never count as
    // policy-governed removals — and an ungoverned chain still cannot leak
    // `connection` / `proxy-authenticate` through the trailer section.
    let backend = headers(&[("content-type", "text/plain")]);
    let surviving = govern_h2(
        &[
            ("connection", "close"),
            ("proxy-authenticate", "Basic"),
            ("x-keep", "yes"),
        ],
        &backend,
        &backend,
        &[],
        false,
        false,
    );
    assert_eq!(surviving, vec![("x-keep".to_string(), "yes".to_string())]);
}

// ── Source contracts ────────────────────────────────────────────────────────

#[test]
fn streaming_h2_body_reconciles_after_the_hop_by_hop_strip() {
    let src = include_str!("../../../src/proxy/body.rs");
    let filter = src
        .split("impl<B> http_body::Body for StripHopByHopTrailers<B>")
        .nth(1)
        .expect("StripHopByHopTrailers body impl")
        .split("fn is_end_stream")
        .next()
        .expect("bounded poll_frame region");
    let strip_at = filter
        .find("strip_response_hop_by_hop_trailers(&mut trailers);")
        .expect("hop-by-hop trailer strip");
    let govern_at = filter
        .find("governor.reconcile(&mut trailers)")
        .expect("response-trailer policy reconciliation");
    let send_at = filter
        .find("Frame::trailers(trailers)")
        .expect("trailer frame handoff");
    assert!(
        strip_at < govern_at && govern_at < send_at,
        "streaming H2 must strip hop-by-hop names, then reconcile, then emit"
    );
}

#[test]
fn every_streaming_h2_body_constructor_carries_the_trailer_governor() {
    let src = include_str!("../../../src/proxy/body.rs");
    for constructor in [
        "pub(crate) fn direct_streaming_h2_body_strip_hop_by_hop_trailers(",
        "pub(crate) fn size_limited_coalescing_h2_body_strip_hop_by_hop_trailers(",
        "pub(crate) fn coalescing_h2_body_strip_hop_by_hop_trailers(",
    ] {
        let body = src
            .split(constructor)
            .nth(1)
            .unwrap_or_else(|| panic!("missing constructor {constructor}"));
        let signature = body.split(") -> ProxyBody {").next().expect("signature");
        assert!(
            signature.contains(
                "trailer_governor: Option<crate::proxy::headers::StreamingResponseTrailerGovernor>"
            ),
            "{constructor} must accept the streaming trailer governor"
        );
        let block = body.split("\n}\n").next().expect("constructor body");
        assert!(
            block.contains("StripHopByHopTrailers::with_trailer_governor("),
            "{constructor} must install the governor on every wrapper it builds"
        );
        assert!(
            !block.contains("StripHopByHopTrailers::new("),
            "{constructor} must not build an ungoverned wrapper on any branch"
        );
    }
}

#[test]
fn native_grpc_and_translated_grpc_web_are_both_governed_on_the_h2_arm() {
    let src = include_str!("../../../src/proxy/mod.rs");
    // The gate is shared by the direct-H2 relay and the H1/H2 frontend ->
    // native-H3 BACKEND relay, so its binding is `streaming_trailer_policy`
    // rather than an H2-only name. Anchored on the `let` + its `if matches!(`
    // head so this cannot latch onto some other mention of the binding.
    let gate = src
        .split("let streaming_trailer_policy = if matches!(")
        .nth(1)
        .expect("streaming H2 trailer policy gate")
        .split("Some((pre_policy, section, unbounded))")
        .next()
        .expect("bounded gate region");
    // Both streaming bodies whose backend TRAILERS frame crosses this boundary
    // enter the gate; neither may be filtered out of it.
    for arm in [
        "ResponseBody::StreamingH2(_)",
        "ResponseBody::StreamingH3(_)",
    ] {
        assert!(
            gate.contains(arm),
            "{arm} must enter the streaming trailer-policy gate"
        );
    }
    // GHSA-r78v-rc86-6r86: native gRPC on this arm (the mesh-mTLS relay) is
    // GOVERNED — its application metadata crosses the same boundary — and is
    // selected as a gRPC terminal section so the reserved status fields survive.
    assert!(
        !gate.contains("!streaming_h2_native_grpc"),
        "native gRPC must no longer be excluded from the trailer boundary"
    );
    assert!(
        gate.contains("TrailerSectionKind::NativeGrpcTerminal")
            && gate.contains("TrailerSectionKind::PlainResponse"),
        "the streaming H2 arm must pick its trailer section structurally from \
         `streaming_h2_native_grpc`"
    );
    // Translated gRPC-Web is governed too. Adapting the terminal metadata into a
    // final DATA frame changes the encoding, not the boundary: a NON-EMPTY
    // streaming response still delivers that metadata in a later TRAILERS frame,
    // which the pristine Trailers-Only snapshot never saw. Its trailer block is a
    // native gRPC terminal section, so the reserved status fields still survive.
    assert!(
        !gate.contains("!grpc_request_is_web_translated"),
        "translated gRPC-Web must not be excluded from the trailer boundary"
    );
    // The section selector is read as a bounded region rather than as one
    // formatting-sensitive literal: rustfmt breaks a three-term `if` across
    // lines, and a substring match would then silently stop proving anything.
    let selector = gate
        .split("let section = if ")
        .nth(1)
        .expect("structural trailer-section selector")
        .split("};")
        .next()
        .expect("bounded trailer-section selector");
    for term in [
        "streaming_h2_native_grpc",
        "streaming_h3_native_grpc",
        "grpc_request_is_web_translated",
    ] {
        assert!(
            selector.contains(term),
            "the trailer section must be chosen structurally from `{term}`, so a \
             translated gRPC-Web or native-gRPC trailer block is governed as a \
             native gRPC terminal section"
        );
    }
    assert!(
        selector.contains("TrailerSectionKind::NativeGrpcTerminal")
            && selector.contains("TrailerSectionKind::PlainResponse"),
        "the selector must resolve to exactly the two structural section kinds"
    );
    assert!(
        gate.contains("PrePolicyResponseHeaders::capture_for_streaming("),
        "the streaming H2 relay must capture the pristine backend header view"
    );
}

#[test]
fn the_direct_grpc_pool_streaming_relay_installs_a_native_grpc_governor() {
    // The advisory's primary reproduction: `GrpcResponseKind::Streaming` runs
    // `after_proxy` on the initial header map, commits the HEADERS frame, and
    // then forwards the backend trailer section through the body. Every one of
    // its three mutually-exclusive body constructors must carry the governor.
    let src = include_str!("../../../src/proxy/mod.rs");
    let arm = src
        .split("Ok(GrpcResponseKind::Streaming(grpc_streaming)) => {")
        .nth(1)
        .expect("native gRPC streaming arm")
        .split("Ok(GrpcResponseKind::Buffered(grpc_resp)) => {")
        .next()
        .expect("bounded native gRPC streaming arm");
    let capture_at = arm
        .find("let grpc_streaming_pre_policy_headers =")
        .expect("native gRPC streaming pre-policy capture");
    let after_proxy_at = arm
        .find("run_after_proxy_hooks(")
        .expect("native gRPC streaming after_proxy phase");
    let seal_at = arm
        .find("let mut grpc_streaming_trailer_governor = None;")
        .expect("native gRPC streaming governor seal");
    assert!(
        capture_at < after_proxy_at,
        "the pre-policy capture must precede the first response-header phase"
    );
    assert!(
        after_proxy_at < seal_at,
        "the governor must be sealed after the response-header phases"
    );
    assert!(
        arm.contains("TrailerSectionKind::NativeGrpcTerminal"),
        "the native gRPC streaming relay must seal a gRPC terminal section"
    );
    let region = &arm[seal_at..];
    let constructors = region
        .matches("_h2_body_strip_hop_by_hop_trailers(")
        .count();
    let governed = region
        .matches("grpc_streaming_trailer_governor.take()")
        .count();
    assert_eq!(
        constructors, 3,
        "native gRPC streaming body construction must keep its three \
         mutually-exclusive constructors: {constructors}"
    );
    assert_eq!(
        governed, constructors,
        "every native gRPC streaming body constructor must receive the governor"
    );
}

#[test]
fn streaming_h2_capture_precedes_the_first_response_header_phase() {
    // Evidence is only evidence if it predates every mutation it must witness.
    // The capture sits above `run_after_proxy_hooks`, which is the first
    // response-header phase on this path; the governor is sealed only after the
    // response BUILDER has taken its gateway-authored writes.
    let src = include_str!("../../../src/proxy/mod.rs");
    let capture_at = src
        .find("let streaming_trailer_policy = if matches!(")
        .expect("streaming H2 trailer policy capture");
    let seal_at = src
        .find("let mut streaming_trailer_governor = None;")
        .expect("streaming H2 trailer governor seal");
    assert!(
        capture_at < seal_at,
        "the pre-policy capture must precede the governor seal"
    );
    let first_phase = "run_after_proxy_hooks(&plugins, &mut ctx, response_status,";
    assert!(
        src[capture_at..seal_at].contains(first_phase),
        "the pre-policy capture must precede the first response-header phase"
    );
    let builder_at = src
        .find("apply_response_headers(resp_builder, &response_headers)")
        .expect("response builder header application");
    assert!(
        builder_at < seal_at,
        "the governor must be sealed after the response builder took its writes"
    );
}

#[test]
fn every_streaming_h2_dispatch_site_installs_the_sealed_governor() {
    // `body.rs` proving each constructor forwards the governor is only half the
    // contract: `handle_proxy_request_inner` must actually hand one to EVERY
    // mutually-exclusive constructor it picks on the plain streaming-H2 arm. A
    // new branch added without `.take()` would silently drop the boundary.
    let src = include_str!("../../../src/proxy/mod.rs");
    let after_seal = src
        .split("let mut streaming_trailer_governor = None;")
        .nth(1)
        .expect("streaming H2 trailer governor seal");
    let region = after_seal
        .split("let mut body = if let Some(inspector) = response_inspector {")
        .next()
        .expect("bounded streaming H2 body-construction region");
    let constructors = region
        .matches("_h2_body_strip_hop_by_hop_trailers(")
        .count();
    let governed = region.matches("streaming_trailer_governor.take()").count();
    assert_eq!(
        constructors, 4,
        "the plain streaming H2 arm should build exactly four body variants"
    );
    assert_eq!(
        governed, constructors,
        "every plain streaming H2 body constructor must receive the sealed trailer governor"
    );

    // The seal folds in the gateway-authored fields written straight onto the
    // response builder AND records each write in `gateway_owned_headers`, so an
    // exact-value pre-seed cannot hide the ownership from the mutation witness.
    // `connection: close` is deliberately absent: it is hop-by-hop and never
    // survives to the reconciliation.
    let seal = region
        .split("// Build response body:")
        .next()
        .expect("bounded seal region");
    for field in [
        "\"x-gateway-error\"",
        "\"x-gateway-upstream-status\"",
        "\"alt-svc\"",
        "\"via\"",
    ] {
        assert!(
            seal.contains(field),
            "the governor's final-header view must fold in the builder-only field {field}"
        );
    }
    assert!(
        seal.contains("gateway_owned_headers.insert("),
        "the seal must declare per-response gateway ownership for each builder write"
    );
    assert!(
        seal.contains("response_trailer_policy_prefixes_shared()"),
        "the seal must carry the precomputed policy-prefix Arc into the governor"
    );
}

#[test]
fn every_streaming_h3_backend_dispatch_site_installs_the_sealed_governor() {
    // The SAME sealed governor serves the H1/H2 frontend -> native-H3 BACKEND
    // relay, whose backend TRAILERS frame reaches the client through
    // `body::H3FrameSource` after this boundary closed. Its three
    // mutually-exclusive constructors need the identical proof the H2 arm gets:
    // a fourth branch added without `.take()` would relay the backend trailer
    // section ungoverned.
    let src = include_str!("../../../src/proxy/mod.rs");
    let region = src
        .split("ResponseBody::StreamingH3(h3_resp) => {")
        .nth(1)
        .expect("native-H3 backend streaming arm")
        .split("let mut body = if let Some(inspector) = response_inspector {")
        .next()
        .expect("bounded native-H3 body-construction region");
    let constructors = region.matches("_h3_body(").count();
    let governed = region.matches("streaming_trailer_governor.take()").count();
    assert_eq!(
        constructors, 3,
        "the native-H3 backend streaming arm should build exactly three body \
         variants: {constructors}"
    );
    assert_eq!(
        governed, constructors,
        "every native-H3 backend streaming body constructor must receive the \
         sealed trailer governor"
    );
}

// ── Native gRPC terminal sections (GHSA-r78v-rc86-6r86) ─────────────────────
//
// A streaming gRPC response runs `after_proxy` on the initial header map only,
// then forwards the backend's terminal metadata later. The advisory reproduces
// exactly that: a `response_transformer` rule removing `x-internal-debug` is a
// no-op because the backend sends the field only as a trailer. These pin the
// two halves of the fix — application metadata is governed, protocol-required
// terminal status is not.

#[test]
fn an_unbounded_policy_drops_grpc_trailer_only_application_metadata() {
    // `response_transformer` declares `Unbounded`: its rule set includes
    // request-scoped route overrides whose field names do not exist at config
    // time, so application metadata fails closed.
    let backend = headers(&[("content-type", "application/grpc")]);
    let surviving = reconcile_grpc(
        &[
            ("grpc-status", "0"),
            ("x-internal-debug", "backend-trace-9f2a"),
            ("x-tenant-shard", "eu-3"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert!(
        !has(&surviving, "x-internal-debug"),
        "trailer-only gRPC application metadata must not bypass an unbounded \
         response-header policy: {surviving:?}"
    );
    assert!(
        !has(&surviving, "x-tenant-shard"),
        "every non-reserved gRPC trailer field must fail closed: {surviving:?}"
    );
}

#[test]
fn reserved_grpc_terminal_fields_survive_the_unbounded_arm() {
    // Generic header policy must never corrupt or suppress valid terminal
    // status: dropping these would ship a truncated RPC with no outcome.
    let backend = headers(&[("content-type", "application/grpc")]);
    let surviving = reconcile_grpc(
        &[
            ("grpc-status", "9"),
            ("grpc-message", "FAILED_PRECONDITION"),
            ("grpc-status-details-bin", "AAECAw"),
            ("x-internal-debug", "leak"),
        ],
        &backend,
        &backend,
        &names(&["grpc-status", "grpc-message", "grpc-status-details-bin"]),
        true,
        true,
    );
    assert_eq!(
        surviving.len(),
        3,
        "exactly the three reserved terminal fields must survive: {surviving:?}"
    );
    for reserved in ["grpc-status", "grpc-message", "grpc-status-details-bin"] {
        assert!(
            has(&surviving, reserved),
            "{reserved} must survive even a declared name AND the unbounded arm: {surviving:?}"
        );
    }
}

#[test]
fn a_grpc_trailer_removal_declared_by_name_is_applied_to_application_metadata() {
    // The bounded shape: the backend sent `x-internal-debug` ONLY as a trailer,
    // so the policy's removal was a no-op on the initial header map and only
    // the config-time declaration can catch it.
    let backend = headers(&[("content-type", "application/grpc")]);
    let surviving = reconcile_grpc(
        &[
            ("grpc-status", "0"),
            ("x-internal-debug", "backend-trace-9f2a"),
            ("x-request-id", "rpc-77"),
        ],
        &backend,
        &backend,
        &names(&["x-internal-debug"]),
        false,
        false,
    );
    assert!(!has(&surviving, "x-internal-debug"), "{surviving:?}");
    assert!(has(&surviving, "grpc-status"), "{surviving:?}");
    assert!(
        has(&surviving, "x-request-id"),
        "an undeclared, unmutated gRPC trailer must still pass through: {surviving:?}"
    );
}

#[test]
fn an_observed_header_removal_governs_the_matching_grpc_trailer() {
    // The backend sent `x-internal-debug` in BOTH the initial headers and the
    // terminal metadata; the policy removed the header. The trailer copy must
    // not undo that.
    let before = headers(&[
        ("content-type", "application/grpc"),
        ("x-internal-debug", "backend-trace-9f2a"),
    ]);
    let after = headers(&[("content-type", "application/grpc")]);
    let surviving = reconcile_grpc(
        &[
            ("grpc-status", "0"),
            ("x-internal-debug", "backend-trace-9f2a"),
        ],
        &before,
        &after,
        &[],
        false,
        true,
    );
    assert!(!has(&surviving, "x-internal-debug"), "{surviving:?}");
    assert!(has(&surviving, "grpc-status"), "{surviving:?}");
}

#[test]
fn an_auth_only_chain_preserves_grpc_application_trailers() {
    // Issue #2941 pass-through must survive on the gRPC section too: nothing in
    // this chain can mutate a response header, so the terminal metadata is
    // forwarded exactly as the backend sent it.
    let backend = headers(&[("content-type", "application/grpc")]);
    let surviving = reconcile_grpc(
        &[
            ("grpc-status", "0"),
            ("x-internal-debug", "backend-trace-9f2a"),
            ("x-request-id", "rpc-77"),
        ],
        &backend,
        &backend,
        &[],
        false,
        false,
    );
    assert_eq!(surviving.len(), 3, "surviving trailers: {surviving:?}");
}

#[test]
fn a_grpc_prefixed_but_unreserved_trailer_is_still_application_metadata() {
    // The reserved set is an EXACT three-name inventory, not a `grpc-` prefix.
    // `grpc-encoding` and friends are application metadata and stay governed —
    // otherwise the exemption would widen into the bypass it exists to avoid.
    let backend = headers(&[("content-type", "application/grpc")]);
    let surviving = reconcile_grpc(
        &[
            ("grpc-status", "0"),
            ("grpc-encoding", "gzip"),
            ("grpc-accept-encoding", "identity"),
            ("grpc-status-detail", "smuggled"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert_eq!(
        surviving.len(),
        1,
        "only the exact reserved names may be exempt: {surviving:?}"
    );
    assert!(has(&surviving, "grpc-status"), "{surviving:?}");
}

#[test]
fn the_plain_section_still_grants_no_exemption_to_the_same_names() {
    // The mirror of the case above: identical trailers, identical policy, PLAIN
    // section. Nothing survives — the exemption is structural, not name-based,
    // so a plain backend cannot buy protection by naming its trailer
    // `grpc-status`.
    let backend = headers(&[("content-type", "text/plain")]);
    let grpc_trailers = [
        ("grpc-status", "0"),
        ("grpc-message", "ok"),
        ("grpc-status-details-bin", "AAECAw"),
    ];
    let plain = reconcile_streaming(&grpc_trailers, &backend, &backend, &[], true, true);
    assert!(
        plain.is_empty(),
        "the plain streaming section must exempt no name: {plain:?}"
    );
    let governed = reconcile_grpc(&grpc_trailers, &backend, &backend, &[], true, true);
    assert_eq!(
        governed.len(),
        3,
        "the same trailers on a native gRPC section must survive: {governed:?}"
    );
}

#[test]
fn the_owned_h2_governor_applies_the_same_grpc_section_rules() {
    // The direct-H2 gRPC pool relay and the mesh-mTLS `StreamingH2` relay hand
    // their body to hyper and return, so the boundary travels as an owned
    // governor. It must reach the identical outcome as the inline H3 relays.
    let backend = headers(&[("content-type", "application/grpc")]);
    let surviving = govern_h2_grpc(
        &[
            ("grpc-status", "5"),
            ("grpc-message", "NOT_FOUND"),
            ("x-internal-debug", "backend-trace-9f2a"),
            // Hop-by-hop names are stripped before the governor runs.
            ("proxy-authenticate", "Basic"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
    );
    assert_eq!(surviving.len(), 2, "surviving trailers: {surviving:?}");
    assert!(has(&surviving, "grpc-status"), "{surviving:?}");
    assert!(has(&surviving, "grpc-message"), "{surviving:?}");
}

#[test]
fn duplicate_case_variants_on_a_grpc_trailer_still_fail_closed() {
    // Ambiguity is unprovable, so it stays governed on the gRPC section too.
    // The reserved fields are unaffected.
    let before = headers(&[
        ("content-type", "application/grpc"),
        ("x-internal-debug", "one"),
        ("X-Internal-Debug", "two"),
    ]);
    let surviving = reconcile_grpc(
        &[("grpc-status", "0"), ("x-internal-debug", "one")],
        &before,
        &before,
        &[],
        false,
        true,
    );
    assert!(!has(&surviving, "x-internal-debug"), "{surviving:?}");
    assert!(has(&surviving, "grpc-status"), "{surviving:?}");
}

// ── Translated gRPC-Web terminal frames (GHSA-r78v-rc86-6r86) ───────────────
//
// A translated gRPC-Web response adapts the backend's terminal metadata into a
// final DATA frame instead of a TRAILERS frame. That changes the ENCODING, not
// the policy boundary: on a NON-EMPTY streaming response the metadata still
// arrives in a later trailer frame, long after `after_proxy` saw the initial
// header map. Only a genuine Trailers-Only response carries it in the initial
// END_STREAM HEADERS block, which the pristine snapshot already governs.
//
// The helper below runs the exact terminal sequence both relays perform —
// hop-by-hop strip, native-gRPC-terminal reconciliation, buffered collection,
// frame build — so a governed name must never appear in the client-visible
// frame in either binary or text mode.

fn frame_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn trailer_only_governed_metadata_never_reaches_a_binary_grpc_web_frame() {
    // `response_transformer` declares `Unbounded`: its governed names do not
    // exist until the request runs, so every non-reserved terminal field is
    // dropped before the frame is built.
    let backend = headers(&[("content-type", "application/grpc")]);
    let (wire, decoded, status) = grpc_web_frame(
        &[
            ("grpc-status", "0"),
            ("grpc-message", "OK"),
            ("x-internal-debug", "backend-trace-9f2a"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
        200,
        false,
    );
    let frame = frame_text(&decoded);
    assert!(
        !frame.contains("x-internal-debug") && !frame.contains("backend-trace-9f2a"),
        "governed trailer-only metadata reached the gRPC-Web frame: {frame:?}"
    );
    assert!(frame.contains("grpc-status"), "{frame:?}");
    assert_eq!(status, 0, "the pristine backend status must be latched");
    assert_eq!(
        wire, decoded,
        "binary mode must emit the frame bytes verbatim"
    );
}

#[test]
fn trailer_only_governed_metadata_never_reaches_a_text_grpc_web_frame() {
    // Text mode base64-encodes the SAME governed frame. Reconciliation must run
    // before that encoding, otherwise the metadata would merely be obscured.
    let backend = headers(&[("content-type", "application/grpc")]);
    let (wire, decoded, status) = grpc_web_frame(
        &[
            ("grpc-status", "0"),
            ("x-internal-debug", "backend-trace-9f2a"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
        200,
        true,
    );
    let frame = frame_text(&decoded);
    assert!(
        !frame.contains("x-internal-debug"),
        "governed metadata reached the text-mode frame: {frame:?}"
    );
    assert!(frame.contains("grpc-status"), "{frame:?}");
    assert_eq!(status, 0);
    assert_ne!(
        wire, decoded,
        "text mode must base64-encode the terminal frame"
    );
    assert!(
        !frame_text(&wire).contains("x-internal-debug"),
        "the encoded wire bytes must not carry the governed name either"
    );
}

#[test]
fn reserved_terminal_status_survives_grpc_web_conversion() {
    // All three reserved fields are exempt by SECTION, not by a `grpc-` prefix:
    // `grpc-encoding` in the same block is ordinary application metadata and is
    // governed like any other name.
    let backend = headers(&[("content-type", "application/grpc")]);
    let (_, decoded, status) = grpc_web_frame(
        &[
            ("grpc-status", "5"),
            ("grpc-message", "NOT_FOUND"),
            ("grpc-status-details-bin", "AAECAw"),
            ("grpc-encoding", "gzip"),
        ],
        &backend,
        &backend,
        &[],
        true,
        true,
        200,
        false,
    );
    let frame = frame_text(&decoded);
    assert!(frame.contains("grpc-status:"), "{frame:?}");
    assert!(frame.contains("grpc-message:"), "{frame:?}");
    assert!(frame.contains("grpc-status-details-bin:"), "{frame:?}");
    assert!(
        !frame.contains("grpc-encoding"),
        "`grpc-` is not a prefix exemption: {frame:?}"
    );
    assert_eq!(status, 5, "the pristine backend status must be latched");
}

#[test]
fn an_auth_only_chain_preserves_ungoverned_grpc_web_application_metadata() {
    // Issue #2941 parity: nothing declared, nothing mutated, no fail-closed arm
    // — the terminal application metadata is forwarded into the frame untouched.
    let backend = headers(&[("content-type", "application/grpc")]);
    let (_, decoded, status) = grpc_web_frame(
        &[
            ("grpc-status", "0"),
            ("x-trace-id", "abc123"),
            // Hop-by-hop names are stripped before governance regardless.
            ("proxy-authenticate", "Basic"),
        ],
        &backend,
        &backend,
        &[],
        false,
        false,
        200,
        false,
    );
    let frame = frame_text(&decoded);
    assert!(
        frame.contains("x-trace-id") && frame.contains("abc123"),
        "an auth/logging-only chain must not drop ungoverned metadata: {frame:?}"
    );
    assert!(frame.contains("grpc-status"), "{frame:?}");
    assert!(
        !frame.contains("proxy-authenticate"),
        "hop-by-hop names must never reach the frame: {frame:?}"
    );
    assert_eq!(status, 0);
}

#[test]
fn a_declared_removal_is_applied_to_the_grpc_web_frame() {
    // The declared-name signal is the only one that catches a policy REMOVAL
    // which was a no-op on the initial header map because the backend sent the
    // field only as a trailer.
    let backend = headers(&[("content-type", "application/grpc")]);
    let (_, decoded, _) = grpc_web_frame(
        &[("grpc-status", "0"), ("x-powered-by", "backend/1.2")],
        &backend,
        &backend,
        &["x-powered-by".to_string()],
        false,
        true,
        200,
        false,
    );
    let frame = frame_text(&decoded);
    assert!(
        !frame.contains("x-powered-by"),
        "a declared removal must bind the gRPC-Web frame too: {frame:?}"
    );
    assert!(frame.contains("grpc-status"), "{frame:?}");
}

// ── Source contracts ────────────────────────────────────────────────────────
//
// The two relays that build a client-visible gRPC-Web terminal frame have no
// local live runtime here (they need a QUIC client / a mesh-mTLS backend), so
// pin the ordering that makes the behavioral coverage above load-bearing.

#[test]
fn the_h3_grpc_web_branch_reconciles_before_collecting_terminal_metadata() {
    let src = include_str!("../../../src/http3/cross_protocol.rs");
    let start = src
        .find("async fn handle_h3_grpc_streaming_response")
        .expect("handle_h3_grpc_streaming_response not found");
    let tail = &src[start..];
    let branch_start = tail
        .find("} else if body_completed && let Some(text_mode) = grpc_web_translation_mode {")
        .expect("translated gRPC-Web branch not found");
    let branch = &tail[branch_start..];
    let branch_end = branch
        .find("} else if body_completed && let Some(mut trailers) = trailers {")
        .expect("end of translated gRPC-Web branch not found");
    let branch = &branch[..branch_end];

    let reconcile = branch
        .find("reconcile_streaming_backend_trailers(")
        .expect("the translated gRPC-Web branch must reconcile backend trailers");
    let collect = branch
        .find("collect_buffered_grpc_trailers(")
        .expect("collect_buffered_grpc_trailers not found in the gRPC-Web branch");
    assert!(
        reconcile < collect,
        "reconciliation must run BEFORE the terminal metadata is collected for encoding"
    );
    assert!(
        branch.contains("TrailerSectionKind::NativeGrpcTerminal"),
        "the gRPC-Web terminal block is a native gRPC terminal section"
    );
    let latch = branch
        .find("pristine_trailer_status = trailers")
        .expect("the pristine backend status must be latched");
    assert!(
        latch < reconcile,
        "the backend gRPC status must be latched BEFORE reconciliation"
    );
}

#[test]
fn the_grpc_web_adapter_wraps_the_governed_body_from_the_outside() {
    // The HTTP/2 relays reconcile inside `StripHopByHopTrailers`, which
    // `into_grpc_web_streaming` must wrap from the OUTSIDE. Reversing that order
    // would hand `GrpcWebStreamingBody` a raw backend trailer frame and encode
    // ungoverned metadata into the client-visible terminal DATA frame.
    let src = include_str!("../../../src/proxy/mod.rs");
    for arm in [
        // Direct-H2 gRPC pool streaming relay.
        "Ok(GrpcResponseKind::Streaming(grpc_streaming)) => {",
        // Generic relay (mesh-mTLS `StreamingH2`): the adapter is applied after
        // the whole `match` that built the governed body.
        "let streaming_trailer_policy = if matches!(",
    ] {
        let region = src.split(arm).nth(1).expect("relay region not found");
        let governed = region
            .find("_strip_hop_by_hop_trailers(")
            .expect("the relay must install the strip/govern wrapper");
        let adapter = region
            .find("into_grpc_web_streaming(")
            .expect("the relay must apply the gRPC-Web adapter");
        assert!(
            governed < adapter,
            "`{arm}`: the gRPC-Web adapter must wrap the already-governed body"
        );
    }
}
