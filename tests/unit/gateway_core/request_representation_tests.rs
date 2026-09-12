//! Shared backend-visible request representation gate (`GHSA-3973-47g5-4mcx`).
//!
//! These drive the PRODUCTION `evaluate_final_request_body_posture` through the
//! `_test_support` seam, so they assert the real fail-closed decision rather than
//! a reimplementation of it.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use ferrum_edge::_test_support::{
    FinalRequestRepresentationOutcome, MAX_DECODED_REQUEST_INSPECTION_BYTES,
    REQUEST_DECODE_OVERLOAD_BODY, REQUEST_DECODE_OVERLOAD_GRPC_MESSAGE,
    REQUEST_DECODE_OVERLOAD_GRPC_STATUS, REQUEST_DECODE_OVERLOAD_STATUS,
    REQUEST_DECODE_WORST_CASE_PEAK_BYTES, REQUEST_REPRESENTATION_UNINSPECTABLE_MESSAGE,
    RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT, RESPONSE_DECODE_BROTLI_SCRATCH_BYTES,
    RESPONSE_DECODE_GZIP_SCRATCH_BYTES, ResponseBufferBudgetProbe, charged_request_plaintext_in,
    clear_final_request_body_plaintext, evaluate_final_request_representation,
    evaluate_final_request_representation_in, final_request_body_plaintext_staged_for_test,
    finalize_synthetic_response_for_test, gateway_capacity_response_selected_for_test,
    gateway_representation_response_selected_for_test, projected_decode_output_capacity_for_test,
    run_request_body_stage_with_context_for_test,
    run_request_body_stage_with_context_in_budget_for_test,
};
use ferrum_edge::plugins::body_validator::BodyValidator;
use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;

// FE-PROTO-001 is a level-1 request-body rule. Query-only SQLi rules would not
// prove that the staged body bytes reached the body scanner.
const BLOCKED_JSON: &str = r#"{"note":"__proto__","approved":false}"#;

fn ctx_with_json_post() -> RequestContext {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/api".into());
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx
}

fn headers(content_encoding: Option<&str>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    if let Some(encoding) = content_encoding {
        headers.insert("content-encoding".to_string(), encoding.to_string());
    }
    headers
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
    writer.write_all(data).expect("brotli write");
    drop(writer);
    out
}

/// A WAF with an enforcing request-body rule: the reference claiming plugin.
fn enforcing_waf() -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "request_body_inspection": true,
            "default_rule_action": "enforce",
        }))
        .expect("waf config"),
    )
}

/// A `body_validator` requiring `approved: true` on JSON requests.
fn approving_body_validator() -> Arc<dyn Plugin> {
    Arc::new(
        BodyValidator::new(&json!({
            "required_fields": ["approved"],
            "content_types": ["application/json"],
        }))
        .expect("body_validator config"),
    )
}

#[test]
fn identity_request_needs_no_decode() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(None),
        BLOCKED_JSON.as_bytes(),
    );
    assert_eq!(outcome, FinalRequestRepresentationOutcome::Inspectable);
}

#[test]
fn explicit_identity_coding_needs_no_decode() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("identity")),
        BLOCKED_JSON.as_bytes(),
    );
    assert_eq!(outcome, FinalRequestRepresentationOutcome::Inspectable);
}

#[test]
fn unclaimed_encoded_request_is_left_alone() {
    // No configured policy claims this request, so an ordinary compressed upload
    // keeps flowing to a backend that understands it.
    let plugins: Vec<Arc<dyn Plugin>> = Vec::new();
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(outcome, FinalRequestRepresentationOutcome::Inspectable);
}

#[test]
fn single_gzip_coding_is_decoded_for_a_claiming_policy() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[test]
fn concatenated_gzip_members_are_rejected_for_a_claiming_policy() {
    let plugins = vec![approving_body_validator()];
    let ctx = ctx_with_json_post();
    let mut encoded = gzip(br#"{"approved":true}"#);
    // Even a second member that adds no plaintext is outside the single-member
    // contract, so rejection cannot depend on the decoded document's contents.
    encoded.extend_from_slice(&gzip(b""));

    let outcome =
        evaluate_final_request_representation(&plugins, &ctx, &headers(Some("gzip")), &encoded);

    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
}

#[test]
fn single_brotli_coding_is_decoded_for_a_claiming_policy() {
    let plugins = vec![approving_body_validator()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("br")),
        &brotli(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[test]
fn chained_gzip_then_brotli_is_decoded_in_reverse_application_order() {
    // `Content-Encoding: gzip, br` means gzip was applied first, then Brotli.
    // The chain the audited build refused to touch at all.
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let stacked = brotli(&gzip(BLOCKED_JSON.as_bytes()));
    let outcome =
        evaluate_final_request_representation(&plugins, &ctx, &headers(Some("gzip, br")), &stacked);
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[test]
fn x_gzip_alias_is_decoded() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("x-gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[test]
fn unsupported_coding_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("zstd")),
        BLOCKED_JSON.as_bytes(),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("unsupported_content_coding")
    );
}

#[test]
fn empty_coding_member_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    for value in ["gzip,", ",gzip", "  ", "gzip,,br"] {
        let outcome = evaluate_final_request_representation(
            &plugins,
            &ctx,
            &headers(Some(value)),
            &gzip(BLOCKED_JSON.as_bytes()),
        );
        assert_eq!(
            outcome,
            FinalRequestRepresentationOutcome::Rejected("malformed_content_coding"),
            "value {value:?} must not be read as an absent coding"
        );
    }
}

#[test]
fn identity_mixed_with_a_transforming_coding_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("identity, gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("malformed_content_coding")
    );
}

#[test]
fn parameterized_coding_member_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip;q=1")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("malformed_content_coding")
    );
}

#[test]
fn too_many_stacked_codings_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip, gzip, gzip, gzip, gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("too_many_content_codings")
    );
}

#[test]
fn truncated_gzip_stream_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let mut encoded = gzip(BLOCKED_JSON.as_bytes());
    encoded.truncate(encoded.len() / 2);
    let outcome =
        evaluate_final_request_representation(&plugins, &ctx, &headers(Some("gzip")), &encoded);
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
}

#[test]
fn plaintext_labelled_as_gzip_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        BLOCKED_JSON.as_bytes(),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
}

#[test]
fn empty_body_under_a_declared_coding_fails_closed() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome =
        evaluate_final_request_representation(&plugins, &ctx, &headers(Some("gzip")), &[]);
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
}

#[test]
fn a_zip_bomb_is_refused_by_the_decoded_size_bound() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    // 32 MiB of zeroes is a few kilobytes encoded and is refused past the
    // 10 MiB decoded ceiling; the decoder stops at the bound rather than
    // materializing the full expansion.
    let bomb = gzip(&vec![0u8; 32 * 1024 * 1024]);
    let outcome =
        evaluate_final_request_representation(&plugins, &ctx, &headers(Some("gzip")), &bomb);
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
}

#[test]
fn multiple_claiming_instances_all_reach_the_same_decision() {
    let plugins = vec![enforcing_waf(), approving_body_validator(), enforcing_waf()];
    let ctx = ctx_with_json_post();
    let outcome = evaluate_final_request_representation(
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    );
    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Decoded(BLOCKED_JSON.as_bytes().to_vec())
    );
}

#[tokio::test]
async fn waf_scans_the_staged_plaintext_not_the_wire_octets() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "include_default_rules": false,
        "request_body_inspection": true,
        "custom_rules": [{
            "id": "TEST-STAGED-PLAINTEXT",
            "name": "staged plaintext marker",
            "category": "custom",
            "severity": "high",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": "__proto__",
            "action": "enforce"
        }],
    }))
    .expect("waf config");
    let mut ctx = ctx_with_json_post();
    // The decode gate itself is exercised above. At this direct hook seam, use
    // a valid marker-free document for the wire argument so unrelated binary
    // encoding protections cannot decide the control case first.
    let wire_body = br#"{"note":"opaque"}"#;

    // Without the gate's plaintext view, the custom marker is absent.
    let opaque = plugin
        .on_final_request_body_with_context(&mut ctx, &headers(Some("gzip")), wire_body)
        .await;
    assert!(matches!(opaque, PluginResult::Continue));

    // With it, the body-only marker inside the document is found and blocked.
    let mut ctx = ctx_with_json_post();
    ferrum_edge::_test_support::stage_final_request_body_plaintext(
        &mut ctx,
        BLOCKED_JSON.as_bytes().to_vec(),
    );
    let scanned = plugin
        .on_final_request_body_with_context(&mut ctx, &headers(Some("gzip")), wire_body)
        .await;
    assert!(
        matches!(scanned, PluginResult::Reject { .. }),
        "WAF must block the plaintext it was configured about"
    );
}

#[tokio::test]
async fn body_validator_validates_the_staged_plaintext() {
    let plugin = BodyValidator::new(&json!({
        "required_fields": ["approved_marker"],
        "content_types": ["application/json"],
    }))
    .expect("body_validator config");
    let document = br#"{"approved":false}"#;
    let encoded = gzip(document);
    let mut ctx = ctx_with_json_post();
    ferrum_edge::_test_support::stage_final_request_body_plaintext(&mut ctx, document.to_vec());

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers(Some("gzip")), &encoded)
        .await;

    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "a missing required field in the decoded document must be rejected"
    );
}

// ---------------------------------------------------------------------------
// The aggregate request-decode budget (GHSA-3973-47g5-4mcx + GHSA-pwcm-6rh8-f2gh).
//
// A per-request ceiling bounds one decode; it does not bound the sum of the
// decodes many concurrent clients can start at once. These tests drive the
// PRODUCTION gate against an isolated semaphore — the same `Budget` type,
// clamping, non-blocking admission, and charge attachment the process-global
// budget uses — so they cannot pass against a parallel implementation of the
// rules and they do not race the process-global budget under a parallel test
// binary.
// ---------------------------------------------------------------------------

/// A probe budget of `total_blocks` reservation blocks, with a one-block
/// per-item floor so the clamp does not dominate the total.
fn probe(total_blocks: usize) -> ResponseBufferBudgetProbe {
    ResponseBufferBudgetProbe::new(UNIT, total_blocks * UNIT)
}

fn blocks(bytes: usize) -> usize {
    bytes.div_ceil(UNIT)
}

/// The output-buffer capacity one decode pass ends up holding for `decoded_len`
/// bytes, computed with the PRODUCTION growth rule rather than a hardcoded block
/// count, so a change to that rule fails with arithmetic rather than looking
/// flaky.
fn decode_capacity(decoded_len: usize) -> usize {
    projected_decode_output_capacity_for_test(decoded_len, MAX_DECODED_REQUEST_INSPECTION_BYTES)
}

/// A JSON document large enough that its decode needs several growth steps, and
/// compressible enough that the encoded form is trivially small.
fn large_json_document() -> Vec<u8> {
    let filler = "a".repeat(64 * 1024);
    format!(r#"{{"note":"{filler}","approved":false}}"#).into_bytes()
}

/// Large Window Brotli asks a non-strict decoder for a ring buffer bounded by
/// 1 GiB rather than 16 MiB, from six header bits, for a coding no client
/// negotiated. RFC 7932 caps the `br` window at 24 bits, so the request gate
/// must treat the LWB marker as a format error — and must reach that conclusion
/// while the budget can comfortably afford an ordinary `br` decode, so a refusal
/// here can only be the strict decoder and never a capacity accident.
#[test]
fn large_window_brotli_is_refused_by_the_request_gate() {
    const LWB_MARKER_BODY: [u8; 8] = [0x11, 0x1e, 0, 0, 0, 0, 0, 0];
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let budget = probe(blocks(RESPONSE_DECODE_BROTLI_SCRATCH_BYTES) + 8);
    let total = budget.available_bytes();

    let outcome = evaluate_final_request_representation_in(
        &budget,
        &plugins,
        &ctx,
        &headers(Some("br")),
        &LWB_MARKER_BODY,
    );

    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding"),
        "the LWB window extension must be a representation error, not a \
         capacity refusal and certainly not an admitted decode"
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "every permit the refused decode took is released"
    );
}

/// The `br` decoder allocates its ring buffer from the stream header on the
/// FIRST read, before any output byte exists. A budget that cannot cover that
/// working set must refuse BEFORE the decoder is constructed, which is only
/// observable as: nothing decoded, nothing charged.
#[test]
fn a_budget_that_cannot_cover_the_brotli_scratch_refuses_before_construction() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    // One block short of the codec working set, so the scratch reservation is
    // the thing that cannot be satisfied.
    let budget = probe(blocks(RESPONSE_DECODE_BROTLI_SCRATCH_BYTES) - 1);
    let total = budget.available_bytes();

    let outcome = evaluate_final_request_representation_in(
        &budget,
        &plugins,
        &ctx,
        &headers(Some("br")),
        &brotli(BLOCKED_JSON.as_bytes()),
    );

    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::CapacityRefused,
        "a decoder heap the aggregate budget cannot admit is a GATEWAY capacity \
         refusal, not a malformed client representation"
    );
    assert_eq!(budget.available_bytes(), total);
}

/// Past the decoder, the OUTPUT allocation is charged before each growth too, so
/// a budget that affords the codec scratch but not the plaintext still refuses
/// instead of allocating and being rejected afterwards.
#[test]
fn a_budget_that_cannot_cover_the_output_refuses_before_the_allocation() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let document = large_json_document();
    // Room for the gzip working set plus exactly one output block: enough to
    // construct the decoder and take the first growth, never enough for the
    // document.
    let budget = probe(blocks(RESPONSE_DECODE_GZIP_SCRATCH_BYTES) + 1);
    let total = budget.available_bytes();
    assert!(
        decode_capacity(document.len()) > UNIT,
        "the document must need more than the one output block the budget affords"
    );

    let outcome = evaluate_final_request_representation_in(
        &budget,
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        &gzip(&document),
    );

    assert_eq!(outcome, FinalRequestRepresentationOutcome::CapacityRefused);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the partially grown buffer and its permits are dropped together"
    );
}

/// The charge is not a decode-local. It has to be alive for exactly as long as
/// the staged inspection view can be read by a final request-body hook, and it
/// has to come back by DROP rather than by anyone remembering to release it.
#[test]
fn the_reservation_is_held_for_as_long_as_the_plaintext_is_readable() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let budget = probe(blocks(RESPONSE_DECODE_GZIP_SCRATCH_BYTES) + 64);
    let total = budget.available_bytes();

    let plaintext = charged_request_plaintext_in(
        &budget,
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        &gzip(BLOCKED_JSON.as_bytes()),
    )
    .expect("a well-formed governed gzip body decodes");
    assert_eq!(plaintext.as_bytes(), BLOCKED_JSON.as_bytes());

    // The decode has returned. Had the charge been a decode-local, the budget
    // would be fully available here while the plaintext stays resident — which
    // is exactly how concurrent decodes escape an aggregate cap.
    let held_after_decode = total - budget.available_bytes();
    assert!(
        held_after_decode > 0,
        "the staged plaintext must still be charged after the decode returns"
    );
    assert!(
        held_after_decode <= blocks(decode_capacity(BLOCKED_JSON.len())) * UNIT,
        "the transient decode peak must be narrowed back to the surviving \
         allocation, not held for the whole request"
    );

    // Staging transfers the same charge onto the context; it does not mint a
    // second one, and it does not release the first.
    let mut ctx = ctx_with_json_post();
    plaintext.stage_on(&mut ctx);
    assert_eq!(
        total - budget.available_bytes(),
        held_after_decode,
        "staging moves the charge rather than duplicating or dropping it"
    );

    // A `RequestContext` clone shares the one owner. A `Vec` field would have
    // duplicated an attacker-amplified allocation with no second permit.
    let cloned = ctx.clone();
    assert_eq!(
        total - budget.available_bytes(),
        held_after_decode,
        "a context clone shares the charged allocation instead of copying it"
    );
    drop(cloned);

    // This is what the gate does at the start of every final-request-body hook
    // run, which is how a retry or second finalization releases the previous
    // decode.
    clear_final_request_body_plaintext(&mut ctx);
    assert_eq!(
        budget.available_bytes(),
        total,
        "re-finalization must return the previous decode's charge in full"
    );
}

/// A representation rejection is not a partial charge. Everything the failed
/// decode took goes back, so a client that floods malformed codings cannot
/// exhaust the budget for everyone else.
#[test]
fn a_rejected_representation_charges_nothing() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let budget = probe(blocks(RESPONSE_DECODE_GZIP_SCRATCH_BYTES) + 64);
    let total = budget.available_bytes();

    let mut encoded = gzip(&large_json_document());
    encoded.truncate(encoded.len() / 2);
    let outcome = evaluate_final_request_representation_in(
        &budget,
        &plugins,
        &ctx,
        &headers(Some("gzip")),
        &encoded,
    );

    assert_eq!(
        outcome,
        FinalRequestRepresentationOutcome::Rejected("undecodable_content_coding")
    );
    assert_eq!(budget.available_bytes(), total);
}

/// A stacked `Content-Encoding` holds one pass's input and the next pass's
/// output at the SAME time, so the budget has to see the peak rather than the
/// larger of the two. The pair of assertions below is what makes that concrete:
/// a budget sized for the peak admits the decode, and a budget one block short
/// of it refuses — even though it is comfortably larger than the surviving
/// plaintext, which is all a non-concurrent accounting would have charged.
#[test]
fn a_stacked_decode_is_charged_at_its_concurrent_peak() {
    let plugins = vec![enforcing_waf()];
    let ctx = ctx_with_json_post();
    let document = large_json_document();
    let inner = gzip(&document);
    let wire = gzip(&inner);

    // Pass 1 decodes the wire bytes to `inner`; pass 2 decodes `inner` to the
    // document while `inner`'s buffer is still resident. Only one decoder is
    // active at a time, so exactly one gzip scratch reservation overlaps.
    let peak_reservation = decode_capacity(inner.len()) + decode_capacity(document.len());
    let peak_blocks = blocks(peak_reservation) + blocks(RESPONSE_DECODE_GZIP_SCRATCH_BYTES);
    assert!(
        blocks(decode_capacity(document.len())) < blocks(peak_reservation),
        "the intermediate buffer must be a real part of the peak, or this test \
         proves nothing about concurrency"
    );

    let short = probe(peak_blocks - 1);
    assert_eq!(
        evaluate_final_request_representation_in(
            &short,
            &plugins,
            &ctx,
            &headers(Some("gzip, gzip")),
            &wire,
        ),
        FinalRequestRepresentationOutcome::CapacityRefused,
        "a budget short of the CONCURRENT peak must refuse, even though it \
         exceeds the surviving plaintext's own allocation"
    );
    assert_eq!(
        short.available_bytes(),
        peak_blocks.saturating_sub(1) * UNIT
    );

    let exact = probe(peak_blocks);
    let total = exact.available_bytes();
    let plaintext =
        charged_request_plaintext_in(&exact, &plugins, &ctx, &headers(Some("gzip, gzip")), &wire)
            .expect("a budget sized for the peak admits the stacked decode");
    assert_eq!(plaintext.as_bytes(), document.as_slice());
    assert_eq!(
        total - exact.available_bytes(),
        blocks(decode_capacity(document.len())) * UNIT,
        "once the intermediate buffer is gone the peak is narrowed back to the \
         surviving allocation"
    );
    drop(plaintext);
    assert_eq!(exact.available_bytes(), total);
}

/// The budget is floored at one worst-case governed request — `br` scratch plus
/// two decode ceilings — so no configuration can leave the gateway unable to run
/// a single governed decode at all.
#[test]
fn the_request_decode_budget_floor_admits_one_worst_case_request() {
    assert_eq!(
        REQUEST_DECODE_WORST_CASE_PEAK_BYTES,
        RESPONSE_DECODE_BROTLI_SCRATCH_BYTES + 2 * MAX_DECODED_REQUEST_INSPECTION_BYTES,
        "the floor must cover the active decoder's heap plus the stacked-pass \
         input and output that are resident beside it"
    );
}

/// The refusal is a GATEWAY-local capacity terminal, and it has to stay
/// redaction-safe and protocol-correct through the shared final-request funnel:
/// a fixed body naming no route, header, coding, or body byte; `503` rather than
/// a `400` blaming a valid upload; and `RESOURCE_EXHAUSTED` rather than the
/// `UNAVAILABLE` a bare `503` would otherwise map to, which would claim the
/// backend is down.
#[test]
fn the_capacity_terminal_is_fixed_redaction_safe_and_protocol_correct() {
    assert_eq!(REQUEST_DECODE_OVERLOAD_STATUS, 503);
    assert_eq!(REQUEST_DECODE_OVERLOAD_GRPC_STATUS, 8); // RESOURCE_EXHAUSTED
    assert_eq!(
        REQUEST_DECODE_OVERLOAD_BODY,
        r#"{"error":"Request inspection capacity exceeded"}"#
    );
    assert_eq!(
        REQUEST_DECODE_OVERLOAD_GRPC_MESSAGE,
        "Request inspection capacity exceeded"
    );

    let proxy = include_str!("../../../src/proxy/mod.rs");
    assert!(
        proxy.contains("FinalRequestBodyPosture::CapacityRefused => {"),
        "the shared final-request funnel — the one every dispatch ladder uses — \
         must handle the capacity posture itself, so H1/H2, native gRPC, \
         gRPC-Web, H3, and the H3 bridge cannot disagree about it"
    );
    assert!(
        proxy.contains("status_code: budget::REQUEST_DECODE_OVERLOAD_STATUS,")
            && proxy.contains("body: budget::REQUEST_DECODE_OVERLOAD_BODY.to_string(),"),
        "the terminal must be the fixed gateway-local one"
    );
    assert!(
        proxy.contains("budget::REQUEST_DECODE_OVERLOAD_GRPC_STATUS.to_string(),")
            && proxy.contains("client_grpc_framing_representation(ctx).is_some()"),
        "native gRPC and gRPC-Web clients must receive RESOURCE_EXHAUSTED, and \
         only they — a plain HTTP 503 must not carry gRPC trailer fields"
    );
}

/// The staged plaintext is decoded client body content. It must never be copied
/// into `metadata` (which is what a transaction log serializes) and no plugin
/// may fabricate or clear it.
#[test]
fn the_staged_plaintext_never_reaches_metadata_or_transaction_output() {
    let plugins = include_str!("../../../src/plugins/mod.rs");
    assert!(
        plugins.contains("governed_request_body_plaintext: Option<bytes::Bytes>,"),
        "the staged view must be typed and outside `metadata`, and must own its \
         budget charge so a context clone shares it rather than duplicating an \
         attacker-amplified allocation"
    );
    for claimant in [
        include_str!("../../../src/plugins/waf/mod.rs"),
        include_str!("../../../src/plugins/body_validator.rs"),
        include_str!("../../../src/plugins/graphql.rs"),
    ] {
        assert!(
            !claimant.contains("inspectable_final_request_body(body).to_vec()"),
            "a claiming hook must take the O(1) owned handle rather than copying \
             the charged plaintext into a second, uncharged allocation"
        );
    }
}

// ---------------------------------------------------------------------------
// Claiming is DISPOSITION-AWARE.
//
// A claim is a fail-closed assertion: it converts an undecodable representation
// into a fixed `400`. A configuration that could never have blocked the request
// has nothing to fail closed about — an unscannable body there is a lost
// observation, not a protection-mechanism failure — so it must not claim. These
// drive the authoritative shared funnel
// (`run_final_request_body_hooks_with_provenance`), not the claim predicate, so
// they assert the behavior the client actually receives.
// ---------------------------------------------------------------------------

/// A WAF that OBSERVES request bodies: globally `monitor`, so no rule of its can
/// block anything.
fn monitoring_waf() -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "monitor",
            "request_body_inspection": true,
            "default_rule_action": "enforce",
        }))
        .expect("monitor waf config"),
    )
}

/// A WAF whose operator opted bodies above `max_scan_bytes` out of scanning
/// entirely (`on_body_too_large: skip`).
fn skip_on_large_waf() -> Arc<dyn Plugin> {
    Arc::new(
        Waf::new(&json!({
            "mode": "enforce",
            "request_body_inspection": true,
            "default_rule_action": "enforce",
            "on_body_too_large": "skip",
            "max_scan_bytes": 32,
        }))
        .expect("skip-on-large waf config"),
    )
}

fn headers_with_length(
    content_encoding: Option<&str>,
    content_length: usize,
) -> HashMap<String, String> {
    let mut headers = headers(content_encoding);
    headers.insert("content-length".to_string(), content_length.to_string());
    headers
}

/// An encoding this gateway does not implement: the strongest possible
/// uninspectable case, since no budget or codec accident can decode it.
const UNSUPPORTED_CODING: &str = "zstd";

async fn run_final_request_stage(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    request_headers: &HashMap<String, String>,
    body: &[u8],
) -> PluginResult {
    run_request_body_stage_with_context_for_test(plugins, ctx, request_headers, body)
        .await
        .1
}

/// The fail-closed baseline this pair is measured against.
#[tokio::test]
async fn an_enforcing_waf_still_refuses_an_undecodable_request_representation() {
    let plugins = vec![enforcing_waf()];
    let mut ctx = ctx_with_json_post();

    let result = run_final_request_stage(
        &plugins,
        &mut ctx,
        &headers(Some(UNSUPPORTED_CODING)),
        BLOCKED_JSON.as_bytes(),
    )
    .await;

    assert!(
        matches!(
            &result,
            PluginResult::Reject {
                status_code: 400,
                ..
            }
        ),
        "an enforcing body policy must not forward a representation it could \
         not read, got {result:?}"
    );
}

/// A `monitor`-mode WAF cannot block, so it must not turn an ordinary encoded
/// upload into a `400` it would never have rejected on its own.
#[tokio::test]
async fn a_monitor_mode_waf_does_not_refuse_an_undecodable_request_representation() {
    let plugins = vec![monitoring_waf()];
    let mut ctx = ctx_with_json_post();

    let result = run_final_request_stage(
        &plugins,
        &mut ctx,
        &headers(Some(UNSUPPORTED_CODING)),
        BLOCKED_JSON.as_bytes(),
    )
    .await;

    assert!(
        matches!(result, PluginResult::Continue),
        "an observe-only WAF loses an observation on an unscannable body; it \
         must not convert one into a client error"
    );
    assert!(
        !gateway_representation_response_selected_for_test(&ctx),
        "no gateway representation terminal may be selected for an unclaimed \
         request"
    );
}

/// `on_body_too_large: skip` is an explicit operator opt-out of scanning bodies
/// this large. No scan means no claim: exactly the applicability terms
/// `should_buffer_request_body` already applies.
#[tokio::test]
async fn a_skip_on_large_waf_does_not_claim_a_body_it_would_not_scan() {
    let plugins = vec![skip_on_large_waf()];
    let mut ctx = ctx_with_json_post();
    let encoded = gzip(BLOCKED_JSON.as_bytes());

    let skipped = run_final_request_stage(
        &plugins,
        &mut ctx,
        &headers_with_length(Some(UNSUPPORTED_CODING), 1_048_576),
        &encoded,
    )
    .await;
    assert!(
        matches!(skipped, PluginResult::Continue),
        "a body the policy declined to scan cannot be a fail-closed claim"
    );

    // The same instance still claims a body inside its scan window, so the
    // opt-out narrows the claim rather than disabling it.
    let mut small_ctx = ctx_with_json_post();
    let claimed = run_final_request_stage(
        &plugins,
        &mut small_ctx,
        &headers_with_length(Some(UNSUPPORTED_CODING), 8),
        &encoded,
    )
    .await;
    assert!(
        matches!(
            &claimed,
            PluginResult::Reject {
                status_code: 400,
                ..
            }
        ),
        "a body within the scan window is still claimed, got {claimed:?}"
    );
}

// ---------------------------------------------------------------------------
// Charge LIFETIME: the staged plaintext belongs to the hook stage, not to the
// request.
//
// On H1/H2 the final hooks receive a throwaway clone, so the decode dies with
// it. Native H3 hands them the REAL `RequestContext`, which would otherwise
// hold an attacker-amplified decode — and its aggregate budget block — until
// request teardown. The stage releases it on every exit instead.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_hook_stage_releases_the_decode_charge_when_it_returns() {
    let plugins = vec![enforcing_waf()];
    // The native-H3 shape: the hooks mutate this very context.
    let mut ctx = ctx_with_json_post();
    let document = large_json_document();
    let wire = gzip(&document);
    let budget = probe(
        blocks(decode_capacity(document.len())) + blocks(RESPONSE_DECODE_GZIP_SCRATCH_BYTES) + 4,
    );
    let baseline = budget.available_bytes();

    let (_, result) = run_request_body_stage_with_context_in_budget_for_test(
        &budget,
        &plugins,
        &mut ctx,
        &headers(Some("gzip")),
        &wire,
    )
    .await;

    assert!(
        matches!(result, PluginResult::Continue),
        "the decoded document carries no blocked marker"
    );
    assert!(
        !final_request_body_plaintext_staged_for_test(&ctx),
        "the staged plaintext must not outlive the hook stage that decoded it"
    );
    assert_eq!(
        budget.available_bytes(),
        baseline,
        "the aggregate request-decode charge must return at the hook-stage \
         boundary, not at request teardown"
    );
}

// ---------------------------------------------------------------------------
// The request gate's two terminals are GATEWAY-authored, and the synthetic
// response-body policy pipeline that finalizes them must publish them as
// written (`.claude/rules/plugins.md` 10b).
// ---------------------------------------------------------------------------

/// A `body_validator` whose RESPONSE schema no gateway error payload satisfies.
/// Without terminal provenance it rewrites the gateway's own answer.
fn body_validator_requiring_approved_response() -> Arc<dyn Plugin> {
    Arc::new(
        BodyValidator::new(&json!({
            "response_required_fields": ["approved"],
            "response_content_types": ["application/json"],
        }))
        .expect("body_validator response config"),
    )
}

async fn finalize_rejection(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    rejection: PluginResult,
) -> (u16, Vec<u8>) {
    let (mut status, mut body, mut response_headers) = match rejection {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, bytes::Bytes::from(body), headers),
        other => panic!("expected a rejection, got {other:?}"),
    };
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    // A route response-body ceiling far below the terminal's own JSON. A
    // gateway-authored terminal must not be recategorized as an oversized
    // backend representation by the size policy this finalizer applies.
    ctx.max_response_body_size_bytes = 8;
    finalize_synthetic_response_for_test(
        plugins,
        ctx,
        &mut status,
        &mut response_headers,
        &mut body,
    )
    .await;
    (status, body.to_vec())
}

/// The fixed `400` for an unreadable request representation must reach the
/// client as the gateway wrote it: neither the response-schema validator in the
/// chain nor the finalizer's route response-size policy may restate it.
#[tokio::test]
async fn the_request_representation_terminal_survives_the_response_policy_finalizer() {
    let plugins = vec![
        enforcing_waf(),
        body_validator_requiring_approved_response(),
    ];
    let mut ctx = ctx_with_json_post();

    let rejection = run_final_request_stage(
        &plugins,
        &mut ctx,
        &headers(Some(UNSUPPORTED_CODING)),
        BLOCKED_JSON.as_bytes(),
    )
    .await;
    assert!(
        gateway_representation_response_selected_for_test(&ctx),
        "the gate must stamp trusted provenance for its own fixed terminal"
    );

    let (status, body) = finalize_rejection(&plugins, &mut ctx, rejection).await;
    assert_eq!(
        status, 400,
        "a response validator must not restate the gateway's request-side \
         terminal as a backend representation failure"
    );
    let body = String::from_utf8_lossy(&body).to_string();
    assert!(
        body.contains(REQUEST_REPRESENTATION_UNINSPECTABLE_MESSAGE),
        "the fixed gateway body must be published verbatim, got {body}"
    );
}

/// The same for the capacity terminal, which is the gateway's health-neutral
/// `503` and likewise never a policy verdict about an application response.
#[tokio::test]
async fn the_request_decode_capacity_terminal_survives_the_response_policy_finalizer() {
    let plugins = vec![
        enforcing_waf(),
        body_validator_requiring_approved_response(),
    ];
    let mut ctx = ctx_with_json_post();
    let document = large_json_document();
    let wire = gzip(&document);
    // One block: far below the decode's working set, so the gate refuses on
    // capacity rather than on the bytes.
    let budget = probe(1);

    let (_, rejection) = run_request_body_stage_with_context_in_budget_for_test(
        &budget,
        &plugins,
        &mut ctx,
        &headers(Some("gzip")),
        &wire,
    )
    .await;
    assert!(
        gateway_capacity_response_selected_for_test(&ctx),
        "a request-decode capacity refusal is the shared gateway-capacity \
         terminal, so the finalizer can recognize it"
    );

    let (status, body) = finalize_rejection(&plugins, &mut ctx, rejection).await;
    assert_eq!(status, REQUEST_DECODE_OVERLOAD_STATUS);
    assert_eq!(String::from_utf8_lossy(&body), REQUEST_DECODE_OVERLOAD_BODY);
}
