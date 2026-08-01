//! Route-scoped request/response body ceilings and `Content-Length`
//! canonicalization (`GHSA-xrfj-852f-645j`).
//!
//! The advisory's core defect was that a route-scoped `request_size_limiting` /
//! `response_size_limiting` ceiling was only ever consulted in a body hook, so
//! it never reached the streaming adapters or buffered collectors. These tests
//! pin the two primitives every dispatch path now shares:
//!
//! 1. the fold that turns (global knob, route ceiling) into one effective bound,
//!    including the "global `0` must not disable an active route ceiling" rule; and
//! 2. the declared-`Content-Length` parse, which must honor standards-valid
//!    repeated identical values instead of failing to parse a comma-folded list
//!    and silently skipping the bound.

use ferrum_edge::_test_support::{
    canonical_header_content_length_for_test, canonical_header_content_length_from_map_for_test,
    declared_request_content_length_over_limit_for_test,
    declared_response_length_exceeds_limit_for_test, effective_request_body_limit_for_test,
    stricter_optional_limit_for_test,
};
use ferrum_edge::plugins::RequestContext;
use ferrum_edge::util::body_limit::{ContentLength, declared_content_length, parse_content_length};
use std::collections::HashMap;

fn map(content_length: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), content_length.to_string());
    headers
}

fn header_map(values: &[&str]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for value in values {
        headers.append(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(value).expect("test header value"),
        );
    }
    headers
}

// === Effective ceiling fold ===

/// The whole point of the advisory fix: an active route ceiling is authoritative
/// even when the operator disabled the global limit (`0` == unlimited). Before
/// the fix a zero global meant the streaming adapter received no bound at all.
#[test]
fn zero_global_limit_does_not_disable_an_active_route_limit() {
    assert_eq!(effective_request_body_limit_for_test(0, Some(1024)), 1024);
}

#[test]
fn effective_limit_is_the_strictest_active_bound() {
    // Route stricter than global.
    assert_eq!(
        effective_request_body_limit_for_test(10 * 1024 * 1024, Some(1024)),
        1024
    );
    // Global stricter than route.
    assert_eq!(effective_request_body_limit_for_test(512, Some(1024)), 512);
}

/// A proxy with no size-limiting plugin must behave byte-for-byte as it did
/// before the fix: the global knob passes through untouched, including `0`.
#[test]
fn absent_route_limit_preserves_the_global_knob_exactly() {
    assert_eq!(effective_request_body_limit_for_test(4096, None), 4096);
    assert_eq!(effective_request_body_limit_for_test(0, None), 0);
}

/// Multiple instances (or a global plus a proxy-scoped instance) compose to the
/// minimum; the composition helper is what the prebuffer phases use to combine
/// their own buffering cap with the route ceiling.
#[test]
fn stricter_optional_limit_composes_to_the_minimum() {
    assert_eq!(
        stricter_optional_limit_for_test(Some(64), Some(32)),
        Some(32)
    );
    assert_eq!(
        stricter_optional_limit_for_test(Some(32), Some(64)),
        Some(32)
    );
    assert_eq!(stricter_optional_limit_for_test(Some(32), None), Some(32));
    assert_eq!(stricter_optional_limit_for_test(None, Some(32)), Some(32));
    assert_eq!(stricter_optional_limit_for_test(None, None), None);
}

// === Content-Length canonicalization ===

#[test]
fn single_declared_length_parses_exactly() {
    assert_eq!(parse_content_length("2048"), ContentLength::Exact(2048));
    // Surrounding OWS is legal field-value whitespace.
    assert_eq!(parse_content_length("  2048\t"), ContentLength::Exact(2048));
}

/// The exact bypass the advisory describes: a standards-valid repeated identical
/// `Content-Length` reaches plugin-facing maps comma-folded, and a whole-list
/// `parse::<u64>()` used to fail and read as "no declared length".
#[test]
fn repeated_identical_declared_lengths_fold_to_one_exact_value() {
    assert_eq!(
        parse_content_length("2048, 2048"),
        ContentLength::Exact(2048)
    );
    assert_eq!(
        parse_content_length("2048,2048,2048"),
        ContentLength::Exact(2048)
    );
}

#[test]
fn disagreeing_declared_lengths_are_ambiguous_not_absent() {
    assert_eq!(parse_content_length("2048, 4096"), ContentLength::Ambiguous);
}

/// `str::parse::<u64>()` accepts a leading `+`, which is not a valid
/// `Content-Length`. The parser validates `1*DIGIT` explicitly so a signed or
/// otherwise malformed member can never be honored as a length.
#[test]
fn non_digit_members_are_ambiguous() {
    for value in [
        "+2048",
        "-1",
        "20.48",
        "0x800",
        "2048abc",
        "not-a-number",
        "2048,",
        ",2048",
        "2048,,2048",
        "20 48",
    ] {
        assert_eq!(
            parse_content_length(value),
            ContentLength::Ambiguous,
            "{value:?} must be refused as ambiguous, never treated as absent"
        );
    }
}

/// A value wider than `u64` cannot bound anything, so it is ambiguous rather
/// than silently truncated or wrapped.
#[test]
fn declared_length_above_u64_is_ambiguous() {
    assert_eq!(
        parse_content_length("184467440737095516160"),
        ContentLength::Ambiguous
    );
}

#[test]
fn absent_field_is_none_but_present_empty_field_is_ambiguous() {
    assert_eq!(parse_content_length(""), ContentLength::Ambiguous);
    assert_eq!(parse_content_length("   "), ContentLength::Ambiguous);
    assert_eq!(declared_content_length(&HashMap::new()), None);
}

// === Raw header-map canonicalization (multi-entry wire shape) ===

/// Hyper accepts a message whose `Content-Length` appears as several separate
/// entries with identical values. Both wire shapes — repeated entries and one
/// coalesced list — must reduce to the same single bound.
#[test]
fn repeated_header_entries_reduce_to_one_length() {
    assert_eq!(
        canonical_header_content_length_for_test(&header_map(&["2048", "2048"])),
        Some(2048)
    );
    assert_eq!(
        canonical_header_content_length_for_test(&header_map(&["2048, 2048"])),
        Some(2048)
    );
}

#[test]
fn disagreeing_header_entries_are_unusable() {
    assert_eq!(
        canonical_header_content_length_for_test(&header_map(&["2048", "4096"])),
        None
    );
    assert_eq!(
        canonical_header_content_length_for_test(&header_map(&["2048, 4096"])),
        None
    );
}

#[test]
fn absent_header_has_no_canonical_length() {
    assert_eq!(
        canonical_header_content_length_for_test(&http::HeaderMap::new()),
        None
    );
}

#[test]
fn folded_map_canonicalization_matches_the_raw_header_view() {
    assert_eq!(
        canonical_header_content_length_from_map_for_test(&map("2048, 2048")),
        Some(2048)
    );
    assert_eq!(
        canonical_header_content_length_from_map_for_test(&map("2048, 4096")),
        None
    );
}

// === Declared-length reject predicates used by every dispatch path ===

/// Exact boundary passes: the ceiling is inclusive (`len == max` is allowed),
/// matching the plugins' own `exceeds_limit` contract.
#[test]
fn request_declared_length_reject_is_inclusive_at_the_boundary() {
    assert!(!declared_request_content_length_over_limit_for_test(
        &map("1024"),
        1024
    ));
    assert!(declared_request_content_length_over_limit_for_test(
        &map("1025"),
        1024
    ));
}

/// A repeated identical declaration over the ceiling must be rejected, not
/// waved through because the folded list failed to parse.
#[test]
fn request_declared_length_reject_honors_repeated_identical_values() {
    assert!(declared_request_content_length_over_limit_for_test(
        &map("2048, 2048"),
        1024
    ));
    assert!(!declared_request_content_length_over_limit_for_test(
        &map("1024, 1024"),
        1024
    ));
}

/// A chunked / unknown-length request has no declared length, so this fast path
/// cannot decide anything — enforcement is the streaming adapter's job, which is
/// exactly the surface the advisory said was unbounded. The predicate must not
/// guess.
#[test]
fn request_declared_length_reject_is_inert_without_a_usable_declaration() {
    assert!(!declared_request_content_length_over_limit_for_test(
        &HashMap::new(),
        1024
    ));
    // Ambiguous declaration: refuse to invent a length here; the bounded
    // stream/collect ceiling still applies.
    assert!(!declared_request_content_length_over_limit_for_test(
        &map("2048, 4096"),
        1024
    ));
}

#[test]
fn request_declared_length_reject_is_disabled_by_an_unlimited_ceiling() {
    assert!(!declared_request_content_length_over_limit_for_test(
        &map("999999"),
        0
    ));
}

#[test]
fn response_declared_length_reject_matches_the_request_side_semantics() {
    // Inclusive boundary.
    assert_eq!(
        declared_response_length_exceeds_limit_for_test(&map("1024"), 1024),
        None
    );
    assert_eq!(
        declared_response_length_exceeds_limit_for_test(&map("1025"), 1024),
        Some(1025)
    );
    // Repeated identical values are honored.
    assert_eq!(
        declared_response_length_exceeds_limit_for_test(&map("2048, 2048"), 1024),
        Some(2048)
    );
    // Ambiguity does not invent a length.
    assert_eq!(
        declared_response_length_exceeds_limit_for_test(&map("2048, 4096"), 1024),
        None
    );
    // Unlimited ceiling disables the fast path.
    assert_eq!(
        declared_response_length_exceeds_limit_for_test(&map("999999"), 0),
        None
    );
}

// === Request-context carriage of the route ceilings ===

fn ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    )
}

/// A default-constructed context must read as "no route policy", so every
/// dispatch path falls back to the global knob exactly as it did before the fix
/// instead of seeing a fabricated "unlimited" that would relax a real bound.
#[test]
fn default_context_carries_no_route_ceilings() {
    let ctx = ctx();
    assert_eq!(ctx.route_request_body_limit_bytes, None);
    assert_eq!(ctx.route_response_body_limit_bytes, None);
    assert_eq!(ctx.route_request_body_limit(), None);
    assert_eq!(ctx.route_response_body_limit(), None);
    // No global set either, so the effective response ceiling is "unlimited".
    assert_eq!(ctx.effective_max_response_body_size_bytes(), 0);
}

/// The response accessor folds the global knob with the route ceiling, and an
/// unlimited global does not disable an active route ceiling. This is the value
/// the buffered-representation decode gate and compression admission read.
#[test]
fn effective_response_ceiling_folds_global_and_route() {
    let mut ctx = ctx();

    // Route stricter than global.
    ctx.max_response_body_size_bytes = 10 * 1024 * 1024;
    ctx.route_response_body_limit_bytes = Some(1024);
    assert_eq!(ctx.effective_max_response_body_size_bytes(), 1024);

    // Global stricter than route.
    ctx.max_response_body_size_bytes = 512;
    assert_eq!(ctx.effective_max_response_body_size_bytes(), 512);

    // Unlimited global, active route ceiling: the route ceiling wins.
    ctx.max_response_body_size_bytes = 0;
    assert_eq!(ctx.effective_max_response_body_size_bytes(), 1024);

    // No route ceiling: the global knob passes through, including `0`.
    ctx.route_response_body_limit_bytes = None;
    assert_eq!(ctx.effective_max_response_body_size_bytes(), 0);
    ctx.max_response_body_size_bytes = 4096;
    assert_eq!(ctx.effective_max_response_body_size_bytes(), 4096);
}

#[test]
fn route_ceilings_convert_to_usize_for_folding() {
    let mut ctx = ctx();
    ctx.route_request_body_limit_bytes = Some(1024);
    ctx.route_response_body_limit_bytes = Some(2048);
    assert_eq!(ctx.route_request_body_limit(), Some(1024));
    assert_eq!(ctx.route_response_body_limit(), Some(2048));
}

// ---------------------------------------------------------------------------
// GHSA-pwcm-6rh8-f2gh — a legacy `0` ("unlimited") response ceiling must not
// produce an unbounded RETAINED buffer, and concurrent retained responses must
// share a finite aggregate budget.
// ---------------------------------------------------------------------------

#[test]
fn a_configured_response_ceiling_is_honored_verbatim_on_the_buffered_path() {
    for limit in [1usize, 4_096, 10_485_760, 1_073_741_824] {
        assert_eq!(
            ferrum_edge::_test_support::buffered_response_body_ceiling_for_test(limit),
            limit,
            "an operator-configured ceiling must not be widened or narrowed"
        );
    }
}

#[test]
fn zero_response_ceiling_becomes_finite_when_the_body_is_retained() {
    let ceiling = ferrum_edge::_test_support::buffered_response_body_ceiling_for_test(0);
    assert!(
        ceiling > 0,
        "`0 = unlimited` is a streaming policy; a retained buffer must stay bounded"
    );
}

#[test]
fn the_aggregate_budget_is_finite_and_always_admits_one_fallback_sized_response() {
    let unit = ferrum_edge::_test_support::RESPONSE_BUFFER_RESERVATION_UNIT_BYTES;
    assert!(unit > 0);

    // A degenerate total must not refuse every response outright.
    assert!(
        ferrum_edge::_test_support::response_buffer_budget_blocks_for_test(unit, 0) >= 1,
        "the aggregate budget is clamped up to at least the FALLBACK per-response ceiling"
    );

    // Stated exactly: the floor is the FALLBACK ceiling, not an arbitrarily
    // larger configured per-response ceiling. A 1 GiB fallback floors the total
    // at 1 GiB...
    let floored =
        ferrum_edge::_test_support::response_buffer_budget_blocks_for_test(1_073_741_824, 0);
    assert_eq!(floored, 1_073_741_824usize.div_ceil(unit));

    // ...but a small configured total is NOT widened to fit a large
    // *per-response* ceiling the operator set elsewhere. The budget below is
    // exactly what was asked for (16 MiB), even though a route could configure a
    // 1 GiB per-response ceiling: such a response is refused rather than
    // silently uncapping the aggregate bound.
    let not_widened =
        ferrum_edge::_test_support::response_buffer_budget_blocks_for_test(unit, 16 * 1024 * 1024);
    assert_eq!(not_widened, (16 * 1024 * 1024usize).div_ceil(unit));

    // The budget scales with the configured total, in whole blocks.
    let blocks = ferrum_edge::_test_support::response_buffer_budget_blocks_for_test(
        10 * 1024 * 1024,
        256 * 1024 * 1024,
    );
    assert_eq!(blocks, (256 * 1024 * 1024usize).div_ceil(unit));

    // And it is finite: no configuration yields an unbounded permit pool.
    assert!(blocks < usize::MAX);
}
