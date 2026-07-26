//! Canonical policy path contract (`src/policy_path.rs`).
//!
//! Covers the representation that routing, WAF, `openapi_validator`,
//! `request_termination`, authorization, cache keys, rewrites, and backend
//! forwarding all share (private advisory GHSA-69xf-42xm-4w4f).

use std::borrow::Cow;

use ferrum_edge::policy_path::{
    PolicyPathRejection, canonicalize_policy_path, non_canonical_policy_path_pattern_reason,
    non_canonical_policy_path_reason,
};

fn canonical(path: &str) -> String {
    canonicalize_policy_path(path)
        .unwrap_or_else(|rejection| panic!("{path:?} unexpectedly rejected: {rejection:?}"))
        .into_owned()
}

fn rejection(path: &str) -> PolicyPathRejection {
    canonicalize_policy_path(path)
        .err()
        .unwrap_or_else(|| panic!("{path:?} was unexpectedly accepted"))
}

// ── Fast path: cleared by a scan, not by the absence of `%` ────────────────

#[test]
fn ordinary_paths_are_borrowed_unchanged() {
    for path in [
        "",
        "/",
        "*",
        "/admin",
        "/api/v1/users/42",
        "/api//double",
        // A `.` inside a segment is an ordinary character; only a *complete*
        // `.` or `..` segment is a dot segment.
        "/a/.hidden/b",
        "/a/..hidden/b",
        "/a/b./c",
        "/v1.0/users",
        "/weird!$&'()*+,;=:@chars",
    ] {
        let result = canonicalize_policy_path(path).expect("ordinary path must be accepted");
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "{path:?} must not allocate"
        );
        assert_eq!(result, path);
    }
}

#[test]
fn the_escape_free_scan_still_rejects_literal_structure() {
    // The fast path is a *validating* scan. A target with no percent escape is
    // not automatically accepted: it is accepted because the scan cleared it.
    assert_eq!(rejection("/a/../b"), PolicyPathRejection::LiteralDotSegment);
    assert_eq!(rejection("/a\\b"), PolicyPathRejection::LiteralBackslash);
}

// ── Ordinary single encoding: the advisory's headline bypass ───────────────

#[test]
fn ordinary_single_encoding_of_a_legal_path_character_is_decoded() {
    // `/%61dmin` and `/admin` must be the same policy path, or an operator's
    // literal `/admin` rule misses while a decoding backend serves `/admin`.
    assert_eq!(canonical("/%61dmin"), "/admin");
    assert_eq!(canonical("/%41DMIN"), "/ADMIN");
    assert_eq!(canonical("/api/%76%31/users"), "/api/v1/users");
    assert_eq!(canonical("/%61%64%6d%69%6e"), "/admin");
}

#[test]
fn every_unreserved_and_sub_delim_escape_is_decoded() {
    // RFC 3986 pchar minus pct-encoded: unreserved / sub-delims / ":" / "@".
    let cases = [
        ("/%2Dx", "/-x"),
        ("/%2Ex", "/.x"),
        ("/%5Fx", "/_x"),
        ("/%7Ex", "/~x"),
        ("/%21x", "/!x"),
        ("/%24x", "/$x"),
        ("/%26x", "/&x"),
        ("/%27x", "/'x"),
        ("/%28x", "/(x"),
        ("/%29x", "/)x"),
        ("/%2Ax", "/*x"),
        ("/%2Bx", "/+x"),
        ("/%2Cx", "/,x"),
        ("/%3Bx", "/;x"),
        ("/%3Dx", "/=x"),
        ("/%3Ax", "/:x"),
        ("/%40x", "/@x"),
    ];
    for (raw, expected) in cases {
        assert_eq!(canonical(raw), expected, "decoding {raw:?}");
    }
}

#[test]
fn escapes_of_characters_illegal_in_a_path_are_rejected() {
    // An escaped space, `{`, `[`, or non-ASCII byte is outside the `pchar`
    // decode set. Retaining the escape would forward `/api%20name` while policy
    // read `/api%20name` and a decoding backend resolved `/api name` — exactly
    // the policy/backend mismatch this module exists to remove — and decoding it
    // would emit a byte the backend URL parser cannot carry or re-encodes, so
    // the forwarded request line would not be the canonical string either. The
    // target is refused instead. (This governs escapes: the same byte sent
    // literally is accepted, see the `src/policy_path.rs` module docs.)
    for path in [
        "/api%20name",
        "/api%7bname",
        "/api%7Dname",
        "/api%5Bname%5D",
        "/api%22name",
        "/api%3Cname%3E",
        "/api%5Ename",
        "/api%60name",
        "/api%7Cname",
        "/caf%c3%a9",
        "/%E2%9C%93",
        "/%FF",
    ] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::UnrepresentableEscape,
            "{path:?}"
        );
    }
}

#[test]
fn no_percent_escape_survives_canonicalization() {
    // The single-coordinate contract: an escape is either decoded to the byte
    // it names or the request is refused, so the canonical path is byte-for-byte
    // what a decoding backend resolves and there is no second spelling to keep
    // in sync.
    for raw in [
        "/%61dmin",
        "/a/%2Ehidden",
        "/%40user/%3Bmatrix",
        "/api/%76%31/users",
    ] {
        let once = canonical(raw);
        assert!(
            !once.contains('%'),
            "{raw:?} canonicalized to {once:?}, which still carries an escape"
        );
        let twice = canonical(&once);
        assert_eq!(
            once, twice,
            "canonicalization must be idempotent for {raw:?}"
        );
        // No byte that would need escaping was emitted literally.
        assert!(
            !once.bytes().any(|byte| byte <= 0x20 || byte >= 0x7F),
            "{once:?} must be transmissible as a request target"
        );
    }
}

// ── Structure-preservation: encoded separators are rejected, not folded ─────

#[test]
fn encoded_separators_are_rejected() {
    for path in [
        "/api%2Fadmin",
        "/api%2fadmin",
        "/%2F",
        "/api%3Fquery",
        "/api%23fragment",
    ] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::EncodedSeparator,
            "{path:?}"
        );
    }
}

#[test]
fn encoded_backslash_is_rejected() {
    // Several backend stacks treat `\` as a separator; folding it would change
    // structure and rejecting is the only reading-independent answer.
    assert_eq!(
        rejection("/api%5Cadmin"),
        PolicyPathRejection::EncodedBackslash
    );
    assert_eq!(
        rejection("/api%5cadmin"),
        PolicyPathRejection::EncodedBackslash
    );
}

#[test]
fn double_encoding_is_rejected_at_the_lead_byte() {
    // `%252F` is the historical encoded-slash bypass; `%2561` is the same
    // trick applied to an ordinary character. Both trip on the encoded `%`.
    for path in ["/api%252Fadmin", "/api%252fadmin", "/%2561dmin", "/a%25b"] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::DoubleEncoding,
            "{path:?}"
        );
    }
}

// ── Invalid escapes and non-ASCII byte sequences ───────────────────────────

#[test]
fn incomplete_or_non_hex_escapes_are_rejected() {
    for path in ["/api%", "/api%2", "/api%zz", "/api%2z", "/api%g0/more"] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::InvalidEscape,
            "{path:?}"
        );
    }
}

#[test]
fn escaped_non_ascii_bytes_are_rejected_whether_or_not_they_form_valid_utf8() {
    // Valid UTF-8 (`%C3%A9`) and invalid UTF-8 (`%C3%28`, a lone `%FF`) reach
    // the same verdict: a non-ASCII byte cannot be spelled literally in the
    // forwarded target, so keeping it escaped would leave the gateway
    // evaluating `/caf%C3%A9` while the backend resolves `/café`.
    for path in ["/caf%C3%A9", "/caf%C3%28", "/%FF", "/%C3", "/%E2%82"] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::UnrepresentableEscape,
            "{path:?}"
        );
    }
}

#[test]
fn encoded_control_characters_including_nul_are_rejected() {
    for path in ["/api%00", "/api%00admin", "/api%0A", "/api%0d", "/api%7F"] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::EncodedControl,
            "{path:?}"
        );
    }
}

// ── Dot segments ───────────────────────────────────────────────────────────

#[test]
fn escape_synthesized_dot_segments_are_rejected() {
    for path in [
        "/api/%2e%2e/admin",
        "/api/%2E%2E/admin",
        "/api/.%2e/admin",
        "/api/%2e./admin",
        "/api/%2e/admin",
        "/api/%2E",
    ] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::AmbiguousDotSegment,
            "{path:?}"
        );
    }
}

#[test]
fn literal_dot_segments_are_rejected_too() {
    // A dot segment is not a single policy/backend coordinate: Ferrum forwards
    // through URL parsers (the `url` crate behind reqwest on the H1/H2 and H3
    // cross-protocol dispatch paths) and every RFC 3986 / WHATWG normalizer
    // removes dot segments, so policy would evaluate `/api/../protected` while
    // the forwarded request line resolves `/protected`. Canonicalization does
    // not remove them either — removal is itself a second reading — it refuses
    // the target.
    for path in [
        "/api/../admin",
        "/api/./admin",
        "/..",
        "/.",
        "/api/..",
        "/api/.",
        "/../api",
        "/./api",
        "..",
        ".",
        "/a/b/../../c",
    ] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::LiteralDotSegment,
            "{path:?}"
        );
    }
}

#[test]
fn a_literal_dot_segment_is_rejected_even_alongside_accepted_escapes() {
    // The literal rules are not confined to a "no percent escape" fast path:
    // a target that also carries a decodable escape is held to them too.
    assert_eq!(
        rejection("/api/../%61dmin"),
        PolicyPathRejection::LiteralDotSegment
    );
    assert_eq!(
        rejection("/%61pi/../admin"),
        PolicyPathRejection::LiteralDotSegment
    );
    assert_eq!(
        rejection("/%61pi/.."),
        PolicyPathRejection::LiteralDotSegment
    );
}

// ── Backslash: literal as well as encoded ──────────────────────────────────

#[test]
fn literal_backslash_is_rejected() {
    // The Rust `url` parser treats `\` as a path separator for special HTTP(S)
    // URLs, as do several backend stacks, so a literal `\` is the same
    // route-structure mismatch `%5C` is. Rejecting only the encoded form would
    // leave the literal one on any path that reaches a permissive frontend.
    for path in ["/api\\admin", "/\\", "/a\\..\\b", "\\admin"] {
        assert_eq!(
            rejection(path),
            PolicyPathRejection::LiteralBackslash,
            "{path:?}"
        );
    }
}

#[test]
fn a_literal_backslash_is_rejected_even_alongside_accepted_escapes() {
    assert_eq!(
        rejection("/%61pi\\admin"),
        PolicyPathRejection::LiteralBackslash
    );
    assert_eq!(
        rejection("/api\\%61dmin"),
        PolicyPathRejection::LiteralBackslash
    );
}

#[test]
fn escapes_in_a_segment_that_is_not_a_dot_segment_are_fine() {
    assert_eq!(canonical("/api/%2ehidden"), "/api/.hidden");
    assert_eq!(canonical("/api/%2e%2ehidden"), "/api/..hidden");
    assert_eq!(canonical("/api/a%2e/b"), "/api/a./b");
}

// ── Rejection metadata is fixed, non-echoing text ──────────────────────────

#[test]
fn rejection_reasons_and_bodies_are_stable_and_echo_no_request_bytes() {
    let variants = [
        (PolicyPathRejection::InvalidEscape, "invalid_escape"),
        (PolicyPathRejection::DoubleEncoding, "double_encoding"),
        (PolicyPathRejection::EncodedSeparator, "encoded_separator"),
        (PolicyPathRejection::EncodedBackslash, "encoded_backslash"),
        (PolicyPathRejection::LiteralBackslash, "literal_backslash"),
        (PolicyPathRejection::EncodedControl, "encoded_control"),
        (
            PolicyPathRejection::UnrepresentableEscape,
            "unrepresentable_escape",
        ),
        (
            PolicyPathRejection::AmbiguousDotSegment,
            "ambiguous_dot_segment",
        ),
        (
            PolicyPathRejection::LiteralDotSegment,
            "literal_dot_segment",
        ),
    ];
    for (variant, reason) in variants {
        assert_eq!(variant.reason(), reason);
        let body = variant.client_error_body();
        assert!(body.starts_with(r#"{"error":""#), "{body}");
        assert!(body.ends_with(r#""}"#), "{body}");
        // Parseable JSON with no interpolation seams.
        serde_json::from_str::<serde_json::Value>(body).expect("error body must be JSON");
        assert!(!variant.grpc_message().is_empty());
    }
}

// ── Admission helper shared with config validation ─────────────────────────

#[test]
fn non_canonical_reason_flags_config_values_that_can_never_match() {
    assert_eq!(non_canonical_policy_path_reason("/admin"), None);
    assert_eq!(non_canonical_policy_path_reason("*"), None);
    assert_eq!(non_canonical_policy_path_reason("/v1.0/reports"), None);

    // A configured value carrying a dot segment or a backslash can never match
    // either: no canonical request path contains one.
    assert_eq!(
        non_canonical_policy_path_reason("/api/../admin"),
        Some("literal_dot_segment")
    );
    assert_eq!(
        non_canonical_policy_path_reason("/api\\admin"),
        Some("literal_backslash")
    );

    assert_eq!(
        non_canonical_policy_path_reason("/%61dmin"),
        Some("percent-escapes that canonicalize to a different path")
    );
    assert_eq!(
        non_canonical_policy_path_reason("/api%2Fadmin"),
        Some("encoded_separator")
    );
    assert_eq!(
        non_canonical_policy_path_reason("/api%252Fadmin"),
        Some("double_encoding")
    );
    assert_eq!(
        non_canonical_policy_path_reason("/api%2"),
        Some("invalid_escape")
    );
    // No escape survives canonicalization, so a configured value carrying one
    // is never usable as written — an escape of a character that cannot appear
    // literally in a path is refused by the same rule the request path is.
    assert_eq!(
        non_canonical_policy_path_reason("/api%20name"),
        Some("unrepresentable_escape")
    );
    assert_eq!(
        non_canonical_policy_path_reason("/api%7bname"),
        Some("unrepresentable_escape")
    );
    assert_eq!(
        non_canonical_policy_path_reason("/caf%C3%A9"),
        Some("unrepresentable_escape")
    );
}

#[test]
fn pattern_admission_holds_regex_listen_paths_to_the_escape_rules_only() {
    // A `~regex` listen_path is a pattern, not a literal path. `\` and `.` are
    // regex syntax there, and the pattern is matched against a canonical
    // request path that already cannot contain a backslash or a dot segment —
    // so applying the literal rules would kill working routes without closing
    // anything.
    for pattern in [
        r"~^/v1\.0/.*",
        r"~^/public\.Service/Allowed$",
        "~^/api/v[0-9]+",
        "~(?i:/Api.*)",
        "~.*",
    ] {
        assert_eq!(
            non_canonical_policy_path_pattern_reason(pattern),
            None,
            "{pattern:?} must stay admissible"
        );
    }

    // The escape half of the contract still applies: no canonical request path
    // contains a `%`, and a regex has no metacharacter that changes that, so a
    // pattern carrying one is dead config.
    assert_eq!(
        non_canonical_policy_path_pattern_reason("~/api%2F.*"),
        Some("encoded_separator")
    );
    assert_eq!(
        non_canonical_policy_path_pattern_reason("~/%61dmin"),
        Some("percent-escapes that canonicalize to a different path")
    );
    assert_eq!(
        non_canonical_policy_path_pattern_reason("~/api%2"),
        Some("invalid_escape")
    );
}
