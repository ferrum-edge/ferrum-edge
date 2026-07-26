//! ACME HTTP-01 challenge resolution shares the one canonical policy path
//! (private advisory GHSA-69xf-42xm-4w4f).
//!
//! HTTP-01 is answered at the frontend boundary *before* overload admission and
//! before `handle_proxy_request_inner` canonicalizes the target, so it is the
//! one handler that establishes its own request coordinate. If it resolved the
//! raw target, an encoded-but-legal spelling of a live challenge would miss the
//! ACME handler, canonicalize a moment later, and fall through to ordinary
//! routing and backend handling — a second reading of one request, which is
//! exactly what the canonical-policy-path contract removes.
//!
//! These tests pin the pure half of that resolution:
//!
//!   - a safe escaped spelling resolves to byte-identically the same token as
//!     its canonical literal spelling;
//!   - every target the canonicalizer refuses resolves to no token, so it
//!     reaches the central fixed, non-echoing 400 instead of being normalized
//!     or accepted here;
//!   - a non-ACME target — encoded or not — resolves to no token and keeps
//!     going through the single request boundary.

use ferrum_edge::tls::acme::http01_challenge_token_for_path;

/// The literal, canonical spelling of a challenge coordinate. Every accepted
/// case below must resolve to the same token this one does.
const CANONICAL_TARGET: &str = "/.well-known/acme-challenge/tok_ABC-123";
const CANONICAL_TOKEN: &str = "tok_ABC-123";

fn token_for(path: &str) -> Option<String> {
    http01_challenge_token_for_path(path).map(|token| token.into_owned())
}

#[test]
fn canonical_literal_challenge_path_resolves_its_token() {
    assert_eq!(
        token_for(CANONICAL_TARGET).as_deref(),
        Some(CANONICAL_TOKEN),
        "the literal challenge coordinate must still resolve"
    );
}

/// The headline case: escaped spellings of a live challenge must resolve to the
/// *same* token rather than miss the handler and fall through to routing. `%2E`
/// is `.`, `%5F` is `_`, `%74` is `t`, `%2D` is `-` — all legal literally in a
/// path, so the canonicalizer decodes them instead of refusing them.
#[test]
fn safe_escaped_spellings_resolve_the_same_token_as_the_literal_one() {
    for target in [
        // Escaped prefix byte: the leading `.` of `.well-known`.
        "/%2Ewell-known/acme-challenge/tok_ABC-123",
        // Escaped base64url token byte.
        "/.well-known/acme-challenge/tok%5FABC-123",
        // Escaped first token byte.
        "/.well-known/acme-challenge/%74ok_ABC-123",
        // Escapes in both the prefix and the token, in mixed hex case.
        "/%2ewell-known/acme-challenge/tok%5fABC%2D123",
    ] {
        assert_eq!(
            token_for(target).as_deref(),
            Some(CANONICAL_TOKEN),
            "{target} must resolve exactly like {CANONICAL_TARGET}"
        );
    }
}

/// Everything the canonicalizer refuses must resolve to no token here, so the
/// request continues to the single boundary rejection rather than being decided
/// twice. ACME must never accept a spelling policy would refuse.
#[test]
fn targets_the_canonicalizer_refuses_resolve_to_no_token() {
    for target in [
        // Encoded separator — never folded into a segment boundary.
        "/.well-known/acme-challenge/tok%2FABC",
        "/%2Fwell-known/acme-challenge/tok_ABC-123",
        // Encoded backslash, and the literal backslash the URL parser would
        // read as a separator.
        "/.well-known/acme-challenge/tok%5CABC",
        "/.well-known/acme-challenge/tok\\ABC",
        // Double encoding.
        "/.well-known/acme-challenge/tok%252FABC",
        // Invalid escapes.
        "/.well-known/acme-challenge/tok%zzABC",
        "/.well-known/acme-challenge/tok%2",
        // Escapes the canonical path cannot render literally.
        "/.well-known/acme-challenge/tok%20ABC",
        "/.well-known/acme-challenge/tok%7BABC",
        "/.well-known/acme-challenge/caf%C3%A9",
        // Encoded control characters, including NUL.
        "/.well-known/acme-challenge/tok%00ABC",
        "/.well-known/acme-challenge/tok%09ABC",
        // Dot segments, escape-synthesized and literal.
        "/.well-known/acme-challenge/%2e%2e/tok_ABC-123",
        "/.well-known/acme-challenge/../tok_ABC-123",
        "/.well-known/acme-challenge/./tok_ABC-123",
    ] {
        assert_eq!(
            token_for(target),
            None,
            "{target} must reach the central boundary rejection, not resolve a challenge"
        );
    }
}

/// A challenge coordinate is exactly one segment below the exact prefix. No
/// case folding, prefix guessing, or deeper-path tolerance is introduced here.
#[test]
fn only_one_segment_below_the_exact_prefix_names_the_challenge() {
    for target in [
        // A deeper path is not a token.
        "/.well-known/acme-challenge/tok_ABC-123/extra",
        // Prefix without a token.
        "/.well-known/acme-challenge",
        // The prefix is matched case-sensitively, as ACME publishes it.
        "/.WELL-KNOWN/acme-challenge/tok_ABC-123",
        "/.well-known/ACME-CHALLENGE/tok_ABC-123",
        // Neither a shortened nor a re-rooted prefix matches.
        "/well-known/acme-challenge/tok_ABC-123",
        "/prefix/.well-known/acme-challenge/tok_ABC-123",
    ] {
        assert_ne!(
            token_for(target).as_deref(),
            Some(CANONICAL_TOKEN),
            "{target} does not name the challenge coordinate"
        );
    }
}

/// The bare prefix yields an empty token, which the order store rejects as
/// invalid. Pinned so the empty case stays a store-side rejection instead of
/// quietly becoming a match on some order.
#[test]
fn bare_prefix_yields_an_empty_token_for_the_store_to_reject() {
    assert_eq!(
        token_for("/.well-known/acme-challenge/").as_deref(),
        Some(""),
        "the bare prefix names an empty token, not a challenge"
    );
}

/// A non-ACME target resolves to nothing whether or not it carries escapes, so
/// it keeps going through the ordinary policy/backend coordinate. The
/// escape-free case is also what keeps the GET hot path allocation-free: a
/// target with no `%` is already its own canonical form, so a literal prefix
/// mismatch is a complete answer without decoding anything.
#[test]
fn non_acme_targets_resolve_to_no_token() {
    for target in [
        // Ordinary traffic.
        "/",
        "/api/users",
        // Encoded but acceptable: canonicalized once, at the boundary.
        "/api/%61dmin",
        // Encoded and refused: refused there too, not here.
        "/api/%2fadmin",
        "/api/a\\b",
    ] {
        assert_eq!(
            token_for(target),
            None,
            "{target} is not a challenge coordinate"
        );
    }
}

/// HTTP-01 is served ahead of the operator's URL-length limit, so the lookup
/// bounds its own work: a target longer than the longest raw spelling of a
/// valid challenge (every byte of a maximum-length token escaped) is discarded
/// before the canonicalizer allocates. A long-but-plausible target is still
/// resolved, because rejecting an oversized token is the order store's job.
#[test]
fn absurdly_long_targets_are_discarded_before_canonicalization() {
    let plausible_token = "a".repeat(300);
    let plausible = format!("/.well-known/acme-challenge/{plausible_token}");
    assert_eq!(
        token_for(&plausible).as_deref(),
        Some(plausible_token.as_str()),
        "a long-but-bounded target is still resolved for the store to validate"
    );

    let absurd = format!("/.well-known/acme-challenge/{}", "a".repeat(4096));
    assert_eq!(
        token_for(&absurd),
        None,
        "a target longer than any valid challenge spelling must not be canonicalized"
    );
}
