//! Shared backend-visible request representation gate.
//!
//! One decision, made identically on every path that can finalize a buffered
//! request body (H1/H2, buffered gRPC, native H3, the H3 cross-protocol bridge,
//! and the terminal-preparation ladders), for the question: *may a configured
//! final request-body policy claim to have been enforced over these bytes?*
//!
//! # Why this exists
//!
//! `waf` and `body_validator` decide in `on_final_request_body`, over the exact
//! bytes the backend will receive. That is the right phase, but it is not by
//! itself an inspection guarantee: when the client declared a
//! `Content-Encoding`, those bytes are a compressed representation of the
//! document the policy is configured about. Scanning them finds no signature and
//! parses no schema, and both plugins previously returned `Continue` — while a
//! backend or framework middleware that honors the coding decodes and executes
//! the hidden payload (`GHSA-3973-47g5-4mcx`).
//!
//! The gateway does have a decoder, but it belongs to the optional `compression`
//! plugin and only runs when an operator separately configured it with
//! `decompress_request: true`. An enforcing security policy must not silently
//! depend on that composition, so the plaintext view is established HERE, by the
//! proxy, for every governed request.
//!
//! # Posture
//!
//! There is exactly one posture, and it is fail-closed:
//!
//! * If **no** configured final request-body policy claims this request, nothing
//!   changes. Ordinary encoded uploads keep flowing to backends that understand
//!   them, exactly as before.
//! * If a policy **does** claim it, the representation must be inspectable. The
//!   ordered `#content-coding` list is parsed, each supported coding is
//!   boundedly decoded in reverse application order, and anything that cannot be
//!   reduced to one complete plaintext document — an unsupported coding, a
//!   malformed or truncated stream, Large Window Brotli, too many stacked
//!   layers, an over-limit or over-amplified decode — is **rejected** with a
//!   fixed `400`, never forwarded.
//! * If a policy claims it and the gateway's own aggregate decode budget cannot
//!   admit the working set, the request is refused with the gateway-local
//!   capacity terminal (`503` / gRPC `RESOURCE_EXHAUSTED`) rather than a `400`.
//!   The client did nothing wrong, but forwarding the encoded body would still
//!   be the bypass, so this is a refusal and never a pass-through.
//!
//! # What is and is not rewritten
//!
//! Unlike the response gate, this one never installs the decoded bytes as the
//! forwarded representation. The backend negotiated (or at least accepted) the
//! coding the client sent, and `Content-Encoding` / `Content-Length` /
//! `Content-Digest` describe those exact octets; silently swapping in plaintext
//! would change the backend-visible request in a way no plugin asked for and
//! would break request signing. The plaintext is instead staged on the request
//! context as an INSPECTION view that the claiming policy hooks read through
//! [`crate::plugins::RequestContext::inspectable_final_request_body`].
//!
//! When `compression` IS configured with request decompression, it already
//! rewrote the body and stripped `Content-Encoding` during the pre-`before_proxy`
//! normalization phase, so this gate sees an identity representation and does no
//! work at all. The two are complementary, not redundant.
//!
//! # Bounds
//!
//! Decoding attacker-supplied compressed input is an amplification vector, so
//! every decode is bounded four ways before a single inspection byte exists.
//!
//! Three of them are PER REQUEST:
//!
//! * at most [`MAX_STACKED_REQUEST_CODINGS`] coding layers;
//! * at most [`decoded_inspection_limit`] bytes per layer and in aggregate —
//!   the operator's effective request-body ceiling narrowed by this module's
//!   hard cap, so enabling a security policy can never buy a larger buffer than
//!   the deployment already allows;
//! * at most [`MAX_REQUEST_DECODE_AMPLIFICATION_RATIO`]:1 expansion, per layer
//!   and end-to-end.
//!
//! The fourth is ACROSS CONCURRENT REQUESTS, and it is the one a per-request
//! ceiling cannot express (`GHSA-pwcm-6rh8-f2gh`). The complete working set of a
//! governed decode is charged against a process-wide aggregate budget
//! ([`crate::proxy::response_buffer_budget`], `FERRUM_REQUEST_DECODE_MAX_TOTAL_BYTES`)
//! BEFORE any of it is allocated:
//!
//! * the decoded output buffer's CAPACITY, reserved before each growth and
//!   topped up to whatever the allocator actually returned;
//! * on a stacked `Content-Encoding`, the previous pass's buffer concurrently
//!   with the next pass's output, because both are resident at once;
//! * a conservative ceiling on the ACTIVE decoder's own heap, reserved before
//!   that decoder is CONSTRUCTED — a `br` decoder allocates its ring buffer from
//!   the stream header before it emits a single byte, so a charge taken
//!   afterwards would be a charge taken after the allocation.
//!
//! When the aggregate budget cannot admit that, the answer is the GATEWAY's own
//! transient-capacity terminal ([`FinalRequestBodyPosture::CapacityRefused`]),
//! not a `400`: the client's upload was well formed and the backend is
//! uninvolved.
//!
//! The codec strictness and the charge ordering are not reimplemented here. Both
//! come from [`crate::plugins::charged_decode`], the module the already-reviewed
//! response gate uses, so a `br` request body is decoded by the same
//! Large-Window-refusing [`crate::plugins::charged_decode::StrictBrotliReader`]
//! that bounds a `br` response body. The generic decoder in
//! [`crate::plugins::utils::content_encoding`] now shares that strict codec,
//! but remains deliberately unreachable from this security gate because it
//! does not reserve decoder/output memory against the aggregate decode budget.
//!
//! The coding-list GRAMMAR is still the shared one: [`classify_codings`] mirrors
//! [`crate::plugins::utils::content_encoding::parse_content_codings`] exactly, so
//! one request cannot be inspectable to one plugin and opaque to another.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;

use super::Plugin;
use super::RequestContext;
use super::charged_decode::{ChargedDecodeError, decode_one_coding};
use crate::proxy::response_buffer_budget::{
    BudgetRef, ResponseBufferReservation, charged_bytes, prospective_retained_len,
};

/// Hard ceiling on the plaintext produced for one governed request body.
///
/// Matches [`crate::plugins::response_representation::MAX_DECODED_RESPONSE_INSPECTION_BYTES`]
/// so a deployment's two inspection directions are bounded alike.
pub(crate) const MAX_DECODED_REQUEST_INSPECTION_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of stacked request content codings decoded for one request.
///
/// `Content-Encoding` may list several codings applied in order. Each one is a
/// separate bounded decode pass, so an unbounded list is itself an amplification
/// vector; a legitimate client does not stack more than a couple.
pub(crate) const MAX_STACKED_REQUEST_CODINGS: usize = 4;

/// Maximum decoded-to-raw expansion admitted per layer and end-to-end.
///
/// The same ratio `compression`'s opt-in request decompression enforces, so a
/// zip bomb is refused identically whether or not that plugin is configured.
pub(crate) const MAX_REQUEST_DECODE_AMPLIFICATION_RATIO: u32 = 1024;

/// The effective decode ceiling for this request.
///
/// This module's hard cap, narrowed by any active route request-body ceiling so
/// a governed decode cannot materialize more plaintext than a route-scoped
/// `request_size_limiting` policy would have admitted as a body
/// (`GHSA-xrfj-852f-645j`). `0` is the project-wide "unlimited" spelling and
/// leaves the hard cap in force.
///
/// The global `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` is deliberately not consulted
/// here: it already bounded the ENCODED bytes at collection time, and it is the
/// wire-transfer bound rather than an inspection bound. The hard cap is what
/// bounds amplification, together with
/// [`MAX_REQUEST_DECODE_AMPLIFICATION_RATIO`].
fn decoded_inspection_limit(ctx: &RequestContext) -> usize {
    match ctx.route_request_body_limit() {
        Some(limit) if limit > 0 => limit.min(MAX_DECODED_REQUEST_INSPECTION_BYTES),
        _ => MAX_DECODED_REQUEST_INSPECTION_BYTES,
    }
}

/// Why a governed request representation could not be inspected.
///
/// Every variant means the same thing operationally: the configured final
/// request-body policy could not be applied, so the request must not be
/// forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestRepresentationRejection {
    /// A content coding the gateway cannot decode (`zstd`, `deflate`, a private
    /// coding). Declining to decode is not permission to forward.
    UnsupportedCoding,
    /// The field is not a well-formed `#content-coding` list: an empty member, a
    /// parameterized member, a non-token member, or `identity` combined with a
    /// transforming coding.
    MalformedCoding,
    /// More stacked codings than [`MAX_STACKED_REQUEST_CODINGS`].
    TooManyCodings,
    /// A supported, well-formed coding list whose stream could not be reduced to
    /// plaintext under the bounds: truncated, corrupt, trailing/concatenated
    /// data, over the byte ceiling, or over the amplification ratio.
    UndecodableCoding,
}

impl RequestRepresentationRejection {
    /// Stable, low-cardinality label for logs and transaction metadata.
    ///
    /// Deliberately describes the representation only — it never carries body
    /// bytes, header values, or decoded content.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::UnsupportedCoding => "unsupported_content_coding",
            Self::MalformedCoding => "malformed_content_coding",
            Self::TooManyCodings => "too_many_content_codings",
            Self::UndecodableCoding => "undecodable_content_coding",
        }
    }
}

/// The single shared decision for one finalized request body.
pub(crate) enum FinalRequestBodyPosture {
    /// No configured final request-body policy claims these bytes, or they are
    /// already the plaintext the policy will inspect. Nothing is staged.
    Inspectable,
    /// A policy claims these bytes and the complete ordered coding chain was
    /// decoded. The caller stages this plaintext as the inspection view.
    ///
    /// The [`Bytes`] OWNS the aggregate-budget charge that paid for it, so
    /// staging it is a move rather than a second acquisition and every disposal
    /// path — success, a later hook's rejection, deadline, cancellation, a retry
    /// that re-finalizes, a caller that simply drops the posture — releases it
    /// by drop.
    Decoded(Bytes),
    /// A policy claims these bytes and they cannot be reduced to plaintext.
    /// The caller must reject; forwarding the encoded body is the bypass.
    Reject(RequestRepresentationRejection),
    /// A policy claims these bytes, but the aggregate request-decode budget
    /// could not admit the working set needed to decode them.
    ///
    /// Distinct from [`Self::Reject`] on purpose: nothing is wrong with the
    /// client's upload and no backend was involved, so the caller must install
    /// the GATEWAY-LOCAL transient-capacity terminal
    /// ([`crate::proxy::response_buffer_budget::REQUEST_DECODE_OVERLOAD_STATUS`]
    /// / `RESOURCE_EXHAUSTED`) rather than a `400` that would blame the client
    /// for the gateway's own budget. Forwarding the encoded body is still the
    /// bypass, so this never falls through to the backend.
    CapacityRefused,
}

/// Fixed client-visible message for a rejected governed request representation.
///
/// Fixed-cardinality on purpose: it never echoes the offending coding token, a
/// header value, or any body byte (`GHSA-5p2h-fq6q-gwh9`).
pub(crate) const REQUEST_REPRESENTATION_UNINSPECTABLE_MESSAGE: &str =
    "Malformed or unsupported Content-Encoding";

/// `ctx.metadata` key recording why a governed request representation was
/// refused. The value is one of [`RequestRepresentationRejection::reason`].
pub(crate) const REQUEST_REPRESENTATION_REJECTED_METADATA_KEY: &str =
    "ferrum:request_representation_rejected";

/// Whether any active plugin's configured final request-body policy claims this
/// request's backend-visible bytes.
fn final_request_body_policy_claimed(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> bool {
    plugins
        .iter()
        .any(|plugin| plugin.enforces_final_request_body_policy(ctx, headers, body))
}

/// Whether a `Content-Encoding` field value must be decoded before a governed
/// policy may claim to have inspected the body.
///
/// True for anything that is not a list of pure `identity` tokens — which
/// includes both a real coding (`gzip`) and a MALFORMED one (`,`, `identity,`, a
/// whitespace-only field). The empty-token case is why the test is "not provably
/// identity" rather than "names a transforming coding": an empty token changes
/// no octets, but it is also not provably `identity`, so a governed request
/// carrying one must reach the fail-closed malformed rejection instead of being
/// silently scanned as though the field were absent.
pub(crate) fn requires_decode_judgment(encoding: &str) -> bool {
    !encoding
        .split(',')
        .map(str::trim)
        .all(|token| token.eq_ignore_ascii_case("identity"))
}

/// True when a `Content-Encoding` member is an HTTP `token` (RFC 9110 §5.6.2).
fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Classify the coding list before any decoding work happens.
///
/// The shared decoder reports every failure as one opaque string, and this gate
/// needs a low-cardinality, non-echoing REASON for operators. Classifying the
/// grammar here — rather than pattern-matching the decoder's message — keeps the
/// reason stable across decoder changes and keeps hostile tokens out of it.
///
/// The rules deliberately mirror [`super::utils::content_encoding::parse_content_codings`]
/// exactly, so a list this function admits is a list the decoder will parse.
fn classify_codings(encoding: &str) -> Result<(), RequestRepresentationRejection> {
    let mut count = 0usize;
    let mut has_identity = false;
    let mut has_transforming = false;
    for raw in encoding.split(',') {
        let coding = raw.trim();
        if coding.is_empty() || coding.contains(';') || !is_http_token(coding) {
            return Err(RequestRepresentationRejection::MalformedCoding);
        }
        count += 1;
        match coding.to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" | "br" => has_transforming = true,
            "identity" => has_identity = true,
            _ => return Err(RequestRepresentationRejection::UnsupportedCoding),
        }
    }
    if count == 0 {
        return Err(RequestRepresentationRejection::MalformedCoding);
    }
    if count > MAX_STACKED_REQUEST_CODINGS {
        return Err(RequestRepresentationRejection::TooManyCodings);
    }
    if has_identity && has_transforming {
        return Err(RequestRepresentationRejection::MalformedCoding);
    }
    Ok(())
}

/// Why a charged request decode did not produce a staged plaintext view.
///
/// Split from [`RequestRepresentationRejection`] because the two have different
/// client-visible terminals: a rejection is a statement about the client's
/// REPRESENTATION (`400`, fixed message), while a capacity refusal is a
/// statement about the GATEWAY (`503` / gRPC `RESOURCE_EXHAUSTED`). Collapsing
/// them would tell a client its valid upload was malformed.
enum RequestDecodeFailure {
    Rejected(RequestRepresentationRejection),
    CapacityRefused,
}

impl From<ChargedDecodeError> for RequestDecodeFailure {
    fn from(error: ChargedDecodeError) -> Self {
        match error {
            // The grammar was already classified before any decode ran, so an
            // unsupported token cannot reach the decoder; if it somehow did, the
            // shared gate's answer is the same fail-closed refusal.
            ChargedDecodeError::Unsupported => {
                Self::Rejected(RequestRepresentationRejection::UnsupportedCoding)
            }
            // One reason for every byte-level failure — truncated, corrupt,
            // Large Window Brotli, trailing data, over the ceiling — because the
            // reason string is client- and log-visible and must stay
            // low-cardinality and free of any coding token or body byte.
            ChargedDecodeError::Malformed | ChargedDecodeError::TooLarge => {
                Self::Rejected(RequestRepresentationRejection::UndecodableCoding)
            }
            ChargedDecodeError::CapacityRefused => Self::CapacityRefused,
        }
    }
}

/// Whether `decoded_len` is within `ratio`:1 of `raw_len`.
///
/// Mirrors [`crate::plugins::utils::content_encoding`]'s amplification rule
/// exactly, including its two deliberate exemptions: a zero ratio disables the
/// check, and a zero-length input has no meaningful ratio (the absolute ceiling
/// still applies to both). An overflowing product means the absolute ceiling is
/// the binding bound, so the ratio abstains rather than wrapping into a smaller
/// one.
fn amplification_is_within_bounds(raw_len: usize, decoded_len: usize, ratio: u32) -> bool {
    if ratio == 0 || raw_len == 0 {
        return true;
    }
    match raw_len.checked_mul(ratio as usize) {
        Some(limit) => decoded_len <= limit,
        None => true,
    }
}

/// Decode a governed request's complete ordered coding chain into a charged
/// plaintext view.
///
/// `Content-Encoding` lists codings in the order they were applied, so they are
/// undone in reverse. [`classify_codings`] has already proven the list is a
/// well-formed, supported, non-`identity`-mixed list of at most
/// [`MAX_STACKED_REQUEST_CODINGS`] members, so this function's job is the bounded
/// arithmetic and the budget:
///
/// * `limit` bounds every intermediate pass, not just the final output, so a
///   stacked chain cannot exceed the ceiling partway through;
/// * the SUM of every layer's output is bounded by the same `limit`, which is
///   what the previous generic decoder expressed as `max_cumulative_bytes`;
/// * each layer, and the end-to-end result, is bounded by
///   [`MAX_REQUEST_DECODE_AMPLIFICATION_RATIO`]:1 against its input;
/// * one growing `reservation` covers the PEAK across passes — a reservation
///   only grows, and the previous pass's still-resident buffer is passed as the
///   concurrent charge — and is narrowed to the surviving allocation when the
///   plaintext is published.
///
/// The wire bytes are never copied: the first pass decodes straight out of
/// `body`, whose allocation the request-body collector already bounded.
fn decode_governed_request_body(
    encoding: &str,
    body: &[u8],
    limit: usize,
    budget: BudgetRef<'_>,
) -> Result<Bytes, RequestDecodeFailure> {
    let codings: Vec<String> = encoding
        .split(',')
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| token.as_str() != "identity")
        .collect();
    if codings.is_empty() {
        // `classify_codings` admits an identity-only list only when the caller
        // already decided a decode was owed, and `requires_decode_judgment`
        // excludes that case. Reaching here would mean the two disagreed, so the
        // fail-closed answer is a refusal rather than an unproven pass-through.
        return Err(RequestDecodeFailure::Rejected(
            RequestRepresentationRejection::UndecodableCoding,
        ));
    }

    let mut reservation = ResponseBufferReservation::new();
    let mut current: Option<Vec<u8>> = None;
    let mut cumulative = 0usize;
    for coding in codings.iter().rev() {
        // The previous pass's buffer is this pass's input and stays resident for
        // the whole of it, so it is charged concurrently with this pass's
        // output.
        let (input, concurrent) = match current.as_ref() {
            Some(previous) => (previous.as_slice(), previous.capacity()),
            None => (body, 0),
        };
        let input_len = input.len();
        let decoded =
            decode_one_coding(coding, input, limit, concurrent, &mut reservation, budget)?;
        if !amplification_is_within_bounds(
            input_len,
            decoded.len(),
            MAX_REQUEST_DECODE_AMPLIFICATION_RATIO,
        ) {
            return Err(RequestDecodeFailure::Rejected(
                RequestRepresentationRejection::UndecodableCoding,
            ));
        }
        cumulative = prospective_retained_len(cumulative, decoded.len());
        if cumulative > limit {
            return Err(RequestDecodeFailure::Rejected(
                RequestRepresentationRejection::UndecodableCoding,
            ));
        }
        current = Some(decoded);
    }

    let Some(plaintext) = current else {
        // Unreachable: the list is non-empty and every pass assigns.
        return Err(RequestDecodeFailure::Rejected(
            RequestRepresentationRejection::UndecodableCoding,
        ));
    };
    // End-to-end amplification against the ORIGINAL coded body, which a
    // per-layer check alone does not bound for a stacked chain.
    if !amplification_is_within_bounds(
        body.len(),
        plaintext.len(),
        MAX_REQUEST_DECODE_AMPLIFICATION_RATIO,
    ) {
        return Err(RequestDecodeFailure::Rejected(
            RequestRepresentationRejection::UndecodableCoding,
        ));
    }
    // Fit the peak reservation to the surviving allocation's ACTUAL capacity
    // before it leaves this function. The loop already topped up after every
    // allocation, so this only ever confirms; keeping it a real reservation
    // (which can refuse) rather than an assertion means the invariant fails
    // closed instead of staging bytes the budget does not bound.
    if !reservation.reserve_in(budget, plaintext.capacity()) {
        return Err(RequestDecodeFailure::CapacityRefused);
    }
    // Moves the buffer and the permit into one owner, so the charge lives
    // exactly as long as any handle to the plaintext does. `None` means the held
    // charge does not cover the real capacity, which the top-ups above exclude —
    // but it is checked, because the alternative is staging bytes the budget
    // does not bound.
    charged_bytes(plaintext, reservation).ok_or(RequestDecodeFailure::CapacityRefused)
}

/// Evaluate the shared request representation gate for one finalized body.
///
/// Called from [`crate::proxy::run_final_request_body_hooks_with_provenance`],
/// the single funnel every dispatch ladder uses, so a frontend protocol cannot
/// reach a different conclusion about the same bytes and the same configuration.
///
/// `budget` is the aggregate request-decode budget the decode charges against.
/// Production passes [`BudgetRef::request_decode`]; it is a parameter only so
/// external tests can bind an isolated semaphore rather than mutating the
/// process-global one from a parallel test binary.
pub(crate) fn evaluate_final_request_body_posture(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
    body: &[u8],
    budget: BudgetRef<'_>,
) -> FinalRequestBodyPosture {
    let Some(encoding) = headers
        .get("content-encoding")
        .map(String::as_str)
        .filter(|encoding| requires_decode_judgment(encoding))
    else {
        // The backend-visible representation is already identity-coded, so the
        // bytes the hooks receive ARE the plaintext. No claim question and no
        // decode: this is the ordinary path, including every request whose
        // encoding a configured `compression` instance already normalized away.
        return FinalRequestBodyPosture::Inspectable;
    };

    // Only ask the claim question once a coding is actually present. An
    // unclaimed encoded request keeps its pre-existing behavior — the gateway
    // does not start rejecting ordinary compressed uploads because a security
    // plugin happens to be configured for a different route or media type.
    if !final_request_body_policy_claimed(plugins, ctx, headers, body) {
        return FinalRequestBodyPosture::Inspectable;
    }

    // An empty encoded body carries nothing a policy could match, and a coding
    // header on it is still malformed input rather than a document. Fall through
    // to the decoder, which rejects a zero-length gzip/br stream — the same
    // answer `compression` gives an empty compressed upload.
    if let Err(rejection) = classify_codings(encoding) {
        return FinalRequestBodyPosture::Reject(rejection);
    }

    let limit = decoded_inspection_limit(ctx);
    match decode_governed_request_body(encoding, body, limit, budget) {
        Ok(plaintext) => FinalRequestBodyPosture::Decoded(plaintext),
        // The failure carries no coding token, header value, or body byte — the
        // reason the caller records is one of the four fixed classifications
        // above.
        Err(RequestDecodeFailure::Rejected(rejection)) => {
            FinalRequestBodyPosture::Reject(rejection)
        }
        // Every block the refused decode had already taken is released with the
        // reservation dropped on the way out, so a refusal costs the budget
        // nothing.
        Err(RequestDecodeFailure::CapacityRefused) => FinalRequestBodyPosture::CapacityRefused,
    }
}
