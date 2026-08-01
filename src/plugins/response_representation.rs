//! Shared buffered-response representation gate.
//!
//! One decision, made identically on every path that can publish a buffered
//! response body (H1/H2, native H3, both H3 cross-protocol bridges, the
//! synthetic/replay short-circuit, and provider/protocol normalization), for
//! the question: *may a configured response body policy claim to have been
//! enforced over these bytes?*
//!
//! # Why this exists
//!
//! A body-rewriting policy such as `response_transformer`'s `body_rules` is a
//! security control when it is configured to strip fields from a response. The
//! transform hook is allowed to return `None` for perfectly ordinary reasons
//! ("no configured rule matched this document"), and the lifecycle reads that
//! as "nothing to do, forward the original bytes". That conflation is the
//! bypass this module closes: a representation the transformer *cannot inspect*
//! — a `gzip`/`br`-encoded body, a `206` range slice, a `226` delta, or a byte
//! string that is not a parseable document — also produces `None`, and the
//! protected bytes were forwarded unchanged while the operator believed the
//! policy applied.
//!
//! # Posture
//!
//! There is exactly one posture, and it is fail-closed:
//!
//! * If **no** configured body policy claims this response, nothing changes.
//!   Ordinary unprotected traffic (range requests for media, encoded assets,
//!   non-JSON payloads) is forwarded exactly as before. A protective gate that
//!   turned every `206` into an error would be a worse defect than the bypass.
//! * If a body policy **does** claim this response, the representation must be
//!   inspectable. Supported content codings are decoded in a bounded
//!   pre-transform phase; anything that cannot be reduced to one complete,
//!   parseable document is **rejected**, never forwarded.
//!
//! Two bounds constrain that decode, and both reject rather than proceed:
//!
//! * **The client must accept identity — when identity is what it would get.**
//!   Decoding publishes identity bytes, so a client whose `Accept-Encoding`
//!   forbids the identity coding (`identity;q=0`, or `*;q=0` with no explicit
//!   `identity`) cannot be served the decoded representation. The gateway does
//!   not re-encode, and silently handing that client the identity bytes would
//!   convert an encoded response it *did* accept into one it explicitly refused.
//!   The refusal is applied only once the decoded bytes are known to be the
//!   representation that will actually be served — i.e. after the post-decode
//!   claim holds. A decode whose plaintext WITHDRAWS the claim forwards the
//!   original encoded bytes untouched, so no downgrade occurs and refusing an
//!   encoding the client accepted would be a defect, not a protection. See
//!   [`RepresentationRejection::IdentityCodingUnacceptable`].
//! * **The operator's size limit still applies.** The decode ceiling is the
//!   smaller of this module's hard cap and the configured
//!   `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, so inflating past the operator's
//!   bound is not something enabling a body policy can buy. See
//!   [`decoded_inspection_limit`].
//!
//! A third bound is not about the representation at all, so it does not reject:
//! decoding materializes attacker-amplified bytes that the client then receives
//! and the gateway retains, so the decode is charged against the process-wide
//! retained-response budget ([`crate::proxy::response_buffer_budget`],
//! `GHSA-pwcm-6rh8-f2gh`). A small compressed body can inflate to the decode
//! ceiling, so a per-response ceiling alone would still multiply by concurrency.
//! What is charged, stated exactly:
//!
//! * the output buffer's CAPACITY, reserved before each growth and topped up to
//!   the capacity the allocator actually returned;
//! * on a stacked `Content-Encoding`, the previous pass's buffer concurrently
//!   with the next pass's output, because both are resident at once;
//! * a conservative ceiling on the ACTIVE decoder's own heap
//!   ([`SupportedCoding`]), reserved before that decoder is constructed and
//!   released when its pass ends. This is not small: a `br` ring buffer alone is
//!   bounded by 16 MiB.
//!
//! When the aggregate budget cannot admit any of that, the answer is the
//! GATEWAY's own transient-capacity terminal
//! ([`ResponseBodyPolicyPosture::CapacityRefused`]) rather than a representation
//! error, because the backend did nothing wrong.
//!
//! Rejection — not relabeling — is the answer for partial and delta
//! representations. The gateway does not fetch the remaining ranges or apply
//! the delta, so it cannot produce the complete resource; presenting a rewritten
//! fragment as a `200 OK` complete representation would misrepresent (and let
//! downstream caches store) a truncated resource under the full resource's
//! identity. See [`RepresentationRejection::PartialRepresentation`].
//!
//! # Pristine origin state
//!
//! Encoding and range/delta state are read from the pre-`after_proxy` snapshot
//! stamped by [`crate::proxy::stamp_original_response_metadata`], never from the
//! live header map. By the time buffered body transforms run, `after_proxy`
//! hooks have already mutated the headers: a header-only `response_transformer`
//! rule can remove `Content-Encoding`, and `compression` legitimately *adds* a
//! `Content-Encoding` describing bytes it has not produced yet. Trusting the
//! live map would let the first case hide an encoded body from the gate and the
//! second case send still-plaintext bytes to a decoder. For a backend response
//! the snapshot is mandatory: an unstamped backend response cannot prove its own
//! representation and is rejected rather than assumed benign.
//!
//! # Known limits
//!
//! This gate governs the **buffered** response lifecycle. Three gaps are known
//! and deliberately out of its scope; none is introduced here, and each needs a
//! separate design rather than a widening of this module:
//!
//! * **Streaming responses.** A response that never buffers never reaches a body
//!   transform, so no body policy applies to it. `response_transformer` declines
//!   to buffer when the *client* sent `Accept: text/event-stream`, which means a
//!   client can currently keep a configured body policy from running by asking
//!   for SSE on a route that answers with ordinary JSON. Closing that requires
//!   deciding on the response media type instead of the request's, plus a
//!   streaming-side enforcement point — tracked separately.
//!
//!   The gap is exactly that narrow: it is about a response that never buffers.
//!   Once anything else *does* buffer such a request's response, the claim
//!   predicate covers it like any other, because the transform runs over it like
//!   any other. `response_transformer` therefore does NOT decline SSE in
//!   `enforces_response_body_policy` — only in `should_buffer_response_body`,
//!   which is its buffering vote rather than its policy claim. A response that
//!   genuinely is `text/event-stream` still falls out on media type.
//! * **Framed gRPC.** `application/grpc+json` and the gRPC-Web `+json` variants
//!   end in `+json`, but carry length-prefixed frames rather than a bare
//!   document, so no JSON field rule can act on them. `response_transformer`
//!   declines that whole media-type family in both its claim predicate and its
//!   transform, which keeps a mixed HTTP/gRPC proxy's valid gRPC responses out
//!   of this gate entirely instead of failing them as unparseable. That decline
//!   is made on pre-`after_proxy` evidence, not only on the live response
//!   `Content-Type`: the pristine stamped media type answers first. So a header
//!   rule that strips or relabels that header cannot push a framed response onto
//!   the untyped-JSON branch and have its frames rejected as an unparseable
//!   document. Redacting inside gRPC frames would need a frame-aware body
//!   policy.
//!
//!   When NOTHING named a type — no snapshot and no live header — the request's
//!   gRPC flavor is a necessary but not sufficient condition, and the response
//!   BYTES decide. The flavor alone was a fail-open: a mixed gRPC route whose
//!   backend answers a bare JSON error/envelope document with no `Content-Type`
//!   would have been declined, skipping a configured redaction over exactly the
//!   untyped-JSON class this gate otherwise covers. The discriminator is a total
//!   parse against the ONE grammar the client's own representation admits —
//!   DATA frames for native gRPC, DATA plus an optional final trailer frame for
//!   gRPC-Web binary, and the base64 of that for gRPC-Web text — never a prefix
//!   sniff and never the union of all three, and it cannot collide with JSON in
//!   either direction. Framing that is legal in some other mode is not framing
//!   here: it stays claimed and fails closed.
//!
//!   Because a decode changes which bytes that parse must run over, the claim is
//!   asked twice: once over the wire bytes to decide whether a decode is owed,
//!   and again over the decoded identity bytes, which is the binding answer and
//!   the exact representation the enforcer receives.
//!
//!   The LIVE `Content-Type` cannot settle this either way on its own, because
//!   the main gRPC path relabels it: `grpc_web`'s `after_proxy` stamps
//!   `application/grpc-web*` on every translated response before this gate runs.
//!   [`effective_response_media_type`] therefore honors a framed gRPC label only
//!   when the pristine snapshot or a total frame parse proves framing; otherwise
//!   the label resolves to the untyped branch, so an untyped backend's malformed
//!   frames or bare JSON document cannot be waved through as framing.
//!
//!   On a TRANSLATED gRPC-Web route the re-encoder runs AFTER the enforcer, so a
//!   claimed backend body that is not already native framing cannot be enforced
//!   at all and is rejected rather than published rewrapped — see
//!   [`RepresentationRejection::UnenforceableFraming`].
//! * **Backend-chosen media type.** A backend that *mislabels* a JSON payload
//!   `text/plain` or `application/octet-stream` is not claimed by a JSON body
//!   policy, here or in the transform itself. Content-type sniffing or an
//!   operator-configured media-type allowlist would be needed. An **absent**
//!   `Content-Type` is not part of this gap: the transform treats it as JSON, so
//!   the claim predicate does too and the gate inspects it (see
//!   [`crate::plugins::response_transformer`]).
//! * **Trailing bytes after a gzip member.** Decoding uses `MultiGzDecoder`, for
//!   consistency with the bounded decoders in `ai_tool_governor` and
//!   `ai_semantic_firewall`. It is stricter than browsers about padding after the
//!   final member, so such a body is rejected rather than decoded. Trailing bytes
//!   after a complete `br` stream are rejected for the same reason.
//! * **Large Window Brotli.** `br` decoding refuses the LWB window extension
//!   (see [`StrictBrotliReader`]). RFC 7932 caps the `br` window at 24 bits, so
//!   a client that advertised `br` has not agreed to a window — or a decoder
//!   allocation — beyond that. An LWB stream is treated as a malformed coding.

use bytes::Bytes;
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use super::Plugin;
use super::RequestContext;
use super::utils::body_transform::{is_framed_grpc_content_type, is_json_content_type};
use crate::proxy::response_buffer_budget::{
    BudgetRef, ResponseBufferReservation, charged_bytes, prospective_retained_len,
};

/// Hard ceiling on the decoded size of one buffered response body inspected on
/// behalf of a configured body policy.
///
/// Bounds decompression amplification: a few kilobytes of `gzip` or `br` can
/// expand to gigabytes, so the decoder is capped and a body that exceeds the
/// cap is rejected rather than materialized. Matches the ceiling
/// `ai_semantic_firewall` already applies to response inspection so a single
/// response cannot be inspectable to one guardrail and uninspectable to another.
///
/// This is a ceiling, not *the* limit: [`decoded_inspection_limit`] narrows it
/// to the operator's configured response-body bound whenever that is smaller.
pub(crate) const MAX_DECODED_RESPONSE_INSPECTION_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of stacked content codings decoded for one response.
///
/// `Content-Encoding` may list several codings applied in order. Each one is a
/// separate bounded decode pass, so an unbounded list is itself an amplification
/// vector; a legitimate origin does not stack more than a couple.
pub(crate) const MAX_STACKED_RESPONSE_CODINGS: usize = 4;

/// The effective decode ceiling for this request.
///
/// A decode installs identity bytes that the client actually receives, so it
/// must respect the operator's `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` exactly as
/// the streaming and buffered wire paths do. Without this, a deployment that
/// caps responses below the hard ceiling could be handed a small compressed
/// JSON body that passes every wire-size check, inflate it here up to
/// [`MAX_DECODED_RESPONSE_INSPECTION_BYTES`], and forward the larger identity
/// representation with a `Content-Length` above the configured bound — the
/// operator's memory and size limit silently relaxed by the very feature that
/// was supposed to tighten inspection.
///
/// `0` is the project-wide "unlimited" spelling for the configured limit, and
/// the hard ceiling still applies to it; otherwise the smaller of the two wins.
///
/// The configured value is the *effective* ceiling — the global limit narrowed
/// by any active route response ceiling — so a decode cannot inflate past the
/// bound a route-scoped `response_size_limiting` instance enforces, including
/// when the global limit is the unlimited `0` (`GHSA-xrfj-852f-645j`).
fn decoded_inspection_limit(ctx: &RequestContext) -> usize {
    match ctx.effective_max_response_body_size_bytes() {
        0 => MAX_DECODED_RESPONSE_INSPECTION_BYTES,
        configured => configured.min(MAX_DECODED_RESPONSE_INSPECTION_BYTES),
    }
}

/// Where the buffered bytes under inspection came from.
///
/// This is passed explicitly by each call site rather than sniffed from context
/// metadata so that adding a new publication path is a compile-time decision
/// about which provenance rules apply, not a silent default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepresentationOrigin {
    /// A real backend response. The pre-`after_proxy` snapshot is authoritative
    /// and its absence is itself a failure to prove the representation.
    Backend,
    /// Bytes the gateway itself produced (plugin short-circuit, mock, semantic
    /// cache hit, serverless terminate, dedup replay). There is no upstream
    /// representation to hide, so live headers are the only description of these
    /// bytes and are read directly.
    GatewayGenerated,
}

/// Why a protected representation could not be inspected.
///
/// Every variant means the same thing operationally: the configured body policy
/// could not be applied, so the response must not be served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepresentationRejection {
    /// A content coding the gateway cannot decode (`zstd`, `deflate`, a private
    /// coding). Declining to decode is not permission to forward.
    UnsupportedCoding,
    /// A supported coding whose stream is malformed or truncated.
    MalformedCoding,
    /// Decoded output exceeded [`MAX_DECODED_RESPONSE_INSPECTION_BYTES`], or the
    /// coding list exceeded [`MAX_STACKED_RESPONSE_CODINGS`].
    DecodedBodyTooLarge,
    /// A `206` range slice or `226` delta: only a fragment of the resource. The
    /// gateway cannot reconstruct the complete representation, and must not
    /// present the fragment as one.
    PartialRepresentation,
    /// The bytes are not a complete parseable document of the media type the
    /// policy operates on, so no field-level rule can be proven to have applied.
    UnparseableDocument,
    /// A backend response reached the body phase without a pre-`after_proxy`
    /// snapshot, so its original encoding and range state cannot be proven.
    UnprovenOriginState,
    /// Inspecting the body requires decoding it to identity, but the client's
    /// `Accept-Encoding` forbids the identity coding. The gateway will not
    /// serve a representation the client explicitly refused, and it does not
    /// re-encode, so neither the encoded nor the decoded bytes are servable.
    IdentityCodingUnacceptable,
    /// A translated gRPC-Web backend response whose bytes are not native gRPC
    /// framing. The gRPC-Web re-encoder rewraps the body AFTER the body-policy
    /// enforcer runs, so the policy provably cannot apply to what the client
    /// receives, and admitting it would publish the document unredacted.
    UnenforceableFraming,
}

impl RepresentationRejection {
    /// Stable, low-cardinality label for logs and transaction metadata.
    ///
    /// Deliberately describes the representation only — it never carries body
    /// bytes, header values, or decoded content.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::UnsupportedCoding => "unsupported_content_coding",
            Self::MalformedCoding => "malformed_content_coding",
            Self::DecodedBodyTooLarge => "decoded_body_too_large",
            Self::PartialRepresentation => "partial_representation",
            Self::UnparseableDocument => "unparseable_document",
            Self::UnprovenOriginState => "unproven_origin_state",
            Self::IdentityCodingUnacceptable => "identity_coding_unacceptable",
            Self::UnenforceableFraming => "unenforceable_grpc_web_framing",
        }
    }
}

/// The single shared decision for one buffered response.
pub(crate) enum ResponseBodyPolicyPosture {
    /// No configured body policy claims these bytes. The lifecycle keeps its
    /// pre-existing behavior, including leaving `206`/`226` bodies untouched.
    Unprotected,
    /// A body policy claims these bytes and they are inspectable. When
    /// `decoded` is `Some`, the caller must install those identity-coded bytes
    /// (and drop the stale `Content-Encoding`) before running transforms, so
    /// every transform sees the representation the policy was evaluated against.
    /// Those bytes already carry their own aggregate-budget charge; installing
    /// them is what transfers it to the client-visible body.
    Enforce { decoded: Option<ChargedDecodedBody> },
    /// A body policy claims these bytes and they are not inspectable. The caller
    /// must replace the response; forwarding the original bytes is the bypass.
    Reject(RepresentationRejection),
    /// A body policy claims these bytes, but the aggregate retained-response
    /// budget could not admit the decode that would make them inspectable.
    ///
    /// Distinct from [`Self::Reject`] on purpose: nothing is wrong with the
    /// backend or its representation, so the caller must install the
    /// GATEWAY-LOCAL transient-capacity terminal
    /// ([`crate::proxy::response_buffer_budget::RESPONSE_BUFFER_OVERLOAD_STATUS`]
    /// / `RESOURCE_EXHAUSTED`), which is non-retryable and neutral to circuit
    /// breaker, passive health, and adaptive concurrency — never a backend
    /// `502`.
    CapacityRefused,
}

/// Whether any active plugin's configured body policy claims this response.
///
/// `body` is the byte string a claim predicate may need to decide structurally
/// (see [`Plugin::enforces_response_body_policy`]). It is asked TWICE for one
/// response: once over the wire bytes, to decide whether a decode is owed, and
/// again over the decoded identity bytes, which are what the enforcer is handed.
/// Only the second answer is binding — see
/// [`evaluate_response_body_policy_posture`].
fn body_policy_claimed(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    content_type: Option<&str>,
    body: &[u8],
) -> bool {
    plugins
        .iter()
        .any(|plugin| plugin.enforces_response_body_policy(ctx, content_type, body))
}

/// Whether a `Content-Encoding` field value must be handed to
/// [`decode_response_body`] for judgment rather than treated as absent.
///
/// True for anything that is not a list of pure `identity` tokens — which
/// includes both a real coding (`gzip`) and a MALFORMED one (`,`, `identity,`,
/// a whitespace-only field). The empty-token case is why the test is "not
/// provably identity" rather than "names a transforming coding": an empty token
/// changes no octets, but it is also not provably `identity`, so a protected
/// response carrying one must reach the fail-closed malformed-coding rejection
/// instead of being silently inspected as though the field were absent.
pub(crate) fn content_encoding_requires_decode_judgment(encoding: &str) -> bool {
    !encoding
        .split(',')
        .map(str::trim)
        .all(|token| token.eq_ignore_ascii_case("identity"))
}

/// Whether a `q=` parameter value is a syntactically valid weight of exactly
/// zero, i.e. an explicit refusal.
///
/// RFC 9110 §12.4.2 defines the grammar exactly:
///
/// ```text
/// qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
/// ```
///
/// This validates that SHAPE rather than parsing a float, because the two are
/// not the same language. `f32::parse` accepts a strictly larger set —
/// `0e0`, `.0`, `0.0000`, `0_`-free scientific and arbitrary-precision decimal
/// forms all parse to floating-point zero while none of them is a `qvalue`. A
/// float-based test therefore reads a syntactically invalid parameter as an
/// explicit refusal, and this predicate's ONLY power is to turn an
/// otherwise-servable response into a `502`. Rejecting live traffic because a
/// client or intermediary emitted an unparseable weight protects nothing, so
/// malformed must stay on the acceptable side — the grammar check is what keeps
/// it there.
///
/// Whether the client will accept identity-coded (uncompressed) bytes.
///
/// RFC 9110 §12.5.3: an absent `Accept-Encoding` places no constraint, an empty
/// field value means only `identity` is acceptable, and identity becomes
/// unacceptable only through an explicit `identity;q=0` or a `*;q=0` with no
/// explicit non-zero `identity`. Parsing — including first-`identity` /
/// last-`*` duplicate handling and malformed-q fail-safe — is shared with
/// compression negotiation via
/// [`crate::plugins::compression::identity_coding_quality`].
///
/// A malformed qvalue is read as acceptable rather than forbidden. This
/// predicate can only ever turn an otherwise-servable response into an error,
/// so inferring "the client refuses identity" from a field the gateway could not
/// validate would break live traffic to protect nothing. Only a value matching
/// the RFC 9110 §12.4.2 `qvalue` grammar can express a refusal, and the refusal
/// is `q=0`. A negative, out-of-range, or non-finite parameter
/// (`identity;q=-1`, `*;q=-1`, `q=5`, `q=inf`) is malformed, and so is anything
/// that is merely *float-parseable* as zero without matching the grammar
/// (`q=0e0`, `q=.0`, `q=0.0000`). None of those is a zero weight, and none may
/// be read as one.
fn identity_coding_is_acceptable(ctx: &RequestContext) -> bool {
    // Read the pristine pre-hook snapshot first. Neither later source can be
    // trusted on its own: `request_transformer` (priority 3000) can remove or
    // rewrite `Accept-Encoding` before `compression` (priority 4050) records its
    // own copy, and `compression`'s `remove_accept_encoding` then deletes the
    // header from the `before_proxy` map, which IS `ctx.headers` (taken and
    // restored around the hook). Both later sources remain as fallbacks for
    // direct plugin callers that never ran the proxy's request-init stamp.
    let Some(accept_encoding) = ctx
        .original_accept_encoding()
        .or_else(|| {
            ctx.metadata
                .get(crate::plugins::compression::REQUEST_ACCEPT_ENCODING_METADATA_KEY)
                .map(String::as_str)
        })
        .or_else(|| ctx.headers.get("accept-encoding").map(String::as_str))
    else {
        return true;
    };

    crate::plugins::compression::identity_coding_quality(accept_encoding) > 0.0
}

/// The origin's non-identity `Content-Encoding`, from the pristine snapshot for
/// a backend response and from the live map for gateway-generated bytes.
fn origin_content_encoding<'a>(
    ctx: &'a RequestContext,
    origin: RepresentationOrigin,
    response_headers: &'a HashMap<String, String>,
) -> Option<&'a str> {
    match origin {
        RepresentationOrigin::Backend => ctx
            .metadata
            .get(crate::proxy::ORIGIN_ENCODED_RESPONSE_METADATA_KEY)
            .map(String::as_str),
        // Pass a PRESENT field through whichever codings it names. Filtering out
        // anything but a real transforming coding here would drop a malformed
        // list whose only members are empty (`,` or `identity,`) before
        // `decode_response_body` could reject it, and the body would then be
        // transformed or forwarded under representation metadata the gateway
        // never proved — the opposite of the fail-closed posture. It is the
        // one place
        // that judges a coding list: it returns `Ok(None)` for an identity-only
        // field (no octets change, nothing to decode) and `MalformedCoding` for
        // an empty token, so `identity` alone still costs nothing here.
        RepresentationOrigin::GatewayGenerated => response_headers
            .get("content-encoding")
            .map(String::as_str)
            .filter(|encoding| content_encoding_requires_decode_judgment(encoding)),
    }
}

/// Whether these bytes are a range slice or a delta rather than a complete
/// representation.
///
/// One rule, two evidence sources. The semantics live in
/// [`crate::proxy::original_response_is_fragment`] and are identical for both
/// provenances — in particular a complete non-2xx status document (a `416`
/// reporting the selected representation's length, a `429`/`503` echoing stale
/// provider metadata) is *not* a fragment and stays fully inspectable. What
/// differs is only which status and headers that rule is applied to:
///
/// * A **backend** response has a pristine pre-`after_proxy` snapshot, so the
///   rule was already evaluated against the original status and headers and
///   stamped as [`crate::proxy::ORIGIN_FRAGMENT_RESPONSE_METADATA_KEY`]. Reading
///   the stamp — not the live map — is what closes the
///   fragment-relabelled-as-`200` bypass.
/// * **Gateway-generated** bytes have no snapshot, so the rule is applied to the
///   live headers, which are the only description of them that exists.
///
/// The live `206`/`226` status test runs first regardless, so a response that
/// still identifies itself as a fragment is rejected on every path even if a
/// snapshot was never taken.
fn is_partial_representation(
    ctx: &RequestContext,
    origin: RepresentationOrigin,
    response_status: u16,
    response_headers: &HashMap<String, String>,
) -> bool {
    if matches!(response_status, 206 | 226) {
        return true;
    }
    match origin {
        RepresentationOrigin::Backend => ctx
            .metadata
            .contains_key(crate::proxy::ORIGIN_FRAGMENT_RESPONSE_METADATA_KEY),
        RepresentationOrigin::GatewayGenerated => {
            crate::proxy::original_response_is_fragment(response_status, response_headers)
        }
    }
}

/// Read granularity of a bounded decode, and the size of the fixed stack
/// scratch buffer one decode pass uses.
///
/// Small enough that the aggregate charge tracks the output allocation closely,
/// large enough that the per-chunk semaphore check is never the dominant cost of
/// a decode. This buffer lives on the stack, so it is not part of the process
/// heap the aggregate budget bounds; the decoder's own HEAP working set is a
/// separate, much larger cost and is charged — see [`SupportedCoding`].
const DECODE_CHUNK_BYTES: usize = 16 * 1024;

/// The growth target for a decode output buffer that currently holds
/// `current_capacity` bytes of capacity and is about to hold `filled` bytes,
/// under `limit`.
///
/// Factored out so the reservation, the allocation, and the external
/// test-support projection of a decode's peak
/// ([`projected_decode_output_capacity`]) cannot disagree about the growth rule.
/// Geometric, so a large body costs `O(log n)` reallocations rather than one per
/// chunk, and saturating so no hostile length can wrap the target down.
#[inline]
fn grown_decode_capacity(current_capacity: usize, filled: usize, limit: usize) -> usize {
    current_capacity
        .saturating_mul(2)
        .max(DECODE_CHUNK_BYTES)
        .min(limit)
        .max(filled)
}

/// The capacity [`read_decoded_bounded`] ends up holding for an output of
/// `decoded_len` bytes under `limit`, computed with the production growth rule.
///
/// External tests use this to derive a decode's exact budget bracket from the
/// actual encoded/intermediate lengths instead of hardcoding block counts, so a
/// change to the growth rule or to a codec's output size fails with a precise
/// arithmetic explanation rather than looking like a flaky budget assertion.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) fn projected_decode_output_capacity(decoded_len: usize, limit: usize) -> usize {
    let mut capacity = 0usize;
    let mut filled = 0usize;
    while filled < decoded_len {
        filled = prospective_retained_len(filled, DECODE_CHUNK_BYTES).min(decoded_len);
        if filled > capacity {
            capacity = grown_decode_capacity(capacity, filled, limit);
        }
    }
    capacity
}

/// A content coding this gate can decode, and the heap its decoder needs.
///
/// # Why the codec's own heap is charged
///
/// The output buffer is not the whole resident cost of a decode. Both supported
/// decoders allocate a working set on the FIRST read — before a single output
/// byte exists, so before any output-growth reservation can have happened — and
/// that working set is chosen by the attacker-supplied stream header, not by the
/// gateway. Leaving it out would mean the aggregate budget bounds something
/// strictly smaller than what concurrent decodes actually hold
/// (`GHSA-pwcm-6rh8-f2gh`). So the ceilings below are reserved BEFORE the
/// decoder is constructed, and a decode that cannot reserve them is refused.
///
/// They are conservative fixed ceilings rather than a budget-aware allocator:
/// both codecs' allocations are bounded by format constants, so a ceiling is
/// provable by inspection and costs nothing on the decode path. They are
/// deliberately over-estimates for a typical stream — a real `br` response uses
/// a 4 MiB window, not the 16 MiB maximum — which is the safe direction.
#[derive(Clone, Copy)]
enum SupportedCoding {
    Gzip,
    Brotli,
}

/// Conservative ceiling on the heap ONE `gzip`/`x-gzip` pass allocates, for the
/// locked `flate2` 1.1.9 (`rust_backend`) → `miniz_oxide` 0.8.9 path.
///
/// Derivation, from the locked sources:
///
/// * `flate2::read::MultiGzDecoder::new` wraps the input in
///   `std::io::BufReader::new` — one 8 KiB buffer (`flate2` `src/gz/read.rs`);
/// * `flate2`'s `Decompress` holds a boxed `miniz_oxide` `InflateState`
///   (`flate2` `src/ffi/miniz_oxide.rs`). `InflateState` is
///   dominated by `dict: [u8; TINFL_LZ_DICT_SIZE]` = 32 KiB plus a
///   `DecompressorOxide` whose three `HuffmanTable`s are
///   `[i16; 1024] + [i16; 576]` = 3,200 B each (`miniz_oxide`
///   `src/inflate/core.rs`), i.e. well under 16 KiB of tables and scalars.
///
/// That is on the order of 56 KiB. DEFLATE's window is fixed at 32 KiB by
/// RFC 1951, so nothing in the stream can enlarge it. `256 KiB` is a ~4.5x
/// margin for allocator overhead and for a future `miniz_oxide` that grows its
/// state, and is still small enough that gzip decodes are not rationed.
pub(crate) const GZIP_DECODER_SCRATCH_BYTES: usize = 256 * 1024;

/// Conservative ceiling on the heap ONE `br` pass allocates, for the locked
/// `brotli` 8.0.2 → `brotli-decompressor` 5.0.0 path under
/// [`StrictBrotliReader`] (`BrotliState::new_strict`, `StandardAlloc`).
///
/// Derivation, from `brotli-decompressor` `src/decode.rs`, `src/state.rs`, and
/// `src/huffman/mod.rs`, with `HuffmanCode` = `#[repr(C)] { u16, u8 }` = 4 B:
///
/// | allocation | bound | bytes |
/// | --- | --- | --- |
/// | ring buffer | `(1 << window_bits) + 42 + 24`, `window_bits <= 24` | 16,777,282 |
/// | three Huffman tree groups | `256 * (4 + 1080 * 4)` each | 3,320,832 |
/// | block-type + block-length trees | `2 * 3 * 1080 * 4` | 25,920 |
/// | context-map table | `1080 * 4` | 4,320 |
/// | literal + distance context maps | `(256 << 6) + (256 << 2)` | 17,408 |
/// | context modes | `256` | 256 |
/// | **total** | | **20,146,018** |
///
/// Every count is a format bound, not an observation: `num_block_types` and
/// `num_htrees` are `DecodeVarLenUint8() + 1`, and that decoder yields at most
/// `(1 << 7) + 127 = 255`, so 256 is the ceiling for all of them.
///
/// **Why `window_bits <= 24`.** `DecodeWindowBits` only reaches the Large Window
/// Brotli branch — 6 further bits, `window_bits` up to `kBrotliLargeMaxWbits`
/// = 30, i.e. a **1 GiB** ring buffer — when the state was created with
/// `large_window = true`. The crate's own `brotli::Decompressor` does exactly
/// that (`BrotliState::new_with_custom_dictionary` sets `large_window = true`),
/// which is why this module does not use it: LWB is not `Content-Encoding: br`
/// (RFC 7932 caps the window at 24 bits and a client advertising `br` has not
/// agreed to anything larger), so admitting it would be an unbounded allocation
/// for a coding nobody negotiated. [`StrictBrotliReader`] uses
/// `BrotliState::new_strict`, which pins `large_window = false`, so the LWB
/// branch is a format error and the ring buffer is capped at `1 << 24`.
///
/// `24 MiB` rounds 20,146,018 B up with ~4 MiB of margin for allocator overhead
/// across the ~10 allocations above.
pub(crate) const BROTLI_DECODER_SCRATCH_BYTES: usize = 24 * 1024 * 1024;

impl SupportedCoding {
    fn from_token(coding: &str) -> Option<Self> {
        match coding {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "br" => Some(Self::Brotli),
            _ => None,
        }
    }

    /// The decoder heap this coding may allocate for one pass.
    fn scratch_bytes(self) -> usize {
        match self {
            Self::Gzip => GZIP_DECODER_SCRATCH_BYTES,
            Self::Brotli => BROTLI_DECODER_SCRATCH_BYTES,
        }
    }
}

/// Why a decode did not produce inspectable identity bytes.
///
/// Split from [`RepresentationRejection`] because the two failures have
/// different client-visible terminals: a rejection is a statement about the
/// REPRESENTATION (the policy cannot be enforced over these bytes, `502` /
/// gRPC `INTERNAL`), while a capacity refusal is a statement about the GATEWAY
/// (transient local memory, `503` / gRPC `RESOURCE_EXHAUSTED`, health-neutral
/// and non-retryable). Collapsing them would blame a correct backend for the
/// gateway's own budget.
enum DecodeFailure {
    Rejected(RepresentationRejection),
    CapacityRefused,
}

/// A `br` reader that refuses Large Window Brotli, so its ring buffer is bounded
/// by `1 << 24` and [`BROTLI_DECODER_SCRATCH_BYTES`] is a real ceiling.
///
/// `brotli::Decompressor` cannot be used for this: it builds its state through
/// `BrotliState::new_with_custom_dictionary`, which sets `large_window = true`,
/// so a handful of header bits can ask it for a 1 GiB ring buffer. This drives
/// the same `BrotliDecompressStream` state machine with `BrotliState::new_strict`
/// instead, which pins `large_window = false` and makes that header a format
/// error.
///
/// Feeding the whole encoded body in at once (it is already resident and
/// collector-charged) also removes the decoder's own input buffer and makes the
/// failure classification exact: with no more input to come, `NeedsMoreInput`
/// can only mean a truncated stream.
struct StrictBrotliReader<'a> {
    input: &'a [u8],
    input_offset: usize,
    total_out: usize,
    state: brotli::BrotliState<
        brotli::reader::StandardAlloc,
        brotli::reader::StandardAlloc,
        brotli::reader::StandardAlloc,
    >,
    done: bool,
}

impl<'a> StrictBrotliReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            input_offset: 0,
            total_out: 0,
            state: brotli::BrotliState::new_strict(
                brotli::reader::StandardAlloc::default(),
                brotli::reader::StandardAlloc::default(),
                brotli::reader::StandardAlloc::default(),
            ),
            done: false,
        }
    }

    /// The one error this reader reports. The caller maps every read failure to
    /// [`RepresentationRejection::MalformedCoding`], so the kind carries no
    /// response content and nothing is logged from here.
    fn malformed() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid brotli stream")
    }
}

impl Read for StrictBrotliReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        let mut available_in = match self.input.len().checked_sub(self.input_offset) {
            Some(len) => len,
            None => return Err(Self::malformed()),
        };
        let mut available_out = buf.len();
        let mut output_offset = 0usize;
        match brotli::BrotliDecompressStream(
            &mut available_in,
            &mut self.input_offset,
            self.input,
            &mut available_out,
            &mut output_offset,
            buf,
            &mut self.total_out,
            &mut self.state,
        ) {
            brotli::BrotliResult::ResultSuccess => {
                self.done = true;
                // Trailing bytes after a complete stream are not a `br`
                // representation, and this gate decides what the client
                // receives, so they are rejected rather than ignored — the same
                // strictness the gzip path already applies to padding after the
                // final member.
                if available_in != 0 {
                    return Err(Self::malformed());
                }
                Ok(output_offset)
            }
            brotli::BrotliResult::NeedsMoreOutput => {
                if output_offset == 0 {
                    // The decoder asked for room it was already given, so it
                    // cannot make progress; refusing beats looping.
                    return Err(Self::malformed());
                }
                Ok(output_offset)
            }
            // The whole body was handed over up front, so there is no more
            // input: the stream is truncated.
            brotli::BrotliResult::NeedsMoreInput | brotli::BrotliResult::ResultFailure => {
                Err(Self::malformed())
            }
        }
    }
}

/// Read a bounded decoder's output, charging the aggregate retained-response
/// budget BEFORE every growth of the output allocation.
///
/// `concurrent_bytes` is what the caller is holding resident alongside this
/// output for the duration of the pass — the previous pass's decoded buffer on a
/// stacked `Content-Encoding`, and zero on the first pass, which reads straight
/// from the collector-charged wire bytes. Charging `concurrent_bytes + capacity`
/// is what keeps a stacked decode from escaping the aggregate bound in the
/// window where both allocations exist. The active decoder's own heap is charged
/// separately by the caller, so the semaphore sees scratch + input + output at
/// once and a large output cannot hide behind an earlier scratch charge.
///
/// The charge is against the buffer's CAPACITY rather than its length, because
/// capacity is what is resident — and against the capacity the allocator
/// actually returned, not merely the one that was requested: `Vec` promises at
/// least what was asked for, so the reservation is topped up immediately after
/// each allocation and the buffer is dropped if that top-up is refused.
fn read_decoded_bounded(
    mut reader: impl Read,
    limit: usize,
    concurrent_bytes: usize,
    reservation: &mut ResponseBufferReservation,
    budget: BudgetRef<'_>,
) -> Result<Vec<u8>, DecodeFailure> {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; DECODE_CHUNK_BYTES];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|_| DecodeFailure::Rejected(RepresentationRejection::MalformedCoding))?;
        if read == 0 {
            break;
        }
        let filled = prospective_retained_len(out.len(), read);
        if filled > limit {
            return Err(DecodeFailure::Rejected(
                RepresentationRejection::DecodedBodyTooLarge,
            ));
        }
        if filled > out.capacity() {
            let grown = grown_decode_capacity(out.capacity(), filled, limit);
            if !reservation.reserve_in(budget, prospective_retained_len(concurrent_bytes, grown)) {
                return Err(DecodeFailure::CapacityRefused);
            }
            out.reserve_exact(grown - out.len());
            // `reserve_exact` guarantees AT LEAST `grown`, so the allocation
            // that just happened may be larger than what was reserved for it.
            // Charge the difference now; returning here drops `out`, so a
            // refusal frees the over-large buffer instead of publishing it.
            let allocated = prospective_retained_len(concurrent_bytes, out.capacity());
            if !reservation.reserve_in(budget, allocated) {
                return Err(DecodeFailure::CapacityRefused);
            }
        }
        out.extend_from_slice(&chunk[..read]);
    }
    Ok(out)
}

/// Decode one supported content coding, bounded by `limit` and by the aggregate
/// retained-response budget.
///
/// The reader is capped one byte past the limit so an output that lands exactly
/// on the ceiling is distinguishable from one that was truncated by it.
///
/// The decoder's own heap working set ([`SupportedCoding::scratch_bytes`]) is
/// reserved BEFORE the decoder is constructed, because the first read can
/// allocate it before a single output byte exists. That reservation is separate
/// from `reservation` and lives exactly as long as this pass: only one decoder
/// is active at a time across a stacked `Content-Encoding`, so the scratch is
/// returned as soon as the pass ends while the decoded buffers it produced stay
/// charged.
fn decode_one_coding(
    coding: &str,
    data: &[u8],
    limit: usize,
    concurrent_bytes: usize,
    reservation: &mut ResponseBufferReservation,
    budget: BudgetRef<'_>,
) -> Result<Vec<u8>, DecodeFailure> {
    let Some(coding) = SupportedCoding::from_token(coding) else {
        return Err(DecodeFailure::Rejected(
            RepresentationRejection::UnsupportedCoding,
        ));
    };
    let mut scratch = ResponseBufferReservation::new();
    if !scratch.reserve_in(budget, coding.scratch_bytes()) {
        return Err(DecodeFailure::CapacityRefused);
    }
    let take = limit as u64 + 1;
    // `scratch` is dropped on every exit from here — success, rejection, and
    // capacity refusal alike — which is what returns the codec's heap charge
    // before the next pass asks for its own.
    match coding {
        SupportedCoding::Gzip => read_decoded_bounded(
            flate2::read::MultiGzDecoder::new(data).take(take),
            limit,
            concurrent_bytes,
            reservation,
            budget,
        ),
        SupportedCoding::Brotli => read_decoded_bounded(
            StrictBrotliReader::new(data).take(take),
            limit,
            concurrent_bytes,
            reservation,
            budget,
        ),
    }
}

/// Decoded identity bytes together with the aggregate-budget charge that paid
/// for them.
///
/// The charge travels WITH the allocation rather than with the request, which is
/// what makes every disposal path leak-free by construction and requires no
/// caller to remember anything:
///
/// * published as the client-visible body — [`install_decoded_response_body`]
///   moves both into one [`bytes::Bytes`] owner, so the permit is returned when
///   the last clone of those bytes drops, wherever they were copied or stored;
/// * claim withdrawn, or the representation rejected after the decode, or the
///   request cancelled — the value is simply dropped, and the whole reservation
///   goes back with it.
pub(crate) struct ChargedDecodedBody {
    data: Vec<u8>,
    /// Covers the PEAK working set of the decode (see
    /// [`crate::proxy::response_buffer_budget`]), narrowed to the surviving
    /// allocation when the bytes are published.
    reservation: ResponseBufferReservation,
}

impl ChargedDecodedBody {
    /// The decoded identity bytes, for the gate's own re-inspection.
    fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Publish the decoded allocation and its permit as one cheaply cloneable
    /// [`Bytes`] owner, handing back the decode's transient peak surplus first
    /// so the long-lived charge is the retained capacity rather than the working
    /// set. `O(1)`: the buffer is moved, never copied.
    ///
    /// `None` when the held charge does not cover the allocation's actual
    /// capacity. Narrowing can only RELEASE permits, so it cannot repair an
    /// under-charge; the fail-closed answer is to publish nothing and drop both
    /// the buffer and the reservation, which the caller turns into the
    /// gateway-local capacity terminal. `decode_response_body` already fits the
    /// reservation to this exact capacity and nothing between there and here
    /// touches the buffer, so this is a checked invariant rather than an
    /// expected outcome — but it is checked, because the alternative is
    /// installing bytes the budget does not bound.
    fn into_charged_bytes(mut self) -> Option<Bytes> {
        if !self.reservation.narrow_to_covered(self.data.capacity()) {
            return None;
        }
        charged_bytes(self.data, self.reservation)
    }
}

/// Decode a possibly stacked `Content-Encoding` down to identity bytes.
///
/// `Content-Encoding` lists codings in the order they were applied, so they are
/// undone in reverse. `identity` tokens are skipped; an empty or whitespace-only
/// token is malformed rather than absent, and is rejected — a present-but-empty
/// coding cannot be proven to describe identity-coded bytes. `None` means the
/// field reduced to identity-only tokens and no client-visible bytes changed.
///
/// `limit` bounds every intermediate pass, not just the final output, so a
/// stacked encoding cannot exceed the caller's ceiling partway through. The
/// aggregate budget bounds the same passes across CONCURRENT responses: a
/// per-response ceiling alone still multiplies by concurrency, which is exactly
/// how a small compressed body could otherwise amplify past the process
/// aggregate (`GHSA-pwcm-6rh8-f2gh`).
///
/// The wire bytes are never copied: the first pass decodes straight out of
/// `body`, whose allocation the collector already charged.
fn decode_response_body(
    encoding: &str,
    body: &[u8],
    limit: usize,
    budget: BudgetRef<'_>,
) -> Result<Option<ChargedDecodedBody>, DecodeFailure> {
    let codings: Vec<&str> = encoding
        .split(',')
        .map(str::trim)
        .filter(|token| !token.eq_ignore_ascii_case("identity"))
        .collect();
    if codings.is_empty() {
        return Ok(None);
    }
    if codings.len() > MAX_STACKED_RESPONSE_CODINGS {
        return Err(DecodeFailure::Rejected(
            RepresentationRejection::DecodedBodyTooLarge,
        ));
    }
    if codings.iter().any(|token| token.is_empty()) {
        return Err(DecodeFailure::Rejected(
            RepresentationRejection::MalformedCoding,
        ));
    }

    let mut reservation = ResponseBufferReservation::new();
    let mut current: Option<Vec<u8>> = None;
    for coding in codings.into_iter().rev() {
        let lowered = coding.to_ascii_lowercase();
        // The previous pass's buffer is the input and stays resident for the
        // whole of this pass, so it is charged concurrently with this pass's
        // output. A reservation only grows, so what is held after the loop is
        // the peak across passes.
        let (input, concurrent) = match current.as_ref() {
            Some(previous) => (previous.as_slice(), previous.capacity()),
            None => (body, 0),
        };
        let decoded =
            decode_one_coding(&lowered, input, limit, concurrent, &mut reservation, budget)?;
        current = Some(decoded);
    }
    match current {
        // Unreachable: the coding list is non-empty and every pass assigns.
        // Answering "nothing was decoded" is the fail-safe direction anyway —
        // it forwards the original bytes rather than publishing an unproven
        // representation.
        None => Ok(None),
        Some(data) => {
            // Fit the peak reservation to the surviving allocation's ACTUAL
            // capacity before it leaves this function. The loop already topped
            // up after every allocation, so this only ever confirms; keeping it
            // as a real reservation (which can refuse) rather than an assertion
            // means the invariant fails closed instead of publishing bytes the
            // budget does not bound.
            if !reservation.reserve_in(budget, data.capacity()) {
                return Err(DecodeFailure::CapacityRefused);
            }
            Ok(Some(ChargedDecodedBody { data, reservation }))
        }
    }
}

/// Resolve the media type the gate — and every claim predicate it consults — may
/// trust as a description of `body`.
///
/// The live `content-type` has already passed through `after_proxy`, and the
/// main gRPC path RELABELS it: [`super::grpc_web`]'s `after_proxy` stamps
/// `application/grpc-web*` onto the live header map of every translated response
/// so its own phase-9 re-encode can run, whatever the backend actually sent.
/// That label states what the gateway INTENDS to emit; it is not proof of what
/// arrived. Letting it stand on its own was a fail-open: a translated gRPC-Web
/// response from a backend that stamped no `Content-Type` at all could carry
/// malformed frames or a bare JSON error document, and the framed label alone
/// made the claim predicate decline it — so the gate answered `Unprotected` and
/// the bytes were forwarded (and re-wrapped) with a configured redaction never
/// applied.
///
/// A framed-gRPC label is therefore honored only when something the pipeline
/// cannot have invented proves framing:
///
/// * the PRISTINE media type stamped by
///   [`crate::proxy::stamp_original_response_metadata`] before any response hook
///   ran was itself a framed gRPC type — the backend's own description, which
///   stays authoritative exactly as it is everywhere else in this gate; or
/// * the bytes TOTAL-PARSE as a complete frame sequence under the one grammar
///   the client's representation admits
///   ([`super::grpc_web::client_grpc_framing_representation`]).
///
/// Otherwise the label resolves to `None` — the untyped branch — so the bytes
/// are claimed, parsed, and either redacted (a genuine bare JSON document) or
/// rejected (malformed, truncated, or mode-illegal framing), which is the same
/// answer the response would have received had no hook relabelled it.
///
/// The resolution is ONE-DIRECTIONAL and cannot manufacture a spurious `502`:
/// bytes that really are complete frames keep their label and stay declined, and
/// a label that is not a framed gRPC type is returned untouched. The pristine
/// type wins outright, so a proven framed backend response is never re-parsed
/// into the JSON branch.
pub(crate) fn effective_response_media_type<'a>(
    ctx: &RequestContext,
    content_type: Option<&'a str>,
    body: &[u8],
) -> Option<&'a str> {
    let live = content_type?;
    if !is_framed_grpc_content_type(live) {
        return content_type;
    }
    let pristine_proves_framing = ctx
        .metadata
        .get(crate::proxy::ORIGINAL_RESPONSE_CONTENT_TYPE_METADATA_KEY)
        .map(String::as_str)
        .is_some_and(is_framed_grpc_content_type);
    if pristine_proves_framing {
        return content_type;
    }
    let representation = super::grpc_web::client_grpc_framing_representation(ctx)?;
    let framed = super::grpc_web::bytes_are_complete_grpc_frames(body, representation);
    framed.then_some(live)
}

/// Whether the decoded bytes are a complete parseable document that a
/// field-level body rule can act on.
///
/// Only JSON is checked, because JSON is the document model every configured
/// body rule in the gateway operates on. A policy that declines on media type
/// never claims the response in the first place, so it never reaches here.
///
/// This parses **exactly** the way the enforcer does — `serde_json::from_slice`
/// over the same bytes, with no normalization. That symmetry is load-bearing: if
/// the gate were more lenient than [`crate::plugins::utils::body_transform::apply_body_rules`]
/// (say, by stripping a UTF-8 BOM the enforcer chokes on), a body could pass the
/// gate, fail to parse inside the transform, return `None`, and be forwarded
/// unredacted — which is precisely the `None`-conflation bypass this module
/// exists to close. A BOM-prefixed body is therefore rejected rather than
/// accommodated; RFC 8259 forbids emitting one, and fail-closed is the posture.
fn document_is_parseable(content_type: Option<&str>, body: &[u8]) -> bool {
    if content_type.is_some_and(|value| !is_json_content_type(value)) {
        return true;
    }
    serde_json::from_slice::<serde_json::Value>(body).is_ok()
}

/// Evaluate the shared representation gate for one buffered response.
///
/// Every buffered publication path calls exactly this function, so a frontend
/// protocol, a bridge, or a synthetic short-circuit cannot reach a different
/// conclusion about the same bytes and the same configuration.
///
/// `budget` is the aggregate retained-response budget the decode charges
/// against. Production passes [`BudgetRef::global`]; it is a parameter only so
/// external tests can bind an isolated semaphore rather than mutating the
/// process-global one from a parallel test binary.
pub(crate) fn evaluate_response_body_policy_posture(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    origin: RepresentationOrigin,
    response_status: u16,
    response_headers: &HashMap<String, String>,
    response_body: &[u8],
    budget: BudgetRef<'_>,
) -> ResponseBodyPolicyPosture {
    // Resolve the live header before anything reads it. A framed gRPC label that
    // neither the pristine snapshot nor a total frame parse supports describes
    // nothing the backend proved, and must not excuse these bytes from either the
    // claim below or the document parse further down — see
    // [`effective_response_media_type`].
    let live_content_type = response_headers.get("content-type").map(String::as_str);
    let content_type = effective_response_media_type(ctx, live_content_type, response_body);
    if !body_policy_claimed(plugins, ctx, content_type, response_body) {
        return ResponseBodyPolicyPosture::Unprotected;
    }
    // An absent body carries nothing the policy could redact, and rejecting
    // empty 200s would break ordinary traffic without protecting anything.
    if response_body.is_empty() {
        return ResponseBodyPolicyPosture::Unprotected;
    }

    if origin == RepresentationOrigin::Backend
        && !ctx
            .metadata
            .contains_key(crate::proxy::ORIGINAL_RESPONSE_METADATA_STAMPED_KEY)
    {
        return ResponseBodyPolicyPosture::Reject(RepresentationRejection::UnprovenOriginState);
    }

    if is_partial_representation(ctx, origin, response_status, response_headers) {
        return ResponseBodyPolicyPosture::Reject(RepresentationRejection::PartialRepresentation);
    }

    let limit = decoded_inspection_limit(ctx);
    let decoded = match origin_content_encoding(ctx, origin, response_headers) {
        None => None,
        Some(encoding) => match decode_response_body(encoding, response_body, limit, budget) {
            Ok(decoded) => decoded,
            Err(DecodeFailure::Rejected(rejection)) => {
                return ResponseBodyPolicyPosture::Reject(rejection);
            }
            // Every block the refused decode had already taken is released with
            // the reservation that `decode_response_body` dropped on its way
            // out, so a refusal costs the budget nothing.
            Err(DecodeFailure::CapacityRefused) => {
                return ResponseBodyPolicyPosture::CapacityRefused;
            }
        },
    };

    let inspected = decoded
        .as_ref()
        .map_or(response_body, ChargedDecodedBody::bytes);
    // Re-resolve the label over the decoded bytes for the same reason the claim
    // is re-asked below: the frame parse that can prove a framed label is a
    // statement about the representation the client actually receives, and after
    // a decode that is `inspected`, not the wire bytes. Skipped when no decode
    // happened, where the two byte strings — and therefore both answers — are
    // identical.
    let content_type = if decoded.is_some() {
        effective_response_media_type(ctx, live_content_type, inspected)
    } else {
        content_type
    };
    // Re-ask the claim over the bytes the enforcer will actually be handed. The
    // first ask ran over the WIRE bytes, which is the only way to know whether a
    // decode was owed at all; but a predicate that decides structurally (framed
    // gRPC vs. a bare JSON document on an untyped response) can only be right
    // about the decoded representation. Without this second ask, an untyped
    // `gzip` body whose plaintext is valid gRPC frames would be claimed on its
    // compressed bytes, decode to frames, fail the JSON parse, and turn a valid
    // RPC reply into a `502`.
    //
    // Declining here forwards the ORIGINAL bytes untouched: `decoded` is dropped
    // with this posture, so nothing is installed and the client still receives
    // the encoded representation the origin produced. No redaction is lost,
    // because a claim predicate only withdraws over bytes it has proven its
    // field rules cannot act on. Dropping it also returns the decode's entire
    // aggregate-budget charge, so a withdrawn claim leaves the budget exactly
    // where it found it — as do the three rejections below, for the same reason.
    if decoded.is_some() && !body_policy_claimed(plugins, ctx, content_type, inspected) {
        return ResponseBodyPolicyPosture::Unprotected;
    }
    // Only NOW is it known that identity bytes are the representation the client
    // would actually receive, which is the sole thing the refusal is about.
    //
    // Asking earlier — before the decode and before the claim was re-asked over
    // the plaintext — rejected responses that were never going to be downgraded.
    // A `gzip` body whose plaintext is valid framed RPC withdraws the claim on
    // the line above and the ORIGINAL encoded bytes go out untouched, so identity
    // is never served and there is nothing for the client's `identity;q=0` to
    // refuse; turning that valid RPC reply into a `502` refused an encoding the
    // client had explicitly accepted.
    //
    // `decoded.is_some()` is the exact condition, not an approximation of one:
    // [`decode_response_body`] answers `None` for a field that reduces to
    // identity-only tokens (no octets change, so the rule does not apply) and
    // rejects a malformed one before reaching here, so `Some` means precisely
    // "a real coding was undone and these plaintext bytes are what gets served".
    //
    // Deferring costs nothing that was previously bounded: the decode this now
    // runs first is the same bounded, ceiling-checked pass every other protected
    // encoded response already performs, and malformed, unsupported, and
    // oversized codings still reject above — only the reported reason changes
    // for a response that is uninspectable AND unacceptable, and both answers
    // are the same fail-closed replacement.
    if decoded.is_some() && !identity_coding_is_acceptable(ctx) {
        return ResponseBodyPolicyPosture::Reject(
            RepresentationRejection::IdentityCodingUnacceptable,
        );
    }
    // A TRANSLATED gRPC-Web response is re-encoded AFTER the enforcer, so a
    // claimed body that is not already native framing cannot be enforced at all.
    // `grpc_web` (priority 260) appends the trailer frame and base64-encodes in
    // the same buffered transform loop, before `response_transformer` (4000) is
    // ever handed the bytes: a field rule would then run over the rewrapped body,
    // fail to parse it, return `None`, and the document would go out WRAPPED AND
    // UNREDACTED. Answering `Enforce` here would be a promise the lifecycle
    // cannot keep — the same `None`-conflation this gate exists to close — so the
    // response is rejected in the client's gRPC-Web flavor instead.
    //
    // This cannot fire on working traffic. A translated request reached the
    // backend as `application/grpc`, so a reply that is not a complete native
    // frame sequence is a broken backend response its gRPC-Web client could not
    // have consumed either; and a reply that IS framing never reaches this line,
    // because the claim declines proven framing above.
    //
    // Scoped to `Backend` origin and to translation on purpose:
    //   * gateway-generated bytes are the gateway's own JSON rejection, which
    //     must survive rather than be overwritten by a generic gate error;
    //   * native gRPC and RETAINED-only gRPC-Web routes run no re-encoder after
    //     the enforcer, so their untyped bare JSON documents stay claimed,
    //     redacted, and served exactly as before.
    let native_framing = super::grpc_web::GrpcFramingRepresentation::Native;
    if origin == RepresentationOrigin::Backend
        && super::grpc_web::request_is_grpc_web_translated(ctx)
        && !super::grpc_web::bytes_are_complete_grpc_frames(inspected, native_framing)
    {
        return ResponseBodyPolicyPosture::Reject(RepresentationRejection::UnenforceableFraming);
    }
    if !document_is_parseable(content_type, inspected) {
        return ResponseBodyPolicyPosture::Reject(RepresentationRejection::UnparseableDocument);
    }

    ResponseBodyPolicyPosture::Enforce { decoded }
}

/// Install decoded identity-coded bytes ahead of the transform phase.
///
/// The stale `Content-Encoding` is dropped and `Content-Length` recomputed so
/// the bytes every subsequent transform sees are exactly the bytes the gate
/// proved inspectable. The pristine origin-encoding marker is cleared for the
/// same reason: a later reader must not conclude these bytes are still encoded.
///
/// Content-bound metadata is invalidated **here**, at the decode, rather than
/// only after a rule matches. A decode already changes the client-visible octets
/// — encoded bytes in, identity bytes out — so the origin's `ETag`, `Digest`,
/// `Content-Digest`, `Content-MD5`, `Last-Modified`, and signature fields
/// describe a representation the client will never receive. Deferring to
/// [`crate::plugins::finalize_response_body_transformation`] would miss the
/// transform no-op case: a decoded body that no configured rule happens to
/// change never reaches that call, and would otherwise be served as identity
/// bytes carrying a validator for the encoded ones, corrupting cache
/// revalidation and integrity checks.
///
/// # Refreshing the stamped representation state
///
/// The pre-`after_proxy` snapshot describes the ENCODED response, and a decode
/// makes two of its fields false. Both are refreshed here, together, because a
/// later body transform reads them as one description:
///
/// * [`crate::proxy::ORIGIN_ENCODED_RESPONSE_METADATA_KEY`] is cleared — these
///   bytes are identity-coded now.
/// * [`crate::proxy::ORIGINAL_RESPONSE_CONTENT_LENGTH_METADATA_KEY`] is set to
///   the decoded length. Clearing the encoding marker alone was not enough:
///   `mcp_gateway`'s buffered transform reads
///   [`crate::proxy::ORIGINAL_RESPONSE_METADATA_STAMPED_KEY`] and then consults
///   ONLY the stamped length, never the live header. A chunked encoded backend
///   response stamps no length at all, so the snapshot said "no length", and the
///   transform's `is_none_or` precheck rejected a body that is now decoded,
///   bounded, and fully inspectable — silently skipping MCP reverse mapping and
///   forwarding upstream-native MCP names and URIs the transform exists to
///   rewrite.
///
/// The refresh is not a fabrication and it does not corrupt pristine origin
/// evidence. The stamped length exists to answer "how many bytes will a body
/// transform be handed?", which every other stamped field (media type, fragment
/// state, range state) already answers about the CURRENT representation once the
/// gate has spoken. The decoded length is bounded by
/// [`decoded_inspection_limit`], so it is a truthful bounded value rather than an
/// attacker-chosen one. The keys describing what the gate still needs to judge
/// provenance — the stamped marker, media type, and fragment/range state — are
/// deliberately untouched; only the two fields the decode actually invalidated
/// are rewritten, and only when a backend snapshot exists to rewrite. Gateway-
/// generated bytes have no snapshot and must keep none: their readers correctly
/// fall back to the live headers this function just set.
///
/// # Owning the charge
///
/// The decoded allocation is client-visible and attacker-amplified, and it
/// survives the transform phase even when NO configured rule matches — the
/// no-op-transform path installs identity bytes and then leaves them alone. It
/// therefore has to own an aggregate retained-response charge for its whole
/// lifetime, not merely for the decode
/// (`GHSA-pwcm-6rh8-f2gh`). [`ChargedDecodedBody::into_charged_bytes`] moves the
/// buffer and its permit into one [`bytes::Bytes`] owner, so the permit is
/// returned exactly when the last clone drops — success, replacement by a later
/// transform, a cache-entry copy outliving the request, deadline expiry, client
/// disconnect, and cancellation are all just drops.
///
/// Returns `false` — installing NOTHING, leaving `response_body` and
/// `response_headers` exactly as the caller had them — when the charge does not
/// cover the decoded allocation's real capacity. The caller must then take the
/// gateway-local capacity terminal, because forwarding the encoded bytes to a
/// client after a body policy claimed the response is the bypass this gate
/// exists to prevent.
#[must_use]
pub(crate) fn install_decoded_response_body(
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
    response_body: &mut Bytes,
    decoded: ChargedDecodedBody,
) -> bool {
    let Some(charged) = decoded.into_charged_bytes() else {
        return false;
    };
    *response_body = charged;
    response_headers.retain(|name, _| !name.eq_ignore_ascii_case("content-encoding"));
    super::invalidate_content_bound_response_headers(response_headers);
    let length = response_body.len().to_string();
    response_headers.insert("content-length".to_string(), length.clone());
    ctx.metadata
        .remove(crate::proxy::ORIGIN_ENCODED_RESPONSE_METADATA_KEY);
    if ctx
        .metadata
        .contains_key(crate::proxy::ORIGINAL_RESPONSE_METADATA_STAMPED_KEY)
    {
        ctx.metadata.insert(
            crate::proxy::ORIGINAL_RESPONSE_CONTENT_LENGTH_METADATA_KEY.to_string(),
            length,
        );
    }
    true
}
