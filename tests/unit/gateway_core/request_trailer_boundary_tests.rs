//! Late request-trailer trust boundary on the HTTP/1.1 and HTTP/2 dispatch
//! paths (issue #4148).
//!
//! Client request trailers are read AFTER the initial header block has been
//! stripped and sanitized, so a client that sends a TRAILERS frame can restate
//! anything the gateway removed from the headers: reserved gateway assertions
//! (the whole `x-consumer-*` namespace, `x-geo-country`), Ferrum
//! internals (`x-ferrum-*`, `x-path-param-*`), credentials, forwarding
//! identity, and hop-by-hop framing controls.
//!
//! HTTP/3 has always applied `sanitize_backend_request_trailers` at that
//! boundary. These tests pin the H1/H2 counterpart: the same canonical
//! predicate, applied at the seams every H1/H2 request-body adapter composes
//! over, so the two protocol families cannot drift.

const BODY_SRC: &str = include_str!("../../../src/proxy/body.rs");
const GRPC_SRC: &str = include_str!("../../../src/proxy/grpc_proxy.rs");
const GRPC_WEB_SRC: &str = include_str!("../../../src/plugins/grpc_web.rs");

const BENIGN_TRAILER: &str = "x-request-checksum";

/// The forged / smuggled trailer block an attacker sends after a sanitized
/// header block, plus one benign application trailer that must survive.
fn hostile_request_trailers() -> Vec<(&'static str, &'static str)> {
    vec![
        // Reserved gateway assertions — documented as "never trusted from
        // clients" and the whole point of this boundary.
        ("x-consumer-username", "admin"),
        ("x-consumer-custom-id", "1"),
        // The whole `x-consumer-*` namespace is gateway-owned.
        ("x-consumer-role", "admin"),
        ("x-consumer-groups", "admins"),
        ("x-geo-country", "US"),
        // Ferrum-owned internals.
        ("x-ferrum-foo", "bar"),
        ("x-path-param-account", "acct-1"),
        // Credentials.
        ("authorization", "Bearer forged"),
        ("x-api-key", "forged"),
        ("cookie", "session=forged"),
        // Forwarding identity the gateway regenerates.
        ("x-forwarded-for", "10.0.0.1"),
        ("x-forwarded-proto", "https"),
        ("forwarded", "for=10.0.0.1"),
        ("via", "1.1 attacker"),
        // RFC 9110 section 7.6.1 request-direction hop-by-hop framing controls.
        ("connection", "close"),
        ("te", "trailers"),
        ("transfer-encoding", "chunked"),
        ("trailer", "x-consumer-username"),
        ("upgrade", "h2c"),
        ("keep-alive", "timeout=5"),
        ("proxy-authorization", "Basic Zm9v"),
        ("proxy-connection", "close"),
        ("content-length", "0"),
        // Initial-only gRPC call parameters.
        ("grpc-timeout", "1S"),
        ("grpc-encoding", "gzip"),
        // Header-section-only fields that are never legitimate in trailers.
        ("host", "internal.example"),
        ("content-type", "application/grpc"),
        ("early-data", "1"),
        // Benign application metadata: this is the one that must survive.
        (BENIGN_TRAILER, "sha256:abc"),
    ]
}

/// Every forbidden name in [`hostile_request_trailers`], for negative
/// assertions.
fn forbidden_names() -> Vec<&'static str> {
    hostile_request_trailers()
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| *name != BENIGN_TRAILER)
        .collect()
}

fn surviving_benign_trailer() -> Vec<(String, String)> {
    vec![(BENIGN_TRAILER.to_string(), "sha256:abc".to_string())]
}

#[test]
fn h1_h2_request_trailer_boundary_strips_forged_gateway_assertions() {
    let sanitized = ferrum_edge::_test_support::sanitized_backend_request_trailer_frame(
        &hostile_request_trailers(),
    );
    let names: Vec<&str> = sanitized.iter().map(|(name, _)| name.as_str()).collect();
    for forbidden in forbidden_names() {
        assert!(
            !names.contains(&forbidden),
            "request trailer `{forbidden}` must not cross the H1/H2 backend boundary: {names:?}"
        );
    }
    assert_eq!(
        sanitized,
        surviving_benign_trailer(),
        "benign application trailers must still reach the backend"
    );
}

#[test]
fn h1_h2_request_trailer_boundary_keeps_repeated_application_metadata() {
    let sanitized = ferrum_edge::_test_support::sanitized_backend_request_trailer_frame(&[
        (BENIGN_TRAILER, "sha256:first"),
        ("x-consumer-username", "admin"),
        (BENIGN_TRAILER, "sha256:second"),
    ]);
    assert_eq!(
        sanitized,
        vec![
            (BENIGN_TRAILER.to_string(), "sha256:first".to_string()),
            (BENIGN_TRAILER.to_string(), "sha256:second".to_string()),
        ]
    );
}

#[test]
fn h1_h2_request_trailer_boundary_leaves_data_frames_untouched() {
    let preserved =
        ferrum_edge::_test_support::sanitize_backend_request_trailer_frame_preserves_data(
            b"x-consumer-username: admin",
        );
    assert!(
        preserved,
        "the boundary is a trailer filter, never a body rewriter: DATA bytes that happen to \
         spell a forbidden name must cross unchanged"
    );
}

/// End-to-end over the production streaming seam
/// (`crate::proxy::body::UploadSource::poll_frame`), which is what
/// `SizeLimitedIncoming`, `CountingIncoming`, and `GrpcBody::Streaming` all
/// read their frames through.
#[tokio::test]
async fn h1_h2_streaming_upload_seam_drops_forged_trailers_and_forwards_the_body() {
    let (data, trailers) = ferrum_edge::_test_support::h1_h2_upload_source_forwarded_frames(
        b"grpc-payload",
        &hostile_request_trailers(),
    )
    .await;
    assert_eq!(data, b"grpc-payload".to_vec());
    let names: Vec<&str> = trailers.iter().map(|(name, _)| name.as_str()).collect();
    for forbidden in forbidden_names() {
        assert!(
            !names.contains(&forbidden),
            "streaming upload forwarded forbidden request trailer `{forbidden}`: {names:?}"
        );
    }
    assert_eq!(trailers, surviving_benign_trailer());
}

#[tokio::test]
async fn h1_h2_streaming_upload_seam_forwards_a_clean_trailer_block_unchanged() {
    let (data, trailers) = ferrum_edge::_test_support::h1_h2_upload_source_forwarded_frames(
        b"payload",
        &[(BENIGN_TRAILER, "sha256:abc"), ("x-tenant", "acme")],
    )
    .await;
    assert_eq!(data, b"payload".to_vec());
    assert_eq!(
        trailers,
        vec![
            (BENIGN_TRAILER.to_string(), "sha256:abc".to_string()),
            ("x-tenant".to_string(), "acme".to_string()),
        ]
    );
}

// -- Source-shape guards ------------------------------------------------------
//
// The behavioural tests above prove the boundary works where it is wired. These
// guards prove it stays wired, and that every H1/H2 request-body adapter keeps
// composing over a seam that applies it.

fn slice_between<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
    let start_at = src
        .find(start)
        .unwrap_or_else(|| panic!("source anchor not found: {start:?}"));
    let tail = &src[start_at..];
    let end_at = tail
        .find(end)
        .unwrap_or_else(|| panic!("source anchor not found after {start:?}: {end:?}"));
    &tail[..end_at]
}

#[test]
fn request_trailer_boundary_reuses_the_canonical_predicate() {
    let applicator = slice_between(
        BODY_SRC,
        "pub(crate) fn sanitize_backend_request_trailer_frame(",
        "\n// -- Gateway-owned upload source",
    );
    let canonical = "crate::proxy::headers::sanitize_backend_request_trailers(&mut trailers)";
    assert!(
        applicator.contains(canonical),
        "the H1/H2 request-trailer boundary must call the shared sanitizer, never a forked \
         predicate — HTTP/3 and HTTP/1.1+HTTP/2 have to agree by construction"
    );
    assert!(
        applicator.contains("if !frame.is_trailers()"),
        "DATA frames must short-circuit on a single discriminant test: the proxy request path \
         cannot afford per-frame trailer work"
    );
}

#[test]
fn streaming_upload_source_applies_the_request_trailer_boundary() {
    let poll = slice_between(
        BODY_SRC,
        "impl UploadSource {",
        "\n    pub(crate) fn is_end_stream(&self) -> bool {",
    );
    assert!(
        poll.contains("sanitize_backend_request_trailer_frame(frame)"),
        "UploadSource::poll_frame is the single late request-trailer boundary for every H1/H2 \
         streaming dispatch (reqwest, direct HTTP/2, native gRPC, mesh mTLS, Unix socket) — \
         removing it re-opens issue #4148"
    );
}

#[test]
fn direct_h2_passthrough_applies_the_request_trailer_boundary() {
    let poll = slice_between(
        BODY_SRC,
        "impl http_body::Body for DirectH2RequestBody {",
        "\n    fn is_end_stream(&self) -> bool {",
    );
    assert!(
        poll.contains("sanitize_backend_request_trailer_frame(frame)"),
        "the direct-HTTP/2 Passthrough arm polls the client `Incoming` in place rather than \
         through `UploadSource`, so it needs its own call to the request-trailer boundary"
    );
}

#[test]
fn h1_h2_streaming_request_bodies_source_frames_through_upload_source() {
    let size_limited = slice_between(BODY_SRC, "pub struct SizeLimitedIncoming {", "\n}");
    assert!(
        size_limited.contains("inner: UploadSource,"),
        "SizeLimitedIncoming must keep reading through UploadSource so it inherits the \
         request-trailer boundary"
    );
    let counting = slice_between(BODY_SRC, "pub struct CountingIncoming {", "\n}");
    assert!(
        counting.contains("inner: UploadSource,"),
        "CountingIncoming must keep reading through UploadSource so it inherits the \
         request-trailer boundary"
    );
    assert!(
        BODY_SRC.contains("DirectH2RequestBody::Limited(limited) => Pin::new(limited)"),
        "the direct-HTTP/2 Limited arm must keep delegating to SizeLimitedIncoming"
    );
    assert!(
        GRPC_SRC.contains("incoming: crate::proxy::body::UploadSource,"),
        "GrpcBody::Streaming — the default native-gRPC fast path — must keep reading through \
         UploadSource so it inherits the request-trailer boundary"
    );
}

#[test]
fn reqwest_request_bodies_still_drop_inbound_trailers_entirely() {
    let sync_body = slice_between(
        BODY_SRC,
        "impl<B> http_body::Body for SyncBody<B>",
        "\n    fn is_end_stream(&self) -> bool {",
    );
    assert!(
        sync_body.contains("Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue"),
        "the reqwest request-body wrapper drops inbound trailer frames outright; that is the \
         second, independent layer protecting the HTTP/1.1 and reqwest-HTTP/2 paths"
    );
}

#[test]
fn buffered_grpc_request_trailers_stay_bound_to_the_validated_staging_path() {
    // `GrpcBody::BufferedWithTrailers`, `GrpcBody::Pumped`, and
    // `ReplayableRequestBody` deliberately emit a terminal TRAILERS frame, but
    // their trailer map is never native client trailers: it comes only from the
    // gRPC-Web plugin's owner-scoped staging, which re-validates every entry
    // against the same canonical backend predicate and fails closed.
    let staged = slice_between(
        GRPC_WEB_SRC,
        "pub(crate) fn staged_request_trailers(",
        "\n/// Whether `data` is a gRPC-Web **text**-mode body",
    );
    assert!(
        staged.contains("is_forbidden_grpc_web_request_trailer_name(&name)"),
        "staged request trailers must be re-validated on read: ctx.metadata is writable by any \
         plugin, so presence is not proof of provenance"
    );
    let predicate = slice_between(
        GRPC_WEB_SRC,
        "fn is_forbidden_grpc_web_request_trailer_name(name: &str) -> bool {",
        "\n}",
    );
    assert!(
        predicate.contains("is_forbidden_backend_request_trailer_name(name)"),
        "the gRPC-Web request-trailer predicate must compose the canonical backend predicate, \
         not restate it"
    );
    assert!(
        GRPC_SRC.contains("Some(trailers) => GrpcBody::BufferedWithTrailers {"),
        "the buffered-with-trailers arm must stay reachable only from \
         `buffered_grpc_request_body_with_write_watermark`, whose trailers come from staging"
    );
}
