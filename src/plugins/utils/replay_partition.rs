//! One fail-closed replay-partition contract for every plugin that can return a
//! retained result before the backend evaluates the current request.
//!
//! `response_caching`, `request_deduplication`, and `ai_semantic_cache` all
//! short-circuit a request with bytes produced for an *earlier* request. That is
//! only sound while the two requests provably share every backend-visible
//! dimension the origin could have used to decide what to return:
//!
//! * **Caller authorization** — not a display subject. Two credentials can carry
//!   the same `sub` with different scopes, audiences, or tenancy claims, so the
//!   partition binds a digest of the actual credential material presented on
//!   this request together with the mechanism that accepted it. *Both* header
//!   views are bound, under distinct provenance labels: the pristine inbound
//!   wire view (`RequestContext`'s retained raw `HeaderMap`) and the live,
//!   backend-visible view the calling plugin was handed. Configured custom auth
//!   headers join the conservative built-in set, and credential-bearing query
//!   parameters are privately digested before authentication stripping. An
//!   earlier plugin that rewrites credentials — `ai_stream_router` strips the
//!   client credential and injects the provider's — therefore cannot erase the
//!   original caller distinction, and cannot demote an authenticated caller to
//!   *anonymous* by consuming the only credential it presented.
//! * **Canonical caller context** — every caller is bound to the
//!   gateway-resolved peer address, because Ferrum regenerates
//!   `X-Forwarded-For` on every outbound HTTP request and the origin therefore
//!   observes it regardless of whether the caller authenticated. Operators whose
//!   origins provably ignore caller address may opt one plugin instance out for
//!   *anonymous* callers only, with [`AnonymousCallerScope::Shared`].
//! * **Effective destination** — the post-routing upstream / host / port /
//!   scheme / authority and rewritten path, not the originally matched proxy.
//! * **Request target** — the original client authority, `Host`, method, path,
//!   and effective outbound query
//!   ([`append_request_target_partition`]).
//! * **Request headers** — the finalized backend-visible header view, for
//!   plugins whose own key does not already bind an equivalent dimension
//!   ([`append_request_context_partition`]). Only hop-by-hop/framing fields
//!   Ferrum provably regenerates are excluded; tracing and correlation headers
//!   reach the origin and are bound. The shared HTTP cache
//!   ([`append_response_cache_request_partition`]) excludes only the entry-
//!   operation headers whose semantics `response_caching` actually implements
//!   (`If-None-Match`, `If-Modified-Since`, pure honored request
//!   `Cache-Control: no-cache` / `no-store` refreshes with no arguments when
//!   `respect_no_cache` is enabled, and single-field zero-length
//!   `Content-Length`) while
//!   conservatively binding every other representation and policy dimension,
//!   including headers absent from `Vary`. Mixed Cache-Control members and
//!   Cache-Control under `respect_no_cache: false` stay bound.
//!
//! Every component is serialized with typed, length-framed fields
//! ([`PartitionHasher`]) so no attacker-controlled byte can impersonate a field
//! boundary. Raw delimiter concatenation (`a:b|c=d`) is structurally unsafe:
//! distinct requests can serialize to identical preimages without breaking
//! SHA-256.
//!
//! Nothing here is ever logged. The returned values are opaque digests; the
//! inputs are credentials, identities, and addresses.

use std::collections::HashMap;
use std::net::IpAddr;

use sha2::{Digest, Sha256};

use crate::plugins::RequestContext;
use crate::util::body_limit::{ContentLength, parse_content_length};

/// Request headers that carry caller authorization context.
///
/// Two requests whose credential material differs are *different callers* even
/// when the gateway resolves them to the same display subject. Only SHA-256
/// digests of these values ever enter a partition.
pub const CREDENTIAL_CONTEXT_HEADERS: &[&str] = &[
    "api-key",
    "apikey",
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-access-token",
    "x-amz-security-token",
    "x-api-key",
    "x-auth-token",
    "x-forwarded-authorization",
    "x-goog-api-key",
];

/// Case-insensitive membership test for [`CREDENTIAL_CONTEXT_HEADERS`].
pub fn is_credential_context_header(name: &str) -> bool {
    CREDENTIAL_CONTEXT_HEADERS
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// Whether `name` is a conservative built-in credential header or a custom
/// credential location precomputed for this request's plugin chain.
pub fn is_request_credential_context_header(ctx: &RequestContext, name: &str) -> bool {
    is_credential_context_header(name)
        || ctx
            .request_headers_requiring_redaction()
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// Headers that are never visible to the backend as sent by the client, and so
/// cannot be a dimension the origin varies on.
///
/// Exactly one class qualifies, and it is provable rather than assumed:
/// transport/hop-by-hop framing fields, which Ferrum owns and regenerates for
/// the backend hop (RFC 9110 §7.6.1). `host` is excluded here only because every
/// caller of [`append_request_context_partition`] binds the canonical authority
/// as its own field.
///
/// Everything else — including ordinary custom, tenancy, routing, versioning,
/// representation, **and per-request tracing/correlation** headers — is bound. A
/// conservative miss is preferred to an unbound dimension.
///
/// Tracing and correlation headers (`traceparent`, `tracestate`, `b3`,
/// `x-b3-*`, `x-request-id`, `x-correlation-id`, …) were previously excluded by
/// reusing the *response*-cache sanitation classifier
/// (`cache_headers::is_per_request_trace_header`) and arguing they carry a
/// fresh value "by construction". That is not a valid request-side proof:
///
/// * `correlation_id` preserves a valid client-supplied identifier rather than
///   regenerating one, so the value is attacker-chosen and stable across
///   requests when the client wants it to be;
/// * the `correlation_id` / `otel_tracing` plugins may not be configured at
///   all, in which case Ferrum neither strips nor rewrites the client's value;
/// * either way the value reaches the origin, which may vary policy or content
///   by it (tenant-scoped tracing, per-trace feature flags, debug modes).
///
/// Under the advisory's complete backend-visible partition contract an unbound
/// backend-visible dimension is exactly the defect, so these headers are bound
/// like any other. The separate response-header replay sanitation contract in
/// `cache_headers` still strips trace identifiers from a *retained response*;
/// that is unchanged and independent.
const NON_BACKEND_VISIBLE_REQUEST_HEADERS: &[&str] = &[
    "connection",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Whether `name` is excluded from the backend-visible request-header view.
///
/// See `NON_BACKEND_VISIBLE_REQUEST_HEADERS` for why the set is exactly this
/// narrow.
pub fn is_non_backend_visible_request_header(name: &str) -> bool {
    NON_BACKEND_VISIBLE_REQUEST_HEADERS
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// How an *anonymous* caller (no gateway identity, no credential header, no
/// peer SPIFFE identity) is partitioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnonymousCallerScope {
    /// Default. Bind the retained result to the gateway-resolved canonical peer
    /// address, which the origin observes through Ferrum's regenerated
    /// `X-Forwarded-For`. A request whose canonical address cannot be derived
    /// is refused rather than partitioned incompletely.
    #[default]
    CallerAddress,
    /// Operator attestation that the origin does not vary its response by
    /// caller address for this route, so anonymous callers may share one
    /// retained result. This deliberately re-opens cross-caller replay for
    /// address-sensitive origins and must only be set when that is known-safe.
    ///
    /// It applies to anonymous callers only. An authenticated caller always
    /// binds its canonical address, because the origin receives Ferrum's
    /// regenerated forwarding identity for that caller too and may vary policy
    /// or content by it independently of the credential.
    Shared,
}

impl AnonymousCallerScope {
    /// Parse the shared `anonymous_caller_scope` configuration value.
    pub fn parse(plugin: &str, value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "caller_address" | "caller-address" => Ok(Self::CallerAddress),
            "shared" => Ok(Self::Shared),
            other => Err(format!(
                "{plugin}: unknown 'anonymous_caller_scope' value '{other}' \
                 (expected caller_address or shared)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallerAddress => "caller_address",
            Self::Shared => "shared",
        }
    }
}

/// Why a complete, stable replay partition could not be derived.
///
/// Every variant is terminal for the request: the plugin must fall through to
/// the origin without looking up, storing, or deduplicating. The strings are
/// static and content-free so they are safe to emit in a debug line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionRefusal {
    /// The caller is anonymous and the canonical peer address could not be
    /// parsed, so the caller dimension the origin observes cannot be bound.
    AnonymousCallerAddressUnavailable,
    /// The caller authenticated but the canonical peer address could not be
    /// parsed. The origin still receives Ferrum's regenerated forwarding
    /// identity, so this dimension is not optional for authenticated callers
    /// either and there is no attestation that relaxes it.
    AuthenticatedCallerAddressUnavailable,
}

impl PartitionRefusal {
    /// Content-free operator-facing reason. Never includes key, caller, or
    /// credential material.
    pub fn reason(self) -> &'static str {
        match self {
            Self::AnonymousCallerAddressUnavailable => {
                "anonymous caller has no canonical peer address to bind"
            }
            Self::AuthenticatedCallerAddressUnavailable => {
                "authenticated caller has no canonical peer address to bind"
            }
        }
    }
}

/// Domain-separated, length-framed hasher for replay-partition keys.
///
/// Every write is `len(label) || label || len(value) || value` with 64-bit
/// big-endian lengths, so no field content can forge a field boundary, an empty
/// field is distinct from an absent one, and a sequence is bound to its own
/// element count.
pub struct PartitionHasher {
    hasher: Sha256,
}

impl PartitionHasher {
    /// Start a partition under an explicit domain-separation tag. Two plugins
    /// (or two key roles inside one plugin) must never share a tag.
    pub fn new(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain.as_bytes());
        Self { hasher }
    }

    /// Append one length-framed labeled field.
    pub fn field(&mut self, label: &str, value: &[u8]) {
        self.hasher.update((label.len() as u64).to_be_bytes());
        self.hasher.update(label.as_bytes());
        self.hasher.update((value.len() as u64).to_be_bytes());
        self.hasher.update(value);
    }

    pub fn text(&mut self, label: &str, value: &str) {
        self.field(label, value.as_bytes());
    }

    /// Append an optional field. Presence is framed separately from the value,
    /// so an absent field can never be confused with a present empty one.
    pub fn optional_text(&mut self, label: &str, value: Option<&str>) {
        match value {
            Some(value) => {
                self.field(label, &[1u8]);
                self.field(label, value.as_bytes());
            }
            None => self.field(label, &[0u8]),
        }
    }

    pub fn bool_value(&mut self, label: &str, value: bool) {
        self.field(label, &[u8::from(value)]);
    }

    pub fn u64_value(&mut self, label: &str, value: u64) {
        self.field(label, &value.to_be_bytes());
    }

    /// Bind the element count of a sequence before its members are appended.
    pub fn count(&mut self, label: &str, count: usize) {
        self.u64_value(label, count as u64);
    }

    /// Append a nested partition digest as one opaque field.
    pub fn nested(&mut self, label: &str, digest: &[u8; 32]) {
        self.field(label, digest);
    }

    pub fn digest(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }

    pub fn hex(self) -> String {
        hex::encode(self.digest())
    }
}

/// SHA-256 of one value, used for credential material that must never appear in
/// a key, a log line, or `RequestContext::metadata`.
pub fn value_digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// SHA-256 of one raw field-line, for wire values that need not be valid UTF-8.
pub fn bytes_digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

/// Bind the gateway-resolved canonical peer address, or refuse.
///
/// The octets are hashed directly — no `format!` on the request path — and the
/// family tag keeps a v4-mapped v6 address distinct from its v4 form.
fn append_canonical_address(
    hasher: &mut PartitionHasher,
    ctx: &RequestContext,
    unavailable: PartitionRefusal,
) -> Result<(), PartitionRefusal> {
    let address = ctx.canonical_client_ip().ok_or(unavailable)?;
    match address {
        IpAddr::V4(v4) => hasher.field("caller.address_v4", &v4.octets()),
        IpAddr::V6(v6) => hasher.field("caller.address_v6", &v6.octets()),
    }
    Ok(())
}

/// Bind the *pristine inbound* credential context from the retained wire
/// `HeaderMap`, under provenance labels distinct from the live view.
///
/// This is what makes the partition survive an earlier credential rewrite.
/// `ai_stream_router` runs at a lower priority than the post-routing replay
/// plugins and replaces the client's `authorization` with the selected
/// provider's key, so by the time `response_caching` or `ai_semantic_cache`
/// builds a key, the live header view no longer distinguishes two client tokens
/// that resolve to one subject with different scopes. `RequestContext` retains
/// the wire map for exactly this class of decision, and plugins never mutate it.
///
/// Every candidate name is framed whether present or not, with its field-line
/// count ahead of its digests, so neither a repeated field line nor an absent
/// header can reproduce another request's preimage. Availability of the wire map
/// is itself framed: a context without one lands in its own keyspace rather than
/// silently matching a request that provably carried no credential.
///
/// Returns whether the pristine view carried at least one candidate credential
/// field-line, which is what [`append_caller_partition`] uses to classify a
/// caller whose credential an earlier plugin already consumed.
fn append_original_credential_context(hasher: &mut PartitionHasher, ctx: &RequestContext) -> bool {
    let available = ctx.has_raw_headers();
    hasher.bool_value("caller.origin_view", available);
    let mut present = false;
    if available {
        let custom_count = ctx
            .request_headers_requiring_redaction()
            .iter()
            .filter(|candidate| !is_credential_context_header(candidate))
            .count();
        hasher.count(
            "caller.origin_names",
            CREDENTIAL_CONTEXT_HEADERS.len() + custom_count,
        );
        for candidate in CREDENTIAL_CONTEXT_HEADERS {
            hasher.text("caller.origin_credential_name", candidate);
            hasher.count(
                "caller.origin_credential_lines",
                ctx.raw_header_value_bytes(candidate).count(),
            );
            for line in ctx.raw_header_value_bytes(candidate) {
                present = true;
                hasher.nested("caller.origin_credential_digest", &bytes_digest(line));
            }
        }
        for candidate in ctx
            .request_headers_requiring_redaction()
            .iter()
            .filter(|candidate| !is_credential_context_header(candidate))
        {
            hasher.text("caller.origin_credential_name", candidate);
            hasher.count(
                "caller.origin_credential_lines",
                ctx.raw_header_value_bytes(candidate).count(),
            );
            for line in ctx.raw_header_value_bytes(candidate) {
                present = true;
                hasher.nested("caller.origin_credential_digest", &bytes_digest(line));
            }
        }
    }

    // Query credentials are captured before authentication and transformer
    // stripping in a private RequestContext field. Their raw values never enter
    // public metadata or the key preimage; only these one-way digests do.
    hasher.count(
        "caller.origin_query_credentials",
        ctx.query_credential_partition_digests().len(),
    );
    for (name, digest) in ctx.query_credential_partition_digests() {
        hasher.text("caller.origin_query_credential_name", name);
        hasher.nested("caller.origin_query_credential_digest", digest);
        present = true;
    }
    present
}

/// Append the caller-authorization dimension of the replay partition.
///
/// Authenticated callers are bound to a *context* fingerprint — mechanism,
/// resolved identity, consumer, peer SPIFFE identity, and a digest of every
/// credential actually presented — rather than to a display subject, so
/// two tokens with the same `sub` and different scopes never share a retained
/// result.
///
/// Two credential views are bound under separate provenance labels:
///
/// * `caller.credential_*` — the **live, backend-visible** view passed in
///   `request_headers`, which is what the origin will actually receive;
/// * `caller.origin_credential_*` — the **pristine inbound wire** view retained
///   by `RequestContext`, which an earlier route-dispatch plugin cannot rewrite.
///
/// Binding only the live view would let `ai_stream_router` — which strips the
/// client credential and injects the provider's before the post-routing replay
/// plugins run — collapse two distinct client tokens onto one partition.
///
/// A caller counts as **authenticated** when it resolved a gateway identity or
/// peer SPIFFE identity, *or* when a candidate credential header/query value is
/// present in either retained view. Reading only the live header view would
/// misclassify a caller whose credential an earlier plugin consumed as
/// anonymous, and an anonymous classification is what unlocks the
/// [`AnonymousCallerScope::Shared`] opt-out.
///
/// Every caller, authenticated or not, additionally binds its canonical peer
/// address: Ferrum regenerates `X-Forwarded-For` on the backend hop for
/// authenticated callers too, so the origin can vary policy or content by it
/// independently of the credential. [`AnonymousCallerScope::Shared`] is the
/// operator's attestation that it does not, and it applies to anonymous callers
/// only. A caller whose canonical address cannot be derived is refused.
///
/// `request_headers` must be the same header view the plugin will use for the
/// rest of the key (the `before_proxy` `headers` parameter, or a restored
/// snapshot of it), never a stale `ctx.headers` alone.
pub fn append_caller_partition(
    hasher: &mut PartitionHasher,
    ctx: &RequestContext,
    request_headers: &HashMap<String, String>,
    anonymous_scope: AnonymousCallerScope,
) -> Result<(), PartitionRefusal> {
    // Credential material present on this request, canonicalized to a lowercase
    // name and reduced to a digest. The candidates combine the conservative
    // built-in set with custom locations precomputed by the plugin cache.
    //
    // Hot path: one hash lookup per candidate. Protocol header maps are already
    // lowercase, so the case-insensitive sweep below is gated on a name
    // actually carrying an uppercase byte (only plugin-synthesised keys do) and
    // never scans the map for an ordinary request.
    let has_uppercase_name = request_headers
        .keys()
        .any(|name| name.bytes().any(|byte| byte.is_ascii_uppercase()));
    let lookup = |candidate: &str| {
        request_headers.get(candidate).or_else(|| {
            has_uppercase_name
                .then(|| {
                    request_headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(candidate))
                        .map(|(_, value)| value)
                })
                .flatten()
        })
    };

    let mut credentials: Vec<(&str, [u8; 32])> = Vec::new();
    for candidate in CREDENTIAL_CONTEXT_HEADERS {
        if let Some(value) = lookup(candidate) {
            credentials.push((*candidate, value_digest(value)));
        }
    }
    for candidate in ctx
        .request_headers_requiring_redaction()
        .iter()
        .filter(|candidate| !is_credential_context_header(candidate))
    {
        if let Some(value) = lookup(candidate) {
            credentials.push((candidate.as_str(), value_digest(value)));
        }
    }
    credentials.sort_by(|left, right| left.0.cmp(right.0).then(left.1.cmp(&right.1)));

    // Bind the pristine inbound view first, because whether it carried a
    // credential is an input to the authenticated/anonymous classification
    // below. A credential that was present on the wire but consumed or removed
    // by an earlier plugin (`key_auth` strips its key header, `ai_stream_router`
    // replaces the client token with the provider's) is invisible in
    // `request_headers` and in `effective_identity()` when that plugin resolved
    // no gateway identity. Classifying such a caller as *anonymous* would let
    // `anonymous_caller_scope: shared` drop its canonical-address binding — the
    // one relaxation that is supposed to apply to callers who presented nothing.
    // Presence in *either* view is therefore authentication for partitioning
    // purposes. Only the digest is bound; no credential byte is retained,
    // logged, or written to metadata.
    let origin_credential_present = append_original_credential_context(hasher, ctx);

    let identity = ctx.effective_identity();
    let peer_spiffe_id = ctx.peer_spiffe_id.as_ref().map(|id| id.as_str());
    let authenticated = identity.is_some()
        || peer_spiffe_id.is_some()
        || !credentials.is_empty()
        || origin_credential_present;

    hasher.text(
        "caller.class",
        if authenticated {
            "authenticated"
        } else {
            "anonymous"
        },
    );
    hasher.optional_text("caller.auth_method", ctx.auth_method);
    hasher.optional_text("caller.identity", identity);
    hasher.optional_text(
        "caller.consumer_id",
        ctx.identified_consumer.as_ref().map(|c| c.id.as_str()),
    );
    hasher.optional_text(
        "caller.identity_header",
        ctx.authenticated_identity_header.as_deref(),
    );
    hasher.optional_text("caller.peer_spiffe_id", peer_spiffe_id);
    hasher.count("caller.credentials", credentials.len());
    for (name, digest) in &credentials {
        hasher.text("caller.credential_name", name);
        hasher.nested("caller.credential_digest", digest);
    }

    if authenticated {
        // The origin observes this caller's regenerated forwarding identity
        // regardless of how it authenticated, so the address is bound here too
        // and no operator attestation relaxes it.
        hasher.text("caller.address_scope", "authenticated_caller_address");
        return append_canonical_address(
            hasher,
            ctx,
            PartitionRefusal::AuthenticatedCallerAddressUnavailable,
        );
    }

    match anonymous_scope {
        AnonymousCallerScope::Shared => {
            hasher.text("caller.address_scope", "shared");
            Ok(())
        }
        AnonymousCallerScope::CallerAddress => {
            hasher.text("caller.address_scope", "caller_address");
            append_canonical_address(
                hasher,
                ctx,
                PartitionRefusal::AnonymousCallerAddressUnavailable,
            )
        }
    }
}

/// Append the effective destination dimension: the route/provider the *current*
/// request would reach, after every route-dispatch plugin has run.
///
/// Callers must invoke this only once route selection is final for the request
/// (or once they have refused composition with anything that could still change
/// it). Proxy *absence* is framed explicitly rather than defaulted to a sentinel,
/// so an unmatched request can never share a partition with a matched one.
pub fn append_destination_partition(hasher: &mut PartitionHasher, ctx: &RequestContext) {
    let Some(proxy) = ctx.matched_proxy.as_ref() else {
        hasher.bool_value("dst.matched_proxy", false);
        // A route-dispatch override is the only destination signal an unmatched
        // context carries, and it is attacker-reachable through the
        // header/host selectors those plugins read. Binding it here too keeps
        // the "different destination, different partition" rule from silently
        // degrading to "no partition at all" whenever proxy matching is absent.
        append_route_override_partition(hasher, ctx);
        return;
    };
    hasher.bool_value("dst.matched_proxy", true);

    hasher.text("dst.proxy_id", &proxy.id);
    hasher.text("dst.proxy_namespace", &proxy.namespace);
    hasher.optional_text("dst.listen_path", proxy.listen_path.as_deref());

    match ctx.effective_upstream_id(proxy) {
        Some(upstream_id) => {
            hasher.text("dst.kind", "upstream");
            hasher.text("dst.upstream_id", upstream_id);
        }
        None => {
            hasher.text("dst.kind", "direct");
            hasher.text("dst.backend_host", ctx.effective_backend_host(proxy));
            hasher.u64_value(
                "dst.backend_port",
                u64::from(ctx.effective_backend_port(proxy)),
            );
            let scheme = ctx
                .route_override_backend_scheme
                .or(proxy.backend_scheme)
                .map(|scheme| scheme.to_scheme_str());
            hasher.optional_text("dst.backend_scheme", scheme);
        }
    }

    append_route_override_partition(hasher, ctx);
}

/// Append the route-dispatch override dimension.
///
/// Shared by both arms of [`append_destination_partition`] so an override is
/// never bound on one path and dropped on the other. The backend host/port/
/// scheme/upstream overrides are framed here as well as through
/// `effective_*`, because the matched-proxy arm resolves them against the proxy
/// while the unmatched arm has nothing to resolve against.
fn append_route_override_partition(hasher: &mut PartitionHasher, ctx: &RequestContext) {
    hasher.optional_text("dst.authority", ctx.route_override_authority.as_deref());
    hasher.optional_text("dst.rewrite_path", ctx.route_override_path.as_deref());
    hasher.bool_value(
        "dst.rewrite_path_is_absolute",
        ctx.route_override_path_is_absolute,
    );
    hasher.optional_text(
        "dst.override_upstream_id",
        ctx.route_override_upstream_id.as_deref(),
    );
    hasher.optional_text(
        "dst.override_backend_host",
        ctx.route_override_backend_host.as_deref(),
    );
    hasher.bool_value(
        "dst.override_backend_port_set",
        ctx.route_override_backend_port.is_some(),
    );
    hasher.u64_value(
        "dst.override_backend_port",
        u64::from(ctx.route_override_backend_port.unwrap_or(0)),
    );
    let override_scheme = ctx
        .route_override_backend_scheme
        .map(|scheme| scheme.to_scheme_str());
    hasher.optional_text("dst.override_backend_scheme", override_scheme);
}

/// Append the backend-visible request *target* dimension: original client
/// authority, `Host`, method, path, and the effective outbound query.
///
/// This is the target half every replay plugin needs. The shared HTTP cache
/// calls it through [`append_response_cache_request_partition`], which also
/// binds every origin-visible request header except the narrow entry-operation
/// set that cache actually implements; its complete `Vary` tuple is an
/// additional dimension — see [`crate::plugins::response_caching`].
///
/// `request_headers` must be the finalized backend-visible header view — the
/// map the proxy will send — not `ctx.headers`.
pub fn append_request_target_partition(
    hasher: &mut PartitionHasher,
    ctx: &RequestContext,
    request_headers: &HashMap<String, String>,
) {
    // Original client-facing authority, independent of any `route_override_*`
    // rewrite the destination partition binds. Multi-host proxies must not
    // collide even when they resolve to one backend.
    hasher.optional_text("req.authority", ctx.request_authority.as_deref());
    hasher.optional_text(
        "req.host",
        request_headers
            .get("host")
            .map(|host| host.to_ascii_lowercase())
            .as_deref(),
    );
    hasher.text("req.method", &ctx.method);
    hasher.text("req.path", &ctx.path);
    // The query the backend will actually receive. `request_transformer`
    // publishes its rewritten query on the context, and `Some("")` (every pair
    // removed) is distinct from `None` (no transform ran), so the transform
    // flag is framed alongside the value. Falls back to the raw wire query
    // exactly as received: no parsing, sorting, or percent-decoding, so two
    // spellings the origin can distinguish stay distinguishable.
    let transformed_query = ctx.outbound_query_string();
    hasher.bool_value("req.query_transformed", transformed_query.is_some());
    hasher.optional_text(
        "req.query",
        transformed_query.or_else(|| ctx.raw_query_string()),
    );
}

/// Append the backend-visible request-context dimension: the request target
/// ([`append_request_target_partition`]) plus the live header view.
///
/// This exists for plugins whose own key is derived from a request *body* and
/// therefore does not already bind the request line and headers the way
/// `response_caching` does. Without it, two requests differing only in a tenancy
/// header or a query parameter share one retained representation even though the
/// origin sees both differences.
///
/// Framing rules:
///
/// * headers are sorted by name so map iteration order cannot change the digest,
///   and the pair count is bound ahead of the pairs;
/// * a header classified by [`is_request_credential_context_header`] contributes a
///   SHA-256 digest of its value, never the value — no secret enters the digest
///   preimage in cleartext, a key, metadata, a log line, or a diagnostic;
/// * only [`is_non_backend_visible_request_header`] names are excluded — the
///   hop-by-hop/framing fields Ferrum provably regenerates for the backend hop,
///   with `host`/authority bound as their own fields above. Tracing and
///   correlation headers are *not* excluded; they reach the origin.
///
/// `request_headers` must be the finalized backend-visible header view — the
/// map the proxy will send — not `ctx.headers`.
pub fn append_request_context_partition(
    hasher: &mut PartitionHasher,
    ctx: &RequestContext,
    request_headers: &HashMap<String, String>,
) {
    append_filtered_request_context_partition(hasher, ctx, request_headers, |_, _| false);
}

/// Append the request context used by `response_caching`.
///
/// Unlike an RFC cache's optional `Vary` optimization, this fail-closed
/// partition binds every origin-visible header that could select tenant or
/// policy state. Only headers whose entry-addressing semantics
/// `response_caching` actually implements are omitted:
///
/// * `If-None-Match` / `If-Modified-Since` — fresh conditional HIT → 304
/// * pure honored request `Cache-Control: no-cache` / `no-store` (bare
///   directives with no arguments, and only when every meaningful member is
///   such a refresh) — when `respect_no_cache` is enabled, bypass + store the
///   replacement under the same partition as the entry being refreshed
/// * `Content-Length` — zero-length framing on an otherwise empty GET/HEAD
///
/// Unsupported precondition / cache-directive dimensions (`If-Match`,
/// `If-Unmodified-Since`, `If-Range`, `Range`, `Pragma`, mixed / arbitrary /
/// unrecognized `Cache-Control` content, and any `Cache-Control` when
/// `respect_no_cache` is false) stay bound so they cannot share a replay key
/// with a request that did not carry them. Labeling unimplemented semantics
/// as "cache operations" would let a fresh HIT ignore a client precondition.
pub fn append_response_cache_request_partition(
    hasher: &mut PartitionHasher,
    ctx: &RequestContext,
    request_headers: &HashMap<String, String>,
    respect_no_cache: bool,
) {
    append_filtered_request_context_partition(hasher, ctx, request_headers, |name, value| {
        is_response_cache_entry_operation_header(name, value, respect_no_cache)
    });
}

/// Whether `name`/`value` is an entry-operation header this response cache
/// safely omits from the request-header partition.
///
/// Name-only exemptions are limited to validators and framing this
/// plugin handles. `Cache-Control` is value-aware and gated by
/// `respect_no_cache`: only a pure honored bare `no-cache` / `no-store` refresh
/// (every meaningful member is such a refresh and has no argument) is omitted
/// so a replacement remains addressable under the original partition. Mixed
/// recognized refresh plus any other member, argument-bearing directives, and
/// any `Cache-Control` when the plugin will not honor request no-cache/no-store
/// as an entry operation stay bound.
fn is_response_cache_entry_operation_header(
    name: &str,
    value: &str,
    respect_no_cache: bool,
) -> bool {
    if name.eq_ignore_ascii_case("if-none-match") || name.eq_ignore_ascii_case("if-modified-since")
    {
        return true;
    }
    if name.eq_ignore_ascii_case("content-length") {
        return !value.contains(',')
            && matches!(parse_content_length(value), ContentLength::Exact(0));
    }
    respect_no_cache
        && name.eq_ignore_ascii_case("cache-control")
        && request_cache_control_is_pure_honored_refresh(value)
}

/// True when every meaningful request `Cache-Control` member is a refresh
/// this cache implements as a standard request operation (bare `no-cache` /
/// `no-store` with no argument), and at least one such member exists.
///
/// The broader cache-control parser deliberately degrades malformed or
/// argument-bearing `no-cache` spellings to a bypass, but they remain bound
/// here: their argument is backend-visible context and is not part of the
/// standard request directive. Presence of any argument, other directive, or
/// extension — including `max-age=0` beside `no-cache` — means the full value
/// remains partitioned. Empty / whitespace-only values are not refreshes.
fn request_cache_control_is_pure_honored_refresh(header_value: &str) -> bool {
    let bytes = header_value.as_bytes();
    let mut index = 0usize;
    let mut saw_refresh = false;

    while index < bytes.len() {
        while matches!(bytes.get(index), Some(b',' | b' ' | b'\t')) {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }

        let name_start = index;
        while !matches!(bytes.get(index), None | Some(b'=' | b',')) {
            index += 1;
        }
        let Some(name) = header_value.get(name_start..index).map(str::trim) else {
            return false;
        };
        if name.is_empty() {
            // `=…` without a directive name is not a recognized refresh.
            if bytes.get(index) == Some(&b'=') {
                return false;
            }
            continue;
        }

        if !name.eq_ignore_ascii_case("no-cache") && !name.eq_ignore_ascii_case("no-store") {
            return false;
        }

        if bytes.get(index) == Some(&b'=') {
            return false;
        }

        saw_refresh = true;
    }

    saw_refresh
}

fn append_filtered_request_context_partition(
    hasher: &mut PartitionHasher,
    ctx: &RequestContext,
    request_headers: &HashMap<String, String>,
    excluded: impl Fn(&str, &str) -> bool,
) {
    append_request_target_partition(hasher, ctx, request_headers);

    let mut names: Vec<&str> = request_headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str();
            if is_non_backend_visible_request_header(name) || excluded(name, value) {
                None
            } else {
                Some(name)
            }
        })
        .collect();
    names.sort_unstable();
    hasher.count("req.headers", names.len());
    for name in names {
        hasher.text("req.header_name", name);
        // `names` came from this map's keys, so the lookup always resolves.
        let value = request_headers.get(name).map(String::as_str).unwrap_or("");
        if is_request_credential_context_header(ctx, name) {
            hasher.bool_value("req.header_is_credential", true);
            hasher.nested("req.header_digest", &value_digest(value));
        } else {
            hasher.bool_value("req.header_is_credential", false);
            hasher.text("req.header_value", value);
        }
    }
}
