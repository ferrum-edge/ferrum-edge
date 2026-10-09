//! Request-time proxy hop limit (issue #6109).
//!
//! A route whose upstream resolves back to the gateway itself — a control
//! plane that admitted a self-referencing target, or DNS that changed after
//! publication — turns every client request into an unbounded request loop.
//! The gateway therefore carries its own hop count on every HTTP-family
//! request it forwards, in the gateway-owned `X-Ferrum-Hops` request header,
//! and refuses a request that already crossed `FERRUM_MAX_PROXY_HOPS` gateway
//! hops with `508 Loop Detected` (gRPC: Trailers-Only `FAILED_PRECONDITION`,
//! which clients do not retry by convention: the refusal is deterministic).
//!
//! The decision is taken ONCE per inbound request at the frontend, before
//! routing or any plugin runs, by both frontends: the H1/H2 handler (which
//! also serves gRPC and the HTTP/1.1 and RFC 8441 WebSocket upgrades) and the
//! native HTTP/3 handler (gRPC, the H3 bridge, and RFC 9220 WebSocket). The
//! frontend stamps `received + 1` over the client's raw header block before
//! it is stored on the request context, so every backend builder — reqwest,
//! direct HTTP/2, native gRPC (raw-map merge), the HTTP/3 client and bridge,
//! WebSocket handshakes, HBONE / mesh-mTLS replay, retries — forwards the
//! incremented count and the client's own value never reaches a backend. A
//! client can only RAISE the count, never reset it.
//!
//! The count is re-asserted on the outbound header map after the request-phase
//! plugins run, inside every later gateway-assertion refresh (the deferred
//! `before_proxy` passes and the finalized-egress header overlay, through
//! `refresh_backend_gateway_assertion_headers`), AND at the end of every final
//! backend-header-policy hook pass (`run_final_backend_header_policy_hooks`),
//! so no plugin output — built-in or custom, including a `serverless_function`
//! `pre_proxy` header copy — can reset it before dispatch.
//!
//! Mesh inbound exception: a mesh inbound hop that forwards to the LOCAL
//! workload through a materialized mesh inbound route (Sidecar inbound or
//! `ingress[]` loopback routes) still CHECKS the received count but forwards
//! it unchanged ([`effective_outbound_proxy_hops`]), so one service call costs
//! one hop (its outbound side) instead of two. Termination is preserved: such
//! a route leaves the gateway only for the local application, and anything
//! the application sends onward re-enters through an incrementing hop. That
//! holds only while the route's loopback target is NOT a port this gateway
//! itself listens on, so the exemption also requires the backend port to be
//! absent from the published [`GatewayListenerPorts`] snapshot (and fails
//! closed — increments — before one is published). The mesh materializer
//! additionally refuses an `ingress[]` `defaultEndpoint` or inbound
//! `targetPort` that names a gateway listener port. Every other route on an
//! inbound listener — a plugin route override, an EgressGateway external
//! route, an operator route, a loopback target on any gateway listener port —
//! increments as usual.
//!
//! Field-value policy (documented in `docs/routing.md`):
//!
//! - The value is `1*DIGIT` with optional surrounding whitespace, read as an
//!   unsigned decimal that saturates instead of overflowing.
//! - An absent field is hop `0`.
//! - A malformed field — empty, signed, fractional, non-decimal, or repeated
//!   (more than one field line) — is REFUSED with `400 Bad Request` (gRPC:
//!   `INVALID_ARGUMENT`; rejection phase [`PROXY_HOPS_INVALID_REJECTION_PHASE`],
//!   no `X-Gateway-Error` token) rather than treated as `0`: the gateway never
//!   writes a malformed value itself, so one can only come from a client or a
//!   foreign intermediary, and resetting it would let a loop through an
//!   intermediary that mangles the field run unbounded.
//! - `FERRUM_MAX_PROXY_HOPS=0` disables the whole feature: no refusal, and the
//!   field is neither parsed nor written (a client value passes through as an
//!   ordinary header).
//!
//! Stream proxies (`tcp`, `tcp_tls`, `udp`, `dtls`) relay opaque bytes and
//! carry no request headers, so the limit does not apply to them.
//!
//! Plugin calls (issue #6128): an HTTP call a plugin makes on behalf of the
//! current request — a serverless function, an MCP upstream, an AI provider or
//! classifier, a policy / introspection / ext_authz service, an OIDC token
//! endpoint, a mirror or load-test replay — carries the same forwarded count
//! through [`stamp_plugin_call_proxy_hops`], so a plugin target that resolves
//! back to a Ferrum gateway is refused at the same limit. Batch and background
//! sinks and shared cache refreshes are not request-scoped and carry none.
//!
//! The stamp adds (at most) one field AFTER the frontend's
//! `FERRUM_MAX_HEADER_COUNT` / header-size limits were checked, like the
//! gateway's own `X-Forwarded-*` fields: a request exactly at the count limit
//! can therefore be refused with `431` at the next Ferrum hop that enforces
//! the same limit.
//!
//! Hot path: the decision is one `HeaderMap` lookup by a pre-built
//! `HeaderName` plus a bounded digit scan, and stamping inserts a pre-built
//! `HeaderValue` backed by static bytes — no allocation and no shared
//! reference count (cloning a `from_static` value copies a pointer). The mesh
//! inbound exemption reads the listener-port snapshot with one lock-free
//! `ArcSwap::load()` and one bit test, and only for a mesh inbound route.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwapOption;

use crate::config::types::HttpFlavor;
use crate::plugins::RequestContext;

/// Lowercase wire name of the gateway-owned hop-count request header.
pub const PROXY_HOPS_HEADER: &str = "x-ferrum-hops";

/// Default `FERRUM_MAX_PROXY_HOPS`.
pub const DEFAULT_MAX_PROXY_HOPS: u8 = 10;

/// Rejection-phase label of the `508 Loop Detected` refusal. It is a
/// diagnostic-reference fence phase and the only phase that maps to the
/// `loop_detected` metrics token.
pub const PROXY_HOP_LIMIT_REJECTION_PHASE: &str = "proxy_hop_limit";

/// Rejection-phase label of the malformed / repeated `X-Ferrum-Hops` `400`.
/// A diagnostic-reference fence phase of its own that maps to NO
/// `X-Gateway-Error` or metrics token: the request is client-caused.
pub const PROXY_HOPS_INVALID_REJECTION_PHASE: &str = "proxy_hops_invalid";

/// Client-visible body of the `508 Loop Detected` refusal.
pub const LOOP_DETECTED_BODY: &str = r#"{"error":"Proxy hop limit exceeded"}"#;

/// gRPC status message of the loop refusal.
pub const LOOP_DETECTED_GRPC_MESSAGE: &str = "Proxy hop limit exceeded";

/// Client-visible body when `X-Ferrum-Hops` cannot be read as one decimal.
pub const INVALID_PROXY_HOPS_BODY: &str = r#"{"error":"Invalid X-Ferrum-Hops header"}"#;

/// gRPC status message of the malformed-field refusal.
pub const INVALID_PROXY_HOPS_GRPC_MESSAGE: &str = "Invalid X-Ferrum-Hops header";

/// [`PROXY_HOPS_HEADER`] as a pre-built `HeaderName`. A `static` rather than a
/// `const`: the custom name holds a `Bytes`, and a `const` would be an
/// interior-mutable constant copied at every use.
static PROXY_HOPS_HEADER_NAME: http::HeaderName = http::HeaderName::from_static(PROXY_HOPS_HEADER);

/// Decimal spellings of `0..=255`, indexed by hop count.
const PROXY_HOPS_LITERALS: [&str; 256] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16",
    "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32",
    "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48",
    "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64",
    "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80",
    "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96",
    "97", "98", "99", "100", "101", "102", "103", "104", "105", "106", "107", "108", "109", "110",
    "111", "112", "113", "114", "115", "116", "117", "118", "119", "120", "121", "122", "123",
    "124", "125", "126", "127", "128", "129", "130", "131", "132", "133", "134", "135", "136",
    "137", "138", "139", "140", "141", "142", "143", "144", "145", "146", "147", "148", "149",
    "150", "151", "152", "153", "154", "155", "156", "157", "158", "159", "160", "161", "162",
    "163", "164", "165", "166", "167", "168", "169", "170", "171", "172", "173", "174", "175",
    "176", "177", "178", "179", "180", "181", "182", "183", "184", "185", "186", "187", "188",
    "189", "190", "191", "192", "193", "194", "195", "196", "197", "198", "199", "200", "201",
    "202", "203", "204", "205", "206", "207", "208", "209", "210", "211", "212", "213", "214",
    "215", "216", "217", "218", "219", "220", "221", "222", "223", "224", "225", "226", "227",
    "228", "229", "230", "231", "232", "233", "234", "235", "236", "237", "238", "239", "240",
    "241", "242", "243", "244", "245", "246", "247", "248", "249", "250", "251", "252", "253",
    "254", "255",
];

/// Pre-built values `0..=255` backed by the static literals above, so stamping
/// a hop count clones a `HeaderValue` whose bytes are `'static`: no per-request
/// formatting and no shared reference count touched by every worker.
static PROXY_HOPS_VALUES: LazyLock<[http::HeaderValue; 256]> = LazyLock::new(proxy_hops_values);

fn proxy_hops_values() -> [http::HeaderValue; 256] {
    std::array::from_fn(proxy_hops_value)
}

fn proxy_hops_value(hops: usize) -> http::HeaderValue {
    // `hops < 256` by construction of the table.
    http::HeaderValue::from_static(PROXY_HOPS_LITERALS[hops])
}

/// Outcome of the hop-limit check for one inbound request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyHopDecision {
    /// `FERRUM_MAX_PROXY_HOPS=0`: nothing is checked or written.
    Disabled,
    /// Forward the request carrying this hop count (`received + 1`).
    Forward(u8),
    /// The received count already reached the limit: `508 Loop Detected`.
    LoopDetected,
    /// The field is present but not one valid decimal: `400 Bad Request`.
    Malformed,
}

/// Parse an `X-Ferrum-Hops` field value as `1*DIGIT`, tolerating surrounding
/// spaces and tabs and saturating at `u32::MAX`. Anything else (empty, sign,
/// separator, fraction, a comma-folded list) is `None`. Allocation-free.
pub fn parse_proxy_hops(value: &[u8]) -> Option<u32> {
    let digits = value.trim_ascii();
    if digits.is_empty() {
        return None;
    }
    let mut total: u32 = 0;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        // Keep validating every byte after saturating, so an oversized value
        // followed by garbage is still malformed.
        total = total
            .saturating_mul(10)
            .saturating_add(u32::from(byte - b'0'));
    }
    Some(total)
}

/// Decide the hop-limit outcome for an inbound request's raw header block.
///
/// `max_hops` is `FERRUM_MAX_PROXY_HOPS`; `0` disables the check. A request
/// whose received count is `>= max_hops` is refused, so with the default `10`
/// a request is forwarded at most ten times through Ferrum gateways.
pub fn decide_proxy_hops(headers: &http::HeaderMap, max_hops: u8) -> ProxyHopDecision {
    if max_hops == 0 {
        return ProxyHopDecision::Disabled;
    }
    let mut values = headers.get_all(&PROXY_HOPS_HEADER_NAME).iter();
    let received = match values.next() {
        None => 0,
        Some(first) => {
            // The field is a single count, not a list (RFC 9110 §5.3): two
            // field lines are malformed, never "pick one".
            if values.next().is_some() {
                return ProxyHopDecision::Malformed;
            }
            match parse_proxy_hops(first.as_bytes()) {
                Some(received) => received,
                None => return ProxyHopDecision::Malformed,
            }
        }
    };
    if received >= u32::from(max_hops) {
        return ProxyHopDecision::LoopDetected;
    }
    // `received < max_hops <= 255`, so the increment always fits.
    match u8::try_from(received.saturating_add(1)) {
        Ok(next) => ProxyHopDecision::Forward(next),
        Err(_) => ProxyHopDecision::LoopDetected,
    }
}

/// Replace every client field line of `X-Ferrum-Hops` with the gateway's
/// forwarded count. Allocation-free: the name and value are pre-built.
pub fn stamp_proxy_hops(headers: &mut http::HeaderMap, hops: u8) {
    headers.insert(
        PROXY_HOPS_HEADER_NAME.clone(),
        PROXY_HOPS_VALUES[usize::from(hops)].clone(),
    );
}

/// Whether `name` is the gateway-owned hop-count field, ASCII
/// case-insensitive with `_` equivalent to `-` (the folding CGI-style
/// backends apply). Plugin configuration that would write, rename, or remove
/// it is refused at admission, so no configured header rule can reset the
/// count a later gateway hop reads.
#[inline]
pub fn is_proxy_hops_header(name: &str) -> bool {
    crate::proxy::headers::field_names_equivalent_for_backends(name, PROXY_HOPS_HEADER)
}

/// The `X-Ferrum-Hops` count a request-scoped plugin call made on behalf of
/// `ctx` carries, or `None` when the limit is disabled.
///
/// Always the frontend's forwarded count (`received + 1`), never the mesh
/// inbound exemption of [`effective_outbound_proxy_hops`]: a plugin call goes
/// to a plugin-configured target, not to the local workload, so it is an
/// ordinary gateway hop. A request refused at the limit never reaches a
/// plugin, so the value is at most `FERRUM_MAX_PROXY_HOPS`.
#[inline]
pub fn plugin_call_proxy_hops(ctx: &RequestContext) -> Option<u8> {
    ctx.outbound_proxy_hops
}

/// Stamp the gateway's hop count on a request-scoped plugin HTTP call.
///
/// The ONE helper every plugin call made on behalf of the current request goes
/// through: `serverless_function`, `mcp_gateway` upstream session and
/// discovery calls, `ai_federation` provider calls, `opa`,
/// `oauth2_introspection`, `mesh_authz` `CUSTOM` (ext_authz) checks,
/// `oidc_relying_party` token / revocation / UserInfo calls, the
/// `ai_semantic_firewall` / `ai_semantic_cache` embedding calls, the
/// `ai_tool_governor` approval webhook, `request_mirror`, and `load_testing`
/// replays and fan-out. A plugin target that resolves back to a Ferrum gateway
/// is therefore refused at the same `FERRUM_MAX_PROXY_HOPS` limit as a looping
/// route. `hops` is [`plugin_call_proxy_hops`], captured before the call leaves
/// the request task. `None` (limit disabled) leaves the request untouched.
///
/// The field is appended, so a caller that forwards a copied header set must
/// drop the copied hop field first ([`strip_copied_proxy_hops`]).
/// Allocation-free: the name and value are the pre-built static ones.
///
/// Not request-scoped, so carrying no hop count: batch and background sinks
/// (`http_logging`, `loki_logging`, `otel_tracing`, `api_chargeback_sink`,
/// `ai_transcript_audit`'s collector, notification webhooks) and shared,
/// coalesced cache refreshes that outlive the request which triggered them
/// (JWKS and OIDC / OAuth discovery, the `ai_federation` Vertex token grant,
/// the `spec_expose` document fetch).
#[inline]
pub fn stamp_plugin_call_proxy_hops(
    request: reqwest::RequestBuilder,
    hops: Option<u8>,
) -> reqwest::RequestBuilder {
    match hops {
        Some(hops) => request.header(
            PROXY_HOPS_HEADER_NAME.clone(),
            PROXY_HOPS_VALUES[usize::from(hops)].clone(),
        ),
        None => request,
    }
}

/// Drop every copied `X-Ferrum-Hops` spelling from a header list a plugin
/// forwards on a secondary request, so [`stamp_plugin_call_proxy_hops`] leaves
/// exactly one field line (two would be refused as malformed by the next
/// Ferrum hop). With the limit disabled (`hops == None`) a client value passes
/// through as an ordinary header. Allocation-free.
pub fn strip_copied_proxy_hops(headers: &mut Vec<(String, String)>, hops: Option<u8>) {
    if hops.is_some() {
        headers.retain(|(name, _)| !is_proxy_hops_header(name));
    }
}

/// Every port this gateway process listens on, as a fixed 65,536-bit set:
/// one bit test per lookup, no hashing, no allocation.
///
/// The mesh runtime builds it on the cold path (startup and every accepted
/// slice apply) from the mesh listener plan, the admin listeners, every proxy
/// `listen_port` (Gateway listeners, stream listeners, dedicated Sidecar
/// `ingress[]` binds), and the dedicated bind overrides, then publishes it
/// with [`publish_gateway_listener_ports`].
/// [`effective_outbound_proxy_hops`] consults it so a mesh inbound route whose
/// loopback target is another gateway listener still increments the count.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayListenerPorts {
    bits: Box<[u64; 1024]>,
}

impl GatewayListenerPorts {
    /// Build the set from `ports`. Port `0` (a disabled listener) is ignored.
    pub fn from_ports<I: IntoIterator<Item = u16>>(ports: I) -> Self {
        let mut bits = Box::new([0u64; 1024]);
        for port in ports {
            if port != 0 {
                bits[usize::from(port >> 6)] |= 1u64 << (port & 63);
            }
        }
        Self { bits }
    }

    /// Whether the gateway listens on `port`. Port `0` is never a listener.
    #[inline]
    pub fn contains(&self, port: u16) -> bool {
        port != 0 && (self.bits[usize::from(port >> 6)] & (1u64 << (port & 63))) != 0
    }

    /// The ports in either set.
    pub fn union(&self, other: &Self) -> Self {
        let mut bits = self.bits.clone();
        for (word, other_word) in bits.iter_mut().zip(other.bits.iter()) {
            *word |= *other_word;
        }
        Self { bits }
    }

    /// Number of ports in the set.
    pub fn len(&self) -> usize {
        self.bits
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    /// Whether the set holds no port.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|word| *word == 0)
    }
}

impl std::fmt::Debug for GatewayListenerPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayListenerPorts")
            .field("len", &self.len())
            .finish()
    }
}

/// The published listener-port snapshot. `None` until a serving runtime
/// publishes one; the mesh inbound exemption then fails closed (increments).
static GATEWAY_LISTENER_PORTS: ArcSwapOption<GatewayListenerPorts> = ArcSwapOption::const_empty();

/// Publish (or, with `None`, withdraw) the gateway's listener-port snapshot.
/// Cold path: called by the mesh runtime at startup and around every slice
/// apply. In-flight requests see the previous or the new snapshot, never a
/// partial one.
pub fn publish_gateway_listener_ports(ports: Option<Arc<GatewayListenerPorts>>) {
    GATEWAY_LISTENER_PORTS.store(ports);
}

/// The currently published listener-port snapshot, if any. Cold path.
pub fn gateway_listener_ports() -> Option<Arc<GatewayListenerPorts>> {
    GATEWAY_LISTENER_PORTS.load_full()
}

/// The `X-Ferrum-Hops` value this request forwards, or `None` when the limit
/// is disabled.
///
/// Normally the count the frontend stamped (`received + 1`). A mesh inbound
/// hop that forwards to the LOCAL workload — the request arrived on a mesh
/// inbound listener, matched a materialized mesh inbound route (Sidecar
/// inbound or `ingress[]` loopback route), no plugin overrode the route's
/// destination, and the route's loopback target is neither the accepting
/// listener's own port nor any other port in the published
/// [`GatewayListenerPorts`] snapshot — forwards the RECEIVED count unchanged
/// instead. The received count was still checked against the limit at the
/// frontend. With no snapshot published the hop increments (fail closed).
///
/// Pure function of the request context and the published snapshot, so every
/// re-assertion site (the main dispatch point, each later gateway-assertion
/// refresh, and each final backend-header-policy pass) agrees even when a
/// deferred plugin pass changes the destination. Outside a mesh inbound route
/// it reads no snapshot at all.
pub fn effective_outbound_proxy_hops(ctx: &RequestContext) -> Option<u8> {
    let hops = ctx.outbound_proxy_hops?;
    let Some(backend_port) = local_mesh_workload_backend_port(ctx) else {
        return Some(hops);
    };
    let listener_ports = GATEWAY_LISTENER_PORTS.load();
    Some(forwarded_count(
        hops,
        backend_port,
        listener_ports.as_deref(),
    ))
}

/// [`effective_outbound_proxy_hops`] against an explicit listener-port
/// snapshot instead of the published one (`None` = no snapshot published).
pub fn effective_outbound_proxy_hops_with_listener_ports(
    ctx: &RequestContext,
    listener_ports: Option<&GatewayListenerPorts>,
) -> Option<u8> {
    let hops = ctx.outbound_proxy_hops?;
    let Some(backend_port) = local_mesh_workload_backend_port(ctx) else {
        return Some(hops);
    };
    Some(forwarded_count(hops, backend_port, listener_ports))
}

/// The loopback backend port of a materialized mesh inbound route this
/// request forwards on unchanged, or `None` for every other hop.
fn local_mesh_workload_backend_port(ctx: &RequestContext) -> Option<u16> {
    if ctx.mesh_direction != Some(crate::modes::mesh::MeshTrafficDirection::Inbound) {
        return None;
    }
    if ctx.has_route_overrides() {
        return None;
    }
    let proxy = ctx.matched_proxy.as_deref()?;
    if crate::modes::mesh::is_mesh_inbound_route_id(&proxy.id)
        && proxy.upstream_id.is_none()
        && ctx.frontend_listen_port != Some(proxy.backend_port)
    {
        Some(proxy.backend_port)
    } else {
        None
    }
}

fn forwarded_count(
    hops: u8,
    backend_port: u16,
    listener_ports: Option<&GatewayListenerPorts>,
) -> u8 {
    match listener_ports {
        // `hops = received + 1 >= 1`, so this is exactly `received`.
        Some(ports) if !ports.contains(backend_port) => hops.saturating_sub(1),
        // The target is a gateway listener (or no snapshot is published): the
        // request re-enters a Ferrum hop, so it must count.
        _ => hops,
    }
}

/// Re-assert the gateway's forwarded hop count on the authoritative outbound
/// header map after every request-phase plugin has run.
///
/// `outbound_hops` is [`effective_outbound_proxy_hops`] (`None` when the limit
/// is disabled). `owned_proxy_headers` is the plugin-transformed outbound map
/// when one exists; otherwise `ctx_headers` IS the outbound map.
pub fn reassert_outbound_proxy_hops(
    outbound_hops: Option<u8>,
    owned_proxy_headers: &mut Option<HashMap<String, String>>,
    ctx_headers: &mut HashMap<String, String>,
) {
    let headers = owned_proxy_headers.as_mut().unwrap_or(ctx_headers);
    reassert_outbound_proxy_hops_in_map(outbound_hops, headers);
}

/// [`reassert_outbound_proxy_hops`] on one outbound header map. Also called
/// from every gateway-assertion refresh (deferred `before_proxy` passes and
/// the finalized-egress header overlay), so a header written after the main
/// re-assertion cannot reset the count either.
///
/// Built-in plugins cannot be configured to touch the field, so this is
/// defence in depth: the common request pays one map lookup and one scan of
/// the key lengths. A changed value is rewritten in place (no allocation when
/// the new value is not longer); only a removed field or a case / underscore
/// variant allocates.
pub fn reassert_outbound_proxy_hops_in_map(
    outbound_hops: Option<u8>,
    headers: &mut HashMap<String, String>,
) {
    let Some(hops) = outbound_hops else {
        return;
    };
    let expected = PROXY_HOPS_LITERALS[usize::from(hops)];
    let has_variant = headers.keys().any(|name| {
        name.len() == PROXY_HOPS_HEADER.len()
            && name != PROXY_HOPS_HEADER
            && is_proxy_hops_header(name)
    });
    if has_variant {
        headers.retain(|name, _| name == PROXY_HOPS_HEADER || !is_proxy_hops_header(name));
    }
    match headers.get_mut(PROXY_HOPS_HEADER) {
        Some(value) => {
            if *value != expected {
                value.clear();
                value.push_str(expected);
            }
        }
        None => {
            headers.insert(PROXY_HOPS_HEADER.to_string(), expected.to_string());
        }
    }
}

/// The response flavor a frontend hop-limit refusal is written in.
///
/// gRPC-Web (`grpc_web == true`, the frontend recognized a gRPC-Web content
/// type) gets the plain HTTP answer — the JSON `508` with
/// `X-Gateway-Error: loop_detected`, or the JSON `400` — exactly as on the
/// HTTP/1.1 and HTTP/2 frontend, even where the frontend otherwise treats the
/// request as effective gRPC. Only native gRPC gets Trailers-Only.
#[inline]
pub fn refusal_http_flavor(http_flavor: HttpFlavor, grpc_web: bool) -> HttpFlavor {
    if grpc_web {
        HttpFlavor::Plain
    } else {
        http_flavor
    }
}

/// Rejection phase recorded for a hop-limit refusal: the `508` and the
/// malformed-field `400` are distinct phases, so only the `508` can ever map
/// to the `loop_detected` token.
#[inline]
pub fn refusal_rejection_phase(loop_detected: bool) -> &'static str {
    if loop_detected {
        PROXY_HOP_LIMIT_REJECTION_PHASE
    } else {
        PROXY_HOPS_INVALID_REJECTION_PHASE
    }
}

/// Rate-limits the operator warning for a request refused at the hop limit,
/// so a live loop cannot flood the log with one line per looped request.
static LOOP_DETECTED_WARN: crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter =
    crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter::new();

/// Emit the rate-limited warning for a `508 Loop Detected` refusal. The line
/// names only the configured limit and the frontend protocol — never the
/// received header value, the route, or the client — so it is safe at any
/// volume and cannot echo request data.
pub(crate) fn warn_loop_detected(max_hops: u8, frontend: &'static str) {
    let now_ms = crate::socket_opts::monotonic_now_ms();
    if let Some(suppressed) = LOOP_DETECTED_WARN.on_event(now_ms) {
        tracing::warn!(
            max_proxy_hops = max_hops,
            frontend,
            suppressed,
            "Refused request at the proxy hop limit (508 Loop Detected): a route's upstream \
             likely resolves back to a Ferrum gateway; raise FERRUM_MAX_PROXY_HOPS only if \
             the chain of gateway hops is intentional"
        );
    }
}
