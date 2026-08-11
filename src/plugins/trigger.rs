//! Runtime binding for declarative per-instance plugin execution triggers.
//!
//! The schema, bounds, compiler, and pure evaluator live in
//! [`crate::config::plugin_trigger`]. This module supplies the two things the
//! gateway runtime adds:
//!
//! 1. [`HttpTriggerFacts`] / [`StreamTriggerFacts`] — zero-copy views that bind
//!    a live `RequestContext` / `StreamConnectionContext` to the evaluator's
//!    [`TriggerFacts`] surface.
//! 2. [`PluginTriggerGate`] — the per-instance gate the plugin cache attaches to
//!    a wrapped plugin. It owns the compiled predicate, an opaque process-local
//!    token, and the precomputed bounded metadata key used to report a skip.
//!
//! # Decide-once semantics
//!
//! A trigger is evaluated **at most once per request/connection per instance**
//! and the outcome is memoized on the context. Every later phase of that
//! instance reuses it. That is what makes a skip symmetric: a `before_proxy`
//! rewrite of the path, headers, or query can never flip an instance from
//! "skipped its request hooks" to "runs its response hooks", which would leave
//! half-initialized plugin state behind.
//!
//! # Phase safety
//!
//! A trigger that reads authenticated identity (`consumer`, `auth_method`,
//! `spiffe_id`) is not authoritative before the authentication boundary. Such a
//! trigger simply **does not gate** hooks at or before `authenticate`
//! ([`TriggerPhase::PreAuth`]): the instance runs, and no decision is memoized,
//! so the first `authorize`-or-later hook makes the real decision. Failing
//! toward "run" there is the only fail-closed choice — skipping a guard because
//! its identity input has not been populated yet would widen access.
//!
//! A **stream** connection is that rule taken to its conclusion. Its only gated
//! phase is `on_stream_connect`, and stream authentication (`mtls_auth`) runs
//! inside that same priority-ordered chain, so every gated stream phase is at or
//! before the stream authentication boundary and there is no later phase to
//! defer the real decision to. An identity-reading trigger therefore never gates
//! a stream connection: [`PluginTriggerGate::admits_stream`] returns "run"
//! without memoizing, so `on_stream_disconnect` runs too. The same trigger still
//! gates that instance's HTTP requests normally.
//!
//! When an instance is STREAM-ONLY (`supported_protocols()` carry no
//! HTTP-family protocol), such a trigger could never gate anything at all, so
//! plugin-cache publication refuses it outright rather than accepting an inert
//! predicate. `spiffe_id` deserves the loudest note: a stream connection carries
//! no authoritative peer SPIFFE fact at all (see
//! [`StreamTriggerFacts::spiffe_id`]).
//!
//! # Contextless phases carry the decision
//!
//! Four surfaces run with no context in hand. None of them re-evaluates a
//! predicate; each consumes one decision taken where authoritative facts still
//! existed, in an opaque, non-serialized carrier that only this crate can
//! populate — never the public, plugin-writable `metadata` map:
//!
//! * `on_stream_disconnect` reads `StreamTransactionSummary`, so a false connect
//!   trigger suppresses the disconnect hook too.
//! * `log` / `log_with_mesh_key` read `TransactionSummary`, stamped centrally by
//!   `plugins::log_with_mirror` from the authoritative `RequestContext`.
//! * WebSocket frame, reassembly, delivery, size-limit, and disconnect hooks
//!   read the decision the relay took at upgrade admission, BEFORE the session's
//!   capability set is computed, so a skipped instance forces no framing and no
//!   parser ceiling.
//! * `on_udp_datagram` reads the decision the `on_stream_connect` chain memoized
//!   on the session; the hook list is filtered once at first-datagram admission,
//!   so no predicate runs per packet.
//!
//! In all four, an explicit `false` skips, an explicit `true` runs, and a
//! MISSING decision RUNS while incrementing a bounded, unlabeled invariant
//! counter. Missing state must never become an accidental suppression of a
//! security or audit hook.
//!
//! # Redaction
//!
//! A skip records exactly one bounded metadata pair,
//! `plugin_trigger.<plugin-config-id>.skipped = "true"`. Cardinality is bounded
//! by the configured instance count, and no header, cookie, query value, claim,
//! token, or body byte is ever copied into it or logged.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use percent_encoding::percent_decode_str;

use crate::config::plugin_trigger::{
    CompiledPluginTrigger, FieldVisitor, PluginTrigger, PluginTriggerProtocol, TriggerFacts,
};
use crate::config::types::{HttpFlavor, HttpWireTransport};
use crate::plugins::{
    RequestContext, StreamConnectionContext, StreamFrontendTransport, StreamTransactionSummary,
    StreamTriggerDecisions, TransactionSummary,
};

/// Process-local token generator. Tokens are opaque and never persisted; they
/// only have to be unique among the instances a single request can observe.
static NEXT_TRIGGER_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Fixed-cardinality observability for the contextless decision carriers.
///
/// These are three process-global counters with NO labels at all: no trigger
/// input, no route, no identity, no header value, no plugin-controlled string,
/// and no secret can reach them. They answer only "how often did a carried
/// decision suppress a terminal/session hook" and "how often did a hook run
/// because no decision was carried" (the fail-open compatibility path, which is
/// an invariant signal rather than an error).
static SKIPPED_TERMINAL_LOG_HOOKS: AtomicU64 = AtomicU64::new(0);
static SKIPPED_SESSION_HOOKS: AtomicU64 = AtomicU64::new(0);
static MISSING_DECISION_CARRIERS: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the trigger-carrier counters for the runtime metrics endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct PluginTriggerCarrierCounters {
    /// Terminal `log` / `log_with_mesh_key` invocations suppressed because the
    /// summary carried an explicit `false` decision for that instance.
    pub skipped_terminal_log_hooks: u64,
    /// WebSocket-session / UDP-DTLS-flow hook sets suppressed because the
    /// session carried an explicit `false` decision for that instance.
    pub skipped_session_hooks: u64,
    /// Contextless hooks that RAN because no decision was carried for the
    /// instance. Backward compatible by design; a sustained nonzero rate on a
    /// triggered deployment means a summary/session path is not stamping the
    /// carrier.
    pub missing_decision_carriers: u64,
}

/// Read the trigger-carrier counters. Monotonic, process-lifetime.
pub fn carrier_counters() -> PluginTriggerCarrierCounters {
    PluginTriggerCarrierCounters {
        skipped_terminal_log_hooks: SKIPPED_TERMINAL_LOG_HOOKS.load(Ordering::Relaxed),
        skipped_session_hooks: SKIPPED_SESSION_HOOKS.load(Ordering::Relaxed),
        missing_decision_carriers: MISSING_DECISION_CARRIERS.load(Ordering::Relaxed),
    }
}

#[inline]
fn record_missing_carrier() {
    MISSING_DECISION_CARRIERS.fetch_add(1, Ordering::Relaxed);
}

/// Lifecycle position of the hook asking for a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerPhase {
    /// `prepare_grpc_deadline`, `on_request_received`, `authenticate` — the
    /// authentication boundary has not committed an identity yet.
    PreAuth,
    /// `authorize` and every later request/response phase.
    PostAuth,
}

/// One plugin instance's compiled execution trigger plus its runtime identity.
#[derive(Debug)]
pub struct PluginTriggerGate {
    compiled: Arc<CompiledPluginTrigger>,
    token: u64,
    /// Precomputed `plugin_trigger.<config-id>.skipped` metadata key, so a skip
    /// costs one clone rather than a `format!` on the request path.
    skip_metadata_key: String,
}

impl PluginTriggerGate {
    /// Compile a configured trigger for one plugin-config instance.
    ///
    /// Every rejection here is a config error surfaced by plugin-cache
    /// publication, file-config validation, or the admin API — never a request.
    pub fn compile(trigger: &PluginTrigger, plugin_config_id: &str) -> Result<Self, String> {
        let compiled = CompiledPluginTrigger::compile(trigger)?;
        Ok(Self {
            compiled: Arc::new(compiled),
            token: NEXT_TRIGGER_TOKEN.fetch_add(1, Ordering::Relaxed),
            skip_metadata_key: format!("plugin_trigger.{plugin_config_id}.skipped"),
        })
    }

    /// Whether the compiled predicate reads authenticated identity.
    pub fn reads_authenticated_identity(&self) -> bool {
        self.compiled.reads_authenticated_identity()
    }

    /// First HTTP-only field the predicate reads (`method`, `path`, `host`,
    /// `header`, `query`, `cookie`), if any. Publication refuses one of these on
    /// a stream-only (TCP / UDP / DTLS) instance.
    pub fn http_only_field(&self) -> Option<&'static str> {
        self.compiled.http_only_field()
    }

    /// Decide whether this instance runs for `ctx`, memoizing the outcome.
    ///
    /// Returns `true` to run. An identity-reading trigger asked at
    /// [`TriggerPhase::PreAuth`] returns `true` without memoizing, leaving the
    /// authoritative decision to the first `authorize`-or-later hook.
    pub fn admits_request(&self, ctx: &mut RequestContext, phase: TriggerPhase) -> bool {
        if let Some(decision) = ctx.plugin_trigger_decision(self.token) {
            return decision;
        }
        if phase == TriggerPhase::PreAuth && self.compiled.reads_authenticated_identity() {
            return true;
        }
        let decision = {
            let facts = HttpTriggerFacts::new(ctx);
            self.compiled.evaluate(&facts)
        };
        let decision = ctx.record_plugin_trigger_decision(self.token, decision);
        if !decision {
            ctx.metadata
                .insert(self.skip_metadata_key.clone(), "true".to_string());
        }
        decision
    }

    /// Read-only view of an already-memoized decision.
    ///
    /// Used by the `&RequestContext` capability predicates (buffering,
    /// enforcement claims) that cannot memoize. It fails closed: an
    /// undecided instance reports "runs", so a trigger can only ever REMOVE
    /// work, never suppress a guard whose decision has not been made.
    pub fn request_decision_or_run(&self, ctx: &RequestContext) -> bool {
        ctx.plugin_trigger_decision(self.token).unwrap_or(true)
    }

    /// Read the decision this instance took at `on_stream_connect`, carried on
    /// the disconnect summary.
    ///
    /// `on_stream_disconnect` receives only a [`StreamTransactionSummary`], so
    /// the connect-time outcome travels with it in an opaque, non-serialized,
    /// crate-constructed carrier rather than through the summary's
    /// plugin-writable `metadata` map — a plugin must not be able to author or
    /// erase another instance's admission decision. Fails closed to "runs" when
    /// the summary carries no decision for this instance (a connection whose
    /// chain never reached this instance's `on_stream_connect`), so a trigger
    /// can only ever remove work.
    pub fn stream_disconnect_decision_or_run(&self, summary: &StreamTransactionSummary) -> bool {
        match summary.plugin_trigger_decisions.decision(self.token) {
            Some(decision) => {
                if !decision {
                    SKIPPED_SESSION_HOOKS.fetch_add(1, Ordering::Relaxed);
                }
                decision
            }
            None => {
                record_missing_carrier();
                true
            }
        }
    }

    /// Read the decision this instance took during the request lifecycle,
    /// carried on the terminal transaction summary.
    ///
    /// `log` / `log_with_mesh_key` receive only a [`TransactionSummary`], so the
    /// request-phase outcome travels with it in an opaque, non-serialized,
    /// crate-constructed carrier rather than through the summary's
    /// plugin-writable `metadata` map. Explicit `false` skips; explicit `true`
    /// runs; a MISSING carrier runs and records a bounded invariant signal, so
    /// missing state can never become an accidental suppression of a security or
    /// audit record.
    pub fn transaction_log_decision_or_run(&self, summary: &TransactionSummary) -> bool {
        match summary.plugin_trigger_decisions.decision(self.token) {
            Some(decision) => {
                if !decision {
                    SKIPPED_TERMINAL_LOG_HOOKS.fetch_add(1, Ordering::Relaxed);
                }
                decision
            }
            None => {
                record_missing_carrier();
                true
            }
        }
    }

    /// Read the decision this instance took at UDP/DTLS session admission,
    /// carried on the generation-owned session.
    ///
    /// Consumed ONCE, when the session's datagram-hook list is built, so every
    /// later datagram hook is a plain list traversal with no predicate
    /// evaluation, allocation, hashing, or locking. Missing state runs and
    /// records the same bounded invariant signal.
    pub fn stream_session_decision_or_run(&self, decisions: &StreamTriggerDecisions) -> bool {
        match decisions.decision(self.token) {
            Some(decision) => {
                if !decision {
                    SKIPPED_SESSION_HOOKS.fetch_add(1, Ordering::Relaxed);
                }
                decision
            }
            None => {
                record_missing_carrier();
                true
            }
        }
    }

    /// Decide, at WebSocket upgrade admission, whether this instance takes part
    /// in the accepted session.
    ///
    /// The upgrade is past the authentication boundary, so this is an ordinary
    /// [`TriggerPhase::PostAuth`] evaluation against the live request facts, and
    /// the outcome is memoized on the context exactly like any other phase — the
    /// frame, reassembly, delivery, size-limit, and disconnect sets are all
    /// derived from this one decision. Counted once per session per instance,
    /// even though the relay asks for the frame and disconnect sets separately.
    pub fn admits_ws_session(&self, ctx: &mut RequestContext) -> bool {
        let already_decided = ctx.plugin_trigger_decision(self.token).is_some();
        let run = self.admits_request(ctx, TriggerPhase::PostAuth);
        if !run && !already_decided {
            SKIPPED_SESSION_HOOKS.fetch_add(1, Ordering::Relaxed);
        }
        run
    }

    /// Decide whether this instance runs for a stream connection, memoizing the
    /// outcome so `on_stream_connect` and `on_stream_disconnect` agree.
    ///
    /// An identity-reading trigger does not gate a stream connection at all: it
    /// returns `true` without memoizing, so both stream hooks run. This is the
    /// same rule as [`TriggerPhase::PreAuth`], applied faithfully — every gated
    /// stream phase is at or before the stream authentication boundary, because
    /// stream authentication runs inside the one `on_stream_connect` chain.
    /// There is no later phase to defer the real decision to, so "run" is where
    /// it stays.
    pub fn admits_stream(&self, ctx: &mut StreamConnectionContext) -> bool {
        if let Some(decision) = ctx.plugin_trigger_decision(self.token) {
            return decision;
        }
        if self.compiled.reads_authenticated_identity() {
            return true;
        }
        let decision = {
            let facts = StreamTriggerFacts::new(ctx);
            self.compiled.evaluate(&facts)
        };
        let decision = ctx.record_plugin_trigger_decision(self.token, decision);
        if !decision {
            let key = self.skip_metadata_key.clone();
            ctx.insert_metadata(key, "true".to_string());
        }
        decision
    }
}

// ---------------------------------------------------------------------------
// HTTP-family facts
// ---------------------------------------------------------------------------

/// Zero-copy [`TriggerFacts`] view over a live HTTP request context.
pub struct HttpTriggerFacts<'a> {
    ctx: &'a RequestContext,
    host: Option<&'a str>,
    protocols: [PluginTriggerProtocol; 3],
    protocol_len: usize,
}

impl<'a> HttpTriggerFacts<'a> {
    /// Build the view. Everything here is a field read or a borrowed slice —
    /// no allocation, no locks.
    pub fn new(ctx: &'a RequestContext) -> Self {
        let mut protocols = [PluginTriggerProtocol::Http1; 3];
        let mut protocol_len = 0;
        if let Some(transport) = ctx.request_wire_transport() {
            protocols[protocol_len] = match transport {
                HttpWireTransport::Http1 => PluginTriggerProtocol::Http1,
                HttpWireTransport::Http2 => PluginTriggerProtocol::Http2,
                HttpWireTransport::Http3 => PluginTriggerProtocol::Http3,
            };
            protocol_len += 1;
        }
        match ctx.request_http_flavor() {
            HttpFlavor::Grpc => {
                protocols[protocol_len] = PluginTriggerProtocol::Grpc;
                protocol_len += 1;
            }
            HttpFlavor::WebSocket => {
                protocols[protocol_len] = PluginTriggerProtocol::Websocket;
                protocol_len += 1;
            }
            HttpFlavor::Plain => {}
        }
        if ctx.request_is_grpc_web() {
            protocols[protocol_len] = PluginTriggerProtocol::GrpcWeb;
            protocol_len += 1;
        }
        Self {
            ctx,
            host: ctx.request_authority.as_deref().map(authority_host),
            protocols,
            protocol_len,
        }
    }
}

/// Strip an optional `:port` from an already-normalized authority, keeping an
/// IPv6 literal's bracketed form intact.
fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return match rest.find(']') {
            // Include the brackets so `[::1]` compares as written.
            Some(end) => &authority[..end + 2],
            None => authority,
        };
    }
    match authority.rfind(':') {
        Some(index) => &authority[..index],
        None => authority,
    }
}

impl TriggerFacts for HttpTriggerFacts<'_> {
    fn is_http(&self) -> bool {
        true
    }

    fn method(&self) -> Option<&str> {
        Some(self.ctx.method.as_str())
    }

    fn path(&self) -> Option<&str> {
        Some(self.ctx.path.as_str())
    }

    fn host(&self) -> Option<&str> {
        self.host
    }

    fn sni(&self) -> Option<&str> {
        self.ctx.frontend_sni_hostname.as_deref()
    }

    fn protocols(&self) -> &[PluginTriggerProtocol] {
        &self.protocols[..self.protocol_len]
    }

    fn client_ip(&self) -> Option<IpAddr> {
        self.ctx.canonical_client_ip()
    }

    fn namespace(&self) -> Option<&str> {
        self.ctx
            .matched_proxy
            .as_ref()
            .map(|proxy| proxy.namespace.as_str())
    }

    fn proxy_id(&self) -> Option<&str> {
        self.ctx
            .matched_proxy
            .as_ref()
            .map(|proxy| proxy.id.as_str())
    }

    fn listen_port(&self) -> Option<u16> {
        self.ctx.frontend_listen_port
    }

    fn consumer_identity(&self) -> Option<&str> {
        self.ctx
            .identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str())
            .or(self.ctx.authenticated_identity.as_deref())
    }

    fn auth_method(&self) -> Option<&str> {
        self.ctx.auth_method
    }

    fn spiffe_id(&self) -> Option<&str> {
        self.ctx.peer_spiffe_id.as_ref().map(|id| id.as_str())
    }

    fn for_each_header_value(&self, lower_name: &str, visit: &mut FieldVisitor<'_>) {
        // Read the PRISTINE inbound wire view. A trigger must describe what the
        // client actually sent, not what an earlier plugin rewrote — and the
        // memoized decision is taken before any transformer runs anyway.
        // A non-UTF-8 value still reports structural presence but is never
        // lossily transcoded, so hostile bytes cannot match a text pattern or
        // make a present credential field look absent.
        if let Some(raw) = self.ctx.raw_headers.as_ref() {
            for value in raw.get_all(lower_name) {
                let Ok(value) = value.to_str() else {
                    if !visit(None) {
                        return;
                    }
                    continue;
                };
                if !visit(Some(value)) {
                    return;
                }
            }
            return;
        }
        // Direct plugin callers and tests that never carried a wire header map
        // fall back to the folded view, which holds one value per name.
        if let Some(value) = self.ctx.headers.get(lower_name) {
            visit(Some(value));
        }
    }

    fn for_each_query_value(&self, name: &str, visit: &mut FieldVisitor<'_>) {
        let Some(query) = self.ctx.raw_query_string() else {
            return;
        };
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_name, raw_value) = match pair.split_once('=') {
                Some((raw_name, raw_value)) => (raw_name, raw_value),
                None => (pair, ""),
            };
            // Decode STRICTLY. `decode_utf8_lossy` would turn an invalid
            // percent-decoded sequence into `U+FFFD`, so `?q=%FF` could satisfy
            // a configured `"\u{FFFD}"` value — and beneath `not` that flips a
            // security instance from "runs" to "skipped". Once the name is
            // known, an unrepresentable value is reported as present without a
            // textual value; an unrepresentable name is skipped because it
            // cannot be attributed to this predicate. The offending bytes are
            // never copied, reflected, or logged.
            let Ok(decoded_name) = percent_decode_str(raw_name).decode_utf8() else {
                continue;
            };
            if decoded_name != name {
                continue;
            }
            let Ok(decoded_value) = percent_decode_str(raw_value).decode_utf8() else {
                if !visit(None) {
                    return;
                }
                continue;
            };
            if !visit(Some(decoded_value.as_ref())) {
                return;
            }
        }
    }

    fn for_each_cookie_value(&self, name: &str, visit: &mut FieldVisitor<'_>) {
        if let Some(raw) = self.ctx.raw_headers.as_ref() {
            for header_value in raw.get_all("cookie") {
                if !visit_cookie_header_bytes(header_value.as_bytes(), name.as_bytes(), visit) {
                    return;
                }
            }
            return;
        }
        self.for_each_header_value("cookie", &mut |header_value: Option<&str>| -> bool {
            let Some(header_value) = header_value else {
                // The Cookie line exists, but without text it cannot prove that
                // this particular cookie name occurred.
                return true;
            };
            for pair in header_value.split(';') {
                let pair = pair.trim();
                if pair.is_empty() {
                    continue;
                }
                let (cookie_name, cookie_value) = match pair.split_once('=') {
                    Some((cookie_name, cookie_value)) => (cookie_name.trim(), cookie_value.trim()),
                    None => (pair, ""),
                };
                if cookie_name != name {
                    continue;
                }
                // A quoted cookie-value is the same value per RFC 6265 §4.1.1.
                let cookie_value = cookie_value
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .unwrap_or(cookie_value);
                if !visit(Some(cookie_value)) {
                    return false;
                }
            }
            true
        });
    }
}

/// Visit one raw Cookie field without lossily transcoding it.
///
/// Cookie names are configured as printable ASCII, so byte comparison can
/// establish the named occurrence even when its value contains obs-text that
/// makes the complete header invalid UTF-8. The occurrence is then reported as
/// present with no textual value, exactly like a named non-UTF-8 header/query
/// value. Returns `false` when the caller settled the predicate early.
fn visit_cookie_header_bytes(
    header_value: &[u8],
    name: &[u8],
    visit: &mut FieldVisitor<'_>,
) -> bool {
    for pair in header_value.split(|byte| *byte == b';') {
        let pair = trim_ascii_whitespace_bytes(pair);
        if pair.is_empty() {
            continue;
        }
        let (cookie_name, cookie_value) = match pair.iter().position(|byte| *byte == b'=') {
            Some(index) => (&pair[..index], &pair[index + 1..]),
            None => (pair, &[][..]),
        };
        if trim_ascii_whitespace_bytes(cookie_name) != name {
            continue;
        }
        let mut cookie_value = trim_ascii_whitespace_bytes(cookie_value);
        if cookie_value.len() >= 2
            && cookie_value.first() == Some(&b'"')
            && cookie_value.last() == Some(&b'"')
        {
            cookie_value = &cookie_value[1..cookie_value.len() - 1];
        }
        let value = std::str::from_utf8(cookie_value).ok();
        if !visit(value) {
            return false;
        }
    }
    true
}

fn trim_ascii_whitespace_bytes(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

// ---------------------------------------------------------------------------
// Stream facts
// ---------------------------------------------------------------------------

/// Zero-copy [`TriggerFacts`] view over a live TCP/UDP/DTLS connection context.
///
/// HTTP-only predicates (method, path, host, header, query, cookie) evaluate to
/// `false` here rather than being silently ignored: a stream connection genuinely
/// has no request line, so "only run on `/orders`" faithfully means "do not run".
pub struct StreamTriggerFacts<'a> {
    ctx: &'a StreamConnectionContext,
    protocols: [PluginTriggerProtocol; 1],
}

impl<'a> StreamTriggerFacts<'a> {
    pub fn new(ctx: &'a StreamConnectionContext) -> Self {
        let protocol = match ctx.frontend_transport {
            StreamFrontendTransport::Tcp => PluginTriggerProtocol::Tcp,
            StreamFrontendTransport::Udp => PluginTriggerProtocol::Udp,
            StreamFrontendTransport::Dtls => PluginTriggerProtocol::Dtls,
        };
        Self {
            ctx,
            protocols: [protocol],
        }
    }
}

impl TriggerFacts for StreamTriggerFacts<'_> {
    fn is_http(&self) -> bool {
        false
    }

    fn method(&self) -> Option<&str> {
        None
    }

    fn path(&self) -> Option<&str> {
        None
    }

    fn host(&self) -> Option<&str> {
        None
    }

    fn sni(&self) -> Option<&str> {
        self.ctx.sni_hostname.as_deref()
    }

    fn protocols(&self) -> &[PluginTriggerProtocol] {
        &self.protocols
    }

    fn client_ip(&self) -> Option<IpAddr> {
        self.ctx.canonical_client_ip()
    }

    fn namespace(&self) -> Option<&str> {
        Some(self.ctx.proxy_namespace.as_str())
    }

    fn proxy_id(&self) -> Option<&str> {
        Some(self.ctx.proxy_id.as_str())
    }

    fn listen_port(&self) -> Option<u16> {
        Some(self.ctx.listen_port)
    }

    // The three identity accessors below are faithful reads of whatever a
    // stream auth plugin has committed SO FAR, and they are unreachable from a
    // configured trigger: `PluginTriggerGate::admits_stream` never evaluates an
    // identity-reading predicate on a stream connection, because the one gated
    // stream phase is also where stream authentication runs. They remain
    // implemented so the facts view stays a faithful description of the context
    // rather than a second, divergent definition of stream identity.

    fn consumer_identity(&self) -> Option<&str> {
        self.ctx.effective_identity()
    }

    fn auth_method(&self) -> Option<&str> {
        self.ctx.auth_method
    }

    /// Always `None`: a stream connection carries no authoritative peer SPIFFE
    /// fact.
    ///
    /// The peer certificate is on the context, but the SPIFFE ID derived from it
    /// is produced by a stream plugin and published only into the
    /// plugin-writable `metadata` map, which must never become a security
    /// authority. Reading it here would let a plugin author another instance's
    /// admission decision; answering "absent" for every stream connection would,
    /// under `not`, silently switch a security instance the wrong way. Neither is
    /// acceptable, so `spiffe_id` — like every identity predicate — simply does
    /// not gate a stream connection (`PluginTriggerGate::admits_stream`), and is
    /// refused outright on a stream-only instance where it could gate nothing at
    /// all. A configured trigger therefore never reaches this accessor.
    fn spiffe_id(&self) -> Option<&str> {
        None
    }

    fn for_each_header_value(&self, _lower_name: &str, _visit: &mut FieldVisitor<'_>) {}

    fn for_each_query_value(&self, _name: &str, _visit: &mut FieldVisitor<'_>) {}

    fn for_each_cookie_value(&self, _name: &str, _visit: &mut FieldVisitor<'_>) {}
}
