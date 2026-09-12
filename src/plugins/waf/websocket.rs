//! WebSocket application-message inspection for the WAF plugin.
//!
//! Before this module the WAF advertised WebSocket support but stopped at the
//! HTTP upgrade handshake: it inherited the default `requires_ws_frame_hooks =
//! false` and the no-op `on_ws_frame`, so an enforcing body rule that rejected
//! a payload on the HTTP path forwarded the same payload verbatim once it was
//! moved into a WebSocket message (private advisory `GHSA-6j3m-vf5h-pgcx`).
//!
//! ## What the hook actually receives
//!
//! `Plugin::on_ws_frame` is invoked with **complete, reassembled, uncompressed
//! application messages**, which is what makes bounded body-rule inspection
//! possible here without duplicating any protocol state:
//!
//! * **Reassembly** — the shared H1/H2/H3 relay reads through tungstenite,
//!   which joins an initial non-final Text/Binary frame and every Continuation
//!   frame into one `Message` before yielding it. The physical fragments a peer
//!   spends on reassembly are charged separately through
//!   `Plugin::on_ws_reassembly_frames`, and a message that never completes is
//!   bounded by the parser
//!   (`FERRUM_WEBSOCKET_MAX_INCOMPLETE_MESSAGE_FRAMES` /
//!   `..._SECONDS`), so this hook never has to hold partial state.
//! * **Compression** — the gateway never negotiates `permessage-deflate`. The
//!   client's `Sec-WebSocket-Extensions` offer is stripped before the backend
//!   handshake (`is_websocket_backend_strip_header`) and no negotiated
//!   extension is echoed back to the client
//!   (`WEBSOCKET_TRANSPORT_MANAGED_RESPONSE_HEADERS`), so no `rsv1` payload can
//!   exist end to end on any frontend.
//! * **Size** — the relay's parser ceilings (`EffectiveWsSizeLimits`) bound the
//!   largest message that can ever reach this hook; the WAF's own
//!   `max_scan_bytes` / `on_body_too_large` policy then decides an
//!   over-ceiling governed message exactly as it does for an HTTP body.
//!
//! ## Session binding
//!
//! `on_ws_frame` carries no request context — a WebSocket session *is* one
//! upgraded request. Rather than re-deriving request-scoped state per message
//! (or, worse, guessing at it), `Plugin::bind_ws_session` resolves it **once**
//! at upgrade admission into an immutable [`WsSessionPolicy`]: global
//! exemptions, every rule's `conditions` verdict, and whether each direction
//! can actually block. The relay then uses the bound instance for the life of
//! the connection. No request headers, bodies, or credentials are retained, and
//! per-message work is a rule scan over the message bytes with no allocation
//! beyond what the shared body scanner already performs.
//!
//! ## Direction mapping
//!
//! * client → backend messages are governed by the **request** body rule set
//!   (`body_text`, `body_json_path`, body Luhn/CIDR rules and the body-scoped
//!   encoding specials), gated by `request_inspection` +
//!   `request_body_inspection`.
//! * backend → client messages are governed by the **response** body rule set
//!   (`response_body`, response Luhn/CIDR rules and the same encoding
//!   specials), gated by `response_inspection` + `response_body_inspection`.
//!
//! Both Text and Binary messages are inspected. The HTTP body eligibility
//! knobs (`body_methods`, `body_content_types`, `inspect_multipart`,
//! `inspect_binary_body`) are HTTP media-type selectors and deliberately do
//! **not** apply: a WebSocket message carries no `Content-Type`, so honoring
//! them would let a client bypass an enforcing rule purely by choosing the
//! Binary opcode.
//!
//! Control frames (Ping / Pong / Close) are protocol machinery, never
//! application payload, and are passed through untouched.

use crate::plugins::utils::log_sampling::warn_sampled;

use std::sync::Arc;

use async_trait::async_trait;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use super::rules::{RuleAction, Severity};
use super::scan::{ScanOutcome, ScanSubject};
use super::{BodyDirection, GlobalMode, TimeoutAction, TooLargeAction, Waf};
use crate::plugins::{
    Plugin, ProxyProtocol, RequestContext, WebSocketFrameDirection, WebSocketSizeLimits,
};

/// Fixed RFC 6455 close reasons. These are compiled-in literals: they never
/// echo message bytes, rule ids, or any peer-controlled value, and each stays
/// well inside the 123-byte control-frame reason budget.
const CLOSE_REASON_RULE: &str = "message rejected by security policy";
const CLOSE_REASON_TOO_LARGE: &str = "message exceeds inspectable size";
const CLOSE_REASON_UNINSPECTABLE: &str = "message could not be inspected";

/// Immutable, per-connection snapshot of every request-scoped WAF predicate,
/// resolved once at WebSocket upgrade admission.
///
/// Bounded by construction: two booleans per direction plus one boolean per
/// compiled rule. Nothing here is attacker-controlled at message time and
/// nothing grows with session length or message count.
pub(super) struct WsSessionPolicy {
    /// A `global_exemptions.header_present` entry matched the upgrade request,
    /// suppressing every rule for this session.
    suppressed_by_request: bool,
    /// Per-compiled-rule `conditions` verdict, indexed by rule index.
    rule_conditions: Box<[bool]>,
    /// Whether client→backend messages are inspected at all.
    inspect_client_to_backend: bool,
    /// Whether backend→client messages are inspected at all.
    inspect_backend_to_client: bool,
    /// Whether a client→backend message can actually be blocked by this
    /// instance (globally enforcing plus an applicable enforcing request-body
    /// rule, or anomaly scoring). Decides whether an *uninspectable* message
    /// is a protection-mechanism failure or merely a lost observation.
    enforcing_client_to_backend: bool,
    /// Backend→client counterpart.
    enforcing_backend_to_client: bool,
}

impl WsSessionPolicy {
    fn from_upgrade(waf: &Waf, ctx: &RequestContext) -> Self {
        // `ctx.headers` must still contain the admitted upgrade request here:
        // rule conditions and `global_exemptions.header_present` are resolved
        // once into this session snapshot. H1/H2 retain them naturally; the H3
        // dispatch handoff explicitly clones rather than takes them for a
        // WebSocket upgrade.
        // A request-wide exemption on the upgrade short-circuits the whole
        // session exactly as it would short-circuit the equivalent HTTP
        // request: nothing is inspected and nothing can block.
        let exempt = waf.exemptions.request_short_circuits(ctx);
        let inspect_client_to_backend = !exempt && waf.requires_request_body_buffering();
        let inspect_backend_to_client = !exempt && waf.requires_response_body_buffering();
        Self {
            suppressed_by_request: waf.exemptions.suppresses_rule_for_request(ctx),
            rule_conditions: waf
                .compiled
                .rules
                .iter()
                .map(|rule| rule.matches_conditions(ctx))
                .collect(),
            inspect_client_to_backend,
            inspect_backend_to_client,
            enforcing_client_to_backend: inspect_client_to_backend
                && waf.has_enforcing_body_policy(BodyDirection::Request, ctx),
            enforcing_backend_to_client: inspect_backend_to_client
                && waf.has_enforcing_body_policy(BodyDirection::Response, ctx),
        }
    }

    /// Replay the admission-time verdict for one rule. Mirrors the HTTP
    /// `conditions` + `header_present` gate in `Waf::rule_applies`.
    pub(super) fn rule_applies(&self, rule_index: usize) -> bool {
        debug_assert!(
            rule_index < self.rule_conditions.len(),
            "WAF WebSocket session policy indexed with a foreign rule index"
        );
        !self.suppressed_by_request
            && self
                .rule_conditions
                .get(rule_index)
                .copied()
                // A foreign index is an internal invariant violation. Release
                // builds still fail closed by treating the condition as
                // matched rather than silently skipping an enforcing rule.
                .unwrap_or(true)
    }

    fn inspects(&self, direction: BodyDirection) -> bool {
        match direction {
            BodyDirection::Request => self.inspect_client_to_backend,
            BodyDirection::Response => self.inspect_backend_to_client,
        }
    }

    fn enforces(&self, direction: BodyDirection) -> bool {
        match direction {
            BodyDirection::Request => self.enforcing_client_to_backend,
            BodyDirection::Response => self.enforcing_backend_to_client,
        }
    }
}

/// Map the relay's wire direction onto the governed body rule set.
fn body_direction(direction: WebSocketFrameDirection) -> BodyDirection {
    match direction {
        WebSocketFrameDirection::ClientToBackend => BodyDirection::Request,
        WebSocketFrameDirection::BackendToClient => BodyDirection::Response,
    }
}

pub(super) fn direction_label(direction: WebSocketFrameDirection) -> &'static str {
    match direction {
        WebSocketFrameDirection::ClientToBackend => "client->backend",
        WebSocketFrameDirection::BackendToClient => "backend->client",
    }
}

fn policy_close(reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame {
        code: CloseCode::Policy,
        reason: reason.into(),
    }))
}

/// Terminal Close for an instance the relay never bound to a session
/// (see the fail-closed fallback in `Waf::on_ws_frame`).
pub(super) fn unbound_policy_close() -> Message {
    policy_close(CLOSE_REASON_UNINSPECTABLE)
}

/// Session-bound WAF instance handed to the shared H1/H2/H3 frame relay.
///
/// Substituted positionally for the shared `waf` instance by
/// `collect_websocket_relay_plugins`, so configured priority order is
/// unchanged and each configured WAF instance still sees every message exactly
/// once, independently of its siblings.
pub(super) struct WafWsSession {
    waf: Arc<Waf>,
    policy: WsSessionPolicy,
}

impl WafWsSession {
    /// Bind `waf` to one upgraded session, or `None` when this instance has no
    /// WebSocket message policy at all.
    pub(super) fn bind(waf: Arc<Waf>, ctx: &RequestContext) -> Option<Arc<dyn Plugin>> {
        if !waf.websocket_message_inspection_active() {
            return None;
        }
        let policy = WsSessionPolicy::from_upgrade(&waf, ctx);
        Some(Arc::new(Self { waf, policy }))
    }

    /// Decide an oversize governed message, mirroring `Waf::clamp_body`.
    ///
    /// `Ok(slice)` scans that slice (the complete message, or a prefix when the
    /// policy concedes the suffix); `Err(message)` is terminal for the whole
    /// message — `Err(None)` forwards it unscanned, `Err(Some(close))` closes
    /// the connection.
    fn clamp<'a>(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        payload: &'a [u8],
    ) -> Result<&'a [u8], Option<Message>> {
        let max_scan_bytes = self.waf.config.max_scan_bytes;
        if payload.len() <= max_scan_bytes {
            return Ok(payload);
        }
        let governed = body_direction(direction);
        let should_block = match self.waf.config.on_body_too_large {
            TooLargeAction::Skip => return Err(None),
            TooLargeAction::ScanTruncated => false,
            TooLargeAction::FailClosed => self.policy.enforces(governed),
            TooLargeAction::Block => self.waf.config.mode == GlobalMode::Enforce,
        };
        // A block is terminal for the session and always recorded. The
        // non-blocking prefix-scan arm is a lost-coverage signal that can
        // repeat per message, so it stays behind `log_to_stdout`. Both records
        // are fixed-cardinality; neither logs message bytes.
        if should_block || self.waf.config.log_to_stdout {
            warn_sampled!(
                target: "waf",
                plugin = "waf",
                proxy = %proxy_id,
                connection_id,
                direction = direction_label(direction),
                max_scan_bytes,
                blocked = should_block,
                "WAF WebSocket message exceeds max_scan_bytes"
            );
        }
        if should_block {
            return Err(Some(policy_close(CLOSE_REASON_TOO_LARGE)));
        }
        Ok(&payload[..max_scan_bytes])
    }

    /// A message this instance cannot inspect at all (a representation the
    /// reassembled-message contract says cannot occur). Fails closed whenever
    /// the direction carries enforcement, and is otherwise a lost observation.
    fn uninspectable(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        kind: &'static str,
    ) -> Option<Message> {
        let blocked = self.policy.enforces(body_direction(direction));
        if blocked || self.waf.config.log_to_stdout {
            warn_sampled!(
                target: "waf",
                plugin = "waf",
                proxy = %proxy_id,
                connection_id,
                direction = direction_label(direction),
                representation = kind,
                blocked,
                "WAF received an uninspectable WebSocket message representation"
            );
        }
        blocked.then(|| policy_close(CLOSE_REASON_UNINSPECTABLE))
    }

    /// Terminal decision for one scanned message.
    ///
    /// Anomaly scoring is evaluated **per complete message**: a WebSocket
    /// session has no request-scoped accumulator, and carrying one across a
    /// long-lived connection would let an unbounded, attacker-driven counter
    /// decide admission (and would make the same benign message block or pass
    /// depending on session history). Each message is scored on its own hits
    /// against the same configured `block_threshold`.
    fn finish(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        outcome: &ScanOutcome,
    ) -> Option<Message> {
        if outcome.hits.is_empty() {
            return self.finish_timeout(proxy_id, connection_id, direction, outcome);
        }

        let enforcing_globally = self.waf.config.mode == GlobalMode::Enforce;
        let mut highest = Severity::Info;
        let mut first_blocking_rule: Option<&str> = None;
        let mut score: u32 = 0;
        for hit in &outcome.hits {
            let rule = &self.waf.compiled.rules[hit.rule_index];
            highest = highest.max(rule.severity);
            if let Some(scoring) = &self.waf.config.scoring {
                let contribution = rule.score.unwrap_or_else(|| scoring.weight(rule.severity));
                score = score.saturating_add(contribution);
            }
            if enforcing_globally
                && rule.action == RuleAction::Enforce
                && first_blocking_rule.is_none()
            {
                first_blocking_rule = Some(rule.id.as_str());
            }
            if self.waf.config.log_to_stdout {
                warn_sampled!(
                    target: "waf",
                    plugin = "waf",
                    proxy = %proxy_id,
                    connection_id,
                    direction = direction_label(direction),
                    rule = %rule.id,
                    rule_name = %rule.name,
                    severity = %rule.severity.as_str(),
                    category = %rule.category,
                    action = %rule.action.effective_log_action(enforcing_globally),
                    rule_action = %rule.action,
                    target_field = %hit.target_name,
                    "WAF rule matched on a WebSocket message"
                );
            }
        }
        let scoring = self.waf.config.scoring.as_ref();
        let over_threshold = scoring.is_some_and(|s| score >= s.block_threshold);
        let score_block = enforcing_globally && over_threshold;

        if let Some(rule_id) = first_blocking_rule {
            // Terminal and always logged: a closed WebSocket session has no
            // transaction-summary metadata surface of its own, so this warning
            // is the operator's record of the decision. Fixed-cardinality
            // fields only — no message bytes are ever logged.
            warn_sampled!(
                target: "waf",
                plugin = "waf",
                proxy = %proxy_id,
                connection_id,
                direction = direction_label(direction),
                waf_instance = %self.waf.identity,
                rule = %rule_id,
                severity = %highest.as_str(),
                block_reason = "rule",
                "WAF blocked a WebSocket message; closing connection"
            );
            return Some(policy_close(CLOSE_REASON_RULE));
        }
        if score_block {
            warn_sampled!(
                target: "waf",
                plugin = "waf",
                proxy = %proxy_id,
                connection_id,
                direction = direction_label(direction),
                severity = %highest.as_str(),
                waf_instance = %self.waf.identity,
                block_reason = "score",
                "WAF blocked a WebSocket message on anomaly score; closing connection"
            );
            return Some(policy_close(CLOSE_REASON_RULE));
        }
        self.finish_timeout(proxy_id, connection_id, direction, outcome)
    }

    /// `on_scan_timeout` for a message whose scan ran over budget without a
    /// confirmed blocking hit. Mirrors `Waf::finish_timeout`.
    fn finish_timeout(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        outcome: &ScanOutcome,
    ) -> Option<Message> {
        if !outcome.timed_out {
            return None;
        }
        let block = matches!(self.waf.config.on_scan_timeout, TimeoutAction::Block);
        if block || self.waf.config.log_to_stdout {
            warn_sampled!(
                target: "waf",
                plugin = "waf",
                proxy = %proxy_id,
                connection_id,
                direction = direction_label(direction),
                blocked = block,
                "WAF WebSocket message scan timed out"
            );
        }
        block.then(|| policy_close(CLOSE_REASON_UNINSPECTABLE))
    }
}

#[async_trait]
impl Plugin for WafWsSession {
    fn name(&self) -> &str {
        self.waf.name()
    }

    fn priority(&self) -> u16 {
        self.waf.priority()
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        self.waf.supported_protocols()
    }

    fn websocket_size_limits(&self) -> Option<WebSocketSizeLimits> {
        self.waf.websocket_size_limits()
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    fn requires_websocket_framing(&self) -> bool {
        true
    }

    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<Message> {
        let payload: &[u8] = match message {
            Message::Text(text) => text.as_bytes(),
            Message::Binary(bytes) => bytes.as_ref(),
            // Control frames are protocol machinery, never application
            // payload: scanning them would corrupt keepalive/close semantics
            // and produce hits on data the application never sees. A Close is
            // additionally already terminal for the session.
            Message::Ping(_) | Message::Pong(_) | Message::Close(_) => return None,
            // The relay only ever yields reassembled Text/Binary/control
            // messages on the read path; `Message::Frame` is a write-side
            // representation with no inspectable application payload. Fail
            // closed rather than forward an unscanned representation.
            Message::Frame(_) => {
                return self.uninspectable(proxy_id, connection_id, direction, "raw_frame");
            }
        };

        let governed = body_direction(direction);
        if !self.policy.inspects(governed) {
            return None;
        }

        let payload = match self.clamp(proxy_id, connection_id, direction, payload) {
            Ok(value) => value,
            Err(terminal) => return terminal,
        };

        // The scan subject is built inside the closure so nothing but `&self`
        // (and the message slice) is held across the budget yield.
        let outcome = self
            .waf
            .run_body_scan_with_budget(|| {
                let subject = ScanSubject::WebSocketSession(&self.policy);
                match governed {
                    BodyDirection::Request => {
                        self.waf.scan_request_body_rules(subject, payload, None)
                    }
                    BodyDirection::Response => {
                        self.waf.scan_response_body_rules(subject, payload, None)
                    }
                }
            })
            .await;
        self.finish(proxy_id, connection_id, direction, &outcome)
    }
}
