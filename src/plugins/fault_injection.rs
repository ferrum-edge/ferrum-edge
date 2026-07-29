//! Fault Injection Plugin
//!
//! Injects controlled failures (delays and aborts) into request processing
//! for chaos engineering workflows. Both fault types are probabilistic —
//! each has a `percentage` field (0.0–100.0) checked per-request / per
//! datagram / per stream admission.
//!
//! Runs in the `before_proxy` phase for HTTP-family requests so it fires after
//! authentication, authorization, and consumer rate limiting but before backend
//! dispatch. When backend-effective path policy is active, the HTTP hook waits
//! until the resolved backend path has been authorized, so a delay or abort
//! cannot precede the route-sensitive denial. Raw TCP proxies run the same fault
//! decision in `on_stream_connect`; stream rejects close the connection and do
//! not deliver HTTP status bodies to clients.
//!
//! UDP and DTLS use the same configured percentages without per-datagram config
//! scans. Session admission aborts run in the isolated per-source /
//! per-DTLS-client setup task (`on_stream_connect`). Per-datagram delays and
//! aborts run in `on_udp_datagram` on the established-session hook-ingress
//! worker (and the first-datagram setup path), never inside the shared listener
//! recv loop, so a delay for peer A cannot stall peer B. UDP/DTLS stream connect
//! deliberately skips delay so the first-datagram path cannot stack two waits;
//! TCP keeps delay+abort on connect. Within one session the worker preserves
//! client→backend ordering: a delayed datagram parks that session's worker under
//! the shared delayed-work budget while later datagrams remain in the bounded
//! hook-ingress queue (or drop fail-closed when that queue is full). Abort is a
//! silent datagram drop. Stream rejects still close / refuse the UDP/DTLS
//! session.
//!
//! ## Config
//!
//! ```json
//! {
//!   "abort": {
//!     "status_code": 503,
//!     "percentage": 50.0,
//!     "grpc_status": 14,
//!     "body": "service unavailable"
//!   },
//!   "delay": {
//!     "duration_ms": 2000,
//!     "percentage": 25.0
//!   },
//!   "runtime_overlay_scope": "checkout"
//! }
//! ```
//!
//! At least one of `abort` or `delay` must be present. When both are
//! configured and both trigger on the same request, the delay executes
//! first, then the abort fires.
//! `runtime_overlay_scope` may be omitted or null to disable RTDS scoping.
//!
//! ## RTDS overlay
//!
//! When `runtime_overlay_scope: "<scope>"` is set, the plugin reads its
//! `abort.percentage` and `delay.percentage` from the RTDS-driven
//! [`MeshRuntimeOverlay`](crate::modes::mesh::config::MeshRuntimeOverlay)
//! from the same plugin-cache/request-epoch generation. Reserved keys:
//!
//! - `ferrum.fault_injection.<scope>.abort_percent`
//! - `ferrum.fault_injection.<scope>.delay_percent`
//!
//! Each accepts either a `Number(0..=100)` or a `FractionalPercent` value.
//! Missing / malformed entries fall back to the static config so a partial
//! overlay never silently disables the plugin. A valid zero temporarily
//! disables that fault side for the accepted generation.
//!
//! ## Delay retention bounds
//!
//! An injected delay deliberately parks a live request, connection, or
//! datagram, so it is bounded three ways by [`super::utils::fault_delay`]: the
//! configuration ceiling ([`MAX_FAULT_DELAY_MS`]), a process-wide budget of
//! concurrently delayed work (`FERRUM_MAX_CONCURRENT_FAULT_DELAYS`), and
//! cancellation on peer departure or gateway shutdown drain. A delay that ends
//! early records `fault_delay_outcome` in metadata; a delay cut short because
//! the client transport is gone rejects with 499 instead of dialing a backend
//! on HTTP paths. UDP/DTLS session teardown cancels an in-flight datagram delay
//! by dropping the hook future (releasing the admission permit) without
//! forwarding.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::utils::fault_delay::{FaultDelayOutcome, run_fault_delay};
use super::utils::fault_roll::{FaultRoller, MAX_FAULT_DELAY_MS};
use super::{
    ALL_PROTOCOLS, Plugin, PluginResult, RequestContext, StreamConnectionContext,
    UdpDatagramContext, UdpDatagramDirection, UdpDatagramVerdict,
};

pub mod runtime_overlay;

/// Metadata key recording why an injected delay ended when it did not run to
/// completion. Absent on the ordinary "the delay elapsed" path so existing
/// log consumers see no new field for normal chaos experiments.
pub(crate) const FAULT_DELAY_OUTCOME_METADATA_KEY: &str = "fault_delay_outcome";

/// Status used when an injected delay is cut short because the client
/// transport is gone. Matches the gateway-wide 499 convention for
/// "client closed request" and never reaches a wire the peer is still reading.
pub(crate) const CLIENT_GONE_STATUS: u16 = 499;

/// Terminal result of an injected HTTP-path delay, shared by the proxy-scoped
/// plugin and `mesh_route_dispatch`'s route-local fault.
pub(crate) enum FaultDelayDisposition {
    /// The delay finished (or was skipped/cut short harmlessly); continue.
    Proceed,
    /// The client transport is gone; abandon the request.
    ClientGone,
}

/// Record a non-completing delay outcome. Values are compiled-in labels from a
/// closed enum, never request-, peer-, or credential-derived.
fn record_delay_outcome(metadata: &mut HashMap<String, String>, outcome: FaultDelayOutcome) {
    let key = FAULT_DELAY_OUTCOME_METADATA_KEY.to_string();
    let label = outcome.metadata_label().to_string();
    metadata.insert(key, label);
}

/// Run an injected HTTP-path delay with the shared retention bounds and record
/// its outcome in `metadata`.
///
/// Returns [`FaultDelayDisposition::ClientGone`] when the frontend's peer watch
/// says the client transport is gone — the caller must then abandon the request
/// instead of dialing a backend for a response nobody will read.
pub(crate) async fn run_http_fault_delay(
    ctx: &mut RequestContext,
    duration_ms: u64,
) -> FaultDelayDisposition {
    // Cheap non-blocking pre-check: an already-dead transport must not even
    // consume a slot from the process-wide delayed-work budget.
    if ctx
        .peer_connection
        .as_ref()
        .is_some_and(|signal| signal.is_closed())
    {
        let gone = FaultDelayOutcome::CancelledByPeer;
        record_delay_outcome(&mut ctx.metadata, gone);
        return FaultDelayDisposition::ClientGone;
    }

    // Race the timer against the frontend's peer-gone watch (HTTP/3 only
    // today) and the gateway shutdown token. Whichever fires first ends the
    // wait, so this task stops holding its request guard, stream, and plugin
    // snapshot the moment they are pointless.
    // Clone the handle (one `Arc` bump, delay path only) so the borrow of
    // `ctx` ends before the metadata write below.
    let signal = ctx.peer_connection.clone();
    let peer_gone = signal.as_ref().map(|signal| signal.closed());
    let outcome = run_fault_delay(duration_ms, peer_gone).await;
    if !outcome.completed() {
        record_delay_outcome(&mut ctx.metadata, outcome);
    }
    if outcome == FaultDelayOutcome::CancelledByPeer {
        FaultDelayDisposition::ClientGone
    } else {
        FaultDelayDisposition::Proceed
    }
}

struct AbortFault {
    status_code: u16,
    percentage: f64,
    grpc_status: Option<u32>,
    body: String,
}

struct DelayFault {
    duration_ms: u64,
    percentage: f64,
}

pub struct FaultInjectionPlugin {
    abort: Option<AbortFault>,
    delay: Option<DelayFault>,
    roller: FaultRoller,
}

impl FaultInjectionPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let obj = config
            .as_object()
            .ok_or("fault_injection: config must be an object")?;
        reject_unknown_keys(
            obj.keys(),
            &["abort", "delay", "runtime_overlay_scope"],
            "config",
        )?;

        let abort = match obj.get("abort") {
            Some(Value::Object(abort_obj)) => {
                reject_unknown_keys(
                    abort_obj.keys(),
                    &["status_code", "percentage", "grpc_status", "body"],
                    "abort",
                )?;
                let status_code = abort_obj
                    .get("status_code")
                    .and_then(|v| v.as_u64())
                    .ok_or(
                        "fault_injection: abort.status_code is required and must be an integer",
                    )?;

                if !(200..=599).contains(&status_code) {
                    return Err(format!(
                        "fault_injection: abort.status_code must be 200-599, got {status_code}"
                    ));
                }

                let percentage = parse_percentage(abort_obj.get("percentage"), "abort.percentage")?;

                let grpc_status = if let Some(grpc_val) = abort_obj.get("grpc_status") {
                    let code = grpc_val
                        .as_u64()
                        .ok_or("fault_injection: abort.grpc_status must be an integer")?;
                    if code > 16 {
                        return Err(format!(
                            "fault_injection: abort.grpc_status must be 0-16, got {code}"
                        ));
                    }
                    Some(code as u32)
                } else {
                    None
                };

                let body = match abort_obj.get("body") {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(_) => {
                        return Err("fault_injection: abort.body must be a string".to_string());
                    }
                };

                Some(AbortFault {
                    status_code: status_code as u16,
                    percentage,
                    grpc_status,
                    body,
                })
            }
            Some(Value::Null) | None => None,
            Some(_) => return Err("fault_injection: 'abort' must be an object".to_string()),
        };

        let delay = match obj.get("delay") {
            Some(Value::Object(delay_obj)) => {
                reject_unknown_keys(delay_obj.keys(), &["duration_ms", "percentage"], "delay")?;
                let duration_ms = delay_obj
                    .get("duration_ms")
                    .and_then(|v| v.as_u64())
                    .ok_or(
                        "fault_injection: delay.duration_ms is required and must be a positive integer",
                    )?;

                if duration_ms == 0 {
                    return Err(
                        "fault_injection: delay.duration_ms must be greater than 0".to_string()
                    );
                }
                if duration_ms > MAX_FAULT_DELAY_MS {
                    return Err(format!(
                        "fault_injection: delay.duration_ms must be <= {MAX_FAULT_DELAY_MS}, got {duration_ms}"
                    ));
                }

                let percentage = parse_percentage(delay_obj.get("percentage"), "delay.percentage")?;

                Some(DelayFault {
                    duration_ms,
                    percentage,
                })
            }
            Some(Value::Null) | None => None,
            Some(_) => return Err("fault_injection: 'delay' must be an object".to_string()),
        };

        if abort.is_none() && delay.is_none() {
            return Err(
                "fault_injection: at least one of 'abort' or 'delay' must be configured"
                    .to_string(),
            );
        }

        match obj.get("runtime_overlay_scope") {
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "fault_injection: runtime_overlay_scope must be a non-empty string"
                            .to_string(),
                    );
                }
            }
            Some(Value::Null) | None => {}
            Some(_) => {
                return Err("fault_injection: runtime_overlay_scope must be a string".to_string());
            }
        }

        Ok(Self {
            abort,
            delay,
            roller: FaultRoller::new(),
        })
    }
}

fn reject_unknown_keys<'a>(
    keys: impl Iterator<Item = &'a String>,
    allowed: &[&str],
    scope: &str,
) -> Result<(), String> {
    for key in keys {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("fault_injection: unknown {scope} field '{key}'"));
        }
    }
    Ok(())
}

fn parse_percentage(val: Option<&Value>, field_name: &str) -> Result<f64, String> {
    let pct = match val {
        Some(Value::Number(n)) => n
            .as_f64()
            .ok_or_else(|| format!("fault_injection: {field_name} must be a number"))?,
        Some(_) => {
            return Err(format!("fault_injection: {field_name} must be a number"));
        }
        None => {
            return Err(format!("fault_injection: {field_name} is required"));
        }
    };

    if !(0.0..=100.0).contains(&pct) {
        return Err(format!(
            "fault_injection: {field_name} must be 0.0-100.0, got {pct}"
        ));
    }
    if pct == 0.0 {
        return Err(format!(
            "fault_injection: {field_name} must be greater than 0.0"
        ));
    }

    Ok(pct)
}

impl FaultInjectionPlugin {
    fn decide_faults(&self) -> (bool, bool) {
        let outcome = self.roller.roll_pair(
            self.delay.as_ref().map(|delay| delay.percentage),
            self.abort.as_ref().map(|abort| abort.percentage),
        );
        (outcome.delay_triggered, outcome.abort_triggered)
    }

    fn reject_for_abort(&self, abort: &AbortFault, is_grpc_request: bool) -> PluginResult {
        let mut headers = HashMap::new();
        if is_grpc_request && let Some(grpc_status) = abort.grpc_status {
            headers.insert("grpc-status".to_string(), grpc_status.to_string());
        }
        PluginResult::Reject {
            status_code: abort.status_code,
            body: abort.body.clone(),
            headers,
        }
    }

    fn reject_for_stream_abort(&self, abort: &AbortFault) -> PluginResult {
        PluginResult::Reject {
            status_code: abort.status_code,
            body: String::new(),
            headers: HashMap::new(),
        }
    }

    /// Record fault metadata onto the UDP/DTLS session summary when a sink is
    /// available. Missing sinks (unit tests without a session map) are no-ops.
    fn record_udp_metadata(&self, ctx: &UdpDatagramContext<'_>, entries: &[(&str, &str)]) {
        let Some(sink) = ctx.metadata_sink else {
            return;
        };
        sink.update(|map| {
            for (key, value) in entries {
                map.insert((*key).to_string(), (*value).to_string());
            }
        });
    }
}

/// Private source marker written by a route-local fault. A normal
/// `fault_injected=true` marker intentionally does not suppress sibling
/// `fault_injection` instances; only a route-local action causes a later,
/// priority-overridden proxy-scoped instance to no-op.
pub(crate) const ROUTE_FAULT_INJECTED_METADATA_KEY: &str = "fault_injection.route_applied";

/// Classify only client-visible native gRPC requests from the immutable flavor
/// fixed before plugin hooks run. Earlier plugins may add, remove, or rewrite
/// `content-type`; none of those mutations may change rejection semantics.
pub(crate) fn is_native_grpc_request(ctx: &RequestContext) -> bool {
    ctx.is_native_grpc_request()
}

#[async_trait]
impl Plugin for FaultInjectionPlugin {
    fn name(&self) -> &str {
        "fault_injection"
    }

    fn priority(&self) -> u16 {
        super::priority::FAULT_INJECTION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        ALL_PROTOCOLS
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        true
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx.metadata.contains_key(ROUTE_FAULT_INJECTED_METADATA_KEY) {
            return PluginResult::Continue;
        }

        let (delay_triggered, abort_triggered) = self.decide_faults();

        if !delay_triggered && !abort_triggered {
            return PluginResult::Continue;
        }

        ctx.metadata
            .insert("fault_injected".to_string(), "true".to_string());

        if delay_triggered && let Some(d) = self.delay.as_ref() {
            let disposition = run_http_fault_delay(ctx, d.duration_ms).await;
            ctx.metadata
                .insert("fault_delay_ms".to_string(), d.duration_ms.to_string());
            if matches!(disposition, FaultDelayDisposition::ClientGone) {
                // The client transport is gone. Abandon the request here
                // rather than dialing a backend for a response nobody will
                // read; the proxy path's normal rejection cleanup releases the
                // request guard and finalizes the stream.
                ctx.metadata
                    .insert("fault_type".to_string(), "delay".to_string());
                return PluginResult::Reject {
                    status_code: CLIENT_GONE_STATUS,
                    body: String::new(),
                    headers: HashMap::new(),
                };
            }
        }

        if abort_triggered && let Some(a) = self.abort.as_ref() {
            let fault_type = if delay_triggered {
                "delay_and_abort"
            } else {
                "abort"
            };
            ctx.metadata
                .insert("fault_type".to_string(), fault_type.to_string());
            ctx.metadata
                .insert("fault_abort_status".to_string(), a.status_code.to_string());

            return self.reject_for_abort(a, is_native_grpc_request(ctx));
        }

        ctx.metadata
            .insert("fault_type".to_string(), "delay".to_string());

        PluginResult::Continue
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let (delay_triggered, abort_triggered) = self.decide_faults();

        // UDP/DTLS application latency is owned by `on_udp_datagram` so the
        // first-datagram setup path (datagram hook, then stream connect) cannot
        // stack two delays for one packet. Session abort still refuses admission
        // here, matching TCP stream rejects. TCP keeps delay+abort on connect.
        let udp_family = matches!(
            ctx.backend_scheme,
            crate::config::types::BackendScheme::Udp | crate::config::types::BackendScheme::Dtls
        );
        let delay_triggered = delay_triggered && !udp_family;

        if !delay_triggered && !abort_triggered {
            return PluginResult::Continue;
        }

        ctx.insert_metadata("fault_injected".to_string(), "true".to_string());

        if delay_triggered && let Some(d) = self.delay.as_ref() {
            // No per-context peer watch here: TCP races this whole hook against
            // a read-half-preserving socket-error watch
            // (`tcp_proxy::wait_for_tcp_peer_reset`); UDP/DTLS session setup
            // already runs in an isolated per-source / per-client task that is
            // cancelled when the pending gate / DTLS accept handler exits. What
            // the plugin still owns is the shutdown token and the process-wide
            // delayed-work budget.
            let outcome = run_fault_delay(d.duration_ms, None).await;
            ctx.insert_metadata("fault_delay_ms".to_string(), d.duration_ms.to_string());
            if !outcome.completed() {
                let key = FAULT_DELAY_OUTCOME_METADATA_KEY.to_string();
                let label = outcome.metadata_label().to_string();
                ctx.insert_metadata(key, label);
            }
        }

        if abort_triggered && let Some(a) = self.abort.as_ref() {
            let fault_type = if delay_triggered {
                "delay_and_abort"
            } else {
                "abort"
            };
            ctx.insert_metadata("fault_type".to_string(), fault_type.to_string());
            ctx.insert_metadata("fault_abort_status".to_string(), a.status_code.to_string());

            return self.reject_for_stream_abort(a);
        }

        ctx.insert_metadata("fault_type".to_string(), "delay".to_string());

        PluginResult::Continue
    }

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        // Mirror HTTP/TCP request-path semantics: only client→backend datagrams
        // are faulted. Backend replies continue so a delayed request can still
        // observe a response after the delay elapses.
        if ctx.direction != UdpDatagramDirection::ClientToBackend {
            return UdpDatagramVerdict::Forward;
        }

        let (delay_triggered, abort_triggered) = self.decide_faults();
        if !delay_triggered && !abort_triggered {
            return UdpDatagramVerdict::Forward;
        }

        self.record_udp_metadata(ctx, &[("fault_injected", "true")]);

        if delay_triggered && let Some(d) = self.delay.as_ref() {
            // Runs on the per-session hook-ingress worker (or the isolated
            // first-datagram setup task), never the shared recv loop. Session
            // teardown selects against this future and drops it, releasing the
            // admission permit without forwarding.
            let outcome = run_fault_delay(d.duration_ms, None).await;
            let delay_ms = d.duration_ms.to_string();
            if outcome.completed() {
                self.record_udp_metadata(ctx, &[("fault_delay_ms", delay_ms.as_str())]);
            } else {
                self.record_udp_metadata(
                    ctx,
                    &[
                        ("fault_delay_ms", delay_ms.as_str()),
                        (FAULT_DELAY_OUTCOME_METADATA_KEY, outcome.metadata_label()),
                    ],
                );
            }
            // Shutdown / admission-skip continue like HTTP/TCP (delay skipped).
            // Peer/session teardown cancels by dropping this future before Forward.
        }

        if abort_triggered && let Some(a) = self.abort.as_ref() {
            let fault_type = if delay_triggered {
                "delay_and_abort"
            } else {
                "abort"
            };
            let status = a.status_code.to_string();
            self.record_udp_metadata(
                ctx,
                &[
                    ("fault_type", fault_type),
                    ("fault_abort_status", status.as_str()),
                ],
            );
            return UdpDatagramVerdict::Drop;
        }

        self.record_udp_metadata(ctx, &[("fault_type", "delay")]);
        UdpDatagramVerdict::Forward
    }
}
