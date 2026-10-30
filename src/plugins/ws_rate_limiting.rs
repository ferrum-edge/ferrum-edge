//! WebSocket frame rate limiting with shared local/Redis/failover storage.

use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use serde_json::Value;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use uuid::Uuid;

use super::utils::rate_limit::{
    LocalStateSemantics, RATE_LIMIT_REDIS_CONFIG_KEYS, RateLimitBackend,
    STANDALONE_RATE_LIMIT_CONFIG_ID, WsFrameRateAlgorithm, WsRateLimitKey, WsRateLimitOp,
    apply_rate_limit_cleanup, debug_assert_closed_root_keys, debug_assert_rate_limit_redis_keys,
    validate_ws_frame_rate_bounds, validate_ws_frame_rate_params,
};
use super::{
    Plugin, PluginHttpClient, ProxyProtocol, RequestContext, WS_ONLY_PROTOCOLS,
    WebSocketFrameDirection, WsDisconnectContext,
};
use crate::util::unknown_keys::reject_unknown_keys;

/// `ws_rate_limiting`-specific top-level config keys (excludes Redis fields).
const WS_RATE_LIMITING_POLICY_CONFIG_KEYS: &[&str] = &[
    "frames_per_second",
    "burst_size",
    "close_reason",
    "limit_by",
];

/// Closed top-level key set for `ws_rate_limiting` plugin config.
///
/// Must stay aligned with OpenAPI `WsRateLimitingConfig`,
/// [`RATE_LIMIT_REDIS_CONFIG_KEYS`], and `docs/plugins.md`. A misspelled
/// `frames_per_secod`/`redis_tsl` otherwise loaded silently as the default
/// frame budget or plaintext Redis transport.
pub const WS_RATE_LIMITING_CONFIG_KEYS: &[&str] = &[
    "frames_per_second",
    "burst_size",
    "close_reason",
    "limit_by",
    // Shared Redis sync (see RATE_LIMIT_REDIS_CONFIG_KEYS)
    "sync_mode",
    "redis_tls",
    "redis_url",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
    "redis_failure_policy",
];

const MAX_STATE_ENTRIES: usize = 50_000;
const EVICTION_CHECK_INTERVAL: u64 = 100_000;
/// Single-flights full-map idle sweeps, below and above the cap, to at most one
/// per cooldown window under high frame rates. Over-cap capacity is still
/// enforced on every frame: live budgets are never force-evicted, and hard
/// cardinality is enforced by atomic admission reservation.
const EVICTION_COOLDOWN_SECS: u64 = 1;

/// The `limit_by` budget dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WsLimitBy {
    /// One budget per accepted WebSocket session (the default).
    Connection,
    /// One budget per authenticated identity (mapped Consumer username, else
    /// the committed external identity); anonymous sessions share their client
    /// IP's budget.
    Consumer,
    /// One budget per resolved client IP.
    Ip,
    /// One budget per proxy (the route / service the session was admitted on).
    Service,
}

impl WsLimitBy {
    /// Canonical rendering of the parsed dimension, recorded in the local-state
    /// compatibility semantics.
    fn as_str(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Consumer => "consumer",
            Self::Ip => "ip",
            Self::Service => "service",
        }
    }

    fn parse(config: &Value) -> Result<Self, String> {
        match optional_string(config, "limit_by")? {
            None | Some("connection") => Ok(Self::Connection),
            Some("consumer") => Ok(Self::Consumer),
            Some("ip") => Ok(Self::Ip),
            Some("service") => Ok(Self::Service),
            // Value-redacted: name the accepted set, never echo the input.
            Some(_) => Err(
                "ws_rate_limiting: `limit_by` must be one of `connection`, `consumer`, `ip`, \
                 or `service`"
                    .to_string(),
            ),
        }
    }
}

pub struct WsRateLimiting {
    close_reason: String,
    limit_by: WsLimitBy,
    frame_counter: AtomicU64,
    redis_instance_id: String,
    limiter: RateLimitBackend<WsRateLimitKey, WsFrameRateAlgorithm>,
    epoch_base: Instant,
    last_periodic_sweep_secs: AtomicU64,
}

impl WsRateLimiting {
    const MAX_CLOSE_REASON_BYTES: usize = 123;

    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, STANDALONE_RATE_LIMIT_CONFIG_ID)
    }

    /// Construct with the stable plugin-config resource id that isolates this
    /// policy's default Redis frame counters from sibling `ws_rate_limiting`
    /// instances in the same namespace. See
    /// [`super::utils::rate_limit::RedisLimiter::new_with_config_id`].
    pub fn new_with_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        config_id: &str,
    ) -> Result<Self, String> {
        Self::from_parts(config, http_client, None, config_id)
    }

    /// Construct with local enforcement state shared across compatible
    /// plugin-cache generations for the stable `(namespace, plugin kind,
    /// plugin-config id)` policy identity.
    ///
    /// Local keys are the proxy's process-wide monotonic WebSocket connection
    /// ids (`ProxyState::ws_connection_counter`), which outlive a config reload,
    /// so a live connection keeps its consumed frame budget instead of being
    /// handed a full bucket by an unrelated plugin-config change.
    pub fn new_with_policy_identity(
        config: &Value,
        http_client: PluginHttpClient,
        namespace: &str,
        config_id: &str,
    ) -> Result<Self, String> {
        Self::from_parts(config, http_client, Some(namespace), config_id)
    }

    fn from_parts(
        config: &Value,
        http_client: PluginHttpClient,
        namespace: Option<&str>,
        config_id: &str,
    ) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "ws_rate_limiting: config must be an object".to_string())?;
        debug_assert_rate_limit_redis_keys();
        debug_assert_closed_root_keys(
            WS_RATE_LIMITING_CONFIG_KEYS,
            WS_RATE_LIMITING_POLICY_CONFIG_KEYS,
            RATE_LIMIT_REDIS_CONFIG_KEYS,
        );
        reject_unknown_keys(
            object,
            "config",
            WS_RATE_LIMITING_CONFIG_KEYS,
            "ws_rate_limiting: `config`: ",
        )?;

        let frames_per_second = optional_positive_u64(config, "frames_per_second")?.unwrap_or(100);
        let burst_size = optional_positive_u64(config, "burst_size")?.unwrap_or(frames_per_second);
        let limit_by = WsLimitBy::parse(config)?;

        // With Redis sync, local token-bucket and Redis two-window enforcement
        // must share the same sustained rate for every accepted config
        // (including Redis failure/recovery), so values Redis cannot represent
        // without over-admitting or under-admitting are rejected
        // (GHSA-cjcm-546w-696v). A local-only policy runs the token bucket
        // alone, which represents any capacity/refill pair, so it only needs
        // the operational bounds. `sync_mode` itself is validated by the shared
        // Redis config parser below; this mirrors its case-insensitive match.
        let redis_sync = config
            .get("sync_mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| mode.eq_ignore_ascii_case("redis"));
        if redis_sync {
            validate_ws_frame_rate_params(frames_per_second, burst_size)?;
        } else {
            validate_ws_frame_rate_bounds(frames_per_second, burst_size)?;
        }

        let mut close_reason = optional_string(config, "close_reason")?
            .unwrap_or("Frame rate exceeded")
            .to_string();
        if close_reason.len() > Self::MAX_CLOSE_REASON_BYTES {
            tracing::debug!(
                max_bytes = Self::MAX_CLOSE_REASON_BYTES,
                "ws_rate_limiting: `close_reason` exceeds WebSocket control-frame limit — truncating"
            );
            close_reason.truncate(Self::truncate_utf8_boundary(
                &close_reason,
                Self::MAX_CLOSE_REASON_BYTES,
            ));
        }

        // Effective enforcement semantics, not raw syntax: the token bucket's
        // sustained rate and burst capacity after defaulting (`frames_per_second`
        // omitted is 100, `burst_size` omitted is the sustained rate), so an
        // explicit default and an omission describe the same bucket.
        // `close_reason` is client-visible presentation only and never resets a
        // live budget; the shared Redis posture is added by the backend.
        let mut semantics = LocalStateSemantics::new();
        semantics.u64("frames_per_second", frames_per_second);
        semantics.u64("burst_size", burst_size);
        semantics.text("limit_by", limit_by.as_str());

        Ok(Self {
            close_reason,
            limit_by,
            frame_counter: AtomicU64::new(0),
            redis_instance_id: Uuid::new_v4().simple().to_string(),
            limiter: RateLimitBackend::from_plugin_config_with_policy_identity(
                "ws_rate_limiting",
                namespace,
                config_id,
                config,
                &http_client,
                WsFrameRateAlgorithm::new(frames_per_second as f64, burst_size as f64),
                &semantics,
            )
            .map_err(|error| format!("ws_rate_limiting: {error}"))?,
            epoch_base: Instant::now(),
            last_periodic_sweep_secs: AtomicU64::new(0),
        })
    }

    /// Whether this instance enforces on the same live local state as `other`.
    ///
    /// A compatible reload generation for one policy identity must share; an
    /// unrelated policy, tenant, plugin kind, or semantically changed policy
    /// must not. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn shares_local_state_with(&self, other: &Self) -> bool {
        self.limiter.shares_local_state_with(&other.limiter)
    }

    /// Local/fallback DashMap shard count. Test-only; not a production API.
    #[cfg(test)]
    pub(crate) fn local_map_shard_amount(&self) -> usize {
        self.limiter.local_map_shard_amount()
    }

    /// Effective `redis_failure_policy` for advisory coverage. Not a production
    /// API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn redis_failure_policy_for_test(
        &self,
    ) -> Option<super::utils::rate_limit::RedisFailurePolicy> {
        self.limiter.redis_failure_policy()
    }

    /// Whether this policy's centralized client demands the Redis server clock
    /// (`TIME`). `None` for a local-only config. Not a production API.
    ///
    /// Only the request-quota ladder selects sub-buckets on the server's clock,
    /// so this is what proves which of the six Redis-backed rate-limit roots
    /// forces an operator's ACL to grant `+time`.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn redis_requires_server_clock_for_test(&self) -> Option<bool> {
        self.limiter
            .redis_client_arc_for_test()
            .map(|client| client.requires_server_clock_for_test())
    }

    /// Charge one frame against the local token bucket at `now` and report
    /// whether it was admitted. Deterministic (no wall-clock sleep) mirror of
    /// the frame budget for stable-state coverage. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn charge_frame_locally_at_for_test(
        &self,
        connection_id: u64,
        now: Instant,
    ) -> bool {
        self.limiter
            .check_local_at(
                WsRateLimitKey::Connection(connection_id),
                &WsRateLimitOp::ONE,
                now,
            )
            .allowed
    }

    /// Controllable-time seed for external cleanup tests. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn seed_connection_at_for_test(&self, connection_id: u64, now: Instant) {
        let _ = self.limiter.check_local_at(
            WsRateLimitKey::Connection(connection_id),
            &WsRateLimitOp::ONE,
            now,
        );
    }

    /// Attempt to seed one local/fallback key through the production atomic
    /// capacity gate. Returns false only for a previously unseen key at cap.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn seed_connection_at_with_cap_for_test(
        &self,
        connection_id: u64,
        now: Instant,
        max_entries: usize,
    ) -> bool {
        self.limiter
            .check_local_at_with_capacity(
                WsRateLimitKey::Connection(connection_id),
                &WsRateLimitOp::ONE,
                now,
                max_entries,
            )
            .is_some()
    }

    /// The production hard cap on resident local/fallback keys. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) const fn max_state_entries_for_test() -> usize {
        MAX_STATE_ENTRIES
    }

    /// Arm the sampled periodic gate without spinning 100k frames. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn arm_periodic_eviction_for_test(&self) {
        self.frame_counter
            .store(EVICTION_CHECK_INTERVAL, Ordering::Relaxed);
        self.last_periodic_sweep_secs.store(0, Ordering::Relaxed);
    }

    /// Block the below-cap cooldown so an armed sample does not scan. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn block_periodic_cooldown_at_for_test(&self, now: Instant) {
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
        self.last_periodic_sweep_secs
            .store(now_secs, Ordering::Relaxed);
    }

    /// Invoke the production sampled/cooldown eviction path at `now`. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn maybe_evict_at_for_test(&self, now: Instant) -> bool {
        self.maybe_evict_at(now)
    }

    /// Exercise the shared prune/enforce branch with a testable cap. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn apply_cleanup_branch_for_test(
        &self,
        now: Instant,
        over_capacity: bool,
        max_entries: usize,
    ) {
        apply_rate_limit_cleanup(&self.limiter, max_entries, now, over_capacity);
    }

    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn contains_connection_for_test(&self, connection_id: u64) -> bool {
        self.limiter
            .contains_local_key(&WsRateLimitKey::Connection(connection_id))
    }

    /// Centralized logical key for one local budget key.
    ///
    /// A connection budget is process-local (`connection_id` comes from a
    /// per-process counter), so it is scoped by this instance's UUID and the
    /// proxy. An aggregate budget names a portable identity, so it is used as
    /// is: replicas of one policy share it under the policy's default
    /// namespace/plugin/config-id prefix. Evaluated only on the Redis arm.
    fn redis_scope_key(&self, proxy_id: &str, key: &WsRateLimitKey) -> String {
        match key {
            WsRateLimitKey::Connection(connection_id) => {
                self.redis_connection_scope_key(proxy_id, *connection_id)
            }
            WsRateLimitKey::Aggregate(scope) => scope.to_string(),
        }
    }

    /// Aggregate budget identity for one upgrade, or `None` in connection mode.
    ///
    /// Resolved once at admission from the authoritative upgrade context, so no
    /// frame re-derives or allocates it.
    fn aggregate_scope(&self, ctx: &RequestContext) -> Option<Arc<str>> {
        let (prefix, value) = match self.limit_by {
            WsLimitBy::Connection => return None,
            WsLimitBy::Consumer => match ctx.effective_identity() {
                Some(identity) => ("consumer:", identity),
                None => ("ip:", ctx.client_ip.as_str()),
            },
            WsLimitBy::Ip => ("ip:", ctx.client_ip.as_str()),
            WsLimitBy::Service => ("service:", ctx.matched_proxy.as_ref()?.id.as_str()),
        };
        let mut scope = String::with_capacity(prefix.len() + value.len());
        scope.push_str(prefix);
        scope.push_str(value);
        Some(Arc::from(scope))
    }

    pub(crate) fn redis_connection_scope_key(&self, proxy_id: &str, connection_id: u64) -> String {
        let mut key = String::with_capacity(self.redis_instance_id.len() + proxy_id.len() + 22);
        key.push_str(&self.redis_instance_id);
        key.push(':');
        key.push_str(proxy_id);
        key.push(':');
        let _ = write!(&mut key, "{connection_id}");
        key
    }

    fn truncate_utf8_boundary(value: &str, max_bytes: usize) -> usize {
        let mut end = value.len().min(max_bytes);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        end
    }

    /// Shared admission for reassembled messages and for the physical fragments
    /// they were built from. Returns the terminal policy Close when the budget
    /// is exhausted or the connection cannot be admitted to local state.
    async fn charge_frames(
        &self,
        proxy_id: &str,
        connection_id: u64,
        key: &WsRateLimitKey,
        direction: WebSocketFrameDirection,
        op: WsRateLimitOp,
    ) -> Option<Message> {
        let _ = self.maybe_evict();
        let Some(outcome) = self
            .limiter
            .check_with_redis_key_and_local_capacity(
                key.clone(),
                || self.redis_scope_key(proxy_id, key),
                &op,
                MAX_STATE_ENTRIES,
            )
            .await
        else {
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            return Some(self.policy_close());
        };

        if outcome.allowed {
            return None;
        }

        // A fail-closed refusal (centralized enforcement unavailable under
        // `redis_failure_policy: "fail_closed"`) closes the connection just like
        // an exceeded budget — a frame stream has no other refusal channel. It is
        // not a budget overrun, so it does not increment `rate_limit_exceeded`;
        // it is counted in `ferrum_rate_limit_enforcement_unavailable_total`,
        // the same per-decision signal `rate_limiting` uses for its `503`s, so an
        // outage that mass-closes sessions moves a metric. It does not log here;
        // the shared backend already emits the bounded once-per-outage warning.
        if outcome.enforcement_unavailable {
            super::prometheus_metrics::global_registry()
                .record_rate_limit_enforcement_unavailable();
            return Some(self.policy_close());
        }

        super::prometheus_metrics::global_registry().record_rate_limit_exceeded();

        let dir_label = match direction {
            WebSocketFrameDirection::ClientToBackend => "client->backend",
            WebSocketFrameDirection::BackendToClient => "backend->client",
        };
        // One bounded, low-cardinality warning per closed connection: this is
        // the terminal decision, not a per-frame event.
        warn_sampled!(
            plugin = "ws_rate_limiting",
            proxy_id = %proxy_id,
            connection_id,
            direction = dir_label,
            charged_frames = op.frame_count(),
            "WebSocket frame rate exceeded, closing connection"
        );
        Some(self.policy_close())
    }

    fn policy_close(&self) -> Message {
        Message::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: self.close_reason.clone().into(),
        }))
    }

    fn maybe_evict(&self) -> bool {
        self.maybe_evict_at(Instant::now())
    }

    /// Unbound charge on the shared instance.
    ///
    /// Connection mode needs no session binding. An aggregate `limit_by`
    /// budget is resolved only through [`Plugin::bind_ws_session`], so reaching
    /// here in that mode means a relay path collected frame hooks without
    /// binding the session: there is no identity to charge, and silently
    /// charging a per-connection budget instead would lift the configured
    /// aggregate ceiling. Fail closed.
    async fn charge_unbound(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        op: WsRateLimitOp,
    ) -> Option<Message> {
        if self.limit_by != WsLimitBy::Connection {
            warn_sampled!(
                plugin = "ws_rate_limiting",
                proxy_id = %proxy_id,
                connection_id,
                limit_by = self.limit_by.as_str(),
                "WebSocket session reached an aggregate frame budget without session binding, \
                 closing connection"
            );
            return Some(self.policy_close());
        }
        let key = WsRateLimitKey::Connection(connection_id);
        self.charge_frames(proxy_id, connection_id, &key, direction, op)
            .await
    }

    fn maybe_evict_at(&self, now: Instant) -> bool {
        let count = self.frame_counter.fetch_add(1, Ordering::Relaxed);
        let tracked_keys = self.limiter.tracked_keys_count();
        // Pressure starts AT the cap. Atomic admission reservation never lets
        // the map grow past `MAX_STATE_ENTRIES`, so a strict `>` was
        // unreachable and a map filled with idle entries kept refusing every
        // previously unseen key until a traffic-count-sampled sweep happened to
        // run.
        let at_capacity = tracked_keys >= MAX_STATE_ENTRIES;

        // Capacity pressure reclaims idle keys, single-flighted by the same
        // once-per-cooldown CAS gate `udp_rate_limiting` uses, so concurrent
        // frames cannot each run a full retain while the map is at the cap.
        // Live budgets are never force-evicted; previously unseen keys fail
        // closed via atomic admission reservation, so a frame that loses the
        // gate still sees the capacity pressure.
        if at_capacity {
            let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
            let last_sweep = self.last_periodic_sweep_secs.load(Ordering::Relaxed);
            if now_secs.saturating_sub(last_sweep) >= EVICTION_COOLDOWN_SECS
                && self
                    .last_periodic_sweep_secs
                    .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                apply_rate_limit_cleanup(&self.limiter, MAX_STATE_ENTRIES, now, true);
                return self.limiter.tracked_keys_count() >= MAX_STATE_ENTRIES;
            }
            return true;
        }

        let periodic =
            count > 0 && count.is_multiple_of(EVICTION_CHECK_INTERVAL) && tracked_keys > 0;
        if periodic {
            let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
            let last_sweep = self.last_periodic_sweep_secs.load(Ordering::Relaxed);
            if now_secs.saturating_sub(last_sweep) >= EVICTION_COOLDOWN_SECS
                && self
                    .last_periodic_sweep_secs
                    .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                apply_rate_limit_cleanup(&self.limiter, MAX_STATE_ENTRIES, now, false);
            }
        }

        self.limiter.tracked_keys_count() >= MAX_STATE_ENTRIES
    }
}

fn optional_positive_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ws_rate_limiting: `{field}` must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "ws_rate_limiting: `{field}` must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ws_rate_limiting: `{field}` must be a string"))
}

#[async_trait]
impl Plugin for WsRateLimiting {
    /// Starts the Redis failover health observer only once this generation is
    /// installed, so validation that builds and drops the plugin spawns
    /// nothing (issue #6616).
    fn commit_background_tasks(&self) {
        self.limiter.commit_background_tasks();
    }

    fn name(&self) -> &str {
        "ws_rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::WS_RATE_LIMITING
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::NONE
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    /// Bind an aggregate `limit_by` budget to one accepted session.
    ///
    /// The budget identity (consumer, client IP, or proxy) is resolved once,
    /// here, from the finalized upgrade context, and the session-bound
    /// instance charges that one shared key for every frame. Connection mode
    /// keeps the shared instance (`None`), which keys on the frame's
    /// `connection_id`.
    fn bind_ws_session(self: Arc<Self>, ctx: &RequestContext) -> Option<Arc<dyn Plugin>> {
        let scope = self.aggregate_scope(ctx)?;
        Some(Arc::new(WsRateLimitingSession {
            plugin: self,
            key: WsRateLimitKey::Aggregate(scope),
        }))
    }

    /// Connection budgets are keyed by a process-unique session id that is
    /// never charged again once the session ends, so they are released at
    /// teardown instead of occupying a capacity slot until an idle sweep.
    /// Aggregate budgets outlive any one session and age out on the sweep.
    fn requires_ws_disconnect_hooks(&self) -> bool {
        self.limit_by == WsLimitBy::Connection
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        if self.limit_by == WsLimitBy::Connection {
            self.limiter
                .remove_local_key(&WsRateLimitKey::Connection(ctx.connection_id));
        }
    }

    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<Message> {
        // An earlier admission/mutating frame plugin may already have synthesized
        // a terminal Close. Do not charge local/Redis budget, run eviction
        // sampling, or replace that Close with a 1008 Policy Violation.
        if matches!(message, Message::Close(_)) {
            return None;
        }

        // One reassembled message or control frame == one wire frame. The
        // fragments it was assembled from were already charged through
        // `on_ws_reassembly_frames`, so this never double-charges them.
        self.charge_unbound(proxy_id, connection_id, direction, WsRateLimitOp::ONE)
            .await
    }

    async fn on_ws_reassembly_frames(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        fragment_frames: u64,
    ) -> Option<Message> {
        if fragment_frames == 0 {
            return None;
        }
        // Physical fragments that produced no message: an initial non-final
        // Text/Binary frame plus every intermediate continuation, including
        // zero-length ones. Charged as one batched op so the Redis path stays
        // at a single round trip (GHSA-qq94-2gv2-phh6).
        self.charge_unbound(
            proxy_id,
            connection_id,
            direction,
            WsRateLimitOp::frames(fragment_frames),
        )
        .await
    }
}

/// One accepted WebSocket session bound to an aggregate `limit_by` budget.
///
/// Holds only the shared plugin instance and the session's precomputed budget
/// key, so per-frame admission is the same allocation-free local path as
/// connection mode (cloning the key is a reference-count bump).
struct WsRateLimitingSession {
    plugin: Arc<WsRateLimiting>,
    key: WsRateLimitKey,
}

#[async_trait]
impl Plugin for WsRateLimitingSession {
    fn name(&self) -> &str {
        "ws_rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::WS_RATE_LIMITING
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::NONE
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    /// The session is the bound `ws_rate_limiting` instance, so it carries the
    /// built-in's declaration rather than the out-of-tree default (issue #6022).
    fn response_body_production(&self) -> super::ResponseBodyProduction {
        Plugin::response_body_production(&*self.plugin)
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<Message> {
        // Same terminal-Close rule as the shared instance.
        if matches!(message, Message::Close(_)) {
            return None;
        }
        self.plugin
            .charge_frames(
                proxy_id,
                connection_id,
                &self.key,
                direction,
                WsRateLimitOp::ONE,
            )
            .await
    }

    async fn on_ws_reassembly_frames(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        fragment_frames: u64,
    ) -> Option<Message> {
        if fragment_frames == 0 {
            return None;
        }
        self.plugin
            .charge_frames(
                proxy_id,
                connection_id,
                &self.key,
                direction,
                WsRateLimitOp::frames(fragment_frames),
            )
            .await
    }
}
