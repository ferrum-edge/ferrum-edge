//! UDP datagram rate limiting with shared local/Redis/failover storage.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::warn;

use super::utils::rate_limit::{
    LocalStateSemantics, RATE_LIMIT_REDIS_CONFIG_KEYS, RateLimitBackend,
    STANDALONE_RATE_LIMIT_CONFIG_ID, UdpRateLimitAlgorithm, UdpRateLimitOp,
    apply_rate_limit_cleanup, debug_assert_closed_root_keys, debug_assert_rate_limit_redis_keys,
    validate_window_seconds,
};
use super::{
    Plugin, PluginHttpClient, ProxyProtocol, UDP_ONLY_PROTOCOLS, UdpDatagramContext,
    UdpDatagramVerdict,
};
use crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter;
use crate::util::unknown_keys::reject_unknown_keys;

/// `udp_rate_limiting`-specific top-level config keys (excludes Redis fields).
const UDP_RATE_LIMITING_POLICY_CONFIG_KEYS: &[&str] =
    &["datagrams_per_second", "bytes_per_second", "window_seconds"];

/// Closed top-level key set for `udp_rate_limiting` plugin config.
///
/// Must stay aligned with OpenAPI `UdpRateLimitingConfig`,
/// [`RATE_LIMIT_REDIS_CONFIG_KEYS`], and `docs/plugins.md`. A misspelled
/// `sync_mdoe`/`bytes_per_secnod` otherwise loaded silently as per-process,
/// datagram-only enforcement.
pub const UDP_RATE_LIMITING_CONFIG_KEYS: &[&str] = &[
    "datagrams_per_second",
    "bytes_per_second",
    "window_seconds",
    // Shared Redis sync (see RATE_LIMIT_REDIS_CONFIG_KEYS)
    "sync_mode",
    "redis_url",
    "redis_tls",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
    "redis_failure_policy",
];

const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_COOLDOWN_SECS: u64 = 1;
const EVICTION_CHECK_INTERVAL: u64 = 100_000;

/// Outcome of a UDP rate-limit rejection diagnostic decision. Test-only fields
/// expose the suppressed counts carried by an emit without logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RejectionWarnDecisionForTest {
    pub(crate) emitted: bool,
    pub(crate) instance_suppressed: Option<u64>,
    pub(crate) global_suppressed: Option<u64>,
}

static GLOBAL_REJECTION_WARN: OnceLock<AtomicLogRateLimiter> = OnceLock::new();

fn global_rejection_warn() -> &'static AtomicLogRateLimiter {
    GLOBAL_REJECTION_WARN.get_or_init(AtomicLogRateLimiter::new)
}

pub struct UdpRateLimiting {
    check_counter: AtomicU64,
    epoch_base: Instant,
    last_eviction_secs: AtomicU64,
    rejection_warn: AtomicLogRateLimiter,
    limiter: RateLimitBackend<Arc<str>, UdpRateLimitAlgorithm>,
}

impl UdpRateLimiting {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new_with_http_client(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, STANDALONE_RATE_LIMIT_CONFIG_ID)
    }

    /// Construct with the stable plugin-config resource id that isolates this
    /// policy's default Redis counters from sibling `udp_rate_limiting`
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
    /// An inherited limiter keeps the algorithm — and therefore the window
    /// epoch — it was created with, so an inherited counter is never
    /// re-indexed onto a replacement generation's fresh epoch. A change to the
    /// effective per-window datagram/byte budgets or the window length isolates
    /// onto fresh state instead.
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
            .ok_or_else(|| "udp_rate_limiting: config must be an object".to_string())?;
        // Keeps the documented key groups aligned with the closed root
        // allowlist used for admission and OpenAPI parity.
        debug_assert_rate_limit_redis_keys();
        debug_assert_closed_root_keys(
            UDP_RATE_LIMITING_CONFIG_KEYS,
            UDP_RATE_LIMITING_POLICY_CONFIG_KEYS,
            RATE_LIMIT_REDIS_CONFIG_KEYS,
        );
        reject_unknown_keys(
            object,
            "config",
            UDP_RATE_LIMITING_CONFIG_KEYS,
            "udp_rate_limiting: `config`: ",
        )?;

        let datagrams_per_second = optional_positive_u64(config, "datagrams_per_second")?;
        let bytes_per_second = optional_positive_u64(config, "bytes_per_second")?;

        if datagrams_per_second.is_none() && bytes_per_second.is_none() {
            return Err(
                "udp_rate_limiting: at least one of `datagrams_per_second` or `bytes_per_second` must be set"
                    .to_string(),
            );
        }

        // A window near `u64::MAX` passed the checked per-window multiplication
        // below when the rate was 1, then wrapped `window + 1` (Redis TTL) to
        // zero and `window * 2` (activity retention) to zero — every increment
        // deleted its own counter, removing enforcement entirely.
        let window_seconds = match optional_positive_u64(config, "window_seconds")? {
            Some(value) => validate_window_seconds("udp_rate_limiting", "window_seconds", value)
                .map_err(|error| format!("udp_rate_limiting: {error}"))?,
            None => 1,
        };
        let datagrams_per_window = per_window_limit(datagrams_per_second, window_seconds)?;
        let bytes_per_window = per_window_limit(bytes_per_second, window_seconds)?;
        // Effective enforcement semantics, not raw syntax: the per-window
        // budgets the algorithm actually enforces and the window length after
        // defaulting (`window_seconds` omitted is 1), so an omitted window and
        // an explicit `1` describe the same budget. An unset axis is encoded
        // distinctly from any set value — unlimited is not a bound. The shared
        // Redis posture is added by the backend.
        let mut semantics = LocalStateSemantics::new();
        semantics.optional_u64("datagrams_per_window", datagrams_per_window);
        semantics.optional_u64("bytes_per_window", bytes_per_window);
        semantics.u64("window_seconds", window_seconds);

        let epoch_base = Instant::now();

        Ok(Self {
            check_counter: AtomicU64::new(0),
            epoch_base,
            last_eviction_secs: AtomicU64::new(0),
            rejection_warn: AtomicLogRateLimiter::new(),
            limiter: RateLimitBackend::from_plugin_config_with_policy_identity(
                "udp_rate_limiting",
                namespace,
                config_id,
                config,
                &http_client,
                UdpRateLimitAlgorithm::new(
                    datagrams_per_window,
                    bytes_per_window,
                    window_seconds,
                    epoch_base,
                ),
                &semantics,
            )
            .map_err(|error| format!("udp_rate_limiting: {error}"))?,
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

    /// Effective `redis_failure_policy` for advisory coverage: `None` for a
    /// local-only config, `FailClosed` unless the operator opted into
    /// `local_fallback`. Not a production API.
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

    /// Effective Redis key prefix for policy-isolation coverage. Not a
    /// production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn redis_key_prefix_for_test(&self) -> Option<String> {
        self.limiter.redis_key_prefix().map(str::to_string)
    }

    /// All-shard `DashMap::len()` observations on the local/fallback map.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn all_shard_len_calls_for_test(&self) -> usize {
        self.limiter.all_shard_len_calls_for_test()
    }

    /// Exact DashMap length for reconciling the atomic entry count in tests.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn map_len_for_test(&self) -> usize {
        self.limiter.map_len_for_test()
    }

    /// Controllable-time seed for external cleanup tests. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn seed_client_at_for_test(
        &self,
        client_ip: Arc<str>,
        datagram_size: u64,
        now: Instant,
    ) {
        let _ = self
            .limiter
            .check_local_at(client_ip, &UdpRateLimitOp { datagram_size }, now);
    }

    /// Attempt to seed one local/fallback key through the production atomic
    /// capacity gate. Returns false only for a previously unseen key at cap.
    #[allow(dead_code)]
    pub(crate) fn seed_client_at_with_cap_for_test(
        &self,
        client_ip: Arc<str>,
        datagram_size: u64,
        now: Instant,
        max_entries: usize,
    ) -> bool {
        self.limiter
            .check_local_at_with_capacity(
                client_ip,
                &UdpRateLimitOp { datagram_size },
                now,
                max_entries,
            )
            .is_some()
    }

    /// Arm the sampled periodic gate without spinning 100k hooks. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn arm_periodic_eviction_for_test(&self) {
        self.check_counter
            .store(EVICTION_CHECK_INTERVAL, Ordering::Relaxed);
        self.last_eviction_secs.store(0, Ordering::Relaxed);
    }

    /// Force the cooldown clock so the next armed periodic sweep is blocked.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn block_eviction_cooldown_at_for_test(&self, now: Instant) {
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
        self.last_eviction_secs.store(now_secs, Ordering::Relaxed);
    }

    /// Invoke the production sampled/cooldown eviction path at `now`. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn maybe_evict_at_for_test(&self, now: Instant) -> bool {
        self.maybe_evict_at(now)
    }

    /// Exercise the production sampled/cooldown path with a testable cap.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn maybe_evict_at_with_cap_for_test(
        &self,
        now: Instant,
        max_entries: usize,
    ) -> bool {
        self.maybe_evict_at_with_cap(now, max_entries)
    }

    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn contains_client_for_test(&self, client_ip: &Arc<str>) -> bool {
        self.limiter.contains_local_key(client_ip)
    }

    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn epoch_base_for_test(&self) -> Instant {
        self.epoch_base
    }

    /// Exercise the production dual-gate decision with an isolated global
    /// limiter so parallel external tests never mutate process-global state.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn record_rate_limit_rejection_warn_detail_for_test(
        &self,
        global: &AtomicLogRateLimiter,
        limit_kind: &'static str,
        proxy_id: &str,
        now_ms: u64,
    ) -> RejectionWarnDecisionForTest {
        self.record_rate_limit_rejection_warn_with_global(global, limit_kind, proxy_id, now_ms)
    }

    /// Observed per-instance suppressed-event accumulator. Test-only.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn rejection_warn_suppressed_count_for_test(&self) -> u64 {
        self.rejection_warn.suppressed_count_for_test()
    }

    /// Reset this instance's rejection diagnostic limiter. Test-only.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn reset_rate_limit_rejection_warn_for_test(&self) {
        self.rejection_warn.reset_for_test();
    }

    fn record_rate_limit_rejection_warn(
        &self,
        limit_kind: &'static str,
        proxy_id: &str,
        now_ms: u64,
    ) -> RejectionWarnDecisionForTest {
        self.record_rate_limit_rejection_warn_with_global(
            global_rejection_warn(),
            limit_kind,
            proxy_id,
            now_ms,
        )
    }

    fn record_rate_limit_rejection_warn_with_global(
        &self,
        global: &AtomicLogRateLimiter,
        limit_kind: &'static str,
        proxy_id: &str,
        now_ms: u64,
    ) -> RejectionWarnDecisionForTest {
        let Some((instance_suppressed, global_suppressed)) =
            AtomicLogRateLimiter::dual_gate_emit(&self.rejection_warn, global, now_ms)
        else {
            return RejectionWarnDecisionForTest {
                emitted: false,
                instance_suppressed: None,
                global_suppressed: None,
            };
        };
        warn!(
            plugin = "udp_rate_limiting",
            proxy_id = %proxy_id,
            limit_kind,
            suppressed = instance_suppressed,
            globally_suppressed = global_suppressed,
            "UDP rate limit exceeded, dropping datagram"
        );
        RejectionWarnDecisionForTest {
            emitted: true,
            instance_suppressed: Some(instance_suppressed),
            global_suppressed: Some(global_suppressed),
        }
    }

    fn redis_ip_key(client_ip: &str) -> String {
        let mut key = String::with_capacity(3 + client_ip.len());
        key.push_str("ip:");
        key.push_str(client_ip);
        key
    }

    fn maybe_evict(&self) -> bool {
        self.maybe_evict_at(Instant::now())
    }

    fn maybe_evict_at(&self, now: Instant) -> bool {
        self.maybe_evict_at_with_cap(now, MAX_STATE_ENTRIES)
    }

    fn maybe_evict_at_with_cap(&self, now: Instant, max_entries: usize) -> bool {
        let count = self.check_counter.fetch_add(1, Ordering::Relaxed);
        let len = self.limiter.tracked_keys_count();
        let over_capacity = len > max_entries;
        let periodic = count > 0 && count.is_multiple_of(EVICTION_CHECK_INTERVAL) && len > 0;
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();

        // Keep capacity pressure visible for every over-cap observation, even
        // when this call wins cleanup and only reclaims idle keys. That
        // preserves the caller's O(1) new-key rejection guard. Live budgets
        // are never force-evicted; hard cardinality is enforced by atomic
        // admission reservation. Reuse the periodic timestamp as a
        // once-per-second single-flight gate so attacker-controlled datagrams
        // cannot trigger retain on every packet.
        if over_capacity {
            let last_sweep = self.last_eviction_secs.load(Ordering::Relaxed);
            if now_secs.saturating_sub(last_sweep) >= EVICTION_COOLDOWN_SECS
                && self
                    .last_eviction_secs
                    .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                apply_rate_limit_cleanup(&self.limiter, max_entries, now, true);
            }
            return true;
        }

        if periodic {
            let last_sweep = self.last_eviction_secs.load(Ordering::Relaxed);
            if now_secs.saturating_sub(last_sweep) >= EVICTION_COOLDOWN_SECS
                && self
                    .last_eviction_secs
                    .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                // Periodic sweeps prune idle keys even while the map is
                // below the hard cap. A later over-cap observation keeps the
                // new-key guard active and reclaims idle state at most once
                // per second after pruning.
                apply_rate_limit_cleanup(&self.limiter, max_entries, now, false);
            }
        }

        self.limiter.tracked_keys_count() > max_entries
    }
}

#[async_trait]
impl Plugin for UdpRateLimiting {
    fn name(&self) -> &str {
        "udp_rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::UDP_RATE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        UDP_ONLY_PROTOCOLS
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        self.maybe_evict();
        let key: Arc<str> = if !ctx.client_ip.contains(':') {
            Arc::clone(&ctx.client_ip)
        } else {
            crate::util::client_identity::parse_canonical_client_ip(ctx.client_ip.as_ref())
                .map(|ip| {
                    Arc::from(crate::util::client_identity::rate_limit_ip_string(ip, 64))
                })
                .unwrap_or_else(|| Arc::clone(&ctx.client_ip))
        };

        let Some(outcome) = self
            .limiter
            .check_with_redis_key_and_local_capacity(
                Arc::clone(&key),
                || Self::redis_ip_key(key.as_ref()),
                &UdpRateLimitOp {
                    datagram_size: ctx.datagram_size as u64,
                },
                MAX_STATE_ENTRIES,
            )
            .await
        else {
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            return UdpDatagramVerdict::Drop;
        };

        if outcome.allowed {
            return UdpDatagramVerdict::Forward;
        }

        if outcome.enforcement_unavailable {
            // Centralized enforcement could not be consulted under
            // `redis_failure_policy: "fail_closed"`. A datagram has no error
            // channel, so failing closed is the drop itself. The shared backend
            // emits the bounded once-per-outage warning; per-datagram warnings
            // here would be attacker-controlled log amplification.
            return UdpDatagramVerdict::Drop;
        }

        super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
        let limit_kind = match outcome.metric {
            Some("bytes") => "byte_count",
            _ => "datagram_count",
        };
        self.record_rate_limit_rejection_warn(
            limit_kind,
            ctx.proxy_id.as_ref(),
            crate::socket_opts::monotonic_now_ms(),
        );

        UdpDatagramVerdict::Drop
    }
}

fn optional_positive_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "udp_rate_limiting: `{field}` must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "udp_rate_limiting: `{field}` must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn per_window_limit(limit: Option<u64>, window_seconds: u64) -> Result<Option<u64>, String> {
    limit
        .map(|value| {
            value.checked_mul(window_seconds).ok_or_else(|| {
                "udp_rate_limiting: per-window limit overflows u64; reduce the rate or window"
                    .to_string()
            })
        })
        .transpose()
}
