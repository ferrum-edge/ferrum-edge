//! Target-aware adaptive backend concurrency.
//!
//! This plugin gates backend dispatch after load balancing has selected the
//! concrete target. It protects slow or degrading upstreams before hard errors
//! show up by shrinking the accepted in-flight request count when latency or
//! failure signals rise, then cautiously increasing it when the target is
//! saturated and healthy.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use serde_json::{Map, Value};

use crate::adaptive_concurrency::{
    AdaptiveConcurrencyConfig, AdaptiveConcurrencyKeyBy, AdaptiveConcurrencyLimitExceeded,
    AdaptiveConcurrencyLimiter,
};
use crate::plugins::{
    BackendAdmissionContext, BackendAdmissionDecision, HTTP_FAMILY_PROTOCOLS, Plugin,
    PluginHttpClient, ProxyProtocol, RequestContext,
};
use crate::retry::OBS_CONCURRENCY_LIMIT;

static CONCURRENCY_LIMIT_HEADERS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    HashMap::from([(
        "x-gateway-error".to_string(),
        OBS_CONCURRENCY_LIMIT.to_string(),
    )])
});

pub struct AdaptiveConcurrency {
    config: Arc<AdaptiveConcurrencyConfig>,
    limiter: Arc<AdaptiveConcurrencyLimiter>,
    policy_generation: u64,
}

impl AdaptiveConcurrency {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config = Arc::new(parse_config_value(config)?);
        Ok(Self {
            config,
            limiter: Arc::new(AdaptiveConcurrencyLimiter::new(
                http_client.pool_shard_amount(),
            )),
            policy_generation: 1,
        })
    }

    pub(crate) fn with_shared_limiter(
        config: Arc<AdaptiveConcurrencyConfig>,
        limiter: Arc<AdaptiveConcurrencyLimiter>,
        policy_generation: u64,
    ) -> Self {
        Self {
            config,
            limiter,
            policy_generation,
        }
    }
}

pub(crate) fn parse_config_value(config: &Value) -> Result<AdaptiveConcurrencyConfig, String> {
    let object = config
        .as_object()
        .ok_or_else(|| format!("adaptive_concurrency: config must be an object, got: {config}"))?;
    parse_config(object)
}

impl Plugin for AdaptiveConcurrency {
    fn name(&self) -> &str {
        "adaptive_concurrency"
    }

    fn priority(&self) -> u16 {
        super::priority::ADAPTIVE_CONCURRENCY
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_FAMILY_PROTOCOLS
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    fn is_authorize_plugin(&self) -> bool {
        false
    }

    fn is_backend_admission_plugin(&self) -> bool {
        true
    }

    fn try_backend_admission(
        &self,
        ctx: &RequestContext,
        admission: &BackendAdmissionContext<'_>,
    ) -> BackendAdmissionDecision {
        match self.limiter.try_acquire_for_generation(
            admission.proxy,
            admission.upstream_target,
            Arc::clone(&self.config),
            self.policy_generation,
            ctx.lb_generation,
        ) {
            Ok(permit) => BackendAdmissionDecision::Admit(permit),
            Err(AdaptiveConcurrencyLimitExceeded::TargetLimit {
                current_in_flight,
                limit,
                expose_headers,
            }) => {
                let mut headers = CONCURRENCY_LIMIT_HEADERS.clone();
                if expose_headers {
                    headers.insert(
                        "x-adaptive-concurrency-limit".to_string(),
                        limit.to_string(),
                    );
                    headers.insert(
                        "x-adaptive-concurrency-inflight".to_string(),
                        current_in_flight.to_string(),
                    );
                }
                BackendAdmissionDecision::Reject {
                    status_code: 503,
                    body: br#"{"error":"Upstream concurrency limit reached"}"#.to_vec(),
                    headers,
                }
            }
            Err(AdaptiveConcurrencyLimitExceeded::GenerationHandoff) => {
                BackendAdmissionDecision::Reject {
                    status_code: 503,
                    body: br#"{"error":"Upstream concurrency limit reached"}"#.to_vec(),
                    headers: CONCURRENCY_LIMIT_HEADERS.clone(),
                }
            }
        }
    }
}

fn parse_config(object: &Map<String, Value>) -> Result<AdaptiveConcurrencyConfig, String> {
    const ALLOWED_KEYS: &[&str] = &[
        "key_by",
        "max_tracked_keys",
        "min_limit",
        "initial_limit",
        "max_limit",
        "min_samples",
        "target_latency_multiplier",
        "decrease_ratio",
        "increase_step",
        "shadow_mode",
        "expose_headers",
    ];
    if let Some(unknown) = object
        .keys()
        .find(|key| !ALLOWED_KEYS.contains(&key.as_str()))
    {
        return Err(format!(
            "adaptive_concurrency: unknown config key '{unknown}'; allowed keys: {}",
            ALLOWED_KEYS.join(", ")
        ));
    }

    let min_limit = optional_u64(object, "min_limit")?.unwrap_or(1);
    let initial_limit = optional_u64(object, "initial_limit")?.unwrap_or(32);
    let max_limit = optional_u64(object, "max_limit")?.unwrap_or(1024);
    let max_tracked_keys = optional_u64(object, "max_tracked_keys")?.unwrap_or(10_000);
    let min_samples = optional_u64(object, "min_samples")?.unwrap_or(20);
    let increase_step = optional_u64(object, "increase_step")?.unwrap_or(1);
    let target_latency_multiplier =
        optional_f64(object, "target_latency_multiplier")?.unwrap_or(1.5);
    let decrease_ratio = optional_f64(object, "decrease_ratio")?.unwrap_or(0.8);
    let shadow_mode = optional_bool(object, "shadow_mode")?.unwrap_or(false);
    let expose_headers = optional_bool(object, "expose_headers")?.unwrap_or(false);
    let key_by = optional_string(object, "key_by")?
        .map(parse_key_by)
        .transpose()?
        .unwrap_or(AdaptiveConcurrencyKeyBy::Proxy);

    if min_limit == 0 {
        return Err("adaptive_concurrency: 'min_limit' must be greater than 0".to_string());
    }
    if max_limit < min_limit {
        return Err(
            "adaptive_concurrency: 'max_limit' must be greater than or equal to 'min_limit'"
                .to_string(),
        );
    }
    if initial_limit < min_limit || initial_limit > max_limit {
        return Err(
            "adaptive_concurrency: 'initial_limit' must be between 'min_limit' and 'max_limit'"
                .to_string(),
        );
    }
    if max_tracked_keys == 0 {
        return Err("adaptive_concurrency: 'max_tracked_keys' must be greater than 0".to_string());
    }
    let max_tracked_keys = usize::try_from(max_tracked_keys).map_err(|_| {
        "adaptive_concurrency: 'max_tracked_keys' is too large for this platform".to_string()
    })?;
    if min_samples == 0 {
        return Err("adaptive_concurrency: 'min_samples' must be greater than 0".to_string());
    }
    if increase_step == 0 {
        return Err("adaptive_concurrency: 'increase_step' must be greater than 0".to_string());
    }
    if !target_latency_multiplier.is_finite() || target_latency_multiplier <= 1.0 {
        return Err(
            "adaptive_concurrency: 'target_latency_multiplier' must be a finite number greater than 1.0"
                .to_string(),
        );
    }
    if !decrease_ratio.is_finite() || decrease_ratio <= 0.0 || decrease_ratio >= 1.0 {
        return Err(
            "adaptive_concurrency: 'decrease_ratio' must be a finite number greater than 0 and less than 1"
                .to_string(),
        );
    }

    Ok(AdaptiveConcurrencyConfig {
        key_by,
        max_tracked_keys,
        min_limit,
        initial_limit,
        max_limit,
        min_samples,
        target_latency_multiplier,
        decrease_ratio,
        increase_step,
        shadow_mode,
        expose_headers,
    })
}

fn parse_key_by(raw: &str) -> Result<AdaptiveConcurrencyKeyBy, String> {
    match raw {
        "proxy_target" => Ok(AdaptiveConcurrencyKeyBy::Proxy),
        "upstream_target" => Ok(AdaptiveConcurrencyKeyBy::Upstream),
        "backend_target" => Ok(AdaptiveConcurrencyKeyBy::Backend),
        other => Err(format!(
            "adaptive_concurrency: unsupported key_by '{other}' (expected proxy_target, upstream_target, or backend_target)"
        )),
    }
}

fn optional_u64(object: &Map<String, Value>, field: &str) -> Result<Option<u64>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("adaptive_concurrency: '{field}' must be an integer"))
        })
        .transpose()
}

fn optional_f64(object: &Map<String, Value>, field: &str) -> Result<Option<f64>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_f64()
                .ok_or_else(|| format!("adaptive_concurrency: '{field}' must be a number"))
        })
        .transpose()
}

fn optional_bool(object: &Map<String, Value>, field: &str) -> Result<Option<bool>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("adaptive_concurrency: '{field}' must be a boolean"))
        })
        .transpose()
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| format!("adaptive_concurrency: '{field}' must be a string"))
        })
        .transpose()
}
