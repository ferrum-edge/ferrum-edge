//! Kafka access logging plugin — async log shipping to Apache Kafka via a
//! Ferrum userspace admission channel of pre-serialized records, with
//! librdkafka still owning internal batching, compression, and delivery
//! retries for both HTTP and stream summaries.
//!
//! Hot-path admission is lock-free: a generation publishes a cloneable
//! [`BatchingLoggerHandle`] behind `ArcSwapOption`, reserves a channel slot and
//! worst-case Ferrum retained-byte lease before cloning or serializing
//! attacker-shaped summary fields, then shrinks the lease to the purpose-built
//! Kafka record's exact retained size.
//! Local `ThreadedProducer::send` success only means the record was admitted
//! to librdkafka's in-memory queue (Ferrum then releases its byte lease).
//! Terminal broker delivery (including `acks: 0` local completion) is observed
//! through a custom [`ProducerContext`] delivery callback and exposed as
//! authenticated diagnostics/metrics.
//!
//! Construction (`new`) is runtime-free: it parses and admits configuration
//! without creating a `ThreadedProducer`, spawning a Ferrum flush worker, or
//! registering a generation. Fallible producer/logger construction and local
//! lifecycle ownership happen in [`Plugin::start_background_tasks`]; the Ferrum
//! flush worker stays dormant until [`Plugin::commit_background_tasks`].
//! Process-global active-generation publication is also deferred to commit
//! after PluginCache atomically installs the generation that owns this instance.
//!
//! Graceful shutdown and reload atomically stop admission, await every
//! already-reserved/transient admit, await the batching worker, then await one
//! bounded producer flush. See #2548, #2551, #2552 and draft advisories
//! GHSA-cm97-4gpw-2v6r, GHSA-7fgr-gqg5-xj6c, GHSA-83h5-52mw-f33p.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use rdkafka::ClientContext;
use rdkafka::config::ClientConfig;
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::message::DeliveryResult;
use rdkafka::producer::{BaseRecord, Producer, ProducerContext, ThreadedProducer};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::task::spawn_blocking;
use tracing::warn;

use super::utils::log_schema::{SchemaCapabilities, SchemaView, SummarySchema, resolve_schema};
use super::utils::{
    BatchConfig, BatchingLogger, BatchingLoggerHandle, LoggerHooks, PluginHttpClient, RetryPolicy,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};
use crate::util::unknown_keys::reject_unknown_keys;

/// Hard ceiling for Ferrum's userspace admission channel (record count).
pub const HARD_MAX_BUFFER_CAPACITY: usize = 100_000;
/// Default Ferrum userspace channel capacity.
pub const DEFAULT_BUFFER_CAPACITY: usize = 10_000;
/// Default per-entry serialized payload ceiling.
pub const DEFAULT_MAX_ENTRY_BYTES: usize = 64 * 1024;
/// Hard maximum per-entry serialized payload ceiling.
pub const HARD_MAX_ENTRY_BYTES: usize = 1_048_576;
/// Default aggregate Ferrum retained-byte budget across queued records.
pub const DEFAULT_BUFFER_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Hard maximum aggregate Ferrum retained-byte budget.
pub const HARD_MAX_BUFFER_MAX_BYTES: usize = 256 * 1024 * 1024;
/// Default bounded shutdown/reload producer flush budget.
pub const DEFAULT_FLUSH_TIMEOUT_SECONDS: u64 = 5;
/// Hard maximum for `flush_timeout_seconds` (conservative shutdown ceiling).
pub const HARD_MAX_FLUSH_TIMEOUT_SECONDS: u64 = 300;
/// Conservative librdkafka queue message budget (replaces 100_000 default).
pub const DEFAULT_QUEUE_MAX_MESSAGES: u32 = 10_000;
pub const HARD_MAX_QUEUE_MAX_MESSAGES: u32 = 100_000;
/// Conservative librdkafka queue byte budget in KiB (replaces ~1 GiB default).
pub const DEFAULT_QUEUE_MAX_KBYTES: u32 = 65_536;
pub const HARD_MAX_QUEUE_MAX_KBYTES: u32 = 262_144;
/// Conservative per-message byte budget.
pub const DEFAULT_MESSAGE_MAX_BYTES: u32 = 1_048_576;
pub const HARD_MAX_MESSAGE_MAX_BYTES: u32 = 4_194_304;

const DELIVERY_WARN_INTERVAL: Duration = Duration::from_secs(60);
const SATURATION_WARN_INTERVAL: Duration = Duration::from_secs(60);
const ADMISSION_DRAIN_POLL: Duration = Duration::from_millis(1);
const ADMISSION_DRAIN_BOUND: Duration = Duration::from_secs(5);

const ALLOWED_CONFIG_KEYS: &[&str] = &[
    "broker_list",
    "topic",
    "key_field",
    "buffer_capacity",
    "buffer_max_bytes",
    "max_entry_bytes",
    "compression",
    "flush_timeout_seconds",
    "acks",
    "message_timeout_ms",
    "security_protocol",
    "sasl_mechanism",
    "sasl_username",
    "sasl_password",
    "ssl_ca_location",
    "ssl_no_verify",
    "ssl_certificate_location",
    "ssl_key_location",
    "producer_config",
    "schema",
    "schema_ref",
];

/// `producer_config` keys that alias top-level security controls and must not
/// silently override them after validation. Values are `(librdkafka key,
/// authoritative top-level field)`.
const FORBIDDEN_PRODUCER_SECURITY_KEYS: &[(&str, &str)] = &[
    ("security.protocol", "security_protocol"),
    ("enable.ssl.certificate.verification", "ssl_no_verify"),
    ("ssl.endpoint.identification.algorithm", "ssl_no_verify"),
    ("ssl.ca.location", "ssl_ca_location"),
    ("ssl.ca.pem", "ssl_ca_location"),
    ("ssl.ca.certificate.stores", "ssl_ca_location"),
    ("ssl.certificate.location", "ssl_certificate_location"),
    ("ssl.certificate.pem", "ssl_certificate_location"),
    ("ssl.key.location", "ssl_key_location"),
    ("ssl.key.pem", "ssl_key_location"),
    (
        "ssl.keystore.location",
        "ssl_certificate_location and ssl_key_location",
    ),
    ("sasl.mechanism", "sasl_mechanism"),
    ("sasl.mechanisms", "sasl_mechanism"),
    ("sasl.username", "sasl_username"),
    ("sasl.password", "sasl_password"),
];

#[derive(Clone, Copy)]
enum KeyField {
    ClientIp,
    ProxyId,
    None,
}

#[derive(Clone, Copy)]
enum KafkaSecurityProtocol {
    Plaintext,
    Ssl,
    SaslPlaintext,
    SaslSsl,
}

impl KafkaSecurityProtocol {
    fn parse(config: &Value) -> Result<Self, String> {
        match optional_non_empty_string(config, "security_protocol")?
            .unwrap_or_else(|| "plaintext".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "plaintext" => Ok(Self::Plaintext),
            "ssl" => Ok(Self::Ssl),
            "sasl_plaintext" => Ok(Self::SaslPlaintext),
            "sasl_ssl" => Ok(Self::SaslSsl),
            other => Err(format!(
                "kafka_logging: unsupported security_protocol '{other}' \
                 (use plaintext/ssl/sasl_plaintext/sasl_ssl)"
            )),
        }
    }

    fn as_librdkafka(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Ssl => "ssl",
            Self::SaslPlaintext => "sasl_plaintext",
            Self::SaslSsl => "sasl_ssl",
        }
    }

    fn uses_tls(self) -> bool {
        matches!(self, Self::Ssl | Self::SaslSsl)
    }

    fn uses_sasl(self) -> bool {
        matches!(self, Self::SaslPlaintext | Self::SaslSsl)
    }
}

struct KafkaSecuritySettings {
    protocol: KafkaSecurityProtocol,
    sasl_mechanism: Option<String>,
    sasl_username: Option<String>,
    sasl_password: Option<String>,
    ssl_ca_location: Option<String>,
    ssl_no_verify: bool,
    ssl_certificate_location: Option<String>,
    ssl_key_location: Option<String>,
}

impl KafkaSecuritySettings {
    fn parse(config: &Value, http_client: &PluginHttpClient) -> Result<Self, String> {
        let protocol = KafkaSecurityProtocol::parse(config)?;
        let sasl_mechanism = optional_non_empty_string(config, "sasl_mechanism")?;
        let sasl_username = optional_non_empty_string(config, "sasl_username")?;
        let sasl_password = optional_non_empty_string(config, "sasl_password")?;
        let ssl_ca_location = optional_non_empty_string(config, "ssl_ca_location")?;
        let configured_ssl_no_verify = optional_bool(config, "ssl_no_verify")?;
        let ssl_certificate_location =
            optional_non_empty_string(config, "ssl_certificate_location")?;
        let ssl_key_location = optional_non_empty_string(config, "ssl_key_location")?;

        if ssl_certificate_location.is_some() != ssl_key_location.is_some() {
            return Err(
                "kafka_logging: 'ssl_certificate_location' and 'ssl_key_location' must be provided together"
                    .to_string(),
            );
        }
        if sasl_username.is_some() != sasl_password.is_some() {
            return Err(
                "kafka_logging: 'sasl_username' and 'sasl_password' must be provided together"
                    .to_string(),
            );
        }

        if !protocol.uses_tls() {
            for key in [
                "ssl_ca_location",
                "ssl_no_verify",
                "ssl_certificate_location",
                "ssl_key_location",
            ] {
                if config.get(key).is_some() {
                    return Err(format!(
                        "kafka_logging: '{key}' requires security_protocol 'ssl' or 'sasl_ssl'"
                    ));
                }
            }
        }
        if !protocol.uses_sasl() {
            for key in ["sasl_mechanism", "sasl_username", "sasl_password"] {
                if config.get(key).is_some() {
                    return Err(format!(
                        "kafka_logging: '{key}' requires security_protocol 'sasl_plaintext' or 'sasl_ssl'"
                    ));
                }
            }
        }

        Ok(Self {
            protocol,
            sasl_mechanism,
            sasl_username,
            sasl_password,
            ssl_ca_location,
            ssl_no_verify: configured_ssl_no_verify.unwrap_or(http_client.tls_no_verify()),
            ssl_certificate_location,
            ssl_key_location,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KafkaSinkFailure {
    pub operation: &'static str,
    pub error_kind: String,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KafkaSinkSnapshot {
    pub generation_id: u64,
    pub healthy: bool,
    pub accepting: bool,
    pub finalized: bool,
    pub flush_timeout_seconds: u64,
    pub max_entry_bytes: u64,
    pub buffer_max_bytes: u64,
    pub retained_bytes: u64,
    pub admitted_total: u64,
    pub delivered_total: u64,
    pub delivery_failed_total: u64,
    pub queue_rejected_total: u64,
    pub ferrum_dropped_total: u64,
    pub entry_oversize_total: u64,
    pub byte_budget_exhausted_total: u64,
    pub flush_failures_total: u64,
    pub flush_timeouts_total: u64,
    pub shutdown_incomplete_total: u64,
    pub in_flight: i32,
    pub last_failure: Option<KafkaSinkFailure>,
}

struct KafkaDeliveryMetrics {
    generation_id: u64,
    admitted: AtomicU64,
    delivered: AtomicU64,
    delivery_failed: AtomicU64,
    queue_rejected: AtomicU64,
    ferrum_dropped: AtomicU64,
    entry_oversize: AtomicU64,
    byte_budget_exhausted: AtomicU64,
    flush_failures: AtomicU64,
    flush_timeouts: AtomicU64,
    shutdown_incomplete: AtomicU64,
    healthy: AtomicBool,
    accepting: AtomicBool,
    last_failure: Mutex<Option<KafkaSinkFailure>>,
    last_delivery_warn: Mutex<Option<Instant>>,
    last_saturation_warn: Mutex<Option<Instant>>,
}

impl KafkaDeliveryMetrics {
    fn new(generation_id: u64) -> Self {
        Self {
            generation_id,
            admitted: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            delivery_failed: AtomicU64::new(0),
            queue_rejected: AtomicU64::new(0),
            ferrum_dropped: AtomicU64::new(0),
            entry_oversize: AtomicU64::new(0),
            byte_budget_exhausted: AtomicU64::new(0),
            flush_failures: AtomicU64::new(0),
            flush_timeouts: AtomicU64::new(0),
            shutdown_incomplete: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
            accepting: AtomicBool::new(true),
            last_failure: Mutex::new(None),
            last_delivery_warn: Mutex::new(None),
            last_saturation_warn: Mutex::new(None),
        }
    }

    fn record_admitted(&self) {
        self.admitted.fetch_add(1, Ordering::Relaxed);
    }

    fn record_delivered(&self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Relaxed);
    }

    fn record_delivery_failed(&self, error: &KafkaError) {
        self.delivery_failed.fetch_add(1, Ordering::Relaxed);
        self.healthy.store(false, Ordering::Relaxed);
        let kind = safe_kafka_error_kind(error);
        self.store_failure("delivery", kind);
        self.warn_delivery(kind);
    }

    fn record_queue_rejected(&self, error: &KafkaError) {
        self.queue_rejected.fetch_add(1, Ordering::Relaxed);
        self.healthy.store(false, Ordering::Relaxed);
        let kind = safe_kafka_error_kind(error);
        self.store_failure("queue_reject", kind);
        self.warn_saturation("producer queue rejected", kind);
    }

    fn record_ferrum_drop(&self, reason: &'static str) {
        self.ferrum_dropped.fetch_add(1, Ordering::Relaxed);
        self.warn_saturation(reason, "ferrum_channel");
    }

    fn record_entry_oversize(&self) {
        self.entry_oversize.fetch_add(1, Ordering::Relaxed);
        self.ferrum_dropped.fetch_add(1, Ordering::Relaxed);
        self.warn_saturation("entry exceeded max_entry_bytes", "entry_oversize");
    }

    fn record_byte_budget_exhausted(&self) {
        self.byte_budget_exhausted.fetch_add(1, Ordering::Relaxed);
        self.ferrum_dropped.fetch_add(1, Ordering::Relaxed);
        self.warn_saturation("retained-byte budget exhausted", "byte_budget");
    }

    fn record_flush_failure(&self, kind: &'static str, timed_out: bool, incomplete: u64) {
        self.flush_failures.fetch_add(1, Ordering::Relaxed);
        if timed_out {
            self.flush_timeouts.fetch_add(1, Ordering::Relaxed);
        }
        if incomplete > 0 {
            self.shutdown_incomplete
                .fetch_add(incomplete, Ordering::Relaxed);
        }
        self.healthy.store(false, Ordering::Relaxed);
        self.store_failure("flush", kind);
        warn!(
            plugin = "kafka_logging",
            generation_id = self.generation_id,
            error_kind = kind,
            timed_out,
            incomplete,
            "kafka_logging: producer flush did not complete cleanly"
        );
    }

    fn record_shutdown_incomplete(&self, incomplete: u64) {
        if incomplete == 0 {
            return;
        }
        self.shutdown_incomplete
            .fetch_add(incomplete, Ordering::Relaxed);
        self.healthy.store(false, Ordering::Relaxed);
        self.store_failure("shutdown", "ferrum_admission_incomplete");
        warn!(
            plugin = "kafka_logging",
            generation_id = self.generation_id,
            incomplete,
            "kafka_logging: closed admission without awaiting Ferrum drain; local work reported incomplete"
        );
    }

    fn store_failure(&self, operation: &'static str, error_kind: &str) {
        let occurred_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut slot = match self.last_failure.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *slot = Some(KafkaSinkFailure {
            operation,
            error_kind: error_kind.to_string(),
            occurred_at,
        });
    }

    fn warn_delivery(&self, error_kind: &str) {
        let mut last = match self.last_delivery_warn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let should_warn = last
            .map(|previous| now.saturating_duration_since(previous) >= DELIVERY_WARN_INTERVAL)
            .unwrap_or(true);
        if should_warn {
            *last = Some(now);
            warn!(
                plugin = "kafka_logging",
                generation_id = self.generation_id,
                error_kind,
                failed = self.delivery_failed.load(Ordering::Relaxed),
                "kafka_logging: terminal broker delivery failure"
            );
        }
    }

    fn warn_saturation(&self, reason: &str, error_kind: &str) {
        let mut last = match self.last_saturation_warn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let should_warn = last
            .map(|previous| now.saturating_duration_since(previous) >= SATURATION_WARN_INTERVAL)
            .unwrap_or(true);
        if should_warn {
            *last = Some(now);
            warn!(
                plugin = "kafka_logging",
                generation_id = self.generation_id,
                reason,
                error_kind,
                "kafka_logging: admission saturation"
            );
        }
    }

    fn snapshot(
        &self,
        in_flight: i32,
        finalized: bool,
        flush_timeout_seconds: u64,
        max_entry_bytes: u64,
        buffer_max_bytes: u64,
        retained_bytes: u64,
    ) -> KafkaSinkSnapshot {
        let last_failure = match self.last_failure.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        KafkaSinkSnapshot {
            generation_id: self.generation_id,
            healthy: self.healthy.load(Ordering::Relaxed),
            accepting: self.accepting.load(Ordering::Relaxed),
            finalized,
            flush_timeout_seconds,
            max_entry_bytes,
            buffer_max_bytes,
            retained_bytes,
            admitted_total: self.admitted.load(Ordering::Relaxed),
            delivered_total: self.delivered.load(Ordering::Relaxed),
            delivery_failed_total: self.delivery_failed.load(Ordering::Relaxed),
            queue_rejected_total: self.queue_rejected.load(Ordering::Relaxed),
            ferrum_dropped_total: self.ferrum_dropped.load(Ordering::Relaxed),
            entry_oversize_total: self.entry_oversize.load(Ordering::Relaxed),
            byte_budget_exhausted_total: self.byte_budget_exhausted.load(Ordering::Relaxed),
            flush_failures_total: self.flush_failures.load(Ordering::Relaxed),
            flush_timeouts_total: self.flush_timeouts.load(Ordering::Relaxed),
            shutdown_incomplete_total: self.shutdown_incomplete.load(Ordering::Relaxed),
            in_flight,
            last_failure,
        }
    }
}

fn safe_kafka_error_kind(error: &KafkaError) -> &'static str {
    match error {
        KafkaError::MessageProduction(code) => match code {
            RDKafkaErrorCode::MessageSizeTooLarge | RDKafkaErrorCode::InvalidMessageSize => {
                "msg_size_too_large"
            }
            RDKafkaErrorCode::TopicAuthorizationFailed => "topic_authorization_failed",
            RDKafkaErrorCode::RequestTimedOut | RDKafkaErrorCode::OperationTimedOut => "timed_out",
            RDKafkaErrorCode::QueueFull => "queue_full",
            RDKafkaErrorCode::UnknownTopic | RDKafkaErrorCode::UnknownPartition => {
                "unknown_topic_or_partition"
            }
            RDKafkaErrorCode::NotEnoughReplicas
            | RDKafkaErrorCode::NotEnoughReplicasAfterAppend => "not_enough_replicas",
            RDKafkaErrorCode::BrokerTransportFailure => "broker_transport_failure",
            RDKafkaErrorCode::AllBrokersDown => "all_brokers_down",
            RDKafkaErrorCode::MessageTimedOut => "message_timed_out",
            _ => "message_production_error",
        },
        KafkaError::Flush(code) => match code {
            RDKafkaErrorCode::OperationTimedOut => "flush_timed_out",
            _ => "flush_error",
        },
        KafkaError::Subscription(_) => "subscription_error",
        KafkaError::ClientConfig(_, _, _, _) => "client_config_error",
        KafkaError::ClientCreation(_) => "client_creation_error",
        KafkaError::Global(_) => "global_error",
        _ => "kafka_error",
    }
}

struct KafkaDeliveryContext {
    metrics: Arc<KafkaDeliveryMetrics>,
}

impl ClientContext for KafkaDeliveryContext {}

impl ProducerContext for KafkaDeliveryContext {
    type DeliveryOpaque = ();

    fn delivery(&self, delivery_result: &DeliveryResult<'_>, _opaque: Self::DeliveryOpaque) {
        match delivery_result {
            Ok(_) => self.metrics.record_delivered(),
            Err((error, _message)) => self.metrics.record_delivery_failed(error),
        }
    }
}

struct KafkaByteLease {
    used_bytes: Arc<AtomicUsize>,
    bytes: AtomicUsize,
}

impl KafkaByteLease {
    fn shrink_to(&self, new_bytes: usize) {
        let mut current = self.bytes.load(Ordering::Acquire);
        while new_bytes < current {
            match self.bytes.compare_exchange_weak(
                current,
                new_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.used_bytes
                        .fetch_sub(current - new_bytes, Ordering::AcqRel);
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for KafkaByteLease {
    fn drop(&mut self) {
        let bytes = self.bytes.swap(0, Ordering::AcqRel);
        if bytes != 0 {
            self.used_bytes.fetch_sub(bytes, Ordering::AcqRel);
        }
    }
}

struct KafkaByteBudget {
    used_bytes: Arc<AtomicUsize>,
    max_bytes: usize,
}

impl KafkaByteBudget {
    fn new(max_bytes: usize) -> Self {
        Self {
            used_bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes,
        }
    }

    fn used(&self) -> usize {
        self.used_bytes.load(Ordering::Acquire)
    }

    fn try_acquire(&self, bytes: usize) -> Option<Arc<KafkaByteLease>> {
        let reserved = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            });
        if reserved.is_err() {
            return None;
        }
        Some(Arc::new(KafkaByteLease {
            used_bytes: Arc::clone(&self.used_bytes),
            bytes: AtomicUsize::new(bytes),
        }))
    }
}

/// Pre-serialized Kafka record retained in the Ferrum userspace channel.
/// The byte lease is released when librdkafka admission returns (or on drop
/// before admission), because librdkafka copies/assumes downstream ownership.
#[derive(Clone)]
struct KafkaRecord {
    payload: Arc<str>,
    key: Option<Arc<str>>,
    lease: Option<Arc<KafkaByteLease>>,
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(4096)),
            max_bytes,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "serialized Kafka entry exceeded its byte limit",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct KafkaProducerState {
    producer: ThreadedProducer<KafkaDeliveryContext>,
    metrics: Arc<KafkaDeliveryMetrics>,
    flush_timeout: Duration,
    max_entry_bytes: usize,
    buffer_max_bytes: usize,
    byte_budget: Arc<KafkaByteBudget>,
    finalized: AtomicBool,
}

impl KafkaProducerState {
    fn snapshot(&self) -> KafkaSinkSnapshot {
        self.metrics.snapshot(
            self.producer.in_flight_count(),
            self.finalized.load(Ordering::Acquire),
            self.flush_timeout.as_secs(),
            self.max_entry_bytes as u64,
            self.buffer_max_bytes as u64,
            self.byte_budget.used() as u64,
        )
    }

    fn flush_once(&self, timeout: Duration) -> Result<(), KafkaError> {
        if self.finalized.load(Ordering::Acquire) {
            return Ok(());
        }
        self.metrics.accepting.store(false, Ordering::Relaxed);
        let pending_before = self.producer.in_flight_count().max(0) as u64;
        let admitted = self.metrics.admitted.load(Ordering::Relaxed);
        let result = if pending_before == 0 && admitted == 0 {
            Ok(())
        } else {
            self.producer.flush(timeout)
        };
        // This flag means the one owned flush attempt completed, not merely
        // that it started. Callers waiting on the lifecycle lock therefore do
        // not hide an in-progress flush from authenticated diagnostics.
        self.finalized.store(true, Ordering::Release);
        result
    }
}

struct KafkaAdmission {
    handle: BatchingLoggerHandle<KafkaRecord>,
    key_field: KeyField,
    schema: Option<Arc<SummarySchema>>,
    max_entry_bytes: usize,
    byte_budget: Arc<KafkaByteBudget>,
    metrics: Arc<KafkaDeliveryMetrics>,
    /// Transient admits that loaded this handle and have not finished yet.
    in_flight: Arc<AtomicUsize>,
}

impl KafkaAdmission {
    fn admit_http(&self, summary: &TransactionSummary) {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let _guard = InFlightGuard {
            counter: &self.in_flight,
        };
        let Some(permit) = self.handle.try_reserve() else {
            self.metrics.record_ferrum_drop("ferrum channel full");
            return;
        };
        let Some(lease) = self.byte_budget.try_acquire(self.max_entry_bytes) else {
            self.metrics.record_byte_budget_exhausted();
            return;
        };
        let key = match self.key_field {
            KeyField::None => None,
            KeyField::ClientIp => Some(summary.client_ip.as_str()),
            KeyField::ProxyId => summary.proxy_id.as_deref(),
        };
        let record = match &self.schema {
            Some(schema) => self.build_record(
                &SchemaView {
                    summary,
                    schema: schema.as_ref(),
                },
                key,
                lease,
            ),
            None => self.build_record(summary, key, lease),
        };
        let Some(record) = record else {
            return;
        };
        permit.send(record);
    }

    fn admit_stream(&self, summary: &StreamTransactionSummary) {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let _guard = InFlightGuard {
            counter: &self.in_flight,
        };
        let Some(permit) = self.handle.try_reserve() else {
            self.metrics.record_ferrum_drop("ferrum channel full");
            return;
        };
        let Some(lease) = self.byte_budget.try_acquire(self.max_entry_bytes) else {
            self.metrics.record_byte_budget_exhausted();
            return;
        };
        let key = match self.key_field {
            KeyField::None => None,
            KeyField::ClientIp => Some(summary.client_ip.as_str()),
            KeyField::ProxyId => Some(summary.proxy_id.as_str()),
        };
        let record = match &self.schema {
            Some(schema) => self.build_record(
                &SchemaView {
                    summary,
                    schema: schema.as_ref(),
                },
                key,
                lease,
            ),
            None => self.build_record(summary, key, lease),
        };
        let Some(record) = record else {
            return;
        };
        permit.send(record);
    }

    fn build_record<T: Serialize>(
        &self,
        value: &T,
        key: Option<&str>,
        lease: Arc<KafkaByteLease>,
    ) -> Option<KafkaRecord> {
        if key.is_some_and(|value| value.len() > self.max_entry_bytes) {
            self.metrics.record_entry_oversize();
            return None;
        }
        let mut writer = BoundedJsonWriter::new(self.max_entry_bytes);
        if let Err(error) = serde_json::to_writer(&mut writer, value) {
            if writer.limit_exceeded {
                self.metrics.record_entry_oversize();
            } else {
                warn!("kafka_logging: failed to serialize log entry: {error}");
                self.metrics.record_ferrum_drop("serialize_failed");
            }
            return None;
        }
        let payload_bytes = writer.bytes.len();
        let key_bytes = key.map(str::len).unwrap_or(0);
        let retained = match payload_bytes.checked_add(key_bytes) {
            Some(total) => total,
            None => {
                self.metrics.record_entry_oversize();
                return None;
            }
        };
        if retained > self.max_entry_bytes {
            self.metrics.record_entry_oversize();
            return None;
        }
        let payload = match String::from_utf8(writer.bytes) {
            Ok(payload) => Arc::<str>::from(payload),
            Err(error) => {
                warn!("kafka_logging: serialized entry was not UTF-8: {error}");
                self.metrics.record_ferrum_drop("serialize_failed");
                return None;
            }
        };
        let key = key.map(Arc::<str>::from);
        lease.shrink_to(retained);
        Some(KafkaRecord {
            payload,
            key,
            lease: Some(lease),
        })
    }
}

struct InFlightGuard<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

struct KafkaGeneration {
    state: Arc<KafkaProducerState>,
    admission: Arc<ArcSwapOption<KafkaAdmission>>,
    /// Lifecycle-only ownership of the batching worker (not touched on hot path).
    logger: Mutex<Option<BatchingLogger<KafkaRecord>>>,
    in_flight: Arc<AtomicUsize>,
    finalize_lock: AsyncMutex<()>,
}

impl KafkaGeneration {
    async fn finalize(&self) {
        let _finalize_guard = self.finalize_lock.lock().await;
        if self.state.finalized.load(Ordering::Acquire) {
            return;
        }
        self.metrics_accepting_off();
        // Atomically stop new hot-path admission, then await every transient
        // admit that already observed the previous handle.
        let previous = self.admission.swap(None);
        wait_admissions_idle(&self.in_flight).await;
        drop(previous);

        let logger = {
            let mut guard = match self.logger.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.take()
        };
        let Some(mut owned) = logger else {
            let incomplete = self.in_flight.load(Ordering::Acquire).max(1) as u64;
            self.state.metrics.record_shutdown_incomplete(incomplete);
            self.state.finalized.store(true, Ordering::Release);
            return;
        };
        if !owned.close_and_await().await {
            let incomplete = owned.queue_depth().max(1) as u64;
            self.state.metrics.record_shutdown_incomplete(incomplete);
        }
        let state = Arc::clone(&self.state);
        let configured_timeout = state.flush_timeout;
        let pending_before = state.producer.in_flight_count().max(0) as u64;
        let admitted = state.metrics.admitted.load(Ordering::Relaxed);
        if pending_before == 0 && admitted == 0 {
            state.finalized.store(true, Ordering::Release);
            return;
        }
        let flush_deadline = Instant::now() + configured_timeout;
        let flush_state = Arc::clone(&state);
        let mut flush_task = spawn_blocking(move || {
            // Include blocking-pool queueing in the documented budget. If the
            // task starts late, librdkafka receives only the time still left;
            // if it never starts, the outer timeout below cancels it while it
            // is still queued instead of detaching shutdown work.
            let remaining = flush_deadline.saturating_duration_since(Instant::now());
            flush_state.flush_once(remaining)
        });
        match tokio::time::timeout(configured_timeout, &mut flush_task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                let remaining = state.producer.in_flight_count().max(0) as u64;
                let timed_out = matches!(
                    error,
                    KafkaError::Flush(RDKafkaErrorCode::OperationTimedOut)
                );
                let incomplete = if remaining > 0 {
                    remaining
                } else {
                    pending_before
                };
                state.metrics.record_flush_failure(
                    safe_kafka_error_kind(&error),
                    timed_out,
                    incomplete,
                );
            }
            Ok(Err(_join_error)) => {
                let incomplete = state.producer.in_flight_count().max(0) as u64;
                state.metrics.record_flush_failure(
                    "flush_task_join_failed",
                    false,
                    incomplete.max(1),
                );
                state.finalized.store(true, Ordering::Release);
            }
            Err(_) => {
                // `abort` prevents a still-queued blocking task from starting.
                // A task that raced into execution computes its librdkafka
                // timeout from the same deadline above, so it cannot begin a
                // fresh full-duration flush after this owner stops waiting.
                flush_task.abort();
                let incomplete = state.producer.in_flight_count().max(0) as u64;
                state.metrics.record_flush_failure(
                    "flush_task_timed_out",
                    true,
                    incomplete.max(pending_before).max(1),
                );
                state.finalized.store(true, Ordering::Release);
            }
        }
    }

    fn metrics_accepting_off(&self) {
        self.state.metrics.accepting.store(false, Ordering::Relaxed);
    }

    /// Close admission without awaiting the worker or flushing librdkafka.
    /// Used only when an ordered graceful finalize cannot be awaited.
    fn close_admission_report_incomplete(&self) {
        self.metrics_accepting_off();
        let previous = self.admission.swap(None);
        let transient = self.in_flight.load(Ordering::Acquire) as u64;
        let queued = previous
            .as_ref()
            .map(|admission| admission.handle.queue_depth() as u64)
            .unwrap_or(0);
        let retained_record = u64::from(self.state.byte_budget.used() > 0);
        let producer_pending = self.state.producer.in_flight_count().max(0) as u64;
        drop(previous);
        let mut guard = match self.logger.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(mut logger) = guard.take() {
            logger.close_and_abort();
        }
        let incomplete = transient
            .saturating_add(queued)
            .max(retained_record)
            .saturating_add(producer_pending);
        if incomplete > 0 {
            self.state.metrics.record_shutdown_incomplete(incomplete);
        }
        // This generation is terminal even though the non-async disposal
        // path cannot perform an ordered producer flush. Mark it finalized so
        // diagnostics distinguish a deliberately aborted generation from one
        // that is still live.
        self.state.finalized.store(true, Ordering::Release);
    }
}

async fn wait_admissions_idle(in_flight: &AtomicUsize) {
    let deadline = Instant::now() + ADMISSION_DRAIN_BOUND;
    while in_flight.load(Ordering::Acquire) > 0 {
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(ADMISSION_DRAIN_POLL).await;
    }
}

static NEXT_GENERATION_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_GENERATIONS: OnceLock<Mutex<BTreeMap<u64, Arc<KafkaGeneration>>>> = OnceLock::new();

fn active_generations() -> &'static Mutex<BTreeMap<u64, Arc<KafkaGeneration>>> {
    ACTIVE_GENERATIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn register_generation(generation: Arc<KafkaGeneration>) {
    let id = generation.state.metrics.generation_id;
    let mut guard = match active_generations().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Idempotent: commit may be invoked more than once for the same owner.
    guard.entry(id).or_insert(generation);
}

fn unregister_generation(id: u64) {
    let mut guard = match active_generations().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.remove(&id);
}

/// Close admission, await Ferrum workers, and flush every live Kafka producer
/// generation within each instance's configured `flush_timeout_seconds`.
/// Exact-once: generations already finalized are skipped.
pub async fn finalize_all_generations() {
    let generations: Vec<Arc<KafkaGeneration>> = {
        let guard = match active_generations().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.values().cloned().collect()
    };
    // Independent producers share no lifecycle state. Finalize them
    // concurrently so the shutdown/reload ceiling is the slowest configured
    // producer budget, rather than the sum of every live generation's budget.
    futures_util::future::join_all(generations.iter().map(|generation| generation.finalize()))
        .await;
    for generation in generations {
        unregister_generation(generation.state.metrics.generation_id);
    }
}

/// Authenticated diagnostics snapshots for every registered generation.
pub fn snapshots() -> Vec<KafkaSinkSnapshot> {
    let guard = match active_generations().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.values().map(|g| g.state.snapshot()).collect()
}

/// Prometheus exposition for Kafka logging sinks (fixed labels only).
pub fn render_prometheus() -> String {
    let snaps = snapshots();
    if snaps.is_empty() {
        return String::new();
    }
    let mut output = String::with_capacity(2_048);
    output.push_str(
        "# HELP ferrum_kafka_logging_healthy Whether the Kafka logging generation recovered from its latest failure.\n\
# TYPE ferrum_kafka_logging_healthy gauge\n",
    );
    output.push_str(
        "# HELP ferrum_kafka_logging_accepting Whether the Kafka logging generation still admits new records.\n\
# TYPE ferrum_kafka_logging_accepting gauge\n",
    );
    output.push_str(
        "# HELP ferrum_kafka_logging_in_flight Records waiting in librdkafka for terminal delivery.\n\
# TYPE ferrum_kafka_logging_in_flight gauge\n",
    );
    output.push_str(
        "# HELP ferrum_kafka_logging_retained_bytes Ferrum userspace retained payload+key bytes awaiting librdkafka admission.\n\
# TYPE ferrum_kafka_logging_retained_bytes gauge\n",
    );
    output.push_str(
        "# HELP ferrum_kafka_logging_records_total Kafka logging record outcomes.\n\
# TYPE ferrum_kafka_logging_records_total counter\n",
    );
    for snap in snaps {
        let id = snap.generation_id;
        output.push_str(&format!(
            "ferrum_kafka_logging_healthy{{generation=\"{id}\"}} {}\n",
            u8::from(snap.healthy)
        ));
        output.push_str(&format!(
            "ferrum_kafka_logging_accepting{{generation=\"{id}\"}} {}\n",
            u8::from(snap.accepting)
        ));
        output.push_str(&format!(
            "ferrum_kafka_logging_in_flight{{generation=\"{id}\"}} {}\n",
            snap.in_flight.max(0)
        ));
        output.push_str(&format!(
            "ferrum_kafka_logging_retained_bytes{{generation=\"{id}\"}} {}\n",
            snap.retained_bytes
        ));
        for (outcome, value) in [
            ("admitted", snap.admitted_total),
            ("delivered", snap.delivered_total),
            ("delivery_failed", snap.delivery_failed_total),
            ("queue_rejected", snap.queue_rejected_total),
            ("ferrum_dropped", snap.ferrum_dropped_total),
            ("entry_oversize", snap.entry_oversize_total),
            ("byte_budget_exhausted", snap.byte_budget_exhausted_total),
            ("flush_failures", snap.flush_failures_total),
            ("flush_timeouts", snap.flush_timeouts_total),
            ("shutdown_incomplete", snap.shutdown_incomplete_total),
        ] {
            output.push_str(&format!(
                "ferrum_kafka_logging_records_total{{generation=\"{id}\",outcome=\"{outcome}\"}} {value}\n"
            ));
        }
    }
    output
}

/// Config + ClientConfig captured by [`KafkaLogging::new`] and consumed by
/// [`Plugin::start_background_tasks`] to finish producer/logger construction.
///
/// Generation IDs are intentionally absent here: allocating
/// [`NEXT_GENERATION_ID`] during validation-only construction would burn live
/// IDs and register nothing. IDs are assigned only in [`KafkaLogging::activate`].
struct KafkaPendingActivation {
    kafka_config: ClientConfig,
    topic: String,
    key_field: KeyField,
    schema: Option<Arc<SummarySchema>>,
    max_entry_bytes: usize,
    buffer_max_bytes: usize,
    buffer_capacity: usize,
    flush_timeout: Duration,
}

pub struct KafkaLogging {
    /// Live generation after [`Plugin::start_background_tasks`]. Local hot-path
    /// admission uses this slot; process-global diagnostics registration waits
    /// for [`Plugin::commit_background_tasks`]. Tolerates `None` when still
    /// empty (validate / unstarted).
    generation: OnceLock<Arc<KafkaGeneration>>,
    pending: Mutex<Option<KafkaPendingActivation>>,
    start_lock: Mutex<()>,
    broker_hostnames: Vec<String>,
    /// Pre-start snapshot ceilings (config-derived; counters stay zero).
    /// Unstarted instances are not live generations — see [`Self::snapshot`].
    flush_timeout_seconds: u64,
    max_entry_bytes: usize,
    buffer_max_bytes: usize,
}

impl KafkaLogging {
    pub fn new(config: &Value, http_client: &PluginHttpClient) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "kafka_logging: config must be an object".to_string())?;
        reject_unknown_keys(object, "config", ALLOWED_CONFIG_KEYS, "kafka_logging: ")?;

        let broker_list = required_non_empty_string(config, "broker_list").ok_or_else(|| {
            near_miss_hint(
                object,
                "broker_list",
                "kafka_logging: 'broker_list' is required (comma-separated broker addresses)",
            )
        })?;
        let brokers = broker_list
            .split(',')
            .map(str::trim)
            .filter(|broker| !broker.is_empty())
            .collect::<Vec<_>>();
        if brokers.is_empty() {
            return Err(
                "kafka_logging: 'broker_list' must contain at least one broker address".to_string(),
            );
        }
        let broker_list = brokers.join(",");

        let topic = required_non_empty_string(config, "topic").ok_or_else(|| {
            if config.get("topic").is_some() {
                "kafka_logging: 'topic' must not be empty".to_string()
            } else {
                near_miss_hint(object, "topic", "kafka_logging: 'topic' is required")
            }
        })?;

        let buffer_capacity = match optional_u64(config, "buffer_capacity")? {
            Some(0) => {
                return Err("kafka_logging: 'buffer_capacity' must be >= 1".to_string());
            }
            Some(value) => value,
            None => DEFAULT_BUFFER_CAPACITY as u64,
        };
        if buffer_capacity > HARD_MAX_BUFFER_CAPACITY as u64 {
            return Err(format!(
                "kafka_logging: 'buffer_capacity' must be <= {HARD_MAX_BUFFER_CAPACITY}"
            ));
        }
        let buffer_capacity = buffer_capacity as usize;

        let max_entry_bytes = match optional_u64(config, "max_entry_bytes")? {
            Some(0) => {
                return Err("kafka_logging: 'max_entry_bytes' must be >= 1".to_string());
            }
            Some(value) => value,
            None => DEFAULT_MAX_ENTRY_BYTES as u64,
        };
        if max_entry_bytes > HARD_MAX_ENTRY_BYTES as u64 {
            return Err(format!(
                "kafka_logging: 'max_entry_bytes' must be <= {HARD_MAX_ENTRY_BYTES}"
            ));
        }
        let max_entry_bytes = max_entry_bytes as usize;

        let buffer_max_bytes = match optional_u64(config, "buffer_max_bytes")? {
            Some(0) => {
                return Err("kafka_logging: 'buffer_max_bytes' must be >= 1".to_string());
            }
            Some(value) => value,
            None => DEFAULT_BUFFER_MAX_BYTES as u64,
        };
        if buffer_max_bytes > HARD_MAX_BUFFER_MAX_BYTES as u64 {
            return Err(format!(
                "kafka_logging: 'buffer_max_bytes' must be <= {HARD_MAX_BUFFER_MAX_BYTES}"
            ));
        }
        if buffer_max_bytes < max_entry_bytes as u64 {
            return Err(
                "kafka_logging: 'buffer_max_bytes' must be greater than or equal to 'max_entry_bytes'"
                    .to_string(),
            );
        }
        let buffer_max_bytes = buffer_max_bytes as usize;

        let flush_timeout_seconds = match optional_u64(config, "flush_timeout_seconds")? {
            Some(0) => {
                return Err("kafka_logging: 'flush_timeout_seconds' must be >= 1".to_string());
            }
            Some(value) => value,
            None => DEFAULT_FLUSH_TIMEOUT_SECONDS,
        };
        if flush_timeout_seconds > HARD_MAX_FLUSH_TIMEOUT_SECONDS {
            return Err(format!(
                "kafka_logging: 'flush_timeout_seconds' must be <= {HARD_MAX_FLUSH_TIMEOUT_SECONDS}"
            ));
        }

        let key_field = match optional_non_empty_string(config, "key_field")?.as_deref() {
            None => KeyField::ClientIp,
            Some("client_ip") => KeyField::ClientIp,
            Some("proxy_id") => KeyField::ProxyId,
            Some("none") => KeyField::None,
            Some(other) => {
                return Err(format!(
                    "kafka_logging: unsupported key_field '{other}' \
                     (use client_ip/proxy_id/none)"
                ));
            }
        };

        let mut kafka_config = ClientConfig::new();
        kafka_config.set("bootstrap.servers", &broker_list);
        // Keep client logs out of Ferrum's process sinks by default.
        kafka_config.set("log.connection.close", "false");

        if let Some(value) = optional_u64(config, "message_timeout_ms")? {
            kafka_config.set("message.timeout.ms", value.to_string());
        }

        let compression =
            optional_non_empty_string(config, "compression")?.unwrap_or_else(|| "lz4".to_string());
        match compression.as_str() {
            value @ ("none" | "gzip" | "snappy" | "lz4" | "zstd") => {
                kafka_config.set("compression.type", value);
            }
            other => {
                return Err(format!(
                    "kafka_logging: unsupported compression '{other}' \
                     (use none/gzip/snappy/lz4/zstd)"
                ));
            }
        }

        if let Some(acks) = optional_non_empty_string(config, "acks")? {
            match acks.as_str() {
                value @ ("0" | "1" | "all" | "-1") => {
                    kafka_config.set("acks", value);
                }
                other => {
                    return Err(format!(
                        "kafka_logging: unsupported acks '{other}' (use 0/1/all)"
                    ));
                }
            }
        }

        let security = KafkaSecuritySettings::parse(config, http_client)?;
        kafka_config.set("security.protocol", security.protocol.as_librdkafka());
        if let Some(mechanism) = security.sasl_mechanism.as_ref() {
            kafka_config.set("sasl.mechanism", mechanism);
        }
        if let Some(username) = security.sasl_username.as_ref() {
            kafka_config.set("sasl.username", username);
        }
        if let Some(password) = security.sasl_password.as_ref() {
            kafka_config.set("sasl.password", password);
        }

        if security.protocol.uses_tls() {
            if let Some(ca) = security.ssl_ca_location.as_ref() {
                kafka_config.set("ssl.ca.location", ca);
            } else if let Some(gateway_ca) = http_client.tls_ca_bundle_path() {
                kafka_config.set("ssl.ca.location", gateway_ca);
            }
            if security.ssl_no_verify {
                kafka_config.set("enable.ssl.certificate.verification", "false");
            }
            if let Some(cert) = security.ssl_certificate_location.as_ref() {
                kafka_config.set("ssl.certificate.location", cert);
            }
            if let Some(key) = security.ssl_key_location.as_ref() {
                kafka_config.set("ssl.key.location", key);
            }
        }

        // Resolve the gateway CRL filesystem identity only when verification
        // is enabled on a TLS transport, so plaintext/SASL-plaintext and
        // ssl_no_verify=true do not fail merely because loaded CRLs lack a path
        // suitable for librdkafka. Path resolution is pure config admission —
        // the producer itself is not created until start_background_tasks.
        let gateway_crl_path = if !security.protocol.uses_tls() || security.ssl_no_verify {
            None
        } else {
            resolve_gateway_crl_path(http_client)?
        };
        let admitted = admit_producer_config(
            config.get("producer_config"),
            security.protocol,
            security.ssl_no_verify,
            gateway_crl_path.as_deref(),
        )?;
        for (key, value) in &admitted.extra_props {
            kafka_config.set(key, value);
        }

        kafka_config.set(
            "queue.buffering.max.messages",
            admitted.queue_messages.to_string(),
        );
        kafka_config.set(
            "queue.buffering.max.kbytes",
            admitted.queue_kbytes.to_string(),
        );
        kafka_config.set("message.max.bytes", admitted.message_max_bytes.to_string());

        if security.protocol.uses_tls() && !security.ssl_no_verify {
            if let Some(gateway) = gateway_crl_path.as_ref() {
                kafka_config.set("ssl.crl.location", gateway);
            } else if let Some(override_path) = admitted.producer_set_crl {
                kafka_config.set("ssl.crl.location", override_path);
            }
        }

        let broker_hostnames: Vec<String> = broker_list
            .split(',')
            .filter_map(|broker| {
                let trimmed = broker.trim();
                let host = if trimmed.starts_with('[') {
                    trimmed
                        .split(']')
                        .next()
                        .map(|value| value.trim_start_matches('['))
                } else {
                    trimmed.split(':').next()
                };
                host.filter(|value| !value.is_empty() && value.parse::<std::net::IpAddr>().is_err())
                    .map(|value| value.to_string())
            })
            .collect();

        let schema = resolve_schema(config, "kafka_logging", SchemaCapabilities::BASE)?;

        Ok(Self {
            generation: OnceLock::new(),
            pending: Mutex::new(Some(KafkaPendingActivation {
                kafka_config,
                topic,
                key_field,
                schema,
                max_entry_bytes,
                buffer_max_bytes,
                buffer_capacity,
                flush_timeout: Duration::from_secs(flush_timeout_seconds),
            })),
            start_lock: Mutex::new(()),
            broker_hostnames,
            flush_timeout_seconds,
            max_entry_bytes,
            buffer_max_bytes,
        })
    }

    fn activate(
        &self,
        pending: KafkaPendingActivation,
    ) -> Result<Arc<KafkaGeneration>, Box<(KafkaPendingActivation, String)>> {
        // Allocate only when activation is attempted so validation-only
        // construction never consumes live generation IDs.
        let generation_id = NEXT_GENERATION_ID.fetch_add(1, Ordering::Relaxed);
        let metrics = Arc::new(KafkaDeliveryMetrics::new(generation_id));
        let context = KafkaDeliveryContext {
            metrics: Arc::clone(&metrics),
        };
        let producer: ThreadedProducer<KafkaDeliveryContext> =
            match pending.kafka_config.create_with_context(context) {
                Ok(producer) => producer,
                Err(error) => {
                    // `KafkaError::ClientConfig` retains and prints the rejected
                    // property value. That value can be credential material supplied
                    // through `producer_config` (for example an OAuth setting), so do
                    // not pass librdkafka's display text across the config-admission
                    // boundary. The fixed classification is enough for operators to
                    // distinguish invalid configuration from client construction
                    // failure without echoing secrets or TLS source identities.
                    return Err(Box::new((
                        pending,
                        format!(
                            "kafka_logging: failed to create Kafka producer ({})",
                            safe_kafka_error_kind(&error)
                        ),
                    )));
                }
            };

        let byte_budget = Arc::new(KafkaByteBudget::new(pending.buffer_max_bytes));
        let state = Arc::new(KafkaProducerState {
            producer,
            metrics: Arc::clone(&metrics),
            flush_timeout: pending.flush_timeout,
            max_entry_bytes: pending.max_entry_bytes,
            buffer_max_bytes: pending.buffer_max_bytes,
            byte_budget: Arc::clone(&byte_budget),
            finalized: AtomicBool::new(false),
        });
        let metrics_for_hooks = Arc::clone(&metrics);
        let hooks = LoggerHooks {
            on_failed_batch: None,
            on_overflow: Some(Arc::new(move |_item, reason| {
                metrics_for_hooks.record_ferrum_drop(reason);
            })),
            on_high_water: None,
            high_watermark_percent: 80,
        };
        let mut logger = BatchingLogger::spawn_with_hooks(
            BatchConfig {
                // Kafka admits one userspace message at a time here while
                // librdkafka owns the real batching underneath.
                batch_size: 1,
                flush_interval: Duration::from_millis(1000),
                buffer_capacity: pending.buffer_capacity,
                // librdkafka handles its own delivery retries; keep the
                // shared logger at a single attempt for each message.
                retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
                plugin_name: "kafka_logging",
            },
            hooks,
            {
                let state = Arc::clone(&state);
                let topic = pending.topic.clone();
                move |batch| {
                    let state = Arc::clone(&state);
                    let topic = topic.clone();
                    async move { send_batch(&state, &topic, batch) }
                }
            },
        );
        let Some(handle) = logger.handle() else {
            // Producer + flush worker were created but admission cannot be
            // published. Abort the Ferrum worker before returning pending so a
            // retry does not leave an unowned flush loop behind.
            logger.close_and_abort();
            return Err(Box::new((
                pending,
                "kafka_logging: failed to publish Ferrum admission handle".to_string(),
            )));
        };
        let in_flight = Arc::new(AtomicUsize::new(0));
        let admission = Arc::new(KafkaAdmission {
            handle,
            key_field: pending.key_field,
            schema: pending.schema,
            max_entry_bytes: pending.max_entry_bytes,
            byte_budget,
            metrics: Arc::clone(&metrics),
            in_flight: Arc::clone(&in_flight),
        });

        Ok(Arc::new(KafkaGeneration {
            state,
            admission: Arc::new(ArcSwapOption::from(Some(admission))),
            logger: Mutex::new(Some(logger)),
            in_flight,
            finalize_lock: AsyncMutex::new(()),
        }))
    }

    /// Snapshot lifecycle counters for external integration and unit tests.
    #[allow(dead_code)] // public test support is unused by the binary target
    pub fn snapshot(&self) -> KafkaSinkSnapshot {
        if let Some(generation) = self.generation.get() {
            return generation.state.snapshot();
        }
        // Never-started: config-derived ceilings only. `generation_id: 0` marks
        // an unactivated validation/construction object — not a live generation.
        KafkaSinkSnapshot {
            generation_id: 0,
            healthy: true,
            accepting: false,
            finalized: false,
            flush_timeout_seconds: self.flush_timeout_seconds,
            max_entry_bytes: self.max_entry_bytes as u64,
            buffer_max_bytes: self.buffer_max_bytes as u64,
            retained_bytes: 0,
            admitted_total: 0,
            delivered_total: 0,
            delivery_failed_total: 0,
            queue_rejected_total: 0,
            ferrum_dropped_total: 0,
            entry_oversize_total: 0,
            byte_budget_exhausted_total: 0,
            flush_failures_total: 0,
            flush_timeouts_total: 0,
            shutdown_incomplete_total: 0,
            in_flight: 0,
            last_failure: None,
        }
    }

    /// Finalize this generation deterministically from external tests.
    #[allow(dead_code)] // public test support is unused by the binary target
    pub async fn finalize(&self) {
        let Some(generation) = self.generation.get() else {
            return;
        };
        generation.finalize().await;
        unregister_generation(generation.state.metrics.generation_id);
    }
}

impl Drop for KafkaLogging {
    fn drop(&mut self) {
        let Some(generation) = self.generation.get() else {
            // Never started: no generation was registered and no producer /
            // Ferrum worker exists. Drop pending config quietly.
            return;
        };
        if generation.state.finalized.load(Ordering::Acquire) {
            unregister_generation(generation.state.metrics.generation_id);
            return;
        }
        // Reload disposal / abandoned instance. Prefer an ordered finalize
        // (close admission → await Ferrum worker → bounded librdkafka flush).
        // Never flush librdkafka while Ferrum entries may still enqueue.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                let generation = Arc::clone(generation);
                tokio::task::block_in_place(|| {
                    handle.block_on(async move {
                        generation.finalize().await;
                        unregister_generation(generation.state.metrics.generation_id);
                    });
                });
                return;
            }
            // Serving modes use a multi-thread runtime and finalize explicitly.
            // A current-thread runtime cannot be synchronously blocked from
            // Drop, so close/abort admission and report any abandoned work
            // instead of spawning an unowned task that runtime teardown may
            // cancel before it unregisters the generation.
            generation.close_admission_report_incomplete();
            unregister_generation(generation.state.metrics.generation_id);
            return;
        }
        // No runtime: close admission and account incomplete local work. Do
        // not flush librdkafka — the Ferrum worker cannot be awaited here.
        generation.close_admission_report_incomplete();
        unregister_generation(generation.state.metrics.generation_id);
    }
}

fn resolve_gateway_crl_path(http_client: &PluginHttpClient) -> Result<Option<String>, String> {
    if let Some(path) = http_client.tls_crl_file_path() {
        return Ok(Some(path.to_string()));
    }
    if http_client.tls_crl_source_configured() || !http_client.tls_crls().is_empty() {
        return Err(
            "kafka_logging: verified broker TLS requires a file-backed gateway CRL source because librdkafka ssl.crl.location cannot consume inline or provider-backed CRL material"
                .to_string(),
        );
    }
    Ok(None)
}

/// Deterministic admission-order probe for external unit tests: a gated
/// Ferrum worker keeps the channel full so a subsequent oversized summary can
/// only observe channel rejection (never `entry_oversize`). The gate is then
/// released and the worker is joined normally. Returns
/// `(ferrum_dropped_total, entry_oversize_total)`.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) async fn probe_reserve_before_serialize_for_test(
    oversized: &TransactionSummary,
) -> (u64, u64) {
    let metrics = Arc::new(KafkaDeliveryMetrics::new(u64::MAX - 7));
    let byte_budget = Arc::new(KafkaByteBudget::new(4_096));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let worker_started = Arc::new(Semaphore::new(0));
    let worker_release = Arc::new(Semaphore::new(0));
    let mut logger = BatchingLogger::spawn_with_hooks(
        BatchConfig {
            batch_size: 1,
            flush_interval: Duration::from_secs(3600),
            buffer_capacity: 1,
            retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
            plugin_name: "kafka_logging",
        },
        LoggerHooks::default(),
        {
            let worker_started = Arc::clone(&worker_started);
            let worker_release = Arc::clone(&worker_release);
            move |batch| {
                let worker_started = Arc::clone(&worker_started);
                let worker_release = Arc::clone(&worker_release);
                async move {
                    drop(batch);
                    worker_started.add_permits(1);
                    let permit = worker_release
                        .acquire()
                        .await
                        .map_err(|_| "test worker release gate closed".to_string())?;
                    permit.forget();
                    Ok(())
                }
            }
        },
    );
    logger.commit();
    let Some(handle) = logger.handle() else {
        return (0, 0);
    };

    // Inject tiny pre-built records so channel saturation does not depend on
    // serializing a real TransactionSummary under a tiny max_entry_bytes.
    let inject = |handle: &BatchingLoggerHandle<KafkaRecord>, budget: &KafkaByteBudget| -> bool {
        let Some(lease) = budget.try_acquire(2) else {
            return false;
        };
        handle.try_send(KafkaRecord {
            payload: Arc::from("{}"),
            key: None,
            lease: Some(lease),
        })
    };
    let _ = inject(&handle, &byte_budget);
    let Ok(started) = worker_started.acquire().await else {
        worker_release.add_permits(1);
        let _ = logger.close_and_await().await;
        return (0, 0);
    };
    started.forget();
    let _ = inject(&handle, &byte_budget);

    let admission = KafkaAdmission {
        handle,
        key_field: KeyField::None,
        schema: None,
        max_entry_bytes: 64,
        byte_budget,
        metrics: Arc::clone(&metrics),
        in_flight,
    };
    admission.admit_http(oversized);

    let dropped = metrics.ferrum_dropped.load(Ordering::Relaxed);
    let oversize = metrics.entry_oversize.load(Ordering::Relaxed);
    drop(admission);
    worker_release.add_permits(2);
    let _ = logger.close_and_await().await;
    (dropped, oversize)
}

/// Deterministic admission-order probe for external unit tests: a lease that
/// consumes the entire aggregate byte budget must reject an oversized summary
/// before its serializer runs. Returns
/// `(byte_budget_exhausted_total, entry_oversize_total)`.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) async fn probe_byte_budget_before_serialize_for_test(
    oversized: &TransactionSummary,
) -> (u64, u64) {
    let metrics = Arc::new(KafkaDeliveryMetrics::new(u64::MAX - 11));
    let byte_budget = Arc::new(KafkaByteBudget::new(64));
    let Some(held_lease) = byte_budget.try_acquire(64) else {
        return (0, 0);
    };
    let in_flight = Arc::new(AtomicUsize::new(0));
    let mut logger: BatchingLogger<KafkaRecord> = BatchingLogger::spawn(
        BatchConfig {
            batch_size: 1,
            flush_interval: Duration::from_secs(3600),
            buffer_capacity: 1,
            retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
            plugin_name: "kafka_logging",
        },
        |_batch| async { Ok(()) },
    );
    logger.commit();
    let Some(handle) = logger.handle() else {
        drop(held_lease);
        let _ = logger.close_and_await().await;
        return (0, 0);
    };
    let admission = KafkaAdmission {
        handle,
        key_field: KeyField::None,
        schema: None,
        max_entry_bytes: 64,
        byte_budget,
        metrics: Arc::clone(&metrics),
        in_flight,
    };

    admission.admit_http(oversized);

    let exhausted = metrics.byte_budget_exhausted.load(Ordering::Relaxed);
    let oversize = metrics.entry_oversize.load(Ordering::Relaxed);
    drop(admission);
    drop(held_lease);
    let _ = logger.close_and_await().await;
    (exhausted, oversize)
}

/// Pure producer-configuration admission used by construction and exposed to
/// external unit tests through `_test_support`. Keeps CRL conflict / budget
/// policy coverage independent of librdkafka OpenSSL availability.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) fn validate_producer_admission(
    config: &Value,
    http_client: &PluginHttpClient,
) -> Result<(), String> {
    let security = KafkaSecuritySettings::parse(config, http_client)?;
    let gateway_crl_path = if !security.protocol.uses_tls() || security.ssl_no_verify {
        None
    } else {
        resolve_gateway_crl_path(http_client)?
    };
    admit_producer_config(
        config.get("producer_config"),
        security.protocol,
        security.ssl_no_verify,
        gateway_crl_path.as_deref(),
    )
    .map(|_| ())
}

struct AdmittedProducerConfig {
    queue_messages: u32,
    queue_kbytes: u32,
    message_max_bytes: u32,
    producer_set_crl: Option<String>,
    extra_props: Vec<(String, String)>,
}

/// Admit `producer_config` overrides (budgets, forbidden keys, CRL conflict)
/// without constructing a Kafka producer.
fn admit_producer_config(
    producer_config: Option<&Value>,
    security_protocol: KafkaSecurityProtocol,
    ssl_no_verify: bool,
    gateway_crl_path: Option<&str>,
) -> Result<AdmittedProducerConfig, String> {
    let mut admitted = AdmittedProducerConfig {
        queue_messages: DEFAULT_QUEUE_MAX_MESSAGES,
        queue_kbytes: DEFAULT_QUEUE_MAX_KBYTES,
        message_max_bytes: DEFAULT_MESSAGE_MAX_BYTES,
        producer_set_crl: None,
        extra_props: Vec::new(),
    };
    let Some(producer_config) = producer_config else {
        return Ok(admitted);
    };
    let props = producer_config
        .as_object()
        .ok_or_else(|| "kafka_logging: 'producer_config' must be an object".to_string())?;
    for (key, value) in props {
        let normalized = key.to_ascii_lowercase();
        if key.trim().is_empty() || key.trim() != key {
            return Err(
                "kafka_logging: 'producer_config' keys must be non-empty and have no surrounding whitespace"
                    .to_string(),
            );
        }
        let prop = value
            .as_str()
            .ok_or_else(|| format!("kafka_logging: 'producer_config.{key}' must be a string"))?;
        if prop.trim().is_empty() {
            return Err(format!(
                "kafka_logging: 'producer_config.{key}' must not be empty"
            ));
        }
        if normalized == "bootstrap.servers" || normalized == "metadata.broker.list" {
            return Err(format!(
                "kafka_logging: 'producer_config.{key}' is not allowed"
            ));
        }
        if let Some((_, authoritative)) = FORBIDDEN_PRODUCER_SECURITY_KEYS
            .iter()
            .find(|(forbidden, _)| normalized.as_str() == *forbidden)
        {
            // Do not echo the configured value — it may be a secret
            // (sasl.password) or otherwise sensitive identity material.
            return Err(format!(
                "kafka_logging: 'producer_config.{key}' is not allowed; use top-level '{authoritative}'"
            ));
        }
        if (normalized.starts_with("ssl.") || normalized.starts_with("enable.ssl."))
            && !security_protocol.uses_tls()
        {
            return Err(format!(
                "kafka_logging: 'producer_config.{key}' requires security_protocol 'ssl' or 'sasl_ssl'"
            ));
        }
        if (normalized.starts_with("sasl.")
            || normalized.starts_with("enable.sasl.")
            || normalized.starts_with("https."))
            && !security_protocol.uses_sasl()
        {
            return Err(format!(
                "kafka_logging: 'producer_config.{key}' requires security_protocol 'sasl_plaintext' or 'sasl_ssl'"
            ));
        }
        if normalized == "ssl.crl.location" {
            admit_producer_crl_location(
                security_protocol.uses_tls(),
                ssl_no_verify,
                gateway_crl_path,
                prop,
            )?;
            admitted.producer_set_crl = Some(prop.to_string());
            continue;
        }
        if normalized == "queue.buffering.max.messages" {
            admitted.queue_messages = parse_bounded_u32(
                prop,
                "producer_config.queue.buffering.max.messages",
                HARD_MAX_QUEUE_MAX_MESSAGES,
            )?;
            continue;
        }
        if normalized == "queue.buffering.max.kbytes" {
            admitted.queue_kbytes = parse_bounded_u32(
                prop,
                "producer_config.queue.buffering.max.kbytes",
                HARD_MAX_QUEUE_MAX_KBYTES,
            )?;
            continue;
        }
        if normalized == "message.max.bytes" {
            admitted.message_max_bytes = parse_bounded_u32(
                prop,
                "producer_config.message.max.bytes",
                HARD_MAX_MESSAGE_MAX_BYTES,
            )?;
            continue;
        }
        admitted.extra_props.push((key.clone(), prop.to_string()));
    }
    Ok(admitted)
}

/// Fail-closed CRL override check shared by construction and pure admission.
fn admit_producer_crl_location(
    tls_enabled: bool,
    ssl_no_verify: bool,
    gateway_crl_path: Option<&str>,
    producer_crl: &str,
) -> Result<(), String> {
    if !tls_enabled {
        return Err(
            "kafka_logging: 'producer_config.ssl.crl.location' requires security_protocol 'ssl' or 'sasl_ssl'"
                .to_string(),
        );
    }
    if ssl_no_verify {
        return Ok(());
    }
    if gateway_crl_path.is_some_and(|gateway| producer_crl != gateway) {
        return Err(
            "kafka_logging: 'producer_config.ssl.crl.location' conflicts with gateway FERRUM_TLS_CRL_FILE_PATH"
                .to_string(),
        );
    }
    Ok(())
}

fn near_miss_hint(object: &Map<String, Value>, required: &str, fallback: &str) -> String {
    match crate::util::unknown_keys::near_miss_for_missing_key(object, required) {
        Some(near) => format!("{fallback} (did you mean '{near}'?)"),
        None => fallback.to_string(),
    }
}

fn parse_bounded_u32(raw: &str, field: &str, hard_max: u32) -> Result<u32, String> {
    let value: u32 = raw
        .parse()
        .map_err(|_| format!("kafka_logging: '{field}' must be an unsigned integer string"))?;
    if value == 0 {
        return Err(format!("kafka_logging: '{field}' must be >= 1"));
    }
    if value > hard_max {
        return Err(format!("kafka_logging: '{field}' must be <= {hard_max}"));
    }
    Ok(value)
}

fn required_non_empty_string(config: &Value, key: &str) -> Option<String> {
    config.get(key)?.as_str().and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn optional_non_empty_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(value) => {
            let value = value
                .as_str()
                .ok_or_else(|| format!("kafka_logging: '{key}' must be a string"))?
                .trim();
            if value.is_empty() {
                return Err(format!("kafka_logging: '{key}' must not be empty"));
            }
            Ok(Some(value.to_string()))
        }
        None => Ok(None),
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("kafka_logging: '{key}' must be a boolean")),
        None => Ok(None),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("kafka_logging: '{key}' must be an unsigned integer")),
        None => Ok(None),
    }
}

#[async_trait]
impl Plugin for KafkaLogging {
    fn name(&self) -> &str {
        "kafka_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::KAFKA_LOGGING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        if self.generation.get().is_some() {
            return Ok(());
        }
        let _guard = self.start_lock.lock().map_err(|_| {
            "kafka_logging: start lock poisoned; refusing to start Kafka generation".to_string()
        })?;
        if self.generation.get().is_some() {
            return Ok(());
        }
        let _runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            "kafka_logging: start_background_tasks requires a Tokio runtime".to_string()
        })?;
        let pending = {
            let mut guard = self
                .pending
                .lock()
                .map_err(|_| "kafka_logging: pending activation lock poisoned".to_string())?;
            guard.take().ok_or_else(|| {
                "kafka_logging: pending activation already consumed without a live generation"
                    .to_string()
            })?
        };
        let generation = match self.activate(pending) {
            Ok(generation) => generation,
            Err(error) => {
                let (pending, error) = *error;
                if let Ok(mut guard) = self.pending.lock() {
                    *guard = Some(pending);
                }
                return Err(error);
            }
        };
        // Own the generation locally only. Process-global ACTIVE_GENERATIONS
        // publication waits for commit_background_tasks after PluginCache
        // installs this instance. Drop/finalize still clean up local ownership
        // whether or not commit ever ran.
        if self.generation.set(Arc::clone(&generation)).is_err() {
            // A racing activation under the start lock should be impossible; if
            // the slot is occupied, tear down this orphan without registering so
            // ACTIVE_GENERATIONS / status stay consistent with the live owner.
            generation.close_admission_report_incomplete();
            return Err(
                "kafka_logging: generation already activated; refusing duplicate start".to_string(),
            );
        }
        Ok(())
    }

    fn commit_background_tasks(&self) {
        let Some(generation) = self.generation.get() else {
            return;
        };
        // Release the Ferrum flush worker before process-global registration so
        // diagnostics cannot advertise a live generation whose worker is still
        // dormant. register_generation stays idempotent via entry().or_insert.
        if let Ok(guard) = generation.logger.lock()
            && let Some(logger) = guard.as_ref()
        {
            logger.commit();
        }
        register_generation(Arc::clone(generation));
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let Some(generation) = self.generation.get() else {
            return;
        };
        if let Some(admission) = generation.admission.load_full() {
            admission.admit_stream(summary);
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        let Some(generation) = self.generation.get() else {
            return;
        };
        if let Some(admission) = generation.admission.load_full() {
            admission.admit_http(summary);
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.broker_hostnames.clone()
    }
}

fn send_batch(
    state: &Arc<KafkaProducerState>,
    topic: &str,
    batch: Vec<KafkaRecord>,
) -> Result<(), String> {
    for mut record in batch {
        // `ThreadedProducer::send` is the non-blocking local-queue admission
        // API; broker I/O and delivery callbacks run on librdkafka's own
        // thread. Calling it directly avoids queueing one Tokio blocking task
        // per record and leaves that pool available for the single owned final
        // flush below.
        let enqueue_error = match record.key.as_deref() {
            Some(key) => state
                .producer
                .send(
                    BaseRecord::<str, str>::to(topic)
                        .payload(record.payload.as_ref())
                        .key(key),
                )
                .err()
                .map(|(error, _)| error),
            None => state
                .producer
                .send(BaseRecord::<(), str>::to(topic).payload(record.payload.as_ref()))
                .err()
                .map(|(error, _)| error),
        };

        match enqueue_error {
            Some(error) => {
                state.metrics.record_queue_rejected(&error);
                // The instance-scoped metric and rate-limited safe
                // classification above are the terminal accounting. Do not
                // feed the raw librdkafka error into the generic per-batch
                // warning path or a second retry loop.
            }
            None => {
                state.metrics.record_admitted();
            }
        }

        // librdkafka has copied/assumed ownership (or rejected). Release the
        // Ferrum retained-byte lease on every path, including errors.
        drop(record.lease.take());
    }

    Ok(())
}
