//! Kafka access logging plugin — async log shipping to Apache Kafka via
//! `BatchingLogger<LogEntry>`, with librdkafka still owning internal batching,
//! compression, and delivery retries for both HTTP and stream summaries.

use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{BaseRecord, DefaultProducerContext, Producer, ThreadedProducer};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::spawn_blocking;
use tracing::warn;

use super::utils::log_schema::{SummaryLogEntryView, SummarySchema, resolve_schema};
use super::utils::{BatchConfig, BatchingLogger, PluginHttpClient, RetryPolicy, SummaryLogEntry};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

#[derive(Clone, Copy)]
enum KeyField {
    ClientIp,
    ProxyId,
    None,
}

struct KafkaFlushState {
    producer: ThreadedProducer<DefaultProducerContext>,
    flush_timeout: Duration,
}

impl Drop for KafkaFlushState {
    fn drop(&mut self) {
        let producer = self.producer.clone();
        let flush_timeout = self.flush_timeout;
        if tokio::runtime::Handle::try_current().is_ok() {
            let _flush_task = spawn_blocking(move || {
                let _ = producer.flush(flush_timeout);
            });
        } else {
            let _ = self.producer.flush(flush_timeout);
        }
    }
}

pub struct KafkaLogging {
    logger: BatchingLogger<SummaryLogEntry>,
    broker_hostnames: Vec<String>,
}

impl KafkaLogging {
    pub fn new(config: &Value, http_client: &PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("kafka_logging: config must be an object".to_string());
        }

        let broker_list = required_non_empty_string(config, "broker_list").ok_or_else(|| {
            "kafka_logging: 'broker_list' is required (comma-separated broker addresses)"
                .to_string()
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
                "kafka_logging: 'topic' is required".to_string()
            }
        })?;

        let buffer_capacity = optional_u64(config, "buffer_capacity")?
            .unwrap_or(10000)
            .max(1)
            .min(usize::MAX as u64) as usize;
        let flush_timeout_seconds = optional_u64(config, "flush_timeout_seconds")?
            .unwrap_or(5)
            .max(1);

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

        if let Some(protocol) = optional_non_empty_string(config, "security_protocol")? {
            kafka_config.set("security.protocol", protocol);
        }
        if let Some(mechanism) = optional_non_empty_string(config, "sasl_mechanism")? {
            kafka_config.set("sasl.mechanism", mechanism);
        }
        if let Some(username) = optional_non_empty_string(config, "sasl_username")? {
            kafka_config.set("sasl.username", username);
        }
        if let Some(password) = optional_non_empty_string(config, "sasl_password")? {
            kafka_config.set("sasl.password", password);
        }

        if let Some(ca) = optional_non_empty_string(config, "ssl_ca_location")? {
            kafka_config.set("ssl.ca.location", ca);
        } else if let Some(gateway_ca) = http_client.tls_ca_bundle_path() {
            kafka_config.set("ssl.ca.location", gateway_ca);
        }

        let ssl_no_verify =
            optional_bool(config, "ssl_no_verify")?.unwrap_or(http_client.tls_no_verify());
        if ssl_no_verify {
            kafka_config.set("enable.ssl.certificate.verification", "false");
        }

        let ssl_certificate_location =
            optional_non_empty_string(config, "ssl_certificate_location")?;
        let ssl_key_location = optional_non_empty_string(config, "ssl_key_location")?;
        if ssl_certificate_location.is_some() != ssl_key_location.is_some() {
            return Err(
                "kafka_logging: 'ssl_certificate_location' and 'ssl_key_location' must be provided together"
                    .to_string(),
            );
        }
        if let Some(cert) = ssl_certificate_location {
            kafka_config.set("ssl.certificate.location", cert);
        }
        if let Some(key) = ssl_key_location {
            kafka_config.set("ssl.key.location", key);
        }

        if let Some(producer_config) = config.get("producer_config") {
            let props = producer_config
                .as_object()
                .ok_or_else(|| "kafka_logging: 'producer_config' must be an object".to_string())?;
            for (key, value) in props {
                if key.trim().is_empty() {
                    return Err(
                        "kafka_logging: 'producer_config' keys must not be empty".to_string()
                    );
                }
                let prop = value.as_str().ok_or_else(|| {
                    format!("kafka_logging: 'producer_config.{key}' must be a string")
                })?;
                if prop.trim().is_empty() {
                    return Err(format!(
                        "kafka_logging: 'producer_config.{key}' must not be empty"
                    ));
                }
                if key.eq_ignore_ascii_case("bootstrap.servers")
                    || key.eq_ignore_ascii_case("metadata.broker.list")
                {
                    return Err(format!(
                        "kafka_logging: 'producer_config.{key}' is not allowed"
                    ));
                }
                kafka_config.set(key, prop);
            }
        }

        let producer: ThreadedProducer<DefaultProducerContext> = kafka_config
            .create()
            .map_err(|error| format!("kafka_logging: failed to create Kafka producer: {error}"))?;

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

        let state = Arc::new(KafkaFlushState {
            producer,
            flush_timeout: Duration::from_secs(flush_timeout_seconds),
        });
        let schema = resolve_schema(config, "kafka_logging")?;
        let logger = BatchingLogger::spawn(
            BatchConfig {
                // Kafka flushes one userspace message at a time here. Larger
                // batches would still serialize one spawn_blocking send per
                // entry while librdkafka owns the real batching underneath.
                batch_size: 1,
                flush_interval: Duration::from_millis(1000),
                buffer_capacity,
                retry: RetryPolicy {
                    // librdkafka handles its own delivery retries; keep the
                    // shared logger at a single attempt for each message.
                    max_attempts: 1,
                    delay: Duration::from_millis(0),
                },
                plugin_name: "kafka_logging",
            },
            move |batch| {
                let state = Arc::clone(&state);
                let topic = topic.clone();
                let schema = schema.clone();
                async move { send_batch(&state, &topic, key_field, batch, schema.as_deref()).await }
            },
        );

        Ok(Self {
            logger,
            broker_hostnames,
        })
    }
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

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.logger.try_send(summary.into());
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.logger.try_send(summary.into());
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.broker_hostnames.clone()
    }
}

async fn send_batch(
    state: &Arc<KafkaFlushState>,
    topic: &str,
    key_field: KeyField,
    batch: Vec<SummaryLogEntry>,
    schema: Option<&SummarySchema>,
) -> Result<(), String> {
    for entry in batch {
        let serialized = match schema {
            Some(schema) => serde_json::to_string(&SummaryLogEntryView {
                entry: &entry,
                schema,
            }),
            None => serde_json::to_string(&entry),
        };
        let payload = match serialized {
            Ok(json) => json,
            Err(error) => {
                warn!("Kafka logging: failed to serialize log entry: {error}");
                continue;
            }
        };
        let key = match key_field {
            KeyField::None => None,
            KeyField::ClientIp => Some(entry.client_ip().to_string()),
            KeyField::ProxyId => entry.proxy_id().map(str::to_string),
        };
        let state = Arc::clone(state);
        let topic = topic.to_string();

        spawn_blocking(move || {
            let enqueue_error = match key {
                Some(key) => state
                    .producer
                    .send(
                        BaseRecord::<str, str>::to(&topic)
                            .payload(&payload)
                            .key(key.as_str()),
                    )
                    .err()
                    .map(|(error, _)| error),
                None => state
                    .producer
                    .send(BaseRecord::<(), str>::to(&topic).payload(&payload))
                    .err()
                    .map(|(error, _)| error),
            };

            match enqueue_error {
                Some(error) => Err(format!("Kafka logging: failed to enqueue message: {error}")),
                None => Ok(()),
            }
        })
        .await
        .map_err(|error| format!("Kafka logging: producer task join failed: {error}"))??;
    }

    Ok(())
}
