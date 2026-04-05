//! Kafka access logging plugin — async log shipping to Apache Kafka.
//!
//! Serializes `TransactionSummary` entries and produces them to a Kafka topic.
//! Uses an mpsc channel to decouple the proxy hot path from Kafka I/O: the
//! `log()` hook enqueues the entry (non-blocking), and a background task drains
//! the channel and produces messages via rdkafka's `ThreadedProducer`.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type. Kafka batching, compression, and delivery retries
//! are handled by librdkafka internally.

use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{BaseRecord, DefaultProducerContext, Producer, ThreadedProducer};
use serde_json::Value;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::warn;

use super::utils::http_client::PluginHttpClient;
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// Union type for log entries sent through the channel.
#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
enum LogEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
}

/// Which `TransactionSummary` field to use as the Kafka partition key.
enum KeyField {
    /// Partition by client IP (default) — groups a client's logs together.
    ClientIp,
    /// Partition by proxy/route ID.
    ProxyId,
    /// Null key — round-robin across partitions.
    None,
}

impl LogEntry {
    fn partition_key(&self, key_field: &KeyField) -> Option<String> {
        match (self, key_field) {
            (_, KeyField::None) => None,
            (LogEntry::Http(s), KeyField::ClientIp) => Some(s.client_ip.clone()),
            (LogEntry::Stream(s), KeyField::ClientIp) => Some(s.client_ip.clone()),
            (LogEntry::Http(s), KeyField::ProxyId) => s.matched_proxy_id.clone(),
            (LogEntry::Stream(s), KeyField::ProxyId) => Some(s.proxy_id.clone()),
        }
    }
}

pub struct KafkaLogging {
    sender: mpsc::Sender<LogEntry>,
    broker_hostnames: Vec<String>,
}

impl KafkaLogging {
    pub fn new(config: &Value, http_client: &PluginHttpClient) -> Result<Self, String> {
        let broker_list = config["broker_list"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "kafka_logging: 'broker_list' is required (comma-separated broker addresses)"
                    .to_string()
            })?;

        let topic = config["topic"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "kafka_logging: 'topic' is required".to_string())?
            .to_string();

        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;

        let key_field = match config["key_field"].as_str().unwrap_or("client_ip") {
            "proxy_id" => KeyField::ProxyId,
            "none" => KeyField::None,
            _ => KeyField::ClientIp,
        };

        // Build rdkafka ClientConfig — librdkafka handles batching, compression, retries.
        let mut kafka_config = ClientConfig::new();
        kafka_config.set("bootstrap.servers", broker_list);

        if let Some(v) = config["message_timeout_ms"].as_u64() {
            kafka_config.set("message.timeout.ms", v.to_string());
        }

        if let Some(compression) = config["compression"].as_str() {
            match compression {
                "none" | "gzip" | "snappy" | "lz4" | "zstd" => {
                    kafka_config.set("compression.type", compression);
                }
                other => {
                    return Err(format!(
                        "kafka_logging: unsupported compression '{other}' \
                         (use none/gzip/snappy/lz4/zstd)"
                    ));
                }
            }
        }

        if let Some(acks) = config["acks"].as_str() {
            match acks {
                "0" | "1" | "all" | "-1" => {
                    kafka_config.set("acks", acks);
                }
                other => {
                    return Err(format!(
                        "kafka_logging: unsupported acks '{other}' (use 0/1/all)"
                    ));
                }
            }
        }

        // Security protocol (plaintext / ssl / sasl_plaintext / sasl_ssl).
        if let Some(protocol) = config["security_protocol"].as_str() {
            kafka_config.set("security.protocol", protocol);
        }

        // SASL authentication.
        if let Some(mechanism) = config["sasl_mechanism"].as_str() {
            kafka_config.set("sasl.mechanism", mechanism);
        }
        if let Some(username) = config["sasl_username"].as_str() {
            kafka_config.set("sasl.username", username);
        }
        if let Some(password) = config["sasl_password"].as_str() {
            kafka_config.set("sasl.password", password);
        }

        // SSL / TLS — plugin-level fields override gateway defaults.
        //
        // CA trust: plugin `ssl_ca_location` > gateway `FERRUM_TLS_CA_BUNDLE_PATH`.
        // When neither is set, librdkafka uses system CA roots.
        if let Some(ca) = config["ssl_ca_location"].as_str() {
            kafka_config.set("ssl.ca.location", ca);
        } else if let Some(gateway_ca) = http_client.tls_ca_bundle_path() {
            kafka_config.set("ssl.ca.location", gateway_ca);
        }

        // Verification: plugin `ssl_no_verify` > gateway `FERRUM_TLS_NO_VERIFY`.
        let ssl_no_verify = config["ssl_no_verify"]
            .as_bool()
            .unwrap_or(http_client.tls_no_verify());
        if ssl_no_verify {
            kafka_config.set("enable.ssl.certificate.verification", "false");
        }

        if let Some(cert) = config["ssl_certificate_location"].as_str() {
            kafka_config.set("ssl.certificate.location", cert);
        }
        if let Some(key) = config["ssl_key_location"].as_str() {
            kafka_config.set("ssl.key.location", key);
        }

        // Escape hatch: arbitrary librdkafka producer properties.
        if let Some(props) = config["producer_config"].as_object() {
            for (k, v) in props {
                if let Some(val) = v.as_str() {
                    kafka_config.set(k, val);
                }
            }
        }

        let producer: ThreadedProducer<DefaultProducerContext> = kafka_config
            .create()
            .map_err(|e| format!("kafka_logging: failed to create Kafka producer: {e}"))?;

        // Extract broker hostnames for DNS warmup (skip IP addresses).
        let broker_hostnames: Vec<String> = broker_list
            .split(',')
            .filter_map(|broker| {
                let trimmed = broker.trim();
                // IPv6 bracket notation: [::1]:9092
                let host = if trimmed.starts_with('[') {
                    trimmed.split(']').next().map(|h| h.trim_start_matches('['))
                } else {
                    trimmed.split(':').next()
                };
                host.filter(|h| !h.is_empty() && h.parse::<std::net::IpAddr>().is_err())
                    .map(|h| h.to_string())
            })
            .collect();

        let (sender, receiver) = mpsc::channel(buffer_capacity);
        tokio::spawn(produce_loop(receiver, producer, topic, key_field));

        Ok(Self {
            sender,
            broker_hostnames,
        })
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
        if self
            .sender
            .try_send(LogEntry::Stream(summary.clone()))
            .is_err()
        {
            warn!("Kafka logging buffer full — dropping stream log entry");
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        if self
            .sender
            .try_send(LogEntry::Http(summary.clone()))
            .is_err()
        {
            warn!("Kafka logging buffer full — dropping log entry");
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.broker_hostnames.clone()
    }
}

/// Background task: drains the mpsc channel and produces to Kafka.
///
/// Each message is serialized to JSON and enqueued into librdkafka's internal
/// buffer via `ThreadedProducer::send()` (synchronous, non-blocking).
/// librdkafka handles batching, compression, delivery retries, and partition
/// assignment in its own background thread.
async fn produce_loop(
    mut receiver: mpsc::Receiver<LogEntry>,
    producer: ThreadedProducer<DefaultProducerContext>,
    topic: String,
    key_field: KeyField,
) {
    while let Some(entry) = receiver.recv().await {
        let payload = match serde_json::to_string(&entry) {
            Ok(json) => json,
            Err(e) => {
                warn!("Kafka logging: failed to serialize log entry: {e}");
                continue;
            }
        };

        let key = entry.partition_key(&key_field);

        // Enqueue into librdkafka's internal buffer. The ThreadedProducer's
        // background thread handles actual delivery and retries.
        let err = match key {
            Some(ref k) => producer
                .send(
                    BaseRecord::<str, str>::to(&topic)
                        .payload(&payload)
                        .key(k.as_str()),
                )
                .err()
                .map(|(e, _)| e),
            None => producer
                .send(BaseRecord::<(), str>::to(&topic).payload(&payload))
                .err()
                .map(|(e, _)| e),
        };
        if let Some(e) = err {
            warn!("Kafka logging: failed to enqueue message: {e}");
        }
    }

    // Channel closed — flush any remaining messages in librdkafka's buffer.
    let _ = producer.flush(Duration::from_secs(5));
}
