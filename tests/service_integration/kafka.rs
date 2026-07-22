//! Real-broker acceptance coverage for `kafka_logging`.
//!
//! Drives the production plugin against a local Redpanda container so hosted CI
//! proves terminal delivery callbacks and ordered finalize — not merely local
//! queue admission. Deterministic unit tests still own CRL/unknown-key/budget
//! admission and OpenSSL-independent policy checks; see
//! `tests/service_integration/README.md`.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use ferrum_edge::plugins::kafka_logging::{KafkaLogging, KafkaSinkSnapshot};
use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::{Plugin, TransactionSummary};
use serde_json::{Value, json};
use serial_test::serial;

use crate::common::containers::{
    RedpandaContainer, fail_in_ci_else_skip, start_redpanda_container,
};

async fn redpanda(test: &str) -> Option<RedpandaContainer> {
    match start_redpanda_container().await {
        Ok(c) => Some(c),
        Err(e) => {
            fail_in_ci_else_skip(test, "Redpanda", &e);
            None
        }
    }
}

fn summary(path: &str, client_ip: &str) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: Utc::now().to_rfc3339(),
        client_ip: client_ip.to_string(),
        consumer_username: None,
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: path.to_string(),
        proxy_id: Some("kafka-si-proxy".to_string()),
        proxy_name: Some("Kafka SI Proxy".to_string()),
        backend_target: Some("http://127.0.0.1:9/".to_string()),
        backend_resolved_ip: Some("127.0.0.1".to_string()),
        response_status_code: 200,
        latency_total_ms: 1.0,
        latency_gateway_processing_ms: 0.0,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        latency_plugin_execution_ms: 0.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 0.0,
        request_user_agent: Some("kafka-service-integration".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: true,
        bytes_sent: 0,
        bytes_received: 0,
        mirror: false,
        metadata: HashMap::new(),
        ai_usage_export: None,
    }
}

fn plugin(bootstrap: &str, topic: &str, overrides: Value) -> KafkaLogging {
    let mut cfg = json!({
        "broker_list": bootstrap,
        "topic": topic,
        "acks": "all",
        "compression": "none",
        "message_timeout_ms": 10_000,
        "flush_timeout_seconds": 10,
        "security_protocol": "plaintext",
        "key_field": "client_ip",
        "buffer_capacity": 1_000,
    });
    if let (Some(base), Some(extra)) = (cfg.as_object_mut(), overrides.as_object()) {
        for (key, value) in extra {
            if key == "producer_config" {
                let mut merged = base
                    .get("producer_config")
                    .and_then(|v| v.as_object().cloned())
                    .unwrap_or_default();
                if let Some(props) = value.as_object() {
                    for (prop_key, prop_value) in props {
                        merged.insert(prop_key.clone(), prop_value.clone());
                    }
                }
                base.insert(key.clone(), Value::Object(merged));
            } else {
                base.insert(key.clone(), value.clone());
            }
        }
    }
    let plugin = KafkaLogging::new(&cfg, &PluginHttpClient::default())
        .unwrap_or_else(|error| panic!("construct kafka_logging for topic {topic}: {error}"));
    plugin
        .start_background_tasks()
        .unwrap_or_else(|error| panic!("start kafka_logging background tasks for topic {topic}: {error}"));
    plugin.commit_background_tasks();
    plugin
}

async fn wait_snapshot<F>(
    plugin: &KafkaLogging,
    timeout: Duration,
    mut pred: F,
) -> KafkaSinkSnapshot
where
    F: FnMut(&KafkaSinkSnapshot) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let snap = plugin.snapshot();
        if pred(&snap) || tokio::time::Instant::now() >= deadline {
            return snap;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Successful broker ack, key/record consume, and bounded finalize.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn kafka_logging_real_broker_delivers_consumes_and_finalizes() {
    let Some(broker) = redpanda("kafka_logging_real_broker_delivers_consumes_and_finalizes").await
    else {
        return;
    };

    let topic = "ferrum-deliver";
    broker
        .create_topic(topic, &[])
        .await
        .expect("create deliver topic");

    let marker = "/kafka-si-deliver-marker";
    let client_ip = "203.0.113.50";
    let plugin = plugin(&broker.bootstrap, topic, json!({}));
    plugin.log(&summary(marker, client_ip)).await;

    let mid = wait_snapshot(&plugin, Duration::from_secs(20), |snap| {
        snap.delivered_total >= 1
    })
    .await;
    assert!(
        mid.admitted_total >= 1,
        "expected local admission before terminal ack: admitted={} delivered={} failed={} rejected={}",
        mid.admitted_total,
        mid.delivered_total,
        mid.delivery_failed_total,
        mid.queue_rejected_total
    );
    assert_eq!(
        mid.delivered_total, 1,
        "expected exactly one successful delivery callback: admitted={} delivered={} failed={}",
        mid.admitted_total, mid.delivered_total, mid.delivery_failed_total
    );
    assert_eq!(mid.delivery_failed_total, 0);
    assert_eq!(mid.queue_rejected_total, 0);

    let consumed = broker
        .consume_one(topic, Duration::from_secs(15))
        .await
        .expect("consume delivered record")
        .expect("broker must retain the delivered access-log record");
    assert_eq!(
        consumed.0.as_deref(),
        Some(client_ip),
        "key_field=client_ip must be the Kafka record key"
    );
    assert!(
        consumed.1.contains(marker),
        "consumed payload must include the known request_path marker"
    );

    plugin.finalize().await;
    let end = plugin.snapshot();
    assert!(end.finalized);
    assert_eq!(end.flush_failures_total, 0);
    assert_eq!(end.flush_timeouts_total, 0);
    assert_eq!(end.shutdown_incomplete_total, 0);
    assert_eq!(end.delivered_total, 1);
    assert_eq!(end.delivery_failed_total, 0);
}

/// Terminal broker/topic rejection, oversized reject, timeout, queue saturation,
/// and stalled finalize accounting against one broker fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn kafka_logging_real_broker_terminal_failure_and_finalize_paths() {
    let Some(broker) =
        redpanda("kafka_logging_real_broker_terminal_failure_and_finalize_paths").await
    else {
        return;
    };

    // --- unknown topic after local admission (auto-create disabled) ---
    let missing = plugin(
        &broker.bootstrap,
        "ferrum-missing-topic",
        json!({
            "message_timeout_ms": 5_000,
            "flush_timeout_seconds": 5,
            "producer_config": {
                "allow.auto.create.topics": "true"
            }
        }),
    );
    missing
        .log(&summary("/kafka-si-missing", "203.0.113.51"))
        .await;
    let missing_snap = wait_snapshot(&missing, Duration::from_secs(20), |snap| {
        snap.admitted_total >= 1 && snap.delivery_failed_total >= 1
    })
    .await;
    assert!(
        missing_snap.admitted_total >= 1,
        "unknown-topic rejection must occur after local producer admission: admitted={} rejected={} failed={}",
        missing_snap.admitted_total,
        missing_snap.queue_rejected_total,
        missing_snap.delivery_failed_total
    );
    assert!(
        missing_snap.delivery_failed_total >= 1,
        "expected terminal unknown-topic delivery failure, got delivered={} failed={} rejected={}",
        missing_snap.delivered_total,
        missing_snap.delivery_failed_total,
        missing_snap.queue_rejected_total
    );
    assert_eq!(missing_snap.delivered_total, 0);
    missing.finalize().await;

    // --- broker-side oversized rejection (topic max < producer max) ---
    // Topic ceiling is well under a serialized access-log with a 2 KiB path;
    // producer message.max.bytes stays high so rejection is broker-side after
    // local admission (create_topic verifies max.message.bytes took effect).
    let oversized_topic = "ferrum-oversized";
    broker
        .create_topic(oversized_topic, &[("max.message.bytes", "512")])
        .await
        .expect("create oversized topic with verified max.message.bytes=512");
    let oversized = plugin(
        &broker.bootstrap,
        oversized_topic,
        json!({
            "max_entry_bytes": 65_536,
            "message_timeout_ms": 8_000,
            "producer_config": {
                "message.max.bytes": "1048576"
            }
        }),
    );
    let big_path = format!("/{}", "x".repeat(2_048));
    oversized.log(&summary(&big_path, "203.0.113.52")).await;
    let oversized_snap = wait_snapshot(&oversized, Duration::from_secs(20), |snap| {
        snap.delivery_failed_total >= 1
            || snap.queue_rejected_total >= 1
            || snap.delivered_total >= 1
    })
    .await;
    assert!(
        oversized_snap.admitted_total >= 1,
        "oversized record must clear local producer admission before broker reject: admitted={} rejected={} failed={}",
        oversized_snap.admitted_total,
        oversized_snap.queue_rejected_total,
        oversized_snap.delivery_failed_total
    );
    assert_eq!(
        oversized_snap.queue_rejected_total,
        0,
        "oversized proof must be broker delivery failure, not local queue rejection: admitted={} rejected={} failed={}",
        oversized_snap.admitted_total,
        oversized_snap.queue_rejected_total,
        oversized_snap.delivery_failed_total
    );
    assert!(
        oversized_snap.delivery_failed_total >= 1,
        "expected broker MESSAGE_TOO_LARGE-style delivery failure after local admission (topic max.message.bytes=512 < payload); got delivered={} failed={} rejected={}",
        oversized_snap.delivered_total,
        oversized_snap.delivery_failed_total,
        oversized_snap.queue_rejected_total
    );
    assert_eq!(oversized_snap.delivered_total, 0);
    oversized.finalize().await;

    // --- delivery timeout / retry exhaustion against a frozen broker ---
    // Redpanda v24.2 does not expose Kafka's `min.insync.replicas` as a topic
    // property, so under-replicated acks=all cannot be configured here. Build
    // the producer while the broker is live, then docker-pause it so produce
    // hangs until `message_timeout_ms`.
    let timeout_topic = "ferrum-timeout";
    broker
        .create_topic(timeout_topic, &[])
        .await
        .expect("create timeout topic");
    let timed = plugin(
        &broker.bootstrap,
        timeout_topic,
        json!({
            "message_timeout_ms": 2_000,
            "flush_timeout_seconds": 3,
        }),
    );
    broker
        .pause_broker()
        .await
        .expect("pause broker for delivery-timeout path");
    timed
        .log(&summary("/kafka-si-timeout", "203.0.113.53"))
        .await;
    let timed_snap = wait_snapshot(&timed, Duration::from_secs(20), |snap| {
        snap.delivery_failed_total >= 1
    })
    .await;
    assert!(
        timed_snap.admitted_total >= 1,
        "timeout path must admit locally after live bootstrap (broker paused before log): {:?}",
        (
            timed_snap.admitted_total,
            timed_snap.delivery_failed_total,
            timed_snap.delivered_total
        )
    );
    assert!(
        timed_snap.delivery_failed_total >= 1,
        "expected delivery timeout/retry exhaustion against paused broker, got delivered={} failed={}",
        timed_snap.delivered_total,
        timed_snap.delivery_failed_total
    );
    assert_eq!(timed_snap.delivered_total, 0);
    timed.finalize().await;
    broker
        .unpause_broker()
        .await
        .expect("unpause broker after delivery-timeout path");

    // --- immediate producer-queue saturation while a prior record is stuck ---
    let queue_topic = "ferrum-queue-sat";
    broker
        .create_topic(queue_topic, &[])
        .await
        .expect("create queue-sat topic");
    let saturated = plugin(
        &broker.bootstrap,
        queue_topic,
        json!({
            "message_timeout_ms": 30_000,
            "flush_timeout_seconds": 2,
            "producer_config": {
                "queue.buffering.max.messages": "1"
            }
        }),
    );
    broker
        .pause_broker()
        .await
        .expect("pause broker for queue-saturation path");
    for idx in 0..8 {
        saturated
            .log(&summary(&format!("/kafka-si-queue-{idx}"), "203.0.113.54"))
            .await;
    }
    let sat_snap = wait_snapshot(&saturated, Duration::from_secs(20), |snap| {
        snap.queue_rejected_total >= 1
    })
    .await;
    assert!(
        sat_snap.admitted_total >= 1,
        "queue saturation requires at least one prior local admission: {:?}",
        (
            sat_snap.admitted_total,
            sat_snap.queue_rejected_total,
            sat_snap.ferrum_dropped_total
        )
    );
    assert!(
        sat_snap.queue_rejected_total >= 1,
        "expected immediate librdkafka queue rejection, got admitted={} rejected={} dropped={}",
        sat_snap.admitted_total,
        sat_snap.queue_rejected_total,
        sat_snap.ferrum_dropped_total
    );
    saturated.finalize().await;
    broker
        .unpause_broker()
        .await
        .expect("unpause broker after queue-saturation path");

    // --- stalled/failed bounded finalize accounting ---
    let stall_topic = "ferrum-finalize-stall";
    broker
        .create_topic(stall_topic, &[])
        .await
        .expect("create finalize-stall topic");
    let stalled = plugin(
        &broker.bootstrap,
        stall_topic,
        json!({
            "message_timeout_ms": 30_000,
            "flush_timeout_seconds": 1,
        }),
    );
    broker
        .pause_broker()
        .await
        .expect("pause broker for finalize-stall path");
    stalled
        .log(&summary("/kafka-si-finalize-stall", "203.0.113.55"))
        .await;
    let admitted = wait_snapshot(&stalled, Duration::from_secs(10), |snap| {
        snap.admitted_total >= 1
    })
    .await;
    assert!(
        admitted.admitted_total >= 1,
        "finalize-stall fixture must admit a pending record first"
    );
    stalled.finalize().await;
    let stall_end = stalled.snapshot();
    assert!(stall_end.finalized);
    assert!(
        stall_end.flush_timeouts_total >= 1
            || stall_end.flush_failures_total >= 1
            || stall_end.shutdown_incomplete_total >= 1
            || stall_end.delivery_failed_total >= 1,
        "stalled finalize must record flush/timeout/incomplete or terminal delivery loss: timeouts={} failures={} incomplete={} failed={}",
        stall_end.flush_timeouts_total,
        stall_end.flush_failures_total,
        stall_end.shutdown_incomplete_total,
        stall_end.delivery_failed_total
    );
}

/// Generation isolation across instances, plus Drop-time disposal while pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn kafka_logging_real_broker_generation_isolation_and_reload_disposal() {
    let Some(broker) =
        redpanda("kafka_logging_real_broker_generation_isolation_and_reload_disposal").await
    else {
        return;
    };

    let topic_a = "ferrum-gen-a";
    let topic_b = "ferrum-gen-b";
    broker
        .create_topic(topic_a, &[])
        .await
        .expect("create gen-a topic");
    broker
        .create_topic(topic_b, &[])
        .await
        .expect("create gen-b topic");

    let plugin_a = plugin(&broker.bootstrap, topic_a, json!({}));
    let plugin_b = plugin(&broker.bootstrap, topic_b, json!({}));
    let gen_a = plugin_a.snapshot().generation_id;
    let gen_b = plugin_b.snapshot().generation_id;
    assert_ne!(
        gen_a, gen_b,
        "each plugin instance must own a distinct generation"
    );

    plugin_a
        .log(&summary("/kafka-si-gen-a", "203.0.113.60"))
        .await;
    plugin_b
        .log(&summary("/kafka-si-gen-b", "203.0.113.61"))
        .await;

    let snap_a = wait_snapshot(&plugin_a, Duration::from_secs(20), |snap| {
        snap.delivered_total >= 1
    })
    .await;
    let snap_b = wait_snapshot(&plugin_b, Duration::from_secs(20), |snap| {
        snap.delivered_total >= 1
    })
    .await;
    assert_eq!(snap_a.generation_id, gen_a);
    assert_eq!(snap_b.generation_id, gen_b);
    assert_eq!(snap_a.delivered_total, 1);
    assert_eq!(snap_b.delivered_total, 1);
    assert_eq!(snap_a.delivery_failed_total, 0);
    assert_eq!(snap_b.delivery_failed_total, 0);

    plugin_a.finalize().await;
    plugin_b.finalize().await;

    // Reload/old-generation disposal: drop a generation with a stuck pending
    // record on the multi-thread runtime (ordered finalize from Drop). Pause
    // the broker after producer construction — Redpanda cannot express
    // under-replicated acks=all via topic `min.insync.replicas`.
    let pending_topic = "ferrum-reload-pending";
    broker
        .create_topic(pending_topic, &[])
        .await
        .expect("create reload-pending topic");
    let old = plugin(
        &broker.bootstrap,
        pending_topic,
        json!({
            "message_timeout_ms": 30_000,
            "flush_timeout_seconds": 1,
        }),
    );
    let old_gen = old.snapshot().generation_id;
    broker
        .pause_broker()
        .await
        .expect("pause broker for reload-pending disposal");
    old.log(&summary("/kafka-si-reload-old", "203.0.113.62"))
        .await;
    let pending = wait_snapshot(&old, Duration::from_secs(10), |snap| {
        snap.admitted_total >= 1
    })
    .await;
    assert!(pending.admitted_total >= 1);
    drop(old);
    broker
        .unpause_broker()
        .await
        .expect("unpause broker before reload-new delivery");

    let healthy_topic = "ferrum-reload-new";
    broker
        .create_topic(healthy_topic, &[])
        .await
        .expect("create reload-new topic");
    let new_plugin = plugin(&broker.bootstrap, healthy_topic, json!({}));
    let new_gen = new_plugin.snapshot().generation_id;
    assert_ne!(old_gen, new_gen);
    new_plugin
        .log(&summary("/kafka-si-reload-new", "203.0.113.63"))
        .await;
    let new_snap = wait_snapshot(&new_plugin, Duration::from_secs(20), |snap| {
        snap.delivered_total >= 1
    })
    .await;
    assert_eq!(new_snap.generation_id, new_gen);
    assert_eq!(new_snap.delivered_total, 1);
    assert_eq!(new_snap.delivery_failed_total, 0);
    new_plugin.finalize().await;
}
