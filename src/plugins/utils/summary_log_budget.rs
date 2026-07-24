//! Pre-serialized summary log admission under shared byte budgets.
//!
//! HTTP/TCP/UDP logging sinks reserve a channel slot and a provisional
//! `max_entry_bytes` lease before cloning or serializing attacker-shaped
//! summary fields. Oversized or saturated records fail closed without
//! enqueueing an unbounded owned payload.

use std::sync::Arc;

use serde::Serialize;

use super::batching_logger::{BatchingLoggerPermit, DeferredBatchingLogger};
use super::byte_budget::{BoundedJsonWriter, ByteBudget, ByteLease, accounted_summary_bytes};
use super::log_schema::{SchemaView, SummarySchema};
use crate::plugins::{StreamTransactionSummary, TransactionSummary};

/// One admitted, pre-serialized summary record retained in a batching queue.
#[derive(Clone)]
pub struct QueuedSummaryPayload {
    json: Arc<str>,
    _lease: Arc<ByteLease>,
}

impl QueuedSummaryPayload {
    pub fn as_bytes(&self) -> &[u8] {
        self.json.as_bytes()
    }
}

/// Serialize `value` under `max_entry_bytes`, shrink the provisional lease, and
/// return a queueable payload. Returns `None` after recording a budget drop.
pub fn serialize_under_byte_budget<T: Serialize + ?Sized>(
    budget: &ByteBudget,
    max_entry_bytes: usize,
    value: &T,
) -> Option<QueuedSummaryPayload> {
    let lease = budget.try_acquire(accounted_summary_bytes(max_entry_bytes))?;
    let mut writer = BoundedJsonWriter::new(max_entry_bytes);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.limit_exceeded {
            budget.record_drop("serialized entry exceeded max_entry_bytes");
        } else {
            tracing::warn!(
                plugin = "summary_log_budget",
                "failed to serialize observability entry: {error}"
            );
            budget.record_drop("serialization failed");
        }
        return None;
    }
    let retained = writer.bytes.len();
    if retained > max_entry_bytes {
        budget.record_drop("serialized entry exceeded max_entry_bytes");
        return None;
    }
    lease.shrink_to(accounted_summary_bytes(retained));
    let json = match String::from_utf8(writer.bytes) {
        Ok(line) => Arc::<str>::from(line),
        Err(_) => {
            budget.record_drop("serialized entry was not UTF-8");
            return None;
        }
    };
    Some(QueuedSummaryPayload {
        json,
        _lease: lease,
    })
}

fn send_payload(
    permit: BatchingLoggerPermit<QueuedSummaryPayload>,
    budget: &ByteBudget,
    max_entry_bytes: usize,
    value: &impl Serialize,
) {
    match serialize_under_byte_budget(budget, max_entry_bytes, value) {
        Some(payload) => permit.send(payload),
        None => {
            // Permit drop releases the channel slot.
        }
    }
}

/// Reserve a queue slot, then serialize an HTTP summary under the byte budget.
pub fn admit_http_summary(
    logger: &DeferredBatchingLogger<QueuedSummaryPayload>,
    budget: &ByteBudget,
    max_entry_bytes: usize,
    summary: &TransactionSummary,
    schema: Option<&SummarySchema>,
) {
    let Some(permit) = logger.try_reserve() else {
        budget.record_drop("queue slot exhausted");
        return;
    };
    match schema.filter(|schema| schema.applies_to_http()) {
        Some(schema) => send_payload(
            permit,
            budget,
            max_entry_bytes,
            &SchemaView { summary, schema },
        ),
        None => send_payload(permit, budget, max_entry_bytes, summary),
    }
}

/// Reserve a queue slot, then serialize a stream summary under the byte budget.
pub fn admit_stream_summary(
    logger: &DeferredBatchingLogger<QueuedSummaryPayload>,
    budget: &ByteBudget,
    max_entry_bytes: usize,
    summary: &StreamTransactionSummary,
    schema: Option<&SummarySchema>,
) {
    let Some(permit) = logger.try_reserve() else {
        budget.record_drop("queue slot exhausted");
        return;
    };
    match schema.filter(|schema| schema.applies_to_stream()) {
        Some(schema) => send_payload(
            permit,
            budget,
            max_entry_bytes,
            &SchemaView { summary, schema },
        ),
        None => send_payload(permit, budget, max_entry_bytes, summary),
    }
}

/// Assemble a JSON array body from pre-serialized entries for HTTP/UDP sinks.
pub fn assemble_json_array(batch: &[QueuedSummaryPayload]) -> String {
    let capacity = batch.iter().fold(2usize, |total, entry| {
        total.saturating_add(entry.json.len().saturating_add(1))
    });
    let mut body = String::with_capacity(capacity);
    body.push('[');
    for (idx, entry) in batch.iter().enumerate() {
        if idx > 0 {
            body.push(',');
        }
        body.push_str(entry.json.as_ref());
    }
    body.push(']');
    body
}

/// Assemble NDJSON from pre-serialized entries for TCP sinks.
pub fn assemble_ndjson(batch: &[QueuedSummaryPayload]) -> Vec<u8> {
    let mut body = Vec::with_capacity(
        batch
            .iter()
            .map(|entry| entry.json.len().saturating_add(1))
            .sum::<usize>(),
    );
    for entry in batch {
        body.extend_from_slice(entry.as_bytes());
        body.push(b'\n');
    }
    body
}
