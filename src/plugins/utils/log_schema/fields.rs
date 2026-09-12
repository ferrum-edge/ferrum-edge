//! Static registry of native field names for [`TransactionSummary`],
//! [`StreamTransactionSummary`], and WebSocket disconnect log entries.
//!
//! The schema customization layer validates operator-supplied field names
//! (in `omit`, `rename`, `order`, derived `from`) against these tables.
//! Drift between this registry and the structs is caught by the integration
//! test in `tests/integration/log_schema_registry_tests.rs`.

use super::{DerivedKind, SummaryType};

/// The record family a schema is compiled against.
///
/// The shared compiler was originally written for the transaction-summary
/// family only. Three non-shipping plugins emit their own externally visible
/// record shapes and reuse the identical compile/resolve machinery against
/// their own field inventory rather than growing divergent mini-projections:
///
/// * [`RecordFamily::ChargebackReport`] — the per-proxy billing row inside the
///   `api_chargeback` `GET /charges` document.
/// * [`RecordFamily::ChargeEvent`] — the `api_chargeback_sink` JSONEachRow
///   charge record.
/// * [`RecordFamily::DebugDiagnostic`] — the `transaction_debugger` terminal
///   diagnostic records (HTTP, stream, and WebSocket disconnect).
///
/// Each family owns its field inventory, whether `summary_type` partitions it,
/// whether its records carry a metadata map, and which derived kinds are
/// representable. Everything a family does not support fails closed at compile
/// time with a plugin- and field-specific diagnostic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RecordFamily {
    /// `TransactionSummary` / `StreamTransactionSummary` (+ `ws_logging`
    /// WebSocket-disconnect entries). The historical, default family.
    #[default]
    TransactionSummary,
    /// `api_chargeback` `/charges` per-proxy billing row.
    ChargebackReport,
    /// `api_chargeback_sink` exported charge event.
    ChargeEvent,
    /// `transaction_debugger` terminal diagnostic record.
    DebugDiagnostic,
}

impl RecordFamily {
    /// Operator-facing label used in compile diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::TransactionSummary => "transaction summary",
            Self::ChargebackReport => "chargeback billing row",
            Self::ChargeEvent => "chargeback charge event",
            Self::DebugDiagnostic => "transaction diagnostic",
        }
    }

    /// `true` when `summary_type` meaningfully partitions this family's
    /// records into HTTP-family and stream-family entries.
    pub const fn uses_summary_type(self) -> bool {
        matches!(self, Self::TransactionSummary | Self::DebugDiagnostic)
    }

    /// `true` when explicit output `order` is honored for this family.
    ///
    /// [`RecordFamily::ChargebackReport`] rows are members of a
    /// `serde_json::Map`-backed document that is assembled and re-serialized as
    /// a whole, so member order is not under the projection's control. Accepting
    /// an `order` there would silently do nothing, so it is rejected instead.
    pub const fn supports_order(self) -> bool {
        !matches!(self, Self::ChargebackReport)
    }

    /// `true` when `timestamp_format` is meaningful for this family.
    ///
    /// The conversion operates on RFC3339 timestamp *strings*. A family with no
    /// such field has nothing to convert: the chargeback billing row carries no
    /// timestamp at all, and a charge event's `received_at` is an epoch-
    /// nanosecond integer whose representation is fixed by the ClickHouse
    /// column it inserts into. Accepting the key there would either do nothing
    /// or silently change a column's type, so it is rejected instead.
    pub const fn supports_timestamp_format(self) -> bool {
        matches!(self, Self::TransactionSummary | Self::DebugDiagnostic)
    }

    /// `true` when this family's records carry a `metadata` map, making the
    /// `metadata` policy (`nested` / `omit` / `flatten`) meaningful.
    pub const fn has_metadata(self) -> bool {
        matches!(self, Self::TransactionSummary | Self::DebugDiagnostic)
    }

    /// `true` when `kind` is representable from this family's records.
    ///
    /// A derived kind that has no source field on the family is rejected at
    /// compile time rather than silently emitting a sentinel: an operator that
    /// asks for `backend_host` on a charge event (which carries no backend
    /// target at all) has a configuration error, not a missing value.
    pub const fn supports_derived(self, kind: DerivedKind) -> bool {
        match self {
            Self::TransactionSummary | Self::DebugDiagnostic => true,
            // Charge events carry a billable status and a gRPC status but no
            // backend target.
            Self::ChargeEvent => !matches!(kind, DerivedKind::BackendHost),
            // A billing row is an aggregate across many transactions: it has
            // no single status, backend, or outcome.
            Self::ChargebackReport => matches!(kind, DerivedKind::SummaryKind),
        }
    }
}

/// Optional field families a specific caller opts into.
///
/// [`super::SummarySchema::compile`] is shared by every logging plugin, but
/// only `ws_logging` serializes `WsDisconnectLogEntry`. The
/// WebSocket-disconnect field family is therefore gated behind an explicit
/// capability so every other caller (`http_logging`, `kafka_logging`,
/// `loki_logging`, `stdout_logging`, …) sees exactly the base HTTP / stream
/// registry: ws-only names stay rejected in `omit` / `rename` / `order` and
/// never reserve output keys that would collide with `static_fields` or
/// flattened metadata.
///
/// [`SchemaCapabilities::family`] selects the record family entirely; the
/// `websocket_disconnect` flag is a family-local opt-in that currently applies
/// to [`RecordFamily::TransactionSummary`] (`ws_logging`) and
/// [`RecordFamily::DebugDiagnostic`] (`transaction_debugger`, which also
/// observes WebSocket disconnects).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SchemaCapabilities {
    /// Expose the WebSocket-disconnect field family to `http`
    /// and `both` summary types.
    pub websocket_disconnect: bool,
    /// Which record family's field inventory this schema compiles against.
    pub family: RecordFamily,
}

impl SchemaCapabilities {
    /// Base registry shared by every non-WebSocket logging plugin — exactly
    /// the HTTP and stream field families, matching pre-WS behavior.
    pub const BASE: Self = Self {
        websocket_disconnect: false,
        family: RecordFamily::TransactionSummary,
    };

    /// `ws_logging` capability: additionally expose the WebSocket-disconnect
    /// field family to `http` / `both` schemas.
    pub const WS_LOGGING: Self = Self {
        websocket_disconnect: true,
        family: RecordFamily::TransactionSummary,
    };

    /// `api_chargeback` capability: the `/charges` per-proxy billing row.
    pub const API_CHARGEBACK: Self = Self {
        websocket_disconnect: false,
        family: RecordFamily::ChargebackReport,
    };

    /// `api_chargeback_sink` capability: the exported charge event.
    pub const API_CHARGEBACK_SINK: Self = Self {
        websocket_disconnect: false,
        family: RecordFamily::ChargeEvent,
    };

    /// `transaction_debugger` capability: terminal diagnostics for HTTP,
    /// stream, and WebSocket-disconnect records.
    pub const TRANSACTION_DEBUGGER: Self = Self {
        websocket_disconnect: true,
        family: RecordFamily::DebugDiagnostic,
    };

    /// The same family without any optional field-family opt-in.
    ///
    /// Used by the compiler to decide which native specs are capability-added
    /// "extension" fields. For [`Self::BASE`] this is the identity, so the
    /// historical behavior of every non-`ws_logging` logging plugin is
    /// unchanged.
    pub const fn without_optional_families(self) -> Self {
        Self {
            websocket_disconnect: false,
            family: self.family,
        }
    }
}

/// Metadata for a single native field on a summary struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldMeta {
    pub name: &'static str,
    /// `true` when the field is an RFC3339 timestamp string subject to
    /// [`super::TimestampFormat`] conversion at serialize time.
    pub is_timestamp: bool,
}

/// Fields on [`crate::plugins::TransactionSummary`] in declaration order.
pub const HTTP_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "timestamp_received",
        is_timestamp: true,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "http_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_path",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_resolved_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "response_status_code",
        is_timestamp: false,
    },
    FieldMeta {
        name: "grpc_status",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_total_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_gateway_processing_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_backend_ttfb_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_backend_total_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_plugin_execution_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_plugin_external_io_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_gateway_overhead_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_user_agent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "response_streamed",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_disconnected",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "body_error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "body_completed",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "grpc_request_messages",
        is_timestamp: false,
    },
    FieldMeta {
        name: "grpc_response_messages",
        is_timestamp: false,
    },
    FieldMeta {
        name: "mirror",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// Fields on [`crate::plugins::StreamTransactionSummary`] in declaration order.
pub const STREAM_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_resolved_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "protocol",
        is_timestamp: false,
    },
    FieldMeta {
        name: "listen_port",
        is_timestamp: false,
    },
    FieldMeta {
        name: "duration_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "connection_error",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "disconnect_direction",
        is_timestamp: false,
    },
    FieldMeta {
        name: "disconnect_cause",
        is_timestamp: false,
    },
    FieldMeta {
        name: "timestamp_connected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "timestamp_disconnected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "sni_hostname",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// Fields on the `ws_logging` WebSocket disconnect entry in declaration order.
///
/// WebSocket disconnect entries belong to the HTTP / WebSocket summary
/// family, but the shared log-schema compiler only exposes them to `http` /
/// `both` schemas when the caller opts in via
/// [`SchemaCapabilities::websocket_disconnect`] (i.e. the `ws_logging`
/// plugin). Every other logging plugin sees the base registry, so ws-only
/// names stay rejected and never reserve output keys.
pub const WS_DISCONNECT_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "event",
        is_timestamp: false,
    },
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "protocol",
        is_timestamp: false,
    },
    FieldMeta {
        name: "listen_port",
        is_timestamp: false,
    },
    FieldMeta {
        name: "duration_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "frames_client_to_backend",
        is_timestamp: false,
    },
    FieldMeta {
        name: "frames_backend_to_client",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_client_to_backend",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_backend_to_client",
        is_timestamp: false,
    },
    FieldMeta {
        name: "timestamp_connected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "timestamp_disconnected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "direction",
        is_timestamp: false,
    },
    FieldMeta {
        name: "io_side",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// Native keys of the `api_chargeback` `/charges` per-proxy billing row, in
/// emission order.
///
/// This is the externally documented representation boundary for
/// `api_chargeback`: the leaf object under
/// `consumers.<consumer>.proxies.<key>`. The registry entry key, the billing
/// identity, and the charge accounting that produce these numbers are
/// unaffected by projection — only the rendered row is projected.
///
/// `by_status`, `bandwidth`, and `stream` are nested objects; they may be
/// renamed, omitted, or ordered like any other native field, but their inner
/// keys are not part of the schema surface. `stream` is emitted only when the
/// row carries stream activity, exactly as in the default rendering.
pub const CHARGEBACK_REPORT_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "currency",
        is_timestamp: false,
    },
    FieldMeta {
        name: "protocol_family",
        is_timestamp: false,
    },
    FieldMeta {
        name: "total_calls",
        is_timestamp: false,
    },
    FieldMeta {
        name: "total_charges",
        is_timestamp: false,
    },
    FieldMeta {
        name: "by_status",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bandwidth",
        is_timestamp: false,
    },
    FieldMeta {
        name: "stream",
        is_timestamp: false,
    },
];

/// Native keys of an `api_chargeback_sink` exported charge event, in
/// declaration order on `ChargeEvent`.
///
/// `received_at` is an epoch-nanosecond integer, not an RFC3339 string, and its
/// representation is fixed by the ClickHouse column it inserts into — so it is
/// not a `timestamp_format` field and the key itself is rejected for this
/// family.
pub const CHARGE_EVENT_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "event_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "received_at",
        is_timestamp: false,
    },
    FieldMeta {
        name: "node_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "route_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "status_code",
        is_timestamp: false,
    },
    FieldMeta {
        name: "http_status_code",
        is_timestamp: false,
    },
    FieldMeta {
        name: "grpc_status",
        is_timestamp: false,
    },
    FieldMeta {
        name: "protocol",
        is_timestamp: false,
    },
    FieldMeta {
        name: "call_count",
        is_timestamp: false,
    },
    FieldMeta {
        name: "charge_call",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "charge_bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "charge_bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "charge_total",
        is_timestamp: false,
    },
    FieldMeta {
        name: "currency",
        is_timestamp: false,
    },
    FieldMeta {
        name: "pricing_version",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "trace_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "snapshot_id",
        is_timestamp: false,
    },
];

/// Native keys of a `transaction_debugger` HTTP / gRPC terminal diagnostic, in
/// the order the default (schema-free) `transaction_debug` event emits them.
pub const DEBUG_HTTP_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "outcome",
        is_timestamp: false,
    },
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "timestamp_received",
        is_timestamp: true,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "path",
        is_timestamp: false,
    },
    FieldMeta {
        name: "status",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_resolved_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "body_error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "response_streamed",
        is_timestamp: false,
    },
    FieldMeta {
        name: "body_completed",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_disconnected",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "rejection_phase",
        is_timestamp: false,
    },
    FieldMeta {
        name: "grpc_status",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "trace_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_total_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_backend_ttfb_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_backend_total_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_plugin_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_gw_overhead_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// Native keys of a `transaction_debugger` stream (TCP/UDP/DTLS) terminal
/// diagnostic, in default emission order.
pub const DEBUG_STREAM_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "outcome",
        is_timestamp: false,
    },
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "protocol",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "listen_port",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_resolved_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "connection_error",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "disconnect_direction",
        is_timestamp: false,
    },
    FieldMeta {
        name: "disconnect_cause",
        is_timestamp: false,
    },
    FieldMeta {
        name: "duration_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "timestamp_connected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "timestamp_disconnected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "sni_hostname",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "trace_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// Native keys of a `transaction_debugger` WebSocket-disconnect terminal
/// diagnostic, in default emission order.
///
/// Gated behind [`SchemaCapabilities::websocket_disconnect`] exactly like the
/// `ws_logging` family, so the WebSocket-only names are extension fields for
/// `order` completeness and per-entry flatten reservation.
pub const DEBUG_WS_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "outcome",
        is_timestamp: false,
    },
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "listen_port",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "duration_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "frames_client_to_backend",
        is_timestamp: false,
    },
    FieldMeta {
        name: "frames_backend_to_client",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_client_to_backend",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_backend_to_client",
        is_timestamp: false,
    },
    FieldMeta {
        name: "disconnect_direction",
        is_timestamp: false,
    },
    FieldMeta {
        name: "io_side",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "trace_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// The field families visible for `summary_type` under `caps`.
///
/// The WebSocket-disconnect family is appended to the `http` / `both`
/// families only when the caller opts in via
/// [`SchemaCapabilities::websocket_disconnect`]. Families that do not partition
/// their records by `summary_type` ignore it entirely — the compiler rejects an
/// explicit `summary_type` for those families before this is reached.
fn field_sets(summary_type: SummaryType, caps: SchemaCapabilities) -> Vec<&'static [FieldMeta]> {
    let (http, stream, ws): (
        &'static [FieldMeta],
        &'static [FieldMeta],
        &'static [FieldMeta],
    ) = match caps.family {
        RecordFamily::TransactionSummary => (HTTP_FIELDS, STREAM_FIELDS, WS_DISCONNECT_FIELDS),
        RecordFamily::DebugDiagnostic => (DEBUG_HTTP_FIELDS, DEBUG_STREAM_FIELDS, DEBUG_WS_FIELDS),
        RecordFamily::ChargebackReport => return vec![CHARGEBACK_REPORT_FIELDS],
        RecordFamily::ChargeEvent => return vec![CHARGE_EVENT_FIELDS],
    };
    let mut sets: Vec<&'static [FieldMeta]> = match summary_type {
        SummaryType::Http => vec![http],
        SummaryType::Stream => vec![stream],
        SummaryType::Both => vec![http, stream],
    };
    if caps.websocket_disconnect && matches!(summary_type, SummaryType::Http | SummaryType::Both) {
        sets.push(ws);
    }
    sets
}

/// Look up a field by name for the given summary type and capabilities.
///
/// For [`SummaryType::Both`] the field may exist on any visible entry type.
pub fn lookup(
    summary_type: SummaryType,
    caps: SchemaCapabilities,
    name: &str,
) -> Option<FieldMeta> {
    field_sets(summary_type, caps)
        .iter()
        .flat_map(|set| set.iter())
        .find(|f| f.name == name)
        .copied()
}

/// All field names visible for the given summary type and capabilities, in
/// declaration order, deduplicated across entry types.
pub fn fields_for(summary_type: SummaryType, caps: SchemaCapabilities) -> Vec<FieldMeta> {
    union_fields(&field_sets(summary_type, caps))
}

fn union_fields(field_sets: &[&[FieldMeta]]) -> Vec<FieldMeta> {
    let mut out = Vec::new();
    for fields in field_sets {
        for field in *fields {
            if !out
                .iter()
                .any(|existing: &FieldMeta| existing.name == field.name)
            {
                out.push(*field);
            }
        }
    }
    out
}

/// Suggest the closest known field name to a misspelling, when the
/// Levenshtein distance is small enough to be useful (≤ 2 for short names,
/// ≤ 3 for long names).
pub fn levenshtein_suggest(
    summary_type: SummaryType,
    caps: SchemaCapabilities,
    name: &str,
) -> Option<&'static str> {
    let candidates = field_sets(summary_type, caps);
    let mut best: Option<(usize, &'static str)> = None;
    for set in &candidates {
        for field in *set {
            let d = levenshtein(name, field.name);
            if best.map(|(b, _)| d < b).unwrap_or(true) {
                best = Some((d, field.name));
            }
        }
    }
    let threshold = if name.len() > 8 { 3 } else { 2 };
    best.filter(|(d, _)| *d <= threshold).map(|(_, n)| n)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: SchemaCapabilities = SchemaCapabilities::BASE;
    const WS: SchemaCapabilities = SchemaCapabilities::WS_LOGGING;

    #[test]
    fn lookup_known_http_field() {
        assert_eq!(
            lookup(SummaryType::Http, BASE, "proxy_id"),
            Some(FieldMeta {
                name: "proxy_id",
                is_timestamp: false
            })
        );
    }

    #[test]
    fn lookup_known_stream_field() {
        assert_eq!(
            lookup(SummaryType::Stream, BASE, "bytes_sent"),
            Some(FieldMeta {
                name: "bytes_sent",
                is_timestamp: false
            })
        );
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup(SummaryType::Http, BASE, "not_a_field").is_none());
    }

    #[test]
    fn lookup_http_field_not_on_stream() {
        // request_path is only on TransactionSummary.
        assert!(lookup(SummaryType::Stream, BASE, "request_path").is_none());
        assert!(lookup(SummaryType::Http, BASE, "request_path").is_some());
        assert!(lookup(SummaryType::Both, BASE, "request_path").is_some());
    }

    #[test]
    fn lookup_stream_only_field_not_on_http() {
        assert!(lookup(SummaryType::Http, BASE, "timestamp_connected").is_none());
        assert!(lookup(SummaryType::Stream, BASE, "timestamp_connected").is_some());
        assert!(lookup(SummaryType::Both, BASE, "timestamp_connected").is_some());
    }

    #[test]
    fn websocket_disconnect_field_gated_by_capability() {
        // WS-only field: invisible without the capability (every non-ws
        // plugin), visible with it (ws_logging).
        assert!(lookup(SummaryType::Http, BASE, "frames_client_to_backend").is_none());
        assert!(lookup(SummaryType::Both, BASE, "frames_client_to_backend").is_none());
        assert!(lookup(SummaryType::Http, WS, "frames_client_to_backend").is_some());
        assert!(lookup(SummaryType::Both, WS, "frames_client_to_backend").is_some());
        // The capability never leaks WS fields into stream schemas.
        assert!(lookup(SummaryType::Stream, WS, "frames_client_to_backend").is_none());
    }

    #[test]
    fn ws_only_protocol_field_gated_on_http() {
        // `protocol` exists on the WS-disconnect family but not on the base
        // HTTP registry. It must stay unknown for http/both without the
        // capability so non-ws plugins reject it exactly as before.
        assert!(lookup(SummaryType::Http, BASE, "protocol").is_none());
        assert!(lookup(SummaryType::Http, WS, "protocol").is_some());
        // Stream summaries carry their own `protocol` field regardless.
        assert!(lookup(SummaryType::Stream, BASE, "protocol").is_some());
    }

    #[test]
    fn timestamp_flag_set_correctly() {
        let f = lookup(SummaryType::Http, BASE, "timestamp_received").unwrap();
        assert!(f.is_timestamp);
        let f = lookup(SummaryType::Stream, BASE, "timestamp_connected").unwrap();
        assert!(f.is_timestamp);
        let f = lookup(SummaryType::Stream, BASE, "timestamp_disconnected").unwrap();
        assert!(f.is_timestamp);
        let f = lookup(SummaryType::Http, BASE, "client_ip").unwrap();
        assert!(!f.is_timestamp);
    }

    #[test]
    fn fields_for_both_unions_and_dedupes() {
        let all = fields_for(SummaryType::Both, BASE);
        // namespace, proxy_id, client_ip etc. exist on both — should appear once.
        let namespaces = all.iter().filter(|f| f.name == "namespace").count();
        assert_eq!(namespaces, 1);
        let proxy_ids = all.iter().filter(|f| f.name == "proxy_id").count();
        assert_eq!(proxy_ids, 1);
        // Base capability: no WS-disconnect family in the union.
        let expected = union_fields(&[HTTP_FIELDS, STREAM_FIELDS]);
        assert_eq!(all, expected);
    }

    #[test]
    fn fields_for_both_includes_ws_family_with_capability() {
        let base = fields_for(SummaryType::Both, BASE);
        let ws = fields_for(SummaryType::Both, WS);
        // The WS capability adds the WS-only fields (deduped against the
        // overlap with HTTP / stream fields).
        assert!(base.iter().all(|f| f.name != "frames_client_to_backend"));
        assert!(ws.iter().any(|f| f.name == "frames_client_to_backend"));
        assert_eq!(
            ws,
            union_fields(&[HTTP_FIELDS, STREAM_FIELDS, WS_DISCONNECT_FIELDS])
        );
    }

    #[test]
    fn levenshtein_suggests_close_match() {
        assert_eq!(
            levenshtein_suggest(SummaryType::Http, BASE, "proxy_idd"),
            Some("proxy_id")
        );
        assert_eq!(
            levenshtein_suggest(SummaryType::Http, BASE, "lateny_total_ms"),
            Some("latency_total_ms")
        );
    }

    #[test]
    fn levenshtein_skips_far_matches() {
        assert!(levenshtein_suggest(SummaryType::Http, BASE, "completely_unrelated").is_none());
    }

    #[test]
    fn http_fields_match_expected_count() {
        // Drift sentinel — the integration test in
        // tests/integration/log_schema_registry_tests.rs verifies the
        // actual serde output keys match these. This is the cheap
        // unit-test guard against accidental deletions.
        assert_eq!(HTTP_FIELDS.len(), 32);
    }

    #[test]
    fn stream_fields_match_expected_count() {
        assert_eq!(STREAM_FIELDS.len(), 21);
    }

    #[test]
    fn websocket_disconnect_fields_match_expected_count() {
        assert_eq!(WS_DISCONNECT_FIELDS.len(), 21);
    }
}
