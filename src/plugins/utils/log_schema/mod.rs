//! Customizable transaction-log output schema.
//!
//! Operators configure a `schema:` (or `schema_ref:`) block on any logging
//! plugin to rename, omit, reorder, or augment the fields in
//! [`crate::plugins::TransactionSummary`], [`crate::plugins::StreamTransactionSummary`],
//! and `ws_logging` WebSocket disconnect entries.
//!
//! Apply order at serialization time is driven by the compiled
//! [`SummarySchema::fields`] vec. Metadata redaction is preserved by routing
//! every metadata write through
//! [`crate::plugins::utils::metadata_redaction`]; sensitive keys cannot be
//! introduced via static or derived fields (the compiler rejects them).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::Value;

use crate::plugins::utils::metadata_redaction::is_sensitive_metadata_key;

/// Fixed-shape keys accepted by [`SummarySchema::compile`]. Intentionally
/// open maps (`rename` and `static_fields`) validate their values separately.
pub const SUMMARY_LOG_SCHEMA_KEYS: &[&str] = &[
    "summary_type",
    "omit",
    "rename",
    "order",
    "static_fields",
    "derived_fields",
    "metadata",
    "timestamp_format",
];

/// Fixed-shape keys accepted for each `derived_fields` entry.
pub const DERIVED_FIELD_KEYS: &[&str] = &["name", "kind"];

/// Fixed-shape keys accepted by the `metadata` policy object.
pub const METADATA_POLICY_KEYS: &[&str] = &["mode", "prefix", "on_collision"];

pub mod fields;
pub mod registry;
pub mod view;

// Re-exports for downstream consumers (integration tests, custom plugins,
// future admin endpoints). The binary itself reaches these through their
// submodule paths so an `unused_imports` lint would otherwise fire.
#[allow(unused_imports)]
pub use fields::{FieldMeta, HTTP_FIELDS, STREAM_FIELDS, SchemaCapabilities, WS_DISCONNECT_FIELDS};
#[allow(unused_imports)]
pub use view::{SchemaSerializable, SchemaView};

/// Which summary struct(s) a schema applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SummaryType {
    Http,
    Stream,
    #[default]
    Both,
}

impl SummaryType {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "http" => Ok(Self::Http),
            "stream" => Ok(Self::Stream),
            "both" => Ok(Self::Both),
            other => Err(format!(
                "schema: 'summary_type' must be 'http', 'stream', or 'both' (got '{other}')"
            )),
        }
    }
}

/// Compiled schema: the source of truth at serialize time.
#[derive(Debug, Clone)]
pub struct SummarySchema {
    pub summary_type: SummaryType,
    /// Fields in the order they are emitted. May include native, static,
    /// and derived entries. `metadata` is handled separately via
    /// `metadata` policy when [`MetadataPolicy::Flatten`] is set; in
    /// other modes it appears here as a native field.
    pub fields: Vec<FieldSpec>,
    pub metadata: MetadataPolicy,
    pub timestamp_format: TimestampFormat,
    /// `true` when this schema was compiled under a capability beyond
    /// [`SchemaCapabilities::BASE`] (i.e. `ws_logging`). Under such a schema a
    /// single `summary_type` (`http` / `both`) is shared by more than one
    /// entry kind (`TransactionSummary` and `WsDisconnectLogEntry`), so
    /// flatten-collision reservation is scoped to the fields the concrete
    /// entry actually owns: a native spec reserves its output key only when
    /// `SchemaSerializable::owns_native` is true for the entry being
    /// serialized. BASE schemas keep reserving every native key
    /// unconditionally, so non-`ws_logging` plugins are byte-identical to
    /// pre-capability behavior.
    pub capability_scoped: bool,
}

/// Compiled output-field spec.
#[derive(Debug, Clone)]
pub enum FieldSpec {
    Native {
        /// The native struct field name (matches a [`FieldMeta::name`]).
        source: &'static str,
        /// The output JSON key. Equals `source` unless renamed.
        out_key: String,
        is_timestamp: bool,
        /// `true` when this native field is present ONLY because the caller
        /// opted into a capability beyond [`SchemaCapabilities::BASE`] (i.e.
        /// a WebSocket-disconnect-exclusive field on a `ws_logging` schema).
        /// Extension fields are treated per entry kind: they are exempt from
        /// `order` completeness and only reserve an output key for the entry
        /// kind that actually owns them. Always `false` for BASE callers, so
        /// non-`ws_logging` plugins behave exactly as before.
        extension: bool,
    },
    Static {
        out_key: String,
        value: Value,
    },
    Derived {
        out_key: String,
        kind: DerivedKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedKind {
    /// `"2xx"`/`"3xx"`/`"4xx"`/`"5xx"`/`"other"` from `response_status_code`.
    /// On stream summaries (no HTTP status), emits `"none"`.
    StatusClass,
    /// Hostname extracted from `backend_target` (HTTP) or
    /// `backend_target` (stream).
    BackendHost,
    /// `"http"`, `"stream"`, or `"websocket_disconnect"` — useful for
    /// unified pipelines.
    SummaryKind,
    /// `"ok"` / `"error"`. HTTP: status ≥ 500 or `error_class.is_some()` →
    /// `error`. Stream: any of `connection_error`, `error_class`,
    /// `disconnect_cause: BackendError` → `error`. WebSocket disconnect:
    /// `error_class.is_some()` → `error`.
    Outcome,
}

impl DerivedKind {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "status_class" => Ok(Self::StatusClass),
            "backend_host" => Ok(Self::BackendHost),
            "summary_kind" => Ok(Self::SummaryKind),
            "outcome" => Ok(Self::Outcome),
            other => Err(format!(
                "schema: unknown derived kind '{other}' (valid: status_class, backend_host, summary_kind, outcome)"
            )),
        }
    }
}

/// How to render the `metadata` map.
#[derive(Debug, Clone, Default)]
pub enum MetadataPolicy {
    /// Emit `metadata` as a nested object under whatever out_key was
    /// chosen (default: `"metadata"`). Sensitive keys redacted.
    #[default]
    Nested,
    /// Omit the metadata map entirely from output.
    Omit,
    /// Promote each metadata key/value to a top-level entry.
    Flatten {
        prefix: Option<String>,
        on_collision: CollisionMode,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CollisionMode {
    /// Existing entry wins; the metadata entry is dropped silently.
    #[default]
    Skip,
    /// Metadata entry overwrites the existing one.
    Overwrite,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimestampFormat {
    #[default]
    Rfc3339,
    EpochMs,
    EpochS,
}

impl TimestampFormat {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "rfc3339" => Ok(Self::Rfc3339),
            "epoch_ms" => Ok(Self::EpochMs),
            "epoch_s" => Ok(Self::EpochS),
            other => Err(format!(
                "schema: 'timestamp_format' must be 'rfc3339', 'epoch_ms', or 'epoch_s' (got '{other}')"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

impl SummarySchema {
    /// Compile a raw schema config into the runtime form.
    ///
    /// `caps` gates optional field families the caller opts into. Every
    /// non-WebSocket logging plugin passes [`SchemaCapabilities::BASE`];
    /// only `ws_logging` passes [`SchemaCapabilities::WS_LOGGING`], which
    /// makes the WebSocket-disconnect field family valid in `http` / `both`
    /// schemas. Under `BASE`, ws-only names are rejected in `omit` /
    /// `rename` / `order` and never reserve output keys — identical to
    /// pre-WS behavior for shared callers.
    pub fn compile(
        raw: &Value,
        plugin_name: &str,
        caps: SchemaCapabilities,
    ) -> Result<Arc<Self>, String> {
        if !raw.is_object() {
            return Err(format!("{plugin_name}: 'schema' must be an object"));
        }

        // Reject unknown top-level keys so typos surface immediately.
        if let Some(obj) = raw.as_object() {
            for key in obj.keys() {
                if !SUMMARY_LOG_SCHEMA_KEYS.contains(&key.as_str()) {
                    return Err(format!(
                        "{plugin_name}: unknown schema key '{key}' (valid keys: {})",
                        SUMMARY_LOG_SCHEMA_KEYS.join(", ")
                    ));
                }
            }
        }

        let summary_type = match raw.get("summary_type") {
            Some(Value::String(s)) => SummaryType::parse(s)?,
            None => SummaryType::default(),
            Some(_) => {
                return Err(format!(
                    "{plugin_name}: schema 'summary_type' must be a string"
                ));
            }
        };

        let omit = parse_string_array(raw.get("omit"), plugin_name, "omit")?;
        for name in &omit {
            if fields::lookup(summary_type, caps, name).is_none() {
                return Err(unknown_field_error(
                    plugin_name,
                    "omit",
                    name,
                    summary_type,
                    caps,
                ));
            }
        }

        let rename = parse_string_map(raw.get("rename"), plugin_name, "rename")?;
        for (source, target) in &rename {
            if fields::lookup(summary_type, caps, source).is_none() {
                return Err(unknown_field_error(
                    plugin_name,
                    "rename",
                    source,
                    summary_type,
                    caps,
                ));
            }
            if omit.contains(source) {
                return Err(format!(
                    "{plugin_name}: schema field '{source}' is both omitted and renamed (rename target '{target}')"
                ));
            }
            if target.is_empty() {
                return Err(format!(
                    "{plugin_name}: schema rename target for '{source}' must be a non-empty string"
                ));
            }
            // The rename target is the operator-visible JSON key. If it
            // matches a sensitive-data substring, downstream log
            // redactors keyed on field name will silently drop legitimate
            // (non-sensitive) values. Reject so the operator picks a
            // different name. Mirrors the static_fields / derived_fields
            // check.
            if is_sensitive_metadata_key(target) {
                return Err(format!(
                    "{plugin_name}: schema rename target '{target}' (for source '{source}') matches a sensitive-data substring; pick a different name"
                ));
            }
        }

        let static_fields = parse_static_fields(raw.get("static_fields"), plugin_name)?;

        let derived_fields = parse_derived_fields(raw.get("derived_fields"), plugin_name)?;

        let metadata = parse_metadata_policy(raw.get("metadata"), plugin_name)?;

        let timestamp_format = match raw.get("timestamp_format") {
            Some(Value::String(s)) => TimestampFormat::parse(s)?,
            None => TimestampFormat::default(),
            Some(_) => {
                return Err(format!(
                    "{plugin_name}: schema 'timestamp_format' must be a string"
                ));
            }
        };

        // ------------------------------------------------------------------
        // Build the unordered FieldSpec set.
        // ------------------------------------------------------------------

        // Fields present under BASE for this summary_type. Any native field
        // beyond this set is a capability-added "extension" field (only the
        // WebSocket-disconnect family, via `ws_logging`). For BASE callers the
        // extension set is empty, so every spec is `extension: false` and the
        // per-entry-kind handling below is a no-op — identical to pre-WS.
        let base_field_names: HashSet<&'static str> =
            fields::fields_for(summary_type, SchemaCapabilities::BASE)
                .into_iter()
                .map(|f| f.name)
                .collect();

        // Native fields, omit applied, rename applied. We preserve native
        // declaration order; reordering happens below if `order` is set.
        let native_specs: Vec<FieldSpec> = fields::fields_for(summary_type, caps)
            .into_iter()
            .filter(|f| {
                // When metadata policy is Omit or Flatten, drop the native
                // metadata entry — it's handled separately by the serializer.
                if f.name == "metadata" && !matches!(metadata, MetadataPolicy::Nested) {
                    return false;
                }
                !omit.contains(&f.name.to_string())
            })
            .map(|f| {
                let out_key = rename
                    .get(f.name)
                    .cloned()
                    .unwrap_or_else(|| f.name.to_string());
                FieldSpec::Native {
                    source: f.name,
                    out_key,
                    is_timestamp: f.is_timestamp,
                    extension: !base_field_names.contains(f.name),
                }
            })
            .collect();

        let static_specs: Vec<FieldSpec> = static_fields
            .into_iter()
            .map(|(k, v)| FieldSpec::Static {
                out_key: k,
                value: v,
            })
            .collect();

        let derived_specs: Vec<FieldSpec> = derived_fields
            .into_iter()
            .map(|(name, kind)| FieldSpec::Derived {
                out_key: name,
                kind,
            })
            .collect();

        // ------------------------------------------------------------------
        // Duplicate-output-key check before reorder.
        // ------------------------------------------------------------------

        let all_specs: Vec<&FieldSpec> = native_specs
            .iter()
            .chain(static_specs.iter())
            .chain(derived_specs.iter())
            .collect();
        let mut seen: HashMap<&str, &str> = HashMap::new();
        for spec in &all_specs {
            let (out, kind) = spec_out_key_and_kind(spec);
            if let Some(prev_kind) = seen.insert(out, kind) {
                return Err(format!(
                    "{plugin_name}: duplicate output key '{out}' produced by {prev_kind} and {kind}"
                ));
            }
        }

        // ------------------------------------------------------------------
        // Apply `order` if present.
        // ------------------------------------------------------------------

        let fields = match raw.get("order") {
            Some(value) => {
                let order = parse_string_array(Some(value), plugin_name, "order")?;
                apply_order(
                    &order,
                    native_specs,
                    static_specs,
                    derived_specs,
                    plugin_name,
                )?
            }
            None => {
                // Default order: native, then static, then derived.
                let mut out = native_specs;
                out.extend(static_specs);
                out.extend(derived_specs);
                out
            }
        };

        Ok(Arc::new(SummarySchema {
            summary_type,
            fields,
            metadata,
            timestamp_format,
            capability_scoped: caps != SchemaCapabilities::BASE,
        }))
    }

    /// `true` when this schema's `summary_type` covers HTTP / gRPC /
    /// WebSocket summaries.
    pub fn applies_to_http(&self) -> bool {
        matches!(self.summary_type, SummaryType::Http | SummaryType::Both)
    }

    /// `true` when this schema's `summary_type` covers stream (TCP/UDP/DTLS)
    /// summaries.
    pub fn applies_to_stream(&self) -> bool {
        matches!(self.summary_type, SummaryType::Stream | SummaryType::Both)
    }

    /// `true` when this schema covers WebSocket disconnect entries.
    ///
    /// WebSocket upgrades belong to the HTTP / WebSocket summary family;
    /// `summary_type: stream` remains reserved for TCP/UDP/DTLS summaries.
    pub fn applies_to_websocket_disconnect(&self) -> bool {
        self.applies_to_http()
    }

    /// Look up the rename target for a native field by source name.
    /// Returns the renamed output key if the field appears in `fields` with
    /// a different out_key, or `None` if no rename applies. Used by
    /// `statsd_logging` to rename tag keys.
    pub fn rename_for_tag(&self, native: &str) -> Option<&str> {
        for spec in &self.fields {
            if let FieldSpec::Native {
                source, out_key, ..
            } = spec
                && *source == native
                && out_key != native
            {
                return Some(out_key);
            }
        }
        None
    }

    /// `true` when a native field is omitted (either via `omit` or because
    /// it's not visible for this schema's summary_type). Used by
    /// `statsd_logging` to drop tags.
    pub fn omits_tag(&self, native: &str) -> bool {
        !self
            .fields
            .iter()
            .any(|s| matches!(s, FieldSpec::Native { source, .. } if *source == native))
    }
}

fn spec_out_key_and_kind(spec: &FieldSpec) -> (&str, &'static str) {
    match spec {
        FieldSpec::Native { out_key, .. } => (out_key.as_str(), "native"),
        FieldSpec::Static { out_key, .. } => (out_key.as_str(), "static_fields"),
        FieldSpec::Derived { out_key, .. } => (out_key.as_str(), "derived_fields"),
    }
}

/// `true` when a spec is a capability-added extension field (WebSocket
/// disconnect only). Extension fields are exempt from `order` completeness so
/// an operator's exhaustive HTTP/stream `order` predating the WS field family
/// stays valid; they may still be listed to position them explicitly.
fn spec_is_extension(spec: &FieldSpec) -> bool {
    matches!(
        spec,
        FieldSpec::Native {
            extension: true,
            ..
        }
    )
}

fn unknown_field_error(
    plugin_name: &str,
    section: &str,
    name: &str,
    summary_type: SummaryType,
    caps: SchemaCapabilities,
) -> String {
    let suggestion = fields::levenshtein_suggest(summary_type, caps, name);
    match suggestion {
        Some(s) => format!(
            "{plugin_name}: schema {section} references unknown field '{name}' (did you mean '{s}'?)"
        ),
        None => format!("{plugin_name}: schema {section} references unknown field '{name}'"),
    }
}

fn parse_string_array(
    value: Option<&Value>,
    plugin_name: &str,
    key: &str,
) -> Result<Vec<String>, String> {
    let Some(v) = value else {
        return Ok(Vec::new());
    };
    let arr = v
        .as_array()
        .ok_or_else(|| format!("{plugin_name}: schema '{key}' must be an array of strings"))?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let s = entry
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: schema '{key}' entries must be strings"))?;
        if s.is_empty() {
            return Err(format!(
                "{plugin_name}: schema '{key}' entries must be non-empty"
            ));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

fn parse_string_map(
    value: Option<&Value>,
    plugin_name: &str,
    key: &str,
) -> Result<HashMap<String, String>, String> {
    let Some(v) = value else {
        return Ok(HashMap::new());
    };
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: schema '{key}' must be an object"))?;
    let mut out = HashMap::with_capacity(obj.len());
    for (k, val) in obj {
        let s = val.as_str().ok_or_else(|| {
            format!("{plugin_name}: schema '{key}' value for '{k}' must be a string")
        })?;
        out.insert(k.clone(), s.to_string());
    }
    Ok(out)
}

fn parse_static_fields(
    value: Option<&Value>,
    plugin_name: &str,
) -> Result<Vec<(String, Value)>, String> {
    let Some(v) = value else {
        return Ok(Vec::new());
    };
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: schema 'static_fields' must be an object"))?;
    let mut out = Vec::with_capacity(obj.len());
    for (k, val) in obj {
        if k.is_empty() {
            return Err(format!(
                "{plugin_name}: schema 'static_fields' keys must be non-empty"
            ));
        }
        if val.is_null() {
            return Err(format!(
                "{plugin_name}: schema 'static_fields' value for '{k}' must not be null (use 'omit' instead)"
            ));
        }
        if is_sensitive_metadata_key(k) {
            return Err(format!(
                "{plugin_name}: schema 'static_fields' key '{k}' matches a sensitive-data substring and would always be redacted; pick a different name"
            ));
        }
        // Defense in depth: walk nested structures, reject sensitive keys.
        reject_sensitive_in_value(val, plugin_name, k)?;
        out.push((k.clone(), val.clone()));
    }
    Ok(out)
}

fn reject_sensitive_in_value(value: &Value, plugin_name: &str, parent: &str) -> Result<(), String> {
    match value {
        Value::Object(obj) => {
            for (k, v) in obj {
                if is_sensitive_metadata_key(k) {
                    return Err(format!(
                        "{plugin_name}: schema 'static_fields' value for '{parent}' contains nested key '{k}' that matches a sensitive-data substring"
                    ));
                }
                reject_sensitive_in_value(v, plugin_name, parent)?;
            }
        }
        Value::Array(arr) => {
            for v in arr {
                reject_sensitive_in_value(v, plugin_name, parent)?;
            }
        }
        Value::String(s) => {
            if let Some(scheme) = detect_credential_scheme(s) {
                return Err(format!(
                    "{plugin_name}: schema 'static_fields' value for '{parent}' looks like an HTTP {scheme} credential — refusing to ship a literal token through the log pipeline; pass a placeholder or non-secret descriptor instead"
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Defense-in-depth scan for literal HTTP auth-scheme credentials pasted
/// into a `static_fields` value.
///
/// Detection rule: the value (after trimming leading whitespace) must
///   1. start with one of the recognized HTTP auth-scheme tokens
///      (case-insensitive),
///   2. be followed by ASCII whitespace,
///   3. and then either
///      - a single non-whitespace credential token (`Bearer eyJ...`,
///        `Basic dXNlcjp...`, `NTLM TlRMTV...`), or
///      - a `key=value` parameter list (`Digest username="..."`,
///        `AWS4-HMAC-SHA256 Credential=...`).
///
/// Prose that happens to contain a scheme name plus a multi-word
/// continuation passes through (`"bearer of bad news"`,
/// `"We use Basic Auth internally"`, `"escalate to digest auth later"`)
/// because the post-scheme content has internal whitespace AND no
/// `key=value` opener.
///
/// Schemes covered are the IANA-registered HTTP Authentication schemes
/// most likely to be copy-pasted from a request log: `Basic`, `Bearer`,
/// `Digest`, `Negotiate`, `NTLM`, `Hoba`, `Mutual`, `SCRAM-SHA-1`,
/// `SCRAM-SHA-256`, `Vapid`, plus AWS SigV4 (`AWS4-HMAC-SHA256`).
fn detect_credential_scheme(value: &str) -> Option<&'static str> {
    const SCHEMES: &[(&str, &str)] = &[
        ("basic", "Basic"),
        ("bearer", "Bearer"),
        ("digest", "Digest"),
        ("negotiate", "Negotiate"),
        ("ntlm", "NTLM"),
        ("hoba", "HOBA"),
        ("mutual", "Mutual"),
        ("scram-sha-1", "SCRAM-SHA-1"),
        ("scram-sha-256", "SCRAM-SHA-256"),
        ("vapid", "vapid"),
        ("aws4-hmac-sha256", "AWS4-HMAC-SHA256"),
    ];
    let trimmed = value.trim_start();
    let bytes = trimmed.as_bytes();
    for (scheme, label) in SCHEMES {
        if bytes.len() <= scheme.len() {
            continue;
        }
        if !bytes[..scheme.len()].eq_ignore_ascii_case(scheme.as_bytes()) {
            continue;
        }
        // Safe to slice at `scheme.len()`: the ASCII-equal-ignoring-case
        // check above guarantees those bytes are ASCII, so the index is
        // on a UTF-8 char boundary.
        let rest = &trimmed[scheme.len()..];
        // Scheme must be followed by RFC 7230 OWS — space or HTAB only.
        // CR/LF/FF cannot legally appear in a header value, and rejecting
        // them keeps the prose-vs-credential distinction crisp.
        let next = rest.chars().next();
        if !matches!(next, Some(' ' | '\t')) {
            continue;
        }
        // Strip surrounding whitespace and require a non-empty payload.
        let payload = rest.trim();
        if payload.is_empty() {
            continue;
        }
        // Pattern A: single non-whitespace credential token.
        if !payload.chars().any(char::is_whitespace) {
            return Some(label);
        }
        // Pattern B: `key=value` opener (Digest, AWS4 SigV4 style).
        // HTTP auth-param allows bad whitespace around "=", so accept
        // `key = value` too while still requiring the key itself to be
        // identifier-shaped.
        if let Some(eq_idx) = payload.find('=') {
            let key = payload[..eq_idx].trim_matches(|c| matches!(c, ' ' | '\t'));
            if !key.is_empty()
                && !key.chars().any(char::is_whitespace)
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Some(label);
            }
        }
        // Multi-word continuation without a key=value opener — prose.
    }
    None
}

fn parse_derived_fields(
    value: Option<&Value>,
    plugin_name: &str,
) -> Result<Vec<(String, DerivedKind)>, String> {
    let Some(v) = value else {
        return Ok(Vec::new());
    };
    let arr = v
        .as_array()
        .ok_or_else(|| format!("{plugin_name}: schema 'derived_fields' must be an array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (index, entry) in arr.iter().enumerate() {
        let obj = entry.as_object().ok_or_else(|| {
            format!("{plugin_name}: schema 'derived_fields[{index}]' entry must be an object")
        })?;
        for key in obj.keys() {
            if !DERIVED_FIELD_KEYS.contains(&key.as_str()) {
                return Err(format!(
                    "{plugin_name}: unknown schema key 'derived_fields[{index}].{key}' (valid entry keys: {})",
                    DERIVED_FIELD_KEYS.join(", ")
                ));
            }
        }
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                format!(
                    "{plugin_name}: schema 'derived_fields[{index}]' entry missing non-empty 'name'"
                )
            })?;
        let kind_str = obj.get("kind").and_then(Value::as_str).ok_or_else(|| {
            format!("{plugin_name}: schema 'derived_fields[{index}]' entry '{name}' missing 'kind'")
        })?;
        let kind = DerivedKind::parse(kind_str)?;
        if is_sensitive_metadata_key(name) {
            return Err(format!(
                "{plugin_name}: schema 'derived_fields' name '{name}' matches a sensitive-data substring and would always be redacted; pick a different name"
            ));
        }
        out.push((name.to_string(), kind));
    }
    Ok(out)
}

fn parse_metadata_policy(
    value: Option<&Value>,
    plugin_name: &str,
) -> Result<MetadataPolicy, String> {
    let Some(v) = value else {
        return Ok(MetadataPolicy::default());
    };
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: schema 'metadata' must be an object"))?;
    for key in obj.keys() {
        if !METADATA_POLICY_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "{plugin_name}: unknown schema key 'metadata.{key}' (valid metadata keys: {})",
                METADATA_POLICY_KEYS.join(", ")
            ));
        }
    }
    let mode = match obj.get("mode") {
        Some(Value::String(mode)) => mode.as_str(),
        None => "nested",
        Some(_) => {
            return Err(format!(
                "{plugin_name}: schema 'metadata.mode' must be a string"
            ));
        }
    };
    match mode {
        "nested" => Ok(MetadataPolicy::Nested),
        "omit" => Ok(MetadataPolicy::Omit),
        "flatten" => {
            let prefix = match obj.get("prefix") {
                Some(Value::String(s)) if s.is_empty() => None,
                Some(Value::String(s)) => {
                    if s.chars().any(|c| c.is_control()) {
                        return Err(format!(
                            "{plugin_name}: schema 'metadata.prefix' must not contain control characters"
                        ));
                    }
                    Some(s.clone())
                }
                None => None,
                Some(_) => {
                    return Err(format!(
                        "{plugin_name}: schema 'metadata.prefix' must be a string"
                    ));
                }
            };
            let on_collision = match obj.get("on_collision") {
                Some(Value::String(s)) => match s.as_str() {
                    "skip" => CollisionMode::Skip,
                    "overwrite" => CollisionMode::Overwrite,
                    other => {
                        return Err(format!(
                            "{plugin_name}: schema 'metadata.on_collision' must be 'skip' or 'overwrite' (got '{other}')"
                        ));
                    }
                },
                None => CollisionMode::default(),
                Some(_) => {
                    return Err(format!(
                        "{plugin_name}: schema 'metadata.on_collision' must be a string"
                    ));
                }
            };
            Ok(MetadataPolicy::Flatten {
                prefix,
                on_collision,
            })
        }
        other => Err(format!(
            "{plugin_name}: schema 'metadata.mode' must be 'nested', 'omit', or 'flatten' (got '{other}')"
        )),
    }
}

/// Reorder the unordered field set according to operator-supplied `order`.
///
/// `*` is a wildcard that expands inline to all unlisted entries (native +
/// static + derived) in their natural order. Without `*`, every entry must
/// be listed explicitly or compilation fails.
fn apply_order(
    order: &[String],
    native: Vec<FieldSpec>,
    statics: Vec<FieldSpec>,
    derived: Vec<FieldSpec>,
    plugin_name: &str,
) -> Result<Vec<FieldSpec>, String> {
    // Combine, preserving natural insertion order.
    let mut all: Vec<FieldSpec> = native;
    all.extend(statics);
    all.extend(derived);

    // Build name → index lookup.
    let mut index: HashMap<String, usize> = HashMap::with_capacity(all.len());
    for (i, spec) in all.iter().enumerate() {
        index.insert(spec_out_key_and_kind(spec).0.to_string(), i);
    }

    // Validate order entries.
    let mut listed: Vec<bool> = vec![false; all.len()];
    let mut output_indices: Vec<Option<usize>> = Vec::with_capacity(order.len());
    let mut wildcard_seen = false;
    for entry in order {
        if entry == "*" {
            if wildcard_seen {
                return Err(format!(
                    "{plugin_name}: schema 'order' may only contain '*' once"
                ));
            }
            wildcard_seen = true;
            output_indices.push(None);
            continue;
        }
        let idx = index.get(entry).ok_or_else(|| {
            format!(
                "{plugin_name}: schema 'order' references unknown output key '{entry}' (must match a renamed/native/static/derived out_key, or use '*')"
            )
        })?;
        if listed[*idx] {
            return Err(format!(
                "{plugin_name}: schema 'order' lists '{entry}' more than once"
            ));
        }
        listed[*idx] = true;
        output_indices.push(Some(*idx));
    }

    if !wildcard_seen {
        // Completeness is evaluated per entry kind: extension (WebSocket
        // disconnect-only) fields may be unlisted without `*` — they never
        // serialize on ordinary HTTP/stream entries and are appended for the
        // WS-disconnect entry below. Base fields must still all be listed.
        let missing: Vec<&str> = all
            .iter()
            .zip(listed.iter())
            .filter(|(spec, l)| !**l && !spec_is_extension(spec))
            .map(|(spec, _)| spec_out_key_and_kind(spec).0)
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "{plugin_name}: schema 'order' missing entries: {} (add them, or use '*' to catch the rest)",
                missing.join(", ")
            ));
        }
    }

    // Build final ordered vec. To allow ownership transfer from `all`,
    // we move into `Option<FieldSpec>` slots. The `listed` bitmap is the
    // authoritative "explicitly placed elsewhere" signal — wildcard
    // expansion must consult it rather than relying on `slot.is_some()`,
    // because listed entries appearing AFTER the wildcard are still
    // un-taken when the wildcard iteration runs.
    let mut slots: Vec<Option<FieldSpec>> = all.into_iter().map(Some).collect();
    let mut out: Vec<FieldSpec> = Vec::with_capacity(slots.len());
    for entry in output_indices {
        match entry {
            Some(i) => {
                out.push(slots[i].take().expect("listed index moved twice"));
            }
            None => {
                // Wildcard — append entries that are neither explicitly
                // listed (handled by their own Some(i) iteration) nor
                // already taken.
                for (i, slot) in slots.iter_mut().enumerate() {
                    if listed[i] {
                        continue;
                    }
                    if let Some(spec) = slot.take() {
                        out.push(spec);
                    }
                }
            }
        }
    }

    // Without an explicit `*`, base fields were all required above, so the
    // only remaining unlisted slots are exempt extension (WS-disconnect)
    // fields. Append them in natural order so the WS entry still emits them
    // even when the operator's `order` predates the WS field family. For BASE
    // callers there are no extension fields, so this loop is a no-op.
    if !wildcard_seen {
        for (i, slot) in slots.iter_mut().enumerate() {
            if listed[i] {
                continue;
            }
            if let Some(spec) = slot.take() {
                out.push(spec);
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Plugin-facing helper: resolve a schema from plugin config.
// ---------------------------------------------------------------------------

/// Read either inline `schema` or `schema_ref` from a plugin config object
/// and return the compiled schema. Returns `Ok(None)` when neither key is
/// present.
///
/// `caps` is honored for BOTH an inline `schema` and a `schema_ref` (see
/// [`SummarySchema::compile`]). A named schema is authored generically and
/// registered under [`SchemaCapabilities::BASE`], so it can never reference
/// ws-only field names; but when a capability-bearing caller (`ws_logging`)
/// resolves it, the named schema's raw definition is recompiled under that
/// caller's capability so `schema_ref` reaches parity with an inline schema —
/// the WebSocket-disconnect field family applies to disconnect entries rather
/// than being silently dropped. BASE callers keep sharing the single
/// registered `Arc`, so non-`ws_logging` plugins are unaffected.
///
/// Errors:
/// - Both `schema` and `schema_ref` present.
/// - `schema_ref` is not a string, or points to a name not registered.
/// - Inline `schema` fails to compile (rules in [`SummarySchema::compile`]).
/// - A `schema_ref` recompiled under a non-BASE capability collides (e.g. a
///   `static_fields` key that becomes a reserved native name under `caps`) —
///   the same error an equivalent inline schema would raise.
pub fn resolve_schema(
    config: &Value,
    plugin_name: &str,
    caps: SchemaCapabilities,
) -> Result<Option<Arc<SummarySchema>>, String> {
    let inline = config.get("schema");
    let by_ref = config.get("schema_ref");

    if inline.is_some() && by_ref.is_some() {
        return Err(format!(
            "{plugin_name}: 'schema' and 'schema_ref' are mutually exclusive"
        ));
    }

    if let Some(name) = by_ref {
        let name = name
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: 'schema_ref' must be a string"))?;
        // BASE callers share the single compiled `Arc` registered by
        // `transaction_log_schema` — zero recompile, identical to before.
        if caps == SchemaCapabilities::BASE {
            return registry::lookup_named(name).map(Some).ok_or_else(|| {
                format!(
                    "{plugin_name}: 'schema_ref' references unknown schema '{name}' (define it in a 'transaction_log_schema' plugin)"
                )
            });
        }
        // Capability-bearing caller (`ws_logging`): recompile the named
        // schema's raw definition under this capability so disconnect fields
        // apply. Recompilation happens once at plugin construction, not on the
        // hot path.
        let raw = registry::lookup_named_raw(name).ok_or_else(|| {
            format!(
                "{plugin_name}: 'schema_ref' references unknown schema '{name}' (define it in a 'transaction_log_schema' plugin)"
            )
        })?;
        return SummarySchema::compile(&raw, plugin_name, caps).map(Some);
    }

    if let Some(inline) = inline {
        return SummarySchema::compile(inline, plugin_name, caps).map(Some);
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // The default helpers exercise the shared compiler in its base form —
    // exactly what every non-WebSocket logging plugin gets.
    fn ok(raw: Value) -> Arc<SummarySchema> {
        SummarySchema::compile(&raw, "test", SchemaCapabilities::BASE).expect("compile succeeded")
    }

    fn err(raw: Value) -> String {
        SummarySchema::compile(&raw, "test", SchemaCapabilities::BASE)
            .expect_err("expected compile error")
    }

    // WebSocket-capability helpers exercise the `ws_logging` opt-in.
    fn ok_ws(raw: Value) -> Arc<SummarySchema> {
        SummarySchema::compile(&raw, "test", SchemaCapabilities::WS_LOGGING)
            .expect("compile succeeded")
    }

    fn err_ws(raw: Value) -> String {
        SummarySchema::compile(&raw, "test", SchemaCapabilities::WS_LOGGING)
            .expect_err("expected compile error")
    }

    #[test]
    fn empty_schema_compiles_to_native_defaults() {
        let s = ok(json!({}));
        assert_eq!(s.summary_type, SummaryType::Both);
        assert!(matches!(s.metadata, MetadataPolicy::Nested));
        assert_eq!(s.timestamp_format, TimestampFormat::Rfc3339);
        // Should have native fields from both, deduped.
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "namespace",
                ..
            }
        )));
    }

    #[test]
    fn rename_changes_out_key() {
        let s = ok(json!({
            "summary_type": "http",
            "rename": { "proxy_id": "route_id" }
        }));
        let proxy = s
            .fields
            .iter()
            .find_map(|f| match f {
                FieldSpec::Native {
                    source: "proxy_id",
                    out_key,
                    ..
                } => Some(out_key.clone()),
                _ => None,
            })
            .expect("proxy_id present");
        assert_eq!(proxy, "route_id");
    }

    #[test]
    fn omit_drops_field() {
        let s = ok(json!({
            "summary_type": "http",
            "omit": ["latency_plugin_external_io_ms"]
        }));
        assert!(!s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "latency_plugin_external_io_ms",
                ..
            }
        )));
    }

    #[test]
    fn unknown_field_in_omit_rejected() {
        let e = err(json!({ "omit": ["typo"] }));
        assert!(e.contains("unknown field 'typo'"), "got: {e}");
    }

    #[test]
    fn unknown_field_offers_suggestion() {
        let e = err(json!({ "omit": ["proxy_idd"] }));
        assert!(e.contains("did you mean 'proxy_id'"), "got: {e}");
    }

    #[test]
    fn omit_and_rename_collision_rejected() {
        let e = err(json!({
            "omit": ["proxy_id"],
            "rename": { "proxy_id": "route_id" }
        }));
        assert!(e.contains("both omitted and renamed"), "got: {e}");
    }

    #[test]
    fn duplicate_output_key_rejected() {
        let e = err(json!({
            "rename": { "proxy_id": "namespace" }
        }));
        assert!(e.contains("duplicate output key 'namespace'"), "got: {e}");
    }

    #[test]
    fn http_schema_rejects_stream_only_field() {
        // `protocol` lives on the stream (and ws-disconnect) families but
        // not on the base HTTP registry. Without the ws capability a shared
        // caller's http schema must still reject it, exactly as on main.
        let e = err(json!({
            "summary_type": "http",
            "omit": ["protocol"]
        }));
        assert!(e.contains("unknown field 'protocol'"), "got: {e}");
    }

    #[test]
    fn http_schema_rejects_ws_only_field_without_capability() {
        // Every non-ws logging plugin (http_logging, kafka_logging, …)
        // compiles under BASE; ws-only names stay unknown.
        for field in [
            "event",
            "frames_client_to_backend",
            "frames_backend_to_client",
            "direction",
            "io_side",
        ] {
            let e = err(json!({
                "summary_type": "http",
                "omit": [field],
            }));
            assert!(e.contains(&format!("unknown field '{field}'")), "got: {e}");
        }
    }

    #[test]
    fn non_ws_http_schema_allows_event_static_field_and_flatten() {
        // Regression for the Codex finding: because `event` is a ws-only
        // field, folding the WS family into every http schema would reserve
        // `event` as a native output key and collide with a static field
        // (and with a flattened `event` metadata key). Under BASE there is
        // no such native key, so both compile cleanly — matching main.
        let s = ok(json!({
            "summary_type": "http",
            "static_fields": { "event": "access" },
            "metadata": { "mode": "flatten" },
        }));
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Static { out_key, .. } if out_key == "event"
        )));
        // No native `event` spec is present to collide with.
        assert!(!s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "event",
                ..
            }
        )));
    }

    #[test]
    fn ws_capability_accepts_ws_disconnect_fields() {
        // ws_logging opts into the WebSocket-disconnect family, so ws-only
        // names are valid in omit / rename / order and reserve output keys.
        let s = ok_ws(json!({
            "summary_type": "http",
            "rename": { "event": "kind", "frames_client_to_backend": "up_frames" },
            "omit": ["frames_backend_to_client"],
        }));
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native { source: "event", out_key, .. } if out_key == "kind"
        )));
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native { source: "frames_client_to_backend", out_key, .. }
                if out_key == "up_frames"
        )));
        assert!(!s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "frames_backend_to_client",
                ..
            }
        )));
    }

    #[test]
    fn ws_capability_reserves_event_key_and_collides_with_static() {
        // Under the ws capability `event` IS a native output key, so a
        // colliding static field is correctly rejected — the mirror of the
        // BASE behavior above.
        let e = err_ws(json!({
            "summary_type": "http",
            "static_fields": { "event": "access" },
        }));
        assert!(e.contains("duplicate output key 'event'"), "got: {e}");
    }

    #[test]
    fn ws_capability_scoped_to_http_family_not_stream() {
        // Even with the capability, WS fields never bleed into a stream
        // schema.
        let e = err_ws(json!({
            "summary_type": "stream",
            "omit": ["frames_client_to_backend"],
        }));
        assert!(
            e.contains("unknown field 'frames_client_to_backend'"),
            "got: {e}"
        );
    }

    #[test]
    fn ws_http_exhaustive_order_stays_valid_without_wildcard() {
        // Regression for the Codex finding: an existing `ws_logging` schema
        // whose `order` exhaustively lists the pre-WS HTTP fields (no `*`)
        // must still compile once the native set grew to include the
        // WebSocket-disconnect family. WS-only fields are exempt from
        // completeness and appended after the listed keys.
        let order: Vec<String> = fields::HTTP_FIELDS
            .iter()
            .map(|f| f.name.to_string())
            .collect();
        let s = ok_ws(json!({
            "summary_type": "http",
            "order": order,
        }));
        // Every listed HTTP key keeps its position at the front.
        for (i, f) in fields::HTTP_FIELDS.iter().enumerate() {
            assert!(
                matches!(&s.fields[i], FieldSpec::Native { source, .. } if *source == f.name),
                "HTTP field '{}' out of position at index {i}",
                f.name
            );
        }
        // WS-only fields were appended (not required, but still emitted for
        // the disconnect entry).
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "event",
                ..
            }
        )));
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "frames_client_to_backend",
                ..
            }
        )));
    }

    #[test]
    fn base_exhaustive_http_order_still_requires_every_field() {
        // BASE is unchanged: with no `*`, omitting even one HTTP field is an
        // error (there are no exempt extension fields under BASE).
        let mut order: Vec<String> = fields::HTTP_FIELDS
            .iter()
            .map(|f| f.name.to_string())
            .collect();
        order.pop(); // drop the last field
        let e = SummarySchema::compile(
            &json!({ "summary_type": "http", "order": order }),
            "http_logging",
            SchemaCapabilities::BASE,
        )
        .expect_err("incomplete order should fail under BASE");
        assert!(e.contains("missing entries"), "got: {e}");
    }

    #[test]
    fn resolve_schema_ref_honors_ws_capability() {
        // schema_ref parity: a portable named schema loses its WebSocket
        // disconnect fields under BASE but regains them when `ws_logging`
        // resolves it under the WS capability, while the portable rename
        // still applies. BASE callers see the exact registered schema.
        let _g = registry::lock_for_tests();
        registry::reset_for_tests();
        registry::begin_reload().expect("reload bracket opens");
        let raw = json!({ "summary_type": "http", "rename": { "proxy_id": "route_id" } });
        let compiled = SummarySchema::compile(
            &raw,
            "transaction_log_schema[portable]",
            SchemaCapabilities::BASE,
        )
        .expect("named schema compiles");
        registry::register_named("portable", Arc::new(raw), compiled)
            .expect("register named schema");
        registry::commit_reload().expect("reload bracket commits");

        let cfg = json!({ "schema_ref": "portable" });
        let base = resolve_schema(&cfg, "http_logging", SchemaCapabilities::BASE)
            .expect("base resolve ok")
            .expect("schema present");
        let ws = resolve_schema(&cfg, "ws_logging", SchemaCapabilities::WS_LOGGING)
            .expect("ws resolve ok")
            .expect("schema present");

        // BASE resolution carries no WebSocket-disconnect native field.
        assert!(!base.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "event",
                ..
            }
        )));
        // WS resolution DOES — disconnect fields are no longer silently
        // dropped for schema_ref users.
        assert!(ws.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "event",
                ..
            }
        )));
        assert!(ws.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "frames_client_to_backend",
                ..
            }
        )));
        // The portable rename applies under both capabilities.
        for schema in [&base, &ws] {
            assert!(schema.fields.iter().any(|f| matches!(
                f,
                FieldSpec::Native { source: "proxy_id", out_key, .. } if out_key == "route_id"
            )));
        }
    }

    #[test]
    fn resolve_schema_ref_static_field_colliding_with_ws_native_rejected_for_ws() {
        // A portable schema whose `static_fields` uses a name that is only a
        // reserved native field under the WS capability compiles for BASE
        // callers but is rejected for `ws_logging` — identical to the
        // equivalent inline schema's collision error.
        let _g = registry::lock_for_tests();
        registry::reset_for_tests();
        registry::begin_reload().expect("reload bracket opens");
        let raw = json!({ "summary_type": "http", "static_fields": { "event": "access" } });
        let compiled = SummarySchema::compile(
            &raw,
            "transaction_log_schema[with_event]",
            SchemaCapabilities::BASE,
        )
        .expect("named schema compiles under BASE");
        registry::register_named("with_event", Arc::new(raw), compiled)
            .expect("register named schema");
        registry::commit_reload().expect("reload bracket commits");

        let cfg = json!({ "schema_ref": "with_event" });
        assert!(resolve_schema(&cfg, "http_logging", SchemaCapabilities::BASE).is_ok());
        let e = resolve_schema(&cfg, "ws_logging", SchemaCapabilities::WS_LOGGING)
            .expect_err("ws recompile collides on reserved 'event'");
        assert!(e.contains("duplicate output key 'event'"), "got: {e}");
    }

    #[test]
    fn stream_schema_rejects_http_only_field() {
        let e = err(json!({
            "summary_type": "stream",
            "rename": { "request_path": "path" }
        }));
        assert!(e.contains("unknown field 'request_path'"), "got: {e}");
    }

    #[test]
    fn both_schema_accepts_either_field() {
        ok(json!({
            "summary_type": "both",
            "omit": ["bytes_sent", "request_path"]
        }));
    }

    #[test]
    fn order_with_wildcard_positions_listed_keys() {
        let s = ok(json!({
            "summary_type": "http",
            "order": ["timestamp_received", "response_status_code", "*"]
        }));
        assert!(matches!(
            &s.fields[0],
            FieldSpec::Native {
                source: "timestamp_received",
                ..
            }
        ));
        assert!(matches!(
            &s.fields[1],
            FieldSpec::Native {
                source: "response_status_code",
                ..
            }
        ));
    }

    #[test]
    fn order_with_wildcard_followed_by_listed_keys() {
        // Regression for a bug where wildcard expansion consumed every
        // still-Some slot, including entries explicitly listed AFTER `*`,
        // causing the next listed-index `.take()` to panic.
        let s = ok(json!({
            "summary_type": "http",
            "order": ["namespace", "*", "response_status_code"]
        }));
        // First key must be the explicitly-placed leading entry.
        assert!(matches!(
            &s.fields[0],
            FieldSpec::Native {
                source: "namespace",
                ..
            }
        ));
        // Last key must be the explicitly-placed trailing entry.
        assert!(matches!(
            s.fields.last(),
            Some(FieldSpec::Native {
                source: "response_status_code",
                ..
            })
        ));
        // The wildcard span must not include either pinned entry — they
        // appear exactly once at their pinned positions.
        let ns_count = s
            .fields
            .iter()
            .filter(|f| {
                matches!(
                    f,
                    FieldSpec::Native {
                        source: "namespace",
                        ..
                    }
                )
            })
            .count();
        let status_count = s
            .fields
            .iter()
            .filter(|f| {
                matches!(
                    f,
                    FieldSpec::Native {
                        source: "response_status_code",
                        ..
                    }
                )
            })
            .count();
        assert_eq!(ns_count, 1, "namespace appears exactly once");
        assert_eq!(status_count, 1, "response_status_code appears exactly once");
        // And the schema must still cover every native HTTP / WebSocket field.
        assert_eq!(
            s.fields.len(),
            fields::fields_for(SummaryType::Http, SchemaCapabilities::BASE).len()
        );
    }

    #[test]
    fn order_without_wildcard_must_be_complete() {
        let e = err(json!({
            "summary_type": "http",
            "order": ["namespace", "client_ip"]
        }));
        assert!(e.contains("missing entries"), "got: {e}");
    }

    #[test]
    fn order_duplicate_entry_rejected() {
        let e = err(json!({
            "order": ["namespace", "namespace", "*"]
        }));
        assert!(e.contains("more than once"), "got: {e}");
    }

    #[test]
    fn order_unknown_key_rejected() {
        let e = err(json!({
            "order": ["not_a_field", "*"]
        }));
        assert!(e.contains("unknown output key 'not_a_field'"), "got: {e}");
    }

    #[test]
    fn order_with_two_wildcards_rejected() {
        let e = err(json!({
            "order": ["*", "*"]
        }));
        assert!(e.contains("'*' once"), "got: {e}");
    }

    #[test]
    fn static_field_sensitive_name_rejected() {
        let e = err(json!({
            "static_fields": { "x_authorization_copy": "redacted-please" }
        }));
        assert!(e.contains("matches a sensitive-data substring"), "got: {e}");
    }

    #[test]
    fn rename_target_sensitive_name_rejected() {
        let e = err(json!({
            "summary_type": "http",
            "rename": { "proxy_id": "x-auth-token" }
        }));
        assert!(e.contains("matches a sensitive-data substring"), "got: {e}");
    }

    #[test]
    fn static_field_nested_sensitive_rejected() {
        let e = err(json!({
            "static_fields": { "audit": { "authorization": "secret" } }
        }));
        assert!(e.contains("contains nested key"), "got: {e}");
    }

    #[test]
    fn static_field_null_rejected() {
        let e = err(json!({
            "static_fields": { "drop_me": null }
        }));
        assert!(e.contains("must not be null"), "got: {e}");
    }

    #[test]
    fn derived_field_unknown_kind_rejected() {
        let e = err(json!({
            "derived_fields": [{ "name": "x", "kind": "not_a_kind" }]
        }));
        assert!(e.contains("unknown derived kind"), "got: {e}");
    }

    #[test]
    fn derived_field_compiles() {
        let s = ok(json!({
            "summary_type": "http",
            "derived_fields": [
                { "name": "status_class", "kind": "status_class" },
                { "name": "outcome", "kind": "outcome" }
            ]
        }));
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Derived {
                kind: DerivedKind::StatusClass,
                ..
            }
        )));
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Derived {
                kind: DerivedKind::Outcome,
                ..
            }
        )));
    }

    #[test]
    fn metadata_flatten_with_prefix() {
        let s = ok(json!({
            "metadata": {
                "mode": "flatten",
                "prefix": "meta_",
                "on_collision": "overwrite"
            }
        }));
        let MetadataPolicy::Flatten {
            prefix,
            on_collision,
        } = &s.metadata
        else {
            panic!("expected Flatten");
        };
        assert_eq!(prefix.as_deref(), Some("meta_"));
        assert_eq!(*on_collision, CollisionMode::Overwrite);
    }

    #[test]
    fn metadata_flatten_empty_prefix_treated_as_none() {
        let s = ok(json!({
            "metadata": { "mode": "flatten", "prefix": "" }
        }));
        let MetadataPolicy::Flatten { prefix, .. } = &s.metadata else {
            panic!("expected Flatten");
        };
        assert!(prefix.is_none());
    }

    #[test]
    fn metadata_flatten_prefix_control_char_rejected() {
        let e = err(json!({
            "metadata": { "mode": "flatten", "prefix": "x\n" }
        }));
        assert!(e.contains("control characters"), "got: {e}");
    }

    #[test]
    fn unknown_top_level_key_rejected() {
        let e = err(json!({ "renaime": { "x": "y" } }));
        assert!(e.contains("unknown schema key 'renaime'"), "got: {e}");
    }

    #[test]
    fn timestamp_format_parsed() {
        let s = ok(json!({ "timestamp_format": "epoch_ms" }));
        assert_eq!(s.timestamp_format, TimestampFormat::EpochMs);
        let s = ok(json!({ "timestamp_format": "epoch_s" }));
        assert_eq!(s.timestamp_format, TimestampFormat::EpochS);
    }

    #[test]
    fn rename_for_tag_returns_renamed() {
        let s = ok(json!({
            "summary_type": "http",
            "rename": { "proxy_id": "route_id" }
        }));
        assert_eq!(s.rename_for_tag("proxy_id"), Some("route_id"));
        assert_eq!(s.rename_for_tag("namespace"), None);
    }

    #[test]
    fn omits_tag_detects_omission() {
        let s = ok(json!({
            "summary_type": "http",
            "omit": ["proxy_name"]
        }));
        assert!(s.omits_tag("proxy_name"));
        assert!(!s.omits_tag("proxy_id"));
    }

    #[test]
    fn resolve_schema_inline() {
        let cfg = json!({ "schema": { "summary_type": "http" } });
        let r = resolve_schema(&cfg, "test", SchemaCapabilities::BASE).unwrap();
        assert!(r.is_some());
    }

    #[test]
    fn resolve_schema_none_when_absent() {
        let cfg = json!({ "other": "field" });
        let r = resolve_schema(&cfg, "test", SchemaCapabilities::BASE).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn resolve_schema_both_present_rejected() {
        let cfg = json!({ "schema": {}, "schema_ref": "x" });
        let r = resolve_schema(&cfg, "test", SchemaCapabilities::BASE);
        assert!(r.is_err());
    }

    #[test]
    fn resolve_schema_inline_ws_capability_accepts_ws_fields() {
        // ws_logging resolves inline schemas with the WS capability, so a
        // ws-only rename compiles here but would fail under BASE.
        let cfg = json!({ "schema": { "summary_type": "http", "rename": { "event": "kind" } } });
        assert!(resolve_schema(&cfg, "ws_logging", SchemaCapabilities::WS_LOGGING).is_ok());
        assert!(resolve_schema(&cfg, "http_logging", SchemaCapabilities::BASE).is_err());
    }

    #[test]
    fn static_fields_string_value_with_bearer_token_rejected() {
        let e = err(json!({
            "static_fields": { "audit_note": "Bearer eyJhbGciOiJIUzI1NiJ9.xxx.yyy" }
        }));
        assert!(
            e.contains("looks like an HTTP Bearer credential"),
            "got: {e}"
        );
    }

    #[test]
    fn static_fields_string_value_with_basic_auth_rejected() {
        let e = err(json!({
            "static_fields": { "note": "Basic dXNlcjpwYXNz" }
        }));
        assert!(
            e.contains("looks like an HTTP Basic credential"),
            "got: {e}"
        );
    }

    #[test]
    fn static_fields_string_value_with_aws_sigv4_rejected() {
        let e = err(json!({
            "static_fields": { "note": "AWS4-HMAC-SHA256 Credential=AKIA.../..." }
        }));
        assert!(e.contains("AWS4-HMAC-SHA256"), "got: {e}");
    }

    #[test]
    fn static_fields_string_value_case_insensitive_rejected() {
        let e = err(json!({
            "static_fields": { "note": "bearer abc" }
        }));
        assert!(
            e.contains("looks like an HTTP Bearer credential"),
            "got: {e}"
        );
    }

    #[test]
    fn static_fields_nested_string_value_with_credential_rejected() {
        // Nested under an array — must still be caught.
        let e = err(json!({
            "static_fields": {
                "notes": ["normal text", "Bearer leaked-secret"]
            }
        }));
        assert!(
            e.contains("looks like an HTTP Bearer credential"),
            "got: {e}"
        );
    }

    #[test]
    fn static_fields_prose_mentioning_scheme_names_accepted() {
        // The scheme keyword on its own (no whitespace + token after) is fine —
        // operators describing auth strategies should not be rejected.
        ok(json!({
            "static_fields": {
                "auth_strategy": "We use bearer tokens internally",
                "phrase": "bearer of bad news",
                "config": "escalate to digest auth later"
            }
        }));
    }

    #[test]
    fn static_fields_short_value_starting_with_scheme_accepted() {
        // "Bearer" alone (no following credential) is not flagged.
        ok(json!({
            "static_fields": {
                "label": "Bearer"
            }
        }));
    }

    #[test]
    fn detect_credential_scheme_single_token() {
        // Direct unit tests on the helper — single-token credential payload.
        assert!(detect_credential_scheme("Bearer ").is_none());
        assert!(detect_credential_scheme("Bearer  ").is_none()); // only whitespace after
        assert_eq!(detect_credential_scheme("Bearer x"), Some("Bearer"));
        assert_eq!(detect_credential_scheme("Bearer x "), Some("Bearer"));
        assert_eq!(detect_credential_scheme("Basic dXNlcg==\t"), Some("Basic"));
        assert_eq!(detect_credential_scheme("  bearer  abc"), Some("Bearer"));
        assert!(detect_credential_scheme("bearerof").is_none()); // no whitespace separator
        assert_eq!(detect_credential_scheme("Basic dXNlcg=="), Some("Basic"));
    }

    #[test]
    fn detect_credential_scheme_multi_word_prose_passes() {
        // Multi-word continuation without key=value is prose, not a credential.
        assert!(detect_credential_scheme("bearer of bad news").is_none());
        assert!(detect_credential_scheme("Bearer Token Authentication").is_none());
        assert!(detect_credential_scheme("Basic auth is enabled").is_none());
        assert!(detect_credential_scheme("escalate to digest auth later").is_none());
    }

    #[test]
    fn detect_credential_scheme_key_value_pattern() {
        // Digest / AWS4 SigV4 carry comma-separated key=value pairs that
        // contain internal whitespace; the key=value opener marks them as
        // credentials.
        assert_eq!(
            detect_credential_scheme("Digest username=\"foo\", realm=\"bar\""),
            Some("Digest")
        );
        assert_eq!(
            detect_credential_scheme("Digest username = \"foo\", realm = \"bar\""),
            Some("Digest")
        );
        assert_eq!(
            detect_credential_scheme(
                "AWS4-HMAC-SHA256 Credential=AKIA.../foo, SignedHeaders=host, Signature=abc123"
            ),
            Some("AWS4-HMAC-SHA256")
        );
        // No `=` opener → still treated as prose even with multi-word.
        assert!(detect_credential_scheme("Digest auth is configured").is_none());
    }
}
