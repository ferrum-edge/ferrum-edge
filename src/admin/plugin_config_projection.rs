//! Schema-aware sensitivity contract for plugin-configuration projections.
//!
//! This module owns the single redacted projection that every non-admin plugin
//! read, every management audit record, and every diagnostic rendering of a
//! plugin `config` blob must go through. It replaces the previous
//! field-name-substring heuristic as the *primary* authority: a per-plugin
//! schema declares exactly which config paths carry credentials, so a vendor
//! header name like `x-honeycomb-team`, an escape-hatch librdkafka property, or
//! a credential embedded in an endpoint URL is classified by *position in the
//! schema* rather than by whether its name happens to contain `secret`.
//!
//! # Layering
//!
//! Projection is strictly additive and never *reveals* anything that a previous
//! layer redacted:
//!
//! 1. **Schema rules** ([`PLUGIN_SENSITIVITY_SCHEMAS`]) — exact, per-plugin
//!    paths with `*` wildcards for arbitrary maps/arrays.
//! 2. **Name heuristics** ([`is_sensitive_plugin_config_key`]) — the historical
//!    substring matcher, retained as a floor. It still covers custom plugins
//!    (which have no built-in schema) and any built-in field that a future edit
//!    adds before its schema entry catches up.
//! 3. **Structural URL sweep** ([`strip_url_userinfo_in_place`]) — any remaining
//!    string anywhere in the tree that parses as a URL carrying userinfo has
//!    that userinfo removed, so `https://user:pass@host/x` can never survive a
//!    projection even on a path no rule names.
//!
//! Because layer 2 runs after layer 1 and only ever replaces a value with the
//! redaction marker, adding a schema rule can never widen disclosure relative
//! to the previous behavior.
//!
//! # Fail-closed shapes
//!
//! A plugin `config` that is not an object (and not `null`) is hostile or
//! legacy data — no built-in plugin accepts a scalar or array config — so it is
//! replaced wholesale rather than walked. Likewise, when a schema rule expects a
//! container (`headers.*`) and finds a scalar, the scalar is redacted rather
//! than echoed. Explicit JSON `null` leaf values on sensitive paths stay
//! `null`: they disclose nothing, so projection must not invent a redaction
//! marker for them.
//!
//! # Admin visibility
//!
//! Full `admin` reads and `GET /backup` stay raw. That is deliberate repository
//! policy: rotation by read-modify-write and restorable backups both require the
//! stored value, and both surfaces are already gated to `AdminRole::Admin`.
//!
//! # Rendering
//!
//! Every point where a layer withholds or rewrites a value goes through a
//! [`RedactionRendering`]. Ordinary reads and audit diffs use
//! [`PlaceholderRendering`], which emits the markers documented above. The
//! read-only configuration export (`GET /config/export`) passes a keyed
//! fingerprint renderer instead, so it fingerprints exactly the values this
//! projection withholds and no others.

use serde_json::{Value, json};

use crate::config::types::{PlaceholderRendering, RedactionRendering};

use crate::plugins::utils::metadata_redaction::{REDACTED_PLACEHOLDER, is_sensitive_metadata_key};
use crate::plugins::utils::redis_rate_limiter;

/// Placeholder substituted for a URL path that may carry credentials.
pub const REDACTED_PATH_PLACEHOLDER: &str = "[REDACTED_PATH]";
/// Placeholder substituted for a URL query that may carry credentials.
pub const REDACTED_QUERY_PLACEHOLDER: &str = "[REDACTED_QUERY]";
/// Placeholder substituted for a URL fragment that may carry credentials.
pub const REDACTED_FRAGMENT_PLACEHOLDER: &str = "[REDACTED_FRAGMENT]";

/// How a schema-declared config path must be projected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FieldSensitivity {
    /// Replace the value wholesale with [`REDACTED_PLACEHOLDER`].
    ///
    /// Used for credential literals, vendor authentication header values, and
    /// operator-authored body templates that may interpolate a routing key.
    Secret,
    /// Project a URL down to `scheme://host[:port]` plus structural markers for
    /// any path/query/fragment that was present.
    ///
    /// Userinfo is never emitted. Collector vendors document credentials in the
    /// path (`/api/v1/push/<token>`) and query (`?code=…`), so those components
    /// are structural markers rather than values. An unparseable value or one
    /// without a host fails closed to [`REDACTED_PLACEHOLDER`].
    EndpointUrl,
    /// Project a Redis URL through the documented Redis projection, which
    /// preserves the database number in the path.
    ///
    /// Kept distinct from [`FieldSensitivity::EndpointUrl`] because
    /// `docs/admin_api.md` pins the `redis://redacted@host:port/db` shape and
    /// the same helper produces the Redis client's log fields, so an operator
    /// reads back byte-identical values from the admin API and the logs.
    RedisUrl,
    /// Project a librdkafka `producer_config` property map: every value is
    /// redacted except a compiled-in allow-list of non-credential tuning
    /// properties.
    ///
    /// `producer_config` is an open escape hatch passed straight to
    /// librdkafka, several of whose properties are marked sensitive upstream
    /// (`ssl.key.pem`, `ssl.key.password`, `sasl.password`,
    /// `sasl.oauthbearer.config`, …). Enumerating the *safe* properties is the
    /// only formulation that stays correct as librdkafka grows new sensitive
    /// ones.
    KafkaProducerProperties,
}

/// One schema-declared sensitive path.
///
/// `path` segments are matched through [`normalize_config_key`], so camelCase,
/// snake_case, kebab-case, dotted, uppercase, and compact spellings of the
/// same segment are equivalent (`customHeaders`, `custom-headers`,
/// `custom.headers`, `custom_headers`, and `customheaders` all match one
/// rule). A `*` segment matches every key of an object. Arrays are traversed
/// transparently, so a rule addresses `channels.*.url` whether `channels` is
/// an object keyed by channel name or an array of channel objects.
pub struct SensitivityRule {
    pub path: &'static [&'static str],
    pub sensitivity: FieldSensitivity,
}

const fn secret(path: &'static [&'static str]) -> SensitivityRule {
    SensitivityRule {
        path,
        sensitivity: FieldSensitivity::Secret,
    }
}

const fn endpoint_url(path: &'static [&'static str]) -> SensitivityRule {
    SensitivityRule {
        path,
        sensitivity: FieldSensitivity::EndpointUrl,
    }
}

const fn redis_url(path: &'static [&'static str]) -> SensitivityRule {
    SensitivityRule {
        path,
        sensitivity: FieldSensitivity::RedisUrl,
    }
}

/// The `redis_url` rule shared by every Redis-backed plugin.
const REDIS_BACKED: &[SensitivityRule] = &[redis_url(&["redis_url"])];

/// Empty rule set: this built-in exposes no credential-bearing config path
/// beyond what the name heuristic and the structural URL sweep already cover.
const NONE: &[SensitivityRule] = &[];

/// Per-plugin sensitivity schema.
///
/// Every name in `BUILTIN_PLUGIN_PARITY_META` must appear here — enforced by
/// `plugin_config_projection_tests`. A new built-in therefore cannot ship
/// without an explicit decision about its credential-bearing fields, even if
/// that decision is [`NONE`].
pub const PLUGIN_SENSITIVITY_SCHEMAS: &[(&str, &[SensitivityRule])] = &[
    // ---- Tracing / correlation -------------------------------------------
    (
        "otel_tracing",
        &[
            endpoint_url(&["endpoint"]),
            secret(&["authorization"]),
            // Vendor auth headers are arbitrary names (`x-honeycomb-team`,
            // `dd-api-key`, `lightstep-access-token`). No name allow-list can
            // stay correct, so every configured header VALUE is secret by
            // default; the header NAMES stay visible as routing diagnostics.
            secret(&["headers", "*"]),
        ],
    ),
    ("correlation_id", NONE),
    // ---- Request-received phase ------------------------------------------
    ("cors", NONE),
    ("request_termination", NONE),
    ("mesh_outbound_registry", NONE),
    ("ip_restriction", NONE),
    ("geo_restriction", NONE),
    ("bot_detection", NONE),
    ("spec_expose", &[endpoint_url(&["spec_url"])]),
    ("sse", NONE),
    ("grpc_web", NONE),
    ("grpc_method_router", REDIS_BACKED),
    // ---- Authentication ---------------------------------------------------
    ("spiffe_identity", NONE),
    ("mtls_auth", NONE),
    (
        "jwks_auth",
        &[
            // The identity plugins (`jwks_auth`, `oauth2_introspection`,
            // `oidc_relying_party`) put every endpoint under the required
            // `providers` array and `reject_unknown_fields` the config root, so
            // the nested path is the one a stored config actually carries. The
            // flat spellings below are kept as a floor, the same way
            // `ai_transcript_audit` keeps its legacy shape.
            endpoint_url(&["providers", "*", "discovery_url"]),
            endpoint_url(&["providers", "*", "jwks_uri"]),
            endpoint_url(&["discovery_url"]),
            endpoint_url(&["jwks_uri"]),
        ],
    ),
    (
        "oauth2_introspection",
        &[
            endpoint_url(&["providers", "*", "discovery_url"]),
            endpoint_url(&["providers", "*", "introspection_endpoint"]),
            endpoint_url(&["discovery_url"]),
            endpoint_url(&["introspection_endpoint"]),
        ],
    ),
    (
        "oidc_relying_party",
        &[
            endpoint_url(&["providers", "*", "discovery_url"]),
            endpoint_url(&["providers", "*", "jwks_uri"]),
            endpoint_url(&["providers", "*", "token_endpoint"]),
            endpoint_url(&["providers", "*", "authorization_endpoint"]),
            endpoint_url(&["providers", "*", "userinfo_endpoint"]),
            endpoint_url(&["providers", "*", "end_session_endpoint"]),
            endpoint_url(&["discovery_url"]),
            endpoint_url(&["jwks_uri"]),
            endpoint_url(&["token_endpoint"]),
            endpoint_url(&["authorization_endpoint"]),
            endpoint_url(&["userinfo_endpoint"]),
            endpoint_url(&["end_session_endpoint"]),
        ],
    ),
    ("jwt_auth", NONE),
    ("key_auth", NONE),
    ("ldap_auth", &[endpoint_url(&["ldap_url"])]),
    ("basic_auth", NONE),
    ("hmac_auth", NONE),
    ("soap_ws_security", NONE),
    // ---- Authorization ----------------------------------------------------
    ("access_control", NONE),
    ("tcp_connection_throttle", NONE),
    ("mesh_authz", NONE),
    (
        "opa",
        &[
            // Static headers attached to every OPA decision request; a bundle
            // or management-API token lives here under an arbitrary name.
            secret(&["headers", "*"]),
        ],
    ),
    ("adaptive_concurrency", NONE),
    ("request_deduplication", REDIS_BACKED),
    ("request_size_limiting", NONE),
    ("ws_message_size_limiting", NONE),
    ("graphql", REDIS_BACKED),
    ("rate_limiting", REDIS_BACKED),
    ("ws_rate_limiting", REDIS_BACKED),
    ("udp_rate_limiting", REDIS_BACKED),
    // ---- AI / governance --------------------------------------------------
    (
        "ai_transcript_audit",
        &[
            // The HTTP sink's collector URL and free-form header map live under
            // `sink` (`AI_TRANSCRIPT_AUDIT_SINK_KEYS`); vendors document a
            // reusable ingest token in the path or query, and a header value
            // template may resolve a `${secret:NAME}` reference.
            endpoint_url(&["sink", "endpoint_url"]),
            secret(&["sink", "custom_headers", "*"]),
            // Retained for a flat/legacy shape so the rules can only add
            // redaction, never reveal.
            endpoint_url(&["endpoint_url"]),
            secret(&["headers", "*"]),
            secret(&["custom_headers", "*"]),
        ],
    ),
    ("ai_prompt_shield", NONE),
    ("waf", NONE),
    ("fault_injection", NONE),
    ("body_validator", NONE),
    ("openapi_validator", NONE),
    (
        "ai_semantic_firewall",
        &[endpoint_url(&["provider", "endpoint"])],
    ),
    ("ai_request_guard", NONE),
    (
        "ai_tool_governor",
        &[
            endpoint_url(&["endpoint_url"]),
            endpoint_url(&["approval", "endpoint_url"]),
        ],
    ),
    (
        "ai_stream_router",
        &[endpoint_url(&["providers", "*", "endpoint"])],
    ),
    (
        "mcp_gateway",
        &[
            // `servers` is an object keyed by server ID; each entry carries the
            // upstream URL, and there is no top-level spelling. Construction
            // refuses userinfo/query/fragment, but a hosted MCP server's ingest
            // token still rides the path — and an `enabled: false` config is
            // stored without construction, so nothing has screened it at all.
            endpoint_url(&["servers", "*", "upstream_url"]),
            endpoint_url(&["upstream_url"]),
        ],
    ),
    ("a2a_gateway", NONE),
    ("mesh_route_dispatch", NONE),
    (
        "ai_semantic_cache",
        &[
            redis_url(&["redis_url"]),
            endpoint_url(&["semantic_embedding_endpoint"]),
            secret(&["semantic_embedding_auth_header"]),
        ],
    ),
    // ---- Transform / dispatch --------------------------------------------
    ("request_transformer", NONE),
    (
        "serverless_function",
        &[
            // Azure/GCP trigger URLs carry a signed `?code=` credential and a
            // secret path segment; AWS endpoint overrides are origin-only but
            // are projected the same way for one contract.
            endpoint_url(&["function_url"]),
            endpoint_url(&["aws_endpoint_url"]),
            // Sent verbatim as `x-functions-key`; a reusable invocation key.
            secret(&["azure_function_key"]),
        ],
    ),
    ("response_mock", NONE),
    ("grpc_deadline", NONE),
    ("load_testing", NONE),
    ("request_mirror", NONE),
    ("response_size_limiting", NONE),
    ("response_caching", NONE),
    ("response_transformer", NONE),
    ("compression", NONE),
    ("ai_prompt_compressor", NONE),
    (
        "ai_federation",
        &[
            endpoint_url(&["base_url"]),
            endpoint_url(&["providers", "*", "base_url"]),
        ],
    ),
    ("ai_response_guard", NONE),
    ("security_headers", NONE),
    ("ai_token_metrics", NONE),
    ("ai_rate_limiter", REDIS_BACKED),
    // ---- Logging sinks ----------------------------------------------------
    ("stdout_logging", NONE),
    ("ws_frame_logging", NONE),
    ("statsd_logging", NONE),
    (
        "http_logging",
        &[
            // `docs/plugins.md` documents collector credentials in the endpoint
            // path/query for the HTTP sink family.
            endpoint_url(&["endpoint_url"]),
            secret(&["custom_headers", "*"]),
        ],
    ),
    ("tcp_logging", NONE),
    (
        "kafka_logging",
        &[SensitivityRule {
            path: &["producer_config"],
            sensitivity: FieldSensitivity::KafkaProducerProperties,
        }],
    ),
    (
        "loki_logging",
        &[
            endpoint_url(&["endpoint_url"]),
            secret(&["authorization_header"]),
            secret(&["custom_headers", "*"]),
        ],
    ),
    ("udp_logging", NONE),
    ("ws_logging", &[endpoint_url(&["endpoint_url"])]),
    ("transaction_debugger", NONE),
    // ---- Notifications ----------------------------------------------------
    (
        "proxy_alerts",
        &[
            // Slack/Teams/Discord incoming-webhook URLs embed the credential in
            // the path; the generic `webhook` channel's `url` may embed it
            // anywhere including userinfo.
            endpoint_url(&["channels", "*", "webhook_url"]),
            endpoint_url(&["channels", "*", "url"]),
            // Arbitrary vendor auth header names, same reasoning as OTel.
            secret(&["channels", "*", "headers", "*"]),
            // Operator-authored template; the documented way to attach a
            // routing key to a generic webhook body is to inline it here.
            secret(&["channels", "*", "body_template"]),
        ],
    ),
    ("prometheus_metrics", NONE),
    ("api_chargeback", NONE),
    (
        "api_chargeback_sink",
        &[
            endpoint_url(&["clickhouse", "url"]),
            // Operator-authored INSERT query parameters are appended to the
            // ClickHouse URL. Credential-*named* keys are already rejected at
            // validation, but the values stay arbitrary strings, so no name
            // rule can vouch for them.
            secret(&["clickhouse", "insert_query_params", "*"]),
        ],
    ),
    (
        "workload_metrics",
        &[
            // Mesh tracing providers are serialized as a tagged `kind` plus a
            // provider-specific `config` object. Collector credentials may be
            // carried in the accepted path/query components, just as they can
            // for the standalone logging/tracing sinks. Cover both the
            // singleton compatibility shape and the canonical provider list.
            endpoint_url(&["tracing_provider", "config", "url"]),
            endpoint_url(&["tracing_provider", "config", "agent_url"]),
            endpoint_url(&["tracing_provider", "config", "collector_url"]),
            endpoint_url(&["tracing_provider", "config", "endpoint"]),
            endpoint_url(&["tracing_providers", "*", "config", "url"]),
            endpoint_url(&["tracing_providers", "*", "config", "agent_url"]),
            endpoint_url(&["tracing_providers", "*", "config", "collector_url"]),
            endpoint_url(&["tracing_providers", "*", "config", "endpoint"]),
        ],
    ),
    ("__mesh_bpf_metrics", NONE),
    ("transaction_log_schema", NONE),
];

/// librdkafka `producer_config` properties that carry no credential material
/// and stay visible in a projected read.
///
/// Deliberately an allow-list of *safe* tuning knobs: librdkafka's sensitive
/// set grows over time (`ssl.key.pem`, `ssl.key.password`, `ssl.keystore.password`,
/// `sasl.password`, `sasl.oauthbearer.config`, `sasl.oauthbearer.client.secret`,
/// …), and a deny-list would silently fall behind. Anything not listed here is
/// redacted.
pub const KAFKA_SAFE_PRODUCER_PROPERTIES: &[&str] = &[
    "acks",
    "batch.num.messages",
    "batch.size",
    "client.id",
    "compression.codec",
    "compression.level",
    "compression.type",
    "delivery.timeout.ms",
    "enable.idempotence",
    "linger.ms",
    "max.in.flight",
    "max.in.flight.requests.per.connection",
    "message.max.bytes",
    "message.send.max.retries",
    "message.timeout.ms",
    "metadata.max.age.ms",
    "partitioner",
    "queue.buffering.max.kbytes",
    "queue.buffering.max.messages",
    "queue.buffering.max.ms",
    "reconnect.backoff.max.ms",
    "reconnect.backoff.ms",
    "request.required.acks",
    "request.timeout.ms",
    "retries",
    "retry.backoff.max.ms",
    "retry.backoff.ms",
    "socket.keepalive.enable",
    "socket.nagle.disable",
    "socket.timeout.ms",
    "sticky.partitioning.linger.ms",
    "topic.metadata.refresh.interval.ms",
];

/// Look up the schema rules for a plugin. Unknown (custom) plugins get no
/// rules and rely on the heuristic + structural URL layers.
pub fn sensitivity_rules_for(plugin_name: &str) -> &'static [SensitivityRule] {
    PLUGIN_SENSITIVITY_SCHEMAS
        .iter()
        .find(|(name, _)| *name == plugin_name)
        .map(|(_, rules)| *rules)
        .unwrap_or(NONE)
}

/// Normalize a config key for matching.
///
/// Lowercases ASCII letters and strips `-`, `.`, and `_` so camelCase,
/// snake_case, kebab-case, dotted, uppercase, and compact spellings of the
/// same schema key compare equal. For example `customHeaders`,
/// `custom-headers`, `custom.headers`, `custom_headers`, `CUSTOMHEADERS`, and
/// `customheaders` all normalize to `customheaders`.
///
/// Matching stays exact on the normalized form: unrelated keys such as
/// `custom_headers_enabled` / `customheader` do not collapse onto
/// `custom_headers`. Normalization may only add redaction relative to a
/// previously redacted spelling; it must never make one visible.
pub fn normalize_config_key(key: &str) -> String {
    key.chars()
        .filter(|c| *c != '-' && *c != '.' && *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Apply the full projection contract to a plugin `config` value in place.
///
/// Safe to call on any JSON shape; see the module docs for the fail-closed
/// rules on non-object configs.
pub fn project_plugin_config(plugin_name: &str, config: &mut Value) {
    project_plugin_config_with(plugin_name, config, &PlaceholderRendering);
}

/// [`project_plugin_config`] with an explicit [`RedactionRendering`].
///
/// This is the one projection; the ordinary reads and audit diffs call it with
/// [`PlaceholderRendering`].
pub fn project_plugin_config_with(
    plugin_name: &str,
    config: &mut Value,
    rendering: &dyn RedactionRendering,
) {
    if config.is_null() {
        return;
    }
    if !config.is_object() {
        // No built-in plugin accepts a scalar or array config. Anything else
        // here is hostile or pre-schema legacy data whose interior cannot be
        // classified, so it is not echoed.
        render_in_place(config, json!(REDACTED_PLACEHOLDER), rendering);
        return;
    }

    for rule in sensitivity_rules_for(plugin_name) {
        apply_rule(config, rule.path, rule.sensitivity, rendering);
    }
    redact_sensitive_plugin_config_fields_with(config, rendering);
    strip_url_userinfo_everywhere(config, rendering);
}

/// Replace `value` with the renderer's form of `redacted`.
fn render_in_place(value: &mut Value, redacted: Value, rendering: &dyn RedactionRendering) {
    let stored = std::mem::take(value);
    *value = rendering.render(&stored, redacted);
}

fn apply_rule(
    value: &mut Value,
    path: &[&str],
    sensitivity: FieldSensitivity,
    rendering: &dyn RedactionRendering,
) {
    let Some((head, rest)) = path.split_first() else {
        apply_sensitivity(value, sensitivity, rendering);
        return;
    };

    match value {
        Value::Object(map) => {
            if *head == "*" {
                for child in map.values_mut() {
                    apply_rule(child, rest, sensitivity, rendering);
                }
            } else {
                let wanted = normalize_config_key(head);
                for (key, child) in map.iter_mut() {
                    if normalize_config_key(key) == wanted {
                        apply_rule(child, rest, sensitivity, rendering);
                    }
                }
            }
        }
        Value::Array(items) => {
            if *head == "*" {
                // `*` names *each entry of the container*. For an array the
                // entries are the elements themselves, so the segment is
                // consumed here. Traversing transparently instead would hand
                // the same `*` to every element's own fields, and the remaining
                // path would then be resolved against sibling scalars
                // (`providers[0].name`), fail-closing values the schema never
                // named.
                for item in items {
                    apply_rule(item, rest, sensitivity, rendering);
                }
            } else {
                // A named segment traverses arrays transparently so one rule
                // covers both an object-keyed and an array-shaped container,
                // and so an array-wrapped scalar still reaches the leaf rule.
                for item in items {
                    apply_rule(item, path, sensitivity, rendering);
                }
            }
        }
        Value::Null => {}
        // The schema expects a container here and found a scalar: legacy or
        // hostile data whose interior cannot be classified. Fail closed.
        _ => apply_sensitivity(value, FieldSensitivity::Secret, rendering),
    }
}

fn apply_sensitivity(
    value: &mut Value,
    sensitivity: FieldSensitivity,
    rendering: &dyn RedactionRendering,
) {
    if value.is_null() {
        return;
    }
    let redacted = match sensitivity {
        FieldSensitivity::Secret => json!(REDACTED_PLACEHOLDER),
        FieldSensitivity::EndpointUrl => match value.as_str() {
            Some(raw) => json!(redact_endpoint_url(raw)),
            // A non-string where a URL belongs may nest credentials at any
            // depth (an array of objects holding signed trigger URLs), so it is
            // replaced wholesale rather than walked.
            None => json!(REDACTED_PLACEHOLDER),
        },
        FieldSensitivity::RedisUrl => match value.as_str() {
            Some(raw) => json!(redis_rate_limiter::redact_url_userinfo(raw)),
            None => json!(REDACTED_PLACEHOLDER),
        },
        FieldSensitivity::KafkaProducerProperties => match value.as_object_mut() {
            Some(props) => {
                for (key, prop) in props.iter_mut() {
                    if !is_safe_kafka_producer_property(key) {
                        // Explicit null discloses nothing; keep it so projection
                        // does not invent a redaction marker for an unset property.
                        apply_sensitivity(prop, FieldSensitivity::Secret, rendering);
                    }
                }
                return;
            }
            None => json!(REDACTED_PLACEHOLDER),
        },
    };
    render_in_place(value, redacted, rendering);
}

/// True when a librdkafka producer property is a known non-credential tuning
/// knob. Matching is case-insensitive on the librdkafka spelling (dots), which
/// is how the property is admitted and forwarded.
pub fn is_safe_kafka_producer_property(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase();
    KAFKA_SAFE_PRODUCER_PROPERTIES
        .iter()
        .any(|safe| *safe == normalized)
}

/// Project a credential-bearing endpoint URL down to its structural form.
///
/// Emits `scheme://host[:port]` plus a marker for each component that was
/// present and may carry credentials. Userinfo is never emitted. Fails closed
/// to [`REDACTED_PLACEHOLDER`] when the value does not parse or has no host,
/// because a value that cannot be structurally decomposed cannot be shown to be
/// credential-free.
pub fn redact_endpoint_url(raw: &str) -> String {
    let Ok(parsed) = url::Url::parse(raw) else {
        return REDACTED_PLACEHOLDER.to_string();
    };
    let host = match parsed.host() {
        Some(url::Host::Domain(host)) => host.to_string(),
        Some(url::Host::Ipv4(host)) => host.to_string(),
        Some(url::Host::Ipv6(host)) => format!("[{host}]"),
        None => return REDACTED_PLACEHOLDER.to_string(),
    };
    let mut redacted = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        redacted.push(':');
        redacted.push_str(&port.to_string());
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        redacted.push('/');
        redacted.push_str(REDACTED_PATH_PLACEHOLDER);
    }
    if parsed.query().is_some() {
        redacted.push('?');
        redacted.push_str(REDACTED_QUERY_PLACEHOLDER);
    }
    if parsed.fragment().is_some() {
        redacted.push('#');
        redacted.push_str(REDACTED_FRAGMENT_PLACEHOLDER);
    }
    redacted
}

/// Heuristic name-based redaction, retained as a floor beneath the schema.
///
/// Custom plugins have no schema entry, and a built-in field can be added
/// before its schema rule lands, so this layer still runs on every projection.
/// It only ever *adds* redaction. Explicit JSON `null` values are left alone —
/// they disclose nothing — matching [`apply_sensitivity`].
pub fn redact_sensitive_plugin_config_fields(value: &mut Value) {
    redact_sensitive_plugin_config_fields_with(value, &PlaceholderRendering);
}

fn redact_sensitive_plugin_config_fields_with(
    value: &mut Value,
    rendering: &dyn RedactionRendering,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_plugin_config_key(key) {
                    apply_sensitivity(child, FieldSensitivity::Secret, rendering);
                } else if is_credential_bearing_url_config_key(key) {
                    apply_sensitivity(child, FieldSensitivity::RedisUrl, rendering);
                } else {
                    redact_sensitive_plugin_config_fields_with(child, rendering);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_sensitive_plugin_config_fields_with(item, rendering);
            }
        }
        _ => {}
    }
}

/// Name-substring sensitivity floor.
///
/// Matching is on the fully delimiter-stripped lowercase key from
/// [`normalize_config_key`], so `apiKey`, `api-key`, `API_KEY`, `api.key`,
/// and `apikey` all match one pattern.
pub fn is_sensitive_plugin_config_key(key: &str) -> bool {
    if is_sensitive_metadata_key(key) {
        return true;
    }

    let normalized = normalize_config_key(key);
    normalized == "key"
        // HMAC signing material for Redis cache envelopes (`ai_semantic_cache`
        // `redis_integrity_key`). Substring match so any future
        // `*_integrity_key` signing secret is covered without another edit; the
        // segment is only ever used for signing/authenticity keys. Patterns are
        // the compact normalized forms (`integrityKey` / `integrity_key` →
        // `integritykey`), matching the same way `apiKey` / `api_key` →
        // `apikey` already does.
        || normalized.contains("integritykey")
        || normalized.contains("apikey")
        || normalized.contains("accesskey")
        || normalized.contains("functionkey")
        || normalized.contains("clientsecret")
        || normalized.contains("credential")
        || normalized.contains("privatekey")
        || normalized.contains("serviceaccountjson")
        || normalized.contains("webhook")
}

/// Config keys whose value is a Redis connection URL that may carry credentials
/// in its userinfo component, matched at *any* nesting depth and for any plugin
/// (including custom ones) rather than only where the schema names them.
///
/// These are deliberately not wholesale-redacted: `docs/admin_api.md` documents
/// that scheme, host, port, and database number stay visible as the diagnostics
/// an operator needs from a Viewer/Operator read or an audit diff. Matching uses
/// the compact normalized form (`redisUrl` / `redis_url` / `redis-url` →
/// `redisurl`) so a nested camelCase or compact spelling cannot bypass
/// projection.
pub fn is_credential_bearing_url_config_key(key: &str) -> bool {
    normalize_config_key(key) == "redisurl"
}

/// Remove userinfo from every URL-shaped string left in the tree.
///
/// The schema names the fields that are *known* to be endpoints; this sweep is
/// the backstop for the ones it does not, including custom-plugin config. Only
/// strings that parse as a URL *and* actually carry a username or password are
/// rewritten, so ordinary configuration values are untouched.
fn strip_url_userinfo_everywhere(value: &mut Value, rendering: &dyn RedactionRendering) {
    match value {
        Value::Object(map) => {
            for child in map.values_mut() {
                strip_url_userinfo_everywhere(child, rendering);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_url_userinfo_everywhere(item, rendering);
            }
        }
        Value::String(_) => strip_url_userinfo_in_place(value, rendering),
        _ => {}
    }
}

/// Rewrite one string value to drop URL userinfo, if it is a URL with userinfo.
fn strip_url_userinfo_in_place(value: &mut Value, rendering: &dyn RedactionRendering) {
    let Some(raw) = value.as_str() else {
        return;
    };
    let Ok(mut parsed) = url::Url::parse(raw) else {
        return;
    };
    if parsed.username().is_empty() && parsed.password().is_none() {
        return;
    }
    // `set_username`/`set_password` return Err for cannot-be-a-base URLs, which
    // by construction have no userinfo to strip; fail closed anyway.
    let stripped = parsed.set_username("redacted").is_ok() && parsed.set_password(None).is_ok();
    let redacted = if stripped {
        json!(parsed.to_string())
    } else {
        json!(REDACTED_PLACEHOLDER)
    };
    render_in_place(value, redacted, rendering);
}
