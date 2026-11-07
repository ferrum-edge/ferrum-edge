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
//!    A custom plugin (no built-in schema) also gets a structural header-map
//!    rule: every value of an object keyed `headers`, `custom_headers`,
//!    `request_headers`, `extra_headers`, or `header_present` (any spelling,
//!    any depth) is withheld ([`HEADER_MAP_KEYS`]). Built-ins declare their
//!    header maps explicitly instead, because several keep a map of that name
//!    visible on purpose (response headers, OpenAPI and JSON-schema documents).
//! 2. **Name heuristics** ([`is_sensitive_plugin_config_key`]) — the historical
//!    substring matcher, retained as a floor. It still covers custom plugins
//!    (which have no built-in schema) and any built-in field that a future edit
//!    adds before its schema entry catches up.
//! 3. **Structural URL sweep** ([`strip_url_userinfo_with`]) — any remaining
//!    string anywhere in the tree that parses as a URL carrying userinfo has
//!    that userinfo removed, so `https://user:pass@host/x` can never survive a
//!    projection even on a path no rule names.
//! 4. **TLS-material sweep** ([`withhold_tls_material_with`]) — any string
//!    carrying a PEM private-key block is withheld wherever it occurs, and a
//!    field named as a private-key source fails closed on any PEM armour or
//!    control character. This is the same classification the Proxy and
//!    Upstream projections use, so a certificate-plus-key bundle pasted into
//!    a certificate field is withheld identically on every resource.
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

use std::cell::RefCell;
use std::collections::HashSet;

use crate::config::types::{PlaceholderRendering, RedactionRendering, push_json_pointer_segment};

use crate::plugins::utils::metadata_redaction::{
    REDACTED_PLACEHOLDER, REDACTED_USERINFO_PLACEHOLDER, is_sensitive_name_by_listed_rules,
};
use crate::plugins::utils::redis_rate_limiter;

/// Placeholder substituted for a URL path that may carry credentials.
pub const REDACTED_PATH_PLACEHOLDER: &str = "[REDACTED_PATH]";
/// Placeholder substituted for a URL query that may carry credentials.
pub const REDACTED_QUERY_PLACEHOLDER: &str =
    crate::plugins::utils::metadata_redaction::REDACTED_QUERY_PLACEHOLDER;
/// Placeholder substituted for a URL fragment that may carry credentials.
pub const REDACTED_FRAGMENT_PLACEHOLDER: &str =
    crate::plugins::utils::metadata_redaction::REDACTED_FRAGMENT_PLACEHOLDER;

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
    /// A TLS private-key source, which accepts inline PEM as well as a
    /// reference (a path, `file://`, `k8s://`, `vault://`, `managed://`, …).
    ///
    /// Classified by [`tls_material_withheld`] as
    /// [`TlsMaterialField::PrivateKey`]: inline key material is replaced by
    /// [`REDACTED_PLACEHOLDER`], while a reference only names where the gateway
    /// loads the key from and stays visible. A non-string fails closed.
    PrivateKeySource,
    /// A certificate or CA-bundle source (inline PEM or a reference).
    ///
    /// Classified by [`tls_material_withheld`] as
    /// [`TlsMaterialField::Public`]: certificate-only PEM and references stay
    /// visible, and a value carrying a PEM private-key block (a
    /// certificate-plus-key bundle) is replaced by [`REDACTED_PLACEHOLDER`]. A
    /// non-string fails closed.
    CertificateSource,
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

const fn private_key_source(path: &'static [&'static str]) -> SensitivityRule {
    SensitivityRule {
        path,
        sensitivity: FieldSensitivity::PrivateKeySource,
    }
}

const fn certificate_source(path: &'static [&'static str]) -> SensitivityRule {
    SensitivityRule {
        path,
        sensitivity: FieldSensitivity::CertificateSource,
    }
}

/// The `redis_url` rule shared by every Redis-backed plugin.
const REDIS_BACKED: &[SensitivityRule] = &[redis_url(&["redis_url"])];

/// Empty rule set: this built-in exposes no credential-bearing config path
/// beyond what the name heuristic and the structural URL sweep already cover.
const NONE: &[SensitivityRule] = &[];

/// `mesh_authz` policy match operands, outbound check headers, and the
/// endpoint URLs its mesh slice carries.
///
/// Policies arrive either as an operator-authored flat `mesh_policies` list or
/// inside the mesh-mode `mesh_slice` (ordinary and NodeWaypoint-capture
/// policies alike). `to[].headers` values and `when[].values` /
/// `when[].not_values` are request-header (or claim, principal, IP) match
/// operands. A `when` entry's `key` decides which, and a path rule cannot read
/// a sibling, so every condition value is withheld, entry by entry so the list
/// shape stays visible (the `key` field itself is already masked by the name
/// heuristic).
///
/// The slice also carries the `include_additional_headers_in_check[].value`
/// headers and the check-URL `path_prefix` of an external authorization
/// provider, two opaque operator-authored payloads (Istio ProxyConfig
/// `environment` values and ECDS extension `value` bytes), all withheld; the
/// TLS sources of the embedded VirtualService L4 `Proxy` / `Upstream` objects,
/// classified by the TLS-material sweep; and collector, JWKS, control-plane,
/// and federation URLs, projected structurally. Every other slice field is
/// inventory (workloads, services, hosts, addresses, ports, labels), public
/// material (trust bundles, inline JWKS), header-name lists, file paths, or
/// static telemetry tags; DestinationRule and Upstream subset `private_key`,
/// Consul tokens, and credential references are already masked by the name
/// heuristic.
const MESH_AUTHZ: &[SensitivityRule] = &[
    secret(&[
        "mesh_policies",
        "*",
        "rules",
        "*",
        "to",
        "*",
        "headers",
        "*",
    ]),
    secret(&[
        "mesh_policies",
        "*",
        "rules",
        "*",
        "when",
        "*",
        "values",
        "*",
    ]),
    secret(&[
        "mesh_policies",
        "*",
        "rules",
        "*",
        "when",
        "*",
        "not_values",
        "*",
    ]),
    secret(&[
        "mesh_slice",
        "mesh_policies",
        "*",
        "rules",
        "*",
        "to",
        "*",
        "headers",
        "*",
    ]),
    secret(&[
        "mesh_slice",
        "mesh_policies",
        "*",
        "rules",
        "*",
        "when",
        "*",
        "values",
        "*",
    ]),
    secret(&[
        "mesh_slice",
        "mesh_policies",
        "*",
        "rules",
        "*",
        "when",
        "*",
        "not_values",
        "*",
    ]),
    secret(&[
        "mesh_slice",
        "node_waypoint_capture_mesh_policies",
        "*",
        "rules",
        "*",
        "to",
        "*",
        "headers",
        "*",
    ]),
    secret(&[
        "mesh_slice",
        "node_waypoint_capture_mesh_policies",
        "*",
        "rules",
        "*",
        "when",
        "*",
        "values",
        "*",
    ]),
    secret(&[
        "mesh_slice",
        "node_waypoint_capture_mesh_policies",
        "*",
        "rules",
        "*",
        "when",
        "*",
        "not_values",
        "*",
    ]),
    secret(&[
        "mesh_slice",
        "ext_authz_providers",
        "*",
        "include_additional_headers_in_check",
        "*",
        "value",
    ]),
    // The check URL's path prefix is a shared secret on some check services.
    secret(&["mesh_slice", "ext_authz_providers", "*", "path_prefix"]),
    secret(&["mesh_slice", "proxy_configs", "*", "environment", "*"]),
    secret(&["mesh_slice", "extension_configs", "*", "value"]),
    // The VirtualService L4 proxies and upstreams are full serialized `Proxy` /
    // `Upstream` objects. Their TLS key, certificate, and CA sources
    // (`backend_tls_*`, `port_overrides.*.tls.*`, subset `traffic_policy.tls`)
    // are classified by field name by the TLS-material sweep, exactly as the
    // standalone Proxy and Upstream projections classify them; their Consul
    // token is masked by the name heuristic and URL userinfo by the URL sweep.
    // The telemetry tracing-provider envelope is the same `TracingProvider`
    // the `workload_metrics` rules cover; keep the four fields in step with
    // them (a parity test enforces it).
    endpoint_url(&[
        "mesh_slice",
        "telemetry_resources",
        "*",
        "config",
        "tracing",
        "providers",
        "*",
        "config",
        "url",
    ]),
    endpoint_url(&[
        "mesh_slice",
        "telemetry_resources",
        "*",
        "config",
        "tracing",
        "providers",
        "*",
        "config",
        "agent_url",
    ]),
    endpoint_url(&[
        "mesh_slice",
        "telemetry_resources",
        "*",
        "config",
        "tracing",
        "providers",
        "*",
        "config",
        "collector_url",
    ]),
    endpoint_url(&[
        "mesh_slice",
        "telemetry_resources",
        "*",
        "config",
        "tracing",
        "providers",
        "*",
        "config",
        "endpoint",
    ]),
    endpoint_url(&[
        "mesh_slice",
        "request_authentications",
        "*",
        "jwt_rules",
        "*",
        "jwks_uri",
    ]),
    endpoint_url(&["mesh_slice", "multi_cluster", "federation_endpoint"]),
    endpoint_url(&[
        "mesh_slice",
        "multi_cluster",
        "remote_clusters",
        "*",
        "control_plane_url",
    ]),
    endpoint_url(&[
        "mesh_slice",
        "multi_cluster",
        "remote_clusters",
        "*",
        "federation_endpoint",
    ]),
];

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
    (
        "request_termination",
        // `trigger.header_value` is the value a request must carry to be
        // terminated: an operator-chosen token, like a `waf` exemption value.
        // The header name and the termination response stay visible.
        &[secret(&["trigger", "header_value"])],
    ),
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
    (
        "mtls_auth",
        // Inline CA certificates; a pasted certificate-plus-key bundle is
        // withheld.
        &[certificate_source(&[
            "allowed_issuers",
            "*",
            "ca_certificate_pem",
        ])],
    ),
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
    (
        "ldap_auth",
        &[
            endpoint_url(&["ldap_url"]),
            endpoint_url(&["failover_ldap_urls"]),
        ],
    ),
    ("basic_auth", NONE),
    ("hmac_auth", NONE),
    (
        "soap_ws_security",
        // Trusted certificate sources (inline PEM or references).
        &[
            certificate_source(&["x509_signature", "trusted_certs", "*"]),
            certificate_source(&["saml", "trusted_signing_certs", "*"]),
        ],
    ),
    // ---- Authorization ----------------------------------------------------
    ("access_control", NONE),
    ("tcp_connection_throttle", NONE),
    ("mesh_authz", MESH_AUTHZ),
    (
        "opa",
        &[
            // The OPA server URL may carry a base path that is kept in every
            // decision URL; project it structurally like any endpoint.
            endpoint_url(&["opa_host"]),
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
    (
        "waf",
        &[
            // `header_present` values are shared secrets that suppress every
            // rule.
            secret(&["global_exemptions", "header_present", "*"]),
            // `conditions.headers` values scope a rule to requests carrying a
            // header value; operators may target with a shared secret or a
            // credential-bearing header, as for `fault_injection`. A `null`
            // (presence-only) condition stays `null`. `custom_rules` is an
            // array and `rule_overrides` is keyed by rule id; `*` covers both.
            secret(&["custom_rules", "*", "conditions", "headers", "*"]),
            secret(&["rule_overrides", "*", "conditions", "headers", "*"]),
        ],
    ),
    (
        "fault_injection",
        // `match.headers` values opt a request into faults; operators may
        // target with a shared secret or a credential-bearing header.
        &[secret(&["match", "headers", "*"])],
    ),
    ("body_validator", NONE),
    (
        "openapi_validator",
        // `bypass.header_present` values are shared secrets that skip
        // validation, exactly like the `waf` exemption above.
        &[secret(&["bypass", "header_present", "*"])],
    ),
    (
        "ai_semantic_firewall",
        &[
            endpoint_url(&["provider", "endpoint"]),
            // Keys the logged snippet hashes; disclosing it lets a reader
            // confirm guessed snippets against the hashes.
            secret(&["privacy", "snippet_hash_salt"]),
        ],
    ),
    ("ai_request_guard", NONE),
    (
        "ai_tool_governor",
        &[
            endpoint_url(&["endpoint_url"]),
            endpoint_url(&["approval", "endpoint_url"]),
            // Static headers attached to every approval webhook call; the
            // approval service's credential lives here under an arbitrary
            // name, so every value is secret, as for `otel_tracing`.
            secret(&["approval", "headers", "*"]),
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
            // Per-server upstream request headers usually carry the hosted MCP
            // server's credential under a vendor name (`Ocp-Apim-Subscription-Key`,
            // `x-functions-key`), so every value is secret, as for `otel_tracing`.
            secret(&["servers", "*", "headers", "*"]),
        ],
    ),
    ("a2a_gateway", NONE),
    (
        "mesh_route_dispatch",
        &[
            // Per-route request-header writes reach the upstream exactly like
            // `request_transformer` rule values, so they are secret for the
            // same reason.
            secret(&["rules", "*", "request_transform", "*", "value"]),
            // Match operands select a route by a value the client presents;
            // operators may route on a shared secret or a credential-bearing
            // header or query parameter. Each operand is a bare string or a
            // one-key `{exact|prefix|regex: ...}` object: the trailing `*`
            // masks the bare string itself (a scalar where a container is
            // expected fails closed) and the inner value of the object form,
            // keeping the match kind visible.
            secret(&["rules", "*", "match", "headers", "*", "*"]),
            secret(&["rules", "*", "match", "without_headers", "*", "*"]),
            secret(&["rules", "*", "match", "query_params", "*", "*"]),
            // The route-local `destination.backend_tls` key, certificate, and
            // CA sources are classified by field name by the TLS-material
            // sweep.
        ],
    ),
    (
        "ai_semantic_cache",
        &[
            redis_url(&["redis_url"]),
            endpoint_url(&["semantic_embedding_endpoint"]),
            secret(&["semantic_embedding_auth_header"]),
        ],
    ),
    // ---- Transform / dispatch --------------------------------------------
    (
        "request_transformer",
        // Each rule writes its `value` into the upstream request (a header,
        // query parameter or body field). Operators use it to inject backend
        // credentials (`Authorization`, `X-Api-Key`, `api_key=`), and the
        // destination name is arbitrary, so every rule value is secret.
        // `operation`, `target` and `new_key` stay visible; `key` is already
        // masked by the name heuristic.
        &[secret(&["rules", "*", "value"])],
    ),
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
    (
        "response_mock",
        // `rules[].match` values select which requests receive a mock;
        // operators may target with a shared secret or a credential-bearing
        // header / query parameter, so every condition value is secret.
        // Response `headers` and `body` are static mock content.
        &[
            secret(&["rules", "*", "match", "headers", "*"]),
            secret(&["rules", "*", "match", "query_params", "*"]),
        ],
    ),
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
    (
        "udp_logging",
        // The DTLS key, certificate, and CA sources accept inline PEM.
        &[
            private_key_source(&["dtls_key_path"]),
            certificate_source(&["dtls_cert_path"]),
            certificate_source(&["dtls_ca_cert_path"]),
        ],
    ),
    (
        "ws_logging",
        &[
            endpoint_url(&["endpoint_url"]),
            // Upgrade-request headers are the supported collector-credential
            // channel (`Authorization`, API-key headers).
            secret(&["custom_headers", "*"]),
        ],
    ),
    (
        "transaction_debugger",
        // The selector value a request must carry to be captured; the plugin
        // already treats it as an operator-chosen token.
        &[secret(&["capture_request_header_value"])],
    ),
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

/// Normalized keys ([`normalize_config_key`]) that name an arbitrary header
/// map in a plugin config: `headers`, `custom_headers`, `request_headers`,
/// `extra_headers`, and `header_present`, in any spelling.
pub const HEADER_MAP_KEYS: &[&str] = &[
    "headers",
    "customheaders",
    "requestheaders",
    "extraheaders",
    "headerpresent",
];

/// Whether `plugin_name` is a built-in with a declared sensitivity schema.
///
/// A custom plugin has none, so the projection cannot know which of its maps
/// carry header values; it gets the structural header-map layer instead (see
/// [`project_plugin_config_with`]).
pub fn has_builtin_sensitivity_schema(plugin_name: &str) -> bool {
    PLUGIN_SENSITIVITY_SCHEMAS
        .iter()
        .any(|(name, _)| *name == plugin_name)
}

/// Look up the schema rules for a plugin. Unknown (custom) plugins get no
/// rules and rely on the heuristic, header-map, and structural layers.
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
    project_plugin_config_with(plugin_name, config, "", &PlaceholderRendering);
}

/// [`project_plugin_config`] with an explicit [`RedactionRendering`].
///
/// This is the one projection; the ordinary reads and audit diffs call it with
/// [`PlaceholderRendering`]. `root_pointer` is the JSON pointer of `config`
/// inside the resource body (`/config` for a PluginConfig); every site handed
/// to the renderer is addressed relative to the resource through it.
pub fn project_plugin_config_with(
    plugin_name: &str,
    config: &mut Value,
    root_pointer: &str,
    rendering: &dyn RedactionRendering,
) {
    if config.is_null() {
        return;
    }
    let mut projector = Projector::new(root_pointer, rendering);
    if !config.is_object() {
        // No built-in plugin accepts a scalar or array config. Anything else
        // here is hostile or pre-schema legacy data whose interior cannot be
        // classified, so it is not echoed.
        projector.render(config, json!(REDACTED_PLACEHOLDER));
        return;
    }

    for rule in sensitivity_rules_for(plugin_name) {
        projector.apply_rule(config, rule.path, rule.sensitivity);
    }
    if !has_builtin_sensitivity_schema(plugin_name) {
        projector.redact_header_maps(config);
    }
    projector.redact_by_name(config);
    projector.strip_url_userinfo(config);
    projector.withhold_tls_material(config, None);
}

/// The structural URL-userinfo sweep on its own: every string anywhere in
/// `value` that parses as a URL carrying a username or password has the
/// userinfo removed. The Proxy and Upstream projections run it over their whole
/// body so a credential embedded in, for example, a Consul `address` never
/// reaches a non-admin read, an audit diff, or the configuration export.
pub fn strip_url_userinfo_with(
    value: &mut Value,
    root_pointer: &str,
    rendering: &dyn RedactionRendering,
) {
    Projector::new(root_pointer, rendering).strip_url_userinfo(value);
}

/// How a field name classifies the TLS material source it holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlsMaterialField {
    /// Names a private key: withheld unless it is plainly a reference.
    PrivateKey,
    /// Names a certificate or CA bundle: public unless it carries a PEM
    /// private-key block.
    Public,
}

/// The TLS material slot a field name denotes, for every slot reachable from a
/// serialized Proxy or Upstream: the top-level `backend_tls_*` fields, a
/// [`crate::config::types::BackendTlsConfig`] (`port_overrides.<port>.tls`,
/// a `mesh_route_dispatch` route's `destination.backend_tls`), and a
/// [`crate::modes::mesh::config::MeshTrafficPolicyTls`]
/// (`subsets[].traffic_policy.tls`). Matched by name wherever it occurs, so a
/// slot nested somewhere new is classified without a code change.
pub fn tls_material_field(name: &str) -> Option<TlsMaterialField> {
    match name {
        "backend_tls_client_key_path" | "client_key_path" | "private_key" => {
            Some(TlsMaterialField::PrivateKey)
        }
        "backend_tls_client_cert_path"
        | "backend_tls_server_ca_cert_path"
        | "client_cert_path"
        | "server_ca_cert_path"
        | "client_certificate"
        | "ca_certificates" => Some(TlsMaterialField::Public),
        _ => None,
    }
}

/// Whether a stored string is withheld from non-admin reads as TLS private-key
/// material.
///
/// A PEM private-key block is withheld wherever it appears (a cert-plus-key
/// bundle pasted into a certificate field, say). A private-key field fails
/// closed further: any PEM armour, or a line break or other control character
/// (never part of a path or typed URI), is treated as inline material.
/// Certificates and CA bundles are public and otherwise stay visible. The
/// exact placeholder at a TLS material field is reported too, so an echoed
/// write is found.
pub fn tls_material_withheld(value: &str, field: Option<TlsMaterialField>) -> bool {
    if crate::plugins::kafka_logging::contains_inline_private_key(value) {
        return true;
    }
    let Some(field) = field else {
        return false;
    };
    if value == REDACTED_PLACEHOLDER {
        return true;
    }
    if field == TlsMaterialField::Public {
        return false;
    }
    let upper = value.to_ascii_uppercase();
    upper.contains("-----BEGIN") || value.chars().any(char::is_control)
}

/// Whether a schema-declared TLS source value is withheld; a non-string fails
/// closed.
fn tls_source_withheld(value: &Value, field: TlsMaterialField) -> bool {
    value
        .as_str()
        .is_none_or(|raw| tls_material_withheld(raw, Some(field)))
}

/// Withhold stored TLS private-key material anywhere under `value`.
///
/// TLS material fields accept inline PEM as well as references. A reference
/// (a path, or a `k8s://`, `vault://`, `managed://`, `pkcs11://`, or
/// `system://` source) names material without disclosing it and stays
/// visible; a value that is or may be key material (see
/// [`tls_material_withheld`], with the field classified by
/// [`tls_material_field`]) is replaced through `rendering` at its exact JSON
/// pointer. Routing the exact placeholder at a TLS material field through the
/// renderer too lets an `operator` write that echoes it back be refused (issue
/// #5925) instead of storing `[REDACTED]` as the source.
///
/// The exact `[REDACTED]` placeholder is routed through `rendering` at every
/// string site, classified or not: a stored value this layer withholds by its
/// content alone leaves nothing to classify once it is echoed back. A
/// non-admin write that carries the literal `[REDACTED]` in any string of a
/// Proxy, Upstream, or plugin config is therefore refused, which reserves the
/// placeholder in those bodies the way it is already reserved for consumer
/// credentials.
///
/// The Proxy and Upstream projections run this over their whole body, and the
/// plugin-config projection runs it as its last layer.
pub fn withhold_tls_material_with(
    value: &mut Value,
    root_pointer: &str,
    rendering: &dyn RedactionRendering,
) {
    Projector::new(root_pointer, rendering).withhold_tls_material(value, None);
}

/// Trigger leaf predicates whose `value` operands are compared against a field
/// the client sends (`header`, `query`, `cookie`).
///
/// A client that knows such an operand can make a trigger fire or not fire at
/// will, for example skipping a `waf` instance whose trigger is
/// `not: {match: {header: {name: x-skip-waf, value: {exact: [<shared value>]}}}}`.
/// The other leaf predicates (`method`, `path`, `host`, `sni`, `protocol`,
/// `source_cidr`, `namespace`, `proxy_id`, `listen_port`, `consumer`,
/// `auth_method`, `spiffe_id`) compare routing facts or authenticated identity
/// that a client cannot simply assert, and stay visible.
pub const TRIGGER_CLIENT_FIELD_PREDICATES: &[&str] = &["header", "query", "cookie"];

/// Trigger leaf predicates that stay visible (see
/// [`TRIGGER_CLIENT_FIELD_PREDICATES`]). A leaf key in neither list is not a
/// `PluginTriggerMatch` field, so its value is withheld.
const TRIGGER_VISIBLE_PREDICATES: &[&str] = &[
    "method",
    "path",
    "host",
    "sni",
    "protocol",
    "source_cidr",
    "namespace",
    "proxy_id",
    "listen_port",
    "consumer",
    "auth_method",
    "spiffe_id",
];

/// Project a resource-level plugin `trigger` (a sibling of `config`).
///
/// Walks the whole `all` / `any` / `not` / `match` tree and withholds every
/// comparison operand (`exact[]` entries, `prefix[]` entries, `regex`) of a
/// [`TRIGGER_CLIENT_FIELD_PREDICATES`] leaf through `rendering`, so reads get
/// the placeholder, the export a fingerprint, and the write path a placeholder
/// site. Field names, `presence`, `multi_value`, `case_insensitive`, the match
/// kinds, and the tree structure stay visible. `root_pointer` is the JSON
/// pointer of the trigger inside the resource body (`/trigger`).
///
/// Like [`project_plugin_config_with`], the walk fails closed: a shape a
/// `PluginTrigger` cannot have (a non-object trigger or one without `when`, a
/// non-object node or leaf, a non-array `all` / `any`, a key the schema does
/// not define, a non-object `value`) is withheld wholesale rather than walked.
pub fn project_plugin_trigger_with(
    trigger: &mut Value,
    root_pointer: &str,
    rendering: &dyn RedactionRendering,
) {
    if trigger.is_null() {
        return;
    }
    let mut projector = Projector::new(root_pointer, rendering);
    if !trigger
        .as_object()
        .is_some_and(|map| map.contains_key("when"))
    {
        projector.apply_sensitivity(trigger, FieldSensitivity::Secret);
        return;
    }
    let Some(map) = trigger.as_object_mut() else {
        return;
    };
    for (key, child) in map.iter_mut() {
        let mark = projector.enter(key);
        if key == "when" {
            projector.project_trigger_node(child);
        } else {
            projector.apply_sensitivity(child, FieldSensitivity::Secret);
        }
        projector.leave(mark);
    }
}

/// One projection pass: the renderer, the JSON pointer of the site being
/// visited, and — for an opaque renderer — the sites already withheld.
struct Projector<'r> {
    rendering: &'r dyn RedactionRendering,
    pointer: String,
    /// Sites an opaque renderer already withheld. A later layer that matches
    /// the same site (a schema rule and then the name heuristic) leaves it
    /// alone instead of fingerprinting a fingerprint.
    withheld: HashSet<String>,
}

impl<'r> Projector<'r> {
    fn new(root_pointer: &str, rendering: &'r dyn RedactionRendering) -> Self {
        Self {
            rendering,
            pointer: root_pointer.to_string(),
            withheld: HashSet::new(),
        }
    }

    /// Descend into `segment`; returns the mark [`Projector::leave`] restores.
    fn enter(&mut self, segment: &str) -> usize {
        let mark = self.pointer.len();
        push_json_pointer_segment(&mut self.pointer, segment);
        mark
    }

    fn leave(&mut self, mark: usize) {
        self.pointer.truncate(mark);
    }

    /// Replace `value` with the renderer's form of `redacted`.
    fn render(&mut self, value: &mut Value, redacted: Value) {
        let opaque = self.rendering.renders_opaque();
        if opaque && self.withheld.contains(&self.pointer) {
            return;
        }
        let withheld = redacted != *value;
        let stored = std::mem::take(value);
        *value = self.rendering.render(&self.pointer, &stored, redacted);
        if opaque && withheld {
            self.withheld.insert(self.pointer.clone());
        }
    }

    fn apply_rule(&mut self, value: &mut Value, path: &[&str], sensitivity: FieldSensitivity) {
        let Some((head, rest)) = path.split_first() else {
            self.apply_sensitivity(value, sensitivity);
            return;
        };

        match value {
            Value::Object(map) => {
                // `*` matches every key; a named segment matches by normalized
                // spelling.
                let wanted = (*head != "*").then(|| normalize_config_key(head));
                for (key, child) in map.iter_mut() {
                    if segment_matches(wanted.as_deref(), key) {
                        let mark = self.enter(key);
                        self.apply_rule(child, rest, sensitivity);
                        self.leave(mark);
                    }
                }
            }
            Value::Array(items) => {
                // `*` names *each entry of the container*. For an array the
                // entries are the elements themselves, so the segment is
                // consumed here. Traversing transparently instead would hand
                // the same `*` to every element's own fields, and the remaining
                // path would then be resolved against sibling scalars
                // (`providers[0].name`), fail-closing values the schema never
                // named.
                //
                // A named segment traverses arrays transparently so one rule
                // covers both an object-keyed and an array-shaped container,
                // and so an array-wrapped scalar still reaches the leaf rule.
                let next = if *head == "*" { rest } else { path };
                for (index, item) in items.iter_mut().enumerate() {
                    let mark = self.enter(&index.to_string());
                    self.apply_rule(item, next, sensitivity);
                    self.leave(mark);
                }
            }
            Value::Null => {}
            // The schema expects a container here and found a scalar: legacy or
            // hostile data whose interior cannot be classified. Fail closed.
            _ => self.apply_sensitivity(value, FieldSensitivity::Secret),
        }
    }

    fn apply_sensitivity(&mut self, value: &mut Value, sensitivity: FieldSensitivity) {
        if value.is_null() {
            return;
        }
        let redacted = match sensitivity {
            FieldSensitivity::Secret => json!(REDACTED_PLACEHOLDER),
            FieldSensitivity::EndpointUrl => match value.as_str() {
                Some(raw) => json!(redact_endpoint_url(raw)),
                // A non-string where a URL belongs may nest credentials at any
                // depth (an array of objects holding signed trigger URLs), so it
                // is replaced wholesale rather than walked.
                None => json!(REDACTED_PLACEHOLDER),
            },
            FieldSensitivity::PrivateKeySource => {
                if !tls_source_withheld(value, TlsMaterialField::PrivateKey) {
                    return;
                }
                json!(REDACTED_PLACEHOLDER)
            }
            FieldSensitivity::CertificateSource => {
                if !tls_source_withheld(value, TlsMaterialField::Public) {
                    return;
                }
                json!(REDACTED_PLACEHOLDER)
            }
            FieldSensitivity::RedisUrl => match value.as_str() {
                Some(raw) => json!(redis_rate_limiter::redact_url_userinfo(raw)),
                None => json!(REDACTED_PLACEHOLDER),
            },
            FieldSensitivity::KafkaProducerProperties => match value.as_object_mut() {
                Some(props) => {
                    for (key, prop) in props.iter_mut() {
                        if !is_safe_kafka_producer_property(key) {
                            // Explicit null discloses nothing; keep it so
                            // projection does not invent a redaction marker for
                            // an unset property.
                            let mark = self.enter(key);
                            self.apply_sensitivity(prop, FieldSensitivity::Secret);
                            self.leave(mark);
                        }
                    }
                    return;
                }
                None => json!(REDACTED_PLACEHOLDER),
            },
        };
        self.render(value, redacted);
    }

    /// One trigger tree node: recurse through `all` / `any` / `not` and
    /// project each `match` leaf. Any other shape is withheld.
    fn project_trigger_node(&mut self, node: &mut Value) {
        if !node.is_object() {
            self.apply_sensitivity(node, FieldSensitivity::Secret);
            return;
        }
        let Some(map) = node.as_object_mut() else {
            return;
        };
        for (key, child) in map.iter_mut() {
            let mark = self.enter(key);
            match (key.as_str(), child) {
                ("all" | "any", Value::Array(items)) => {
                    for (index, item) in items.iter_mut().enumerate() {
                        let item_mark = self.enter(&index.to_string());
                        self.project_trigger_node(item);
                        self.leave(item_mark);
                    }
                }
                ("not", child) => self.project_trigger_node(child),
                ("match", child) => self.project_trigger_leaf(child),
                (_, child) => self.apply_sensitivity(child, FieldSensitivity::Secret),
            }
            self.leave(mark);
        }
    }

    /// One trigger `match` leaf: withhold the `value` operands of a
    /// client-presented field predicate, keep the other predicates, and
    /// withhold anything that is not a predicate.
    fn project_trigger_leaf(&mut self, leaf: &mut Value) {
        if !leaf.is_object() {
            self.apply_sensitivity(leaf, FieldSensitivity::Secret);
            return;
        }
        let Some(map) = leaf.as_object_mut() else {
            return;
        };
        for (key, predicate) in map.iter_mut() {
            if TRIGGER_VISIBLE_PREDICATES.contains(&key.as_str()) {
                continue;
            }
            let mark = self.enter(key);
            if TRIGGER_CLIENT_FIELD_PREDICATES.contains(&key.as_str()) {
                self.project_trigger_field_predicate(predicate);
            } else {
                self.apply_sensitivity(predicate, FieldSensitivity::Secret);
            }
            self.leave(mark);
        }
    }

    /// A `header` / `query` / `cookie` predicate: `name`, `presence`, and
    /// `multi_value` stay visible, `value` is projected, and anything else is
    /// withheld.
    fn project_trigger_field_predicate(&mut self, predicate: &mut Value) {
        if !predicate.is_object() {
            self.apply_sensitivity(predicate, FieldSensitivity::Secret);
            return;
        }
        let Some(map) = predicate.as_object_mut() else {
            return;
        };
        for (key, child) in map.iter_mut() {
            let mark = self.enter(key);
            match key.as_str() {
                "name" | "presence" | "multi_value" => {}
                "value" => self.project_trigger_operands(child),
                _ => self.apply_sensitivity(child, FieldSensitivity::Secret),
            }
            self.leave(mark);
        }
    }

    /// A trigger string match: every operand except a boolean
    /// `case_insensitive` flag is withheld, entry by entry for the `exact` /
    /// `prefix` lists so their length stays visible. A non-object fails closed.
    fn project_trigger_operands(&mut self, value: &mut Value) {
        if !value.is_object() {
            self.apply_sensitivity(value, FieldSensitivity::Secret);
            return;
        }
        let Some(map) = value.as_object_mut() else {
            return;
        };
        for (key, operand) in map.iter_mut() {
            if key == "case_insensitive" && operand.is_boolean() {
                continue;
            }
            let mark = self.enter(key);
            if let Value::Array(items) = operand {
                for (index, item) in items.iter_mut().enumerate() {
                    let item_mark = self.enter(&index.to_string());
                    self.apply_sensitivity(item, FieldSensitivity::Secret);
                    self.leave(item_mark);
                }
            } else {
                self.apply_sensitivity(operand, FieldSensitivity::Secret);
            }
            self.leave(mark);
        }
    }

    /// TLS-material layer; see [`withhold_tls_material_with`]. `field` is the
    /// classification of the key `value` sits under (array entries inherit
    /// it).
    fn withhold_tls_material(&mut self, value: &mut Value, field: Option<TlsMaterialField>) {
        if let Some(text) = value.as_str() {
            // Content-based withholding (a PEM private-key block in a field
            // with no TLS classification) leaves nothing in an echoed
            // `[REDACTED]` to classify, so the exact placeholder is routed
            // through the renderer at every string site: the write path then
            // refuses it wherever this layer could have masked a stored value.
            // Reads are unchanged, since the placeholder renders as itself.
            if text == REDACTED_PLACEHOLDER || tls_material_withheld(text, field) {
                self.render(value, json!(REDACTED_PLACEHOLDER));
            }
            return;
        }
        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    let mark = self.enter(key);
                    self.withhold_tls_material(child, tls_material_field(key));
                    self.leave(mark);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter_mut().enumerate() {
                    let mark = self.enter(&index.to_string());
                    self.withhold_tls_material(item, field);
                    self.leave(mark);
                }
            }
            _ => {}
        }
    }

    /// Custom-plugin header-map layer: every value of an object whose key
    /// normalizes to one of [`HEADER_MAP_KEYS`] is withheld, at any depth.
    /// An array under such a key is a header-name list and stays visible, as
    /// do the header names themselves.
    fn redact_header_maps(&mut self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    let mark = self.enter(key);
                    match child {
                        Value::Object(headers) if is_header_map_key(key) => {
                            for (name, header_value) in headers.iter_mut() {
                                let header_mark = self.enter(name);
                                self.apply_sensitivity(header_value, FieldSensitivity::Secret);
                                self.leave(header_mark);
                            }
                        }
                        other => self.redact_header_maps(other),
                    }
                    self.leave(mark);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter_mut().enumerate() {
                    let mark = self.enter(&index.to_string());
                    self.redact_header_maps(item);
                    self.leave(mark);
                }
            }
            _ => {}
        }
    }

    /// Heuristic name-based layer; see [`redact_sensitive_plugin_config_fields`].
    fn redact_by_name(&mut self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    let mark = self.enter(key);
                    if is_sensitive_plugin_config_key(key) {
                        self.apply_sensitivity(child, FieldSensitivity::Secret);
                    } else if is_credential_bearing_url_config_key(key) {
                        self.apply_sensitivity(child, FieldSensitivity::RedisUrl);
                    } else {
                        self.redact_by_name(child);
                    }
                    self.leave(mark);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter_mut().enumerate() {
                    let mark = self.enter(&index.to_string());
                    self.redact_by_name(item);
                    self.leave(mark);
                }
            }
            _ => {}
        }
    }

    /// Remove userinfo from every URL-shaped string left in the tree.
    ///
    /// The schema names the fields that are *known* to be endpoints; this
    /// sweep is the backstop for the ones it does not, including custom-plugin
    /// config. Only strings that parse as a URL *and* actually carry a username
    /// or password are rewritten, so ordinary configuration values are
    /// untouched.
    fn strip_url_userinfo(&mut self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    let mark = self.enter(key);
                    self.strip_url_userinfo(child);
                    self.leave(mark);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter_mut().enumerate() {
                    let mark = self.enter(&index.to_string());
                    self.strip_url_userinfo(item);
                    self.leave(mark);
                }
            }
            Value::String(_) => {
                if let Some(redacted) = value.as_str().and_then(url_without_userinfo) {
                    self.render(value, redacted);
                }
            }
            _ => {}
        }
    }
}

/// Whether an object key names an arbitrary header map ([`HEADER_MAP_KEYS`]).
fn is_header_map_key(key: &str) -> bool {
    HEADER_MAP_KEYS.contains(&normalize_config_key(key).as_str())
}

/// Whether an object key matches a schema path segment; `None` is `*`.
fn segment_matches(wanted: Option<&str>, key: &str) -> bool {
    wanted.is_none_or(|wanted| normalize_config_key(key) == wanted)
}

/// The userinfo-stripped form of `raw`, or `None` when it is not a URL that
/// carries a username or password.
fn url_without_userinfo(raw: &str) -> Option<Value> {
    let mut parsed = url::Url::parse(raw).ok()?;
    if parsed.username().is_empty() && parsed.password().is_none() {
        return None;
    }
    // `set_username`/`set_password` return Err for cannot-be-a-base URLs, which
    // by construction have no userinfo to strip; fail closed anyway.
    let stripped = parsed.set_username(REDACTED_USERINFO_PLACEHOLDER).is_ok()
        && parsed.set_password(None).is_ok();
    if stripped {
        Some(json!(parsed.to_string()))
    } else {
        Some(json!(REDACTED_PLACEHOLDER))
    }
}

/// Whether `value` is one of the redaction markers a projection emits in place
/// of a stored value, rather than a value anyone could mean to store (issue
/// #5925).
///
/// Every comparison is exact against a placeholder constant, so a legitimate
/// value is never matched by resemblance:
///
/// * the string is exactly [`REDACTED_PLACEHOLDER`];
/// * or it parses as a URL whose path is exactly `/` +
///   [`REDACTED_PATH_PLACEHOLDER`], whose query is exactly
///   [`REDACTED_QUERY_PLACEHOLDER`], or whose fragment is exactly
///   [`REDACTED_FRAGMENT_PLACEHOLDER`] (the structural endpoint projection);
/// * or it parses as a URL whose username is exactly
///   [`REDACTED_USERINFO_PLACEHOLDER`] with no password (the userinfo sweep
///   and the Redis URL projection).
///
/// A URL whose userinfo is literally `redacted@` with no password is therefore
/// indistinguishable from a projected one and is treated as the placeholder.
pub fn is_redaction_placeholder(value: &Value) -> bool {
    let Some(raw) = value.as_str() else {
        return false;
    };
    if raw == REDACTED_PLACEHOLDER {
        return true;
    }
    let Ok(parsed) = url::Url::parse(raw) else {
        return false;
    };
    (parsed.username() == REDACTED_USERINFO_PLACEHOLDER && parsed.password().is_none())
        || parsed.path().strip_prefix('/') == Some(REDACTED_PATH_PLACEHOLDER)
        || parsed.query() == Some(REDACTED_QUERY_PLACEHOLDER)
        || parsed.fragment() == Some(REDACTED_FRAGMENT_PLACEHOLDER)
}

/// A [`RedactionRendering`] that renders exactly like [`PlaceholderRendering`]
/// and records every site whose *incoming* value is already a redaction
/// placeholder (see [`is_redaction_placeholder`]).
///
/// Run a read projection over a write body with this renderer to find the
/// fields that would overwrite a stored secret with the marker the caller was
/// shown in its place (issue #5925). Only the first render of each site is
/// inspected: a later projection layer at the same site sees the earlier
/// layer's output (a structural URL, say), not the value the caller sent.
#[derive(Debug, Default)]
pub struct PlaceholderSiteRecorder {
    visited: RefCell<HashSet<String>>,
    sites: RefCell<Vec<String>>,
}

impl PlaceholderSiteRecorder {
    /// The JSON pointers of the sites that carried a placeholder, in the order
    /// the projection visited them.
    pub fn into_sites(self) -> Vec<String> {
        self.sites.into_inner()
    }
}

impl RedactionRendering for PlaceholderSiteRecorder {
    fn render(&self, pointer: &str, stored: &Value, redacted: Value) -> Value {
        let first_visit = self.visited.borrow_mut().insert(pointer.to_string());
        if first_visit && is_redaction_placeholder(stored) {
            self.sites.borrow_mut().push(pointer.to_string());
        }
        redacted
    }
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
/// present and may carry credentials. Original userinfo is never emitted.
/// Fails closed to [`REDACTED_PLACEHOLDER`] when the value does not parse or has no host,
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
    let mut redacted = format!("{}://", parsed.scheme());
    if !parsed.username().is_empty() || parsed.password().is_some() {
        redacted.push_str(REDACTED_USERINFO_PLACEHOLDER);
        redacted.push('@');
    }
    redacted.push_str(&host);
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
/// they disclose nothing, matching the schema layer.
pub fn redact_sensitive_plugin_config_fields(value: &mut Value) {
    Projector::new("", &PlaceholderRendering).redact_by_name(value);
}

/// Name-substring sensitivity floor.
///
/// Matching is on the fully delimiter-stripped lowercase key from
/// [`normalize_config_key`], so `apiKey`, `api-key`, `API_KEY`, `api.key`,
/// and `apikey` all match one pattern.
pub fn is_sensitive_plugin_config_key(key: &str) -> bool {
    // Config field names, not metadata keys: the listed rules only, so
    // vocabulary such as `session_ttl_seconds` stays visible (issue #6619).
    if is_sensitive_name_by_listed_rules(key) {
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
