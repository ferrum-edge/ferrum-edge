//! Central registry of plugin config fields that make the gateway use its own
//! identity: TLS certificates, keys and trust read through the shared TLS
//! source loader, gateway filesystem paths, and native library settings.
//!
//! Namespace-bounded `operator` tokens are confined by default-deny:
//!
//! - A field registered as [`ScopedReferenceClass::TlsMaterial`] admits only
//!   inline PEM, `system://`, or a `k8s://` Secret in the addressed namespace.
//! - A field registered as [`ScopedReferenceClass::GatewayOnly`] admits no
//!   newly introduced value at all.
//! - A key of a registered open map (a config object forwarded verbatim to a
//!   native library) is admitted only when it is on that map's reviewed
//!   tenant-safe list.
//!
//! An open map may also list native keys: properties that load native code,
//! run a host command, or make the gateway read one of its own files. Those
//! are refused for every token, `admin` included, unless the operator opts in
//! for the process (issue #6539; see [`open_map_native_key`]).
//! - A plugin that is not a built-in cannot be classified, so a
//!   namespace-bounded operator may not introduce or change its config.
//!
//! A value already stored at the same field path stays admitted.
//! `tests/unit/admin/scoped_reference_registry_tests.rs` fails when a
//! built-in plugin schema gains a path-, file-, certificate-, key-, module- or
//! library-shaped field that is neither registered here nor listed in
//! [`REVIEWED_NON_MATERIAL_FIELDS`].

use crate::tls::source::MaterialKind;
use serde_json::Value;

/// How the gateway uses a registered field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ScopedReferenceClass {
    /// Read through the shared TLS source loader (paths, `file://`, inline
    /// PEM, `k8s://`, secret-manager and managed sources).
    TlsMaterial(MaterialKind),
    /// A gateway filesystem path (read or written), or a native library
    /// setting. Never introduced by a namespace-bounded operator.
    GatewayOnly,
}

/// One registered field. `path` is dot-separated config keys; `name[]` walks
/// every element of an array and `*` walks every value of an object.
pub(crate) struct ScopedField {
    pub(crate) path: &'static str,
    pub(crate) class: ScopedReferenceClass,
}

/// A config object forwarded to a native library key by key.
pub(crate) struct OpenMapField {
    pub(crate) path: &'static str,
    /// Keys reviewed as tuning-only (no files, modules, commands or
    /// credentials). Compared case-insensitively.
    pub(crate) tenant_safe_keys: &'static [&'static str],
    /// `(key, what it makes the gateway do)` for keys that load native code,
    /// run a host command, or read a gateway file. Refused for every token
    /// unless the plugin's own operator opt-in is set. Compared
    /// case-insensitively. Disjoint from `tenant_safe_keys`.
    pub(crate) native_keys: &'static [(&'static str, &'static str)],
}

pub(crate) struct PluginScopedFields {
    pub(crate) plugin: &'static str,
    pub(crate) fields: &'static [ScopedField],
    pub(crate) open_maps: &'static [OpenMapField],
}

const fn tls(path: &'static str, kind: MaterialKind) -> ScopedField {
    ScopedField {
        path,
        class: ScopedReferenceClass::TlsMaterial(kind),
    }
}

const fn gateway_only(path: &'static str) -> ScopedField {
    ScopedField {
        path,
        class: ScopedReferenceClass::GatewayOnly,
    }
}

/// librdkafka producer properties reviewed as tuning-only.
const KAFKA_TENANT_SAFE_PRODUCER_KEYS: &[&str] = &[
    "acks",
    "request.required.acks",
    "batch.num.messages",
    "batch.size",
    "client.id",
    "compression.codec",
    "compression.level",
    "compression.type",
    "enable.idempotence",
    "linger.ms",
    "max.in.flight",
    "max.in.flight.requests.per.connection",
    "message.max.bytes",
    "message.send.max.retries",
    "message.timeout.ms",
    "queue.buffering.max.kbytes",
    "queue.buffering.max.messages",
    "queue.buffering.max.ms",
    "request.timeout.ms",
    "retries",
    "retry.backoff.max.ms",
    "retry.backoff.ms",
    "socket.keepalive.enable",
    "socket.timeout.ms",
    "topic.metadata.refresh.interval.ms",
];

/// librdkafka properties that load native code, run a host command, or make
/// the gateway read one of its own files (issue #6539).
///
/// Audited against `CONFIGURATION.md` of the pinned librdkafka 2.12.1
/// (`rdkafka-sys 4.10.0+2.12.1`). None of these properties has an alias there.
/// Properties that already have a top-level field (`ssl.ca.location`,
/// `ssl.certificate.location`, `ssl.key.location`, `ssl.keystore.location`,
/// `ssl.ca.certificate.stores`) are refused outright by `kafka_logging`, and
/// `ssl.crl.location` keeps its own contract there: it is read only as a CRL
/// and must match the gateway CRL file when one is configured.
pub(crate) const KAFKA_NATIVE_PRODUCER_KEYS: &[(&str, &str)] = &[
    (
        "plugin.library.paths",
        "loads shared libraries into the gateway process",
    ),
    ("ssl.engine.location", "loads an OpenSSL engine library"),
    ("ssl.engine.id", "loads an OpenSSL engine by name"),
    ("ssl.providers", "loads OpenSSL provider modules"),
    (
        "sasl.kerberos.kinit.cmd",
        "runs a shell command on the gateway host",
    ),
    (
        "sasl.kerberos.keytab",
        "makes the Kerberos kinit command read a gateway keytab file",
    ),
    (
        "sasl.oauthbearer.assertion.private.key.file",
        "signs OAuth assertions with a gateway private key file",
    ),
    (
        "sasl.oauthbearer.assertion.file",
        "sends a gateway file to the OAuth token endpoint",
    ),
    (
        "sasl.oauthbearer.assertion.jwt.template.file",
        "reads a gateway file into the OAuth assertion",
    ),
    ("https.ca.location", "reads a gateway CA file or directory"),
    (
        "offset.store.path",
        "writes offset files on the gateway host",
    ),
];

/// Every built-in plugin field that names gateway-resolved material.
pub(crate) const PLUGIN_SCOPED_FIELDS: &[PluginScopedFields] = &[
    PluginScopedFields {
        plugin: "mesh_route_dispatch",
        fields: &[
            tls(
                "rules[].destination.backend_tls.client_cert_path",
                MaterialKind::Cert,
            ),
            tls(
                "rules[].destination.backend_tls.client_key_path",
                MaterialKind::Key,
            ),
            tls(
                "rules[].destination.backend_tls.server_ca_cert_path",
                MaterialKind::CaBundle,
            ),
        ],
        open_maps: &[],
    },
    PluginScopedFields {
        plugin: "udp_logging",
        fields: &[
            tls("dtls_cert_path", MaterialKind::Cert),
            tls("dtls_key_path", MaterialKind::Key),
            tls("dtls_ca_cert_path", MaterialKind::CaBundle),
        ],
        open_maps: &[],
    },
    PluginScopedFields {
        plugin: "soap_ws_security",
        fields: &[
            tls("x509_signature.trusted_certs[]", MaterialKind::Cert),
            tls("saml.trusted_signing_certs[]", MaterialKind::Cert),
        ],
        open_maps: &[],
    },
    PluginScopedFields {
        plugin: "kafka_logging",
        // librdkafka reads these as local filenames.
        fields: &[
            gateway_only("ssl_certificate_location"),
            gateway_only("ssl_key_location"),
            gateway_only("ssl_ca_location"),
        ],
        open_maps: &[OpenMapField {
            path: "producer_config",
            tenant_safe_keys: KAFKA_TENANT_SAFE_PRODUCER_KEYS,
            native_keys: KAFKA_NATIVE_PRODUCER_KEYS,
        }],
    },
    PluginScopedFields {
        plugin: "api_chargeback_sink",
        fields: &[
            gateway_only("clickhouse.tls.ca_file"),
            gateway_only("clickhouse.tls.client_cert_file"),
            gateway_only("clickhouse.tls.client_key_file"),
            gateway_only("spool.dir"),
        ],
        open_maps: &[],
    },
    PluginScopedFields {
        plugin: "ai_response_guard",
        fields: &[gateway_only("grpc.descriptor_path")],
        open_maps: &[],
    },
    PluginScopedFields {
        plugin: "ai_transcript_audit",
        fields: &[gateway_only("grpc.descriptor_path")],
        open_maps: &[],
    },
    PluginScopedFields {
        plugin: "body_validator",
        fields: &[gateway_only("protobuf_descriptor_path")],
        open_maps: &[],
    },
    PluginScopedFields {
        plugin: "geo_restriction",
        fields: &[gateway_only("db_path")],
        open_maps: &[],
    },
];

/// Built-in plugin fields whose names look path-, key- or provider-shaped but
/// that name no gateway file, credential store or native module: URL paths,
/// header and cache key names, inline PEM, provider kinds, or values the
/// gateway sends without reading anything with its own identity.
pub(crate) const REVIEWED_NON_MATERIAL_FIELDS: &[(&str, &str)] = &[
    ("a2a_gateway", "endpoint.path"),
    ("a2a_gateway", "endpoint.agent_card_path"),
    ("adaptive_concurrency", "key_by"),
    ("ai_federation", "providers"),
    ("ai_federation", "providers[].provider_type"),
    ("ai_federation", "providers[].api_key"),
    ("ai_federation", "providers[].aws_access_key_id"),
    ("ai_federation", "providers[].aws_secret_access_key"),
    ("ai_federation", "fail_on_no_matching_provider"),
    ("ai_rate_limiter", "provider"),
    ("ai_rate_limiter", "redis_key_prefix"),
    ("ai_semantic_cache", "include_model_in_key"),
    ("ai_semantic_cache", "include_params_in_key"),
    ("ai_semantic_cache", "semantic_embedding_provider"),
    ("ai_semantic_cache", "semantic_embedding_api_key"),
    ("ai_semantic_cache", "redis_key_prefix"),
    ("ai_semantic_cache", "redis_integrity_key"),
    ("ai_semantic_firewall", "provider"),
    // Environment references are limited to `FERRUM_PLUGIN_SECRET_*`.
    ("ai_semantic_firewall", "provider.api_key_env"),
    ("ai_semantic_firewall", "extraction.request_json_paths"),
    ("ai_semantic_firewall", "extraction.response_json_paths"),
    ("ai_stream_router", "fail_on_no_matching_provider"),
    ("ai_stream_router", "providers"),
    ("ai_stream_router", "providers[].provider_type"),
    ("ai_stream_router", "providers[].api_key"),
    ("ai_token_metrics", "provider"),
    ("ai_transcript_audit", "capture.mcp_endpoint_path"),
    ("ai_transcript_audit", "privacy.path_mode"),
    ("graphql", "redis_key_prefix"),
    ("grpc_method_router", "redis_key_prefix"),
    ("hmac_auth", "redis_key_prefix"),
    ("jwks_auth", "providers"),
    ("jwks_auth", "redis_key_prefix"),
    ("kafka_logging", "key_field"),
    ("key_auth", "key_location"),
    ("load_testing", "key"),
    ("mcp_gateway", "endpoint.path"),
    ("mcp_gateway", "servers.*.openapi.operations[].path"),
    (
        "mesh_authz",
        "mesh_policies[].rules[].action.custom.provider",
    ),
    ("mesh_authz", "mesh_policies[].rules[].to[].paths"),
    ("mesh_authz", "mesh_policies[].rules[].to[].not_paths"),
    ("mesh_authz", "mesh_policies[].rules[].when[].key"),
    (
        "mesh_route_dispatch",
        "rules[].destination.backend_tls.verify_server_cert",
    ),
    ("mesh_route_dispatch", "rules[].request_transform[].key"),
    ("mesh_route_dispatch", "rules[].response_transform[].key"),
    ("mtls_auth", "cert_field"),
    // Inline PEM only; never a reference.
    ("mtls_auth", "allowed_issuers[].ca_certificate_pem"),
    ("mtls_auth", "allowed_ca_fingerprints_sha256"),
    ("oauth2_introspection", "providers"),
    // Inline PEM only; never a reference.
    (
        "oauth2_introspection",
        "providers[].client_auth.private_key_pem",
    ),
    (
        "oauth2_introspection",
        "providers[].client_auth.private_key_jwt_alg",
    ),
    (
        "oauth2_introspection",
        "providers[].client_auth.private_key_jwt_kid",
    ),
    ("oauth2_introspection", "allow_provider_fanout"),
    ("oidc_relying_party", "providers"),
    // Inline PEM only; never a reference.
    (
        "oidc_relying_party",
        "providers[].client_auth.private_key_pem",
    ),
    (
        "oidc_relying_party",
        "providers[].client_auth.private_key_jwt_alg",
    ),
    (
        "oidc_relying_party",
        "providers[].client_auth.private_key_jwt_kid",
    ),
    ("oidc_relying_party", "providers[].callback_path"),
    ("oidc_relying_party", "providers[].logout_path"),
    ("oidc_relying_party", "session.path"),
    ("oidc_relying_party", "behavior.post_login_default_path"),
    ("opa", "policy_path"),
    ("opa", "include_path"),
    ("openapi_validator", "operations[].path_template"),
    ("openapi_validator", "operations[].path_regex"),
    ("openapi_validator", "bypass.paths"),
    ("otel_tracing", "include_url_path"),
    ("rate_limiting", "mcp_tool_calls.endpoint_path"),
    ("rate_limiting", "redis_key_prefix"),
    ("request_deduplication", "redis_key_prefix"),
    ("request_mirror", "mirror_path"),
    ("request_termination", "trigger.path_prefix"),
    ("request_transformer", "rules[].key"),
    ("request_transformer", "rules[].new_key"),
    ("response_caching", "cache_key_include_query"),
    ("response_caching", "cache_key_include_consumer"),
    ("response_mock", "rules[].path"),
    ("response_transformer", "rules[].key"),
    ("response_transformer", "rules[].new_key"),
    ("serverless_function", "provider"),
    ("serverless_function", "aws_access_key_id"),
    ("serverless_function", "aws_secret_access_key"),
    ("serverless_function", "azure_function_key"),
    ("soap_ws_security", "redis_key_prefix"),
    ("tcp_connection_throttle", "max_connections_per_key"),
    ("udp_rate_limiting", "redis_key_prefix"),
    ("waf", "rule_overrides.*.conditions.paths"),
    ("waf", "custom_rules[].target.path"),
    ("waf", "custom_rules[].conditions.paths"),
    ("waf", "global_exemptions.paths"),
    ("workload_metrics", "tracing_providers"),
    ("workload_metrics", "tracing_provider"),
    ("ws_rate_limiting", "redis_key_prefix"),
];

/// The registry entry for `plugin`, when it has registered fields.
pub(crate) fn plugin_scoped_fields(plugin: &str) -> Option<&'static PluginScopedFields> {
    PLUGIN_SCOPED_FIELDS
        .iter()
        .find(|entry| entry.plugin == plugin)
}

/// What a native key of `plugin`'s open map at `map_path` makes the gateway
/// do, or `None` when `key` is not a registered native key (issue #6539).
///
/// The plugin's admission refuses such a key for every token unless its
/// operator opt-in is set. A namespace-bounded operator cannot introduce or
/// change one even then, because no native key is tenant-safe.
pub(crate) fn open_map_native_key(plugin: &str, map_path: &str, key: &str) -> Option<&'static str> {
    // librdkafka also accepts a topic property at the global level under a
    // `topic.` prefix, which it strips (`rd_kafka_conf_set`). Match both
    // spellings so the prefix cannot bypass the gate.
    let key = match key.get(..6) {
        Some(prefix) if prefix.eq_ignore_ascii_case("topic.") => &key[6..],
        _ => key,
    };
    plugin_scoped_fields(plugin)?
        .open_maps
        .iter()
        .find(|map| map.path == map_path)?
        .native_keys
        .iter()
        .find(|(native, _)| native.eq_ignore_ascii_case(key))
        .map(|(_, effect)| *effect)
}

/// Whether the registry can classify `plugin` at all: every built-in is
/// classified (registered fields, reviewed fields, or none), a custom plugin
/// is not.
pub(crate) fn plugin_is_classified(plugin: &str) -> bool {
    crate::plugins::BUILTIN_PLUGIN_REGISTRATIONS
        .iter()
        .any(|registration| registration.name == plugin)
}

/// Concrete `(config.<path>, value, class)` references in `config`.
pub(crate) fn plugin_scoped_references<'a>(
    plugin: &str,
    config: &'a Value,
) -> Vec<(String, &'a str, ScopedReferenceClass)> {
    let Some(entry) = plugin_scoped_fields(plugin) else {
        return Vec::new();
    };
    let mut references = Vec::new();
    for field in entry.fields {
        let segments: Vec<&str> = field.path.split('.').collect();
        let mut found = Vec::new();
        collect_values(config, &segments, "config".to_string(), &mut found);
        for (path, value) in found {
            if let Some(value) = value.as_str() {
                references.push((path, value, field.class));
            }
        }
    }
    for map in entry.open_maps {
        let segments: Vec<&str> = map.path.split('.').collect();
        let mut found = Vec::new();
        collect_values(config, &segments, "config".to_string(), &mut found);
        for (path, value) in found {
            let Some(object) = value.as_object() else {
                continue;
            };
            for (key, value) in object {
                let safe = map
                    .tenant_safe_keys
                    .iter()
                    .any(|safe| safe.eq_ignore_ascii_case(key));
                if safe {
                    continue;
                }
                // Non-string values are refused by plugin validation; an
                // empty marker still keys the exemption on the exact value.
                let value = value.as_str().unwrap_or("");
                references.push((
                    format!("{path}.{key}"),
                    value,
                    ScopedReferenceClass::GatewayOnly,
                ));
            }
        }
    }
    references
}

fn collect_values<'a>(
    value: &'a Value,
    segments: &[&str],
    prefix: String,
    out: &mut Vec<(String, &'a Value)>,
) {
    let Some((first, rest)) = segments.split_first() else {
        out.push((prefix, value));
        return;
    };
    let (name, array) = match first.strip_suffix("[]") {
        Some(name) => (name, true),
        None => (*first, false),
    };
    let children: Vec<(String, &'a Value)> = if name == "*" {
        value
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .map(|(key, child)| (format!("{prefix}.{key}"), child))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        value
            .get(name)
            .map(|child| vec![(format!("{prefix}.{name}"), child)])
            .unwrap_or_default()
    };
    for (path, child) in children {
        match child.as_array() {
            Some(items) if array => {
                for (index, item) in items.iter().enumerate() {
                    collect_values(item, rest, format!("{path}[{index}]"), out);
                }
            }
            _ => collect_values(child, rest, path, out),
        }
    }
}
