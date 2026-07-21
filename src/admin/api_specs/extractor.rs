//! OpenAPI/Swagger spec parser and Ferrum resource extractor.
//!
//! Parses an OpenAPI 2.0 (Swagger), 3.0.x, 3.1.x, or 3.2.x spec document
//! (JSON or YAML) and extracts Ferrum-native resources from the
//! `x-ferrum-proxy`, `x-ferrum-upstream`, and `x-ferrum-plugins` extensions.
//!
//! # Extension protocol
//!
//! - `x-ferrum-proxy` (required): serialised [`Proxy`] object.
//! - `x-ferrum-upstream` (optional): serialised [`Upstream`] object.
//! - `x-ferrum-plugins` (optional): array of serialised [`PluginConfig`] objects.
//! - `x-ferrum-consumers` (forbidden): rejected with [`ExtractError::ConsumerExtensionNotAllowed`].
//!
//! The caller's `namespace` overrides any namespace embedded in the spec.
//! All plugins are forced to `scope = proxy` and `proxy_id = proxy.id`.

// Re-export so Wave 3 handlers can `use crate::admin::api_specs::SpecFormat`
// without knowing that the canonical definition lives in config::types.
pub use crate::config::types::SpecFormat;
use crate::config::types::{
    MAX_OPENAPI_VALIDATOR_CONFIG_DEPTH, MAX_OPENAPI_VALIDATOR_CONFIG_SIZE,
    OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES, json_depth, validate_resource_id,
};
use crate::config::types::{PluginAssociation, PluginConfig, PluginScope, Proxy, Upstream};
use chrono::Utc;
use serde_json::{Map, Value, json};

/// HTTP method keys counted when computing `operation_count`.
const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "delete", "options", "head", "patch", "trace",
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Resources extracted from an OpenAPI spec document.
#[derive(Debug, Clone)]
pub struct ExtractedBundle {
    pub proxy: Proxy,
    pub upstream: Option<Upstream>,
    pub plugins: Vec<PluginConfig>,
}

/// Metadata about the OpenAPI spec document itself (not the extracted resources).
#[derive(Debug, Clone)]
pub struct SpecMetadata {
    /// Spec language version: `"2.0"`, `"3.0.3"`, `"3.1.0"`, `"3.2.0"`, etc.
    pub version: String,
    pub format: SpecFormat,
    /// `info.title` from the spec, if present and a string.
    pub title: Option<String>,
    /// `info.version` from the spec, if present and a string.
    pub info_version: Option<String>,
    // --- Tier 1 metadata (Wave 5) ---
    /// `info.description` truncated at 4096 bytes (UTF-8-safe).
    pub description: Option<String>,
    /// `info.contact.name`
    pub contact_name: Option<String>,
    /// `info.contact.email`
    pub contact_email: Option<String>,
    /// `info.license.name`
    pub license_name: Option<String>,
    /// `info.license.identifier` (3.1+) or `info.license.url` fallback.
    pub license_identifier: Option<String>,
    /// Top-level `tags[].name`, de-duplicated and sorted.
    pub tags: Vec<String>,
    /// Server URLs (`servers[].url` for 3.x; constructed from `schemes + host + basePath` for 2.0).
    pub server_urls: Vec<String>,
    /// Count of HTTP method keys across all `paths.*` entries.
    pub operation_count: u32,
}

/// Errors that can occur during spec extraction.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("invalid YAML: {0}")]
    InvalidYaml(String),
    #[error("unknown spec version (expected 'swagger: \"2.0\"' or 'openapi: \"3.x.y\"')")]
    UnknownVersion,
    #[error("missing required x-ferrum-proxy extension at root")]
    MissingProxyExtension,
    #[error("malformed {which} extension: {error}")]
    MalformedExtension { which: &'static str, error: String },
    #[error("consumers cannot be created via spec; use POST /consumers")]
    ConsumerExtensionNotAllowed,
    #[error(
        "plugin {plugin_id}: only proxy-scoped plugins are allowed in specs (got scope='{scope}')"
    )]
    PluginInvalidScope { plugin_id: String, scope: String },
    #[error(
        "plugin {plugin_id}: proxy_id mismatch (plugin has '{plugin_proxy_id}', spec has '{spec_proxy_id}')"
    )]
    PluginProxyIdMismatch {
        plugin_id: String,
        plugin_proxy_id: String,
        spec_proxy_id: String,
    },
    #[error("plugin {plugin_id} contains forbidden credential/consumer key '{key}'")]
    PluginContainsCredentials { plugin_id: String, key: String },
    #[error(
        "proxy {proxy_id}: upstream_id '{proxy_upstream_id}' conflicts with x-ferrum-upstream id '{spec_upstream_id}'"
    )]
    ProxyUpstreamIdMismatch {
        proxy_id: String,
        proxy_upstream_id: String,
        spec_upstream_id: String,
    },
    /// Tag name contains a character that would cause false LIKE matches in the
    /// SQL `has_tag` filter (`"`, `%`, `_`, or `\`).  Tag names with these
    /// characters are rejected at extraction time rather than escaping them at
    /// query time, because tag names are short identifiers and these characters
    /// have no legitimate use in them.  Note that `_` is also a single-character
    /// SQL LIKE wildcard, so `?has_tag=api_v1` would otherwise falsely match
    /// `apixv1`. See `db_loader.rs` `list_api_specs` `has_tag` branch for the
    /// matching LIKE pattern.
    #[error("tag '{name}' contains forbidden character '{char}' (\", %, _, or \\\\)")]
    InvalidTagName { name: String, char: char },
    #[error("external $ref '{reference}' is not supported in x-ferrum-validate schemas")]
    UnsupportedExternalRef { reference: String },
    #[error("schema reference depth exceeded while resolving '{location}'")]
    SchemaTooDeep { location: String },
}

// ---------------------------------------------------------------------------
// OpenAPI 3.x version-string matcher
// ---------------------------------------------------------------------------

/// Returns `true` iff `s` is a valid SemVer string for OpenAPI 3.x.
fn is_openapi3_version(s: &str) -> bool {
    semver::Version::parse(s).is_ok_and(|version| version.major == 3)
}

/// Plugin config keys that are forbidden inside a plugin's `config` value.
/// The walk is recursive; finding any of these keys at any depth is an error.
const FORBIDDEN_CONFIG_KEYS: &[&str] = &[
    "credentials",
    "keyauth",
    "basicauth",
    "jwt",
    "hmac",
    "mtls",
    "consumer",
    "consumer_id",
    "consumer_groups",
    "consumers",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sniff whether `body` looks like JSON or YAML by inspecting the first
/// non-whitespace byte.
///
/// JSON documents always start with `{` or `[`; YAML docs start with
/// a letter or `---`. The byte sniff is a best-effort heuristic; the full
/// parse will produce a more precise error if the bytes are invalid.
pub fn autodetect_format(body: &[u8]) -> SpecFormat {
    let first = body.iter().find(|&&b| !b.is_ascii_whitespace());
    match first {
        Some(b'{') | Some(b'[') => SpecFormat::Json,
        _ => SpecFormat::Yaml,
    }
}

/// Parse `body` as an OpenAPI spec document and extract Ferrum resources.
///
/// # Arguments
///
/// * `body` – raw bytes of the spec document.
/// * `declared_format` – caller-supplied format hint (`Content-Type` header).
///   When `None`, [`autodetect_format`] is used.
/// * `namespace` – the namespace to stamp on every extracted resource,
///   overriding whatever the spec document declares.
///
/// # Returns
///
/// `(bundle, metadata)` on success, or an [`ExtractError`] describing the
/// first problem encountered.
pub fn extract(
    body: &[u8],
    declared_format: Option<SpecFormat>,
    namespace: &str,
) -> Result<(ExtractedBundle, SpecMetadata), ExtractError> {
    let (root, actual_format) = parse_root_document(body, declared_format)?;

    // --- Version detection -----------------------------------------------
    let version = detect_version(&root)?;

    // --- info.title / info.version ---------------------------------------
    // Both fields are truncated at UTF-8 character boundaries so an operator
    // with a 25 MiB spec cannot store a 1 MiB title or version string.
    // `description` was already bounded to 4096 bytes in `extract_spec_metadata`.
    let title = root
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, 1024)); // titles are short identifiers

    let info_version = root
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, 256)); // version strings are short

    // --- Tier 1 metadata (Wave 5) ----------------------------------------
    let tier1 = extract_spec_metadata(&root, &version);

    // --- Tag name validation ---------------------------------------------
    // SAFETY-CRITICAL CROSS-FILE INVARIANT:
    // The SQL `has_tag` filter in src/config/db_loader.rs uses a bare LIKE
    // pattern (`tags LIKE '%"<tag>"%'`) that embeds tag names directly without
    // an ESCAPE clause.  Tag names containing `"`, `%`, `_`, or `\` would
    // produce false matches or wildcard matches against the stored JSON-array
    // column.  In particular, `_` is the SQL LIKE single-character wildcard:
    // without rejecting it, `?has_tag=api_v1` would falsely match `apixv1`.
    // We reject those characters here to keep the LIKE filter correct.
    // MongoDB uses native array membership (`filter_doc.insert("tags", tag)`)
    // and is unaffected, but we still reject these characters for consistency.
    //
    // If you change or extend this tag-character whitelist, also update:
    //   src/config/db_loader.rs  — list_api_specs, has_tag branch (comment there)
    //   docs/api_specs.md        — "Tag-name rules" section
    for tag in &tier1.tags {
        for ch in ['"', '%', '_', '\\'] {
            if tag.contains(ch) {
                return Err(ExtractError::InvalidTagName {
                    name: tag.clone(),
                    char: ch,
                });
            }
        }
    }

    // --- x-ferrum-consumers guard ----------------------------------------
    if root.get("x-ferrum-consumers").is_some() {
        return Err(ExtractError::ConsumerExtensionNotAllowed);
    }

    // --- x-ferrum-proxy (required) ---------------------------------------
    let proxy_val = root
        .get("x-ferrum-proxy")
        .ok_or(ExtractError::MissingProxyExtension)?;

    let mut proxy: Proxy = serde_json::from_value(proxy_val.clone()).map_err(|e| {
        ExtractError::MalformedExtension {
            which: "x-ferrum-proxy",
            error: e.to_string(),
        }
    })?;
    proxy.namespace = namespace.to_string();

    // --- ID validation for proxy (BEFORE auto-linking) ----------------------
    // Non-empty id → validate format; malformed ids are rejected here rather
    // than at the DB layer so the error message is actionable.
    // Empty id → leave empty; the route handler (assign_ids_for_post /
    // assign_ids_for_put) is responsible for assigning or reusing IDs so that
    // PUT idempotency works correctly.
    if !proxy.id.is_empty()
        && let Err(e) = validate_resource_id(&proxy.id)
    {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-proxy",
            error: format!("invalid id: {}", e),
        });
    }

    // --- x-ferrum-upstream (optional) ------------------------------------
    let upstream = if let Some(up_val) = root.get("x-ferrum-upstream") {
        let mut up: Upstream = serde_json::from_value(up_val.clone()).map_err(|e| {
            ExtractError::MalformedExtension {
                which: "x-ferrum-upstream",
                error: e.to_string(),
            }
        })?;
        up.namespace = namespace.to_string();

        // --- ID validation for upstream (BEFORE auto-linking) ---------------
        // Empty id → leave empty; handler assigns / reuses IDs.
        if !up.id.is_empty()
            && let Err(e) = validate_resource_id(&up.id)
        {
            return Err(ExtractError::MalformedExtension {
                which: "x-ferrum-upstream",
                error: format!("invalid id: {}", e),
            });
        }

        Some(up)
    } else {
        None
    };

    // --- Auto-link upstream to proxy ----------------------------------------
    // If the spec includes an upstream, set proxy.upstream_id to the upstream's
    // id unless the operator already pinned a different one (which is an error).
    if let Some(ref u) = upstream {
        match proxy.upstream_id.as_deref() {
            None => proxy.upstream_id = Some(u.id.clone()),
            Some(existing) if existing == u.id => {} // explicit + same → ok
            Some(existing) => {
                return Err(ExtractError::ProxyUpstreamIdMismatch {
                    proxy_id: proxy.id.clone(),
                    proxy_upstream_id: existing.to_string(),
                    spec_upstream_id: u.id.clone(),
                });
            }
        }
    }

    // --- x-ferrum-plugins (optional array) --------------------------------
    let mut plugins = if let Some(plugins_val) = root.get("x-ferrum-plugins") {
        let arr = plugins_val
            .as_array()
            .ok_or_else(|| ExtractError::MalformedExtension {
                which: "x-ferrum-plugins",
                error: "expected an array".to_string(),
            })?;

        let mut out = Vec::with_capacity(arr.len());
        for entry in arr {
            // Default scope to "proxy" when the spec omits it — proxy-scope
            // is the only allowed value here (enforced below), so requiring
            // explicit `scope: proxy` everywhere would just be friction.
            // Explicit non-proxy scopes still fail downstream with a clear
            // error.
            let mut entry_with_default = entry.clone();
            if let Some(map) = entry_with_default.as_object_mut() {
                map.entry("scope".to_string())
                    .or_insert(serde_json::Value::String("proxy".to_string()));
            }

            let mut pc: PluginConfig = serde_json::from_value(entry_with_default).map_err(|e| {
                ExtractError::MalformedExtension {
                    which: "x-ferrum-plugins",
                    error: e.to_string(),
                }
            })?;

            // --- ID validation for plugin (BEFORE auto-linking) -------------
            // Empty id → leave empty; handler assigns / reuses IDs.
            if !pc.id.is_empty()
                && let Err(e) = validate_resource_id(&pc.id)
            {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-plugins",
                    error: format!("invalid id: {}", e),
                });
            }

            // Scope must be proxy (or absent/defaulted to proxy).
            if pc.scope != PluginScope::Proxy {
                let scope_str = match pc.scope {
                    PluginScope::Global => "global".to_string(),
                    PluginScope::ProxyGroup => "proxy_group".to_string(),
                    PluginScope::Proxy => "proxy".to_string(),
                };
                return Err(ExtractError::PluginInvalidScope {
                    plugin_id: pc.id,
                    scope: scope_str,
                });
            }

            // proxy_id must be absent or match the spec's proxy id.
            if let Some(ref pid) = pc.proxy_id
                && pid != &proxy.id
            {
                return Err(ExtractError::PluginProxyIdMismatch {
                    plugin_id: pc.id,
                    plugin_proxy_id: pid.clone(),
                    spec_proxy_id: proxy.id.clone(),
                });
            }

            // Walk config for forbidden credential / consumer keys.
            if let Some(key) = find_forbidden_key_for_plugin(&pc.plugin_name, &pc.config) {
                return Err(ExtractError::PluginContainsCredentials {
                    plugin_id: pc.id,
                    key: key.to_string(),
                });
            }

            // Reject duplicate non-empty plugin IDs within the same spec.
            if !pc.id.is_empty()
                && out
                    .iter()
                    .any(|existing: &PluginConfig| existing.id == pc.id)
            {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-plugins",
                    error: format!("duplicate plugin id '{}'", pc.id),
                });
            }

            // Stamp namespace and link to proxy.
            pc.namespace = namespace.to_string();
            pc.proxy_id = Some(proxy.id.clone());

            out.push(pc);
        }
        out
    } else {
        Vec::new()
    };

    if let Some(validate_ext) = parse_x_ferrum_validate_extension(&root)? {
        let operations = extract_operation_schemas(&root, &version)?;
        auto_inject_openapi_validator(
            &mut plugins,
            &proxy,
            namespace,
            validate_ext,
            operations,
            &version,
        )?;
    }

    // --- Build proxy.plugins association list (Fix 2) -----------------------
    // The PluginCache only instantiates plugins whose IDs appear in the proxy's
    // `plugins` association list (junction table). Without this step, imported
    // plugins are stored in plugin_configs but never run.
    // Preserve any associations the operator wrote into x-ferrum-proxy.plugins
    // directly (e.g. associating an existing global plugin), then add the
    // spec-extracted ones.
    {
        let mut associations = std::mem::take(&mut proxy.plugins);
        for plugin in &plugins {
            if !associations.iter().any(|a| a.plugin_config_id == plugin.id) {
                associations.push(PluginAssociation {
                    plugin_config_id: plugin.id.clone(),
                });
            }
        }
        proxy.plugins = associations;
    }

    let metadata = SpecMetadata {
        version,
        format: actual_format,
        title,
        info_version,
        description: tier1.description,
        contact_name: tier1.contact_name,
        contact_email: tier1.contact_email,
        license_name: tier1.license_name,
        license_identifier: tier1.license_identifier,
        tags: tier1.tags,
        server_urls: tier1.server_urls,
        operation_count: tier1.operation_count,
    };

    Ok((
        ExtractedBundle {
            proxy,
            upstream,
            plugins,
        },
        metadata,
    ))
}

/// Return plugin IDs explicitly listed in `x-ferrum-proxy.plugins`.
///
/// This deliberately ignores associations auto-added from `x-ferrum-plugins`.
/// Replacement code uses it to distinguish associations owned by the previous
/// spec document from associations an operator added later through direct CRUD.
pub fn extract_declared_proxy_plugin_association_ids(
    body: &[u8],
    declared_format: Option<SpecFormat>,
) -> Result<Vec<String>, ExtractError> {
    let (root, _) = parse_root_document(body, declared_format)?;
    let Some(proxy_val) = root.get("x-ferrum-proxy") else {
        return Ok(Vec::new());
    };
    let Some(plugins_val) = proxy_val.get("plugins") else {
        return Ok(Vec::new());
    };
    let arr = plugins_val
        .as_array()
        .ok_or_else(|| ExtractError::MalformedExtension {
            which: "x-ferrum-proxy.plugins",
            error: "expected an array".to_string(),
        })?;

    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let assoc: PluginAssociation = serde_json::from_value(entry.clone()).map_err(|e| {
            ExtractError::MalformedExtension {
                which: "x-ferrum-proxy.plugins",
                error: e.to_string(),
            }
        })?;
        if !assoc.plugin_config_id.is_empty() && !out.iter().any(|id| id == &assoc.plugin_config_id)
        {
            out.push(assoc.plugin_config_id);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Public helpers — metadata extraction + resource hashing
// ---------------------------------------------------------------------------

/// Intermediate result from [`extract_spec_metadata`].
pub struct ExtractedMetadata {
    pub description: Option<String>,
    pub contact_name: Option<String>,
    pub contact_email: Option<String>,
    pub license_name: Option<String>,
    pub license_identifier: Option<String>,
    pub tags: Vec<String>,
    pub server_urls: Vec<String>,
    pub operation_count: u32,
}

fn parse_x_ferrum_validate_extension(root: &Value) -> Result<Option<Value>, ExtractError> {
    let Some(value) = root.get("x-ferrum-validate") else {
        return Ok(None);
    };
    match value {
        Value::Bool(true) => Ok(Some(json!({}))),
        Value::Bool(false) | Value::Null => Ok(None),
        Value::Object(_) => Ok(Some(value.clone())),
        other => Err(ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!("expected true, false, or object; got {other}"),
        }),
    }
}

fn auto_inject_openapi_validator(
    plugins: &mut Vec<PluginConfig>,
    proxy: &Proxy,
    namespace: &str,
    validate_ext: Value,
    operations: Vec<Value>,
    version: &str,
) -> Result<(), ExtractError> {
    let mut config = Map::new();
    config.insert(
        "enforcement_mode".to_string(),
        Value::String("block".to_string()),
    );
    config.insert("validate_request".to_string(), Value::Bool(true));
    config.insert("validate_response".to_string(), Value::Bool(true));
    config.insert(
        "request_content_types".to_string(),
        json!(OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES),
    );
    config.insert(
        "response_content_types".to_string(),
        json!(OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES),
    );
    config.insert("fail_on_unknown_operation".to_string(), Value::Bool(true));
    config.insert(
        "fail_on_missing_response_schema".to_string(),
        Value::Bool(false),
    );
    config.insert(
        "schema_draft".to_string(),
        Value::String(schema_draft_for_openapi(version)),
    );
    apply_validate_extension(&mut config, validate_ext)?;
    config.insert("operations".to_string(), Value::Array(operations));

    let auto_config = Value::Object(config);
    if let Some(existing) = plugins
        .iter_mut()
        .find(|plugin| plugin.plugin_name == "openapi_validator")
    {
        let merged = merge_openapi_validator_config(auto_config, &existing.config)?;
        validate_openapi_validator_config_budget(&merged)?;
        existing.config = merged;
        return Ok(());
    }

    validate_openapi_validator_config_budget(&auto_config)?;
    let now = Utc::now();
    plugins.push(PluginConfig {
        id: String::new(),
        plugin_name: "openapi_validator".to_string(),
        namespace: namespace.to_string(),
        config: auto_config,
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy.id.clone()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    });
    Ok(())
}

fn schema_draft_for_openapi(version: &str) -> String {
    if version == "2.0" || version.starts_with("3.0.") {
        "draft7".to_string()
    } else {
        "draft2020-12".to_string()
    }
}

fn validate_openapi_validator_config_budget(config: &Value) -> Result<(), ExtractError> {
    let size = serde_json::to_vec(config)
        .map_err(|error| ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!("generated openapi_validator config could not be serialized: {error}"),
        })?
        .len();
    if size > MAX_OPENAPI_VALIDATOR_CONFIG_SIZE {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!(
                "generated openapi_validator config must not exceed {MAX_OPENAPI_VALIDATOR_CONFIG_SIZE} bytes (got {size})"
            ),
        });
    }
    let depth = json_depth(config);
    if depth > MAX_OPENAPI_VALIDATOR_CONFIG_DEPTH {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!(
                "generated openapi_validator config depth must not exceed {MAX_OPENAPI_VALIDATOR_CONFIG_DEPTH} (got {depth})"
            ),
        });
    }
    Ok(())
}

fn apply_validate_extension(
    config: &mut Map<String, Value>,
    validate_ext: Value,
) -> Result<(), ExtractError> {
    let Value::Object(map) = validate_ext else {
        return Ok(());
    };
    for (key, value) in map {
        match key.as_str() {
            "operations" => {}
            "mode" => {
                config.insert("enforcement_mode".to_string(), value);
            }
            "request" => {
                apply_validate_side_extension(config, "request", value)?;
            }
            "response" => {
                apply_validate_side_extension(config, "response", value)?;
            }
            "bypass" => {
                validate_openapi_validator_bypass("x-ferrum-validate", &value)?;
                config.insert(key, value);
            }
            _ => {
                config.insert(key, value);
            }
        }
    }
    Ok(())
}

fn apply_validate_side_extension(
    config: &mut Map<String, Value>,
    side: &'static str,
    value: Value,
) -> Result<(), ExtractError> {
    let Value::Object(map) = value else {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!("'{side}' must be an object"),
        });
    };
    for (key, value) in map {
        match key.as_str() {
            "enabled" => {
                config.insert(format!("validate_{side}"), value);
            }
            "content_types" => {
                config.insert(format!("{side}_content_types"), value);
            }
            _ => {
                config.insert(key, value);
            }
        }
    }
    Ok(())
}

fn validate_openapi_validator_bypass(
    which: &'static str,
    value: &Value,
) -> Result<(), ExtractError> {
    let object = value
        .as_object()
        .ok_or_else(|| ExtractError::MalformedExtension {
            which,
            error: "openapi_validator bypass config must be an object".to_string(),
        })?;
    for key in ["paths", "methods", "consumers"] {
        if let Some(value) = object.get(key)
            && !value.is_array()
        {
            return Err(ExtractError::MalformedExtension {
                which,
                error: format!("openapi_validator bypass.{key} must be an array"),
            });
        }
    }
    if let Some(value) = object.get("header_present")
        && !value.is_object()
    {
        return Err(ExtractError::MalformedExtension {
            which,
            error: "openapi_validator bypass.header_present must be an object".to_string(),
        });
    }
    Ok(())
}

fn merge_openapi_validator_config(
    auto_config: Value,
    operator_config: &Value,
) -> Result<Value, ExtractError> {
    let mut base =
        auto_config
            .as_object()
            .cloned()
            .ok_or_else(|| ExtractError::MalformedExtension {
                which: "x-ferrum-validate",
                error: "generated openapi_validator config was not an object".to_string(),
            })?;
    let operator = operator_config
        .as_object()
        .ok_or_else(|| ExtractError::MalformedExtension {
            which: "x-ferrum-plugins",
            error: "openapi_validator config must be an object".to_string(),
        })?;
    for (key, value) in operator {
        match key.as_str() {
            "operations" => {}
            "bypass" => merge_bypass_config(&mut base, value)?,
            _ => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(Value::Object(base))
}

fn merge_bypass_config(
    base: &mut Map<String, Value>,
    operator_bypass: &Value,
) -> Result<(), ExtractError> {
    validate_openapi_validator_bypass("x-ferrum-plugins", operator_bypass)?;
    let operator = operator_bypass
        .as_object()
        .ok_or_else(|| ExtractError::MalformedExtension {
            which: "x-ferrum-plugins",
            error: "openapi_validator bypass config must be an object".to_string(),
        })?;
    let base_bypass = base
        .entry("bypass".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let base_object =
        base_bypass
            .as_object_mut()
            .ok_or_else(|| ExtractError::MalformedExtension {
                which: "x-ferrum-validate",
                error: "generated openapi_validator bypass config was not an object".to_string(),
            })?;
    for (key, value) in operator {
        match key.as_str() {
            "paths" | "methods" | "consumers" => {
                let mut values = match base_object.get(key) {
                    Some(Value::Array(values)) => values.clone(),
                    Some(_) => {
                        return Err(ExtractError::MalformedExtension {
                            which: "x-ferrum-validate",
                            error: format!("openapi_validator bypass.{key} must be an array"),
                        });
                    }
                    None => Vec::new(),
                };
                if let Some(operator_values) = value.as_array() {
                    for candidate in operator_values {
                        if !values.iter().any(|existing| existing == candidate) {
                            values.push(candidate.clone());
                        }
                    }
                    base_object.insert(key.clone(), Value::Array(values));
                } else {
                    return Err(ExtractError::MalformedExtension {
                        which: "x-ferrum-plugins",
                        error: format!("openapi_validator bypass.{key} must be an array"),
                    });
                }
            }
            "header_present" => {
                let mut headers = match base_object.get(key) {
                    Some(Value::Object(headers)) => headers.clone(),
                    Some(_) => {
                        return Err(ExtractError::MalformedExtension {
                            which: "x-ferrum-validate",
                            error: "openapi_validator bypass.header_present must be an object"
                                .to_string(),
                        });
                    }
                    None => Map::new(),
                };
                let Some(operator_headers) = value.as_object() else {
                    return Err(ExtractError::MalformedExtension {
                        which: "x-ferrum-plugins",
                        error: "openapi_validator bypass.header_present must be an object"
                            .to_string(),
                    });
                };
                headers.extend(operator_headers.clone());
                base_object.insert(key.clone(), Value::Object(headers));
            }
            _ => {
                base_object.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
}

fn extract_operation_schemas(root: &Value, version: &str) -> Result<Vec<Value>, ExtractError> {
    let Some(paths) = root.get("paths").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut operations = Vec::new();
    let schema_draft = if version == "2.0" || version.starts_with("3.0.") {
        "draft7"
    } else {
        "draft2020-12"
    };
    for (path_template, path_item) in paths {
        let Some(path_object) = path_item.as_object() else {
            continue;
        };
        for method in HTTP_METHODS {
            let Some(operation) = path_object.get(*method).and_then(Value::as_object) else {
                continue;
            };
            let request_body = if version == "2.0" {
                extract_swagger_request_body(root, path_object, operation, version)?
            } else {
                extract_openapi_request_body(root, operation, version)?
            };
            let responses = if version == "2.0" {
                extract_swagger_responses(root, path_object, operation, version)?
            } else {
                extract_openapi_responses(root, operation, version)?
            };
            let mut entry = Map::new();
            entry.insert(
                "method".to_string(),
                Value::String(method.to_ascii_uppercase()),
            );
            entry.insert(
                "path_template".to_string(),
                Value::String(path_template.clone()),
            );
            entry.insert(
                "path_regex".to_string(),
                Value::String(path_template_to_regex(path_template)?),
            );
            entry.insert(
                "schema_draft".to_string(),
                Value::String(schema_draft.to_string()),
            );
            if let Some((required, content)) = request_body {
                entry.insert("request_required".to_string(), Value::Bool(required));
                entry.insert("request_body".to_string(), json!({ "content": content }));
            }
            if !responses.is_empty() {
                entry.insert("responses".to_string(), Value::Object(responses));
            }
            operations.push(Value::Object(entry));
        }
    }
    Ok(operations)
}

fn extract_openapi_request_body(
    root: &Value,
    operation: &Map<String, Value>,
    version: &str,
) -> Result<ExtractedRequestBodySchemas, ExtractError> {
    let Some(request_body) = operation.get("requestBody") else {
        return Ok(None);
    };
    let resolved = resolve_refs(
        root,
        request_body,
        "#/paths/requestBody",
        MAX_SCHEMA_REF_DEPTH,
    )?;
    let Some(object) = resolved.as_object() else {
        return Ok(None);
    };
    let required = object
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut content_schemas = Map::new();
    if let Some(content) = object.get("content").and_then(Value::as_object) {
        for (media_type, media) in content {
            if let Some(schema) = media.get("schema") {
                let schema = resolve_refs(root, schema, media_type, MAX_SCHEMA_REF_DEPTH)?;
                content_schemas.insert(
                    media_type.clone(),
                    normalize_schema_for_openapi(schema, version, SchemaDirection::Request),
                );
            }
        }
    }
    if content_schemas.is_empty() {
        Ok(None)
    } else {
        Ok(Some((required, content_schemas)))
    }
}

fn extract_openapi_responses(
    root: &Value,
    operation: &Map<String, Value>,
    version: &str,
) -> Result<Map<String, Value>, ExtractError> {
    let mut out = Map::new();
    let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
        return Ok(out);
    };
    for (status, response) in responses {
        let resolved = resolve_refs(root, response, status, MAX_SCHEMA_REF_DEPTH)?;
        let Some(response_object) = resolved.as_object() else {
            continue;
        };
        let mut content_schemas = Map::new();
        if let Some(content) = response_object.get("content").and_then(Value::as_object) {
            for (media_type, media) in content {
                if let Some(schema) = media.get("schema") {
                    let schema = resolve_refs(root, schema, media_type, MAX_SCHEMA_REF_DEPTH)?;
                    content_schemas.insert(
                        media_type.clone(),
                        normalize_schema_for_openapi(schema, version, SchemaDirection::Response),
                    );
                }
            }
        }
        if !content_schemas.is_empty() {
            out.insert(status.clone(), Value::Object(content_schemas));
        }
    }
    Ok(out)
}

fn extract_swagger_request_body(
    root: &Value,
    path_item: &Map<String, Value>,
    operation: &Map<String, Value>,
    version: &str,
) -> Result<ExtractedRequestBodySchemas, ExtractError> {
    let parameters = operation
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            path_item
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        );
    for parameter in parameters {
        let resolved = resolve_refs(root, parameter, "#/paths/parameters", MAX_SCHEMA_REF_DEPTH)?;
        let Some(parameter_object) = resolved.as_object() else {
            continue;
        };
        if parameter_object.get("in").and_then(Value::as_str) != Some("body") {
            continue;
        }
        let Some(schema) = parameter_object.get("schema") else {
            continue;
        };
        let schema = resolve_refs(root, schema, "body", MAX_SCHEMA_REF_DEPTH)?;
        let schema = normalize_schema_for_openapi(schema, version, SchemaDirection::Request);
        let required = parameter_object
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut content = Map::new();
        for media_type in swagger_media_types(root, path_item, operation, "consumes") {
            content.insert(media_type, schema.clone());
        }
        return Ok(Some((required, content)));
    }
    Ok(None)
}

fn extract_swagger_responses(
    root: &Value,
    path_item: &Map<String, Value>,
    operation: &Map<String, Value>,
    version: &str,
) -> Result<Map<String, Value>, ExtractError> {
    let mut out = Map::new();
    let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
        return Ok(out);
    };
    let produces = swagger_media_types(root, path_item, operation, "produces");
    for (status, response) in responses {
        let resolved = resolve_refs(root, response, status, MAX_SCHEMA_REF_DEPTH)?;
        let Some(response_object) = resolved.as_object() else {
            continue;
        };
        let Some(schema) = response_object.get("schema") else {
            continue;
        };
        let schema = resolve_refs(root, schema, status, MAX_SCHEMA_REF_DEPTH)?;
        let schema = normalize_schema_for_openapi(schema, version, SchemaDirection::Response);
        let mut content = Map::new();
        for media_type in &produces {
            content.insert(media_type.clone(), schema.clone());
        }
        out.insert(status.clone(), Value::Object(content));
    }
    Ok(out)
}

fn swagger_media_types(
    root: &Value,
    path_item: &Map<String, Value>,
    operation: &Map<String, Value>,
    key: &'static str,
) -> Vec<String> {
    operation
        .get(key)
        .or_else(|| path_item.get(key))
        .or_else(|| root.get(key))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .filter(|values: &Vec<String>| !values.is_empty())
        .unwrap_or_else(|| vec!["application/json".to_string()])
}

const MAX_SCHEMA_REF_DEPTH: usize = 32;
type ExtractedRequestBodySchemas = Option<(bool, Map<String, Value>)>;

fn resolve_refs(
    root: &Value,
    value: &Value,
    location: &str,
    depth: usize,
) -> Result<Value, ExtractError> {
    if depth == 0 {
        return Err(ExtractError::SchemaTooDeep {
            location: location.to_string(),
        });
    }
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                if !reference.starts_with('#') {
                    return Err(ExtractError::UnsupportedExternalRef {
                        reference: reference.to_string(),
                    });
                }
                let pointer = reference.strip_prefix('#').unwrap_or("");
                let target = if pointer.is_empty() {
                    root
                } else {
                    root.pointer(pointer)
                        .ok_or_else(|| ExtractError::MalformedExtension {
                            which: "x-ferrum-validate",
                            error: format!("unresolved internal $ref '{reference}'"),
                        })?
                };
                let mut resolved = resolve_refs(root, target, reference, depth - 1)?;
                if object.len() > 1
                    && let Some(resolved_object) = resolved.as_object_mut()
                {
                    for (key, child) in object {
                        if key != "$ref" {
                            resolved_object.insert(
                                key.clone(),
                                resolve_refs(root, child, location, depth - 1)?,
                            );
                        }
                    }
                }
                return Ok(resolved);
            }
            let mut resolved = Map::new();
            for (key, child) in object {
                resolved.insert(key.clone(), resolve_refs(root, child, location, depth - 1)?);
            }
            Ok(Value::Object(resolved))
        }
        Value::Array(values) => values
            .iter()
            .map(|child| resolve_refs(root, child, location, depth - 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        other => Ok(other.clone()),
    }
}

/// Whether a schema is being compiled for request or response validation.
///
/// OpenAPI 3.0 and Swagger 2.0 apply `required` differently for `readOnly` /
/// `writeOnly` properties depending on this direction. OpenAPI 3.1+ treats
/// those keywords as JSON Schema annotations and does not inherit the 3.0 rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaDirection {
    Request,
    Response,
}

fn normalize_schema_for_openapi(schema: Value, version: &str, direction: SchemaDirection) -> Value {
    if version != "2.0" && !version.starts_with("3.0.") {
        // OpenAPI 3.1+: keep the schema as authored. `readOnly`/`writeOnly` are
        // JSON Schema annotations; Ferrum does not rewrite `required` here.
        return schema;
    }
    normalize_legacy_schema(schema, direction)
}

fn normalize_legacy_schema(schema: Value, direction: SchemaDirection) -> Value {
    match schema {
        Value::Object(mut object) => {
            let nullable = object
                .remove("nullable")
                .or_else(|| object.remove("x-nullable"))
                .and_then(|value| value.as_bool())
                .unwrap_or(false);

            if object.get("exclusiveMinimum").and_then(Value::as_bool) == Some(true) {
                if let Some(minimum) = object.get("minimum").cloned() {
                    object.insert("exclusiveMinimum".to_string(), minimum);
                    object.remove("minimum");
                }
            } else if object
                .get("exclusiveMinimum")
                .is_some_and(Value::is_boolean)
            {
                object.remove("exclusiveMinimum");
            }

            if object.get("exclusiveMaximum").and_then(Value::as_bool) == Some(true) {
                if let Some(maximum) = object.get("maximum").cloned() {
                    object.insert("exclusiveMaximum".to_string(), maximum);
                    object.remove("maximum");
                }
            } else if object
                .get("exclusiveMaximum")
                .is_some_and(Value::is_boolean)
            {
                object.remove("exclusiveMaximum");
            }

            // Filter `required` against same-object `properties` before
            // recursing so nested objects / composition members keep their
            // own direction semantics.
            apply_direction_required_semantics(&mut object, direction);

            for child in object.values_mut() {
                *child = normalize_legacy_schema(std::mem::take(child), direction);
            }
            let value = Value::Object(object);
            if nullable {
                add_null_type(value)
            } else {
                value
            }
        }
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|child| normalize_legacy_schema(child, direction))
                .collect(),
        ),
        other => other,
    }
}

/// OpenAPI 3.0 / Swagger 2.0 direction-specific `required` filtering.
///
/// - Request: a required `readOnly: true` property applies only to responses.
/// - Response: a required `writeOnly: true` property applies only to requests.
///
/// Swagger 2.0 defines `readOnly` but not `writeOnly`; response filtering is
/// therefore a no-op for Swagger documents. Property schemas without a local
/// `properties` entry (for example names satisfied only via sibling `allOf`
/// members) are left in `required` so composition is not weakened.
fn apply_direction_required_semantics(object: &mut Map<String, Value>, direction: SchemaDirection) {
    let Some(required) = object.get("required").and_then(Value::as_array) else {
        return;
    };
    if required.is_empty() {
        return;
    }
    let Some(properties) = object.get("properties").and_then(Value::as_object) else {
        return;
    };

    let filtered: Vec<Value> = required
        .iter()
        .filter(|name| {
            let Some(prop_name) = name.as_str() else {
                // Preserve non-string entries rather than silently dropping them.
                return true;
            };
            let Some(prop) = properties.get(prop_name).and_then(Value::as_object) else {
                return true;
            };
            match direction {
                SchemaDirection::Request => {
                    prop.get("readOnly").and_then(Value::as_bool) != Some(true)
                }
                SchemaDirection::Response => {
                    prop.get("writeOnly").and_then(Value::as_bool) != Some(true)
                }
            }
        })
        .cloned()
        .collect();

    if filtered.len() == required.len() {
        return;
    }
    if filtered.is_empty() {
        object.remove("required");
    } else {
        object.insert("required".to_string(), Value::Array(filtered));
    }
}

fn add_null_type(schema: Value) -> Value {
    let Value::Object(mut object) = schema else {
        return json!({ "anyOf": [schema, { "type": "null" }] });
    };
    match object.remove("type") {
        Some(Value::String(existing)) => {
            object.insert(
                "type".to_string(),
                Value::Array(vec![Value::String(existing), json!("null")]),
            );
            Value::Object(object)
        }
        Some(Value::Array(mut types)) => {
            if !types.iter().any(|value| value.as_str() == Some("null")) {
                types.push(json!("null"));
            }
            object.insert("type".to_string(), Value::Array(types));
            Value::Object(object)
        }
        Some(other) => {
            object.insert("type".to_string(), other);
            json!({ "anyOf": [Value::Object(object), { "type": "null" }] })
        }
        _ => json!({ "anyOf": [Value::Object(object), { "type": "null" }] }),
    }
}

fn path_template_to_regex(path_template: &str) -> Result<String, ExtractError> {
    let mut regex = String::from("^");
    let mut literal = String::new();
    let mut chars = path_template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' {
            if !literal.is_empty() {
                regex.push_str(&regex::escape(&literal));
                literal.clear();
            }
            let mut name = String::new();
            let mut closed = false;
            for inner in chars.by_ref() {
                if inner == '}' {
                    closed = true;
                    break;
                }
                name.push(inner);
            }
            if !closed || name.trim().is_empty() {
                return Err(ExtractError::MalformedExtension {
                    which: "paths",
                    error: format!("invalid OpenAPI path template '{path_template}'"),
                });
            }
            regex.push_str("[^/]+");
        } else {
            literal.push(ch);
        }
    }
    if !literal.is_empty() {
        regex.push_str(&regex::escape(&literal));
    }
    regex.push('$');
    Ok(regex)
}

/// Truncate a string at a UTF-8 character boundary so the result is ≤ `max_bytes` bytes.
fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    s[..s.floor_char_boundary(max_bytes)].to_string()
}

/// Extract Tier 1 metadata from the parsed spec root value.
///
/// Handles both Swagger 2.0 and OpenAPI 3.x.
fn extract_spec_metadata(root: &serde_json::Value, version: &str) -> ExtractedMetadata {
    let info = root.get("info");

    // description — truncated to 4096 bytes.
    let description = info
        .and_then(|i| i.get("description"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, 4096));

    // contact.name / email
    // contact_name  → 256 bytes (human names are short)
    // contact_email → 320 bytes (RFC 5321 maximum email address length)
    let contact = info.and_then(|i| i.get("contact"));
    let contact_name = contact
        .and_then(|c| c.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, 256));
    let contact_email = contact
        .and_then(|c| c.get("email"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, 320));

    // license.name / identifier-or-url
    // license_name       → 256 bytes
    // license_identifier → 128 bytes (SPDX identifiers are short)
    let license = info.and_then(|i| i.get("license"));
    let license_name = license
        .and_then(|l| l.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, 256));
    let license_identifier = license
        .and_then(|l| {
            // 3.1+ uses `identifier`; fallback to `url`
            l.get("identifier").or_else(|| l.get("url"))
        })
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, 128));

    // tags — top-level `tags[].name` (both 2.0 and 3.x)
    // Each tag is truncated at 128 bytes; the list is capped at 64 entries.
    const MAX_TAG_BYTES: usize = 128;
    const MAX_TAGS: usize = 64;
    let mut tags: Vec<String> = root
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("name"))
                .filter_map(|v| v.as_str())
                .map(|s| truncate_utf8(s, MAX_TAG_BYTES))
                .collect()
        })
        .unwrap_or_default();
    tags.sort();
    tags.dedup();
    tags.truncate(MAX_TAGS);

    // server_urls
    // Each URL is truncated at 2048 bytes; the list is capped at 32 entries.
    // An unbounded list would allow an operator to store megabytes of URL data
    // in the metadata columns without triggering the body-size limit (which only
    // caps the raw spec document).
    const MAX_SERVER_URL_BYTES: usize = 2048;
    const MAX_SERVER_URLS: usize = 32;

    let server_urls = if version == "2.0" {
        // Swagger 2.0: construct from schemes[] + host + basePath
        let host = root.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let base_path = root.get("basePath").and_then(|v| v.as_str()).unwrap_or("");
        if host.is_empty() {
            Vec::new()
        } else {
            let schemes: Vec<&str> = root
                .get("schemes")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str()).collect())
                .unwrap_or_default();
            if schemes.is_empty() {
                Vec::new()
            } else {
                schemes
                    .iter()
                    .map(|scheme| {
                        truncate_utf8(
                            &format!("{scheme}://{host}{base_path}"),
                            MAX_SERVER_URL_BYTES,
                        )
                    })
                    .take(MAX_SERVER_URLS)
                    .collect()
            }
        }
    } else {
        // OpenAPI 3.x: servers[].url
        let raw: Vec<String> = root
            .get("servers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("url"))
                    .filter_map(|v| v.as_str())
                    .map(|s| truncate_utf8(s, MAX_SERVER_URL_BYTES))
                    .collect()
            })
            .unwrap_or_default();
        if raw.len() > MAX_SERVER_URLS {
            tracing::debug!(
                "extract_spec_metadata: server_urls has {} entries; truncating to {}",
                raw.len(),
                MAX_SERVER_URLS
            );
            raw.into_iter().take(MAX_SERVER_URLS).collect()
        } else {
            raw
        }
    };

    // operation_count — count HTTP method keys across all paths.*
    let operation_count = root
        .get("paths")
        .and_then(|v| v.as_object())
        .map(|paths| {
            paths
                .values()
                .filter_map(|path_item| path_item.as_object())
                .flat_map(|path_item| path_item.keys())
                .filter(|k| HTTP_METHODS.contains(&k.as_str()))
                .count()
                .min(u32::MAX as usize) as u32
        })
        .unwrap_or(0);

    ExtractedMetadata {
        description,
        contact_name,
        contact_email,
        license_name,
        license_identifier,
        tags,
        server_urls,
        operation_count,
    }
}

/// Compute a stable SHA-256 hex hash over the resource bundle, excluding
/// metadata fields (`api_spec_id`, `created_at`, `updated_at`).
///
/// Same bundle in → same hash out. Used by [`replace_api_spec_bundle`] to
/// skip proxy/upstream/plugin writes when only the spec document changed.
///
/// # Errors
///
/// Returns an error if any resource in the bundle cannot be serialized to JSON.
/// In practice this should never happen for a `serde_json::Value`-backed bundle,
/// but returning `Result` ensures call sites handle the failure as an internal
/// error rather than silently producing an empty hash that could trigger a false
/// hash collision.
pub fn hash_resource_bundle(bundle: &ExtractedBundle) -> Result<String, anyhow::Error> {
    let mut buf = Vec::new();

    // Proxy — strip metadata then serialize
    let proxy_json = strip_metadata(
        serde_json::to_value(&bundle.proxy)
            .map_err(|e| anyhow::anyhow!("failed to serialize proxy for resource hash: {}", e))?,
    );
    buf.extend_from_slice(&serde_json::to_vec(&proxy_json).map_err(|e| {
        anyhow::anyhow!("failed to re-serialize proxy JSON for resource hash: {}", e)
    })?);
    buf.push(b'|');

    // Upstream (optional)
    if let Some(u) = &bundle.upstream {
        let upstream_json = strip_metadata(serde_json::to_value(u).map_err(|e| {
            anyhow::anyhow!("failed to serialize upstream for resource hash: {}", e)
        })?);
        buf.extend_from_slice(&serde_json::to_vec(&upstream_json).map_err(|e| {
            anyhow::anyhow!(
                "failed to re-serialize upstream JSON for resource hash: {}",
                e
            )
        })?);
    }
    buf.push(b'|');

    // Plugins sorted by id for determinism
    let mut plugins: Vec<_> = bundle.plugins.iter().collect();
    plugins.sort_by(|a, b| a.id.cmp(&b.id));
    for p in plugins {
        let pj = strip_metadata(serde_json::to_value(p).map_err(|e| {
            anyhow::anyhow!(
                "failed to serialize plugin '{}' for resource hash: {}",
                p.id,
                e
            )
        })?);
        buf.extend_from_slice(&serde_json::to_vec(&pj).map_err(|e| {
            anyhow::anyhow!(
                "failed to re-serialize plugin JSON for resource hash: {}",
                e
            )
        })?);
        buf.push(b';');
    }

    Ok(crate::admin::spec_codec::sha256_hex(&buf))
}

/// Remove metadata-only fields from a JSON value so they don't affect the hash.
fn strip_metadata(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        obj.remove("api_spec_id");
        obj.remove("created_at");
        obj.remove("updated_at");
    }
    sort_json_value(v)
}

fn sort_json_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(obj) => {
            let mut entries: Vec<_> = obj.into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            serde_json::Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sort_json_value(value)))
                    .collect(),
            )
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sort_json_value).collect())
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Determine the OpenAPI version from the root JSON value.
fn detect_version(root: &serde_json::Value) -> Result<String, ExtractError> {
    // OpenAPI 2.0 (Swagger)
    if let Some(sw) = root.get("swagger")
        && sw.as_str() == Some("2.0")
    {
        return Ok("2.0".to_string());
    }

    // OpenAPI 3.x
    if let Some(oa) = root.get("openapi")
        && let Some(s) = oa.as_str()
        && is_openapi3_version(s)
    {
        return Ok(s.to_string());
    }

    Err(ExtractError::UnknownVersion)
}

fn parse_root_document(
    body: &[u8],
    declared_format: Option<SpecFormat>,
) -> Result<(serde_json::Value, SpecFormat), ExtractError> {
    let fmt = declared_format.unwrap_or_else(|| autodetect_format(body));

    // Parse to serde_json::Value.  serde_yaml accepts JSON as a YAML subset, so
    // a single serde_yaml parse covers both formats.  For JSON we still prefer
    // serde_json so the error messages mention "JSON" rather than "YAML".
    //
    // Fallback: YAML flow-style documents start with `{` and look like JSON to
    // autodetect_format, but they use unquoted keys which serde_json rejects.
    // When JSON parsing fails on autodetected (not declared) input, retry as
    // YAML before surfacing the error.
    let (root, parsed_via_yaml, actual_format): (serde_json::Value, bool, SpecFormat) = match fmt {
        SpecFormat::Json => match serde_json::from_slice(body) {
            Ok(v) => (v, false, SpecFormat::Json),
            Err(e) if declared_format.is_none() => {
                // Autodetected as JSON but failed — try YAML (covers flow-style).
                reject_yaml_alias_or_anchor_syntax(body)?;
                let yv: serde_yaml::Value = serde_yaml::from_slice(body)
                    .map_err(|_| ExtractError::InvalidJson(e.to_string()))?;
                let val = serde_json::to_value(yv)
                    .map_err(|e2| ExtractError::InvalidYaml(e2.to_string()))?;
                (val, true, SpecFormat::Yaml)
            }
            Err(e) => return Err(ExtractError::InvalidJson(e.to_string())),
        },
        SpecFormat::Yaml => {
            reject_yaml_alias_or_anchor_syntax(body)?;
            let yv: serde_yaml::Value = serde_yaml::from_slice(body)
                .map_err(|e| ExtractError::InvalidYaml(e.to_string()))?;
            let val =
                serde_json::to_value(yv).map_err(|e| ExtractError::InvalidYaml(e.to_string()))?;
            (val, true, SpecFormat::Yaml)
        }
    };

    // Defence-in-depth for very large literal YAML trees.  Anchor/alias syntax
    // is rejected before serde_yaml materializes the Value, so this post-parse
    // walk does not serve as the primary alias-bomb memory cap.
    if parsed_via_yaml {
        let mut budget = MAX_YAML_EXPANDED_NODES;
        if !count_value_nodes(&root, &mut budget) {
            return Err(ExtractError::InvalidYaml(
                "YAML document exceeds expanded node limit; reduce nesting".to_string(),
            ));
        }
    }

    Ok((root, actual_format))
}

// ---------------------------------------------------------------------------
// YAML alias-bomb defence
// ---------------------------------------------------------------------------

const YAML_ANCHORS_UNSUPPORTED_MESSAGE: &str =
    "YAML anchors and aliases are not supported in API specs; inline repeated content instead";

/// Maximum number of `serde_json::Value` nodes allowed after YAML → JSON
/// conversion.  500k nodes is generous for any real OpenAPI spec (the largest
/// public specs top out around 50k nodes). Anchors and aliases are rejected
/// before parsing; this guard caps large literal YAML documents.
pub(crate) const MAX_YAML_EXPANDED_NODES: usize = 500_000;

fn reject_yaml_alias_or_anchor_syntax(body: &[u8]) -> Result<(), ExtractError> {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped = false;
    let mut flow_depth: usize = 0;
    let mut expect_node_start = true;
    let mut i = 0;
    let mut block_scalar_min_indent: Option<usize> = None;

    while i < body.len() {
        let line_start = i;
        let mut line_end = i;
        while line_end < body.len() && body[line_end] != b'\n' && body[line_end] != b'\r' {
            line_end += 1;
        }

        let mut next_line_start = line_end;
        if next_line_start < body.len() {
            if body[next_line_start] == b'\r'
                && body.get(next_line_start + 1).copied() == Some(b'\n')
            {
                next_line_start += 2;
            } else {
                next_line_start += 1;
            }
        }

        let line = &body[line_start..line_end];
        let indent = line.iter().take_while(|&&b| b == b' ').count();
        let line_blank = line.iter().all(|b| b.is_ascii_whitespace());

        if let Some(min_indent) = block_scalar_min_indent {
            if line_blank || indent >= min_indent {
                i = next_line_start;
                continue;
            }
            block_scalar_min_indent = None;
        }

        let mut j = line_start;
        if flow_depth == 0 {
            expect_node_start = true;
        }
        while j < line_end {
            let byte = body[j];

            if in_single_quote {
                if byte == b'\'' {
                    if body.get(j + 1) == Some(&b'\'') {
                        j += 2;
                        continue;
                    }
                    in_single_quote = false;
                    expect_node_start = false;
                }
                j += 1;
                continue;
            }

            if in_double_quote {
                if escaped {
                    escaped = false;
                    j += 1;
                    continue;
                }
                match byte {
                    b'\\' => escaped = true,
                    b'"' => {
                        in_double_quote = false;
                        expect_node_start = false;
                    }
                    _ => {}
                }
                j += 1;
                continue;
            }

            match byte {
                b'#' => {
                    break;
                }
                b'\'' => {
                    in_single_quote = true;
                    expect_node_start = false;
                }
                b'"' => {
                    in_double_quote = true;
                    expect_node_start = false;
                }
                b'|' | b'>'
                    if yaml_block_scalar_header_min_indent(line, j - line_start, indent)
                        .is_some() =>
                {
                    block_scalar_min_indent =
                        yaml_block_scalar_header_min_indent(line, j - line_start, indent);
                    break;
                }
                b'&' | b'*'
                    if expect_node_start
                        && body
                            .get(j + 1)
                            .copied()
                            .is_some_and(is_yaml_anchor_name_byte) =>
                {
                    return Err(ExtractError::InvalidYaml(format!(
                        "{YAML_ANCHORS_UNSUPPORTED_MESSAGE} (found '{}' at byte {j})",
                        char::from(byte)
                    )));
                }
                b'[' | b'{' if expect_node_start => {
                    flow_depth += 1;
                    expect_node_start = true;
                }
                b']' | b'}' if flow_depth > 0 => {
                    flow_depth -= 1;
                    expect_node_start = false;
                }
                b',' if flow_depth > 0 => {
                    expect_node_start = true;
                }
                b':' if yaml_colon_is_mapping_separator(line, j - line_start) => {
                    expect_node_start = true;
                }
                b'-' if expect_node_start
                    && line
                        .get(j - line_start + 1)
                        .copied()
                        .is_none_or(|next| next.is_ascii_whitespace()) =>
                {
                    expect_node_start = true;
                }
                byte if byte.is_ascii_whitespace() => {}
                _ => {
                    expect_node_start = false;
                }
            }

            j += 1;
        }

        i = next_line_start;
    }

    Ok(())
}

fn yaml_block_scalar_header_min_indent(
    line: &[u8],
    indicator_idx: usize,
    line_indent: usize,
) -> Option<usize> {
    let prefix = line.get(..indicator_idx)?;
    let prefix_trimmed_end = prefix
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let prefix_trimmed = &prefix[..prefix_trimmed_end];

    if !prefix_trimmed.is_empty()
        && !matches!(prefix_trimmed.last().copied(), Some(b':' | b'-' | b'?'))
    {
        return None;
    }

    let mut explicit_indent: Option<usize> = None;
    let mut suffix_idx = indicator_idx + 1;
    while let Some(byte) = line.get(suffix_idx).copied() {
        match byte {
            b'1'..=b'9' => {
                explicit_indent = Some((byte - b'0') as usize);
                suffix_idx += 1;
            }
            b'+' | b'-' => {
                suffix_idx += 1;
            }
            b' ' | b'\t' => {
                suffix_idx += 1;
                break;
            }
            b'#' => break,
            _ => return None,
        }
    }

    while let Some(byte) = line.get(suffix_idx).copied() {
        match byte {
            b' ' | b'\t' => suffix_idx += 1,
            b'#' => break,
            _ => return None,
        }
    }

    Some(line_indent + explicit_indent.unwrap_or(1))
}

fn yaml_colon_is_mapping_separator(line: &[u8], colon_idx: usize) -> bool {
    line.get(colon_idx + 1)
        .copied()
        .is_none_or(|next| next.is_ascii_whitespace() || matches!(next, b'#' | b',' | b']' | b'}'))
}

fn is_yaml_anchor_name_byte(byte: u8) -> bool {
    !byte.is_ascii_whitespace()
        && !matches!(
            byte,
            b',' | b'[' | b']' | b'{' | b'}' | b':' | b'#' | b'\'' | b'"'
        )
}

/// Walk a `serde_json::Value` tree, decrementing `budget` for each node
/// visited.  Returns `false` (reject) when the budget hits zero.
pub(crate) fn count_value_nodes(val: &serde_json::Value, budget: &mut usize) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                if !count_value_nodes(item, budget) {
                    return false;
                }
            }
            true
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map {
                if !count_value_nodes(v, budget) {
                    return false;
                }
            }
            true
        }
        _ => true,
    }
}

/// Maximum recursion depth for [`find_forbidden_key`].
///
/// serde_yaml's own parser enforces a depth limit of ~128 for the YAML
/// document. We set an explicit, lower limit here (32) so the contract
/// is documented in code rather than relying on the parser's internal
/// behaviour.  Configs nested deeper than 32 levels are rejected with a
/// synthetic `"__depth_exceeded__"` sentinel, causing the spec to be
/// rejected at extract time (fail-closed).
const MAX_FORBIDDEN_KEY_SCAN_DEPTH: usize = 32;

/// Recursively walk a JSON value and return the first key whose name appears
/// in [`FORBIDDEN_CONFIG_KEYS`], or `None` if the value is clean.
///
/// The walk visits every level of objects and every element of arrays.
/// The walk is on the plugin's `config` VALUE only, not on the plugin
/// metadata fields (`plugin_name`, `scope`, etc.), so legitimate auth plugins
/// (`plugin_name: "jwt"`) are not falsely flagged.
///
/// Recursion is bounded by [`MAX_FORBIDDEN_KEY_SCAN_DEPTH`].  When the depth
/// limit is reached the function returns `Some("__depth_exceeded__")` so the
/// spec is rejected (fail-closed), consistent with discovering a real
/// forbidden key.
fn find_forbidden_key(value: &serde_json::Value) -> Option<&'static str> {
    find_forbidden_key_depth(value, MAX_FORBIDDEN_KEY_SCAN_DEPTH)
}

fn find_forbidden_key_for_plugin(
    plugin_name: &str,
    value: &serde_json::Value,
) -> Option<&'static str> {
    if plugin_name == "openapi_validator" {
        return find_forbidden_key_depth_for_openapi_validator(
            value,
            MAX_FORBIDDEN_KEY_SCAN_DEPTH,
            0,
        );
    }
    find_forbidden_key(value)
}

fn find_forbidden_key_depth(value: &serde_json::Value, depth: usize) -> Option<&'static str> {
    if depth == 0 {
        // Fail closed: treat excessively nested config as forbidden.
        return Some("__depth_exceeded__");
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                // Case-insensitive + trimmed match so variants like "JWT",
                // "jwt ", or NBSP-prefixed keys don't bypass the check.
                let trimmed = key.trim();
                if let Some(found) = FORBIDDEN_CONFIG_KEYS
                    .iter()
                    .find(|&&k| k.eq_ignore_ascii_case(trimmed))
                {
                    return Some(found);
                }
                // Recurse into the child value.
                if let Some(found) = find_forbidden_key_depth(child, depth - 1) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(found) = find_forbidden_key_depth(item, depth - 1) {
                    return Some(found);
                }
            }
            None
        }
        // Primitives carry no keys.
        _ => None,
    }
}

fn find_forbidden_key_depth_for_openapi_validator(
    value: &serde_json::Value,
    depth: usize,
    path_level: u8,
) -> Option<&'static str> {
    if depth == 0 {
        return Some("__depth_exceeded__");
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let trimmed = key.trim();
                let is_bypass_consumers =
                    path_level == 1 && trimmed.eq_ignore_ascii_case("consumers");
                if !is_bypass_consumers
                    && let Some(found) = FORBIDDEN_CONFIG_KEYS
                        .iter()
                        .find(|&&k| k.eq_ignore_ascii_case(trimmed))
                {
                    return Some(found);
                }
                let child_path_level = if path_level == 0 && trimmed.eq_ignore_ascii_case("bypass")
                {
                    1
                } else {
                    2
                };
                if let Some(found) = find_forbidden_key_depth_for_openapi_validator(
                    child,
                    depth - 1,
                    child_path_level,
                ) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(found) =
                    find_forbidden_key_depth_for_openapi_validator(item, depth - 1, 2)
                {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Minimal spec builders
    // -----------------------------------------------------------------------

    /// Build the smallest valid JSON spec string that has a proxy extension.
    fn minimal_json_spec(proxy_json: &str) -> String {
        format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "Test API", "version": "1.0.0"}},
                "x-ferrum-proxy": {proxy_json}
            }}"#
        )
    }

    /// Minimal proxy JSON suitable for embedding in a spec.
    fn minimal_proxy() -> &'static str {
        r#"{"id": "my-proxy", "backend_host": "api.example.com", "backend_port": 443}"#
    }

    // -----------------------------------------------------------------------
    // is_openapi3_version — SemVer parser constrained to major version 3
    // -----------------------------------------------------------------------

    #[test]
    fn is_openapi3_version_accepts_canonical_releases() {
        for v in [
            "3.0.0",
            "3.0.3",
            "3.1.0",
            "3.1.5",
            "3.2.0",
            "3.10.99",
            "3.0.123456",
        ] {
            assert!(is_openapi3_version(v), "must accept {v}");
        }
    }

    #[test]
    fn is_openapi3_version_accepts_prerelease_suffix() {
        for v in [
            "3.2.0-rc1",
            "3.1.0-alpha",
            "3.0.0-beta.2",
            "3.2.0-rc1.with.dots",
        ] {
            assert!(is_openapi3_version(v), "must accept {v}");
        }
    }

    #[test]
    fn is_openapi3_version_accepts_build_metadata() {
        for v in [
            "3.1.0+build.7",
            "3.1.0-rc.1+build.7",
            "3.2.0+exp.sha.5114f85",
            "3.0.0-alpha.1+001",
        ] {
            assert!(is_openapi3_version(v), "must accept {v}");
        }
    }

    #[test]
    fn is_openapi3_version_rejects_non_threes() {
        for v in ["2.0.0", "4.0.0", "30.0.0", "3", "3.0", "3.", ""] {
            assert!(!is_openapi3_version(v), "must reject {v:?}");
        }
    }

    #[test]
    fn is_openapi3_version_rejects_non_digit_components() {
        for v in [
            "3.x.0",
            "3.0.x",
            "3.0a.0",
            "3.0.0a",
            "3..0",
            "3.0.",
            "3.0.0-",
            "3.0.0+",
            "3.0.0-rc+",
            "3.0.0-rc+build+again",
            "3.0.0-rc..1",
            "3.0.0+build..1",
            "3.0.0-\u{0}",
            "3.-1.0",
        ] {
            assert!(!is_openapi3_version(v), "must reject {v:?}");
        }
    }

    #[test]
    fn is_openapi3_version_rejects_leading_or_trailing_whitespace() {
        // The original regex was anchored (^...$) — no whitespace allowed.
        for v in [" 3.0.0", "3.0.0 ", "\t3.0.0", "3.0.0\n"] {
            assert!(!is_openapi3_version(v), "must reject {v:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Version detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_swagger_2_0() {
        let spec = minimal_json_spec(minimal_proxy());
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "2.0");
    }

    #[test]
    fn test_version_openapi_3_0_3() {
        let spec = format!(
            r#"{{"openapi": "3.0.3", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.0.3");
    }

    #[test]
    fn test_version_openapi_3_1_0() {
        let spec = format!(
            r#"{{"openapi": "3.1.0", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.1.0");
    }

    #[test]
    fn test_version_openapi_3_2_0() {
        let spec = format!(
            r#"{{"openapi": "3.2.0", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.2.0");
    }

    #[test]
    fn test_version_openapi_3_2_prerelease() {
        let spec = format!(
            r#"{{"openapi": "3.2.0-rc1", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.2.0-rc1");
    }

    #[test]
    fn test_version_openapi_3_1_build_metadata() {
        let spec = format!(
            r#"{{"openapi": "3.1.0+build.7", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.1.0+build.7");
    }

    #[test]
    fn test_version_openapi_3_1_prerelease_build_metadata() {
        let spec = format!(
            r#"{{"openapi": "3.1.0-rc.1+build.7", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.1.0-rc.1+build.7");
    }

    #[test]
    fn test_version_missing_returns_unknown() {
        let spec = format!(
            r#"{{"info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(matches!(err, ExtractError::UnknownVersion), "got: {err}");
    }

    #[test]
    fn test_version_openapi_4_returns_unknown() {
        let spec = format!(
            r#"{{"openapi": "4.0.0", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(matches!(err, ExtractError::UnknownVersion), "got: {err}");
    }

    #[test]
    fn test_version_openapi_not_semver_returns_unknown() {
        let spec = format!(
            r#"{{"openapi": "not-a-version", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(matches!(err, ExtractError::UnknownVersion), "got: {err}");
    }

    // -----------------------------------------------------------------------
    // Format autodetect
    // -----------------------------------------------------------------------

    #[test]
    fn test_autodetect_json_brace() {
        assert_eq!(
            autodetect_format(b"{\"openapi\": \"3.0.3\"}"),
            SpecFormat::Json
        );
    }

    #[test]
    fn test_autodetect_yaml_keyword() {
        assert_eq!(autodetect_format(b"openapi: \"3.0.3\""), SpecFormat::Yaml);
    }

    #[test]
    fn test_autodetect_json_with_leading_whitespace() {
        assert_eq!(
            autodetect_format(b"  \n  {\"swagger\": \"2.0\"}"),
            SpecFormat::Json
        );
    }

    #[test]
    fn test_autodetected_flow_style_yaml_records_yaml_format() {
        let spec = format!(
            "{{openapi: '3.1.0', info: {{title: flow, version: '1.0'}}, x-ferrum-proxy: {}}}",
            minimal_proxy()
        );

        let (_, meta) = extract(spec.as_bytes(), None, "prod").expect("flow YAML must parse");

        assert_eq!(
            meta.format,
            SpecFormat::Yaml,
            "flow-style YAML starts with '{{' and first autodetects as JSON, \
             but the YAML fallback must record the actual stored format"
        );
    }

    // -----------------------------------------------------------------------
    // Happy-path extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_minimal_json_proxy_only() {
        let spec = minimal_json_spec(minimal_proxy());
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.proxy.id, "my-proxy");
        assert_eq!(bundle.proxy.backend_host, "api.example.com");
        assert!(bundle.upstream.is_none());
        assert!(bundle.plugins.is_empty());
    }

    #[test]
    fn test_minimal_yaml_proxy_only() {
        let spec = r##"
swagger: "2.0"
info:
  title: "YAML Test"
  version: "2.0.0"
x-ferrum-proxy:
  id: "yaml-proxy"
  backend_host: "backend.example.com"
  backend_port: 8080
"##;
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
        assert_eq!(bundle.proxy.id, "yaml-proxy");
        assert!(bundle.upstream.is_none());
        assert!(bundle.plugins.is_empty());
    }

    #[test]
    fn test_full_bundle_proxy_upstream_plugins() {
        let spec = r##"
{
    "openapi": "3.1.0",
    "info": {"title": "Full API", "version": "3.0.0"},
    "x-ferrum-proxy": {
        "id": "full-proxy",
        "backend_host": "backend.internal",
        "backend_port": 443
    },
    "x-ferrum-upstream": {
        "id": "full-upstream",
        "targets": [
            {"host": "target1.internal", "port": 443},
            {"host": "target2.internal", "port": 443}
        ]
    },
    "x-ferrum-plugins": [
        {
            "id": "plugin-1",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "config": {"limits": [{"scope": "default", "requests_per_minute": 100}]}
        },
        {
            "id": "plugin-2",
            "plugin_name": "cors",
            "scope": "proxy",
            "config": {"allowed_origins": ["https://example.com"]}
        }
    ]
}
"##;
        let (bundle, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.proxy.id, "full-proxy");
        assert!(bundle.upstream.is_some());
        assert_eq!(bundle.upstream.as_ref().unwrap().id, "full-upstream");
        assert_eq!(bundle.plugins.len(), 2);
        assert_eq!(bundle.plugins[0].id, "plugin-1");
        assert_eq!(bundle.plugins[1].id, "plugin-2");
        // All plugins must be proxy-scoped and linked to the proxy.
        for p in &bundle.plugins {
            assert_eq!(p.scope, PluginScope::Proxy);
            assert_eq!(p.proxy_id.as_deref(), Some("full-proxy"));
        }
        assert_eq!(meta.version, "3.1.0");
        assert_eq!(meta.title.as_deref(), Some("Full API"));
        assert_eq!(meta.info_version.as_deref(), Some("3.0.0"));
    }

    #[test]
    fn test_x_ferrum_validate_auto_injects_openapi_validator() {
        let spec = r##"
{
  "openapi": "3.0.3",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "components": {
    "schemas": {
      "Order": {
        "type": "object",
        "required": ["id"],
        "properties": {
          "id": {"type": "string", "nullable": true}
        }
      }
    }
  },
  "paths": {
    "/orders/{id}": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {"$ref": "#/components/schemas/Order"}
            }
          }
        },
        "responses": {
          "200": {
            "description": "ok",
            "content": {
              "application/json": {
                "schema": {"$ref": "#/components/schemas/Order"}
              }
            }
          }
        }
      }
    }
  }
}
"##;
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.plugins.len(), 1);
        let plugin = &bundle.plugins[0];
        assert_eq!(plugin.plugin_name, "openapi_validator");
        assert_eq!(plugin.scope, PluginScope::Proxy);
        assert_eq!(plugin.proxy_id.as_deref(), Some("contract-proxy"));

        let operations = plugin
            .config
            .get("operations")
            .and_then(Value::as_array)
            .expect("operations array");
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0]["path_regex"], "^/orders/[^/]+$");
        assert_eq!(operations[0]["request_required"], true);
        assert_eq!(plugin.config["schema_draft"], "draft7");

        let id_type = &operations[0]["request_body"]["content"]["application/json"]["properties"]["id"]
            ["type"];
        assert_eq!(id_type, &json!(["string", "null"]));
    }

    #[test]
    fn test_x_ferrum_validate_absent_does_not_inject_validator() {
        let spec = minimal_json_spec(minimal_proxy());
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert!(bundle.plugins.is_empty());
    }

    #[test]
    fn test_x_ferrum_validate_merges_operator_openapi_validator_config() {
        let spec = r#"
{
  "openapi": "3.1.0",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": {
    "bypass": {"paths": ["^/health$"], "consumers": ["spec-bypass"]},
    "request": {"content_types": ["application/json", "application/problem+json"]}
  },
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "x-ferrum-plugins": [{
    "id": "operator-validator",
    "plugin_name": "openapi_validator",
    "config": {
      "enforcement_mode": "log_only",
      "bypass": {"paths": ["^/ready$"], "methods": ["OPTIONS"], "consumers": ["break-glass"]},
      "operations": [{"method": "GET", "path_template": "/wrong", "path_regex": "^/wrong$"}]
    }
  }],
  "paths": {
    "/orders": {
      "post": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {"type": "object"}
            }
          }
        },
        "responses": {"204": {"description": "ok"}}
      }
    }
  }
}
"#;
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.plugins.len(), 1);
        let plugin = &bundle.plugins[0];
        assert_eq!(plugin.id, "operator-validator");
        assert_eq!(plugin.config["enforcement_mode"], "log_only");
        assert_eq!(plugin.config["schema_draft"], "draft2020-12");
        assert_eq!(plugin.config["operations"][0]["path_template"], "/orders");

        let bypass_paths = plugin.config["bypass"]["paths"].as_array().unwrap();
        assert!(bypass_paths.contains(&json!("^/health$")));
        assert!(bypass_paths.contains(&json!("^/ready$")));
        assert_eq!(plugin.config["bypass"]["methods"], json!(["OPTIONS"]));
        let bypass_consumers = plugin.config["bypass"]["consumers"].as_array().unwrap();
        assert!(bypass_consumers.contains(&json!("spec-bypass")));
        assert!(bypass_consumers.contains(&json!("break-glass")));
        assert_eq!(
            plugin.config["request_content_types"],
            json!(["application/json", "application/problem+json"])
        );
    }

    #[test]
    fn test_x_ferrum_validate_rejects_malformed_spec_bypass() {
        let spec = r#"
{
  "openapi": "3.1.0",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": {
    "bypass": {"paths": "^/health$"}
  },
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "paths": {
    "/orders": {
      "get": {
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}
"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap_err();
        assert!(matches!(
            err,
            ExtractError::MalformedExtension {
                which: "x-ferrum-validate",
                ..
            }
        ));
        assert!(
            err.to_string()
                .contains("openapi_validator bypass.paths must be an array")
        );
    }

    #[test]
    fn test_x_ferrum_validate_preserves_wildcard_response_statuses() {
        let spec = r#"
{
  "openapi": "3.1.0",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "paths": {
    "/orders": {
      "get": {
        "responses": {
          "4XX": {
            "description": "client error",
            "content": {
              "application/json": {
                "schema": {"type": "object", "required": ["error"]}
              }
            }
          }
        }
      }
    }
  }
}
"#;
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        let plugin = &bundle.plugins[0];
        assert_eq!(
            plugin.config["operations"][0]["responses"]["4XX"]["application/json"]["required"],
            json!(["error"])
        );
    }

    #[test]
    fn test_x_ferrum_validate_rejects_external_refs() {
        let spec = r#"
{
  "openapi": "3.1.0",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "paths": {
    "/orders": {
      "post": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {"$ref": "https://example.com/schemas/order.json"}
            }
          }
        },
        "responses": {"204": {"description": "ok"}}
      }
    }
  }
}
"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap_err();
        assert!(
            matches!(err, ExtractError::UnsupportedExternalRef { .. }),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Namespace override
    // -----------------------------------------------------------------------

    #[test]
    fn test_namespace_override_ignores_spec_namespace() {
        // Spec embeds namespace "evil"; extractor must stamp "prod" instead.
        let spec = r#"{
            "swagger": "2.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "ns-proxy",
                "namespace": "evil",
                "backend_host": "be.internal",
                "backend_port": 443
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.proxy.namespace, "prod");
    }

    // -----------------------------------------------------------------------
    // info extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_info_fields_populated() {
        let spec = minimal_json_spec(minimal_proxy());
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.title.as_deref(), Some("Test API"));
        assert_eq!(meta.info_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_info_fields_absent_when_no_info() {
        let spec = format!(
            r#"{{"swagger": "2.0", "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert!(meta.title.is_none());
        assert!(meta.info_version.is_none());
    }

    // -----------------------------------------------------------------------
    // Rejection paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_x_ferrum_consumers() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-consumers": [{{"username": "alice"}}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(err, ExtractError::ConsumerExtensionNotAllowed),
            "got: {err}"
        );
    }

    #[test]
    fn test_plugin_scope_omitted_defaults_to_proxy() {
        // Matches the canonical example in docs/api_specs.md and CLAUDE.md,
        // which shows plugins WITHOUT an explicit `scope` field. The extractor
        // must default to PluginScope::Proxy rather than fail deserialization.
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "rl-1",
                    "plugin_name": "rate_limiting",
                    "config": {{"limits": [{{"scope": "default", "window_seconds": 60, "max_requests": 100}}]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let (bundle, _md) = extract(spec.as_bytes(), None, "ferrum").expect("extract ok");
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(bundle.plugins[0].scope, PluginScope::Proxy);
        assert_eq!(bundle.plugins[0].proxy_id.as_deref(), Some("my-proxy"));
    }

    #[test]
    fn test_reject_plugin_scope_global() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "bad-plugin",
                    "plugin_name": "rate_limiting",
                    "scope": "global",
                    "config": {{}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginInvalidScope { plugin_id, scope }
                if plugin_id == "bad-plugin" && scope == "global"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_scope_proxy_group() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "grp-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy_group",
                    "config": {{"allowed_origins": ["*"]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginInvalidScope { plugin_id, scope }
                if plugin_id == "grp-plugin" && scope == "proxy_group"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_proxy_id_mismatch() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "mismatch-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy",
                    "proxy_id": "some-other-proxy",
                    "config": {{"allowed_origins": ["*"]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginProxyIdMismatch {
                    plugin_id,
                    plugin_proxy_id,
                    spec_proxy_id
                }
                if plugin_id == "mismatch-plugin"
                    && plugin_proxy_id == "some-other-proxy"
                    && spec_proxy_id == "my-proxy"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_duplicate_plugin_ids() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [
                    {{
                        "id": "dup-id",
                        "plugin_name": "rate_limiting",
                        "scope": "proxy",
                        "config": {{"limits": [{{"scope": "default", "requests_per_second": 10}}]}}
                    }},
                    {{
                        "id": "dup-id",
                        "plugin_name": "cors",
                        "scope": "proxy",
                        "config": {{"allowed_origins": ["*"]}}
                    }}
                ]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::MalformedExtension { which, error }
                if *which == "x-ferrum-plugins" && error.contains("duplicate plugin id")
            ),
            "duplicate plugin IDs must be rejected; got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_credentials_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "cred-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "settings": {{
                            "credentials": {{"key": "secret"}}
                        }}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "cred-plugin" && key == "credentials"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_nested_jwt_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "nested-jwt",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "auth": {{
                            "jwt": {{"secret": "abc"}}
                        }}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "nested-jwt" && key == "jwt"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_consumer_id_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "consumer-id-plugin",
                    "plugin_name": "acl",
                    "scope": "proxy",
                    "config": {{
                        "consumer_id": "alice"
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "consumer-id-plugin" && key == "consumer_id"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_missing_proxy_extension() {
        let spec = r#"{"swagger": "2.0", "info": {"title": "T", "version": "1"}}"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(err, ExtractError::MissingProxyExtension),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_malformed_proxy_extension() {
        // hosts must be an array; passing a plain string triggers a serde error.
        let spec = r#"{
            "swagger": "2.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "bad",
                "backend_host": "h",
                "backend_port": 80,
                "hosts": "not-an-array"
            }
        }"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                err,
                ExtractError::MalformedExtension {
                    which: "x-ferrum-proxy",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Counter-example: a `jwt` plugin with legitimate config is NOT flagged
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Fix 1: Upstream auto-link to proxy
    // -----------------------------------------------------------------------

    #[test]
    fn test_upstream_auto_links_to_proxy() {
        // Proxy has no upstream_id; extractor must set it from the upstream's id.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "link-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-upstream": {
                "id": "link-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();
        assert_eq!(
            bundle.proxy.upstream_id.as_deref(),
            Some("link-upstream"),
            "upstream_id must be auto-linked to the spec upstream's id"
        );
    }

    #[test]
    fn test_upstream_auto_link_skipped_when_proxy_already_has_matching_id() {
        // Proxy explicitly declares the same upstream_id as the spec upstream — no error.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "matching-proxy",
                "backend_host": "be.internal",
                "backend_port": 443,
                "upstream_id": "same-upstream"
            },
            "x-ferrum-upstream": {
                "id": "same-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();
        assert_eq!(
            bundle.proxy.upstream_id.as_deref(),
            Some("same-upstream"),
            "matching explicit upstream_id must be accepted unchanged"
        );
    }

    #[test]
    fn test_upstream_link_mismatch_rejected() {
        // Proxy pinned a different upstream_id than the spec upstream's id — hard error.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "mismatch-proxy",
                "backend_host": "be.internal",
                "backend_port": 443,
                "upstream_id": "pinned-upstream"
            },
            "x-ferrum-upstream": {
                "id": "spec-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::ProxyUpstreamIdMismatch {
                    proxy_id,
                    proxy_upstream_id,
                    spec_upstream_id,
                }
                if proxy_id == "mismatch-proxy"
                    && proxy_upstream_id == "pinned-upstream"
                    && spec_upstream_id == "spec-upstream"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_jwt_plugin_with_legitimate_config_is_allowed() {
        // plugin_name = "jwt", but the config VALUE does not contain any
        // forbidden keys — so it must pass the forbidden-key walk.
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "jwt-plugin",
                    "plugin_name": "jwt",
                    "scope": "proxy",
                    "config": {{
                        "secret_lookup": "env",
                        "validation": {{
                            "validate_exp": true
                        }}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        // Must succeed — no error.
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(bundle.plugins[0].plugin_name, "jwt");
    }

    // -----------------------------------------------------------------------
    // L2 — find_forbidden_key depth limit
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_forbidden_key_depth_limit() {
        // Build a 50-level-deep nested object whose innermost value is
        // {"keyauth": {}}.  The scan must stop at MAX_FORBIDDEN_KEY_SCAN_DEPTH (32)
        // and return Some("__depth_exceeded__"), rejecting the spec before it
        // reaches the keyauth key at depth 50.
        let mut inner = serde_json::json!({ "keyauth": {} });
        for _ in 0..50 {
            inner = serde_json::json!({ "nested": inner });
        }

        let result = find_forbidden_key(&inner);
        assert!(
            result.is_some(),
            "deeply nested config must be rejected (fail-closed)"
        );
        assert_eq!(
            result.unwrap(),
            "__depth_exceeded__",
            "depth limit must fire before finding keyauth at depth 50 \
             (limit is {})",
            MAX_FORBIDDEN_KEY_SCAN_DEPTH
        );
    }

    // -----------------------------------------------------------------------
    // Fix 1: ID assignment is deferred to the route handler (extractor
    // leaves empty IDs empty; handler calls assign_ids_for_post /
    // assign_ids_for_put). The extractor only does auto-linking with
    // whatever id values are present.
    // -----------------------------------------------------------------------

    #[test]
    fn test_proxy_id_empty_leaves_id_empty_and_plugins_stamped_to_empty() {
        // When x-ferrum-proxy.id is empty, the extractor must leave it empty
        // (ID assignment is deferred to the handler). The plugin's proxy_id
        // and the association list will also reference the empty string — the
        // handler's assign_ids_for_* call fixes these up.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-plugins": [
                {
                    "id": "plugin-a",
                    "plugin_name": "rate_limiting",
                    "config": {"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]}
                }
            ]
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        // proxy.id must remain empty — handler will assign it.
        assert!(
            bundle.proxy.id.is_empty(),
            "extractor must leave empty proxy.id empty"
        );

        // plugin.proxy_id must be empty (reflecting the empty proxy.id).
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(
            bundle.plugins[0].proxy_id.as_deref(),
            Some(""),
            "plugin.proxy_id is stamped with whatever proxy.id is (empty here)"
        );

        // proxy.plugins association list must reference plugin-a
        assert_eq!(bundle.proxy.plugins.len(), 1);
        assert_eq!(bundle.proxy.plugins[0].plugin_config_id, "plugin-a");
    }

    #[test]
    fn test_upstream_id_empty_leaves_id_empty_and_proxy_upstream_id_auto_links() {
        // When x-ferrum-upstream.id is empty, the extractor leaves it empty.
        // The auto-link sets proxy.upstream_id = Some("") — handler fixes it.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "fixed-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-upstream": {
                "id": "",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        let upstream = bundle.upstream.as_ref().expect("upstream must be present");
        assert!(
            upstream.id.is_empty(),
            "extractor must leave empty upstream.id empty"
        );
        // Auto-link still fires: proxy.upstream_id set to the upstream's id (empty).
        assert_eq!(
            bundle.proxy.upstream_id.as_deref(),
            Some(""),
            "auto-link sets proxy.upstream_id to upstream.id even when both are empty"
        );
    }

    #[test]
    fn test_plugin_id_empty_leaves_id_empty_and_proxy_id_stamped() {
        // When a plugin entry has id = "", the extractor leaves it empty.
        // proxy_id is stamped with proxy.id (which may also be empty if not provided).
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "my-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-plugins": [
                {
                    "id": "",
                    "plugin_name": "cors",
                    "config": {"allowed_origins": ["*"]}
                }
            ]
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        assert_eq!(bundle.plugins.len(), 1);
        let plugin = &bundle.plugins[0];
        assert!(
            plugin.id.is_empty(),
            "extractor must leave empty plugin.id empty"
        );
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some("my-proxy"),
            "plugin.proxy_id must be stamped with proxy.id"
        );
    }

    #[test]
    fn test_invalid_proxy_id_returns_malformed_extension() {
        // An id with spaces is invalid and must return MalformedExtension.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "has spaces",
                "backend_host": "be.internal",
                "backend_port": 443
            }
        }"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::MalformedExtension { which, .. }
                if *which == "x-ferrum-proxy"
            ),
            "expected MalformedExtension for x-ferrum-proxy, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Fix 2: proxy.plugins association list is populated
    // -----------------------------------------------------------------------

    #[test]
    fn test_imported_plugins_appear_in_proxy_plugins_associations() {
        // After extraction, proxy.plugins must contain PluginAssociation entries
        // for every plugin in x-ferrum-plugins, so PluginCache can instantiate them.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "assoc-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-plugins": [
                {"id": "p1", "plugin_name": "rate_limiting", "config": {"limits": [{"scope": "default", "requests_per_minute": 100}]}},
                {"id": "p2", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}
            ]
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        assert_eq!(bundle.plugins.len(), 2);
        assert_eq!(
            bundle.proxy.plugins.len(),
            2,
            "proxy.plugins must have one entry per imported plugin"
        );

        let assoc_ids: Vec<&str> = bundle
            .proxy
            .plugins
            .iter()
            .map(|a| a.plugin_config_id.as_str())
            .collect();
        assert!(assoc_ids.contains(&"p1"), "proxy.plugins must reference p1");
        assert!(assoc_ids.contains(&"p2"), "proxy.plugins must reference p2");
    }

    #[test]
    fn test_existing_proxy_plugins_preserved_when_importing() {
        // If the operator writes an explicit plugin association in x-ferrum-proxy.plugins
        // (e.g., pointing to a pre-existing global plugin), those entries must survive
        // and spec-extracted plugins must be added without duplication.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "preserve-proxy",
                "backend_host": "be.internal",
                "backend_port": 443,
                "plugins": [{"plugin_config_id": "existing-global-plugin"}]
            },
            "x-ferrum-plugins": [
                {"id": "new-plugin", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}
            ]
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        // Must have both the pre-existing association AND the newly imported one
        let ids: Vec<&str> = bundle
            .proxy
            .plugins
            .iter()
            .map(|a| a.plugin_config_id.as_str())
            .collect();
        assert!(
            ids.contains(&"existing-global-plugin"),
            "pre-existing association must be preserved"
        );
        assert!(
            ids.contains(&"new-plugin"),
            "newly imported plugin must be added"
        );
        assert_eq!(ids.len(), 2, "no duplicates");
    }

    // -----------------------------------------------------------------------
    // M1 — Tag name validation (reject forbidden SQL LIKE characters)
    // -----------------------------------------------------------------------

    fn spec_with_tag(tag: &str) -> String {
        format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "tags": [{{"name": "{tag}"}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        )
    }

    #[test]
    fn test_tag_with_percent_rejected() {
        let spec = spec_with_tag("foo%bar");
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidTagName { name, char: '%' } if name == "foo%bar"),
            "expected InvalidTagName for '%'; got: {err}"
        );
    }

    #[test]
    fn test_tag_with_quote_rejected() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "tags": [{{"name": "foo\"bar"}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidTagName { char: '"', .. }),
            "expected InvalidTagName for '\"'; got: {err}"
        );
    }

    #[test]
    fn test_tag_with_backslash_rejected() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "tags": [{{"name": "foo\\\\bar"}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidTagName { char: '\\', .. }),
            "expected InvalidTagName for '\\\\'; got: {err}"
        );
    }

    /// `_` is the SQL LIKE single-character wildcard — without rejecting it,
    /// `?has_tag=api_v1` would falsely match `apixv1`.
    #[test]
    fn test_tag_with_underscore_rejected() {
        let spec = spec_with_tag("api_v1");
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidTagName { name, char: '_' } if name == "api_v1"),
            "expected InvalidTagName for '_'; got: {err}"
        );
    }

    #[test]
    fn test_tag_with_normal_chars_accepted() {
        let spec = spec_with_tag("my-tag-v1.0");
        // Must not error. Note: `_` is NOT in the allowed set (see
        // test_tag_with_underscore_rejected).
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum")
            .expect("tag with normal chars must be accepted");
        assert!(meta.tags.contains(&"my-tag-v1.0".to_string()));
    }

    // -----------------------------------------------------------------------
    // L3 — title and info_version truncation
    // -----------------------------------------------------------------------

    #[test]
    fn test_title_truncated_to_1024_bytes() {
        // Construct a title that is 2048 ASCII characters long.
        let long_title: String = "A".repeat(2048);
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "{long_title}", "version": "1.0"}},
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum")
            .expect("extract with long title must succeed");
        let title = meta.title.expect("title must be present");
        assert_eq!(
            title.len(),
            1024,
            "title must be truncated to 1024 bytes; got {} bytes",
            title.len()
        );
    }

    #[test]
    fn test_info_version_truncated_to_256_bytes() {
        // Construct a version string that is 1024 ASCII characters long.
        let long_ver: String = "1".repeat(1024);
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "{long_ver}"}},
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum")
            .expect("extract with long info_version must succeed");
        let iv = meta.info_version.expect("info_version must be present");
        assert_eq!(
            iv.len(),
            256,
            "info_version must be truncated to 256 bytes; got {} bytes",
            iv.len()
        );
    }

    // -----------------------------------------------------------------------
    // Item 4 — Tier 1 metadata field truncation tests
    // -----------------------------------------------------------------------

    fn spec_with_info_contact_license(
        contact_name: &str,
        contact_email: &str,
        license_name: &str,
        license_id: &str,
    ) -> String {
        format!(
            r#"{{
                "swagger": "2.0",
                "info": {{
                    "title": "T", "version": "1",
                    "contact": {{"name": "{contact_name}", "email": "{contact_email}"}},
                    "license": {{"name": "{license_name}", "identifier": "{license_id}"}}
                }},
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        )
    }

    #[test]
    fn test_contact_name_truncated() {
        let long_name: String = "N".repeat(512);
        let spec = spec_with_info_contact_license(&long_name, "a@b.com", "MIT", "MIT");
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "2.0",
        );
        let name = meta.contact_name.expect("contact_name must be present");
        assert_eq!(
            name.len(),
            256,
            "contact_name must be truncated to 256 bytes; got {}",
            name.len()
        );
    }

    #[test]
    fn test_contact_email_truncated() {
        let long_email: String = "e".repeat(500) + "@example.com";
        let spec = spec_with_info_contact_license("Alice", &long_email, "MIT", "MIT");
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "2.0",
        );
        let email = meta.contact_email.expect("contact_email must be present");
        assert_eq!(
            email.len(),
            320,
            "contact_email must be truncated to 320 bytes; got {}",
            email.len()
        );
    }

    #[test]
    fn test_license_name_truncated() {
        let long_name: String = "L".repeat(512);
        let spec = spec_with_info_contact_license("Alice", "a@b.com", &long_name, "MIT");
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "2.0",
        );
        let lname = meta.license_name.expect("license_name must be present");
        assert_eq!(
            lname.len(),
            256,
            "license_name must be truncated to 256 bytes; got {}",
            lname.len()
        );
    }

    #[test]
    fn test_license_identifier_truncated() {
        let long_id: String = "X".repeat(512);
        let spec = spec_with_info_contact_license("Alice", "a@b.com", "MIT", &long_id);
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "2.0",
        );
        let lid = meta
            .license_identifier
            .expect("license_identifier must be present");
        assert_eq!(
            lid.len(),
            128,
            "license_identifier must be truncated to 128 bytes; got {}",
            lid.len()
        );
    }

    #[test]
    fn test_server_url_individual_truncated() {
        // A single very long server URL must be truncated at 2048 bytes.
        let long_url: String = format!("https://example.com/{}", "p".repeat(4000));
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "T", "version": "1"}},
                "servers": [{{"url": "{long_url}"}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "3.1.0",
        );
        assert_eq!(meta.server_urls.len(), 1, "must have one server URL");
        assert_eq!(
            meta.server_urls[0].len(),
            2048,
            "server URL must be truncated to 2048 bytes; got {}",
            meta.server_urls[0].len()
        );
    }

    #[test]
    fn test_server_urls_cardinality_capped() {
        // Build 50 distinct server URLs — only the first 32 should survive.
        let urls: String = (0..50)
            .map(|i| format!("{{\"url\": \"https://server-{i}.example.com\"}}"))
            .collect::<Vec<_>>()
            .join(", ");
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "T", "version": "1"}},
                "servers": [{urls}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "3.1.0",
        );
        assert_eq!(
            meta.server_urls.len(),
            32,
            "server_urls must be capped at 32 entries; got {}",
            meta.server_urls.len()
        );
    }

    // -----------------------------------------------------------------------
    // YAML alias-bomb defence
    // -----------------------------------------------------------------------

    #[test]
    fn count_value_nodes_within_budget() {
        let val: serde_json::Value = serde_json::from_str(r#"{"a": [1, 2, {"b": 3}]}"#).unwrap();
        let mut budget: usize = 100;
        assert!(count_value_nodes(&val, &mut budget));
        // root object + "a" array + 1 + 2 + inner object + 3 = 6 nodes
        assert_eq!(budget, 94);
    }

    #[test]
    fn count_value_nodes_exceeds_budget() {
        let val: serde_json::Value = serde_json::from_str(r#"[1, 2, 3, 4, 5]"#).unwrap();
        let mut budget: usize = 3;
        assert!(!count_value_nodes(&val, &mut budget));
    }

    #[test]
    fn yaml_anchor_syntax_rejected_before_parse() {
        let yaml = b"openapi: '3.1.0'\n\
                     info: &info\n\
                       title: Anchored\n\
                       version: '1.0'\n\
                     x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}";
        let err = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("anchors and aliases")),
            "expected YAML anchor preflight rejection, got {err:?}"
        );
    }

    #[test]
    fn yaml_alias_syntax_rejected_before_parse() {
        let yaml = b"openapi: '3.1.0'\n\
                     info: *common_info\n\
                     x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}";
        let err = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("anchors and aliases")),
            "expected YAML alias preflight rejection, got {err:?}"
        );
    }

    #[test]
    fn flow_style_yaml_anchor_rejected_on_json_fallback() {
        let yaml = b"{openapi: '3.1.0', info: &info {title: flow, version: '1.0'}, \
                     x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}}";
        let err = extract(yaml, None, "default").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("anchors and aliases")),
            "expected YAML fallback preflight rejection, got {err:?}"
        );
    }

    #[test]
    fn yaml_anchor_like_text_in_quotes_and_comments_allowed() {
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: \"R&D *literal*\"\n",
            "  version: '1.0'\n",
            "  description: 'quoted &anchor and *alias text'\n",
            "# comment mentions &anchor and *alias\n",
            "x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}",
        )
        .as_bytes();
        let (bundle, _meta) = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
    }

    #[test]
    fn yaml_anchor_like_text_in_plain_scalars_allowed() {
        let yaml = concat!(
            "openapi: 3.1.0\n",
            "info:\n",
            "  title: Terms & Conditions\n",
            "  version: 1.0\n",
            "  description: Use *bold* text and https://example.com?a=1&b=2 literally.\n",
            "servers:\n",
            "  - url: https://example.com?a=1&b=2\n",
            "x-ferrum-proxy:\n",
            "  id: test\n",
            "  backend_host: x.com\n",
            "  backend_port: 443",
        )
        .as_bytes();
        let (bundle, meta) = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
        assert_eq!(meta.title.as_deref(), Some("Terms & Conditions"));
        assert!(
            meta.description
                .as_deref()
                .is_some_and(|desc| desc.contains("*bold*"))
        );
        assert_eq!(
            meta.server_urls,
            vec!["https://example.com?a=1&b=2".to_string()]
        );
    }

    #[test]
    fn yaml_anchor_like_text_in_block_scalars_allowed() {
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Block Scalars\n",
            "  version: '1.0'\n",
            "  description: |\n",
            "    Use *bold* text in Markdown.\n",
            "    HTML entity text like &copy; is literal here.\n",
            "x-ferrum-proxy:\n",
            "  id: test\n",
            "  backend_host: x.com\n",
            "  backend_port: 443",
        )
        .as_bytes();
        let (bundle, meta) = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
        assert!(
            meta.description
                .as_deref()
                .is_some_and(|desc| desc.contains("*bold*"))
        );
    }

    #[test]
    fn yaml_anchor_after_block_scalar_still_rejected() {
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Block Scalars\n",
            "  version: '1.0'\n",
            "  description: >-\n",
            "    Folded *literal* text is fine.\n",
            "servers: &servers\n",
            "  - url: https://example.com\n",
            "x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}",
        )
        .as_bytes();
        let err = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("anchors and aliases")),
            "expected YAML anchor preflight rejection after block scalar, got {err:?}"
        );
    }

    #[test]
    fn yaml_alias_bomb_rejected() {
        // Build a YAML doc with deeply nested anchors that expands
        // exponentially.  The preflight rejects anchors and aliases before
        // serde_yaml can materialize the expanded tree.
        let yaml = b"a: &a [1,2,3,4,5,6,7,8]\n\
                      b: &b [*a,*a,*a,*a,*a,*a,*a,*a]\n\
                      c: &c [*b,*b,*b,*b,*b,*b,*b,*b]\n\
                      d: &d [*c,*c,*c,*c,*c,*c,*c,*c]\n\
                      e: &e [*d,*d,*d,*d,*d,*d,*d,*d]\n\
                      f: &f [*e,*e,*e,*e,*e,*e,*e,*e]\n\
                      g: &g [*f,*f,*f,*f,*f,*f,*f,*f]\n\
                      openapi: '3.0.0'\n\
                      info: {title: bomb, version: '1.0'}\n\
                      x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}";
        let err = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("anchors and aliases")),
            "alias bomb must be rejected before YAML parsing, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Spec without x-ferrum-consumers passes (positive control)
    // -----------------------------------------------------------------------

    #[test]
    fn test_spec_without_consumers_extension_passes() {
        let spec = minimal_json_spec(minimal_proxy());
        let result = extract(spec.as_bytes(), Some(SpecFormat::Json), "test");
        assert!(
            result.is_ok(),
            "spec without x-ferrum-consumers must pass; got: {:?}",
            result.unwrap_err()
        );
    }

    // -----------------------------------------------------------------------
    // Plugin with matching proxy_id accepted
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_with_matching_proxy_id_accepted() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "matching-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy",
                    "proxy_id": "my-proxy",
                    "config": {{"allowed_origins": ["*"]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test")
            .expect("plugin with matching proxy_id must be accepted");
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(bundle.plugins[0].proxy_id.as_deref(), Some("my-proxy"));
    }

    // -----------------------------------------------------------------------
    // Credential key detection — all FORBIDDEN_CONFIG_KEYS
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_plugin_config_with_keyauth_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "keyauth-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "keyauth": {{"key": "abc123"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "keyauth-plugin" && key == "keyauth"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_basicauth_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "basicauth-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "basicauth": {{"username": "admin", "password": "pass"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "basicauth-plugin" && key == "basicauth"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_hmac_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "hmac-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "hmac": {{"secret": "s3cret"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "hmac-plugin" && key == "hmac"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_mtls_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "mtls-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "mtls": {{"cert_path": "/path/to/cert"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "mtls-plugin" && key == "mtls"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_consumer_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "consumer-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "consumer": {{"id": "alice"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "consumer-plugin" && key == "consumer"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_consumer_groups_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "groups-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "consumer_groups": ["admins"]
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "groups-plugin" && key == "consumer_groups"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_consumers_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "consumers-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "consumers": ["alice", "bob"]
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "consumers-plugin" && key == "consumers"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_credential_key_detection_is_case_insensitive() {
        // Upper-case "JWT" in config key must still be caught.
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "case-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "JWT": {{"secret": "abc"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "case-plugin" && key == "jwt"
            ),
            "case-insensitive credential key detection must catch 'JWT'; got: {err}"
        );
    }

    #[test]
    fn test_credential_key_in_array_element_detected() {
        // Forbidden key nested inside an array element must be caught.
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "arr-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "rules": [
                            {{"keyauth": {{"key": "secret"}}}}
                        ]
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "arr-plugin" && key == "keyauth"
            ),
            "forbidden key inside array element must be detected; got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // find_forbidden_key — clean configs pass
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_forbidden_key_returns_none_for_clean_config() {
        let config = serde_json::json!({
            "window_size": 60,
            "window_count": 100,
            "nested": {
                "deep": {
                    "setting": true
                }
            }
        });
        assert!(
            find_forbidden_key(&config).is_none(),
            "clean config must not trigger forbidden key detection"
        );
    }

    #[test]
    fn test_find_forbidden_key_returns_none_for_primitive_values() {
        assert!(find_forbidden_key(&serde_json::json!(42)).is_none());
        assert!(find_forbidden_key(&serde_json::json!("hello")).is_none());
        assert!(find_forbidden_key(&serde_json::json!(true)).is_none());
        assert!(find_forbidden_key(&serde_json::json!(null)).is_none());
    }

    // -----------------------------------------------------------------------
    // Tag validation — empty tag name
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_tag_name_accepted() {
        // Empty strings don't contain forbidden characters, so they pass
        // the tag validation. The tag array is de-duplicated and sorted, so
        // a single empty tag survives as [""].
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "tags": [{{"name": ""}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let result = extract(spec.as_bytes(), Some(SpecFormat::Json), "test");
        assert!(
            result.is_ok(),
            "empty tag name must be accepted; got: {:?}",
            result.unwrap_err()
        );
    }

    // -----------------------------------------------------------------------
    // hash_resource_bundle — determinism and metadata-independence
    // -----------------------------------------------------------------------

    fn build_test_bundle(proxy_id: &str, api_spec_id: Option<&str>) -> ExtractedBundle {
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "Hash Test", "version": "1"}},
                "x-ferrum-proxy": {{
                    "id": "{proxy_id}",
                    "backend_host": "be.internal",
                    "backend_port": 443
                }},
                "x-ferrum-upstream": {{
                    "id": "hash-upstream",
                    "targets": [{{"host": "t.internal", "port": 443}}]
                }},
                "x-ferrum-plugins": [{{
                    "id": "hash-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy",
                    "config": {{"allowed_origins": ["https://example.com"]}}
                }}]
            }}"#
        );
        let (mut bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();

        // Stamp api_spec_id if requested (simulating post-extraction handler behavior).
        if let Some(spec_id) = api_spec_id {
            bundle.proxy.api_spec_id = Some(spec_id.to_string());
            if let Some(ref mut u) = bundle.upstream {
                u.api_spec_id = Some(spec_id.to_string());
            }
            for p in &mut bundle.plugins {
                p.api_spec_id = Some(spec_id.to_string());
            }
        }

        bundle
    }

    #[test]
    fn test_hash_same_resources_produces_same_hash() {
        let bundle1 = build_test_bundle("hash-proxy", None);
        let bundle2 = build_test_bundle("hash-proxy", None);

        let hash1 = hash_resource_bundle(&bundle1).unwrap();
        let hash2 = hash_resource_bundle(&bundle2).unwrap();

        assert_eq!(hash1, hash2, "identical bundles must produce the same hash");
    }

    #[test]
    fn test_hash_different_resources_produces_different_hash() {
        let bundle1 = build_test_bundle("hash-proxy-a", None);
        let bundle2 = build_test_bundle("hash-proxy-b", None);

        let hash1 = hash_resource_bundle(&bundle1).unwrap();
        let hash2 = hash_resource_bundle(&bundle2).unwrap();

        assert_ne!(
            hash1, hash2,
            "different proxy IDs must produce different hashes"
        );
    }

    #[test]
    fn test_hash_ignores_api_spec_id() {
        let bundle_without = build_test_bundle("hash-proxy", None);
        let bundle_with_a = build_test_bundle("hash-proxy", Some("spec-aaa"));
        let bundle_with_b = build_test_bundle("hash-proxy", Some("spec-bbb"));

        let hash_without = hash_resource_bundle(&bundle_without).unwrap();
        let hash_a = hash_resource_bundle(&bundle_with_a).unwrap();
        let hash_b = hash_resource_bundle(&bundle_with_b).unwrap();

        assert_eq!(
            hash_without, hash_a,
            "api_spec_id must not affect resource hash"
        );
        assert_eq!(
            hash_a, hash_b,
            "different api_spec_id values must produce the same hash"
        );
    }

    #[test]
    fn test_hash_ignores_created_at_and_updated_at() {
        use chrono::{TimeZone, Utc};

        let mut bundle1 = build_test_bundle("hash-proxy", None);
        let mut bundle2 = build_test_bundle("hash-proxy", None);

        // Stamp different timestamps — hash_resource_bundle strips
        // created_at / updated_at via strip_metadata, so these must not
        // affect the hash.
        bundle1.proxy.created_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        bundle1.proxy.updated_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        bundle2.proxy.created_at = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        bundle2.proxy.updated_at = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let hash1 = hash_resource_bundle(&bundle1).unwrap();
        let hash2 = hash_resource_bundle(&bundle2).unwrap();

        assert_eq!(
            hash1, hash2,
            "different created_at/updated_at must not affect resource hash"
        );
    }

    #[test]
    fn test_hash_is_valid_hex_sha256() {
        let bundle = build_test_bundle("hash-proxy", None);
        let hash = hash_resource_bundle(&bundle).unwrap();

        // SHA-256 hex digest is exactly 64 hex characters.
        assert_eq!(
            hash.len(),
            64,
            "hash must be 64 hex chars; got {}",
            hash.len()
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be valid hex; got: {hash}"
        );
    }

    #[test]
    fn test_hash_without_upstream_differs_from_with_upstream() {
        let bundle_with = build_test_bundle("hash-proxy", None);

        // Build a bundle without upstream.
        let spec_no_upstream = r#"{
            "openapi": "3.1.0",
            "info": {"title": "Hash Test", "version": "1"},
            "x-ferrum-proxy": {
                "id": "hash-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-plugins": [{
                "id": "hash-plugin",
                "plugin_name": "cors",
                "scope": "proxy",
                "config": {"allowed_origins": ["https://example.com"]}
            }]
        }"#;
        let (bundle_without, _) =
            extract(spec_no_upstream.as_bytes(), Some(SpecFormat::Json), "test").unwrap();

        let hash_with = hash_resource_bundle(&bundle_with).unwrap();
        let hash_without = hash_resource_bundle(&bundle_without).unwrap();

        assert_ne!(
            hash_with, hash_without,
            "bundle with upstream must hash differently from bundle without"
        );
    }

    // -----------------------------------------------------------------------
    // Basic extraction: doc missing x-ferrum-proxy
    // -----------------------------------------------------------------------

    #[test]
    fn test_doc_missing_proxy_extension_returns_error() {
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "No Proxy", "version": "1"},
            "x-ferrum-upstream": {
                "id": "orphan-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(err, ExtractError::MissingProxyExtension),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Basic extraction: doc with only x-ferrum-upstream extracts upstream
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_upstream_sets_namespace() {
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "up-ns-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-upstream": {
                "id": "up-ns-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "custom-ns").unwrap();
        let upstream = bundle.upstream.as_ref().expect("upstream must be present");
        assert_eq!(
            upstream.namespace, "custom-ns",
            "upstream namespace must be overridden to the caller's namespace"
        );
    }

    // -----------------------------------------------------------------------
    // Basic extraction: plugins get namespace stamped
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_plugins_get_namespace_stamped() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "ns-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy",
                    "config": {{"allowed_origins": ["*"]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "my-namespace").unwrap();
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(
            bundle.plugins[0].namespace, "my-namespace",
            "plugin namespace must be stamped with the caller's namespace"
        );
    }

    // -----------------------------------------------------------------------
    // Operation count extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_operation_count_from_paths() {
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "T", "version": "1"}},
                "paths": {{
                    "/users": {{
                        "get": {{"summary": "List users"}},
                        "post": {{"summary": "Create user"}}
                    }},
                    "/users/{{id}}": {{
                        "get": {{"summary": "Get user"}},
                        "put": {{"summary": "Update user"}},
                        "delete": {{"summary": "Delete user"}}
                    }}
                }},
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(
            meta.operation_count, 5,
            "operation_count must be 5 (2 + 3 HTTP methods); got {}",
            meta.operation_count
        );
    }
}
