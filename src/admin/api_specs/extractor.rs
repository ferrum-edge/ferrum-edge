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
use crate::config::types::{PluginConfig, PluginScope, Proxy, Upstream};
use regex::Regex;
use std::sync::LazyLock;

/// HTTP method keys counted when computing `operation_count`.
const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "delete", "options", "head", "patch", "trace",
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Resources extracted from an OpenAPI spec document.
#[derive(Debug)]
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
}

// ---------------------------------------------------------------------------
// Regex for OpenAPI 3.x version strings
// ---------------------------------------------------------------------------

/// Matches `3.MINOR.PATCH` with an optional pre-release suffix like `-rc1`.
static OPENAPI3_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^3\.\d+\.\d+(-.+)?$").expect("invalid openapi3 version regex"));

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
    let fmt = declared_format.unwrap_or_else(|| autodetect_format(body));

    // Parse to serde_json::Value.  serde_yaml accepts JSON as a YAML subset, so
    // a single serde_yaml parse covers both formats.  For JSON we still prefer
    // serde_json so the error messages mention "JSON" rather than "YAML".
    let root: serde_json::Value = match fmt {
        SpecFormat::Json => {
            serde_json::from_slice(body).map_err(|e| ExtractError::InvalidJson(e.to_string()))?
        }
        SpecFormat::Yaml => {
            let yv: serde_yaml::Value = serde_yaml::from_slice(body)
                .map_err(|e| ExtractError::InvalidYaml(e.to_string()))?;
            serde_json::to_value(yv).map_err(|e| ExtractError::InvalidYaml(e.to_string()))?
        }
    };

    // --- Version detection -----------------------------------------------
    let version = detect_version(&root)?;

    // --- info.title / info.version ---------------------------------------
    let title = root
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let info_version = root
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // --- Tier 1 metadata (Wave 5) ----------------------------------------
    let tier1 = extract_spec_metadata(&root, &version);

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

    // --- x-ferrum-upstream (optional) ------------------------------------
    let upstream = if let Some(up_val) = root.get("x-ferrum-upstream") {
        let mut up: Upstream = serde_json::from_value(up_val.clone()).map_err(|e| {
            ExtractError::MalformedExtension {
                which: "x-ferrum-upstream",
                error: e.to_string(),
            }
        })?;
        up.namespace = namespace.to_string();
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
    let plugins = if let Some(plugins_val) = root.get("x-ferrum-plugins") {
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
            if let Some(key) = find_forbidden_key(&pc.config) {
                return Err(ExtractError::PluginContainsCredentials {
                    plugin_id: pc.id,
                    key: key.to_string(),
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

    let metadata = SpecMetadata {
        version,
        format: fmt,
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

/// Truncate a string at a UTF-8 character boundary so the result is ≤ `max_bytes` bytes.
fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // Walk char boundaries; keep the last one that fits within max_bytes.
    let mut last_boundary = 0usize;
    for (i, _) in s.char_indices() {
        if i > max_bytes {
            break;
        }
        last_boundary = i;
    }
    s[..last_boundary].to_string()
}

/// Extract Tier 1 metadata from the parsed spec root value.
///
/// Handles both Swagger 2.0 and OpenAPI 3.x.
pub fn extract_spec_metadata(root: &serde_json::Value, version: &str) -> ExtractedMetadata {
    let info = root.get("info");

    // description — truncated to 4096 bytes.
    let description = info
        .and_then(|i| i.get("description"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, 4096));

    // contact.name / email
    let contact = info.and_then(|i| i.get("contact"));
    let contact_name = contact
        .and_then(|c| c.get("name"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let contact_email = contact
        .and_then(|c| c.get("email"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // license.name / identifier-or-url
    let license = info.and_then(|i| i.get("license"));
    let license_name = license
        .and_then(|l| l.get("name"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let license_identifier = license
        .and_then(|l| {
            // 3.1+ uses `identifier`; fallback to `url`
            l.get("identifier").or_else(|| l.get("url"))
        })
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // tags — top-level `tags[].name` (both 2.0 and 3.x)
    let mut tags: Vec<String> = root
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("name"))
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    tags.sort();
    tags.dedup();

    // server_urls
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
                    .map(|scheme| format!("{scheme}://{host}{base_path}"))
                    .collect()
            }
        }
    } else {
        // OpenAPI 3.x: servers[].url
        root.get("servers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("url"))
                    .filter_map(|v| v.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
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
                .count() as u32
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
pub fn hash_resource_bundle(bundle: &ExtractedBundle) -> String {
    let mut buf = Vec::new();

    // Proxy — strip metadata then serialize
    let proxy_json =
        strip_metadata(serde_json::to_value(&bundle.proxy).unwrap_or(serde_json::Value::Null));
    buf.extend_from_slice(&serde_json::to_vec(&proxy_json).unwrap_or_default());
    buf.push(b'|');

    // Upstream (optional)
    if let Some(u) = &bundle.upstream {
        let upstream_json =
            strip_metadata(serde_json::to_value(u).unwrap_or(serde_json::Value::Null));
        buf.extend_from_slice(&serde_json::to_vec(&upstream_json).unwrap_or_default());
    }
    buf.push(b'|');

    // Plugins sorted by id for determinism
    let mut plugins: Vec<_> = bundle.plugins.iter().collect();
    plugins.sort_by(|a, b| a.id.cmp(&b.id));
    for p in plugins {
        let pj = strip_metadata(serde_json::to_value(p).unwrap_or(serde_json::Value::Null));
        buf.extend_from_slice(&serde_json::to_vec(&pj).unwrap_or_default());
        buf.push(b';');
    }

    crate::admin::spec_codec::sha256_hex(&buf)
}

/// Remove metadata-only fields from a JSON value so they don't affect the hash.
fn strip_metadata(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        obj.remove("api_spec_id");
        obj.remove("created_at");
        obj.remove("updated_at");
    }
    v
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
        && OPENAPI3_VERSION_RE.is_match(s)
    {
        return Ok(s.to_string());
    }

    Err(ExtractError::UnknownVersion)
}

/// Recursively walk a JSON value and return the first key whose name appears
/// in [`FORBIDDEN_CONFIG_KEYS`], or `None` if the value is clean.
///
/// The walk visits every level of objects and every element of arrays.
/// The walk is on the plugin's `config` VALUE only, not on the plugin
/// metadata fields (`plugin_name`, `scope`, etc.), so legitimate auth plugins
/// (`plugin_name: "jwt"`) are not falsely flagged.
fn find_forbidden_key(value: &serde_json::Value) -> Option<&'static str> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                // Check the key itself.
                if let Some(found) = FORBIDDEN_CONFIG_KEYS.iter().find(|&&k| k == key.as_str()) {
                    return Some(found);
                }
                // Recurse into the child value.
                if let Some(found) = find_forbidden_key(child) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(found) = find_forbidden_key(item) {
                    return Some(found);
                }
            }
            None
        }
        // Primitives carry no keys.
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
        let spec = r#"
swagger: "2.0"
info:
  title: "YAML Test"
  version: "2.0.0"
x-ferrum-proxy:
  id: "yaml-proxy"
  backend_host: "backend.example.com"
  backend_port: 8080
"#;
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
        assert_eq!(bundle.proxy.id, "yaml-proxy");
        assert!(bundle.upstream.is_none());
        assert!(bundle.plugins.is_empty());
    }

    #[test]
    fn test_full_bundle_proxy_upstream_plugins() {
        let spec = r#"
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
            "config": {"limit": 100, "window": "minute"}
        },
        {
            "id": "plugin-2",
            "plugin_name": "cors",
            "scope": "proxy",
            "config": {"origins": ["https://example.com"]}
        }
    ]
}
"#;
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
                    "config": {{"window_size": 60, "window_count": 100}}
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
                    "config": {{}}
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
}
