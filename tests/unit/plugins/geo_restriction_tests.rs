use base64::Engine;
use chrono::Utc;
use ferrum_edge::PluginCache;
use ferrum_edge::config::file_loader::load_config_from_file;
use ferrum_edge::config::types::{
    CURRENT_CONFIG_VERSION, GatewayConfig, MAX_COUNTRY_MMDB_SIZE_BYTES, PluginConfig, PluginScope,
    default_namespace, load_validated_country_mmdb, validate_mmdb_file,
};
use ferrum_edge::plugins::geo_restriction::GeoRestriction;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, priority,
    validate_plugin_config,
};
use http::{HeaderMap, HeaderValue};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

const COUNTRY_MMDB_B64: &str = include_str!("../../fixtures/maxmind/GeoIP2-Country-Test.mmdb.b64");

fn country_mmdb_bytes() -> Vec<u8> {
    let encoded: String = COUNTRY_MMDB_B64.lines().collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("MaxMind fixture base64 decodes")
}

#[test]
fn upstream_country_mmdb_fixture_has_pinned_sha256() {
    let digest = Sha256::digest(country_mmdb_bytes());
    assert_eq!(
        hex::encode(digest),
        "b37601903448683d241af52893c8cbf0fed461e0cdebe0bfaca01891fdeb6db9"
    );
}

fn write_fixture(directory: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.path().join(name);
    std::fs::write(&path, bytes).expect("write generated MMDB fixture");
    path
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("temporary MMDB path is UTF-8")
}

fn replace_database_type(mut bytes: Vec<u8>) -> Vec<u8> {
    const ORIGINAL: &[u8] = b"GeoIP2-Country";
    const REPLACEMENT: &[u8] = b"GeoIP2-ASN-XYZ";
    assert_eq!(ORIGINAL.len(), REPLACEMENT.len());
    let offset = bytes
        .windows(ORIGINAL.len())
        .position(|window| window == ORIGINAL)
        .expect("fixture contains its database type");
    bytes[offset..offset + ORIGINAL.len()].copy_from_slice(REPLACEMENT);
    bytes
}

fn replace_direct_country_with_unsupported_code(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut replacements = 0;
    for offset in 0..bytes.len().saturating_sub(1) {
        if &bytes[offset..offset + 2] == b"SE" {
            bytes[offset..offset + 2].copy_from_slice(b"ZZ");
            replacements += 1;
        }
    }
    assert!(replacements > 0, "fixture contains the SE country code");

    let reader = maxminddb::Reader::from_source(bytes.as_slice())
        .expect("country-code replacement preserves MMDB structure");
    reader
        .verify()
        .expect("country-code replacement preserves comprehensive verification");
    let lookup = reader
        .lookup("89.160.20.112".parse().unwrap())
        .expect("fixture address still resolves");
    let country: Option<&str> = lookup
        .decode_path(&maxminddb::path!["country", "iso_code"])
        .expect("fixture country path still decodes");
    assert_eq!(country, Some("ZZ"));
    drop(reader);

    bytes
}

fn replace_direct_country_with_supported_code(
    mut bytes: Vec<u8>,
    replacement: &[u8; 2],
) -> Vec<u8> {
    let mut replacements = 0;
    for offset in 0..bytes.len().saturating_sub(1) {
        if &bytes[offset..offset + 2] == b"SE" {
            bytes[offset..offset + 2].copy_from_slice(replacement);
            replacements += 1;
        }
    }
    assert!(replacements > 0, "fixture contains the SE country code");

    let reader = maxminddb::Reader::from_source(bytes.as_slice())
        .expect("supported country-code replacement preserves MMDB structure");
    reader
        .verify()
        .expect("supported country-code replacement preserves verification");
    drop(reader);
    bytes
}

fn partially_corrupt_mmdb(mut bytes: Vec<u8>) -> Vec<u8> {
    let reader = maxminddb::Reader::from_source(bytes.as_slice())
        .expect("valid fixture opens before corruption");
    let search_tree_size =
        reader.metadata.node_count as usize * reader.metadata.record_size as usize / 4;
    drop(reader);

    for offset in 0..search_tree_size {
        let original = bytes[offset];
        bytes[offset] ^= 0xff;
        let verification_rejects = maxminddb::Reader::from_source(bytes.as_slice())
            .is_ok_and(|candidate| candidate.verify().is_err());
        if verification_rejects {
            return bytes;
        }
        bytes[offset] = original;
    }
    panic!("failed to derive a partially corrupt MMDB fixture");
}

fn request_context(client_ip: &str) -> RequestContext {
    RequestContext::new(
        client_ip.to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn materialized_spoofed_context(client_ip: &str) -> RequestContext {
    let mut raw_headers = HeaderMap::new();
    raw_headers.append("x-geo-country", HeaderValue::from_static("attacker-first"));
    raw_headers.append("x-geo-country", HeaderValue::from_static("attacker-second"));
    let mut ctx = request_context(client_ip);
    ctx.set_raw_headers(raw_headers);
    ctx.materialize_headers();
    ctx
}

fn make_geo_plugin(id: &str, enabled: bool, config: serde_json::Value) -> PluginConfig {
    PluginConfig {
        id: id.into(),
        namespace: default_namespace(),
        plugin_name: "geo_restriction".into(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_new_missing_db_path_fails() {
    let config = json!({
        "allow_countries": ["US"]
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("db_path"));
}

#[test]
fn test_new_invalid_db_path_succeeds_with_none_reader() {
    // Constructor no longer fails on missing .mmdb file — it stores reader: None
    // and degrades gracefully at request time using on_lookup_failure policy.
    let config = json!({
        "db_path": "/nonexistent/path/to/GeoLite2-Country.mmdb",
        "allow_countries": ["US"]
    });
    let result = GeoRestriction::new(&config);
    assert!(
        result.is_ok(),
        "Constructor should succeed with missing file"
    );
}

#[test]
fn test_plugin_metadata_and_protocol_flags() {
    let config = json!({
        "db_path": "/nonexistent/path/to/GeoLite2-Country.mmdb",
        "allow_countries": ["US"]
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    assert_eq!(plugin.name(), "geo_restriction");
    assert_eq!(plugin.priority(), priority::GEO_RESTRICTION);
    assert_eq!(plugin.priority(), 175);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_new_no_countries_fails() {
    // With reader now optional, this properly tests the no-countries validation.
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb"
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(
        result.err().unwrap().contains("allow_countries"),
        "Should fail due to missing country lists"
    );
}

#[test]
fn test_new_both_allow_and_deny_fails() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["US"],
        "deny_countries": ["CN"]
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(
        result.err().unwrap().contains("mutually exclusive"),
        "Should fail due to both allow and deny lists"
    );
}

#[test]
fn test_new_rejects_invalid_country_code() {
    for country in ["USA", " US ", "U1"] {
        let config = json!({
            "db_path": "/nonexistent/path/to/test.mmdb",
            "allow_countries": [country]
        });
        let result = GeoRestriction::new(&config);
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("country code"));
    }
}

#[test]
fn test_new_rejects_unassigned_and_alias_country_codes() {
    for country in ["ZZ", "EU", "UK"] {
        let config = json!({
            "db_path": "/nonexistent/path/to/test.mmdb",
            "allow_countries": [country]
        });
        let result = GeoRestriction::new(&config);
        assert!(
            result.is_err(),
            "unassigned code must be rejected: {country}"
        );
        assert!(result.err().unwrap().contains("unassigned"));
    }
}

#[test]
fn test_new_accepts_supported_country_codes_case_insensitively() {
    for country in ["ad", "uS", "xK", "Zw"] {
        let config = json!({
            "db_path": "/nonexistent/path/to/test.mmdb",
            "allow_countries": [country]
        });
        assert!(
            GeoRestriction::new(&config).is_ok(),
            "assigned code must be accepted case-insensitively: {country}"
        );
    }
}

#[test]
fn test_new_rejects_unknown_and_null_fields() {
    for config in [
        json!({
            "db_path": "/nonexistent/path/to/test.mmdb",
            "allow_countries": ["US"],
            "on_lookup_failur": "deny"
        }),
        json!({
            "db_path": "/nonexistent/path/to/test.mmdb",
            "allow_countries": null
        }),
        json!({
            "db_path": "/nonexistent/path/to/test.mmdb",
            "allow_countries": ["US"],
            "inject_headers": null
        }),
        json!({
            "db_path": "/nonexistent/path/to/test.mmdb",
            "allow_countries": ["US"],
            "on_lookup_failure": null
        }),
    ] {
        assert!(
            GeoRestriction::new(&config).is_err(),
            "strict config must reject {config}"
        );
    }
}

#[test]
fn test_new_rejects_non_string_country_code() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "deny_countries": [42]
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("entries must be strings"));
}

#[test]
fn test_new_rejects_non_array_country_list() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": "US"
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("allow_countries"));
}

#[test]
fn test_new_rejects_invalid_on_lookup_failure() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["US"],
        "on_lookup_failure": "block"
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("on_lookup_failure"));
}

#[test]
fn test_new_rejects_non_bool_inject_headers() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["US"],
        "inject_headers": "yes"
    });
    let result = GeoRestriction::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("inject_headers"));
}

#[tokio::test]
async fn test_missing_reader_uses_deny_lookup_failure_policy() {
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["US"],
        "on_lookup_failure": "deny"
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    let mut ctx = RequestContext::new(
        "203.0.113.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}

#[tokio::test]
async fn test_missing_reader_uses_allow_lookup_failure_policy_fail_open() {
    // #47: with an explicit `allow` policy and a missing .mmdb, the geo gate
    // fails open — the request is permitted (Continue). The fix surfaces this
    // via logging (a one-time warn) without changing the behavior, so we lock
    // the fail-open behavior here.
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["US"],
        "on_lookup_failure": "allow"
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    let mut ctx = RequestContext::new(
        "203.0.113.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "explicit allow policy must fail open (Continue) when the .mmdb is missing"
    );
}

#[tokio::test]
async fn test_default_on_lookup_failure_is_allow_fail_open() {
    // #47: when `on_lookup_failure` is omitted it defaults to `allow`
    // (fail-open). A missing .mmdb therefore permits all traffic. The
    // constructor logs a one-time startup warning in this case; behavior is
    // unchanged (Continue), which we assert here.
    let config = json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "deny_countries": ["CN"]
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    let mut ctx = RequestContext::new(
        "203.0.113.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "omitted on_lookup_failure defaults to allow (fail-open → Continue)"
    );
}

#[tokio::test]
async fn valid_mmdb_preserves_direct_country_precedence() {
    let directory = TempDir::new().unwrap();
    let path = write_fixture(&directory, "country.mmdb", &country_mmdb_bytes());

    // 89.160.20.112 is direct country SE and registered country DE in the
    // generated upstream fixture. The direct country must win.
    let deny_direct = GeoRestriction::new(&json!({
        "db_path": path_text(&path),
        "deny_countries": ["SE"],
        "on_lookup_failure": "deny"
    }))
    .unwrap();
    let mut direct_ctx = request_context("89.160.20.112");
    assert!(matches!(
        deny_direct.on_request_received(&mut direct_ctx).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    let deny_registered = GeoRestriction::new(&json!({
        "db_path": path_text(&path),
        "deny_countries": ["DE"],
        "on_lookup_failure": "deny"
    }))
    .unwrap();
    let mut registered_ctx = request_context("89.160.20.112");
    assert!(matches!(
        deny_registered
            .on_request_received(&mut registered_ctx)
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn valid_mmdb_canonicalizes_ipv4_mapped_ipv6_for_policy() {
    let directory = TempDir::new().unwrap();
    let path = write_fixture(&directory, "country.mmdb", &country_mmdb_bytes());
    let plugin = GeoRestriction::new(&json!({
        "db_path": path_text(&path),
        "deny_countries": ["SE"],
        "on_lookup_failure": "allow"
    }))
    .unwrap();

    for client_ip in ["89.160.20.112", "::ffff:89.160.20.112"] {
        let mut ctx = request_context(client_ip);
        assert!(
            matches!(
                plugin.on_request_received(&mut ctx).await,
                PluginResult::Reject {
                    status_code: 403,
                    ..
                }
            ),
            "native and mapped forms must receive the same country decision: {client_ip}"
        );
    }
}

#[tokio::test]
async fn authoritative_header_overwrites_spoof_only_after_successful_lookup() {
    let directory = TempDir::new().unwrap();
    let path = write_fixture(&directory, "country.mmdb", &country_mmdb_bytes());
    let plugin = GeoRestriction::new(&json!({
        "db_path": path_text(&path),
        "allow_countries": ["SE"],
        "inject_headers": true,
        "on_lookup_failure": "deny"
    }))
    .unwrap();
    let mut ctx = materialized_spoofed_context("89.160.20.112");

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.headers.get("x-geo-country").map(String::as_str),
        Some("SE")
    );
    assert_eq!(ctx.backend_geo_country(), Some("SE"));

    ctx.headers
        .insert("x-geo-country".to_string(), "ATTACKER".to_string());
    assert_eq!(
        ctx.backend_geo_country(),
        Some("SE"),
        "mutable plugin headers must not replace the private GeoIP assertion"
    );
}

#[tokio::test]
async fn fail_open_preserves_ingress_country_header_stripping() {
    for inject_headers in [false, true] {
        let plugin = GeoRestriction::new(&json!({
            "db_path": "/nonexistent/path/to/test.mmdb",
            "allow_countries": ["US"],
            "inject_headers": inject_headers,
            "on_lookup_failure": "allow"
        }))
        .unwrap();
        let mut raw_headers = HeaderMap::new();
        raw_headers.append("x-geo-country", HeaderValue::from_static("attacker-first"));
        raw_headers.append("x-geo-country", HeaderValue::from_static("attacker-second"));
        assert_eq!(raw_headers.get_all("x-geo-country").iter().count(), 2);
        let mut ctx = request_context("203.0.113.1");
        ctx.set_raw_headers(raw_headers);
        ctx.materialize_headers();
        assert!(
            !ctx.headers.contains_key("x-geo-country"),
            "the production materialization boundary strips every spoofed value"
        );

        assert!(matches!(
            plugin.on_request_received(&mut ctx).await,
            PluginResult::Continue
        ));
        assert!(!ctx.headers.contains_key("x-geo-country"));
    }
}

#[tokio::test]
async fn later_instances_preserve_an_earlier_authoritative_assertion() {
    let directory = TempDir::new().unwrap();
    let path = write_fixture(&directory, "country.mmdb", &country_mmdb_bytes());
    let authoritative = GeoRestriction::new(&json!({
        "db_path": path_text(&path),
        "allow_countries": ["SE"],
        "inject_headers": true,
        "on_lookup_failure": "deny"
    }))
    .unwrap();
    let non_injecting = GeoRestriction::new(&json!({
        "db_path": path_text(&path),
        "allow_countries": ["SE"],
        "inject_headers": false,
        "on_lookup_failure": "deny"
    }))
    .unwrap();
    let fail_open = GeoRestriction::new(&json!({
        "db_path": "/nonexistent/path/to/test.mmdb",
        "allow_countries": ["SE"],
        "inject_headers": true,
        "on_lookup_failure": "allow"
    }))
    .unwrap();

    for later in [&non_injecting, &fail_open] {
        let mut ctx = materialized_spoofed_context("89.160.20.112");
        assert!(matches!(
            authoritative.on_request_received(&mut ctx).await,
            PluginResult::Continue
        ));
        assert_eq!(ctx.headers.get("x-geo-country").unwrap(), "SE");
        assert!(matches!(
            later.on_request_received(&mut ctx).await,
            PluginResult::Continue
        ));
        assert_eq!(
            ctx.headers.get("x-geo-country").map(String::as_str),
            Some("SE"),
            "a later non-authoritative instance must not erase an earlier assertion"
        );
    }
}

#[tokio::test]
async fn live_reader_owns_bytes_across_in_place_update_and_reload() {
    let directory = TempDir::new().unwrap();
    let valid = country_mmdb_bytes();
    let corrupt = partially_corrupt_mmdb(valid.clone());
    let path = write_fixture(&directory, "country.mmdb", &valid);
    let config = json!({
        "db_path": path_text(&path),
        "deny_countries": ["SE"],
        "on_lookup_failure": "deny"
    });
    let old_generation = GeoRestriction::new(&config).unwrap();

    std::fs::write(&path, &corrupt).unwrap();
    assert!(
        GeoRestriction::new(&config).is_err(),
        "a corrupt replacement must not publish"
    );

    let mut in_flight = request_context("89.160.20.112");
    assert!(matches!(
        old_generation.on_request_received(&mut in_flight).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    std::fs::write(&path, &valid).unwrap();
    assert!(
        GeoRestriction::new(&config).is_ok(),
        "a fully valid replacement can publish on reload"
    );
}

// --- validate_mmdb_file tests ---

#[test]
fn test_validate_mmdb_file_nonexistent() {
    let result = validate_mmdb_file("geo_restriction.db_path", "/nonexistent/path/test.mmdb");
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("not accessible"));
}

#[test]
fn test_validate_mmdb_file_is_directory() {
    let result = validate_mmdb_file("geo_restriction.db_path", "/tmp");
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("not a regular file"));
}

#[cfg(unix)]
#[test]
fn validate_mmdb_file_rejects_fifo_before_blocking_open() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let directory = TempDir::new().unwrap();
    let path = directory.path().join("country.mmdb");
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a live, NUL-terminated path and the mode contains
    // only ordinary permission bits.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

    let result = validate_mmdb_file("geo_restriction.db_path", path_text(&path));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("not a regular file"));
}

#[test]
fn test_validate_mmdb_file_rejects_invalid_mmdb_contents() {
    let temp_path = std::env::temp_dir().join(format!(
        "ferrum-edge-invalid-geo-{}.mmdb",
        std::process::id()
    ));
    std::fs::write(&temp_path, b"not a maxmind database").unwrap();

    let result = validate_mmdb_file(
        "geo_restriction.db_path",
        temp_path.to_str().expect("temp path utf-8"),
    );

    let _ = std::fs::remove_file(&temp_path);

    assert!(result.is_err());
    assert!(result.err().unwrap().contains("not a valid readable .mmdb"));
}

#[test]
fn validate_mmdb_file_accepts_verified_country_fixture() {
    let directory = TempDir::new().unwrap();
    let path = write_fixture(&directory, "country.mmdb", &country_mmdb_bytes());
    assert!(validate_mmdb_file("geo_restriction.db_path", path_text(&path)).is_ok());
}

#[test]
fn validate_mmdb_file_rejects_oversized_sparse_file_before_reading() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("oversized.mmdb");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(MAX_COUNTRY_MMDB_SIZE_BYTES + 1).unwrap();
    drop(file);

    let validation = validate_mmdb_file("geo_restriction.db_path", path_text(&path));
    assert!(validation.is_err());
    assert!(validation.err().unwrap().contains("maximum supported size"));
}

#[test]
fn plugin_shape_validation_does_not_scan_node_local_mmdb() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("oversized.mmdb");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(MAX_COUNTRY_MMDB_SIZE_BYTES + 1).unwrap();
    drop(file);
    let config = json!({
        "db_path": path_text(&path),
        "allow_countries": ["US"],
        "on_lookup_failure": "deny"
    });

    assert!(
        validate_plugin_config("geo_restriction", &config).is_ok(),
        "generic plugin validation must remain shape-only for file dependencies"
    );
    assert!(
        validate_mmdb_file("geo_restriction.db_path", path_text(&path)).is_err(),
        "the mode-aware dependency stage must still enforce the MMDB bound"
    );
}

#[test]
fn reload_rereads_same_length_timestamp_preserving_replacement() {
    let directory = TempDir::new().unwrap();
    let valid = country_mmdb_bytes();
    let replacement = replace_direct_country_with_unsupported_code(valid.clone());
    assert_eq!(valid.len(), replacement.len());
    let path = write_fixture(&directory, "country.mmdb", &valid);
    let old_snapshot = load_validated_country_mmdb(path_text(&path)).unwrap();
    let old_modified = std::fs::metadata(&path).unwrap().modified().unwrap();

    std::fs::write(&path, replacement).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(old_modified))
        .unwrap();

    assert!(
        load_validated_country_mmdb(path_text(&path)).is_err(),
        "metadata-equivalent replacement must always be re-digested"
    );
    assert_eq!(old_snapshot.metadata.database_type, "GeoIP2-Country");
}

#[test]
#[serial_test::serial(country_mmdb_validation_handoff)]
fn rejected_config_generation_releases_mmdb_handoff() {
    let directory = TempDir::new().unwrap();
    let unique = replace_direct_country_with_supported_code(country_mmdb_bytes(), b"XK");
    let path = write_fixture(&directory, "country-xk.mmdb", &unique);
    let snapshot = load_validated_country_mmdb(path_text(&path)).unwrap();
    let weak_snapshot = Arc::downgrade(&snapshot);

    let config_path = directory.path().join("rejected.json");
    let config = json!({
        "version": "1",
        "expected_resource_counts": {
            "proxies": 1,
            "consumers": 0,
            "upstreams": 0,
            "plugin_configs": 1
        },
        "proxies": [{
            "id": "invalid-stream",
            "backend_scheme": "tcp",
            "backend_host": "127.0.0.1",
            "backend_port": 9000
        }],
        "consumers": [],
        "plugin_configs": [{
            "id": "geo",
            "plugin_name": "geo_restriction",
            "config": {
                "db_path": path_text(&path),
                "allow_countries": ["XK"],
                "on_lookup_failure": "deny"
            },
            "scope": "global",
            "enabled": true
        }]
    });
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

    let error = load_config_from_file(
        path_text(&config_path),
        30,
        &ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        "ferrum",
    )
    .expect_err("the stream validation stage must reject this generation");
    assert!(error.to_string().contains("stream proxy"));
    drop(snapshot);
    assert!(
        weak_snapshot.upgrade().is_none(),
        "rejected generation must release its validation handoff snapshot"
    );
}

#[tokio::test]
#[serial_test::serial(country_mmdb_validation_handoff)]
async fn accepted_generation_hands_every_distinct_mmdb_path_to_cache_build() {
    let directory = TempDir::new().unwrap();
    let first_path = write_fixture(&directory, "country-one.mmdb", &country_mmdb_bytes());
    let second_path = write_fixture(&directory, "country-two.mmdb", &country_mmdb_bytes());
    let config_path = directory.path().join("accepted.json");
    let config = json!({
        "version": "1",
        "expected_resource_counts": {
            "proxies": 1,
            "consumers": 0,
            "upstreams": 0,
            "plugin_configs": 2
        },
        "proxies": [{
            "id": "http",
            "listen_path": "/",
            "backend_host": "127.0.0.1",
            "backend_port": 9000
        }],
        "consumers": [],
        "plugin_configs": [
            {
                "id": "geo-one",
                "plugin_name": "geo_restriction",
                "config": {
                    "db_path": path_text(&first_path),
                    "deny_countries": ["SE"],
                    "on_lookup_failure": "allow"
                },
                "scope": "global",
                "enabled": true
            },
            {
                "id": "geo-two",
                "plugin_name": "geo_restriction",
                "config": {
                    "db_path": path_text(&second_path),
                    "deny_countries": ["SE"],
                    "on_lookup_failure": "allow"
                },
                "scope": "global",
                "enabled": true
            }
        ]
    });
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

    let loaded = load_config_from_file(
        path_text(&config_path),
        30,
        &ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        "ferrum",
    )
    .expect("both MMDB paths pass one accepted validation generation");
    std::fs::remove_file(&first_path).unwrap();
    std::fs::remove_file(&second_path).unwrap();

    PluginCache::new(&GatewayConfig::default())
        .expect("an unrelated cache build must not consume the accepted handoff");
    let cache = PluginCache::new(&loaded).expect("cache build claims both validated snapshots");
    let plugins = cache.request_view("http", ProxyProtocol::Http).plugins();
    let geo_plugins = plugins
        .iter()
        .filter(|plugin| plugin.name() == "geo_restriction")
        .collect::<Vec<_>>();
    assert_eq!(geo_plugins.len(), 2);
    for plugin in geo_plugins {
        let mut ctx = request_context("89.160.20.112");
        assert!(matches!(
            plugin.on_request_received(&mut ctx).await,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ));
    }
}

#[test]
fn validated_mmdb_snapshots_are_shared_across_live_instances() {
    let directory = TempDir::new().unwrap();
    let path = write_fixture(&directory, "country.mmdb", &country_mmdb_bytes());

    let first = load_validated_country_mmdb(path_text(&path)).unwrap();
    let second = load_validated_country_mmdb(path_text(&path)).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
}

#[tokio::test]
async fn delta_budget_counts_retained_and_rebuilt_mmdb_snapshots() {
    let directory = TempDir::new().unwrap();
    let original_bytes = country_mmdb_bytes();
    let first_path = write_fixture(&directory, "country-one.mmdb", &original_bytes);
    let second_path = write_fixture(&directory, "country-two.mmdb", &original_bytes);
    let timestamp = "2026-01-01T00:00:00Z";
    let mut config: GatewayConfig = serde_json::from_value(json!({
        "version": CURRENT_CONFIG_VERSION,
        "proxies": [
            {
                "id": "p1",
                "listen_path": "/one",
                "backend_host": "127.0.0.1",
                "backend_port": 9001,
                "plugins": [{"plugin_config_id": "geo-one"}],
                "created_at": timestamp,
                "updated_at": timestamp
            },
            {
                "id": "p2",
                "listen_path": "/two",
                "backend_host": "127.0.0.1",
                "backend_port": 9002,
                "plugins": [{"plugin_config_id": "geo-two"}],
                "created_at": timestamp,
                "updated_at": timestamp
            }
        ],
        "consumers": [],
        "plugin_configs": [
            {
                "id": "geo-one",
                "plugin_name": "geo_restriction",
                "config": {
                    "db_path": path_text(&first_path),
                    "deny_countries": ["SE"],
                    "on_lookup_failure": "deny"
                },
                "scope": "proxy",
                "proxy_id": "p1",
                "created_at": timestamp,
                "updated_at": timestamp
            },
            {
                "id": "geo-two",
                "plugin_name": "geo_restriction",
                "config": {
                    "db_path": path_text(&second_path),
                    "deny_countries": ["SE"],
                    "on_lookup_failure": "deny"
                },
                "scope": "proxy",
                "proxy_id": "p2",
                "created_at": timestamp,
                "updated_at": timestamp
            }
        ]
    }))
    .unwrap();
    config.normalize_fields();

    let cache = PluginCache::new(&config).unwrap();
    assert_eq!(
        cache.country_mmdb_snapshot_bytes(),
        original_bytes.len() as u64,
        "identical content must share one live snapshot"
    );

    let replacement = replace_direct_country_with_supported_code(original_bytes.clone(), b"US");
    assert_eq!(replacement.len(), original_bytes.len());
    std::fs::write(&second_path, replacement).unwrap();
    config.plugin_configs[1].updated_at = "2026-01-01T00:00:01Z".parse().unwrap();
    cache
        .apply_delta(&config, &HashSet::from(["p2".to_string()]), &[], false)
        .unwrap();

    assert_eq!(
        cache.country_mmdb_snapshot_bytes(),
        (original_bytes.len() as u64) * 2,
        "the resulting generation budget includes p1's retained snapshot and p2's rebuilt snapshot"
    );
    let p1_plugins = cache.request_view("p1", ProxyProtocol::Http).plugins();
    let p1_geo = p1_plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let mut p1 = request_context("89.160.20.112");
    assert!(matches!(
        p1_geo.on_request_received(&mut p1).await,
        PluginResult::Reject { .. }
    ));
    let p2_plugins = cache.request_view("p2", ProxyProtocol::Http).plugins();
    let p2_geo = p2_plugins
        .iter()
        .find(|plugin| plugin.name() == "geo_restriction")
        .unwrap();
    let mut p2 = request_context("89.160.20.112");
    assert!(matches!(
        p2_geo.on_request_received(&mut p2).await,
        PluginResult::Continue
    ));
}

#[test]
fn validate_mmdb_file_rejects_structurally_valid_unsupported_country_code() {
    let directory = TempDir::new().unwrap();
    let bytes = replace_direct_country_with_unsupported_code(country_mmdb_bytes());
    let path = write_fixture(&directory, "unsupported-country.mmdb", &bytes);

    let validation = validate_mmdb_file("geo_restriction.db_path", path_text(&path));
    assert!(validation.is_err());
    assert!(
        validation
            .err()
            .unwrap()
            .contains("unsupported country code")
    );
    assert!(
        GeoRestriction::new(&json!({
            "db_path": path_text(&path),
            "deny_countries": ["US"],
            "on_lookup_failure": "deny"
        }))
        .is_err(),
        "constructor admission must reject unsupported MMDB country codes"
    );
}

#[test]
fn validate_mmdb_file_rejects_wrong_database_type() {
    let directory = TempDir::new().unwrap();
    let bytes = replace_database_type(country_mmdb_bytes());
    let path = write_fixture(&directory, "asn.mmdb", &bytes);

    let validation = validate_mmdb_file("geo_restriction.db_path", path_text(&path));
    assert!(validation.is_err());
    assert!(
        validation
            .err()
            .unwrap()
            .contains("unsupported database type")
    );
    assert!(
        GeoRestriction::new(&json!({
            "db_path": path_text(&path),
            "allow_countries": ["US"]
        }))
        .is_err(),
        "constructor admission must reject a readable wrong-product database"
    );
}

#[test]
fn validate_mmdb_file_rejects_partial_corruption_after_open() {
    let directory = TempDir::new().unwrap();
    let bytes = partially_corrupt_mmdb(country_mmdb_bytes());
    let reader = maxminddb::Reader::from_source(bytes.as_slice())
        .expect("generated corruption must pass the shallow open step");
    assert!(reader.verify().is_err());
    let path = write_fixture(&directory, "corrupt.mmdb", &bytes);

    let validation = validate_mmdb_file("geo_restriction.db_path", path_text(&path));
    assert!(validation.is_err());
    assert!(
        validation
            .err()
            .unwrap()
            .contains("failed comprehensive verification")
    );
    assert!(
        GeoRestriction::new(&json!({
            "db_path": path_text(&path),
            "allow_countries": ["US"]
        }))
        .is_err(),
        "constructor admission must reject a partially corrupt database"
    );
}

// --- validate_plugin_file_dependencies tests ---

#[test]
fn test_validate_plugin_file_deps_catches_missing_mmdb() {
    let config = GatewayConfig {
        plugin_configs: vec![make_geo_plugin(
            "pc1",
            true,
            json!({
                "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                "allow_countries": ["US"]
            }),
        )],
        ..Default::default()
    };
    let errors = config.validate_plugin_file_dependencies();
    assert!(!errors.is_empty(), "Should report missing .mmdb file");
    assert!(
        errors[0].contains("MaxMind database file"),
        "Error should mention MaxMind: {}",
        errors[0]
    );
}

#[test]
fn test_validate_plugin_file_deps_skips_disabled_plugin() {
    let config = GatewayConfig {
        plugin_configs: vec![make_geo_plugin(
            "pc1",
            false,
            json!({
                "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                "allow_countries": ["US"]
            }),
        )],
        ..Default::default()
    };
    let errors = config.validate_plugin_file_dependencies();
    assert!(errors.is_empty(), "Disabled plugin should not be validated");
}

#[test]
fn test_validate_plugin_file_deps_deduplicates_paths() {
    // Two plugins referencing the same missing file should only produce one error.
    let config = GatewayConfig {
        plugin_configs: vec![
            make_geo_plugin(
                "pc1",
                true,
                json!({
                    "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                    "allow_countries": ["US"]
                }),
            ),
            make_geo_plugin(
                "pc2",
                true,
                json!({
                    "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                    "deny_countries": ["CN"]
                }),
            ),
        ],
        ..Default::default()
    };
    let errors = config.validate_plugin_file_dependencies();
    let mmdb_errors: Vec<_> = errors
        .iter()
        .filter(|e| e.contains("MaxMind database file"))
        .collect();
    assert_eq!(
        mmdb_errors.len(),
        1,
        "Same path should only be validated once: {:?}",
        errors
    );
}

// --- header mutation capability ---

#[test]
fn test_injection_does_not_require_before_proxy_header_clone() {
    // Geo assertions are stripped/replaced in on_request_received while the
    // materialized request map is still authoritative. Keep the expensive
    // before_proxy clone capability disabled even when injection is enabled.
    let config = json!({
        "db_path": "/nonexistent/path/test.mmdb",
        "allow_countries": ["US"],
        "inject_headers": true
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    assert!(!plugin.modifies_request_headers());
}

#[test]
fn test_modifies_request_headers_false_when_inject_disabled() {
    let config = json!({
        "db_path": "/nonexistent/path/test.mmdb",
        "allow_countries": ["US"]
    });
    let plugin = GeoRestriction::new(&config).unwrap();
    assert!(!plugin.modifies_request_headers());
}

#[test]
fn test_validate_all_fields_does_not_check_mmdb() {
    // validate_all_fields should NOT catch missing .mmdb files — that's
    // handled by validate_plugin_file_dependencies() so each mode can
    // treat it independently (fatal vs warn vs skip).
    let config = GatewayConfig {
        plugin_configs: vec![make_geo_plugin(
            "pc1",
            true,
            json!({
                "db_path": "/nonexistent/path/GeoLite2-Country.mmdb",
                "allow_countries": ["US"]
            }),
        )],
        ..Default::default()
    };
    let result = config.validate_all_fields(30);
    // Should pass — .mmdb validation is NOT in validate_all_fields
    assert!(
        result.is_ok(),
        "validate_all_fields should not check .mmdb files: {:?}",
        result.err()
    );
}
