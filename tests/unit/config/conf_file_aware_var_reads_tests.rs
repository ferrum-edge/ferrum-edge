//! Issue #3624: settings documented in ferrum.conf must route through the
//! conf-file-aware resolver instead of reading `std::env::var` only.

use crate::unit::env_lock::EnvGuard;
use ferrum_edge::config::CompressionAdmissionPolicy;
use ferrum_edge::config::conf_file::ConfFile;
use ferrum_edge::plugins::api_chargeback_sink::resolve_node_id_with_primary;
use ferrum_edge::plugins::utils::metadata_redaction::{
    parse_extras_from_env, parse_extras_from_resolved,
};

const ISSUE_3624_CONF: &str = r"
FERRUM_LOG_REDACT_METADATA_KEYS = conf_only_redact,tenant_marker
FERRUM_NODE_ID = conf-chargeback-node
FERRUM_COMPRESSION_GZIP_ENABLED = false
FERRUM_COMPRESSION_BROTLI_ENABLED = 0
FERRUM_MAX_REQUEST_BODY_SIZE_BYTES = 2048
";

#[test]
fn conf_file_values_honored_for_metadata_redaction_extras() {
    let conf = ConfFile::parse(ISSUE_3624_CONF).unwrap();
    let extras = parse_extras_from_resolved(
        conf.get("FERRUM_LOG_REDACT_METADATA_KEYS")
            .map(|s| s.to_string()),
    );
    assert_eq!(extras, ["conf_only_redact", "tenant_marker"]);
}

#[test]
fn conf_file_values_honored_for_chargeback_node_id() {
    let conf = ConfFile::parse(ISSUE_3624_CONF).unwrap();
    let node_id = resolve_node_id_with_primary(conf.get("FERRUM_NODE_ID").map(|s| s.to_string()));
    assert_eq!(node_id, "conf-chargeback-node");
}

#[test]
fn conf_file_values_honored_for_validation_client_compression_gates() {
    let conf = ConfFile::parse(ISSUE_3624_CONF).unwrap();
    let policy = CompressionAdmissionPolicy::from_resolved(
        conf.get("FERRUM_COMPRESSION_GZIP_ENABLED"),
        conf.get("FERRUM_COMPRESSION_BROTLI_ENABLED"),
        conf.get("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES"),
    )
    .expect("conf values must parse");
    assert!(!policy.gzip_enabled);
    assert!(!policy.brotli_enabled);
    assert_eq!(policy.max_request_body_size_bytes, 2048);
}

#[test]
fn compression_policy_refuses_typoed_values_instead_of_falling_back() {
    // Issue #6651 item 3: the old infallible helpers silently mapped a typo
    // to enabled/default. The typed policy refuses, naming the variable.
    let err = CompressionAdmissionPolicy::from_resolved(Some("flase"), None, None)
        .expect_err("typo'd gzip gate must refuse");
    assert!(err.contains("FERRUM_COMPRESSION_GZIP_ENABLED"), "{err}");
    let err = CompressionAdmissionPolicy::from_resolved(None, None, Some("10MB"))
        .expect_err("suffixed body ceiling must refuse");
    assert!(err.contains("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES"), "{err}");
    // Unset resolves to the EnvConfig defaults.
    assert_eq!(
        CompressionAdmissionPolicy::from_resolved(None, None, None).unwrap(),
        CompressionAdmissionPolicy::default(),
    );
}

#[test]
fn env_still_overrides_conf_for_metadata_redaction_extras() {
    let _guard = EnvGuard::new(&["FERRUM_LOG_REDACT_METADATA_KEYS"]);
    unsafe {
        std::env::set_var("FERRUM_LOG_REDACT_METADATA_KEYS", "env_wins");
    }
    let extras = parse_extras_from_env();
    assert_eq!(extras, ["env_wins"]);
}

/// Strip all whitespace so these source-shape guards survive rustfmt.
///
/// rustfmt splits a long call across lines (it already did for
/// `resolve_ferrum_var("FERRUM_LOG_REDACT_METADATA_KEYS")`), which breaks a
/// naive one-line `contains`. The property under test is which *call* is made,
/// not how it is wrapped.
fn squeeze(source: &str) -> String {
    let stripped: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    // rustfmt also inserts a trailing comma when it breaks a call across lines,
    // so `f("X")` becomes `f(\n    "X",\n)` -> `f("X",)`. Drop that comma too,
    // or the needle never matches the reflowed source.
    stripped.replace(",)", ")")
}

#[test]
fn issue_3624_reads_use_conf_aware_resolver_not_std_env_var() {
    let metadata = squeeze(include_str!(
        "../../../src/plugins/utils/metadata_redaction.rs"
    ));
    assert!(
        metadata.contains(&squeeze(
            "resolve_ferrum_var(\"FERRUM_LOG_REDACT_METADATA_KEYS\")"
        )),
        "metadata redaction must resolve through ferrum.conf"
    );
    assert!(
        !metadata.contains(&squeeze(
            "std::env::var(\"FERRUM_LOG_REDACT_METADATA_KEYS\")"
        )),
        "metadata redaction must not bypass ferrum.conf"
    );

    let chargeback = squeeze(include_str!("../../../src/plugins/api_chargeback_sink.rs"));
    assert!(
        chargeback.contains(&squeeze("resolve_ferrum_var(\"FERRUM_NODE_ID\")")),
        "chargeback node id must resolve through ferrum.conf"
    );
    assert!(
        !chargeback.contains(&squeeze("std::env::var(\"FERRUM_NODE_ID\")")),
        "chargeback node id must not bypass ferrum.conf"
    );

    // Since #6651 item 3 the compression gates resolve in exactly one
    // place: CompressionAdmissionPolicy in env_config.rs.
    let env_config = squeeze(include_str!("../../../src/config/env_config.rs"));
    assert!(
        env_config.contains(&squeeze("resolve(\"FERRUM_COMPRESSION_GZIP_ENABLED\")")),
        "compression gates must resolve through ferrum.conf"
    );
    assert!(
        env_config.contains(&squeeze("ConfFile::load()?")),
        "a sticky conf-load failure must refuse, not resolve to defaults"
    );
    assert!(
        env_config.contains(&squeeze("resolve(\"FERRUM_MAX_REQUEST_BODY_SIZE_BYTES\")")),
        "validation client body ceiling must resolve through ferrum.conf"
    );
    let http_client = squeeze(include_str!("../../../src/plugins/utils/http_client.rs"));
    assert!(
        !http_client.contains(&squeeze(
            "std::env::var(\"FERRUM_COMPRESSION_GZIP_ENABLED\")"
        )),
        "gzip gate must not bypass ferrum.conf"
    );
    assert!(
        !http_client.contains(&squeeze(
            "std::env::var(\"FERRUM_COMPRESSION_BROTLI_ENABLED\")"
        )),
        "brotli gate must not bypass ferrum.conf"
    );
    assert!(
        !http_client.contains(&squeeze(
            "std::env::var(\"FERRUM_MAX_REQUEST_BODY_SIZE_BYTES\")"
        )),
        "body ceiling must not bypass ferrum.conf"
    );
    assert!(
        !http_client.contains("FERRUM_COMPRESSION_GZIP_ENABLED"),
        "http_client must not re-parse compression gates"
    );
}

#[test]
fn compression_policy_from_process_env_matches_env_config() {
    // Defaults parity + one parse path: the typed policy resolved from the
    // process must equal the one projected from a parsed EnvConfig.
    let guard = EnvGuard::new(&[]);
    guard.set("FERRUM_MODE", "file");
    guard.set("FERRUM_FILE_CONFIG_PATH", "/tmp/ferrum-test-config.yaml");
    guard.set("FERRUM_COMPRESSION_GZIP_ENABLED", "false");
    guard.set("FERRUM_COMPRESSION_BROTLI_ENABLED", "1");
    guard.set("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "4096");
    let conf = ConfFile::parse("").unwrap();
    let env_config = ferrum_edge::config::EnvConfig::from_env_with_conf(&conf).unwrap();
    assert_eq!(
        CompressionAdmissionPolicy::from_process_env().unwrap(),
        CompressionAdmissionPolicy::from_env_config(&env_config),
    );
    assert_eq!(
        CompressionAdmissionPolicy::default(),
        CompressionAdmissionPolicy {
            gzip_enabled: true,
            brotli_enabled: true,
            max_request_body_size_bytes: 10_485_760,
        },
    );
}

#[test]
fn library_validation_refuses_typoed_compression_gate() {
    // Behavioral: the library entry point never built an EnvConfig, and a
    // typo'd gate must refuse instead of silently meaning "enabled".
    let guard = EnvGuard::new(&[]);
    guard.set("FERRUM_COMPRESSION_GZIP_ENABLED", "flase");
    let err = ferrum_edge::plugins::validate_plugin_config(
        "compression",
        &serde_json::json!({"algorithms": ["gzip"]}),
    )
    .expect_err("typo'd compression gate must refuse library validation");
    assert!(err.contains("FERRUM_COMPRESSION_GZIP_ENABLED"), "{err}");
}
