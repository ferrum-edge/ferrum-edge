//! Successful policy construction must withhold selections at the INFO emitter,
//! before the sink's external-secret redaction, without changing the policy.

use std::sync::{Arc, Mutex};

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::conf_file::ConfFile;
use ferrum_edge::tls::TlsPolicy;
use rustls::{CipherSuite, NamedGroup, ProtocolVersion};

use crate::unit::env_lock::EnvGuard;

const CIPHER: &str = "ECDHE-RSA-AES128-GCM-SHA256";
const CURVE: &str = "P-256";

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn construct_and_capture(config: &EnvConfig) -> (TlsPolicy, String) {
    let logs = CapturedLogs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    crate::diagnostic_test_interest::ensure_interest_floor();
    let policy = tracing::subscriber::with_default(subscriber, || {
        TlsPolicy::from_env_config(config).expect("accepted TLS policy")
    });
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    (policy, output)
}

fn assert_policy_and_log(config: &EnvConfig, versions: &[ProtocolVersion]) {
    let (policy, output) = construct_and_capture(config);
    assert_eq!(
        policy
            .protocol_versions
            .iter()
            .map(|version| version.version)
            .collect::<Vec<_>>(),
        versions
    );
    assert_eq!(
        policy
            .crypto_provider
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect::<Vec<_>>(),
        [CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
    );
    assert_eq!(
        policy
            .crypto_provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect::<Vec<_>>(),
        [NamedGroup::secp256r1]
    );
    assert_eq!(
        policy.prefer_server_cipher_order,
        config.tls_prefer_server_cipher_order
    );
    assert_eq!(policy.session_cache_size, config.tls_session_cache_size);
    assert_eq!(
        policy.early_data_max_size,
        if config.tls_early_data_methods.is_empty() {
            0
        } else {
            16_384
        }
    );

    let records: Vec<serde_json::Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON tracing record"))
        .collect();
    let policy_records: Vec<_> = records
        .iter()
        .filter(|record| {
            record["fields"]["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("TLS policy:"))
        })
        .collect();
    assert_eq!(
        policy_records.len(),
        1,
        "policy INFO event missing: {output}"
    );
    let record = policy_records[0];
    assert_eq!(record["level"], "INFO");
    let message = record["fields"]["message"].as_str().unwrap();
    for expected in [
        format!("version_count={}", versions.len()),
        "cipher_suite_count=1".to_string(),
        "group_count=1".to_string(),
    ] {
        assert!(message.contains(&expected), "missing {expected}: {output}");
    }
    for field in [
        "FERRUM_TLS_MIN_VERSION",
        "FERRUM_TLS_MAX_VERSION",
        "FERRUM_TLS_CIPHER_SUITES",
        "FERRUM_TLS_CURVES",
        "FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER",
    ] {
        assert!(message.contains(field), "missing {field}: {output}");
    }
    let lower = output.to_ascii_lowercase();
    for withheld in [
        CIPHER,
        CURVE,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "secp256r1",
        "1.2",
        "1.3",
        "true",
        "false",
        "927451",
        "16384",
    ] {
        assert!(
            !lower.contains(&withheld.to_ascii_lowercase()),
            "leaked {withheld}: {output}"
        );
    }
}

#[test]
fn successful_policy_info_withholds_direct_selections_and_scalars() {
    let _env = EnvGuard::new(&[]);
    for (max, prefer_server_order, early_data_methods, versions) in [
        ("1.2", false, Vec::new(), vec![ProtocolVersion::TLSv1_2]),
        (
            "1.3",
            true,
            vec!["GET".to_string()],
            vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
        ),
    ] {
        let config = EnvConfig {
            tls_min_version: "1.2".to_string(),
            tls_max_version: max.to_string(),
            tls_cipher_suites: Some(CIPHER.to_string()),
            tls_curves: Some(CURVE.to_string()),
            tls_prefer_server_cipher_order: prefer_server_order,
            tls_session_cache_size: 927451,
            tls_early_data_methods: early_data_methods.into_iter().collect(),
            ..EnvConfig::default()
        };
        assert_policy_and_log(&config, &versions);
    }
}

#[test]
fn successful_policy_info_withholds_external_selections_and_scalars() {
    // Registration and the candidate plan are process-lifetime OnceLocks. Use
    // an exact-test child so real TLS keys never poison sibling diagnostics.
    // The non-FERRUM marker survives EnvGuard's ambient configuration cleanup.
    const CHILD: &str = "TLS_POLICY_LOG_TEST_CHILD";
    let env = EnvGuard::new(&[]);
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "unit::tls::policy_log_redaction_tests::successful_policy_info_withholds_external_selections_and_scalars",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let fixtures = [
        ("FERRUM_TLS_CIPHER_SUITES", CIPHER),
        ("FERRUM_TLS_CURVES", CURVE),
        ("FERRUM_TLS_MIN_VERSION", "1.2"),
        ("FERRUM_TLS_MAX_VERSION", "1.3"),
        ("FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER", "false"),
        ("FERRUM_TLS_SESSION_CACHE_SIZE", "927451"),
    ];
    for (key, value) in fixtures {
        let path = dir.path().join(key);
        std::fs::write(&path, value).unwrap();
        env.set(&format!("{key}_FILE"), path.to_str().unwrap());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let resolved = runtime
        .block_on(ferrum_edge::secrets::resolve_all_env_secrets())
        .unwrap();
    drop(runtime);
    assert_eq!(resolved.vars.len(), fixtures.len());
    for (key, value) in &resolved.vars {
        env.set(key, value);
    }
    for key in &resolved.source_keys_to_remove {
        env.unset(key);
    }
    ferrum_edge::secrets::record_external_secret_keys(
        resolved.vars.iter().map(|(key, _)| key.clone()),
    );
    for (key, value) in fixtures {
        assert!(ferrum_edge::secrets::is_external_secret_key(key));
        assert_eq!(std::env::var(key).unwrap(), value);
    }
    // Build the lazy plan while EnvGuard still owns the environment lock.
    assert_eq!(
        ferrum_edge::secrets::redact_external_secret_values(CIPHER),
        ferrum_edge::secrets::EXTERNAL_SECRET_PLACEHOLDER
    );
    env.set("FERRUM_MODE", "file");
    env.set("FERRUM_FILE_CONFIG_PATH", "unused-policy-log-fixture.yaml");
    let config = EnvConfig::from_env_with_conf(&ConfFile::default()).unwrap();
    assert_eq!(config.tls_cipher_suites.as_deref(), Some(CIPHER));
    assert_eq!(config.tls_curves.as_deref(), Some(CURVE));
    assert_eq!(config.tls_min_version, "1.2");
    assert_eq!(config.tls_max_version, "1.3");
    assert!(!config.tls_prefer_server_cipher_order);
    assert_eq!(config.tls_session_cache_size, 927451);
    assert_policy_and_log(
        &config,
        &[ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
    );
}
