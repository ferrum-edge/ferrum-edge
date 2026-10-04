//! Metadata is captured from the immutable policy, not current env strings.

use ferrum_edge::config::conf_file::ConfFile;
use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy, EnvConfig};

use crate::unit::env_lock::EnvGuard;

#[test]
fn metadata_captures_production_defaults_and_ignores_later_env_changes() {
    let guard = EnvGuard::new(&[]);
    guard.set("FERRUM_MODE", "file");
    guard.set("FERRUM_FILE_CONFIG_PATH", "/unused/config.yaml");
    let env = EnvConfig::from_env_with_conf(&ConfFile::default()).unwrap();
    let metadata = env.backend_allow_ips.metadata();
    assert_eq!(metadata.allow_ips, BackendAllowIps::Both);
    assert!(metadata.dangerous_ranges_blocked);
    assert!(!metadata.allow_cidr_overrides_present);
    assert!(!metadata.deny_cidr_overrides_present);

    guard.set("FERRUM_BACKEND_ALLOW_IPS", "public");
    guard.set("FERRUM_BACKEND_ALLOW_CIDRS", "10.45.67.89/32");
    guard.set("FERRUM_BACKEND_DENY_CIDRS", "8.8.8.8/32");
    guard.set("FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES", "false");
    assert_eq!(env.backend_allow_ips.metadata(), metadata);
    assert!(
        env.backend_allow_ips
            .is_allowed(&"10.0.0.1".parse().unwrap())
    );
    assert!(
        !env.backend_allow_ips
            .is_allowed(&"169.254.169.254".parse().unwrap())
    );
}

#[test]
fn metadata_preserves_loaded_overrides_without_changing_enforcement() {
    let policy = BackendEgressPolicy::from_env(
        BackendAllowIps::Public,
        "10.45.67.89/32",
        "10.45.67.89/32,8.8.8.8/32",
        false,
    )
    .unwrap();
    let metadata = policy.metadata();
    assert_eq!(metadata.allow_ips, BackendAllowIps::Public);
    assert!(metadata.allow_cidr_overrides_present);
    assert!(metadata.deny_cidr_overrides_present);
    assert!(!metadata.dangerous_ranges_blocked);
    assert!(policy.is_allowed(&"10.45.67.89".parse().unwrap()));
    assert!(!policy.is_allowed(&"8.8.8.8".parse().unwrap()));
    assert!(!policy.is_allowed(&"10.45.67.90".parse().unwrap()));
}
