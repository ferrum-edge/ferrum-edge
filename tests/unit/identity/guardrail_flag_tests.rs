//! Issue #7237: the five identity guardrail flags share one strict truthy rule
//! (`true`/`false`/`1`/`0`, trimmed, case-insensitive; blank is unset). Any
//! other spelling is refused by `validate_guardrail_env`, so a typo can never
//! read as a different posture.

use super::env_guard::EnvGuard;
use ferrum_edge::identity::ca::bootstrap::dev_bootstrap_opted_in;
use ferrum_edge::identity::{
    IDENTITY_GUARDRAIL_ENV_KEYS, allow_ephemeral_jwt_key, allow_no_ca, allow_static_id,
    parse_guardrail_flag, production_mode, validate_guardrail_env,
};
use std::env::VarError;

fn read(value: &str) -> Result<String, VarError> {
    Ok(value.to_string())
}

#[test]
fn guardrail_flags_accept_the_shared_boolean_spellings() {
    let key = "FERRUM_MESH_ALLOW_STATIC_ID";
    for truthy in ["true", "TRUE", " True ", "1", " 1"] {
        assert_eq!(
            parse_guardrail_flag(key, read(truthy)),
            Ok(Some(true)),
            "{truthy:?}"
        );
    }
    for falsy in ["false", "FALSE", " 0 "] {
        assert_eq!(
            parse_guardrail_flag(key, read(falsy)),
            Ok(Some(false)),
            "{falsy:?}"
        );
    }
    assert_eq!(
        parse_guardrail_flag(key, Err(VarError::NotPresent)),
        Ok(None)
    );
    assert_eq!(parse_guardrail_flag(key, read("")), Ok(None));
    assert_eq!(parse_guardrail_flag(key, read("   ")), Ok(None));
}

#[test]
fn guardrail_flags_refuse_any_other_spelling() {
    for invalid in ["yes", "on", "tru", "enabled", "2"] {
        let error = parse_guardrail_flag("FERRUM_MESH_PRODUCTION_MODE", read(invalid))
            .expect_err("a typo must be refused");
        assert!(error.contains("FERRUM_MESH_PRODUCTION_MODE"), "{error}");
    }
}

#[test]
fn every_opt_in_reads_one_as_true() {
    let guard = EnvGuard::new(&IDENTITY_GUARDRAIL_ENV_KEYS);
    guard.unset("FERRUM_MESH_PRODUCTION_MODE");
    guard.set("FERRUM_MESH_ALLOW_NO_CA", "1");
    guard.set("FERRUM_MESH_ALLOW_STATIC_ID", "1");
    guard.set("FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY", "1");
    guard.set("FERRUM_MESH_CA_BOOTSTRAP_DEV", "1");
    assert!(!production_mode());
    assert!(allow_no_ca());
    assert!(allow_static_id());
    assert!(allow_ephemeral_jwt_key());
    assert!(dev_bootstrap_opted_in());
    assert_eq!(validate_guardrail_env(), Ok(()));
}

#[test]
fn production_mode_one_disables_the_dev_opt_ins() {
    let guard = EnvGuard::new(&IDENTITY_GUARDRAIL_ENV_KEYS);
    guard.set("FERRUM_MESH_PRODUCTION_MODE", "1");
    guard.set("FERRUM_MESH_ALLOW_STATIC_ID", "true");
    guard.set("FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY", "true");
    assert!(production_mode());
    assert!(!allow_static_id());
    assert!(!allow_ephemeral_jwt_key());
}

#[test]
fn an_invalid_production_flag_fails_closed_and_fails_validation() {
    let guard = EnvGuard::new(&IDENTITY_GUARDRAIL_ENV_KEYS);
    guard.set("FERRUM_MESH_PRODUCTION_MODE", "yes");
    guard.set("FERRUM_MESH_ALLOW_STATIC_ID", "true");
    assert!(
        production_mode(),
        "an unreadable production guardrail must not read as off"
    );
    assert!(!allow_static_id());
    let error = validate_guardrail_env().expect_err("validation must refuse the typo");
    assert!(error.contains("FERRUM_MESH_PRODUCTION_MODE"), "{error}");
}

#[test]
fn an_invalid_opt_in_stays_off_and_fails_validation() {
    for key in [
        "FERRUM_MESH_ALLOW_NO_CA",
        "FERRUM_MESH_ALLOW_STATIC_ID",
        "FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY",
        "FERRUM_MESH_CA_BOOTSTRAP_DEV",
    ] {
        let guard = EnvGuard::new(&IDENTITY_GUARDRAIL_ENV_KEYS);
        guard.set(key, "yes");
        assert!(!allow_no_ca());
        assert!(!allow_static_id());
        assert!(!allow_ephemeral_jwt_key());
        assert!(!dev_bootstrap_opted_in());
        let error = validate_guardrail_env().expect_err("validation must refuse the typo");
        assert!(error.contains(key), "{error}");
        drop(guard);
    }
}
