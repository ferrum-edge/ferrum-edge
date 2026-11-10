//! Strict parsing of mesh-adjacent settings that used to fall back silently
//! (issue #7237): injector booleans, the node-agent's `FERRUM_MESH_TOPOLOGY`,
//! and `FERRUM_NODE_AGENT_FALLBACK_MODE`. A typo must fail startup instead of
//! producing a different deployment.

use ferrum_edge::config::EnvConfig;
use ferrum_edge::ebpf::FallbackMode;
use ferrum_edge::modes::injector::InjectorConfig;
use ferrum_edge::modes::node_agent::NodeAgentConfig;

use crate::unit::env_lock::EnvGuard;

const INJECTOR_ENV_KEYS: &[&str] = &[
    "FERRUM_INJECTOR_REQUIRE_ANNOTATION",
    "FERRUM_INJECTOR_ALLOW_PLAINTEXT",
    "FERRUM_INJECTOR_SIDECAR_IMAGE",
    "FERRUM_INJECTOR_TLS_CERT_PATH",
    "FERRUM_INJECTOR_TLS_KEY_PATH",
    "FERRUM_MESH_CAPTURE_MODE",
];

fn injector_config(require_annotation: Option<&str>) -> Result<InjectorConfig, String> {
    let guard = EnvGuard::new(INJECTOR_ENV_KEYS);
    for key in INJECTOR_ENV_KEYS {
        guard.unset(key);
    }
    // No TLS material in a unit test: opt in to the dev-only plaintext mode.
    guard.set("FERRUM_INJECTOR_ALLOW_PLAINTEXT", "true");
    if let Some(raw) = require_annotation {
        guard.set("FERRUM_INJECTOR_REQUIRE_ANNOTATION", raw);
    }
    InjectorConfig::from_env_config(&EnvConfig::default())
}

#[test]
fn injector_require_annotation_accepts_the_repo_wide_boolean_spellings() {
    let cases = [
        (None, true),
        (Some("  "), true),
        (Some("true"), true),
        (Some(" TRUE "), true),
        (Some("1"), true),
        (Some("false"), false),
        (Some("False"), false),
        // `0` used to be ignored and fall back to the default `true`.
        (Some("0"), false),
    ];
    for (raw, expected) in cases {
        let config = injector_config(raw).unwrap_or_else(|err| panic!("{raw:?} must parse: {err}"));
        assert_eq!(config.require_annotation, expected, "value {raw:?}");
    }
}

#[test]
fn injector_require_annotation_typo_fails_startup() {
    let err = injector_config(Some("flase")).expect_err("a typo must not fall back");
    assert!(err.contains("FERRUM_INJECTOR_REQUIRE_ANNOTATION"), "{err}");
    assert!(err.contains("true, false, 1, or 0"), "{err}");
}

#[test]
fn injector_allow_plaintext_typo_fails_startup() {
    let guard = EnvGuard::new(INJECTOR_ENV_KEYS);
    for key in INJECTOR_ENV_KEYS {
        guard.unset(key);
    }
    guard.set("FERRUM_INJECTOR_ALLOW_PLAINTEXT", "yes");

    let err = InjectorConfig::from_env_config(&EnvConfig::default())
        .expect_err("a typo must not fall back");
    assert!(err.contains("FERRUM_INJECTOR_ALLOW_PLAINTEXT"), "{err}");
    assert!(err.contains("true, false, 1, or 0"), "{err}");
}

#[test]
fn injector_allow_plaintext_accepts_one() {
    let guard = EnvGuard::new(INJECTOR_ENV_KEYS);
    for key in INJECTOR_ENV_KEYS {
        guard.unset(key);
    }
    guard.set("FERRUM_INJECTOR_ALLOW_PLAINTEXT", "1");

    let config = InjectorConfig::from_env_config(&EnvConfig::default())
        .expect("`1` is a canonical boolean spelling");
    assert!(config.allow_plaintext);
}

const NODE_AGENT_ENV_KEYS: &[&str] = &[
    "FERRUM_NODE_AGENT_NODE_NAME",
    "FERRUM_MESH_TOPOLOGY",
    "FERRUM_NODE_AGENT_FALLBACK_MODE",
];

fn node_agent_config(
    topology: Option<&str>,
    fallback_mode: Option<&str>,
) -> Result<NodeAgentConfig, String> {
    let guard = EnvGuard::new(NODE_AGENT_ENV_KEYS);
    for key in NODE_AGENT_ENV_KEYS {
        guard.unset(key);
    }
    guard.set("FERRUM_NODE_AGENT_NODE_NAME", "node-a");
    if let Some(raw) = topology {
        guard.set("FERRUM_MESH_TOPOLOGY", raw);
    }
    if let Some(raw) = fallback_mode {
        guard.set("FERRUM_NODE_AGENT_FALLBACK_MODE", raw);
    }
    NodeAgentConfig::from_env_config(&EnvConfig::default())
}

#[test]
fn node_agent_rejects_an_unknown_mesh_topology() {
    // `ambiant` used to be read as "not ambient" and silently disabled the
    // Ambient registry and UDP readiness guard.
    let err = node_agent_config(Some("ambiant"), None)
        .err()
        .expect("an unknown topology must fail node-agent startup");
    assert!(err.contains("FERRUM_MESH_TOPOLOGY"), "{err}");
}

#[test]
fn node_agent_accepts_every_mesh_topology_the_proxy_accepts() {
    for topology in [
        None,
        Some("sidecar"),
        Some(" Ambient "),
        Some("node_waypoint"),
        Some("node-waypoint"),
    ] {
        node_agent_config(topology, None)
            .unwrap_or_else(|err| panic!("{topology:?} must be accepted: {err}"));
    }
}

#[test]
fn node_agent_fallback_mode_is_trimmed() {
    let config = node_agent_config(None, Some(" fail "))
        .unwrap_or_else(|err| panic!("a padded fallback mode must parse: {err}"));
    assert_eq!(config.fallback_mode, FallbackMode::Fail);
    assert_eq!(
        FallbackMode::parse("\tIPTABLES\n"),
        Ok(FallbackMode::Iptables)
    );
}
