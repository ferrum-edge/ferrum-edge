//! Capture configuration regressions for issues #5625 and #5626.

use ferrum_ebpf_common::{INCLUDE_PORTS_MAX, IncludePortsPolicy};
use ferrum_edge::capture::{
    CaptureConfig, DEFAULT_PROXY_UID, EbpfPlan, FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION,
    ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION, IptablesPlan, include_outbound_ports_from_annotations,
};
use ferrum_edge::config::EnvConfig;
use ferrum_edge::modes::injector::InjectorConfig;
use ferrum_edge::modes::node_agent::NodeAgentConfig;

use crate::unit::env_lock::EnvGuard;

#[test]
fn merged_ports_are_sorted_and_deduplicated_before_applying_the_bpf_cap() {
    let raw = (1..=INCLUDE_PORTS_MAX as u16)
        .rev()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let include = include_outbound_ports_from_annotations([
        (ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION, Some(raw.as_str())),
        (FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION, Some("16,1,16,1")),
    ])
    .unwrap();
    let policy = IncludePortsPolicy::explicit(&include.ports);
    assert!(!policy.is_all_ports());
    assert_eq!(policy.port_count as usize, INCLUDE_PORTS_MAX);
    assert_eq!(policy.ports.as_slice(), include.ports.as_slice());
    assert_eq!(include.ports, (1..=16).collect::<Vec<u16>>());

    let overflow = include_outbound_ports_from_annotations([
        (ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION, Some(raw.as_str())),
        (FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION, Some("17,1,17")),
    ])
    .unwrap();
    assert_eq!(overflow.ports.len(), 17);
    assert_eq!(overflow.ports.last(), Some(&17));
    assert_eq!(
        IncludePortsPolicy::explicit(&overflow.ports),
        IncludePortsPolicy::all()
    );

    // The unbounded iptables path still emits the seventeenth requested port.
    let mut config = CaptureConfig::explicit(15006, 15001);
    config.include_cidrs.push("::/0".to_string());
    config.include_outbound_ports = overflow.ports;
    let plan = IptablesPlan::for_config(&config).unwrap();
    for commands in [&plan.v4_commands, &plan.v6_commands] {
        assert!(
            commands.iter().any(|command| {
                command.contains("--dport 17 ") && command.contains("-j REDIRECT")
            })
        );
    }
}

#[test]
fn proxy_uid_environment_boundary_is_shared_by_capture_node_agent_and_injector() {
    let env = EnvGuard::new(&[
        "FERRUM_MESH_PROXY_UID",
        "FERRUM_NODE_AGENT_NODE_NAME",
        "FERRUM_INJECTOR_ALLOW_PLAINTEXT",
    ]);
    env.set("FERRUM_NODE_AGENT_NODE_NAME", "test-node");
    env.set("FERRUM_INJECTOR_ALLOW_PLAINTEXT", "true");
    let config = EnvConfig::default();
    assert_eq!(
        CaptureConfig::from_env().unwrap().proxy_uid,
        Some(DEFAULT_PROXY_UID)
    );
    assert_eq!(
        InjectorConfig::from_env_config(&config).unwrap().proxy_uid,
        None
    );

    for raw in ["0", " 000 ", "+0", "-1", "4294967296", "uid-secret\nvalue"] {
        env.set("FERRUM_MESH_PROXY_UID", raw);
        let capture_error = CaptureConfig::from_env().unwrap_err();
        let node_error = NodeAgentConfig::from_env_config(&config).unwrap_err();
        let injector_error = InjectorConfig::from_env_config(&config).unwrap_err();
        assert_eq!(node_error, capture_error);
        assert_eq!(injector_error, capture_error);
        let rendered = ferrum_edge::startup::sanitize_startup_cause(capture_error, &[]);
        assert!(rendered.contains("FERRUM_MESH_PROXY_UID"));
        assert!(!rendered.contains("uid-secret"));
        assert!(!rendered.contains('\n'));
    }

    for (raw, expected) in [
        ("", DEFAULT_PROXY_UID),
        (" \t ", DEFAULT_PROXY_UID),
        ("1", 1),
        (" +1338 ", 1338),
        ("4294967295", u32::MAX),
    ] {
        env.set("FERRUM_MESH_PROXY_UID", raw);
        assert_eq!(CaptureConfig::from_env().unwrap().proxy_uid, Some(expected));
        assert_eq!(
            NodeAgentConfig::from_env_config(&config)
                .unwrap()
                .capture_config
                .proxy_uid,
            Some(expected)
        );
        assert_eq!(
            InjectorConfig::from_env_config(&config)
                .unwrap()
                .proxy_uid
                .unwrap_or(DEFAULT_PROXY_UID),
            expected
        );
    }
}

#[test]
fn directly_constructed_root_uid_cannot_generate_tcp_udp_or_fallback_rules() {
    let mut config = CaptureConfig::explicit(15006, 15001);
    config.proxy_uid = Some(0);
    config.include_cidrs.push("::/0".to_string());
    config.udp_capture_enabled = true;
    for error in [
        IptablesPlan::for_config(&config).unwrap_err(),
        IptablesPlan::udp_only_for_config(&config).unwrap_err(),
        IptablesPlan::udp_setup_script(&config).unwrap_err(),
        IptablesPlan::host_udp_for_config(&config, &["veth-test".to_string()]).unwrap_err(),
        EbpfPlan::for_config(&config).unwrap_err(),
    ] {
        assert!(error.contains("FERRUM_MESH_PROXY_UID"));
        assert!(error.contains("non-zero"));
    }

    for uid in [None, Some(1), Some(DEFAULT_PROXY_UID), Some(u32::MAX)] {
        config.proxy_uid = uid;
        let plan = IptablesPlan::for_config(&config).unwrap();
        for commands in [&plan.v4_commands, &plan.v6_commands] {
            let owner_rules: Vec<_> = commands
                .iter()
                .filter(|command| command.contains("--uid-owner"))
                .collect();
            if let Some(uid) = uid {
                assert_eq!(owner_rules.len(), 2, "TCP and UDP owner exemptions");
                let owner_match = format!("--uid-owner {uid} -j RETURN");
                assert!(
                    owner_rules
                        .iter()
                        .all(|command| command.contains(&owner_match))
                );
            } else {
                assert!(owner_rules.is_empty());
            }
        }
    }
}
