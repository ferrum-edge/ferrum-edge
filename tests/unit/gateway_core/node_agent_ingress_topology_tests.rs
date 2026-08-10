//! External unit coverage for NodeWaypoint ingress-interface topology proof.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ferrum_edge::_test_support::{
    apply_bounded_node_topology_sequence_for_test,
    apply_node_agent_ingress_topology_outcome_for_test,
    node_agent_cni_capture_readiness_rejection_for_test,
    node_agent_cni_topology_readiness_rejection_for_test,
    run_with_node_agent_topology_outcome_stream_for_test,
    set_node_agent_startup_readiness_for_test, spawn_node_agent_ingress_topology_monitor_for_test,
};
use ferrum_edge::capture::{CaptureConfig, CaptureMode};
use ferrum_edge::cni::rpc::RpcVerb;
use ferrum_edge::ebpf::ingress_topology::{
    IngressTopologyOutcome, IngressTopologyReason, IngressTopologyState, IngressTopologyStatus,
    IngressTopologyValidator, IpCidr, LinkState, NodeWatchCacheDecision, NodeWatchCacheRecovery,
    RouteEntry, TopologyRequirements, parse_ipv4_route_file, parse_ipv6_route_file,
    read_link_state_from_root, requirements_from_nodes, validate_host_topology_from_roots,
    validate_topology_snapshot,
};
use ferrum_edge::ebpf::{
    CaptureContract, FallbackMode, MockEbpfBackend, NODE_AGENT_CAPTURE_STATE_READY,
    NODE_WAYPOINT_INGRESS_REDIRECT_MARK, NodeAgentMetrics, NodeAgentProxyMode,
};
use ferrum_edge::modes::node_agent::NodeAgentConfig;
use futures::{StreamExt, stream};
use k8s_openapi::api::core::v1::Node;
use kube::runtime::watcher::Event;
use serde_json::json;
use tempfile::tempdir;

fn cidr(raw: &str) -> IpCidr {
    IpCidr::parse(raw).expect("valid test CIDR")
}

fn route(raw: &str, interface: &str, metric: u32) -> RouteEntry {
    RouteEntry {
        destination: cidr(raw),
        interface: interface.to_string(),
        metric,
        usable: true,
    }
}

fn up_link() -> LinkState {
    LinkState {
        exists: true,
        up: true,
        loopback: false,
        supported: true,
    }
}

fn node(
    name: &str,
    pod_cidrs: &[&str],
    ready: Option<&str>,
    unschedulable: bool,
    addresses: &[(&str, &str)],
) -> Node {
    let conditions = ready.map(|status| {
        json!([{
            "type": "Ready",
            "status": status,
            "lastHeartbeatTime": null,
            "lastTransitionTime": null
        }])
    });
    serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": { "name": name },
        "spec": {
            "podCIDRs": pod_cidrs,
            "unschedulable": unschedulable
        },
        "status": {
            "conditions": conditions,
            "addresses": addresses.iter().map(|(kind, address)| {
                json!({ "type": kind, "address": address })
            }).collect::<Vec<_>>()
        }
    }))
    .expect("valid test Node")
}

fn write_link(root: &std::path::Path, name: &str, ifindex: u32, iflink: u32) {
    let link = root.join(name);
    fs::create_dir_all(link.join("device")).expect("create test link");
    fs::write(link.join("flags"), "0x1\n").expect("write flags");
    fs::write(link.join("operstate"), "up\n").expect("write operstate");
    fs::write(link.join("carrier"), "1\n").expect("write carrier");
    fs::write(link.join("type"), "1\n").expect("write type");
    fs::write(link.join("ifindex"), format!("{ifindex}\n")).expect("write ifindex");
    fs::write(link.join("iflink"), format!("{iflink}\n")).expect("write iflink");
}

fn v4_requirements() -> TopologyRequirements {
    TopologyRequirements {
        remote_pod_cidrs: vec![cidr("10.244.2.0/24")],
        remote_node_addresses: vec![IpAddr::V4(Ipv4Addr::new(172, 18, 0, 3))],
        require_ipv4: true,
        require_ipv6: false,
    }
}

fn node_waypoint_config() -> NodeAgentConfig {
    let mut capture_config = CaptureConfig::explicit(15006, 15001);
    capture_config.mode = CaptureMode::Ebpf;
    let mut capture_contract = CaptureContract::new(
        NodeAgentProxyMode::NodeWaypoint,
        15001,
        15008,
        "/run/ferrum/node-agent.sock",
    )
    .expect("valid NodeWaypoint capture contract");
    capture_contract.ingress_redirect_ifaces = vec!["eth0".to_string()];
    capture_contract.node_waypoint_ingress_redirect_mark = NODE_WAYPOINT_INGRESS_REDIRECT_MARK;
    capture_contract.ingress_capture_port = 15006;
    capture_contract.ingress_capture_supports_ipv6 = true;
    NodeAgentConfig {
        node_name: "local".to_string(),
        capture_config,
        cgroup_root: "/nonexistent".to_string(),
        bpf_fs_path: "/nonexistent".to_string(),
        fallback_mode: FallbackMode::Fail,
        excluded_namespaces: HashSet::new(),
        capture_contract,
        trust_domain: "cluster.local".to_string(),
        node_waypoint_pod_registry_dir: None,
    }
}

fn ready_outcome() -> IngressTopologyOutcome {
    validate_topology_snapshot(
        &["eth0".to_string()],
        &v4_requirements(),
        &[
            route("10.244.2.0/24", "eth0", 0),
            route("172.18.0.0/16", "eth0", 0),
        ],
        &BTreeMap::from([("eth0".to_string(), up_link())]),
    )
}

fn unavailable_outcome() -> IngressTopologyOutcome {
    IngressTopologyOutcome::monitor_stopped(1)
}

#[test]
fn exact_single_uplink_ipv4_topology_is_ready() {
    let links = BTreeMap::from([("eth0".to_string(), up_link())]);
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    let outcome =
        validate_topology_snapshot(&["eth0".to_string()], &v4_requirements(), &routes, &links);

    assert_eq!(outcome.status.state, IngressTopologyState::Ready);
    assert_eq!(outcome.status.reason, IngressTopologyReason::Valid);
    assert_eq!(outcome.status.expected_interfaces, 1);
    assert!(outcome.status.ipv4_covered);
    assert!(!outcome.status.ipv6_required);
}

#[test]
fn existing_but_wrong_interface_is_unavailable() {
    let links = BTreeMap::from([
        ("eth0".to_string(), up_link()),
        ("mgmt0".to_string(), up_link()),
    ]);
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    let outcome =
        validate_topology_snapshot(&["mgmt0".to_string()], &v4_requirements(), &routes, &links);

    assert_eq!(outcome.status.state, IngressTopologyState::Unavailable);
    assert_eq!(outcome.status.reason, IngressTopologyReason::WrongInterface);
    assert_eq!(outcome.status.configured_interfaces, 1);
    assert_eq!(outcome.status.expected_interfaces, 1);
}

#[test]
fn down_and_loopback_devices_are_rejected_before_route_evidence() {
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    let down = BTreeMap::from([(
        "eth0".to_string(),
        LinkState {
            up: false,
            ..up_link()
        },
    )]);
    assert_eq!(
        validate_topology_snapshot(&["eth0".to_string()], &v4_requirements(), &routes, &down,)
            .status
            .reason,
        IngressTopologyReason::DeviceDown,
    );

    let loopback = BTreeMap::from([(
        "lo".to_string(),
        LinkState {
            loopback: true,
            ..up_link()
        },
    )]);
    assert_eq!(
        validate_topology_snapshot(&["lo".to_string()], &v4_requirements(), &routes, &loopback,)
            .status
            .reason,
        IngressTopologyReason::Loopback,
    );
}

#[test]
fn missing_invalid_and_unsupported_devices_are_rejected() {
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    assert_eq!(
        validate_topology_snapshot(
            &["missing0".to_string()],
            &v4_requirements(),
            &routes,
            &BTreeMap::new(),
        )
        .status
        .reason,
        IngressTopologyReason::DeviceMissing,
    );
    assert_eq!(
        validate_topology_snapshot(
            &["bad/name".to_string()],
            &v4_requirements(),
            &routes,
            &BTreeMap::new(),
        )
        .status
        .reason,
        IngressTopologyReason::InvalidInterfaceName,
    );
    let unsupported = BTreeMap::from([(
        "eth0".to_string(),
        LinkState {
            supported: false,
            ..up_link()
        },
    )]);
    assert_eq!(
        validate_topology_snapshot(
            &["eth0".to_string()],
            &v4_requirements(),
            &routes,
            &unsupported,
        )
        .status
        .reason,
        IngressTopologyReason::UnsupportedDevice,
    );
    for unsafe_name in [".", ".."] {
        assert_eq!(
            validate_topology_snapshot(
                &[unsafe_name.to_string()],
                &v4_requirements(),
                &routes,
                &BTreeMap::new(),
            )
            .status
            .reason,
            IngressTopologyReason::InvalidInterfaceName,
        );
    }
}

#[test]
fn dual_stack_requires_complete_family_coverage() {
    let requirements = TopologyRequirements {
        remote_pod_cidrs: vec![cidr("10.244.2.0/24"), cidr("fd00:10:244:2::/64")],
        remote_node_addresses: vec![
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 3)),
            IpAddr::V6("fd00::3".parse::<Ipv6Addr>().expect("test IPv6")),
        ],
        require_ipv4: true,
        require_ipv6: true,
    };
    let links = BTreeMap::from([("eth0".to_string(), up_link())]);
    let incomplete = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    assert_eq!(
        validate_topology_snapshot(&["eth0".to_string()], &requirements, &incomplete, &links,)
            .status
            .reason,
        IngressTopologyReason::RouteMissing,
    );

    let complete = [
        incomplete,
        vec![
            route("fd00:10:244:2::/64", "eth0", 0),
            route("fd00::/64", "eth0", 0),
        ],
    ]
    .concat();
    let outcome =
        validate_topology_snapshot(&["eth0".to_string()], &requirements, &complete, &links);
    assert_eq!(outcome.status.state, IngressTopologyState::Ready);
    assert!(outcome.status.ipv4_covered);
    assert!(outcome.status.ipv6_covered);
}

#[test]
fn multi_uplink_requires_the_complete_exact_set() {
    let requirements = TopologyRequirements {
        remote_pod_cidrs: vec![cidr("10.244.2.0/24"), cidr("10.244.3.0/24")],
        remote_node_addresses: vec![
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 3)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        ],
        require_ipv4: true,
        require_ipv6: false,
    };
    let links = BTreeMap::from([
        ("eth0".to_string(), up_link()),
        ("eth1".to_string(), up_link()),
    ]);
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
        route("10.244.3.0/24", "eth1", 0),
        route("192.0.2.0/24", "eth1", 0),
    ];

    let incomplete =
        validate_topology_snapshot(&["eth0".to_string()], &requirements, &routes, &links);
    assert_eq!(
        incomplete.status.reason,
        IngressTopologyReason::IncompleteInterfaceSet,
    );

    let complete = validate_topology_snapshot(
        &["eth0".to_string(), "eth1".to_string()],
        &requirements,
        &routes,
        &links,
    );
    assert_eq!(complete.status.state, IngressTopologyState::Ready);
    assert_eq!(complete.status.expected_interfaces, 2);
}

#[test]
fn equal_cost_or_split_routes_are_ambiguous() {
    let links = BTreeMap::from([
        ("eth0".to_string(), up_link()),
        ("eth1".to_string(), up_link()),
    ]);
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("10.244.2.0/24", "eth1", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    assert_eq!(
        validate_topology_snapshot(
            &["eth0".to_string(), "eth1".to_string()],
            &v4_requirements(),
            &routes,
            &links,
        )
        .status
        .reason,
        IngressTopologyReason::RouteAmbiguous,
    );
}

#[test]
fn rejected_subprefix_disproves_complete_route_coverage() {
    let links = BTreeMap::from([("eth0".to_string(), up_link())]);
    let mut rejected = route("10.244.2.128/25", "lo", 0);
    rejected.usable = false;
    let routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        rejected,
        route("172.18.0.0/16", "eth0", 0),
    ];

    assert_eq!(
        validate_topology_snapshot(&["eth0".to_string()], &v4_requirements(), &routes, &links,)
            .status
            .reason,
        IngressTopologyReason::RouteAmbiguous,
    );
}

#[test]
fn route_drift_withdraws_a_previously_valid_proof() {
    let links = BTreeMap::from([
        ("eth0".to_string(), up_link()),
        ("eth1".to_string(), up_link()),
    ]);
    let initial_routes = vec![
        route("10.244.2.0/24", "eth0", 0),
        route("172.18.0.0/16", "eth0", 0),
    ];
    assert_eq!(
        validate_topology_snapshot(
            &["eth0".to_string()],
            &v4_requirements(),
            &initial_routes,
            &links,
        )
        .status
        .state,
        IngressTopologyState::Ready,
    );

    let drifted_routes = vec![
        route("10.244.2.0/24", "eth1", 0),
        route("172.18.0.0/16", "eth1", 0),
    ];
    let drifted = validate_topology_snapshot(
        &["eth0".to_string()],
        &v4_requirements(),
        &drifted_routes,
        &links,
    );
    assert_eq!(drifted.status.state, IngressTopologyState::Unavailable);
    assert_eq!(drifted.status.reason, IngressTopologyReason::WrongInterface);
}

#[test]
fn proc_route_parsers_preserve_endianness_metrics_flags_and_negative_evidence() {
    let ipv4 = concat!(
        "Iface\tDestination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
        "eth0\t0002F40A 00000000 0001 0 0 7 00FFFFFF 0 0 0\n",
        "lo\t8002F40A 00000000 0201 0 0 0 80FFFFFF 0 0 0\n",
        "eth9\t00000000 00000000 0000 0 0 0 00000000 0 0 0\n",
    );
    let routes = parse_ipv4_route_file(ipv4).expect("parse IPv4 proc route file");
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].destination, cidr("10.244.2.0/24"));
    assert_eq!(routes[0].metric, 7);
    assert!(routes[0].usable);
    assert_eq!(routes[1].destination, cidr("10.244.2.128/25"));
    assert!(!routes[1].usable);

    let ipv6 = concat!(
        "fd001024000200000000000000000000 40 00000000000000000000000000000000 00 ",
        "00000000000000000000000000000000 00000005 00000000 00000000 00000001 eth0\n",
        "fd001024000280000000000000000000 41 fd000000000000000000000000000000 40 ",
        "00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n",
        "fd0010240002c0000000000000000000 42 00000000000000000000000000000000 00 ",
        "00000000000000000000000000000000 00000000 00000000 00000000 00000201 lo\n",
    );
    let routes = parse_ipv6_route_file(ipv6).expect("parse IPv6 proc route file");
    assert_eq!(routes.len(), 3);
    assert_eq!(routes[0].destination, cidr("fd00:1024:2::/64"));
    assert_eq!(routes[0].metric, 5);
    assert!(routes[0].usable);
    assert!(
        !routes[1].usable,
        "source-specific route is negative evidence"
    );
    assert!(!routes[2].usable, "reject route is negative evidence");
}

#[test]
fn malformed_ipv6_hex_is_rejected_without_utf8_indexing() {
    // Exactly 32 bytes with a multibyte scalar crossing the old byte-slice
    // boundary. The parser must return a closed error, never panic.
    let destination = format!("0é{}", "0".repeat(29));
    let non_ascii = format!(
        "{destination} 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n"
    );
    assert_eq!(
        parse_ipv6_route_file(&non_ascii),
        Err(IngressTopologyReason::RouteTableInvalid),
    );
    let malformed = "gg000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n";
    assert_eq!(
        parse_ipv6_route_file(malformed),
        Err(IngressTopologyReason::RouteTableInvalid),
    );
}

#[test]
fn real_procfs_and_sysfs_ingestion_proves_ipv4_and_ipv6_only_topologies() {
    let fixture = tempdir().expect("temporary topology fixture");
    let proc_root = fixture.path().join("proc");
    let sys_root = fixture.path().join("sys/class/net");
    fs::create_dir_all(proc_root.join("net")).expect("create proc net");
    fs::create_dir_all(&sys_root).expect("create sys net");
    write_link(&sys_root, "eth0", 2, 1);
    fs::write(
        proc_root.join("net/route"),
        concat!(
            "Iface\tDestination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            "eth0\t0002F40A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n",
            "eth0\t000012AC 00000000 0001 0 0 0 0000FFFF 0 0 0\n",
        ),
    )
    .expect("write IPv4 routes");
    let ipv4 = validate_host_topology_from_roots(
        &["eth0".to_string()],
        &v4_requirements(),
        &proc_root,
        &sys_root,
    );
    assert_eq!(ipv4.status.state, IngressTopologyState::Ready);

    fs::remove_file(proc_root.join("net/route")).expect("remove unused IPv4 table");
    fs::write(
        proc_root.join("net/ipv6_route"),
        concat!(
            "fd001024000200000000000000000000 40 00000000000000000000000000000000 00 ",
            "00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n",
            "fd000000000000000000000000000000 40 00000000000000000000000000000000 00 ",
            "00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth0\n",
        ),
    )
    .expect("write IPv6 routes");
    let ipv6_requirements = TopologyRequirements {
        remote_pod_cidrs: vec![cidr("fd00:1024:2::/64")],
        remote_node_addresses: vec!["fd00::3".parse().expect("IPv6 InternalIP")],
        require_ipv4: false,
        require_ipv6: true,
    };
    let ipv6 = validate_host_topology_from_roots(
        &["eth0".to_string()],
        &ipv6_requirements,
        &proc_root,
        &sys_root,
    );
    assert_eq!(ipv6.status.state, IngressTopologyState::Ready);
}

#[test]
fn real_route_ingestion_rejects_non_utf8_oversized_and_excessive_line_input() {
    let fixture = tempdir().expect("temporary topology fixture");
    let proc_root = fixture.path().join("proc");
    let sys_root = fixture.path().join("sys/class/net");
    fs::create_dir_all(proc_root.join("net")).expect("create proc net");
    fs::create_dir_all(&sys_root).expect("create sys net");
    write_link(&sys_root, "eth0", 2, 1);

    fs::write(proc_root.join("net/route"), [0xff, 0xfe]).expect("write non-UTF8 route");
    assert_eq!(
        validate_host_topology_from_roots(
            &["eth0".to_string()],
            &v4_requirements(),
            &proc_root,
            &sys_root,
        )
        .status
        .reason,
        IngressTopologyReason::RouteTableInvalid,
    );

    let oversized = fs::File::create(proc_root.join("net/route")).expect("create route file");
    oversized.set_len(1_048_577).expect("extend route file");
    assert_eq!(
        validate_host_topology_from_roots(
            &["eth0".to_string()],
            &v4_requirements(),
            &proc_root,
            &sys_root,
        )
        .status
        .reason,
        IngressTopologyReason::RouteTableTooLarge,
    );

    fs::write(proc_root.join("net/route"), "\n".repeat(4_098))
        .expect("write excessive route lines");
    assert_eq!(
        validate_host_topology_from_roots(
            &["eth0".to_string()],
            &v4_requirements(),
            &proc_root,
            &sys_root,
        )
        .status
        .reason,
        IngressTopologyReason::RouteTableTooLarge,
    );
}

#[test]
fn sysfs_link_ingestion_classifies_physical_peer_loopback_and_unsafe_shapes() {
    let fixture = tempdir().expect("temporary sysfs fixture");
    let root = fixture.path();
    write_link(root, "physical0", 2, 2);
    assert!(read_link_state_from_root(root, "physical0").supported);

    write_link(root, "veth0", 3, 9);
    fs::remove_dir(root.join("veth0/device")).expect("remove physical marker");
    assert!(read_link_state_from_root(root, "veth0").supported);

    write_link(root, "dummy0", 4, 4);
    fs::remove_dir(root.join("dummy0/device")).expect("remove physical marker");
    assert!(!read_link_state_from_root(root, "dummy0").supported);

    write_link(root, "bridge0", 5, 5);
    fs::create_dir(root.join("bridge0/bridge")).expect("create bridge marker");
    assert!(!read_link_state_from_root(root, "bridge0").supported);

    write_link(root, "tun0", 6, 7);
    fs::create_dir(root.join("tun0/tun_flags")).expect("create tunnel marker");
    assert!(!read_link_state_from_root(root, "tun0").supported);

    write_link(root, "down0", 7, 1);
    fs::write(root.join("down0/carrier"), "0\n").expect("drop carrier");
    assert!(!read_link_state_from_root(root, "down0").up);

    write_link(root, "lo", 1, 1);
    fs::write(root.join("lo/type"), "772\n").expect("write loopback type");
    assert!(read_link_state_from_root(root, "lo").loopback);
    assert!(!read_link_state_from_root(root, "missing0").exists);
}

#[test]
fn node_requirements_use_complete_topology_evidence_without_admitting_peer_health() {
    let local = node("local", &[], None, false, &[]);
    let ready = node(
        "remote",
        &["10.244.2.0/24"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3"), ("ExternalIP", "203.0.113.3")],
    );
    let requirements = requirements_from_nodes(&[local.clone(), ready], "local", true)
        .expect("complete Ready Node evidence");
    assert_eq!(
        requirements.remote_node_addresses,
        [IpAddr::V4(Ipv4Addr::new(172, 18, 0, 3))]
    );
    assert!(requirements.require_ipv4);
    assert!(!requirements.require_ipv6);

    for incomplete in [
        node(
            "remote",
            &[],
            Some("True"),
            false,
            &[("InternalIP", "172.18.0.3")],
        ),
        node(
            "remote",
            &["10.244.2.0/24"],
            Some("True"),
            false,
            &[("ExternalIP", "203.0.113.3")],
        ),
    ] {
        assert_eq!(
            requirements_from_nodes(&[local.clone(), incomplete], "local", true),
            Err(IngressTopologyReason::NodeTopologyIncomplete),
        );
    }
}

#[test]
fn joining_rebooting_and_draining_nodes_do_not_poison_cluster_topology_proof() {
    let local = node("local", &[], None, false, &[]);
    let ready = node(
        "ready",
        &["10.244.2.0/24"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3")],
    );
    for transient in [
        node("joining", &[], None, false, &[]),
        node("rebooting", &[], Some("Unknown"), false, &[]),
        node("draining", &[], Some("False"), true, &[]),
    ] {
        let requirements =
            requirements_from_nodes(&[local.clone(), ready.clone(), transient], "local", false)
                .expect("peer health must not invalidate unchanged route evidence");
        assert_eq!(requirements.remote_pod_cidrs, [cidr("10.244.2.0/24")]);
    }

    // Complete evidence remains useful even while a peer is non-Ready: Ready
    // is a health condition, not an admission predicate for cluster topology.
    let allocated = node(
        "allocated",
        &["10.244.9.0/24"],
        Some("False"),
        true,
        &[("InternalIP", "172.18.0.9")],
    );
    let requirements = requirements_from_nodes(&[local, ready, allocated], "local", false)
        .expect("complete non-Ready topology evidence");
    assert!(
        requirements
            .remote_pod_cidrs
            .contains(&cidr("10.244.9.0/24"))
    );
}

#[test]
fn single_node_cluster_has_a_truthful_closed_outcome() {
    let local = node("local", &[], Some("True"), false, &[]);
    assert_eq!(
        requirements_from_nodes(std::slice::from_ref(&local), "local", true),
        Err(IngressTopologyReason::NoRemoteTopologyEvidence),
    );
    assert_eq!(
        requirements_from_nodes(
            &[local, node("joining", &[], None, false, &[])],
            "local",
            true,
        ),
        Err(IngressTopologyReason::NoRemoteTopologyEvidence),
    );
}

#[test]
fn node_family_derivation_handles_ipv4_dual_stack_and_ipv6_only_capture() {
    let local = node("local", &[], None, false, &[]);
    let ipv4 = node(
        "v4",
        &["10.244.2.0/24"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3")],
    );
    let v4_requirements = requirements_from_nodes(&[local.clone(), ipv4], "local", true)
        .expect("IPv4 cluster with dual-capable listener");
    assert!(v4_requirements.require_ipv4);
    assert!(!v4_requirements.require_ipv6);

    let dual = node(
        "dual",
        &["10.244.2.0/24", "fd00:10:244:2::/64"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3"), ("InternalIP", "fd00::3")],
    );
    let dual_requirements =
        requirements_from_nodes(&[local.clone(), dual], "local", true).expect("dual-stack cluster");
    assert!(dual_requirements.require_ipv4);
    assert!(dual_requirements.require_ipv6);

    let dual_without_ipv6_internal_ip = node(
        "dual-v4-capture",
        &["10.244.2.0/24", "fd00:10:244:2::/64"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3")],
    );
    let v4_capture_requirements = requirements_from_nodes(
        &[local.clone(), dual_without_ipv6_internal_ip],
        "local",
        false,
    )
    .expect("dual-stack cluster intersected with IPv4-only capture");
    assert!(v4_capture_requirements.require_ipv4);
    assert!(!v4_capture_requirements.require_ipv6);

    let ipv6 = node(
        "v6",
        &["fd00:10:244:2::/64"],
        Some("True"),
        false,
        &[("InternalIP", "fd00::3")],
    );
    let ipv6_requirements = requirements_from_nodes(&[local.clone(), ipv6.clone()], "local", true)
        .expect("IPv6-only cluster with IPv6-capable listener");
    assert!(!ipv6_requirements.require_ipv4);
    assert!(ipv6_requirements.require_ipv6);
    assert_eq!(
        requirements_from_nodes(&[local, ipv6], "local", false),
        Err(IngressTopologyReason::FamilyUnproved),
    );
}

#[test]
fn node_and_aggregate_requirement_bounds_have_distinct_closed_reasons() {
    let too_many_nodes: Vec<Node> = (0..257)
        .map(|index| node(&format!("node-{index}"), &[], Some("False"), true, &[]))
        .collect();
    assert_eq!(
        requirements_from_nodes(&too_many_nodes, "node-0", true),
        Err(IngressTopologyReason::NodeSetTooLarge),
    );

    let local = node("local", &[], None, false, &[]);
    // 1,023 pending CIDRs plus two pending same-family InternalIPs proves the
    // aggregate calculation counts every collection, not only the destination
    // vector currently receiving an item.
    let cidrs: Vec<String> = (0..1_023)
        .map(|index| format!("fd00::{index:x}/128"))
        .collect();
    let cidr_refs: Vec<&str> = cidrs.iter().map(String::as_str).collect();
    let oversized = node(
        "remote",
        &cidr_refs,
        Some("True"),
        false,
        &[("InternalIP", "fd00::fffe"), ("InternalIP", "fd00::ffff")],
    );
    assert_eq!(
        requirements_from_nodes(&[local, oversized], "local", true),
        Err(IngressTopologyReason::RequirementSetTooLarge),
    );
}

#[test]
fn invalid_node_cache_never_allows_ready_from_incremental_events() {
    let mut recovery = NodeWatchCacheRecovery::new();
    assert_eq!(
        recovery.on_incremental_invalid(IngressTopologyReason::NodeSetTooLarge),
        NodeWatchCacheDecision::ForceRelist {
            backoff_secs: 1_200
        },
    );
    assert_eq!(
        recovery.invalid_reason(),
        Some(IngressTopologyReason::NodeSetTooLarge),
    );

    // Deletes/Applies after an authoritative overflow must stay suppressed.
    // Ready may only return through a later complete valid snapshot.
    for _ in 0..8 {
        assert_eq!(
            recovery.on_incremental(),
            NodeWatchCacheDecision::SuppressIncremental {
                reason: IngressTopologyReason::NodeSetTooLarge,
            },
        );
    }
    assert_ne!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::AllowIncremental,
    );
    assert_ne!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::CommitSnapshot,
    );
}

#[test]
fn node_cache_recovery_requires_complete_valid_replacement_snapshot() {
    let mut recovery = NodeWatchCacheRecovery::new();
    assert_eq!(
        recovery.on_init(),
        NodeWatchCacheDecision::StartInitializing,
    );
    assert_eq!(
        recovery.on_invalid_snapshot(IngressTopologyReason::NodeSetTooLarge),
        NodeWatchCacheDecision::ForceRelist {
            backoff_secs: 1_200
        },
    );
    assert_eq!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::SuppressIncremental {
            reason: IngressTopologyReason::NodeSetTooLarge,
        },
    );

    // A fresh Init withdraws readiness again but still does not authorize
    // incremental repair of the previous invalid generation.
    assert_eq!(
        recovery.on_init(),
        NodeWatchCacheDecision::StartInitializing,
    );
    assert_eq!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::SuppressIncremental {
            reason: IngressTopologyReason::KubernetesUnavailable,
        },
    );

    assert_eq!(
        recovery.on_valid_snapshot(),
        NodeWatchCacheDecision::CommitSnapshot,
    );
    assert_eq!(recovery.invalid_reason(), None);
    assert_eq!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::AllowIncremental,
    );
    assert_eq!(recovery.relist_backoff_secs(), 1);
}

#[test]
fn repeated_invalid_node_cache_snapshots_stay_bounded_without_spinning() {
    let mut recovery = NodeWatchCacheRecovery::new();
    let mut observed = Vec::new();
    for _ in 0..8 {
        match recovery.on_invalid_snapshot(IngressTopologyReason::NodeSetTooLarge) {
            NodeWatchCacheDecision::ForceRelist { backoff_secs } => {
                observed.push(backoff_secs);
            }
            other => panic!("expected paced ForceRelist, got {other:?}"),
        }
        // Incremental noise between forced relists must not clear the failure
        // or authorize Ready from partial state.
        assert_eq!(
            recovery.on_incremental(),
            NodeWatchCacheDecision::SuppressIncremental {
                reason: IngressTopologyReason::NodeSetTooLarge,
            },
        );
    }

    assert_eq!(observed, vec![1_200; 8]);
    assert_eq!(recovery.relist_backoff_secs(), 1);

    // A successful replacement snapshot is the only path that resets pacing.
    assert_eq!(
        recovery.on_valid_snapshot(),
        NodeWatchCacheDecision::CommitSnapshot,
    );
    assert_eq!(recovery.relist_backoff_secs(), 1);
    assert_eq!(
        recovery.on_invalid_snapshot(IngressTopologyReason::NodeTopologyIncomplete),
        NodeWatchCacheDecision::ForceRelist { backoff_secs: 1 },
    );
}

#[tokio::test]
async fn production_topology_monitor_processes_synthetic_node_events_and_skips_heartbeats() {
    let fixture = tempdir().expect("temporary topology fixture");
    let proc_root = fixture.path().join("proc");
    let sys_root = fixture.path().join("sys/class/net");
    fs::create_dir_all(proc_root.join("net")).expect("create proc net");
    fs::create_dir_all(&sys_root).expect("create sys net");
    write_link(&sys_root, "eth0", 2, 1);
    fs::write(
        proc_root.join("net/route"),
        concat!(
            "Iface\tDestination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            "eth0\t0002F40A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n",
            "eth0\t000012AC 00000000 0001 0 0 0 0000FFFF 0 0 0\n",
        ),
    )
    .expect("write IPv4 routes");

    let validator = IngressTopologyValidator::new(vec!["eth0".to_string()], "local", false)
        .with_roots(proc_root.clone(), sys_root);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (event_tx, event_rx) =
        tokio::sync::mpsc::channel::<Result<Event<Node>, kube::runtime::watcher::Error>>(16);
    let event_stream = stream::unfold(event_rx, |mut receiver| async move {
        receiver.recv().await.map(|event| (event, receiver))
    });
    let (mut outcomes, task) =
        spawn_node_agent_ingress_topology_monitor_for_test(validator, shutdown_rx, event_stream);

    let local = node("local", &[], Some("True"), false, &[]);
    let remote = node(
        "remote",
        &["10.244.2.0/24"],
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3")],
    );
    for event in [
        Event::Init,
        Event::InitApply(local),
        Event::InitApply(remote.clone()),
        Event::InitDone,
    ] {
        event_tx.send(Ok(event)).await.expect("send init event");
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), outcomes.changed())
        .await
        .expect("initial topology outcome timeout")
        .expect("monitor outcome channel");
    assert_eq!(
        outcomes.borrow_and_update().status.state,
        IngressTopologyState::Ready,
    );

    // Remove the host evidence after the initial proof. An unrelated Node
    // heartbeat must not trigger procfs/sysfs validation; the periodic drift
    // lane will detect it on its own five-second tick.
    fs::remove_file(proc_root.join("net/route")).expect("remove route evidence");
    let mut heartbeat = remote;
    heartbeat.metadata.annotations = Some(BTreeMap::from([(
        "example.test/heartbeat".to_string(),
        "changed".to_string(),
    )]));
    event_tx
        .send(Ok(Event::Apply(heartbeat)))
        .await
        .expect("send heartbeat");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), outcomes.changed())
            .await
            .is_err(),
        "unchanged projected evidence must not publish a host revalidation",
    );

    // A newly joining non-Ready Node changes the projected cache but not the
    // derived requirements, so it must neither poison readiness nor force a
    // host revalidation.
    event_tx
        .send(Ok(Event::Apply(node("joining", &[], None, false, &[]))))
        .await
        .expect("send joining Node");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), outcomes.changed())
            .await
            .is_err(),
        "an incomplete non-Ready peer must not poison the proved topology",
    );

    event_tx
        .send(Ok(Event::Apply(node(
            "remote",
            &[],
            Some("True"),
            false,
            &[("InternalIP", "172.18.0.3")],
        ))))
        .await
        .expect("send incomplete Ready Node");
    tokio::time::timeout(std::time::Duration::from_secs(2), outcomes.changed())
        .await
        .expect("closed topology outcome timeout")
        .expect("monitor outcome channel");
    assert_eq!(
        outcomes.borrow_and_update().status.reason,
        IngressTopologyReason::NodeTopologyIncomplete,
    );

    shutdown_tx.send(true).expect("request monitor shutdown");
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .expect("monitor shutdown timeout")
        .expect("monitor task");
}

#[test]
fn topology_outcome_application_arms_and_quarantines_the_bpf_redirect() {
    let config = node_waypoint_config();
    let metrics = NodeAgentMetrics::default();
    let mut backend = MockEbpfBackend::default();

    let flags = apply_node_agent_ingress_topology_outcome_for_test(
        &mut backend,
        &config,
        &metrics,
        false,
        false,
        true,
        &ready_outcome(),
    );
    assert_eq!(flags, (true, true));
    assert!(
        backend
            .capture_config
            .expect("ready capture config")
            .ingress_redirect_armed()
    );

    backend.fail_update_capture_config = true;
    let flags = apply_node_agent_ingress_topology_outcome_for_test(
        &mut backend,
        &config,
        &metrics,
        true,
        true,
        true,
        &unavailable_outcome(),
    );
    assert_eq!(flags, (false, false));
    assert_eq!(
        metrics.snapshot().ingress_topology.reason,
        IngressTopologyReason::DatapathUpdateFailed,
    );

    // The production select loop retries a failed capture-map publication on
    // its bounded timer. Drive that retry through the same transition helper.
    backend.fail_update_capture_config = false;
    let flags = apply_node_agent_ingress_topology_outcome_for_test(
        &mut backend,
        &config,
        &metrics,
        false,
        false,
        true,
        &unavailable_outcome(),
    );
    assert_eq!(flags, (false, false));
    assert!(
        !backend
            .capture_config
            .expect("quarantined capture config")
            .ingress_redirect_armed()
    );
    assert_eq!(
        metrics.snapshot().ingress_topology.reason,
        IngressTopologyReason::KubernetesUnavailable,
    );
}

#[test]
fn disabled_ingress_topology_skips_map_republication_and_does_not_gate_readiness() {
    let mut config = node_waypoint_config();
    config.capture_contract.ingress_redirect_ifaces.clear();
    let metrics = NodeAgentMetrics::default();
    let mut backend = MockEbpfBackend {
        fail_update_capture_config: true,
        ..Default::default()
    };
    let outcome = IngressTopologyOutcome {
        status: IngressTopologyStatus::disabled(),
        diagnostic: "inbound ingress redirect is disabled".to_string(),
    };

    let flags = apply_node_agent_ingress_topology_outcome_for_test(
        &mut backend,
        &config,
        &metrics,
        true,
        false,
        true,
        &outcome,
    );

    assert_eq!(flags, (true, true));
    assert!(backend.capture_config_updates.is_empty());
    assert_eq!(
        metrics.snapshot().ingress_topology.state,
        IngressTopologyState::Disabled,
    );
}

#[test]
fn startup_readiness_requires_sync_topology_and_udp_migration_proofs() {
    for initial_sync_complete in [false, true] {
        for topology_ready in [false, true] {
            for udp_migration_ready in [false, true] {
                assert_eq!(
                    set_node_agent_startup_readiness_for_test(
                        initial_sync_complete,
                        topology_ready,
                        udp_migration_ready,
                    ),
                    initial_sync_complete && topology_ready && udp_migration_ready,
                );
            }
        }
    }
}

#[test]
fn aggregate_node_snapshot_evidence_is_bounded_before_cache_commit() {
    let cidrs = vec!["10.0.0.0/24"; 512];
    let snapshot = vec![
        node(
            "local",
            &cidrs,
            Some("True"),
            false,
            &[("InternalIP", "172.18.0.2")],
        ),
        node(
            "remote",
            &cidrs,
            Some("True"),
            false,
            &[("InternalIP", "172.18.0.3")],
        ),
    ];

    assert_eq!(
        apply_bounded_node_topology_sequence_for_test(snapshot, None),
        Err(IngressTopologyReason::RequirementSetTooLarge),
    );
}

#[test]
fn aggregate_node_cache_rejects_an_oversized_incremental_replacement() {
    let replacement_cidrs = vec!["10.0.0.0/24"; 1024];
    let snapshot = vec![
        node(
            "local",
            &["10.244.1.0/24"],
            Some("True"),
            false,
            &[("InternalIP", "172.18.0.2")],
        ),
        node(
            "remote",
            &["10.244.2.0/24"],
            Some("True"),
            false,
            &[("InternalIP", "172.18.0.3")],
        ),
    ];
    let replacement = node(
        "remote",
        &replacement_cidrs,
        Some("True"),
        false,
        &[("InternalIP", "172.18.0.3")],
    );

    assert_eq!(
        apply_bounded_node_topology_sequence_for_test(snapshot, Some(replacement)),
        Err(IngressTopologyReason::RequirementSetTooLarge),
    );
}

#[test]
fn projected_node_cache_rejects_oversized_topology_strings() {
    let oversized_address = "a".repeat(65);
    let snapshot = vec![node(
        "remote",
        &["10.244.2.0/24"],
        Some("False"),
        false,
        &[("InternalIP", oversized_address.as_str())],
    )];

    assert_eq!(
        apply_bounded_node_topology_sequence_for_test(snapshot, None),
        Err(IngressTopologyReason::RequirementSetTooLarge),
    );
}

#[test]
fn cni_add_check_and_status_withhold_capture_ready_during_topology_loss() {
    for verb in [RpcVerb::Add, RpcVerb::Check, RpcVerb::Status] {
        assert!(
            node_agent_cni_topology_readiness_rejection_for_test(verb, true, false).is_some(),
            "{verb:?} must be rejected while topology is quarantined",
        );
        assert_eq!(
            node_agent_cni_topology_readiness_rejection_for_test(verb, true, true),
            None,
        );
    }
    assert_eq!(
        node_agent_cni_topology_readiness_rejection_for_test(RpcVerb::Del, true, false),
        None,
        "cleanup must remain available while capture is quarantined",
    );
    assert!(
        node_agent_cni_topology_readiness_rejection_for_test(RpcVerb::Gc, false, false).is_some()
    );
    assert_eq!(
        node_agent_cni_topology_readiness_rejection_for_test(RpcVerb::Gc, true, false),
        None,
        "post-sync GC must remain available while capture is quarantined",
    );
}

#[test]
fn cni_add_check_and_status_require_the_udp_migration_proof() {
    for verb in [RpcVerb::Add, RpcVerb::Check, RpcVerb::Status] {
        assert_eq!(
            node_agent_cni_capture_readiness_rejection_for_test(verb, true, true, false),
            Some("Ambient UDP migration registry proof is unavailable; enrollment is fenced"),
        );
        assert_eq!(
            node_agent_cni_capture_readiness_rejection_for_test(verb, true, true, true),
            None,
        );
    }
    assert_eq!(
        node_agent_cni_capture_readiness_rejection_for_test(RpcVerb::Del, true, false, false,),
        None,
        "cleanup must remain available while either readiness proof is unavailable",
    );
    assert_eq!(
        node_agent_cni_capture_readiness_rejection_for_test(RpcVerb::Gc, true, false, false,),
        None,
        "post-sync GC must remain available while either readiness proof is unavailable",
    );
}

#[tokio::test]
async fn production_select_loop_applies_synthetic_ready_to_unavailable_transition() {
    let config = node_waypoint_config();
    let metrics = Arc::new(NodeAgentMetrics::default());
    metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_READY);
    let mut backend = MockEbpfBackend::default();
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);

    let pod_events =
        stream::iter(vec![Ok(Event::Init), Ok(Event::InitDone)]).chain(stream::pending());
    let transitions =
        stream::iter(vec![ready_outcome(), unavailable_outcome()]).then(|outcome| async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            outcome
        });
    let shutdown = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let _ = shutdown.send(true);
    });

    let result = run_with_node_agent_topology_outcome_stream_for_test(
        &mut backend,
        &config,
        metrics.clone(),
        &shutdown_tx,
        pod_events,
        ready_outcome(),
        Box::pin(transitions),
    )
    .await;

    assert!(
        result.is_ok(),
        "synthetic transition loop failed: {result:?}"
    );
    assert!(
        backend
            .capture_config_updates
            .iter()
            .any(|config| config.ingress_redirect_armed()),
        "Ready transition must arm the redirect",
    );
    assert!(
        !backend
            .capture_config_updates
            .last()
            .expect("at least one topology publication")
            .ingress_redirect_armed(),
        "topology loss must leave the redirect quarantined",
    );
    assert_eq!(
        metrics.snapshot().ingress_topology.reason,
        IngressTopologyReason::KubernetesUnavailable,
    );
}

#[test]
fn ended_node_watch_forces_a_paced_fresh_snapshot() {
    let mut recovery = NodeWatchCacheRecovery::new();
    assert_eq!(
        recovery.on_stream_end(),
        NodeWatchCacheDecision::ForceRelist { backoff_secs: 1 },
    );
    assert_eq!(
        recovery.invalid_reason(),
        Some(IngressTopologyReason::KubernetesUnavailable),
    );
    assert_eq!(
        recovery.on_incremental(),
        NodeWatchCacheDecision::SuppressIncremental {
            reason: IngressTopologyReason::KubernetesUnavailable,
        },
    );
    assert_eq!(
        recovery.on_stream_end(),
        NodeWatchCacheDecision::ForceRelist { backoff_secs: 2 },
    );

    assert_eq!(
        recovery.on_valid_snapshot(),
        NodeWatchCacheDecision::CommitSnapshot,
    );
    assert_eq!(recovery.relist_backoff_secs(), 1);
}
