use ferrum_ebpf_common::{IncludePortsPolicy, INCLUDE_PORTS_MAX};

#[test]
fn explicit_policy_preserves_every_port_at_capacity() {
    let ports: Vec<u16> = (1..=INCLUDE_PORTS_MAX as u16).collect();
    let policy = IncludePortsPolicy::explicit(&ports);
    assert!(!policy.is_all_ports());
    assert_eq!(policy.port_count as usize, ports.len());
    assert_eq!(policy.ports.as_slice(), ports.as_slice());
}

#[test]
fn seventeenth_port_selects_capture_all_instead_of_a_truncated_list() {
    let ports: Vec<u16> = (1..=INCLUDE_PORTS_MAX as u16 + 1).collect();
    let policy = IncludePortsPolicy::explicit(&ports);
    // Both connect hooks consume this sentinel before walking the port array.
    // No array of sixteen entries can retain all seventeen requested ports.
    assert_eq!(policy, IncludePortsPolicy::all());
    assert!(policy.is_all_ports());
    assert_eq!(policy.port_count, 0);
    assert!(policy.ports.iter().all(|port| *port == 0));
}
