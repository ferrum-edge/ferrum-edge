//! Source-contract coverage for namespace-qualified stream plugin lookups.
//!
//! After #3094 rekeyed `PluginCacheInner` protocol snapshots by `namespace|id`,
//! TCP/UDP/DTLS/mesh connect paths must call the scratch-buffer
//! `plugins_for_protocol(namespace, id, protocol)` accessor. Allocating a
//! `namespaced_runtime_key` and feeding the bare-key `get_plugins_for_protocol`
//! both wastes a per-connection `String` and invites bare-id fallthrough to the
//! global plugin chain.

const STREAM_PLUGIN_LOOKUP: &str = "plugins_for_protocol(";
const ALLOCATING_KEY: &str = "namespaced_runtime_key";
const BARE_KEY_LOOKUP: &str = "get_plugins_for_protocol(";

fn assert_stream_plugin_lookup_contract(path: &str, source: &str) {
    assert!(
        source.contains(STREAM_PLUGIN_LOOKUP),
        "{path} must resolve stream plugins through plugins_for_protocol"
    );
    assert!(
        !source.contains(ALLOCATING_KEY),
        "{path} must not allocate namespaced_runtime_key on the stream plugin path"
    );
    assert!(
        !source.contains(BARE_KEY_LOOKUP),
        "{path} must not call the composed-key get_plugins_for_protocol directly"
    );
}

#[test]
fn tcp_proxy_uses_namespace_scratch_plugin_lookup() {
    assert_stream_plugin_lookup_contract(
        "tcp_proxy.rs",
        include_str!("../../../src/proxy/tcp_proxy.rs"),
    );
}

#[test]
fn udp_proxy_uses_namespace_scratch_plugin_lookup() {
    assert_stream_plugin_lookup_contract(
        "udp_proxy.rs",
        include_str!("../../../src/proxy/udp_proxy.rs"),
    );
}

#[test]
fn mesh_tcp_inbound_uses_namespace_scratch_plugin_lookup() {
    assert_stream_plugin_lookup_contract(
        "mesh_tcp_inbound.rs",
        include_str!("../../../src/proxy/mesh_tcp_inbound.rs"),
    );
}

#[test]
fn mesh_egress_observability_uses_namespace_scratch_plugin_lookup() {
    assert_stream_plugin_lookup_contract(
        "mesh_egress_observability.rs",
        include_str!("../../../src/proxy/mesh_egress_observability.rs"),
    );
}
