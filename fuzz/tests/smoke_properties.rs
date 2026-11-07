use ferrum_edge::fuzz_support::{
    MAX_FUZZ_INPUT_BYTES, fuzz_decode_config_document, fuzz_drain_mesh_udp_frames,
    fuzz_jwks_accepts, fuzz_jwt_svid_invariant, fuzz_parse_datagram_header,
    fuzz_parse_proxy_protocol, fuzz_pem_certificate_record_count, fuzz_tls_material_accepts,
    fuzz_tls_material_invariant, fuzz_translate_k8s_json, fuzz_validate_ocsp_structure,
    fuzz_validate_plugin_config, mesh_udp_frame_round_trip, ocsp_structure_invariant,
    smoke_invariants, traceparent_round_trip_invariant,
};
use ferrum_edge::proxy::mesh_udp_frame::MAX_FRAME_PAYLOAD;
use proptest::prelude::*;

#[test]
fn smoke_invariants_hold() {
    smoke_invariants().expect("smoke invariants");
}

proptest! {
    #[test]
    fn traceparent_round_trip_never_panics(input in prop::string::string_regex(".{0,256}").unwrap()) {
        let _ = ferrum_edge::fuzz_support::parse_traceparent_header(&input);
        prop_assert!(
            traceparent_round_trip_invariant(&input),
            "accepted traceparent must round-trip"
        );
    }

    #[test]
    fn mesh_udp_frame_round_trip_for_bounded_payload(payload in prop::collection::vec(any::<u8>(), 0..=256)) {
        if payload.len() <= MAX_FRAME_PAYLOAD {
            mesh_udp_frame_round_trip(&payload).expect("round-trip");
        }
    }

    #[test]
    fn mesh_udp_framing_never_panics(wire in prop::collection::vec(any::<u8>(), 0..=1024)) {
        let _ = fuzz_drain_mesh_udp_frames(&wire);
    }

    #[test]
    fn proxy_protocol_never_panics(data in prop::collection::vec(any::<u8>(), 0..=1024)) {
        let _ = fuzz_parse_proxy_protocol(&data);
    }

    #[test]
    fn datagram_client_address_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..=1024),
    ) {
        let _ = fuzz_parse_datagram_header(&data);
    }

    #[test]
    fn ocsp_structure_invariants_hold(data in prop::collection::vec(any::<u8>(), 0..=1024)) {
        prop_assert!(ocsp_structure_invariant(&data));
    }

    #[test]
    fn jwt_svid_rejects_every_unsigned_input(data in prop::collection::vec(any::<u8>(), 0..=1024)) {
        prop_assert!(fuzz_jwt_svid_invariant(&data));
    }

    #[test]
    fn tls_material_invariants_hold(data in prop::collection::vec(any::<u8>(), 0..=1024)) {
        prop_assert!(fuzz_tls_material_invariant(&data));
    }
}

/// Every committed seed must keep its target's invariant, and the
/// well-formed OCSP seeds must actually reach acceptance so the fuzzer starts
/// from the deep end of the grammar rather than the envelope check.
#[test]
fn ocsp_response_seeds_hold_invariants_and_the_valid_ones_are_accepted() {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/ocsp_response");
    let mut seeds = 0;
    for entry in std::fs::read_dir(&corpus).expect("ocsp_response corpus") {
        let path = entry.expect("corpus entry").path();
        let bytes = std::fs::read(&path).expect("seed bytes");
        assert!(ocsp_structure_invariant(&bytes), "{}", path.display());
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("valid_") {
            fuzz_validate_ocsp_structure(&bytes)
                .unwrap_or_else(|error| panic!("{name} must be accepted: {error}"));
        }
        seeds += 1;
    }
    assert!(seeds > 0);
}

#[test]
fn jwt_svid_seeds_hold_the_forgery_invariant() {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/jwt_svid");
    let mut seeds = 0;
    for entry in std::fs::read_dir(&corpus).expect("jwt_svid corpus") {
        let path = entry.expect("corpus entry").path();
        let bytes = std::fs::read(&path).expect("seed bytes");
        assert!(fuzz_jwt_svid_invariant(&bytes), "{}", path.display());
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("jwks_valid_") {
            assert!(
                fuzz_jwks_accepts(&bytes[1..]),
                "{name} must be an accepted JWKS so the round trip is exercised"
            );
        } else if name.starts_with("jwks_") {
            assert!(
                !fuzz_jwks_accepts(&bytes[1..]),
                "{name} is a policy-negative JWKS and must be refused"
            );
        }
        seeds += 1;
    }
    assert!(seeds > 0);
}

#[test]
fn tls_material_seeds_hold_invariants_and_pin_admission() {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/tls_material");
    let mut seeds = 0;
    for entry in std::fs::read_dir(&corpus).expect("tls_material corpus") {
        let path = entry.expect("corpus entry").path();
        let bytes = std::fs::read(&path).expect("seed bytes");
        assert!(fuzz_tls_material_invariant(&bytes), "{}", path.display());
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // `valid_*` seeds must be admitted and every other seed refused, so a
        // bypassed record limit, key-count, key-form, or window check fails.
        assert_eq!(
            fuzz_tls_material_accepts(&bytes),
            name.starts_with("valid_"),
            "{name}: unexpected admission outcome"
        );
        seeds += 1;
    }
    assert!(seeds > 0);
}

#[test]
fn encode_pop_round_trip_empty_datagram() {
    mesh_udp_frame_round_trip(b"").expect("empty frame round-trip");
}

#[test]
fn config_decode_minimal_json() {
    let doc = r#"{"version":"1","proxies":[],"consumers":[],"plugin_configs":[],"upstreams":[]}"#;
    fuzz_decode_config_document(doc).expect("minimal config");
}

/// A `tcp_connection_throttle` attached to an HTTP proxy. The two
/// `ValidationPipeline` chains accept it; only the shared runtime admission
/// gate (`collect_rejecting_runtime_config_errors`, `87c97cbd6`) refuses it.
/// Mirrors `http-proxy-throttle` in `tests/fixtures/file_admission_cases.json`.
const HTTP_PROXY_THROTTLE_JSON: &str = r#"{
    "version":"1",
    "proxies":[{"id":"fixture-proxy","listen_path":"/fixture","backend_scheme":"http",
        "backend_host":"localhost","backend_port":3000,
        "plugins":[{"plugin_config_id":"throttle"}]}],
    "consumers":[],
    "plugin_configs":[{"id":"throttle","plugin_name":"tcp_connection_throttle","scope":"proxy",
        "enabled":true,"config":{"max_connections_per_key":1},"proxy_id":"fixture-proxy"}],
    "upstreams":[]
}"#;

const HTTP_PROXY_THROTTLE_YAML: &str = "version: '1'
proxies:
- id: fixture-proxy
  listen_path: /fixture
  backend_scheme: http
  backend_host: localhost
  backend_port: 3000
  plugins:
  - plugin_config_id: throttle
consumers: []
plugin_configs:
- id: throttle
  plugin_name: tcp_connection_throttle
  scope: proxy
  enabled: true
  config:
    max_connections_per_key: 1
  proxy_id: fixture-proxy
upstreams: []
";

/// Two global `correlation_id` configs writing the same effective header.
/// Mirrors `duplicate-global-correlation` in the same fixture file.
const DUPLICATE_GLOBAL_CORRELATION_JSON: &str = r#"{
    "version":"1",
    "proxies":[{"id":"fixture-proxy","listen_path":"/fixture","backend_scheme":"http",
        "backend_host":"localhost","backend_port":3000}],
    "consumers":[],
    "plugin_configs":[
        {"id":"correlation-0","plugin_name":"correlation_id","scope":"global","enabled":true,
         "config":{}},
        {"id":"correlation-1","plugin_name":"correlation_id","scope":"global","enabled":true,
         "config":{"header_name":"x-request-id"},"priority_override":75}],
    "upstreams":[]
}"#;

/// The same throttle on a TCP proxy is valid. Mirrors `valid-tcp-proxy-throttle`.
const VALID_TCP_PROXY_THROTTLE_JSON: &str = r#"{
    "version":"1",
    "proxies":[{"id":"fixture-proxy","backend_scheme":"tcp","backend_host":"localhost",
        "backend_port":3000,"listen_port":31001,"plugins":[{"plugin_config_id":"throttle"}]}],
    "consumers":[],
    "plugin_configs":[{"id":"throttle","plugin_name":"tcp_connection_throttle","scope":"proxy",
        "enabled":true,"config":{"max_connections_per_key":1},"proxy_id":"fixture-proxy"}],
    "upstreams":[]
}"#;

#[test]
fn config_decode_applies_the_shared_runtime_admission_gate() {
    // The in-memory decode shares file mode's decode-and-validate core, so it
    // must refuse what `validate` and SIGHUP refuse, for JSON and for sniffed
    // YAML alike.
    for (name, doc, expected) in [
        (
            "http-proxy-throttle json",
            HTTP_PROXY_THROTTLE_JSON,
            "tcp_connection_throttle",
        ),
        (
            "http-proxy-throttle yaml",
            HTTP_PROXY_THROTTLE_YAML,
            "tcp_connection_throttle",
        ),
        (
            "duplicate-global-correlation",
            DUPLICATE_GLOBAL_CORRELATION_JSON,
            "duplicate effective header_name",
        ),
    ] {
        let error = fuzz_decode_config_document(doc).expect_err(name);
        assert!(error.contains(expected), "{name}: {error}");
    }
    fuzz_decode_config_document(VALID_TCP_PROXY_THROTTLE_JSON)
        .expect("a TCP proxy throttle passes the shared gate");
}

#[test]
fn config_decode_sniffs_yaml_without_a_path() {
    // File mode picks YAML vs JSON from the path extension; the in-memory
    // decode has no path and sniffs the content instead.
    let doc = "version: 1\nproxies: []\nconsumers: []\nplugin_configs: []\nupstreams: []\n";
    fuzz_decode_config_document(doc).expect("YAML document decodes without a path");
}

/// One valid `prod` proxy plus a `staging` proxy whose `upstream_id` does not
/// exist. File mode loading `prod` drops the staging proxy before the
/// cross-resource validators run, so it accepts this document
/// (`file_mode_skips_cross_resource_checks_for_other_namespaces` in
/// `tests/unit/config/config_file_loader_tests.rs`).
const OTHER_NAMESPACE_DANGLING_UPSTREAM_JSON: &str = r#"{
    "version":"1",
    "proxies":[
        {"id":"prod-proxy","namespace":"prod","listen_path":"/prod",
         "backend_scheme":"http","backend_host":"localhost","backend_port":3001},
        {"id":"staging-proxy","namespace":"staging","listen_path":"/staging",
         "backend_scheme":"http","backend_host":"localhost","backend_port":3002,
         "upstream_id":"missing-upstream"}
    ],
    "consumers":[],
    "plugin_configs":[],
    "upstreams":[]
}"#;

#[test]
fn config_decode_validates_every_namespace_together() {
    // The in-memory decode has no gateway namespace
    // (`DocumentNamespaceScope::Unfiltered`), so the cross-resource validators
    // also see every other namespace's resources and refuse the dangling
    // staging reference.
    let error = fuzz_decode_config_document(OTHER_NAMESPACE_DANGLING_UPSTREAM_JSON)
        .expect_err("unfiltered decode must check the staging proxy's upstream reference");
    assert!(error.contains("upstream reference"), "{error}");
}

#[test]
fn config_decode_does_not_materialize_runtime_file_dependencies() {
    let doc = r#"{
        "version":"1",
        "proxies":[],
        "consumers":[],
        "upstreams":[],
        "plugin_configs":[{
            "id":"geo",
            "plugin_name":"geo_restriction",
            "config":{
                "db_path":"/fuzz-target-must-not-read-this.mmdb",
                "deny_countries":["SE"],
                "on_lookup_failure":"deny"
            },
            "scope":"global",
            "enabled":true
        }]
    }"#;
    fuzz_decode_config_document(doc)
        .expect("pure config fuzzing must not materialize runtime file dependencies");
}

#[test]
fn k8s_minimal_virtual_service() {
    let json = br#"[{"apiVersion":"networking.istio.io/v1","kind":"VirtualService","metadata":{"name":"reviews","namespace":"default"},"spec":{"hosts":["reviews"],"http":[{"route":[{"destination":{"host":"reviews"}}]}]}}]"#;
    let _ = fuzz_translate_k8s_json(json);
}

#[test]
fn plugin_config_cors_minimal() {
    let input = br#"0{"allowed_origins":["*"]}"#;
    fuzz_validate_plugin_config(input).expect("minimal CORS config");
}

#[test]
fn input_budget_is_documented() {
    assert_eq!(MAX_FUZZ_INPUT_BYTES, 64 * 1024);
}

/// The certificate record limit (4096) sits far outside the fuzz input budget,
/// so it is pinned here with minimal PEM records on both sides of the bound.
#[test]
fn pem_certificate_bundle_record_limit_is_exact() {
    let record = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
    let at_limit = record.repeat(4096);
    assert_eq!(fuzz_pem_certificate_record_count(&at_limit), Some(4096));
    let over_limit = record.repeat(4097);
    assert_eq!(fuzz_pem_certificate_record_count(&over_limit), None);
}
