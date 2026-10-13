use ferrum_edge::fuzz_support::{
    MAX_FUZZ_INPUT_BYTES, fuzz_decode_config_document, fuzz_drain_mesh_udp_frames,
    fuzz_jwt_svid_invariant, fuzz_parse_datagram_header, fuzz_parse_proxy_protocol,
    fuzz_translate_k8s_json, fuzz_validate_ocsp_structure, fuzz_validate_plugin_config,
    mesh_udp_frame_round_trip, ocsp_structure_invariant, smoke_invariants,
    traceparent_round_trip_invariant,
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
