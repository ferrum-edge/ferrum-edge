#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(data) = ferrum_edge::fuzz_support::enforce_input_budget(data) else {
        return;
    };
    let _ = ferrum_edge::fuzz_support::fuzz_drain_mesh_udp_frames(data);
    if data.len() <= ferrum_edge::proxy::mesh_udp_frame::MAX_FRAME_PAYLOAD {
        ferrum_edge::fuzz_support::mesh_udp_frame_round_trip(data)
            .expect("bounded mesh UDP payload must round-trip");
    }
});
