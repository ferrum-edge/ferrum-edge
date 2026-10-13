#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(data) = ferrum_edge::fuzz_support::enforce_input_budget(data) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = ferrum_edge::fuzz_support::parse_traceparent_header(text);
    assert!(
        ferrum_edge::fuzz_support::traceparent_round_trip_invariant(text),
        "accepted traceparent must round-trip"
    );
});
