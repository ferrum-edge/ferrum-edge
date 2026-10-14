#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(data) = ferrum_edge::fuzz_support::enforce_input_budget(data) else {
        return;
    };
    assert!(
        ferrum_edge::fuzz_support::fuzz_jwt_svid_invariant(data),
        "a JWT-SVID invariant broke: an unsigned token validated or a JWKS failed its round trip"
    );
});
