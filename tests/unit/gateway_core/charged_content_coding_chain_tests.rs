//! The strict, budget-charged content-coding chain decoder that `compression`'s
//! opt-in `decompress_request` normalizer runs (`GHSA-q76p-952x-7c3v`).
//!
//! The normalizer used to call the generic inspection decoder, whose Brotli
//! state allocates its ring buffer and Huffman tables from the stream header
//! before a single output byte exists. The per-layer output ceilings ran AFTER
//! that call, so the bounded 32-slot codec pool bounded how many decodes ran at
//! once but nothing bounded how much memory each one took. These drive the
//! PRODUCTION decoder through the `_test_support` seam against an ISOLATED
//! budget, so admission and release are observable without mutating the
//! process-global semaphore under a parallel test binary.

use std::io::Write;

use ferrum_edge::_test_support::{
    ChargedCodingChainOutcome, RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT,
    RESPONSE_DECODE_BROTLI_SCRATCH_BYTES, RESPONSE_DECODE_GZIP_SCRATCH_BYTES,
    ResponseBufferBudgetProbe, decode_charged_coding_chain_in,
    projected_decode_output_capacity_for_test,
};

/// The per-layer ceiling `compression` derives from its default
/// `max_decompressed_request_size` (10 MiB).
const LIMIT: usize = 10 * 1024 * 1024;

/// The plugin's raw-to-decoded amplification bound.
const RATIO: u32 = 1024;

fn probe(total_blocks: usize) -> ResponseBufferBudgetProbe {
    ResponseBufferBudgetProbe::new(UNIT, total_blocks * UNIT)
}

fn blocks(bytes: usize) -> usize {
    bytes.div_ceil(UNIT)
}

/// Decode under the plugin's default bounds.
fn decode(
    budget: &ResponseBufferBudgetProbe,
    codings: &[&str],
    body: &[u8],
) -> ChargedCodingChainOutcome {
    decode_with(budget, codings, body, LIMIT, LIMIT, RATIO)
}

/// Decode with explicit per-layer, cumulative, and amplification bounds.
fn decode_with(
    budget: &ResponseBufferBudgetProbe,
    codings: &[&str],
    body: &[u8],
    max_decoded: usize,
    max_cumulative: usize,
    ratio: u32,
) -> ChargedCodingChainOutcome {
    let owned: Vec<String> = codings.iter().map(|name| (*name).to_string()).collect();
    decode_charged_coding_chain_in(budget, &owned, body, max_decoded, max_cumulative, ratio)
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
    writer.write_all(data).expect("brotli write");
    drop(writer);
    out
}

fn document() -> Vec<u8> {
    br#"{"note":"ordinary upload","approved":true}"#.to_vec()
}

/// Comfortably more than any single decode below needs, so a refusal in these
/// tests can only be the decoder and never an accidentally tight budget.
fn generous_budget() -> ResponseBufferBudgetProbe {
    let scratch = blocks(RESPONSE_DECODE_BROTLI_SCRATCH_BYTES);
    probe(scratch + 2 * blocks(LIMIT) + 8)
}

#[test]
fn an_ordinary_gzip_upload_round_trips_and_releases_its_charge() {
    let plaintext = document();
    let budget = generous_budget();
    let total = budget.available_bytes();

    let outcome = decode(&budget, &["gzip"], &gzip(&plaintext));

    assert_eq!(outcome, ChargedCodingChainOutcome::Decoded(plaintext));
    assert_eq!(
        budget.available_bytes(),
        total,
        "the decode working set is released when the plaintext is handed back"
    );
}

#[test]
fn gzip_suffixes_are_refused_at_every_layer_and_release_the_charge() {
    let budget = generous_budget();
    let total = budget.available_bytes();

    for suffix in [
        vec![0],
        b"trailing bytes".to_vec(),
        gzip(b""),
        gzip(b"second member"),
    ] {
        let mut encoded = gzip(&document());
        encoded.extend_from_slice(&suffix);
        let wrapped = gzip(&encoded);

        for (codings, body) in [
            (vec!["gzip"], encoded.as_slice()),
            (vec!["x-gzip"], encoded.as_slice()),
            (vec!["gzip", "gzip"], wrapped.as_slice()),
        ] {
            assert_eq!(
                decode(&budget, &codings, body),
                ChargedCodingChainOutcome::Malformed
            );
            assert_eq!(
                budget.available_bytes(),
                total,
                "a gzip suffix rejection must release scratch and output charges"
            );
        }
    }
}

#[test]
fn an_ordinary_brotli_upload_round_trips_and_releases_its_charge() {
    let plaintext = document();
    let budget = generous_budget();
    let total = budget.available_bytes();

    let outcome = decode(&budget, &["br"], &brotli(&plaintext));

    assert_eq!(outcome, ChargedCodingChainOutcome::Decoded(plaintext));
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn a_stacked_chain_is_undone_in_reverse_application_order() {
    // `Content-Encoding: gzip, br` means gzip was applied first and br second,
    // so br is removed first. Encoding in that order and asserting the exact
    // plaintext is what proves the direction, not just that "something decoded".
    let plaintext = document();
    let encoded = brotli(&gzip(&plaintext));
    let budget = generous_budget();
    let total = budget.available_bytes();

    let outcome = decode(&budget, &["gzip", "br"], &encoded);

    assert_eq!(outcome, ChargedCodingChainOutcome::Decoded(plaintext));
    assert_eq!(
        budget.available_bytes(),
        total,
        "both passes release, including the peak where two buffers are resident"
    );
}

#[test]
fn large_window_brotli_is_refused_as_a_representation_fault() {
    // Six header bits ask a permissive Brotli state for a ring buffer bounded by
    // 1 GiB rather than 16 MiB, for a coding no client negotiated (RFC 7932 caps
    // the `br` window at 24 bits). The strict decoder must treat the marker as a
    // format error — and must do so while the budget could comfortably afford an
    // ordinary `br` decode, so this can only be strictness and never capacity.
    const LWB_MARKER_BODY: [u8; 8] = [0x11, 0x1e, 0, 0, 0, 0, 0, 0];
    let budget = generous_budget();
    let total = budget.available_bytes();

    let outcome = decode(&budget, &["br"], &LWB_MARKER_BODY);

    assert_eq!(outcome, ChargedCodingChainOutcome::Malformed);
    assert_eq!(
        budget.available_bytes(),
        total,
        "a refused decode costs the budget nothing"
    );
}

#[test]
fn a_budget_that_cannot_cover_the_brotli_scratch_refuses_before_construction() {
    // The `br` decoder's heap is reserved BEFORE the decoder exists, so a budget
    // one block short of it must refuse without decoding — the whole point of
    // charging the codec's own working set rather than only its output.
    let encoded = brotli(&document());
    let budget = probe(blocks(RESPONSE_DECODE_BROTLI_SCRATCH_BYTES) - 1);
    let total = budget.available_bytes();

    let outcome = decode(&budget, &["br"], &encoded);

    assert_eq!(outcome, ChargedCodingChainOutcome::CapacityRefused);
    assert_eq!(
        budget.available_bytes(),
        total,
        "nothing is held after a capacity refusal"
    );
}

#[test]
fn a_budget_that_covers_the_scratch_but_not_the_output_still_refuses() {
    // Scratch alone is not admission: the output buffer's growth is reserved
    // before each allocation too, so a budget sized to the codec heap plus one
    // block must refuse rather than allocate an uncharged output.
    let plaintext = vec![b'a'; 512 * 1024];
    let encoded = gzip(&plaintext);
    let capacity = projected_decode_output_capacity_for_test(plaintext.len(), LIMIT);
    assert!(
        capacity > UNIT,
        "the fixture must need more than one reservation block"
    );
    let budget = probe(blocks(RESPONSE_DECODE_GZIP_SCRATCH_BYTES) + 1);
    let total = budget.available_bytes();

    let outcome = decode(&budget, &["gzip"], &encoded);

    assert_eq!(outcome, ChargedCodingChainOutcome::CapacityRefused);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn a_coding_the_strict_decoder_does_not_implement_is_refused() {
    let budget = generous_budget();
    let outcome = decode(&budget, &["deflate"], b"anything");
    assert_eq!(outcome, ChargedCodingChainOutcome::Unsupported);
}

#[test]
fn a_truncated_stream_is_a_representation_fault_not_a_silent_short_read() {
    let encoded = gzip(&document());
    let budget = generous_budget();
    let total = budget.available_bytes();

    let outcome = decode(&budget, &["gzip"], &encoded[..encoded.len() - 4]);

    assert_eq!(outcome, ChargedCodingChainOutcome::Malformed);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn the_per_layer_ceiling_still_binds() {
    let plaintext = vec![b'a'; 256 * 1024];
    let encoded = gzip(&plaintext);
    let budget = generous_budget();
    let total = budget.available_bytes();

    let outcome = decode_with(&budget, &["gzip"], &encoded, 4096, 4096, RATIO);

    assert_eq!(outcome, ChargedCodingChainOutcome::TooLarge);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn the_amplification_bound_still_binds() {
    let plaintext = vec![b'a'; 256 * 1024];
    let encoded = gzip(&plaintext);
    let budget = generous_budget();
    let total = budget.available_bytes();

    let outcome = decode_with(&budget, &["gzip"], &encoded, LIMIT, LIMIT, 2);

    assert_eq!(outcome, ChargedCodingChainOutcome::TooLarge);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn the_cumulative_ceiling_still_binds() {
    let plaintext = vec![b'a'; 256 * 1024];
    let encoded = gzip(&plaintext);
    let budget = generous_budget();
    let total = budget.available_bytes();

    let outcome = decode_with(&budget, &["gzip"], &encoded, LIMIT, 4096, RATIO);

    assert_eq!(outcome, ChargedCodingChainOutcome::TooLarge);
    assert_eq!(budget.available_bytes(), total);
}
