//! The one strict, budget-charged content-coding decoder both representation
//! gates use.
//!
//! [`crate::plugins::response_representation`] established this discipline for
//! buffered responses under `GHSA-pwcm-6rh8-f2gh`; the request gate
//! ([`crate::plugins::request_representation`], `GHSA-3973-47g5-4mcx`) decodes
//! attacker-supplied bytes for exactly the same reason and under exactly the
//! same threat. Two implementations of it would be two chances to get the
//! codec strictness or the charge ordering wrong, so the machinery lives here
//! once and each gate keeps only its own posture, reasons, and terminals.
//!
//! What "strict and charged" means, precisely:
//!
//! * **Strict codecs.** `br` is decoded through [`StrictBrotliReader`], which
//!   drives `BrotliState::new_strict` and therefore refuses Large Window
//!   Brotli. That refusal is what makes [`BROTLI_DECODER_SCRATCH_BYTES`] a real
//!   ceiling rather than a guess: the crate's own `brotli::Decompressor` sets
//!   `large_window = true`, so a handful of header bits can ask it for a 1 GiB
//!   ring buffer. RFC 7932 caps the `br` window at 24 bits, and a peer that
//!   named `br` has not agreed to anything larger. `gzip` is decoded through
//!   `flate2::bufread::GzDecoder`, whose DEFLATE window RFC 1951 fixes at
//!   32 KiB. Each gzip coding must contain exactly one complete member; any
//!   remaining bytes, including another valid member, are rejected. Request
//!   normalization and both representation gates share this rule.
//! * **Charged before allocation.** Every growth of the output buffer is
//!   reserved against an aggregate budget BEFORE the allocator is asked for it,
//!   and topped up to the capacity the allocator actually returned. The active
//!   decoder's own heap ceiling is reserved BEFORE the decoder is constructed,
//!   because the first read allocates that working set from the stream header
//!   before a single output byte exists. A stacked coding list holds one pass's
//!   input and the next pass's output at once, so the caller passes the
//!   still-resident `concurrent_bytes` and the peak is what stays charged.
//!   What is charged here is the DECODE's own working set. The first pass's
//!   INPUT — the encoded bytes handed in — is owned and already bounded by the
//!   caller's collection limit, but whether it additionally holds a budget
//!   charge is gate-specific: a buffered response's wire bytes carry their
//!   retained-body charge, while a request's wire bytes are bounded per request
//!   and are not charged to `FERRUM_REQUEST_DECODE_MAX_TOTAL_BYTES`. Neither
//!   gate may therefore treat its input as a substitute for reserving the
//!   output.
//!
//! Nothing here decides a posture. A refusal is reported as a
//! [`ChargedDecodeError`] and each gate maps it onto its own client-visible
//! terminal: a representation rejection when the bytes are at fault, and a
//! gateway-local capacity terminal when only the budget is.

use std::io::Read;

use crate::proxy::response_buffer_budget::{
    BudgetRef, ResponseBufferReservation, prospective_retained_len,
};

/// Read granularity of a bounded decode, and the size of the fixed stack
/// scratch buffer one decode pass uses.
///
/// Small enough that the aggregate charge tracks the output allocation closely,
/// large enough that the per-chunk semaphore check is never the dominant cost of
/// a decode. This buffer lives on the stack, so it is not part of the process
/// heap the aggregate budget bounds; the decoder's own HEAP working set is a
/// separate, much larger cost and is charged — see [`SupportedCoding`].
const DECODE_CHUNK_BYTES: usize = 16 * 1024;

/// The growth target for a decode output buffer that currently holds
/// `current_capacity` bytes of capacity and is about to hold `filled` bytes,
/// under `limit`.
///
/// Factored out so the reservation, the allocation, and the external
/// test-support projection of a decode's peak
/// ([`projected_decode_output_capacity`]) cannot disagree about the growth rule.
/// Geometric, so a large body costs `O(log n)` reallocations rather than one per
/// chunk, and saturating so no hostile length can wrap the target down.
#[inline]
fn grown_decode_capacity(current_capacity: usize, filled: usize, limit: usize) -> usize {
    current_capacity
        .saturating_mul(2)
        .max(DECODE_CHUNK_BYTES)
        .min(limit)
        .max(filled)
}

/// The capacity [`read_decoded_bounded`] ends up holding for an output of
/// `decoded_len` bytes under `limit`, computed with the production growth rule.
///
/// External tests use this to derive a decode's exact budget bracket from the
/// actual encoded/intermediate lengths instead of hardcoding block counts, so a
/// change to the growth rule or to a codec's output size fails with a precise
/// arithmetic explanation rather than looking like a flaky budget assertion.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) fn projected_decode_output_capacity(decoded_len: usize, limit: usize) -> usize {
    let mut capacity = 0usize;
    let mut filled = 0usize;
    while filled < decoded_len {
        filled = prospective_retained_len(filled, DECODE_CHUNK_BYTES).min(decoded_len);
        if filled > capacity {
            capacity = grown_decode_capacity(capacity, filled, limit);
        }
    }
    capacity
}

/// Conservative ceiling on the heap ONE `gzip`/`x-gzip` pass allocates, for the
/// locked `flate2` 1.1.9 (`rust_backend`) → `miniz_oxide` 0.8.9 path.
///
/// Derivation, from the locked sources:
///
/// * `flate2::bufread::GzDecoder` reads the input slice directly, without an
///   additional `std::io::BufReader` allocation;
/// * `flate2`'s `Decompress` holds a boxed `miniz_oxide` `InflateState`
///   (`flate2` `src/ffi/miniz_oxide.rs`). `InflateState` is
///   dominated by `dict: [u8; TINFL_LZ_DICT_SIZE]` = 32 KiB plus a
///   `DecompressorOxide` whose three `HuffmanTable`s are
///   `[i16; 1024] + [i16; 576]` = 3,200 B each (`miniz_oxide`
///   `src/inflate/core.rs`), i.e. well under 16 KiB of tables and scalars.
///
/// That is on the order of 48 KiB. DEFLATE's window is fixed at 32 KiB by
/// RFC 1951, so nothing in the stream can enlarge it. `256 KiB` is a >5x
/// margin for allocator overhead and for a future `miniz_oxide` that grows its
/// state, and is still small enough that gzip decodes are not rationed.
pub(crate) const GZIP_DECODER_SCRATCH_BYTES: usize = 256 * 1024;

/// Conservative ceiling on the heap ONE `br` pass allocates, for the locked
/// `brotli` 8.0.2 → `brotli-decompressor` 5.0.0 path under
/// [`StrictBrotliReader`] (`BrotliState::new_strict`, `StandardAlloc`).
///
/// Derivation, from `brotli-decompressor` `src/decode.rs`, `src/state.rs`, and
/// `src/huffman/mod.rs`, with `HuffmanCode` = `#[repr(C)] { u16, u8 }` = 4 B:
///
/// | allocation | bound | bytes |
/// | --- | --- | --- |
/// | ring buffer | `(1 << window_bits) + 42 + 24`, `window_bits <= 24` | 16,777,282 |
/// | three Huffman tree groups | `256 * (4 + 1080 * 4)` each | 3,320,832 |
/// | block-type + block-length trees | `2 * 3 * 1080 * 4` | 25,920 |
/// | context-map table | `1080 * 4` | 4,320 |
/// | literal + distance context maps | `(256 << 6) + (256 << 2)` | 17,408 |
/// | context modes | `256` | 256 |
/// | **total** | | **20,146,018** |
///
/// Every count is a format bound, not an observation: `num_block_types` and
/// `num_htrees` are `DecodeVarLenUint8() + 1`, and that decoder yields at most
/// `(1 << 7) + 127 = 255`, so 256 is the ceiling for all of them.
///
/// **Why `window_bits <= 24`.** `DecodeWindowBits` only reaches the Large Window
/// Brotli branch — 6 further bits, `window_bits` up to `kBrotliLargeMaxWbits`
/// = 30, i.e. a **1 GiB** ring buffer — when the state was created with
/// `large_window = true`. The crate's own `brotli::Decompressor` does exactly
/// that (`BrotliState::new_with_custom_dictionary` sets `large_window = true`),
/// which is why neither gate uses it: LWB is not `Content-Encoding: br`
/// (RFC 7932 caps the window at 24 bits and a peer advertising `br` has not
/// agreed to anything larger), so admitting it would be an unbounded allocation
/// for a coding nobody negotiated. [`StrictBrotliReader`] uses
/// `BrotliState::new_strict`, which pins `large_window = false`, so the LWB
/// branch is a format error and the ring buffer is capped at `1 << 24`.
///
/// `24 MiB` rounds 20,146,018 B up with ~4 MiB of margin for allocator overhead
/// across the ~10 allocations above.
pub(crate) const BROTLI_DECODER_SCRATCH_BYTES: usize = 24 * 1024 * 1024;

/// A content coding both gates can decode, and the heap its decoder needs.
///
/// # Why the codec's own heap is charged
///
/// The output buffer is not the whole resident cost of a decode. Both supported
/// decoders allocate a working set on the FIRST read — before a single output
/// byte exists, so before any output-growth reservation can have happened — and
/// that working set is chosen by the attacker-supplied stream header, not by the
/// gateway. Leaving it out would mean the aggregate budget bounds something
/// strictly smaller than what concurrent decodes actually hold. So the ceilings
/// above are reserved BEFORE the decoder is constructed, and a decode that
/// cannot reserve them is refused.
///
/// They are conservative fixed ceilings rather than a budget-aware allocator:
/// both codecs' allocations are bounded by format constants, so a ceiling is
/// provable by inspection and costs nothing on the decode path. They are
/// deliberately over-estimates for a typical stream — a real `br` body uses a
/// 4 MiB window, not the 16 MiB maximum — which is the safe direction.
#[derive(Clone, Copy)]
pub(crate) enum SupportedCoding {
    Gzip,
    Brotli,
}

impl SupportedCoding {
    /// The canonical lowercase tokens this decoder accepts. `x-gzip` is the
    /// RFC 9110 deprecated alias for `gzip`.
    pub(crate) fn from_token(coding: &str) -> Option<Self> {
        match coding {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "br" => Some(Self::Brotli),
            _ => None,
        }
    }

    /// The decoder heap this coding may allocate for one pass.
    pub(crate) fn scratch_bytes(self) -> usize {
        match self {
            Self::Gzip => GZIP_DECODER_SCRATCH_BYTES,
            Self::Brotli => BROTLI_DECODER_SCRATCH_BYTES,
        }
    }
}

/// Why a charged decode did not produce plaintext.
///
/// Deliberately not a client-visible terminal. Each gate maps these onto its own
/// vocabulary, because the two directions blame different parties and reach the
/// client through different transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChargedDecodeError {
    /// A coding token this decoder does not implement.
    Unsupported,
    /// A supported coding whose stream is malformed, truncated, Large Window
    /// Brotli, or followed by trailing bytes (including another gzip member).
    Malformed,
    /// The decode would have produced more than the caller's ceiling.
    TooLarge,
    /// The aggregate budget could not admit the decoder heap or the output
    /// allocation. Nothing is wrong with the bytes; the gateway is out of
    /// capacity, and every block this attempt had taken is released with the
    /// reservation on the way out.
    CapacityRefused,
}

/// A `br` reader that refuses Large Window Brotli, so its ring buffer is bounded
/// by `1 << 24` and [`BROTLI_DECODER_SCRATCH_BYTES`] is a real ceiling.
///
/// `brotli::Decompressor` cannot be used for this: it builds its state through
/// `BrotliState::new_with_custom_dictionary`, which sets `large_window = true`,
/// so a handful of header bits can ask it for a 1 GiB ring buffer. This drives
/// the same `BrotliDecompressStream` state machine with `BrotliState::new_strict`
/// instead, which pins `large_window = false` and makes that header a format
/// error.
///
/// Feeding the whole encoded body in at once (it is already resident, owned by
/// the caller and bounded by its collection limit) also removes the decoder's
/// own input buffer and makes the
/// failure classification exact: with no more input to come, `NeedsMoreInput`
/// can only mean a truncated stream.
pub(crate) struct StrictBrotliReader<'a> {
    input: &'a [u8],
    input_offset: usize,
    total_out: usize,
    state: brotli::BrotliState<
        brotli::reader::StandardAlloc,
        brotli::reader::StandardAlloc,
        brotli::reader::StandardAlloc,
    >,
    done: bool,
}

impl<'a> StrictBrotliReader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            input_offset: 0,
            total_out: 0,
            state: brotli::BrotliState::new_strict(
                brotli::reader::StandardAlloc::default(),
                brotli::reader::StandardAlloc::default(),
                brotli::reader::StandardAlloc::default(),
            ),
            done: false,
        }
    }

    /// The one error this reader reports. Callers map every read failure to
    /// [`ChargedDecodeError::Malformed`], so the kind carries no message
    /// content and nothing is logged from here.
    fn malformed() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid brotli stream")
    }
}

impl Read for StrictBrotliReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        let mut available_in = match self.input.len().checked_sub(self.input_offset) {
            Some(len) => len,
            None => return Err(Self::malformed()),
        };
        let mut available_out = buf.len();
        let mut output_offset = 0usize;
        match brotli::BrotliDecompressStream(
            &mut available_in,
            &mut self.input_offset,
            self.input,
            &mut available_out,
            &mut output_offset,
            buf,
            &mut self.total_out,
            &mut self.state,
        ) {
            brotli::BrotliResult::ResultSuccess => {
                self.done = true;
                // Trailing bytes after a complete stream are not a `br`
                // representation, and these gates decide what a policy is
                // enforced over, so they are rejected rather than ignored — the
                // same strictness the gzip path already applies to padding after
                // the final member.
                if available_in != 0 {
                    return Err(Self::malformed());
                }
                Ok(output_offset)
            }
            brotli::BrotliResult::NeedsMoreOutput => {
                if output_offset == 0 {
                    // The decoder asked for room it was already given, so it
                    // cannot make progress; refusing beats looping.
                    return Err(Self::malformed());
                }
                Ok(output_offset)
            }
            // The whole body was handed over up front, so there is no more
            // input: the stream is truncated.
            brotli::BrotliResult::NeedsMoreInput | brotli::BrotliResult::ResultFailure => {
                Err(Self::malformed())
            }
        }
    }
}

/// Read a bounded decoder's output, charging the aggregate budget BEFORE every
/// growth of the output allocation.
///
/// `concurrent_bytes` is what the caller is holding resident alongside this
/// output for the duration of the pass — the previous pass's decoded buffer on a
/// stacked `Content-Encoding`, and zero on the first pass, which reads straight
/// from wire bytes this decoder does not own. Those bytes are bounded by the
/// caller's collection limit; whether they ALSO hold a charge is gate-specific
/// (a buffered response's do, a request's do not), so this accounting never
/// leans on them. Charging `concurrent_bytes + capacity`
/// is what keeps a stacked decode from escaping the aggregate bound in the
/// window where both allocations exist. The active decoder's own heap is charged
/// separately by [`decode_one_coding`], so the semaphore sees scratch + input +
/// output at once and a large output cannot hide behind an earlier scratch
/// charge.
///
/// The charge is against the buffer's CAPACITY rather than its length, because
/// capacity is what is resident — and against the capacity the allocator
/// actually returned, not merely the one that was requested: `Vec` promises at
/// least what was asked for, so the reservation is topped up immediately after
/// each allocation and the buffer is dropped if that top-up is refused.
fn read_decoded_bounded(
    mut reader: impl Read,
    limit: usize,
    concurrent_bytes: usize,
    reservation: &mut ResponseBufferReservation,
    budget: BudgetRef<'_>,
) -> Result<Vec<u8>, ChargedDecodeError> {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; DECODE_CHUNK_BYTES];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|_| ChargedDecodeError::Malformed)?;
        if read == 0 {
            break;
        }
        let filled = prospective_retained_len(out.len(), read);
        if filled > limit {
            return Err(ChargedDecodeError::TooLarge);
        }
        if filled > out.capacity() {
            let grown = grown_decode_capacity(out.capacity(), filled, limit);
            if !reservation.reserve_in(budget, prospective_retained_len(concurrent_bytes, grown)) {
                return Err(ChargedDecodeError::CapacityRefused);
            }
            out.reserve_exact(grown - out.len());
            // `reserve_exact` guarantees AT LEAST `grown`, so the allocation
            // that just happened may be larger than what was reserved for it.
            // Charge the difference now; returning here drops `out`, so a
            // refusal frees the over-large buffer instead of publishing it.
            let allocated = prospective_retained_len(concurrent_bytes, out.capacity());
            if !reservation.reserve_in(budget, allocated) {
                return Err(ChargedDecodeError::CapacityRefused);
            }
        }
        out.extend_from_slice(&chunk[..read]);
    }
    Ok(out)
}

/// Decode one supported content coding, bounded by `limit` and by the aggregate
/// budget `budget` names.
///
/// The reader is capped one byte past the limit so an output that lands exactly
/// on the ceiling is distinguishable from one that was truncated by it.
///
/// The decoder's own heap working set ([`SupportedCoding::scratch_bytes`]) is
/// reserved BEFORE the decoder is constructed, because the first read can
/// allocate it before a single output byte exists. That reservation is separate
/// from `reservation` and lives exactly as long as this pass: only one decoder
/// is active at a time across a stacked `Content-Encoding`, so the scratch is
/// returned as soon as the pass ends while the decoded buffers it produced stay
/// charged.
pub(crate) fn decode_one_coding(
    coding: &str,
    data: &[u8],
    limit: usize,
    concurrent_bytes: usize,
    reservation: &mut ResponseBufferReservation,
    budget: BudgetRef<'_>,
) -> Result<Vec<u8>, ChargedDecodeError> {
    let Some(coding) = SupportedCoding::from_token(coding) else {
        return Err(ChargedDecodeError::Unsupported);
    };
    let mut scratch = ResponseBufferReservation::new();
    if !scratch.reserve_in(budget, coding.scratch_bytes()) {
        return Err(ChargedDecodeError::CapacityRefused);
    }
    let take = limit as u64 + 1;
    // `scratch` is dropped on every exit from here — success, rejection, and
    // capacity refusal alike — which is what returns the codec's heap charge
    // before the next pass asks for its own.
    match coding {
        SupportedCoding::Gzip => {
            // BufRead over the slice leaves all bytes after the first member
            // visible, without read-ahead hiding a suffix in an internal buffer.
            let mut decoder = flate2::bufread::GzDecoder::new(data);
            let decoded = read_decoded_bounded(
                (&mut decoder).take(take),
                limit,
                concurrent_bytes,
                reservation,
                budget,
            )?;
            if !decoder.into_inner().is_empty() {
                return Err(ChargedDecodeError::Malformed);
            }
            Ok(decoded)
        }
        SupportedCoding::Brotli => read_decoded_bounded(
            StrictBrotliReader::new(data).take(take),
            limit,
            concurrent_bytes,
            reservation,
            budget,
        ),
    }
}

/// Whether `decoded_len` is within `ratio`:1 of `raw_len`.
///
/// Mirrors [`crate::plugins::utils::content_encoding`]'s amplification rule
/// exactly, including its two deliberate exemptions: a zero ratio disables the
/// check, and a zero-length input has no meaningful ratio (the absolute
/// ceilings still apply to both). An overflowing product means the absolute
/// ceiling is the binding bound, so the ratio abstains rather than wrapping
/// into a smaller one.
fn amplification_is_within_bounds(raw_len: usize, decoded_len: usize, ratio: u32) -> bool {
    if ratio == 0 || raw_len == 0 {
        return true;
    }
    match raw_len.checked_mul(ratio as usize) {
        Some(limit) => decoded_len <= limit,
        None => true,
    }
}

/// Decode an ordered `#content-coding` list into one plaintext buffer with the
/// strict codecs and the aggregate charge this module owns.
///
/// This is the charged counterpart of
/// [`crate::plugins::utils::content_encoding::decode_content_encoding`], for the
/// one caller that REWRITES the request rather than merely inspecting it:
/// `compression`'s opt-in `decompress_request` normalizer
/// (`GHSA-q76p-952x-7c3v`). That normalizer decodes unauthenticated upload bytes
/// on the request path, so it needs exactly what the representation gates need —
/// Large-Window-refusing `br`, and every byte of the decode's working set
/// reserved against `FERRUM_REQUEST_DECODE_MAX_TOTAL_BYTES` BEFORE it is
/// allocated:
///
/// * the ACTIVE decoder's own heap ceiling, charged before the decoder is
///   constructed (a `br` decoder sizes its ring buffer from the stream header
///   before it emits one output byte);
/// * every growth of the output buffer, topped up to the capacity the allocator
///   actually returned;
/// * on a stacked list, the previous pass's still-resident buffer concurrently
///   with the next pass's output.
///
/// `codings` are canonical lowercase tokens in APPLICATION order (the order the
/// field lists them); they are undone in reverse. The caller has already parsed
/// the field, bounded the layer COUNT, and resolved `identity`, so an
/// `identity` member here is an unsupported coding rather than a no-op.
///
/// The charge is released when this returns: the reservation is local and the
/// plaintext is handed back as a plain `Vec`. That is the DECODE working set
/// bound the advisory names — the surviving plaintext is separately bounded per
/// request by `max_decompressed_request_size` and the wire body limit, and the
/// buffered-request budget charges the body the caller publishes.
pub(crate) fn decode_charged_content_coding_chain(
    codings: &[String],
    body: &[u8],
    limits: crate::plugins::utils::content_encoding::DecodeLimits,
    budget: BudgetRef<'_>,
) -> Result<Vec<u8>, ChargedDecodeError> {
    if codings.is_empty() {
        // The caller resolved `identity`-only lists before reaching here, so an
        // empty list means the parse and this decode disagreed. Fail closed.
        return Err(ChargedDecodeError::Malformed);
    }

    let ratio = limits.max_amplification_ratio;
    let mut reservation = ResponseBufferReservation::new();
    let mut current: Option<Vec<u8>> = None;
    let mut cumulative = 0usize;
    for coding in codings.iter().rev() {
        // The previous pass's buffer is this pass's input and stays resident for
        // the whole of it, so it is charged concurrently with this pass's
        // output. The FIRST pass reads straight out of the caller's wire bytes,
        // which this decode does not own.
        let (input, concurrent) = match current.as_ref() {
            Some(previous) => (previous.as_slice(), previous.capacity()),
            None => (body, 0),
        };
        let input_len = input.len();
        let decoded = decode_one_coding(
            coding,
            input,
            limits.max_decoded_bytes,
            concurrent,
            &mut reservation,
            budget,
        )?;
        if !amplification_is_within_bounds(input_len, decoded.len(), ratio) {
            return Err(ChargedDecodeError::TooLarge);
        }
        cumulative = prospective_retained_len(cumulative, decoded.len());
        if cumulative > limits.max_cumulative_bytes {
            return Err(ChargedDecodeError::TooLarge);
        }
        current = Some(decoded);
    }

    let Some(plaintext) = current else {
        // Unreachable: the list is non-empty and every pass assigns.
        return Err(ChargedDecodeError::Malformed);
    };
    // End-to-end amplification against the ORIGINAL coded body, which a
    // per-layer check alone does not bound for a stacked chain.
    if !amplification_is_within_bounds(body.len(), plaintext.len(), ratio) {
        return Err(ChargedDecodeError::TooLarge);
    }
    Ok(plaintext)
}
