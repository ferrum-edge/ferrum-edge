//! Thread-local fast non-cryptographic ID generation for request tracing and
//! correlation identifiers (`correlation_id`, `otel_tracing`,
//! `mesh/workload_metrics`).
//!
//! W3C Trace Context trace/span IDs and `X-Request-ID` correlation tokens are
//! uniqueness identifiers for distributed observability rather than
//! cryptographic secrets. Seeding a per-thread `xoshiro256++` generator once
//! from 256 bits of OS CSPRNG entropy (`Uuid::new_v4()`) eliminates 1–3
//! `getrandom(2)` syscalls on every request while preserving uniform random
//! distribution, RFC 4122 UUIDv4 framing, and non-zero W3C trace/span IDs.

use std::cell::Cell;
use uuid::Uuid;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

struct Xoshiro256PlusPlus {
    s: [u64; 4],
}

impl Xoshiro256PlusPlus {
    fn seed_from_os() -> Self {
        let a = *Uuid::new_v4().as_bytes();
        let b = *Uuid::new_v4().as_bytes();
        let mut s = [
            u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]),
            u64::from_le_bytes([a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]]),
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        ];
        if s == [0, 0, 0, 0] {
            s[0] = 0x9e37_79b9_7f4a_7c15;
        }
        Self { s }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let result = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);

        let t = self.s[1] << 17;

        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];

        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);

        result
    }
}

thread_local! {
    static THREAD_RNG: Cell<Option<Xoshiro256PlusPlus>> = const { Cell::new(None) };
}

#[inline]
fn with_rng<R>(f: impl FnOnce(&mut Xoshiro256PlusPlus) -> R) -> R {
    THREAD_RNG.with(|cell| {
        let mut rng = cell.take().unwrap_or_else(Xoshiro256PlusPlus::seed_from_os);
        let out = f(&mut rng);
        cell.set(Some(rng));
        out
    })
}

/// Generate an RFC 4122 version-4 UUID formatted as a 36-byte lowercase
/// hyphenated string without hitting the OS CSPRNG per call.
#[inline]
pub fn fast_uuid_v4_string() -> String {
    let (hi, lo) = with_rng(|rng| (rng.next_u64(), rng.next_u64()));
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&hi.to_le_bytes());
    bytes[8..].copy_from_slice(&lo.to_le_bytes());
    // RFC 4122 §4.4: version 4 (random) and variant 1 (10xxxxxx).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut buf = [0u8; 36];
    Uuid::from_bytes(bytes)
        .hyphenated()
        .encode_lower(&mut buf)
        .to_owned()
}

/// Generate a non-zero 128-bit W3C Trace Context trace ID.
#[inline]
pub fn fast_trace_id_bytes() -> [u8; 16] {
    with_rng(|rng| {
        loop {
            let hi = rng.next_u64();
            let lo = rng.next_u64();
            if hi != 0 || lo != 0 {
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&hi.to_le_bytes());
                bytes[8..].copy_from_slice(&lo.to_le_bytes());
                return bytes;
            }
        }
    })
}

/// Generate a non-zero 64-bit W3C Trace Context span ID.
#[inline]
pub fn fast_span_id_bytes() -> [u8; 8] {
    with_rng(|rng| {
        loop {
            let v = rng.next_u64();
            if v != 0 {
                return v.to_le_bytes();
            }
        }
    })
}

/// Encode `bytes` as lowercase hex into a stack buffer and return a `String`.
#[inline]
pub fn encode_hex_lower_16(bytes: &[u8; 16]) -> String {
    let mut out = [0u8; 32];
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX_LOWER[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_LOWER[(b & 0x0f) as usize];
    }
    // `HEX_LOWER` contains exclusively ASCII bytes.
    String::from_utf8(out.to_vec()).unwrap_or_default()
}

/// Encode `bytes` as lowercase hex into a stack buffer and return a `String`.
#[inline]
pub fn encode_hex_lower_8(bytes: &[u8; 8]) -> String {
    let mut out = [0u8; 16];
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX_LOWER[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_LOWER[(b & 0x0f) as usize];
    }
    // `HEX_LOWER` contains exclusively ASCII bytes.
    String::from_utf8(out.to_vec()).unwrap_or_default()
}

/// Generate a 32-char lowercase hex W3C Trace Context trace ID.
#[inline]
pub fn fast_trace_id_hex() -> String {
    encode_hex_lower_16(&fast_trace_id_bytes())
}

/// Generate a 16-char lowercase hex W3C Trace Context span ID.
#[inline]
pub fn fast_span_id_hex() -> String {
    encode_hex_lower_8(&fast_span_id_bytes())
}

/// Generate a uniform random `f64` in `[0.0, 1.0)` from 53 random bits using
/// the per-thread OS-seeded PRNG (zero syscalls on the hot path).
#[inline]
pub fn fast_unit_f64() -> f64 {
    let bits = with_rng(Xoshiro256PlusPlus::next_u64) >> 11;
    (bits as f64) * (1.0 / ((1u64 << 53) as f64))
}
