//! Per-direction traffic-key confidentiality budget for kTLS sessions
//! (issue #3619).
//!
//! # Why this module exists
//!
//! rustls normally counts the messages each traffic key has protected and
//! refuses to keep going once the negotiated suite's
//! `CipherSuiteCommon::confidentiality_limit` is reached. Handing the keys to
//! the kernel with `dangerous_into_kernel_connection` ends that: the rustls
//! `kernel` module states plainly that a `KernelConnection` "has no way to
//! track this" and that tracking approximately how many messages have been
//! sent — and aborting before the limit — becomes the caller's job.
//!
//! In the pinned providers (`rustls 0.23.45`, aws-lc-rs and ring alike) the
//! TLS 1.2 AES-GCM suites carry `confidentiality_limit: 1 << 24` and
//! ChaCha20-Poly1305 carries `u64::MAX`. So an AES-GCM kTLS session must be
//! torn down before 2^24 records in **either** direction, while ChaCha keeps
//! its genuinely unlimited posture and pays nothing here.
//!
//! # Why plaintext byte counters are not a record bound
//!
//! A peer chooses its own record sizing. A hostile client can emit minimum- or
//! zero-length records, so "bytes relayed / 2^14" understates the record count
//! by an unbounded factor. The only trustworthy record counter is the kernel's
//! own: the TLS ULP keeps the live per-direction record sequence number in
//! `cipher_context.rec_seq` and returns it from
//! `getsockopt(SOL_TLS, TLS_TX | TLS_RX)`, already including whatever the
//! handshake consumed before handoff. [`crate::socket_opts::ktls::read_ktls_record_seq`]
//! reads and validates that value; this module decides when to read it and what
//! it means.
//!
//! # Why polling it is not a per-byte syscall
//!
//! Reading the counter before every relayed byte would be absurd, and reading
//! it once per `splice(2)` would still add a syscall to the hot path. Instead
//! the guard runs a **pre-charged watchdog**: before every relay syscall it
//! reserves that syscall's *pessimistic upper bound* on records out of the
//! remaining budget, and only when the reservation no longer fits does it pay
//! for a fresh kernel observation. Because the reservation happens **before**
//! the syscall, the true sequence number can never pass the threshold between
//! two observations:
//!
//! > `true_seq ≤ observed_seq + (charges since the observation) ≤ threshold`
//!
//! The two bounds are:
//!
//! * **Transmit** — [`transmit_record_bound`]. The kernel packs a write into
//!   at most `ceil(bytes / 2^14)` full records, plus one for a record left
//!   partially filled by an earlier write.
//! * **Receive** — [`receive_record_bound`]. One non-blocking receive can only
//!   consume records the kernel has already queued, and queued data is capped
//!   by the socket receive buffer, so the record count is capped by
//!   `receive-ceiling / minimum-record-wire-size`.
//!
//! With a multi-megabyte ceiling that is roughly one `getsockopt` per few dozen
//! splice calls, and with a quiet socket it is one per several hundred
//! megabytes.
//!
//! # Why finite-limit suites never reach the kernel
//!
//! The receive bound is only as good as the claim "the kernel cannot hold more
//! than this". Linux offers no race-free way to establish that claim after
//! accept: a live `SO_RCVBUF` reading moves with TCP receive autotuning, and
//! data admitted before any `SO_RCVBUF` pin cannot be measured afterwards
//! because `FIONREAD` omits out-of-order skbs. So instead of estimating a
//! ceiling, `proxy::ktls_accept` removes every finite-limit (AES-GCM) suite
//! from the kTLS ClientHello eligibility check before the handshake consumes
//! the socket; those connections stay on the buffered userspace rustls relay.
//! Only ChaCha20-Poly1305, whose limit is unlimited, is handed off, so
//! [`KtlsConfidentialityPolicy::stable_receive_ceiling`] is `0` for every
//! session that reaches the kernel and the handoff re-checks, against the
//! suite rustls actually negotiated, that no enforcement-requiring suite got
//! through. Do not restore AES-GCM handoff with `FIONREAD`, `SO_RCVBUF`,
//! `tcp_rmem`, `/proc`, or another userspace queue sample
//! (`.claude/rules/ktls.md`).
//!
//! The receive and transmit guard arithmetic below stays exact and tested so
//! the refusal is restated, not assumed, wherever a guard could be built.
//!
//! # Fail closed
//!
//! Every uncertainty ends the relay rather than relaxing the bound: an
//! unreadable or malformed kernel counter ([`KtlsConfidentialityError::Unobservable`]),
//! a counter that moves backwards ([`KtlsConfidentialityError::NonMonotonic`]),
//! a single observation window that cannot be proven to fit in the remaining
//! budget ([`KtlsConfidentialityError::WindowExceedsBudget`]), and of course
//! reaching the threshold itself ([`KtlsConfidentialityError::LimitReached`]).
//! Ciphers whose limit is enforceable are additionally refused *before the
//! handshake is consumed*, preserving the userspace rustls fallback — see
//! `proxy::ktls_accept`.

use crate::socket_opts::ktls::KtlsCipher;

/// Records held back below the negotiated suite's confidentiality limit.
///
/// The pre-charge discipline already keeps the true sequence number at or
/// below the threshold, so this is pure headroom: it absorbs the handful of
/// records teardown may still emit (the `close_notify` alert) and any kernel
/// accounting subtlety, at a cost of 0.4% of an AES-GCM budget.
pub const KTLS_CONFIDENTIALITY_RESERVE_RECORDS: u64 = 1 << 16;

/// Largest `TLSPlaintext.length` (2^14) — the record granularity the kernel
/// packs transmitted plaintext into.
pub const MAX_TLS_PLAINTEXT_BYTES: u64 = 16_384;

/// Fewest wire bytes a TLS 1.2 AEAD record can occupy: a 5-byte record header,
/// the 8-byte explicit nonce, and the 16-byte AEAD tag, with an empty payload.
///
/// This is what makes a receive-side record count boundable at all: a peer may
/// choose the payload size, but it cannot make a record cheaper than this on
/// the wire, and the kernel cannot hold more unread wire bytes than the socket
/// receive buffer allows.
///
/// It is an **AES-GCM** figure, and deliberately so: AES-GCM is the only family
/// with a finite confidentiality limit, and only a finite-limit suite ever
/// consults a receive-record bound. ChaCha20-Poly1305 carries no explicit
/// nonce, so its minimum record is 21 wire bytes — using this constant for it
/// would under-count records. That is safe today only because an unlimited
/// suite builds no guard at all; a future finite-limit non-AES suite must bring
/// its own per-cipher minimum rather than reuse this one.
pub const MIN_TLS12_AEAD_RECORD_WIRE_BYTES: u64 = 29;

/// Which traffic key a budget belongs to.
///
/// The two directions have independent keys and independent record sequence
/// numbers, so they get independent budgets — and, because each relay
/// direction owns its own guard, no lock is shared between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtlsDirection {
    /// Gateway → client: records the kernel encrypts on write.
    Transmit,
    /// Client → gateway: records the kernel decrypts on read.
    Receive,
}

impl KtlsDirection {
    /// Stable label for logs and error text.
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            KtlsDirection::Transmit => "transmit",
            KtlsDirection::Receive => "receive",
        }
    }

    /// Whether this direction maps to the kernel's `TLS_TX` option.
    #[inline]
    pub fn is_transmit(self) -> bool {
        matches!(self, KtlsDirection::Transmit)
    }
}

impl std::fmt::Display for KtlsDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a kTLS relay direction must stop.
///
/// Every variant is terminal. None of them may be downgraded to a warning:
/// continuing past any of them means relaying records this process cannot
/// prove are still inside the cipher's confidentiality bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KtlsConfidentialityError {
    /// The traffic key has protected as many records as it safely can.
    LimitReached {
        /// Direction whose budget ran out.
        direction: KtlsDirection,
        /// Kernel record sequence number at the refusal.
        observed: u64,
        /// Sequence number at which relaying stops.
        threshold: u64,
    },
    /// The kernel record sequence number moved backwards, so it cannot be
    /// trusted as a monotonic message counter.
    NonMonotonic {
        /// Direction whose counter regressed.
        direction: KtlsDirection,
        /// Previously observed value.
        previous: u64,
        /// Value just read.
        observed: u64,
    },
    /// The counter could not be read, or did not match the layout/version/
    /// cipher this session installed.
    Unobservable {
        /// Direction that could not be observed.
        direction: KtlsDirection,
        /// Kernel or validation detail.
        detail: String,
    },
    /// One observation window's pessimistic record bound does not fit in the
    /// remaining budget, so no further syscall can be proven safe.
    WindowExceedsBudget {
        /// Direction that could not be charged.
        direction: KtlsDirection,
        /// Records the next syscall could consume in the worst case.
        step_records: u64,
        /// Records left below the threshold.
        remaining: u64,
    },
}

impl std::fmt::Display for KtlsConfidentialityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KtlsConfidentialityError::LimitReached {
                direction,
                observed,
                threshold,
            } => write!(
                f,
                "kTLS {direction} side: cipher confidentiality limit reached \
                 (record {observed} of {threshold}); ending the connection so the \
                 traffic key is not used beyond its safe bound"
            ),
            KtlsConfidentialityError::NonMonotonic {
                direction,
                previous,
                observed,
            } => write!(
                f,
                "kTLS {direction} side: kernel record sequence went backwards \
                 ({previous} then {observed}); the confidentiality budget cannot be trusted"
            ),
            KtlsConfidentialityError::Unobservable { direction, detail } => write!(
                f,
                "kTLS {direction} side: kernel record sequence is unreadable ({detail}); \
                 the confidentiality budget cannot be enforced"
            ),
            KtlsConfidentialityError::WindowExceedsBudget {
                direction,
                step_records,
                remaining,
            } => write!(
                f,
                "kTLS {direction} side: next relay step could consume {step_records} records \
                 but only {remaining} remain below the confidentiality limit"
            ),
        }
    }
}

impl std::error::Error for KtlsConfidentialityError {}

/// Upper bound on the records one write of `bytes` plaintext can produce.
///
/// The kernel fills a record to `MAX_TLS_PLAINTEXT_BYTES` before emitting it,
/// so `bytes` produce at most `ceil(bytes / 2^14)` records — plus one, because
/// this write may also complete a record an earlier write left partially
/// filled.
#[inline]
pub fn transmit_record_bound(bytes: u64) -> u64 {
    bytes.div_ceil(MAX_TLS_PLAINTEXT_BYTES).saturating_add(1)
}

/// Upper bound on the records one non-blocking receive can consume.
///
/// A receive only sees records the kernel already holds, and what it holds is
/// capped by the session's receive ceiling
/// ([`KtlsConfidentialityPolicy::stable_receive_ceiling`]). Every record costs at least
/// [`MIN_TLS12_AEAD_RECORD_WIRE_BYTES`] there, so the count cannot exceed
/// `ceiling / 29`. The `+ 1` covers a record straddling the accounting edge.
#[inline]
pub fn receive_record_bound(receive_ceiling_bytes: u64) -> u64 {
    receive_ceiling_bytes
        .div_ceil(MIN_TLS12_AEAD_RECORD_WIRE_BYTES)
        .saturating_add(1)
}

/// One reading of a direction's kernel record sequence number.
///
/// An observation carries the sequence number and nothing else, deliberately.
/// The per-syscall record bound is fixed at handoff from the session's receive
/// ceiling, so there is no field here through which a later reading could
/// widen the window — which is exactly the hazard a re-measured, autotuning-
/// or sysctl-derived bound reintroduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KtlsObservation {
    /// Live `rec_seq` for the direction.
    pub record_seq: u64,
}

/// Everything about a handed-off session that decides whether — and how — the
/// confidentiality limit is enforced.
#[derive(Debug, Clone, Copy)]
pub struct KtlsSessionLimits {
    /// Kernel cipher family installed on the socket.
    pub cipher: KtlsCipher,
    /// Wire version installed on the socket (TLS 1.2 today).
    pub tls_version: u16,
    /// The negotiated suite's `CipherSuiteCommon::confidentiality_limit`, read
    /// from rustls rather than hardcoded, so a provider change cannot silently
    /// leave this stale.
    pub confidentiality_limit: u64,
}

impl KtlsSessionLimits {
    /// Whether this suite has a finite record budget to enforce.
    ///
    /// `u64::MAX` is rustls's encoding of "no confidentiality limit applies"
    /// (ChaCha20-Poly1305), and enforcing nothing there is the correct posture,
    /// not an omission.
    #[inline]
    pub fn requires_enforcement(&self) -> bool {
        self.confidentiality_limit != u64::MAX
    }

    /// Sequence number at which relaying must stop.
    #[inline]
    pub fn threshold(&self) -> u64 {
        self.confidentiality_limit
            .saturating_sub(KTLS_CONFIDENTIALITY_RESERVE_RECORDS)
    }
}

/// The per-connection budget seed produced by the kTLS accept.
///
/// The initial sequence numbers are the kernel's own readback taken right
/// after the keys were installed, so they already account for every record the
/// handshake consumed (a TLS 1.2 server has at minimum encrypted and decrypted
/// one `Finished` record before handoff).
#[derive(Debug, Clone, Copy)]
pub struct KtlsConfidentialityPolicy {
    /// Cipher, version, and limit for this session.
    pub limits: KtlsSessionLimits,
    /// Kernel `TLS_TX` `rec_seq` observed immediately after key install.
    pub initial_transmit_seq: u64,
    /// Kernel `TLS_RX` `rec_seq` observed immediately after key install.
    pub initial_receive_seq: u64,
    /// The receive ceiling this session's receive guard is bounded with, fixed
    /// at handoff and never revised. Always `0` today: Linux offers no
    /// race-free post-accept receive bound, so every finite-limit suite is
    /// refused before the handshake and only unlimited suites, which build no
    /// guard, are handed off (see the module docs).
    pub stable_receive_ceiling: u64,
}

impl KtlsConfidentialityPolicy {
    /// A policy for a suite rustls reports as unlimited.
    ///
    /// No guard is ever built from it, so no receive window is ever sized and
    /// the ceiling is zero; the socket keeps ordinary TCP receive autotuning.
    pub fn unlimited(cipher: KtlsCipher, tls_version: u16) -> Self {
        Self {
            limits: KtlsSessionLimits {
                cipher,
                tls_version,
                confidentiality_limit: u64::MAX,
            },
            initial_transmit_seq: 0,
            initial_receive_seq: 0,
            stable_receive_ceiling: 0,
        }
    }

    /// Build the guard for one direction.
    ///
    /// `Ok(None)` means the suite carries no confidentiality limit. An `Err`
    /// means the session is already at or beyond its budget at handoff, which
    /// must fail the connection rather than start a relay.
    pub fn guard(
        &self,
        direction: KtlsDirection,
    ) -> Result<Option<KtlsConfidentialityGuard>, KtlsConfidentialityError> {
        if !self.limits.requires_enforcement() {
            return Ok(None);
        }
        let ceiling = self.stable_receive_ceiling;
        let seq = match direction {
            KtlsDirection::Transmit => self.initial_transmit_seq,
            KtlsDirection::Receive => self.initial_receive_seq,
        };
        let step = match direction {
            KtlsDirection::Transmit => transmit_record_bound(MAX_TLS_PLAINTEXT_BYTES),
            KtlsDirection::Receive => receive_record_bound(ceiling),
        };
        let threshold = self.limits.threshold();
        let guard = KtlsConfidentialityGuard::new(direction, threshold, seq, step)?;
        Ok(Some(guard))
    }
}

/// A single direction's record budget.
///
/// Owned outright by the relay future for that direction — never shared, never
/// locked, never allocated per byte.
#[derive(Debug, Clone)]
pub struct KtlsConfidentialityGuard {
    direction: KtlsDirection,
    threshold: u64,
    observed: u64,
    allowance: u64,
    step_records: u64,
}

impl KtlsConfidentialityGuard {
    /// Seed a guard from an authoritative kernel observation.
    pub fn new(
        direction: KtlsDirection,
        threshold: u64,
        initial_seq: u64,
        step_records: u64,
    ) -> Result<Self, KtlsConfidentialityError> {
        if initial_seq >= threshold {
            return Err(KtlsConfidentialityError::LimitReached {
                direction,
                observed: initial_seq,
                threshold,
            });
        }
        Ok(Self {
            direction,
            threshold,
            observed: initial_seq,
            allowance: threshold - initial_seq,
            step_records: step_records.max(1),
        })
    }

    /// Direction this budget belongs to.
    #[inline]
    pub fn direction(&self) -> KtlsDirection {
        self.direction
    }

    /// Sequence number at which the relay stops.
    #[inline]
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// Most recent kernel observation.
    #[inline]
    pub fn observed(&self) -> u64 {
        self.observed
    }

    /// Records still reservable before a fresh observation is required.
    #[inline]
    pub fn allowance(&self) -> u64 {
        self.allowance
    }

    /// Pessimistic record bound charged for the next relay syscall.
    ///
    /// Fixed for the life of the guard. On the receive side it is derived from
    /// the session's receive ceiling at handoff; there is intentionally no setter,
    /// so no later observation can enlarge it.
    #[inline]
    pub fn step_records(&self) -> u64 {
        self.step_records
    }

    /// Reserve `records` against the current window.
    ///
    /// Returns `false` when the reservation does not fit, which means a fresh
    /// kernel observation is required *before* the syscall runs.
    #[inline]
    pub fn charge(&mut self, records: u64) -> bool {
        if records > self.allowance {
            return false;
        }
        self.allowance -= records;
        true
    }

    /// Adopt a fresh kernel observation.
    ///
    /// Rejects a counter that regressed and a counter that has reached the
    /// threshold; otherwise the window reopens at `threshold - record_seq`.
    pub fn refresh(&mut self, record_seq: u64) -> Result<(), KtlsConfidentialityError> {
        if record_seq < self.observed {
            return Err(KtlsConfidentialityError::NonMonotonic {
                direction: self.direction,
                previous: self.observed,
                observed: record_seq,
            });
        }
        if record_seq >= self.threshold {
            return Err(KtlsConfidentialityError::LimitReached {
                direction: self.direction,
                observed: record_seq,
                threshold: self.threshold,
            });
        }
        self.observed = record_seq;
        self.allowance = self.threshold - record_seq;
        Ok(())
    }
}

/// Reserve `records`, paying for one kernel observation if the current window
/// cannot cover them.
///
/// This is the whole enforcement loop, kept free of syscalls so it can be
/// driven deterministically from tests: `observe` is only invoked when the
/// pre-charge fails, and a reservation that still does not fit afterwards is a
/// terminal refusal rather than a retry.
///
/// An observation reopens the window at `threshold - record_seq` and nothing
/// more. It cannot change what a step costs, because the receive step was fixed
/// against the session's receive ceiling before the first relayed byte.
pub fn charge_or_observe<F>(
    guard: &mut KtlsConfidentialityGuard,
    records: u64,
    observe: F,
) -> Result<(), KtlsConfidentialityError>
where
    F: FnOnce() -> Result<KtlsObservation, KtlsConfidentialityError>,
{
    if guard.charge(records) {
        return Ok(());
    }
    let observation = observe()?;
    guard.refresh(observation.record_seq)?;
    if guard.charge(records) {
        return Ok(());
    }
    Err(KtlsConfidentialityError::WindowExceedsBudget {
        direction: guard.direction(),
        step_records: records,
        remaining: guard.allowance(),
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::io::RawFd;

    use super::{KtlsConfidentialityError, KtlsDirection, KtlsObservation, KtlsSessionLimits};
    use crate::socket_opts::ktls;

    /// Read one direction's live kernel record sequence number.
    ///
    /// Validation lives in [`ktls::read_ktls_record_seq`]: the returned option
    /// length must match the cipher's `tls12_crypto_info_*` layout exactly and
    /// the echoed version/cipher type must be the ones this session installed,
    /// so a kernel that answers with a different structure fails closed here
    /// instead of yielding a garbage counter.
    pub fn observe_record_seq(
        fd: RawFd,
        limits: &KtlsSessionLimits,
        direction: KtlsDirection,
    ) -> Result<KtlsObservation, KtlsConfidentialityError> {
        let is_tx = direction.is_transmit();
        let cipher = limits.cipher;
        let version = limits.tls_version;
        let observed = ktls::read_ktls_record_seq(fd, cipher, version, is_tx);
        let record_seq = observed.map_err(|e| KtlsConfidentialityError::Unobservable {
            direction,
            detail: e.to_string(),
        })?;
        // Deliberately nothing else: the receive window's size was fixed at
        // handoff, so re-measuring a mutable buffer size here is precisely
        // what must not happen.
        Ok(KtlsObservation { record_seq })
    }
}

#[cfg(target_os = "linux")]
pub use linux::observe_record_seq;
