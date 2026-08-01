//! Fail-closed bounds for response bodies the gateway retains in memory.
//!
//! Response-body buffering is entered whenever an active plugin needs the
//! complete representation (`response_transformer` body rules,
//! `response_caching`, `waf` body inspection, …) or the operator forced
//! [`crate::config::types::ResponseBodyMode::Buffer`]. Two properties have to
//! hold for that to be safe against a remote client that can pick the backend
//! response (GHSA-pwcm-6rh8-f2gh):
//!
//! * **Per response.** The legacy `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`
//!   documents `0` as "unlimited". That is a defensible *streaming* policy —
//!   nothing is retained — but on a buffered path it means one response can
//!   grow a `Vec` until the process dies. [`buffered_response_body_ceiling`]
//!   folds a finite fail-closed fallback in for exactly that case, and only for
//!   buffered collection: streaming enforcement keeps `0 = unlimited`.
//! * **Across concurrent responses.** A finite per-response ceiling still
//!   multiplies by concurrency. [`ResponseBufferReservation`] charges retained
//!   bytes against one process-wide budget, so total retained buffered-response
//!   bytes stay bounded no matter how many clients arrive at once.
//!
//! # Charge lifetime
//!
//! The budget is only a bound if a permit outlives the allocation it paid for.
//! A collector-local reservation does not: collection finishes, the local
//! drops, and the bytes stay resident in `BackendResponse` / `GrpcResponse` /
//! `H3BufferedResponse`, in retry state, through the response-plugin phases,
//! and all the way down to the wire — and anything copied out of them (a
//! `response_caching` entry) stays resident longer still. Many responses could
//! therefore each pass admission, release, and remain resident at once — which
//! is exactly the bypass this module exists to prevent.
//!
//! So the charge is not a collector local. [`charged_bytes`] moves the retained
//! `Vec<u8>` *and* its permit into one owner and hands back a
//! [`bytes::Bytes`] view of it ([`bytes::Bytes::from_owner`], `O(1)`, no copy).
//! From then on:
//!
//! * every cheap clone (dedup replay, concurrent delivery, cache-entry replay)
//!   shares the one owner, so the allocation is charged **exactly once** no
//!   matter how many handles exist — a clone never mints a second permit. A
//!   *copy* is a different allocation and takes its own charge (below);
//! * the permit is returned when the **last** handle drops, which covers
//!   success, retry abandonment, plugin replacement, response conversion,
//!   deadline expiry, client disconnect, and task cancellation identically,
//!   because they are all just drops;
//! * nothing has to remember to release, so no path can leak the budget and no
//!   path can release early while the bytes are still resident.
//!
//! A plugin phase that *replaces* the body installs a different allocation,
//! which the collector's charge does not cover — and the plugin, not this
//! module, is what allocates it. Charging such a buffer when it arrives would be
//! charging *after* the allocation, so under concurrency an unbounded number of
//! attacker-shaped transform outputs could exist at once outside the cap. Those
//! phases therefore open a [`ResponseTransformWindow`] **before** invoking the
//! producer, sized to the per-response retained ceiling, and
//! [`ResponseTransformWindow::charge`] transfers the covering blocks out of that
//! window into the finished allocation. Dropping the old `Bytes` returns its
//! permit, so a replacement is a move of the charge rather than a second one.
//! The charge is attached to the **replacement allocation**, never to the
//! request that produced it: a replacement that is copied into a longer-lived
//! structure keeps its charge, and a request context that drops (or is cloned)
//! neither releases nor duplicates it.
//!
//! The window is a *precondition*, not a best-effort convenience. A chain can
//! contain several producers, and after the first replacement the window is
//! short by whatever that replacement carried away. Refilling it while the body
//! it replaced is still alive would double-count, so the window is refilled only
//! AFTER the caller has installed the replacement (which drops the previous
//! body's charge), and [`ResponseTransformWindow::ensure_covering_window`] must
//! succeed BEFORE the next producer is invoked. When it cannot, the caller
//! installs the neutral fail-closed capacity terminal instead of running the
//! producer — a producer is never invoked under a partial window.
//!
//! A reserved window bounds what the gateway will RETAIN; on its own it does not
//! bound what a producer may allocate before handing bytes over. So the producer
//! boundary is bounded on the construction side too: a replacement body is built
//! through [`BoundedResponseBodySink`], which refuses the write that would push
//! the buffer past the per-response retained ceiling instead of allocating it and
//! being rejected afterwards. Built-ins declare that contract
//! ([`crate::plugins::ResponseBodyProduction`]); a plugin the gateway cannot
//! prove declares it is treated as potentially unbounded and fails closed rather
//! than being invoked.
//!
//! "Built through the sink" is meant literally, and it is the half a first
//! reading gets wrong. A bounded COPY of a finished replacement is not a bound on
//! construction: while the copy is being measured, the complete attacker-shaped
//! original is already resident beside the old body and the window, so the
//! aggregate the window exists to enforce is untrue for exactly the bytes most
//! under a client's influence. Every declared producer therefore writes its
//! output from the FIRST byte into a [`BoundedResponseBodySink`],
//! [`bounded_json_vec`], or an equivalently ceiling-aware writer — an SSE event
//! at a time, a base64 encoder streaming into the sink, a protobuf message
//! encoded directly into reserved room ([`BoundedResponseBodySink::append_with`])
//! — rather than assembling a complete `String`/`Vec` and calling
//! [`bounded_vec_from`] on it afterwards. [`bounded_vec_from`] remains correct
//! only where its input is not itself a would-be complete replacement.
//!
//! Three corollaries follow, and all are load-bearing:
//!
//! * a producer that genuinely needs an intermediate representation (the
//!   `ai_response_guard` regex redactor applies its pattern set in sequential
//!   passes, because a placeholder one pattern renders may legitimately be
//!   rewritten by a later one) keeps its live input and its pass output under ONE
//!   shared ceiling — budgeting the still-live prior pass by its resident
//!   CAPACITY, not its logical length — so geometric growth slack cannot mint
//!   room for the next sink past the covering window;
//! * a producer that needs to know its own output's LENGTH before it can write
//!   it does not learn that by building the output and measuring it. The
//!   gRPC-Web reframer has to put the trailer payload's length in the frame
//!   header that precedes the payload, so it emits the payload twice from one
//!   writer — once into a bounded counter that retains nothing, once straight
//!   into the final bounded destination (the binary sink, or the base64 encoder
//!   streaming into the text sink) — and re-checks the written length before
//!   publishing. Neither a complete trailer payload nor a complete binary
//!   preimage is ever resident beside the output;
//! * a full-size candidate body built OUTSIDE a producer phase is charged like
//!   one. `ai_response_guard` builds the exact bytes the client would receive in
//!   order to decide whether to fail closed — the SSE residual scan, the JSON /
//!   content residual scan, and the native-gRPC redaction preflight all do this
//!   during inspection, where no window is open. Each opens a
//!   [`ResponseTransformWindow`] sized to this response's retained ceiling for
//!   exactly the lifetime of its candidate, and each treats a refused window as
//!   a REJECTION (residual / unredactable) rather than as licence to build the
//!   candidate anyway.
//!
//! A promised rewrite that never happens is the same hole seen from the other
//! side. A refused construction used to return "no replacement", and to a
//! transform loop that was indistinguishable from "nothing to change" — so a
//! policy plugin that already decided the original bytes are unsafe would have
//! them forwarded by the very refusal that was supposed to be fail-closed.
//! Producers therefore return
//! [`crate::plugins::ResponseBodyTransformOutcome`]: intentional no-ops stay
//! [`crate::plugins::ResponseBodyTransformOutcome::Unchanged`], while a
//! retained-ceiling refusal after a required change is
//! [`crate::plugins::ResponseBodyTransformOutcome::CapacityRefused`] and the
//! shared loop installs the neutral capacity terminal. `ai_response_guard`
//! additionally records a detected-but-not-yet-redacted response in typed
//! request state (`RequestContext::ai_response_guard_pending_redactions`) for
//! representations its rewriter cannot address, discharges it only when its
//! producer actually installs bytes, and rejects at `on_final_response_body`
//! when the promise is still outstanding.
//!
//! The same rule covers a body a plugin *copies out* into storage that outlives
//! the request — `response_caching`'s entry copy is a distinct allocation from
//! the collected body, so it acquires its own charge through
//! [`charge_retained_copy`] and holds it until the entry is evicted and the last
//! clone of it drops. If the budget cannot admit that copy, the store is skipped
//! (a cache miss, exactly like the `max_entry_size_bytes` refusal beside it)
//! rather than retaining an uncharged entry.
//!
//! There is deliberately no "attach a charge to a buffer somebody else already
//! allocated" entry point for a request path. Awaiting an opaque read (reqwest's
//! `Response::bytes()`) materialises an allocation of unknown capacity *before*
//! anything can measure it, so many tasks could each be holding such a buffer
//! while only one declared `Content-Length` had been charged — a declared length
//! is a backend claim, not an allocation-capacity proof, and a top-up taken
//! after the await is a charge taken after the allocation. The eager
//! small-response paths therefore use the same [`ChargedBodyCollector`] the
//! buffered paths use, driven over `Response::bytes_stream()`, so every byte of
//! resident capacity on those paths is charged before it is asked for.
//!
//! # What is charged, and when
//!
//! Every retained allocation is charged **before** it exists, by whoever is in a
//! position to know its size:
//!
//! * a growing collector ([`ChargedBodyCollector`]) picks its own growth target,
//!   reserves it, and only then asks the allocator for exactly that much, so
//!   `Vec`'s amortised doubling can never pick a capacity the budget did not
//!   approve. What is charged is the buffer's CAPACITY, not its length, because
//!   capacity is what is resident;
//! * capacity reserved before the first DATA frame is resident memory just like
//!   bytes already written, so the native-H3 and gRPC collectors charge their
//!   preallocation hint before allocating it (headers-only, empty, or stalled
//!   responses therefore cannot accumulate uncharged capacity under
//!   concurrency). Growth afterwards is charged as a delta against the same
//!   reservation, so a preallocated response is never charged twice;
//! * an allocation produced by code this module does not control — a plugin's
//!   replacement body, the gRPC-Web trailer reframe — is produced inside a
//!   [`ResponseTransformWindow`] reserved beforehand, and the covering blocks
//!   are transferred into it rather than acquired after the fact;
//! * a copy that outlives its request ([`charge_retained_copy`]) reserves, then
//!   sizes the copy's allocation itself.
//!
//! The only remaining gap between a charge and its allocation is the allocator's
//! right to return MORE than it was asked for. That window is a single statement
//! on one thread with no `await` in it, it is repaired by an immediate top-up,
//! and nothing is published out of it: [`charged_bytes`] measures
//! [`Vec::capacity`] at the single publication point and REFUSES an allocation
//! its charge does not cover, so an allocation whose real capacity outran its
//! charge is dropped rather than installed.
//!
//! # Decompression working set
//!
//! The representation gate
//! ([`crate::plugins::response_representation`]) may DECODE a protected
//! response before any transform runs, and a few kilobytes of `gzip` can
//! inflate to the decode ceiling. Those bytes are attacker-amplified and
//! client-visible, so they are charged like any other retained allocation, with
//! two additional properties:
//!
//! * the charge is taken **before** each growth of the output buffer, in whole
//!   chunks, so a refusal happens instead of the allocation rather than after
//!   it. What is charged is the buffer's CAPACITY, not just the bytes written
//!   into it, because capacity is what is resident;
//! * a stacked `Content-Encoding` holds one pass's input and the next pass's
//!   output at the same time, so the reservation tracks the PEAK of
//!   input + output across passes. A reservation only ever grows, so holding
//!   the peak is automatic;
//!   [`ResponseBufferReservation::narrow_to_covered`] then hands the surplus
//!   back when the surviving allocation is published;
//! * the CODEC's own heap — a `brotli` ring buffer and Huffman/context tables,
//!   a `miniz_oxide` inflate state — is not represented by the output buffer at
//!   all, and the first read into a freshly constructed decoder can allocate it
//!   before any output exists. So the representation gate reserves a
//!   conservative per-codec ceiling on that working set *before it constructs
//!   the decoder*, as a SEPARATE reservation held for exactly the length of one
//!   pass. Being separate is what stops a large output from hiding behind an
//!   earlier scratch charge: the semaphore sees the sum, not the maximum. The
//!   ceilings and their derivation live beside the decoder in
//!   [`crate::plugins::response_representation`].
//!
//! The first pass decodes straight from the collector-charged wire bytes, so no
//! copy of them is made or charged.
//!
//! ## Allocator slop, stated exactly
//!
//! `Vec` guarantees *at least* the capacity that was requested, not exactly it.
//! Every site that grows a retained buffer — the decode, the collectors, the
//! retained copy — therefore reserves its computed growth target, allocates, and
//! then immediately tops the reservation up to the resulting `Vec::capacity()`,
//! failing closed (and dropping the buffer) if the top-up is refused. The window
//! in which capacity exceeds the reservation is the single statement between the
//! allocation and the top-up, on one thread, with no await in it. Nothing is
//! published out of that window:
//! [`ResponseBufferReservation::narrow_to_covered`] gates the handoff, via
//! [`charged_bytes`], and REFUSES rather than narrowing when the charge is
//! smaller than the surviving capacity, so an allocation whose real capacity
//! outran its charge is dropped rather than installed.
//!
//! ## What the aggregate cap does and does not bound
//!
//! It bounds every allocation described above: the collected wire body, its
//! preallocation, the decode's output and codec working set, the cache-entry
//! copy, the eagerly collected body, and a plugin-produced replacement, which
//! cannot be produced at all until its window is reserved. It does not attempt
//! to bound allocations that are not retained response representations — header
//! maps, TLS records, connection read buffers — which have their own bounds
//! elsewhere in the gateway.
//!
//! ## Peak accounting, stated exactly
//!
//! The aggregate cap bounds a PEAK, and the peak of a rewriting response is not
//! one ceiling. While a producer runs, three things can be charged at once:
//!
//! * the body it is reading from, charged at up to one ceiling;
//! * the covering window reserved for its output, one ceiling;
//! * for a stacked decode, the decode's own transient input+output peak, which
//!   [`ResponseBufferReservation::narrow_to_covered`] hands back at publication.
//!
//! So the worst case for a maximum-size response being rewritten is **two**
//! ceilings, not one, and the concurrent-rewrite arithmetic an operator should
//! use is `FERRUM_RESPONSE_BUFFER_MAX_TOTAL_BYTES / (2 × ceiling)` — not
//! `total / ceiling`. Responses that are merely buffered (no plugin that can
//! replace the body) cost one ceiling and no window at all, because a chain with
//! no declared producer never opens one.
//!
//! Two is the exact number, not a rounding. It holds only because no producer
//! materialises a complete replacement outside the window's ceiling: a producer
//! that built its output first and copied it in afterwards would peak at three,
//! and so would one whose intermediate passes each got their own full ceiling.
//! Both shapes are structurally excluded above, and
//! `tests/unit/gateway_core/response_buffer_budget_tests.rs` holds static
//! source guards over the declared producer set so neither can come back.
//!
//! Stated as precisely as the implementation actually proves it, "two ceilings"
//! bounds the RETAINED-REPRESENTATION allocations: the body being read, and the
//! reserved window the replacement is built inside (or, outside a producer
//! phase, the window a fail-closed candidate is built inside). It is not a claim
//! about every byte a producer touches. A producer still holds ordinary parse
//! state derived from its already-charged input — a `serde_json::Value` tree for
//! one buffered document, one SSE event's parsed frame, one decoded protobuf
//! message — which is bounded by that input and by the per-event / per-message
//! caps the plugins enforce, not by a second window. What is excluded is the
//! shape this advisory is about: a COMPLETE would-be client-visible body, or a
//! complete preimage of one, alive outside a reservation.
//!
//! # Admission
//!
//! Acquisition is non-blocking (`try_acquire_many_owned`): a collector that
//! cannot reserve fails the response immediately rather than queueing behind
//! other buffers and burning the client's deadline. The refusal is
//! *gateway-local transient capacity*, not a backend fault, so every transport
//! surfaces it through the constants below —
//! [`RESPONSE_BUFFER_OVERLOAD_STATUS`] / [`RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS`]
//! with the health-neutral [`RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS`] — and never
//! as a backend `502` / `ResponseBodyTooLarge` that would poison circuit
//! breaker, passive health, and adaptive-concurrency accounting.
//!
//! No lock is taken on the streaming hot path — a released response never
//! constructs a reservation — and the state is one process-global semaphore, so
//! there is no per-route or per-client cardinality.

use std::sync::Arc;
use std::sync::OnceLock;

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::retry::ErrorClass;

/// Granularity of one budget block. Retained bytes are charged in whole blocks,
/// so a typical small JSON response costs exactly one.
pub(crate) const RESERVATION_UNIT_BYTES: usize = 64 * 1024;

/// Per-response ceiling applied when the effective response-body limit is `0`
/// and the body is being retained rather than streamed.
pub(crate) const DEFAULT_BUFFERED_RESPONSE_FALLBACK_BYTES: usize = 10 * 1024 * 1024;

/// Aggregate ceiling on bytes retained by concurrent buffered responses.
pub(crate) const DEFAULT_RESPONSE_BUFFER_TOTAL_BYTES: usize = 256 * 1024 * 1024;

/// Status returned when the aggregate budget cannot admit another buffered
/// response. `503` (not `502`) because the backend behaved correctly and the
/// condition is transient gateway capacity.
pub(crate) const RESPONSE_BUFFER_OVERLOAD_STATUS: u16 = 503;

/// gRPC status for the same refusal. `RESOURCE_EXHAUSTED` is the resource/
/// capacity status; `UNAVAILABLE` would suggest the backend is down and
/// `INTERNAL` would suggest a gateway defect.
pub(crate) const RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS: u32 =
    crate::proxy::grpc_proxy::grpc_status::RESOURCE_EXHAUSTED;

/// Client-visible body for an aggregate-budget refusal. Fixed bytes: it names
/// no route, header, credential, or response content.
pub(crate) const RESPONSE_BUFFER_OVERLOAD_BODY: &str =
    r#"{"error":"Response buffering capacity exceeded"}"#;

/// Fixed `grpc-message` for the same refusal. Redaction-safe for the same
/// reason: fixed cardinality, no request or response content.
pub(crate) const RESPONSE_BUFFER_OVERLOAD_GRPC_MESSAGE: &str =
    "Response buffering capacity exceeded";

/// Telemetry/retry class for the refusal. Gateway-local by construction, so it
/// is a `client_side_no_backend_signal` class: neutral to the circuit breaker,
/// passive health, and adaptive concurrency, and never retried (another
/// upstream would hit the same process-global budget).
pub(crate) const RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS: ErrorClass =
    ErrorClass::GatewayBufferCapacity;

/// Whole blocks needed to cover `retained_bytes`.
///
/// Saturating at `u32::MAX` rather than wrapping: a saturated block count is
/// unsatisfiable by any real semaphore, so an absurd byte count is refused
/// instead of wrapping down into an affordable one.
fn blocks_for(retained_bytes: usize) -> u32 {
    u32::try_from(retained_bytes.div_ceil(RESERVATION_UNIT_BYTES)).unwrap_or(u32::MAX)
}

struct Budget {
    fallback_per_response_bytes: usize,
    permits: Arc<Semaphore>,
}

static BUDGET: OnceLock<Budget> = OnceLock::new();

/// Which aggregate budget one charge is taken against.
///
/// Production always resolves to the process-global budget, so this costs a
/// null check and nothing else. External tests bind an [`IsolatedBudget`]
/// instead ([`IsolatedBudget::handle`]), which is what lets a parallel test
/// binary observe admission and release deterministically without mutating the
/// process-global semaphore under its neighbors.
#[derive(Clone, Copy)]
pub(crate) struct BudgetRef<'a>(Option<&'a Budget>);

impl<'a> BudgetRef<'a> {
    /// The process-global budget every production path charges.
    pub(crate) const fn global() -> Self {
        Self(None)
    }

    fn resolve(self) -> &'a Budget {
        match self.0 {
            Some(budget) => budget,
            None => budget(),
        }
    }
}

fn budget() -> &'static Budget {
    BUDGET.get_or_init(|| {
        Budget::new(
            DEFAULT_BUFFERED_RESPONSE_FALLBACK_BYTES,
            DEFAULT_RESPONSE_BUFFER_TOTAL_BYTES,
        )
    })
}

impl Budget {
    fn new(fallback_per_response_bytes: usize, total_bytes: usize) -> Self {
        // A zero/short fallback would not cover even one reservation block, and
        // an enormous one would make the fallback arithmetic needlessly close
        // to `usize` overflow, so normalize it to the documented range first. A
        // zero/short total would then refuse every buffered response and take
        // the proxy down, so the aggregate budget is floored at that FALLBACK
        // per-response ceiling — and at nothing else.
        //
        // Stated exactly, because the difference is load-bearing: the floor
        // guarantees the gateway can always admit one *fallback-ceiling-sized*
        // response. It does NOT guarantee that an arbitrarily large configured
        // or route-effective per-response ceiling is admissible. If an operator
        // configures a 4 GiB per-response ceiling under a 256 MiB aggregate
        // budget, responses above the aggregate budget are refused with
        // [`RESPONSE_BUFFER_OVERLOAD_STATUS`] — the aggregate cap is not
        // silently widened to fit one huge response, because that would hand
        // the memory bound back to whoever picks the response.
        let fallback_per_response_bytes =
            fallback_per_response_bytes.clamp(RESERVATION_UNIT_BYTES, usize::MAX / 2);
        let total_bytes = total_bytes.max(fallback_per_response_bytes);
        let blocks = total_bytes.div_ceil(RESERVATION_UNIT_BYTES);
        Self {
            fallback_per_response_bytes,
            permits: Arc::new(Semaphore::new(blocks.min(Semaphore::MAX_PERMITS))),
        }
    }

    fn ceiling(&self, effective_limit: usize) -> usize {
        if effective_limit > 0 {
            effective_limit
        } else {
            self.fallback_per_response_bytes
        }
    }
}

/// Publish the operator-configured bounds. Called once during startup, before
/// any listener accepts traffic. Later calls are ignored: the semaphore backs
/// live reservations, so resizing it under them is not expressible — changing
/// these values requires a restart, like the other process-global limits.
///
/// `#[allow(dead_code)]`: the binary calls this from `main`, but the same
/// module is separately compiled into the library crate where that binary-only
/// call site is invisible.
#[allow(dead_code)] // binary startup caller; dead in the separately compiled library unit
pub(crate) fn init(fallback_per_response_bytes: usize, total_bytes: usize) {
    let _ = BUDGET.set(Budget::new(fallback_per_response_bytes, total_bytes));
}

/// The effective ceiling for a response the gateway is about to *retain*.
///
/// `effective_limit` is the already-folded strictest active limit (global +
/// route). A configured value is honored verbatim. `0` — documented as
/// "unlimited" for streaming — becomes the finite fallback here, because an
/// unlimited retained buffer is not a policy the gateway can honor safely.
///
/// Note that a configured ceiling larger than the aggregate budget is honored
/// as a *ceiling* but is not thereby admissible: the aggregate reservation
/// below still refuses what will not fit. See [`Budget::new`].
pub(crate) fn buffered_response_body_ceiling(effective_limit: usize) -> usize {
    budget().ceiling(effective_limit)
}

/// A growing claim on the process-wide buffered-response budget.
///
/// Construct one before collecting a response body, call [`Self::reserve_in`] with
/// the running retained length (and with the preallocated capacity *before*
/// allocating it), then hand it to [`charged_bytes`] together with the bytes it
/// paid for so the charge outlives the collector. Dropping it without doing so
/// returns every block, which is what makes rejection, error, and cancellation
/// leak-free.
#[derive(Default)]
pub(crate) struct ResponseBufferReservation {
    /// Merged permits for `blocks` reserved blocks. `None` while nothing is
    /// reserved yet.
    permit: Option<OwnedSemaphorePermit>,
    blocks: u32,
}

impl ResponseBufferReservation {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Charge `retained_bytes`, acquiring more blocks when the collector has
    /// grown past what is already reserved.
    ///
    /// Returns `false` when the aggregate budget cannot cover the growth; the
    /// caller must then abandon collection and surface
    /// [`RESPONSE_BUFFER_OVERLOAD_STATUS`]. Already-held blocks stay held until
    /// this value drops.
    fn reserve_against(&mut self, budget: &Budget, retained_bytes: usize) -> bool {
        // Nothing retained, nothing charged. A zero-length body occupies no
        // memory, so rounding it up to a block would both over-charge the
        // budget and let memory pressure refuse a bodyless response that costs
        // nothing to serve.
        if retained_bytes == 0 {
            return true;
        }
        let wanted = blocks_for(retained_bytes);
        if wanted <= self.blocks {
            return true;
        }
        let additional = wanted - self.blocks;
        match Arc::clone(&budget.permits).try_acquire_many_owned(additional) {
            Ok(acquired) => {
                match self.permit.as_mut() {
                    Some(held) => held.merge(acquired),
                    None => self.permit = Some(acquired),
                }
                self.blocks = wanted;
                true
            }
            Err(_) => false,
        }
    }

    /// Charge `retained_bytes` against an explicitly chosen budget.
    ///
    /// The reservation path every charge takes; only the semaphore differs.
    /// Production passes [`BudgetRef::global`].
    pub(crate) fn reserve_in(&mut self, budget: BudgetRef<'_>, retained_bytes: usize) -> bool {
        self.reserve_against(budget.resolve(), retained_bytes)
    }

    /// Narrow the charge to exactly what `retained_bytes` needs, returning every
    /// surplus block — but only when the charge already COVERS those bytes.
    ///
    /// This exists for one shape: a working reservation that had to cover a
    /// transient PEAK (a stacked decode holds its input and its output at once)
    /// and is then handed to [`charged_bytes`] together with only the surviving
    /// allocation. Without narrowing, the peak would stay charged for the whole
    /// response lifetime, which is safe but needlessly shrinks the budget other
    /// responses can use.
    ///
    /// Narrowing only ever RELEASES permits, so it can never itself acquire.
    /// That is exactly why it must not be described as *preventing* an
    /// under-charge: if the surviving allocation is larger than what was
    /// reserved — an allocator that returned more capacity than requested and a
    /// caller that did not top the reservation up — narrowing would silently
    /// publish under-charged bytes. So this returns `false` in that case and the
    /// caller must not publish; dropping the reservation and the buffer together
    /// is the fail-closed answer.
    #[must_use]
    pub(crate) fn narrow_to_covered(&mut self, retained_bytes: usize) -> bool {
        let wanted = blocks_for(retained_bytes);
        if wanted > self.blocks {
            return false;
        }
        if wanted == self.blocks {
            return true;
        }
        if wanted == 0 {
            // Dropping the whole permit is the same release, without
            // constructing a zero-permit handle.
            self.permit = None;
            self.blocks = 0;
            return true;
        }
        let surplus = self.blocks - wanted;
        if let Some(held) = self.permit.as_mut() {
            // `split` returns `None` only when the permit holds fewer than
            // `surplus` blocks, which cannot happen: the permit holds exactly
            // `self.blocks` and `surplus < self.blocks`. Treating a `None` as
            // "keep the whole charge" keeps even that impossible case
            // conservative rather than under-charged.
            if held.split(surplus as usize).is_some() {
                self.blocks = wanted;
            }
        }
        true
    }

    /// Carve the blocks that cover `retained_bytes` OUT of this reservation into
    /// a separate one, without touching the semaphore.
    ///
    /// This is the transfer half of "reserve before the allocation exists": a
    /// window is reserved up front, the allocation is then produced inside it,
    /// and the blocks that cover the finished allocation move to the owner that
    /// will hold them for its lifetime. Nothing is acquired here, so the split
    /// cannot fail for capacity reasons — it fails only when the window is
    /// SMALLER than the allocation, which means the producer overran the bound
    /// the window was sized from and the caller must fail closed.
    #[must_use]
    pub(crate) fn split_charge(&mut self, retained_bytes: usize) -> Option<Self> {
        let wanted = blocks_for(retained_bytes);
        if wanted == 0 {
            return Some(Self::new());
        }
        if wanted > self.blocks {
            return None;
        }
        let held = self.permit.as_mut()?;
        // `split` returns `None` only when the permit holds fewer than `wanted`
        // blocks, which the check above already excluded. Treating it as a
        // refusal keeps even that impossible case fail-closed.
        let carved = held.split(wanted as usize)?;
        self.blocks -= wanted;
        if self.blocks == 0 {
            self.permit = None;
        }
        Some(Self {
            permit: Some(carved),
            blocks: wanted,
        })
    }

    /// Bytes currently reserved (whole blocks). Diagnostics only.
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.blocks as usize * RESERVATION_UNIT_BYTES
    }

    fn into_permit(self) -> Option<OwnedSemaphorePermit> {
        self.permit
    }
}

/// The length a retained buffer would have after appending `added` bytes to
/// `current`, computed once so the ceiling check, the budget reservation, and
/// the allocation that follows all use the SAME value.
///
/// Saturating rather than wrapping: on a 64-bit target the sum cannot really
/// overflow, but a hostile `Content-Length`/frame sequence must not be able to
/// turn a bounds check into a debug-build panic or a release-build wrap that
/// *passes* the ceiling comparison. Saturation pins the prospective length at
/// `usize::MAX`, which fails every finite ceiling — the fail-closed direction.
#[inline]
pub(crate) fn prospective_retained_len(current: usize, added: usize) -> usize {
    current.saturating_add(added)
}

/// One retained buffered-response allocation and the budget permit that paid
/// for it, owned together so neither can outlive the other.
struct ChargedBuffer {
    data: Vec<u8>,
    /// Released on drop. `None` only for the degenerate empty case, which is
    /// never charged.
    _permit: Option<OwnedSemaphorePermit>,
}

impl AsRef<[u8]> for ChargedBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Publish a collected retained body as cheaply cloneable [`Bytes`] whose
/// budget charge is released exactly when the last clone drops.
///
/// `O(1)`: the `Vec` is moved, never copied, and `reservation` is moved into the
/// same owner. Every clone shares that owner, so the allocation stays charged
/// exactly once for as long as any handle to it exists.
///
/// What is measured here is [`Vec::capacity`], not [`Vec::len`]. A `Vec` that
/// grew is free to hold capacity beyond its length, and capacity is what stays
/// resident; charging the length would leave the difference outside the budget
/// on every response that reallocated. This is the SINGLE publication point for
/// a collected `Vec`, so making it capacity-exact is what makes the module's
/// claim structural rather than a convention each collector has to remember.
///
/// `None` means the reservation does not cover that capacity. Narrowing can only
/// release permits, never acquire, so it cannot repair an under-charge: the
/// fail-closed answer is to publish nothing and let the caller drop both the
/// buffer and the reservation. Every collector reserves its own growth target
/// before allocating it, so a `None` is a checked invariant rather than an
/// expected outcome — but it is checked, because the alternative is publishing
/// bytes the budget does not bound.
#[must_use]
pub(crate) fn charged_bytes(
    data: Vec<u8>,
    mut reservation: ResponseBufferReservation,
) -> Option<Bytes> {
    if data.is_empty() {
        // Nothing is retained, so nothing should stay charged. The `Vec` — and
        // any capacity it preallocated for a body that never arrived — is
        // dropped here together with the reservation, so neither survives this
        // return.
        return Some(Bytes::new());
    }
    if !reservation.narrow_to_covered(data.capacity()) {
        return None;
    }
    Some(Bytes::from_owner(ChargedBuffer {
        data,
        _permit: reservation.into_permit(),
    }))
}

/// Charge a COPY that will outlive the request which produced it — the
/// `response_caching` entry body.
///
/// The copy is a distinct allocation from the collected body, so it cannot
/// share the collector's charge: the collected body is released when the
/// response finishes while the entry stays resident until eviction. Reserving
/// before `to_vec` also means a refusal never materialises the copy at all.
///
/// `None` means the budget refused; the caller must skip the store rather than
/// retain an uncharged entry.
pub(crate) fn charge_retained_copy(data: &[u8]) -> Option<Bytes> {
    charge_retained_copy_against(budget(), data)
}

fn charge_retained_copy_against(budget: &Budget, data: &[u8]) -> Option<Bytes> {
    if data.is_empty() {
        return Some(Bytes::new());
    }
    let mut reservation = ResponseBufferReservation::new();
    if !reservation.reserve_against(budget, data.len()) {
        return None;
    }
    // Size the copy's allocation here rather than letting `to_vec` pick it, so
    // the capacity that becomes resident is the one that was just reserved. The
    // allocator may still hand back more than `reserve_exact` asked for, so top
    // the reservation up before publishing; a refused top-up drops `copy` here
    // rather than storing under-charged bytes.
    let mut copy: Vec<u8> = Vec::new();
    copy.reserve_exact(data.len());
    if !reservation.reserve_against(budget, copy.capacity()) {
        return None;
    }
    copy.extend_from_slice(data);
    charged_bytes(copy, reservation)
}

/// Charge an allocation this module did not size, measured by its CAPACITY.
///
/// This is the external-test seam only, and deliberately not reachable from a
/// request path. A request path that charged a plugin-produced buffer this way
/// would be charging AFTER the allocation, which is the accounting hole
/// [`ResponseTransformWindow`] exists to close: production reserves the window
/// first and TRANSFERS blocks into the finished allocation with
/// [`ResponseBufferReservation::split_charge`].
#[allow(dead_code)] // used only by external tests via IsolatedBudget; dead in binary unit
fn charge_owned_allocation_against(budget: &Budget, data: Vec<u8>) -> Option<Bytes> {
    if data.is_empty() {
        return Some(Bytes::new());
    }
    let mut reservation = ResponseBufferReservation::new();
    if !reservation.reserve_against(budget, data.capacity()) {
        return None;
    }
    charged_bytes(data, reservation)
}

/// Why a retained allocation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetainRejection {
    /// The response exceeded the per-response buffered ceiling. A BACKEND
    /// attribution: the origin sent more than the operator allows to be
    /// retained, so each transport keeps its own `ResponseBodyTooLarge` shape.
    TooLarge,
    /// The aggregate budget could not admit the allocation. A GATEWAY-LOCAL
    /// transient-capacity attribution, surfaced with
    /// [`RESPONSE_BUFFER_OVERLOAD_STATUS`] /
    /// [`RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS`] and the health-neutral
    /// [`RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS`].
    BudgetExhausted,
}

/// The capacity a growing collector will ask its allocator for, chosen by this
/// module rather than by `Vec`'s own growth so it can be CHARGED before it is
/// allocated.
///
/// `Vec::extend_from_slice` grows by amortised doubling, which routinely leaves
/// capacity well above length — that surplus is resident, and charging only the
/// post-append length is exactly how a collector can publish more bytes than it
/// paid for. Computing the target here and asking for it with `reserve_exact`
/// makes the resulting capacity known BEFORE the allocation happens, so the
/// budget check precedes it instead of chasing it.
///
/// Doubling is preserved so collection stays amortised `O(n)`, and the target is
/// clamped to the per-response ceiling: growth headroom is not licence to
/// allocate past the bound the response is being collected under.
fn growth_target(current_capacity: usize, needed: usize, ceiling: usize) -> usize {
    let doubled = current_capacity.saturating_mul(2);
    doubled.max(needed).min(ceiling.max(needed)).max(needed)
}

/// A growing retained-response buffer whose budget reservation is proven to
/// cover its CAPACITY at every point in its life.
///
/// This is the one collector every buffered transport uses (reqwest, hyper H2,
/// native H3, the H3→HTTP bridge, and buffered gRPC), so the accounting rule
/// cannot drift per protocol. The invariant it maintains is:
///
/// > `reservation.reserved_bytes() >= data.capacity()`, established before each
/// > allocation and re-checked after it.
///
/// Every growth is charged first and allocated second. There is no design in
/// which a larger buffer is allocated speculatively and the budget only
/// consulted afterwards: the only gap between charge and allocation is the
/// allocator's own right to return MORE than `reserve_exact` asked for, which is
/// a single statement with no `await` in it and is repaired by the immediate
/// top-up on the next line — and, failing that, refused at publication by
/// [`charged_bytes`], which never installs an allocation its charge does not
/// cover.
pub(crate) struct ChargedBodyCollector<'a> {
    budget: BudgetRef<'a>,
    /// The per-response buffered ceiling ([`buffered_response_body_ceiling`]),
    /// already folded, so `0 = unlimited` cannot reach a retained buffer.
    ceiling: usize,
    data: Vec<u8>,
    reservation: ResponseBufferReservation,
}

impl<'a> ChargedBodyCollector<'a> {
    /// A collector with no allocation yet. `ceiling` must already be the folded
    /// buffered ceiling.
    pub(crate) fn new(budget: BudgetRef<'a>, ceiling: usize) -> Self {
        Self {
            budget,
            ceiling,
            data: Vec::new(),
            reservation: ResponseBufferReservation::new(),
        }
    }

    /// A collector that preallocates `hint` bytes, charged BEFORE the allocation
    /// exists so a flood of responses that advertise a large `content-length`
    /// and then send nothing cannot each hold uncharged capacity.
    ///
    /// `hint` is clamped to `ceiling`: a preallocation hint is a size promise
    /// from the backend, and a promise past the retained ceiling buys nothing
    /// the collector is allowed to keep.
    pub(crate) fn with_preallocation(
        budget: BudgetRef<'a>,
        ceiling: usize,
        hint: usize,
    ) -> Result<Self, RetainRejection> {
        let mut collector = Self::new(budget, ceiling);
        let hint = hint.min(ceiling);
        if hint == 0 {
            // A zero hint allocates nothing, so it is deliberately not charged:
            // rounding every bodyless response up to a block would let traffic
            // that occupies no memory consume the budget.
            return Ok(collector);
        }
        if !collector.charge(hint) {
            return Err(RetainRejection::BudgetExhausted);
        }
        collector.data.reserve_exact(hint);
        if !collector.charge(collector.data.capacity()) {
            return Err(RetainRejection::BudgetExhausted);
        }
        Ok(collector)
    }

    fn charge(&mut self, bytes: usize) -> bool {
        let budget = self.budget;
        self.reservation.reserve_in(budget, bytes)
    }

    /// Bytes collected so far. This is the LENGTH — framing checks
    /// (`Content-Length` completeness, truncation) are about the payload, not
    /// about the allocation that holds it.
    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// Append one wire chunk under both bounds.
    ///
    /// The prospective post-append length is computed once and reused by the
    /// ceiling check and the charge, so a hostile frame sequence cannot make
    /// them disagree, and [`prospective_retained_len`] saturates rather than
    /// wrapping so an impossible length fails every finite ceiling.
    pub(crate) fn append(&mut self, chunk: &[u8]) -> Result<(), RetainRejection> {
        if chunk.is_empty() {
            return Ok(());
        }
        let prospective = prospective_retained_len(self.data.len(), chunk.len());
        if prospective > self.ceiling {
            return Err(RetainRejection::TooLarge);
        }
        if prospective > self.data.capacity() {
            let target = growth_target(self.data.capacity(), prospective, self.ceiling);
            // Charge first: the reservation covers the capacity that is about to
            // be requested, so an exhausted budget refuses INSTEAD of allocating.
            if !self.charge(target) {
                return Err(RetainRejection::BudgetExhausted);
            }
            // `reserve_exact` asks for exactly `target`, so `Vec`'s own doubling
            // never picks a capacity this module did not charge.
            self.data.reserve_exact(target - self.data.len());
            // The allocator is still free to hand back more than it was asked
            // for. Top up immediately; a refusal drops the whole collector,
            // buffer included, rather than continuing under-charged.
            if !self.charge(self.data.capacity()) {
                return Err(RetainRejection::BudgetExhausted);
            }
        }
        self.data.extend_from_slice(chunk);
        Ok(())
    }

    /// Publish the collected body, moving the charge into the returned handle.
    ///
    /// `None` only when the held charge does not cover the final capacity, which
    /// the invariant above excludes; it is still checked, because publishing is
    /// the last point at which under-charged bytes can be stopped.
    #[must_use]
    pub(crate) fn into_charged_bytes(self) -> Option<Bytes> {
        charged_bytes(self.data, self.reservation)
    }
}

/// A budget window reserved BEFORE a producer this module does not control
/// allocates into it.
///
/// A plugin that rewrites a buffered response — `response_transformer`, a
/// provider normalizer, the gRPC-Web trailer reframer — allocates its output
/// itself and hands the gateway a finished `Vec`. Charging that `Vec` on arrival
/// is charging AFTER the allocation: under concurrency, arbitrarily many
/// attacker-shaped transform outputs can exist at once with nothing bounding
/// their sum, which would make the aggregate cap untrue for exactly the
/// allocations most under a client's influence.
///
/// So the window is reserved first, sized to the per-response retained ceiling —
/// the same real, finite, operator-configured upper bound the collector already
/// enforces on a backend body. The producer then runs INSIDE that reservation,
/// and [`Self::charge`] transfers the blocks that cover the finished allocation
/// out of the window and into the owner that will hold them for its lifetime
/// ([`ResponseBufferReservation::split_charge`] — a transfer, never a second
/// acquisition). An output larger than the window is refused, which is the same
/// answer the collector gives a backend body above the ceiling.
///
/// The arithmetic is deliberately visible to operators: while a producer runs,
/// the body it is reading from is still charged AND a full ceiling-sized window
/// is reserved, so a maximum-size response being rewritten peaks at TWO
/// ceilings. The gateway therefore admits about
/// `FERRUM_RESPONSE_BUFFER_MAX_TOTAL_BYTES / (2 × FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES)`
/// concurrent maximum-size rewrites and refuses the rest with the neutral
/// capacity terminal. Lowering the per-response ceiling or raising the aggregate
/// budget widens that; there is no configuration in which the window is skipped
/// for a chain that can produce, because skipping it is the resource gap. A
/// chain with no declared producer opens no window at all and costs one ceiling.
///
/// The window is a PRECONDITION of every producer invocation, not a running
/// balance. After a replacement is charged out of it the window is short, and it
/// is refilled only once the caller has installed the replacement (dropping the
/// previous body's charge). [`Self::ensure_covering_window`] is what the caller
/// must succeed on before invoking the next producer; when it fails the caller
/// installs the neutral capacity terminal instead of calling the producer, so no
/// producer ever allocates under a partial window.
pub(crate) struct ResponseTransformWindow<'a> {
    budget: BudgetRef<'a>,
    window_bytes: usize,
    reservation: ResponseBufferReservation,
}

impl ResponseTransformWindow<'static> {
    /// Open a window against the process-global budget. `effective_limit` is the
    /// already-folded strictest active response-body limit; `0` folds to the
    /// fail-closed fallback exactly as [`buffered_response_body_ceiling`] does.
    ///
    /// `None` means the budget cannot admit the window, and the caller must fail
    /// closed with the neutral capacity terminal BEFORE letting the producer
    /// allocate.
    #[must_use]
    pub(crate) fn open(effective_limit: usize) -> Option<Self> {
        Self::open_in(BudgetRef::global(), effective_limit)
    }
}

impl<'a> ResponseTransformWindow<'a> {
    #[must_use]
    pub(crate) fn open_in(budget: BudgetRef<'a>, effective_limit: usize) -> Option<Self> {
        let window_bytes = budget.resolve().ceiling(effective_limit);
        let mut reservation = ResponseBufferReservation::new();
        if !reservation.reserve_in(budget, window_bytes) {
            return None;
        }
        Some(Self {
            budget,
            window_bytes,
            reservation,
        })
    }

    /// A bounded sink for the NEXT producer's output, sized to this window.
    ///
    /// Handing the producer a sink rather than letting it return an arbitrary
    /// `Vec` is what makes an over-ceiling output impossible to *materialise*
    /// rather than merely impossible to install: the sink refuses the write that
    /// would carry the buffer past the ceiling, so the larger allocation is
    /// never requested from the allocator in the first place.
    #[allow(dead_code)] // reached via `_test_support` from the external test crate
    pub(crate) fn sink(&self) -> BoundedResponseBodySink {
        BoundedResponseBodySink::with_ceiling(self.window_bytes)
    }

    /// Re-establish a FULL covering window, and report whether it is now full.
    ///
    /// Callers must succeed on this immediately before every producer
    /// invocation, and must only call it once the previously replaced body has
    /// actually been installed/dropped — refilling while the old body is alive
    /// would charge the same bytes twice and make the aggregate cap untrue in
    /// the other direction. A `false` means the budget cannot currently cover a
    /// full window, and the caller must install the neutral capacity terminal
    /// instead of running the producer.
    #[must_use]
    pub(crate) fn ensure_covering_window(&mut self) -> bool {
        let budget = self.budget;
        self.reservation.reserve_in(budget, self.window_bytes)
    }

    /// Transfer the blocks covering `data` out of the window and publish it.
    ///
    /// `None` when the finished allocation does not fit the window — the
    /// producer overran the per-response retained ceiling — or when its capacity
    /// is not covered at publication. Either way the caller must fail closed;
    /// `data` is dropped here rather than retained uncharged.
    ///
    /// This deliberately does NOT refill the window. The body being replaced is
    /// still alive at this point (the caller installs the return value over it),
    /// so a refill here would hold the old body's blocks and a fresh full window
    /// at the same time. [`Self::ensure_covering_window`] is the refill, and it
    /// runs after the install and before the next producer.
    #[must_use]
    pub(crate) fn charge(&mut self, data: Vec<u8>) -> Option<Bytes> {
        if data.is_empty() {
            return Some(Bytes::new());
        }
        let carved = self.reservation.split_charge(data.capacity())?;
        charged_bytes(data, carved)
    }

    /// Bytes still available in the window. Diagnostics and external tests only.
    #[allow(dead_code)]
    pub(crate) fn available_bytes(&self) -> usize {
        self.reservation.reserved_bytes()
    }

    /// The full window size, i.e. this response's retained ceiling.
    #[allow(dead_code)]
    pub(crate) fn window_bytes(&self) -> usize {
        self.window_bytes
    }
}

/// A replacement-body buffer that cannot grow past a per-response ceiling.
///
/// Every retained allocation on the collector side is charged before it exists.
/// A plugin-produced replacement cannot be charged that way — the plugin, not
/// this module, decides how many bytes to write — so the bound is enforced on
/// the construction side instead: the sink refuses the write that would take the
/// buffer past `ceiling` and never asks the allocator for that capacity. A
/// producer that overruns therefore fails DURING construction, with only the
/// bytes it had already written resident, instead of materialising an oversized
/// `Vec` that is rejected after the fact.
///
/// Growth reuses the collector's [`growth_target`], clamped to the ceiling, so
/// the buffer stays amortised `O(n)` without doubling past the bound. The only
/// residual slack is the allocator's right to return more than `reserve_exact`
/// asked for; when that happens the sink immediately sticky-overflows and
/// releases its partial allocation, so a producer that holds the sink across
/// awaits cannot retain over-ceiling capacity before publication. The window's
/// [`ResponseTransformWindow::charge`] remains a second gate that refuses to
/// install an allocation whose real capacity its blocks do not cover.
pub(crate) struct BoundedResponseBodySink {
    ceiling: usize,
    data: Vec<u8>,
    overflowed: bool,
}

impl BoundedResponseBodySink {
    pub(crate) fn with_ceiling(ceiling: usize) -> Self {
        Self {
            ceiling,
            data: Vec::new(),
            overflowed: false,
        }
    }

    pub(crate) fn ceiling(&self) -> usize {
        self.ceiling
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// Resident allocation capacity currently held by the sink.
    ///
    /// External tests observe this so they can pin that a successful write never
    /// leaves `capacity() > ceiling()`, without inventing allocator assumptions
    /// about when `reserve_exact` over-returns.
    #[allow(dead_code)] // reached via `_test_support` from the external test crate
    pub(crate) fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Whether a write has already been refused. Once set, the buffer is
    /// released and every later write is refused too, so a producer that ignores
    /// a `false` cannot accumulate anything further.
    pub(crate) fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// After `reserve_exact`, refuse immediately if the allocator reported more
    /// capacity than this sink's admitted ceiling. Sticky-overflow and release
    /// the partial allocation so the over-ceiling bytes cannot outlive the
    /// current write — including across a producer await before publication.
    fn refuse_if_capacity_exceeds_ceiling(&mut self) -> bool {
        if self.data.capacity() > self.ceiling {
            self.overflowed = true;
            self.data = Vec::new();
            return false;
        }
        true
    }

    /// Append `bytes`, or refuse. `false` means the ceiling would have been
    /// exceeded and nothing was appended or allocated.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> bool {
        if self.overflowed {
            return false;
        }
        if bytes.is_empty() {
            return true;
        }
        let prospective = prospective_retained_len(self.data.len(), bytes.len());
        if prospective > self.ceiling {
            // Release what was written: the output is refused, so retaining a
            // partial buffer would be resident bytes nobody will ever use.
            self.overflowed = true;
            self.data = Vec::new();
            return false;
        }
        if prospective > self.data.capacity() {
            let target = growth_target(self.data.capacity(), prospective, self.ceiling);
            self.data.reserve_exact(target - self.data.len());
            if !self.refuse_if_capacity_exceeds_ceiling() {
                return false;
            }
        }
        self.data.extend_from_slice(bytes);
        true
    }

    /// Append exactly `additional` bytes written by `fill`, or refuse.
    ///
    /// The `push`/`Write` surfaces cover producers that already hold their bytes.
    /// Some do not: a protobuf message knows its encoded length before it can
    /// produce the bytes, and `prost` needs a `BufMut` to write into. Handing
    /// such a producer its own `Vec` would materialise a complete would-be
    /// replacement beside the sink — exactly the shape this module exists to
    /// stop — so instead the room is checked and reserved FIRST and the producer
    /// writes into the sink's own buffer.
    ///
    /// What `fill` receives is deliberately NOT the sink's `Vec`. A `Vec` is an
    /// auto-growing target: a producer whose declared length disagreed with what
    /// it writes would reallocate past the ceiling first and only be caught by
    /// the length check afterwards, which is the "measure a finished
    /// over-ceiling allocation" shape this module exists to exclude. `fill` gets
    /// a [`bytes::buf::Limit`] over that buffer instead, whose `remaining_mut()`
    /// is exactly `additional`, so the room admitted here is the room the
    /// producer can address. `prost::Message::encode` — the only production
    /// `fill` — checks `remaining_mut()` against `encoded_len()` up front and
    /// returns `EncodeError` rather than writing when it is short, so an
    /// over-declaring producer fails closed instead of growing anything.
    ///
    /// `additional` must be the exact byte count `fill` will write, INCLUDING
    /// zero: a zero-length append still invokes `fill` and still verifies the
    /// resulting length, because "the fill ran and wrote nothing" and "the fill
    /// was never called" are different facts and this seam documents the former.
    /// A `fill` that writes a different length, or fails, is fail-closed: the
    /// sink is marked overflowed and releases what it held, so nothing partial
    /// can be published.
    pub(crate) fn append_with<E>(
        &mut self,
        additional: usize,
        fill: impl FnOnce(&mut bytes::buf::Limit<&mut Vec<u8>>) -> Result<(), E>,
    ) -> bool {
        if self.overflowed {
            return false;
        }
        let prospective = prospective_retained_len(self.data.len(), additional);
        if prospective > self.ceiling {
            self.overflowed = true;
            self.data = Vec::new();
            return false;
        }
        if prospective > self.data.capacity() {
            let target = growth_target(self.data.capacity(), prospective, self.ceiling);
            self.data.reserve_exact(target - self.data.len());
            if !self.refuse_if_capacity_exceeds_ceiling() {
                return false;
            }
        }
        let wrote = {
            use bytes::BufMut;
            let mut limited = (&mut self.data).limit(additional);
            fill(&mut limited).is_ok()
        };
        if !wrote || self.data.len() != prospective {
            // Either the producer failed, or it wrote a length that disagrees
            // with the room it was admitted for. Neither may be published.
            self.overflowed = true;
            self.data = Vec::new();
            return false;
        }
        true
    }

    /// Discard everything written after `len`.
    ///
    /// This only ever SHRINKS, and only for a sink that has not already refused
    /// a write: an overflowed sink released its buffer, so there is nothing left
    /// to roll back to and the refusal must stay sticky. The one caller is a
    /// producer that accumulates across several driver calls and has to abandon
    /// the current call's emission without losing the ones before it
    /// ([`crate::plugins::ai_stream_router`]'s normalized-output bound).
    pub(crate) fn truncate(&mut self, len: usize) {
        if !self.overflowed && len < self.data.len() {
            self.data.truncate(len);
        }
    }

    /// The finished buffer, or `None` when any write was refused.
    #[must_use]
    pub(crate) fn finish(self) -> Option<Vec<u8>> {
        if self.overflowed {
            None
        } else {
            Some(self.data)
        }
    }
}

impl std::io::Write for BoundedResponseBodySink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.push(buf) {
            Ok(buf.len())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "response body replacement exceeds the retained-response ceiling",
            ))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Serialize `value` as JSON into a ceiling-bounded buffer.
///
/// The single materialisation helper for the JSON-producing response
/// transforms. `serde_json::to_vec` would allocate the whole document first and
/// only then be measured; writing THROUGH the sink stops serialization at the
/// ceiling, so an amplifying rewrite is refused while it is being built.
///
/// `None` means the document did not fit (or did not serialize) and the caller
/// must leave the response unchanged / fail closed per its own contract.
#[must_use]
pub(crate) fn bounded_json_vec<T>(value: &T, ceiling: usize) -> Option<Vec<u8>>
where
    T: serde::Serialize + ?Sized,
{
    let mut sink = BoundedResponseBodySink::with_ceiling(ceiling);
    serde_json::to_writer(&mut sink, value).ok()?;
    sink.finish()
}

/// Copy `bytes` into a ceiling-bounded buffer, or refuse.
#[must_use]
pub(crate) fn bounded_vec_from(bytes: &[u8], ceiling: usize) -> Option<Vec<u8>> {
    let mut sink = BoundedResponseBodySink::with_ceiling(ceiling);
    if !sink.push(bytes) {
        return None;
    }
    sink.finish()
}

/// An isolated budget with the same construction, clamping, reservation, and
/// charge-attachment code the process-global one uses.
///
/// External tests need to observe admission and release deterministically,
/// which a shared process-global semaphore cannot offer under a parallel test
/// binary. This is the *same* [`Budget`] type and the *same* reservation path —
/// only the semaphore differs — so a test cannot pass against a parallel
/// implementation of the rules.
pub(crate) struct IsolatedBudget(Budget);

/// External tests bind this through [`crate::_test_support::ResponseBufferBudgetProbe`];
/// the separately compiled binary unit has no caller.
#[allow(dead_code)]
impl IsolatedBudget {
    pub(crate) fn new(fallback_per_response_bytes: usize, total_bytes: usize) -> Self {
        Self(Budget::new(fallback_per_response_bytes, total_bytes))
    }

    /// Currently unreserved capacity, in bytes.
    pub(crate) fn available_bytes(&self) -> usize {
        self.0.permits.available_permits() * RESERVATION_UNIT_BYTES
    }

    /// Bind this budget where production binds [`BudgetRef::global`], so a test
    /// drives the *same* admission code against an isolated semaphore.
    #[allow(dead_code)]
    pub(crate) fn handle(&self) -> BudgetRef<'_> {
        BudgetRef(Some(&self.0))
    }

    pub(crate) fn buffered_response_body_ceiling(&self, effective_limit: usize) -> usize {
        self.0.ceiling(effective_limit)
    }

    /// Reserve `bytes` before allocating them, exactly as the H3 / gRPC
    /// preallocation sites do.
    pub(crate) fn try_reserve(&self, bytes: usize) -> Option<ResponseBufferReservation> {
        let mut reservation = ResponseBufferReservation::new();
        let admitted = reservation.reserve_against(&self.0, bytes);
        if admitted { Some(reservation) } else { None }
    }

    /// Grow an existing reservation, exactly as a collector does per chunk.
    pub(crate) fn grow(&self, reservation: &mut ResponseBufferReservation, bytes: usize) -> bool {
        reservation.reserve_against(&self.0, bytes)
    }

    /// Charge an allocation by its CAPACITY and publish it, exactly as the
    /// transform window does once its producer has finished.
    pub(crate) fn charge_retained_body(&self, data: Vec<u8>) -> Option<Bytes> {
        charge_owned_allocation_against(&self.0, data)
    }

    /// The PRODUCTION growing collector, bound to this isolated budget: same
    /// ceiling folding, same charge-before-allocate growth, same publication
    /// gate.
    pub(crate) fn collector(&self, effective_limit: usize) -> ChargedBodyCollector<'_> {
        ChargedBodyCollector::new(self.handle(), self.0.ceiling(effective_limit))
    }

    /// The same collector with the preallocation hint the native-H3 and gRPC
    /// sites pass.
    pub(crate) fn collector_with_preallocation(
        &self,
        effective_limit: usize,
        hint: usize,
    ) -> Result<ChargedBodyCollector<'_>, RetainRejection> {
        ChargedBodyCollector::with_preallocation(
            self.handle(),
            self.0.ceiling(effective_limit),
            hint,
        )
    }

    /// The PRODUCTION pre-allocation window a plugin-produced replacement body
    /// is charged out of.
    pub(crate) fn transform_window(
        &self,
        effective_limit: usize,
    ) -> Option<ResponseTransformWindow<'_>> {
        ResponseTransformWindow::open_in(self.handle(), effective_limit)
    }

    /// Charge a copy that outlives the request that produced it, exactly as the
    /// `response_caching` entry store does.
    pub(crate) fn charge_retained_copy(&self, data: &[u8]) -> Option<Bytes> {
        charge_retained_copy_against(&self.0, data)
    }
}

/// Blocks a degenerate configuration would leave available, for external tests.
/// Exercises the same clamp production uses without touching the process-global
/// budget.
#[allow(dead_code)]
pub(crate) fn available_blocks_for_config(
    fallback_per_response_bytes: usize,
    total_bytes: usize,
) -> usize {
    Budget::new(fallback_per_response_bytes, total_bytes)
        .permits
        .available_permits()
}
