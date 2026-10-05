//! Admission primitives for the approved rejection preparation contract.
//!
//! These types do not invoke a plugin, evaluate a trigger, allocate a body, or
//! establish that an operation is raw-free. Runtime enrollment must additionally
//! supply the reviewed typed operation and retire every caller-owned raw view.
//! The existing terminal runners have not yet migrated to these primitives.

use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const PROCESS_BYTES: usize = 128 * 1024 * 1024;
pub const REQUEST_TICKETS: usize = 1024;
pub const CONTROL_BYTES: usize = 2 * 1024 * 1024;
pub const WORKSPACE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PARTICIPANTS: usize = 64;
pub const ROOT_BYTES: usize = 4096;
pub const SLOT_BYTES: usize = 256;
pub const WRAPPER_BYTES: usize = 512;
pub const CARRIER_BYTES: usize = 128 * 1024;
pub const CARRIER_OWNED_BYTES: usize = 98_304;
pub const CARRIER_OVERHEAD_BYTES: usize = 32_768;
pub const MAX_FIELD_OCCURRENCES: usize = 256;
pub const MAX_FIELD_NAME_BYTES: usize = 256;
pub const MAX_FIELD_VALUE_BYTES: usize = 16_384;
pub const MAX_PATCH_ACTIONS: usize = 64;
pub const MAX_RATE_KEY_BYTES: usize = 8192;
pub const MAX_REDIS_PREFIX_BYTES: usize = 512;
pub const MAX_REDIS_WIRE_KEY_BYTES: usize = 26_624;
pub const MAX_COOKIE_BYTES: usize = 16_384;
pub const DETACHED_SUMMARY_BYTES: usize = 2048;
pub const EMERGENCY_BYTES: usize = 4096;
pub const CAPACITY_MESSAGE: &str = "Rejection preparation capacity exceeded";
pub const CAPACITY_HTTP_BODY: &[u8] = br#"{"error":"Rejection preparation capacity exceeded"}"#;

const PAGE_BYTES: usize = 4096;
const TICKET_SHIFT: u32 = 32;
const BYTE_MASK: u64 = u32::MAX as u64;

/// Process-local identity of an actual configured instance, never its name or
/// chain position. The cache supplying a manifest owns generation pinning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalInstanceToken(pub u64);

/// Preparation dependencies are closed facts, not arbitrary metadata keys.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TerminalFacts(u16);

impl TerminalFacts {
    pub const NONE: Self = Self(0);
    pub const BODY: Self = Self(1 << 0);
    pub const METHOD: Self = Self(1 << 1);
    pub const REQUEST_HEADERS: Self = Self(1 << 2);
    pub const IDENTITY: Self = Self(1 << 3);
    pub const PATH: Self = Self(1 << 4);
    pub const ENROLLMENT: Self = Self(1 << 5);
    pub const TRIGGER: Self = Self(1 << 6);
    pub const PROVIDER_USAGE: Self = Self(1 << 7);
    pub const RESPONSE_STATUS: Self = Self(1 << 8);
    pub const RESPONSE_HEADERS: Self = Self(1 << 9);
    pub const ACCOUNTING: Self = Self(1 << 10);
    pub const TELEMETRY: Self = Self(1 << 11);

    const PREPARATION_ONLY: Self = Self((1 << 8) - 1);
    const RESPONSE: Self = Self((1 << 8) | (1 << 9));

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

/// Maximum total allocated capacities and overhead of one prepared operation.
/// Audit records and replacement bodies require their separate existing leases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalBounds {
    pub control: usize,
    pub output: usize,
    pub workspace: usize,
}

impl TerminalBounds {
    pub const PURE_NOOP: Self = Self {
        control: 256,
        output: 0,
        workspace: 0,
    };

    pub const CUSTOM_STARTER: Self = Self {
        control: 131_072,
        output: 65_536,
        workspace: 0,
    };
}

/// Explicit declaration of the actual implementation. A declaration is not
/// permission to call the old async hook through an adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TerminalDeclaration {
    #[default]
    Undeclared,
    PureNoop,
    Prepared {
        bounds: TerminalBounds,
        prep_reads: TerminalFacts,
        prep_writes: TerminalFacts,
        trigger_reads: TerminalFacts,
        cursor_writes: TerminalFacts,
    },
}

/// Potential R/C enrollment, computed from the actual protocol-filtered chain.
/// A default-false reject gate does not exempt a charged-terminal non-replacer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalEligibility {
    pub rejection: bool,
    pub charged: bool,
}

impl TerminalEligibility {
    pub const fn participates(self) -> bool {
        self.rejection || self.charged
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalRefusal {
    Undeclared,
    DuplicateInstance,
    TooManyParticipants,
    ArithmeticOverflow,
    ControlCapacity,
    WorkspaceCapacity,
    ResponseReadDuringPreparation,
    PreparationWriteAfterSuspension,
    CursorDependency,
    ProcessCapacity,
    TicketCapacity,
    WorkspaceAlreadyBorrowed,
    UnroundedReservation,
}

/// Fixed reasons and numeric counts only; no request values or provider errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalAdmissionError {
    pub reason: TerminalRefusal,
    pub instance: Option<TerminalInstanceToken>,
    pub required: usize,
    pub allowed: usize,
}

impl TerminalAdmissionError {
    fn new(reason: TerminalRefusal, required: usize, allowed: usize) -> Self {
        Self {
            reason,
            instance: None,
            required,
            allowed,
        }
    }

    fn at(mut self, instance: TerminalInstanceToken) -> Self {
        self.instance = Some(instance);
        self
    }
}

impl fmt::Display for TerminalAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "terminal preparation {:?}: instance {:?}, required {} bytes/count, allowed {}",
            self.reason, self.instance, self.required, self.allowed
        )
    }
}

impl std::error::Error for TerminalAdmissionError {}

#[derive(Clone, Copy, Debug)]
pub struct TerminalManifestEntry {
    pub instance: TerminalInstanceToken,
    pub declaration: TerminalDeclaration,
    pub eligibility: TerminalEligibility,
    /// One wrapper allowance for this effective instance, not another slot.
    pub wrapped: bool,
}

/// Generation-owned, fixed-capacity manifest. Building it performs neither
/// trigger evaluation nor per-request staging allocation.
#[derive(Clone, Debug)]
pub struct TerminalManifest {
    entries: [Option<TerminalManifestEntry>; MAX_PARTICIPANTS],
    len: usize,
    unrounded_control: usize,
    control: usize,
    workspace: usize,
    earlier_cursor_writes: TerminalFacts,
    refusal: Option<TerminalAdmissionError>,
}

impl Default for TerminalManifest {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalManifest {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_PARTICIPANTS],
            len: 0,
            unrounded_control: ROOT_BYTES + CARRIER_BYTES,
            control: 0,
            workspace: 0,
            earlier_cursor_writes: TerminalFacts::NONE,
            refusal: None,
        }
    }

    /// Add in effective priority order. Validate before modifying the candidate
    /// so a failed add leaves its prefix intact for diagnostics. Latch refusal:
    /// the rejected candidate cannot subsequently admit its weakened prefix.
    pub fn push(&mut self, entry: TerminalManifestEntry) -> Result<(), TerminalAdmissionError> {
        if let Some(error) = self.refusal {
            return Err(error);
        }
        let result = self.try_push(entry);
        if let Err(error) = result {
            self.refusal = Some(error);
        }
        result
    }

    fn try_push(&mut self, entry: TerminalManifestEntry) -> Result<(), TerminalAdmissionError> {
        if !entry.eligibility.participates() {
            return Ok(());
        }
        let instance = entry.instance;
        let (bounds, reads, cursor_writes) = match entry.declaration {
            TerminalDeclaration::Undeclared => {
                let error = TerminalAdmissionError::new(TerminalRefusal::Undeclared, 0, 0);
                return Err(error.at(instance));
            }
            TerminalDeclaration::PureNoop => (
                TerminalBounds::PURE_NOOP,
                TerminalFacts::NONE,
                TerminalFacts::NONE,
            ),
            TerminalDeclaration::Prepared {
                bounds,
                prep_reads,
                prep_writes,
                trigger_reads,
                cursor_writes,
            } => {
                let reads = prep_reads.union(trigger_reads);
                if reads.intersects(TerminalFacts::RESPONSE)
                    || prep_writes.intersects(TerminalFacts::RESPONSE)
                {
                    let error = TerminalAdmissionError::new(
                        TerminalRefusal::ResponseReadDuringPreparation,
                        0,
                        0,
                    );
                    return Err(error.at(instance));
                }
                if cursor_writes.intersects(TerminalFacts::PREPARATION_ONLY) {
                    let error = TerminalAdmissionError::new(
                        TerminalRefusal::PreparationWriteAfterSuspension,
                        0,
                        0,
                    );
                    return Err(error.at(instance));
                }
                (bounds, reads, cursor_writes)
            }
        };
        if self.earlier_cursor_writes.intersects(reads) {
            let error = TerminalAdmissionError::new(TerminalRefusal::CursorDependency, 0, 0);
            return Err(error.at(instance));
        }
        if self.entries().any(|previous| previous.instance == instance) {
            let error = TerminalAdmissionError::new(TerminalRefusal::DuplicateInstance, 0, 0);
            return Err(error.at(instance));
        }
        if self.len == MAX_PARTICIPANTS {
            let error = TerminalAdmissionError::new(
                TerminalRefusal::TooManyParticipants,
                self.len + 1,
                MAX_PARTICIPANTS,
            );
            return Err(error.at(instance));
        }
        let overflow = || {
            TerminalAdmissionError::new(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0)
                .at(instance)
        };
        let addition = bounds
            .control
            .checked_add(bounds.output)
            .and_then(|bytes| bytes.checked_add(SLOT_BYTES))
            .and_then(|bytes| bytes.checked_add(if entry.wrapped { WRAPPER_BYTES } else { 0 }))
            .ok_or_else(overflow)?;
        let unrounded_control = self
            .unrounded_control
            .checked_add(addition)
            .ok_or_else(overflow)?;
        let control = round_pages(unrounded_control).ok_or_else(overflow)?;
        if control > CONTROL_BYTES {
            let error = TerminalAdmissionError::new(
                TerminalRefusal::ControlCapacity,
                control,
                CONTROL_BYTES,
            );
            return Err(error.at(instance));
        }
        if bounds.workspace > WORKSPACE_BYTES {
            let error = TerminalAdmissionError::new(
                TerminalRefusal::WorkspaceCapacity,
                bounds.workspace,
                WORKSPACE_BYTES,
            );
            return Err(error.at(instance));
        }
        let workspace = round_pages(bounds.workspace).ok_or_else(overflow)?;
        self.entries[self.len] = Some(entry);
        self.len += 1;
        self.unrounded_control = unrounded_control;
        self.control = control;
        self.workspace = self.workspace.max(workspace);
        self.earlier_cursor_writes = self.earlier_cursor_writes.union(cursor_writes);
        Ok(())
    }

    pub fn entries(&self) -> impl Iterator<Item = &TerminalManifestEntry> {
        self.entries[..self.len].iter().filter_map(Option::as_ref)
    }

    pub const fn participant_count(&self) -> usize {
        self.len
    }

    pub const fn control_bytes(&self) -> usize {
        self.control
    }

    pub const fn workspace_bytes(&self) -> usize {
        self.workspace
    }

    /// An empty effective R/C union opens no ticket or selected carrier.
    pub fn admit<'a>(
        &self,
        ledger: &'a PreparationLedger,
    ) -> Result<Option<ControlReservation<'a>>, TerminalAdmissionError> {
        if let Some(error) = self.refusal {
            return Err(error);
        }
        if self.len == 0 {
            return Ok(None);
        }
        ledger.reserve_control(self.control).map(Some)
    }
}

const fn round_pages(bytes: usize) -> Option<usize> {
    match bytes.checked_add(PAGE_BYTES - 1) {
        Some(bytes) => Some(bytes / PAGE_BYTES * PAGE_BYTES),
        None => None,
    }
}

/// Shared across frontends, proxies, generations and detached owners. A single
/// CAS admits bytes and the ticket together, with no partial ticket reservation,
/// waiting queue, plugin call or staged allocation on failure.
pub static PROCESS_PREPARATION_LEDGER: PreparationLedger = PreparationLedger::new();

#[derive(Debug)]
pub struct PreparationLedger {
    // Low 32 bits: reserved bytes. High 32 bits: live request tickets.
    state: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationUsage {
    pub bytes: usize,
    pub tickets: usize,
}

impl Default for PreparationLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl PreparationLedger {
    /// Independent ledgers are useful for deterministic ownership fixtures.
    /// Runtime callers must use `PROCESS_PREPARATION_LEDGER` exclusively.
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }

    pub fn usage(&self) -> PreparationUsage {
        let state = self.state.load(Ordering::Acquire);
        PreparationUsage {
            bytes: (state & BYTE_MASK) as usize,
            tickets: (state >> TICKET_SHIFT) as usize,
        }
    }

    /// Low-level reservation; runtime must pass the pinned manifest's checked
    /// control sum. It reserves credit without eagerly allocating that sum.
    pub fn reserve_control(
        &self,
        bytes: usize,
    ) -> Result<ControlReservation<'_>, TerminalAdmissionError> {
        validate_reservation(bytes, CONTROL_BYTES, TerminalRefusal::ControlCapacity)?;
        if bytes == 0 {
            return Err(TerminalAdmissionError::new(
                TerminalRefusal::ControlCapacity,
                ROOT_BYTES,
                0,
            ));
        }
        self.reserve(bytes, true)?;
        Ok(ControlReservation {
            ledger: self,
            bytes,
            workspace_borrowed: AtomicBool::new(false),
        })
    }

    fn reserve(&self, bytes: usize, ticket: bool) -> Result<(), TerminalAdmissionError> {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            let current_bytes = (current & BYTE_MASK) as usize;
            let current_tickets = (current >> TICKET_SHIFT) as usize;
            let required_bytes = current_bytes.checked_add(bytes).ok_or_else(|| {
                TerminalAdmissionError::new(
                    TerminalRefusal::ArithmeticOverflow,
                    usize::MAX,
                    PROCESS_BYTES,
                )
            })?;
            if required_bytes > PROCESS_BYTES {
                return Err(TerminalAdmissionError::new(
                    TerminalRefusal::ProcessCapacity,
                    required_bytes,
                    PROCESS_BYTES,
                ));
            }
            let required_tickets = current_tickets + usize::from(ticket);
            if required_tickets > REQUEST_TICKETS {
                return Err(TerminalAdmissionError::new(
                    TerminalRefusal::TicketCapacity,
                    required_tickets,
                    REQUEST_TICKETS,
                ));
            }
            let next = required_bytes as u64 | ((required_tickets as u64) << TICKET_SHIFT);
            match self.state.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self, bytes: usize, ticket: bool) {
        // Each reservation has exactly one Drop owner. A workspace borrows its
        // control owner, so the ticket cannot die before its top-up is returned.
        let released = bytes as u64 | (u64::from(ticket) << TICKET_SHIFT);
        self.state.fetch_sub(released, Ordering::AcqRel);
    }
}

fn validate_reservation(
    bytes: usize,
    limit: usize,
    reason: TerminalRefusal,
) -> Result<(), TerminalAdmissionError> {
    if bytes > limit {
        return Err(TerminalAdmissionError::new(reason, bytes, limit));
    }
    if !bytes.is_multiple_of(PAGE_BYTES) {
        return Err(TerminalAdmissionError::new(
            TerminalRefusal::UnroundedReservation,
            bytes,
            PAGE_BYTES,
        ));
    }
    Ok(())
}

/// One request ticket. Share this owner with `Arc`, rather than acquiring again
/// on clone, retry or detached handoff. The last owner returns both resources.
#[derive(Debug)]
pub struct ControlReservation<'a> {
    ledger: &'a PreparationLedger,
    bytes: usize,
    workspace_borrowed: AtomicBool,
}

impl<'a> ControlReservation<'a> {
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// At most one synchronous workspace interval per request. Drop this lease
    /// before every terminal await; scratch surviving suspension is C/O state.
    pub fn workspace(
        &self,
        bytes: usize,
    ) -> Result<WorkspaceReservation<'_, 'a>, TerminalAdmissionError> {
        validate_reservation(bytes, WORKSPACE_BYTES, TerminalRefusal::WorkspaceCapacity)?;
        if self
            .workspace_borrowed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(TerminalAdmissionError::new(
                TerminalRefusal::WorkspaceAlreadyBorrowed,
                bytes,
                0,
            ));
        }
        if let Err(error) = self.ledger.reserve(bytes, false) {
            self.workspace_borrowed.store(false, Ordering::Release);
            return Err(error);
        }
        Ok(WorkspaceReservation {
            control: self,
            bytes,
            _synchronous: PhantomData,
        })
    }
}

impl Drop for ControlReservation<'_> {
    fn drop(&mut self) {
        self.ledger.release(self.bytes, true);
    }
}

#[derive(Debug)]
pub struct WorkspaceReservation<'a, 'b> {
    control: &'a ControlReservation<'b>,
    bytes: usize,
    // Scratch credit cannot move into a Send terminal/detached future. The
    // driver must also end the interval before any same-thread suspension.
    _synchronous: PhantomData<Rc<()>>,
}

impl WorkspaceReservation<'_, '_> {
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for WorkspaceReservation<'_, '_> {
    fn drop(&mut self) {
        self.control.ledger.release(self.bytes, false);
        self.control.workspace_borrowed.store(false, Ordering::Release);
    }
}
