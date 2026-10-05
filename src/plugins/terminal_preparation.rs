//! Admission primitives for the approved rejection preparation contract.
//!
//! Generation manifests and one process ledger bound the synchronous prepared
//! boundary. Only closed immediate operations are currently implemented.
//! Unmigrated participants are refused; an ordinary async successful-response
//! hook is never used as a terminal adapter. Full qualification remains pending.

use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::terminal_storage::{
    AllocationBlock, AllocationPlan, FixedSlots, SharedTerminal, TerminalTicket,
};

mod carrier;
pub use carrier::SelectedTerminalCarrier;

#[derive(Clone, Debug)]
pub struct TerminalGeneration(Option<SharedTerminal<TerminalManifest>>);

impl std::ops::Deref for TerminalGeneration {
    type Target = TerminalManifest;

    fn deref(&self) -> &TerminalManifest {
        static EMPTY: TerminalManifest = TerminalManifest::new();
        self.0.as_deref().unwrap_or(&EMPTY)
    }
}

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
    UnimplementedOperation,
    FieldCapacity,
    PatchCapacity,
    AuthorizationExpired,
    AlreadyPrepared,
    PinnedGeneration,
    AllocatorUnavailable,
    AllocationFailure,
    EntropyUnavailable,
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
    pub fn new(reason: TerminalRefusal, required: usize, allowed: usize) -> Self {
        Self {
            reason,
            instance: None,
            required,
            allowed,
        }
    }

    pub fn at(mut self, instance: TerminalInstanceToken) -> Self {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalManifestEntry {
    pub instance: TerminalInstanceToken,
    pub declaration: TerminalDeclaration,
    pub eligibility: TerminalEligibility,
    /// One wrapper allowance for this effective instance, not another slot.
    pub wrapped: bool,
}

/// Generation-owned, exactly sized manifest. Building it performs neither
/// trigger evaluation nor per-request staging allocation.
pub struct TerminalManifest {
    entries: Option<FixedSlots<TerminalManifestEntry>>,
    source_chain: Option<FixedSlots<std::sync::Arc<dyn super::Plugin>>>,
    sources: Option<FixedSlots<std::sync::Arc<dyn super::Plugin>>>,
    len: usize,
    unrounded_control: usize,
    control: usize,
    workspace: usize,
    earlier_cursor_writes: TerminalFacts,
    refusal: Option<TerminalAdmissionError>,
}

impl fmt::Debug for TerminalManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TerminalManifest")
            .field("entries", &self.entries)
            .field("control", &self.control)
            .field("workspace", &self.workspace)
            .field("refusal", &self.refusal)
            .finish()
    }
}

impl Default for TerminalManifest {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalManifest {
    /// Pin an already compiled generation before request lifecycle/body work.
    /// Custom runtimes must use the same actual plugin chain at preparation.
    pub fn pin(
        self: &std::sync::Arc<Self>,
        ctx: &mut super::RequestContext,
    ) -> Result<(), TerminalAdmissionError> {
        // The public Arc convenience entry is copied into charged generation
        // storage. Runtime cache handles already use TerminalGeneration.
        ctx.pin_terminal_manifest(self.try_clone()?.into_generation()?)
    }

    fn matches_plugins(&self, plugins: &[std::sync::Arc<dyn super::Plugin>]) -> bool {
        let Some(chain) = &self.source_chain else {
            return self.len == 0 && plugins.is_empty();
        };
        chain.as_slice().len() == plugins.len()
            && chain
                .as_slice()
                .iter()
                .zip(plugins)
                .all(|(pinned, plugin)| std::sync::Arc::ptr_eq(pinned, plugin))
    }

    pub const fn new() -> Self {
        Self {
            entries: None,
            source_chain: None,
            sources: None,
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
        // Candidate and old allocations coexist until the new prefix is
        // complete. Each backing obtains process credit before construction;
        // a rejected candidate leaves the old pinned generation untouched.
        let mut entries = FixedSlots::generation(self.len + 1, &PROCESS_PREPARATION_LEDGER)?;
        for previous in self.entries() {
            entries.push(*previous)?;
        }
        entries.push(entry)?;
        self.entries = Some(entries);
        self.len += 1;
        self.unrounded_control = unrounded_control;
        self.control = control;
        self.workspace = self.workspace.max(workspace);
        self.earlier_cursor_writes = self.earlier_cursor_writes.union(cursor_writes);
        Ok(())
    }

    pub fn entries(&self) -> impl Iterator<Item = &TerminalManifestEntry> {
        self.entries
            .as_ref()
            .map_or(&[][..], FixedSlots::as_slice)
            .iter()
    }

    fn try_clone(&self) -> Result<Self, TerminalAdmissionError> {
        let mut cloned = Self::new();
        for entry in self.entries() {
            cloned.push(*entry)?;
        }
        for (target, source) in [
            (&mut cloned.source_chain, &self.source_chain),
            (&mut cloned.sources, &self.sources),
        ] {
            if let Some(source) = source {
                let mut slots = FixedSlots::generation(
                    source.as_slice().len(),
                    &PROCESS_PREPARATION_LEDGER,
                )?;
                for plugin in source.as_slice() {
                    slots.push(std::sync::Arc::clone(plugin))?;
                }
                *target = Some(slots);
            }
        }
        cloned.refusal = self.refusal;
        Ok(cloned)
    }

    pub(crate) fn into_generation(self) -> Result<TerminalGeneration, TerminalAdmissionError> {
        if self.len == 0
            && self.refusal.is_none()
            && self
                .source_chain
                .as_ref()
                .is_none_or(|chain| chain.as_slice().is_empty())
        {
            return Ok(TerminalGeneration(None));
        }
        SharedTerminal::generation(self, &PROCESS_PREPARATION_LEDGER)
            .map(|owner| TerminalGeneration(Some(owner)))
    }

    pub(crate) fn admission_refusal(&self) -> Option<TerminalAdmissionError> {
        self.refusal
    }

    pub fn same_chain(&self, other: &Self) -> bool {
        self.len == other.len && self.entries().eq(other.entries())
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

pub(crate) fn empty_terminal_generation() -> Result<TerminalGeneration, TerminalAdmissionError> {
    Ok(TerminalGeneration(None))
}

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
            terminal_prepared: AtomicBool::new(false),
            allocated_backing: AtomicUsize::new(0),
            field_epoch: AtomicU64::new(1),
        })
    }

    pub fn reserve_owned(
        &'static self,
        bytes: usize,
    ) -> Result<TerminalTicket, TerminalAdmissionError> {
        TerminalTicket::new_ticket(self.reserve_control(bytes)?)
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

    pub(crate) fn reserve_backing(&self, bytes: usize) -> Result<(), TerminalAdmissionError> {
        self.reserve(bytes, false)
    }

    pub(crate) fn release_backing(&self, bytes: usize) {
        self.release(bytes, false);
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

mod workspace_value {
    pub trait Sealed {}

    impl Sealed for () {}
    impl Sealed for bool {}
    impl Sealed for u64 {}
    impl<const N: usize> Sealed for [u8; N] {}
}

/// Only closed, allocation-free values can cross a workspace interval. Parser
/// trees, references, closures and futures cannot implement this sealed trait.
pub trait WorkspaceValue: workspace_value::Sealed {}

impl WorkspaceValue for () {}
impl WorkspaceValue for bool {}
impl WorkspaceValue for u64 {}
impl<const N: usize> WorkspaceValue for [u8; N] {}

/// One request ticket. Share this owner with `TerminalTicket`, rather than acquiring again
/// on clone, retry or detached handoff. The last owner returns both resources.
#[derive(Debug)]
pub struct ControlReservation<'a> {
    ledger: &'a PreparationLedger,
    bytes: usize,
    workspace_borrowed: AtomicBool,
    terminal_prepared: AtomicBool,
    allocated_backing: AtomicUsize,
    field_epoch: AtomicU64,
}

impl<'a> ControlReservation<'a> {
    fn next_field_epoch(&self) -> Result<u64, TerminalAdmissionError> {
        self.field_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))
    }

    /// Borrow only initialized fixed backing for this synchronous interval.
    /// The higher-ranked borrow cannot appear in R, including a returned
    /// parser/tree/future; backing is freed before its W credit is returned.
    pub fn with_workspace<R: WorkspaceValue>(
        &self,
        bytes: usize,
        use_workspace: impl for<'w> FnOnce(&'w mut [u8]) -> Result<R, TerminalAdmissionError>,
    ) -> Result<R, TerminalAdmissionError> {
        if bytes == 0 {
            return use_workspace(&mut []);
        }
        let plan = AllocationPlan::array::<u8>(bytes)?;
        let charged = round_pages(plan.backing_bytes()).ok_or_else(|| {
            capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, WORKSPACE_BYTES)
        })?;
        let lease = self.workspace(charged)?;
        let result = lease.synchronous(bytes, use_workspace);
        drop(lease);
        result
    }

    /// Actual backing inside this request's already admitted C/O/carrier sum.
    /// No allocator is called until this atomic claim succeeds.
    pub(crate) fn reserve_backing(&self, bytes: usize) -> Result<(), TerminalAdmissionError> {
        self.allocated_backing
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.bytes)
            })
            .map(|_| ())
            .map_err(|used| {
                capacity_error(
                    TerminalRefusal::ControlCapacity,
                    used.saturating_add(bytes),
                    self.bytes,
                )
            })
    }

    pub(crate) fn release_backing(&self, bytes: usize) {
        self.allocated_backing.fetch_sub(bytes, Ordering::AcqRel);
    }

    pub fn allocated_backing_bytes(&self) -> usize {
        self.allocated_backing.load(Ordering::Acquire)
    }

    fn claim_preparation(&self) -> Result<(), TerminalAdmissionError> {
        self.terminal_prepared
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| capacity_error(TerminalRefusal::AlreadyPrepared, 1, 0))
    }

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
    fn synchronous<R: WorkspaceValue>(
        &self,
        bytes: usize,
        use_workspace: impl for<'w> FnOnce(&'w mut [u8]) -> Result<R, TerminalAdmissionError>,
    ) -> Result<R, TerminalAdmissionError> {
        let plan = AllocationPlan::array::<u8>(bytes)?;
        if plan.backing_bytes() > self.bytes {
            return Err(capacity_error(
                TerminalRefusal::WorkspaceCapacity,
                plan.backing_bytes(),
                self.bytes,
            ));
        }
        let mut block = AllocationBlock::workspace(plan)?;
        let result = use_workspace(block.bytes_mut());
        drop(block);
        result
    }

    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for WorkspaceReservation<'_, '_> {
    fn drop(&mut self) {
        self.control.ledger.release(self.bytes, false);
        self.control
            .workspace_borrowed
            .store(false, Ordering::Release);
    }
}

/// Only a synchronous borrow may expose request state to terminal preparation.
/// No operation variant below can contain this view, a context, a plugin, a
/// closure, a request body or a collector charge.
pub struct ReachedRequestView<'a> {
    pub context: &'a mut super::RequestContext,
    output_limit: usize,
    control_limit: usize,
    workspace_limit: usize,
    workspace: Option<&'a WorkspaceReservation<'a, 'static>>,
    action_allowed: bool,
    ticket: Option<TerminalTicket>,
    instance: TerminalInstanceToken,
}

impl ReachedRequestView<'_> {
    pub fn with_workspace<R: WorkspaceValue>(
        &self,
        bytes: usize,
        use_workspace: impl for<'w> FnOnce(&'w mut [u8]) -> Result<R, TerminalAdmissionError>,
    ) -> Result<R, TerminalAdmissionError> {
        if bytes > self.workspace_limit {
            return Err(capacity_error(
                TerminalRefusal::WorkspaceCapacity,
                bytes,
                self.workspace_limit,
            ));
        }
        if bytes == 0 {
            return use_workspace(&mut []);
        }
        let required = AllocationPlan::array::<u8>(bytes)?.backing_bytes();
        if required > self.workspace_limit {
            return Err(capacity_error(
                TerminalRefusal::WorkspaceCapacity,
                required,
                self.workspace_limit,
            ));
        }
        self.workspace
            .ok_or_else(|| capacity_error(TerminalRefusal::WorkspaceCapacity, bytes, 0))?
            .synchronous(bytes, use_workspace)
    }

    pub(crate) fn control_patch(
        &self,
        actions: usize,
    ) -> Result<TerminalPatch, TerminalAdmissionError> {
        let ticket = self.ticket.as_ref().ok_or_else(|| {
            capacity_error(TerminalRefusal::PinnedGeneration, 0, 0)
        })?;
        TerminalPatch::new(actions, self.control_limit, ticket, self.instance)
    }

    pub(crate) fn apply_metadata(
        &mut self,
        patch: TerminalPatch,
    ) -> Result<(), TerminalAdmissionError> {
        if self
            .context
            .precommit_response_phase_bound()
            .elapsed_authorization()
            .is_some()
        {
            return Err(capacity_error(TerminalRefusal::AuthorizationExpired, 0, 0));
        }
        apply_terminal_metadata(patch, self.context)
    }

    /// Preparation and response action eligibility are distinct. Capture must
    /// still prepare when this is false; one-shot response actions must not
    /// consume their source state merely because they were suppressed.
    pub const fn action_allowed(&self) -> bool {
        self.action_allowed
    }

    /// Transfer an existing staged cookie only after checking its full capacity
    /// against admitted O credit. The closed wrapper cannot be constructed by
    /// an arbitrary caller with an unchecked String.
    pub fn take_cookie_metadata(
        &mut self,
        key: &str,
    ) -> Result<Option<TerminalCookie>, TerminalAdmissionError> {
        if !self.action_allowed {
            return Ok(None);
        }
        let Some(cookie) = self.context.metadata.get(key) else {
            return Ok(None);
        };
        let allowed = self.output_limit.min(MAX_COOKIE_BYTES);
        if cookie.len() > allowed || cookie.capacity() > allowed {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                cookie.capacity(),
                allowed,
            ));
        }
        if cookie
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t' && byte != b'\n') || byte == 0x7f)
        {
            return Err(capacity_error(TerminalRefusal::FieldCapacity, 0, 0));
        }
        let ticket = self.ticket.as_ref().ok_or_else(|| {
            capacity_error(TerminalRefusal::PinnedGeneration, 0, 0)
        })?;
        let plan = TerminalString::plan(cookie)?;
        if plan.backing_bytes() > allowed {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                plan.backing_bytes(),
                allowed,
            ));
        }
        let lineage = TerminalFieldLineage {
            origin: TerminalFieldOrigin::GatewayInstance(self.instance),
            policy_contribution: false,
            section: TerminalFieldSection::Initial,
            epoch: ticket.next_field_epoch()?,
        };
        let value = TerminalString::copy(cookie, plan, ticket)?;
        // The old staged backing is dropped before this operation can escape.
        self.context.metadata.remove(key);
        Ok(Some(TerminalCookie { value, lineage }))
    }

    /// Construct a patch using only this instance's admitted output credit.
    pub fn patch(&self, actions: usize) -> Result<TerminalPatch, TerminalAdmissionError> {
        let ticket = self.ticket.as_ref().ok_or_else(|| {
            capacity_error(TerminalRefusal::PinnedGeneration, 0, 0)
        })?;
        TerminalPatch::new(actions, self.output_limit, ticket, self.instance)
    }
}

/// Closed terminal actions. External operations require their own reviewed
/// typed variant; arbitrary futures and plugin handles cannot be inserted here.
pub enum PreparedTerminalOp {
    Noop,
    Fields(TerminalPatch),
    EmptyBody,
    Cookie(TerminalCookie),
}

/// Capacity-checked, moved cookie owner; construction is confined to the
/// synchronous admitted view, before any cursor or external poll.
pub struct TerminalCookie {
    value: TerminalString,
    lineage: TerminalFieldLineage,
}

/// Closed results carry response work only. No request-fact or raw metadata
/// patch can be produced after the preparation boundary.
pub enum TerminalResult {
    Noop,
    Fields(TerminalPatch),
    EmptyBody,
    Cookie(TerminalCookie),
}

impl PreparedTerminalOp {
    fn validate(
        &self,
        declaration: TerminalDeclaration,
        ticket: Option<&TerminalTicket>,
        instance: TerminalInstanceToken,
    ) -> Result<(), TerminalAdmissionError> {
        match self {
            Self::Fields(patch)
                if patch.instance != instance
                    || ticket.is_none_or(|ticket| !ticket.ptr_eq(&patch.ticket)) =>
            {
                return Err(capacity_error(TerminalRefusal::PinnedGeneration, 0, 0));
            }
            Self::Cookie(cookie)
                if cookie.lineage.origin != TerminalFieldOrigin::GatewayInstance(instance) =>
            {
                return Err(capacity_error(TerminalRefusal::PinnedGeneration, 0, 0));
            }
            _ => {}
        }
        let output = match declaration {
            TerminalDeclaration::Prepared { bounds, .. } => bounds.output,
            TerminalDeclaration::PureNoop if matches!(self, Self::Noop) => return Ok(()),
            _ => {
                return Err(capacity_error(
                    TerminalRefusal::UnimplementedOperation,
                    0,
                    0,
                ));
            }
        };
        let required = match self {
            Self::Noop | Self::EmptyBody => 0,
            Self::Fields(patch) => patch.owned_bytes,
            Self::Cookie(cookie) => {
                if cookie.value.as_str().len() > MAX_COOKIE_BYTES
                    || cookie.value.block.backing_bytes() > MAX_COOKIE_BYTES
                {
                    return Err(capacity_error(
                        TerminalRefusal::FieldCapacity,
                        cookie.value.block.backing_bytes(),
                        MAX_COOKIE_BYTES,
                    ));
                }
                cookie.value.block.backing_bytes()
            }
        };
        if required > output {
            return Err(capacity_error(
                TerminalRefusal::PatchCapacity,
                required,
                output,
            ));
        }
        Ok(())
    }

    pub fn execute(self) -> TerminalResult {
        match self {
            Self::Noop => TerminalResult::Noop,
            Self::Fields(patch) => TerminalResult::Fields(patch),
            Self::EmptyBody => TerminalResult::EmptyBody,
            Self::Cookie(cookie) => TerminalResult::Cookie(cookie),
        }
    }
}

/// Origin is attached by the producer to each value, before copying it.
/// Renaming a field cannot change origin or manufacture a policy contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalFieldOrigin {
    Backend,
    GatewayCore,
    GatewayInstance(TerminalInstanceToken),
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalFieldSection {
    Initial,
    ApplicationTrailer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalFieldLineage {
    pub origin: TerminalFieldOrigin,
    pub policy_contribution: bool,
    pub section: TerminalFieldSection,
    pub epoch: u64,
}

/// Exact-length copy in a class-sized block. A caller's excess String capacity
/// is never retained by a prepared operation.
struct TerminalString {
    block: AllocationBlock,
}

impl TerminalString {
    fn plan(value: &str) -> Result<AllocationPlan, TerminalAdmissionError> {
        AllocationPlan::array::<u8>(value.len())
    }

    fn copy(
        value: &str,
        plan: AllocationPlan,
        ticket: &TerminalTicket,
    ) -> Result<Self, TerminalAdmissionError> {
        let mut block = AllocationBlock::zeroed_request(plan, ticket)?;
        block.bytes_mut().copy_from_slice(value.as_bytes());
        Ok(Self { block })
    }

    fn as_str(&self) -> &str {
        // SAFETY: construction copies exactly one already validated Rust str;
        // this owner exposes no mutable access to those bytes.
        unsafe { std::str::from_utf8_unchecked(self.block.bytes()) }
    }
}

enum TerminalFieldAction {
    Set {
        name: TerminalString,
        value: TerminalString,
        override_existing: bool,
        case_insensitive: bool,
        lineage: TerminalFieldLineage,
    },
    Remove(TerminalString),
    Metadata {
        name: String,
        value: Option<String>,
    },
}

/// Fixed, allocation-backed actions and exact-length field blocks. Every copy
/// is planned and claimed before allocation. No push can grow the action table.
pub struct TerminalPatch {
    actions: FixedSlots<TerminalFieldAction>,
    action_limit: usize,
    output_limit: usize,
    owned_bytes: usize,
    ticket: TerminalTicket,
    instance: TerminalInstanceToken,
    // Actions (including adopted Strings) drop before their custody/credit.
    metadata_custody: Option<SharedTerminal<TerminalMetadataCustody>>,
}

impl TerminalPatch {
    fn new(
        actions: usize,
        output: usize,
        ticket: &TerminalTicket,
        instance: TerminalInstanceToken,
    ) -> Result<Self, TerminalAdmissionError> {
        if actions > MAX_PATCH_ACTIONS {
            return Err(capacity_error(
                TerminalRefusal::PatchCapacity,
                actions,
                MAX_PATCH_ACTIONS,
            ));
        }
        let required = AllocationPlan::array::<TerminalFieldAction>(actions)?.backing_bytes();
        if required > output {
            return Err(capacity_error(TerminalRefusal::PatchCapacity, required, output));
        }
        Ok(Self {
            actions: FixedSlots::request(actions, ticket)?,
            action_limit: actions,
            output_limit: output,
            owned_bytes: required,
            ticket: ticket.clone(),
            instance,
            metadata_custody: None,
        })
    }

    fn field_plans(
        &self,
        name: &str,
        value: &str,
    ) -> Result<(AllocationPlan, AllocationPlan), TerminalAdmissionError> {
        validate_field(name, value)?;
        self.field_plans_unchecked(name, value)
    }

    fn field_plans_unchecked(
        &self,
        name: &str,
        value: &str,
    ) -> Result<(AllocationPlan, AllocationPlan), TerminalAdmissionError> {
        if name.len() > MAX_FIELD_NAME_BYTES || value.len() > MAX_FIELD_VALUE_BYTES {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                value.len(),
                MAX_FIELD_VALUE_BYTES,
            ));
        }
        if self.actions.as_slice().len() == self.action_limit {
            return Err(capacity_error(
                TerminalRefusal::PatchCapacity,
                self.action_limit + 1,
                self.action_limit,
            ));
        }
        let name_plan = TerminalString::plan(name)?;
        let value_plan = TerminalString::plan(value)?;
        let required = self
            .owned_bytes
            .checked_add(name_plan.backing_bytes())
            .and_then(|bytes| bytes.checked_add(value_plan.backing_bytes()))
            .ok_or_else(|| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
        if required > self.output_limit {
            return Err(capacity_error(
                TerminalRefusal::PatchCapacity,
                required,
                self.output_limit,
            ));
        }
        Ok((name_plan, value_plan))
    }

    pub fn set(
        &mut self,
        name: &str,
        value: &str,
        override_existing: bool,
    ) -> Result<(), TerminalAdmissionError> {
        self.set_field(name, value, override_existing, false)
    }

    pub fn set_policy(
        &mut self,
        name: &str,
        value: &str,
        override_existing: bool,
    ) -> Result<(), TerminalAdmissionError> {
        self.set_field(name, value, override_existing, true)
    }

    fn set_field(
        &mut self,
        name: &str,
        value: &str,
        override_existing: bool,
        case_insensitive: bool,
    ) -> Result<(), TerminalAdmissionError> {
        let (name_plan, value_plan) = self.field_plans(name, value)?;
        let lineage = TerminalFieldLineage {
            origin: TerminalFieldOrigin::GatewayInstance(self.instance),
            policy_contribution: case_insensitive,
            section: TerminalFieldSection::Initial,
            epoch: self.ticket.next_field_epoch()?,
        };
        let name = TerminalString::copy(name, name_plan, &self.ticket)?;
        let value = TerminalString::copy(value, value_plan, &self.ticket)?;
        self.actions.push(TerminalFieldAction::Set {
            name,
            value,
            override_existing,
            case_insensitive,
            lineage,
        })?;
        self.owned_bytes += name_plan.backing_bytes() + value_plan.backing_bytes();
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<(), TerminalAdmissionError> {
        let (plan, _) = self.field_plans(name, "")?;
        let name = TerminalString::copy(name, plan, &self.ticket)?;
        self.actions.push(TerminalFieldAction::Remove(name))?;
        self.owned_bytes += plan.backing_bytes();
        Ok(())
    }

    pub(crate) fn set_metadata(
        &mut self,
        name: &str,
        value: &str,
    ) -> Result<(), TerminalAdmissionError> {
        let (name_plan, value_plan) = self.field_plans_unchecked(name, value)?;
        let lineage = TerminalFieldLineage {
            origin: TerminalFieldOrigin::GatewayInstance(self.instance),
            policy_contribution: false,
            section: TerminalFieldSection::Initial,
            epoch: self.ticket.next_field_epoch()?,
        };
        let name = TerminalString::copy(name, name_plan, &self.ticket)?;
        let value = TerminalString::copy(value, value_plan, &self.ticket)?;
        self.actions.push(TerminalFieldAction::Set {
            name,
            value,
            override_existing: true,
            case_insensitive: false,
            lineage,
        })?;
        self.owned_bytes += name_plan.backing_bytes() + value_plan.backing_bytes();
        Ok(())
    }

    pub(crate) fn metadata_get(&self, key: &str) -> Option<Option<&str>> {
        self.actions
            .as_slice()
            .iter()
            .rev()
            .find_map(|action| match action {
                TerminalFieldAction::Set { name, value, .. } if name.as_str() == key => {
                    Some(Some(value.as_str()))
                }
                TerminalFieldAction::Remove(name) if name.as_str() == key => Some(None),
                _ => None,
            })
    }

    pub(crate) fn merge_metadata_names(
        &mut self,
        key: &str,
        existing: &str,
        marker: &str,
    ) -> Result<(), TerminalAdmissionError> {
        let mut length = existing.len();
        let mut count = if existing.is_empty() {
            0
        } else {
            existing.split(',').count()
        };
        for name in marker.split(',') {
            if !existing.split(',').any(|old| old == name) {
                length = length
                    .checked_add(name.len() + usize::from(length != 0))
                    .ok_or_else(|| {
                        capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0)
                    })?;
                count += 1;
            }
        }
        if count > 32 || length > 32 * 128 + 31 {
            return Err(capacity_error(
                TerminalRefusal::ControlCapacity,
                length,
                32 * 128 + 31,
            ));
        }
        let name_plan = TerminalString::plan(key)?;
        let value_plan = AllocationPlan::array::<u8>(length)?;
        let required = self
            .owned_bytes
            .saturating_add(name_plan.backing_bytes())
            .saturating_add(value_plan.backing_bytes());
        if self.actions.as_slice().len() == self.action_limit || required > self.output_limit {
            return Err(capacity_error(
                TerminalRefusal::ControlCapacity,
                required,
                self.output_limit,
            ));
        }
        let lineage = TerminalFieldLineage {
            origin: TerminalFieldOrigin::GatewayInstance(self.instance),
            policy_contribution: false,
            section: TerminalFieldSection::Initial,
            epoch: self.ticket.next_field_epoch()?,
        };
        let name = TerminalString::copy(key, name_plan, &self.ticket)?;
        let mut block = AllocationBlock::zeroed_request(value_plan, &self.ticket)?;
        block.bytes_mut()[..existing.len()].copy_from_slice(existing.as_bytes());
        let mut offset = existing.len();
        for name in marker.split(',') {
            if !existing.split(',').any(|old| old == name) {
                if offset != 0 {
                    block.bytes_mut()[offset] = b',';
                    offset += 1;
                }
                block.bytes_mut()[offset..offset + name.len()].copy_from_slice(name.as_bytes());
                offset += name.len();
            }
        }
        self.actions.push(TerminalFieldAction::Set {
            name,
            value: TerminalString { block },
            override_existing: true,
            case_insensitive: false,
            lineage,
        })?;
        self.owned_bytes = required;
        Ok(())
    }
}

/// Keeps adopted metadata strings charged until their context has dropped its
/// metadata table. A successor keeps the previous custody; no ledger cycle.
pub(crate) struct TerminalMetadataCustody {
    _credit: super::terminal_storage::AllocationCredit,
    _previous: Option<SharedTerminal<TerminalMetadataCustody>>,
}

impl fmt::Debug for TerminalMetadataCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TerminalMetadataCustody")
    }
}

fn apply_terminal_metadata(
    mut patch: TerminalPatch,
    ctx: &mut super::RequestContext,
) -> Result<(), TerminalAdmissionError> {
    use super::terminal_storage::{global_string, global_string_plan, request_credit};

    let mut adopted_bytes = 0usize;
    let mut added_keys = 0usize;
    for (index, action) in patch.actions.as_slice().iter().enumerate() {
        let (name, value) = match action {
            TerminalFieldAction::Set { name, value, .. } => (name.as_str(), value.as_str()),
            TerminalFieldAction::Remove(_) => continue,
            TerminalFieldAction::Metadata { .. } => {
                return Err(capacity_error(TerminalRefusal::AlreadyPrepared, 1, 0));
            }
        };
        let name_bytes = global_string_plan(name.len())?.backing_bytes();
        let value_bytes = global_string_plan(value.len())?.backing_bytes();
        adopted_bytes = adopted_bytes
            .checked_add(name_bytes)
            .and_then(|bytes| bytes.checked_add(value_bytes))
            .ok_or_else(|| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
        if !ctx.metadata.contains_key(name)
            && !patch.actions.as_slice()[..index].iter().any(|previous| {
                matches!(
                    previous,
                    TerminalFieldAction::Set { name: old, .. } if old.as_str() == name
                )
            })
        {
            added_keys += 1;
        }
    }
    // Never grow an unqualified foreign HashMap. Capacity is a guarantee of
    // insertion without reallocation, not an estimate of its owned layout.
    let required_keys = ctx.metadata.len().saturating_add(added_keys);
    if required_keys > ctx.metadata.capacity() {
        return Err(capacity_error(
            TerminalRefusal::AllocatorUnavailable,
            required_keys,
            ctx.metadata.capacity(),
        ));
    }
    let custody_plan = SharedTerminal::<TerminalMetadataCustody>::allocation_plan()?;
    let custody_bytes = custody_plan.backing_bytes();
    let required = patch
        .owned_bytes
        .saturating_add(adopted_bytes)
        .saturating_add(custody_bytes);
    if required > patch.output_limit {
        return Err(capacity_error(
            TerminalRefusal::ControlCapacity,
            required,
            patch.output_limit,
        ));
    }
    patch.metadata_custody = Some(SharedTerminal::request(
        TerminalMetadataCustody {
            _credit: request_credit(global_string_plan(0)?, &patch.ticket)?,
            _previous: ctx.terminal_metadata_custody.clone(),
        },
        &patch.ticket,
    )?);
    let custody = patch
        .metadata_custody
        .as_mut()
        .and_then(SharedTerminal::get_mut)
        .ok_or_else(|| capacity_error(TerminalRefusal::AlreadyPrepared, 1, 0))?;
    for action in patch.actions.as_mut_slice() {
        let (name, value) = match action {
            TerminalFieldAction::Set { name, value, .. } => (name.as_str(), Some(value.as_str())),
            TerminalFieldAction::Remove(_) => continue,
            TerminalFieldAction::Metadata { .. } => {
                return Err(capacity_error(TerminalRefusal::AlreadyPrepared, 1, 0));
            }
        };
        let (name, name_credit) = global_string(name, &patch.ticket)?;
        custody._credit.merge(name_credit)?;
        let value = if let Some(value) = value {
            let (value, value_credit) = global_string(value, &patch.ticket)?;
            custody._credit.merge(value_credit)?;
            Some(value)
        } else {
            None
        };
        *action = TerminalFieldAction::Metadata { name, value };
    }
    ctx.terminal_metadata_custody = patch.metadata_custody.take();
    // All copies and custody construction completed before the first mutation.
    for action in patch.actions.as_mut_slice() {
        match action {
            TerminalFieldAction::Metadata { name, value } => {
                let name = std::mem::take(name);
                if let Some(value) = value.take() {
                    ctx.metadata.insert(name, value);
                } else {
                    ctx.metadata.remove(&name);
                }
            }
            TerminalFieldAction::Remove(name) => {
                ctx.metadata.remove(name.as_str());
            }
            TerminalFieldAction::Set { .. } => {}
        }
    }
    Ok(())
}

fn validate_field(name: &str, value: &str) -> Result<(), TerminalAdmissionError> {
    if name.len() > MAX_FIELD_NAME_BYTES || value.len() > MAX_FIELD_VALUE_BYTES {
        return Err(capacity_error(
            TerminalRefusal::FieldCapacity,
            name.len().max(value.len()),
            MAX_FIELD_VALUE_BYTES,
        ));
    }
    if name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
        })
        || value.bytes().any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
    {
        return Err(capacity_error(TerminalRefusal::FieldCapacity, 0, 0));
    }
    Ok(())
}

fn capacity_error(
    reason: TerminalRefusal,
    required: usize,
    allowed: usize,
) -> TerminalAdmissionError {
    TerminalAdmissionError::new(reason, required, allowed)
}

/// Validate legacy input capacities and repeated wire-field shape. This does
/// not qualify the foreign HashMap's allocation layout or transport conversion.
pub fn validate_terminal_headers(
    headers: &std::collections::HashMap<String, String>,
) -> Result<(), TerminalAdmissionError> {
    let mut owned = 0usize;
    let mut wire_bytes = 0usize;
    let mut fields = 0usize;
    for (name, value) in headers {
        owned = owned
            .checked_add(name.capacity())
            .and_then(|bytes| bytes.checked_add(value.capacity()))
            .ok_or_else(|| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
        if name.eq_ignore_ascii_case("set-cookie") {
            for value in value.split('\n') {
                validate_field(name, value)?;
                fields += 1;
                wire_bytes = wire_bytes.saturating_add(name.len()).saturating_add(value.len());
            }
        } else {
            validate_field(name, value)?;
            fields += 1;
            wire_bytes = wire_bytes.saturating_add(name.len()).saturating_add(value.len());
        }
    }
    // Copying repeated cookies charges every name occurrence. A tiny value
    // with huge caller capacity also refuses before any selected-carrier copy.
    if owned > CARRIER_OWNED_BYTES
        || wire_bytes > CARRIER_OWNED_BYTES
        || fields > MAX_FIELD_OCCURRENCES
    {
        return Err(capacity_error(
            TerminalRefusal::FieldCapacity,
            owned.max(wire_bytes),
            CARRIER_OWNED_BYTES,
        ));
    }
    Ok(())
}

/// Apply one closed result to the sole selected response. Check prospective
/// allocation/field counts first. No raw request facts are available here.
pub fn apply_terminal_patch(
    patch: TerminalPatch,
    headers: &mut std::collections::HashMap<String, String>,
) -> Result<(), TerminalAdmissionError> {
    preflight_legacy_patch(&patch, headers)?;
    let mut carrier = SelectedTerminalCarrier::new(&patch.ticket)?;
    carrier.load_legacy(headers)?;
    carrier.apply(&patch)?;
    // The legacy adapter below remains outside the qualified wire-handoff
    // proof. All semantic/field-capacity checks finish before its mutations.
    drop(carrier);
    apply_legacy_patch(&patch, headers)
}

// This is a logical legacy-String guard, not a foreign-table allocation proof.
// Conservatively include the old input capacities and every prospective copy
// before changing either selected representation. Suppressed writes copy nothing.
fn preflight_legacy_patch(
    patch: &TerminalPatch,
    headers: &std::collections::HashMap<String, String>,
) -> Result<(), TerminalAdmissionError> {
    validate_terminal_headers(headers)?;
    let mut owned = headers.iter().fold(0usize, |bytes, (name, value)| {
        bytes
            .saturating_add(name.capacity())
            .saturating_add(value.capacity())
    });
    for (index, action) in patch.actions.as_slice().iter().enumerate() {
        match action {
            TerminalFieldAction::Set {
                name,
                value,
                override_existing,
                ..
            } => {
                let exists = headers
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case(name.as_str()));
                let previously_removed = patch.actions.as_slice()[..index].iter().any(|previous| {
                    matches!(
                        previous,
                        TerminalFieldAction::Remove(old)
                            if old.as_str().eq_ignore_ascii_case(name.as_str())
                    )
                });
                if !*override_existing && exists && !previously_removed {
                    continue;
                }
                owned = owned
                    .saturating_add(name.as_str().len())
                    .saturating_add(value.as_str().len());
            }
            TerminalFieldAction::Remove(_) => {}
            TerminalFieldAction::Metadata { .. } => {
                return Err(capacity_error(TerminalRefusal::UnimplementedOperation, 0, 0));
            }
        }
    }
    if owned > CARRIER_OWNED_BYTES {
        return Err(capacity_error(
            TerminalRefusal::FieldCapacity,
            owned,
            CARRIER_OWNED_BYTES,
        ));
    }
    Ok(())
}

fn apply_legacy_patch(
    patch: &TerminalPatch,
    headers: &mut std::collections::HashMap<String, String>,
) -> Result<(), TerminalAdmissionError> {
    for action in patch.actions.as_slice() {
        match action {
            TerminalFieldAction::Remove(name) => {
                headers.retain(|key, _| !key.eq_ignore_ascii_case(name.as_str()));
            }
            TerminalFieldAction::Set {
                name,
                value,
                override_existing,
                case_insensitive,
                lineage: _,
            } => {
                if !*override_existing
                    && headers
                        .keys()
                        .any(|key| key.eq_ignore_ascii_case(name.as_str()))
                {
                    continue;
                }
                if *case_insensitive {
                    headers.retain(|key, _| !key.eq_ignore_ascii_case(name.as_str()));
                }
                headers.insert(name.as_str().to_string(), value.as_str().to_string());
            }
            TerminalFieldAction::Metadata { .. } => {
                return Err(capacity_error(TerminalRefusal::UnimplementedOperation, 0, 0));
            }
        }
    }
    validate_terminal_headers(headers)
}

fn check_carrier_growth(
    headers: &std::collections::HashMap<String, String>,
    name: usize,
    value: usize,
    fields: usize,
) -> Result<(), TerminalAdmissionError> {
    let owned = headers
        .iter()
        .try_fold(name + value, |bytes, (name, value)| {
            bytes
                .checked_add(name.capacity())?
                .checked_add(value.capacity())
        })
        .unwrap_or(usize::MAX);
    let occurrences: usize = headers
        .iter()
        .map(|(name, value)| {
            if name.eq_ignore_ascii_case("set-cookie") {
                value.split('\n').count()
            } else {
                1
            }
        })
        .sum();
    // Legacy logical growth guard. It does not claim a foreign table layout
    // or its allocator backing; full wire handoff is still unqualified.
    if owned > CARRIER_OWNED_BYTES || occurrences + fields > MAX_FIELD_OCCURRENCES {
        return Err(capacity_error(
            TerminalRefusal::FieldCapacity,
            owned,
            CARRIER_OWNED_BYTES,
        ));
    }
    Ok(())
}

pub fn field_declaration(control: usize, output: usize) -> TerminalDeclaration {
    TerminalDeclaration::Prepared {
        bounds: TerminalBounds {
            control,
            output,
            workspace: 0,
        },
        prep_reads: TerminalFacts::TELEMETRY,
        prep_writes: TerminalFacts::NONE,
        trigger_reads: TerminalFacts::NONE,
        cursor_writes: TerminalFacts::RESPONSE_HEADERS,
    }
}

/// Cold-path bound for the same action table and exact field blocks used by
/// view.patch(). This includes allocator classes, not guessed per-field bytes.
pub fn field_output_bound<'a>(
    actions: usize,
    fields: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<usize, TerminalAdmissionError> {
    if actions > MAX_PATCH_ACTIONS {
        return Err(capacity_error(
            TerminalRefusal::PatchCapacity,
            actions,
            MAX_PATCH_ACTIONS,
        ));
    }
    let mut required = AllocationPlan::array::<TerminalFieldAction>(actions)?.backing_bytes();
    for (name, value) in fields {
        validate_field(name, value)?;
        let name_bytes = TerminalString::plan(name)?.backing_bytes();
        let value_bytes = TerminalString::plan(value)?.backing_bytes();
        required = required
            .checked_add(name_bytes)
            .and_then(|bytes| bytes.checked_add(value_bytes))
            .ok_or_else(|| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
    }
    Ok(required)
}

/// Compile the actual implementation union. Names never establish trust.
/// Stream/WebSocket-only chains do not enter the HTTP terminal lifecycle.
pub fn compile_terminal_manifest(
    plugins: &[std::sync::Arc<dyn super::Plugin>],
) -> Result<TerminalManifest, TerminalAdmissionError> {
    static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);
    let mut manifest = TerminalManifest::new();
    let mut chain = FixedSlots::generation(plugins.len(), &PROCESS_PREPARATION_LEDGER)?;
    for plugin in plugins {
        chain.push(std::sync::Arc::clone(plugin))?;
    }
    manifest.source_chain = Some(chain);
    for plugin in plugins {
        if !plugin.supported_protocols().iter().any(|protocol| {
            matches!(protocol, super::ProxyProtocol::Http | super::ProxyProtocol::Grpc)
        }) {
            continue;
        }
        let instance = TerminalInstanceToken(
            NEXT_INSTANCE
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?,
        );
        let eligibility = TerminalEligibility {
            rejection: plugin.applies_after_proxy_on_reject(),
            charged: !plugin.may_replace_rejection_response(),
        };
        if eligibility.participates()
            && manifest.sources.as_ref().is_some_and(|sources| {
                sources
                    .as_slice()
                    .iter()
                    .any(|previous| std::sync::Arc::ptr_eq(previous, plugin))
            })
        {
            return Err(capacity_error(TerminalRefusal::DuplicateInstance, 0, 0).at(instance));
        }
        let declaration = plugin.terminal_declaration();
        if eligibility.participates()
            && matches!(declaration, TerminalDeclaration::Prepared { .. })
            && !plugin.terminal_preparation_available()
        {
            return Err(capacity_error(TerminalRefusal::UnimplementedOperation, 0, 0).at(instance));
        }
        manifest.push(TerminalManifestEntry {
            instance,
            declaration,
            eligibility,
            wrapped: plugin.terminal_is_wrapped(),
        })?;
        if eligibility.participates() {
            // The frozen eligibility above selects the exact source instance.
            // Candidate and old table backing are both charged while copying.
            let mut sources = FixedSlots::generation(manifest.len, &PROCESS_PREPARATION_LEDGER)?;
            if let Some(previous) = &manifest.sources {
                for source in previous.as_slice() {
                    sources.push(std::sync::Arc::clone(source))?;
                }
            }
            sources.push(std::sync::Arc::clone(plugin))?;
            manifest.sources = Some(sources);
        }
    }
    Ok(manifest)
}

/// All preparations finish before the caller executes any cursor action.
/// This fixed slot owner contains no plugin/context/raw view and invokes no
/// old-hook fallback. Unsupported operations fail before terminal execution.
pub struct PreparedTerminalChain {
    slots: Option<FixedSlots<Option<PreparedTerminalOp>>>,
    selected: Option<SelectedTerminalCarrier>,
    len: usize,
    cursor: usize,
    _ticket: Option<TerminalTicket>,
}

impl PreparedTerminalChain {
    pub fn prepare(
        plugins: &[std::sync::Arc<dyn super::Plugin>],
        ctx: &mut super::RequestContext,
        charged: bool,
        suppress_replacers: bool,
    ) -> Result<Self, TerminalAdmissionError> {
        let prepared = Self::prepare_operations(plugins, ctx, charged, suppress_replacers);
        // Including refusal/partial preparation: no context-owned upload or
        // decoder owner survives the public preparation boundary.
        ctx.retire_terminal_request_views();
        prepared
    }

    fn prepare_operations(
        plugins: &[std::sync::Arc<dyn super::Plugin>],
        ctx: &mut super::RequestContext,
        charged: bool,
        suppress_replacers: bool,
    ) -> Result<Self, TerminalAdmissionError> {
        let Some(manifest) = ctx.terminal_manifest_pin.clone() else {
            return Err(capacity_error(TerminalRefusal::PinnedGeneration, 0, 0));
        };
        if !manifest.matches_plugins(plugins) {
            return Err(capacity_error(TerminalRefusal::PinnedGeneration, 0, 0));
        }
        ctx.admit_terminal_manifest(&manifest)?;
        let ticket = ctx.terminal_control_reservation.clone();
        if let Some(ticket) = &ticket {
            ticket.claim_preparation()?;
        }
        let workspace = ticket
            .as_ref()
            .map(|ticket| ticket.workspace(manifest.workspace_bytes()))
            .transpose()?;
        let slots = if manifest.participant_count() == 0 {
            None
        } else {
            let ticket = ticket.as_ref().ok_or_else(|| {
                capacity_error(TerminalRefusal::PinnedGeneration, 0, 0)
            })?;
            let plan = AllocationPlan::array::<Option<PreparedTerminalOp>>(
                manifest.participant_count(),
            )?;
            let allowance = manifest.participant_count() * SLOT_BYTES;
            if plan.backing_bytes() > allowance {
                return Err(capacity_error(
                    TerminalRefusal::ControlCapacity,
                    plan.backing_bytes(),
                    allowance,
                ));
            }
            Some(FixedSlots::request(manifest.participant_count(), ticket)?)
        };
        let mut chain = Self {
            slots,
            selected: None,
            len: 0,
            cursor: 0,
            _ticket: ticket.clone(),
        };
        let sources = manifest
            .sources
            .as_ref()
            .map_or(&[][..], FixedSlots::as_slice);
        for (plugin, entry) in sources.iter().zip(manifest.entries()) {
            if ctx
                .precommit_response_phase_bound()
                .elapsed_authorization()
                .is_some()
            {
                return Err(capacity_error(TerminalRefusal::AuthorizationExpired, 0, 0));
            }
            let rejection = entry.eligibility.rejection;
            let charged_action = entry.eligibility.charged;
            let action_allowed = (if charged { charged_action } else { rejection })
                && !(suppress_replacers && !charged_action);
            if chain.len == MAX_PARTICIPANTS {
                return Err(capacity_error(
                    TerminalRefusal::TooManyParticipants,
                    chain.len + 1,
                    MAX_PARTICIPANTS,
                ));
            }
            let declaration = entry.declaration;
            let pure_noop = declaration == TerminalDeclaration::PureNoop;
            let operation = if pure_noop {
                PreparedTerminalOp::Noop
            } else {
                let (control_limit, output_limit, workspace_limit) = match declaration {
                    TerminalDeclaration::Prepared { bounds, .. } => {
                        (bounds.control, bounds.output, bounds.workspace)
                    }
                    _ => (0, 0, 0),
                };
                plugin.prepare_terminal(&mut ReachedRequestView {
                    context: ctx,
                    output_limit,
                    control_limit,
                    workspace_limit,
                    workspace: workspace.as_ref(),
                    action_allowed,
                    ticket: ticket.clone(),
                    instance: entry.instance,
                })?
            };
            operation.validate(declaration, ticket.as_ref(), entry.instance)?;
            let operation = Some(if !action_allowed {
                PreparedTerminalOp::Noop
            } else {
                operation
            });
            let slots = chain.slots.as_mut().ok_or_else(|| {
                capacity_error(TerminalRefusal::PinnedGeneration, 0, 0)
            })?;
            slots.push(operation)?;
            chain.len += 1;
        }
        drop(workspace);
        Ok(chain)
    }

    fn selected(
        &mut self,
        headers: &std::collections::HashMap<String, String>,
    ) -> Result<&mut SelectedTerminalCarrier, TerminalAdmissionError> {
        if self.selected.is_none() {
            let ticket = self._ticket.as_ref().ok_or_else(|| {
                capacity_error(TerminalRefusal::PinnedGeneration, 0, 0)
            })?;
            let mut selected = SelectedTerminalCarrier::new(ticket)?;
            selected.load_legacy(headers)?;
            self.selected = Some(selected);
        }
        self.selected.as_mut().ok_or_else(|| {
            capacity_error(TerminalRefusal::PinnedGeneration, 0, 0)
        })
    }

    pub(crate) fn reset_selected(
        &mut self,
        headers: &std::collections::HashMap<String, String>,
    ) -> Result<(), TerminalAdmissionError> {
        if let Some(selected) = &mut self.selected {
            selected.load_legacy(headers)?;
        }
        Ok(())
    }

    pub(crate) fn apply_fields(
        &mut self,
        patch: TerminalPatch,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> Result<(), TerminalAdmissionError> {
        preflight_legacy_patch(&patch, headers)?;
        self.selected(headers)?.apply(&patch)?;
        apply_legacy_patch(&patch, headers)
    }

    pub(crate) fn apply_cookie(
        &mut self,
        cookie: TerminalCookie,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> Result<(), TerminalAdmissionError> {
        preflight_legacy_cookie(cookie.value.as_str(), headers)?;
        self.selected(headers)?.append_cookie(&cookie)?;
        apply_terminal_cookie(cookie, headers)
    }

    /// Consume each operation exactly once in source order. All currently
    /// admitted variants are immediate; pending I/O variants are deliberately
    /// unavailable until their bounded transport/accounting migration exists.
    pub fn next_operation(&mut self) -> Option<PreparedTerminalOp> {
        if self.cursor == self.len {
            return None;
        }
        let operation = self.slots.as_mut()?.as_mut_slice()[self.cursor].take();
        self.cursor += 1;
        operation
    }

    pub fn allocated_backing_bytes(&self) -> usize {
        self._ticket
            .as_ref()
            .map_or(0, |ticket| ticket.allocated_backing_bytes())
    }
}

tokio::task_local! {
    pub(crate) static RESPONSE_TERMINAL_TICKET:
        std::cell::RefCell<Option<TerminalTicket>>;
}

pub const CAPACITY_GRPC_WEB_BINARY: &[u8] =
    b"\x80\x00\x00\x00\x47grpc-status: 8\r\ngrpc-message: Rejection preparation capacity exceeded\r\n";
pub const CAPACITY_GRPC_WEB_TEXT: &[u8] = concat!(
    "gAAAAEdncnBjLXN0YXR1czogOA0KZ3JwYy1tZXNzYWdlOiBSZWplY3Rpb24gcHJlcGFy",
    "YXRpb24gY2FwYWNpdHkgZXhjZWVkZWQNCg==",
)
.as_bytes();

/// Existing emergency wire shape. Values and body are static, but HeaderMap
/// construction still allocates. Pre-owned emergency backing and its 4096-byte
/// proof remain unimplemented; this function does not claim that qualification.
/// No plugin, parser, staged writer or recursive rejection chain runs.
pub fn capacity_wire_parts(
    native_grpc: bool,
    grpc_web: Option<&str>,
    head: bool,
) -> (http::StatusCode, http::HeaderMap, bytes::Bytes) {
    let mut headers = http::HeaderMap::with_capacity(6);
    let (status, content_type, body) = if let Some(content_type) = grpc_web {
        let text = content_type.starts_with("application/grpc-web-text");
        let proto = content_type.ends_with("+proto");
        let content_type = match (text, proto) {
            (true, true) => "application/grpc-web-text+proto",
            (true, false) => "application/grpc-web-text",
            (false, true) => "application/grpc-web+proto",
            (false, false) => "application/grpc-web",
        };
        headers.insert("x-grpc-web", http::HeaderValue::from_static("1"));
        headers.insert("vary", http::HeaderValue::from_static("Accept"));
        headers.insert(
            "access-control-expose-headers",
            http::HeaderValue::from_static("grpc-status, grpc-message, grpc-status-details-bin"),
        );
        let body = if text {
            CAPACITY_GRPC_WEB_TEXT
        } else {
            CAPACITY_GRPC_WEB_BINARY
        };
        (http::StatusCode::OK, content_type, body)
    } else if native_grpc {
        headers.insert("grpc-status", http::HeaderValue::from_static("8"));
        headers.insert(
            "grpc-message",
            http::HeaderValue::from_static(CAPACITY_MESSAGE),
        );
        (http::StatusCode::OK, "application/grpc", &[][..])
    } else {
        (
            http::StatusCode::SERVICE_UNAVAILABLE,
            "application/json",
            CAPACITY_HTTP_BODY,
        )
    };
    headers.insert("content-type", http::HeaderValue::from_static(content_type));
    let body = if head && !native_grpc && grpc_web.is_none() {
        &[][..]
    } else {
        body
    };
    (status, headers, bytes::Bytes::from_static(body))
}

/// Pure candidate registry. Each row delegates to the actual implementation's
/// source-owned declaration, not a name reported by an arbitrary Plugin. Custom
/// factories always use their real constructed object and bypass this registry.
/// Active/unmigrated implementations have no trusted placeholder declaration.
pub(crate) fn builtin_composition_declaration(name: &str) -> TerminalDeclaration {
    match name {
        "__mesh_bpf_metrics" => super::mesh::bpf_metrics::terminal_composition_declaration(),
        "access_control" => super::access_control::terminal_composition_declaration(),
        "adaptive_concurrency" => super::adaptive_concurrency::terminal_composition_declaration(),
        "ai_prompt_compressor" => super::ai_prompt_compressor::terminal_composition_declaration(),
        "ai_prompt_shield" => super::ai_prompt_shield::terminal_composition_declaration(),
        "ai_request_guard" => super::ai_request_guard::terminal_composition_declaration(),
        "ai_semantic_firewall" => super::ai_semantic_firewall::terminal_composition_declaration(),
        "ai_token_metrics" => super::ai_token_metrics::terminal_composition_declaration(),
        "ai_tool_governor" => super::ai_tool_governor::terminal_composition_declaration(),
        "api_chargeback" => super::api_chargeback::terminal_composition_declaration(),
        "api_chargeback_sink" => super::api_chargeback_sink::terminal_composition_declaration(),
        "basic_auth" => super::utils::auth_flow::terminal_composition_declaration(),
        "bot_detection" => super::bot_detection::terminal_composition_declaration(),
        "fault_injection" => super::fault_injection::terminal_composition_declaration(),
        "geo_restriction" => super::geo_restriction::terminal_composition_declaration(),
        "graphql" => super::graphql::terminal_composition_declaration(),
        "grpc_deadline" => super::grpc_deadline::terminal_composition_declaration(),
        "grpc_method_router" => super::grpc_method_router::terminal_composition_declaration(),
        "hmac_auth" => super::utils::auth_flow::terminal_composition_declaration(),
        "http_logging" => super::http_logging::terminal_composition_declaration(),
        "ip_restriction" => super::ip_restriction::terminal_composition_declaration(),
        "jwks_auth" => super::jwks_auth::terminal_composition_declaration(),
        "jwt_auth" => super::utils::auth_flow::terminal_composition_declaration(),
        "kafka_logging" => super::kafka_logging::terminal_composition_declaration(),
        "key_auth" => super::utils::auth_flow::terminal_composition_declaration(),
        "ldap_auth" => super::utils::auth_flow::terminal_composition_declaration(),
        "load_testing" => super::load_testing::terminal_composition_declaration(),
        "loki_logging" => super::loki_logging::terminal_composition_declaration(),
        "mesh_authz" => super::mesh::authz::terminal_composition_declaration(),
        "workload_metrics" => super::mesh::workload_metrics::terminal_composition_declaration(),
        "mesh_outbound_registry" => {
            super::mesh::outbound_registry::terminal_composition_declaration()
        }
        "mesh_route_dispatch" => super::mesh_route_dispatch::terminal_composition_declaration(),
        "mtls_auth" => super::utils::auth_flow::terminal_composition_declaration(),
        "oauth2_introspection" => super::oauth2_introspection::terminal_composition_declaration(),
        "opa" => super::opa::terminal_composition_declaration(),
        "prometheus_metrics" => super::prometheus_metrics::terminal_composition_declaration(),
        "proxy_alerts" => super::proxy_alerts::terminal_composition_declaration(),
        "request_deduplication" => super::request_deduplication::terminal_composition_declaration(),
        "request_mirror" => super::request_mirror::terminal_composition_declaration(),
        "request_size_limiting" => super::request_size_limiting::terminal_composition_declaration(),
        "request_termination" => super::request_termination::terminal_composition_declaration(),
        "request_transformer" => super::request_transformer::terminal_composition_declaration(),
        "response_mock" => super::response_mock::terminal_composition_declaration(),
        "serverless_function" => super::serverless_function::terminal_composition_declaration(),
        "soap_ws_security" => super::soap_ws_security::terminal_composition_declaration(),
        "spiffe_identity" => super::mesh::spiffe_identity::terminal_composition_declaration(),
        "statsd_logging" => super::statsd_logging::terminal_composition_declaration(),
        "stdout_logging" => super::stdout_logging::terminal_composition_declaration(),
        "tcp_connection_throttle" => {
            super::tcp_connection_throttle::terminal_composition_declaration()
        }
        "tcp_logging" => super::tcp_logging::terminal_composition_declaration(),
        "udp_logging" => super::udp_logging::terminal_composition_declaration(),
        "udp_rate_limiting" => super::udp_rate_limiting::terminal_composition_declaration(),
        "ws_frame_logging" => super::ws_frame_logging::terminal_composition_declaration(),
        "ws_logging" => super::ws_logging::terminal_composition_declaration(),
        "ws_message_size_limiting" => {
            super::ws_message_size_limiting::terminal_composition_declaration()
        }
        "ws_rate_limiting" => super::ws_rate_limiting::terminal_composition_declaration(),
        "ai_semantic_cache" => super::ai_semantic_cache::terminal_composition_declaration(),
        "spec_expose" => super::spec_expose::terminal_composition_declaration(),
        _ => TerminalDeclaration::Undeclared,
    }
}

fn preflight_legacy_cookie(
    cookie: &str,
    headers: &std::collections::HashMap<String, String>,
) -> Result<Option<usize>, TerminalAdmissionError> {
    validate_terminal_headers(headers)?;
    if cookie.len() > MAX_COOKIE_BYTES {
        return Err(capacity_error(
            TerminalRefusal::FieldCapacity,
            cookie.len(),
            MAX_COOKIE_BYTES,
        ));
    }
    let Some(existing) = headers.get("set-cookie") else {
        check_carrier_growth(headers, 10, cookie.len(), cookie.split('\n').count())?;
        return Ok(None);
    };
    let length = existing
        .len()
        .checked_add(cookie.len())
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(|| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
    // Each opaque cookie occurrence has its own 16 KiB value bound. The
    // legacy combined String has the whole carrier's logical byte guard;
    // its foreign backing/export overlap remains unqualified.
    if length > CARRIER_OWNED_BYTES {
        return Err(capacity_error(
            TerminalRefusal::FieldCapacity,
            length,
            CARRIER_OWNED_BYTES,
        ));
    }
    check_carrier_growth(headers, 10, length, cookie.split('\n').count())?;
    Ok(Some(length))
}

pub fn apply_terminal_cookie(
    cookie: TerminalCookie,
    headers: &mut std::collections::HashMap<String, String>,
) -> Result<(), TerminalAdmissionError> {
    let cookie = cookie.value.as_str();
    let Some(length) = preflight_legacy_cookie(cookie, headers)? else {
        headers.insert("set-cookie".to_string(), cookie.to_string());
        return Ok(());
    };
    let Some(existing) = headers.get("set-cookie") else {
        return Err(capacity_error(TerminalRefusal::UnimplementedOperation, 0, 0));
    };
    let mut combined = String::with_capacity(length);
    combined.push_str(existing);
    combined.push('\n');
    combined.push_str(cookie);
    headers.insert("set-cookie".to_string(), combined);
    validate_terminal_headers(headers)
}
