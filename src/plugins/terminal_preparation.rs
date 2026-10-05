//! Admission primitives for the approved rejection preparation contract.
//!
//! Generation manifests and one process ledger bound the synchronous prepared
//! boundary. Only closed immediate operations are currently implemented.
//! Unmigrated participants are refused; an ordinary async successful-response
//! hook is never used as a terminal adapter. Full qualification remains pending.

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
    UnimplementedOperation,
    FieldCapacity,
    PatchCapacity,
    AuthorizationExpired,
    AlreadyPrepared,
    PinnedGeneration,
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
    /// Pin an already compiled generation before request lifecycle/body work.
    /// Custom runtimes must use the same actual plugin chain at preparation.
    pub fn pin(
        self: &std::sync::Arc<Self>,
        ctx: &mut super::RequestContext,
    ) -> Result<(), TerminalAdmissionError> {
        ctx.pin_terminal_manifest(std::sync::Arc::clone(self))
    }

    fn matches_plugins(&self, plugins: &[std::sync::Arc<dyn super::Plugin>]) -> bool {
        let mut index = 0;
        for plugin in plugins {
            let eligibility = TerminalEligibility {
                rejection: plugin.applies_after_proxy_on_reject(),
                charged: !plugin.may_replace_rejection_response(),
            };
            if !eligibility.participates()
                || !plugin.supported_protocols().iter().any(|protocol| {
                    matches!(
                        protocol,
                        super::ProxyProtocol::Http | super::ProxyProtocol::Grpc
                    )
                })
            {
                continue;
            }
            let pointer = std::sync::Arc::as_ptr(plugin) as *const () as usize;
            let actual = TerminalManifestEntry {
                instance: TerminalInstanceToken(pointer as u64),
                declaration: plugin.terminal_declaration(),
                eligibility,
                wrapped: plugin.terminal_is_wrapped(),
            };
            if index == self.len || self.entries[index] != Some(actual) {
                return false;
            }
            index += 1;
        }
        index == self.len
    }

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
    terminal_prepared: AtomicBool,
}

impl<'a> ControlReservation<'a> {
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
    action_allowed: bool,
    ticket: Option<std::sync::Arc<ControlReservation<'static>>>,
}

impl ReachedRequestView<'_> {
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
        Ok(self
            .context
            .metadata
            .remove(key)
            .map(|value| TerminalCookie {
                value,
                _ticket: self.ticket.clone(),
            }))
    }

    /// Construct a patch using only this instance's admitted output credit.
    pub fn patch(&self, actions: usize) -> Result<TerminalPatch, TerminalAdmissionError> {
        let mut patch = TerminalPatch::new(actions, self.output_limit)?;
        patch._ticket = self.ticket.clone();
        Ok(patch)
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
    value: String,
    _ticket: Option<std::sync::Arc<ControlReservation<'static>>>,
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
    fn validate(&self, declaration: TerminalDeclaration) -> Result<(), TerminalAdmissionError> {
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
                if cookie.value.len() > MAX_COOKIE_BYTES
                    || cookie.value.capacity() > MAX_COOKIE_BYTES
                {
                    return Err(capacity_error(
                        TerminalRefusal::FieldCapacity,
                        cookie.value.capacity(),
                        MAX_COOKIE_BYTES,
                    ));
                }
                cookie.value.capacity()
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

enum TerminalFieldAction {
    Set {
        name: Box<str>,
        value: Box<str>,
        override_existing: bool,
        case_insensitive: bool,
    },
    Remove(Box<str>),
}

/// Allocates a fixed action vector only after the declaration's output credit
/// is known. Names/values use exact-size boxed strings, never cloned capacities.
/// Push never grows the vector, and checks before constructing either string.
pub struct TerminalPatch {
    actions: Vec<TerminalFieldAction>,
    output_limit: usize,
    owned_bytes: usize,
    _ticket: Option<std::sync::Arc<ControlReservation<'static>>>,
}

impl TerminalPatch {
    fn new(actions: usize, output: usize) -> Result<Self, TerminalAdmissionError> {
        let required = actions
            .checked_mul(128)
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| {
                capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, output)
            })?;
        if actions > MAX_PATCH_ACTIONS {
            return Err(capacity_error(
                TerminalRefusal::PatchCapacity,
                actions,
                MAX_PATCH_ACTIONS,
            ));
        }
        if required > output {
            return Err(capacity_error(
                TerminalRefusal::PatchCapacity,
                required,
                output,
            ));
        }
        Ok(Self {
            actions: Vec::with_capacity(actions),
            output_limit: output,
            owned_bytes: required,
            _ticket: None,
        })
    }

    fn reserve_field(&mut self, name: &str, value: &str) -> Result<(), TerminalAdmissionError> {
        if name.len() > MAX_FIELD_NAME_BYTES {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                name.len(),
                MAX_FIELD_NAME_BYTES,
            ));
        }
        if value.len() > MAX_FIELD_VALUE_BYTES {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                value.len(),
                MAX_FIELD_VALUE_BYTES,
            ));
        }
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || value
                .bytes()
                .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(capacity_error(TerminalRefusal::FieldCapacity, 0, 0));
        }
        if self.actions.len() == self.actions.capacity() {
            return Err(capacity_error(
                TerminalRefusal::PatchCapacity,
                self.actions.len() + 1,
                self.actions.capacity(),
            ));
        }
        let required = self
            .owned_bytes
            .checked_add(name.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or_else(|| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
        if required > self.output_limit {
            return Err(capacity_error(
                TerminalRefusal::PatchCapacity,
                required,
                self.output_limit,
            ));
        }
        self.owned_bytes = required;
        Ok(())
    }

    pub fn set(
        &mut self,
        name: &str,
        value: &str,
        override_existing: bool,
    ) -> Result<(), TerminalAdmissionError> {
        self.reserve_field(name, value)?;
        self.actions.push(TerminalFieldAction::Set {
            name: name.into(),
            value: value.into(),
            override_existing,
            case_insensitive: false,
        });
        Ok(())
    }

    pub fn set_policy(
        &mut self,
        name: &str,
        value: &str,
        override_existing: bool,
    ) -> Result<(), TerminalAdmissionError> {
        self.reserve_field(name, value)?;
        self.actions.push(TerminalFieldAction::Set {
            name: name.into(),
            value: value.into(),
            override_existing,
            case_insensitive: true,
        });
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<(), TerminalAdmissionError> {
        self.reserve_field(name, "")?;
        self.actions.push(TerminalFieldAction::Remove(name.into()));
        Ok(())
    }
}

fn capacity_error(
    reason: TerminalRefusal,
    required: usize,
    allowed: usize,
) -> TerminalAdmissionError {
    TerminalAdmissionError::new(reason, required, allowed)
}

/// Check the actual allocated capacities, repeated wire fields (including
/// newline-separated cookies), and retained map backing before any cursor work.
pub fn validate_terminal_headers(
    headers: &std::collections::HashMap<String, String>,
) -> Result<(), TerminalAdmissionError> {
    let mut owned = 0usize;
    let mut fields = 0usize;
    for (name, value) in headers {
        if name.len() > MAX_FIELD_NAME_BYTES {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                name.len(),
                MAX_FIELD_NAME_BYTES,
            ));
        }
        if value.len() > MAX_FIELD_VALUE_BYTES {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                value.len(),
                MAX_FIELD_VALUE_BYTES,
            ));
        }
        owned = owned
            .checked_add(name.capacity())
            .and_then(|bytes| bytes.checked_add(value.capacity()))
            .ok_or_else(|| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
        fields += if name.eq_ignore_ascii_case("set-cookie") {
            value.split('\n').count()
        } else {
            1
        };
    }
    // HashMap's supported load factor rounds backing buckets above capacity.
    // 64 bytes per reported capacity conservatively covers buckets/control
    // bytes, entries, allocator and map ownership, within the fixed allowance.
    let overhead = headers.capacity().checked_mul(64).unwrap_or(usize::MAX);
    if owned > CARRIER_OWNED_BYTES
        || overhead > CARRIER_OVERHEAD_BYTES
        || fields > MAX_FIELD_OCCURRENCES
    {
        return Err(capacity_error(
            TerminalRefusal::FieldCapacity,
            owned,
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
    validate_terminal_headers(headers)?;
    for action in patch.actions {
        match action {
            TerminalFieldAction::Remove(name) => {
                headers.retain(|key, _| !key.eq_ignore_ascii_case(&name));
            }
            TerminalFieldAction::Set {
                name,
                value,
                override_existing,
                case_insensitive,
            } => {
                if !override_existing && headers.keys().any(|key| key.eq_ignore_ascii_case(&name)) {
                    continue;
                }
                // Reserve the complete prospective carrier before map or string
                // growth, including simultaneous old and new owned field bytes.
                let replacing = if case_insensitive {
                    headers.keys().any(|key| key.eq_ignore_ascii_case(&name))
                } else {
                    headers.contains_key(name.as_ref())
                };
                check_carrier_growth(headers, name.len(), value.len(), usize::from(!replacing))?;
                if case_insensitive {
                    headers.retain(|key, _| !key.eq_ignore_ascii_case(&name));
                }
                headers.insert(name.into_string(), value.into_string());
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
    // Bound the next HashMap growth BEFORE insert, including its old allocation
    // while rehashing. No growth occurs when spare entry capacity remains.
    let capacity = if fields != 0 && headers.len() == headers.capacity() {
        headers.capacity().max(3).saturating_mul(3)
    } else {
        headers.capacity()
    };
    if owned > CARRIER_OWNED_BYTES
        || capacity.saturating_mul(64) > CARRIER_OVERHEAD_BYTES
        || occurrences + fields > MAX_FIELD_OCCURRENCES
    {
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

/// Compile the actual implementation union. Names never establish trust.
/// Stream/WebSocket-only chains do not enter the HTTP terminal lifecycle.
pub fn compile_terminal_manifest(
    plugins: &[std::sync::Arc<dyn super::Plugin>],
) -> Result<TerminalManifest, TerminalAdmissionError> {
    let mut manifest = TerminalManifest::new();
    for plugin in plugins {
        if !plugin.supported_protocols().iter().any(|protocol| {
            matches!(
                protocol,
                super::ProxyProtocol::Http | super::ProxyProtocol::Grpc
            )
        }) {
            continue;
        }
        let pointer = std::sync::Arc::as_ptr(plugin) as *const () as usize;
        let instance = TerminalInstanceToken(pointer as u64);
        let declaration = plugin.terminal_declaration();
        if (plugin.applies_after_proxy_on_reject() || !plugin.may_replace_rejection_response())
            && matches!(declaration, TerminalDeclaration::Prepared { .. })
            && !plugin.terminal_preparation_available()
        {
            return Err(capacity_error(TerminalRefusal::UnimplementedOperation, 0, 0).at(instance));
        }
        manifest.push(TerminalManifestEntry {
            instance,
            declaration,
            eligibility: TerminalEligibility {
                rejection: plugin.applies_after_proxy_on_reject(),
                charged: !plugin.may_replace_rejection_response(),
            },
            wrapped: plugin.terminal_is_wrapped(),
        })?;
    }
    Ok(manifest)
}

/// All preparations finish before the caller executes any cursor action.
/// This fixed slot owner contains no plugin/context/raw view and invokes no
/// old-hook fallback. Unsupported operations fail before terminal execution.
pub struct PreparedTerminalChain {
    slots: [Option<PreparedTerminalOp>; MAX_PARTICIPANTS],
    len: usize,
    cursor: usize,
    _ticket: Option<std::sync::Arc<ControlReservation<'static>>>,
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
        let mut chain = Self {
            slots: std::array::from_fn(|_| None),
            len: 0,
            cursor: 0,
            _ticket: ticket.clone(),
        };
        for plugin in plugins {
            if ctx
                .precommit_response_phase_bound()
                .elapsed_authorization()
                .is_some()
            {
                return Err(capacity_error(TerminalRefusal::AuthorizationExpired, 0, 0));
            }
            if !plugin.supported_protocols().iter().any(|protocol| {
                matches!(
                    protocol,
                    super::ProxyProtocol::Http | super::ProxyProtocol::Grpc
                )
            }) {
                continue;
            }
            let rejection = plugin.applies_after_proxy_on_reject();
            let charged_action = !plugin.may_replace_rejection_response();
            if !rejection && !charged_action {
                continue;
            }
            let action_allowed = (if charged { charged_action } else { rejection })
                && !(suppress_replacers && plugin.may_replace_rejection_response());
            if chain.len == MAX_PARTICIPANTS {
                return Err(capacity_error(
                    TerminalRefusal::TooManyParticipants,
                    chain.len + 1,
                    MAX_PARTICIPANTS,
                ));
            }
            let declaration = plugin.terminal_declaration();
            let pure_noop = declaration == TerminalDeclaration::PureNoop;
            let operation = if pure_noop {
                PreparedTerminalOp::Noop
            } else {
                let output_limit = match declaration {
                    TerminalDeclaration::Prepared { bounds, .. } => bounds.output,
                    _ => 0,
                };
                plugin.prepare_terminal(&mut ReachedRequestView {
                    context: ctx,
                    output_limit,
                    action_allowed,
                    ticket: ticket.clone(),
                })?
            };
            operation.validate(declaration)?;
            chain.slots[chain.len] = Some(if !action_allowed {
                PreparedTerminalOp::Noop
            } else {
                operation
            });
            chain.len += 1;
        }
        drop(workspace);
        Ok(chain)
    }

    /// Consume each operation exactly once in source order. All currently
    /// admitted variants are immediate; pending I/O variants are deliberately
    /// unavailable until their bounded transport/accounting migration exists.
    pub fn next_operation(&mut self) -> Option<PreparedTerminalOp> {
        if self.cursor == self.len {
            return None;
        }
        let operation = self.slots[self.cursor].take();
        self.cursor += 1;
        operation
    }
}

tokio::task_local! {
    pub(crate) static RESPONSE_TERMINAL_TICKET:
        std::cell::RefCell<Option<std::sync::Arc<ControlReservation<'static>>>>;
}

pub const CAPACITY_GRPC_WEB_BINARY: &[u8] =
    b"\x80\x00\x00\x00\x47grpc-status: 8\r\ngrpc-message: Rejection preparation capacity exceeded\r\n";
pub const CAPACITY_GRPC_WEB_TEXT: &[u8] = concat!(
    "gAAAAEdncnBjLXN0YXR1czogOA0KZ3JwYy1tZXNzYWdlOiBSZWplY3Rpb24gcHJlcGFy",
    "YXRpb24gY2FwYWNpdHkgZXhjZWVkZWQNCg==",
)
.as_bytes();

/// Emergency transport shape. Every value/body is static, and the fixed number
/// of transport header entries stays within the independent 4096-byte reserve.
/// No ledger, hook, parser, fallible staged writer or recursive rejection runs.
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

pub fn apply_terminal_cookie(
    cookie: TerminalCookie,
    headers: &mut std::collections::HashMap<String, String>,
) -> Result<(), TerminalAdmissionError> {
    let TerminalCookie {
        value: cookie,
        _ticket,
    } = cookie;
    validate_terminal_headers(headers)?;
    if cookie.len() > MAX_COOKIE_BYTES || cookie.capacity() > MAX_COOKIE_BYTES {
        return Err(capacity_error(
            TerminalRefusal::FieldCapacity,
            cookie.capacity(),
            MAX_COOKIE_BYTES,
        ));
    }
    let Some(existing) = headers.get("set-cookie") else {
        check_carrier_growth(headers, 10, cookie.capacity(), cookie.split('\n').count())?;
        headers.insert("set-cookie".to_string(), cookie);
        return Ok(());
    };
    let length = existing
        .len()
        .checked_add(cookie.len())
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(|| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
    // Cookie ownership remains charged to O. New and old selected field
    // capacities are charged to the carrier before allocating the combination.
    if length > MAX_COOKIE_BYTES {
        return Err(capacity_error(
            TerminalRefusal::FieldCapacity,
            length,
            MAX_COOKIE_BYTES,
        ));
    }
    check_carrier_growth(headers, 10, length, cookie.split('\n').count())?;
    let mut combined = String::with_capacity(length);
    combined.push_str(existing);
    combined.push('\n');
    combined.push_str(&cookie);
    headers.insert("set-cookie".to_string(), combined);
    validate_terminal_headers(headers)
}
