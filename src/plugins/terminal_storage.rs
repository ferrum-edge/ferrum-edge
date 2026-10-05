//! Allocation-backed storage for synchronous terminal preparation.
//!
//! These blocks use the locked, prefixed jemalloc directly, including in a
//! library whose global allocator is System. `nallocx` supplies the backing
//! size before `mallocx`; Rust collection capacity is not an allocation proof.
//! Windows has no qualified allocator here and refuses before allocation.
//! Allocator arena bookkeeping and transport-task RSS are outside this domain.

use std::alloc::Layout;
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::terminal_preparation::{
    ControlReservation, PreparationLedger, ROOT_BYTES, TerminalAdmissionError, TerminalRefusal,
};

#[cfg(not(windows))]
unsafe extern "C" {
    // Cargo.lock: tikv-jemalloc-sys 0.6.1, default prefixed build. The binary's
    // allocator uses the same symbols; no global-allocator assumption is made.
    #[link_name = "_rjem_nallocx"]
    fn nallocx(size: usize, flags: std::ffi::c_int) -> usize;
    #[link_name = "_rjem_mallocx"]
    fn mallocx(size: usize, flags: std::ffi::c_int) -> *mut std::ffi::c_void;
    #[link_name = "_rjem_sdallocx"]
    fn sdallocx(pointer: *mut std::ffi::c_void, size: usize, flags: std::ffi::c_int);
}

/// A plan includes alignment padding and jemalloc's actual allocation class.
/// It is inseparable from the allocator which executes it.
#[derive(Clone, Copy, Debug)]
pub struct AllocationPlan {
    layout: Layout,
    backing: usize,
    #[cfg_attr(windows, allow(dead_code))]
    flags: std::ffi::c_int,
}

impl AllocationPlan {
    pub fn for_layout(layout: Layout) -> Result<Self, TerminalAdmissionError> {
        if layout.size() == 0 {
            return Ok(Self {
                layout,
                backing: 0,
                flags: 0,
            });
        }
        #[cfg(windows)]
        {
            Err(error(TerminalRefusal::AllocatorUnavailable, 0, 0))
        }
        #[cfg(not(windows))]
        {
            // MALLOCX_ALIGN is log2(alignment), as defined by the locked sys
            // crate. Layout guarantees a nonzero power-of-two alignment.
            let flags = layout.align().trailing_zeros() as std::ffi::c_int;
            // SAFETY: nallocx does not allocate or dereference any pointer.
            // Its size is nonzero and its alignment flag is valid.
            let backing = unsafe { nallocx(layout.size(), flags) };
            if backing < layout.size() {
                return Err(error(
                    TerminalRefusal::AllocatorUnavailable,
                    layout.size(),
                    backing,
                ));
            }
            Ok(Self {
                layout,
                backing,
                flags,
            })
        }
    }

    pub fn array<T>(count: usize) -> Result<Self, TerminalAdmissionError> {
        let layout = Layout::array::<T>(count)
            .map_err(|_| error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
        Self::for_layout(layout)
    }

    pub const fn backing_bytes(self) -> usize {
        self.backing
    }

    pub const fn requested_bytes(self) -> usize {
        self.layout.size()
    }
}

fn error(reason: TerminalRefusal, required: usize, allowed: usize) -> TerminalAdmissionError {
    TerminalAdmissionError::new(reason, required, allowed)
}

/// Credit has no reference to its allocation. Allocation -> ticket -> ledger
/// is the only ownership direction; the ledger owns no allocation or ticket.
pub(crate) enum AllocationCredit {
    Generation {
        ledger: &'static PreparationLedger,
        bytes: usize,
    },
    Request {
        ticket: TerminalTicket,
        bytes: usize,
    },
    Root,
}

static GLOBAL_JEMALLOC: AtomicBool = AtomicBool::new(false);

/// Register the allocator already installed by the binary, before workers
/// start. Library consumers do not inherit the binary's allocator profile.
///
/// # Safety
/// The process global allocator must forward this locked jemalloc's allocation
/// and deallocation without changing layout or allocating additional backing.
pub unsafe fn register_global_jemalloc() {
    #[cfg(not(windows))]
    GLOBAL_JEMALLOC.store(true, Ordering::Release);
}

pub(crate) fn global_string_plan(length: usize) -> Result<AllocationPlan, TerminalAdmissionError> {
    if !GLOBAL_JEMALLOC.load(Ordering::Acquire) {
        return Err(error(TerminalRefusal::AllocatorUnavailable, length, 0));
    }
    AllocationPlan::array::<u8>(length)
}

pub(crate) fn request_credit(
    plan: AllocationPlan,
    ticket: &TerminalTicket,
) -> Result<AllocationCredit, TerminalAdmissionError> {
    ticket.reserve_backing(plan.backing)?;
    Ok(AllocationCredit::Request {
        ticket: ticket.clone(),
        bytes: plan.backing,
    })
}

impl Drop for AllocationCredit {
    fn drop(&mut self) {
        match self {
            Self::Generation { ledger, bytes } => ledger.release_backing(*bytes),
            Self::Request { ticket, bytes } => ticket.release_backing(*bytes),
            Self::Root => {}
        }
    }
}

impl AllocationCredit {
    pub(crate) fn merge(&mut self, other: Self) -> Result<(), TerminalAdmissionError> {
        let Self::Request { ticket, bytes } = self else {
            return Err(error(TerminalRefusal::PinnedGeneration, 0, 0));
        };
        let Self::Request {
            ticket: other_ticket,
            bytes: other_bytes,
        } = &other
        else {
            return Err(error(TerminalRefusal::PinnedGeneration, 0, 0));
        };
        if ticket.pointer != other_ticket.pointer {
            return Err(error(TerminalRefusal::PinnedGeneration, 0, 0));
        }
        let total = bytes
            .checked_add(*other_bytes)
            .ok_or_else(|| error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))?;
        let other = std::mem::ManuallyDrop::new(other);
        if let Self::Request { ticket, .. } = &*other {
            // SAFETY: consume only the redundant reference-count owner; its
            // backing byte credit transfers into self and is not released.
            drop(unsafe { std::ptr::read(ticket) });
        }
        *bytes = total;
        Ok(())
    }
}

pub(crate) fn global_string(
    value: &str,
    ticket: &TerminalTicket,
) -> Result<(String, AllocationCredit), TerminalAdmissionError> {
    let plan = global_string_plan(value.len())?;
    if value.is_empty() {
        return Ok((String::new(), request_credit(plan, ticket)?));
    }
    let block = std::mem::ManuallyDrop::new(AllocationBlock::request(plan, ticket)?);
    // SAFETY: copy the entire UTF-8 input into unique backing. The registered
    // global allocator is this same jemalloc; String's align-1, exact-capacity
    // deallocation therefore calls sdallocx with this original size/flags.
    let string = unsafe {
        std::ptr::copy_nonoverlapping(value.as_ptr(), block.pointer.as_ptr(), value.len());
        String::from_raw_parts(block.pointer.as_ptr(), value.len(), value.len())
    };
    // SAFETY: the suppressed block destructor transfers its sole credit owner.
    let credit = unsafe { std::ptr::read(&block._credit) };
    Ok((string, credit))
}

/// Unique nonmoving backing. Credit is acquired before this constructor is
/// called, and returned only after `sdallocx` has dropped the backing.
pub(crate) struct AllocationBlock {
    pointer: NonNull<u8>,
    plan: AllocationPlan,
    _credit: AllocationCredit,
}

impl AllocationBlock {
    pub(crate) fn workspace(plan: AllocationPlan) -> Result<Self, TerminalAdmissionError> {
        // The scoped caller already owns an exact class-sized workspace lease.
        let block = Self::allocate(plan, AllocationCredit::Root)?;
        // SAFETY: initialize the full unique region before any slice exists.
        unsafe { block.pointer.as_ptr().write_bytes(0, plan.layout.size()) };
        Ok(block)
    }

    fn allocate(
        plan: AllocationPlan,
        credit: AllocationCredit,
    ) -> Result<Self, TerminalAdmissionError> {
        if plan.backing == 0 {
            return Ok(Self {
                pointer: NonNull::new(plan.layout.align() as *mut u8)
                    .ok_or_else(|| error(TerminalRefusal::AllocatorUnavailable, 0, 0))?,
                plan,
                _credit: credit,
            });
        }
        #[cfg(windows)]
        let pointer: *mut u8 = std::ptr::null_mut();
        #[cfg(not(windows))]
        // SAFETY: the nonzero, checked Layout and matching flags are exactly
        // the plan for which credit was acquired. Null is handled below.
        let pointer = unsafe { mallocx(plan.layout.size(), plan.flags).cast::<u8>() };
        let pointer = NonNull::new(pointer)
            .ok_or_else(|| error(TerminalRefusal::AllocationFailure, plan.backing, 0))?;
        Ok(Self {
            pointer,
            plan,
            _credit: credit,
        })
    }

    pub(crate) fn generation(
        plan: AllocationPlan,
        ledger: &'static PreparationLedger,
    ) -> Result<Self, TerminalAdmissionError> {
        ledger.reserve_backing(plan.backing)?;
        Self::allocate(
            plan,
            AllocationCredit::Generation {
                ledger,
                bytes: plan.backing,
            },
        )
    }

    pub(crate) fn request(
        plan: AllocationPlan,
        ticket: &TerminalTicket,
    ) -> Result<Self, TerminalAdmissionError> {
        ticket.reserve_backing(plan.backing)?;
        Self::allocate(
            plan,
            AllocationCredit::Request {
                ticket: ticket.clone(),
                bytes: plan.backing,
            },
        )
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: initialized bytes are provided only by the byte-arena users,
        // which initialize the whole region before exposing it.
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.plan.layout.size()) }
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the block is uniquely owned and byte storage is initialized
        // at construction by `zeroed_request`; no typed values share it.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.plan.layout.size()) }
    }

    pub(crate) fn zeroed_request(
        plan: AllocationPlan,
        ticket: &TerminalTicket,
    ) -> Result<Self, TerminalAdmissionError> {
        let block = Self::request(plan, ticket)?;
        // SAFETY: mallocx supplied the entire requested writable region.
        unsafe { block.pointer.as_ptr().write_bytes(0, plan.layout.size()) };
        Ok(block)
    }

    pub(crate) const fn backing_bytes(&self) -> usize {
        self.plan.backing
    }
}

impl Drop for AllocationBlock {
    fn drop(&mut self) {
        if self.plan.backing != 0 {
            #[cfg(not(windows))]
            // SAFETY: unique pointer, original requested size and flags, same
            // allocator. Credit drops after this destructor body completes.
            unsafe {
                sdallocx(
                    self.pointer.as_ptr().cast(),
                    self.plan.layout.size(),
                    self.plan.flags,
                );
            }
        }
    }
}

// SAFETY: the block owns its backing exclusively. Shared byte access is
// immutable; writes require &mut self. Typed storage imposes T's bounds below.
unsafe impl Send for AllocationBlock {}
unsafe impl Sync for AllocationBlock {}

/// Exactly `capacity` out-of-line elements; neither push nor take allocates.
/// The initialized prefix is tracked separately from the allocation length.
pub(crate) struct FixedSlots<T> {
    block: AllocationBlock,
    len: usize,
    capacity: usize,
    _element: PhantomData<T>,
}

impl<T> FixedSlots<T> {
    pub(crate) fn generation(
        capacity: usize,
        ledger: &'static PreparationLedger,
    ) -> Result<Self, TerminalAdmissionError> {
        let block = AllocationBlock::generation(AllocationPlan::array::<T>(capacity)?, ledger)?;
        Ok(Self {
            block,
            len: 0,
            capacity,
            _element: PhantomData,
        })
    }

    pub(crate) fn request(
        capacity: usize,
        ticket: &TerminalTicket,
    ) -> Result<Self, TerminalAdmissionError> {
        let block = AllocationBlock::request(AllocationPlan::array::<T>(capacity)?, ticket)?;
        Ok(Self {
            block,
            len: 0,
            capacity,
            _element: PhantomData,
        })
    }

    pub(crate) fn push(&mut self, value: T) -> Result<(), TerminalAdmissionError> {
        if self.len == self.capacity {
            return Err(error(
                TerminalRefusal::ControlCapacity,
                self.len + 1,
                self.capacity,
            ));
        }
        // SAFETY: this element is within the allocation and uninitialized.
        unsafe {
            self.block
                .pointer
                .as_ptr()
                .cast::<T>()
                .add(self.len)
                .write(value)
        };
        self.len += 1;
        Ok(())
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: the prefix contains exactly len initialized, aligned Ts.
        unsafe { std::slice::from_raw_parts(self.block.pointer.as_ptr().cast(), self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        if self.len == 0 {
            return &mut [];
        }
        // SAFETY: unique owner of the initialized, aligned prefix.
        unsafe { std::slice::from_raw_parts_mut(self.block.pointer.as_ptr().cast(), self.len) }
    }

    pub(crate) fn clear(&mut self) {
        while self.len != 0 {
            // Retire the initialized element before its destructor runs, so a
            // panicking destructor cannot cause a second drop during unwind.
            self.len -= 1;
            // SAFETY: this was the last initialized element in the prefix.
            unsafe {
                std::ptr::drop_in_place(self.block.pointer.as_ptr().cast::<T>().add(self.len));
            }
        }
    }
}

impl<T> Drop for FixedSlots<T> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<T: fmt::Debug> fmt::Debug for FixedSlots<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

// SAFETY: elements are accessible only through the owner's Rust borrows.
unsafe impl<T: Send> Send for FixedSlots<T> {}
unsafe impl<T: Sync> Sync for FixedSlots<T> {}

#[repr(C)]
struct SharedHeader<T> {
    references: AtomicUsize,
    value: T,
    credit: AllocationCredit,
    #[cfg_attr(windows, allow(dead_code))]
    plan: AllocationPlan,
}

/// Thin shared owner. Cloning does not allocate; the last clone frees actual
/// backing before dropping the reservation value which releases its credit.
pub struct SharedTerminal<T> {
    pointer: NonNull<SharedHeader<T>>,
}

pub type TerminalTicket = SharedTerminal<ControlReservation<'static>>;

impl<T> SharedTerminal<T> {
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        self.pointer == other.pointer
    }

    pub(crate) fn get_mut(&mut self) -> Option<&mut T> {
        // SAFETY: &mut self excludes cloning this owner during the check. No
        // weak references exist, so a count of one proves exclusive access.
        if unsafe { self.pointer.as_ref() }
            .references
            .load(Ordering::Acquire)
            != 1
        {
            return None;
        }
        // SAFETY: the reference-count check established exclusive ownership.
        Some(unsafe { &mut self.pointer.as_mut().value })
    }

    pub(crate) fn allocation_plan() -> Result<AllocationPlan, TerminalAdmissionError> {
        AllocationPlan::for_layout(Layout::new::<SharedHeader<T>>())
    }

    pub(crate) fn request(
        value: T,
        ticket: &TerminalTicket,
    ) -> Result<Self, TerminalAdmissionError> {
        let plan = AllocationPlan::for_layout(Layout::new::<SharedHeader<T>>())?;
        let block = std::mem::ManuallyDrop::new(AllocationBlock::request(plan, ticket)?);
        let pointer = block.pointer.cast::<SharedHeader<T>>();
        // SAFETY: transfer the sole credit/backing owner to this exact header.
        let credit = unsafe { std::ptr::read(&block._credit) };
        unsafe {
            pointer.as_ptr().write(SharedHeader {
                references: AtomicUsize::new(1),
                value,
                credit,
                plan,
            });
        }
        Ok(Self { pointer })
    }

    pub(crate) fn generation(
        value: T,
        ledger: &'static PreparationLedger,
    ) -> Result<Self, TerminalAdmissionError> {
        let plan = AllocationPlan::for_layout(Layout::new::<SharedHeader<T>>())?;
        let block = std::mem::ManuallyDrop::new(AllocationBlock::generation(plan, ledger)?);
        let pointer = block.pointer.cast::<SharedHeader<T>>();
        // SAFETY: the block destructor is suppressed, transferring its sole
        // credit owner into the initialized shared header.
        let credit = unsafe { std::ptr::read(&block._credit) };
        // SAFETY: the plan is for this exact header, and backing is unique.
        unsafe {
            pointer.as_ptr().write(SharedHeader {
                references: AtomicUsize::new(1),
                value,
                credit,
                plan,
            });
        }
        Ok(Self { pointer })
    }
}

impl TerminalTicket {
    pub(crate) fn new_ticket(
        value: ControlReservation<'static>,
    ) -> Result<Self, TerminalAdmissionError> {
        let layout = Layout::new::<SharedHeader<ControlReservation<'_>>>();
        let plan = AllocationPlan::for_layout(layout)?;
        if plan.backing > ROOT_BYTES {
            return Err(error(
                TerminalRefusal::ControlCapacity,
                plan.backing,
                ROOT_BYTES,
            ));
        }
        value.reserve_backing(plan.backing)?;
        let block = AllocationBlock::allocate(plan, AllocationCredit::Root)?;
        let pointer = block
            .pointer
            .cast::<SharedHeader<ControlReservation<'static>>>();
        // SAFETY: the plan is for this exact header, and backing is unique.
        unsafe {
            pointer.as_ptr().write(SharedHeader {
                references: AtomicUsize::new(1),
                value,
                credit: AllocationCredit::Root,
                plan,
            });
        }
        // Ownership passes to SharedTerminal, not to a second allocation.
        std::mem::forget(block);
        Ok(Self { pointer })
    }
}

impl<T> Clone for SharedTerminal<T> {
    fn clone(&self) -> Self {
        // SAFETY: this live owner keeps the initialized header alive.
        let previous = unsafe { self.pointer.as_ref() }
            .references
            .fetch_add(1, Ordering::Relaxed);
        // Same finite reference-count invariant as Arc: allowing a wrap could
        // free live backing. This cannot be reached by the admitted finite
        // cursor, but a process abort protects memory safety if misused.
        if previous >= isize::MAX as usize {
            std::process::abort();
        }
        Self {
            pointer: self.pointer,
        }
    }
}

impl<T> Deref for SharedTerminal<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this live shared owner keeps value initialized and alive.
        unsafe { &self.pointer.as_ref().value }
    }
}

impl<T: fmt::Debug> fmt::Debug for SharedTerminal<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.deref().fmt(f)
    }
}

impl<T> Drop for SharedTerminal<T> {
    fn drop(&mut self) {
        // SAFETY: the owner keeps the header alive through this decrement.
        if unsafe { self.pointer.as_ref() }
            .references
            .fetch_sub(1, Ordering::Release)
            != 1
        {
            return;
        }
        std::sync::atomic::fence(Ordering::Acquire);
        // SAFETY: the last reference exclusively owns value and backing. Move
        // value out, free its backing, then release the reservation it owns.
        #[cfg(not(windows))]
        let plan = unsafe { self.pointer.as_ref() }.plan;
        let value = unsafe { std::ptr::read(&self.pointer.as_ref().value) };
        // SAFETY: this is also exclusively owned by the last reference.
        let credit = unsafe { std::ptr::read(&self.pointer.as_ref().credit) };
        #[cfg(not(windows))]
        unsafe {
            sdallocx(self.pointer.as_ptr().cast(), plan.layout.size(), plan.flags);
        }
        drop(value);
        drop(credit);
    }
}

// SAFETY: the immutable shared value obeys the same Send/Sync requirements as
// Arc. The atomic reference count is the only mutable shared header state.
unsafe impl<T: Send + Sync> Send for SharedTerminal<T> {}
unsafe impl<T: Send + Sync> Sync for SharedTerminal<T> {}
